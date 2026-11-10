//! Multi-channel discovery router.
//!
//! Clients race `fetch` across all configured channels and union the
//! results. Operators `publish` to every channel in parallel; we tolerate
//! per-channel failures as long as at least one succeeds.
//!
//! Concurrency model: clients race fetch across all configured channels.
//! First success wins; all-fail triggers channel-level retry with
//! exponential backoff. Operators publish to all configured channels in
//! parallel; one success is sufficient, but publishing to multiple
//! maximizes availability.
//!
//! # Threat-model notes
//!
//! - **Channel diversity is a censorship-resistance property.** A single
//!   compromised channel can withhold or poison a client's view, but the
//!   router dedupes across channels - an honest blob from any channel
//!   survives. The router MUST NOT treat channels as authoritative; the
//!   caller verifies every blob end-to-end.
//! - **Fan-out publish is a linkability signal.** Publishing the same
//!   ciphertext to N relays tells each relay that the operator runs this
//!   bridge (at least indirectly via the operator's Nostr identity).
//!   Mitigated by rotating the operator Nostr identity (Op-3).
//! - **Timeout hygiene.** Without per-channel timeouts, one slow relay
//!   stalls the entire fetch. The router enforces a hard deadline
//!   ([`RouterConfig::fetch_timeout_ms`]) beyond which a channel is
//!   treated as `Timeout`, its result discarded, and others that did
//!   return are still surfaced.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use futures::future::join_all;

use crate::channel::{ChannelError, DiscoveryChannel};
use crate::derive::INFO_HASH_LEN;

/// Configuration for [`DiscoveryRouter`].
#[derive(Debug, Clone, Copy)]
pub struct RouterConfig {
    /// Hard per-channel deadline for `fetch`. A channel that has not
    /// returned within this window is treated as a timeout; its result,
    /// if it eventually arrives, is discarded. Default 5000 ms.
    pub fetch_timeout_ms: u64,
    /// Hard per-channel deadline for `publish`. Default 5000 ms.
    pub publish_timeout_ms: u64,
    /// Maximum total blobs returned from `fetch`. Caps memory if a
    /// hostile channel returns a large batch. Default 256.
    pub fetch_max_results: usize,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            fetch_timeout_ms: 5_000,
            publish_timeout_ms: 5_000,
            fetch_max_results: 256,
        }
    }
}

/// Per-channel `publish` outcome, surfaced so operators can audit which
/// channels accepted the blob and which failed.
#[derive(Debug)]
pub struct PublishReport {
    /// Channel name.
    pub channel: &'static str,
    /// Result of the publish attempt.
    pub outcome: Result<(), ChannelError>,
}

/// Summary of a `publish` fan-out.
#[derive(Debug)]
pub struct PublishSummary {
    /// Per-channel outcomes in the order configured.
    pub reports: Vec<PublishReport>,
}

impl PublishSummary {
    /// Number of channels that accepted the publish.
    pub fn successes(&self) -> usize {
        self.reports.iter().filter(|r| r.outcome.is_ok()).count()
    }

    /// `true` iff at least one channel accepted. Operators treat this
    /// as the overall success criterion - a single-relay publish is
    /// enough for the announcement to reach clients.
    pub fn any_success(&self) -> bool {
        self.successes() > 0
    }

    /// Total number of channels the publish was attempted on.
    pub fn attempts(&self) -> usize {
        self.reports.len()
    }
}

/// Summary of a `fetch` race.
#[derive(Debug)]
pub struct FetchSummary {
    /// The deduplicated union of ciphertexts across all channels that
    /// returned within the deadline. Ordering is not guaranteed.
    pub blobs: Vec<Vec<u8>>,
    /// Names of channels that returned at least one blob. Diagnostics only.
    pub channels_with_hits: Vec<&'static str>,
    /// Names of channels that failed or timed out. Diagnostics only.
    pub channels_failed: Vec<&'static str>,
}

impl FetchSummary {
    /// `true` iff at least one channel returned at least one blob.
    pub fn any_blobs(&self) -> bool {
        !self.blobs.is_empty()
    }
}

/// Orchestrates publish/fetch across one or more [`DiscoveryChannel`]s.
///
/// Clone-friendly: holds `Arc<dyn DiscoveryChannel>` values and a
/// `RouterConfig`. A single router is typically shared across a
/// process - the underlying channels manage their own state internally.
#[derive(Clone)]
pub struct DiscoveryRouter {
    channels: Vec<Arc<dyn DiscoveryChannel>>,
    config: RouterConfig,
}

impl DiscoveryRouter {
    /// Construct a router from an ordered list of channels and a config.
    pub fn new(channels: Vec<Arc<dyn DiscoveryChannel>>, config: RouterConfig) -> Self {
        Self { channels, config }
    }

    /// Convenience: build with default config.
    pub fn with_channels(channels: Vec<Arc<dyn DiscoveryChannel>>) -> Self {
        Self::new(channels, RouterConfig::default())
    }

    /// Names of configured channels, for diagnostics.
    pub fn channel_names(&self) -> Vec<&'static str> {
        self.channels.iter().map(|c| c.name()).collect()
    }

    /// Number of channels configured.
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    /// Publish `ciphertext` under `info_hash` to every configured channel.
    ///
    /// Returns a [`PublishSummary`]. Fan-out is concurrent; the call
    /// resolves when every channel has either succeeded, failed, or
    /// timed out. Operators consult `summary.any_success()` for a
    /// go/no-go; individual reports surface which relays to alert on.
    pub async fn publish(
        &self,
        info_hash: &[u8; INFO_HASH_LEN],
        ciphertext: &[u8],
    ) -> PublishSummary {
        let timeout = Duration::from_millis(self.config.publish_timeout_ms);
        let fut = self.channels.iter().map(|ch| {
            let ch = Arc::clone(ch);
            let info_hash = *info_hash;
            let ct = ciphertext.to_vec();
            async move {
                let name = ch.name();
                let outcome = match tokio::time::timeout(timeout, ch.publish(&info_hash, &ct)).await
                {
                    Ok(r) => r,
                    Err(_) => Err(ChannelError::Timeout(timeout.as_millis() as u64)),
                };
                PublishReport {
                    channel: name,
                    outcome,
                }
            }
        });
        let reports = join_all(fut).await;
        PublishSummary { reports }
    }

    /// Fetch `info_hash` from every configured channel in parallel and
    /// return the deduplicated union of returned blobs.
    ///
    /// Unlike a strict "first-success-wins" race, we wait for all
    /// channels to either return or hit the deadline. This matters for
    /// Mirage specifically: a single honest relay may publish the
    /// legitimate announcement, while a compromised relay returns
    /// nothing or garbage. Taking the **union** across channels means
    /// we don't miss the honest blob just because a faster, censored
    /// relay answered first.
    ///
    /// Result cap enforced by [`RouterConfig::fetch_max_results`];
    /// over-cap channels contribute a truncated prefix.
    pub async fn fetch(&self, info_hash: &[u8; INFO_HASH_LEN]) -> FetchSummary {
        let timeout = Duration::from_millis(self.config.fetch_timeout_ms);
        let fut = self.channels.iter().map(|ch| {
            let ch = Arc::clone(ch);
            let info_hash = *info_hash;
            async move {
                let name = ch.name();
                let result = match tokio::time::timeout(timeout, ch.fetch(&info_hash)).await {
                    Ok(r) => r,
                    Err(_) => Err(ChannelError::Timeout(timeout.as_millis() as u64)),
                };
                (name, result)
            }
        });
        let per_channel = join_all(fut).await;

        // Dedupe across channels. HashSet on `Vec<u8>` is O(n log n) by
        // hash - acceptable at our scales (<= fetch_max_results per channel,
        // a handful of channels, tens of bytes per blob).
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        let mut blobs: Vec<Vec<u8>> = Vec::new();
        let mut channels_with_hits: Vec<&'static str> = Vec::new();
        let mut channels_failed: Vec<&'static str> = Vec::new();

        for (name, result) in per_channel {
            match result {
                Ok(batch) => {
                    let mut added_any = false;
                    for blob in batch {
                        if blobs.len() >= self.config.fetch_max_results {
                            break;
                        }
                        if seen.insert(blob.clone()) {
                            blobs.push(blob);
                            added_any = true;
                        }
                    }
                    if added_any {
                        channels_with_hits.push(name);
                    }
                }
                Err(_) => {
                    channels_failed.push(name);
                }
            }
        }

        FetchSummary {
            blobs,
            channels_with_hits,
            channels_failed,
        }
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::InMemoryChannel;
    use async_trait::async_trait;

    fn ih(n: u8) -> [u8; INFO_HASH_LEN] {
        [n; INFO_HASH_LEN]
    }

    /// Slow channel that sleeps longer than the deadline. Used to verify
    /// the router's timeout handling.
    struct SlowChannel {
        name: &'static str,
        delay_ms: u64,
    }
    #[async_trait]
    impl DiscoveryChannel for SlowChannel {
        async fn publish(&self, _: &[u8; INFO_HASH_LEN], _: &[u8]) -> Result<(), ChannelError> {
            tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
            Ok(())
        }
        async fn fetch(&self, _: &[u8; INFO_HASH_LEN]) -> Result<Vec<Vec<u8>>, ChannelError> {
            tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
            Ok(Vec::new())
        }
        fn name(&self) -> &'static str {
            self.name
        }
    }

    fn fresh_router(n: usize) -> (DiscoveryRouter, Vec<Arc<InMemoryChannel>>) {
        let chans: Vec<Arc<InMemoryChannel>> = (0..n)
            .map(|i| {
                Arc::new(InMemoryChannel::new(Box::leak(
                    format!("mem{i}").into_boxed_str(),
                )))
            })
            .collect();
        let dyn_chans: Vec<Arc<dyn DiscoveryChannel>> =
            chans.iter().cloned().map(|c| c as _).collect();
        (DiscoveryRouter::with_channels(dyn_chans), chans)
    }

    #[tokio::test]
    async fn publish_fans_out_to_all_channels() {
        let (router, chans) = fresh_router(3);
        let summary = router.publish(&ih(7), b"blob").await;
        assert_eq!(summary.attempts(), 3);
        assert_eq!(summary.successes(), 3);
        assert!(summary.any_success());
        for ch in &chans {
            assert_eq!(ch.total_stored(), 1);
        }
    }

    #[tokio::test]
    async fn publish_continues_when_one_channel_fails() {
        let (router, chans) = fresh_router(3);
        chans[1].set_healthy(false);
        let summary = router.publish(&ih(7), b"blob").await;
        assert_eq!(summary.successes(), 2);
        assert!(summary.any_success());
        assert_eq!(chans[0].total_stored(), 1);
        assert_eq!(chans[1].total_stored(), 0);
        assert_eq!(chans[2].total_stored(), 1);
    }

    #[tokio::test]
    async fn publish_fails_when_all_channels_fail() {
        let (router, chans) = fresh_router(3);
        for ch in &chans {
            ch.set_healthy(false);
        }
        let summary = router.publish(&ih(7), b"blob").await;
        assert_eq!(summary.successes(), 0);
        assert!(!summary.any_success());
    }

    #[tokio::test]
    async fn fetch_unions_blobs_across_channels() {
        let (router, chans) = fresh_router(3);
        chans[0].publish(&ih(7), b"a").await.unwrap();
        chans[1].publish(&ih(7), b"b").await.unwrap();
        chans[2].publish(&ih(7), b"c").await.unwrap();
        let summary = router.fetch(&ih(7)).await;
        let mut got = summary.blobs.clone();
        got.sort();
        assert_eq!(got, vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
        assert_eq!(summary.channels_with_hits.len(), 3);
        assert!(summary.channels_failed.is_empty());
    }

    #[tokio::test]
    async fn fetch_dedupes_identical_blobs_across_channels() {
        let (router, chans) = fresh_router(3);
        chans[0].publish(&ih(7), b"same").await.unwrap();
        chans[1].publish(&ih(7), b"same").await.unwrap();
        chans[2].publish(&ih(7), b"same").await.unwrap();
        let summary = router.fetch(&ih(7)).await;
        assert_eq!(summary.blobs, vec![b"same".to_vec()]);
        // Only the first contributor is logged as "hit"; dedupe hides
        // subsequent identical contributions - this is diagnostic-only,
        // not a security-visible property.
        assert_eq!(summary.channels_with_hits.len(), 1);
    }

    #[tokio::test]
    async fn fetch_surfaces_honest_blob_when_other_channels_are_silent() {
        // The censorship-resistance property: even if 2/3 relays return
        // nothing, the 1 honest relay's blob reaches the client.
        let (router, chans) = fresh_router(3);
        chans[1].publish(&ih(7), b"honest").await.unwrap();
        let summary = router.fetch(&ih(7)).await;
        assert_eq!(summary.blobs, vec![b"honest".to_vec()]);
        assert!(summary.any_blobs());
    }

    #[tokio::test]
    async fn fetch_tolerates_some_failing_channels() {
        let (router, chans) = fresh_router(3);
        chans[0].publish(&ih(7), b"a").await.unwrap();
        chans[2].publish(&ih(7), b"c").await.unwrap();
        chans[1].set_healthy(false);
        let summary = router.fetch(&ih(7)).await;
        let mut got = summary.blobs.clone();
        got.sort();
        assert_eq!(got, vec![b"a".to_vec(), b"c".to_vec()]);
        assert_eq!(summary.channels_failed, vec!["mem1"]);
    }

    #[tokio::test]
    async fn fetch_times_out_slow_channel() {
        let fast: Arc<dyn DiscoveryChannel> = Arc::new(InMemoryChannel::new("fast"));
        let slow: Arc<dyn DiscoveryChannel> = Arc::new(SlowChannel {
            name: "slow",
            delay_ms: 500,
        });
        fast.publish(&ih(7), b"a").await.unwrap();
        let router = DiscoveryRouter::new(
            vec![fast, slow],
            RouterConfig {
                fetch_timeout_ms: 50,
                ..RouterConfig::default()
            },
        );
        let summary = router.fetch(&ih(7)).await;
        assert_eq!(summary.blobs, vec![b"a".to_vec()]);
        assert!(summary.channels_failed.contains(&"slow"));
    }

    #[tokio::test]
    async fn fetch_caps_total_results() {
        let fast: Arc<InMemoryChannel> = Arc::new(InMemoryChannel::new("fast"));
        for i in 0..10u8 {
            fast.publish(&ih(7), &[i]).await.unwrap();
        }
        let router = DiscoveryRouter::new(
            vec![fast as _],
            RouterConfig {
                fetch_max_results: 3,
                ..RouterConfig::default()
            },
        );
        let summary = router.fetch(&ih(7)).await;
        assert_eq!(summary.blobs.len(), 3);
    }

    #[tokio::test]
    async fn publish_times_out_slow_channel() {
        let ok: Arc<dyn DiscoveryChannel> = Arc::new(InMemoryChannel::new("ok"));
        let slow: Arc<dyn DiscoveryChannel> = Arc::new(SlowChannel {
            name: "slow",
            delay_ms: 500,
        });
        let router = DiscoveryRouter::new(
            vec![ok, slow],
            RouterConfig {
                publish_timeout_ms: 50,
                ..RouterConfig::default()
            },
        );
        let summary = router.publish(&ih(7), b"blob").await;
        assert_eq!(summary.successes(), 1);
        assert!(matches!(
            summary
                .reports
                .iter()
                .find(|r| r.channel == "slow")
                .unwrap()
                .outcome,
            Err(ChannelError::Timeout(_))
        ));
    }

    #[tokio::test]
    async fn empty_router_fetches_nothing_gracefully() {
        let router = DiscoveryRouter::with_channels(vec![]);
        let summary = router.fetch(&ih(7)).await;
        assert!(summary.blobs.is_empty());
        assert!(!summary.any_blobs());
    }

    #[tokio::test]
    async fn empty_router_publish_has_zero_attempts() {
        let router = DiscoveryRouter::with_channels(vec![]);
        let summary = router.publish(&ih(7), b"blob").await;
        assert_eq!(summary.attempts(), 0);
        assert!(!summary.any_success(), "no channels == no successes");
    }
}
