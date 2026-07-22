//! [`DnsTxtChannel`] - DNS TXT-backed `DiscoveryChannel` adapter.

use async_trait::async_trait;

use mirage_discovery::channel::{ChannelError, DiscoveryChannel};
use mirage_discovery::derive::INFO_HASH_LEN;

use crate::chunk::{chunks_to_blob, MAX_REASSEMBLED_BYTES};
use crate::resolver::{DnsTxtResolver, ResolverError};

/// Hard cap on one announcement payload passed through this
/// channel. Matches [`MAX_REASSEMBLED_BYTES`] - the TXT chunk
/// codec's upper bound. Mirage's own announcements cap at ~800 B
/// sealed so this has headroom.
pub const MAX_ANNOUNCEMENT_SIZE: usize = MAX_REASSEMBLED_BYTES;

/// RT-dns-8: cap on the number of TXT `RRsets` we'll process per
/// fetch. A malicious resolver could otherwise return thousands
/// of bogus `RRsets` and force the channel into ~MB-scale working
/// memory per call. Mirage publishes ONE `RRset` per name in
/// v0.1; > 16 is operationally suspicious.
pub const MAX_RRSETS_PER_FETCH: usize = 16;

/// Errors from [`DnsTxtChannel`] operations.
#[derive(Debug, thiserror::Error)]
pub enum DnsTxtChannelError {
    /// Upstream resolver reported an error.
    #[error("resolver: {0}")]
    Resolver(#[from] ResolverError),
    /// A resolved TXT `RRset` failed to reassemble into a blob.
    /// One bad `RRset` at a name doesn't fail the whole fetch; this
    /// error is only produced if EVERY `RRset` failed.
    #[error("no valid mirage TXT records at name")]
    NoUsableRecords,
}

impl From<DnsTxtChannelError> for ChannelError {
    fn from(e: DnsTxtChannelError) -> Self {
        match e {
            DnsTxtChannelError::Resolver(ResolverError::Transport(s)) => ChannelError::Transport(s),
            DnsTxtChannelError::Resolver(
                ResolverError::NoRecords(_) | ResolverError::NxDomain(_),
            ) => ChannelError::Transport("no records".to_string()),
            DnsTxtChannelError::Resolver(ResolverError::Timeout) => ChannelError::Timeout(0),
            DnsTxtChannelError::NoUsableRecords => ChannelError::Invalid("no usable TXT records"),
        }
    }
}

/// Convert Mirage's 20-byte `info_hash` to a lowercase hex label
/// suitable as a DNS subdomain component.
pub fn info_hash_to_label(info_hash: &[u8; INFO_HASH_LEN]) -> String {
    let mut s = String::with_capacity(INFO_HASH_LEN * 2);
    for b in info_hash {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A [`DiscoveryChannel`] that reads Mirage announcements from
/// DNS TXT records.
///
/// # Query name construction
///
/// Each fetch resolves:
///
/// ```text
///   _mirage.<hex(info_hash)>.<apex>
/// ```
///
/// where `apex` is the operator-configured zone under their
/// control. Clients hold the apex in their deployment config; the
/// `info_hash` hex is computed locally per epoch.
///
/// # Publish
///
/// **Not supported.** The trait's `publish` implementation returns
/// `ChannelError::Invalid("publish via DNS requires zone-authority API")`.
/// A real deployment pushes TXT records via whatever their DNS
/// authority's API exposes (Route 53, Cloudflare, nsupdate). The
/// operator's glue script reads the sealed ciphertext produced by
/// [`mirage_discovery::OperatorPublisher`] and uploads it out of
/// band.
pub struct DnsTxtChannel<R: DnsTxtResolver> {
    resolver: R,
    /// Apex zone. Trailing dot is added automatically during
    /// lookup so operators can pass `example.com` or
    /// `example.com.` interchangeably.
    apex: String,
    name: &'static str,
}

impl<R: DnsTxtResolver> DnsTxtChannel<R> {
    /// Construct a channel over `resolver` resolving under `apex`.
    ///
    /// `name` is a static label used by the router's diagnostics
    /// and metrics. Typical value: `"dns-txt"`.
    ///
    /// RT-dns-10: leading dots are stripped + adjacent dots are
    /// rejected. `.example.com` would otherwise produce malformed
    /// `_mirage.HEX..example.com.` queries.
    pub fn new(resolver: R, apex: impl Into<String>, name: &'static str) -> Self {
        let raw = apex.into();
        let trimmed = raw.trim().trim_start_matches('.');
        if trimmed.is_empty() || trimmed.contains("..") {
            // We tolerate this rather than panic - channels live in
            // an `Arc<dyn>` and operator misconfiguration shouldn't
            // crash the whole router. The empty/malformed apex will
            // produce queries the resolver rejects, surfacing a
            // loud error at fetch time rather than a silent foot-
            // gun. Log so operators see it.
            tracing::warn!(apex = %raw, "DnsTxtChannel: apex looks malformed");
        }
        let mut apex = trimmed.to_string();
        if !apex.ends_with('.') {
            apex.push('.');
        }
        Self {
            resolver,
            apex,
            name,
        }
    }

    fn query_name(&self, info_hash: &[u8; INFO_HASH_LEN]) -> String {
        // The leading label is `info_hash_to_label(info_hash)`, itself derived
        // from a per-epoch keyed BLAKE3 secret (see discovery::derive) precisely
        // so the location is un-enumerable to keyless observers. A constant
        // `_mirage.` marker in front of it would immediately re-identify every
        // such name to passive-DNS enumeration - so it is deliberately omitted.
        // The derived label is random-looking and will not collide with any
        // operator-run records at the apex, so no coexistence marker is needed.
        format!("{}.{}", info_hash_to_label(info_hash), self.apex)
    }
}

#[async_trait]
impl<R: DnsTxtResolver + 'static> DiscoveryChannel for DnsTxtChannel<R> {
    async fn publish(
        &self,
        _info_hash: &[u8; INFO_HASH_LEN],
        _ciphertext: &[u8],
    ) -> Result<(), ChannelError> {
        Err(ChannelError::Invalid(
            "publish via DNS requires zone-authority API - push TXT records out of band",
        ))
    }

    async fn fetch(&self, info_hash: &[u8; INFO_HASH_LEN]) -> Result<Vec<Vec<u8>>, ChannelError> {
        let name = self.query_name(info_hash);
        let rrsets = match self.resolver.resolve(&name).await {
            Ok(v) => v,
            Err(ResolverError::NoRecords(_) | ResolverError::NxDomain(_)) => {
                // "No Mirage record at this name" is a clean empty
                // result, NOT a transport error. Matches the
                // spec's note on `DiscoveryChannel::fetch`.
                return Ok(Vec::new());
            }
            Err(e) => return Err(DnsTxtChannelError::Resolver(e).into()),
        };
        // RT-dns-8: cap the RRset processing budget. Truncate
        // (rather than error) so a flood of fake records doesn't
        // dark-fleet a fetch that would have found a legitimate
        // RRset within the first MAX_RRSETS_PER_FETCH entries.
        let take_count = rrsets.len().min(MAX_RRSETS_PER_FETCH);
        if rrsets.len() > MAX_RRSETS_PER_FETCH {
            tracing::warn!(
                got = rrsets.len(),
                cap = MAX_RRSETS_PER_FETCH,
                "DNS resolver returned more RRsets than cap; truncating"
            );
        }
        let mut out = Vec::new();
        for rrset in rrsets.into_iter().take(take_count) {
            // Each RRset is one logical Mirage record. If it fails
            // to reassemble we DROP it (a poisoned RRset from a
            // misbehaving authoritative / compromised resolver
            // doesn't tank the legitimate ones).
            match chunks_to_blob(&rrset) {
                Ok(blob) => out.push(blob),
                Err(_) => continue,
            }
        }
        Ok(out)
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn is_healthy(&self) -> bool {
        self.resolver.is_healthy()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::blob_to_chunks;
    use crate::resolver::InMemoryDnsTxt;

    fn ih(n: u8) -> [u8; INFO_HASH_LEN] {
        [n; INFO_HASH_LEN]
    }

    #[tokio::test]
    async fn fetch_reassembles_single_record() {
        let dns = InMemoryDnsTxt::new();
        let query = format!("{}.example.com.", info_hash_to_label(&ih(1)));
        dns.insert(&query, blob_to_chunks(b"sealed-bytes").unwrap());
        let chan = DnsTxtChannel::new(dns, "example.com.", "dns");
        let got = chan.fetch(&ih(1)).await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], b"sealed-bytes");
    }

    #[tokio::test]
    async fn fetch_missing_name_returns_empty_not_error() {
        let dns = InMemoryDnsTxt::new();
        let chan = DnsTxtChannel::new(dns, "example.com", "dns");
        let got = chan.fetch(&ih(9)).await.unwrap();
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn publish_is_refused() {
        let dns = InMemoryDnsTxt::new();
        let chan = DnsTxtChannel::new(dns, "example.com", "dns");
        let err = chan.publish(&ih(0), b"x").await.unwrap_err();
        assert!(matches!(err, ChannelError::Invalid(_)));
    }

    #[tokio::test]
    async fn poisoned_rrset_does_not_tank_legitimate() {
        let dns = InMemoryDnsTxt::new();
        let query = format!("{}.example.com.", info_hash_to_label(&ih(7)));
        // Legitimate record (1 chunk):
        let good = blob_to_chunks(b"good-sealed-blob").unwrap();
        dns.insert(&query, good);
        // Poisoned record (impossible index):
        dns.insert(&query, vec!["0/0:AAA".to_string()]);
        let chan = DnsTxtChannel::new(dns, "example.com", "dns");
        let got = chan.fetch(&ih(7)).await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], b"good-sealed-blob");
    }

    #[tokio::test]
    async fn resolver_timeout_bubbles_as_channel_error() {
        let dns = InMemoryDnsTxt::new();
        let query = format!("{}.example.com.", info_hash_to_label(&ih(3)));
        dns.insert(&query, vec!["1/1:QUFB".to_string()]);
        dns.fail_next_resolve_with(ResolverError::Timeout);
        let chan = DnsTxtChannel::new(dns, "example.com", "dns");
        let err = chan.fetch(&ih(3)).await.unwrap_err();
        assert!(matches!(err, ChannelError::Timeout(_)));
    }

    #[tokio::test]
    async fn apex_with_trailing_dot_and_without_work_the_same() {
        let dns1 = InMemoryDnsTxt::new();
        let dns2 = InMemoryDnsTxt::new();
        let a = DnsTxtChannel::new(dns1, "example.com", "a");
        let b = DnsTxtChannel::new(dns2, "example.com.", "b");
        assert_eq!(a.query_name(&ih(1)), b.query_name(&ih(1)));
    }

    #[tokio::test]
    async fn fetch_caps_rrset_processing_at_max() {
        // RT-dns-8 regression: a flood of fake RRsets must not
        // cause unbounded work. Insert MAX+10 RRsets at one name;
        // expect AT MOST MAX legitimate decodes (here all are
        // legit-looking - the cap is the property under test).
        let dns = InMemoryDnsTxt::new();
        let query = format!("{}.example.com.", info_hash_to_label(&ih(2)));
        for i in 0..(MAX_RRSETS_PER_FETCH + 10) {
            let payload = format!("payload-{i}");
            dns.insert(&query, blob_to_chunks(payload.as_bytes()).unwrap());
        }
        let chan = DnsTxtChannel::new(dns, "example.com", "dns");
        let got = chan.fetch(&ih(2)).await.unwrap();
        assert!(
            got.len() <= MAX_RRSETS_PER_FETCH,
            "unbounded processing: got {} RRsets",
            got.len()
        );
    }

    #[tokio::test]
    async fn apex_with_leading_dot_is_normalized() {
        // RT-dns-10 regression: leading dots stripped so the
        // produced query name doesn't have `..` in it.
        let dns = InMemoryDnsTxt::new();
        let chan = DnsTxtChannel::new(dns, ".example.com", "a");
        let q = chan.query_name(&ih(1));
        assert!(!q.contains(".."), "query name should not have '..' : {q}");
        assert!(q.ends_with(".example.com."));
    }

    #[tokio::test]
    async fn router_fan_out_treats_dns_like_any_other_channel() {
        use mirage_discovery::channel::InMemoryChannel;
        use mirage_discovery::router::{DiscoveryRouter, RouterConfig};
        use std::sync::Arc;

        let dns = InMemoryDnsTxt::new();
        let query = format!("{}.example.com.", info_hash_to_label(&ih(5)));
        dns.insert(&query, blob_to_chunks(b"dns-record").unwrap());
        let dns_chan: Arc<dyn DiscoveryChannel> =
            Arc::new(DnsTxtChannel::new(dns, "example.com", "dns"));

        let mem = InMemoryChannel::new("mem");
        mem.publish(&ih(5), b"mem-record").await.unwrap();
        let mem_chan: Arc<dyn DiscoveryChannel> = Arc::new(mem);

        let router = DiscoveryRouter::new(vec![dns_chan, mem_chan], RouterConfig::default());
        let fetched = router.fetch(&ih(5)).await;
        assert!(!fetched.blobs.is_empty());
        assert!(fetched.blobs.iter().any(|b| b.as_slice() == b"dns-record"));
        assert!(fetched.blobs.iter().any(|b| b.as_slice() == b"mem-record"));
    }
}
