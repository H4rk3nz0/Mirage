//! Cohort liveness heartbeats - the
//! [`mirage_discovery::GossipEvent::CohortMembership`] wiring.
//!
//! # Why
//!
//! `ProbeScanDetected` / `TokenBurned` / `EntryDistressed` are
//! *event-driven*: a peer's silence might be "nothing to
//! report" or "I'm dead." Without an explicit liveness signal,
//! the cohort can't distinguish.
//!
//! The fix is a periodic heartbeat: each entry publishes its
//! current view of which cohort peers it considers "alive"
//! (i.e., seen recently). Peers cross-check: if entry A reports
//! seeing B but B's local view says A is gone, the cohort has
//! detected a partition.
//!
//! # Primitives
//!
//! - [`LivePeerTracker`] - `peer_pk -> last_seen` map. Updated
//!   on every gossip event from any authorized peer.
//!   `living_peers(within: Duration)` returns the set seen in
//!   the last `within`.
//! - [`spawn_gossip_to_live_tracker`] - subscriber that
//!   timestamps every inbound event by publisher.
//! - [`CohortHeartbeat`] - ticker that publishes the local
//!   `CohortMembership` view at `heartbeat_interval`.
//!
//! # Threat model
//!
//! - **Liveness lying**: a malicious peer can publish a false
//!   membership view. The defense is *agreement-based*: a
//!   single peer's view doesn't dictate anything; callers
//!   majority-vote across the cohort. Out of scope for this
//!   primitive; callers consume the per-peer views and decide.
//! - **Memory**: `LivePeerTracker` is keyed by `publisher_pk`,
//!   which is bounded by the cohort's authorized set. No
//!   attacker-controlled growth.
//! - **Replay**: 5-min freshness window in
//!   [`MemoryGossip`]/[`TcpCohortGossip`] guards against
//!   captured-heartbeat replay.

use mirage_crypto::ed25519_dalek::SigningKey;
use mirage_discovery::cohort_gossip::{CohortGossip, GossipEvent, SignedGossipEvent};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

/// Tracks the last time each authorized publisher emitted any
/// gossip event. Used to derive a "currently alive" view.
#[derive(Debug, Default)]
pub struct LivePeerTracker {
    inner: Mutex<HashMap<[u8; 32], Instant>>,
}

impl LivePeerTracker {
    /// Construct empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that we just heard from `peer_pk` (any event).
    pub async fn touch(&self, peer_pk: [u8; 32]) {
        self.inner.lock().await.insert(peer_pk, Instant::now());
    }

    /// Return the set of peers seen within `within`.
    pub async fn living_peers(&self, within: Duration) -> Vec<[u8; 32]> {
        let g = self.inner.lock().await;
        let now = Instant::now();
        g.iter()
            .filter(|(_, t)| now.saturating_duration_since(**t) <= within)
            .map(|(k, _)| *k)
            .collect()
    }

    /// Total entries (alive OR stale).
    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    /// True iff no peers have ever been seen.
    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.is_empty()
    }

    /// Sweep entries older than `keep_for`.
    pub async fn reap(&self, keep_for: Duration) -> usize {
        let now = Instant::now();
        let mut g = self.inner.lock().await;
        let before = g.len();
        g.retain(|_, t| now.saturating_duration_since(*t) <= keep_for);
        before - g.len()
    }
}

/// Spawn a subscriber that timestamps every inbound gossip
/// event by its publisher.
pub fn spawn_gossip_to_live_tracker(
    gossip: Arc<dyn CohortGossip>,
    tracker: Arc<LivePeerTracker>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut rx = gossip.subscribe().await;
        loop {
            match rx.recv().await {
                Ok(signed) => {
                    tracker.touch(signed.publisher_ed_pk).await;
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(skipped = n, "live tracker subscriber lagged");
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            }
        }
    })
}

/// Configuration for [`CohortHeartbeat`].
#[derive(Debug, Clone)]
pub struct HeartbeatConfig {
    /// How often we publish our local view.
    pub heartbeat_interval: Duration,
    /// "Alive" cutoff: peers we last saw within this window
    /// are listed in our `alive` field.
    pub alive_window: Duration,
    /// Reap interval for the `LivePeerTracker`. Older entries
    /// are dropped from memory (different from "alive" - this
    /// is housekeeping).
    pub reap_after: Duration,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval: Duration::from_secs(30),
            alive_window: Duration::from_secs(90),
            reap_after: Duration::from_secs(60 * 60),
        }
    }
}

/// Periodic publisher of [`GossipEvent::CohortMembership`].
/// Owns no state of its own - borrows a `LivePeerTracker` for
/// the "who's alive" answer and uses the supplied `SigningKey`
/// to sign outbound heartbeats.
pub struct CohortHeartbeat {
    _ticker: JoinHandle<()>,
}

impl std::fmt::Debug for CohortHeartbeat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CohortHeartbeat").finish_non_exhaustive()
    }
}

impl CohortHeartbeat {
    /// Construct + start the heartbeat ticker.
    pub fn new(
        gossip: Arc<dyn CohortGossip>,
        signing_key: SigningKey,
        tracker: Arc<LivePeerTracker>,
        config: HeartbeatConfig,
    ) -> Self {
        let publisher_pk = signing_key.verifying_key().to_bytes();
        let ticker = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(config.heartbeat_interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // Skip the immediate tick (so callers can wire up
            // subscribers before the first publish).
            ticker.tick().await;
            loop {
                ticker.tick().await;
                // Reap stale entries.
                tracker.reap(config.reap_after).await;
                // Build the alive list.
                let alive = tracker.living_peers(config.alive_window).await;
                if alive.len() > 64 {
                    tracing::warn!(
                        alive_count = alive.len(),
                        "CohortHeartbeat: alive list >64; truncating"
                    );
                }
                let alive: Vec<[u8; 32]> = alive.into_iter().take(64).collect();
                let event = GossipEvent::CohortMembership {
                    publisher_ed_pk: publisher_pk,
                    alive,
                    observed_at: unix_now_secs(),
                };
                let signed = SignedGossipEvent::sign(event, &signing_key);
                gossip.publish(signed).await;
                tracing::debug!("CohortHeartbeat published");
            }
        });
        Self { _ticker: ticker }
    }
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_discovery::cohort_gossip::MemoryGossip;

    fn fresh_sk() -> SigningKey {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        SigningKey::from_bytes(&seed)
    }

    #[tokio::test]
    async fn tracker_records_and_filters_by_window() {
        let t = LivePeerTracker::new();
        t.touch([0x01; 32]).await;
        tokio::time::sleep(Duration::from_millis(60)).await;
        t.touch([0x02; 32]).await;

        let recent = t.living_peers(Duration::from_millis(40)).await;
        assert_eq!(recent.len(), 1);
        assert!(recent.contains(&[0x02; 32]));

        let all = t.living_peers(Duration::from_secs(60)).await;
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn tracker_reap_drops_old_entries() {
        let t = LivePeerTracker::new();
        t.touch([0xAA; 32]).await;
        tokio::time::sleep(Duration::from_millis(60)).await;
        let reaped = t.reap(Duration::from_millis(30)).await;
        assert_eq!(reaped, 1);
        assert_eq!(t.len().await, 0);
    }

    #[tokio::test]
    async fn subscriber_touches_tracker_on_event() {
        let gossip = Arc::new(MemoryGossip::new());
        let sk = fresh_sk();
        let pk = sk.verifying_key().to_bytes();
        gossip.authorize(pk).await;
        let tracker = Arc::new(LivePeerTracker::new());
        let _t =
            spawn_gossip_to_live_tracker(gossip.clone() as Arc<dyn CohortGossip>, tracker.clone());
        tokio::time::sleep(Duration::from_millis(10)).await;
        let event = GossipEvent::TokenBurned {
            token_id: [0xDD; 32],
            burned_at: unix_now_secs(),
        };
        gossip.publish(SignedGossipEvent::sign(event, &sk)).await;
        for _ in 0..50 {
            if !tracker.is_empty().await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(tracker
            .living_peers(Duration::from_secs(60))
            .await
            .contains(&pk));
    }

    #[tokio::test]
    async fn heartbeat_publishes_periodically() {
        let gossip = Arc::new(MemoryGossip::new());
        let sk = fresh_sk();
        let pk = sk.verifying_key().to_bytes();
        gossip.authorize(pk).await;
        let mut rx = gossip.subscribe().await;
        let tracker = Arc::new(LivePeerTracker::new());
        // Pretend we've seen one peer recently so alive is
        // non-empty.
        tracker.touch([0x99; 32]).await;
        let _h = CohortHeartbeat::new(
            gossip.clone() as Arc<dyn CohortGossip>,
            sk,
            tracker,
            HeartbeatConfig {
                heartbeat_interval: Duration::from_millis(50),
                alive_window: Duration::from_secs(60),
                reap_after: Duration::from_secs(60 * 60),
            },
        );
        let received = tokio::time::timeout(Duration::from_millis(200), rx.recv())
            .await
            .expect("heartbeat should publish")
            .unwrap();
        match received.event {
            GossipEvent::CohortMembership { alive, .. } => {
                assert!(alive.contains(&[0x99; 32]));
            }
            other => panic!("unexpected {:?}", other),
        }
    }

    #[tokio::test]
    async fn heartbeat_truncates_to_64_peers() {
        // The wire codec caps `n <= 64`. The heartbeat must
        // truncate before publishing, even if the tracker has
        // more peers.
        let tracker = Arc::new(LivePeerTracker::new());
        for i in 0u16..80 {
            let mut pk = [0u8; 32];
            pk[0..2].copy_from_slice(&i.to_be_bytes());
            tracker.touch(pk).await;
        }
        let gossip = Arc::new(MemoryGossip::new());
        let sk = fresh_sk();
        let pk = sk.verifying_key().to_bytes();
        gossip.authorize(pk).await;
        let mut rx = gossip.subscribe().await;
        let _h = CohortHeartbeat::new(
            gossip.clone() as Arc<dyn CohortGossip>,
            sk,
            tracker,
            HeartbeatConfig {
                heartbeat_interval: Duration::from_millis(30),
                alive_window: Duration::from_secs(60),
                reap_after: Duration::from_secs(60 * 60),
            },
        );
        let received = tokio::time::timeout(Duration::from_millis(200), rx.recv())
            .await
            .expect("heartbeat")
            .unwrap();
        match received.event {
            GossipEvent::CohortMembership { alive, .. } => {
                assert_eq!(alive.len(), 64, "heartbeat must truncate to 64");
            }
            other => panic!("unexpected {:?}", other),
        }
    }
}
