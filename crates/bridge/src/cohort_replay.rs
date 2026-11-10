//! Cohort-wide TokenBurned propagation.
//!
//! # Why
//!
//! Mirage tokens are single-use. The local
//! [`mirage_discovery::replay::SyncReplaySet`] catches an
//! in-process replay, and the persistent
//! [`mirage_discovery::FileRevealStore`] catches a
//! cross-restart replay. But until a peer bridge's replay-set
//! sees the burned `token_id`, a censor who captured a
//! one-time token can attempt the same token at every cohort
//! member sequentially - racing the operator's reveal-store
//! sync.
//!
//! Closing that race is what
//! [`mirage_discovery::GossipEvent::TokenBurned`] is for. This
//! module:
//!
//! - [`spawn_gossip_to_replay_set`] - subscriber that absorbs
//!   inbound `TokenBurned` into the local replay set.
//! - [`CohortReplayCoordinator`] - the bridge daemon's
//!   one-call API: `record_burn(token_id, expires_at)` adds to
//!   the local set + publishes signed gossip; `check(token_id)`
//!   returns whether the cohort has already burned it.
//!
//! # Threat model considerations
//!
//! - **Replay window** - the gossip event carries `burned_at`;
//!   the existing freshness check (5 min default) on
//!   `CohortGossip` ensures a captured `TokenBurned` cannot be
//!   re-injected to forever-block a specific token's reuse by
//!   the legitimate holder. (Token TTL is bounded anyway, but
//!   this guards against operator-induced unavailability.)
//! - **Memory bound** - the underlying `SyncReplaySet` is
//!   capped via its `max_entries` parameter; gossip ingest
//!   inherits the cap.
//! - **TTL clamp** - inbound `TokenBurned` carries `burned_at`;
//!   we compute the replay-set TTL as `burned_at + max_token_ttl`
//!   to bound the entry's lifetime even if a peer publishes
//!   garbage.

use mirage_crypto::ed25519_dalek::SigningKey;
use mirage_discovery::cohort_gossip::{CohortGossip, GossipEvent, SignedGossipEvent};
use mirage_discovery::replay::SyncReplaySet;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;

/// Hard cap on the lifetime of a gossip-derived replay entry.
/// 24h is well past any legitimate token TTL but bounded so a
/// malicious authorized peer cannot pin a `token_id` in the
/// replay set forever.
pub const MAX_GOSSIP_REPLAY_TTL_SECS: u64 = 24 * 3600;

/// Per-peer token-burn ingest rate-limit window. A malicious
/// authorized peer can otherwise publish unlimited fake
/// `TokenBurned`s to exhaust every peer's `SyncReplaySet`.
/// Closes RT-CR-3.
pub const PER_PEER_BURN_RATE_WINDOW: Duration = Duration::from_secs(60);

/// Max `TokenBurned`s accepted per authorized peer within
/// [`PER_PEER_BURN_RATE_WINDOW`]. Excess events are dropped +
/// counted. 100/min is generously above any honest cohort's
/// actual burn rate.
pub const PER_PEER_BURN_RATE_LIMIT: u32 = 100;

/// Subscriber that listens on `gossip` and inserts every
/// inbound [`GossipEvent::TokenBurned`] into `replay_set`.
/// Other event variants are ignored. Closes the race where a
/// censor races a captured token across cohort members faster
/// than the persistent `RevealStore` propagates.
///
/// `ingest_ttl_secs` is the lifetime (added to the burn
/// timestamp) that the entry is held in the local replay set.
/// Clamped to [`MAX_GOSSIP_REPLAY_TTL_SECS`].
pub fn spawn_gossip_to_replay_set(
    gossip: Arc<dyn CohortGossip>,
    replay_set: Arc<SyncReplaySet>,
    ingest_ttl_secs: u64,
) -> JoinHandle<()> {
    let ttl = ingest_ttl_secs.min(MAX_GOSSIP_REPLAY_TTL_SECS);
    // Per-publisher sliding-window burn counter. Closes
    // RT-CR-3. Capped at 256 distinct publishers - beyond
    // typical cohort size, and a hard memory bound.
    let rate_limit: Arc<AsyncMutex<HashMap<[u8; 32], Vec<Instant>>>> =
        Arc::new(AsyncMutex::new(HashMap::new()));
    tokio::spawn(async move {
        let mut rx = gossip.subscribe().await;
        loop {
            match rx.recv().await {
                Ok(signed) => {
                    // RT-CR-4: defense-in-depth signature
                    // verify. The trait contract promises
                    // pre-verified events but we don't trust
                    // every future transport.
                    if signed.verify(&signed.publisher_ed_pk).is_err() {
                        tracing::debug!(
                            "TokenBurned subscriber: bad sig (transport bug?); dropping"
                        );
                        continue;
                    }
                    if let GossipEvent::TokenBurned {
                        token_id,
                        burned_at,
                    } = signed.event
                    {
                        // RT-CR-3: per-publisher rate limit.
                        let admit = {
                            let mut g = rate_limit.lock().await;
                            // Cap publishers tracked.
                            if !g.contains_key(&signed.publisher_ed_pk) && g.len() >= 256 {
                                if let Some(victim) = g
                                    .iter()
                                    .min_by_key(|(_, v)| {
                                        v.last().copied().unwrap_or_else(Instant::now)
                                    })
                                    .map(|(k, _)| *k)
                                {
                                    g.remove(&victim);
                                }
                            }
                            let entry = g.entry(signed.publisher_ed_pk).or_default();
                            let now = Instant::now();
                            entry.retain(|t| {
                                now.saturating_duration_since(*t) <= PER_PEER_BURN_RATE_WINDOW
                            });
                            if entry.len() as u32 >= PER_PEER_BURN_RATE_LIMIT {
                                false
                            } else {
                                entry.push(now);
                                true
                            }
                        };
                        if !admit {
                            tracing::warn!(
                                publisher = ?hex::encode(signed.publisher_ed_pk),
                                "TokenBurned: per-peer rate limit exceeded; dropping"
                            );
                            continue;
                        }
                        let expires_at = burned_at.saturating_add(ttl);
                        let now = unix_now_secs();
                        let _ = replay_set.check_and_insert(&token_id, expires_at, now);
                        tracing::debug!(
                            token_id = ?hex::encode(token_id),
                            burned_at,
                            expires_at,
                            "cohort gossip: TokenBurned absorbed"
                        );
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(skipped = n, "gossip replay-set subscriber lagged");
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            }
        }
    })
}

/// One-call coordinator the bridge daemon uses on every
/// successful msg_3 token consumption. Wires
/// [`SyncReplaySet`] + a [`CohortGossip`] publisher /
/// subscriber pair so a token burned at THIS bridge propagates
/// to peers, and a token burned at a peer is refused here.
pub struct CohortReplayCoordinator {
    replay_set: Arc<SyncReplaySet>,
    gossip: Arc<dyn CohortGossip>,
    signing_key: SigningKey,
    /// Lifetime (seconds added to burn timestamp) for entries
    /// added via gossip ingest.
    ingest_ttl_secs: u64,
    _subscriber: JoinHandle<()>,
}

impl std::fmt::Debug for CohortReplayCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CohortReplayCoordinator")
            .field("replay_set_len", &self.replay_set.len())
            .field("ingest_ttl_secs", &self.ingest_ttl_secs)
            .finish_non_exhaustive()
    }
}

impl CohortReplayCoordinator {
    /// Build. Spawns the gossip -> replay-set subscriber.
    pub fn new(
        gossip: Arc<dyn CohortGossip>,
        signing_key: SigningKey,
        replay_set: Arc<SyncReplaySet>,
        ingest_ttl_secs: u64,
    ) -> Self {
        let ttl = ingest_ttl_secs.min(MAX_GOSSIP_REPLAY_TTL_SECS);
        let subscriber = spawn_gossip_to_replay_set(gossip.clone(), replay_set.clone(), ttl);
        Self {
            replay_set,
            gossip,
            signing_key,
            ingest_ttl_secs: ttl,
            _subscriber: subscriber,
        }
    }

    /// Call after a successful msg_3 (token accepted at this
    /// bridge). Adds the token to the local replay set AND
    /// publishes a signed `TokenBurned` event so peers add it
    /// to theirs.
    ///
    /// `expires_at` is the token's own expiry (Unix seconds).
    /// It is clamped to `now + MAX_GOSSIP_REPLAY_TTL_SECS`
    /// before insertion (RT-CR-2) so a caller bug or upstream
    /// malicious-TTL can't pin the entry forever.
    ///
    /// Returns `true` if the local insert succeeded (and the
    /// gossip publish was issued); `false` if the replay set
    /// refused the insert (replay, set full, or poisoned). In
    /// the `false` case we do NOT publish - otherwise peers
    /// would diverge from us. The caller MUST refuse the
    /// handshake when this returns false (RT-CR-5).
    pub async fn record_local_burn(&self, token_id: [u8; 32], expires_at: u64) -> bool {
        let now = unix_now_secs();
        // RT-CR-2: clamp expires_at.
        let clamped = expires_at.min(now.saturating_add(MAX_GOSSIP_REPLAY_TTL_SECS));
        let inserted = self.replay_set.check_and_insert(&token_id, clamped, now);
        if !inserted {
            // RT-CR-5: local insert failed (capacity exhaustion,
            // poisoned mutex, or already-present). Do NOT
            // gossip - peers would think we burned it while we
            // actually didn't.
            tracing::error!(
                token_id = ?hex::encode(token_id),
                "CohortReplayCoordinator: local insert failed; suppressing gossip"
            );
            return false;
        }
        let event = GossipEvent::TokenBurned {
            token_id,
            burned_at: now,
        };
        let signed = SignedGossipEvent::sign(event, &self.signing_key);
        self.gossip.publish(signed).await;
        tracing::debug!(
            token_id = ?hex::encode(token_id),
            "CohortReplayCoordinator: published TokenBurned"
        );
        true
    }

    /// Publish a `TokenBurned` gossip event for a token that the
    /// caller has **already** inserted into the replay set (e.g.,
    /// via `mirage_session::accept()` -> `TokenVerifier`).
    ///
    /// This is the integration point for the production bridge
    /// accept path: the local burn already happened inside
    /// `accept()`; this method only needs to gossip it to peers
    /// so they can pre-empt a cross-bridge replay attempt.
    ///
    /// Does NOT touch the local replay set. Does NOT check
    /// whether the token is already in the set - the caller is
    /// responsible for only calling this after a confirmed
    /// successful local burn.
    pub async fn notify_burn(&self, token_id: [u8; 32]) {
        let now = unix_now_secs();
        let event = GossipEvent::TokenBurned {
            token_id,
            burned_at: now,
        };
        let signed = SignedGossipEvent::sign(event, &self.signing_key);
        self.gossip.publish(signed).await;
        tracing::debug!(
            token_id = ?hex::encode(token_id),
            "CohortReplayCoordinator: published TokenBurned (notify-only)"
        );
    }

    /// Check whether the token has already been burned (locally
    /// or via gossip). Pure read; does NOT mutate the replay
    /// set. Closes RT-CR-1 (previous probe-via-insert
    /// implementation pinned probed token_ids in the set).
    pub fn already_burned(&self, token_id: &[u8; 32], now_unix: u64) -> bool {
        self.replay_set.contains(token_id, now_unix)
    }

    /// Current replay-set size (diagnostic).
    pub fn replay_set_len(&self) -> usize {
        self.replay_set.len()
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
    async fn coordinator_publishes_on_local_burn() {
        let gossip = Arc::new(MemoryGossip::new());
        let sk = fresh_sk();
        gossip.authorize(sk.verifying_key().to_bytes()).await;
        let mut rx = gossip.subscribe().await;
        let rs = Arc::new(SyncReplaySet::new(128));
        let coord =
            CohortReplayCoordinator::new(gossip.clone() as Arc<dyn CohortGossip>, sk, rs, 3600);
        let now = unix_now_secs();
        coord
            .record_local_burn([0xAA; 32], now.saturating_add(60))
            .await;
        let received = tokio::time::timeout(Duration::from_millis(200), rx.recv())
            .await
            .expect("publish")
            .unwrap();
        match received.event {
            GossipEvent::TokenBurned { token_id, .. } => assert_eq!(token_id, [0xAA; 32]),
            other => panic!("unexpected {:?}", other),
        }
    }

    #[tokio::test]
    async fn subscriber_absorbs_remote_burn() {
        let gossip = Arc::new(MemoryGossip::new());
        let sk = fresh_sk();
        gossip.authorize(sk.verifying_key().to_bytes()).await;
        let rs = Arc::new(SyncReplaySet::new(128));
        let _task =
            spawn_gossip_to_replay_set(gossip.clone() as Arc<dyn CohortGossip>, rs.clone(), 3600);
        tokio::time::sleep(Duration::from_millis(10)).await;

        let now = unix_now_secs();
        let event = GossipEvent::TokenBurned {
            token_id: [0x55; 32],
            burned_at: now,
        };
        gossip.publish(SignedGossipEvent::sign(event, &sk)).await;

        // Wait for absorption.
        for _ in 0..50 {
            if !rs.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(rs.len(), 1, "subscriber must absorb the burn");
        // Local replay set should now reject the same token.
        assert!(!rs.check_and_insert(&[0x55; 32], now + 60, now));
    }

    #[tokio::test]
    async fn coordinator_blocks_token_burned_by_peer() {
        // End-to-end: peer A burns a token, peer B's coordinator
        // refuses the same token.
        let gossip = Arc::new(MemoryGossip::new());
        let sk_a = fresh_sk();
        let sk_b = fresh_sk();
        gossip.authorize(sk_a.verifying_key().to_bytes()).await;
        gossip.authorize(sk_b.verifying_key().to_bytes()).await;
        let rs_a = Arc::new(SyncReplaySet::new(128));
        let rs_b = Arc::new(SyncReplaySet::new(128));
        let coord_a =
            CohortReplayCoordinator::new(gossip.clone() as Arc<dyn CohortGossip>, sk_a, rs_a, 3600);
        let coord_b = CohortReplayCoordinator::new(
            gossip.clone() as Arc<dyn CohortGossip>,
            sk_b,
            rs_b.clone(),
            3600,
        );
        tokio::time::sleep(Duration::from_millis(10)).await;

        let now = unix_now_secs();
        coord_a.record_local_burn([0x77; 32], now + 60).await;

        // Give B's subscriber time to absorb.
        for _ in 0..50 {
            if coord_b.replay_set_len() > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // B now refuses the same token.
        assert!(coord_b.already_burned(&[0x77; 32], now));
    }

    #[tokio::test]
    async fn subscriber_ignores_non_token_burned_events() {
        let gossip = Arc::new(MemoryGossip::new());
        let sk = fresh_sk();
        gossip.authorize(sk.verifying_key().to_bytes()).await;
        let rs = Arc::new(SyncReplaySet::new(128));
        let _task =
            spawn_gossip_to_replay_set(gossip.clone() as Arc<dyn CohortGossip>, rs.clone(), 3600);
        tokio::time::sleep(Duration::from_millis(10)).await;
        let now = unix_now_secs();
        let unrelated = GossipEvent::ProbeScanDetected {
            source_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
            expire_secs: 60,
            detected_at: now,
        };
        gossip
            .publish(SignedGossipEvent::sign(unrelated, &sk))
            .await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(rs.len(), 0, "replay set must not be polluted");
    }

    /// RT-CR-6: `notify_burn` publishes a signed `TokenBurned`
    /// event without inserting into the local replay set.  This
    /// is the production accept-path integration point: `accept()`
    /// already burned the token locally; `notify_burn` only gossips
    /// it to peers.
    #[tokio::test]
    async fn notify_burn_publishes_and_does_not_insert() {
        let gossip = Arc::new(MemoryGossip::new());
        let sk = fresh_sk();
        gossip.authorize(sk.verifying_key().to_bytes()).await;
        let mut rx = gossip.subscribe().await;
        let rs = Arc::new(SyncReplaySet::new(128));
        // Pre-burn the token locally (simulating what `accept()` does).
        let now = unix_now_secs();
        let pre_inserted = rs.check_and_insert(&[0xBB; 32], now + 60, now);
        assert!(pre_inserted, "pre-insert must succeed on empty set");
        assert_eq!(rs.len(), 1);

        let coord = CohortReplayCoordinator::new(
            gossip.clone() as Arc<dyn CohortGossip>,
            sk,
            rs.clone(),
            3600,
        );
        // notify_burn must NOT touch the replay set (it was pre-burned).
        coord.notify_burn([0xBB; 32]).await;

        // The gossip event must arrive on the channel.
        let event = tokio::time::timeout(Duration::from_millis(200), rx.recv())
            .await
            .expect("publish must complete")
            .expect("channel must be open");
        match event.event {
            GossipEvent::TokenBurned { token_id, .. } => {
                assert_eq!(token_id, [0xBB; 32], "published token must match");
            }
            other => panic!("expected TokenBurned, got {:?}", other),
        }
        // Replay set must still have exactly 1 entry (the pre-burned one);
        // notify_burn must not add a second entry.
        assert_eq!(rs.len(), 1, "notify_burn must not insert into replay set");
    }

    /// `notify_burn` on an EMPTY replay set still publishes the event.
    /// Covers the theoretical path where the coordinator is used without
    /// a prior local burn (e.g., re-gossip of a remotely-received burn).
    #[tokio::test]
    async fn notify_burn_publishes_even_when_token_not_in_set() {
        let gossip = Arc::new(MemoryGossip::new());
        let sk = fresh_sk();
        gossip.authorize(sk.verifying_key().to_bytes()).await;
        let mut rx = gossip.subscribe().await;
        let rs = Arc::new(SyncReplaySet::new(128));
        let coord = CohortReplayCoordinator::new(
            gossip.clone() as Arc<dyn CohortGossip>,
            sk,
            rs.clone(),
            3600,
        );
        coord.notify_burn([0xCC; 32]).await;
        let event = tokio::time::timeout(Duration::from_millis(200), rx.recv())
            .await
            .expect("publish must complete")
            .expect("channel must be open");
        match event.event {
            GossipEvent::TokenBurned { token_id, .. } => {
                assert_eq!(token_id, [0xCC; 32]);
            }
            other => panic!("expected TokenBurned, got {:?}", other),
        }
        // notify_burn must not insert anything.
        assert_eq!(rs.len(), 0, "notify_burn must not insert into empty set");
    }
}
