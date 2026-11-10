//! Client-side bridge pool: the set of live bridges a client can dial.
//!
//! The pool is the bridge between the *discovery* layer (what announcements
//! the network is currently showing) and the *transport* / *session* layer
//! (which endpoint do we actually try next?). It:
//!
//! 1. Absorbs announcements from [`ClientSubscriber::fetch_for_epoch`].
//! 2. Absorbs revocations and removes revoked bridges immediately.
//! 3. Tracks per-bridge health counters (success, fail, last-seen).
//! 4. Picks a bridge for the next connection attempt using a simple,
//!    reviewable selection policy (see [`SelectionPolicy`]).
//!
//! Implements the client-side revocation semantics ("trust the most
//! recent signed statement; a revocation always wins against a prior
//! announcement of the same key") and the operational notes ("clients
//! race fetch across all configured channels ... first success wins").
//!
//! # Threat-model notes
//!
//! - **Revocation is sticky.** A bridge key that has ever been revoked
//!   for `Compromised` or `Rotating` stays in a local blocklist for
//!   [`BRIDGE_REVOCATION_MEMORY_SECONDS`] so a hostile channel cannot
//!   remove the revocation by withholding future copies of it.
//! - **Sybil-bridging resistance.** Nothing here prevents a single
//!   operator from publishing a thousand bridges under different keys;
//!   that's an operator-level trust problem (the invite binds the
//!   trust root). The pool treats every bridge the invite's operator
//!   signs as equally trusted - scoring is about *liveness*, not
//!   *authenticity*.
//! - **Health counters are information.** An adversary who can trigger
//!   failed handshakes against a specific bridge (e.g., by RST-ing the
//!   TCP connection) can push a legitimate bridge off the top of the
//!   selection queue. The scoring formula must tolerate occasional
//!   noise without flipping to another bridge on a single fail.
//! - **Bounded size.** `max_bridges` cap prevents a chatty announcement
//!   pipeline (bug, attack, or exuberant operator) from ballooning pool
//!   memory. LRU on `last_seen_unix` evicts stale entries first.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::wire::{Announcement, Revocation, RevocationReason, ED25519_PK_LEN, X25519_PK_LEN};

/// How long a revocation stays remembered locally after its `issued_at`.
/// Spec §7 calls for revocations to persist for at least one grace
/// window past the key's natural expiry. 7 days is the v0.1 default.
pub const BRIDGE_REVOCATION_MEMORY_SECONDS: u64 = 7 * 24 * 3600;

/// Maximum number of bridges the pool retains before LRU eviction
/// (by `last_seen_unix`). A typical deployment has dozens of bridges
/// per operator; 1024 is generous, bounded, and fits in ~400 KiB.
pub const DEFAULT_MAX_BRIDGES: usize = 1024;

/// Per-bridge record held in the pool.
#[derive(Debug, Clone)]
pub struct BridgeEntry {
    /// Bridge long-term identity (used as map key).
    pub bridge_ed25519_pk: [u8; ED25519_PK_LEN],
    /// Bridge X25519 static (used in Noise handshake).
    pub bridge_x25519_pk: [u8; X25519_PK_LEN],
    /// Transport capability bitfield from the announcement.
    pub transport_caps: u32,
    /// Endpoint encoded on the wire (IPv4/IPv6/hostname+port).
    pub endpoint: crate::wire::Endpoint,
    /// `issued_at` of the announcement that last updated this record.
    pub announcement_issued_at: u64,
    /// `expires_at` of that announcement. Used to drop stale records.
    pub announcement_expires_at: u64,
    /// Successful session handshakes completed against this bridge.
    pub successes: u32,
    /// Failed connection attempts (any layer: TCP, TLS, auth, timeout).
    pub failures: u32,
    /// Unix seconds when we last learned of this bridge (announcement
    /// received OR health event). Drives LRU eviction.
    pub last_seen_unix: u64,
}

impl BridgeEntry {
    fn from_announcement(ann: &Announcement, now_unix: u64) -> Self {
        Self {
            bridge_ed25519_pk: ann.bridge_ed25519_pk,
            bridge_x25519_pk: ann.bridge_x25519_pk,
            transport_caps: ann.transport_caps,
            endpoint: ann.endpoint.clone(),
            announcement_issued_at: ann.issued_at,
            announcement_expires_at: ann.expires_at,
            successes: 0,
            failures: 0,
            last_seen_unix: now_unix.max(ann.issued_at),
        }
    }

    /// Score used for selection. Higher is better.
    ///
    /// Laplace-smoothed Bernoulli estimate: `(s + 1) / (s + f + 2)`.
    /// Properties:
    /// - Untested bridge scores 0.5 (prior assumption of 50/50).
    /// - A bridge with 10 successes and 1 failure scores ~ 0.846 -
    ///   above the untested prior, so a known-working bridge is
    ///   preferred to an unproven one.
    /// - A bridge with 0 successes and 5 failures scores ~ 0.143 -
    ///   well below the untested prior, so an untested announcement
    ///   displaces it.
    /// - A single transient failure against a bridge with dozens of
    ///   successes barely moves the score (10/12 -> 10/13), so the
    ///   selection doesn't flip on noise.
    pub fn score(&self) -> f64 {
        let s = f64::from(self.successes);
        let f = f64::from(self.failures);
        (s + 1.0) / (s + f + 2.0)
    }
}

/// Reason a bridge was evicted from the pool. Diagnostics only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictReason {
    /// A `Revocation` with this bridge's key was seen.
    Revoked,
    /// The announcement's `expires_at` is past `now_unix`.
    Expired,
    /// Pool hit `max_bridges`; this was the least-recently-seen entry.
    Lru,
}

/// Entry kept in the blocklist after a revocation.
///
/// `reason` is kept for future telemetry / UI surfacing - a compromised
/// bridge and a rotated bridge have different operator implications
/// even though both end up in the same blocklist.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
struct BlocklistEntry {
    reason: RevocationReason,
    issued_at: u64,
    /// When to forget the block (usually `issued_at + BRIDGE_REVOCATION_MEMORY_SECONDS`).
    forget_at: u64,
}

/// Pool selection policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionPolicy {
    /// Highest `score()` wins. Ties broken by most recent
    /// `last_seen_unix`, then lexicographic on the key.
    BestScore,
    /// Round-robin across all bridges in the pool. Deterministic
    /// across calls on the same pool state; useful for tests.
    RoundRobin,
}

/// Client-side bridge pool.
///
/// Thread-safe: all mutating operations lock a single `Mutex`. High
/// throughput is not a goal - the pool is consulted once per connection
/// attempt (seconds apart, not microseconds).
pub struct BridgePool {
    inner: Mutex<PoolState>,
}

struct PoolState {
    bridges: HashMap<[u8; ED25519_PK_LEN], BridgeEntry>,
    blocklist: HashMap<[u8; ED25519_PK_LEN], BlocklistEntry>,
    round_robin_cursor: usize,
    max_bridges: usize,
}

impl BridgePool {
    /// Construct an empty pool with the default size cap.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_BRIDGES)
    }

    /// Construct an empty pool with a custom bridge cap. Tests set this
    /// to small numbers to exercise LRU eviction.
    pub fn with_capacity(max_bridges: usize) -> Self {
        Self {
            inner: Mutex::new(PoolState {
                bridges: HashMap::new(),
                blocklist: HashMap::new(),
                round_robin_cursor: 0,
                max_bridges,
            }),
        }
    }

    /// Number of currently pooled bridges.
    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.bridges.len()).unwrap_or(0)
    }

    /// `true` iff no bridges are pooled.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of keys currently on the blocklist.
    pub fn blocklist_len(&self) -> usize {
        self.inner.lock().map(|g| g.blocklist.len()).unwrap_or(0)
    }

    /// Ingest the output of a `ClientSubscriber::fetch_for_epoch` call.
    ///
    /// - For each announcement: add or update the bridge (monotonic by
    ///   `issued_at` - older announcement cannot overwrite a newer one).
    ///   If the bridge is on the blocklist, the announcement is rejected.
    /// - For each revocation: remove the bridge and add to the blocklist.
    /// - Garbage-collect blocklist entries older than
    ///   [`BRIDGE_REVOCATION_MEMORY_SECONDS`].
    /// - Evict announcements past `expires_at`.
    /// - Apply LRU cap.
    ///
    /// Returns a small struct describing what changed.
    pub fn apply_fetch(
        &self,
        announcements: &[Announcement],
        revocations: &[Revocation],
        now_unix: u64,
    ) -> ApplyReport {
        let mut rep = ApplyReport::default();

        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let state = &mut *guard;

        // 1. Revocations first - a revocation in the same fetch as a
        //    (re-)announcement must win.
        for rev in revocations {
            if state.bridges.remove(&rev.target_ed25519_pk).is_some() {
                rep.evicted
                    .push((rev.target_ed25519_pk, EvictReason::Revoked));
            }
            let forget_at = rev
                .issued_at
                .saturating_add(BRIDGE_REVOCATION_MEMORY_SECONDS);
            let insert = !matches!(
                state.blocklist.get(&rev.target_ed25519_pk),
                Some(existing) if existing.issued_at >= rev.issued_at
            );
            if insert {
                state.blocklist.insert(
                    rev.target_ed25519_pk,
                    BlocklistEntry {
                        reason: rev.reason,
                        issued_at: rev.issued_at,
                        forget_at,
                    },
                );
                rep.revocations_ingested += 1;
            }
        }

        // 2. Announcements.
        for ann in announcements {
            if state.blocklist.contains_key(&ann.bridge_ed25519_pk) {
                rep.rejected_by_blocklist += 1;
                continue;
            }
            let entry = state
                .bridges
                .entry(ann.bridge_ed25519_pk)
                .or_insert_with(|| {
                    rep.announcements_new += 1;
                    BridgeEntry::from_announcement(ann, now_unix)
                });
            if ann.issued_at >= entry.announcement_issued_at {
                // Newer or same-generation announcement updates metadata
                // but preserves health counters - failures against a
                // bridge shouldn't be reset just because the operator
                // re-publishes.
                entry.bridge_x25519_pk = ann.bridge_x25519_pk;
                entry.transport_caps = ann.transport_caps;
                entry.endpoint = ann.endpoint.clone();
                entry.announcement_issued_at = ann.issued_at;
                entry.announcement_expires_at = ann.expires_at;
                entry.last_seen_unix = now_unix.max(entry.last_seen_unix);
                rep.announcements_updated += 1;
            } else {
                rep.announcements_stale += 1;
            }
        }

        // 3. GC expired announcements.
        if now_unix > 0 {
            let expired: Vec<_> = state
                .bridges
                .iter()
                .filter(|(_, e)| e.announcement_expires_at <= now_unix)
                .map(|(k, _)| *k)
                .collect();
            for k in expired {
                state.bridges.remove(&k);
                rep.evicted.push((k, EvictReason::Expired));
            }
        }

        // 4. GC old blocklist entries.
        if now_unix > 0 {
            state.blocklist.retain(|_, b| b.forget_at > now_unix);
        }

        // 5. LRU cap.
        while state.bridges.len() > state.max_bridges {
            if let Some((&key, _)) = state.bridges.iter().min_by_key(|(_, e)| e.last_seen_unix) {
                state.bridges.remove(&key);
                rep.evicted.push((key, EvictReason::Lru));
            } else {
                break;
            }
        }

        rep
    }

    /// Select the next bridge to try. Returns `None` if the pool is
    /// empty (caller falls back to a bootstrap announcement).
    pub fn select(&self, policy: SelectionPolicy) -> Option<BridgeEntry> {
        let mut guard = self.inner.lock().ok()?;
        if guard.bridges.is_empty() {
            return None;
        }
        match policy {
            SelectionPolicy::BestScore => guard
                .bridges
                .values()
                .max_by(|a, b| {
                    a.score()
                        .partial_cmp(&b.score())
                        .unwrap_or(std::cmp::Ordering::Equal)
                        .then_with(|| a.last_seen_unix.cmp(&b.last_seen_unix))
                        .then_with(|| a.bridge_ed25519_pk.cmp(&b.bridge_ed25519_pk))
                })
                .cloned(),
            SelectionPolicy::RoundRobin => {
                let mut keys: Vec<_> = guard.bridges.keys().copied().collect();
                keys.sort();
                let idx = guard.round_robin_cursor % keys.len();
                guard.round_robin_cursor = guard.round_robin_cursor.wrapping_add(1);
                guard.bridges.get(&keys[idx]).cloned()
            }
        }
    }

    /// Record a successful handshake. Caller passes the bridge's ID so
    /// the pool can bump that specific entry's counter.
    pub fn record_success(&self, bridge_ed25519_pk: &[u8; ED25519_PK_LEN], now_unix: u64) {
        if let Ok(mut g) = self.inner.lock() {
            if let Some(e) = g.bridges.get_mut(bridge_ed25519_pk) {
                e.successes = e.successes.saturating_add(1);
                e.last_seen_unix = now_unix.max(e.last_seen_unix);
            }
        }
    }

    /// Record a failed handshake.
    pub fn record_failure(&self, bridge_ed25519_pk: &[u8; ED25519_PK_LEN], now_unix: u64) {
        if let Ok(mut g) = self.inner.lock() {
            if let Some(e) = g.bridges.get_mut(bridge_ed25519_pk) {
                e.failures = e.failures.saturating_add(1);
                e.last_seen_unix = now_unix.max(e.last_seen_unix);
            }
        }
    }

    /// Snapshot all entries for diagnostics / UI. Not used in hot paths.
    pub fn snapshot(&self) -> Vec<BridgeEntry> {
        self.inner
            .lock()
            .map(|g| g.bridges.values().cloned().collect())
            .unwrap_or_default()
    }

    /// True iff this bridge is currently blocklisted by a known revocation.
    pub fn is_blocklisted(&self, bridge_ed25519_pk: &[u8; ED25519_PK_LEN]) -> bool {
        self.inner
            .lock()
            .map(|g| g.blocklist.contains_key(bridge_ed25519_pk))
            .unwrap_or(false)
    }
}

impl Default for BridgePool {
    fn default() -> Self {
        Self::new()
    }
}

/// Report surfaced from [`BridgePool::apply_fetch`] so operators and
/// clients can observe what happened in a single line of structured log.
#[derive(Debug, Default, Clone)]
pub struct ApplyReport {
    /// Bridges newly inserted into the pool.
    pub announcements_new: u32,
    /// Bridges updated with a newer announcement.
    pub announcements_updated: u32,
    /// Announcements we already had a newer copy of.
    pub announcements_stale: u32,
    /// Announcements dropped because the target is on the blocklist.
    pub rejected_by_blocklist: u32,
    /// Revocations that added (or refreshed) a blocklist entry.
    pub revocations_ingested: u32,
    /// Entries evicted in this call. (key, reason).
    pub evicted: Vec<([u8; ED25519_PK_LEN], EvictReason)>,
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{transport_caps, Endpoint, RevocationReason, SIG_LEN};

    fn ann(key_tag: u8, issued: u64, expires: u64) -> Announcement {
        Announcement {
            issued_at: issued,
            expires_at: expires,
            bridge_ed25519_pk: [key_tag; 32],
            bridge_x25519_pk: [key_tag; 32],
            transport_caps: transport_caps::REALITY_V2,
            endpoint: Endpoint::Ipv4 {
                addr: [127, 0, 0, 1],
                port: 443,
            },
            extra_endpoints: Vec::new(),
            signature: [0u8; SIG_LEN],
        }
    }

    fn rev(key_tag: u8, issued: u64, reason: RevocationReason) -> Revocation {
        Revocation {
            target_ed25519_pk: [key_tag; 32],
            reason,
            issued_at: issued,
            signature: [0u8; SIG_LEN],
        }
    }

    #[test]
    fn empty_pool_returns_none() {
        let pool = BridgePool::new();
        assert!(pool.is_empty());
        assert!(pool.select(SelectionPolicy::BestScore).is_none());
        assert!(pool.select(SelectionPolicy::RoundRobin).is_none());
    }

    #[test]
    fn announcement_adds_bridge() {
        let pool = BridgePool::new();
        let rep = pool.apply_fetch(&[ann(1, 100, 200)], &[], 100);
        assert_eq!(rep.announcements_new, 1);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn newer_announcement_updates_metadata() {
        let pool = BridgePool::new();
        pool.apply_fetch(&[ann(1, 100, 200)], &[], 100);
        let rep = pool.apply_fetch(&[ann(1, 150, 300)], &[], 150);
        assert_eq!(rep.announcements_new, 0);
        assert_eq!(rep.announcements_updated, 1);
        let e = &pool.snapshot()[0];
        assert_eq!(e.announcement_issued_at, 150);
        assert_eq!(e.announcement_expires_at, 300);
    }

    #[test]
    fn older_announcement_is_rejected_as_stale() {
        let pool = BridgePool::new();
        pool.apply_fetch(&[ann(1, 150, 300)], &[], 150);
        let rep = pool.apply_fetch(&[ann(1, 100, 200)], &[], 150);
        assert_eq!(rep.announcements_stale, 1);
        assert_eq!(pool.snapshot()[0].announcement_issued_at, 150);
    }

    #[test]
    fn revocation_removes_bridge_and_blocklists() {
        let pool = BridgePool::new();
        pool.apply_fetch(&[ann(1, 100, 1_000_000)], &[], 100);
        let rep = pool.apply_fetch(&[], &[rev(1, 200, RevocationReason::Compromised)], 200);
        assert_eq!(rep.revocations_ingested, 1);
        assert_eq!(rep.evicted.len(), 1);
        assert!(pool.is_empty());
        assert!(pool.is_blocklisted(&[1u8; 32]));
    }

    #[test]
    fn revocation_is_sticky_against_reannouncement() {
        let pool = BridgePool::new();
        pool.apply_fetch(&[ann(1, 100, 1_000_000)], &[], 100);
        pool.apply_fetch(&[], &[rev(1, 200, RevocationReason::Compromised)], 200);
        assert!(pool.is_empty());
        // Hostile channel re-publishes the announcement with a *newer*
        // `issued_at` than the revocation. Must still be rejected.
        let rep = pool.apply_fetch(&[ann(1, 300, 1_000_000)], &[], 300);
        assert_eq!(rep.rejected_by_blocklist, 1);
        assert!(pool.is_empty());
    }

    #[test]
    fn expired_announcement_gets_evicted_on_next_fetch() {
        let pool = BridgePool::new();
        pool.apply_fetch(&[ann(1, 100, 200)], &[], 150);
        assert_eq!(pool.len(), 1);
        let rep = pool.apply_fetch(&[], &[], 500);
        assert_eq!(rep.evicted.len(), 1);
        assert_eq!(rep.evicted[0].1, EvictReason::Expired);
        assert!(pool.is_empty());
    }

    #[test]
    fn blocklist_expires_after_memory_window() {
        let pool = BridgePool::new();
        pool.apply_fetch(&[], &[rev(1, 100, RevocationReason::Compromised)], 100);
        assert!(pool.is_blocklisted(&[1u8; 32]));
        // Jump forward past the memory window.
        let now = 100 + BRIDGE_REVOCATION_MEMORY_SECONDS + 1;
        pool.apply_fetch(&[], &[], now);
        assert!(!pool.is_blocklisted(&[1u8; 32]));
    }

    #[test]
    fn lru_evicts_least_recently_seen_bridge() {
        let pool = BridgePool::with_capacity(2);
        pool.apply_fetch(&[ann(1, 100, 1_000_000)], &[], 100);
        pool.apply_fetch(&[ann(2, 110, 1_000_000)], &[], 110);
        // ann(1) is now least recently seen; inserting ann(3) should evict it.
        let rep = pool.apply_fetch(&[ann(3, 120, 1_000_000)], &[], 120);
        assert!(rep
            .evicted
            .iter()
            .any(|(k, r)| *k == [1u8; 32] && *r == EvictReason::Lru));
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn best_score_picks_untested_over_known_failing() {
        let pool = BridgePool::new();
        pool.apply_fetch(&[ann(1, 100, 1_000_000)], &[], 100);
        // Bridge 1 has a history of failures.
        for _ in 0..5 {
            pool.record_failure(&[1u8; 32], 120);
        }
        pool.apply_fetch(&[ann(2, 130, 1_000_000)], &[], 130);

        let pick = pool.select(SelectionPolicy::BestScore).unwrap();
        assert_eq!(
            pick.bridge_ed25519_pk, [2u8; 32],
            "fresh announcement scores above repeatedly-failing bridge"
        );
    }

    #[test]
    fn single_failure_does_not_flip_selection() {
        let pool = BridgePool::new();
        pool.apply_fetch(&[ann(1, 100, 1_000_000)], &[], 100);
        pool.apply_fetch(&[ann(2, 100, 1_000_000)], &[], 100);
        // Bridge 1 accrues 10 successes, then 1 failure. It should still
        // score higher than untested bridge 2.
        for _ in 0..10 {
            pool.record_success(&[1u8; 32], 110);
        }
        pool.record_failure(&[1u8; 32], 120);
        let pick = pool.select(SelectionPolicy::BestScore).unwrap();
        assert_eq!(pick.bridge_ed25519_pk, [1u8; 32]);
    }

    #[test]
    fn round_robin_cycles_deterministically() {
        let pool = BridgePool::new();
        pool.apply_fetch(
            &[
                ann(1, 100, 1_000_000),
                ann(2, 100, 1_000_000),
                ann(3, 100, 1_000_000),
            ],
            &[],
            100,
        );
        let mut seen = Vec::new();
        for _ in 0..6 {
            seen.push(
                pool.select(SelectionPolicy::RoundRobin)
                    .unwrap()
                    .bridge_ed25519_pk[0],
            );
        }
        assert_eq!(seen, vec![1, 2, 3, 1, 2, 3]);
    }

    #[test]
    fn record_success_updates_last_seen() {
        let pool = BridgePool::new();
        pool.apply_fetch(&[ann(1, 100, 1_000_000)], &[], 100);
        pool.record_success(&[1u8; 32], 200);
        let e = &pool.snapshot()[0];
        assert_eq!(e.last_seen_unix, 200);
        assert_eq!(e.successes, 1);
    }

    #[test]
    fn record_ops_on_unknown_bridge_are_noops() {
        let pool = BridgePool::new();
        pool.record_success(&[99u8; 32], 100);
        pool.record_failure(&[99u8; 32], 100);
        assert!(pool.is_empty());
    }

    #[test]
    fn concurrent_revocation_and_announcement_in_same_fetch_revokes() {
        let pool = BridgePool::new();
        // Adversarial channel returns ann and rev in the same batch.
        // Revocation wins by design - §7 "most recent signed statement".
        let rep = pool.apply_fetch(
            &[ann(1, 100, 1_000_000)],
            &[rev(1, 200, RevocationReason::Compromised)],
            200,
        );
        // The announcement was inserted first, then the revocation evicted it.
        // `apply_fetch` processes revocations before announcements in this
        // impl, so the announcement is rejected by blocklist - report shows
        // `rejected_by_blocklist = 1`.
        assert_eq!(rep.rejected_by_blocklist, 1);
        assert!(pool.is_empty());
    }

    #[test]
    fn blocklist_takes_most_recent_revocation() {
        let pool = BridgePool::new();
        pool.apply_fetch(&[], &[rev(1, 100, RevocationReason::Compromised)], 100);
        // Older revocation should not overwrite the newer one.
        pool.apply_fetch(&[], &[rev(1, 50, RevocationReason::Rotating)], 100);
        // Pool still blocklists.
        assert!(pool.is_blocklisted(&[1u8; 32]));
    }
}
