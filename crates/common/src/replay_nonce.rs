//! Bounded, TTL'd seen-nonce / seen-event set for replay defense.
//!
//! Several Mirage layers authenticate with a freshness *window* but no
//! per-message seen-set: an HTTP-ish transport auth frame
//! (`nonce[32] || mac[32] || timestamp[8]`), a signed cohort-gossip event, or
//! an onion INTRODUCE cell. A window alone is NOT replay protection - a
//! passive observer who captures one valid message can re-send it verbatim
//! within the window and observe the authenticated effect (a confirmation
//! oracle, a re-applied soft-block, a re-triggered introduction). A
//! [`SeenNonceSet`] closes it: the per-message random nonce (or a hash of the
//! signed bytes) is recorded on first use and any repeat within the window is
//! rejected, making each captured message single-use.
//!
//! Lives in `mirage-common` (the dependency root) so every layer - transports,
//! discovery/gossip, onion services - can share one primitive.
//!
//! The set is bounded (oldest-evicted) so a flood of distinct nonces cannot
//! exhaust memory, and entries past `ttl` are pruned lazily - set the TTL
//! `>=` the auth/freshness window so an entry outlives the period in which its
//! message would still pass the timestamp check.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Default cap on tracked nonces. At 32 B key + bookkeeping this is a few MiB.
pub const DEFAULT_SEEN_NONCE_CAPACITY: usize = 65_536;

/// Guarded state: the seen-set plus a FIFO insertion-order queue that drives
/// amortized-O(1) overflow eviction (pop the front) instead of an O(capacity)
/// min-scan. `order` mirrors the live keys of `map` as a *set*: a key is pushed
/// once when first inserted and dropped from both on eviction or [`reap`], so
/// `order` never accumulates stale entries and stays bounded by `capacity`.
struct Inner {
    map: HashMap<[u8; 32], Instant>,
    order: VecDeque<[u8; 32]>,
}

/// A set of recently-seen 32-byte nonces (or signed-message hashes) with
/// per-entry TTL.
pub struct SeenNonceSet {
    inner: Mutex<Inner>,
    ttl: Duration,
    capacity: usize,
}

impl std::fmt::Debug for SeenNonceSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeenNonceSet")
            .field("ttl", &self.ttl)
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl SeenNonceSet {
    /// Construct with the given TTL (set `>=` the auth/freshness window) and
    /// the default capacity.
    pub fn new(ttl: Duration) -> Self {
        Self::with_capacity(ttl, DEFAULT_SEEN_NONCE_CAPACITY)
    }

    /// Construct with an explicit TTL and capacity.
    pub fn with_capacity(ttl: Duration, capacity: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                order: VecDeque::new(),
            }),
            ttl,
            capacity: capacity.max(1),
        }
    }

    /// Record `nonce` as seen-at-`now`. Returns `true` if the nonce was
    /// FRESH (not seen within the TTL - caller should ACCEPT), or `false` if
    /// it is a replay (caller should REJECT).
    ///
    /// A poisoned lock fails CLOSED (returns `false`, rejecting) - a stuck
    /// replay set must never silently admit replays.
    #[must_use = "dropping the result disables replay protection (false = replay -> reject)"]
    pub fn check_and_insert(&self, nonce: [u8; 32], now: Instant) -> bool {
        let Ok(mut g) = self.inner.lock() else {
            return false;
        };
        let inner = &mut *g;
        if let Some(seen_at) = inner.map.get(&nonce) {
            if now.saturating_duration_since(*seen_at) <= self.ttl {
                return false; // replay within window
            }
        }
        let is_new = !inner.map.contains_key(&nonce);
        if is_new && inner.map.len() >= self.capacity {
            // Amortized-O(1) FIFO eviction: drop the oldest-inserted key. Skip
            // any queue entries already gone from the map (belt-and-suspenders;
            // `reap` keeps them in sync) so one live victim is always removed.
            while let Some(victim) = inner.order.pop_front() {
                if inner.map.remove(&victim).is_some() {
                    break;
                }
            }
        }
        if is_new {
            inner.order.push_back(nonce);
        }
        inner.map.insert(nonce, now);
        true
    }

    /// Sweep entries older than the TTL. Returns the number removed.
    pub fn reap(&self, now: Instant) -> usize {
        let Ok(mut g) = self.inner.lock() else {
            return 0;
        };
        let ttl = self.ttl;
        let inner = &mut *g;
        let before = inner.map.len();
        inner
            .map
            .retain(|_, t| now.saturating_duration_since(*t) <= ttl);
        // Keep the FIFO queue in step with the map so it stays bounded by
        // `capacity` and never leaks entries that were reaped by time alone.
        let map = &inner.map;
        inner.order.retain(|k| map.contains_key(k));
        before - inner.map.len()
    }

    /// Number of nonces currently tracked.
    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.map.len()).unwrap_or(0)
    }

    /// True iff empty.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().map(|g| g.map.is_empty()).unwrap_or(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_nonce_accepted_replay_rejected() {
        let s = SeenNonceSet::new(Duration::from_secs(60));
        let now = Instant::now();
        let n = [0x11u8; 32];
        assert!(s.check_and_insert(n, now), "first sighting is fresh");
        assert!(!s.check_and_insert(n, now), "exact replay is rejected");
        assert!(s.check_and_insert([0x22u8; 32], now));
    }

    #[test]
    fn nonce_accepted_again_after_ttl() {
        let s = SeenNonceSet::new(Duration::from_secs(30));
        let now = Instant::now();
        let n = [0x33u8; 32];
        assert!(s.check_and_insert(n, now));
        assert!(!s.check_and_insert(n, now + Duration::from_secs(10)));
        assert!(s.check_and_insert(n, now + Duration::from_secs(31)));
    }

    #[test]
    fn capacity_bounds_memory() {
        let s = SeenNonceSet::with_capacity(Duration::from_secs(600), 4);
        let now = Instant::now();
        for i in 0..100u32 {
            let mut n = [0u8; 32];
            n[..4].copy_from_slice(&i.to_be_bytes());
            assert!(s.check_and_insert(n, now));
        }
        assert!(s.len() <= 4, "must not grow past capacity");
    }

    #[test]
    fn overflow_evicts_oldest_inserted_fifo() {
        // Capacity 4: fill with n0..n3, then n4 overflows and must evict the
        // oldest-inserted (n0) in amortized O(1) - not scan for a min.
        let s = SeenNonceSet::with_capacity(Duration::from_secs(600), 4);
        let now = Instant::now();
        let key = |i: u8| {
            let mut k = [0u8; 32];
            k[0] = i;
            k
        };
        for i in 0..4u8 {
            assert!(s.check_and_insert(key(i), now));
        }
        // n4 is fresh -> triggers one eviction (FIFO front = n0).
        assert!(s.check_and_insert(key(4), now));
        assert_eq!(s.len(), 4, "capacity held");
        // n1 survived and is still tracked within the window. Check it first:
        // it is already in the map so it does NOT evict anything (replay).
        assert!(
            !s.check_and_insert(key(1), now),
            "surviving nonce still detected as replay"
        );
        // n0 was the FIFO front, so it was evicted and is fresh again.
        // (Re-inserting it at capacity now evicts the next-oldest, n2.)
        assert!(
            s.check_and_insert(key(0), now),
            "evicted nonce is fresh again"
        );
    }

    #[test]
    fn reap_keeps_order_queue_bounded() {
        // Many insert+reap cycles where every entry expires: the internal FIFO
        // queue must be pruned by reap (not just the map) or it would leak.
        // Observable proxy: len() stays 0 and inserts keep succeeding.
        let s = SeenNonceSet::with_capacity(Duration::from_secs(1), 8);
        let base = Instant::now();
        for i in 0..10_000u32 {
            let mut n = [0u8; 32];
            n[..4].copy_from_slice(&i.to_be_bytes());
            let t = base + Duration::from_secs(u64::from(i) * 10);
            assert!(s.check_and_insert(n, t));
            assert_eq!(s.reap(t + Duration::from_secs(5)), 1);
        }
        assert!(
            s.is_empty(),
            "all expired entries reaped from map and queue"
        );
    }

    #[test]
    fn reap_drops_expired() {
        let s = SeenNonceSet::new(Duration::from_secs(30));
        let now = Instant::now();
        let _ = s.check_and_insert([0x44u8; 32], now); // populate; first-insert result unused here
        assert_eq!(s.reap(now + Duration::from_secs(5)), 0);
        assert_eq!(s.reap(now + Duration::from_secs(31)), 1);
        assert!(s.is_empty());
    }
}
