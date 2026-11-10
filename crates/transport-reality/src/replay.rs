//! Bridge-side replay-probe set for REALITY-v2.
//!
//! Distinct from [`mirage_discovery::replay::ReplaySet`]:
//! - Discovery `ReplaySet` stores 32-byte `token_id` values (single-use
//!   capability tokens, validity hours to days).
//! - This `ReplayProbeSet` stores `(nonce, timestamp)` pairs from TLS
//!   ClientHellos (validity only while in the freshness window, seconds).
//!
//! The probe set sits at the very edge of the bridge's attack surface -
//! it's consulted once per incoming TCP connection. Capacity must be
//! generous (default 65k entries; tune up at high probe rates), and
//! `check_and_insert` must be O(1) under contention. Thread-safety wraps
//! are the caller's responsibility (single `Mutex` for v0.1; consider
//! sharded for high throughput).

use std::collections::HashMap;

/// Entry key: `(nonce, timestamp)` pair. 16 bytes.
type Key = ([u8; 12], u32);

/// Capacity-bounded replay set for REALITY-v2 auth probes.
pub struct ReplayProbeSet {
    entries: HashMap<Key, u64>, // key -> retention_deadline_unix
    max_entries: usize,
    /// Sticky flag: set true if the most recent `check_and_insert` failed
    /// because the set was full (no expired entries to evict). Used by
    /// callers for operator-metrics differentiation; cleared on the next
    /// successful insert.
    recently_full: bool,
}

impl ReplayProbeSet {
    /// Construct with a hard capacity cap.
    ///
    /// Sizing guidance from spec §4.4:
    /// `max_entries >= expected_probe_rate x 120 s x safety_factor`.
    /// Default `65_536` suits ~540 probes/sec at 2x safety.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
            recently_full: false,
        }
    }

    /// Number of entries currently retained.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True iff no entries are retained.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Evict entries whose retention has passed.
    pub fn evict_expired(&mut self, now_unix: u64) {
        self.entries.retain(|_, deadline| *deadline >= now_unix);
    }

    /// Did the most recent `check_and_insert` reject because the set was full?
    /// Cleared on next successful insert.
    pub fn was_recently_full(&self) -> bool {
        self.recently_full
    }

    /// Check-and-insert. Returns `true` iff this is the first time we've
    /// seen `(nonce, timestamp)` AND the set had capacity.
    ///
    /// If the set is at capacity with no expired entries, returns `false`
    /// and sets `recently_full = true` so the caller can emit a specific
    /// operator metric. Both "replay" and "capacity" failures MUST map to
    /// the same wire behavior (fall through to cover-service); the
    /// distinction is for diagnostics only.
    pub fn check_and_insert(
        &mut self,
        nonce: &[u8; 12],
        timestamp: u32,
        retention_deadline: u64,
        now_unix: u64,
    ) -> bool {
        let key = (*nonce, timestamp);

        if self.entries.contains_key(&key) {
            // Replay. Not a capacity failure.
            self.recently_full = false;
            return false;
        }

        if self.entries.len() >= self.max_entries {
            self.evict_expired(now_unix);
            if self.entries.len() >= self.max_entries {
                self.recently_full = true;
                return false;
            }
        }

        self.entries.insert(key, retention_deadline);
        self.recently_full = false;
        true
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_probe_accepted() {
        let mut rs = ReplayProbeSet::new(16);
        assert!(rs.check_and_insert(&[0u8; 12], 100, 200, 100));
        assert_eq!(rs.len(), 1);
    }

    #[test]
    fn replay_rejected() {
        let mut rs = ReplayProbeSet::new(16);
        assert!(rs.check_and_insert(&[0u8; 12], 100, 200, 100));
        assert!(!rs.check_and_insert(&[0u8; 12], 100, 200, 101));
        assert!(!rs.was_recently_full(), "replay != full");
    }

    #[test]
    fn different_nonces_are_independent() {
        let mut rs = ReplayProbeSet::new(16);
        assert!(rs.check_and_insert(&[0u8; 12], 100, 200, 100));
        assert!(rs.check_and_insert(&[1u8; 12], 100, 200, 100));
        assert!(
            rs.check_and_insert(&[0u8; 12], 101, 200, 100),
            "same nonce different timestamp is distinct"
        );
        assert_eq!(rs.len(), 3);
    }

    #[test]
    fn evict_expired_frees_space() {
        let mut rs = ReplayProbeSet::new(2);
        assert!(rs.check_and_insert(&[0u8; 12], 100, 150, 100)); // expires at 150
        assert!(rs.check_and_insert(&[1u8; 12], 100, 500, 100)); // expires at 500
        assert!(
            !rs.check_and_insert(&[2u8; 12], 100, 500, 100),
            "at capacity"
        );
        assert!(rs.was_recently_full());

        // Advance past entry-0's expiry.
        rs.evict_expired(200);
        assert_eq!(rs.len(), 1);
        assert!(rs.check_and_insert(&[2u8; 12], 100, 500, 200));
        assert!(!rs.was_recently_full(), "reset on successful insert");
    }

    #[test]
    fn check_and_insert_auto_evicts_at_capacity() {
        let mut rs = ReplayProbeSet::new(2);
        assert!(rs.check_and_insert(&[0u8; 12], 100, 150, 100));
        assert!(rs.check_and_insert(&[1u8; 12], 100, 500, 100));
        // Full, but now=200 would evict entry-0 (expires 150).
        assert!(rs.check_and_insert(&[2u8; 12], 100, 500, 200));
    }

    #[test]
    fn recently_full_flag_semantics() {
        let mut rs = ReplayProbeSet::new(1);
        assert!(rs.check_and_insert(&[0u8; 12], 100, 500, 100));
        assert!(!rs.was_recently_full());
        // Full, can't evict.
        assert!(!rs.check_and_insert(&[1u8; 12], 100, 500, 100));
        assert!(rs.was_recently_full());
        // Replay: not a capacity issue; flag clears.
        assert!(!rs.check_and_insert(&[0u8; 12], 100, 500, 100));
        assert!(!rs.was_recently_full());
    }
}
