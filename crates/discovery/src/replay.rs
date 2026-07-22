//! Bridge-side token replay set.
//!
//! Enforces the single-use property of capability tokens (spec §02 §11.3
//! step 6-7). A bridge maintains one instance across all concurrent
//! handshakes and consults it via [`ReplaySet::check_and_insert`].
//!
//! Evicts entries once their recorded expiry has passed (plus the
//! `grace_seconds` the bridge allowed). This bounds memory while
//! preserving the replay-rejection property for the token's entire
//! acceptance window.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::replay_log::{PersistentReplayLog, ReplayLogError};

/// A bounded-capacity replay set keyed by token_id.
///
/// Thread-safety note: this struct is not inherently `Sync`. Bridge daemons
/// with concurrent handshakes should use [`SyncReplaySet`] (a wrapper that
/// takes `&self` and locks internally) or a sharded variant (v0.2).
pub struct ReplaySet {
    entries: HashMap<[u8; 32], u64>, // token_id -> expiry (inclusive)
    max_entries: usize,
    /// Optional append-only disk log. When `Some`, every successful
    /// `check_and_insert` mirrors the record to disk BEFORE
    /// returning `true`. A disk-write failure rolls back the
    /// in-memory accept and surfaces as replay rejection - the
    /// bridge would rather refuse a legitimate client than grant a
    /// token without durable replay protection.
    log: Option<PersistentReplayLog>,
}

impl ReplaySet {
    /// Construct a new replay set with a hard cap on entry count.
    ///
    /// `max_entries` bounds memory. If the set hits the cap, inserts evict
    /// one expired entry before accepting; if no entries are expired, the
    /// insert is refused (returning `false` from `check_and_insert`),
    /// which manifests as a denial-of-service for legitimate clients. Set
    /// this generously (>= `expected_handshake_rate x token_lifetime` with
    /// healthy margin).
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
            log: None,
        }
    }

    /// Construct a replay set backed by a persistent append-only
    /// log. On startup, every unexpired `(token_id, expires_at)`
    /// record in the log is restored into the in-memory set, then
    /// the log is compacted in place. Every subsequent
    /// successful `check_and_insert` appends to the log before
    /// returning `true`.
    ///
    /// Bridge-restart behavior: the A14b invariant (accepted
    /// capability tokens stay blocked across reboot) holds for the
    /// token's entire acceptance window, not just the bridge's
    /// uptime window.
    ///
    /// # Over-capacity restore (finding #16)
    ///
    /// If the persisted log holds MORE unexpired records than
    /// `max_entries`, we cannot restore all of them. Dropping an
    /// arbitrary subset would let some still-valid burned tokens be
    /// replayed after restart, breaking single-use (A14b). We therefore
    /// retain the entries with the LATEST expiry (the longest remaining
    /// replay window - the most dangerous to drop) and log the
    /// truncation at ERROR level, since it reopens a replay window for
    /// the dropped tokens until their original expiry. The full set stays
    /// on disk (the log is compacted, not truncated), so raising
    /// `max_entries` and restarting recovers them. Operators who need a
    /// hard guarantee should size `max_entries` so this branch never
    /// fires (>= `handshake_rate x token_lifetime` with margin) rather
    /// than treat truncation as normal.
    pub fn new_with_log(
        max_entries: usize,
        log: PersistentReplayLog,
        now_unix: u64,
    ) -> Result<Self, ReplayLogError> {
        let path = log.path().to_path_buf();
        let fsync = log.fsync_every_write();
        let mut entries = PersistentReplayLog::load(&path, now_unix)?;
        // Drop the pre-compact handle before rename; POSIX is
        // tolerant, Windows would reject rename-over-open.
        drop(log);
        // Compact the FULL unexpired set to disk before any in-memory
        // truncation, so an over-capacity restore never loses durable
        // records - only the in-memory working set is bounded.
        PersistentReplayLog::compact(&path, &entries)?;
        let fresh = PersistentReplayLog::open(&path, fsync)?;

        let mut rs = Self {
            entries: HashMap::new(),
            max_entries,
            log: Some(fresh),
        };
        // Finding #16: if the log holds more unexpired records than we can
        // retain, we MUST NOT drop a hash-unordered arbitrary subset - that
        // would let an arbitrary set of still-valid burned tokens be replayed
        // after restart, defeating single-use (A14b). Order by expiry DESCENDING
        // and keep the highest-expiry entries (longest remaining replay window,
        // most dangerous to drop); truncation then only discards the shortest-
        // lived burns.
        if entries.len() > max_entries {
            entries.sort_unstable_by(|a, b| b.1.cmp(&a.1));
            tracing::error!(
                persisted = entries.len(),
                max_entries,
                dropped = entries.len() - max_entries,
                "replay log holds more unexpired records than max_entries; \
                 retaining the highest-expiry entries and dropping the rest - \
                 this reopens a replay window for the dropped tokens until their \
                 original expiry. Raise max_entries to close it."
            );
            entries.truncate(max_entries);
        }
        for (tid, exp) in &entries {
            // Direct insert; skips both the log append (we're
            // restoring, not accepting) and the capacity check
            // (already bounded above).
            rs.entries.insert(*tid, *exp);
        }
        Ok(rs)
    }

    /// Number of entries currently retained.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True iff no entries are retained.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Evict entries whose expiry (plus grace) has passed. Called
    /// opportunistically by `check_and_insert` and can also be called
    /// periodically from a bridge maintenance loop.
    pub fn evict_expired(&mut self, now_unix: u64) {
        self.entries.retain(|_, expiry| *expiry >= now_unix);
    }

    /// Remove one entry. Used by the persistent-log wrapper to roll
    /// back an in-memory accept when the disk write fails. Returns
    /// `true` if an entry was actually removed.
    pub fn remove(&mut self, token_id: &[u8; 32]) -> bool {
        self.entries.remove(token_id).is_some()
    }

    /// Peek without inserting. Returns `true` iff `token_id` is
    /// currently in the set AND its expiry has not lapsed.
    /// Closes RT-CR-1 - `already_burned` callers can now check
    /// without polluting the set.
    pub fn contains(&self, token_id: &[u8; 32], now_unix: u64) -> bool {
        match self.entries.get(token_id) {
            Some(expiry) => *expiry >= now_unix,
            None => false,
        }
    }

    /// Check if `token_id` has been seen, and insert it if not.
    ///
    /// Returns `true` if the token is accepted (first use); `false` if it
    /// was already seen (replay) or if the set is full and cannot make room.
    ///
    /// `expires_at` is the token's own expiry - used as the replay-set
    /// retention bound for this entry.
    pub fn check_and_insert(
        &mut self,
        token_id: &[u8; 32],
        expires_at: u64,
        now_unix: u64,
    ) -> bool {
        // Replay check first.
        if self.entries.contains_key(token_id) {
            return false;
        }

        // If at capacity, try to free room by evicting expired entries.
        if self.entries.len() >= self.max_entries {
            self.evict_expired(now_unix);
            if self.entries.len() >= self.max_entries {
                return false;
            }
        }

        self.entries.insert(*token_id, expires_at);

        // Persist to disk, if configured. Durability happens INSIDE
        // the same critical section as the in-memory accept, so a
        // crash between "set says accepted" and "log says accepted"
        // is not possible under Rust semantics. A write failure
        // rolls back the in-memory acceptance - denying a
        // legitimate client is preferable to granting a token
        // without durable replay protection.
        if let Some(log) = self.log.as_mut() {
            if let Err(e) = log.append(token_id, expires_at) {
                self.entries.remove(token_id);
                tracing::error!(error = %e, "replay log append failed; rolling back");
                return false;
            }
        }
        true
    }
}

/// Thread-safe wrapper around [`ReplaySet`] using `std::sync::Mutex`.
///
/// A bridge daemon handling concurrent handshakes shares one
/// `Arc<SyncReplaySet>` across tasks; every method takes `&self` and
/// locks internally, so callers do not need to thread the mutex guard
/// through the handshake state machine.
///
/// # Why `std::sync::Mutex` and not `tokio::sync::Mutex`?
///
/// The critical section is a handful of HashMap operations (~hundreds of
/// nanoseconds). `tokio::sync::Mutex` is designed for holding a lock
/// across `.await`, at the cost of ~10x the overhead of `std::sync::Mutex`
/// for uncontended acquire/release. A replay-set lookup never yields, so
/// the async mutex buys nothing and costs every probe. If a future
/// implementation moves replay checks behind a network call, revisit.
///
/// # Poisoning
///
/// If a caller panics while holding the lock, we intentionally propagate
/// the poison - every subsequent `check_and_insert` returns `false`. The
/// reasoning: a panic inside the replay check means the invariant is
/// broken; silently continuing could let a replay through. The bridge
/// daemon's supervisor should restart the process on poisoning.
pub struct SyncReplaySet {
    inner: Mutex<ReplaySet>,
}

impl SyncReplaySet {
    /// Construct a new shared replay set. See [`ReplaySet::new`].
    pub fn new(max_entries: usize) -> Self {
        Self {
            inner: Mutex::new(ReplaySet::new(max_entries)),
        }
    }

    /// Construct a replay set backed by a persistent append-only
    /// log. See [`ReplaySet::new_with_log`]; this wrapper only adds
    /// the internal `Mutex`.
    pub fn with_log(
        max_entries: usize,
        log: PersistentReplayLog,
        now_unix: u64,
    ) -> Result<Self, ReplayLogError> {
        let rs = ReplaySet::new_with_log(max_entries, log, now_unix)?;
        Ok(Self {
            inner: Mutex::new(rs),
        })
    }

    /// Number of entries currently retained. Acquires the lock.
    ///
    /// On a poisoned mutex, returns `0` rather than panicking. This is a
    /// **safe lie**: the value is only used for operator metrics and
    /// debug assertions, never for access-control decisions. If you
    /// need authoritative state, restart the process - a poisoned
    /// mutex means an invariant was already broken.
    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// True iff no entries are retained. Acquires the lock.
    ///
    /// On a poisoned mutex, returns `true`. Same rationale as [`len`]:
    /// metrics-only, never a security predicate.
    ///
    /// [`len`]: Self::len
    pub fn is_empty(&self) -> bool {
        self.inner.lock().map(|g| g.is_empty()).unwrap_or(true)
    }

    /// Evict expired entries. Acquires the lock.
    pub fn evict_expired(&self, now_unix: u64) {
        if let Ok(mut g) = self.inner.lock() {
            g.evict_expired(now_unix);
        }
    }

    /// Check-and-insert. Returns `false` on replay, capacity
    /// exhaustion, a poisoned mutex, or (when backed by a
    /// persistent log) a disk-write failure. Acquires the lock.
    pub fn check_and_insert(&self, token_id: &[u8; 32], expires_at: u64, now_unix: u64) -> bool {
        match self.inner.lock() {
            Ok(mut g) => g.check_and_insert(token_id, expires_at, now_unix),
            // Poisoned: fail closed. See struct-level docs.
            Err(_) => false,
        }
    }

    /// Peek without inserting. Returns `true` iff `token_id` is
    /// present AND fresh. Closes RT-CR-1.
    pub fn contains(&self, token_id: &[u8; 32], now_unix: u64) -> bool {
        match self.inner.lock() {
            Ok(g) => g.contains(token_id, now_unix),
            // Poisoned: same fail-closed posture as check_and_insert.
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_use_accepted() {
        let mut rs = ReplaySet::new(16);
        assert!(rs.check_and_insert(&[0u8; 32], 1000, 500));
    }

    #[test]
    fn replay_rejected() {
        let mut rs = ReplaySet::new(16);
        assert!(rs.check_and_insert(&[0u8; 32], 1000, 500));
        assert!(!rs.check_and_insert(&[0u8; 32], 1000, 501));
    }

    #[test]
    fn different_token_ids_independent() {
        let mut rs = ReplaySet::new(16);
        assert!(rs.check_and_insert(&[0u8; 32], 1000, 500));
        assert!(rs.check_and_insert(&[1u8; 32], 1000, 500));
        assert!(!rs.check_and_insert(&[0u8; 32], 1000, 500));
        assert!(!rs.check_and_insert(&[1u8; 32], 1000, 500));
    }

    #[test]
    fn evict_expired_frees_space() {
        let mut rs = ReplaySet::new(2);
        assert!(rs.check_and_insert(&[0u8; 32], 500, 0));
        assert!(rs.check_and_insert(&[1u8; 32], 2000, 0));
        // Full; no expiries at now=0.
        assert!(!rs.check_and_insert(&[2u8; 32], 2000, 0));
        // Advance past token0's expiry.
        rs.evict_expired(1000);
        // Room for a new entry.
        assert!(rs.check_and_insert(&[2u8; 32], 2000, 1000));
        assert_eq!(rs.len(), 2);
    }

    #[test]
    fn check_and_insert_auto_evicts_at_capacity() {
        let mut rs = ReplaySet::new(2);
        assert!(rs.check_and_insert(&[0u8; 32], 500, 0));
        assert!(rs.check_and_insert(&[1u8; 32], 2000, 0));
        // At capacity; token 0 is expired at now=1000, so auto-evict frees room.
        assert!(rs.check_and_insert(&[2u8; 32], 2000, 1000));
    }

    #[test]
    fn rejects_when_full_and_no_expired() {
        let mut rs = ReplaySet::new(2);
        assert!(rs.check_and_insert(&[0u8; 32], 2000, 0));
        assert!(rs.check_and_insert(&[1u8; 32], 2000, 0));
        // Full, nothing expired.
        assert!(!rs.check_and_insert(&[2u8; 32], 2000, 100));
    }

    // ---- SyncReplaySet ----

    #[test]
    fn sync_rejects_replay() {
        let rs = SyncReplaySet::new(16);
        assert!(rs.check_and_insert(&[0u8; 32], 1000, 500));
        assert!(!rs.check_and_insert(&[0u8; 32], 1000, 501));
    }

    #[test]
    fn sync_concurrent_single_winner() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        // 32 threads race to insert the same token_id. Exactly one must
        // win; the other 31 must all see a replay rejection. This is the
        // property that fails if the set were behind an RwLock where a
        // window between contains_key and insert leaves a TOCTOU hole.
        const THREADS: usize = 32;
        let rs = Arc::new(SyncReplaySet::new(64));
        let barrier = Arc::new(Barrier::new(THREADS));
        let mut handles = Vec::with_capacity(THREADS);
        for _ in 0..THREADS {
            let rs = Arc::clone(&rs);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                rs.check_and_insert(&[7u8; 32], 1_000, 0)
            }));
        }
        let wins: usize = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|b| *b)
            .count();
        assert_eq!(wins, 1, "exactly one thread must win the race");
        assert_eq!(rs.len(), 1);
    }

    #[test]
    fn sync_distinct_ids_all_accepted_concurrently() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        // Concurrent inserts of *distinct* token_ids must all succeed.
        const THREADS: usize = 32;
        let rs = Arc::new(SyncReplaySet::new(64));
        let barrier = Arc::new(Barrier::new(THREADS));
        let mut handles = Vec::with_capacity(THREADS);
        for i in 0..THREADS {
            let rs = Arc::clone(&rs);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let mut id = [0u8; 32];
                id[0] = i as u8;
                barrier.wait();
                rs.check_and_insert(&id, 1_000, 0)
            }));
        }
        let wins: usize = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|b| *b)
            .count();
        assert_eq!(wins, THREADS);
        assert_eq!(rs.len(), THREADS);
    }

    // ---- SyncReplaySet + PersistentReplayLog integration ----

    #[test]
    fn with_log_persists_accepts_across_reopen() {
        // Simulates a bridge restart: accept a token, drop the
        // replay set (closes the log file), reopen with the same
        // path. The token id must still be rejected on the re-use
        // attempt - the A14b invariant this whole module exists to
        // deliver.
        let d = tempfile::TempDir::new().unwrap();
        let p = d.path().join("rl");
        let now = 1_000;
        let exp = 5_000;
        let tid = [0x42u8; 32];

        {
            let log = PersistentReplayLog::open(&p, false).unwrap();
            let rs = SyncReplaySet::with_log(64, log, now).unwrap();
            assert!(rs.check_and_insert(&tid, exp, now), "first use accepted");
            assert!(
                !rs.check_and_insert(&tid, exp, now),
                "replay rejected in-memory"
            );
        } // rs drops -> log closes

        // "Restart": fresh open, fresh SyncReplaySet over the same file.
        let log2 = PersistentReplayLog::open(&p, false).unwrap();
        let rs2 = SyncReplaySet::with_log(64, log2, now).unwrap();
        assert!(
            !rs2.check_and_insert(&tid, exp, now),
            "replay rejected after restart - A14b closed"
        );
        assert_eq!(rs2.len(), 1);
    }

    #[test]
    fn with_log_drops_expired_on_restart() {
        // An entry whose expiry predates `now_unix` at load time
        // should NOT be restored - otherwise the replay set would
        // grow unboundedly over long uptime.
        let d = tempfile::TempDir::new().unwrap();
        let p = d.path().join("rl");

        {
            let log = PersistentReplayLog::open(&p, false).unwrap();
            let rs = SyncReplaySet::with_log(64, log, 100).unwrap();
            assert!(rs.check_and_insert(&[0x01u8; 32], 200, 100));
            assert!(rs.check_and_insert(&[0x02u8; 32], 5_000, 100));
        }

        // Load at now=1000: the first entry (exp=200) is already gone.
        let log2 = PersistentReplayLog::open(&p, false).unwrap();
        let rs2 = SyncReplaySet::with_log(64, log2, 1_000).unwrap();
        assert_eq!(rs2.len(), 1);
        // The expired id can be re-accepted (it's past its TTL
        // and the token itself would be rejected by the caller's
        // `is_expired` check before reaching here anyway).
        assert!(rs2.check_and_insert(&[0x01u8; 32], 5_000, 1_000));
        // The unexpired one remains replay-blocked.
        assert!(!rs2.check_and_insert(&[0x02u8; 32], 5_000, 1_000));
    }

    #[test]
    fn with_log_restore_keeps_highest_expiry_when_over_cap() {
        // Finding #16: when the persisted log holds MORE unexpired records than
        // max_entries, restore must retain the entries with the LATEST expiry
        // (longest remaining replay window). Dropping those would let a still-
        // valid burned token be replayed after restart (A14b regression).
        let d = tempfile::TempDir::new().unwrap();
        let p = d.path().join("rl");
        let now = 1_000;

        {
            let log = PersistentReplayLog::open(&p, false).unwrap();
            let rs = SyncReplaySet::with_log(64, log, now).unwrap();
            // 5 unexpired tokens; token i has expiry 2000 + i*1000, so token 4
            // has the latest expiry and token 0 the earliest.
            for i in 0..5u8 {
                let mut tid = [0u8; 32];
                tid[0] = i;
                assert!(rs.check_and_insert(&tid, 2_000 + (i as u64) * 1_000, now));
            }
        }

        // "Restart" with max_entries = 2: only the 2 highest-expiry tokens
        // (i = 3 and i = 4) must be retained; the low-expiry ones are dropped.
        let log2 = PersistentReplayLog::open(&p, false).unwrap();
        let rs2 = ReplaySet::new_with_log(2, log2, now).unwrap();
        assert_eq!(rs2.len(), 2, "restore truncated to max_entries");

        let tid = |i: u8| {
            let mut t = [0u8; 32];
            t[0] = i;
            t
        };
        // The two highest-expiry burns are still blocked (most dangerous to drop).
        assert!(rs2.contains(&tid(4), now), "highest-expiry token retained");
        assert!(
            rs2.contains(&tid(3), now),
            "2nd-highest-expiry token retained"
        );
        // The lowest-expiry burns were the ones sacrificed.
        assert!(!rs2.contains(&tid(0), now), "lowest-expiry token dropped");
        assert!(!rs2.contains(&tid(1), now), "low-expiry token dropped");
    }

    #[test]
    fn with_log_bad_header_is_surfaced() {
        let d = tempfile::TempDir::new().unwrap();
        let p = d.path().join("rl");
        std::fs::write(&p, b"XXXX\x00\x00\x00\x00").unwrap();
        match PersistentReplayLog::open(&p, false) {
            Err(ReplayLogError::BadHeader) => {}
            Ok(_) => panic!("expected BadHeader"),
            Err(e) => panic!("wrong error: {e}"),
        }
    }

    #[test]
    fn sync_poisoned_mutex_fails_closed() {
        use std::sync::Arc;
        use std::thread;

        let rs = Arc::new(SyncReplaySet::new(16));
        // Poison the inner mutex by panicking while holding it.
        let rs_clone = Arc::clone(&rs);
        let _ = thread::spawn(move || {
            let _guard = rs_clone.inner.lock().expect("acquire");
            panic!("intentional panic to poison the mutex");
        })
        .join();

        // After poisoning, check_and_insert must return false (fail-closed).
        assert!(!rs.check_and_insert(&[0u8; 32], 1000, 500));
        // Reads similarly yield safe defaults.
        assert_eq!(rs.len(), 0);
        assert!(rs.is_empty());
    }
}
