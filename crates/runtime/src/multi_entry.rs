//! Multi-entry cooperative routing - Mirage's headline feature.
//!
//! # Why
//!
//! Tor's guard model has the "single-IP-at-a-time" weakness: a
//! client uses ONE guard at a time, so blocking that guard's IP
//! cuts off the client until they discover and roll to a new
//! guard. Mirage addresses this differently: a client maintains
//! **multiple entry bridges simultaneously**, each over its own
//! Mirage session (potentially over different transports).
//! Application streams are distributed across entries. If a
//! censor blocks one entry's IP, others keep flowing without
//! the client noticing.
//!
//! The "entry pool" is the unit of resilience, not the
//! individual entry. Operators run cohorts of entries that
//! cooperate (shared cohort manifest, shared reveal-cap counter
//! via [`mirage_discovery::RevealStore`], optionally shared
//! cover-traffic budgets) so a client connecting to ANY entry
//! in the cohort gets the same security properties.
//!
//! # Architecture
//!
//! ```text
//!                  +-- entry_A (reality-v2) --+
//!  client ---------+-- entry_B (obfs-tcp)   --+-- relay -- exit -- destination
//!                  +-- entry_C (masque)     --+
//! ```
//!
//! Each entry is reached over a potentially different transport
//! ("multi-protocol"). The cohort backing all three entries
//! shares an operator key + reveal-store, so a token issued to
//! the client is accepted by any cohort member without that
//! member having to coordinate with peers at request time.
//!
//! # 3-hop max
//!
//! Mirage caps circuit chains at 3 hops (entry, relay, exit).
//! Beyond 3, additional anonymity comes from POOL diversity,
//! not chain depth - the client uses MULTIPLE 3-hop circuits
//! through DIFFERENT entries simultaneously.
//!
//! # Failure semantics
//!
//! - **Soft failure**: entry's session breaks mid-stream -> the
//!   stream fails; subsequent streams pick a different entry.
//! - **Hard failure**: an entry has accumulated N failures in
//!   the recent window -> the entry is retired from the pool
//!   until the operator publishes a fresh announcement.
//! - **Cohort wipeout**: ALL entries fail -> the client falls
//!   back to discovery to find new entries (Phase 3C work).

use crate::HopRuntime;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Mutex;

/// Configuration knobs for a multi-entry pool.
#[derive(Debug, Clone)]
pub struct MultiEntryConfig {
    /// Minimum number of healthy entries the pool tries to
    /// maintain. If below this, a background refill task dials
    /// fresh entries from the discovery catalogue. Default 3.
    pub min_entries: usize,
    /// Maximum simultaneous entries. Caps memory + handshake
    /// load. Default 5.
    pub max_entries: usize,
    /// Sliding window over which entry failures are counted.
    /// Failures older than this don't count toward
    /// `failure_threshold`. Default 5 minutes.
    pub failure_window: Duration,
    /// Number of failures within `failure_window` before an
    /// entry is retired. Default 3.
    pub failure_threshold: u32,
}

impl Default for MultiEntryConfig {
    fn default() -> Self {
        Self {
            min_entries: 3,
            max_entries: 5,
            failure_window: Duration::from_secs(5 * 60),
            failure_threshold: 3,
        }
    }
}

/// Errors from the multi-entry pool.
#[derive(Debug, Error)]
pub enum MultiEntryError {
    /// All entries in the pool have failed and the catalogue
    /// has no replacements. The client SHOULD fall back to
    /// discovery to find new operators / cohorts.
    #[error("all entries failed; cohort exhausted")]
    CohortExhausted,
    /// The pool is configured for `min_entries > max_entries`.
    #[error("invalid config: min={min} > max={max}")]
    InvalidConfig {
        /// Min from config.
        min: usize,
        /// Max from config.
        max: usize,
    },
}

/// Per-entry health bookkeeping. Wraps a runtime conn handle +
/// a sliding-window failure counter.
struct EntryHealth {
    /// Stable, process-unique handle assigned at registration and
    /// never reused. Callers hold this across the `pick_entry` ->
    /// `mark_failure` lock gap; using it (instead of the Vec index)
    /// means a concurrent `reap_retired` that compacts the Vec can
    /// never cause a failure to be attributed to the wrong entry.
    id: u64,
    /// Identity of this entry. Used for diagnostics + cohort
    /// reveal-counter keying.
    name: String,
    /// Times within the failure window. Drained on tick.
    recent_failures: Vec<std::time::Instant>,
    /// True if the entry has been retired (failure threshold
    /// hit). Retired entries stay in the pool until tick reaps
    /// them - this lets in-flight requests finish gracefully.
    retired: bool,
}

impl EntryHealth {
    fn new(id: u64, name: String) -> Self {
        Self {
            id,
            name,
            recent_failures: Vec::new(),
            retired: false,
        }
    }

    fn record_failure(&mut self, now: std::time::Instant, window: Duration) {
        // Drop expired failures, then push.
        self.recent_failures
            .retain(|t| now.saturating_duration_since(*t) <= window);
        self.recent_failures.push(now);
    }

    fn failure_count(&self, now: std::time::Instant, window: Duration) -> u32 {
        self.recent_failures
            .iter()
            .filter(|t| now.saturating_duration_since(**t) <= window)
            .count() as u32
    }
}

/// A pool of concurrent entry bridges. The client picks an
/// entry per stream; failures retire entries; min-entries
/// refilling keeps the pool healthy.
///
/// `H` is a [`HopRuntime`] - the same trait `build_circuit`
/// uses. The pool builds full circuits THROUGH each entry; this
/// type just orchestrates which circuit a stream binds to.
pub struct MultiEntryPool<H: HopRuntime> {
    _runtime: Arc<H>,
    inner: Arc<Mutex<MultiEntryInner>>,
    config: MultiEntryConfig,
}

impl<H: HopRuntime> std::fmt::Debug for MultiEntryPool<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiEntryPool")
            .field("config", &self.config)
            .field("inner", &"<locked>")
            .finish()
    }
}

struct MultiEntryInner {
    entries: Vec<EntryHealth>,
    /// Round-robin cursor. Stream `i` picks entries[i %
    /// `healthy.len()`] when healthy is non-empty.
    cursor: usize,
    /// Monotonic source of stable [`EntryHealth::id`] handles.
    /// Never wraps in practice (a pool would exhaust memory long
    /// before 2^64 registrations).
    next_id: u64,
}

impl<H: HopRuntime> MultiEntryPool<H> {
    /// Construct.
    pub fn new(runtime: Arc<H>, config: MultiEntryConfig) -> Result<Self, MultiEntryError> {
        if config.min_entries > config.max_entries {
            return Err(MultiEntryError::InvalidConfig {
                min: config.min_entries,
                max: config.max_entries,
            });
        }
        Ok(Self {
            _runtime: runtime,
            inner: Arc::new(Mutex::new(MultiEntryInner {
                entries: Vec::new(),
                cursor: 0,
                next_id: 0,
            })),
            config,
        })
    }

    /// Register a freshly-established entry. Called after the
    /// caller dials a bridge + verifies the session handshake.
    /// The pool tracks the entry's health; the caller retains
    /// ownership of the connection handle.
    pub async fn register_entry(&self, name: String) {
        let mut g = self.inner.lock().await;
        if g.entries.len() < self.config.max_entries {
            let id = g.next_id;
            g.next_id += 1;
            g.entries.push(EntryHealth::new(id, name));
        }
    }

    /// Pick the next healthy entry by round-robin. Returns
    /// `None` if no entries are healthy. The returned value is the
    /// entry's stable [`EntryHealth::id`] handle - pass it back to
    /// [`mark_failure`](Self::mark_failure). It is deliberately NOT
    /// a Vec index: a concurrent [`reap_retired`](Self::reap_retired)
    /// compacts the Vec and would shift indices out from under a
    /// caller holding one across the lock gap.
    pub async fn pick_entry(&self) -> Option<u64> {
        let mut g = self.inner.lock().await;
        let n = g.entries.len();
        if n == 0 {
            return None;
        }
        // Probe up to n entries starting at cursor; return the
        // first non-retired one.
        for offset in 0..n {
            let idx = (g.cursor + offset) % n;
            if !g.entries[idx].retired {
                g.cursor = (idx + 1) % n;
                return Some(g.entries[idx].id);
            }
        }
        None
    }

    /// Record a failure on the entry identified by the stable `id`
    /// handle returned from [`pick_entry`](Self::pick_entry). After
    /// `failure_threshold` failures within `failure_window`, the
    /// entry is marked retired. If the entry has already been reaped
    /// (its id no longer resolves) this is a no-op - crucially, the
    /// failure is never mis-attributed to a different entry that has
    /// since taken the reaped entry's old Vec slot.
    pub async fn mark_failure(&self, id: u64) {
        let mut g = self.inner.lock().await;
        let now = std::time::Instant::now();
        let window = self.config.failure_window;
        if let Some(entry) = g.entries.iter_mut().find(|e| e.id == id) {
            entry.record_failure(now, window);
            if entry.failure_count(now, window) >= self.config.failure_threshold {
                entry.retired = true;
                tracing::warn!(
                    name = %entry.name,
                    "MultiEntryPool: entry retired after exceeding failure threshold"
                );
            }
        }
    }

    /// Count healthy (non-retired) entries.
    pub async fn healthy_count(&self) -> usize {
        let g = self.inner.lock().await;
        g.entries.iter().filter(|e| !e.retired).count()
    }

    /// Total entries (healthy + retired). Used to decide
    /// whether to refill.
    pub async fn total_count(&self) -> usize {
        let g = self.inner.lock().await;
        g.entries.len()
    }

    /// True iff the pool's healthy-count is below
    /// `min_entries`. Caller's refill task should dial more.
    pub async fn needs_refill(&self) -> bool {
        self.healthy_count().await < self.config.min_entries
    }

    /// Sweep retired entries. Called periodically by the
    /// caller's tick loop. Returns the number reaped.
    pub async fn reap_retired(&self) -> usize {
        let mut g = self.inner.lock().await;
        let before = g.entries.len();
        g.entries.retain(|e| !e.retired);
        before - g.entries.len()
    }

    /// Diagnostic snapshot of entry names + retired flags.
    pub async fn snapshot(&self) -> Vec<(String, bool)> {
        let g = self.inner.lock().await;
        g.entries
            .iter()
            .map(|e| (e.name.clone(), e.retired))
            .collect()
    }

    /// True iff every entry in a non-empty pool is retired -
    /// **cohort wipeout**. The caller MUST react: either dial
    /// fresh entries from discovery (preferred) or call
    /// [`attempt_recovery`](Self::attempt_recovery) to re-arm
    /// existing entries after a cool-down (fallback when
    /// discovery is unreachable). Closes RT-ME-3 - without this
    /// API the pool would deadlock at zero healthy entries
    /// forever.
    pub async fn is_wiped_out(&self) -> bool {
        let g = self.inner.lock().await;
        !g.entries.is_empty() && g.entries.iter().all(|e| e.retired)
    }

    /// Probationary recovery: clear the `retired` flag on any
    /// entry whose most-recent failure was longer ago than
    /// `min_age`, AND clear that entry's failure-window history.
    /// Returns the number of entries un-retired.
    ///
    /// Caller's tick loop SHOULD call this when [`is_wiped_out`]
    /// returns true AND no fresh discovery replacements are
    /// available. The cool-down avoids hot-looping retries on
    /// genuinely-broken entries.
    pub async fn attempt_recovery(&self, min_age: Duration) -> usize {
        let mut g = self.inner.lock().await;
        let now = std::time::Instant::now();
        let mut recovered = 0usize;
        for entry in &mut g.entries {
            if !entry.retired {
                continue;
            }
            let last_fail = entry.recent_failures.iter().copied().max();
            let eligible = match last_fail {
                Some(t) => now.saturating_duration_since(t) >= min_age,
                None => true,
            };
            if eligible {
                entry.retired = false;
                entry.recent_failures.clear();
                recovered += 1;
                tracing::info!(
                    name = %entry.name,
                    "MultiEntryPool: entry un-retired after cool-down"
                );
            }
        }
        recovered
    }

    /// Emergency reset: clear `retired` on EVERY entry + drop
    /// all failure history. Caller invokes this when the cohort
    /// is wiped out, no fresh discovery exists, AND the wait for
    /// natural recovery via [`attempt_recovery`] isn't
    /// acceptable. Use sparingly - it makes the pool retry
    /// entries that previously failed hard.
    pub async fn force_reset_health(&self) {
        let mut g = self.inner.lock().await;
        for entry in &mut g.entries {
            entry.retired = false;
            entry.recent_failures.clear();
        }
        g.cursor = 0;
        tracing::warn!("MultiEntryPool: emergency reset of all entry health");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockHopRuntime;

    fn rt() -> Arc<MockHopRuntime> {
        Arc::new(MockHopRuntime::new(vec![]))
    }

    #[tokio::test]
    async fn pool_starts_empty_and_needs_refill() {
        let pool = MultiEntryPool::new(rt(), MultiEntryConfig::default()).unwrap();
        assert_eq!(pool.healthy_count().await, 0);
        assert!(pool.needs_refill().await);
        assert!(pool.pick_entry().await.is_none());
    }

    #[tokio::test]
    async fn pool_round_robin_picks_each_entry_once() {
        let pool = MultiEntryPool::new(rt(), MultiEntryConfig::default()).unwrap();
        pool.register_entry("entry-A".into()).await;
        pool.register_entry("entry-B".into()).await;
        pool.register_entry("entry-C".into()).await;
        let mut picks = Vec::new();
        for _ in 0..3 {
            picks.push(pool.pick_entry().await.unwrap());
        }
        // Round-robin: each entry gets picked exactly once in
        // 3 calls (in some order).
        picks.sort_unstable();
        assert_eq!(picks, vec![0, 1, 2]);
    }

    #[tokio::test]
    async fn pool_retires_entry_after_failure_threshold() {
        let config = MultiEntryConfig {
            failure_threshold: 2,
            ..Default::default()
        };
        let pool = MultiEntryPool::new(rt(), config).unwrap();
        pool.register_entry("entry-A".into()).await;
        pool.register_entry("entry-B".into()).await;
        // 2 failures on entry 0 -> retired.
        pool.mark_failure(0).await;
        pool.mark_failure(0).await;
        // 4 picks: each should return entry 1 (the only healthy).
        for _ in 0..4 {
            assert_eq!(pool.pick_entry().await, Some(1));
        }
        assert_eq!(pool.healthy_count().await, 1);
    }

    #[tokio::test]
    async fn pool_returns_none_when_all_retired() {
        let config = MultiEntryConfig {
            failure_threshold: 1,
            ..Default::default()
        };
        let pool = MultiEntryPool::new(rt(), config).unwrap();
        pool.register_entry("entry-A".into()).await;
        pool.register_entry("entry-B".into()).await;
        pool.mark_failure(0).await;
        pool.mark_failure(1).await;
        assert!(pool.pick_entry().await.is_none());
        assert_eq!(pool.healthy_count().await, 0);
    }

    #[tokio::test]
    async fn pool_reap_retired_compacts_after_failures() {
        let config = MultiEntryConfig {
            failure_threshold: 1,
            ..Default::default()
        };
        let pool = MultiEntryPool::new(rt(), config).unwrap();
        pool.register_entry("entry-A".into()).await;
        pool.register_entry("entry-B".into()).await;
        pool.register_entry("entry-C".into()).await;
        pool.mark_failure(0).await;
        pool.mark_failure(2).await;
        assert_eq!(pool.healthy_count().await, 1);
        assert_eq!(pool.reap_retired().await, 2);
        assert_eq!(pool.total_count().await, 1);
    }

    // Regression (RT-ME race): a handle held across a reap must
    // still resolve to its own entry, and a stale handle to a
    // reaped entry must NOT be mis-attributed to whichever entry
    // now occupies the old Vec slot.
    #[tokio::test]
    async fn pool_handle_is_stable_across_reap() {
        let config = MultiEntryConfig {
            failure_threshold: 1,
            ..Default::default()
        };
        let pool = MultiEntryPool::new(rt(), config).unwrap();
        pool.register_entry("entry-A".into()).await; // id 0
        pool.register_entry("entry-B".into()).await; // id 1
        pool.register_entry("entry-C".into()).await; // id 2

        // Retire A (id 0) and C (id 2), then reap. B (id 1) is now
        // compacted from Vec index 1 down to index 0.
        pool.mark_failure(0).await;
        pool.mark_failure(2).await;
        assert_eq!(pool.reap_retired().await, 2);
        assert_eq!(pool.total_count().await, 1);

        // A stale handle to the reaped entry-A (id 0) must be a
        // no-op: it must NOT retire entry-B, which now sits where
        // entry-A used to be at Vec index 0.
        pool.mark_failure(0).await;
        assert_eq!(pool.healthy_count().await, 1);
        assert!(pool.pick_entry().await.is_some());

        // The live handle for entry-B (id 1) must still resolve to
        // entry-B even though its index changed.
        pool.mark_failure(1).await;
        assert_eq!(pool.healthy_count().await, 0);
        assert!(pool.pick_entry().await.is_none());
        let snap = pool.snapshot().await;
        assert_eq!(snap, vec![("entry-B".to_string(), true)]);
    }

    #[tokio::test]
    async fn pool_rejects_invalid_config() {
        let bad = MultiEntryConfig {
            min_entries: 5,
            max_entries: 3,
            ..Default::default()
        };
        let err = MultiEntryPool::new(rt(), bad).unwrap_err();
        assert!(matches!(err, MultiEntryError::InvalidConfig { .. }));
    }

    #[tokio::test]
    async fn pool_max_entries_caps_registration() {
        let config = MultiEntryConfig {
            min_entries: 1,
            max_entries: 2,
            ..Default::default()
        };
        let pool = MultiEntryPool::new(rt(), config).unwrap();
        pool.register_entry("A".into()).await;
        pool.register_entry("B".into()).await;
        pool.register_entry("C".into()).await; // overflow - silently dropped
        assert_eq!(pool.total_count().await, 2);
    }

    #[tokio::test]
    async fn pool_detects_wipeout_and_force_reset_recovers() {
        // RT-ME-3: when every entry is retired, is_wiped_out
        // returns true. force_reset_health brings them back.
        let config = MultiEntryConfig {
            failure_threshold: 1,
            ..Default::default()
        };
        let pool = MultiEntryPool::new(rt(), config).unwrap();
        pool.register_entry("A".into()).await;
        pool.register_entry("B".into()).await;
        assert!(!pool.is_wiped_out().await);
        pool.mark_failure(0).await;
        pool.mark_failure(1).await;
        assert!(pool.is_wiped_out().await);
        assert!(pool.pick_entry().await.is_none());
        pool.force_reset_health().await;
        assert!(!pool.is_wiped_out().await);
        assert_eq!(pool.healthy_count().await, 2);
        // Pick now succeeds.
        assert!(pool.pick_entry().await.is_some());
    }

    #[tokio::test]
    async fn pool_attempt_recovery_respects_cool_down() {
        let config = MultiEntryConfig {
            failure_threshold: 1,
            ..Default::default()
        };
        let pool = MultiEntryPool::new(rt(), config).unwrap();
        pool.register_entry("A".into()).await;
        pool.mark_failure(0).await;
        // Immediately after retirement, cool-down NOT elapsed.
        assert_eq!(pool.attempt_recovery(Duration::from_secs(60)).await, 0);
        // Cool-down of 0 -> always eligible.
        assert_eq!(pool.attempt_recovery(Duration::from_secs(0)).await, 1);
        assert!(!pool.is_wiped_out().await);
    }

    #[tokio::test]
    async fn pool_not_wiped_out_when_empty() {
        // is_wiped_out is only meaningful when the pool is
        // non-empty. An empty pool isn't "wiped" - it just
        // hasn't been populated yet.
        let pool = MultiEntryPool::new(rt(), MultiEntryConfig::default()).unwrap();
        assert!(!pool.is_wiped_out().await);
    }
}
