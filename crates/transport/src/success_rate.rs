//! Per-network success-rate map.
//!
//! Per-network success rates are persisted and bias the next
//! race. A client moving between networks (home Wi-Fi ->
//! cafe -> cellular -> school filter) sees wildly different transport
//! survival rates. The map stores per-(network, transport) success
//! statistics so the next race can prefer transports that worked
//! recently from the same network.
//!
//! # Network fingerprint
//!
//! A "network" is identified by [`NetworkFingerprint`] - a coarse
//! identifier derived from observable signals (DHCP gateway MAC,
//! SSID hash, default-route IP /24). The fingerprint deliberately
//! avoids storing user-identifying values; an observer who reads
//! the map gets nothing more identifying than "the user has been on
//! N distinct local networks."
//!
//! # Persistence
//!
//! The map is in-memory; clients SHOULD persist it to disk
//! (`~/.config/mirage/success.json` or platform equivalent) so the
//! "what worked yesterday" knowledge survives a restart. Persistence
//! is the caller's responsibility - the map's [`SuccessRateMap::snapshot`]
//! and [`SuccessRateMap::load`] expose serializable views without
//! pulling in a JSON dependency at this layer.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// A coarse identifier for "the network the client is currently on."
/// Stable across short-term IP changes (DHCP renew with same gateway)
/// but flips when the user moves between networks.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetworkFingerprint {
    /// 16-byte BLAKE3 of the network's identifying signals. The
    /// fingerprinting fn is up to the platform layer; this struct
    /// just stores the result.
    pub digest: [u8; 16],
}

impl NetworkFingerprint {
    /// Construct from a 16-byte digest.
    pub fn from_digest(digest: [u8; 16]) -> Self {
        Self { digest }
    }

    /// "Unknown network" sentinel - used by callers that don't have
    /// a platform-level fingerprinter wired up yet. Maps every
    /// network to the same key, which means the success-rate bias
    /// is global rather than per-network. Better than nothing.
    pub fn unknown() -> Self {
        Self { digest: [0u8; 16] }
    }
}

/// One transport's success statistics for one network.
#[derive(Debug, Clone, Copy, Default)]
pub struct SuccessStats {
    /// Successful dials.
    pub successes: u32,
    /// Failed dials.
    pub failures: u32,
    /// Last success time. Used to age out stale entries.
    pub last_success: Option<Instant>,
    /// Last failure time. In-memory only (not persisted - `Instant`
    /// has no portable wire form). Drives the selection layer's
    /// backoff: a transport that just failed is deprioritized until
    /// its cooldown elapses, then re-probed.
    pub last_failure: Option<Instant>,
    /// Consecutive failures since the last success. In-memory only.
    /// Scales the backoff window exponentially so a persistently
    /// blocked transport is retried less and less often (but never
    /// dropped - censorship is not assumed permanent).
    pub consecutive_failures: u32,
}

impl SuccessStats {
    /// Empirical success rate as a fraction in [0.0, 1.0]. Returns
    /// 0.5 (neutral) for entries with no observations to avoid
    /// dividing by zero.
    pub fn rate(&self) -> f64 {
        let total = self.successes + self.failures;
        if total == 0 {
            return 0.5;
        }
        f64::from(self.successes) / f64::from(total)
    }

    /// True if the last-success was within `max_age`.
    pub fn is_recent(&self, max_age: Duration) -> bool {
        self.last_success.is_some_and(|t| t.elapsed() < max_age)
    }
}

/// Per-network, per-transport success-rate store.
///
/// Thread-safe via interior `std::sync::RwLock`. Reads (lookup,
/// snapshot, len) run concurrently; writes (record, load) are
/// exclusive. Picked over `Mutex` so a `snapshot()` for disk
/// persistence (which clones N entries) doesn't block concurrent
/// `lookup()` calls from in-flight dial races.
pub struct SuccessRateMap {
    inner: RwLock<HashMap<(NetworkFingerprint, &'static str), SuccessStats>>,
}

impl std::fmt::Debug for SuccessRateMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SuccessRateMap")
            .field("entries", &self.len())
            .finish()
    }
}

impl Default for SuccessRateMap {
    fn default() -> Self {
        Self::new()
    }
}

impl SuccessRateMap {
    /// New empty map.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Record a dial outcome.
    pub fn record(&self, network: &NetworkFingerprint, transport: &'static str, success: bool) {
        let mut map = match self.inner.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let entry = map
            .entry((network.clone(), transport))
            .or_insert_with(SuccessStats::default);
        if success {
            entry.successes = entry.successes.saturating_add(1);
            entry.last_success = Some(Instant::now());
            entry.consecutive_failures = 0;
        } else {
            entry.failures = entry.failures.saturating_add(1);
            entry.last_failure = Some(Instant::now());
            entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        }
    }

    /// Look up stats; returns the default (rate=0.5, no observations)
    /// for unknown (network, transport) pairs.
    pub fn lookup(&self, network: &NetworkFingerprint, transport: &'static str) -> SuccessStats {
        match self.inner.read() {
            Ok(g) => g
                .get(&(network.clone(), transport))
                .copied()
                .unwrap_or_default(),
            Err(_) => SuccessStats::default(),
        }
    }

    /// Snapshot the entire map. Useful for persistence (the caller
    /// serializes to disk in their preferred format) or for metrics
    /// emission. Held under a read-lock so concurrent `lookup()`
    /// calls aren't blocked.
    pub fn snapshot(&self) -> Vec<(NetworkFingerprint, &'static str, SuccessStats)> {
        match self.inner.read() {
            Ok(g) => g.iter().map(|(k, v)| (k.0.clone(), k.1, *v)).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Restore a map from a snapshot. Used at process startup to
    /// reload disk-persisted state.
    pub fn load(
        entries: impl IntoIterator<Item = (NetworkFingerprint, &'static str, SuccessStats)>,
    ) -> Self {
        let map = entries.into_iter().map(|(n, t, s)| ((n, t), s)).collect();
        Self {
            inner: RwLock::new(map),
        }
    }

    /// Total entries in the map. Diagnostics-only.
    pub fn len(&self) -> usize {
        match self.inner.read() {
            Ok(g) => g.len(),
            Err(p) => p.into_inner().len(),
        }
    }

    /// True iff the map has zero entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(tag: u8) -> NetworkFingerprint {
        NetworkFingerprint::from_digest([tag; 16])
    }

    #[test]
    fn record_and_lookup_roundtrip() {
        let m = SuccessRateMap::new();
        m.record(&n(1), "reality", true);
        m.record(&n(1), "reality", true);
        m.record(&n(1), "reality", false);
        let s = m.lookup(&n(1), "reality");
        assert_eq!(s.successes, 2);
        assert_eq!(s.failures, 1);
        assert!((s.rate() - 2.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn separate_networks_independent() {
        let m = SuccessRateMap::new();
        m.record(&n(1), "reality", true);
        m.record(&n(2), "reality", false);
        assert_eq!(m.lookup(&n(1), "reality").successes, 1);
        assert_eq!(m.lookup(&n(1), "reality").failures, 0);
        assert_eq!(m.lookup(&n(2), "reality").successes, 0);
        assert_eq!(m.lookup(&n(2), "reality").failures, 1);
    }

    #[test]
    fn unknown_network_returns_neutral() {
        let m = SuccessRateMap::new();
        let s = m.lookup(&n(99), "reality");
        assert_eq!(s.rate(), 0.5);
        assert_eq!(s.successes, 0);
        assert_eq!(s.failures, 0);
    }

    #[test]
    fn snapshot_and_load_roundtrip() {
        let m = SuccessRateMap::new();
        m.record(&n(1), "reality", true);
        m.record(&n(2), "trojan", false);
        let snap = m.snapshot();
        assert_eq!(snap.len(), 2);
        let restored = SuccessRateMap::load(snap);
        assert_eq!(restored.lookup(&n(1), "reality").successes, 1);
        assert_eq!(restored.lookup(&n(2), "trojan").failures, 1);
    }

    #[test]
    fn unknown_sentinel_collapses_to_global() {
        let m = SuccessRateMap::new();
        m.record(&NetworkFingerprint::unknown(), "reality", true);
        m.record(&NetworkFingerprint::unknown(), "reality", true);
        assert_eq!(
            m.lookup(&NetworkFingerprint::unknown(), "reality")
                .successes,
            2
        );
    }

    #[test]
    fn poisoned_lock_returns_neutral_lookup() {
        use std::panic;
        let m = SuccessRateMap::new();
        let _ = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            let _g = m.inner.write().unwrap();
            panic!("poison");
        }));
        // Recovery path returns default (zero-count) stats.
        let s = m.lookup(&n(1), "reality");
        assert_eq!(s.successes, 0);
    }
}
