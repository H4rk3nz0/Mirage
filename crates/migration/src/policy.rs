//! Migration policy.

use std::time::Duration;

/// Default time the local side waits for `PATH_RESPONSE` after
/// emitting a `PATH_CHALLENGE`. RFC 9000 recommends ~3 RTTs;
/// Mirage's default 1500 ms accommodates 3 x 500 ms RTT (a
/// generous mobile-network upper bound).
pub const DEFAULT_VALIDATION_TIMEOUT_MS: u64 = 1500;

/// Default cap on migrations per minute. A flood of fake-IP
/// migrations is a `DoS` vector; we bound the rate.
pub const DEFAULT_MAX_MIGRATIONS_PER_MIN: u32 = 6;

/// Default grace period after a path is retired before it's fully
/// forgotten. In-flight packets on the old path during this window
/// are drained (counted as `Active`); after the window expires, a
/// packet from that address is treated as a brand-new path and
/// will trigger a fresh challenge. Bounded so `retiring` cannot
/// stick forever - without auto-clear, a single migration would
/// pin one slot until manual `finalize_retirement()`.
pub const DEFAULT_RETIREMENT_GRACE_MS: u64 = 3_000;

/// Operator-tunable migration policy.
#[derive(Debug, Clone)]
pub struct MigrationPolicy {
    /// `PATH_CHALLENGE` -> `PATH_RESPONSE` timeout.
    pub validation_timeout: Duration,
    /// Cap on completed migrations per rolling 60 s window.
    /// Exceeding this resets the connection (anti-DoS).
    pub max_migrations_per_min: u32,
    /// If true, the receiver REQUIRES `PATH_CHALLENGE` / RESPONSE
    /// before migrating. If false, an unvalidated path can be
    /// promoted on first packet (faster but spoof-prone). Default
    /// `true` (RFC 9000 §8.2 conformant).
    pub require_validation: bool,
    /// How long a retired path remains in the "drain in-flight"
    /// state before it's fully forgotten. See
    /// [`DEFAULT_RETIREMENT_GRACE_MS`].
    pub retirement_grace: Duration,
}

impl Default for MigrationPolicy {
    fn default() -> Self {
        Self {
            validation_timeout: Duration::from_millis(DEFAULT_VALIDATION_TIMEOUT_MS),
            max_migrations_per_min: DEFAULT_MAX_MIGRATIONS_PER_MIN,
            require_validation: true,
            retirement_grace: Duration::from_millis(DEFAULT_RETIREMENT_GRACE_MS),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_safe() {
        let p = MigrationPolicy::default();
        assert!(p.require_validation);
        assert_eq!(p.validation_timeout, Duration::from_millis(1500));
        assert_eq!(p.max_migrations_per_min, 6);
    }
}
