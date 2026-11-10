//! Pool tunables.
//!
//! [`PoolPolicy`] caps + jitter knobs for the [`crate::pool::CircuitPool`]
//! state machine. [`RouterPolicy`] is a future home for cross-pool
//! tunables (per-class hint defaults, TCP/UDP-default overrides) -
//! currently a thin wrapper around `PoolPolicy` + a [`Classifier`]
//! for callers that want one struct.

use crate::class::Class;
use crate::classifier::Classifier;
use std::time::Duration;
use thiserror::Error;

/// Errors produced by [`PoolPolicy::validate`].
///
/// A policy that fails validation guarantees acquire-time deadlock
/// for at least one class - fixing the policy at construction is
/// strictly cheaper than debugging a "no streams flow" production
/// outage. Closes [RT-M4].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    /// Class with `min_pool_size > 0` has `max_per_class = 0`.
    /// Tick will demand a build but acquire will refuse to insert
    /// a Building entry -> spin forever.
    #[error("class {0:?} demands min_pool_size > 0 but max_per_class is 0")]
    ClassDeadlock(Class),
    /// `max_pending_builds_per_class = 0` while at least one class
    /// has `min_pool_size > 0`. Pool floor enforcement can't insert
    /// any Building entries -> spin forever.
    #[error("max_pending_builds_per_class is 0 but at least one class needs floor enforcement")]
    NoBuildsAllowed,
}

/// Pool tunables. Per-class caps and jitter for refresh.
#[derive(Debug, Clone)]
pub struct PoolPolicy {
    /// Hard cap on concurrent entries per class. Pool refuses new
    /// builds beyond this. Default keeps Interactive at 8 (room
    /// for hot pool + isolation slots) and other classes lower.
    pub max_per_class: PerClass<u32>,
    /// Random jitter window applied to per-circuit `max_age`
    /// expirations so the whole pool doesn't rotate in lockstep
    /// (would create a "Mirage refresh" wire signal).
    ///
    /// Each entry's effective max age is `profile.max_age + uniform(0, refresh_jitter)`.
    pub refresh_jitter: Duration,
    /// Cap on concurrent in-flight (Building) entries per class.
    /// Bounds caller's circuit-build amplification - without this,
    /// a stuck build path could trigger unbounded retries.
    pub max_pending_builds_per_class: u32,
}

impl Default for PoolPolicy {
    fn default() -> Self {
        Self {
            max_per_class: PerClass {
                metadata: 4,
                interactive: 8,
                bulk: 4,
                realtime: 2,
                onion_service: 4,
                background: 4,
            },
            refresh_jitter: Duration::from_secs(60),
            max_pending_builds_per_class: 4,
        }
    }
}

impl PoolPolicy {
    /// Cap on concurrent entries for `class`.
    pub fn max_for(&self, class: Class) -> u32 {
        self.max_per_class.get(class)
    }

    /// Validate the policy against the per-class floor demands.
    /// A policy with `min_pool_size > 0` for some class but
    /// `max_per_class = 0` for that class is structurally
    /// dead-locked - tick demands a build, acquire refuses,
    /// repeat. Catches misconfiguration at construction time.
    ///
    /// Closes [RT-M4]. Production code SHOULD call this on any
    /// non-default policy before constructing a [`crate::CircuitPool`].
    pub fn validate(&self) -> Result<(), PolicyError> {
        let any_floor_class = Class::all()
            .iter()
            .any(|c| c.default_profile().min_pool_size > 0);
        if any_floor_class && self.max_pending_builds_per_class == 0 {
            return Err(PolicyError::NoBuildsAllowed);
        }
        for &class in Class::all() {
            let min = class.default_profile().min_pool_size;
            let max = self.max_for(class);
            if min > 0 && max == 0 {
                return Err(PolicyError::ClassDeadlock(class));
            }
        }
        Ok(())
    }
}

/// Generic per-class tunable. Avoids stringly-typed `HashMap<Class, T>`
/// for hot-path accesses.
#[derive(Debug, Clone, Copy)]
pub struct PerClass<T> {
    /// Value for [`Class::Metadata`].
    pub metadata: T,
    /// Value for [`Class::Interactive`].
    pub interactive: T,
    /// Value for [`Class::Bulk`].
    pub bulk: T,
    /// Value for [`Class::Realtime`].
    pub realtime: T,
    /// Value for [`Class::OnionService`].
    pub onion_service: T,
    /// Value for [`Class::Background`].
    pub background: T,
}

impl<T: Copy> PerClass<T> {
    /// Look up the value for `class`.
    pub fn get(&self, class: Class) -> T {
        match class {
            Class::Metadata => self.metadata,
            Class::Interactive => self.interactive,
            Class::Bulk => self.bulk,
            Class::Realtime => self.realtime,
            Class::OnionService => self.onion_service,
            Class::Background => self.background,
        }
    }

    /// Set the value for `class`.
    pub fn set(&mut self, class: Class, value: T) {
        match class {
            Class::Metadata => self.metadata = value,
            Class::Interactive => self.interactive = value,
            Class::Bulk => self.bulk = value,
            Class::Realtime => self.realtime = value,
            Class::OnionService => self.onion_service = value,
            Class::Background => self.background = value,
        }
    }
}

impl<T: Copy> PerClass<T> {
    /// Construct with the same `value` for every class.
    pub fn uniform(value: T) -> Self {
        Self {
            metadata: value,
            interactive: value,
            bulk: value,
            realtime: value,
            onion_service: value,
            background: value,
        }
    }
}

/// One-stop config bundle: classifier + pool policy. Future-home
/// for cross-cutting tunables.
pub struct RouterPolicy {
    /// Classifier used at SOCKS5 ingress.
    pub classifier: Classifier,
    /// Pool tunables.
    pub pool: PoolPolicy,
}

impl Default for RouterPolicy {
    fn default() -> Self {
        Self {
            classifier: Classifier::standard(),
            pool: PoolPolicy::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_per_class_caps_are_distinct() {
        let p = PoolPolicy::default();
        assert!(p.max_for(Class::Interactive) >= p.max_for(Class::Realtime));
        // Realtime cap is intentionally low - 2-hop circuits are
        // an explicit anonymity downgrade and operators should
        // limit how many co-exist.
        assert!(p.max_for(Class::Realtime) <= 2);
    }

    #[test]
    fn per_class_get_set_roundtrips() {
        let mut pc: PerClass<u32> = PerClass::uniform(0);
        for &class in Class::all() {
            pc.set(class, class as u32 + 1);
        }
        for &class in Class::all() {
            assert_eq!(pc.get(class), class as u32 + 1);
        }
    }

    #[test]
    fn per_class_uniform_sets_all_fields() {
        let pc = PerClass::uniform(42u32);
        for &class in Class::all() {
            assert_eq!(pc.get(class), 42);
        }
    }

    #[test]
    fn router_policy_default_uses_standard_classifier() {
        let r = RouterPolicy::default();
        // Web port -> Interactive via the standard table.
        assert_eq!(r.classifier.classify_tcp(443), Class::Interactive);
    }

    // --- PolicyError validation (RT-M4 closure) ---

    #[test]
    fn default_policy_validates() {
        assert!(PoolPolicy::default().validate().is_ok());
    }

    #[test]
    fn policy_with_zero_max_for_floor_class_fails_validation() {
        // Interactive has min_pool_size = 3 by default. Setting
        // max_per_class.interactive = 0 is structural deadlock.
        let mut p = PoolPolicy::default();
        p.max_per_class.set(Class::Interactive, 0);
        let err = p.validate().unwrap_err();
        assert_eq!(err, PolicyError::ClassDeadlock(Class::Interactive));
    }

    #[test]
    fn policy_with_zero_pending_builds_fails_validation() {
        let p = PoolPolicy {
            max_pending_builds_per_class: 0,
            ..Default::default()
        };
        let err = p.validate().unwrap_err();
        assert_eq!(err, PolicyError::NoBuildsAllowed);
    }

    #[test]
    fn policy_lowering_non_floor_class_to_zero_passes() {
        // Background has min_pool_size = 0. Setting its cap to 0
        // is fine - it's never floor-enforced.
        let mut p = PoolPolicy::default();
        p.max_per_class.set(Class::Background, 0);
        assert!(p.validate().is_ok());
    }
}
