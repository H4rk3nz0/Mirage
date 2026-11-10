//! Per-class circuit profiles.
//!
//! A [`CircuitProfile`] describes how to build the circuit for a
//! given [`crate::Class`]: how many hops, which transports to prefer,
//! how aggressively to pad, what cover-traffic budget to allocate,
//! and what lifetime parameters apply (when to refresh, when to
//! tear down).
//!
//! Defaults are exposed via [`Class::default_profile`]. Operators
//! MAY override.

use crate::class::Class;
use std::time::Duration;
use thiserror::Error;

// PaddingProfile

/// Padding profile for a circuit's session-frame layer.
///
/// Trades anonymity (smaller traffic-shape signal) for performance
/// (fewer wasted bytes + lower latency on small frames).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingProfile {
    /// Every session-frame plaintext is rounded via Padme. Default
    /// for all classes except [`Class::Realtime`].
    Strict,
    /// Padme rounding active but cover-traffic dialed down.
    /// Allocated for future use; v0.2 doesn't currently emit this.
    Standard,
    /// Padme **bypassed for media frames** below a configurable
    /// size threshold (default 1500 bytes). Cover-traffic-only
    /// padding. Used by [`Class::Realtime`] - the tradeoff: leak
    /// per-frame sizes in exchange for sub-150 ms RTT. Control
    /// frames are still Padme-padded; only the high-rate media
    /// flow opts out.
    Minimal,
}

// CoverProfile

/// Cover-traffic budget for a circuit. Maps to a budget tier in the
/// cover-traffic scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverProfile {
    /// No cover traffic. Currently unused by built-in profiles; a
    /// pure-bytes mode for callers that want zero overhead and
    /// accept the traffic-shape leak.
    Off,
    /// Low share of cover bytes; fills idle gaps only. Used by
    /// [`Class::Metadata`] and [`Class::Bulk`] where the real flow
    /// is already substantive.
    Low,
    /// Standard scheduler cadence. Default for [`Class::Interactive`].
    Medium,
    /// Aggressive cover. Used by [`Class::Realtime`] (compensates
    /// for the 2-hop anonymity downgrade) and [`Class::Background`]
    /// (background streams act as cover-traffic carriers for
    /// other users).
    High,
}

// TransportBias

/// Ordered preference list for transport selection on each hop of
/// a circuit, plus a fallback policy.
///
/// The race-driver in `mirage-transport` tries `preferred` in order
/// for each hop. If all preferred fail and `allow_fallback` is
/// `true`, any other available transport is acceptable. If `false`
/// the circuit build fails - used by [`Class::Realtime`] so a
/// TLS-faking transport doesn't sneak in and torpedo the latency
/// budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportBias {
    /// Transport names in preference order. Names match
    /// [`mirage_transport::ClientTransport::name`] return values.
    pub preferred: &'static [&'static str],
    /// If true, fall back to ANY other available transport when
    /// all preferred fail. If false, fail-fast.
    pub allow_fallback: bool,
}

impl TransportBias {
    /// True iff `transport_name` is in the preferred list.
    pub fn prefers(&self, transport_name: &str) -> bool {
        self.preferred.iter().any(|&n| n == transport_name)
    }
}

// CircuitProfile

/// A circuit's build + maintenance profile.
///
/// Constructed via [`Class::default_profile`]; operators MAY clone +
/// mutate to override defaults.
///
/// Field semantics are stable across releases - operator policy
/// files MAY pin specific values and rely on them surviving
/// minor-version bumps.
#[derive(Debug, Clone)]
pub struct CircuitProfile {
    /// The class this profile is for.
    pub class: Class,
    /// Number of hops. Range `2..=3`. The 3-hop ceiling reflects
    /// Mirage's design: anonymity beyond a 3-hop chain comes from
    /// concurrent multi-entry pools, not from stacking more hops.
    /// 2-hop is a deliberate latency-vs-anonymity downgrade
    /// reserved for `Class::Realtime`.
    pub hop_count: u8,
    /// Per-hop transport selection policy.
    pub transport_bias: TransportBias,
    /// Frame padding policy.
    pub padding: PaddingProfile,
    /// Cover-traffic budget tier.
    pub cover_traffic: CoverProfile,
    /// Time after which an unused circuit is torn down.
    pub idle_ttl: Duration,
    /// Hard age cap. After this, the circuit transitions to
    /// `Draining` regardless of activity - forces rotation so a
    /// long-running session doesn't pile per-circuit state on a
    /// small set of bridges.
    pub max_age: Duration,
    /// Mux ceiling - max concurrent streams on this circuit.
    pub max_streams: u32,
    /// Pool floor - pool keeps at least this many healthy
    /// circuits of this class hot.
    pub min_pool_size: u32,
    /// If true, the bulk-stream splitter MAY open multiple
    /// circuits with this profile in parallel and stripe a single
    /// transfer across them. Only [`Class::Bulk`] sets this.
    pub allow_parallel: bool,
}

impl CircuitProfile {
    /// True iff this profile is a strict anonymity downgrade
    /// from the 3-hop Mirage baseline. Equivalent to
    /// `hop_count < 3`.
    pub fn is_anonymity_downgrade(&self) -> bool {
        self.hop_count < 3
    }

    /// True iff streams on this profile use the v0.2 split-exit
    /// path (resolver R + forwarder F) instead of the v0.1u
    /// last-hop-as-exit path.
    ///
    /// Eligibility:
    ///
    /// - `hop_count >= 3` - we need at least one upstream hop
    ///   plus the R/F pair.
    /// - `class != OnionService` - the destination is in-protocol
    ///   for hidden services, no exit at all.
    /// - `class != Realtime` - Realtime is 2-hop by design; no
    ///   room for the split.
    ///
    /// Closes [RT-M6]: split-exit-eligibility is now an explicit
    /// API on the profile, not a convention spread across the
    /// integration layer.
    pub fn split_exit_eligible(&self) -> bool {
        self.hop_count >= 3
            && !matches!(self.class, Class::OnionService)
            && !matches!(self.class, Class::Realtime)
    }

    /// Index of the resolver hop ("R") in a split-exit circuit.
    /// Returns `None` for profiles where split-exit doesn't apply.
    /// R is the second-to-last hop - it receives `CMD_RESOLVE`,
    /// performs DNS, and emits `CMD_HANDOFF` to F.
    pub fn resolver_hop_idx(&self) -> Option<usize> {
        if self.split_exit_eligible() {
            Some(self.hop_count as usize - 2)
        } else {
            None
        }
    }

    /// Index of the forwarder hop ("F") in a split-exit circuit.
    /// Returns `None` for profiles where split-exit doesn't apply.
    /// F is the last hop - it receives `CMD_HANDOFF` carrying only
    /// an IP literal, opens the TCP socket, and pumps bytes.
    pub fn forwarder_hop_idx(&self) -> Option<usize> {
        if self.split_exit_eligible() {
            Some(self.hop_count as usize - 1)
        } else {
            None
        }
    }
}

// Default profiles per class

const TCP_PREFERRED: &[&str] = &["reality-v2", "obfs-tcp"];
const REALTIME_PREFERRED: &[&str] = &["quic-masque", "webrtc"];
const BACKGROUND_PREFERRED: &[&str] = &["reality-v2", "obfs-tcp", "quic-masque"];

const TCP_BIAS: TransportBias = TransportBias {
    preferred: TCP_PREFERRED,
    allow_fallback: true,
};

const REALTIME_BIAS: TransportBias = TransportBias {
    preferred: REALTIME_PREFERRED,
    // No fallback to TLS-fake transports - they'd torpedo the
    // sub-150 ms RTT budget.
    allow_fallback: false,
};

const BACKGROUND_BIAS: TransportBias = TransportBias {
    preferred: BACKGROUND_PREFERRED,
    allow_fallback: true,
};

/// Operator-tunable overrides on top of [`Class::default_profile`].
///
/// Lets deployments adjust circuit-build parameters without
/// recompiling. All fields are `Option`; `None` means "use the
/// class default." Apply via [`Class::profile_with_overrides`].
///
/// Closes [RT-L2]: profile defaults are now config-loadable
/// without losing the typed-default fallback.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileOverrides {
    /// Override [`CircuitProfile::hop_count`]. Range 2..=3.
    pub hop_count: Option<u8>,
    /// Override [`CircuitProfile::padding`].
    pub padding: Option<PaddingProfile>,
    /// Override [`CircuitProfile::cover_traffic`].
    pub cover_traffic: Option<CoverProfile>,
    /// Override [`CircuitProfile::idle_ttl`].
    pub idle_ttl: Option<Duration>,
    /// Override [`CircuitProfile::max_age`].
    pub max_age: Option<Duration>,
    /// Override [`CircuitProfile::max_streams`].
    pub max_streams: Option<u32>,
    /// Override [`CircuitProfile::min_pool_size`].
    pub min_pool_size: Option<u32>,
    /// Override [`CircuitProfile::allow_parallel`].
    pub allow_parallel: Option<bool>,
    /// Override [`CircuitProfile::transport_bias`].
    pub transport_bias: Option<TransportBias>,
}

impl ProfileOverrides {
    /// Apply these overrides to `base`, returning the merged
    /// profile. Class is preserved; only the listed fields change.
    /// Does **not** validate the resulting profile - call
    /// [`CircuitProfile::validate`] if you want fail-fast on
    /// operator misconfiguration. (Selector / pool layers also
    /// validate at use time, so a bad profile cannot silently
    /// produce a malformed circuit.)
    pub fn apply_to(&self, base: &CircuitProfile) -> CircuitProfile {
        CircuitProfile {
            class: base.class,
            hop_count: self.hop_count.unwrap_or(base.hop_count),
            transport_bias: self.transport_bias.unwrap_or(base.transport_bias),
            padding: self.padding.unwrap_or(base.padding),
            cover_traffic: self.cover_traffic.unwrap_or(base.cover_traffic),
            idle_ttl: self.idle_ttl.unwrap_or(base.idle_ttl),
            max_age: self.max_age.unwrap_or(base.max_age),
            max_streams: self.max_streams.unwrap_or(base.max_streams),
            min_pool_size: self.min_pool_size.unwrap_or(base.min_pool_size),
            allow_parallel: self.allow_parallel.unwrap_or(base.allow_parallel),
        }
    }

    /// Apply overrides AND validate the result. Prefer this in
    /// config-load paths where catching a misconfigured profile
    /// at startup is preferable to a circuit-build failure later.
    /// Closes [RT-H9] (Phase 2E re-scan).
    pub fn apply_to_checked(&self, base: &CircuitProfile) -> Result<CircuitProfile, ProfileError> {
        let merged = self.apply_to(base);
        merged.validate()?;
        Ok(merged)
    }
}

// Profile validation

/// Errors produced by [`CircuitProfile::validate`].
///
/// The selector / pool layers re-validate the same invariants at
/// circuit-build time, so an invalid profile cannot produce a
/// malformed circuit - `validate` exists only to surface operator
/// misconfiguration earlier (typically at config load).
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ProfileError {
    /// `hop_count` outside the legal range. Multi-hop anonymity
    /// requires at least 2 hops; the upper bound is fixed by the
    /// circuit-cell `hops` field.
    #[error("hop_count {got} outside legal range [{min}..={max}]")]
    HopCountOutOfRange {
        /// Configured value.
        got: u8,
        /// Inclusive lower bound.
        min: u8,
        /// Inclusive upper bound.
        max: u8,
    },
    /// `max_streams` is zero - would mean a circuit can carry no
    /// data, which is never useful.
    #[error("max_streams must be >= 1, got 0")]
    MaxStreamsZero,
    /// `min_pool_size` is unreasonably large, indicating a
    /// configuration error (e.g., user typed bytes instead of
    /// circuit count). Hard cap chosen so a paranoid power user
    /// who genuinely wants a 64-circuit pool is allowed; anything
    /// larger is almost certainly a typo.
    #[error("min_pool_size {0} exceeds sane maximum (64)")]
    MinPoolSizeTooLarge(u32),
    /// `transport_bias.preferred` is empty AND `allow_fallback` is
    /// false - no transport will ever be picked, every build fails.
    #[error(
        "transport_bias has no preferred entries and allow_fallback=false; no transport reachable"
    )]
    NoReachableTransport,
}

impl CircuitProfile {
    /// Lower bound on `hop_count` for circuit profiles. Mirrors
    /// `mirage_circuit::MIN_CIRCUIT_HOPS` for the multi-hop case -
    /// a 1-hop "circuit" provides no anonymity and is rejected
    /// at the profile layer.
    pub const MIN_HOP_COUNT: u8 = 2;
    /// Upper bound on `hop_count`. Mirrors
    /// `mirage_circuit::MAX_CIRCUIT_HOPS` - capped at 3 because
    /// Mirage's anonymity strategy is multi-entry concurrency,
    /// not deep single chains.
    pub const MAX_HOP_COUNT: u8 = 3;
    /// Sane upper bound on `min_pool_size`. Operators wanting a
    /// larger pool can patch this constant; the default rejects
    /// likely-typo values.
    pub const MAX_MIN_POOL_SIZE: u32 = 64;

    /// Validate that this profile's invariants hold. Closes
    /// [RT-H9] (Phase 2E re-scan): the previous round added
    /// [`ProfileOverrides::apply_to`] but did not check that the
    /// merged result was itself valid; an operator who set
    /// `hop_count = 1` plus `allow_parallel = true` would only
    /// fail at the first circuit build, with a confusing
    /// `SelectorError::HopCountInvalid`.
    pub fn validate(&self) -> Result<(), ProfileError> {
        if !(Self::MIN_HOP_COUNT..=Self::MAX_HOP_COUNT).contains(&self.hop_count) {
            return Err(ProfileError::HopCountOutOfRange {
                got: self.hop_count,
                min: Self::MIN_HOP_COUNT,
                max: Self::MAX_HOP_COUNT,
            });
        }
        if self.max_streams == 0 {
            return Err(ProfileError::MaxStreamsZero);
        }
        if self.min_pool_size > Self::MAX_MIN_POOL_SIZE {
            return Err(ProfileError::MinPoolSizeTooLarge(self.min_pool_size));
        }
        if self.transport_bias.preferred.is_empty() && !self.transport_bias.allow_fallback {
            return Err(ProfileError::NoReachableTransport);
        }
        Ok(())
    }
}

impl Class {
    /// Class default profile with operator overrides applied.
    /// Equivalent to `overrides.apply_to(self.default_profile())`.
    pub fn profile_with_overrides(self, overrides: &ProfileOverrides) -> CircuitProfile {
        overrides.apply_to(&self.default_profile())
    }

    /// Default circuit profile for this class.
    pub fn default_profile(self) -> CircuitProfile {
        match self {
            Class::Metadata => CircuitProfile {
                class: self,
                hop_count: 3,
                transport_bias: TCP_BIAS,
                padding: PaddingProfile::Strict,
                cover_traffic: CoverProfile::Low,
                idle_ttl: Duration::from_secs(5 * 60),
                max_age: Duration::from_secs(15 * 60),
                max_streams: 32,
                min_pool_size: 1,
                allow_parallel: false,
            },
            Class::Interactive => CircuitProfile {
                class: self,
                hop_count: 3,
                transport_bias: TCP_BIAS,
                padding: PaddingProfile::Strict,
                cover_traffic: CoverProfile::Medium,
                idle_ttl: Duration::from_secs(10 * 60),
                max_age: Duration::from_secs(60 * 60),
                max_streams: 64,
                min_pool_size: 3,
                allow_parallel: false,
            },
            Class::Bulk => CircuitProfile {
                class: self,
                hop_count: 3,
                transport_bias: TCP_BIAS,
                padding: PaddingProfile::Strict,
                cover_traffic: CoverProfile::Low,
                idle_ttl: Duration::from_secs(5 * 60),
                max_age: Duration::from_secs(30 * 60),
                max_streams: 8,
                min_pool_size: 1,
                allow_parallel: true,
            },
            Class::Realtime => CircuitProfile {
                class: self,
                // Anonymity downgrade - explicit, opt-in.
                hop_count: 2,
                transport_bias: REALTIME_BIAS,
                padding: PaddingProfile::Minimal,
                cover_traffic: CoverProfile::High,
                idle_ttl: Duration::from_secs(5 * 60),
                max_age: Duration::from_secs(15 * 60),
                max_streams: 4,
                min_pool_size: 1,
                allow_parallel: false,
            },
            Class::OnionService => CircuitProfile {
                class: self,
                // 3-hop ceiling per Mirage's multi-entry design.
                // The 6-hop "client + service rendezvous" model
                // from Tor doesn't apply: Mirage's anonymity
                // comes from concurrent entries across the cohort,
                // not from chain depth. Rendezvous semantics for
                // hidden services are handled via a separate
                // rendezvous-bridge primitive (Phase 3+).
                hop_count: 3,
                transport_bias: BACKGROUND_BIAS,
                padding: PaddingProfile::Strict,
                cover_traffic: CoverProfile::Medium,
                idle_ttl: Duration::from_secs(10 * 60),
                max_age: Duration::from_secs(60 * 60),
                max_streams: 32,
                min_pool_size: 1,
                allow_parallel: false,
            },
            Class::Background => CircuitProfile {
                class: self,
                // 3-hop ceiling. Background was 4 in the legacy
                // model; the extra hop bought no anonymity beyond
                // what multi-entry concurrency already provides.
                hop_count: 3,
                transport_bias: BACKGROUND_BIAS,
                padding: PaddingProfile::Strict,
                cover_traffic: CoverProfile::High,
                idle_ttl: Duration::from_secs(30 * 60),
                max_age: Duration::from_secs(120 * 60),
                max_streams: 16,
                min_pool_size: 0,
                allow_parallel: false,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn realtime_is_the_only_anonymity_downgrade() {
        for &class in Class::all() {
            let p = class.default_profile();
            assert_eq!(
                p.is_anonymity_downgrade(),
                class == Class::Realtime,
                "{}.default_profile() downgrade flag mismatch",
                class.name()
            );
        }
    }

    #[test]
    fn realtime_disallows_transport_fallback() {
        // Why: a fallback to Reality (which fakes TLS) would
        // torpedo the sub-150 ms latency budget. Realtime fails
        // fast if its preferred transports aren't available.
        let p = Class::Realtime.default_profile();
        assert!(!p.transport_bias.allow_fallback);
        assert!(p.transport_bias.prefers("quic-masque"));
        assert!(p.transport_bias.prefers("webrtc"));
        assert!(!p.transport_bias.prefers("reality-v2"));
    }

    #[test]
    fn only_bulk_allows_parallel_circuits() {
        for &class in Class::all() {
            let p = class.default_profile();
            assert_eq!(
                p.allow_parallel,
                class == Class::Bulk,
                "{}.default_profile() parallel flag mismatch",
                class.name()
            );
        }
    }

    #[test]
    fn hop_counts_within_documented_range() {
        // Mirage caps chains at 3 hops. Anonymity beyond comes
        // from concurrent-entry diversity, not chain depth.
        for &class in Class::all() {
            let p = class.default_profile();
            assert!(
                (2..=3).contains(&p.hop_count),
                "{}.default_profile().hop_count = {} out of [2, 3]",
                class.name(),
                p.hop_count
            );
            assert_eq!(p.class, class, "{} profile class mismatch", class.name());
        }
    }

    #[test]
    fn onion_service_capped_at_three_hops() {
        let p = Class::OnionService.default_profile();
        assert_eq!(p.hop_count, 3);
    }

    #[test]
    fn realtime_uses_minimal_padding() {
        let p = Class::Realtime.default_profile();
        assert_eq!(p.padding, PaddingProfile::Minimal);
        // Cover traffic is High to compensate for the padding +
        // hop-count downgrade.
        assert_eq!(p.cover_traffic, CoverProfile::High);
    }

    #[test]
    fn interactive_uses_strict_padding_medium_cover() {
        let p = Class::Interactive.default_profile();
        assert_eq!(p.padding, PaddingProfile::Strict);
        assert_eq!(p.cover_traffic, CoverProfile::Medium);
        assert_eq!(p.hop_count, 3);
    }

    #[test]
    fn min_pool_floors_match_hot_class_intuition() {
        // Interactive is the dominant class; its hot pool is
        // largest. Background has zero floor - built on demand.
        assert_eq!(Class::Interactive.default_profile().min_pool_size, 3);
        assert_eq!(Class::Background.default_profile().min_pool_size, 0);
    }

    #[test]
    fn idle_ttl_less_than_max_age_for_every_class() {
        for &class in Class::all() {
            let p = class.default_profile();
            assert!(
                p.idle_ttl <= p.max_age,
                "{}.default_profile() idle_ttl > max_age",
                class.name()
            );
        }
    }

    // --- Split-exit eligibility (RT-M6 closure) ---

    #[test]
    fn split_exit_eligibility_per_class() {
        // Interactive, Bulk, Background -> split-exit eligible
        // (3+ hops, clearnet exits).
        for class in [Class::Interactive, Class::Bulk, Class::Background] {
            let p = class.default_profile();
            assert!(
                p.split_exit_eligible(),
                "{} should be split-exit eligible",
                class.name()
            );
            assert_eq!(p.resolver_hop_idx(), Some(p.hop_count as usize - 2));
            assert_eq!(p.forwarder_hop_idx(), Some(p.hop_count as usize - 1));
        }
        // Metadata -> 3-hop, clearnet exits, also split-exit eligible.
        let meta = Class::Metadata.default_profile();
        assert!(meta.split_exit_eligible());
        // Realtime -> 2-hop, NOT eligible.
        let rt = Class::Realtime.default_profile();
        assert!(!rt.split_exit_eligible());
        assert_eq!(rt.resolver_hop_idx(), None);
        assert_eq!(rt.forwarder_hop_idx(), None);
        // OnionService -> in-protocol destination, NOT eligible.
        let onion = Class::OnionService.default_profile();
        assert!(!onion.split_exit_eligible());
        assert_eq!(onion.resolver_hop_idx(), None);
        assert_eq!(onion.forwarder_hop_idx(), None);
    }

    #[test]
    fn split_exit_indexes_are_distinct_and_in_range() {
        // R and F must be distinct hops within the circuit.
        for class in [
            Class::Interactive,
            Class::Bulk,
            Class::Background,
            Class::Metadata,
        ] {
            let p = class.default_profile();
            let r = p.resolver_hop_idx().unwrap();
            let f = p.forwarder_hop_idx().unwrap();
            assert_ne!(r, f, "{} R and F must be distinct hops", class.name());
            assert!(
                r < p.hop_count as usize && f < p.hop_count as usize,
                "{} R/F indices must be in range",
                class.name()
            );
            assert_eq!(f, r + 1, "{} F must immediately follow R", class.name());
        }
    }

    // --- ProfileOverrides (RT-L2 closure) ---

    #[test]
    fn empty_overrides_preserve_default_profile() {
        let overrides = ProfileOverrides::default();
        for &class in Class::all() {
            let merged = class.profile_with_overrides(&overrides);
            let default = class.default_profile();
            assert_eq!(merged.hop_count, default.hop_count);
            assert_eq!(merged.padding, default.padding);
            assert_eq!(merged.cover_traffic, default.cover_traffic);
            assert_eq!(merged.idle_ttl, default.idle_ttl);
            assert_eq!(merged.max_age, default.max_age);
            assert_eq!(merged.max_streams, default.max_streams);
            assert_eq!(merged.min_pool_size, default.min_pool_size);
            assert_eq!(merged.allow_parallel, default.allow_parallel);
            assert_eq!(merged.class, default.class);
        }
    }

    #[test]
    fn overrides_apply_individual_fields() {
        let overrides = ProfileOverrides {
            hop_count: Some(5),
            max_streams: Some(128),
            min_pool_size: Some(10),
            ..Default::default()
        };
        let p = Class::Interactive.profile_with_overrides(&overrides);
        assert_eq!(p.hop_count, 5);
        assert_eq!(p.max_streams, 128);
        assert_eq!(p.min_pool_size, 10);
        // Unchanged fields keep defaults.
        let default = Class::Interactive.default_profile();
        assert_eq!(p.padding, default.padding);
        assert_eq!(p.cover_traffic, default.cover_traffic);
    }

    #[test]
    fn class_preserved_through_overrides() {
        let overrides = ProfileOverrides {
            hop_count: Some(2),
            ..Default::default()
        };
        let p = Class::Bulk.profile_with_overrides(&overrides);
        assert_eq!(p.class, Class::Bulk);
    }

    #[test]
    fn transport_bias_prefers_recognises_listed_names() {
        let bias = TransportBias {
            preferred: &["reality-v2", "obfs-tcp"],
            allow_fallback: true,
        };
        assert!(bias.prefers("reality-v2"));
        assert!(bias.prefers("obfs-tcp"));
        assert!(!bias.prefers("quic-masque"));
    }

    // --- Profile validation (RT-H9 closure) ---

    #[test]
    fn validate_accepts_every_default_profile() {
        for &class in Class::all() {
            let p = class.default_profile();
            assert!(
                p.validate().is_ok(),
                "{}.default_profile() must validate",
                class.name()
            );
        }
    }

    #[test]
    fn validate_rejects_hop_count_too_low() {
        let overrides = ProfileOverrides {
            hop_count: Some(1),
            ..Default::default()
        };
        let merged = Class::Interactive.profile_with_overrides(&overrides);
        assert!(matches!(
            merged.validate(),
            Err(ProfileError::HopCountOutOfRange { got: 1, .. })
        ));
        // apply_to_checked surfaces the same error pre-merge.
        let err = overrides
            .apply_to_checked(&Class::Interactive.default_profile())
            .unwrap_err();
        assert!(matches!(
            err,
            ProfileError::HopCountOutOfRange { got: 1, .. }
        ));
    }

    #[test]
    fn validate_rejects_hop_count_too_high() {
        let overrides = ProfileOverrides {
            hop_count: Some(7),
            ..Default::default()
        };
        let merged = Class::Interactive.profile_with_overrides(&overrides);
        assert!(matches!(
            merged.validate(),
            Err(ProfileError::HopCountOutOfRange { got: 7, .. })
        ));
    }

    #[test]
    fn validate_rejects_zero_max_streams() {
        let overrides = ProfileOverrides {
            max_streams: Some(0),
            ..Default::default()
        };
        let merged = Class::Bulk.profile_with_overrides(&overrides);
        assert_eq!(merged.validate(), Err(ProfileError::MaxStreamsZero));
    }

    #[test]
    fn validate_rejects_oversized_min_pool_size() {
        let overrides = ProfileOverrides {
            min_pool_size: Some(1_000_000),
            ..Default::default()
        };
        let merged = Class::Interactive.profile_with_overrides(&overrides);
        assert!(matches!(
            merged.validate(),
            Err(ProfileError::MinPoolSizeTooLarge(1_000_000))
        ));
    }

    #[test]
    fn validate_rejects_unreachable_transport() {
        let overrides = ProfileOverrides {
            transport_bias: Some(TransportBias {
                preferred: &[],
                allow_fallback: false,
            }),
            ..Default::default()
        };
        let merged = Class::Interactive.profile_with_overrides(&overrides);
        assert_eq!(merged.validate(), Err(ProfileError::NoReachableTransport));
    }

    #[test]
    fn empty_preferred_with_fallback_is_acceptable() {
        // allow_fallback=true means the selector can pick from
        // the global set, so an empty preferred list is fine.
        let overrides = ProfileOverrides {
            transport_bias: Some(TransportBias {
                preferred: &[],
                allow_fallback: true,
            }),
            ..Default::default()
        };
        let merged = Class::Interactive.profile_with_overrides(&overrides);
        assert!(merged.validate().is_ok());
    }

    #[test]
    fn apply_to_checked_returns_merged_profile_on_success() {
        // Hop cap is now 3 (was 6 historically). hop_count=3 is
        // the in-range upper bound.
        let overrides = ProfileOverrides {
            hop_count: Some(3),
            ..Default::default()
        };
        let merged = overrides
            .apply_to_checked(&Class::Interactive.default_profile())
            .expect("hop_count=3 is in range");
        assert_eq!(merged.hop_count, 3);
        assert_eq!(merged.class, Class::Interactive);
    }
}
