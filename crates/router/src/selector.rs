//! Hop selection.
//!
//! Given a [`CircuitProfile`] and a catalogue of available bridges,
//! pick the `profile.hop_count` bridges that will form the circuit's
//! hops. Output is a `Vec<HopSpec>` ready to hand to
//! [`mirage_circuit::CircuitBuilder::new`].
//!
//! # Anti-affinity guarantees (normative)
//!
//! 1. **Operator anti-affinity** - no two hops in a single circuit
//!    are run by the same operator (same `operator_id`). A hostile
//!    operator running 3 nodes cannot land all 3 on a circuit.
//! 2. **IP-prefix anti-affinity** - no two hops share the same
//!    /24 (IPv4) or /48 (IPv6). Defends against same-ISP / same-
//!    rack collusion + against a single network observer correlating
//!    multiple hops by adjacency.
//! 3. **Transport-bias filter** - every selected hop MUST advertise
//!    at least one transport from `profile.transport_bias.preferred`.
//!    If `profile.transport_bias.allow_fallback = false` (Realtime),
//!    this is mandatory; if `true`, hops without a preferred
//!    transport are de-prioritised but acceptable as a fallback.
//!
//! # Determinism
//!
//! `HopSelector::select` is deterministic given the same
//! `(profile, catalogue, identity_salt)`. Repeated calls produce the
//! same hops - useful for retries that shouldn't spuriously rotate
//! bridges. Callers seeking variability per build SHOULD vary
//! `identity_salt`.
//!
//! # Determinism choice (informative)
//!
//! Picking deterministically from a fresh CSPRNG salt at session
//! startup balances two goals:
//!
//! - **Within a session**: same circuit-class consistently picks
//!   the same hop set (good for stream-isolation slot reuse).
//! - **Across sessions**: a fresh salt rotates the hop set entirely
//!   (defeats long-term per-client fingerprinting).
//!
//! The salt is provided by the caller; the selector itself is
//! salt-stateless.

use crate::profile::CircuitProfile;
use mirage_circuit::{HopEndpoint, HopSpec};
use mirage_crypto::blake3;
use mirage_discovery::wire::{transport_caps, Announcement, Endpoint};
use std::collections::HashSet;
use std::time::{Duration, Instant};
use thiserror::Error;

// BridgeCandidate

/// One bridge entry in the discovery catalogue.
///
/// Contains everything `HopSelector` needs to evaluate and rank a
/// candidate. Constructed by the discovery layer (Phase 2 wiring) -
/// this struct is the contract between discovery and the router.
#[derive(Debug, Clone)]
pub struct BridgeCandidate {
    /// Static x25519 public key. Identifies the bridge cryptographically.
    pub static_pk: [u8; 32],
    /// Network endpoint where the bridge is reachable.
    pub endpoint: HopEndpoint,
    /// Operator-id (16-byte BLAKE3 of operator-public-key + label).
    /// Bridges run by the same operator MUST share an `operator_id`.
    /// The discovery layer surfaces this from the announcement
    /// signing key (an operator's bridges are all signed by their
    /// long-term identity).
    pub operator_id: [u8; 16],
    /// Transport names this bridge supports. Names match
    /// [`mirage_transport::ClientTransport::name`] return values.
    /// Owned `Vec` (rather than `&'static [&'static str]`) so the
    /// list can be built at runtime from a `transport_caps`
    /// bitfield via
    /// [`mirage_discovery::wire::transport_caps::names_for_caps`].
    pub transports: Vec<&'static str>,
    /// Last time the discovery layer observed this bridge alive.
    /// Used by [`filter_fresh`] to drop stale candidates before
    /// selection. `None` is treated as "freshness-unknown" and
    /// retained - discovery layers without per-bridge timestamps
    /// don't accidentally lose every candidate.
    ///
    /// Closes [RT-H8].
    pub last_seen: Option<Instant>,
}

impl BridgeCandidate {
    /// Construct from a verified [`Announcement`] + the operator
    /// pk that signed it. Caller MUST have already verified the
    /// signature; this constructor does NOT re-verify.
    ///
    /// `last_seen` SHOULD be the time the discovery layer last
    /// observed this announcement (DHT response timestamp, Nostr
    /// event time, etc.). Pass `None` if unknown - the candidate
    /// is then exempt from `filter_fresh`'s staleness drop.
    ///
    /// Closes [RT-H2/H3]: `operator_id` is derived canonically from
    /// the operator pk, transports are derived from the
    /// announcement's `transport_caps` bitfield, and the IP-prefix
    /// anti-affinity input is captured from the primary endpoint.
    ///
    /// Returns [`SelectorError::NoTransports`] if `transport_caps`
    /// resolves to an empty name list (closes [RT-S5]). The wire
    /// decoder already enforces non-zero caps; this guard catches
    /// direct struct construction that bypassed it.
    pub fn from_announcement(
        announcement: &Announcement,
        operator_pk: &[u8; 32],
        last_seen: Option<Instant>,
    ) -> Result<Self, SelectorError> {
        let transports = transport_caps::names_for_caps(announcement.transport_caps);
        if transports.is_empty() {
            return Err(SelectorError::NoTransports);
        }
        let endpoint = endpoint_to_hop_endpoint(&announcement.endpoint)?;
        Ok(Self {
            static_pk: announcement.bridge_x25519_pk,
            endpoint,
            operator_id: mirage_discovery::wire::operator_id_from_pk(operator_pk),
            transports,
            last_seen,
        })
    }
}

/// Convert the discovery wire's [`Endpoint`] to the circuit's
/// [`HopEndpoint`]. The two types are intentionally distinct (the
/// discovery layer accepts more variants for legacy reasons; the
/// circuit layer rejects deprecated ones), so the conversion
/// canonicalises.
///
/// Returns [`SelectorError::DomainEndpoint`] for `Endpoint::Domain`.
/// The previous behaviour silently rewrote these to `0.0.0.0:0`,
/// which created a recognisable fingerprint for any party watching
/// the candidate-construction path. Closes [RT-L1] (Phase 2E
/// re-scan). Callers MUST pre-resolve domain endpoints before
/// constructing a `BridgeCandidate`.
fn endpoint_to_hop_endpoint(ep: &Endpoint) -> Result<HopEndpoint, SelectorError> {
    match ep {
        Endpoint::Ipv4 { addr, port } => Ok(HopEndpoint::Ipv4 {
            addr: *addr,
            port: *port,
        }),
        Endpoint::Ipv6 { addr, port } => Ok(HopEndpoint::Ipv6 {
            addr: *addr,
            port: *port,
        }),
        Endpoint::Domain { .. } => Err(SelectorError::DomainEndpoint),
        Endpoint::OnionV3 { ascii, port } => Ok(HopEndpoint::OnionV3 {
            ascii: *ascii,
            port: *port,
        }),
    }
}

impl BridgeCandidate {
    /// True iff this candidate is fresher than `now - threshold`,
    /// or if its `last_seen` is `None` (unknown freshness retained).
    pub fn is_fresh(&self, now: Instant, threshold: Duration) -> bool {
        match self.last_seen {
            None => true,
            Some(last) => now.saturating_duration_since(last) < threshold,
        }
    }

    /// True iff this bridge supports any transport in `preferred`.
    fn supports_any(&self, preferred: &[&'static str]) -> bool {
        preferred
            .iter()
            .any(|p| self.transports.iter().any(|t| t == p))
    }

    /// IP prefix used for anti-affinity. Returns the /24 octet for
    /// IPv4 or /48 octet for IPv6. Onion endpoints have no IP and
    /// produce `None` (skipped from prefix anti-affinity since two
    /// onion-only hops aren't IP-correlatable in the same way).
    fn ip_prefix(&self) -> Option<[u8; 6]> {
        match &self.endpoint {
            HopEndpoint::Ipv4 { addr, .. } => {
                let mut prefix = [0u8; 6];
                prefix[..3].copy_from_slice(&addr[..3]);
                Some(prefix)
            }
            HopEndpoint::Ipv6 { addr, .. } => {
                let mut prefix = [0u8; 6];
                prefix.copy_from_slice(&addr[..6]);
                Some(prefix)
            }
            HopEndpoint::OnionV3 { .. } => None,
        }
    }
}

// SelectorError

/// Errors produced by hop selection.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SelectorError {
    /// Catalogue contains fewer bridges than the profile demands.
    #[error("catalogue has only {got} bridges; profile demands {need}")]
    InsufficientCatalogue {
        /// Hops the profile requested.
        need: usize,
        /// Bridges actually in the catalogue.
        got: usize,
    },
    /// After filtering by `transport_bias`, fewer than `need` bridges
    /// remain. With `allow_fallback = false` (Realtime), this is a
    /// hard failure.
    #[error("after transport filter, only {got} of {need} hops available")]
    InsufficientPreferredTransport {
        /// Hops needed.
        need: usize,
        /// Hops available with a preferred transport.
        got: usize,
    },
    /// Anti-affinity constraints (operator / IP-prefix) consumed
    /// the candidate pool before the requested hop count was met.
    #[error(
        "anti-affinity exhausted catalogue: picked {picked} of {need} \
         (insufficient operator or IP-prefix diversity)"
    )]
    AntiAffinityExhausted {
        /// Hops needed.
        need: usize,
        /// Hops actually picked before exhaustion.
        picked: usize,
    },
    /// Profile demands more hops than [`mirage_circuit::MAX_CIRCUIT_HOPS`].
    /// Should never fire under normal use - `default_profile` caps
    /// at 6.
    #[error("profile hop_count {0} exceeds circuit cap")]
    HopCountInvalid(u8),
    /// `BridgeCandidate::from_announcement` was called with an
    /// announcement whose `transport_caps` resolved to zero
    /// transport names. The wire decoder rejects empty caps
    /// directly, so this only fires on direct struct construction
    /// that bypassed the decoder. Closes [RT-S5].
    #[error("announcement carries no transports")]
    NoTransports,
    /// Announcement carries an `Endpoint::Domain` (deprecated for
    /// circuit hops). The previous behaviour silently
    /// rewrote these to `0.0.0.0:0`, which (a) is unroutable so
    /// the build fails anyway and (b) creates a fingerprint
    /// recognisable to any party who controls a transport-layer
    /// observer at the bridge cohort. Reject explicitly so
    /// callers either pre-resolve or skip the announcement.
    /// Closes [RT-L1] (Phase 2E re-scan).
    #[error("announcement carries a deprecated Domain endpoint; pre-resolve before constructing BridgeCandidate")]
    DomainEndpoint,
}

// HopSelector

/// Stateless hop selector.
///
/// Constructed once per client; `select` is called per-circuit-build.
pub struct HopSelector {
    /// Salt used to deterministically rank candidates. Rotated
    /// per-session by the caller; the selector itself is stateless.
    identity_salt: [u8; 16],
}

impl HopSelector {
    /// Construct with the given identity salt. Two selectors with
    /// the same salt produce the same hops for the same `(profile,
    /// catalogue)` inputs.
    pub fn new(identity_salt: [u8; 16]) -> Self {
        Self { identity_salt }
    }

    /// Pick `profile.hop_count` hops from `catalogue` honouring
    /// the anti-affinity + transport-bias constraints.
    ///
    /// Algorithm:
    ///
    /// 1. Validate profile and catalogue size.
    /// 2. Score each candidate: BLAKE3-keyed(salt, profile.class || `candidate.static_pk`)
    ///    -> 8-byte rank prefix. Lower prefix wins.
    /// 3. Sort candidates by rank ascending.
    /// 4. If `allow_fallback = false`: filter out candidates that
    ///    don't support a preferred transport. If `true`: stable-
    ///    partition so preferred-transport candidates come first
    ///    but non-preferred remain in the tail.
    /// 5. Walk the sorted candidates picking each that doesn't
    ///    violate operator-id or IP-prefix anti-affinity. Stop when
    ///    `hop_count` are picked.
    /// 6. If fewer than `hop_count` survive, return
    ///    `AntiAffinityExhausted`.
    pub fn select(
        &self,
        profile: &CircuitProfile,
        catalogue: &[BridgeCandidate],
    ) -> Result<Vec<HopSpec>, SelectorError> {
        let need = profile.hop_count as usize;
        if profile.hop_count == 0 || profile.hop_count as usize > mirage_circuit::MAX_CIRCUIT_HOPS {
            return Err(SelectorError::HopCountInvalid(profile.hop_count));
        }
        if catalogue.len() < need {
            return Err(SelectorError::InsufficientCatalogue {
                need,
                got: catalogue.len(),
            });
        }

        let allow_fallback = profile.transport_bias.allow_fallback;
        let preferred = profile.transport_bias.preferred;

        // Step 2 + 3: rank-and-sort.
        let mut ranked: Vec<(u64, &BridgeCandidate)> = catalogue
            .iter()
            .map(|c| (self.rank(profile, c), c))
            .collect();
        // Stable sort so equal ranks resolve by catalogue order
        // (deterministic across re-runs).
        ranked.sort_by_key(|(r, _)| *r);

        // Step 4: filter / partition by transport bias.
        let filtered: Vec<&BridgeCandidate> = if allow_fallback {
            // Partition: preferred-transport candidates first,
            // others after. Stable order within each partition.
            let (mut preferred_set, mut fallback_set): (Vec<_>, Vec<_>) = ranked
                .iter()
                .map(|(_, c)| *c)
                .partition(|c| c.supports_any(preferred));
            preferred_set.append(&mut fallback_set);
            preferred_set
        } else {
            // Strict: drop candidates that don't support a
            // preferred transport.
            let kept: Vec<&BridgeCandidate> = ranked
                .iter()
                .map(|(_, c)| *c)
                .filter(|c| c.supports_any(preferred))
                .collect();
            if kept.len() < need {
                return Err(SelectorError::InsufficientPreferredTransport {
                    need,
                    got: kept.len(),
                });
            }
            kept
        };

        // Step 5: greedy pick honouring anti-affinity.
        let mut picked: Vec<HopSpec> = Vec::with_capacity(need);
        let mut used_operators: HashSet<[u8; 16]> = HashSet::new();
        let mut used_prefixes: HashSet<[u8; 6]> = HashSet::new();
        for candidate in &filtered {
            if picked.len() == need {
                break;
            }
            if used_operators.contains(&candidate.operator_id) {
                continue;
            }
            if let Some(prefix) = candidate.ip_prefix() {
                if used_prefixes.contains(&prefix) {
                    continue;
                }
                used_prefixes.insert(prefix);
            }
            used_operators.insert(candidate.operator_id);
            picked.push(HopSpec {
                static_pk: candidate.static_pk,
                endpoint: candidate.endpoint.clone(),
            });
        }

        if picked.len() < need {
            return Err(SelectorError::AntiAffinityExhausted {
                need,
                picked: picked.len(),
            });
        }

        Ok(picked)
    }

    /// Selector salt (diagnostics).
    pub fn salt(&self) -> &[u8; 16] {
        &self.identity_salt
    }

    fn rank(&self, profile: &CircuitProfile, candidate: &BridgeCandidate) -> u64 {
        let mut hasher = blake3::Hasher::new_keyed(&{
            // Pad salt to 32 bytes for BLAKE3 keyed input.
            let mut k = [0u8; 32];
            k[..16].copy_from_slice(&self.identity_salt);
            k
        });
        hasher.update(profile.class.name().as_bytes());
        hasher.update(&candidate.static_pk);
        let out = *hasher.finalize().as_bytes();
        u64::from_be_bytes([
            out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7],
        ])
    }
}

/// Filter `candidates` to those fresher than `threshold` (or with
/// no freshness data). Caller's preferred entry point for closing
/// [RT-H8] - pre-filter the catalogue before passing to
/// [`HopSelector::select`].
///
/// Returns a new `Vec` rather than filtering in-place; the
/// catalogue is typically small (tens to hundreds of bridges) so
/// the allocation cost is negligible.
pub fn filter_fresh(
    candidates: &[BridgeCandidate],
    now: Instant,
    threshold: Duration,
) -> Vec<BridgeCandidate> {
    candidates
        .iter()
        .filter(|c| c.is_fresh(now, threshold))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::class::Class;

    fn ipv4_bridge(tag: u8, op: u8, transports: &[&'static str]) -> BridgeCandidate {
        BridgeCandidate {
            static_pk: [tag; 32],
            endpoint: HopEndpoint::Ipv4 {
                addr: [10, 0, tag, 1],
                port: 4433,
            },
            operator_id: [op; 16],
            transports: transports.to_vec(),
            last_seen: None,
        }
    }

    fn selector() -> HopSelector {
        HopSelector::new([0x42; 16])
    }

    // --- Construction + size validation ---

    #[test]
    fn empty_catalogue_rejected() {
        let s = selector();
        let p = Class::Interactive.default_profile();
        let err = s.select(&p, &[]).unwrap_err();
        assert!(matches!(err, SelectorError::InsufficientCatalogue { .. }));
    }

    #[test]
    fn under_size_catalogue_rejected() {
        let s = selector();
        let p = Class::Interactive.default_profile();
        let cat = vec![
            ipv4_bridge(1, 1, &["reality-v2"]),
            ipv4_bridge(2, 2, &["reality-v2"]),
        ];
        // Interactive needs 3 hops; only 2 in catalogue.
        let err = s.select(&p, &cat).unwrap_err();
        assert!(matches!(
            err,
            SelectorError::InsufficientCatalogue { need: 3, got: 2 }
        ));
    }

    // --- Operator anti-affinity ---

    #[test]
    fn same_operator_never_selected_twice() {
        let s = selector();
        let p = Class::Interactive.default_profile();
        // 3 bridges, all run by operator 1.
        let cat = vec![
            ipv4_bridge(1, 1, &["reality-v2"]),
            ipv4_bridge(2, 1, &["reality-v2"]),
            ipv4_bridge(3, 1, &["reality-v2"]),
        ];
        let err = s.select(&p, &cat).unwrap_err();
        assert!(matches!(
            err,
            SelectorError::AntiAffinityExhausted { picked: 1, .. }
        ));
    }

    #[test]
    fn distinct_operators_pass_anti_affinity() {
        let s = selector();
        let p = Class::Interactive.default_profile();
        let cat = vec![
            ipv4_bridge(1, 1, &["reality-v2"]),
            ipv4_bridge(2, 2, &["reality-v2"]),
            ipv4_bridge(3, 3, &["reality-v2"]),
        ];
        let hops = s.select(&p, &cat).unwrap();
        assert_eq!(hops.len(), 3);
        // All distinct pubkeys (i.e., all distinct bridges).
        let pks: HashSet<[u8; 32]> = hops.iter().map(|h| h.static_pk).collect();
        assert_eq!(pks.len(), 3);
    }

    // --- IP-prefix anti-affinity ---

    #[test]
    fn same_ipv4_24_prefix_never_selected_twice() {
        let s = selector();
        let p = Class::Interactive.default_profile();
        // 3 bridges in the same /24 (10.0.7.x).
        let mut cat: Vec<BridgeCandidate> = (1..=3)
            .map(|i| BridgeCandidate {
                static_pk: [i; 32],
                endpoint: HopEndpoint::Ipv4 {
                    addr: [10, 0, 7, i],
                    port: 4433,
                },
                operator_id: [i; 16],
                transports: vec!["reality-v2"],
                last_seen: None,
            })
            .collect();
        // Add a 4th in a DIFFERENT /24 - needed since /24 anti-
        // affinity rejects all 3 of the above after the first.
        cat.push(BridgeCandidate {
            static_pk: [99; 32],
            endpoint: HopEndpoint::Ipv4 {
                addr: [10, 0, 8, 1],
                port: 4433,
            },
            operator_id: [99; 16],
            transports: vec!["reality-v2"],
            last_seen: None,
        });
        // Only 2 prefixes available (10.0.7.0/24 and 10.0.8.0/24)
        // -> can pick at most 2 distinct-prefix hops.
        let err = s.select(&p, &cat).unwrap_err();
        assert!(matches!(
            err,
            SelectorError::AntiAffinityExhausted { picked: 2, .. }
        ));
    }

    // --- Transport bias ---

    #[test]
    fn realtime_strict_no_fallback_excludes_non_preferred_transports() {
        let s = selector();
        let p = Class::Realtime.default_profile();
        assert!(!p.transport_bias.allow_fallback);
        // 5 bridges, none of which support MASQUE or WebRTC.
        let cat: Vec<BridgeCandidate> = (1..=5)
            .map(|i| ipv4_bridge(i, i, &["reality-v2", "obfs-tcp"]))
            .collect();
        let err = s.select(&p, &cat).unwrap_err();
        assert!(matches!(
            err,
            SelectorError::InsufficientPreferredTransport { .. }
        ));
    }

    #[test]
    fn realtime_picks_only_preferred_transport_bridges() {
        let s = selector();
        let p = Class::Realtime.default_profile();
        // Mix: 2 MASQUE-capable, 3 reality-only.
        let cat = vec![
            ipv4_bridge(1, 1, &["quic-masque"]),
            ipv4_bridge(2, 2, &["reality-v2"]),
            ipv4_bridge(3, 3, &["webrtc"]),
            ipv4_bridge(4, 4, &["reality-v2"]),
            ipv4_bridge(5, 5, &["obfs-tcp"]),
        ];
        // Realtime needs 2 hops, both MUST support a preferred transport.
        let hops = s.select(&p, &cat).unwrap();
        assert_eq!(hops.len(), 2);
        // All picked bridges have static_pk in {1, 3} (the MASQUE/WebRTC ones).
        for h in &hops {
            assert!(
                h.static_pk == [1; 32] || h.static_pk == [3; 32],
                "picked bridge with non-preferred transport: {:?}",
                h.static_pk
            );
        }
    }

    #[test]
    fn interactive_with_fallback_prefers_preferred_but_falls_back() {
        let s = selector();
        let p = Class::Interactive.default_profile();
        assert!(p.transport_bias.allow_fallback);
        // Mix: 2 reality-capable, 3 random-transport.
        let cat = vec![
            ipv4_bridge(1, 1, &["reality-v2"]),
            ipv4_bridge(2, 2, &["quic-masque"]),
            ipv4_bridge(3, 3, &["webrtc"]),
            ipv4_bridge(4, 4, &["reality-v2"]),
            ipv4_bridge(5, 5, &["obfs-tcp"]),
        ];
        let hops = s.select(&p, &cat).unwrap();
        assert_eq!(hops.len(), 3);
        // Selector ranks reality-v2 + obfs-tcp candidates first
        // (preferred), so they should fill before quic-masque/webrtc.
        // The exact ordering depends on the BLAKE3 rank, but at
        // minimum the preferred-transport bridges (1, 4, 5) outnumber
        // non-preferred (2, 3) so the picked set should contain all
        // 3 of the preferred ones.
        let pks: HashSet<[u8; 32]> = hops.iter().map(|h| h.static_pk).collect();
        let preferred_pks: HashSet<[u8; 32]> =
            [[1; 32], [4; 32], [5; 32]].iter().copied().collect();
        assert_eq!(
            pks, preferred_pks,
            "Interactive with fallback should fill from preferred-transport first"
        );
    }

    // --- Determinism ---

    #[test]
    fn same_salt_produces_same_selection() {
        let s1 = HopSelector::new([0x42; 16]);
        let s2 = HopSelector::new([0x42; 16]);
        let p = Class::Interactive.default_profile();
        let cat: Vec<BridgeCandidate> = (1..=8)
            .map(|i| ipv4_bridge(i, i, &["reality-v2"]))
            .collect();
        let h1 = s1.select(&p, &cat).unwrap();
        let h2 = s2.select(&p, &cat).unwrap();
        let pks1: Vec<[u8; 32]> = h1.iter().map(|h| h.static_pk).collect();
        let pks2: Vec<[u8; 32]> = h2.iter().map(|h| h.static_pk).collect();
        assert_eq!(pks1, pks2);
    }

    #[test]
    fn different_salts_produce_different_selections() {
        // Probabilistic; 10 candidates ranked by 8-byte BLAKE3 prefix.
        // Two different salts producing the SAME ordering for the
        // first 3 picks is ~1 in 2^192 - statistically zero.
        let s1 = HopSelector::new([0x01; 16]);
        let s2 = HopSelector::new([0x02; 16]);
        let p = Class::Interactive.default_profile();
        let cat: Vec<BridgeCandidate> = (1..=10)
            .map(|i| ipv4_bridge(i, i, &["reality-v2"]))
            .collect();
        let h1 = s1.select(&p, &cat).unwrap();
        let h2 = s2.select(&p, &cat).unwrap();
        let pks1: Vec<[u8; 32]> = h1.iter().map(|h| h.static_pk).collect();
        let pks2: Vec<[u8; 32]> = h2.iter().map(|h| h.static_pk).collect();
        assert_ne!(pks1, pks2);
    }

    // --- Class isolation in ranking ---

    #[test]
    fn different_classes_produce_independent_orderings() {
        // The rank inputs `profile.class.name()` so Interactive and
        // Bulk produce independent orderings even with the same salt
        // and catalogue. This is the "stream-isolation across classes"
        // property - different traffic types don't share circuits.
        let s = selector();
        let cat: Vec<BridgeCandidate> = (1..=10)
            .map(|i| ipv4_bridge(i, i, &["reality-v2"]))
            .collect();
        let h_int = s
            .select(&Class::Interactive.default_profile(), &cat)
            .unwrap();
        let h_bulk = s.select(&Class::Bulk.default_profile(), &cat).unwrap();
        // Interactive picks 3, Bulk picks 3 - they MAY or MAY NOT
        // overlap, but the rank ORDERING within each picked set is
        // class-dependent. Test: the SET of picked bridges differs
        // between classes for at least one bridge.
        let int_pks: HashSet<[u8; 32]> = h_int.iter().map(|h| h.static_pk).collect();
        let bulk_pks: HashSet<[u8; 32]> = h_bulk.iter().map(|h| h.static_pk).collect();
        assert_ne!(
            int_pks, bulk_pks,
            "Interactive and Bulk should not pick identical bridge sets"
        );
    }

    // --- Hop count matches profile ---

    #[test]
    fn realtime_picks_exactly_two_hops() {
        let s = selector();
        let p = Class::Realtime.default_profile();
        let cat: Vec<BridgeCandidate> = (1..=10)
            .map(|i| ipv4_bridge(i, i, &["quic-masque"]))
            .collect();
        let hops = s.select(&p, &cat).unwrap();
        assert_eq!(hops.len(), 2);
    }

    #[test]
    fn onion_service_picks_three_hops() {
        // Hop cap is 3 across all profiles. OnionService no
        // longer stacks 6 - anonymity beyond a 3-hop chain
        // comes from multi-entry concurrency at the pool
        // layer, not chain depth.
        let s = selector();
        let p = Class::OnionService.default_profile();
        let cat: Vec<BridgeCandidate> = (1..=12)
            .map(|i| ipv4_bridge(i, i, &["reality-v2"]))
            .collect();
        let hops = s.select(&p, &cat).unwrap();
        assert_eq!(hops.len(), 3);
    }

    // --- Freshness filtering (RT-H8 closure) ---

    #[test]
    fn filter_fresh_drops_stale_entries() {
        let now = Instant::now();
        let threshold = Duration::from_secs(60);
        let stale = BridgeCandidate {
            last_seen: Some(now.checked_sub(Duration::from_secs(120)).unwrap()),
            ..ipv4_bridge(1, 1, &["reality-v2"])
        };
        let fresh = BridgeCandidate {
            last_seen: Some(now.checked_sub(Duration::from_secs(10)).unwrap()),
            ..ipv4_bridge(2, 2, &["reality-v2"])
        };
        let unknown = ipv4_bridge(3, 3, &["reality-v2"]); // last_seen: None
        let cat = vec![stale, fresh, unknown];
        let kept = filter_fresh(&cat, now, threshold);
        assert_eq!(kept.len(), 2);
        let pks: Vec<[u8; 32]> = kept.iter().map(|c| c.static_pk).collect();
        assert!(pks.contains(&[2; 32]), "fresh kept");
        assert!(pks.contains(&[3; 32]), "unknown-freshness kept");
        assert!(!pks.contains(&[1; 32]), "stale dropped");
    }

    #[test]
    fn is_fresh_with_unknown_last_seen_returns_true() {
        let c = ipv4_bridge(1, 1, &["reality-v2"]);
        assert!(c.is_fresh(Instant::now(), Duration::from_secs(60)));
    }

    #[test]
    fn is_fresh_with_recent_last_seen_returns_true() {
        let now = Instant::now();
        let c = BridgeCandidate {
            last_seen: Some(now.checked_sub(Duration::from_secs(10)).unwrap()),
            ..ipv4_bridge(1, 1, &["reality-v2"])
        };
        assert!(c.is_fresh(now, Duration::from_secs(60)));
    }

    #[test]
    fn is_fresh_with_stale_last_seen_returns_false() {
        let now = Instant::now();
        let c = BridgeCandidate {
            last_seen: Some(now.checked_sub(Duration::from_secs(120)).unwrap()),
            ..ipv4_bridge(1, 1, &["reality-v2"])
        };
        assert!(!c.is_fresh(now, Duration::from_secs(60)));
    }

    // --- BridgeCandidate::from_announcement (RT-H2/H3 closure) ---

    fn fake_announcement(transport_caps: u32) -> Announcement {
        Announcement {
            issued_at: 1_700_000_000,
            expires_at: 1_700_000_000 + 3600,
            bridge_ed25519_pk: [0xAA; 32],
            bridge_x25519_pk: [0xBB; 32],
            transport_caps,
            endpoint: Endpoint::Ipv4 {
                addr: [203, 0, 113, 5],
                port: 4433,
            },
            extra_endpoints: Vec::new(),
            signature: [0; 64],
        }
    }

    #[test]
    fn from_announcement_populates_operator_id_canonically() {
        let ann = fake_announcement(transport_caps::REALITY_V2);
        let op_pk = [0x42u8; 32];
        let cand = BridgeCandidate::from_announcement(&ann, &op_pk, None).unwrap();
        let expected_op_id = mirage_discovery::wire::operator_id_from_pk(&op_pk);
        assert_eq!(cand.operator_id, expected_op_id);
    }

    #[test]
    fn from_announcement_maps_transport_caps_to_names() {
        let caps = transport_caps::REALITY_V2 | transport_caps::OBFS_TCP;
        let ann = fake_announcement(caps);
        let cand = BridgeCandidate::from_announcement(&ann, &[0; 32], None).unwrap();
        assert_eq!(cand.transports, vec!["reality-v2", "obfs-tcp"]);
    }

    #[test]
    fn from_announcement_carries_endpoint_for_ip_prefix_check() {
        let ann = fake_announcement(transport_caps::REALITY_V2);
        let cand = BridgeCandidate::from_announcement(&ann, &[0; 32], None).unwrap();
        // Endpoint preserved as-is - the selector's ip_prefix()
        // method will derive the /24 from this.
        match cand.endpoint {
            HopEndpoint::Ipv4 { addr, port } => {
                assert_eq!(addr, [203, 0, 113, 5]);
                assert_eq!(port, 4433);
            }
            _ => panic!("expected ipv4"),
        }
    }

    #[test]
    fn from_announcement_uses_bridge_x25519_pk_as_static_pk() {
        // The HopSelector uses static_pk (bridge x25519) for
        // Mirage handshakes, NOT the operator's pk. Verify the
        // constructor pulls the right field.
        let ann = fake_announcement(transport_caps::REALITY_V2);
        let cand = BridgeCandidate::from_announcement(&ann, &[0x42; 32], None).unwrap();
        assert_eq!(cand.static_pk, ann.bridge_x25519_pk);
        assert_ne!(cand.static_pk, [0x42; 32], "must use bridge pk, not op pk");
    }

    #[test]
    fn from_announcement_rejects_empty_transports() {
        // RT-S5 closure: a directly-constructed announcement with
        // transport_caps = 0 produces an empty Vec<&'static str>.
        // Constructor returns an explicit error rather than silently
        // building a candidate the selector would always filter.
        let mut ann = fake_announcement(transport_caps::REALITY_V2);
        ann.transport_caps = 0;
        let err = BridgeCandidate::from_announcement(&ann, &[0; 32], None).unwrap_err();
        assert_eq!(err, SelectorError::NoTransports);
    }

    #[test]
    fn from_announcement_rejects_domain_endpoint() {
        // RT-L1 closure (Phase 2E re-scan): a candidate carrying
        // a deprecated Domain endpoint must be rejected at the
        // constructor, not silently rewritten to 0.0.0.0:0.
        // The previous fallback created a recognisable fingerprint
        // for any party watching candidate construction.
        let mut ann = fake_announcement(transport_caps::REALITY_V2);
        ann.endpoint = Endpoint::Domain {
            domain: "example.com".to_string(),
            port: 4433,
        };
        let err = BridgeCandidate::from_announcement(&ann, &[0; 32], None).unwrap_err();
        assert_eq!(err, SelectorError::DomainEndpoint);
    }

    #[test]
    fn from_announcement_propagates_last_seen() {
        let now = Instant::now();
        let ann = fake_announcement(transport_caps::REALITY_V2);
        let cand = BridgeCandidate::from_announcement(&ann, &[0; 32], Some(now)).unwrap();
        assert_eq!(cand.last_seen, Some(now));
    }

    #[test]
    fn operator_id_from_pk_is_deterministic() {
        let pk = [0x42u8; 32];
        let id1 = mirage_discovery::wire::operator_id_from_pk(&pk);
        let id2 = mirage_discovery::wire::operator_id_from_pk(&pk);
        assert_eq!(id1, id2);
        let id3 = mirage_discovery::wire::operator_id_from_pk(&[0x43u8; 32]);
        assert_ne!(id1, id3);
    }

    #[test]
    fn distinct_operators_via_announcement_pass_anti_affinity() {
        // End-to-end: 3 announcements signed by 3 distinct
        // operators (different op pks) -> 3 distinct operator_ids
        // -> selector picks all 3 for a 3-hop circuit.
        let ann = fake_announcement(transport_caps::REALITY_V2);
        let mut cat = Vec::new();
        for (i, op_pk) in [[0x01; 32], [0x02; 32], [0x03; 32]].iter().enumerate() {
            // Distinct bridge pks AND distinct /24 too.
            let mut a = ann.clone();
            a.bridge_x25519_pk = [(i as u8) + 1; 32];
            a.endpoint = Endpoint::Ipv4 {
                addr: [10, 0, (i as u8) + 1, 1],
                port: 4433,
            };
            cat.push(BridgeCandidate::from_announcement(&a, op_pk, None).unwrap());
        }
        let s = HopSelector::new([0x42; 16]);
        let p = Class::Interactive.default_profile();
        let hops = s.select(&p, &cat).unwrap();
        assert_eq!(hops.len(), 3);
    }

    // --- Reality-test: realistic adversary scenario ---

    #[test]
    fn hostile_operator_running_3_nodes_lands_at_most_one_on_circuit() {
        // RT-H2 closure: the red-team finding "hostile bridge
        // operator runs 3 nodes, hopes to land all 3 on a circuit"
        // is mitigated by operator anti-affinity. This is the
        // explicit unit test of that property.
        let s = selector();
        let p = Class::Interactive.default_profile();
        // Operator 1 runs bridges 1, 2, 3 - all the SAME operator_id.
        // Operators 2, 3, 4 each run one bridge.
        let cat = vec![
            ipv4_bridge(1, 1, &["reality-v2"]), // hostile
            ipv4_bridge(2, 1, &["reality-v2"]), // hostile
            ipv4_bridge(3, 1, &["reality-v2"]), // hostile
            ipv4_bridge(4, 2, &["reality-v2"]),
            ipv4_bridge(5, 3, &["reality-v2"]),
            ipv4_bridge(6, 4, &["reality-v2"]),
        ];
        let hops = s.select(&p, &cat).unwrap();
        assert_eq!(hops.len(), 3);
        // At most ONE hop has operator_id = 1.
        let hostile_count = hops
            .iter()
            .filter(|h| {
                // hop's static_pk maps back to candidate; bridges
                // 1, 2, 3 have op=1.
                h.static_pk[0] <= 3
            })
            .count();
        assert!(
            hostile_count <= 1,
            "hostile operator landed {hostile_count} of 3 hops; should be <= 1"
        );
    }
}
