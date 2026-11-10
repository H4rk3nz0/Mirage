//! Closed-loop self-adversary: the client runs a censor's own
//! fully-encrypted-traffic classifier against each transport's egress character
//! and folds the verdict back into transport selection as a predictive penalty.
//! (Current wiring uses a per-transport wire-character prior, not a live per-flow
//! tap - see "Current wiring vs. the forward-looking design" below.)
//!
//! # Why this exists
//!
//! The adaptive router ([`crate::adaptive`]) learns from dial OUTCOMES - a
//! transport that connects scores well, one that is blocked scores badly. But a
//! transport can connect *today* and still be trivially flaggable: a raw
//! uniformly-random carrier (Shadowsocks / obfs-style) sails through a naive
//! network yet is exactly what an entropy-DPI censor blocks the moment it looks.
//! By the time the block signal arrives, the client has already been fingerprinted.
//!
//! This module closes the loop: it evaluates the client's egress with the SAME
//! heuristic a real censor uses (Wu et al., USENIX Security 2023 - the GFW's
//! fully-encrypted-traffic classifier) and emits a **predictive** penalty, so the
//! router steers off an entropy-DPI-flaggable transport BEFORE the censor blocks
//! it. No upstream circumvention tool grades its own egress this way.
//!
//! # Stability
//!
//! A naive coupling (raw per-flow verdict straight into the bandit) oscillates.
//! Three dampers, all here:
//! - an **EWMA** over samples (`alpha`) smooths per-flow noise,
//! - a **min-sample** gate (hysteresis) reports zero penalty until there is
//!   enough evidence, and
//! - a bounded **max penalty** floors the reward multiplier at `1 - max_penalty`,
//!   so a flagged transport is dispreferred but never zeroed (it stays
//!   explorable - a censor's entropy rule can be lifted, mirroring the EXP3
//!   recovery floor).
//!
//! The verdict is keyed per network + transport (a transport flagged on one
//! network says nothing about another), matching the router's per-network state.
//!
//! # Current wiring vs. the forward-looking design
//!
//! The client currently feeds [`Self::observe`] a *representative* first-packet
//! sample per transport (a character model - what the carrier's outer framing
//! looks like), not a live per-flow socket tap. So the verdict is a constant per
//! transport, the loop reduces to standard EXP3 on stationary rewards (provably
//! convergent), and the EWMA / min-sample dampers are currently inert - stability
//! comes from EXP3's own de-biasing plus the bounded penalty. The dampers are
//! deliberately in place for when a live per-flow tap makes the sample stochastic
//! (a transport whose *actual* egress deviates from its intended character); at
//! that point the loop becomes non-stationary and this coupling must be
//! re-reviewed for oscillation.
//!
//! # Cost on benign (non-DPI) networks
//!
//! The penalty is an always-on prior: it disprefers raw-ciphertext carriers on
//! EVERY network, including ones that run no entropy-DPI, where such a carrier
//! would work fine and is often cheaper/faster. Because the verdict is a static
//! per-transport constant, this module cannot tell a DPI network from a benign
//! one (that would need either a live per-flow tap or a signal that entropy-DPI
//! was observed on this network). The `max_penalty` bound keeps the mild cost
//! contained - a dispreferred carrier stays explorable and, where it actually
//! works, its dial-success reward keeps it viable - so the net is a bounded
//! protocol-mimicry bias, appropriate as a default against censors that DO use
//! entropy-DPI, at a bounded cost where they do not.

use std::collections::HashMap;

use crate::success_rate::NetworkFingerprint;

/// Wu et al. (USENIX Security 2023) fully-encrypted-traffic classifier: the
/// heuristic the GFW uses to block protocols whose bytes look uniformly random
/// (Shadowsocks, obfs4, `VMess`, ...). A flow is **exempted** (allowed) if ANY of
/// a few "this looks like a real protocol, not raw ciphertext" rules fires; if
/// none fires the flow looks fully encrypted and is blocked.
///
/// Returns `true` if `bytes` would be classified **fully encrypted** (blockable),
/// i.e. no exemption applies. `false` = exempt (looks like a plaintext protocol
/// or a structured handshake), which is what a good carrier wants.
///
/// Exemptions (paper §4.2, `Ex1..Ex4`):
/// - `Ex1` popcount: average set-bits-per-byte outside `[3.4, 4.6]` (i.e. the
///   set-bit fraction outside `[0.425, 0.575]`) - a skew no CSPRNG output shows.
/// - `Ex2`: the first 6 bytes are all printable ASCII (`0x20..=0x7e`).
/// - `Ex3`: more than 50% of bytes are printable ASCII.
/// - `Ex4`: a contiguous printable-ASCII run longer than 20 bytes.
#[must_use]
pub fn looks_fully_encrypted(bytes: &[u8]) -> bool {
    // Nothing to judge (e.g. a zero-length probe) is not a blockable signal.
    if bytes.is_empty() {
        return false;
    }

    // Ex1: bit-population fraction. Uniform ciphertext sits at ~0.5.
    let set_bits: u64 = bytes.iter().map(|b| u64::from(b.count_ones())).sum();
    let total_bits = (bytes.len() as u64) * 8;
    let frac = set_bits as f64 / total_bits as f64;
    // 3.4/8 = 0.425, 4.6/8 = 0.575.
    if !(0.425..=0.575).contains(&frac) {
        return false;
    }

    let printable = |b: u8| (0x20..=0x7e).contains(&b);

    // Ex2: first six bytes printable (many protocols open with text).
    if bytes.len() >= 6 && bytes[..6].iter().all(|&b| printable(b)) {
        return false;
    }

    // Ex3: majority printable.
    let n_print = bytes.iter().filter(|&&b| printable(b)).count();
    if n_print * 2 > bytes.len() {
        return false;
    }

    // Ex4: a long contiguous printable run.
    let mut run = 0usize;
    for &b in bytes {
        if printable(b) {
            run += 1;
            if run > 20 {
                return false;
            }
        } else {
            run = 0;
        }
    }

    // No exemption fired: looks fully encrypted -> a censor blocks it.
    true
}

/// Tunables for [`SelfAdversary`].
#[derive(Debug, Clone, Copy)]
pub struct SelfAdversaryParams {
    /// EWMA weight for a fresh sample (damping). Smaller = smoother / slower.
    pub alpha: f64,
    /// Below this many observed samples, report zero penalty (hysteresis - do
    /// not react to a single noisy flow).
    pub min_samples: u32,
    /// Maximum reward penalty a fully-flagged transport suffers, in `[0, 1)`.
    /// The reward multiplier floors at `1 - max_penalty`, so a flagged transport
    /// is dispreferred but never zeroed (stays explorable).
    pub max_penalty: f64,
}

impl Default for SelfAdversaryParams {
    fn default() -> Self {
        Self {
            alpha: 0.2,
            min_samples: 3,
            max_penalty: 0.5,
        }
    }
}

#[derive(Clone, Copy)]
struct Score {
    ewma: f64,
    n: u32,
}

/// Per-`(network, transport)` damped estimate of how likely a censor's
/// fully-encrypted-traffic classifier is to flag this transport's egress, fed as
/// a predictive negative reward into [`crate::adaptive::AdaptiveRouter`].
///
/// One instance per client, alongside the router. Call [`Self::observe`] with a
/// sample of a transport's egress each time the client has bytes on the wire, and
/// fold [`Self::reward_multiplier`] into the reward passed to
/// `AdaptiveRouter::record`.
pub struct SelfAdversary {
    scores: HashMap<([u8; 16], &'static str), Score>,
    params: SelfAdversaryParams,
}

impl Default for SelfAdversary {
    fn default() -> Self {
        Self::new()
    }
}

impl SelfAdversary {
    /// Construct with default [`SelfAdversaryParams`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_params(SelfAdversaryParams::default())
    }

    /// Construct with explicit tunables (`alpha`/`min_samples`/`max_penalty` are
    /// clamped to sane ranges).
    #[must_use]
    pub fn with_params(params: SelfAdversaryParams) -> Self {
        Self {
            scores: HashMap::new(),
            params: SelfAdversaryParams {
                alpha: params.alpha.clamp(1e-3, 1.0),
                min_samples: params.min_samples.max(1),
                max_penalty: params.max_penalty.clamp(0.0, 0.99),
            },
        }
    }

    /// Fold an egress byte `sample` for `(network, transport)` into the estimate.
    /// The classifier's binary verdict is EWMA-smoothed; the first sample seeds
    /// the EWMA (so the estimate does not have to climb from zero).
    pub fn observe(
        &mut self,
        network: &NetworkFingerprint,
        transport: &'static str,
        sample: &[u8],
    ) {
        let blocked = f64::from(u8::from(looks_fully_encrypted(sample)));
        let alpha = self.params.alpha;
        let e = self
            .scores
            .entry((network.digest, transport))
            .or_insert(Score { ewma: 0.0, n: 0 });
        e.ewma = if e.n == 0 {
            blocked
        } else {
            (1.0 - alpha) * e.ewma + alpha * blocked
        };
        e.n = e.n.saturating_add(1);
    }

    /// Estimated block probability in `[0, 1]` for `(network, transport)`; `0.0`
    /// until at least `min_samples` observations (hysteresis).
    #[must_use]
    pub fn distinguishability(&self, network: &NetworkFingerprint, transport: &str) -> f64 {
        match self.scores.get(&(network.digest, transport)) {
            Some(s) if s.n >= self.params.min_samples => s.ewma,
            _ => 0.0,
        }
    }

    /// Reward multiplier in `[1 - max_penalty, 1]` to fold into the reward passed
    /// to `AdaptiveRouter::record`: `1.0` when the transport looks like a
    /// protocol (or too little evidence), down to `1 - max_penalty` when it
    /// consistently looks fully encrypted.
    #[must_use]
    pub fn reward_multiplier(&self, network: &NetworkFingerprint, transport: &str) -> f64 {
        1.0 - self.params.max_penalty * self.distinguishability(network, transport)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(tag: u8) -> NetworkFingerprint {
        NetworkFingerprint::from_digest([tag; 16])
    }

    /// Deterministic "ciphertext-like" bytes (SplitMix64-filled) - high entropy,
    /// ~0.5 set-bit fraction, no printable structure.
    fn random_like(n: usize, seed: u64) -> Vec<u8> {
        let mut x = seed;
        (0..n)
            .map(|_| {
                x = x.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
                let z = x ^ (x >> 31);
                (z >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn ciphertext_looks_fully_encrypted() {
        for seed in 0..32u64 {
            let s = random_like(512, seed.wrapping_mul(0x1234_5678).wrapping_add(1));
            assert!(
                looks_fully_encrypted(&s),
                "uniform ciphertext (seed {seed}) must be flagged fully-encrypted"
            );
        }
    }

    #[test]
    fn http_request_is_exempt() {
        let s = b"GET /index.html HTTP/1.1\r\nHost: cdn.example.com\r\n\r\n";
        assert!(!looks_fully_encrypted(s), "an HTTP request must be exempt");
    }

    #[test]
    fn all_zeros_exempt_via_bit_skew() {
        // All-zero (or all-one) payloads have a set-bit fraction far from 0.5, so
        // Ex1 exempts them - they are not fully-encrypted-looking.
        assert!(!looks_fully_encrypted(&[0u8; 256]));
        assert!(!looks_fully_encrypted(&[0xFFu8; 256]));
    }

    #[test]
    fn long_printable_run_is_exempt() {
        // Ciphertext with a >20-byte ASCII banner spliced in (e.g. an SNI /
        // plaintext header) trips Ex4 even though the rest is random.
        let mut s = random_like(512, 7);
        let banner = b"this-is-a-long-printable-banner-xyz";
        s[10..10 + banner.len()].copy_from_slice(banner);
        assert!(!looks_fully_encrypted(&s));
    }

    #[test]
    fn empty_sample_not_blockable() {
        assert!(!looks_fully_encrypted(&[]));
    }

    #[test]
    fn hysteresis_reports_zero_below_min_samples() {
        let mut sa = SelfAdversary::new(); // min_samples = 3
        let n = net(1);
        sa.observe(&n, "obfs", &random_like(256, 1));
        assert_eq!(sa.distinguishability(&n, "obfs"), 0.0, "1 sample < min");
        sa.observe(&n, "obfs", &random_like(256, 2));
        assert_eq!(sa.distinguishability(&n, "obfs"), 0.0, "2 samples < min");
        sa.observe(&n, "obfs", &random_like(256, 3));
        assert!(
            sa.distinguishability(&n, "obfs") > 0.9,
            "after 3 flagged samples the estimate is high"
        );
    }

    #[test]
    fn structured_transport_scores_zero() {
        let mut sa = SelfAdversary::new();
        let n = net(2);
        // A TLS-record-like sample: a structured header then ciphertext, but with
        // enough printable bytes to be exempt (as a real TLS flow's cleartext
        // record headers + SNI are).
        let sample = b"\x16\x03\x03\x00\x50 cdn.example.com ---- HTTP/1.1 200 OK ----";
        for _ in 0..8 {
            sa.observe(&n, "reality", sample);
        }
        assert_eq!(
            sa.distinguishability(&n, "reality"),
            0.0,
            "a protocol-shaped transport must not be penalised"
        );
        assert_eq!(sa.reward_multiplier(&n, "reality"), 1.0);
    }

    #[test]
    fn reward_multiplier_is_bounded_and_penalises_flagged() {
        let mut sa = SelfAdversary::new(); // max_penalty 0.5
        let n = net(3);
        for seed in 0..8u64 {
            sa.observe(&n, "obfs", &random_like(256, seed + 1));
        }
        let m = sa.reward_multiplier(&n, "obfs");
        assert!(
            (0.49..=0.51).contains(&m),
            "a consistently-flagged transport floors at 1 - max_penalty (~0.5), got {m}"
        );
        // Never below the floor even at full distinguishability.
        assert!(m >= 1.0 - 0.5 - 1e-9);
    }

    #[test]
    fn per_network_isolation() {
        let mut sa = SelfAdversary::new();
        let a = net(10);
        let b = net(20);
        for seed in 0..8u64 {
            sa.observe(&a, "obfs", &random_like(256, seed + 1));
        }
        assert!(sa.distinguishability(&a, "obfs") > 0.9, "network A flagged");
        assert_eq!(
            sa.distinguishability(&b, "obfs"),
            0.0,
            "network B has no data for the same transport - independent"
        );
    }

    #[test]
    fn closed_loop_steers_router_off_a_flagged_transport() {
        // The MECHANISM: two transports connect EQUALLY well (same base reward),
        // but one ("obfs") emits fully-encrypted-looking first packets and the
        // other ("reality") a structured one. Folding the self-adversary penalty
        // into the reward must make the adaptive router learn to prefer the exempt
        // transport. This proves the penalty CAUSES the steering (the A/B isolates
        // it); it does NOT prove the steering is beneficial in the wild - that
        // depends on the network actually running entropy-DPI, which this static
        // prior assumes rather than observes (see the module's benign-network note).
        use crate::adaptive::{AdaptiveRouter, Posture};
        use crate::success_rate::SuccessRateMap;
        use std::time::Instant;

        let candidates: [&'static str; 2] = ["reality", "obfs"];
        let http = b"GET / HTTP/1.1\r\nHost: cdn.example.com\r\n\r\n".to_vec();

        // Run the learning loop; `penalise` toggles whether the self-adversary
        // penalty is folded into the reward. Both transports SUCCEED equally;
        // only the egress character differs (obfs random/flagged, reality
        // http/exempt). Returns reality's share of a large post-learning sample.
        let run = |penalise: bool| -> f64 {
            let mut router = AdaptiveRouter::new(0x5EED);
            let mut sa = SelfAdversary::new();
            let n = net(7);
            let history = SuccessRateMap::new();
            let posture = Posture::open();
            for i in 0..300u64 {
                let now = Instant::now();
                let pick = router
                    .select(&n, &candidates, &history, &posture, now)
                    .unwrap();
                let witness = if pick == "obfs" {
                    random_like(64, i + 1)
                } else {
                    http.clone()
                };
                sa.observe(&n, pick, &witness);
                let reward = if penalise {
                    sa.reward_multiplier(&n, pick)
                } else {
                    1.0
                };
                router.record(&n, pick, reward);
            }
            let (mut r, mut o) = (0u32, 0u32);
            for _ in 0..4000 {
                match router
                    .select(&n, &candidates, &history, &posture, Instant::now())
                    .unwrap()
                {
                    "obfs" => o += 1,
                    _ => r += 1,
                }
            }
            f64::from(r) / f64::from(r + o)
        };

        // A/B on the SAME seed, so the only difference between runs is the
        // self-adversary penalty - isolating its causal effect. It must shift the
        // learned distribution toward the exempt transport by a clear margin,
        // while the bounded penalty (and the router's diversity cap) keep the
        // flagged one explorable rather than abandoned.
        let control = run(false);
        let treated = run(true);
        assert!(
            treated > control + 0.08,
            "self-adversary must steer toward the exempt transport: control {control:.3} -> \
             treated {treated:.3}"
        );
        assert!(
            (0.05..0.95).contains(&treated),
            "both transports stay explorable under the bounded penalty: {treated:.3}"
        );
    }

    #[test]
    fn ewma_recovers_when_egress_changes() {
        // A transport flagged early but later structured (e.g. gains an obfs
        // wrapper) should see its penalty decay, not stick forever.
        let mut sa = SelfAdversary::new();
        let n = net(4);
        for seed in 0..8u64 {
            sa.observe(&n, "obfs", &random_like(256, seed + 1));
        }
        let hi = sa.distinguishability(&n, "obfs");
        let exempt = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        for _ in 0..20 {
            sa.observe(&n, "obfs", exempt);
        }
        let lo = sa.distinguishability(&n, "obfs");
        assert!(
            lo < hi * 0.5,
            "penalty decays as egress becomes structured: {hi} -> {lo}"
        );
    }
}
