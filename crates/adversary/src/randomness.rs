//! Randomness adversary - statistical uniformity tests on opaque-transport
//! wire bytes.
//!
//! # Why this exists
//!
//! Mirage's T1 claim for its opaque transports (obfs-tcp, Shadowsocks-
//! 2022, and the Reality auth-probe MAC) is that the on-wire bytes are
//! **indistinguishable from uniform random** - there is no protocol-specific
//! structure for a signature-DPI to key on. Real censors (the GFW most
//! famously) run exactly the inverse test: an **entropy / randomness classifier**
//! that flags "too-uniform from byte 0" *and* "not-uniform-enough." Either
//! verdict is a distinguisher.
//!
//! This adversary turns that censor capability into a runnable test. It is the
//! byte-entropy counterpart to [`crate::flow_classifier`]'s flow-shape
//! distinguisher - together they cover the two dominant passive-DPI axes
//! (per-packet byte distribution + cross-packet size/timing distribution).
//!
//! # The battery
//!
//! Three standard, dependency-free statistical tests over a byte sample:
//!
//! - **Monobit (frequency):** the count of 1-bits should be ~ `n/2`; reported
//!   as a z-score. A truncation/encoding bug that biases the high bit shows up
//!   here immediately. (NIST SP 800-22 §2.1.)
//! - **Byte chi-square:** the 256 byte values should be uniformly distributed;
//!   a structural marker (a fixed prefix, a low-entropy field) inflates the
//!   statistic. (256 bins, 255 dof.)
//! - **Per-bit-position bias:** each of the 8 bit positions should be `1` ~ 50%
//!   of the time; catches a single skewed bit a whole-sample monobit can mask.
//!
//! Thresholds are deliberately **lax** (~6σ on monobit, a p~0.001 chi-square
//! critical value, 3% per-bit) so a genuinely-uniform source never flakes; the
//! goal is to catch a *gross* regression (a future change that reintroduces
//! structure), not to be a NIST-grade RNG qualifier.
//!
//! # Scope notes (honoring the real wire formats)
//!
//! - The Reality auth-probe `session_id` is NOT uniform end-to-end: bytes 12-15
//!   are a plaintext timestamp. A correct adversary tests only the
//!   uniform slices (the 12-byte nonce + the 16-byte MAC), never the timestamp.
//! - obfs4's Elligator2 representative has a genuine uniformity subtlety (the
//!   curve->representative map); testing it validates the external
//!   `curve25519-elligator2` crate. It needs a public sampling hook on the
//!   obfs4 crate - tracked as the v2 target. v1 covers the in-reach uniform
//!   fields (the obfs-tcp BLAKE3 auth tag).

use crate::{AdversaryResult, DetectionVerdict};

/// Sample size for the in-crate adversaries: 16 KiB (~131k bits, ~64 samples
/// per byte-bin) - enough for a stable chi-square while staying instant.
pub const SAMPLE_BYTES: usize = 16384;

/// Monobit z-score tolerance (~6σ; a uniform source exceeds this with
/// probability ~ 2e-9).
pub const MONOBIT_Z_MAX: f64 = 6.0;

/// Byte chi-square critical value (255 dof, ~p=0.001). A uniform sample stays
/// well under this; a structural marker blows past it.
pub const CHI2_BYTE_MAX: f64 = 360.0;

/// Maximum per-bit-position deviation from 0.5 (3% - ~7σ at 16 KiB).
pub const BIT_BIAS_MAX: f64 = 0.03;

/// Outcome of the uniformity battery over a byte sample.
#[derive(Debug, Clone)]
pub struct UniformityReport {
    /// Monobit z-score (signed).
    pub monobit_z: f64,
    /// Byte-value chi-square statistic (255 dof).
    pub chi2_byte: f64,
    /// Largest per-bit-position deviation from 0.5.
    pub max_bit_bias: f64,
    /// Number of bytes tested.
    pub n: usize,
}

impl UniformityReport {
    /// Whether every test is within its (lax) tolerance.
    pub fn within_tolerance(&self) -> bool {
        self.monobit_z.abs() <= MONOBIT_Z_MAX
            && self.chi2_byte <= CHI2_BYTE_MAX
            && self.max_bit_bias <= BIT_BIAS_MAX
    }

    /// The first failing test, if any (for citing the distinguisher).
    pub fn first_failure(&self) -> Option<String> {
        if self.monobit_z.abs() > MONOBIT_Z_MAX {
            Some(format!(
                "monobit z={:.2} exceeds +/-{MONOBIT_Z_MAX} (bit-frequency bias)",
                self.monobit_z
            ))
        } else if self.chi2_byte > CHI2_BYTE_MAX {
            Some(format!(
                "byte chi-square {:.1} exceeds {CHI2_BYTE_MAX} (non-uniform byte distribution)",
                self.chi2_byte
            ))
        } else if self.max_bit_bias > BIT_BIAS_MAX {
            Some(format!(
                "per-bit bias {:.4} exceeds {BIT_BIAS_MAX} (a skewed bit position)",
                self.max_bit_bias
            ))
        } else {
            None
        }
    }
}

/// Run the uniformity battery over `bytes`.
pub fn uniformity_report(bytes: &[u8]) -> UniformityReport {
    let n = bytes.len();
    let nbits = (n * 8) as f64;

    // Monobit: z = (ones - bits/2) / sqrt(bits/4).
    let ones: u64 = bytes.iter().map(|b| b.count_ones() as u64).sum();
    let monobit_z = if nbits > 0.0 {
        (ones as f64 - nbits / 2.0) / (nbits / 4.0).sqrt()
    } else {
        0.0
    };

    // Byte chi-square over 256 bins.
    let mut hist = [0u64; 256];
    for &b in bytes {
        hist[b as usize] += 1;
    }
    let expected = n as f64 / 256.0;
    let chi2_byte = if expected > 0.0 {
        hist.iter()
            .map(|&o| {
                let d = o as f64 - expected;
                d * d / expected
            })
            .sum()
    } else {
        0.0
    };

    // Per-bit-position bias: for each of 8 positions, fraction of 1s.
    let mut max_bit_bias = 0.0f64;
    if n > 0 {
        for pos in 0..8u8 {
            let ones_pos: u64 = bytes.iter().map(|b| ((b >> pos) & 1) as u64).sum();
            let frac = ones_pos as f64 / n as f64;
            max_bit_bias = max_bit_bias.max((frac - 0.5).abs());
        }
    }

    UniformityReport {
        monobit_z,
        chi2_byte,
        max_bit_bias,
        n,
    }
}

/// Verdict from the battery over a byte sample: `Defended` if uniform within
/// tolerance, `Distinguished` (citing the failing test) otherwise,
/// `Inconclusive` if the sample is too small for a meaningful chi-square.
pub fn uniformity_verdict(bytes: &[u8]) -> AdversaryResult {
    // Chi-square needs an expected count >= ~5 per bin (256 bins -> >= 1280 B).
    if bytes.len() < 1280 {
        return Ok(DetectionVerdict::Inconclusive(format!(
            "need >= 1280 bytes for a meaningful byte chi-square; got {}",
            bytes.len()
        )));
    }
    let r = uniformity_report(bytes);
    match r.first_failure() {
        None => Ok(DetectionVerdict::Defended),
        Some(reason) => Ok(DetectionVerdict::Distinguished(format!(
            "wire bytes are NOT indistinguishable from random: {reason}"
        ))),
    }
}

/// **Randomness adversary - obfs-tcp auth tag.** The obfs-tcp handshake's
/// 32-byte auth tag is a BLAKE3-keyed PRF output; a censor's entropy classifier
/// must not distinguish a stream of them from random. Generates
/// [`SAMPLE_BYTES`] of tags (deterministic, fixed key + counter nonces) and runs
/// the battery.
pub fn obfs_auth_tag_uniformity() -> AdversaryResult {
    let bridge_pk = [0x42u8; 32];
    let mut bytes = Vec::with_capacity(SAMPLE_BYTES + 32);
    let mut ctr: u64 = 0;
    while bytes.len() < SAMPLE_BYTES {
        let mut nonce = [0u8; 32];
        nonce[..8].copy_from_slice(&ctr.to_le_bytes());
        let tag = mirage_transport_obfs::obfs_auth_tag(&bridge_pk, &nonce);
        bytes.extend_from_slice(&tag);
        ctr += 1;
    }
    uniformity_verdict(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic uniform stream: BLAKE3 in counter mode (a PRF, so its
    /// output is uniform) - reproducible, never flaky.
    fn uniform_stream(n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n + 32);
        let mut ctr: u64 = 0;
        while out.len() < n {
            let h = mirage_crypto::blake3::hash(&ctr.to_le_bytes());
            out.extend_from_slice(h.as_bytes());
            ctr += 1;
        }
        out.truncate(n);
        out
    }

    #[test]
    fn uniform_input_is_defended() {
        let v = uniformity_verdict(&uniform_stream(SAMPLE_BYTES)).unwrap();
        assert!(v.is_defended(), "BLAKE3-CTR stream must pass: {v:?}");
    }

    #[test]
    fn all_zero_input_is_distinguished() {
        let v = uniformity_verdict(&vec![0u8; SAMPLE_BYTES]).unwrap();
        assert!(v.is_distinguished(), "all-zero must be flagged: {v:?}");
    }

    #[test]
    fn high_bit_bias_is_distinguished() {
        // A "uniform" stream with the top bit of every byte forced to 0 - a
        // realistic truncation/encoding regression the monobit/bit-bias catches.
        let mut s = uniform_stream(SAMPLE_BYTES);
        for b in &mut s {
            *b &= 0x7F;
        }
        let v = uniformity_verdict(&s).unwrap();
        assert!(
            v.is_distinguished(),
            "high-bit-cleared must be flagged: {v:?}"
        );
    }

    #[test]
    fn structured_prefix_input_is_distinguished() {
        // Byte distribution skewed toward a structural marker (90% 0xAA).
        let mut s = uniform_stream(SAMPLE_BYTES);
        for (i, b) in s.iter_mut().enumerate() {
            if i % 10 != 0 {
                *b = 0xAA;
            }
        }
        let v = uniformity_verdict(&s).unwrap();
        assert!(v.is_distinguished(), "byte-skew must be flagged: {v:?}");
    }

    #[test]
    fn too_small_is_inconclusive() {
        let v = uniformity_verdict(&[0u8; 100]).unwrap();
        assert!(matches!(v, DetectionVerdict::Inconclusive(_)), "got {v:?}");
    }

    #[test]
    fn obfs_auth_tags_are_uniform() {
        // The load-bearing claim: obfs-tcp's BLAKE3 auth tag is indistinguishable
        // from random. If a future change biases it, this fires.
        let v = obfs_auth_tag_uniformity().unwrap();
        assert!(v.is_defended(), "obfs-tcp auth tag must be uniform: {v:?}");
    }
}
