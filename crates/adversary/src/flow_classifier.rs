//! Flow-shape distinguisher - a concrete, runnable F4.
//!
//! # Why this exists
//!
//! The F4 invariant ("Mirage traffic MUST be indistinguishable from
//! cover under an ML flow classifier") has, until now, been *aspirational* -
//! there was no classifier, so the claim was untestable. Every other adversary
//! in this crate models a hand-specified signal (a JA3 string, a fixed cell
//! length, a timing oracle). This one is different: it is a **learned**
//! distinguisher. You hand it a sample of Mirage flows and a sample of cover
//! (real-service) flows, and it asks the censor's actual question - *can any
//! simple classifier separate them better than chance?* - and answers with a
//! number.
//!
//! That turns "we believe we're unobservable" into a measured, CI-gateable
//! property, and gives the [`crate::flow_classifier::flow_shape_distinguisher`]
//! a concrete signal to cite when a future change regresses the flow shape
//! (e.g. the [`mirage_transport_reality::RecordShaper`] losing its variance, or
//! a transport reintroducing a fixed packet size).
//!
//! # The classifier
//!
//! v1 keys on the **record/packet size sequence** a passive observer sees (the
//! most ML-load-bearing flow feature, and the one the `RecordShaper` + Padme are
//! built to obscure). It extracts a small fixed feature vector per flow and, for
//! each feature, computes the **Mann-Whitney AUC** - the probability that the
//! feature ranks a Mirage flow above a cover flow. The best single feature's
//! achievable classifier accuracy (`max(auc, 1-auc)`) is the separability:
//! `0.5` = indistinguishable (the censor does no better than a coin flip),
//! `1.0` = perfectly separable. This is a deterministic, dependency-free,
//! offline distinguisher - no training loop, no float-fragile matrix inversion,
//! and it names the offending feature.
//!
//! A single best-feature threshold is intentionally *weaker* than a real
//! adversary's multi-feature model: if even this trivial classifier separates
//! Mirage, a real one certainly will, so `Distinguished` is a true positive.
//! `Defended` is the weaker claim "not separable by the best single feature" -
//! honest, and strengthened in v2 by adding feature axes (inter-arrival timing)
//! and a multivariate model.
//!
//! # Honesty about the verdict
//!
//! The verdict is only as meaningful as the `cover` sample. A *synthetic* cover
//! set proves the classifier RUNS and that Mirage's shape differs (or not) from
//! that synthetic baseline - it does NOT prove unobservability in the wild. A
//! load-bearing `Defended` requires a real-traffic capture as the cover set
//! (the same capture the [`mirage_transport_reality::SplitSource::Cdf`] needs).
//! Until then, treat `Defended`-against-synthetic as "the tool is wired and the
//! shaper isn't trivially separable," not "proven unobservable."

use crate::{AdversaryResult, DetectionVerdict};

/// One observed flow: the ordered sequence of wire record/packet sizes a
/// passive network observer sees. v1 keys on size only; inter-arrival timing
/// is the v2 feature axis.
#[derive(Debug, Clone)]
pub struct FlowTrace {
    /// Wire sizes of each record/packet in the flow, in order.
    pub record_sizes: Vec<u32>,
}

impl FlowTrace {
    /// Construct from a size sequence.
    pub fn new(record_sizes: Vec<u32>) -> Self {
        Self { record_sizes }
    }
}

/// Number of scalar features extracted per flow.
const N_FEATURES: usize = 14;

/// Human-readable feature names, index-aligned with [`features`].
///
/// The last three are **sequential** (order-dependent) features: unlike the
/// marginal features above them (which an i.i.d. size draw from the right CDF
/// already matches), these key on the *ordering* of the length sequence -
/// autocorrelation and run structure - which is exactly what TLS-in-TLS
/// detectors (Xue et al., USENIX '22/'24) exploit and what an i.i.d. record
/// shaper reproduces none of. They are the axis that separates a marginal-only
/// shaper (`cdf_split`) from a conditional record-length *process*.
pub const FEATURE_NAMES: [&str; N_FEATURES] = [
    "record_count",
    "total_bytes",
    "mean_size",
    "size_stddev",
    "min_size",
    "max_size",
    "size_range",
    "mean_abs_succ_diff",
    "frac_max_record",
    "distinct_sizes",
    "size_entropy_bits",
    "lag1_autocorr",
    "mean_run_length",
    "frac_size_repeats",
];

/// Largest TLS-1.3 record plaintext (2^14); a flow saturated with these is a
/// "bulk transfer" shape that a 1:1 transport leaks and a shaper should break.
const RECORD_MAX: u32 = 16384;

fn features(t: &FlowTrace) -> [f64; N_FEATURES] {
    let n = t.record_sizes.len();
    if n == 0 {
        return [0.0; N_FEATURES];
    }
    let s: Vec<f64> = t.record_sizes.iter().map(|&x| f64::from(x)).collect();
    let count = n as f64;
    let total: f64 = s.iter().sum();
    let mean = total / count;
    let var = s.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / count;
    let std = var.sqrt();
    let min = s.iter().copied().fold(f64::INFINITY, f64::min);
    let max = s.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let range = max - min;
    let masd = if n >= 2 {
        s.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f64>() / (n - 1) as f64
    } else {
        0.0
    };
    let frac_max = t.record_sizes.iter().filter(|&&x| x >= RECORD_MAX).count() as f64 / count;
    let distinct = {
        let mut v = t.record_sizes.clone();
        v.sort_unstable();
        v.dedup();
        v.len() as f64
    };
    let entropy = {
        use std::collections::HashMap;
        let mut hist: HashMap<u32, usize> = HashMap::new();
        for &x in &t.record_sizes {
            *hist.entry(x).or_default() += 1;
        }
        let mut e = 0.0;
        for &c in hist.values() {
            let p = c as f64 / count;
            e -= p * p.log2();
        }
        e
    };
    // ---- sequential (order-dependent) features ----
    // Lag-1 autocorrelation of the length sequence. ~0 for an i.i.d. size draw;
    // > 0 when equal/similar sizes cluster into runs (real TLS bulk transfers and
    // a conditional/Markov shaper), which is the structure an i.i.d. `cdf_split`
    // omits. Normalised by the full variance sum so |r| <= 1.
    let lag1_autocorr = if n >= 2 && var > 0.0 {
        let cov: f64 = s.windows(2).map(|w| (w[0] - mean) * (w[1] - mean)).sum();
        cov / (var * count)
    } else {
        0.0
    };
    // Run structure over exact-equal consecutive sizes. `transitions` counts
    // positions where the size changes; `num_runs = transitions + 1`.
    // `mean_run_length` ~ 1 for an i.i.d. draw over many buckets and grows as the
    // process makes same-size records cluster; `frac_size_repeats` is the share
    // of adjacent pairs with identical size.
    let (mean_run_length, frac_repeats) = if n >= 2 {
        let transitions = t.record_sizes.windows(2).filter(|w| w[0] != w[1]).count();
        let num_runs = transitions + 1;
        let repeats = (n - 1 - transitions) as f64 / (n - 1) as f64;
        (count / num_runs as f64, repeats)
    } else {
        (1.0, 0.0)
    };
    [
        count,
        total,
        mean,
        std,
        min,
        max,
        range,
        masd,
        frac_max,
        distinct,
        entropy,
        lag1_autocorr,
        mean_run_length,
        frac_repeats,
    ]
}

/// Mann-Whitney AUC of a single feature used as a threshold classifier:
/// `P(a > b) + 0.5*P(a == b)` over all class-A x class-B pairs - the
/// probability the feature ranks a class-A flow above a class-B flow. `0.5` is
/// chance. `O(|a|*|b|)`, fine for CI sample sizes.
fn single_feature_auc(a: &[f64], b: &[f64]) -> f64 {
    let total = (a.len() * b.len()) as f64;
    if total == 0.0 {
        return 0.5;
    }
    let mut wins = 0.0f64;
    for &ai in a {
        for &bj in b {
            if ai > bj {
                wins += 1.0;
            } else if (ai - bj).abs() < f64::EPSILON {
                wins += 0.5;
            }
        }
    }
    wins / total
}

/// How separable two sets of flows are.
#[derive(Debug, Clone)]
pub struct Distinguishability {
    /// Best single-feature classifier accuracy: `max over features of
    /// max(auc, 1-auc)`. `0.5` = indistinguishable, `1.0` = perfectly separable.
    pub best_accuracy: f64,
    /// The most-discriminating feature's name.
    pub top_feature: &'static str,
    /// The top feature's raw AUC (may be `< 0.5` if anti-correlated).
    pub top_auc: f64,
}

/// Minimum flows per class for a statistically meaningful verdict.
pub const MIN_SAMPLES: usize = 16;

/// "Close enough to chance" bar: best single-feature classifier accuracy at or
/// below this is treated as indistinguishable. `0.5` is perfect; `0.60` absorbs
/// modest finite-sample noise while still catching real separability. The F4
/// target is AUC ~ `0.5`.
pub const DEFAULT_MARGIN: f64 = 0.60;

/// Measure separability of two flow sets (no verdict / no sample-size gate).
pub fn measure(class_a: &[FlowTrace], class_b: &[FlowTrace]) -> Distinguishability {
    let fa: Vec<[f64; N_FEATURES]> = class_a.iter().map(features).collect();
    let fb: Vec<[f64; N_FEATURES]> = class_b.iter().map(features).collect();
    let mut best = Distinguishability {
        best_accuracy: 0.5,
        top_feature: FEATURE_NAMES[0],
        top_auc: 0.5,
    };
    for (i, &name) in FEATURE_NAMES.iter().enumerate() {
        let ai: Vec<f64> = fa.iter().map(|f| f[i]).collect();
        let bi: Vec<f64> = fb.iter().map(|f| f[i]).collect();
        let auc = single_feature_auc(&ai, &bi);
        let acc = auc.max(1.0 - auc);
        if acc > best.best_accuracy {
            best = Distinguishability {
                best_accuracy: acc,
                top_feature: name,
                top_auc: auc,
            };
        }
    }
    best
}

/// **`DistinguisherAdversary` (concrete F4).** A passive flow classifier: given a
/// sample of Mirage flows and a sample of cover (real-service) flows, can the
/// best single-feature threshold classifier separate them better than chance?
///
/// - `Defended` - best classifier accuracy <= `margin` (indistinguishable).
/// - `Distinguished(..)` - Mirage's flow shape is separable; cites the feature.
/// - `Inconclusive(..)` - fewer than [`MIN_SAMPLES`] flows in a class.
///
/// See the module docs on what a `Defended`-against-synthetic verdict does and
/// does NOT prove (a load-bearing verdict needs a real-traffic cover capture).
pub fn flow_shape_distinguisher(
    mirage: &[FlowTrace],
    cover: &[FlowTrace],
    margin: f64,
) -> AdversaryResult {
    if mirage.len() < MIN_SAMPLES || cover.len() < MIN_SAMPLES {
        return Ok(DetectionVerdict::Inconclusive(format!(
            "need >= {MIN_SAMPLES} flows per class; got mirage={} cover={}",
            mirage.len(),
            cover.len()
        )));
    }
    let d = measure(mirage, cover);
    if d.best_accuracy <= margin {
        Ok(DetectionVerdict::Defended)
    } else {
        Ok(DetectionVerdict::Distinguished(format!(
            "flow-shape feature '{}' separates Mirage from cover with \
             single-feature classifier accuracy {:.3} (AUC {:.3}); F4 target ~ 0.5",
            d.top_feature, d.best_accuracy, d.top_auc
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tiny deterministic LCG so tests are reproducible without a dep.
    struct Lcg(u64);
    impl Lcg {
        fn next_u32(&mut self) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }
        /// Uniform in [lo, hi].
        fn range(&mut self, lo: u32, hi: u32) -> u32 {
            lo + self.next_u32() % (hi - lo + 1)
        }
    }

    fn traces<F: FnMut(&mut Lcg) -> FlowTrace>(n: usize, seed: u64, mut f: F) -> Vec<FlowTrace> {
        let mut rng = Lcg(seed);
        (0..n).map(|_| f(&mut rng)).collect()
    }

    #[test]
    fn flags_obviously_different_flows() {
        // Class A: every record a fixed 1450 B. Class B: every record 16384 B.
        // A best-feature classifier must separate these near-perfectly.
        let a = traces(32, 1, |_| FlowTrace::new(vec![1450; 20]));
        let b = traces(32, 2, |_| FlowTrace::new(vec![16384; 20]));
        let v = flow_shape_distinguisher(&a, &b, DEFAULT_MARGIN).unwrap();
        assert!(
            v.is_distinguished(),
            "must distinguish 1450-only from 16384-only: {v:?}"
        );
        let m = measure(&a, &b);
        assert!(m.best_accuracy > 0.95, "near-perfect separation: {m:?}");
    }

    #[test]
    fn same_distribution_is_indistinguishable() {
        // Both classes drawn from the SAME size distribution (different seeds):
        // the best single feature must do no better than ~chance.
        let gen = |rng: &mut Lcg| {
            let n = rng.range(8, 24) as usize;
            FlowTrace::new((0..n).map(|_| rng.range(200, 1500)).collect())
        };
        let a = traces(64, 0xA1, gen);
        let b = traces(64, 0xB2, gen);
        let v = flow_shape_distinguisher(&a, &b, DEFAULT_MARGIN).unwrap();
        assert!(
            v.is_defended(),
            "same distribution must be indistinguishable, got {v:?} (acc {:.3})",
            measure(&a, &b).best_accuracy
        );
    }

    #[test]
    fn too_few_samples_is_inconclusive() {
        let a = traces(4, 1, |_| FlowTrace::new(vec![1000; 5]));
        let b = traces(4, 2, |_| FlowTrace::new(vec![1000; 5]));
        let v = flow_shape_distinguisher(&a, &b, DEFAULT_MARGIN).unwrap();
        assert!(matches!(v, DetectionVerdict::Inconclusive(_)), "got {v:?}");
    }

    #[test]
    fn detects_record_shaper_effect_vs_naive_1to1() {
        // Demonstrate the adversary MEASURING a real Mirage component: the
        // RecordShaper splits large writes into 2-3 sub-records, whereas a naive
        // 1:1 transport emits one record per write. The distinguisher must
        // detect that the shaper changes the record-size distribution - proving
        // it can score Mirage's flow shape. (This shows shaped != naive, NOT
        // shaped == real-browser; the latter needs a capture, see module docs.)
        use mirage_transport_reality::RecordShaper;
        let shaper = RecordShaper::fixed_policy();

        // A representative bulk workload: a mix of write sizes, several large.
        let workload: [usize; 6] = [800, 5000, 9000, 1200, 16000, 7000];

        let shaped = traces(40, 0x5A, |rng| {
            let mut sizes = Vec::new();
            for &w in &workload {
                let mut ent = [0u8; 4];
                for e in &mut ent {
                    *e = rng.next_u32() as u8;
                }
                for sub in shaper.split_boundaries(w, &ent) {
                    sizes.push(sub as u32);
                }
            }
            FlowTrace::new(sizes)
        });
        // Naive 1:1: one record per write (no splitting).
        let naive = traces(40, 0x6B, |_| {
            FlowTrace::new(workload.iter().map(|&w| w as u32).collect())
        });

        let m = measure(&shaped, &naive);
        // The shaper provably changes the distribution -> detectable vs naive.
        assert!(
            m.best_accuracy > DEFAULT_MARGIN,
            "shaper must be distinguishable from naive 1:1 (it splits records): {m:?}"
        );
        // And the cited feature is a size/structure feature, not noise.
        assert!(
            [
                "record_count",
                "mean_size",
                "max_size",
                "distinct_sizes",
                "size_entropy_bits",
                "frac_max_record",
                "size_range",
                "mean_abs_succ_diff",
                "size_stddev",
                "min_size",
                "total_bytes",
            ]
            .contains(&m.top_feature),
            "top feature should be a real size feature: {}",
            m.top_feature
        );
    }

    #[test]
    fn iid_cdf_split_is_distinguished_from_structured_cover_on_the_sequence() {
        // The certification premise for the conditional-record-length PROCESS
        // (#1): an i.i.d. draw from the RIGHT marginal CDF still leaks the length
        // SEQUENCE. Cover and Mirage share the same marginal (same buckets and
        // weights), but the cover arranges sizes into RUNS (the autocorrelation a
        // real TLS bulk-then-interactive flow shows) while the i.i.d. shaper draws
        // each record independently. The adversary must separate them, and the
        // discriminating feature must be a SEQUENTIAL one - i.e. a marginal-only
        // shaper (`cdf_split`) cannot close this gap; only a conditional process
        // can. This test is the measurement half of #1; the Markov shaper is
        // certified against it (it must flip this verdict to Defended).
        const BUCKETS: [(u32, f64); 7] = [
            (64, 0.08),
            (256, 0.17),
            (1024, 0.28),
            (1460, 0.17),
            (4096, 0.12),
            (8192, 0.08),
            (16384, 0.10),
        ];
        let pick = |u: f64| -> u32 {
            let mut acc = 0.0;
            for (sz, w) in BUCKETS {
                acc += w;
                if u < acc {
                    return sz;
                }
            }
            BUCKETS[BUCKETS.len() - 1].0
        };
        let unit = |rng: &mut Lcg| f64::from(rng.next_u32()) / f64::from(u32::MAX);
        // Mirage: i.i.d. draws from the CDF (what `cdf_split` produces).
        let iid = traces(48, 0xD1, |rng| {
            FlowTrace::new((0..60).map(|_| pick(unit(rng))).collect())
        });
        // Cover: SAME marginal, arranged into geometric-ish runs (each pick emits
        // a 2..=8-long run of one size), so the length SEQUENCE is autocorrelated.
        let cover = traces(48, 0xE2, |rng| {
            let mut sizes = Vec::with_capacity(60);
            while sizes.len() < 60 {
                let sz = pick(unit(rng));
                let run = 2 + (rng.next_u32() % 7) as usize; // 2..=8
                for _ in 0..run {
                    if sizes.len() < 60 {
                        sizes.push(sz);
                    }
                }
            }
            FlowTrace::new(sizes)
        });
        let v = flow_shape_distinguisher(&iid, &cover, DEFAULT_MARGIN).unwrap();
        assert!(
            v.is_distinguished(),
            "i.i.d. shaper must be distinguishable from a run-structured cover: {v:?}"
        );
        let m = measure(&iid, &cover);
        assert!(
            [
                "lag1_autocorr",
                "mean_run_length",
                "frac_size_repeats",
                "mean_abs_succ_diff",
            ]
            .contains(&m.top_feature),
            "the discriminating feature must be SEQUENTIAL (the i.i.d. gap), got '{}' acc {:.3}",
            m.top_feature,
            m.best_accuracy
        );
        // And the MARGINAL is NOT what separates them: mean_size (feature 2) alone
        // is ~chance, confirming the gap is purely in the ordering.
        let fa: Vec<f64> = iid.iter().map(|t| features(t)[2]).collect();
        let fb: Vec<f64> = cover.iter().map(|t| features(t)[2]).collect();
        let mean_auc = single_feature_auc(&fa, &fb);
        assert!(
            mean_auc.max(1.0 - mean_auc) < DEFAULT_MARGIN,
            "marginal mean_size must NOT separate same-CDF flows: acc {:.3}",
            mean_auc.max(1.0 - mean_auc)
        );
    }

    #[test]
    fn calibrated_markov_closes_the_gap_only_against_a_matched_cover() {
        // SCOPE (measured, honest): this proves the MECHANISM works when the
        // Markov process is CALIBRATED to the cover - the cover here is itself a
        // first-order sticky chain with the same alpha the Markov class uses. It
        // does NOT prove the process helps against an arbitrary real cover. See
        // `first_order_markov_does_not_beat_iid_against_bimodal_cover` for the
        // counter-evidence: against a bimodal (interactive+bulk) cover - what real
        // TLS actually is - a first-order single-alpha chain is WORSE than i.i.d.,
        // which is why the live shaper default is i.i.d., not this process.
        //
        //  (1) the i.i.d. `cdf_split` shaper is DISTINGUISHED from this matched
        //      run-structured cover on a SEQUENTIAL feature (the gap);
        //  (2) the matched Markov process closes it (separability drops to ~chance);
        //  (3) yet it PRESERVES the marginal (mean_size stays ~chance vs i.i.d.).
        // All flows have the SAME marginal (N draws from identical buckets) so
        // only the ORDERING differs - isolating the sequential axis. The i.i.d.
        // and Markov classes use the same sticky first-order chain the shaper
        // applies (`mirage_transport_reality::shaper::markov_next`: with prob
        // `alpha` keep the previous bucket, else redraw from the marginal;
        // alpha = 0 is the i.i.d. `cdf_split` draw). The real shaper's threading
        // + marginal-preservation are certified in that crate's `shaper` tests;
        // here we certify the distinguisher-level property.
        const N: usize = 50;
        const BUCKETS: [(u32, f64); 7] = [
            (64, 0.08),
            (256, 0.17),
            (1024, 0.28),
            (1460, 0.17),
            (4096, 0.12),
            (8192, 0.08),
            (16384, 0.10),
        ];
        let pick = |u: f64| -> u32 {
            let mut acc = 0.0;
            for (sz, w) in BUCKETS {
                acc += w;
                if u < acc {
                    return sz;
                }
            }
            BUCKETS[BUCKETS.len() - 1].0
        };
        let unit = |rng: &mut Lcg| f64::from(rng.next_u32()) / f64::from(u32::MAX);

        // Sticky first-order chain (identical logic to the shaper's markov_next).
        let chain = |rng: &mut Lcg, alpha: f64| -> FlowTrace {
            let mut sizes = Vec::with_capacity(N);
            let mut prev: Option<u32> = None;
            for _ in 0..N {
                let sz = match prev {
                    Some(p) if unit(rng) < alpha => p,
                    _ => pick(unit(rng)),
                };
                prev = Some(sz);
                sizes.push(sz);
            }
            FlowTrace::new(sizes)
        };

        // Reference cover with a first-order run structure (real TLS run-lengths
        // are ~geometric, i.e. first-order-Markov). `COVER_ALPHA` is the run
        // stickiness a deployment would MEASURE from a capture. The Markov shaper
        // is CALIBRATED to it (`markov` below uses the same alpha); the i.i.d.
        // shaper cannot express it (alpha = 0). This certifies that the
        // stickiness knob is the right one - not that any single hard-coded alpha
        // is universal. (Test `iid_cdf_split_is_distinguished_...` separately
        // shows the gap holds against a DIFFERENT-shaped run cover.)
        const COVER_ALPHA: f64 = 0.55;
        let cover = traces(64, 0xC0FFEE, |rng| chain(rng, COVER_ALPHA));
        let iid = traces(64, 0x1D, |rng| chain(rng, 0.0));
        let markov = traces(64, 0x33, |rng| chain(rng, COVER_ALPHA));

        // Max separability accuracy over ONLY the SEQUENTIAL features - the axis
        // an i.i.d. draw cannot match and a conditional process can. (Comparing
        // the overall best would fold in finite-sample marginal-stat noise from
        // the cover's uniform-vs-geometric run-length mismatch, which no
        // uncalibrated process removes.)
        let seq = ["lag1_autocorr", "mean_run_length", "frac_size_repeats"];
        let seq_auc = |a: &[FlowTrace], b: &[FlowTrace]| -> f64 {
            let fa: Vec<[f64; N_FEATURES]> = a.iter().map(features).collect();
            let fb: Vec<[f64; N_FEATURES]> = b.iter().map(features).collect();
            let mut best = 0.5f64;
            for (i, name) in FEATURE_NAMES.iter().enumerate() {
                if !seq.contains(name) {
                    continue;
                }
                let ai: Vec<f64> = fa.iter().map(|f| f[i]).collect();
                let bi: Vec<f64> = fb.iter().map(|f| f[i]).collect();
                let auc = single_feature_auc(&ai, &bi);
                best = best.max(auc.max(1.0 - auc));
            }
            best
        };

        // (1) i.i.d. leaves a LARGE sequential gap vs the structured cover.
        let iid_seq = seq_auc(&iid, &cover);
        assert!(
            iid_seq > 0.85,
            "i.i.d. draw must be strongly separable from a run-structured cover on \
             the sequential axis: {iid_seq:.3}"
        );

        // (2) The calibrated Markov process CLOSES that gap: near-chance on the
        // sequential axis, and far below the i.i.d. draw.
        let markov_seq = seq_auc(&markov, &cover);
        assert!(
            markov_seq < 0.65 && markov_seq < iid_seq - 0.20,
            "calibrated Markov process must close the sequential gap: markov {markov_seq:.3} \
             vs iid {iid_seq:.3}"
        );

        // (3) Marginal preserved: mean_size does NOT separate the Markov class
        // from the i.i.d. one - the process fixed the SEQUENCE, not the histogram.
        let ma: Vec<f64> = markov.iter().map(|t| features(t)[2]).collect();
        let mb: Vec<f64> = iid.iter().map(|t| features(t)[2]).collect();
        let mean_auc = single_feature_auc(&ma, &mb);
        assert!(
            mean_auc.max(1.0 - mean_auc) < DEFAULT_MARGIN,
            "Markov must preserve the marginal (mean_size) vs i.i.d.: acc {:.3}",
            mean_auc.max(1.0 - mean_auc)
        );
    }

    #[test]
    fn first_order_markov_does_not_beat_iid_against_bimodal_cover() {
        // COUNTER-EVIDENCE (why the live shaper default is i.i.d., not the Markov
        // process). Real TLS record-size sequences are BIMODAL: short interactive
        // record bursts (run length ~1) interleaved with long bulk-transfer runs
        // (a big download is a run of many max-size records). A first-order
        // single-stickiness Markov chain produces UNIMODAL geometric run-lengths,
        // matching neither mode, and its uniform autocorrelation is itself a
        // signature a bimodal flow lacks. Result: against a bimodal cover the
        // Markov process is NOT closer than i.i.d. - it is measurably farther.
        // (Verified out-of-band across alphas/seeds; here we assert the direction
        // on one representative draw so the finding is guarded in CI.)
        const N: usize = 60;
        const BUCKETS: [(u32, f64); 7] = [
            (64, 0.08),
            (256, 0.17),
            (1024, 0.28),
            (1460, 0.17),
            (4096, 0.12),
            (8192, 0.08),
            (16384, 0.10),
        ];
        let pick = |u: f64| -> u32 {
            let mut acc = 0.0;
            for (sz, w) in BUCKETS {
                acc += w;
                if u < acc {
                    return sz;
                }
            }
            BUCKETS[6].0
        };
        let unit = |rng: &mut Lcg| f64::from(rng.next_u32()) / f64::from(u32::MAX);
        let chain = |rng: &mut Lcg, alpha: f64| -> FlowTrace {
            let mut v = Vec::with_capacity(N);
            let mut prev: Option<u32> = None;
            for _ in 0..N {
                let sz = match prev {
                    Some(p) if unit(rng) < alpha => p,
                    _ => pick(unit(rng)),
                };
                prev = Some(sz);
                v.push(sz);
            }
            FlowTrace::new(v)
        };
        // Bimodal cover: 55% interactive bursts of a few small records, 45% bulk
        // runs of one large size - what real HTTPS browsing looks like.
        let bimodal = traces(64, 0xB1, |rng| {
            let mut v = Vec::with_capacity(N + 16);
            while v.len() < N {
                if unit(rng) < 0.55 {
                    let k = 1 + rng.next_u32() % 3;
                    for _ in 0..k {
                        v.push(pick(unit(rng) * 0.6)); // bias small
                    }
                } else {
                    let big = if unit(rng) < 0.5 { 8192 } else { 16384 };
                    let k = 5 + rng.next_u32() % 8;
                    for _ in 0..k {
                        v.push(big);
                    }
                }
            }
            v.truncate(N);
            FlowTrace::new(v)
        });
        let iid = traces(64, 0x1D, |rng| chain(rng, 0.0));
        // The best case for the Markov process across a range of stickiness.
        let markov_best = [0.3f64, 0.5, 0.7]
            .iter()
            .map(|&a| {
                let mk = traces(64, 0x30 + (a * 100.0) as u64, |rng| chain(rng, a));
                measure(&mk, &bimodal).best_accuracy
            })
            .fold(1.0f64, f64::min);
        let iid_acc = measure(&iid, &bimodal).best_accuracy;
        assert!(
            markov_best >= iid_acc - 0.02,
            "a first-order Markov chain must NOT beat i.i.d. against a bimodal cover \
             (it does not match real TLS run structure): markov_best {markov_best:.3} \
             vs iid {iid_acc:.3}"
        );
    }

    // SplitSource::PhaseState (RT circumvention #3/#5) - marginal-preservation
    // guard + honest scope note.
    //
    // FINDING (measured, not assumed): a phase-state sequence model does NOT
    // certifiably beat the i.i.d. default against a *synthetic* bimodal cover.
    // Two reasons, both empirical: (1) the bulk-run structure a sequence
    // classifier keys on comes from the APPLICATION's large writes, which
    // `cdf_split` already fragments into runs of max-size records IDENTICALLY for
    // every source - so the sub-max phase machine changes nothing there; (2) the
    // real shaper emits continuous partial/tail records that a discrete synthetic
    // cover lacks, making BOTH i.i.d. and phase trivially separable from it.
    // A meaningful sequence certification therefore needs a REAL cover pcap
    // (matching the marginal AND the partial-record structure). Until then i.i.d.
    // stays the Reality default and PhaseState is opt-in.
    //
    // What we CAN and DO certify here: PhaseState is marginal-PRESERVING - its
    // emitted record-size histogram tracks the i.i.d. source's (both track the
    // browser_https CDF), so enabling it is never a size-marginal regression. The
    // sequence benefit is what awaits a real capture.
    #[test]
    fn phase_state_preserves_marginal() {
        use mirage_transport_reality::shaper::{PhaseProfile, RecordShaper, TrafficProfile};

        // Collect the emitted record-size histogram (bucketed) from each real
        // shaper over the same medium-write workload.
        let hist = |phase: bool| -> [f64; 8] {
            let mut sh = if phase {
                RecordShaper::from_phase_profile(&PhaseProfile::browser_https())
            } else {
                RecordShaper::from_profile(&TrafficProfile::browser_https())
            };
            let mut counts = [0u64; 8];
            let mut total = 0u64;
            let mut rng = Lcg(if phase { 0xF0 } else { 0xC0 });
            for _ in 0..4000 {
                let mut e = [0u8; 32];
                for b in e.iter_mut() {
                    *b = rng.next_u32() as u8;
                }
                for r in sh.split_plan_with_entropy(12_000, &e) {
                    // 8 log-ish buckets covering 0..=16384.
                    let idx = match r {
                        0..=128 => 0,
                        129..=384 => 1,
                        385..=1200 => 2,
                        1201..=2048 => 3,
                        2049..=6144 => 4,
                        6145..=12288 => 5,
                        12289..=16383 => 6,
                        _ => 7,
                    };
                    counts[idx] += 1;
                    total += 1;
                }
            }
            let mut out = [0.0; 8];
            for i in 0..8 {
                out[i] = counts[i] as f64 / total.max(1) as f64;
            }
            out
        };

        let iid_h = hist(false);
        let phase_h = hist(true);
        // Total-variation distance between the two histograms.
        let tvd: f64 = iid_h
            .iter()
            .zip(phase_h.iter())
            .map(|(a, b)| (a - b).abs())
            .sum::<f64>()
            / 2.0;
        eprintln!("phase vs i.i.d. record-size TVD = {tvd:.4} (0 = identical marginal)");
        assert!(
            tvd < 0.12,
            "PhaseState must PRESERVE the size marginal (TVD vs i.i.d. {tvd:.3} too large) - \
             enabling it must never regress the size-histogram defense"
        );
    }

    // Grounds the shipped Reality record-size CDF in a REAL packet capture and
    // guards against drift back to a hand-guessed distribution. The reference is
    // the measured server->client TLS 1.3 `tls.record.length` distribution of a
    // representative browsing mix (Wikipedia/BBC/GitHub/JSON/image/download over
    // Cloudflare/CDN, 420 records, tcpdump+tshark, 2026-07-20), mapped to the
    // profile's 7 buckets (plaintext). The prior hand-picked CDF was far off
    // (1024 B: 28% shipped vs 2% measured; 16384 B: 10% vs 26%).
    #[test]
    fn reality_cdf_matches_real_capture() {
        // Measured real distribution (normalized over the 7 buckets).
        let real: [(u16, f32); 7] = [
            (64, 0.112),
            (256, 0.098),
            (1024, 0.021),
            (1460, 0.136),
            (4096, 0.252),
            (8192, 0.117),
            (16384, 0.264),
        ];
        let cdf = mirage_transport_reality::shaper::TrafficProfile::browser_https().record_size_cdf;
        let tot: f32 = cdf.iter().map(|(_, w)| w).sum();
        // Total-variation distance between the shipped CDF and the measurement.
        let tvd: f64 = real
            .iter()
            .map(|(sz, rw)| {
                let sw = cdf
                    .iter()
                    .find(|(s, _)| s == sz)
                    .map_or(0.0, |(_, w)| w / tot);
                f64::from((rw - sw).abs())
            })
            .sum::<f64>()
            / 2.0;
        assert!(
            tvd < 0.03,
            "the shipped browser_https CDF must track the real capture (TVD {tvd:.3}); \
             re-calibrate from a fresh tshark tls.record.length capture if the cover changed"
        );
    }

    #[test]
    fn auc_is_symmetric_and_bounded() {
        let a = [1.0, 2.0, 3.0];
        let b = [4.0, 5.0, 6.0];
        let ab = single_feature_auc(&a, &b);
        let ba = single_feature_auc(&b, &a);
        assert!((ab + ba - 1.0).abs() < 1e-9, "AUC(a,b)+AUC(b,a)==1");
        assert!((0.0..=1.0).contains(&ab));
        // Identical sets -> exactly 0.5.
        assert!((single_feature_auc(&a, &a) - 0.5).abs() < 1e-9);
    }
}
