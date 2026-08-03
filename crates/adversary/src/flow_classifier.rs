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
    let (na, nb) = (a.len(), b.len());
    let total = (na * nb) as f64;
    if total == 0.0 {
        return 0.5;
    }
    // Rank-sum form of the same statistic, O((n+m) log(n+m)) instead of the
    // O(n*m) pairwise sweep this replaces. That matters because
    // `permutation_floor` calls this hundreds of times: at 500 flows a class the
    // pairwise version is 250k comparisons per feature per repetition, which
    // makes a data-derived null distribution too slow to compute, which is why
    // the floor was a hard-coded constant in the first place.
    //
    //   AUC = (R_a - n_a(n_a+1)/2) / (n_a * n_b)
    //
    // with MID-RANKS for ties, which reproduces the pairwise rule's half-credit
    // for equal values exactly. `auc_matches_the_pairwise_definition` asserts the
    // two agree, including on data that is mostly ties.
    let mut all: Vec<(f64, bool)> = Vec::with_capacity(na + nb);
    all.extend(a.iter().map(|&v| (v, true)));
    all.extend(b.iter().map(|&v| (v, false)));
    all.sort_by(|x, y| x.0.total_cmp(&y.0));

    let mut rank_sum_a = 0.0f64;
    let mut i = 0usize;
    while i < all.len() {
        // Span of exactly-equal values gets the average of the ranks it covers.
        let mut j = i;
        while j + 1 < all.len() && all[j + 1].0 == all[i].0 {
            j += 1;
        }
        let mid = (i + j) as f64 / 2.0 + 1.0; // ranks are 1-based
        for entry in &all[i..=j] {
            if entry.1 {
                rank_sum_a += mid;
            }
        }
        i = j + 1;
    }
    let na_f = na as f64;
    ((rank_sum_a - na_f * (na_f + 1.0) / 2.0) / total).clamp(0.0, 1.0)
}

/// Each feature's own null distribution, derived from the data by PERMUTATION.
///
/// # Why a constant floor is not good enough
///
/// [`noise_floor`] is one number for fourteen features whose sampling
/// distributions are nothing alike, calibrated once on a synthetic size mixture.
/// Measured on real null captures it understates the extremes badly enough to
/// invent leaks: `max_size` and `size_range` reached 0.571 against its 0.552 on
/// data with nothing to find, and were duly reported as the winning separator in
/// two control runs.
///
/// This computes the real thing instead. Under the null hypothesis the two
/// classes are the same distribution, so pooling every flow and RELABELLING at
/// random produces draws from exactly that null. Doing it many times and taking a
/// high quantile per feature gives each feature the floor its own tail earns,
/// with no calibration constant and no extra capture runs.
///
/// `quantile` is the fraction of null draws a result must beat, e.g. `0.95` for
/// a one-sided 5% false-positive rate PER FEATURE. Note that `measure` maximises
/// over 14 features, so per-feature 5% is not 5% overall; compare with
/// [`excess_over`], which ranks by margin over each feature's own floor and so
/// stops an unstable feature winning on its tail alone.
///
/// `seed` makes it reproducible - a floor that moved run to run would be worse
/// than a wrong constant.
#[must_use]
pub fn permutation_floor(
    pooled: &[FlowTrace],
    class_a_len: usize,
    reps: usize,
    quantile: f64,
    seed: u64,
) -> [f64; N_FEATURES] {
    null_model(pooled, class_a_len, reps, quantile, seed).per_feature
}

/// The null distribution of the whole procedure, not of one feature.
///
/// Per-feature floors are necessary and NOT sufficient, which is easy to get
/// wrong: thresholding each feature at its own 95th percentile controls that
/// feature at 5%, but [`measure`] reports the MAXIMUM over fourteen of them, so
/// the chance that at least one clears its own 95th percentile is far above 5%.
/// Measured, that is not theoretical - a null control whose `max_size` sat at
/// 0.571 cleared both a pooled floor of 0.552 AND its own permuted floor of
/// 0.551, and was still nothing.
///
/// [`Self::familywise`] fixes it the standard way (max-T, Westfall-Young): each
/// permutation draw contributes the LARGEST centred accuracy across all
/// features, and the quantile of that maximum is the bar a real finding has to
/// clear. Centring each feature on its own null median first stops a
/// heavy-tailed feature dominating the maximum purely by being wide.
#[derive(Debug, Clone, Copy)]
pub struct NullModel {
    /// Per-feature quantile of the folded accuracy under relabelling.
    pub per_feature: [f64; N_FEATURES],
    /// Per-feature median under relabelling: the centre to measure excess from.
    pub median: [f64; N_FEATURES],
    /// Quantile of `max over features of (accuracy - that feature's median)`.
    /// A finding must beat THIS to survive the max-over-features selection.
    pub familywise: f64,
}

impl NullModel {
    /// Does this observation clear the family-wise bar, and on which feature?
    ///
    /// Returns `(feature, accuracy, margin)` where `margin` is the centred
    /// excess minus [`Self::familywise`]. Positive means separable after paying
    /// for having looked at fourteen features.
    #[must_use]
    pub fn verdict(
        &self,
        class_a: &[FlowTrace],
        class_b: &[FlowTrace],
    ) -> (&'static str, f64, f64) {
        let aucs = measure_all(class_a, class_b);
        let mut best = (FEATURE_NAMES[0], 0.5, f64::NEG_INFINITY);
        for (i, &name) in FEATURE_NAMES.iter().enumerate() {
            let acc = aucs[i].max(1.0 - aucs[i]);
            let centred = acc - self.median[i];
            if centred > best.2 {
                best = (name, acc, centred);
            }
        }
        (best.0, best.1, best.2 - self.familywise)
    }
}

/// Build a [`NullModel`] by relabelling the pooled flows `reps` times.
#[must_use]
pub fn null_model(
    pooled: &[FlowTrace],
    class_a_len: usize,
    reps: usize,
    quantile: f64,
    seed: u64,
) -> NullModel {
    let n = pooled.len();
    let na = class_a_len.min(n);
    if n < 4 || na == 0 || na == n || reps == 0 {
        // Not enough to permute: fall back to the pooled estimate rather than
        // returning 0.5, which would call everything separable.
        let f = noise_floor(na.min(n.saturating_sub(na)).max(1));
        return NullModel {
            per_feature: [f; N_FEATURES],
            median: [0.5; N_FEATURES],
            familywise: f - 0.5,
        };
    }
    let feats: Vec<[f64; N_FEATURES]> = pooled.iter().map(features).collect();
    let mut idx: Vec<usize> = (0..n).collect();
    let mut rng = seed | 1;
    let mut next = || {
        rng = rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };
    // Built per element, not `vec![Vec::with_capacity(reps); N]`: that form
    // evaluates the expression once and CLONES it, and cloning an empty Vec
    // drops its capacity, so all but one would reallocate their way up through
    // `reps` pushes.
    let mut draws: Vec<Vec<f64>> = (0..N_FEATURES).map(|_| Vec::with_capacity(reps)).collect();
    let (mut ai, mut bi) = (Vec::with_capacity(na), Vec::with_capacity(n - na));
    for _ in 0..reps {
        // Fisher-Yates, so every split is equally likely.
        for k in (1..n).rev() {
            let j = (next() % (k as u64 + 1)) as usize;
            idx.swap(k, j);
        }
        for (f, slot) in draws.iter_mut().enumerate() {
            ai.clear();
            bi.clear();
            for (pos, &i) in idx.iter().enumerate() {
                if pos < na {
                    ai.push(feats[i][f]);
                } else {
                    bi.push(feats[i][f]);
                }
            }
            let auc = single_feature_auc(&ai, &bi);
            slot.push(auc.max(1.0 - auc));
        }
    }
    let q = quantile.clamp(0.0, 1.0);
    let pick = |sorted: &[f64], q: f64| -> f64 {
        let k = (((sorted.len() - 1) as f64) * q).round() as usize;
        sorted[k.min(sorted.len() - 1)]
    };
    // Per-feature median first: it is the centre the family-wise statistic
    // measures excess from, so a wide feature does not win the maximum just for
    // being wide.
    let mut median = [0.5f64; N_FEATURES];
    let mut per_feature = [0.5f64; N_FEATURES];
    let mut sorted: Vec<Vec<f64>> = Vec::with_capacity(N_FEATURES);
    for slot in &draws {
        let mut s = slot.clone();
        s.sort_by(f64::total_cmp);
        sorted.push(s);
    }
    for f in 0..N_FEATURES {
        median[f] = pick(&sorted[f], 0.5);
        per_feature[f] = pick(&sorted[f], q);
    }
    // max-T: for each draw, the largest centred accuracy across features. Its
    // quantile is what a finding must beat, having been selected as a maximum.
    let mut maxima: Vec<f64> = (0..reps)
        .map(|r| {
            (0..N_FEATURES)
                .map(|f| draws[f][r] - median[f])
                .fold(f64::NEG_INFINITY, f64::max)
        })
        .collect();
    maxima.sort_by(f64::total_cmp);
    NullModel {
        per_feature,
        median,
        familywise: pick(&maxima, q),
    }
}

/// The feature with the greatest margin over ITS OWN floor, and that margin.
///
/// This is the statistic to rank on. Ranking by raw accuracy lets whichever
/// feature has the heaviest tail win on noise - which is exactly how `max_size`
/// came to be reported as a leak on captures with nothing in them. Returns
/// `(feature, accuracy, excess)`; a non-positive excess means nothing cleared
/// its own null.
#[must_use]
pub fn excess_over(
    class_a: &[FlowTrace],
    class_b: &[FlowTrace],
    floors: &[f64; N_FEATURES],
) -> (&'static str, f64, f64) {
    let aucs = measure_all(class_a, class_b);
    let mut best = (FEATURE_NAMES[0], 0.5, f64::NEG_INFINITY);
    for (i, &name) in FEATURE_NAMES.iter().enumerate() {
        let acc = aucs[i].max(1.0 - aucs[i]);
        let ex = acc - floors[i];
        if ex > best.2 {
            best = (name, acc, ex);
        }
    }
    best
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

/// Minimum flows per class before a verdict is attempted at all.
///
/// This is a floor for RUNNING, not for BELIEVING. At 16 flows per class the
/// estimator reports a mean 0.681 and has been observed at 0.895 on data with
/// nothing to find (see `the_metric_has_a_floor_above_one_half_when_nothing_separates`),
/// so a verdict here is dominated by [`noise_floor`]. Compare against that, not
/// against 0.5.
pub const MIN_SAMPLES: usize = 16;

/// What [`measure`] reports when the two classes are the SAME distribution.
///
/// `measure` maximises `max(auc, 1 - auc)` over 14 features on the sample it
/// reports on. Both halves bias upward - the fold turns sampling noise into
/// apparent signal even for one feature, and the max over 14 compounds it - so
/// `best_accuracy` sits strictly above 0.5 for any data at all, by construction.
/// The bias is a small-sample effect and decays as flows accumulate:
///
/// | flows/class | mean | worst seen |
/// |---|---|---|
/// | 16 | 0.681 | 0.895 |
/// | 30 | 0.617 | 0.681 |
/// | 66 | 0.574 | 0.628 |
/// | 150 | 0.552 | 0.606 |
///
/// This is not a defect. A censor does get to pick whichever feature works best,
/// so max-over-features is the right threat model. It only means a raw number
/// cannot be read as "0.5 is chance, therefore 0.60 is signal".
///
/// Calibrated on a synthetic size mixture, so treat it as an estimate of the
/// shape rather than an exact bound for any particular capture - the live
/// `NULL_CONTROL` run in `scripts/podman-e2e/cover-traffic.sh` measures the real
/// floor for a real run and remains the authority.
///
/// # It is ONE number for FOURTEEN incomparable features
///
/// That is the load-bearing caveat. `measure` maximises over features whose
/// sampling distributions are nothing alike: a mean or a total concentrates
/// quickly and sits well under this floor, while an EXTREME like `max_size` -
/// and `size_range`, which is `max - min` and inherits it - is set by whichever
/// rare record landed in the window, so it is heavy-tailed and its own floor is
/// higher than this returns.
///
/// Measured on three null-control captures (nothing to detect), upstream at a
/// 40-record window: `max_size` and `size_range` both reached 0.571 against this
/// function's 0.552, and were duly reported as the "winning separator" in two
/// control runs at 0.642 and 0.563. Those were artifacts.
///
/// The regime matters too, not just the feature: at a 60-record downstream
/// window nearly every window's maximum is the MSS, so `max_size` is degenerate
/// and pins at 0.500 while `lag1_autocorr` becomes the least stable one.
///
/// So: read this as a lower bound for the stable features and an UNDERESTIMATE
/// for the extremes, and distrust a near-floor win on `max_size` or
/// `size_range`. `examples/feature_floor` reports the per-feature spread across
/// a set of null captures; a properly calibrated per-feature floor is the real
/// fix and needs a batch of control runs to establish.
#[must_use]
pub fn noise_floor(flows_per_class: usize) -> f64 {
    // Measured points, then log-linear interpolation between them: the bias
    // falls roughly with the log of the sample size over this range.
    const POINTS: [(f64, f64); 4] = [(16.0, 0.681), (30.0, 0.617), (66.0, 0.574), (150.0, 0.552)];
    let n = (flows_per_class.max(1)) as f64;
    if n <= POINTS[0].0 {
        return POINTS[0].1;
    }
    for w in POINTS.windows(2) {
        let ((n0, f0), (n1, f1)) = (w[0], w[1]);
        if n <= n1 {
            let t = (n.ln() - n0.ln()) / (n1.ln() - n0.ln());
            return f0 + t * (f1 - f0);
        }
    }
    // Past the calibrated range the bias keeps shrinking, but slowly; hold the
    // last measured value rather than extrapolating toward 0.5 and understating
    // the floor, which is the direction that turns noise into a finding.
    POINTS[3].1
}

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

/// Every feature's AUC, not just the winner.
///
/// [`measure`] reports `max` over features, which is the right threat model - a
/// censor picks whatever works - but it hides WHICH features are doing the
/// separating and how stable each one is. That matters because [`noise_floor`]
/// is a single number applied to all 14, calibrated on a synthetic size mixture,
/// while the features are wildly different statistics: a mean concentrates
/// quickly, an extreme like `max_size` is dominated by rare records and has a
/// heavy-tailed sampling distribution, so its own floor is higher than the
/// pooled estimate. Reading a `max_size` win against the pooled floor therefore
/// overstates it.
///
/// Returned in [`FEATURE_NAMES`] order, as the raw AUC (which may be below 0.5
/// when the feature is anti-correlated).
#[must_use]
pub fn measure_all(class_a: &[FlowTrace], class_b: &[FlowTrace]) -> [f64; N_FEATURES] {
    let fa: Vec<[f64; N_FEATURES]> = class_a.iter().map(features).collect();
    let fb: Vec<[f64; N_FEATURES]> = class_b.iter().map(features).collect();
    let mut out = [0.5f64; N_FEATURES];
    for (i, slot) in out.iter_mut().enumerate() {
        let ai: Vec<f64> = fa.iter().map(|f| f[i]).collect();
        let bi: Vec<f64> = fb.iter().map(|f| f[i]).collect();
        *slot = single_feature_auc(&ai, &bi);
    }
    out
}

/// Separability once an observer AGGREGATES several flows from the same target.
///
/// See [`measure_aggregated`]. Carries the group count and the floor for that
/// count, because aggregation trades sample size for signal and reading the
/// accuracy without the floor beside it inverts the conclusion.
#[derive(Debug, Clone, Copy)]
pub struct AggregatedDistinguishability {
    /// Flows combined into one decision.
    pub group_size: usize,
    /// Decisions available per class after grouping.
    pub groups_per_class: usize,
    /// Best single-feature accuracy over the AGGREGATED samples.
    pub best_accuracy: f64,
    /// The most-discriminating feature at this aggregation level.
    pub top_feature: &'static str,
    /// [`noise_floor`] evaluated at `groups_per_class`, not at the flow count.
    pub floor: f64,
}

impl AggregatedDistinguishability {
    /// How far above this sample size's own floor the result sits. Negative or
    /// near zero means the aggregation bought nothing that the smaller sample
    /// does not explain on its own.
    #[must_use]
    pub fn excess(&self) -> f64 {
        self.best_accuracy - self.floor
    }
}

/// Separability when the observer pools `group_size` flows per decision.
///
/// # Why this exists
///
/// A per-flow AUC near the floor is routinely read as "indistinguishable", and
/// for a ONE-SHOT observer it is. A real observer is not one-shot: a proxy
/// session emits hundreds of windows from one host, and nothing stops a censor
/// averaging them into a single per-host decision. For independent observations
/// the separation grows as `sqrt(N)` in `d'`, so a per-flow AUC of 0.57
/// (`d' ~ 0.25`) reaches `d' ~ 2.5` at N = 100, which is AUC ~ 0.96.
///
/// That arithmetic is why a small residual leak is not automatically a safe one,
/// and this function is how to find out rather than assume. It aggregates by
/// taking each feature's MEAN over the group - the natural statistic for a
/// threshold classifier, and the one the `sqrt(N)` argument is about.
///
/// # The trap it is built to avoid
///
/// Grouping divides the sample count, and [`noise_floor`] RISES as samples fall.
/// So aggregation inflates the raw accuracy for two quite different reasons -
/// real signal accumulating, and the estimator getting noisier - and reading the
/// number without its floor would credit the second to the first. The floor at
/// the GROUP count travels with the result for exactly that reason; compare
/// [`AggregatedDistinguishability::excess`] across levels, never the raw
/// accuracy.
///
/// Returns `None` when there are not at least two groups per class, which is
/// too few to say anything at all.
///
/// # Independence caveat
///
/// `sqrt(N)` is an upper bound. Windows from one session share a cover trace,
/// a host and a network condition, so they are correlated and the real gain is
/// smaller. That makes the measured curve the thing to trust and the arithmetic
/// only a reason to look.
#[must_use]
pub fn measure_aggregated(
    class_a: &[FlowTrace],
    class_b: &[FlowTrace],
    group_size: usize,
) -> Option<AggregatedDistinguishability> {
    let g = group_size.max(1);
    let pool = |flows: &[FlowTrace]| -> Vec<[f64; N_FEATURES]> {
        flows
            .chunks(g)
            // Drop a short trailing chunk: averaging fewer flows makes that
            // group noisier than the rest, which shows up as separability the
            // grouping invented.
            .filter(|c| c.len() == g)
            .map(|chunk| {
                let mut acc = [0.0f64; N_FEATURES];
                for t in chunk {
                    let f = features(t);
                    for (a, v) in acc.iter_mut().zip(f.iter()) {
                        *a += *v;
                    }
                }
                for a in &mut acc {
                    *a /= chunk.len() as f64;
                }
                acc
            })
            .collect()
    };
    let (ga, gb) = (pool(class_a), pool(class_b));
    if ga.len() < 2 || gb.len() < 2 {
        return None;
    }
    let mut best_accuracy = 0.5;
    let mut top_feature = FEATURE_NAMES[0];
    for (i, &name) in FEATURE_NAMES.iter().enumerate() {
        let ai: Vec<f64> = ga.iter().map(|f| f[i]).collect();
        let bi: Vec<f64> = gb.iter().map(|f| f[i]).collect();
        let auc = single_feature_auc(&ai, &bi);
        let acc = auc.max(1.0 - auc);
        if acc > best_accuracy {
            best_accuracy = acc;
            top_feature = name;
        }
    }
    let groups_per_class = ga.len().min(gb.len());
    Some(AggregatedDistinguishability {
        group_size: g,
        groups_per_class,
        best_accuracy,
        top_feature,
        floor: noise_floor(groups_per_class),
    })
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

    /// The floor this metric reports when there is genuinely nothing to find.
    ///
    /// `measure` maximises `max(auc, 1 - auc)` over all 14 features on the same
    /// sample it reports. Both halves of that bias upward: the fold means even a
    /// single feature whose true AUC is 0.5 reports above 0.5 once sampling
    /// noise is folded, and taking the max over 14 features compounds it. So
    /// `best_accuracy` has a floor strictly above 0.5 BY CONSTRUCTION, for any
    /// data whatsoever, and the floor grows as the sample shrinks.
    ///
    /// This is not a defect - a censor really does get to pick the feature that
    /// works best - but it means a number near 0.5 cannot be read as "0.5 is
    /// chance, so 0.55 is signal". It is why `cover-traffic.sh` measures a null
    /// control, and why the live control (0.52-0.55 at 60-160 flows) lands where
    /// it does rather than at 0.50.
    ///
    /// Both classes here are drawn from the SAME distribution, so any reported
    /// separability is the estimator, not the data.
    #[test]
    fn auc_matches_the_pairwise_definition() {
        // The rank-sum form is an optimisation, not a redefinition. It has to
        // agree with the O(n*m) rule it replaced - including on data that is
        // mostly ties, which is the case mid-ranks exist to handle and the case
        // real size features actually produce (a downstream window where nearly
        // every record is the MSS).
        fn pairwise(a: &[f64], b: &[f64]) -> f64 {
            let total = (a.len() * b.len()) as f64;
            if total == 0.0 {
                return 0.5;
            }
            let mut wins = 0.0;
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
        let mut rng = 0x0D15_EA5E_u64;
        let mut next = || {
            rng = rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = rng;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z ^ (z >> 31)
        };
        for buckets in [2u64, 5, 50, 1000] {
            for _ in 0..30 {
                let a: Vec<f64> = (0..17).map(|_| (next() % buckets) as f64).collect();
                let b: Vec<f64> = (0..23).map(|_| (next() % buckets) as f64).collect();
                let fast = single_feature_auc(&a, &b);
                let slow = pairwise(&a, &b);
                assert!(
                    (fast - slow).abs() < 1e-9,
                    "rank-sum {fast} != pairwise {slow} with {buckets} distinct values"
                );
            }
        }
        // Degenerate cases the caller can actually hit.
        assert!((single_feature_auc(&[1.0; 5], &[1.0; 5]) - 0.5).abs() < 1e-12);
        assert!((single_feature_auc(&[2.0, 3.0], &[0.0, 1.0]) - 1.0).abs() < 1e-12);
        assert!((single_feature_auc(&[], &[1.0]) - 0.5).abs() < 1e-12);
    }

    #[test]
    fn maxt_controls_the_error_rate_that_per_feature_floors_do_not() {
        // The defect: `measure` reports the MAXIMUM over 14 features, so
        // thresholding each feature at its own 95th percentile leaves a
        // family-wise false-positive rate far above 5%. This measures both rates
        // on data with nothing to find and asserts max-T is the calibrated one.
        struct Rng(u64);
        impl Rng {
            fn next(&mut self) -> u64 {
                self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut z = self.0;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                z ^ (z >> 31)
            }
        }
        let mut rng = Rng(0x0BAD_C0DE);
        let trials = 40;
        let (mut per_feature_fp, mut maxt_fp) = (0usize, 0usize);
        for _ in 0..trials {
            // One distribution, split in two. Any "separation" is noise. The
            // heavy tail on the maximum is what makes extremes misbehave.
            let flows: Vec<FlowTrace> = (0..80)
                .map(|_| {
                    FlowTrace::new(
                        (0..40)
                            .map(|_| {
                                if rng.next() % 15 == 0 {
                                    (rng.next() % 9000) as u32 + 2000
                                } else {
                                    1448
                                }
                            })
                            .collect(),
                    )
                })
                .collect();
            let (a, b) = flows.split_at(40);
            let nm = null_model(&flows, 40, 60, 0.95, rng.next());

            // Per-feature rule: ANY feature over its own p95 counts as a find.
            let aucs = measure_all(a, b);
            if aucs
                .iter()
                .enumerate()
                .any(|(i, &auc)| auc.max(1.0 - auc) > nm.per_feature[i])
            {
                per_feature_fp += 1;
            }
            // Family-wise rule.
            if nm.verdict(a, b).2 > 0.0 {
                maxt_fp += 1;
            }
        }
        eprintln!(
            "  false positives on null data: per-feature {per_feature_fp}/{trials}, \
             max-T {maxt_fp}/{trials}"
        );
        assert!(
            maxt_fp <= per_feature_fp,
            "max-T must not be LOOSER than per-feature thresholds \
             (max-T {maxt_fp}, per-feature {per_feature_fp})"
        );
        // The bar it has to clear: a nominal 5% rate, with slack for 40 trials.
        assert!(
            maxt_fp * 5 <= trials,
            "max-T false-positive rate {maxt_fp}/{trials} is far above the nominal 5%"
        );
    }

    #[test]
    fn a_permutation_floor_beats_a_constant_on_the_unstable_features() {
        // The defect this fixes: one constant floor across features whose
        // sampling distributions differ wildly. `max_size` is an extreme, so its
        // null tail is fatter than a mean's - measured on real null captures it
        // cleared the pooled floor and was reported as a leak.
        //
        // Build data with NOTHING to find, in a shape that makes max heavy-tailed:
        // mostly a constant, with occasional large outliers.
        struct Rng(u64);
        impl Rng {
            fn next(&mut self) -> u64 {
                self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut z = self.0;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z ^ (z >> 31)
            }
        }
        let mut rng = Rng(0xFEED_FACE);
        let flows: Vec<FlowTrace> = (0..120)
            .map(|_| {
                FlowTrace::new(
                    (0..40)
                        .map(|_| {
                            if rng.next() % 20 == 0 {
                                (rng.next() % 9000) as u32 + 2000
                            } else {
                                1448
                            }
                        })
                        .collect(),
                )
            })
            .collect();
        let floors = permutation_floor(&flows, 60, 120, 0.95, 7);
        let max_i = FEATURE_NAMES.iter().position(|&n| n == "max_size").unwrap();
        let mean_i = FEATURE_NAMES
            .iter()
            .position(|&n| n == "mean_size")
            .unwrap();
        assert!(
            floors[max_i] > floors[mean_i],
            "an extreme must earn a HIGHER floor than a mean on heavy-tailed data: \
             max_size {:.3} vs mean_size {:.3}",
            floors[max_i],
            floors[mean_i]
        );

        // And on a fresh null split, ranking by excess must not crown anything:
        // every feature should sit at or under its own floor most of the time.
        let (a, b) = flows.split_at(60);
        let (feat, acc, ex) = excess_over(a, b, &floors);
        assert!(
            ex <= 0.05,
            "null data must not clear its own permutation floor by much: \
             {feat} acc {acc:.3} excess {ex:+.3}"
        );
    }

    #[test]
    fn aggregating_flows_amplifies_a_residual_a_single_flow_hides() {
        // The threat this measures: a per-flow AUC near the floor reads as
        // "indistinguishable", but an observer watching one host gets HUNDREDS
        // of flows and can average them. For independent samples the separation
        // grows as sqrt(N), so a residual that looks like noise per flow can be
        // decisive per session.
        struct Rng(u64);
        impl Rng {
            fn next(&mut self) -> u64 {
                self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut z = self.0;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                z ^ (z >> 31)
            }
            /// Sizes with a TINY mean shift between classes - small enough that
            /// one flow is nearly useless to a classifier.
            fn size(&mut self, shift: u32) -> u32 {
                if self.next() % 3 == 0 {
                    (self.next() % 1400) as u32 + 40 + shift
                } else {
                    1448
                }
            }
        }

        let mut rng = Rng(0xA11C_E5EE);
        let n = 600;
        let draw = |rng: &mut Rng, shift: u32| -> Vec<FlowTrace> {
            (0..n)
                .map(|_| FlowTrace::new((0..40).map(|_| rng.size(shift)).collect()))
                .collect()
        };
        let a = draw(&mut rng, 0);
        let b = draw(&mut rng, 12);

        let per_flow = measure(&a, &b);
        eprintln!(
            "  group=  1  acc={:.3}  floor={:.3}  excess={:+.3}",
            per_flow.best_accuracy,
            noise_floor(n),
            per_flow.best_accuracy - noise_floor(n)
        );

        // Excess over the floor AT THAT GROUP COUNT is the honest quantity:
        // grouping shrinks the sample, which raises the floor on its own.
        let mut best_excess: f64 = per_flow.best_accuracy - noise_floor(n);
        for g in [5usize, 20, 60] {
            let agg = measure_aggregated(&a, &b, g).expect("enough groups");
            eprintln!(
                "  group={:>3}  acc={:.3}  floor={:.3}  excess={:+.3}  ({} groups)",
                agg.group_size,
                agg.best_accuracy,
                agg.floor,
                agg.excess(),
                agg.groups_per_class
            );
            best_excess = best_excess.max(agg.excess());
        }

        let solo_excess = per_flow.best_accuracy - noise_floor(n);
        assert!(
            best_excess > solo_excess,
            "aggregation must expose more of the residual than a single flow does \
             (solo excess {solo_excess:+.3}, best aggregated {best_excess:+.3})"
        );
        // And the strongest aggregation should be decisively separable, not
        // marginal - that is the whole point of the threat. Assert on EXCESS,
        // the quantity that survives the floor moving underneath it; the raw
        // accuracy is quoted alongside only because it is what people read.
        let deep = measure_aggregated(&a, &b, 60).expect("enough groups");
        assert!(
            deep.excess() > 0.15 && deep.best_accuracy >= 0.85,
            "a residual this size must become decisive once pooled: acc {:.3}, \
             floor {:.3}, excess {:+.3}",
            deep.best_accuracy,
            deep.floor,
            deep.excess()
        );
    }

    #[test]
    fn aggregation_reports_the_floor_for_its_own_group_count() {
        // The trap: grouping trades sample size for signal, and `noise_floor`
        // rises as samples fall. A result read without its own floor credits the
        // estimator's noise to the shaper's leak.
        let flat: Vec<FlowTrace> = (0..400)
            .map(|i| FlowTrace::new(vec![1448, 600 + (i % 7) as u32, 1448, 200]))
            .collect();
        let a = &flat[..200];
        let b = &flat[200..];
        let one = measure_aggregated(a, b, 1).expect("groups");
        let many = measure_aggregated(a, b, 50).expect("groups");
        assert!(
            many.floor > one.floor,
            "fewer groups must carry a HIGHER floor: {} groups floor {:.3} vs {} groups floor {:.3}",
            many.groups_per_class,
            many.floor,
            one.groups_per_class,
            one.floor
        );
        // Too few groups to say anything is None, not a confident number.
        assert!(measure_aggregated(a, b, 150).is_none());
    }

    #[test]
    fn the_metric_has_a_floor_above_one_half_when_nothing_separates() {
        // splitmix64: deterministic, so this test cannot flake.
        struct Rng(u64);
        impl Rng {
            fn next(&mut self) -> u64 {
                self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut z = self.0;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                z ^ (z >> 31)
            }
            /// A plausible record size: mostly full-MTU, some short.
            fn size(&mut self) -> u32 {
                if self.next() % 3 == 0 {
                    (self.next() % 1400) as u32 + 40
                } else {
                    1448
                }
            }
        }

        let mut rng = Rng(0x5EED_C0DE);
        let reps = 40;
        let mut results = Vec::new();
        for &n in &[16usize, 30, 66, 150] {
            let mut sum = 0.0;
            let mut worst: f64 = 0.0;
            for _ in 0..reps {
                let draw = |rng: &mut Rng| -> Vec<FlowTrace> {
                    (0..n)
                        .map(|_| FlowTrace::new((0..40).map(|_| rng.size()).collect()))
                        .collect()
                };
                let a = draw(&mut rng);
                let b = draw(&mut rng);
                let d = measure(&a, &b);
                sum += d.best_accuracy;
                worst = worst.max(d.best_accuracy);
            }
            let mean = sum / f64::from(reps);
            eprintln!("  flows/class={n:>4}  mean floor={mean:.3}  worst={worst:.3}");
            results.push((n, mean));
            assert!(
                mean > 0.5,
                "the fold plus max-over-14-features must bias upward at n={n}"
            );
            assert!(
                mean < 0.75,
                "a floor of {mean:.3} at n={n} would mean the metric is mostly noise"
            );
        }
        // The bias is a small-sample effect: more flows, lower floor.
        let (_, small) = results[0];
        let (_, large) = results[results.len() - 1];
        assert!(
            small > large,
            "floor must fall as the sample grows ({small:.3} at 16 flows vs {large:.3} at 150)"
        );
    }

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
