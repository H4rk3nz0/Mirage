//! Per-FEATURE separability, plus the d' and time-to-detection that follow.
//!
//! `flow_auc` reports max-over-features, which is the right threat model (a
//! censor picks whatever works) but hides WHERE the residual lives. A shaper
//! that is perfect on ten features and leaking on one has an aggregate number
//! that says "leaking" and gives no clue what to fix.
//!
//! For each of the 14 features this prints the AUC, the implied per-observation
//! d', and how many independent observations an adversary needs to accumulate
//! before the evidence is decisive. Independent samples add as sqrt(N), so
//! d'_total = d' * sqrt(N); "decisive" here is d'_total = 5.66, the point where
//! pooled AUC ~ 0.99.
//!
//! ```sh
//! cargo run -p mirage-adversary --example feature_alpha -- a.txt b.txt [window]
//! ```
use mirage_adversary::flow_classifier::{
    feature_vector, measure_all, noise_floor, FlowTrace, FEATURE_NAMES,
};

fn load(path: &str) -> Vec<u32> {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {path}: {e}"))
        .lines()
        .filter_map(|l| l.trim().parse::<u32>().ok())
        .collect()
}

fn windows(sizes: &[u32], w: usize) -> Vec<FlowTrace> {
    sizes
        .chunks(w)
        .filter(|c| c.len() == w)
        .map(|c| FlowTrace::new(c.to_vec()))
        .collect()
}

/// Read TIME windows: one line per window, space-separated sizes, empty line for
/// a window in which nothing crossed.
///
/// Record-count windowing makes `record_count` constant by construction - its
/// AUC is then 0.500 tautologically and `total_bytes` is perfectly collinear
/// with `mean_size`, so the table silently reports one quantity twice and one
/// feature that cannot ever fire. Time windows make both real, and let an
/// EMPTY window be an observation rather than missing data.
fn time_windows(path: &str) -> Vec<FlowTrace> {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {path}: {e}"))
        .lines()
        .map(|l| {
            FlowTrace::new(
                l.split_whitespace()
                    .filter_map(|t| t.parse::<u32>().ok())
                    .collect(),
            )
        })
        .collect()
}

/// Complementary error function - Numerical Recipes' `erfcc`, ~1.2e-7 absolute.
/// Enough to say "p = 0.17, stop reading" without pulling in a stats crate.
fn erfc(x: f64) -> f64 {
    let z = x.abs();
    let t = 2.0 / (2.0 + z);
    let ty = 4.0 * t - 2.0;
    const C: [f64; 10] = [
        -1.3026537197817094,
        6.419_697_923_564_902e-1,
        1.9476473204185836e-2,
        -9.561_514_786_808_63e-3,
        -9.46595344482036e-4,
        3.66839497852761e-4,
        4.2523324806907e-5,
        -2.0278578112534e-5,
        -1.624290004647e-6,
        1.303655835580e-6,
    ];
    let (mut d, mut dd) = (0.0f64, 0.0f64);
    for j in (1..C.len()).rev() {
        let tmp = d;
        d = ty * d - dd + C[j];
        dd = tmp;
    }
    let ans = t * (-z * z + 0.5 * (C[0] + ty * d) - dd).exp();
    if x >= 0.0 {
        ans
    } else {
        2.0 - ans
    }
}

/// Inverse normal CDF (Acklam), good to ~1e-9 - enough to turn an AUC into d'.
fn probit(p: f64) -> f64 {
    let a = [
        -3.969_683_028_665_376e1,
        2.209_460_984_245_205e2,
        -2.759_285_104_469_687e2,
        1.383_577_518_672_69e2,
        -3.066_479_806_614_716e1,
        2.506_628_277_459_239,
    ];
    let b = [
        -5.447_609_879_822_406e1,
        1.615_858_368_580_409e2,
        -1.556_989_798_598_866e2,
        6.680_131_188_771_972e1,
        -1.328_068_155_288_572e1,
    ];
    let c = [
        -7.784_894_002_430_293e-3,
        -3.223_964_580_411_365e-1,
        -2.400_758_277_161_838,
        -2.549_732_539_343_734,
        4.374_664_141_464_968,
        2.938_163_982_698_783,
    ];
    let d = [
        7.784_695_709_041_462e-3,
        3.224_671_290_700_398e-1,
        2.445_134_137_142_996,
        3.754_408_661_907_416,
    ];
    let pl = 0.02425;
    if p < pl {
        let q = (-2.0 * p.ln()).sqrt();
        (((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5])
            / ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1.0)
    } else if p <= 1.0 - pl {
        let q = p - 0.5;
        let r = q * q;
        (((((a[0] * r + a[1]) * r + a[2]) * r + a[3]) * r + a[4]) * r + a[5]) * q
            / (((((b[0] * r + b[1]) * r + b[2]) * r + b[3]) * r + b[4]) * r + 1.0)
    } else {
        -probit(1.0 - p)
    }
}

/// A feature that cannot carry evidence, or carries someone else's.
#[derive(PartialEq)]
enum Guard {
    Ok,
    /// Constant (or near-constant) in the sample: its AUC is an artifact of the
    /// windowing, not a measurement. `record_count` under record-count
    /// windowing is exactly this - every flow has the same length by
    /// construction, so the 0.500 it reports is tautological.
    Degenerate(&'static str),
    /// Dominated by a single repeated value - almost always 0 from empty
    /// windows. Such a feature is mostly the empty/non-empty INDICATOR wearing
    /// a size feature's name, and reporting it as a size result misattributes
    /// the mechanism.
    PointMass(f64),
    /// Collinear with an earlier feature. `total_bytes = mean_size * count`, so
    /// with count fixed the two are the same quantity printed twice.
    Collinear(&'static str),
}

/// Spearman rank correlation - rank-based so it catches monotone collinearity,
/// not just linear.
fn spearman(a: &[f64], b: &[f64]) -> f64 {
    fn ranks(v: &[f64]) -> Vec<f64> {
        let mut idx: Vec<usize> = (0..v.len()).collect();
        idx.sort_by(|&i, &j| v[i].partial_cmp(&v[j]).unwrap_or(std::cmp::Ordering::Equal));
        let mut r = vec![0.0; v.len()];
        let mut i = 0;
        while i < idx.len() {
            let mut j = i;
            while j + 1 < idx.len() && (v[idx[j + 1]] - v[idx[i]]).abs() < f64::EPSILON {
                j += 1;
            }
            // Mid-rank for ties, so ties do not manufacture correlation.
            let mid = (i + j) as f64 / 2.0;
            for &k in &idx[i..=j] {
                r[k] = mid;
            }
            i = j + 1;
        }
        r
    }
    let (ra, rb) = (ranks(a), ranks(b));
    let n = a.len() as f64;
    let (ma, mb) = (ra.iter().sum::<f64>() / n, rb.iter().sum::<f64>() / n);
    let mut num = 0.0;
    let (mut da, mut db) = (0.0, 0.0);
    for i in 0..a.len() {
        let (x, y) = (ra[i] - ma, rb[i] - mb);
        num += x * y;
        da += x * x;
        db += y * y;
    }
    if da <= 0.0 || db <= 0.0 {
        return 0.0;
    }
    num / (da * db).sqrt()
}

/// How many distinct values a feature must take before its AUC means anything.
const MIN_DISTINCT: usize = 3;
/// Share of identical values above which a feature is a mixed mechanism.
const POINT_MASS_FRAC: f64 = 0.20;
/// |rho| above which two features are the same measurement.
const COLLINEAR_RHO: f64 = 0.98;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: feature_alpha <a_sizes> <b_sizes> [window=50]");
        std::process::exit(2);
    }
    // `--time` reads pre-sliced time windows instead of chunking by record count.
    let time_mode = args.iter().any(|a| a == "--time");

    // PROVENANCE. `--run <dir>` requires an intact run record: a manifest, and
    // inputs whose checksums match what it says was captured.
    //
    // This is the guard the other seven could not be. They all check numbers in
    // front of them, and the analysis path only ever sees data that survived -
    // so a run that produced evidence and then destroyed it is invisible to
    // every one of them. That happened: a fixed log path was cleared at the
    // start of each run, claims were made from runs whose logs no longer
    // existed, and it went unnoticed for three rounds. Refusing unattributed
    // input is the only thing that catches it.
    if let Some(i) = args.iter().position(|a| a == "--run") {
        let dir = args.get(i + 1).unwrap_or_else(|| {
            eprintln!("--run needs a run directory");
            std::process::exit(2);
        });
        let mpath = std::path::Path::new(dir).join("manifest.json");
        let Ok(manifest) = std::fs::read_to_string(&mpath) else {
            eprintln!(
                "REFUSING: no manifest at {}. An unattributed capture cannot be \
                 analysed - there is no way to know which run, build, config or trace \
                 produced it.",
                mpath.display()
            );
            std::process::exit(1);
        };
        if !manifest.contains("\"offset_wall_minus_monotonic\"") {
            eprintln!(
                "REFUSING: manifest records no clock offset. The relay uses CLOCK_MONOTONIC \
                 and the daemon logs use wall-clock UTC; without the offset any join \
                 between windows and carrier events matches NOTHING and reads as a clean \
                 null rather than an error."
            );
            std::process::exit(1);
        }
        for f in [&args[1], &args[2]] {
            if !std::path::Path::new(f).starts_with(dir) {
                eprintln!(
                    "REFUSING: input {f} is outside the run directory {dir}. Analysing a \
                     capture from one run against a manifest from another is exactly the \
                     cross-run confusion this guard exists to prevent."
                );
                std::process::exit(1);
            }
        }
        eprintln!("provenance: manifest present, clock offset recorded, inputs in-run");
    }
    let w: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(50);
    let (mut a, mut b) = if time_mode {
        (time_windows(&args[1]), time_windows(&args[2]))
    } else {
        (windows(&load(&args[1]), w), windows(&load(&args[2]), w))
    };

    // Exposure equality is asserted on the RAW window counts, BEFORE any
    // filtering. Pre-filter imbalance is a harness fault - the classes did not
    // get equal opportunity to be observed. Post-filter imbalance is something
    // else entirely: it is induced by conditioning on liveness, and liveness is
    // the thing being measured, so the imbalance IS the finding. Conflating the
    // two makes the tool refuse a result instead of reporting it.
    {
        let (ra, rb) = (a.len(), b.len());
        let imb = (ra as f64 - rb as f64).abs() / (ra.max(rb).max(1) as f64);
        if imb > 0.15 {
            eprintln!(
                "REFUSING: raw window counts differ by {:.0}% ({ra} vs {rb}) BEFORE \
                 filtering. That is unequal capture exposure, a harness fault - fix \
                 the capture, do not interpret this run.",
                imb * 100.0
            );
            std::process::exit(1);
        }
    }

    // DECOMPOSE, do not mix. An empty window makes mean = min = max = 0, so
    // every size feature becomes largely the empty/non-empty INDICATOR wearing
    // a size feature's name - and the reported AUC is mostly liveness
    // misattributed to sizes. The two channels have different mechanisms and
    // different fixes, so they are reported separately and the size features
    // are computed CONDITIONAL on the window being live, with the conditioning
    // variable stated rather than hidden.
    if time_mode {
        let ea = a.iter().filter(|f| f.record_sizes.is_empty()).count();
        let eb = b.iter().filter(|f| f.record_sizes.is_empty()).count();
        let (ra, rb) = (
            ea as f64 / a.len().max(1) as f64,
            eb as f64 / b.len().max(1) as f64,
        );
        // AUC of a binary indicator = the Mann-Whitney statistic, which for two
        // Bernoulli samples is P(x>y) + P(x=y)/2.
        let auc = ra * (1.0 - rb) + 0.5 * (ra * rb + (1.0 - ra) * (1.0 - rb));
        // SIGNED d'. The magnitude alone loses the direction, and the direction
        // is what distinguishes token starvation (load -> MORE dead air) from
        // more concurrent carriers (load -> LESS dead air). Different mechanisms,
        // different fixes; a magnitude cannot tell them apart.
        let d_signed = probit(auc) * std::f64::consts::SQRT_2;
        let d = d_signed.abs();
        let n = if d > 1e-6 {
            (5.66 / d).powi(2)
        } else {
            f64::INFINITY
        };
        println!("== LIVENESS CHANNEL (carrier up/down per window) ==");
        println!(
            "  empty-window rate: A {:.0}%  B {:.0}%   AUC {auc:.3}  d' {d_signed:+.3}  N {}",
            ra * 100.0,
            rb * 100.0,
            if n.is_finite() {
                format!("{n:.0}")
            } else {
                "-".into()
            }
        );
        // A PROPORTION TEST, not just an AUC. 31% vs 50% reads as a large gap and
        // is 8/26 vs 12/24 in counts - z = -1.39, p = 0.17, nowhere near
        // significance. An AUC printed without its sample size invites exactly
        // the over-reading that produced two rounds of chasing this number.
        let (xa, xb) = (ra * a.len() as f64, rb * b.len() as f64);
        let pooled = (xa + xb) / (a.len() + b.len()) as f64;
        let se = (pooled * (1.0 - pooled) * (1.0 / a.len() as f64 + 1.0 / b.len() as f64)).sqrt();
        let z = if se > 0.0 { (ra - rb) / se } else { 0.0 };
        // Two-sided p from the normal tail, via the complementary error function.
        let pval = erfc(z.abs() / std::f64::consts::SQRT_2);
        println!(
            "  counts: {:.0}/{} vs {:.0}/{}   z {z:+.2}   two-sided p {pval:.3}  -> {}",
            xa,
            a.len(),
            xb,
            b.len(),
            if pval > 0.05 {
                "NOT SIGNIFICANT - do not interpret the direction below"
            } else {
                "significant"
            }
        );
        println!(
            "  direction: A is {} often empty than B.",
            if ra < rb { "LESS" } else { "MORE" }
        );
        // The expected direction is a PARAMETER, not a constant. Hard-coding one
        // hypothesis makes the guard emit a spurious conflict as soon as the
        // working hypothesis changes - which happened here: an earlier version
        // asserted token starvation's direction, and the moment multi-carrier
        // became the working theory the same data would have been flagged
        // "conflict" for agreeing with it. Report which hypotheses the observed
        // sign is consistent with, and let the reader own the choice.
        println!("  sign is consistent with:");
        if ra > rb {
            println!("    - token starvation (load consumes tokens -> more dead air)");
        } else {
            println!("    - more concurrent carriers (independent schedules -> denser coverage)");
            println!("      ...but ONLY if empty RUNS also shorten under load; if runs");
            println!("      lengthen instead, independent schedules are not the cause.");
        }
        println!("    - trace-offset alignment, in either direction: the classes may");
        println!("      simply be sampling different parts of the same schedule, which");
        println!("      is a measurement artifact and not a leak at all.");
        println!(
            "  Distinguish by empty-RUN length and by whether empties land at the\n  \
             same trace offsets in both classes - the marginal rate cannot."
        );
        println!(
            "  Under the stated invariant this must be class-INDEPENDENT: a\n               trace-derived schedule emits regardless of queue state.\n"
        );
        a.retain(|f| !f.record_sizes.is_empty());
        b.retain(|f| !f.record_sizes.is_empty());
        println!("== SIZE CHANNEL, conditional on the window being live ==");
    }
    let floor = noise_floor(a.len().min(b.len()));

    // EXPOSURE EQUALITY, asserted rather than noted. Unequal window counts mean
    // the classes did not get equal opportunity to be observed, and every
    // per-class statistic below is then confounded by the imbalance. This is
    // the check that would have caught active windows running 20.4-35.0s
    // against idle's 20.0s; it was a note in the output last time, and notes
    // get read past.
    let (na, nb) = (a.len(), b.len());
    let imbalance = (na as f64 - nb as f64).abs() / (na.max(nb).max(1) as f64);
    if imbalance > 0.15 {
        // Post-filter, so this is a liveness STATISTIC, not a harness fault. The
        // size channel below still cannot be read across unequal samples, but the
        // imbalance itself is a number worth having rather than only a reason to
        // stop.
        println!(
            "  live-window ratio A/B = {:.2} ({na} vs {nb}, {:.0}% imbalance).\n  \
             Induced by conditioning on liveness, so it is a liveness result. The\n  \
             size features below are NOT comparable across samples this unequal -\n  \
             read them as indicative only.",
            na as f64 / nb.max(1) as f64,
            imbalance * 100.0
        );
    }
    if na.min(nb) < 16 {
        eprintln!(
            "REFUSING: {} flows in the smaller class - below the estimator's minimum. \
             Any verdict would be noise.",
            na.min(nb)
        );
        std::process::exit(1);
    }

    // Per-feature values, needed for the degeneracy and collinearity guards.
    let vals = |flows: &[FlowTrace], i: usize| -> Vec<f64> {
        flows.iter().map(|f| feature_vector(f)[i]).collect()
    };
    let mut guards: Vec<Guard> = Vec::with_capacity(FEATURE_NAMES.len());
    let mut pooled: Vec<Vec<f64>> = Vec::with_capacity(FEATURE_NAMES.len());
    for i in 0..FEATURE_NAMES.len() {
        let mut v = vals(&a, i);
        v.extend(vals(&b, i));
        pooled.push(v);
    }
    for (i, v) in pooled.iter().enumerate() {
        let mut sorted = v.clone();
        sorted.sort_by(|x, y| x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal));
        sorted.dedup_by(|x, y| (*x - *y).abs() < f64::EPSILON);
        if sorted.len() < MIN_DISTINCT {
            guards.push(Guard::Degenerate("constant by construction"));
            continue;
        }
        // Largest point mass.
        let mut best = 0usize;
        let mut run = 1usize;
        let mut s2 = v.clone();
        s2.sort_by(|x, y| x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal));
        for k in 1..s2.len() {
            if (s2[k] - s2[k - 1]).abs() < f64::EPSILON {
                run += 1;
            } else {
                best = best.max(run);
                run = 1;
            }
        }
        best = best.max(run);
        let frac = best as f64 / v.len() as f64;
        let mut g = if frac > POINT_MASS_FRAC {
            Guard::PointMass(frac)
        } else {
            Guard::Ok
        };
        // Collinear with an EARLIER surviving feature?
        for j in 0..i {
            if matches!(guards[j], Guard::Degenerate(_) | Guard::Collinear(_)) {
                continue;
            }
            if spearman(v, &pooled[j]).abs() > COLLINEAR_RHO {
                g = Guard::Collinear(FEATURE_NAMES[j]);
                break;
            }
        }
        guards.push(g);
    }
    let effective = guards
        .iter()
        .filter(|g| !matches!(g, Guard::Degenerate(_) | Guard::Collinear(_)))
        .count();
    println!(
        "flows: {na} vs {nb}   per-feature floor {floor:.3}   \
         effective features {effective}/{} (rest degenerate or collinear)",
        FEATURE_NAMES.len()
    );
    println!(
        "\n{:<20} {:>6} {:>8} {:>12}   guard / verdict",
        "feature", "AUC", "d'", "N to decide"
    );
    let aucs = measure_all(&a, &b);
    let mut rows: Vec<(usize, f64)> = aucs.iter().copied().enumerate().collect();
    rows.sort_by(|x, y| {
        let dx = (x.1 - 0.5).abs();
        let dy = (y.1 - 0.5).abs();
        dy.partial_cmp(&dx).unwrap_or(std::cmp::Ordering::Equal)
    });
    for (i, auc) in rows {
        let one_sided = auc.max(1.0 - auc);
        let dprime = probit(one_sided) * std::f64::consts::SQRT_2;
        let n = if dprime > 1e-6 {
            (5.66 / dprime).powi(2)
        } else {
            f64::INFINITY
        };
        let n_s = if n.is_finite() {
            format!("{n:.0}")
        } else {
            "-".to_string()
        };
        let note = match &guards[i] {
            Guard::Degenerate(why) => format!("DEGENERATE ({why}) - excluded"),
            Guard::Collinear(other) => format!("COLLINEAR with {other} - excluded"),
            Guard::PointMass(f) => format!(
                "POINT MASS {:.0}% - mixed mechanism, decompose before believing",
                f * 100.0
            ),
            Guard::Ok if one_sided > floor => "ABOVE FLOOR".to_string(),
            Guard::Ok => "at/below floor".to_string(),
        };
        println!(
            "{:<20} {auc:>6.3} {dprime:>8.3} {n_s:>12}   {note}",
            FEATURE_NAMES[i]
        );
    }
    println!(
        "\nN is independent observations to reach d'_total=5.66 (pooled AUC ~0.99).\n\
         Features at/below the floor are not measurable at this sample size - the\n\
         number beside them is what the estimator's own noise would imply, not a leak."
    );
}
