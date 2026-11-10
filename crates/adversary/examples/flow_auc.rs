//! Measure how separable two flows are, using the real learned distinguisher.
//!
//! Honest, non-circular Proteus check: pass Mirage's ACTUAL wire sizes (captured
//! off the paced tunnel) and an independently-captured cover flow. Each input file
//! is one wire size per line (a single long flow); it is split into fixed windows
//! so the distinguisher has >= MIN_SAMPLES flows per class.
//!
//! ```sh
//! cargo run -p mirage-adversary --example flow_auc -- mirage.txt cover.txt [window]
//! ```
//! best_accuracy 0.5 = indistinguishable, 1.0 = perfectly separable.

use mirage_adversary::flow_classifier::{
    measure, measure_aggregated, noise_floor, null_model, FlowTrace, MIN_SAMPLES,
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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: flow_auc <mirage_sizes> <cover_sizes> [window=300]");
        std::process::exit(2);
    }
    let window: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(300);
    let mirage = windows(&load(&args[1]), window);
    let cover = windows(&load(&args[2]), window);
    println!(
        "mirage flows={} cover flows={} (window={window} records each)",
        mirage.len(),
        cover.len()
    );
    // REFUSE rather than warn. An under-sampled class does not produce a weak
    // verdict, it produces a CONFIDENT WRONG one: with an empty class every
    // feature's AUC falls back to 0.5, `best` is seeded at 0.5, and the tool
    // prints "accuracy 0.500 - indistinguishable", which is the best possible
    // result. A caller that greps for "BEST separator" then records a broken
    // capture as a passing cell. Exiting non-zero is what lets the harness's
    // existing failure path fire.
    if mirage.len() < MIN_SAMPLES || cover.len() < MIN_SAMPLES {
        eprintln!(
            "REFUSING: need >= {MIN_SAMPLES} flows per class, got {} and {}. At this \
             sample size the estimator's own floor is {:.3} (it maximises over 14 \
             features), so any verdict would be noise. Capture longer or shrink the \
             window.",
            mirage.len(),
            cover.len(),
            noise_floor(mirage.len().min(cover.len()))
        );
        std::process::exit(3);
    }
    let d = measure(&mirage, &cover);
    println!(
        "\nBEST separator: {} (accuracy {:.3}, raw AUC {:.3})  [0.5=indistinguishable]",
        d.top_feature, d.best_accuracy, d.top_auc
    );
    // Compare against the FLOOR for this sample size, not against 0.5 and not
    // against a fixed 0.60. `measure` maximises max(auc, 1-auc) over 14 features
    // on the sample it reports, so it scores above 0.5 on data with nothing in it
    // - 0.681 at 16 flows per class. A fixed threshold calls that a leak.
    let floor = noise_floor(mirage.len().min(cover.len()));
    println!(
        "FLOOR at {} flows/class: {floor:.3} (what this estimator scores when nothing separates)",
        mirage.len().min(cover.len())
    );
    println!(
        "VERDICT: {}",
        if d.best_accuracy <= floor {
            "indistinguishable - at or below this sample size's floor"
        } else {
            "SEPARABLE above the floor - the shaper leaks on the feature above"
        }
    );

    // The verdict above compares the best of 14 features against ONE constant
    // floor, and the features are not comparable statistics: an extreme like
    // `max_size` has a fatter null tail than a mean, so it clears a pooled floor
    // on data with nothing in it. Measured on real null captures, `max_size` and
    // `size_range` hit 0.571 against a 0.552 pooled floor and were reported as
    // the winning separator on two control runs.
    //
    // So derive each feature's floor from THIS data by permutation - pool both
    // classes, relabel at random many times, take the 95th percentile per
    // feature - and rank by the margin over each feature's own null instead.
    let mut pooled: Vec<FlowTrace> = Vec::with_capacity(mirage.len() + cover.len());
    pooled.extend_from_slice(&mirage);
    pooled.extend_from_slice(&cover);
    // Per-feature floors alone are still not enough, because `measure` reports a
    // MAXIMUM over fourteen of them: thresholding each at its own 95th percentile
    // leaves a family-wise false-positive rate far above 5%. Measured, a null
    // control's `max_size` at 0.571 cleared the pooled floor (0.552) AND its own
    // permuted floor (0.551) and was still nothing. So the bar is the max-T
    // quantile: the null distribution of the LARGEST centred accuracy across
    // features, which is the statistic actually being selected.
    let nm = null_model(&pooled, mirage.len(), 200, 0.95, 0x5EED);
    let (feat, acc, margin) = nm.verdict(&mirage, &cover);
    println!("\nAgainst a null PERMUTED from this data (200 draws, max-T at p95):");
    println!(
        "  strongest: {feat} (accuracy {acc:.3}), family-wise bar {:+.3} on centred excess",
        nm.familywise
    );
    println!(
        "  VERDICT: {}",
        if margin <= 0.0 {
            format!("indistinguishable - {margin:+.3} against the bar, having paid for 14 features")
        } else {
            format!("SEPARABLE - clears the family-wise bar by {margin:+.3}")
        }
    );
    if d.top_feature != feat {
        println!(
            "  NOTE: the pooled-floor winner was {}, which does not survive its own\n\
             \x20       floor. That is the failure mode this check exists for.",
            d.top_feature
        );
    }

    // A per-window verdict answers "can a censor tell from ONE window", which is
    // not the threat. A censor watching a host gets every window that host
    // produces and can average them, and for independent samples the separation
    // grows as sqrt(N) - so a residual that reads as noise per window can be
    // decisive per session. Report the curve rather than leaving the reader to
    // assume it stays flat.
    //
    // EXCESS is the column to read, not accuracy. Grouping divides the sample
    // count and the floor rises as samples fall, so raw accuracy climbs for two
    // unrelated reasons and only the margin over each level's OWN floor
    // separates them.
    println!("\nIf an observer pools several windows from the same host:");
    println!(
        "{:>7}  {:>8}  {:>7}  {:>8}  {:>7}",
        "windows", "accuracy", "floor", "excess", "groups"
    );
    let solo_excess = d.best_accuracy - floor;
    println!(
        "{:>7}  {:>8.3}  {:>7.3}  {:>+8.3}  {:>7}",
        1,
        d.best_accuracy,
        floor,
        solo_excess,
        mirage.len().min(cover.len())
    );
    let mut worst_excess = solo_excess;
    for g in [4usize, 16, 64] {
        let Some(agg) = measure_aggregated(&mirage, &cover, g) else {
            continue;
        };
        println!(
            "{:>7}  {:>8.3}  {:>7.3}  {:>+8.3}  {:>7}",
            agg.group_size,
            agg.best_accuracy,
            agg.floor,
            agg.excess(),
            agg.groups_per_class
        );
        worst_excess = worst_excess.max(agg.excess());
    }
    if worst_excess > solo_excess + 0.02 {
        println!(
            "\nNOTE: pooling widens the margin ({solo_excess:+.3} -> {worst_excess:+.3}). A \
             per-window verdict of 'indistinguishable' does NOT imply a session is."
        );
    }
}
