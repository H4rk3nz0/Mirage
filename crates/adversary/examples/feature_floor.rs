//! Which FEATURES are unstable on data that has nothing to find?
//!
//! `noise_floor` is one number applied to all 14 features, calibrated on a
//! synthetic size mixture. The features are not comparable statistics, though: a
//! mean concentrates fast, while an extreme like `max_size` is set by rare
//! records and has a heavy-tailed sampling distribution. If the pooled floor
//! understates the unstable ones, a `max_size` "leak" is a measurement artifact.
//!
//! Feed it NULL CONTROL captures - runs with no user traffic, where every AUC
//! should be chance - and it reports each feature's spread across them.
//!
//! ```sh
//! cargo run -p mirage-adversary --example feature_floor -- <idle.sizes> <active.sizes> [more pairs...]
//! ```

use mirage_adversary::flow_classifier::{measure_all, noise_floor, FlowTrace, FEATURE_NAMES};

fn load(p: &str) -> Vec<u32> {
    std::fs::read_to_string(p)
        .unwrap_or_else(|e| panic!("read {p}: {e}"))
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
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 || args.len() % 2 != 0 {
        eprintln!("usage: feature_floor <idle.sizes> <active.sizes> [<idle> <active> ...]");
        std::process::exit(2);
    }
    // Window size matters enormously: at a large window on a downstream flow,
    // `max_size` is 1448 in nearly every window and is degenerate, while on a
    // small-record upstream at a short window it is a genuine extreme statistic
    // and among the least stable. Overridable so both regimes can be checked.
    let w: usize = std::env::var("MIRAGE_W")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);
    let mut runs: Vec<[f64; 14]> = Vec::new();
    let mut n_flows = usize::MAX;
    for pair in args.chunks(2) {
        let a = windows(&load(&pair[0]), w);
        let b = windows(&load(&pair[1]), w);
        n_flows = n_flows.min(a.len().min(b.len()));
        runs.push(measure_all(&a, &b));
    }
    let floor = noise_floor(n_flows);
    println!(
        "{} null-control run(s), window={w}, {n_flows} flows/class, pooled floor {floor:.3}\n",
        runs.len()
    );
    println!(
        "{:<22} {:>8} {:>8} {:>8}   accuracy per run",
        "feature", "worst", "mean", "spread"
    );
    println!("{}", "-".repeat(78));
    let mut rows: Vec<(f64, String)> = Vec::new();
    for (i, name) in FEATURE_NAMES.iter().enumerate() {
        // Accuracy is the folded AUC: what `measure` would score on this feature.
        let accs: Vec<f64> = runs.iter().map(|r| r[i].max(1.0 - r[i])).collect();
        let worst = accs.iter().cloned().fold(0.0f64, f64::max);
        let mean = accs.iter().sum::<f64>() / accs.len() as f64;
        let spread = worst - accs.iter().cloned().fold(1.0f64, f64::min);
        let each: Vec<String> = accs.iter().map(|a| format!("{a:.3}")).collect();
        rows.push((
            worst,
            format!(
                "{name:<22} {worst:>8.3} {mean:>8.3} {spread:>8.3}   {}",
                each.join(" ")
            ),
        ));
    }
    rows.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    for (_, line) in &rows {
        println!("{line}");
    }
    let over: Vec<&str> = FEATURE_NAMES
        .iter()
        .enumerate()
        .filter(|(i, _)| runs.iter().any(|r| r[*i].max(1.0 - r[*i]) > floor))
        .map(|(_, n)| *n)
        .collect();
    println!(
        "\n{} of {} features exceed the pooled floor on data with NOTHING to find:",
        over.len(),
        FEATURE_NAMES.len()
    );
    println!("  {}", over.join(", "));
    println!(
        "\nThose are the features whose own floor is higher than the pooled estimate.\n\
         A 'leak' reported on one of them, near the floor, is not evidence."
    );
}
