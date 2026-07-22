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

use mirage_adversary::flow_classifier::{measure, FlowTrace, MIN_SAMPLES};

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
    if mirage.len() < MIN_SAMPLES || cover.len() < MIN_SAMPLES {
        eprintln!(
            "WARNING: need >= {MIN_SAMPLES} flows per class for a meaningful verdict; \
             capture more records or shrink the window"
        );
    }
    let d = measure(&mirage, &cover);
    println!(
        "\nBEST separator: {} (accuracy {:.3}, raw AUC {:.3})  [0.5=indistinguishable]",
        d.top_feature, d.best_accuracy, d.top_auc
    );
    println!(
        "VERDICT: {}",
        if d.best_accuracy <= 0.60 {
            "indistinguishable (<= 0.60) - the shaper does not leak on any single feature"
        } else {
            "SEPARABLE - the shaper leaks on the feature above"
        }
    );
}
