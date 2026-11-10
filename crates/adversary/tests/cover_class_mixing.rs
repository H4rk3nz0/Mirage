//! A session must wear ONE cover class, and this is the measurement that says so.
//!
//! `read_profile` used to pool every downstream class into one chain, so a single
//! session's rate stepped phase-to-phase with whichever trace the shuffle drew.
//! Scored with this crate's own 14-feature distinguisher over real captures, that
//! was **separable**: AUC 0.807 against a real browsing session and 0.759 against
//! a real streaming one, reaching a perfect 1.000 once an observer pooled 16
//! windows. Selecting one class per session put both back on the null control
//! (0.511 / 0.517 against a 0.552 floor). See `docs/proteus.md` and
//! `tools/cover-sources/class-mixing-auc.py`.
//!
//! That measurement needed real recorded traffic and a network. This test keeps
//! the PROPERTY under guard without either: it builds two synthetic classes whose
//! size distributions differ the way browse and video really do, drives the real
//! `pace_wire_sizes` path, and asserts that what a session emits is separable from
//! neither - which is only true if the selection never mixes them.
//!
//! It is deliberately a guardrail rather than a reproduction. A future change that
//! reintroduces pooling does not have to be caught by someone remembering to
//! re-run a Python script against a freshly recorded library.

use mirage_adversary::flow_classifier::{measure, noise_floor, FlowTrace};
use mirage_transport_reality::paced::{pace_wire_sizes, set_pace_override};

/// Records per scored window. Matches the 300 used for the real measurement.
const WINDOW: usize = 300;
/// Sessions drawn per class. Enough windows that the floor is meaningful.
const SESSIONS: u64 = 40;
/// The two classes' record sizes, far enough apart that a mixed chain is
/// unmistakable on the size axis.
const BROWSE_SIZE: u16 = 400;
const VIDEO_SIZE: u16 = 1400;

/// Write a trace whose records are all `size`, so the two classes differ on the
/// size axis the way a browse capture and a video capture actually do (measured:
/// browse 494-960 kbit/s in short bursty spans, video 330 kbit/s in long steady
/// ones). Constant sizes make the contrast unambiguous - if selection ever mixes
/// classes, a window straddling the seam is trivially separable.
fn write_trace(dir: &std::path::Path, idx: usize, size: u16, rows: usize) {
    let mut s = String::from("t,size,dir\n");
    for i in 0..rows {
        // Downstream (dir > 0): the direction a censor watches from the bridge.
        s.push_str(&format!("{:.3},{size},1\n", i as f64 * 0.01));
    }
    std::fs::write(dir.join(format!("{idx}.csv")), s).expect("write trace");
}

fn windows(sizes: &[u16]) -> Vec<FlowTrace> {
    sizes
        .chunks(WINDOW)
        .filter(|c| c.len() == WINDOW)
        .map(|c| FlowTrace::new(c.iter().map(|&x| u32::from(x)).collect()))
        .collect()
}

/// The downstream sizes ONE session emits.
fn session_sizes(seed: u64) -> Vec<u16> {
    pace_wire_sizes(true, seed)
        .map(|rows| rows.into_iter().map(|(sz, _)| sz).collect())
        .unwrap_or_default()
}

/// Windows from every session in `seeds` whose class matches `size`.
fn windows_of_class(seeds: std::ops::Range<u64>, size: u16) -> Vec<FlowTrace> {
    let mut out = Vec::new();
    for seed in seeds {
        let s = session_sizes(seed);
        if s.first() != Some(&size) {
            continue;
        }
        out.extend(windows(&s));
    }
    out
}

#[test]
fn a_session_never_mixes_cover_classes() {
    let root = std::env::temp_dir().join(format!("mirage_classmix_{}", std::process::id()));
    let browse = root.join("browse");
    let video = root.join("video");
    std::fs::create_dir_all(&browse).expect("mkdir browse");
    std::fs::create_dir_all(&video).expect("mkdir video");
    // Deliberately NOT a multiple of WINDOW: with trace length aligned to the
    // window size every seam falls on a window boundary, so a mixed chain still
    // yields pure windows and the whole check passes vacuously. That is exactly
    // how the first version of this test failed to catch reintroduced pooling.
    for i in 0..6 {
        write_trace(&browse, i, BROWSE_SIZE, 730);
    }
    for i in 0..4 {
        write_trace(&video, i, VIDEO_SIZE, 730);
    }

    set_pace_override(
        "replay",
        Some(root.to_string_lossy().into_owned()),
        // No upstream library: this measures the DOWNSTREAM envelope, which is
        // what the pooling defect corrupted and what a censor watching a bridge
        // sees most of.
        None,
    );

    // 1. THE PROPERTY, checked per SESSION rather than per window. A pooled chain
    //    mixes classes at trace seams, which a window-level check can miss but a
    //    whole-session check cannot.
    let mut saw = std::collections::HashSet::new();
    for seed in 0..SESSIONS {
        let sizes = session_sizes(seed);
        assert!(!sizes.is_empty(), "seed {seed} produced no cover at all");
        let distinct: std::collections::HashSet<u16> = sizes.iter().copied().collect();
        assert!(
            distinct.len() <= 1,
            "seed {seed} wore two cover classes in one session ({distinct:?});              selection is pooling again - see docs/proteus.md"
        );
        saw.extend(distinct);
    }
    // 2. COVERAGE. Dropping a class would also make sessions pure, and would be a
    //    silent loss of cover diversity rather than a fix.
    assert!(
        saw.contains(&BROWSE_SIZE) && saw.contains(&VIDEO_SIZE),
        "both classes must still be worn across sessions, saw {saw:?}"
    );

    // 3. And a session must sit on the floor against an independently seeded draw
    //    of the SAME class - the contrast that matters, because a real session is
    //    homogeneous. (Scoring pooled-against-pooled is vacuous: both sides carry
    //    the same mixture, so they match each other while matching nothing real.)
    for (label, size) in [("browse", BROWSE_SIZE), ("video", VIDEO_SIZE)] {
        let cover = windows_of_class(0..SESSIONS, size);
        let reference = windows_of_class(1000..1000 + SESSIONS, size);
        if cover.len() < 10 || reference.len() < 10 {
            continue; // too few draws of this class to score honestly
        }
        let d = measure(&cover, &reference);
        let floor = noise_floor(cover.len().min(reference.len()));
        assert!(
            d.best_accuracy <= floor,
            "{label} cover is separable from an independent draw of itself: \
             {:.3} on `{}` against a {:.3} floor",
            d.best_accuracy,
            d.top_feature,
            floor
        );
    }

    std::fs::remove_dir_all(&root).ok();
}
