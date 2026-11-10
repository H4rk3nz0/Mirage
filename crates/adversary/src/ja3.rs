//! **Attack**: JA3 signature match.
//!
//! A passive DPI tool collects `ClientHello` fingerprints from a
//! network sample and compares them against a known-Mirage JA3
//! signature. If Mirage always emits the SAME `ClientHello` shape,
//! the censor catches it on the first signature in their database.
//!
//! **Defense being tested**: per-CLIENT template pinning across
//! multiple browser templates (Chrome / Firefox / Safari), weighted
//! by real-world distribution (RT-CN-4 closure). Each client pins one
//! template for its lifetime; the diversity shows up ACROSS the client
//! population, not within a single client's connections.
//!
//! **Distinguisher we look for**: a sample of N sessions produces
//! fewer than M distinct JA3 strings (low template diversity), or
//! the distribution diverges significantly from real-world browser
//! shares.

use crate::{AdversaryError, AdversaryResult, DetectionVerdict};
use mirage_transport_reality::tls_fingerprint;
use std::collections::HashMap;

/// Run the JA3 signature attack. Samples `n_sessions` independent
/// client population draws (each modelling a separate client process,
/// which pins one template for its lifetime) and analyses the
/// resulting JA3 distribution.
///
/// Returns:
/// - `Defended` if the distribution covers >= 3 distinct JA3
///   strings AND no single string dominates above 80% (just
///   above the ~75% Chrome top-share the weighted picker targets).
/// - `Distinguished(_)` if fewer than 3 distinct JA3 are seen -
///   Mirage covers too few browsers (`ALL_TEMPLATES` ships 3:
///   Chrome / Firefox / Safari).
/// - `Inconclusive(_)` if `n_sessions < 100` (too few samples
///   for the dominance check).
pub async fn ja3_signature_match(n_sessions: usize) -> AdversaryResult {
    if n_sessions < 100 {
        return Ok(DetectionVerdict::Inconclusive(format!(
            "need >= 100 sessions for statistical claim, got {n_sessions}"
        )));
    }

    // Each network session in a censor's sample comes from a DIFFERENT client
    // process. A real client pins ONE browser template for its whole lifetime
    // (`pick_weighted_template`), so the per-connection JA3 never rotates within
    // a client; the population blend happens ACROSS clients. Model that here by
    // drawing the un-pinned population sample once per simulated client -
    // sampling the pinned picker in this single test process would (correctly)
    // return one fixed JA3 for all N sessions.
    let mut counts: HashMap<String, usize> = HashMap::new();
    for _ in 0..n_sessions {
        let tpl = tls_fingerprint::pick_weighted_population();
        let ja3 = tls_fingerprint::ja3_string(tpl);
        *counts.entry(ja3).or_default() += 1;
    }

    let distinct = counts.len();
    // Contract: the rotation MUST surface all 3 `ALL_TEMPLATES` browsers
    // (Chrome / Firefox / Safari). Fewer than 3 means a template dropped
    // out of the rotation - a diversity regression a JA3 database exploits.
    if distinct < 3 {
        return Ok(DetectionVerdict::Distinguished(format!(
            "only {distinct} distinct JA3 across {n_sessions} sessions \
             - expected 3 (Chrome / Firefox / Safari). Defense regression: \
             check `pick_weighted_template` and `ALL_TEMPLATES`."
        )));
    }

    // The weighted picker targets ~75% Chrome; 0.80 sits just above that
    // top-share so genuine population blending passes but a collapse toward
    // one browser (which a population classifier flags) trips the gate.
    let max_share = *counts.values().max().unwrap() as f64 / n_sessions as f64;
    if max_share > 0.80 {
        return Ok(DetectionVerdict::Distinguished(format!(
            "single JA3 dominates at {:.1}% of sessions ({} of {} hits) \
             - distribution too narrow for population blending.",
            max_share * 100.0,
            *counts.values().max().unwrap(),
            n_sessions
        )));
    }

    Ok(DetectionVerdict::Defended)
}

/// Same attack but uses the **uniform** rotation. Documents the
/// historical (pre-RT-CN-4) behavior - uniform across 3 templates
/// = ~33% each, which diverges from real-world ~75/15/10 shares.
/// A long-flow population classifier with a baseline of "real
/// internet traffic" can see this skew. We accept it as
/// `Distinguished` to demonstrate the contrast with weighted.
pub async fn ja3_uniform_population_skew(n_sessions: usize) -> AdversaryResult {
    if n_sessions < 1000 {
        return Ok(DetectionVerdict::Inconclusive(format!(
            "need >= 1000 sessions for population-skew claim, got {n_sessions}"
        )));
    }

    let mut counts: HashMap<&'static str, usize> = HashMap::new();
    for _ in 0..n_sessions {
        let tpl = tls_fingerprint::pick_random_template();
        *counts.entry(tpl.name).or_default() += 1;
    }

    // Expected real-world ~ 75/15/10; uniform ~ 33/33/33.
    // Chrome share check: uniform gives ~33%, real-world ~75%.
    let chrome_share =
        counts.get("chrome-desktop").copied().unwrap_or(0) as f64 / n_sessions as f64;
    if chrome_share < 0.5 {
        return Ok(DetectionVerdict::Distinguished(format!(
            "uniform rotation produces chrome share {:.1}% - real \
             internet traffic is ~75% Chrome. Use \
             `pick_weighted_template` for population blending.",
            chrome_share * 100.0
        )));
    }

    Ok(DetectionVerdict::Defended)
}

/// Boxed [`Adversary`] for the JA3 attack - usable in lists.
pub struct Ja3SignatureMatch {
    /// Number of sessions to sample.
    pub n_sessions: usize,
}

#[async_trait::async_trait]
impl crate::Adversary for Ja3SignatureMatch {
    async fn run(&self) -> Result<DetectionVerdict, AdversaryError> {
        ja3_signature_match(self.n_sessions).await
    }
    fn name(&self) -> &'static str {
        "ja3_signature_match"
    }
    fn defense(&self) -> &'static str {
        "RT-CN-4: weighted JA3 rotation (tls_fingerprint::pick_weighted_template)"
    }
}
