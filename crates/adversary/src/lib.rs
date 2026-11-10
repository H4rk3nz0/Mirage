//! Canonical censorship attacks against Mirage's defenses.
//!
//! # Philosophy
//!
//! Mirage's claim is **continuously verified defenses**, not just
//! documented ones. Every defense in the protocol stack MUST have
//! a corresponding [`Adversary`] in this crate that simulates the
//! attack the defense was built for. If the defense regresses, the
//! adversary test fires.
//!
//! This is what separates Mirage from a list of "things we said
//! we did": every defensive claim is a runnable test. The censor's
//! playbook IS the test harness.
//!
//! # Threat catalog
//!
//! Each adversary corresponds to a real attack a censor would run:
//!
//! - [`ja3_signature_match`] - passive DPI matches Mirage's
//!   `ClientHello` against a JA3 database. Defense: weighted
//!   real-world distribution (RT-CN-4).
//! - [`active_probe_replay`] - censor captures a legitimate
//!   `ClientHello` and replays it. Defense: replay-probe set + per-
//!   prober key.
//! - [`tarpit_timing_oracle`] - censor probes obfs-tcp with
//!   garbage and times the close. Defense: fast-close jitter
//!   (RT-CN-3).
//! - [`announcement_version_tag_leak`] - passive observer of the
//!   discovery channel buckets operators by version byte. Defense:
//!   universal `V0_1T` encoding (RT-CN-9).
//! - [`token_batch_correlator`] - observer of leaked tokens
//!   correlates expiries to recover mint timestamp. Defense:
//!   per-token expiry jitter (RT-CN-11).
//! - [`cohort_restart_dos`] - censor exhausts cohort reveal cap,
//!   triggers bridge restart, retries. Defense: persistent
//!   [`mirage_discovery::RevealStore`] (RT-CN-10).
//! - [`relay_payload_length_classifier`] - passive observer
//!   classifies traffic by Mirage's fixed-1024-byte cell shape.
//!   Defense: padding policy + cover traffic.
//! - `auth_fail_timing_oracle` (RT-CN-1) - active prober times the
//!   `ServerHello` response gap. Defense: eager parallel cover-connect.
//!   **Not yet implemented (Phase 2L)** - the runtime adversary needs
//!   an in-process bridge mock; the defense itself is code-reviewed at
//!   [`mirage_transport_reality::carrier::reality_accept`] (see
//!   `DEFENSES.md`, "Active probing").
//! - [`flow_shape_distinguisher`] - a passive **learned** flow
//!   classifier (concrete F4): can a best-single-feature threshold
//!   classifier separate Mirage's record-size distribution from
//!   cover better than chance? Defense: the
//!   [`mirage_transport_reality::RecordShaper`] + Padme + cover
//!   traffic. The first learned distinguisher here - it makes the
//!   aspirational F4 invariant a measured, CI-gateable property.
//! - [`uniformity_verdict`] / [`obfs_auth_tag_uniformity`] - the
//!   byte-entropy counterpart: a censor's entropy/randomness DPI
//!   (monobit + byte chi-square + per-bit bias) run against Mirage's
//!   own claimed-uniform opaque-transport bytes. Defense: BLAKE3/
//!   CSPRNG wire fields. Asserts the T1 "uniform random bytes" claim
//!   is a runnable test, not a hope.
//!
//! # Verdict semantics
//!
//! Each adversary returns a [`DetectionVerdict`]:
//!
//! - `Defended` - the defense held; the adversary couldn't
//!   distinguish Mirage from cover.
//! - `Distinguished` - the adversary found a signal that
//!   distinguishes Mirage. Test SHOULD fail.
//! - `Inconclusive` - the adversary needs more data; e.g., a
//!   timing attack with too few samples to be statistically
//!   meaningful.
//!
//! Adversaries that return `Distinguished` MUST cite the
//! distinguisher concretely so a developer fixing it knows what
//! to look at.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod adaptive_routing;
pub mod cell_length;
pub mod cohort_dos;
pub mod flow_classifier;
pub mod ja3;
pub mod probe_replay;
pub mod quic_initial;
pub mod randomness;
pub mod tarpit;
pub mod token_batch;
pub mod version_leak;

use thiserror::Error;

/// One adversary's verdict against a defense.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectionVerdict {
    /// The defense held - the adversary couldn't distinguish
    /// Mirage from the cover protocol. Test passes.
    Defended,
    /// The adversary found a distinguisher. Test fails. The
    /// embedded `String` cites the concrete signal - a developer
    /// closing the regression knows what to look at.
    Distinguished(String),
    /// The adversary needs more data / samples / time. Test
    /// neither passes nor fails - caller decides (typically:
    /// re-run with a larger budget, or treat as failure if the
    /// budget was already at the spec'd ceiling).
    Inconclusive(String),
}

impl DetectionVerdict {
    /// Convenience: true iff the defense held.
    pub fn is_defended(&self) -> bool {
        matches!(self, DetectionVerdict::Defended)
    }
    /// Convenience: true iff the adversary distinguished.
    pub fn is_distinguished(&self) -> bool {
        matches!(self, DetectionVerdict::Distinguished(_))
    }
}

/// Errors an adversary can produce during execution (separate
/// from the verdict - these mean the adversary itself failed,
/// not that a distinguisher was found).
#[derive(Debug, Error)]
pub enum AdversaryError {
    /// Underlying I/O failure (cover server unreachable, etc.).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Wire-format / parser error in the adversary's
    /// reconstruction of the target's traffic.
    #[error("parse: {0}")]
    Parse(String),
    /// The adversary needs operator config (e.g., a known-good
    /// bridge pubkey) that wasn't supplied.
    #[error("missing input: {0}")]
    MissingInput(&'static str),
}

/// A configured adversary that runs one specific attack against
/// a specific target. Implementations are usually plain functions
/// - the trait exists for the rare case where the adversary needs
/// stateful setup (e.g., long-running passive observers).
#[async_trait::async_trait]
pub trait Adversary: Send + Sync {
    /// Run the attack. Returns a verdict.
    async fn run(&self) -> Result<DetectionVerdict, AdversaryError>;

    /// A short human-readable name. Used in test output.
    fn name(&self) -> &'static str;

    /// The defense this adversary tests (RT-* id + description).
    /// Pinned so a developer reading test output knows what's at
    /// stake.
    fn defense(&self) -> &'static str;
}

/// Result type for adversary functions.
pub type AdversaryResult = Result<DetectionVerdict, AdversaryError>;

pub use cell_length::relay_payload_length_classifier;
pub use cohort_dos::cohort_restart_dos;
pub use flow_classifier::{flow_shape_distinguisher, Distinguishability, FlowTrace};
pub use ja3::ja3_signature_match;
pub use probe_replay::active_probe_replay;
pub use randomness::{obfs_auth_tag_uniformity, uniformity_verdict, UniformityReport};
pub use tarpit::tarpit_timing_oracle;
pub use token_batch::token_batch_correlator;
pub use version_leak::announcement_version_tag_leak;
