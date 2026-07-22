//! Shared types, errors, and utilities used across Mirage crates.
//!
//! This crate has no dependencies on other Mirage crates; it is the root of
//! the internal dependency tree.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod process_hardening;
pub mod replay_nonce;
pub mod secure_file;

pub use replay_nonce::{SeenNonceSet, DEFAULT_SEEN_NONCE_CAPACITY};

use thiserror::Error;

/// Top-level error type for the Mirage protocol.
///
/// Layer-specific errors wrap into these variants so higher layers can
/// categorize failures without depending on each lower-layer crate.
#[derive(Debug, Error)]
pub enum Error {
    /// Protocol-level error: wire format, version mismatch, invariant violation.
    #[error("protocol: {0}")]
    Protocol(String),

    /// Cryptographic operation failed.
    #[error("crypto: {0}")]
    Crypto(String),

    /// Transport layer failure (connect, TLS, QUIC, etc.).
    #[error("transport: {0}")]
    Transport(String),

    /// Discovery layer failure (DHT, Nostr, broker).
    #[error("discovery: {0}")]
    Discovery(String),

    /// Session layer failure (handshake, ratchet, decrypt).
    #[error("session: {0}")]
    Session(String),

    /// I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Shorthand for `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// Threat tiers of the Mirage threat model.
///
/// Each Mirage component declares which tiers it defeats. The build system
/// rejects components that claim to defeat a tier without a documented path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ThreatTier {
    /// Signature-matching DPI. Corporate firewalls, school filters.
    T1,
    /// Nation-state, limited ISP cooperation. Iran, Russia (pre-2022), UAE.
    T2,
    /// Nation-state, full ISP cooperation, ML at line rate. GFW, etc.
    T3,
}

/// Initialize structured logging. Idempotent; safe to call multiple times.
///
/// Respects the `RUST_LOG` environment variable. Default filter: `info`.
pub fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threat_tiers_are_ordered() {
        assert!(ThreatTier::T1 < ThreatTier::T2);
        assert!(ThreatTier::T2 < ThreatTier::T3);
    }

    #[test]
    fn error_displays_cleanly() {
        let e = Error::Protocol("bad version".into());
        assert_eq!(e.to_string(), "protocol: bad version");
    }
}
