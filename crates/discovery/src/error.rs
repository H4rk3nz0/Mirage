//! Discovery-layer errors.

use thiserror::Error;

/// Error produced by the discovery layer.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    /// Wire format violation: wrong length, bad magic, wrong doc_type.
    #[error("wire: {0}")]
    Wire(&'static str),

    /// Signature verification failed.
    #[error("signature: {0}")]
    Signature(&'static str),

    /// Decryption or MAC check failed (wrong salt, wrong epoch, tampered blob).
    #[error("decrypt: {0}")]
    Decrypt(&'static str),

    /// A time-based check failed (expired, not-yet-valid, out-of-window).
    #[error("time: {0}")]
    Time(&'static str),

    /// Ed25519 public-key validity failure (e.g., malformed).
    #[error("ed25519: {0}")]
    Ed25519(&'static str),
}

impl From<DiscoveryError> for mirage_common::Error {
    fn from(e: DiscoveryError) -> Self {
        mirage_common::Error::Discovery(e.to_string())
    }
}
