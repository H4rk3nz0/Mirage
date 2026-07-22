//! Session-layer errors. Maps to `mirage_common::Error::Session` at the boundary.

use thiserror::Error;

/// Error produced by the session layer during handshake or framing.
#[derive(Debug, Error)]
pub enum SessionError {
    /// Wire format violation: wrong length, bad magic, wrong message type.
    #[error("wire: {0}")]
    Wire(&'static str),

    /// Peer announced an incompatible wire version.
    #[error("version mismatch: peer={peer}, supported=[{min}..={max}]")]
    VersionMismatch {
        /// Version the peer announced.
        peer: u16,
        /// Minimum version we support.
        min: u16,
        /// Maximum (current) version we support.
        max: u16,
    },

    /// Underlying Noise protocol error.
    #[error("noise: {0}")]
    Noise(#[from] snow::Error),

    /// ML-KEM operation failed.
    #[error("ml-kem: {0}")]
    MlKem(&'static str),

    /// State machine was driven incorrectly (e.g., write_message_3 before read_message_2).
    #[error("state: {0}")]
    State(&'static str),

    /// Capability-token verification failed: signature / bridge-pin / expiry / replay.
    #[error("token: {0}")]
    TokenVerification(&'static str),

    /// Underlying byte-stream I/O failure (e.g., TCP, tokio duplex).
    /// Used by [`crate::tunnel`] orchestrators; not produced by the
    /// I/O-free state machines.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl From<SessionError> for mirage_common::Error {
    fn from(e: SessionError) -> Self {
        mirage_common::Error::Session(e.to_string())
    }
}
