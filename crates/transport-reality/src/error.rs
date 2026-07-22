//! Errors produced by the REALITY-v2 auth-probe layer.
//!
//! **Security note**: on the bridge side, these errors MUST NOT be
//! signaled to the remote peer. Any failure of the probe layer means the
//! bridge falls through to the cover-service forwarding path - the peer
//! receives a legitimate TLS session from the cover destination, not
//! information about why Mirage auth rejected them.

use thiserror::Error;

/// Auth-probe error variants. Used internally by the bridge; not
/// serialized to the wire.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RealityError {
    /// `session_id` bytes do not match the required 32-byte length.
    #[error("session_id length")]
    SessionIdLen,

    /// Timestamp is outside the `+/-TIMESTAMP_WINDOW_SECONDS` window.
    #[error("timestamp out of window")]
    TimestampStale,

    /// The MAC tag computed over the probe fields does not match the wire value.
    #[error("tag mismatch")]
    TagMismatch,

    /// The `(nonce, timestamp)` pair was already seen in the replay set.
    #[error("replay")]
    Replay,

    /// Replay set is full; no free capacity to record this probe.
    /// Treat as auth fail (fall through to cover).
    #[error("replay set capacity")]
    ReplaySetFull,

    /// X25519 shared secret is the all-zero point (peer sent a bogus pubkey).
    #[error("x25519 zero point")]
    ZeroPoint,

    /// Underlying byte-stream I/O failure (TCP, duplex, etc.). Used by
    /// [`crate::carrier`]; the probe layer itself is I/O-free.
    #[error("io: {0}")]
    Io(String),
}

impl From<RealityError> for mirage_transport::TransportError {
    fn from(e: RealityError) -> Self {
        // All Reality probe errors map to Auth - the uniform signal
        // callers rely on to trigger the cover-service path.
        mirage_transport::TransportError::Auth(match e {
            RealityError::SessionIdLen => "session_id length",
            RealityError::TimestampStale => "timestamp stale",
            RealityError::TagMismatch => "tag mismatch",
            RealityError::Replay => "replay",
            RealityError::ReplaySetFull => "replay set full",
            RealityError::ZeroPoint => "zero point",
            RealityError::Io(_) => "io",
        })
    }
}
