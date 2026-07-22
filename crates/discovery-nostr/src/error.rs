//! Errors produced by the Nostr discovery adapter.

use thiserror::Error;

/// Error variants for the Nostr adapter.
#[derive(Debug, Error)]
pub enum NostrError {
    /// Wire format invalid (JSON parse, field missing, wrong type).
    #[error("wire: {0}")]
    Wire(&'static str),

    /// Hex decode failed (id, pubkey, sig).
    #[error("hex: {0}")]
    Hex(&'static str),

    /// Event ID mismatch: the event's `id` field doesn't equal SHA-256 of
    /// the canonical serialization of the event's other fields.
    #[error("event id mismatch")]
    IdMismatch,

    /// Schnorr signature verification failed.
    #[error("signature verification failed")]
    SignatureInvalid,

    /// Event content (base64) decoding failed.
    #[error("base64: {0}")]
    Base64(&'static str),

    /// Required tag missing (e.g., `d` tag for parametric-replaceable events).
    #[error("tag: {0}")]
    Tag(&'static str),

    /// JSON canonicalization / serialization failed.
    #[error("json: {0}")]
    Json(&'static str),
}

impl From<NostrError> for mirage_common::Error {
    fn from(e: NostrError) -> Self {
        mirage_common::Error::Discovery(e.to_string())
    }
}
