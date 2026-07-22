//! Protocol version + wire constants - the source of truth for "what protocol
//! version does this binary implement." Clients and bridges negotiate
//! [`MIN_SUPPORTED_SPEC_VERSION`] at session establishment.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Protocol version implemented by this build.
pub const SPEC_VERSION: &str = "0.1.0";

/// Minimum spec version this implementation will negotiate with a peer.
///
/// Peers announcing a lower version are refused. Updating this is a breaking
/// change and requires a major version bump of the binary.
pub const MIN_SUPPORTED_SPEC_VERSION: &str = "0.1.0";

/// Protocol wire version. Incremented on every breaking wire change.
pub const WIRE_VERSION: u16 = 1;

/// Ratchet epoch - how often session keys advance.
///
/// Changing this value is a wire-compatible change but affects forward secrecy
/// guarantees.
pub const RATCHET_EPOCH_SECONDS: u64 = 3600;

/// Capability token validity window (seconds).
///
/// Spec reference: §L1 invariant D4. Tokens outside this window are rejected.
pub const CAPABILITY_TOKEN_WINDOW_SECONDS: u64 = 3600;

/// Discovery epoch - how often discovery info-hashes rotate.
///
/// Tied to `CAPABILITY_TOKEN_WINDOW_SECONDS`: a token cannot outlive the
/// discovery epoch in which it was issued.
pub const DISCOVERY_EPOCH_SECONDS: u64 = CAPABILITY_TOKEN_WINDOW_SECONDS;

/// Maximum session frame size (bytes, plaintext).
///
/// Chosen to fit comfortably inside a single TCP segment on common MTUs
/// after transport overhead. Transports MAY fragment further.
pub const MAX_FRAME_SIZE: usize = 16384;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::const_is_empty)] // deliberately asserts the version consts are populated
    fn versions_are_present() {
        assert!(!SPEC_VERSION.is_empty());
        assert!(!MIN_SUPPORTED_SPEC_VERSION.is_empty());
    }

    #[test]
    fn ratchet_matches_capability_window() {
        // If these diverge, forward-secrecy and token-freshness windows drift
        // apart - keep them equal unless you intend that.
        assert_eq!(RATCHET_EPOCH_SECONDS, CAPABILITY_TOKEN_WINDOW_SECONDS);
    }
}
