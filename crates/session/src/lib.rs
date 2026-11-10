//! Mirage session layer.
//!
//! Implements the Noise-XX + ML-KEM-768 handshake and (forthcoming) the
//! ratcheted post-handshake session.
//!
//! # Module layout
//!
//! - [`wire`] - fixed-size handshake-message codecs + cleartext alerts (§3, §6.1)
//! - [`handshake`] - initiator/responder state machines, session-key derivation (§3, §3.5)
//! - [`error`] - session-layer errors (map to `mirage_common::Error::Session`)
//!
//! Post-handshake frame encryption, ratcheting (§4, §5), and encrypted alerts
//! (§6.2) land in follow-up modules.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// Safety gate for the `_danger_no_token_*` handshake constructors. They
// bypass capability-token verification, which is a core access-control
// invariant. Enabling the feature in
// a release build silently removes that invariant, so we refuse to
// compile. `debug_assertions` is on for `dev`/`test` and off for
// `release`/`bench` - tests and fuzz harnesses remain unaffected.
#[cfg(all(feature = "danger-no-token", not(debug_assertions)))]
compile_error!(
    "The `danger-no-token` feature is enabled in a release profile. \
     This feature exposes handshake constructors that bypass capability-token \
     verification and MUST NEVER ship in a production binary. If you see this \
     from CI, search for `features = [\"danger-no-token\"]` and remove it; \
     if you are running fuzz harnesses in release mode, switch them to dev."
);

pub mod cover;
pub mod error;
pub mod frames;
pub mod handshake;
pub mod padding;
pub mod stream;
pub mod tunnel;
pub mod udp_frame;
pub mod wire;

pub use cover::{
    cbr_csprng_jitter, cbr_deterministic_jitter, cbr_zero_jitter, CbrCoverPolicy,
    CbrCoverScheduler, CbrTickDecision,
};
pub use error::SessionError;
pub use frames::{
    Direction, SessionFramer, AEAD_TAG_LEN, MAX_FRAME_PLAINTEXT, MAX_OUTER_CT_LEN, MIN_OUTER_CT_LEN,
};
pub use handshake::{
    AcceptedTokenKind, HandshakeInitiator, HandshakeResponder, SessionKeys, TokenVerifier,
};
pub use padding::{
    pad_for_kind, pad_to_padme, padme, unpad_from_padme, FrameKind, PaddingPolicy, PadmeError,
};
pub use stream::SessionStream;
pub use tunnel::{
    accept, accept_with_peer_static, connect, connect_fs, read_padded_handshake,
    read_padded_handshake_m3, write_padded_handshake, write_padded_handshake_floor,
};
pub use udp_frame::{
    UdpFramer, MAX_UDP_DATAGRAM_BYTES, UDP_LENGTH_PREFIX_LEN, UDP_RELAY_MAGIC_HOSTNAME,
    UDP_RELAY_MAGIC_PORT,
};

/// Role in a session handshake. Threaded into [`frames::SessionFramer`] to
/// pick the per-direction key + nonce assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Initiator - client side.
    Initiator,
    /// Responder - bridge side.
    Responder,
}
