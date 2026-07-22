//! Mirage L2 transport framework.
//!
//! v0.1t expansion: this crate provides the full transport-architecture
//! surface - [`ClientTransport`] (uniform dial trait), the [`adaptive`]
//! EXP3 router + [`SuccessRateMap`] (per-network success bias). Concrete
//! transports (REALITY-v2, Trojan-style, MASQUE, WebRTC, etc.) each ship as
//! their own crate, adapt to [`ClientTransport`], and are SELECTED by the
//! adaptive router.
//!
//! Note: a naive `race_transports` (parallel-race-to-connect) primitive was
//! removed - dialing many carriers in parallel contradicts this crate's own
//! anti-enumeration design ([`select::SelectionPolicy`] + the [`adaptive`]
//! router's diversity/entropy floor deliberately SPREAD load), so racing would
//! trade first-connect latency for a louder per-bridge enumeration signature.
//! Carrier choice is the adaptive router's job; a bounded hedged-dial could be
//! reconsidered as an explicit optimization but is not a default.
//!
//! # Architecture
//!
//! ```text
//! Client
//!  +-- DiscoveryRouter fetches announcements (per-epoch info-hash)
//!       +-- filter by client.transport_mask & ann.transport_caps
//!            +-- adaptive router SELECTS a ClientTransport (EXP3 + posture)
//!                 +-- dial it -> session-layer Mirage handshake over the result
//!
//! Bridge
//!  +-- per-transport accept loop (each transport has its own server-side adapter)
//!       +-- after auth, hand the byte stream to session::accept()
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use async_trait::async_trait;
use mirage_discovery::wire::{Announcement, Endpoint};
use std::pin::Pin;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

pub mod adaptive;
pub mod cover_bandit;
pub mod netfp;
pub mod posture_net;
pub mod select;
pub mod self_adversary;
pub mod success_persist;
pub mod success_rate;

pub use cover_bandit::{CoverClass, CoverClassBandit};
pub use select::{rank, rank_names, Ranked, SelectionPolicy};
// Re-exported from `mirage-common` (the dependency root) so transports keep
// using `mirage_transport::SeenNonceSet` while discovery/onion share the same
// primitive without depending on this crate.
pub use mirage_common::{SeenNonceSet, DEFAULT_SEEN_NONCE_CAPACITY};
pub use success_persist::{load_from_path, save_to_path, PersistError};
pub use success_rate::{NetworkFingerprint, SuccessRateMap, SuccessStats};

/// Error returned by transport operations.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Authentication failed at the transport-probe layer (e.g., REALITY
    /// pre-TLS `session_id` check). Transport MUST NOT signal this error to
    /// the remote peer; it MUST fall through to the cover-service path.
    #[error("auth: {0}")]
    Auth(&'static str),

    /// Wire format violation before auth completes (malformed `ClientHello`,
    /// wrong length, etc.). Transport MUST NOT signal this to the remote
    /// peer; it MUST fall through to the cover-service path.
    #[error("wire: {0}")]
    Wire(&'static str),

    /// Underlying I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// State-machine misuse (e.g., read before handshake complete).
    #[error("state: {0}")]
    State(&'static str),

    /// Dial deadline expired before the transport finished its handshake.
    #[error("timeout: {0:?}")]
    Timeout(Duration),

    /// Transport-specific failure (carries an opaque payload).
    #[error("transport: {0}")]
    Other(String),
}

impl From<TransportError> for mirage_common::Error {
    fn from(e: TransportError) -> Self {
        mirage_common::Error::Transport(e.to_string())
    }
}

/// Categorizes why a connection attempt failed, so the client-side
/// race-to-connect can make informed retry/fallback decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportOutcome {
    /// Handshake completed; session layer may proceed.
    Success,
    /// The remote endpoint was reachable but declined at transport level
    /// (likely a non-bridge serving cover content). Client SHOULD not
    /// retry this endpoint immediately.
    NonBridge,
    /// Network-level failure (TCP connect timeout, DNS failure, TLS
    /// handshake aborted). Client MAY retry.
    NetworkFailure,
    /// Transport was actively blocked (TLS downgrade, RST, SNI block).
    /// Client SHOULD try a different transport or bridge.
    Blocked,
}

/// Role at transport-probe time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Initiator - client side.
    Initiator,
    /// Responder - bridge side.
    Responder,
}

// ClientTransport trait

/// Type-erased duplex byte stream produced by a successful
/// [`ClientTransport::dial`]. The session layer's `accept` /
/// `connect` consumes any `AsyncRead + AsyncWrite + Send + Unpin`,
/// which this satisfies.
pub type DuplexStream = Pin<Box<dyn AsyncReadWrite + Send>>;

/// Marker trait combining `AsyncRead` and `AsyncWrite` for object-
/// safety. Auto-implemented for any type that satisfies both.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite + ?Sized> AsyncReadWrite for T {}

/// Inputs handed to a [`ClientTransport`] at dial time.
///
/// The transport is responsible for:
/// 1. Connecting to `endpoint` via the appropriate underlying network
///    (TCP for Reality/Trojan, UDP for MASQUE/WireGuard, etc.).
/// 2. Performing transport-specific authentication (Reality probe,
///    Trojan password, etc.) using `bridge_static_pk` and any
///    transport-specific shared secrets.
/// 3. Returning a duplex byte stream the session layer can drive,
///    or a `TransportError` if any step fails.
pub struct DialInputs<'a> {
    /// Endpoint to dial (resolved IP / domain / onion + port).
    pub endpoint: &'a Endpoint,
    /// Bridge's long-term X25519 static public key (from the
    /// announcement). Most transports derive auth from this.
    pub bridge_static_pk: &'a [u8; 32],
    /// Optional per-bridge obfuscation SECRET from the invite
    /// (`MasterInvite::obfs_secret`). When `Some`, transports that
    /// authenticate with a pre-session knock (obfs-tcp, websocket)
    /// key it on this secret instead of the public `bridge_static_pk`
    /// (audit #9), so a prober who only scraped the announcement
    /// pubkey cannot forge a valid knock. `None` falls back to the
    /// legacy pubkey-derived key.
    pub obfs_secret: Option<&'a [u8; 32]>,
    /// Hard deadline for the entire dial operation. Transports MUST
    /// abort on this deadline rather than relying on per-call
    /// timeouts. The race driver passes a smaller deadline to each
    /// transport so the global race is bounded.
    pub deadline: Duration,
}

/// A pluggable client-side transport.
///
/// Implementations:
/// - SHOULD complete dialing within the supplied `deadline` and return
///   [`TransportError::Timeout`] otherwise.
/// - MUST be safe to call concurrently from multiple tasks (the race
///   driver dials many endpoints at once).
/// - MUST NOT mutate global process state on dial.
#[async_trait]
pub trait ClientTransport: Send + Sync {
    /// Stable name for diagnostics ("reality-v2", "trojan", "masque",
    /// "webrtc", etc.). Used as the metric label and in success-rate
    /// keys.
    fn name(&self) -> &'static str;

    /// Capability bit (one of the `transport_caps::*` constants from
    /// [`mirage_discovery::wire`]). Used to filter announcements
    /// the client can use vs. ones it doesn't speak. Returning `0`
    /// is reserved for "synthetic" transports the announcement
    /// layer is unaware of (loopback test transports, etc.).
    fn capability_bit(&self) -> u32;

    /// Dial the bridge, return a duplex byte stream on success.
    async fn dial(&self, inputs: &DialInputs<'_>) -> Result<DuplexStream, TransportError>;
}

/// Filter announcements by the client's transport mask. Returns the
/// subset whose `transport_caps` overlaps with `client_mask`.
///
/// This is the capability-negotiation step: a client
/// supporting only Reality skips announcements whose
/// `transport_caps` declares only WebRTC.
pub fn filter_by_capability(
    announcements: &[Announcement],
    client_mask: u32,
) -> Vec<&Announcement> {
    announcements
        .iter()
        .filter(|a| a.transport_caps & client_mask != 0)
        .collect()
}

#[doc(hidden)]
pub fn _now_for_tests() -> Instant {
    Instant::now()
}

#[allow(missing_docs)]
pub mod _arc_box {
    /// Re-export so callers can construct an Arc<Box<dyn ClientTransport>>
    /// without depending on this crate's choice of Arc/Box.
    pub use std::sync::Arc;
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_discovery::wire::{transport_caps, Endpoint};

    fn ann(caps: u32) -> Announcement {
        Announcement {
            issued_at: 0,
            expires_at: 1,
            bridge_ed25519_pk: [0u8; 32],
            bridge_x25519_pk: [0u8; 32],
            transport_caps: caps,
            endpoint: Endpoint::Ipv4 {
                addr: [127, 0, 0, 1],
                port: 443,
            },
            extra_endpoints: Vec::new(),
            signature: [0u8; 64],
        }
    }

    #[test]
    fn capability_filter_keeps_overlap() {
        let anns = vec![
            ann(transport_caps::REALITY_V2),
            ann(transport_caps::QUIC_MASQUE),
            ann(transport_caps::REALITY_V2 | transport_caps::QUIC_MASQUE),
        ];
        // Client speaks only Reality.
        let f = filter_by_capability(&anns, transport_caps::REALITY_V2);
        assert_eq!(f.len(), 2);
        // Client speaks both.
        let f = filter_by_capability(
            &anns,
            transport_caps::REALITY_V2 | transport_caps::QUIC_MASQUE,
        );
        assert_eq!(f.len(), 3);
        // Client speaks neither.
        let f = filter_by_capability(&anns, transport_caps::WEBRTC);
        assert_eq!(f.len(), 0);
    }

    #[test]
    fn capability_filter_zero_mask_yields_empty() {
        let anns = vec![ann(transport_caps::REALITY_V2)];
        assert!(filter_by_capability(&anns, 0).is_empty());
    }

    // The Arc helper is for downstream callers; smoke-import it.
    #[test]
    fn arc_helper_is_reachable() {
        let _: _arc_box::Arc<u8> = _arc_box::Arc::new(0u8);
    }
}
