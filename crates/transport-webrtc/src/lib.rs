//! WebRTC data-channel transport for Mirage.
//!
//! # Why WebRTC is the strongest carrier
//!
//! WebRTC is **the** universally-allowed real-time-comms transport. Blocking it
//! breaks every video conference, voice call, and browser game that rides
//! STUN/TURN/DTLS-SCTP. The collateral cost of blocking it is orders of
//! magnitude higher than blocking a V2Ray/Trojan/REALITY-style transport - this
//! asymmetry is exactly what makes Tor's Snowflake so hard to kill. A Mirage
//! session that rides a WebRTC **data channel** inherits that leverage, and the
//! NAT traversal comes for free.
//!
//! # Layering
//!
//! ```text
//!   Client (offerer)            Signaling                Bridge (answerer)
//!   ----------------            ---------                -----------------
//!   create PeerConnection
//!   create data channel
//!   create SDP offer  ---------> exchange -------------> set remote offer
//!                                (CDN-fronted HTTPS,      create data channel
//!                                 or any Signaling impl)  create SDP answer
//!   set remote answer <--------- exchange <------------- (answer)
//!   -- ICE (host/STUN/TURN) -> DTLS -> SCTP data channel --
//!   Mirage session frames over the reliable, ordered data channel
//! ```
//!
//! - **Signaling** is a thin seam ([`Signaling`]): the client hands its SDP
//!   offer to some rendezvous and gets the bridge's answer back. Any transport
//!   works - a CDN-fronted HTTPS broker, an existing Mirage discovery channel,
//!   even manual copy-paste. The crate ships the WebRTC mechanics; the
//!   deployment picks the rendezvous.
//! - **Data channel** carries the opaque Mirage session bytes over DTLS-SCTP.
//!   [`WebRtcStream`] adapts it to `AsyncRead + AsyncWrite` so the session layer
//!   drives it exactly like any socket.
//!
//! # Feature gate
//!
//! The real ICE/DTLS/SCTP stack (`webrtc-rs`, ~50 crates) is behind the opt-in
//! **`webrtc`** feature so the default build stays lean and the supply-chain
//! gate stays green. Without the feature the crate still compiles and
//! [`WebRtcClientTransport::dial`] returns an explanatory error; with it, the
//! real [`imp`] module ([`webrtc_dial`], [`webrtc_answer`], [`WebRtcStream`],
//! [`Signaling`]) is available.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use async_trait::async_trait;
use mirage_transport::{ClientTransport, DialInputs, DuplexStream, TransportError};

pub mod imp;
pub mod signaling;

pub use imp::{
    webrtc_answer, webrtc_dial, Signaling, WebRtcAccept, WebRtcError, WebRtcSession, WebRtcStream,
    DEFAULT_STUN_SERVER,
};
pub use signaling::{read_offer_request, write_answer_response, HttpSignaling};

/// Capability bit for WebRTC (bit 2).
pub const WEBRTC_CAPABILITY_BIT: u32 = 1 << 2;

/// Default WebRTC data-channel label. Picked to match common browser-to-browser
/// data-channel labels so wire-shape doesn't distinguish Mirage clients from
/// generic WebRTC apps.
pub const DEFAULT_DATACHANNEL_LABEL: &str = "data";

/// Operator-side WebRTC configuration carried alongside a bridge announcement.
#[derive(Debug, Clone)]
pub struct WebRtcOperatorConfig {
    /// HTTPS URL of the signaling broker. Both client and bridge exchange SDP
    /// here (or via any other [`Signaling`](imp::Signaling) implementation).
    pub broker_url: String,
    /// Operator-controlled STUN/TURN servers. Empty = use the built-in default
    /// STUN (`stun:stun.l.google.com:19302`) - for a bridge with a public IP,
    /// host candidates alone often suffice and STUN can be dropped entirely.
    pub ice_servers: Vec<String>,
    /// Data-channel label. Defaults to [`DEFAULT_DATACHANNEL_LABEL`].
    pub datachannel_label: String,
}

impl Default for WebRtcOperatorConfig {
    fn default() -> Self {
        Self {
            broker_url: String::new(),
            ice_servers: Vec::new(),
            datachannel_label: DEFAULT_DATACHANNEL_LABEL.to_string(),
        }
    }
}

/// Client-side WebRTC transport.
///
/// WebRTC dials through a [`Signaling`](imp::Signaling) rendezvous rather than a
/// bare endpoint, so - like the other self-managed carriers (meek, dnstt) - it
/// is driven through a dedicated entry point ([`webrtc_dial`](imp::webrtc_dial))
/// rather than the generic race. The [`ClientTransport`] impl exists for
/// registry/name/capability uniformity; its [`dial`](ClientTransport::dial)
/// returns an explanatory error directing callers to the signaling path.
pub struct WebRtcClientTransport;

impl Default for WebRtcClientTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl WebRtcClientTransport {
    /// Construct the transport handle.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ClientTransport for WebRtcClientTransport {
    fn name(&self) -> &'static str {
        "webrtc"
    }

    fn capability_bit(&self) -> u32 {
        WEBRTC_CAPABILITY_BIT
    }

    async fn dial(&self, _inputs: &DialInputs<'_>) -> Result<DuplexStream, TransportError> {
        Err(TransportError::Other(
            "WebRTC dials through a signaling rendezvous - use \
             mirage_transport_webrtc::webrtc_dial(signaling, ..), not the generic race dial"
                .into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_bit_matches_registry() {
        assert_eq!(
            WEBRTC_CAPABILITY_BIT,
            mirage_discovery::wire::transport_caps::WEBRTC
        );
    }

    #[test]
    fn name_is_stable() {
        assert_eq!(WebRtcClientTransport::new().name(), "webrtc");
    }

    #[tokio::test]
    async fn dial_without_signaling_is_an_explicit_error() {
        let t = WebRtcClientTransport::new();
        let ep = mirage_discovery::wire::Endpoint::Ipv4 {
            addr: [127, 0, 0, 1],
            port: 443,
        };
        let inputs = DialInputs {
            endpoint: &ep,
            bridge_static_pk: &[0u8; 32],
            obfs_secret: None,
            deadline: std::time::Duration::from_secs(1),
        };
        assert!(t.dial(&inputs).await.is_err());
    }
}
