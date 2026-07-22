//! HTTP/WebSocket tunnel transport for Mirage.
//!
//! # Overview
//!
//! `transport-ws` wraps Mirage session bytes inside standard
//! WebSocket frames over an HTTP/1.1 upgrade. The client speaks
//! CLEARTEXT `ws://` HTTP over the TCP socket - it does NOT originate
//! TLS (red-team #4). It is indistinguishable from routine HTTPS ->
//! CDN -> origin WebSocket ONLY when the operator fronts the bridge
//! with a real TLS terminator (a CDN reverse proxy like Cloudflare/
//! Fastly/Akamai, or a local nginx/Caddy on :443) that terminates TLS
//! and forwards the WebSocket cleartext to the bridge. Used bare
//! (client dialing the bridge directly), the upgrade request + auth
//! token are plaintext on the wire; never expose a bare ws port on a
//! censored network.
//!
//! # Wire format
//!
//! ```text
//!  Client                                  Bridge
//!  ------                                  ------
//!  Phase 1 - HTTP/1.1 WebSocket upgrade
//!  ------------------------------------->
//!                                          101 Switching Protocols
//!                                         <-------------------------
//!
//!  Phase 2 - Mirage auth frame (72 B, binary WS frame)
//!    nonce[32]       CSPRNG random
//!    mac[32]         BLAKE3_keyed(bridge_static_pk,
//!                     "mirage-ws-v1" || nonce || timestamp_be)
//!    timestamp[8]    BE u64 unix seconds
//!  ------------------------------------->
//!                                          verify MAC + timestamp +/-30 s
//!                                          on failure: close WS silently
//!
//!  Phase 3 - Mirage session bytes as binary WS frames
//!  <------------------------------------>
//! ```
//!
//! # Threat model fit
//!
//! - **T1 (signature DPI):** [ok] - traffic masquerades as WebSocket
//!   to a CDN; no protocol-specific Mirage signature.
//! - **T2 (active prober):** [ok] - the `bridge_static_pk` is required
//!   to construct a valid MAC; a prober without it cannot auth.
//!   The timestamp check prevents replay attacks.
//! - **T3 (ML on flow shape):** partial - WebSocket framing adds
//!   some structure; compose with traffic-shaping for fuller
//!   coverage.
//!
//! # Capability bit
//!
//! `WS_CAPABILITY_BIT` = bit 7 (`WS_TUNNEL`).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use blake3 as b3;
use futures::{Sink, Stream};
use mirage_crypto::subtle::ConstantTimeEq;
use mirage_discovery::wire::Endpoint;
use mirage_transport::{ClientTransport, DialInputs, DuplexStream, TransportError};
use sha1::{Digest, Sha1};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;

/// Capability bit for the WebSocket tunnel transport.
///
/// Bit 7 - allocated as `WS_TUNNEL`.
/// Operators set this bit in their announcement's `transport_caps`
/// to indicate the bridge accepts WebSocket tunnel connections.
pub const WS_CAPABILITY_BIT: u32 = 1 << 7;

/// Length of the Mirage auth frame sent after the WebSocket upgrade.
///
/// Layout: `nonce[32] || mac[32] || timestamp[8]` = 72 bytes.
pub const WS_AUTH_FRAME_LEN: usize = 72;

/// The BLAKE3 keyed-hash domain separator for the WS auth MAC.
const WS_MAC_LABEL: &[u8] = b"mirage-ws-v1";

/// Domain separator for the secret-keyed WS knock key derivation (audit #9).
const WS_SECRET_KEY_LABEL: &[u8] = b"mirage-ws-secret-v1-key";

/// Maximum timestamp skew allowed during bridge-side auth validation.
const WS_TIMESTAMP_SKEW_SECS: u64 = 30;

/// Maximum size of the HTTP upgrade request the server will read (bytes).
const HTTP_REQUEST_MAX_BYTES: usize = 4096;

/// The WebSocket magic GUID required by RFC 6455 for accept-key derivation.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// Audit #13: the Mirage auth token used to ride in a second
// `Sec-WebSocket-Protocol` entry behind a fixed `v1.bearer.` prefix. Even
// namespaced, a 96-char high-entropy base64url subprotocol is a
// zero-false-positive passive tell, and the constant prefix was one grep rule
// for every Mirage WS handshake. The token now rides in a realistic session
// `Cookie` (see `ws_cookie_name`), where a value that long is ordinary, so the
// `Sec-WebSocket-Protocol` offer is a plain real cover subprotocol with nothing
// Mirage-unique on the wire.

// Configuration

/// Client-side configuration for the WebSocket transport.
///
/// The `cover_host` is sent as the HTTP `Host` header, enabling CDN
/// domain fronting: the TLS SNI targets a CDN edge node while the
/// `Host` header routes the request to the actual bridge origin.
#[derive(Debug, Clone)]
pub struct WsClientConfig {
    /// HTTP `Host` header value (for CDN fronting).
    ///
    /// Example: `"bridge.cdn-tenant.example.com"`. Does not affect
    /// TCP dial - the dial target comes from `DialInputs::endpoint`.
    pub cover_host: String,
    /// HTTP request path. Defaults to `"/ws"`.
    pub path: String,
}

impl WsClientConfig {
    /// Construct a config with the given cover host and default path `"/ws"`.
    pub fn new(cover_host: impl Into<String>) -> Self {
        Self {
            cover_host: cover_host.into(),
            path: "/ws".into(),
        }
    }
}

impl Default for WsClientConfig {
    fn default() -> Self {
        Self::new("localhost")
    }
}

// Client-side transport

/// Client-side WebSocket tunnel transport.
///
/// Stateless beyond its `config`; safe to share via `Arc` across tasks.
/// Each call to [`dial`](ClientTransport::dial) opens a fresh TCP
/// connection, performs the HTTP WebSocket upgrade, sends the Mirage
/// auth frame, and returns the post-auth stream.
pub struct WsClientTransport {
    /// Transport configuration (cover host, path).
    config: WsClientConfig,
}

impl WsClientTransport {
    /// Construct a new client transport with the provided config.
    pub fn new(config: WsClientConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl ClientTransport for WsClientTransport {
    fn name(&self) -> &'static str {
        "ws-tunnel"
    }

    fn capability_bit(&self) -> u32 {
        WS_CAPABILITY_BIT
    }

    async fn dial(&self, inputs: &DialInputs<'_>) -> Result<DuplexStream, TransportError> {
        // Single source of truth: this method owns only the TCP connect and then
        // delegates the WebSocket upgrade + Mirage auth to [`ws_client_connect`],
        // the live client path exercised by mirage-client. Keeping one wire
        // implementation ensures the trait-object dial and the standalone dial
        // can never drift (RT #15: pre-101 auth in `Sec-WebSocket-Protocol`,
        // F20-M cover subprotocol, mandatory `Sec-WebSocket-Key`).
        let addr = endpoint_to_socket_addr(inputs.endpoint)?;

        let tcp = tokio::time::timeout(inputs.deadline, TcpStream::connect(addr))
            .await
            .map_err(|_| TransportError::Timeout(inputs.deadline))?
            .map_err(TransportError::Io)?;

        let stream = ws_client_connect(
            tcp,
            inputs.bridge_static_pk,
            inputs.obfs_secret,
            &self.config.path,
            &self.config.cover_host,
            inputs.deadline,
        )
        .await?;

        Ok(Box::pin(stream))
    }
}

// WsStream: AsyncRead + AsyncWrite wrapper around WebSocket

/// Adapts a [`tokio_tungstenite::WebSocketStream`] to `AsyncRead + AsyncWrite`.
///
/// Binary frames from the peer are buffered in `read_buf`; writes are
/// sent as single binary frames. Control frames (Ping/Pong/Close) are
/// silently consumed on the read path.
pub struct WsStream<S> {
    inner: tokio_tungstenite::WebSocketStream<S>,
    /// Buffered bytes from the last received binary frame.
    read_buf: bytes::Bytes,
    /// Pending write bytes accumulated until flush is called.
    write_buf: Vec<u8>,
    /// A Pong owed in reply to a received Ping (RFC 6455 §5.5.2). Sent eagerly
    /// from the read path so that even a read-only stream answers a DPI
    /// liveness Ping - silence is an instant active-probe distinguisher
    /// (DPI-R4). `None` when nothing is owed.
    pending_pong: Option<bytes::Bytes>,
}

impl<S> WsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Wrap a WebSocket stream.
    pub fn new(ws: tokio_tungstenite::WebSocketStream<S>) -> Self {
        Self {
            inner: ws,
            read_buf: bytes::Bytes::new(),
            write_buf: Vec::new(),
            pending_pong: None,
        }
    }
}

impl<S> AsyncRead for WsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;

        let me = self.get_mut();

        loop {
            // If we owe a Pong (RFC 6455 §5.5.3), try to send it before reading
            // more. poll_ready registers the sink's write-waker with `cx`, so a
            // not-ready sink re-wakes this poll_read when it can accept the Pong
            // - even on an otherwise read-only stream.
            if let Some(payload) = me.pending_pong.take() {
                match Sink::<Message>::poll_ready(std::pin::Pin::new(&mut me.inner), cx) {
                    Poll::Ready(Ok(())) => {
                        let _ = Sink::<Message>::start_send(
                            std::pin::Pin::new(&mut me.inner),
                            Message::Pong(payload),
                        );
                        let _ = Sink::<Message>::poll_flush(std::pin::Pin::new(&mut me.inner), cx);
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(std::io::Error::other(e))),
                    Poll::Pending => {
                        me.pending_pong = Some(payload);
                        return Poll::Pending;
                    }
                }
            }

            // Drain buffered bytes first.
            if !me.read_buf.is_empty() {
                let n = std::cmp::min(me.read_buf.len(), buf.remaining());
                buf.put_slice(&me.read_buf[..n]);
                me.read_buf = me.read_buf.slice(n..);
                return Poll::Ready(Ok(()));
            }

            // Poll the inner WebSocket stream for the next message.
            match std::pin::Pin::new(&mut me.inner).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())), // EOF
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(std::io::Error::other(e)));
                }
                Poll::Ready(Some(Ok(msg))) => match msg {
                    Message::Binary(data) => {
                        me.read_buf = bytes::Bytes::from(data.to_vec());
                        // Loop to drain from read_buf.
                    }
                    Message::Text(t) => {
                        // Text frames are not used by this transport. Treat as
                        // binary by copying UTF-8 bytes.
                        me.read_buf = bytes::Bytes::copy_from_slice(t.as_bytes());
                    }
                    // RFC 6455 §5.5.2: a Ping MUST be answered with a Pong
                    // carrying the same application data. Queue it; the top of
                    // the loop flushes it. A silent endpoint is an instant
                    // active-probe tell (DPI-R4).
                    Message::Ping(payload) => {
                        me.pending_pong = Some(payload);
                        // Loop to send the Pong before reading on.
                    }
                    // Pong (unsolicited / heartbeat reply) and Close/Frame:
                    // nothing owed, skip and poll again.
                    Message::Pong(_) | Message::Close(_) | Message::Frame(_) => {
                        continue;
                    }
                },
            }
        }
    }
}

impl<S> AsyncWrite for WsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let me = self.get_mut();
        me.write_buf.extend_from_slice(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;

        let me = self.get_mut();
        if !me.write_buf.is_empty() {
            let data = std::mem::take(&mut me.write_buf);
            // Check that the sink is ready to accept a message.
            match Sink::<Message>::poll_ready(std::pin::Pin::new(&mut me.inner), cx) {
                Poll::Pending => {
                    // Put data back; we cannot send yet.
                    me.write_buf = data;
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(std::io::Error::other(e)));
                }
                Poll::Ready(Ok(())) => {}
            }
            if let Err(e) = Sink::<Message>::start_send(
                std::pin::Pin::new(&mut me.inner),
                Message::Binary(data.into()),
            ) {
                return Poll::Ready(Err(std::io::Error::other(e)));
            }
        }
        Sink::<Message>::poll_flush(std::pin::Pin::new(&mut me.inner), cx)
            .map_err(std::io::Error::other)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Sink::<Message>::poll_close(std::pin::Pin::new(&mut self.get_mut().inner), cx)
            .map_err(std::io::Error::other)
    }
}

// Auth frame helpers

/// A plausible, host-stable real WebSocket subprotocol to offer alongside the
/// Mirage auth token (F20-M). All entries are real, widely-deployed
/// subprotocols (graphql-ws/Apollo, Rails `ActionCable`, MQTT-over-WS, WAMP),
/// so the offer blends with ordinary web traffic. Chosen deterministically
/// from the cover host - a given site consistently offers the same one, as a
/// real deployment would.
const COVER_SUBPROTOCOLS: [&str; 6] = [
    "graphql-ws",
    "graphql-transport-ws",
    "actioncable-v1-json",
    "mqtt",
    "wamp.2.json",
    "chat",
];

/// Pick a cover subprotocol for `host`, stable per host (FNV-1a -> index).
fn cover_subprotocol(host: &str) -> &'static str {
    COVER_SUBPROTOCOLS[(fnv1a(host.as_bytes()) % COVER_SUBPROTOCOLS.len() as u64) as usize]
}

/// FNV-1a over `data` (used for host-stable, deterministic cover selection).
fn fnv1a(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Realistic session-cookie NAMES the auth token is carried under (audit #13).
/// A long high-entropy base64url value is unremarkable as a *cookie* (session
/// IDs and JWTs look exactly like this) but was a zero-false-positive passive
/// tell as a `Sec-WebSocket-Protocol` entry. The bridge does NOT rely on the
/// name (it scans every cookie for one whose value decodes to a valid auth
/// frame), so the name is free to vary per host across these real-world names.
const WS_SESSION_COOKIE_NAMES: [&str; 6] = [
    "sessionid",
    "SID",
    "connect.sid",
    "JSESSIONID",
    "__Secure-1PSID",
    "session",
];

/// Pick the session-cookie name for `host`, stable per host.
fn ws_cookie_name(host: &str) -> &'static str {
    WS_SESSION_COOKIE_NAMES
        [(fnv1a(host.as_bytes()) % WS_SESSION_COOKIE_NAMES.len() as u64) as usize]
}

/// Build the 72-byte Mirage WS auth frame.
///
/// Layout: `nonce[32] || mac[32] || timestamp[8]`
///
/// The MAC is `BLAKE3_keyed(key=bridge_static_pk, data="mirage-ws-v1" ||
/// nonce || timestamp_be)`.
pub fn build_auth_frame(
    bridge_static_pk: &[u8; 32],
    obfs_secret: Option<&[u8; 32]>,
) -> Result<[u8; WS_AUTH_FRAME_LEN], String> {
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut nonce);

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system time: {e}"))?
        .as_secs()
        .to_be_bytes();

    let mac = ws_auth_mac(bridge_static_pk, obfs_secret, &nonce, &ts);

    let mut frame = [0u8; WS_AUTH_FRAME_LEN];
    frame[0..32].copy_from_slice(&nonce);
    frame[32..64].copy_from_slice(&mac);
    frame[64..72].copy_from_slice(&ts);
    Ok(frame)
}

/// Compute the BLAKE3-keyed MAC over the WS auth payload.
///
/// `mac = BLAKE3_keyed(key=bridge_static_pk,
///                     data="mirage-ws-v1" || nonce || timestamp_be)`
///
/// THREAT MODEL - this is a cheap pre-auth KNOCK, not authentication. When
/// `obfs_secret` is `None`, the key is the bridge's static *public* X25519 key,
/// which any authorized client learns from the (sealed) announcement - so a
/// pubkey scraper could forge a knock (the T2 hole). When `obfs_secret` is
/// `Some` (audit #9), the key is derived from the per-bridge invite secret, so
/// only a party holding an actual invite - not merely the scraped pubkey - can
/// mint a valid knock. Either way this is only a scanner filter; the REAL
/// client<->bridge authentication is the inner Mirage Noise handshake that runs
/// after the WS upgrade. The timestamp window (+ the mux replay set) bounds
/// capture-replay of a knock.
pub fn ws_auth_mac(
    bridge_static_pk: &[u8; 32],
    obfs_secret: Option<&[u8; 32]>,
    nonce: &[u8; 32],
    timestamp_be: &[u8; 8],
) -> [u8; 32] {
    // Secret-keyed when available (bind the pk in so a shared secret still
    // yields per-bridge MACs); pubkey-keyed otherwise (legacy).
    let key = match obfs_secret {
        Some(secret) => {
            let mut kh = b3::Hasher::new_keyed(secret);
            kh.update(WS_SECRET_KEY_LABEL);
            kh.update(bridge_static_pk);
            *kh.finalize().as_bytes()
        }
        None => *bridge_static_pk,
    };
    let mut hasher = b3::Hasher::new_keyed(&key);
    hasher.update(WS_MAC_LABEL);
    hasher.update(nonce);
    hasher.update(timestamp_be);
    *hasher.finalize().as_bytes()
}

/// Verify a WS auth frame (constant-time MAC check + timestamp window).
///
/// Returns `true` only when the MAC matches and the timestamp is within
/// +/-[`WS_TIMESTAMP_SKEW_SECS`] seconds of the current wall clock.
#[must_use = "dropping the auth result silently accepts an unauthenticated client"]
pub fn ws_auth_verify(
    bridge_static_pk: &[u8; 32],
    obfs_secret: Option<&[u8; 32]>,
    frame: &[u8; WS_AUTH_FRAME_LEN],
) -> bool {
    let nonce: &[u8; 32] = frame[0..32].try_into().expect("nonce slice");
    let presented_mac: &[u8; 32] = frame[32..64].try_into().expect("mac slice");
    let ts_bytes: &[u8; 8] = frame[64..72].try_into().expect("ts slice");

    // Constant-time MAC check.
    let expected = ws_auth_mac(bridge_static_pk, obfs_secret, nonce, ts_bytes);
    if expected.ct_eq(presented_mac).unwrap_u8() != 1 {
        return false;
    }

    // Timestamp window check.
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return false;
    };
    let peer_ts = u64::from_be_bytes(*ts_bytes);
    let now_secs = now.as_secs();
    let skew = if peer_ts > now_secs {
        peer_ts - now_secs
    } else {
        now_secs - peer_ts
    };
    skew <= WS_TIMESTAMP_SKEW_SECS
}

// WebSocket accept header computation

/// Compute the `Sec-WebSocket-Accept` response header value (RFC 6455).
///
/// `accept = base64(SHA1(client_key + WS_GUID))`
///
/// This is used by the server-side [`ws_server_auth`] when generating
/// the HTTP 101 response.
pub fn ws_accept_header(client_key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(client_key.as_bytes());
    hasher.update(WS_GUID.as_bytes());
    B64.encode(hasher.finalize())
}

// Client-side convenience function

/// Client-side: perform the WebSocket upgrade and Mirage auth frame exchange
/// on an already-connected stream, within `deadline`.
///
/// Steps performed:
/// 1. Hand-build and send an HTTP/1.1 `GET <path> Upgrade: websocket` request
///    with a Chrome-exact header order/casing (the Mirage auth frame rides in
///    `Sec-WebSocket-Protocol`; see [`ws_client_connect_inner`]).
/// 2. Read the `101 Switching Protocols` and verify `Sec-WebSocket-Accept`,
///    then adopt the raw upgraded socket as a client-role `WebSocketStream`.
/// 3. Return a [`WsStream`] ready for bidirectional Mirage session bytes.
///
/// # Errors
///
/// - [`TransportError::Timeout`] if `deadline` expires.
/// - [`TransportError::Other`] on WS handshake or auth frame send failure.
pub async fn ws_client_connect<S>(
    stream: S,
    bridge_pk: &[u8; 32],
    obfs_secret: Option<&[u8; 32]>,
    path: &str,
    host: &str,
    deadline: Duration,
) -> Result<impl AsyncRead + AsyncWrite + Unpin + Send, TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let bridge_pk = *bridge_pk;
    let obfs_secret = obfs_secret.copied();
    let path = path.to_owned();
    let host = host.to_owned();
    tokio::time::timeout(
        deadline,
        ws_client_connect_inner(stream, &bridge_pk, obfs_secret.as_ref(), &path, &host),
    )
    .await
    .map_err(|_| TransportError::Timeout(deadline))?
}

/// Browser header persona for the WS Upgrade (F4 fingerprint). A real browser
/// WebSocket handshake carries a `User-Agent`, `Origin`, `Accept-*`, client
/// hints, and a `permessage-deflate` offer; omitting them (as the pre-F4
/// Upgrade did) is a UA-less tell - the same one meek fixed. One persona is
/// drawn per connection and held for its lifetime.
struct WsPersona {
    user_agent: &'static str,
    sec_ch_ua: &'static str,
    platform: &'static str,
}

const WS_PERSONAS: &[WsPersona] = &[
    WsPersona {
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                     (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        sec_ch_ua: "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
        platform: "\"Windows\"",
    },
    WsPersona {
        user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                     (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        sec_ch_ua: "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
        platform: "\"macOS\"",
    },
    WsPersona {
        user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
                     (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        sec_ch_ua: "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
        platform: "\"Linux\"",
    },
];

fn ws_pick_persona() -> &'static WsPersona {
    // Pick ONCE per process and reuse it for every WS connection (red-team): a
    // real device runs ONE OS/browser, so rotating the User-Agent / platform /
    // client-hints per connection means one source IP presents different OSes
    // across reconnects - a passive correlation tell. A per-process persona
    // (chosen from the CSPRNG at first use) matches a single real client.
    use rand::Rng as _;
    static PERSONA_IDX: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let i = *PERSONA_IDX.get_or_init(|| rand::rng().random_range(0..WS_PERSONAS.len()));
    &WS_PERSONAS[i]
}

/// Inner (non-timeout) implementation of [`ws_client_connect`].
async fn ws_client_connect_inner<S>(
    mut stream: S,
    bridge_pk: &[u8; 32],
    obfs_secret: Option<&[u8; 32]>,
    path: &str,
    host: &str,
) -> Result<WsStream<S>, TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // RT #15: carry the Mirage auth frame in the upgrade request's
    // `Sec-WebSocket-Protocol` header (base64url-no-pad -> a valid subprotocol
    // token) so the bridge can validate BEFORE replying 101. We no longer send
    // a post-101 binary auth frame; a rejected client simply never receives a
    // 101 (the bridge forwards it to its decoy instead).
    let auth_frame = build_auth_frame(bridge_pk, obfs_secret)
        .map_err(|e| TransportError::Other(format!("ws auth frame: {e}")))?;
    let auth_token = B64URL.encode(auth_frame);

    // Host mirrors a real CDN-fronted WebSocket: a plausible cover domain, NOT
    // "localhost" (which no real wss:// traffic ever carries - a ~100% passive
    // Mirage tell). Falls back to a neutral placeholder if the caller passes
    // an empty host.
    let host = if host.is_empty() {
        "cdn.example.com"
    } else {
        host
    };

    // F20-M/F22 + audit #13: a lone 96-char high-entropy `Sec-WebSocket-Protocol`
    // entry is a zero-false-positive passive signature - a base64url token that
    // long is not a real subprotocol. Offer ONLY a plausible, host-stable real
    // subprotocol here, and carry the auth token in a `Cookie` instead (below),
    // where a 96-char opaque value is completely ordinary (session IDs / JWTs
    // look exactly like this). Nothing on the wire is now Mirage-unique.
    let cover_proto = cover_subprotocol(host);
    let sec_protocol = cover_proto.to_string();
    // Auth cookie: a realistic session-cookie name (host-stable) whose value is
    // the base64url auth frame. The bridge scans cookies for the one that
    // decodes + MAC-verifies, so the name need not be coordinated.
    let cookie_name = ws_cookie_name(host);
    let cookie_header = format!("{cookie_name}={auth_token}");

    // A valid `Sec-WebSocket-Key` is base64(16 random CSPRNG bytes) (RFC 6455
    // §4.1). The bridge reads it to derive the `Sec-WebSocket-Accept` reply,
    // which we verify below.
    let mut key_bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut key_bytes);
    let ws_key = B64.encode(key_bytes);

    // F4 (fingerprint): HAND-BUILD the Upgrade request so it lands on the wire
    // in Chrome's EXACT header order and casing. Do NOT let tokio-tungstenite
    // serialize it: its `generate_request` emits a fixed
    // Host/Connection/Upgrade/Sec-WebSocket-Version/Sec-WebSocket-Key prefix and
    // then iterates the remaining `http::HeaderMap` with LOWERCASED names (an
    // `http::HeaderName` canonicalizes to lowercase), so `user-agent:`,
    // `origin:`, `sec-websocket-extensions:` would go out lowercased and
    // `Sec-WebSocket-Key` would sit 5th instead of last - a one-rule
    // tungstenite fingerprint. Real Chrome sends Title-Case standard names with
    // the `Sec-WebSocket-*` keys last (the `sec-ch-ua*` client hints ARE
    // lowercase in real Chrome, so they stay lower). The sibling meek transport
    // hand-builds its Chrome POST the same way. `permessage-deflate` is
    // request-side realism only (the bridge never echoes it, so no compression
    // is negotiated).
    let persona = ws_pick_persona();
    let origin = format!("https://{host}");
    let ua = persona.user_agent;
    let sec_ch_ua = persona.sec_ch_ua;
    let platform = persona.platform;
    let request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Connection: Upgrade\r\n\
         Pragma: no-cache\r\n\
         Cache-Control: no-cache\r\n\
         User-Agent: {ua}\r\n\
         Upgrade: websocket\r\n\
         Origin: {origin}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Accept-Encoding: gzip, deflate, br, zstd\r\n\
         Accept-Language: en-US,en;q=0.9\r\n\
         sec-ch-ua: {sec_ch_ua}\r\n\
         sec-ch-ua-mobile: ?0\r\n\
         sec-ch-ua-platform: {platform}\r\n\
         Cookie: {cookie_header}\r\n\
         Sec-WebSocket-Key: {ws_key}\r\n\
         Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\
         Sec-WebSocket-Protocol: {sec_protocol}\r\n\r\n",
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(TransportError::Io)?;
    stream.flush().await.map_err(TransportError::Io)?;

    // Read the `101 Switching Protocols` response head (up to the blank line)
    // and verify `Sec-WebSocket-Accept == base64(SHA1(key || GUID))` (RFC 6455
    // §4.1), so a wrong or garbled accept fails the handshake exactly as a
    // conformant browser client would.
    let mut resp = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        stream
            .read_exact(&mut byte)
            .await
            .map_err(TransportError::Io)?;
        resp.push(byte[0]);
        if resp.ends_with(b"\r\n\r\n") {
            break;
        }
        if resp.len() > HTTP_REQUEST_MAX_BYTES {
            return Err(TransportError::Wire("ws 101 response too large"));
        }
    }
    let resp_str =
        std::str::from_utf8(&resp).map_err(|_| TransportError::Wire("non-utf8 ws 101 response"))?;
    let status_ok = resp_str
        .lines()
        .next()
        .is_some_and(|l| l.starts_with("HTTP/1.1 101"));
    if !status_ok {
        return Err(TransportError::Wire("ws upgrade not accepted (no 101)"));
    }
    let expected_accept = ws_accept_header(&ws_key);
    let accept_ok = resp_str.lines().any(|l| {
        l.to_ascii_lowercase().starts_with("sec-websocket-accept:")
            && l.split_once(':').map(|kv| kv.1.trim()) == Some(expected_accept.as_str())
    });
    if !accept_ok {
        return Err(TransportError::Wire("ws 101 Sec-WebSocket-Accept mismatch"));
    }

    // Adopt the raw, already-upgraded socket as a client-role WebSocket without
    // re-parsing the handshake - the same `from_raw_socket` pattern the server
    // side uses.
    let ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
        stream,
        tokio_tungstenite::tungstenite::protocol::Role::Client,
        None,
    )
    .await;

    Ok(WsStream::new(ws))
}

// Server-side 101 response persona (F20)

/// A plausible server/CDN identity for the `101 Switching Protocols` response
/// (F20). Real servers and CDNs always emit `Date` and `Server` on the 101;
/// a 101 carrying only Upgrade/Connection/Sec-WebSocket-Accept was a passive
/// tell. Mirrors meek's `ResponsePersona`. Chosen per handshake; the 101 is
/// sent once, so no cross-response consistency is required.
struct WsResponsePersona {
    /// `Server` header value.
    server: &'static str,
    /// CDN-specific extra header lines (each CRLF-terminated), generated at pick
    /// time so any per-connection identifier (e.g. a Cloudflare `CF-RAY`) is
    /// unique. Empty for a bare origin server.
    extra: String,
}

/// Cloudflare edge colo codes used to build a realistic `CF-RAY` value (mirrors
/// meek's `CF_COLOS`).
const WS_CF_COLOS: [&str; 8] = ["DFW", "LAX", "IAD", "AMS", "FRA", "LHR", "SIN", "NRT"];

impl WsResponsePersona {
    /// Choose a server persona at random for one handshake.
    fn pick() -> WsResponsePersona {
        use rand::Rng as _;
        let mut rng = rand::rng();
        match rng.random_range(0..3u8) {
            // Cloudflare edge terminating the WebSocket: `Server: cloudflare`
            // plus a `CF-RAY`. (No `Vary` on a 101 - it is not a cacheable
            // response, unlike meek's 200.)
            0 => {
                let ray: u64 = rng.random();
                let colo = WS_CF_COLOS[rng.random_range(0..WS_CF_COLOS.len())];
                WsResponsePersona {
                    server: "cloudflare",
                    extra: format!("CF-RAY: {ray:016x}-{colo}\r\n"),
                }
            }
            // Bare nginx / nginx-fronted origin.
            _ => WsResponsePersona {
                server: "nginx",
                extra: String::new(),
            },
        }
    }
}

/// Format `secs` (seconds since the Unix epoch) as an RFC 7231 IMF-fixdate
/// (`Sun, 06 Jul 2026 10:00:00 GMT`) for the `Date` header. A response with no
/// `Date` is a passive tell; real HTTP servers always send one. Mirrors meek's
/// `http_date` (Howard Hinnant's civil-from-days algorithm, no date crate).
fn http_date(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let sod = secs % 86_400;
    let (hh, mm, ss) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    let dow = (((days % 7) + 4) % 7) as usize; // 1970-01-01 was Thursday
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    const DOW: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MON: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        DOW[dow],
        d,
        MON[(month - 1) as usize],
        year,
        hh,
        mm,
        ss
    )
}

// Server-side auth helper

/// Perform the server-side WebSocket upgrade and Mirage auth on `stream`.
///
/// Steps:
/// 1. Read HTTP request line + headers (up to 4096 bytes; reject if larger).
/// 2. Check for `Upgrade: websocket` (case-insensitive).
/// 3. Extract `Sec-WebSocket-Key`.
/// 4. Send HTTP 101 with `Sec-WebSocket-Accept`.
/// 5. Read the first binary WebSocket frame (72 bytes - the Mirage auth frame).
/// 6. Validate MAC + timestamp (constant-time). Close without error details on failure.
/// 7. Return the `tokio_tungstenite::WebSocketStream` ready for Mirage session bytes.
///
/// The returned stream implements `AsyncRead + AsyncWrite`. The Mirage
/// session layer drives it as a duplex byte stream from this point forward.
pub async fn ws_server_auth<S>(
    stream: S,
    bridge_static_pk: &[u8; 32],
    obfs_secret: Option<&[u8; 32]>,
    deadline: Duration,
    seen_nonces: &mirage_transport::SeenNonceSet,
) -> Result<impl AsyncRead + AsyncWrite + Unpin + Send, WsReject<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // On timeout the stream may be mid-read (unknown state) - not replayable.
    tokio::time::timeout(
        deadline,
        ws_server_auth_inner(stream, bridge_static_pk, obfs_secret, seen_nonces),
    )
    .await
    .map_err(|_| (TransportError::Timeout(deadline), None))?
}

/// Reject context from [`ws_server_auth`]: `(error, Some((stream, consumed
/// HTTP-upgrade bytes)))` for a **pre-101** failure that the bridge can replay
/// byte-identically to a shadow backend, or `(error, None)` for a post-101 /
/// broken-stream failure that is not forwardable.
pub type WsReject<S> = (TransportError, Option<(S, Vec<u8>)>);

/// Inner (non-timeout) implementation of [`ws_server_auth`].
///
/// On failure the `Err` carries `Some((stream, header_bytes))` ONLY for
/// **pre-101** failures - where the raw TCP stream is intact and the consumed
/// HTTP upgrade-request bytes can be replayed byte-identically to a shadow
/// backend (the dominant active-probe shape: a plain `GET /` with no WS
/// upgrade). Once the bridge has committed its 101 Switching Protocols and
/// upgraded the socket, later failures return `None`: the socket is now a
/// `WebSocketStream` and a bridge-origin 101 was already sent, so it is NOT
/// byte-identically forwardable (deferring the 101 until after auth is a
/// separate, larger restructure).
async fn ws_server_auth_inner<S>(
    mut stream: S,
    bridge_static_pk: &[u8; 32],
    obfs_secret: Option<&[u8; 32]>,
    seen_nonces: &mirage_transport::SeenNonceSet,
) -> Result<WsStream<S>, WsReject<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Phase 1: Read HTTP upgrade request headers.
    let mut header_buf = Vec::with_capacity(512);
    let mut tmp = [0u8; 1];
    loop {
        if let Err(e) = stream.read_exact(&mut tmp).await {
            // Mid-header Io error: connection is broken, nothing to forward.
            return Err((TransportError::Io(e), None));
        }
        header_buf.push(tmp[0]);
        if header_buf.len() > HTTP_REQUEST_MAX_BYTES {
            return Err((
                TransportError::Wire("http upgrade request too large"),
                Some((stream, header_buf)),
            ));
        }
        // Detect end of HTTP headers: "\r\n\r\n"
        if header_buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    // Parse the upgrade request. RT #15: the Mirage auth frame is carried
    // PRE-101 in `Sec-WebSocket-Protocol` (base64url-no-pad of the 72-byte
    // frame - token-safe, so it looks like an ordinary WS subprotocol offer),
    // and is validated BEFORE any 101 is sent. Previously the bridge committed
    // a `101 Switching Protocols` and only then read a post-101 binary auth
    // frame, so any prober that sent a valid WS upgrade received a bridge-
    // origin 101 the shadow path could not cover. Now EVERY pre-101 failure
    // (no upgrade, missing/garbled auth, bad MAC, replay) returns the consumed
    // request bytes so the bridge replays them byte-identically to the shadow
    // decoy, and a 101 is sent ONLY after the auth verifies.
    let parsed: Result<(String, Vec<u8>, Option<String>), TransportError> = (|| {
        let header_str = std::str::from_utf8(&header_buf)
            .map_err(|_| TransportError::Wire("non-utf8 in http headers"))?;
        let has_upgrade = header_str.lines().any(|l| {
            l.to_ascii_lowercase().starts_with("upgrade:")
                && l.to_ascii_lowercase().contains("websocket")
        });
        if !has_upgrade {
            return Err(TransportError::Wire("missing websocket upgrade header"));
        }
        let key = header_str
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("sec-websocket-key:"))
            .and_then(|l| l.split_once(':').map(|x| x.1))
            .map(|v| v.trim().to_string())
            .ok_or(TransportError::Wire("missing sec-websocket-key"))?;
        // The `Sec-WebSocket-Protocol` offer now carries ONLY a plausible cover
        // subprotocol (audit #13); the cover is its first entry, echoed in the
        // 101 so the response selects a real subprotocol. The header may be
        // absent (some real clients omit it), in which case there is no cover to
        // echo - not an error.
        let cover: Option<String> = header_str
            .lines()
            .find(|l| {
                l.to_ascii_lowercase()
                    .starts_with("sec-websocket-protocol:")
            })
            .and_then(|l| l.split_once(':').map(|x| x.1))
            .and_then(|v| v.split(',').next())
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty());
        // The Mirage auth frame is carried in a `Cookie` (audit #13): a 96-char
        // base64url cookie value is ordinary, whereas the same blob as a
        // subprotocol was a zero-false-positive passive tell. Scan every cookie
        // for the one whose value base64url-decodes to exactly WS_AUTH_FRAME_LEN
        // bytes (MAC-verified below); the cookie NAME is not relied upon, so it
        // can vary per host across realistic session-cookie names.
        let mut auth: Option<Vec<u8>> = None;
        if let Some(cookie_line) = header_str
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("cookie:"))
            .and_then(|l| l.split_once(':').map(|x| x.1))
        {
            for pair in cookie_line.split(';') {
                let val = match pair.split_once('=') {
                    Some((_name, v)) => v.trim(),
                    None => continue,
                };
                if let Ok(bytes) = B64URL.decode(val.as_bytes()) {
                    if bytes.len() == WS_AUTH_FRAME_LEN {
                        auth = Some(bytes);
                        break;
                    }
                }
            }
        }
        let auth = auth.ok_or(TransportError::Wire("no auth cookie offered"))?;
        Ok((key, auth, cover))
    })();
    let (client_key, auth, cover_proto) = match parsed {
        Ok(v) => v,
        // Pre-101 logical failure (plain GET probe, missing/garbled auth):
        // replayable to the shadow byte-for-byte.
        Err(e) => return Err((e, Some((stream, header_buf)))),
    };

    // Validate the Mirage auth frame - MAC + timestamp (RT #8 replay too) -
    // BEFORE committing a 101. Every failure is still pre-101 -> forwardable.
    let auth_frame: &[u8; WS_AUTH_FRAME_LEN] = match auth.as_slice().try_into() {
        Ok(f) => f,
        Err(_) => {
            return Err((
                TransportError::Wire("auth frame wrong length"),
                Some((stream, header_buf)),
            ))
        }
    };
    if !ws_auth_verify(bridge_static_pk, obfs_secret, auth_frame) {
        return Err((
            TransportError::Auth("ws auth verify failed"),
            Some((stream, header_buf)),
        ));
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&auth_frame[0..32]);
    if !seen_nonces.check_and_insert(nonce, std::time::Instant::now()) {
        return Err((
            TransportError::Auth("ws auth replay"),
            Some((stream, header_buf)),
        ));
    }

    // Auth verified - NOW send the 101. Echo the REAL cover subprotocol the
    // client offered (a normal server selects one of the offered subprotocols);
    // echoing the 96-char auth blob was itself a passive tell (F20-M). If the
    // client offered no cover proto (legacy), decline all - a valid 101 too.
    let accept = ws_accept_header(&client_key);
    // F20: synthesize `Date` + `Server` (and any CDN extra) so the 101 carries
    // the header block a real server/CDN always emits; a 101 with only
    // Upgrade/Connection/Sec-WebSocket-Accept was a passive tell.
    let persona = WsResponsePersona::pick();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let date = http_date(now);
    let server = persona.server;
    let extra = persona.extra.as_str();
    let response = match &cover_proto {
        Some(cp) => format!(
            "HTTP/1.1 101 Switching Protocols\r\nDate: {date}\r\nServer: {server}\r\n{extra}Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: {cp}\r\n\r\n"
        ),
        None => format!(
            "HTTP/1.1 101 Switching Protocols\r\nDate: {date}\r\nServer: {server}\r\n{extra}Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        ),
    };
    if let Err(e) = stream.write_all(response.as_bytes()).await {
        return Err((TransportError::Io(e), None));
    }
    if let Err(e) = stream.flush().await {
        return Err((TransportError::Io(e), None));
    }

    // Wrap in WebSocket server role. There is no post-101 auth frame anymore.
    let ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
        stream,
        tokio_tungstenite::tungstenite::protocol::Role::Server,
        None,
    )
    .await;
    Ok(WsStream::new(ws))
}

// Helper: endpoint -> SocketAddr

fn endpoint_to_socket_addr(ep: &Endpoint) -> Result<std::net::SocketAddr, TransportError> {
    match ep {
        Endpoint::Ipv4 { addr, port } => Ok(std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3])),
            *port,
        )),
        Endpoint::Ipv6 { addr, port } => Ok(std::net::SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(*addr)),
            *port,
        )),
        Endpoint::Domain { .. } => Err(TransportError::Other(
            "ws-tunnel: resolve domain before dialing".into(),
        )),
        Endpoint::OnionV3 { .. } => Err(TransportError::Other(
            "ws-tunnel: onion endpoints not supported; use a Tor SOCKS forwarder".into(),
        )),
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::io::duplex;

    // 1. mac_auth_frame_round_trips

    #[test]
    fn mac_auth_frame_round_trips() {
        let pk = [0xABu8; 32];
        let frame = build_auth_frame(&pk, None).expect("build auth frame");
        assert!(
            ws_auth_verify(&pk, None, &frame),
            "freshly-built auth frame should verify"
        );
    }

    #[test]
    fn secret_keyed_knock_closes_pubkey_forgery() {
        // Audit #9: a secret-keyed WS knock cannot be forged from the public key
        // alone. A pubkey-only frame (what a scraper could build) must NOT verify
        // against a bridge that requires the secret.
        let pk = [0xABu8; 32];
        let secret = [0x77u8; 32];
        let pubkey_frame = build_auth_frame(&pk, None).expect("frame");
        let secret_frame = build_auth_frame(&pk, Some(&secret)).expect("frame");

        // Bridge requiring the secret rejects the pubkey-only frame ...
        assert!(!ws_auth_verify(&pk, Some(&secret), &pubkey_frame));
        // ... accepts the genuine secret-keyed frame ...
        assert!(ws_auth_verify(&pk, Some(&secret), &secret_frame));
        // ... and a wrong secret does not verify.
        let other = [0x11u8; 32];
        assert!(!ws_auth_verify(&pk, Some(&other), &secret_frame));
        // A legacy (no-secret) bridge still accepts the pubkey frame (compat).
        assert!(ws_auth_verify(&pk, None, &pubkey_frame));
    }

    // 2. mac_rejects_wrong_key

    #[test]
    fn mac_rejects_wrong_key() {
        let signing_pk = [0x11u8; 32];
        let wrong_pk = [0x22u8; 32];
        let frame = build_auth_frame(&signing_pk, None).expect("build auth frame");
        assert!(
            !ws_auth_verify(&wrong_pk, None, &frame),
            "auth frame signed with a different pk must be rejected"
        );
    }

    // 3. mac_rejects_old_timestamp

    #[test]
    fn mac_rejects_old_timestamp() {
        let pk = [0x33u8; 32];
        let mut nonce = [0u8; 32];
        nonce[0] = 7;

        // Construct a timestamp 60 seconds in the past (outside +/-30 s window).
        let old_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(60)
            .to_be_bytes();

        let mac = ws_auth_mac(&pk, None, &nonce, &old_ts);

        let mut frame = [0u8; WS_AUTH_FRAME_LEN];
        frame[0..32].copy_from_slice(&nonce);
        frame[32..64].copy_from_slice(&mac);
        frame[64..72].copy_from_slice(&old_ts);

        assert!(
            !ws_auth_verify(&pk, None, &frame),
            "timestamp 60 s in the past must be rejected"
        );
    }

    // 4. ws_handshake_accept_computation

    #[test]
    fn ws_handshake_accept_computation() {
        // RFC 6455 §1.3 example: key = "dGhlIHNhbXBsZSBub25jZQ=="
        // Expected accept: "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = ws_accept_header(key);
        assert_eq!(
            accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
            "Sec-WebSocket-Accept computation must match RFC 6455 §1.3"
        );
    }

    // 5. full_ws_auth_round_trip

    #[tokio::test]
    async fn full_ws_auth_round_trip() {
        // We simulate the WebSocket upgrade + auth using tokio::io::duplex.
        // The client side does a minimal manual HTTP upgrade + auth frame,
        // and the server side calls ws_server_auth.

        let (client_io, server_io) = duplex(65536);
        let pk = [0xCDu8; 32];

        // Run server auth concurrently.
        let pk_server = pk;
        let server = tokio::spawn(async move {
            let seen = mirage_transport::SeenNonceSet::new(Duration::from_secs(60));
            ws_server_auth(server_io, &pk_server, None, Duration::from_secs(5), &seen).await
        });

        // Client: perform manual HTTP upgrade then send auth frame.
        let pk_client = pk;
        let client = tokio::spawn(async move { client_ws_auth(client_io, &pk_client).await });

        let (server_result, client_result) = tokio::join!(server, client);
        server_result
            .expect("server task")
            .expect("server auth succeeded");
        client_result
            .expect("client task")
            .expect("client auth succeeded");
    }

    /// Perform the client side of the WS upgrade + Mirage auth, used only
    /// in tests where we drive both sides over `tokio::io::duplex`.
    async fn client_ws_auth<S>(
        mut stream: S,
        bridge_static_pk: &[u8; 32],
    ) -> Result<(), TransportError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // Generate a random WS key.
        let raw_key = [0x42u8; 16]; // deterministic for tests
        let ws_key = B64.encode(raw_key);

        // RT #15 + audit #13: carry the Mirage auth frame in a Cookie, validated
        // by the server BEFORE the 101. No post-101 binary auth frame. The
        // Sec-WebSocket-Protocol offer is now ONLY a real cover subprotocol; the
        // auth token rides in a realistic session cookie.
        let auth_frame = build_auth_frame(bridge_static_pk, None).map_err(TransportError::Other)?;
        let auth_token = B64URL.encode(auth_frame);
        let cover = cover_subprotocol("test.local");
        let cookie_name = ws_cookie_name("test.local");
        let req = format!(
            "GET /ws HTTP/1.1\r\nHost: test.local\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nCookie: {cookie_name}={auth_token}\r\nSec-WebSocket-Key: {ws_key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: {cover}\r\n\r\n"
        );
        stream
            .write_all(req.as_bytes())
            .await
            .map_err(TransportError::Io)?;
        stream.flush().await.map_err(TransportError::Io)?;

        // Read the server's 101 response (only sent if auth verified).
        let mut resp_buf = Vec::with_capacity(256);
        let mut tmp = [0u8; 1];
        loop {
            stream
                .read_exact(&mut tmp)
                .await
                .map_err(TransportError::Io)?;
            resp_buf.push(tmp[0]);
            if resp_buf.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let resp = std::str::from_utf8(&resp_buf).unwrap();
        assert!(
            resp.starts_with("HTTP/1.1 101"),
            "expected 101, got: {resp}"
        );
        // The server must echo the REAL cover subprotocol, never the 96-char
        // auth blob (F20-M).
        assert!(
            resp.contains(&format!("Sec-WebSocket-Protocol: {cover}\r\n")),
            "server must select the cover subprotocol; got: {resp}"
        );
        assert!(
            !resp.contains(&auth_token),
            "server must NOT echo the auth token; got: {resp}"
        );
        Ok(())
    }

    /// The real client path (`ws_client_connect_inner`, hand-built request +
    /// raw-socket adoption) must complete the handshake against `ws_server_auth`
    /// when the server echoes the cover subprotocol (not the auth blob, F20-M),
    /// verify the `Sec-WebSocket-Accept`, and the upgraded stream must carry
    /// bytes. This is the client<->bridge interop guard for the F4/F22 change.
    #[tokio::test]
    async fn real_client_path_completes_handshake() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client_io, server_io) = duplex(65536);
        let pk = [0x9Au8; 32];

        let server = tokio::spawn(async move {
            let seen = mirage_transport::SeenNonceSet::new(Duration::from_secs(60));
            ws_server_auth(server_io, &pk, None, Duration::from_secs(5), &seen).await
        });
        let client = tokio::spawn(async move {
            ws_client_connect_inner(client_io, &pk, None, "/ws", "cdn.example.com").await
        });

        let (s, c) = tokio::join!(server, client);
        let mut server_stream = s
            .expect("server task")
            .map_err(|e| e.0)
            .expect("server auth");
        let mut client_stream = c.expect("client task").expect("client connect");

        // Data-plane sanity: client -> server through the upgraded WS stream.
        client_stream
            .write_all(b"ping")
            .await
            .expect("client write");
        client_stream.flush().await.expect("client flush");
        let mut buf = [0u8; 4];
        server_stream
            .read_exact(&mut buf)
            .await
            .expect("server read");
        assert_eq!(&buf, b"ping");
    }

    /// F4: the client's hand-built Upgrade request must land on the wire in
    /// Chrome's Title-Case header names and header order, with the
    /// `Sec-WebSocket-*` keys AFTER the persona headers - never lowercased or
    /// reordered the way tungstenite's serializer would. Also proves the auth
    /// token rides in a realistic session Cookie (audit #13, no `v1.bearer.`
    /// subprotocol tell), and that the client completes on a valid 101.
    #[tokio::test]
    async fn client_request_is_titlecase_and_chrome_ordered() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client_io, mut server_io) = duplex(65536);
        let pk = [0x5Au8; 32];

        let client = tokio::spawn(async move {
            ws_client_connect_inner(client_io, &pk, None, "/ws", "cdn.example.com").await
        });

        // Capture the client's hand-built request head.
        let mut req = Vec::new();
        let mut b = [0u8; 1];
        loop {
            server_io.read_exact(&mut b).await.expect("read req byte");
            req.push(b[0]);
            if req.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let req = String::from_utf8(req).expect("utf8 request");

        // Standard header names are Title-Case (tungstenite would lowercase).
        // The raw request bytes must carry the Title-Case form and NOT the
        // lowercased spelling tungstenite's serializer would emit.
        assert!(
            req.contains("\r\nUser-Agent: "),
            "User-Agent must be Title-Case:\n{req}"
        );
        assert!(
            !req.contains("\r\nuser-agent:"),
            "must not emit a lowercased user-agent:\n{req}"
        );
        assert!(req.contains("\r\nOrigin: "), "Origin must be Title-Case");
        assert!(
            req.contains("\r\nSec-WebSocket-Extensions: "),
            "Sec-WebSocket-Extensions must be Title-Case"
        );
        assert!(req.contains("\r\nSec-WebSocket-Version: 13\r\n"));
        // Client hints ARE lowercase in real Chrome - keep them lower.
        assert!(req.contains("\r\nsec-ch-ua: "), "sec-ch-ua stays lowercase");
        // `Sec-WebSocket-Key` must come AFTER the persona headers (Chrome order),
        // never in tungstenite's fixed 5th slot.
        let key_pos = req.find("\r\nSec-WebSocket-Key:").expect("has key");
        let ua_pos = req.find("\r\nUser-Agent:").expect("has UA");
        let origin_pos = req.find("\r\nOrigin:").expect("has origin");
        assert!(
            key_pos > ua_pos && key_pos > origin_pos,
            "Sec-WebSocket-Key must follow the persona headers:\n{req}"
        );
        // Audit #13: the Sec-WebSocket-Protocol offer is ONLY the real cover
        // subprotocol - no lone high-entropy auth blob. The auth rides in a
        // realistic session Cookie instead, where a long base64url value is
        // ordinary.
        let cover = cover_subprotocol("cdn.example.com");
        assert!(
            req.contains(&format!("Sec-WebSocket-Protocol: {cover}\r\n")),
            "Sec-WebSocket-Protocol must offer only the cover subprotocol:\n{req}"
        );
        assert!(
            !req.contains("v1.bearer."),
            "the Mirage-unique v1.bearer. tell must be gone:\n{req}"
        );
        let cookie_name = ws_cookie_name("cdn.example.com");
        assert!(
            req.contains(&format!("\r\nCookie: {cookie_name}=")),
            "auth token must ride in a realistic session cookie:\n{req}"
        );

        // Complete the handshake so the client returns Ok (proves accept check).
        let key = req
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("sec-websocket-key:"))
            .and_then(|l| l.split_once(':'))
            .map(|kv| kv.1.trim().to_string())
            .expect("key present");
        let accept = ws_accept_header(&key);
        let resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\nDate: Sun, 06 Jul 2026 10:00:00 GMT\r\nServer: nginx\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        server_io
            .write_all(resp.as_bytes())
            .await
            .expect("write 101");
        server_io.flush().await.expect("flush 101");

        client
            .await
            .expect("client task")
            .expect("client connect ok");
    }

    /// F4: the client MUST reject a 101 whose `Sec-WebSocket-Accept` does not
    /// match `base64(SHA1(key || GUID))`, exactly as a conformant browser does.
    #[tokio::test]
    async fn client_rejects_wrong_accept() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client_io, mut server_io) = duplex(65536);
        let pk = [0x7Bu8; 32];

        let client = tokio::spawn(async move {
            ws_client_connect_inner(client_io, &pk, None, "/ws", "cdn.example.com").await
        });

        // Drain the request head, then reply with a deliberately wrong accept.
        let mut req = Vec::new();
        let mut b = [0u8; 1];
        loop {
            server_io.read_exact(&mut b).await.expect("read req byte");
            req.push(b[0]);
            if req.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let resp = "HTTP/1.1 101 Switching Protocols\r\nDate: Sun, 06 Jul 2026 10:00:00 GMT\r\nServer: nginx\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n";
        server_io.write_all(resp.as_bytes()).await.expect("write");
        server_io.flush().await.expect("flush");

        let result = client.await.expect("client task");
        assert!(
            result.is_err(),
            "client must reject a 101 with a mismatched Sec-WebSocket-Accept"
        );
    }

    #[test]
    fn cover_subprotocol_is_stable_and_real() {
        // Deterministic per host.
        assert_eq!(
            cover_subprotocol("a.example"),
            cover_subprotocol("a.example")
        );
        // Always one of the known real subprotocols.
        assert!(COVER_SUBPROTOCOLS.contains(&cover_subprotocol("cdn.example.com")));
        // The auth token (96 base64url chars) is never mistaken for a cover
        // proto: it decodes to exactly WS_AUTH_FRAME_LEN bytes, the cover protos
        // do not.
        for cp in COVER_SUBPROTOCOLS {
            let decoded_len = B64URL.decode(cp.as_bytes()).map(|b| b.len()).unwrap_or(0);
            assert_ne!(
                decoded_len, WS_AUTH_FRAME_LEN,
                "cover {cp} collides with auth length"
            );
        }
    }
}
