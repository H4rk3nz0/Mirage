//! Meek (domain-fronted HTTP long-polling) transport for Mirage.
//!
//! # Overview
//!
//! Meek is a domain-fronting transport that uses HTTP/1.1 long-polling
//! to carry Mirage session bytes. The client makes repeated HTTP POST
//! requests to a CDN-fronted endpoint; each request carries a batch of
//! outbound bytes, and each response delivers whatever the bridge has
//! queued for that session.
//!
//! DEPLOYMENT REQUIREMENT (red-team #4): this client speaks CLEARTEXT HTTP over
//! the TCP socket - it does NOT originate TLS. It is "HTTPS to a CDN" ONLY when
//! the operator fronts the bridge with a real TLS terminator: a CDN edge
//! (Cloudflare/Fastly) reached via a fronting domain, OR a local nginx/Caddy on
//! :443 with an ACME cert, that terminates TLS and forwards cleartext to the
//! bridge's mux port. THEN, from a censor's view, the traffic is an HTTPS client
//! repeatedly `POSTing` to a well-known CDN, and blocking needs CDN-level
//! collateral. Used bare (client dialing the bridge directly, no terminator),
//! the POST - persona headers, the session cookie, and the payload - is on the
//! wire in plaintext and trivially fingerprinted. Never expose a bare meek port
//! on a censored network.
//!
//! # Wire format
//!
//! ```text
//!  Client                                    Bridge
//!  ------                                    ------
//!  First POST (includes 72-byte auth prefix)
//!  POST /mirage HTTP/1.1
//!  Host: <front_domain>
//!  Content-Type: application/octet-stream
//!  Content-Length: 72 + N
//!  Cookie: sid=<base64(session_id[32])>
//!  [72-byte auth frame][Mirage session bytes...]
//!  ------------------------------------------>
//!                                             verify auth frame
//!                                             (hold response until session data ready)
//!                                             HTTP/200 + queued response bytes
//!                                            <------------------------------
//!
//!  Subsequent POSTs (no auth prefix)
//!  POST /mirage HTTP/1.1
//!  [Mirage session bytes...]
//!  ------------------------------------------>
//!                                             HTTP/200 + queued response bytes
//!                                            <------------------------------
//! ```
//!
//! # Auth frame layout (first POST only)
//!
//! ```text
//!   nonce[32]       CSPRNG random
//!   mac[32]         BLAKE3_keyed(key=bridge_static_pk,
//!                     "mirage-meek-v1" || nonce || timestamp_be)
//!   timestamp[8]    BE u64 unix seconds
//! ```
//!
//! # Driver architecture
//!
//! Both client and server use a background driver task that owns the TCP
//! socket and handles the HTTP polling loop. The session layer (Noise
//! handshake + SOCKS5 framing) communicates with the driver via Tokio
//! channels:
//!
//! - **Inbound channel** (`driver -> stream`): HTTP POST bodies are pushed
//!   here by the driver for the session layer to read.
//! - **Outbound channel** (`stream -> driver`): session layer writes are
//!   buffered here; the driver drains them into HTTP response bodies.
//! - **Flush signal** (`stream -> driver`): session layer calls `flush()`
//!   to signal that a response should be sent immediately (e.g., after
//!   a Noise handshake message).
//!
//! The bridge driver holds each HTTP POST open until either a flush signal
//! arrives or a short wait (`MEEK_RESPONSE_WAIT_MS`) expires, then responds
//! with whatever the session layer has written. This gives zero-overhead
//! handshake latency (session produces data instantly) while falling back
//! to a polling rhythm for idle periods.
//!
//! The client driver fires a POST on each flush signal (coalescing all
//! buffered writes), and also sends keepalive empty POSTs periodically
//! (`MEEK_KEEPALIVE_MS`) so the client can receive unsolicited bridge data.
//!
//! # Threat model fit
//!
//! - **T1 (signature DPI):** [ok] - traffic looks like HTTPS POSTs to a CDN.
//! - **T2 (active prober):** [ok] - `bridge_static_pk` is required to
//!   forge a valid MAC; the timestamp check prevents replay.
//! - **T3 (ML on flow shape):** partial - the polling cadence has a
//!   distinctive request/response rhythm; compose with jitter for
//!   fuller coverage.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use blake3 as b3;
use mirage_crypto::subtle::ConstantTimeEq;
use mirage_discovery::wire::Endpoint;
use mirage_transport::{ClientTransport, DialInputs, DuplexStream, TransportError};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// Capability bit for the Meek domain-fronted HTTP transport.
///
/// Bit 10 - allocated as `MEEK`.
/// Operators set this bit in their announcement's `transport_caps`
/// to indicate the bridge accepts Meek connections.
pub const MEEK_CAPABILITY_BIT: u32 = 1 << 10;

/// Length of the Mirage Meek auth frame (first POST body prefix).
///
/// Layout: `nonce[32] || mac[32] || timestamp[8]` = 72 bytes.
pub const MEEK_AUTH_FRAME_LEN: usize = 72;

/// The BLAKE3 keyed-hash domain separator for the Meek auth MAC.
const MEEK_MAC_LABEL: &[u8] = b"mirage-meek-v1";

/// Maximum timestamp skew allowed during bridge-side auth validation.
const MEEK_TIMESTAMP_SKEW_SECS: u64 = 30;

/// Maximum body bytes per HTTP POST request (client -> bridge direction).
const MEEK_MAX_REQUEST_BODY: usize = 65536;

/// Maximum bytes buffered per session in the bridge-side receive queue.
const MEEK_MAX_SESSION_BUFFER: usize = 1024 * 1024; // 1 MiB

/// Maximum bytes read for HTTP request or response headers.
const HTTP_REQUEST_MAX_BYTES: usize = 4096;

/// How long the bridge holds a POST open waiting for session-layer output
/// before sending an empty HTTP 200 response. This is the *base* hold; the
/// actual window is jittered per response via [`jittered_response_wait`] so the
/// bridge's reply cadence is not a fixed server-side signature (F21).
const MEEK_RESPONSE_WAIT_MS: u64 = 400;

/// Base interval the client waits between keepalive (empty-body) POSTs when the
/// session layer has no data to send. This is the *floor* of an exponential
/// backoff (see [`MEEK_KEEPALIVE_MAX_MS`]) and is additionally jittered per
/// poll via [`jittered_poll_delay`], so an idle client's polling cadence is
/// neither a fixed 200 ms metronome nor uniform across clients (F21). Shorter =
/// lower latency for unsolicited bridge data; longer = less polling overhead.
const MEEK_KEEPALIVE_MS: u64 = 200;

/// Cap on the client idle-poll interval after exponential backoff. While the
/// link stays idle the interval doubles from [`MEEK_KEEPALIVE_MS`] up to this
/// ceiling; any data sent or received resets it back to the floor.
const MEEK_KEEPALIVE_MAX_MS: u64 = 4000;

/// Cookie name carrying the base64 session id on each meek/DoH POST.
///
/// Replaces the previous bespoke `X-Session:` request header - a custom
/// header no real web client sends, i.e. a one-rule, zero-collateral
/// cleartext selector visible to any HTTP-aware DPI or CDN-edge observer.
/// A generic session `Cookie` is what real web apps actually use; the value
/// is opaque base64, indistinguishable from a normal session token. (A
/// rotating, capture-derived header persona - User-Agent/Accept/order - is
/// the deeper follow-up; this is the safe pure-subtraction half.)
const MEEK_SESSION_COOKIE: &str = "sid";

// Configuration

/// Client-side configuration for the Meek transport.
///
/// The `front_domain` is used as the HTTP `Host` header, enabling CDN
/// domain fronting: TLS SNI targets the CDN edge while `Host` routes
/// the request through to the bridge's meek reflector.
#[derive(Debug, Clone)]
pub struct MeekClientConfig {
    /// HTTP `Host` header value (the CDN front domain).
    ///
    /// Example: `"meek.cdn.example.com"`. Does not affect TCP dial -
    /// the dial target comes from `DialInputs::endpoint`.
    pub front_domain: String,

    /// HTTP request path. Defaults to `"/"` - an innocuous, extremely common
    /// endpoint (and the canonical meek path). NEVER default to a
    /// project-identifying string like `/mirage`, which a censor can path-match
    /// on. Operators can override per-deployment (ideally to a path that blends
    /// with the fronted origin's real API).
    pub path: String,

    /// Stable 32-byte random session identifier for this logical connection.
    ///
    /// Generated once per logical connection at start. Sent in every HTTP
    /// request as a `sid` cookie carrying `base64(session_id)` so the bridge can
    /// reassemble the session across independent poll round-trips.
    pub session_id: [u8; 32],

    /// `Content-Type` header sent on each POST request. Defaults to
    /// `"application/octet-stream"`. Set to `"application/dns-message"`
    /// for `DoH` tunnel transport.
    pub content_type: String,
}

impl MeekClientConfig {
    /// Construct a config with the given front domain, default path, and a
    /// random session ID.
    pub fn new(front_domain: impl Into<String>) -> Self {
        let mut session_id = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut session_id);
        Self {
            front_domain: front_domain.into(),
            path: "/".into(),
            session_id,
            content_type: "application/octet-stream".into(),
        }
    }
}

// Client-side transport

/// Client-side Meek domain-fronted HTTP transport.
///
/// Implements [`ClientTransport`]. Each call to
/// [`dial`](ClientTransport::dial) opens a TCP connection to the
/// bridge endpoint, performs the HTTP auth POST, and returns a
/// [`MeekClientStream`] that implements `AsyncRead + AsyncWrite` via
/// the long-polling mechanism.
pub struct MeekClientTransport {
    /// Transport configuration (front domain, path, session ID).
    config: MeekClientConfig,
}

impl MeekClientTransport {
    /// Construct a new client transport with the provided config.
    pub fn new(config: MeekClientConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl ClientTransport for MeekClientTransport {
    fn name(&self) -> &'static str {
        "meek"
    }

    fn capability_bit(&self) -> u32 {
        MEEK_CAPABILITY_BIT
    }

    async fn dial(&self, inputs: &DialInputs<'_>) -> Result<DuplexStream, TransportError> {
        let addr = endpoint_to_socket_addr(inputs.endpoint)?;

        let tcp = tokio::time::timeout(inputs.deadline, TcpStream::connect(addr))
            .await
            .map_err(|_| TransportError::Timeout(inputs.deadline))?
            .map_err(TransportError::Io)?;

        // Build the auth frame and first POST body.
        let auth_frame = build_auth_frame(inputs.bridge_static_pk)
            .map_err(|e| TransportError::Other(format!("auth frame: {e}")))?;

        let session_b64 = B64.encode(self.config.session_id);

        let stream = MeekClientStream::new_with_content_type(
            tcp,
            self.config.front_domain.clone(),
            self.config.path.clone(),
            self.config.session_id,
            Some(auth_frame.to_vec()),
            session_b64,
            self.config.content_type.clone(),
        )
        .await;

        Ok(Box::pin(stream))
    }
}

// MeekClientStream: AsyncRead + AsyncWrite backed by a polling driver task

/// Duplex byte-stream abstraction for the Meek transport (client side).
///
/// Backed by a background [`meek_client_driver`] task that owns the TCP
/// socket and handles the HTTP polling loop. The session layer interacts
/// with this struct via [`AsyncRead`] / [`AsyncWrite`] and the driver
/// handles all HTTP framing.
pub struct MeekClientStream {
    /// Bytes received from bridge HTTP response bodies.
    inbound_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    /// Leftover bytes from the last partially-consumed inbound chunk.
    inbound_buf: VecDeque<u8>,
    /// Bytes to include in the next HTTP POST body.
    outbound_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// Signal to the driver: "I just flushed, send a POST now."
    flush_tx: mpsc::UnboundedSender<()>,
}

impl MeekClientStream {
    /// Construct a new `MeekClientStream`.
    ///
    /// `first_post_prefix` is the auth frame bytes prepended to the first POST body.
    pub async fn new<S>(
        inner: S,
        front_domain: String,
        path: String,
        session_id: [u8; 32],
        first_post_prefix: Option<Vec<u8>>,
        session_b64: String,
    ) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::new_with_content_type(
            inner,
            front_domain,
            path,
            session_id,
            first_post_prefix,
            session_b64,
            "application/octet-stream".into(),
        )
        .await
    }

    /// Construct with a custom `Content-Type` header (e.g. `"application/dns-message"` for `DoH`).
    // Kept `async` for API consistency with `new` and because `.await` call sites in
    // other crates (incl. `mirage-client`) depend on the async signature.
    #[allow(clippy::unused_async)]
    pub async fn new_with_content_type<S>(
        inner: S,
        front_domain: String,
        path: String,
        _session_id: [u8; 32],
        first_post_prefix: Option<Vec<u8>>,
        session_b64: String,
        content_type: String,
    ) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (flush_tx, flush_rx) = mpsc::unbounded_channel::<()>();

        tokio::spawn(meek_client_driver(
            inner,
            first_post_prefix,
            front_domain,
            path,
            session_b64,
            content_type,
            outbound_rx,
            flush_rx,
            inbound_tx,
        ));

        Self {
            inbound_rx,
            inbound_buf: VecDeque::new(),
            outbound_tx,
            flush_tx,
        }
    }
}

impl AsyncRead for MeekClientStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;

        let me = self.get_mut();

        // Drain buffered bytes from previous partial read.
        if !me.inbound_buf.is_empty() {
            let n = me.inbound_buf.len().min(buf.remaining());
            let taken: Vec<u8> = me.inbound_buf.drain(..n).collect();
            buf.put_slice(&taken);
            return Poll::Ready(Ok(()));
        }

        // Wait for the driver to deliver the next inbound chunk.
        match me.inbound_rx.poll_recv(cx) {
            Poll::Ready(Some(chunk)) => {
                let n = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..n]);
                me.inbound_buf.extend(chunk[n..].iter().copied());
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // driver shut down -> EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for MeekClientStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let me = self.get_mut();
        let _ = me.outbound_tx.send(buf.to_vec());
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Signal driver to dispatch the next POST immediately rather than
        // waiting for the keepalive timer.
        let me = self.get_mut();
        let _ = me.flush_tx.send(());
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

// MeekServerStream: AsyncRead + AsyncWrite backed by a bridge driver task

/// Duplex byte-stream abstraction for the Meek transport (bridge side).
///
/// Returned by [`meek_bridge_serve`]. Backed by a background
/// [`meek_bridge_driver`] task that drives the HTTP polling loop on the
/// accepted TCP connection. The session layer (Noise handshake + SOCKS5)
/// reads from and writes to this struct as if it were a plain TCP stream.
pub struct MeekServerStream {
    /// Bytes received from client HTTP POST bodies.
    inbound_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    /// Leftover bytes from the last partially-consumed inbound chunk.
    inbound_buf: VecDeque<u8>,
    /// Bytes written by the session layer, queued for the next HTTP response.
    outbound_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// Signal to the driver: "session layer flushed, send HTTP response now."
    flush_tx: mpsc::UnboundedSender<()>,
    /// Shared in-flight inbound byte counter (RT #22). Decremented as chunks
    /// are drained from `inbound_rx`, mirroring the producer's increments, so
    /// the session's inbound buffer is bounded by `MEEK_MAX_SESSION_BUFFER`.
    inbound_buffered: Arc<AtomicUsize>,
}

impl MeekServerStream {
    fn new(
        inbound_rx: mpsc::UnboundedReceiver<Vec<u8>>,
        outbound_tx: mpsc::UnboundedSender<Vec<u8>>,
        flush_tx: mpsc::UnboundedSender<()>,
        inbound_buffered: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            inbound_rx,
            inbound_buf: VecDeque::new(),
            outbound_tx,
            flush_tx,
            inbound_buffered,
        }
    }
}

impl AsyncRead for MeekServerStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;

        let me = self.get_mut();

        if !me.inbound_buf.is_empty() {
            let n = me.inbound_buf.len().min(buf.remaining());
            let taken: Vec<u8> = me.inbound_buf.drain(..n).collect();
            buf.put_slice(&taken);
            return Poll::Ready(Ok(()));
        }

        match me.inbound_rx.poll_recv(cx) {
            Poll::Ready(Some(chunk)) => {
                // RT #22: this chunk has left the inbound channel - release its
                // bytes from the in-flight counter (saturating, so the
                // single-conn path's unenforced counter never underflows).
                let chunk_len = chunk.len();
                let _ =
                    me.inbound_buffered
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |x| {
                            Some(x.saturating_sub(chunk_len))
                        });
                let n = chunk_len.min(buf.remaining());
                buf.put_slice(&chunk[..n]);
                me.inbound_buf.extend(chunk[n..].iter().copied());
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // driver closed -> EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for MeekServerStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let me = self.get_mut();
        let _ = me.outbound_tx.send(buf.to_vec());
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = self.get_mut();
        let _ = me.flush_tx.send(());
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

// Bridge serve

/// Accept a Mirage Meek session on `stream`.
///
/// Reads the first HTTP POST, validates the 72-byte auth frame, spawns a
/// background HTTP polling driver, and returns a [`MeekServerStream`] that
/// the Mirage session layer can use as a plain `AsyncRead + AsyncWrite` pipe.
///
/// The `response_content_type` is used for all HTTP responses generated by
/// the driver (use `"application/octet-stream"` for plain Meek, or
/// `"application/dns-message"` for DoH-variant sessions).
///
/// Returns [`TransportError::Timeout`] if the first POST is not received
/// within `deadline`.
pub async fn meek_bridge_serve<S>(
    stream: S,
    bridge_static_pk: &[u8; 32],
    deadline: Duration,
    response_content_type: &'static str,
) -> Result<MeekServerStream, TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::time::timeout(
        deadline,
        meek_bridge_serve_inner(stream, bridge_static_pk, response_content_type),
    )
    .await
    .map_err(|_| TransportError::Timeout(deadline))?
}

async fn meek_bridge_serve_inner<S>(
    mut stream: S,
    bridge_static_pk: &[u8; 32],
    response_content_type: &'static str,
) -> Result<MeekServerStream, TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // --- Read and authenticate the first POST ---

    let (request_info, _) = read_http_request_headers(&mut stream).await?;

    if request_info.method != "POST" {
        return Err(TransportError::Wire("meek: expected POST request"));
    }

    let content_length = request_info
        .content_length
        .ok_or(TransportError::Wire("meek: missing Content-Length"))?;
    if content_length > MEEK_MAX_REQUEST_BODY {
        return Err(TransportError::Wire("meek: Content-Length exceeds limit"));
    }
    if content_length < MEEK_AUTH_FRAME_LEN {
        return Err(TransportError::Wire(
            "meek: body too short to contain auth frame",
        ));
    }

    // RT R3-#3: the session cookie is OPTIONAL here. This single-connection
    // path binds the session to this TCP connection and never uses a store
    // key, so a cookieless DoH POST (a real resolver sends no cookie) is fine;
    // the auth frame below is the real gate. Meek clients still send a cookie,
    // which is simply ignored on this path.
    let _session_id = request_info.session_id;

    let mut body = vec![0u8; content_length];
    stream
        .read_exact(&mut body)
        .await
        .map_err(TransportError::Io)?;

    let auth_frame: &[u8; MEEK_AUTH_FRAME_LEN] = body[..MEEK_AUTH_FRAME_LEN]
        .try_into()
        .map_err(|_| TransportError::Wire("meek: auth frame slice error"))?;

    if !meek_auth_verify(bridge_static_pk, auth_frame) {
        return Err(TransportError::Auth("meek auth verify failed"));
    }

    let first_body = body[MEEK_AUTH_FRAME_LEN..].to_vec();

    // --- Create channels and spawn the polling driver ---

    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (outbound_tx, outbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (flush_tx, flush_rx) = mpsc::unbounded_channel::<()>();

    tokio::spawn(meek_bridge_driver(
        stream,
        first_body,
        response_content_type,
        inbound_tx,
        outbound_rx,
        flush_rx,
    ));

    // Single-connection path: one POST body at a time, no cross-connection
    // accumulation, so a fresh (unenforced) counter suffices here; the
    // multconn driver is the one that needed the in-flight cap (RT #22).
    Ok(MeekServerStream::new(
        inbound_rx,
        outbound_tx,
        flush_tx,
        Arc::new(AtomicUsize::new(0)),
    ))
}

// Multi-connection session store

/// How long an idle session entry lives in the store before GC evicts it.
const MEEK_SESSION_TTL_SECS: u64 = 300;

/// GC sweep interval.
const MEEK_SESSION_GC_INTERVAL_SECS: u64 = 60;

/// Outbound channels (session layer -> HTTP response direction), wrapped in a
/// `tokio::sync::Mutex` so multiple concurrent TCP connections can take turns
/// draining session-layer output without racing.
struct SessionChannels {
    outbound_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    flush_rx: mpsc::UnboundedReceiver<()>,
}

/// Per-session channel state stored in [`MeekSessionStore`].
struct SessionEntry {
    inbound_tx: mpsc::UnboundedSender<Vec<u8>>,
    channels: Arc<tokio::sync::Mutex<SessionChannels>>,
    last_seen: std::sync::Mutex<Instant>,
    /// In-flight inbound bytes pushed to `inbound_tx` but not yet drained by
    /// the session-layer reader (RT #22). The producer refuses to enqueue more
    /// once this would exceed [`MEEK_MAX_SESSION_BUFFER`] - a client that
    /// uploads POST bodies faster than the session drains them can no longer
    /// grow an UNBOUNDED inbound channel and exhaust bridge memory. Shared
    /// (same `Arc`) with the consuming [`MeekServerStream`], which decrements
    /// it as it drains.
    inbound_buffered: Arc<AtomicUsize>,
}

/// Bridge-side Meek session store.
///
/// Maps 32-byte session IDs (decoded from the `sid` session cookie) to the
/// channel handles of their in-flight Mirage sessions. This allows CDN-
/// fronted deployments where the CDN forwards each HTTP POST on a
/// separate backend TCP connection: the first connection creates the
/// session; subsequent connections are matched by session ID and stitched
/// into the same session channel without creating a new session task.
///
/// # Usage
///
/// ```text
/// let store = Arc::new(MeekSessionStore::new());
/// // ...in the accept loop:
/// match meek_bridge_serve_multconn(tcp, &store, &pk, deadline, content_type).await {
///     Ok(MeekServeOutcome::NewSession(s)) => { tokio::spawn(session_task(s)); }
///     Ok(MeekServeOutcome::Existing)      => {}   // already being served
///     Err(e)                              => { /* auth or wire error */ }
/// }
/// ```
///
/// Internally spawns a GC task that evicts sessions idle for more than 5 minutes.
/// Must be created within a running Tokio runtime.
pub struct MeekSessionStore {
    sessions: Arc<tokio::sync::Mutex<HashMap<[u8; 32], Arc<SessionEntry>>>>,
}

impl Default for MeekSessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MeekSessionStore {
    /// Create a new session store and start its background GC task.
    pub fn new() -> Self {
        let sessions = Arc::new(tokio::sync::Mutex::new(HashMap::<
            [u8; 32],
            Arc<SessionEntry>,
        >::new()));
        let gc_sessions = Arc::clone(&sessions);
        tokio::spawn(async move {
            let ttl = Duration::from_secs(MEEK_SESSION_TTL_SECS);
            let interval = Duration::from_secs(MEEK_SESSION_GC_INTERVAL_SECS);
            loop {
                tokio::time::sleep(interval).await;
                let now = Instant::now();
                let mut map = gc_sessions.lock().await;
                map.retain(|_, entry| {
                    let last = *entry
                        .last_seen
                        .lock()
                        .expect("meek last_seen mutex poisoned");
                    now.duration_since(last) < ttl
                });
            }
        });
        Self { sessions }
    }
}

/// Result of [`meek_bridge_serve_multconn`].
pub enum MeekServeOutcome {
    /// Brand-new logical session. The bridge must spawn a Mirage session
    /// task on the enclosed [`MeekServerStream`].
    NewSession(MeekServerStream),
    /// Continuation of an existing session. The TCP connection has been
    /// routed to the existing session; no new session task is needed.
    Existing,
}

/// Accept a Meek HTTP connection, routing it through `store`.
///
/// On the first POST for a session ID (not yet in `store`):
/// - Validates the 72-byte auth frame.
/// - Creates channel handles, inserts them into `store`.
/// - Spawns a per-connection HTTP-serving task.
/// - Returns `MeekServeOutcome::NewSession(stream)` - the caller spawns
///   a Mirage session task on that stream.
///
/// On a subsequent POST for a known session ID:
/// - Attaches this TCP connection to the existing session's channels.
/// - Spawns a per-connection HTTP-serving task.
/// - Returns `MeekServeOutcome::Existing`.
///
/// Returns [`TransportError::Timeout`] if the first POST is not received
/// within `deadline`.
pub async fn meek_bridge_serve_multconn<S>(
    stream: S,
    store: &MeekSessionStore,
    bridge_static_pk: &[u8; 32],
    deadline: Duration,
    response_content_type: &'static str,
    seen_nonces: &mirage_transport::SeenNonceSet,
) -> Result<MeekServeOutcome, MeekReject<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // On timeout the stream may be mid-read (unknown state) - not replayable.
    tokio::time::timeout(
        deadline,
        meek_bridge_serve_multconn_inner(
            stream,
            store,
            bridge_static_pk,
            response_content_type,
            seen_nonces,
        ),
    )
    .await
    .map_err(|_| (TransportError::Timeout(deadline), None))?
}

/// Reject context returned on a recoverable serve failure: the still-raw
/// `stream` plus the exact request bytes consumed so far (`replay`). The
/// bridge replays `replay` to a plaintext-HTTP shadow backend and splices
/// the rest, so an active prober that fails auth gets the decoy's genuine
/// response - byte-identical to probing the decoy directly. `None` means
/// the stream is in an unknown read state (partial/malformed) and cannot be
/// cleanly replayed, so the caller drops it.
pub type MeekReject<S> = (TransportError, Option<(S, Vec<u8>)>);

async fn meek_bridge_serve_multconn_inner<S>(
    mut stream: S,
    store: &MeekSessionStore,
    bridge_static_pk: &[u8; 32],
    response_content_type: &'static str,
    seen_nonces: &mirage_transport::SeenNonceSet,
) -> Result<MeekServeOutcome, MeekReject<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Capture the raw request-header bytes so a validation/auth failure can
    // replay the prober's EXACT request to a shadow backend. No bytes are
    // written to `stream` before the success path, so `stream` + the consumed
    // bytes reconstruct precisely what the prober sent. For failures that
    // occur before the body is read, copy_bidirectional drains any pipelined
    // body at the bridge, so replaying just the headers is still complete.
    let (request_info, header_bytes) = match read_http_request_headers(&mut stream).await {
        Ok(v) => v,
        // Malformed/partial HTTP framing: unknown read state, not replayable.
        Err(e) => return Err((e, None)),
    };

    if request_info.method != "POST" {
        return Err((
            TransportError::Wire("meek: expected POST request"),
            Some((stream, header_bytes)),
        ));
    }

    // RT R3-#3: the session cookie is OPTIONAL. Meek (CDN-fetch) clients send
    // one and rely on it for multi-connection session re-attach. DoH clients
    // deliberately send NO cookie (a stateless resolver never would), so for
    // them `session_id` is `None` and the bridge assigns a fresh random store
    // key below - the session is bound to this authenticated TCP connection,
    // which is all the single-connection DoH client needs.
    let session_id = request_info.session_id;

    let Some(content_length) = request_info.content_length else {
        return Err((
            TransportError::Wire("meek: missing Content-Length"),
            Some((stream, header_bytes)),
        ));
    };
    if content_length > MEEK_MAX_REQUEST_BODY {
        return Err((
            TransportError::Wire("meek: Content-Length exceeds limit"),
            Some((stream, header_bytes)),
        ));
    }

    // Check whether this session already exists in the store. Only cookie-
    // bearing (meek) requests can re-attach; a cookieless DoH request always
    // starts a fresh session.
    let existing = match session_id {
        Some(sid) => {
            let map = store.sessions.lock().await;
            map.get(&sid).cloned()
        }
        None => None,
    };

    if let Some(entry) = existing {
        // Existing session: just consume the body and attach this TCP
        // connection to the existing channels.
        let mut body = vec![0u8; content_length];
        if let Err(e) = stream.read_exact(&mut body).await {
            // Partial body read: stream state is unknown, not replayable.
            return Err((TransportError::Io(e), None));
        }
        *entry
            .last_seen
            .lock()
            .expect("meek last_seen mutex poisoned") = Instant::now();
        tokio::spawn(serve_connection_against_session(
            stream,
            entry,
            body,
            response_content_type,
        ));
        return Ok(MeekServeOutcome::Existing);
    }

    // New session: the first POST MUST contain the auth frame.
    if content_length < MEEK_AUTH_FRAME_LEN {
        return Err((
            TransportError::Wire("meek: body too short to contain auth frame"),
            Some((stream, header_bytes)),
        ));
    }

    let mut body = vec![0u8; content_length];
    if let Err(e) = stream.read_exact(&mut body).await {
        return Err((TransportError::Io(e), None));
    }

    let auth_frame: &[u8; MEEK_AUTH_FRAME_LEN] =
        if let Ok(f) = body[..MEEK_AUTH_FRAME_LEN].try_into() {
            f
        } else {
            let mut replay = header_bytes;
            replay.extend_from_slice(&body);
            return Err((
                TransportError::Wire("meek: auth frame slice error"),
                Some((stream, replay)),
            ));
        };

    if !meek_auth_verify(bridge_static_pk, auth_frame) {
        // The whole request (headers ++ body, including the junk auth frame)
        // is replayed to the shadow so it sees a complete, well-formed POST.
        let mut replay = header_bytes;
        replay.extend_from_slice(&body);
        return Err((
            TransportError::Auth("meek auth verify failed"),
            Some((stream, replay)),
        ));
    }

    // RT #8: replay defense. The MAC + +/-skew window are not enough - a
    // captured auth frame replays within the window to confirm a bridge.
    // Reject a reused nonce (frame[0..32]) and forward the request to the
    // shadow decoy, exactly as a failed auth does, so a replay is
    // indistinguishable from any other rejected probe.
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&auth_frame[0..32]);
    if !seen_nonces.check_and_insert(nonce, std::time::Instant::now()) {
        let mut replay = header_bytes;
        replay.extend_from_slice(&body);
        return Err((
            TransportError::Auth("meek auth replay"),
            Some((stream, replay)),
        ));
    }

    let first_body = body[MEEK_AUTH_FRAME_LEN..].to_vec();

    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (outbound_tx, outbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (flush_tx, flush_rx) = mpsc::unbounded_channel::<()>();
    // RT #22: shared in-flight inbound byte counter (producer in the entry,
    // consumer in the MeekServerStream).
    let inbound_buffered = Arc::new(AtomicUsize::new(0));

    let entry = Arc::new(SessionEntry {
        inbound_tx,
        channels: Arc::new(tokio::sync::Mutex::new(SessionChannels {
            outbound_rx,
            flush_rx,
        })),
        last_seen: std::sync::Mutex::new(Instant::now()),
        inbound_buffered: Arc::clone(&inbound_buffered),
    });

    // Cookie-bearing meek: key the store by the client-chosen id so later
    // connections can re-attach. Cookieless DoH: assign a fresh random key
    // (the client never re-attaches, so it never needs to name this session).
    let session_key = session_id.unwrap_or_else(|| {
        let mut k = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut k);
        k
    });
    {
        let mut map = store.sessions.lock().await;
        map.insert(session_key, Arc::clone(&entry));
    }

    tokio::spawn(serve_connection_against_session(
        stream,
        entry,
        first_body,
        response_content_type,
    ));

    Ok(MeekServeOutcome::NewSession(MeekServerStream::new(
        inbound_rx,
        outbound_tx,
        flush_tx,
        inbound_buffered,
    )))
}

/// Serve one TCP connection's HTTP round-trips against `entry`'s session channels.
///
/// Pushes `first_body` to the session layer, sends the first HTTP response,
/// then loops reading any subsequent POSTs on the same TCP connection.
async fn serve_connection_against_session<S>(
    mut stream: S,
    entry: Arc<SessionEntry>,
    first_body: Vec<u8>,
    response_content_type: &'static str,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // One server persona for the whole connection (F6).
    let persona = ResponsePersona::pick();

    if !first_body.is_empty() {
        // RT #22: enforce the in-flight inbound cap. If the session layer is
        // not draining, refuse to buffer more (close the connection) rather
        // than grow the unbounded channel and exhaust bridge memory.
        let len = first_body.len();
        if entry
            .inbound_buffered
            .load(Ordering::Relaxed)
            .saturating_add(len)
            > MEEK_MAX_SESSION_BUFFER
        {
            return;
        }
        entry.inbound_buffered.fetch_add(len, Ordering::Relaxed);
        if entry.inbound_tx.send(first_body).is_err() {
            return;
        }
    }

    {
        let mut guard = entry.channels.lock().await;
        // Explicit deref through the MutexGuard so the borrow checker sees the
        // two field borrows as disjoint (it can't infer this through DerefMut).
        let chans: &mut SessionChannels = &mut guard;
        let resp = collect_outbound(
            &mut chans.outbound_rx,
            &mut chans.flush_rx,
            jittered_response_wait(),
        )
        .await;
        if send_http_response(&mut stream, &resp, response_content_type, &persona)
            .await
            .is_err()
        {
            return;
        }
    }

    loop {
        let Ok((next_info, _)) = read_http_request_headers(&mut stream).await else {
            return;
        };

        if next_info.method != "POST" {
            return;
        }

        let body_len = match next_info.content_length {
            Some(n) if n <= MEEK_MAX_REQUEST_BODY => n,
            _ => return,
        };

        let mut body = vec![0u8; body_len];
        if stream.read_exact(&mut body).await.is_err() {
            return;
        }

        *entry
            .last_seen
            .lock()
            .expect("meek last_seen mutex poisoned") = Instant::now();
        if !body.is_empty() {
            // RT #22: same in-flight cap on every subsequent POST body.
            let len = body.len();
            if entry
                .inbound_buffered
                .load(Ordering::Relaxed)
                .saturating_add(len)
                > MEEK_MAX_SESSION_BUFFER
            {
                return;
            }
            entry.inbound_buffered.fetch_add(len, Ordering::Relaxed);
            if entry.inbound_tx.send(body).is_err() {
                return;
            }
        }

        let mut guard = entry.channels.lock().await;
        let chans: &mut SessionChannels = &mut guard;
        let resp = collect_outbound(
            &mut chans.outbound_rx,
            &mut chans.flush_rx,
            jittered_response_wait(),
        )
        .await;
        drop(guard);

        if send_http_response(&mut stream, &resp, response_content_type, &persona)
            .await
            .is_err()
        {
            return;
        }
    }
}

// Bridge driver task

/// Background task that drives the HTTP polling loop for a bridge-side
/// Meek connection.
///
/// Lifecycle:
/// 1. Pushes `initial_body` (post-auth bytes from the first POST) to the
///    session layer.
/// 2. Waits for the session layer to flush or for `MEEK_RESPONSE_WAIT_MS`
///    to elapse, then sends an HTTP 200 response with queued outbound bytes.
/// 3. Reads subsequent HTTP POSTs from the TCP connection, pushing their
///    bodies to the session layer and responding with queued bytes.
/// 4. Exits when the TCP connection closes or either channel is closed.
async fn meek_bridge_driver<S>(
    mut stream: S,
    initial_body: Vec<u8>,
    response_content_type: &'static str,
    inbound_tx: mpsc::UnboundedSender<Vec<u8>>,
    mut outbound_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    mut flush_rx: mpsc::UnboundedReceiver<()>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // One server persona for the whole connection (F6).
    let persona = ResponsePersona::pick();

    // Push the initial bytes (after auth frame) to the session layer.
    if !initial_body.is_empty() && inbound_tx.send(initial_body).is_err() {
        return;
    }

    // Respond to the first POST: hold the HTTP connection open until the
    // session layer flushes (e.g., after writing the Noise handshake
    // response) or the wait timeout expires.
    let resp = collect_outbound(&mut outbound_rx, &mut flush_rx, jittered_response_wait()).await;
    if send_http_response(&mut stream, &resp, response_content_type, &persona)
        .await
        .is_err()
    {
        return;
    }

    // Main polling loop: one HTTP POST per round-trip.
    loop {
        // client closed connection or parse error
        let Ok((next_info, _)) = read_http_request_headers(&mut stream).await else {
            return;
        };

        if next_info.method != "POST" {
            return;
        }

        let body_len = match next_info.content_length {
            Some(n) if n <= MEEK_MAX_REQUEST_BODY => n,
            _ => return,
        };

        let mut body = vec![0u8; body_len];
        if stream.read_exact(&mut body).await.is_err() {
            return;
        }

        if !body.is_empty() && inbound_tx.send(body).is_err() {
            return;
        }

        let resp =
            collect_outbound(&mut outbound_rx, &mut flush_rx, jittered_response_wait()).await;
        if send_http_response(&mut stream, &resp, response_content_type, &persona)
            .await
            .is_err()
        {
            return;
        }
    }
}

/// Drain queued outbound bytes from the session layer.
///
/// Returns immediately (with all available data) on a flush signal or when
/// the first data chunk arrives. Falls back to `max_wait` if no signal or
/// data appears, in which case the returned `Vec` may be empty.
async fn collect_outbound(
    outbound_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    flush_rx: &mut mpsc::UnboundedReceiver<()>,
    max_wait: Duration,
) -> Vec<u8> {
    let mut result = Vec::new();

    tokio::select! {
        // Session layer explicitly flushed: drain all queued data.
        Some(()) = flush_rx.recv() => {
            while let Ok(chunk) = outbound_rx.try_recv() {
                result.extend(chunk);
            }
        }
        // First data chunk arrived without an explicit flush.
        Some(chunk) = outbound_rx.recv() => {
            result.extend(chunk);
            while let Ok(c) = outbound_rx.try_recv() {
                result.extend(c);
            }
        }
        // Timeout: return whatever has accumulated (may be empty).
        () = tokio::time::sleep(max_wait) => {
            while let Ok(chunk) = outbound_rx.try_recv() {
                result.extend(chunk);
            }
        }
    }

    result
}

/// Default (Chrome-on-Windows) browser-persona `User-Agent`. Retained as a
/// named symbol and used as the first entry of [`REQUEST_PERSONAS`]. A POST
/// with no UA is a ~100%-specificity passive tell (F16); a *frozen* UA + a
/// header block no real Chrome sends is a hardcoded-signature tell (F6) - see
/// [`RequestPersona`].
pub(crate) const PERSONA_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

/// A realistic, internally consistent browser request persona (F6).
///
/// The crate writes cleartext HTTP over the (CDN-TLS-wrapped) connection, so
/// the full request header block is on the wire. A real Chrome/Edge `fetch()`
/// POST always emits the client-hint (`sec-ch-ua*`), `Sec-Fetch-*`,
/// `Accept-Encoding` and `Accept-Language` headers - a bare `User-Agent`
/// alone is itself anomalous. Every entry here is a genuine Chromium-family
/// instance, so they share one header ordering and set (only the UA /
/// client-hint / platform / mobile fields differ). One persona is selected
/// per connection (see [`RequestPersona::pick`]) and held for the connection's
/// lifetime, giving per-connection variation without flipping identity between
/// polls on the same TCP flow.
struct RequestPersona {
    /// `User-Agent` value.
    user_agent: &'static str,
    /// `sec-ch-ua` value (already quoted/comma-joined).
    sec_ch_ua: &'static str,
    /// `sec-ch-ua-platform` value (already quoted), e.g. `"Windows"`.
    platform: &'static str,
    /// `sec-ch-ua-mobile` value: `?0` (desktop) or `?1` (mobile).
    mobile: &'static str,
    /// `Accept-Language` value.
    accept_language: &'static str,
    /// `Accept-Encoding` value.
    accept_encoding: &'static str,
}

/// `sec-ch-ua` brand string shared by the plain-Chrome personas.
const CH_UA_CHROME: &str =
    "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"";

/// The rotation pool. All Chromium-family so a single render path in
/// [`do_http_post`] is byte-consistent for every entry.
const REQUEST_PERSONAS: &[RequestPersona] = &[
    // Chrome on Windows.
    RequestPersona {
        user_agent: PERSONA_USER_AGENT,
        sec_ch_ua: CH_UA_CHROME,
        platform: "\"Windows\"",
        mobile: "?0",
        accept_language: "en-US,en;q=0.9",
        accept_encoding: "gzip, deflate, br, zstd",
    },
    // Chrome on macOS.
    RequestPersona {
        user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        sec_ch_ua: CH_UA_CHROME,
        platform: "\"macOS\"",
        mobile: "?0",
        accept_language: "en-US,en;q=0.9",
        accept_encoding: "gzip, deflate, br, zstd",
    },
    // Microsoft Edge on Windows.
    RequestPersona {
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
        sec_ch_ua: "\"Microsoft Edge\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
        platform: "\"Windows\"",
        mobile: "?0",
        accept_language: "en-US,en;q=0.9",
        accept_encoding: "gzip, deflate, br, zstd",
    },
    // Chrome on Android (mobile).
    RequestPersona {
        user_agent: "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
        sec_ch_ua: CH_UA_CHROME,
        platform: "\"Android\"",
        mobile: "?1",
        accept_language: "en-US,en;q=0.9",
        accept_encoding: "gzip, deflate, br, zstd",
    },
];

impl RequestPersona {
    /// Choose a persona at random for one connection.
    fn pick() -> &'static RequestPersona {
        use rand::Rng as _;
        let i = rand::rng().random_range(0..REQUEST_PERSONAS.len());
        &REQUEST_PERSONAS[i]
    }
}

/// A consistent server/CDN response persona (F6). Domain-fronted traffic is
/// reflected back through a CDN edge, so a plain `Server: nginx` on every
/// response is a frozen tell. One persona is chosen per connection and held
/// for its lifetime (a live server does not change its `Server` header between
/// responses on one connection).
struct ResponsePersona {
    /// `Server` header value.
    server: &'static str,
    /// CDN/server-specific extra header lines (each CRLF-terminated), generated
    /// at pick time so any per-connection identifier (e.g. a Cloudflare
    /// `CF-RAY`) is unique. Empty for a bare origin server.
    extra: String,
}

/// Cloudflare edge colo codes used to build a realistic `CF-RAY` value.
const CF_COLOS: [&str; 8] = ["DFW", "LAX", "IAD", "AMS", "FRA", "LHR", "SIN", "NRT"];

impl ResponsePersona {
    /// Choose a server persona at random for one connection.
    fn pick() -> ResponsePersona {
        use rand::Rng as _;
        let mut rng = rand::rng();
        match rng.random_range(0..3u8) {
            0 => ResponsePersona {
                server: "nginx",
                extra: String::new(),
            },
            1 => {
                // Cloudflare edge: `CF-RAY: <16 hex>-<colo>` + a Vary line.
                let ray: u64 = rng.random();
                let colo = CF_COLOS[rng.random_range(0..CF_COLOS.len())];
                ResponsePersona {
                    server: "cloudflare",
                    extra: format!("CF-RAY: {ray:016x}-{colo}\r\nVary: Accept-Encoding\r\n"),
                }
            }
            _ => ResponsePersona {
                server: "Apache",
                extra: String::new(),
            },
        }
    }
}

/// Jittered client idle-poll delay (F21). Returns a duration uniformly sampled
/// in `[base_ms/2, base_ms*3/2]` so the keepalive cadence is not a fixed
/// metronome and differs across clients. `base_ms` grows via exponential
/// backoff while the link is idle.
fn jittered_poll_delay(base_ms: u64) -> Duration {
    use rand::Rng as _;
    let base = base_ms.max(1);
    let lo = base / 2;
    let hi = base.saturating_mul(3) / 2;
    Duration::from_millis(rand::rng().random_range(lo..=hi))
}

/// Jittered bridge response-hold window (F21). The bridge holds each POST open
/// for a randomized duration around [`MEEK_RESPONSE_WAIT_MS`] rather than a
/// fixed 400 ms, so the server-side response cadence is not a fixed signature.
fn jittered_response_wait() -> Duration {
    use rand::Rng as _;
    let base = MEEK_RESPONSE_WAIT_MS;
    let lo = base.saturating_mul(3) / 4; // 300 ms
    let hi = base.saturating_mul(3) / 2; // 600 ms
    Duration::from_millis(rand::rng().random_range(lo..=hi))
}

/// Format `secs` (seconds since the Unix epoch) as an RFC 7231 IMF-fixdate
/// (`Sun, 06 Jul 2026 10:00:00 GMT`) for the `Date` header. A response with no
/// `Date` is a passive tell; real HTTP servers always send one. Uses Howard
/// Hinnant's civil-from-days algorithm (no date-crate dependency).
pub(crate) fn http_date(secs: u64) -> String {
    const DOW: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MON: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
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

/// Write an HTTP/1.1 200 OK response to `stream` with `body` as the payload.
///
/// `persona` is the per-connection server persona (F6): its `Server` header and
/// any CDN-specific extra headers are held constant for the connection's whole
/// lifetime.
async fn send_http_response<S>(
    stream: &mut S,
    body: &[u8],
    content_type: &str,
    persona: &ResponsePersona,
) -> Result<(), TransportError>
where
    S: AsyncWrite + Unpin,
{
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Date + Server complete the response persona (F16): a real HTTP server
    // always sends both; their absence was a ~100%-specificity passive tell.
    // The persona's `extra` lines carry any CDN-specific headers (e.g. a
    // Cloudflare CF-RAY) so the server identity is internally consistent (F6).
    let date = http_date(now);
    let server = persona.server;
    let extra = persona.extra.as_str();
    let content_length = body.len();
    let header = format!(
        "HTTP/1.1 200 OK\r\nDate: {date}\r\nServer: {server}\r\n{extra}Content-Type: {content_type}\r\nContent-Length: {content_length}\r\nConnection: keep-alive\r\n\r\n",
    );
    stream
        .write_all(header.as_bytes())
        .await
        .map_err(TransportError::Io)?;
    if !body.is_empty() {
        stream.write_all(body).await.map_err(TransportError::Io)?;
    }
    stream.flush().await.map_err(TransportError::Io)?;
    Ok(())
}

// Client driver task

/// Background task that drives the HTTP polling loop for a client-side
/// Meek connection.
///
/// Lifecycle:
/// 1. Waits for the session layer to call `flush()` (which sends the first
///    POST, including `first_post_prefix` as a body prefix - the auth frame).
/// 2. After the first POST, enters a keepalive loop: sends a POST on each
///    subsequent flush signal or after `MEEK_KEEPALIVE_MS` to poll for
///    unsolicited bridge data.
/// 3. All HTTP responses are pushed to `inbound_tx` for the session layer.
/// 4. Exits when either the TCP connection closes or the session drops its
///    channel handles.
// Distinct I/O handles + config; bundling into a struct adds indirection
// without improving clarity for a single internal driver call site.
#[allow(clippy::too_many_arguments)]
async fn meek_client_driver<S>(
    mut tcp: S,
    first_post_prefix: Option<Vec<u8>>,
    front_domain: String,
    path: String,
    session_b64: String,
    content_type: String,
    mut outbound_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    mut flush_rx: mpsc::UnboundedReceiver<()>,
    inbound_tx: mpsc::UnboundedSender<Vec<u8>>,
) where
    // Generic so the carrier can be plain TCP OR a client-originated TLS stream
    // (mirage-client's carrier_tls, red-team #4). The driver only reads/writes.
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut pending_prefix = first_post_prefix;

    // One browser persona for the whole connection (F6): the request header
    // block (UA + client hints + Sec-Fetch-* + Accept-*) stays consistent
    // across every poll on this TCP flow rather than flipping identity.
    let persona = RequestPersona::pick();

    // Phase 1: send the first POST, which MUST include the auth frame.
    // The session layer always writes (Noise Init) + flush before reading,
    // so we wait for the flush signal rather than using a keepalive timer.
    {
        // Drain all pending outbound bytes once the flush signal arrives.
        let flush = flush_rx.recv().await;
        if flush.is_none() {
            return; // stream dropped before first flush
        }
        let mut body = Vec::new();
        while let Ok(chunk) = outbound_rx.try_recv() {
            body.extend(chunk);
        }

        let mut post_body = Vec::new();
        if let Some(prefix) = pending_prefix.take() {
            post_body.extend(prefix);
        }
        post_body.extend(body);

        if do_http_post(
            &mut tcp,
            &post_body,
            &front_domain,
            &path,
            &session_b64,
            &content_type,
            persona,
        )
        .await
        .is_err()
        {
            return;
        }

        match read_http_response(&mut tcp).await {
            Ok(resp) if !resp.is_empty() => {
                if inbound_tx.send(resp).is_err() {
                    return;
                }
            }
            Ok(_) => {} // empty response (bridge had nothing yet)
            Err(_) => return,
        }
    }

    // Phase 2: keepalive polling loop.
    //
    // F21: an idle client must NOT emit a fixed 200 ms metronome. The base
    // interval grows via exponential backoff while the link stays idle (capped
    // at `MEEK_KEEPALIVE_MAX_MS`) and each sleep is independently jittered, so
    // the cadence is neither fixed nor uniform across clients. Any activity -
    // an explicit flush, unsolicited outbound bytes, or a non-empty response -
    // resets the interval back to the floor for responsiveness.
    let mut idle_ms = MEEK_KEEPALIVE_MS;
    loop {
        let mut body = Vec::new();
        let mut had_flush = false;

        tokio::select! {
            result = flush_rx.recv() => {
                if result.is_none() { return; } // stream dropped
                had_flush = true;
                while let Ok(chunk) = outbound_rx.try_recv() {
                    body.extend(chunk);
                }
            }
            () = tokio::time::sleep(jittered_poll_delay(idle_ms)) => {
                // Drain anything that arrived without an explicit flush.
                while let Ok(chunk) = outbound_rx.try_recv() {
                    body.extend(chunk);
                }
                // Send keepalive even if body is empty to poll for bridge data.
            }
        }

        let sent_data = had_flush || !body.is_empty();

        if do_http_post(
            &mut tcp,
            &body,
            &front_domain,
            &path,
            &session_b64,
            &content_type,
            persona,
        )
        .await
        .is_err()
        {
            return;
        }

        let got_data = match read_http_response(&mut tcp).await {
            Ok(resp) if !resp.is_empty() => {
                if inbound_tx.send(resp).is_err() {
                    return;
                }
                true
            }
            Ok(_) => false,
            Err(_) => return,
        };

        // Adapt the idle cadence: reset on activity, otherwise back off.
        if sent_data || got_data {
            idle_ms = MEEK_KEEPALIVE_MS;
        } else {
            idle_ms = idle_ms.saturating_mul(2).min(MEEK_KEEPALIVE_MAX_MS);
        }
    }
}

/// Send an HTTP POST with `body` on `tcp` and return.
///
/// `persona` is the per-connection browser persona (F6): the emitted header
/// block reproduces the full set - and ordering - a real Chromium-family
/// `fetch()` POST sends, so it is internally consistent rather than a bare,
/// frozen `User-Agent` no real client emits.
async fn do_http_post<S>(
    tcp: &mut S,
    body: &[u8],
    front_domain: &str,
    path: &str,
    session_b64: &str,
    content_type: &str,
    persona: &RequestPersona,
) -> Result<(), TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // DoH (RFC 8484) vs generic CDN fetch are DIFFERENT client personas, and
    // mixing them is itself a distinguisher: a native DoH resolver echoes the DNS
    // wire media type in Accept and does NOT send the browser page-context headers
    // (client hints, Sec-Fetch-*, Origin, Referer) that a `fetch()`/XHR from a web
    // page carries. A meek CDN fetch does. Emit the persona that matches the mode.
    let is_doh = content_type == "application/dns-message";
    let accept = if is_doh {
        "application/dns-message"
    } else {
        "*/*"
    };
    let ua = persona.user_agent;
    let sec_ch_ua = persona.sec_ch_ua;
    let mobile = persona.mobile;
    let platform = persona.platform;
    let accept_encoding = persona.accept_encoding;
    let accept_language = persona.accept_language;
    let content_length = body.len();

    // Headers common to both personas.
    let mut request = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {front_domain}\r\n\
         Connection: keep-alive\r\n\
         Content-Length: {content_length}\r\n"
    );
    if is_doh {
        // Native DoH client: a plain resolver POST. No client hints, no
        // Sec-Fetch-*, no Origin/Referer - those are page-context headers a
        // background DNS resolver never emits (cf. Firefox TRR, curl --doh-url).
        //
        // RT R3-#3: and NO Cookie. Real DoH resolvers are stateless - they do
        // not carry a session cookie, so a `Cookie: sid=...` on a DoH POST is a
        // standalone distinguisher. The bridge derives session correlation for
        // DoH from the connection itself (the authenticated first-POST binds
        // the session to this TCP flow; subsequent POSTs ride the same flow),
        // so the cookie is redundant here. `session_b64` is therefore unused in
        // DoH mode.
        let _ = session_b64;
        request.push_str(&format!(
            "User-Agent: {ua}\r\n\
             Accept: {accept}\r\n\
             Content-Type: {content_type}\r\n\
             Accept-Encoding: {accept_encoding}\r\n\
             Cache-Control: no-store\r\n\r\n"
        ));
    } else {
        // Meek: a same-origin fetch()/XHR from a real page - full Chromium-family
        // header block (F6): client hints, Sec-Fetch-*, Origin/Referer.
        request.push_str(&format!(
            "sec-ch-ua: {sec_ch_ua}\r\n\
             sec-ch-ua-mobile: {mobile}\r\n\
             sec-ch-ua-platform: {platform}\r\n\
             User-Agent: {ua}\r\n\
             Content-Type: {content_type}\r\n\
             Accept: {accept}\r\n\
             Origin: https://{front_domain}\r\n\
             Sec-Fetch-Site: same-origin\r\n\
             Sec-Fetch-Mode: cors\r\n\
             Sec-Fetch-Dest: empty\r\n\
             Referer: https://{front_domain}/\r\n\
             Accept-Encoding: {accept_encoding}\r\n\
             Accept-Language: {accept_language}\r\n\
             Cookie: {MEEK_SESSION_COOKIE}={session_b64}\r\n\r\n"
        ));
    }
    tcp.write_all(request.as_bytes())
        .await
        .map_err(TransportError::Io)?;
    if !body.is_empty() {
        tcp.write_all(body).await.map_err(TransportError::Io)?;
    }
    tcp.flush().await.map_err(TransportError::Io)?;
    Ok(())
}

// Server-side auth (kept for DoH backward compatibility)

/// Per-session state maintained by the bridge after successful Meek auth.
///
/// **Prefer [`meek_bridge_serve`] for new code.** This type is kept for
/// backward compatibility with the `DoH` transport's unit tests and existing
/// call sites that do not need the full HTTP long-poll loop (e.g. testing
/// auth-frame validation in isolation).
///
/// The bridge holds one `MeekServerSession` per `session_id`. On each
/// incoming POST, it hands the request body to
/// [`MeekServerSession::push_inbound`] and polls
/// [`MeekServerSession::drain_outbound`] to build the HTTP response body.
pub struct MeekServerSession {
    /// Inbound bytes from the client, buffered for the session layer to consume.
    inbound: VecDeque<u8>,
    /// Outbound bytes from the session layer, buffered for the next poll response.
    outbound: VecDeque<u8>,
    /// Current total bytes in `inbound` (used for bound checks).
    inbound_len: usize,
    /// Current total bytes in `outbound` (used for bound checks).
    outbound_len: usize,
}

impl MeekServerSession {
    /// Construct a new, empty session.
    pub fn new() -> Self {
        Self {
            inbound: VecDeque::new(),
            outbound: VecDeque::new(),
            inbound_len: 0,
            outbound_len: 0,
        }
    }

    /// Push bytes received from the client (POST body, after stripping any
    /// auth prefix) into the inbound buffer.
    ///
    /// Returns `Err` if the buffer would exceed [`MEEK_MAX_SESSION_BUFFER`].
    pub fn push_inbound(&mut self, data: &[u8]) -> Result<(), TransportError> {
        if self.inbound_len + data.len() > MEEK_MAX_SESSION_BUFFER {
            return Err(TransportError::Wire("meek inbound buffer overflow"));
        }
        for &b in data {
            self.inbound.push_back(b);
        }
        self.inbound_len += data.len();
        Ok(())
    }

    /// Drain all currently buffered outbound bytes (to be sent as the HTTP
    /// response body). Returns an empty `Vec` if nothing is queued.
    pub fn drain_outbound(&mut self) -> Vec<u8> {
        let out: Vec<u8> = self.outbound.drain(..).collect();
        self.outbound_len = 0;
        out
    }

    /// Push bytes produced by the session layer into the outbound buffer
    /// (to be delivered to the client on the next poll response).
    ///
    /// Returns `Err` if the buffer would exceed [`MEEK_MAX_SESSION_BUFFER`].
    pub fn push_outbound(&mut self, data: &[u8]) -> Result<(), TransportError> {
        if self.outbound_len + data.len() > MEEK_MAX_SESSION_BUFFER {
            return Err(TransportError::Wire("meek outbound buffer overflow"));
        }
        for &b in data {
            self.outbound.push_back(b);
        }
        self.outbound_len += data.len();
        Ok(())
    }
}

impl Default for MeekServerSession {
    fn default() -> Self {
        Self::new()
    }
}

impl AsyncRead for MeekServerSession {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        let me = self.get_mut();
        if !me.inbound.is_empty() {
            let n = me.inbound.len().min(buf.remaining());
            let taken: Vec<u8> = me.inbound.drain(..n).collect();
            me.inbound_len = me.inbound_len.saturating_sub(n);
            buf.put_slice(&taken);
            return Poll::Ready(Ok(()));
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl AsyncWrite for MeekServerSession {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let me = self.get_mut();
        if me.outbound_len + buf.len() > MEEK_MAX_SESSION_BUFFER {
            return std::task::Poll::Ready(Err(std::io::Error::other(
                "meek outbound buffer overflow",
            )));
        }
        for &b in buf {
            me.outbound.push_back(b);
        }
        me.outbound_len += buf.len();
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// Perform the server-side Meek auth on the first HTTP POST received from
/// `stream`.
///
/// **Prefer [`meek_bridge_serve`] for production use.** This function
/// validates auth and returns a static [`MeekServerSession`] buffer - it
/// does not drive the HTTP long-poll loop, so it only works for single-POST
/// exchanges (e.g., the `DoH` unit tests).
///
/// Reads the HTTP request line and headers, extracts the `sid` session cookie
/// (32-byte session ID), reads the POST body (max
/// [`MEEK_MAX_REQUEST_BODY`] bytes), validates the 72-byte auth frame
/// prefix, and returns a [`MeekServerSession`] populated with any body
/// bytes that follow the auth frame.
pub async fn meek_server_auth<S>(
    stream: S,
    bridge_static_pk: &[u8; 32],
    deadline: Duration,
) -> Result<MeekServerSession, TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::time::timeout(deadline, meek_server_auth_inner(stream, bridge_static_pk))
        .await
        .map_err(|_| TransportError::Timeout(deadline))?
}

/// Inner (non-timeout) implementation of [`meek_server_auth`].
async fn meek_server_auth_inner<S>(
    mut stream: S,
    bridge_static_pk: &[u8; 32],
) -> Result<MeekServerSession, TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Read HTTP request line + headers.
    let (request_info, _header_raw) = read_http_request_headers(&mut stream).await?;

    // Validate method.
    if request_info.method != "POST" {
        return Err(TransportError::Wire("meek: expected POST request"));
    }

    // Validate Content-Length is present and within bounds.
    let content_length = request_info
        .content_length
        .ok_or(TransportError::Wire("meek: missing Content-Length"))?;
    if content_length > MEEK_MAX_REQUEST_BODY {
        return Err(TransportError::Wire("meek: Content-Length exceeds limit"));
    }
    if content_length < MEEK_AUTH_FRAME_LEN {
        return Err(TransportError::Wire(
            "meek: body too short to contain auth frame",
        ));
    }

    // RT R3-#3: the session cookie is optional (a cookieless DoH POST is
    // valid). `session_id` is unused on this path; the auth frame below is
    // the gate.
    let _session_id = request_info.session_id;

    // Read the full body.
    let mut body = vec![0u8; content_length];
    stream
        .read_exact(&mut body)
        .await
        .map_err(TransportError::Io)?;

    // Extract and validate the auth frame prefix.
    let auth_frame: &[u8; MEEK_AUTH_FRAME_LEN] = body[..MEEK_AUTH_FRAME_LEN]
        .try_into()
        .map_err(|_| TransportError::Wire("meek: auth frame slice error"))?;

    if !meek_auth_verify(bridge_static_pk, auth_frame) {
        return Err(TransportError::Auth("meek auth verify failed"));
    }

    // Build the session, push any body bytes after the auth frame.
    let mut session = MeekServerSession::new();
    let post_auth = &body[MEEK_AUTH_FRAME_LEN..];
    if !post_auth.is_empty() {
        session.push_inbound(post_auth)?;
    }

    // Send HTTP 200 response.
    let response = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n";
    stream
        .write_all(response)
        .await
        .map_err(TransportError::Io)?;
    stream.flush().await.map_err(TransportError::Io)?;

    Ok(session)
}

// HTTP request parsing

/// Parsed fields from an incoming HTTP/1.1 request.
#[derive(Debug)]
pub struct HttpRequestInfo {
    /// HTTP method (e.g., `"POST"`).
    pub method: String,
    /// Request path (e.g., `"/"` or an API path that blends with the origin).
    pub path: String,
    /// `Host` header value.
    pub host: Option<String>,
    /// `Content-Length` header value (parsed as `usize`).
    pub content_length: Option<usize>,
    /// Decoded `sid` session-cookie value (32-byte session ID).
    pub session_id: Option<[u8; 32]>,
}

/// Read and parse an HTTP/1.1 request line + headers from `stream`.
///
/// Returns the parsed [`HttpRequestInfo`] and the raw header bytes (for
/// debugging). Rejects requests whose headers exceed 4096 bytes.
pub async fn read_http_request_headers<S>(
    stream: &mut S,
) -> Result<(HttpRequestInfo, Vec<u8>), TransportError>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(512);
    let mut tmp = [0u8; 1];

    loop {
        stream
            .read_exact(&mut tmp)
            .await
            .map_err(TransportError::Io)?;
        buf.push(tmp[0]);
        if buf.len() > HTTP_REQUEST_MAX_BYTES {
            return Err(TransportError::Wire("http request headers too large"));
        }
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    let text = std::str::from_utf8(&buf)
        .map_err(|_| TransportError::Wire("non-utf8 in http request headers"))?;

    let mut lines = text.lines();

    // Parse request line: "METHOD PATH HTTP/1.1"
    let request_line = lines
        .next()
        .ok_or(TransportError::Wire("empty http request"))?;
    let mut parts = request_line.splitn(3, ' ');
    let method = parts
        .next()
        .ok_or(TransportError::Wire("missing method"))?
        .to_string();
    let path = parts
        .next()
        .ok_or(TransportError::Wire("missing path"))?
        .to_string();

    // Parse relevant headers.
    let mut host = None;
    let mut content_length = None;
    let mut session_id = None;

    for line in lines {
        if line.is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("host:") {
            host = Some(line["host:".len()..].trim().to_string());
        } else if lower.starts_with("content-length:") {
            content_length = line["content-length:".len()..].trim().parse::<usize>().ok();
        } else if lower.starts_with("cookie:") {
            // Extract the session id from the `MEEK_SESSION_COOKIE` cookie.
            // Cookie values are case-sensitive base64, so parse from the
            // original-case `line`, not `lower`.
            for kv in line["cookie:".len()..].split(';') {
                let kv = kv.trim();
                if let Some(val) = kv
                    .strip_prefix(MEEK_SESSION_COOKIE)
                    .and_then(|r| r.strip_prefix('='))
                {
                    if let Ok(decoded) = B64.decode(val.trim()) {
                        if decoded.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&decoded);
                            session_id = Some(arr);
                        }
                    }
                }
            }
        }
    }

    Ok((
        HttpRequestInfo {
            method,
            path,
            host,
            content_length,
            session_id,
        },
        buf,
    ))
}

// HTTP response reading (client side)

/// Read an HTTP/1.1 response from `stream` and return the body bytes.
///
/// Parses the status line and headers, extracts `Content-Length`, reads
/// exactly that many body bytes. Returns an empty `Vec` if `Content-Length`
/// is 0 or absent.
async fn read_http_response<S>(stream: &mut S) -> Result<Vec<u8>, TransportError>
where
    S: AsyncRead + Unpin,
{
    let mut header_buf = Vec::with_capacity(256);
    let mut tmp = [0u8; 1];

    loop {
        stream
            .read_exact(&mut tmp)
            .await
            .map_err(TransportError::Io)?;
        header_buf.push(tmp[0]);
        if header_buf.len() > HTTP_REQUEST_MAX_BYTES {
            return Err(TransportError::Wire("http response headers too large"));
        }
        if header_buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    let text = std::str::from_utf8(&header_buf)
        .map_err(|_| TransportError::Wire("non-utf8 in http response headers"))?;

    let mut content_length = 0usize;
    for line in text.lines().skip(1) {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("content-length:") {
            content_length = line["content-length:".len()..]
                .trim()
                .parse::<usize>()
                .unwrap_or(0);
            break;
        }
    }

    if content_length == 0 {
        return Ok(Vec::new());
    }
    if content_length > MEEK_MAX_REQUEST_BODY {
        return Err(TransportError::Wire("http response body too large"));
    }

    let mut body = vec![0u8; content_length];
    stream
        .read_exact(&mut body)
        .await
        .map_err(TransportError::Io)?;
    Ok(body)
}

// Auth frame helpers

/// Build the 72-byte Mirage Meek auth frame.
///
/// Layout: `nonce[32] || mac[32] || timestamp[8]`
///
/// The MAC is `BLAKE3_keyed(key=bridge_static_pk, data="mirage-meek-v1" ||
/// nonce || timestamp_be)`.
pub fn build_auth_frame(bridge_static_pk: &[u8; 32]) -> Result<[u8; MEEK_AUTH_FRAME_LEN], String> {
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut nonce);

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system time: {e}"))?
        .as_secs()
        .to_be_bytes();

    let mac = meek_auth_mac(bridge_static_pk, &nonce, &ts);

    let mut frame = [0u8; MEEK_AUTH_FRAME_LEN];
    frame[0..32].copy_from_slice(&nonce);
    frame[32..64].copy_from_slice(&mac);
    frame[64..72].copy_from_slice(&ts);
    Ok(frame)
}

/// Compute the BLAKE3-keyed MAC over the Meek auth payload.
///
/// `mac = BLAKE3_keyed(key=bridge_static_pk,
///                     data="mirage-meek-v1" || nonce || timestamp_be)`
pub fn meek_auth_mac(
    bridge_static_pk: &[u8; 32],
    nonce: &[u8; 32],
    timestamp_be: &[u8; 8],
) -> [u8; 32] {
    let mut hasher = b3::Hasher::new_keyed(bridge_static_pk);
    hasher.update(MEEK_MAC_LABEL);
    hasher.update(nonce);
    hasher.update(timestamp_be);
    *hasher.finalize().as_bytes()
}

/// Verify a Meek auth frame (constant-time MAC check + timestamp window).
///
/// Returns `true` only when the MAC matches and the timestamp is within
/// +/-[`MEEK_TIMESTAMP_SKEW_SECS`] seconds of the current wall clock.
#[must_use = "dropping the auth result silently accepts an unauthenticated client"]
pub fn meek_auth_verify(bridge_static_pk: &[u8; 32], frame: &[u8; MEEK_AUTH_FRAME_LEN]) -> bool {
    let nonce: &[u8; 32] = frame[0..32].try_into().expect("nonce slice");
    let presented_mac: &[u8; 32] = frame[32..64].try_into().expect("mac slice");
    let ts_bytes: &[u8; 8] = frame[64..72].try_into().expect("ts slice");

    // Constant-time MAC verification.
    let expected = meek_auth_mac(bridge_static_pk, nonce, ts_bytes);
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
    skew <= MEEK_TIMESTAMP_SKEW_SECS
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
            "meek: resolve domain before dialing".into(),
        )),
        Endpoint::OnionV3 { .. } => Err(TransportError::Other(
            "meek: onion endpoints not supported; use a Tor SOCKS forwarder".into(),
        )),
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    // RT R3-#3: a DoH POST must NOT carry a session Cookie (a stateless
    // resolver never would); a meek CDN-fetch POST still must. Drive
    // `do_http_post` for both content-types and inspect the emitted headers.
    #[tokio::test]
    async fn doh_post_omits_cookie_meek_keeps_it() {
        async fn emit(content_type: &str) -> String {
            // The request is a few hundred bytes and the duplex buffer is 8 KiB,
            // so `do_http_post` completes without a concurrent reader; then we
            // read the emitted bytes back off the other end.
            let (mut a, mut b) = tokio::io::duplex(8192);
            let persona = RequestPersona::pick();
            do_http_post(
                &mut a,
                b"hello",
                "front.example",
                "/dns-query",
                "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU=",
                content_type,
                persona,
            )
            .await
            .expect("post");
            drop(a); // close the write half so the read sees EOF after the bytes
            let mut buf = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut b, &mut buf)
                .await
                .expect("read");
            String::from_utf8_lossy(&buf).into_owned()
        }

        let doh = emit("application/dns-message").await;
        assert!(
            !doh.contains("Cookie:"),
            "DoH request must not carry a session cookie:\n{doh}"
        );
        assert!(
            !doh.to_ascii_lowercase().contains("sec-ch-ua"),
            "DoH request must not carry browser client-hint headers:\n{doh}"
        );
        assert!(doh.contains("Content-Type: application/dns-message"));

        let meek = emit("application/octet-stream").await;
        assert!(
            meek.contains(&format!("Cookie: {MEEK_SESSION_COOKIE}=")),
            "meek CDN-fetch request must still carry the session cookie:\n{meek}"
        );
    }

    // 0. http_date - the hand-rolled civil-from-days formatter must match the
    //    RFC 7231 IMF-fixdate format exactly (a malformed Date header would be
    //    a worse tell than none). Canonical vectors below.

    #[test]
    fn http_date_matches_rfc7231() {
        // Unix epoch.
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        // The canonical RFC 7231 §7.1.1.1 example date.
        assert_eq!(http_date(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
        // A leap-year boundary (2016-01-01 was a Friday).
        assert_eq!(http_date(1_451_606_400), "Fri, 01 Jan 2016 00:00:00 GMT");
        // Day after a leap day (2020-02-29 23:59:59, a Saturday).
        assert_eq!(http_date(1_583_020_799), "Sat, 29 Feb 2020 23:59:59 GMT");
    }

    // 1. auth_frame_valid

    #[test]
    fn auth_frame_valid() {
        let pk = [0x11u8; 32];
        let frame = build_auth_frame(&pk).expect("build auth frame");
        assert!(
            meek_auth_verify(&pk, &frame),
            "freshly-built Meek auth frame must verify"
        );
    }

    // 2. auth_frame_wrong_key

    #[test]
    fn auth_frame_wrong_key() {
        let signing_pk = [0x22u8; 32];
        let wrong_pk = [0x33u8; 32];
        let frame = build_auth_frame(&signing_pk).expect("build auth frame");
        assert!(
            !meek_auth_verify(&wrong_pk, &frame),
            "auth frame signed with a different pk must be rejected"
        );
    }

    // 3. http_request_parser

    #[tokio::test]
    async fn http_request_parser() {
        let session_id = [0xABu8; 32];
        let session_b64 = B64.encode(session_id);
        let raw = format!(
            "POST /mirage HTTP/1.1\r\nHost: meek.cdn.example.com\r\nContent-Type: application/octet-stream\r\nContent-Length: 72\r\nCookie: sid={session_b64}\r\n\r\n"
        );
        let mut cursor = tokio::io::BufReader::new(std::io::Cursor::new(raw.into_bytes()));
        let (info, _raw_bytes) = read_http_request_headers(&mut cursor)
            .await
            .expect("parse http request headers");

        assert_eq!(info.method, "POST");
        // The request line above is an explicit "/mirage"; the parser must
        // return it verbatim (this tests the parser, not the default path).
        assert_eq!(info.path, "/mirage");
        assert_eq!(
            info.host.as_deref(),
            Some("meek.cdn.example.com"),
            "host header parsed"
        );
        assert_eq!(info.content_length, Some(72), "content-length parsed");
        assert!(
            info.session_id.is_some(),
            "session_id parsed from sid cookie"
        );
    }

    // 4. meek_session_id_extraction

    #[tokio::test]
    async fn meek_session_id_extraction() {
        // Verify that a 32-byte session ID round-trips through base64 encoding
        // in the sid session cookie.
        let original_id = [0xDEu8; 32];
        let encoded = B64.encode(original_id);
        let raw = format!(
            "POST /mirage HTTP/1.1\r\nHost: test\r\nContent-Length: 72\r\nCookie: sid={encoded}\r\n\r\n"
        );
        let mut cursor = tokio::io::BufReader::new(std::io::Cursor::new(raw.into_bytes()));
        let (info, _) = read_http_request_headers(&mut cursor).await.expect("parse");
        let extracted = info
            .session_id
            .expect("session_id must be extracted from sid cookie");
        assert_eq!(
            extracted, original_id,
            "session_id round-trips through base64 sid cookie"
        );
    }

    // Additional: MAC determinism and cross-protocol label isolation

    #[test]
    fn meek_mac_is_deterministic() {
        let pk = [0x44u8; 32];
        let nonce = [0x55u8; 32];
        let ts = 1_700_000_000u64.to_be_bytes();
        let m1 = meek_auth_mac(&pk, &nonce, &ts);
        let m2 = meek_auth_mac(&pk, &nonce, &ts);
        assert_eq!(m1, m2, "MAC must be deterministic");
    }

    #[test]
    fn meek_mac_label_differs_from_ws() {
        // "mirage-meek-v1" and "mirage-ws-v1" must produce different MACs
        // for the same inputs, preventing cross-protocol replay.
        let pk = [0x66u8; 32];
        let nonce = [0x77u8; 32];
        let ts = 1_700_000_000u64.to_be_bytes();

        let meek_mac = meek_auth_mac(&pk, &nonce, &ts);

        // WS MAC: same structure but different label.
        let mut ws_hasher = b3::Hasher::new_keyed(&pk);
        ws_hasher.update(b"mirage-ws-v1");
        ws_hasher.update(&nonce);
        ws_hasher.update(&ts);
        let ws_mac = *ws_hasher.finalize().as_bytes();

        assert_ne!(
            meek_mac, ws_mac,
            "meek and ws MACs must differ due to different domain labels"
        );
    }

    #[test]
    fn auth_frame_rejects_old_timestamp() {
        let pk = [0x88u8; 32];
        let mut nonce = [0u8; 32];
        nonce[0] = 9;

        // 60 seconds in the past - outside +/-30 s window.
        let old_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(60)
            .to_be_bytes();

        let mac = meek_auth_mac(&pk, &nonce, &old_ts);
        let mut frame = [0u8; MEEK_AUTH_FRAME_LEN];
        frame[0..32].copy_from_slice(&nonce);
        frame[32..64].copy_from_slice(&mac);
        frame[64..72].copy_from_slice(&old_ts);

        assert!(
            !meek_auth_verify(&pk, &frame),
            "auth frame with timestamp 60 s in the past must be rejected"
        );
    }

    #[test]
    fn session_buffer_bounds_inbound() {
        let mut sess = MeekServerSession::new();
        // Push up to the limit in 65536-byte chunks.
        let chunk = vec![0u8; 65536];
        let mut total = 0;
        while total + 65536 <= MEEK_MAX_SESSION_BUFFER {
            sess.push_inbound(&chunk).expect("within limit");
            total += 65536;
        }
        // One more byte should be rejected.
        let result = sess.push_inbound(&[0u8; 1]);
        assert!(
            result.is_err(),
            "pushing beyond MEEK_MAX_SESSION_BUFFER must fail"
        );
    }

    // multconn_new_session_accepted - first POST creates a session and returns
    // MeekServeOutcome::NewSession.

    #[tokio::test]
    async fn multconn_new_session_accepted() {
        let pk = [0x42u8; 32];
        let store = MeekSessionStore::new();

        let (client_end, server_end) = tokio::io::duplex(65536);
        let auth_frame = build_auth_frame(&pk).expect("build_auth_frame");
        let body = auth_frame.to_vec();
        let session_id = [0xBBu8; 32];
        let session_b64 = B64.encode(session_id);
        let request = format!(
            "POST /mirage HTTP/1.1\r\nHost: cdn.example.com\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nCookie: sid={session_b64}\r\n\r\n",
            body.len()
        );

        let serve_task = tokio::spawn(async move {
            meek_bridge_serve_multconn(
                server_end,
                &store,
                &pk,
                Duration::from_secs(5),
                "application/octet-stream",
                &mirage_transport::SeenNonceSet::new(std::time::Duration::from_secs(60)),
            )
            .await
        });

        let mut client = client_end;
        use tokio::io::AsyncWriteExt;
        client.write_all(request.as_bytes()).await.unwrap();
        client.write_all(&body).await.unwrap();
        client.flush().await.unwrap();

        let outcome = serve_task.await.expect("task").expect("serve");
        assert!(
            matches!(outcome, MeekServeOutcome::NewSession(_)),
            "first POST must yield NewSession"
        );
    }

    /// RT #8: the SAME auth frame (same nonce) presented twice against a
    /// SHARED seen-set is accepted once, then rejected as a replay - a
    /// captured frame cannot be replayed within the window to confirm the
    /// bridge.
    #[tokio::test]
    async fn multconn_rejects_replayed_auth_nonce() {
        let pk = [0x42u8; 32];
        let store = MeekSessionStore::new();
        let seen = mirage_transport::SeenNonceSet::new(Duration::from_secs(60));
        let auth_frame = build_auth_frame(&pk).expect("build_auth_frame");
        let body = auth_frame.to_vec();

        // One captured request, replayed verbatim on two connections.
        let serve_once = |conn_seed: u8| {
            let store = &store;
            let seen = &seen;
            let body = body.clone();
            async move {
                let (client_end, server_end) = tokio::io::duplex(65536);
                let session_b64 = B64.encode([conn_seed; 32]);
                let request = format!(
                    "POST /mirage HTTP/1.1\r\nHost: cdn.example.com\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nCookie: sid={session_b64}\r\n\r\n",
                    body.len()
                );
                let mut client = client_end;
                use tokio::io::AsyncWriteExt;
                client.write_all(request.as_bytes()).await.unwrap();
                client.write_all(&body).await.unwrap();
                client.flush().await.unwrap();
                meek_bridge_serve_multconn(
                    server_end,
                    store,
                    &pk,
                    Duration::from_secs(5),
                    "application/octet-stream",
                    seen,
                )
                .await
            }
        };

        // First use: accepted.
        assert!(
            matches!(serve_once(0xB1).await, Ok(MeekServeOutcome::NewSession(_))),
            "first auth frame must be accepted"
        );
        // Replay of the SAME nonce: rejected (forwarded to shadow -> Err).
        assert!(
            matches!(
                serve_once(0xB2).await,
                Err((TransportError::Auth("meek auth replay"), _))
            ),
            "replayed auth nonce must be rejected"
        );
    }

    // multconn_existing_session_stitched - second TCP connection with the same
    // session ID is routed to the existing session.

    #[tokio::test]
    async fn multconn_existing_session_stitched() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let pk = [0x43u8; 32];
        let store = Arc::new(MeekSessionStore::new());
        let session_id = [0xCCu8; 32];
        let session_b64 = B64.encode(session_id);

        // --- First connection: new session ---
        let (client1, server1) = tokio::io::duplex(65536);
        let auth_frame = build_auth_frame(&pk).expect("build_auth_frame");
        let body1 = auth_frame.to_vec();
        let req1 = format!(
            "POST /mirage HTTP/1.1\r\nHost: cdn.example.com\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nCookie: sid={session_b64}\r\n\r\n",
            body1.len()
        );

        let store_clone = Arc::clone(&store);
        let pk_clone = pk;
        let serve_task1 = tokio::spawn(async move {
            meek_bridge_serve_multconn(
                server1,
                &store_clone,
                &pk_clone,
                Duration::from_secs(5),
                "application/octet-stream",
                &mirage_transport::SeenNonceSet::new(std::time::Duration::from_secs(60)),
            )
            .await
        });

        let mut c1 = client1;
        c1.write_all(req1.as_bytes()).await.unwrap();
        c1.write_all(&body1).await.unwrap();
        c1.flush().await.unwrap();

        let outcome1 = serve_task1.await.expect("task1").expect("serve1");
        assert!(
            matches!(outcome1, MeekServeOutcome::NewSession(_)),
            "first conn -> NewSession"
        );

        // Give the serve_connection_against_session task a moment to start.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // --- Second connection: same session_id, no auth frame needed ---
        let (client2, server2) = tokio::io::duplex(65536);
        // Just a raw body (no auth frame required for existing sessions)
        let body2 = b"hello from second connection".to_vec();
        let req2 = format!(
            "POST /mirage HTTP/1.1\r\nHost: cdn.example.com\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nCookie: sid={session_b64}\r\n\r\n",
            body2.len()
        );

        let store_clone2 = Arc::clone(&store);
        let serve_task2 = tokio::spawn(async move {
            meek_bridge_serve_multconn(
                server2,
                &store_clone2,
                &pk_clone,
                Duration::from_secs(5),
                "application/octet-stream",
                &mirage_transport::SeenNonceSet::new(std::time::Duration::from_secs(60)),
            )
            .await
        });

        let mut c2 = client2;
        c2.write_all(req2.as_bytes()).await.unwrap();
        c2.write_all(&body2).await.unwrap();
        c2.flush().await.unwrap();

        // Read the HTTP response on client2 to unblock serve_connection_against_session
        let mut resp_buf = vec![0u8; 4096];
        let _ = c2.read(&mut resp_buf).await.unwrap_or(0);

        let outcome2 = serve_task2.await.expect("task2").expect("serve2");
        assert!(
            matches!(outcome2, MeekServeOutcome::Existing),
            "second conn with same session_id -> Existing"
        );
    }

    // multconn_wrong_pk_rejected - auth still enforced for new sessions.

    #[tokio::test]
    async fn multconn_wrong_pk_rejected() {
        let right_pk = [0x44u8; 32];
        let wrong_pk = [0xFFu8; 32];
        let store = MeekSessionStore::new();

        let (_client, server_end) = tokio::io::duplex(65536);
        let auth_frame = build_auth_frame(&right_pk).expect("build_auth_frame");
        let body = auth_frame.to_vec();
        let session_id = [0xDDu8; 32];
        let session_b64 = B64.encode(session_id);
        let request = format!(
            "POST /mirage HTTP/1.1\r\nHost: cdn.example.com\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nCookie: sid={session_b64}\r\n\r\n",
            body.len()
        );

        let serve_task = tokio::spawn(async move {
            meek_bridge_serve_multconn(
                server_end,
                &store,
                &wrong_pk, // wrong key
                Duration::from_secs(5),
                "application/octet-stream",
                &mirage_transport::SeenNonceSet::new(std::time::Duration::from_secs(60)),
            )
            .await
        });

        let mut client = _client;
        use tokio::io::AsyncWriteExt;
        client.write_all(request.as_bytes()).await.unwrap();
        client.write_all(&body).await.unwrap();
        client.flush().await.unwrap();

        let result = serve_task.await.expect("task");
        match result {
            Err((TransportError::Auth(_), Some((_stream, replay)))) => {
                // Core acceptance: the reject must carry a byte-identical
                // reconstruction of the prober's request (headers ++ body) so
                // a shadow backend emits a response indistinguishable from
                // probing the decoy directly.
                let mut expected = request.into_bytes();
                expected.extend_from_slice(&body);
                assert_eq!(
                    replay, expected,
                    "auth-fail replay must be byte-identical to the prober's request"
                );
            }
            Err((e, _)) => panic!("wrong PK must yield Auth error, got {e:?}"),
            Ok(_) => panic!("wrong PK must be rejected for a new session"),
        }
    }
}
