//! HTTP/3 carrier: the Mirage session rides inside HTTP/3 DATA frames on a
//! QUIC bidirectional stream, so the wire looks like an HTTP/3 request to a
//! web origin (the #1 DPI signal - QUIC on :443 with ALPN `h3` + HTTP/3 frame
//! structure on the streams).
//!
//! This is a CARRIER (both endpoints are ours): we run the minimal real HTTP/3
//! shape - a unidirectional control stream carrying a SETTINGS frame, then a
//! bidi request stream with a HEADERS frame followed by DATA frames that carry
//! the opaque Mirage session bytes. The peer authenticates via the inner
//! Noise-XX handshake, exactly like every other Mirage carrier; the TLS cert is
//! decorative (a self-signed `h3` endpoint).
//!
//! Wiring into the bridge listener / client dial / keygen / transport-selection
//! is the next step; this module is the validated transport core.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use mirage_transport::TransportError;

/// ALPN negotiated at the QUIC/TLS layer (RFC 9114 §3.1).
pub const ALPN_H3: &[u8] = b"h3";

// HTTP/3 frame types (RFC 9114 §7.2).
const FRAME_DATA: u64 = 0x00;
const FRAME_HEADERS: u64 = 0x01;
const FRAME_SETTINGS: u64 = 0x04;
/// HTTP/3 unidirectional stream type for the control stream (RFC 9114 §6.2.1).
const STREAM_TYPE_CONTROL: u64 = 0x00;

/// Max payload per DATA frame. Keeps frames in a realistic size band and the
/// length varint small; large writes are split across frames.
const MAX_DATA_FRAME: usize = 16 * 1024;

/// ASCII marker our own extended-CONNECT HEADERS always carry (the `:protocol`
/// value, emitted as a literal QPACK field line by [`qpack_connect_headers`]).
/// A benign HTTP/3 probe (a scanner's `GET /`) never contains it, so the server
/// uses its presence to tell a real Mirage client from a probe worth answering
/// with a plausible 404 (F11-M - a real origin never stays silent).
const CONNECT_UDP_MARKER: &[u8] = b"connect-udp";

/// The nginx default 404 body, byte-for-byte, so a probe that reads it sees a
/// stock origin rather than anything Mirage-shaped.
const BENIGN_404_BODY: &str = "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n";

// QUIC variable-length integers (RFC 9000 §16)

/// Append `v` as a QUIC varint (1/2/4/8 bytes by the 2 MSBs of byte 0).
fn put_varint(out: &mut Vec<u8>, v: u64) {
    if v < (1 << 6) {
        out.push(v as u8);
    } else if v < (1 << 14) {
        out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else if v < (1 << 30) {
        out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(v | 0xC000_0000_0000_0000).to_be_bytes());
    }
}

/// Read a QUIC varint from an async stream.
async fn read_varint<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<u64> {
    let mut first = [0u8; 1];
    r.read_exact(&mut first).await?;
    let len = 1usize << (first[0] >> 6); // 1, 2, 4, or 8
    let mut val = u64::from(first[0] & 0x3F);
    let mut rest = [0u8; 7];
    if len > 1 {
        r.read_exact(&mut rest[..len - 1]).await?;
        for b in &rest[..len - 1] {
            val = (val << 8) | u64::from(*b);
        }
    }
    Ok(val)
}

/// Number of bytes a varint with this leading byte occupies.
fn varint_len(first: u8) -> usize {
    1usize << (first >> 6)
}

/// Decode a complete varint from a byte slice (caller guarantees length).
fn decode_varint(buf: &[u8]) -> u64 {
    let len = varint_len(buf[0]);
    let mut val = u64::from(buf[0] & 0x3F);
    for b in &buf[1..len] {
        val = (val << 8) | u64::from(*b);
    }
    val
}

// QUIC endpoint configuration (mirrors transport-hysteria2's approach)

/// Build a server `quinn::ServerConfig` with a self-signed cert + ALPN `h3`.
fn server_quinn_config(server_name: &str) -> Result<quinn::ServerConfig, TransportError> {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec![server_name.to_string()])
            .map_err(|e| TransportError::Other(format!("h3: rcgen: {e}")))?;
    let cert_der = CertificateDer::from(cert);
    let priv_key = PrivatePkcs8KeyDer::from(key_pair.serialize_der());

    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], priv_key.into())
        .map_err(|e| TransportError::Other(format!("h3: rustls server: {e}")))?;
    tls.alpn_protocols = vec![ALPN_H3.to_vec()];

    Ok(quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(tls)
            .map_err(|e| TransportError::Other(format!("h3: quinn server crypto: {e}")))?,
    )))
}

/// Move the numeric QUIC transport parameters toward Chrome-QUIC magnitudes (the
/// values reachable via quinn's public API; the parameter set/order + GREASE need
/// the quinn-proto fork). Applies to real-QUIC/mimicry flows.
fn apply_chrome_transport_params(t: &mut quinn::TransportConfig) {
    use std::time::Duration;
    if let Ok(idle) = quinn::IdleTimeout::try_from(Duration::from_secs(30)) {
        t.max_idle_timeout(Some(idle));
    }
    t.receive_window(quinn::VarInt::from_u32(15_728_640));
    t.stream_receive_window(quinn::VarInt::from_u32(6_291_456));
    t.max_concurrent_bidi_streams(quinn::VarInt::from_u32(100));
    t.max_concurrent_uni_streams(quinn::VarInt::from_u32(103));
}

/// Build a client `quinn::ClientConfig` that skips cert verification (the
/// inner Noise handshake is the real auth) + ALPN `h3`.
fn client_quinn_config() -> Result<quinn::ClientConfig, TransportError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerify::new(Arc::clone(&provider)))
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN_H3.to_vec()];
    let qcc = QuicClientConfig::try_from(tls)
        .map_err(|e| TransportError::Other(format!("h3: quinn client crypto: {e}")))?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(qcc));
    // Chrome-QUIC alignment for real-QUIC (mimicry) flows: 8-byte initial DCID
    // (quinn default 20) + Chrome transport-parameter magnitudes. Harmless under
    // the Salamander obfs (which XORs the handshake).
    client_config.initial_dst_cid_provider(Arc::new(|| {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).expect("OS CSPRNG for QUIC DCID");
        quinn::ConnectionId::new(&b)
    }));
    let mut transport = quinn::TransportConfig::default();
    apply_chrome_transport_params(&mut transport);
    client_config.transport_config(Arc::new(transport));
    Ok(client_config)
}

/// A TLS verifier that accepts any cert. Safe in Mirage's model: the Noise-XX
/// handshake inside the H3 stream provides authentication; TLS only satisfies
/// QUIC and produces HTTPS/H3-looking traffic.
#[derive(Debug)]
struct SkipServerVerify(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerify {
    fn new(p: Arc<rustls::crypto::CryptoProvider>) -> Arc<Self> {
        Arc::new(Self(p))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

// HTTP/3 handshake helpers

/// Open the unidirectional control stream and send an (empty) SETTINGS frame,
/// as RFC 9114 §6.2.1/§7.2.4 require before any request. Returns the open
/// control `SendStream`: it MUST stay open for the connection's lifetime
/// (never `finish()` it - closing a critical stream is `H3_CLOSED_CRITICAL_STREAM`,
/// RFC 9114 §6.2.1), so ownership passes to the caller (the returned
/// [`H3Stream`]) and it drops with the stream rather than leaking.
async fn send_control_settings(
    conn: &quinn::Connection,
) -> Result<quinn::SendStream, TransportError> {
    let mut ctrl = conn
        .open_uni()
        .await
        .map_err(|e| TransportError::Other(format!("h3: open control: {e}")))?;
    let mut buf = Vec::with_capacity(4);
    put_varint(&mut buf, STREAM_TYPE_CONTROL);
    put_varint(&mut buf, FRAME_SETTINGS);
    put_varint(&mut buf, 0); // zero-length settings payload
    ctrl.write_all(&buf)
        .await
        .map_err(|e| TransportError::Other(format!("h3: write settings: {e}")))?;
    // Do not finish(): the control stream must stay open. Hand the live handle
    // back to the caller so it is owned for the connection's lifetime.
    Ok(ctrl)
}

/// Accept and drain the peer's control stream + SETTINGS (best-effort; we don't
/// act on any settings).
async fn recv_control_settings(conn: &quinn::Connection) -> Result<(), TransportError> {
    let mut ctrl = conn
        .accept_uni()
        .await
        .map_err(|e| TransportError::Other(format!("h3: accept control: {e}")))?;
    // stream type
    let st = read_varint(&mut ctrl).await.map_err(io_other)?;
    if st != STREAM_TYPE_CONTROL {
        return Err(TransportError::Other(format!(
            "h3: first uni stream type 0x{st:x} != control"
        )));
    }
    // one SETTINGS frame (type + len + payload)
    let ftype = read_varint(&mut ctrl).await.map_err(io_other)?;
    let flen = read_varint(&mut ctrl).await.map_err(io_other)? as usize;
    if ftype != FRAME_SETTINGS {
        return Err(TransportError::Other(
            "h3: control: first frame not SETTINGS".into(),
        ));
    }
    if flen > 0 {
        let mut skip = vec![0u8; flen.min(4096)];
        let _ = ctrl.read_exact(&mut skip).await;
    }
    Ok(())
}

/// Minimal QPACK-encoded HEADERS payload for an extended-CONNECT-UDP request.
/// Both ends are ours and the receiver skips the HEADERS frame by length, so
/// this only needs to be a plausible, well-formed QPACK field section for DPI
/// shape. Uses the QPACK static table where possible + literal field lines.
fn qpack_connect_headers(authority: &str, path: &str) -> Vec<u8> {
    let mut b = Vec::with_capacity(32 + authority.len() + path.len());
    // QPACK encoded field section prefix: Required Insert Count = 0, Base = 0.
    b.push(0x00);
    b.push(0x00);
    // Literal field line with literal name (no name reference), no Huffman:
    //   0010NNNN where N is the name-length prefix (4-bit), then name, then
    //   0VVVVVVV value-length (7-bit), then value. (RFC 9204 §4.5.6.)
    let lit = |name: &str, value: &str, out: &mut Vec<u8>| {
        // name length (assume < 16 for our fixed pseudo-headers; safe here)
        out.push(0x20 | (name.len() as u8 & 0x0F));
        out.extend_from_slice(name.as_bytes());
        out.push((value.len() as u8) & 0x7F);
        out.extend_from_slice(value.as_bytes());
    };
    lit(":method", "CONNECT", &mut b);
    lit(":scheme", "https", &mut b);
    lit(":authority", authority, &mut b);
    lit(":path", path, &mut b);
    lit(":protocol", "connect-udp", &mut b);
    b
}

fn io_other(e: io::Error) -> TransportError {
    TransportError::Other(format!("h3: io: {e}"))
}

/// True if `needle` appears contiguously in `haystack`.
fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack.windows(needle.len()).any(|w| w == needle)
}

// QPACK response encoding for the benign-probe answer (RFC 9204)
//
// Unlike the request HEADERS (which the peer skips by length), the benign 404
// is decoded by a *real* HTTP/3 client (curl/chrome/a scanner), so it must be
// correct QPACK: static-table indexed lines for `:status`, correctly
// prefix-encoded literal field lines for the rest. No dynamic table -> the field
// section prefix is `Required Insert Count = 0, Base = 0`.

/// Encode `value` as a QPACK/HPACK prefix integer with a `prefix_bits`-bit
/// prefix, OR-ing the pattern bits of the first byte with `flags` (RFC 7541
/// §5.1).
fn qpack_int(out: &mut Vec<u8>, flags: u8, prefix_bits: u8, value: u64) {
    let max = (1u64 << prefix_bits) - 1;
    if value < max {
        out.push(flags | value as u8);
    } else {
        out.push(flags | max as u8);
        let mut v = value - max;
        while v >= 128 {
            out.push((v as u8 & 0x7f) | 0x80);
            v >>= 7;
        }
        out.push(v as u8);
    }
}

/// Append a QPACK "Literal Field Line with Literal Name" (RFC 9204 §4.5.6), no
/// Huffman: name uses a 3-bit-prefix length, value a 7-bit-prefix length.
fn qpack_lit(out: &mut Vec<u8>, name: &str, value: &str) {
    qpack_int(out, 0x20, 3, name.len() as u64); // 001NH<name-len>, N=H=0
    out.extend_from_slice(name.as_bytes());
    qpack_int(out, 0x00, 7, value.len() as u64); // 0H<value-len>, H=0
    out.extend_from_slice(value.as_bytes());
}

/// Format `secs` (seconds since the Unix epoch) as an RFC 7231 IMF-fixdate
/// (`Sun, 06 Jul 2026 10:00:00 GMT`) for the `Date` header. A response with no
/// `Date` is a passive tell - real HTTP servers always send one (F36). Uses
/// Howard Hinnant's civil-from-days algorithm (no date-crate dependency).
/// Kept byte-identical to `mirage_transport_meek`'s helper (copied, not shared,
/// to avoid a cross-crate dependency for one function).
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

/// Encode a minimal, valid QPACK field section for an HTTP/3 response with the
/// given status, `Date`, and body length. `:status` uses the QPACK static table
/// (single indexed byte) where available (RFC 9204 Appendix A: 200->25, 404->27,
/// 503->28). The remaining fields mirror nginx's response order - `server`,
/// `date`, `content-type`, `content-length` - with `connection` omitted (a
/// connection-specific field forbidden in HTTP/3, RFC 9114 §4.2). Matching this
/// set/order (and, per F36, not dropping `date`) keeps the benign 404 cover
/// indistinguishable from a real nginx origin.
fn qpack_response_headers(status: &str, date: &str, content_len: usize) -> Vec<u8> {
    let mut b = Vec::with_capacity(64);
    b.push(0x00); // Required Insert Count = 0
    b.push(0x00); // sign + Delta Base = 0
    match status {
        "200" => b.push(0xC0 | 25),
        "404" => b.push(0xC0 | 27),
        "503" => b.push(0xC0 | 28),
        other => qpack_lit(&mut b, ":status", other),
    }
    qpack_lit(&mut b, "server", "nginx");
    qpack_lit(&mut b, "date", date);
    qpack_lit(&mut b, "content-type", "text/html");
    qpack_lit(&mut b, "content-length", &content_len.to_string());
    b
}

/// Write a plausible HTTP/3 `404 Not Found` (HEADERS + DATA) on `send` and
/// finish the stream, so a benign probe sees a real origin's response instead
/// of the silent hang that would fingerprint the bridge (F11-M).
async fn send_benign_h3_response(send: &mut quinn::SendStream) -> Result<(), TransportError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let body = BENIGN_404_BODY.as_bytes();
    let headers = qpack_response_headers("404", &http_date(now), body.len());
    let mut out = Vec::with_capacity(headers.len() + body.len() + 18);
    put_varint(&mut out, FRAME_HEADERS);
    put_varint(&mut out, headers.len() as u64);
    out.extend_from_slice(&headers);
    put_varint(&mut out, FRAME_DATA);
    put_varint(&mut out, body.len() as u64);
    out.extend_from_slice(body);
    send.write_all(&out)
        .await
        .map_err(|e| TransportError::Other(format!("h3: benign write: {e}")))?;
    let _ = send.finish();
    Ok(())
}

// H3Stream - AsyncRead + AsyncWrite over a quinn bidi stream, DATA-framed

/// A quinn bidirectional stream presenting an `AsyncRead + AsyncWrite` byte
/// pipe. Writes are emitted as HTTP/3 DATA frames; reads decode DATA frames
/// (skipping any non-DATA frame, e.g. a trailing HEADERS).
pub struct H3Stream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    /// Decoded DATA payload not yet handed to the reader.
    read_buf: Vec<u8>,
    read_off: usize,
    /// Frame-parser state for the read side.
    rx: RxFrame,
    /// Encrypted/encoded bytes awaiting write to `send` (full DATA frame),
    /// drained fully before the next frame so a partial write never truncates.
    write_buf: Vec<u8>,
    write_off: usize,
    /// Client-side resources kept alive for the connection's lifetime and
    /// dropped exactly when this stream drops - never leaked. The QUIC
    /// `Endpoint` owns the UDP socket + driver task; the HTTP/3 control
    /// `SendStream` must stay open (RFC 9114 §6.2.1). Holding the `Endpoint`
    /// handle keeps quinn's driver running so the connection stays live; when
    /// the stream drops, the handle drops, the connection closes, and the
    /// socket + task are reclaimed. `None` on the server side, where the caller
    /// owns the endpoint and the peer owns the control stream. (Previously
    /// leaked via `std::mem::forget`, accumulating FDs/tasks on every dial.)
    _endpoint: Option<quinn::Endpoint>,
    _control: Option<quinn::SendStream>,
}

/// Read-side frame parser state.
enum RxFrame {
    /// Accumulating the frame header (type varint + length varint).
    Header { buf: Vec<u8> },
    /// Reading `remaining` payload bytes of a DATA frame.
    Data { remaining: usize },
    /// Discarding `remaining` bytes of a non-DATA frame.
    Skip { remaining: usize },
}

impl H3Stream {
    /// Server-side constructor: the caller owns the `Endpoint` and the peer
    /// owns the control stream, so this stream holds neither.
    fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self::with_owned(send, recv, None, None)
    }

    /// Client-side constructor: the stream takes ownership of the dial's
    /// `Endpoint` and control `SendStream` so they live exactly as long as the
    /// stream and are reclaimed on drop (previously leaked by
    /// `std::mem::forget`).
    fn new_client(
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        endpoint: quinn::Endpoint,
        control: quinn::SendStream,
    ) -> Self {
        Self::with_owned(send, recv, Some(endpoint), Some(control))
    }

    fn with_owned(
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        endpoint: Option<quinn::Endpoint>,
        control: Option<quinn::SendStream>,
    ) -> Self {
        Self {
            send,
            recv,
            read_buf: Vec::new(),
            read_off: 0,
            rx: RxFrame::Header {
                buf: Vec::with_capacity(16),
            },
            write_buf: Vec::new(),
            write_off: 0,
            _endpoint: endpoint,
            _control: control,
        }
    }
}

impl AsyncRead for H3Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            // Serve buffered DATA payload first.
            if this.read_off < this.read_buf.len() {
                let n = (this.read_buf.len() - this.read_off).min(out.remaining());
                let start = this.read_off;
                out.put_slice(&this.read_buf[start..start + n]);
                this.read_off += n;
                return Poll::Ready(Ok(()));
            }
            this.read_buf.clear();
            this.read_off = 0;

            match &mut this.rx {
                RxFrame::Header { buf } => {
                    // Read 1 byte at a time into `buf` and parse the type +
                    // length varints when both are complete.
                    let mut one = [0u8; 1];
                    let mut tmp = ReadBuf::new(&mut one);
                    match Pin::new(&mut this.recv).poll_read(cx, &mut tmp) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            if tmp.filled().is_empty() {
                                return Poll::Ready(Ok(())); // EOF
                            }
                            buf.push(one[0]);
                            if let Some((ftype, flen, _consumed)) = try_parse_frame_header(buf) {
                                this.rx = if ftype == FRAME_DATA {
                                    RxFrame::Data {
                                        remaining: flen as usize,
                                    }
                                } else {
                                    RxFrame::Skip {
                                        remaining: flen as usize,
                                    }
                                };
                            }
                        }
                    }
                }
                RxFrame::Data { remaining } => {
                    if *remaining == 0 {
                        this.rx = RxFrame::Header {
                            buf: Vec::with_capacity(16),
                        };
                        continue;
                    }
                    let want = (*remaining).min(64 * 1024);
                    let mut chunk = vec![0u8; want];
                    let mut tmp = ReadBuf::new(&mut chunk);
                    match Pin::new(&mut this.recv).poll_read(cx, &mut tmp) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            let n = tmp.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "h3: truncated DATA frame",
                                )));
                            }
                            let rem = *remaining - n;
                            chunk.truncate(n);
                            this.read_buf = chunk;
                            this.read_off = 0;
                            this.rx = if rem == 0 {
                                RxFrame::Header {
                                    buf: Vec::with_capacity(16),
                                }
                            } else {
                                RxFrame::Data { remaining: rem }
                            };
                        }
                    }
                }
                RxFrame::Skip { remaining } => {
                    if *remaining == 0 {
                        this.rx = RxFrame::Header {
                            buf: Vec::with_capacity(16),
                        };
                        continue;
                    }
                    let want = (*remaining).min(4096);
                    let mut skip = vec![0u8; want];
                    let mut tmp = ReadBuf::new(&mut skip);
                    match Pin::new(&mut this.recv).poll_read(cx, &mut tmp) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            let n = tmp.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "h3: truncated frame",
                                )));
                            }
                            let rem = *remaining - n;
                            this.rx = if rem == 0 {
                                RxFrame::Header {
                                    buf: Vec::with_capacity(16),
                                }
                            } else {
                                RxFrame::Skip { remaining: rem }
                            };
                        }
                    }
                }
            }
        }
    }
}

/// Parse a frame header (type varint + length varint) from `buf` if both are
/// fully present. Returns `(type, length, bytes_consumed)`.
fn try_parse_frame_header(buf: &[u8]) -> Option<(u64, u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let tlen = varint_len(buf[0]);
    if buf.len() < tlen {
        return None;
    }
    let ftype = decode_varint(&buf[..tlen]);
    if buf.len() <= tlen {
        return None;
    }
    let llen = varint_len(buf[tlen]);
    if buf.len() < tlen + llen {
        return None;
    }
    let flen = decode_varint(&buf[tlen..tlen + llen]);
    Some((ftype, flen, tlen + llen))
}

impl AsyncWrite for H3Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        // Drain a partially-written frame first.
        while this.write_off < this.write_buf.len() {
            match Pin::new(&mut this.send).poll_write(cx, &this.write_buf[this.write_off..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "h3: send accepted 0 bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => this.write_off += n,
            }
        }
        this.write_buf.clear();
        this.write_off = 0;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let take = buf.len().min(MAX_DATA_FRAME);
        // Build one DATA frame: type(0x00) + length varint + payload.
        let mut frame = Vec::with_capacity(take + 9);
        put_varint(&mut frame, FRAME_DATA);
        put_varint(&mut frame, take as u64);
        frame.extend_from_slice(&buf[..take]);
        this.write_buf = frame;
        this.write_off = 0;
        // Best-effort drain.
        while this.write_off < this.write_buf.len() {
            match Pin::new(&mut this.send).poll_write(cx, &this.write_buf[this.write_off..]) {
                Poll::Pending => break,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "h3: send accepted 0 bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => this.write_off += n,
            }
        }
        if this.write_off >= this.write_buf.len() {
            this.write_buf.clear();
            this.write_off = 0;
        }
        Poll::Ready(Ok(take))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        while this.write_off < this.write_buf.len() {
            match Pin::new(&mut this.send).poll_write(cx, &this.write_buf[this.write_off..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "h3: send accepted 0 bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => this.write_off += n,
            }
        }
        this.write_buf.clear();
        this.write_off = 0;
        Pin::new(&mut this.send)
            .poll_flush(cx)
            .map_err(io::Error::other)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_shutdown(cx)
            .map_err(io::Error::other)
    }
}

// Client / server entry points

/// Dial an H3 endpoint at `addr` and open a request stream ready to carry the
/// Mirage session. Performs: QUIC connect (ALPN h3) -> control stream + SETTINGS
/// -> bidi request stream -> HEADERS (extended CONNECT-UDP). Returns the request
/// stream as a byte pipe.
pub async fn h3_client_connect(
    addr: SocketAddr,
    server_name: &str,
    authority: &str,
    path: &str,
    deadline: Duration,
    obfs_key: Option<[u8; 32]>,
) -> Result<H3Stream, TransportError> {
    tokio::time::timeout(deadline, async move {
        let bind: SocketAddr = "0.0.0.0:0".parse().expect("valid bind");
        let mut endpoint = match obfs_key {
            // Gecko/Salamander QUIC obfuscation: the UDP socket scrambles every
            // datagram so the wire shows no QUIC fingerprint.
            Some(key) => mirage_quic_obfs::client_endpoint(bind, key)
                .map_err(|e| TransportError::Other(format!("h3: obfs client endpoint: {e}")))?,
            None => quinn::Endpoint::client(bind)
                .map_err(|e| TransportError::Other(format!("h3: client endpoint: {e}")))?,
        };
        endpoint.set_default_client_config(client_quinn_config()?);
        let conn = endpoint
            .connect(addr, server_name)
            .map_err(|e| TransportError::Other(format!("h3: connect: {e}")))?
            .await
            .map_err(|e| TransportError::Other(format!("h3: handshake: {e}")))?;

        let control = send_control_settings(&conn).await?;

        let (mut send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| TransportError::Other(format!("h3: open_bi: {e}")))?;

        // HEADERS frame for the extended CONNECT request.
        let qpack = qpack_connect_headers(authority, path);
        let mut hdr = Vec::with_capacity(qpack.len() + 9);
        put_varint(&mut hdr, FRAME_HEADERS);
        put_varint(&mut hdr, qpack.len() as u64);
        hdr.extend_from_slice(&qpack);
        send.write_all(&hdr)
            .await
            .map_err(|e| TransportError::Other(format!("h3: write headers: {e}")))?;

        // Own the endpoint + control stream inside the returned stream so they
        // live for the connection's lifetime and drop with it - no leak. quinn
        // keeps the connection alive while the Endpoint handle (and the request
        // streams) are held.
        Ok(H3Stream::new_client(send, recv, endpoint, control))
    })
    .await
    .map_err(|_| TransportError::Timeout(deadline))?
}

/// Accept one H3 request on `conn`: drain the peer control stream + SETTINGS,
/// accept the bidi request stream, read past its HEADERS frame, and return the
/// stream as a byte pipe ready to carry the Mirage session.
pub async fn h3_server_accept_conn(conn: quinn::Connection) -> Result<H3Stream, TransportError> {
    recv_control_settings(&conn).await?;
    let (mut send, mut recv) = conn
        .accept_bi()
        .await
        .map_err(|e| TransportError::Other(format!("h3: accept_bi: {e}")))?;

    // Read the HEADERS frame.
    let ftype = read_varint(&mut recv).await.map_err(io_other)?;
    let flen = read_varint(&mut recv).await.map_err(io_other)? as usize;
    if ftype != FRAME_HEADERS {
        return Err(TransportError::Other(format!(
            "h3: first request frame 0x{ftype:x} != HEADERS"
        )));
    }
    let mut headers = vec![0u8; flen.min(64 * 1024)];
    if flen > 0 {
        recv.read_exact(&mut headers)
            .await
            .map_err(|e| TransportError::Other(format!("h3: read headers: {e}")))?;
    }

    // Benign-probe cover (F11-M): a real HTTP/3 origin answers every request. A
    // Mirage client sends our extended CONNECT-UDP HEADERS (carrying the
    // `connect-udp` marker); anything else - a scanner's `GET /`, a `curl
    // --http3` probe - gets a plausible nginx 404 instead of the silent
    // handshake-timeout hang that would fingerprint the bridge as "not a web
    // server". The response is flushed on a detached task so it lands before the
    // connection closes, and it holds no session slot.
    if !contains_subsequence(&headers, CONNECT_UDP_MARKER) {
        tokio::spawn(async move {
            let _ = send_benign_h3_response(&mut send).await;
            // Keep `conn`/`recv` alive briefly so QUIC transmits the response +
            // FIN before the connection is dropped.
            tokio::time::sleep(Duration::from_millis(300)).await;
            drop(recv);
            drop(conn);
        });
        return Err(TransportError::Auth("h3: benign probe answered with 404"));
    }

    Ok(H3Stream::new(send, recv))
}

/// Build a QUIC server endpoint bound to `addr` (ALPN h3, self-signed cert).
pub fn h3_server_endpoint(
    addr: SocketAddr,
    server_name: &str,
    obfs_key: Option<[u8; 32]>,
) -> Result<quinn::Endpoint, TransportError> {
    let cfg = server_quinn_config(server_name)?;
    match obfs_key {
        Some(key) => mirage_quic_obfs::server_endpoint(addr, cfg, key)
            .map_err(|e| TransportError::Other(format!("h3: obfs server endpoint: {e}"))),
        None => quinn::Endpoint::server(cfg, addr)
            .map_err(|e| TransportError::Other(format!("h3: server endpoint: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn varint_roundtrips() {
        for v in [0u64, 1, 63, 64, 16383, 16384, 1 << 20, 1 << 30, 1 << 40] {
            let mut b = Vec::new();
            put_varint(&mut b, v);
            assert_eq!(varint_len(b[0]), b.len(), "len mismatch for {v}");
            assert_eq!(decode_varint(&b), v, "decode mismatch for {v}");
        }
    }

    #[test]
    fn frame_header_parses_incrementally() {
        let mut b = Vec::new();
        put_varint(&mut b, FRAME_DATA);
        put_varint(&mut b, 16384); // 2-byte length varint
                                   // Feed byte by byte; only the last byte completes it.
        for i in 1..b.len() {
            assert!(
                try_parse_frame_header(&b[..i]).is_none(),
                "premature parse at {i}"
            );
        }
        let (t, l, c) = try_parse_frame_header(&b).unwrap();
        assert_eq!((t, l, c), (FRAME_DATA, 16384, b.len()));
    }

    /// The copied `http_date` helper must stay byte-identical to
    /// `mirage_transport_meek`'s (RFC 7231 IMF-fixdate), or the `Date` header
    /// on the benign 404 would be malformed and re-introduce F36.
    #[test]
    fn http_date_matches_rfc7231() {
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(http_date(1_451_606_400), "Fri, 01 Jan 2016 00:00:00 GMT");
        assert_eq!(http_date(1_583_020_799), "Sat, 29 Feb 2020 23:59:59 GMT");
    }

    #[test]
    fn qpack_int_prefix_encoding() {
        // Small values fit the prefix; boundary triggers the continuation byte.
        let mut b = Vec::new();
        qpack_int(&mut b, 0x20, 3, 6); // name-len 6, 3-bit prefix
        assert_eq!(b, vec![0x26]);
        b.clear();
        qpack_int(&mut b, 0x20, 3, 14); // 14 = 7 (max) + 7 continuation
        assert_eq!(b, vec![0x27, 0x07]);
        b.clear();
        qpack_int(&mut b, 0x00, 7, 9); // value-len 9, 7-bit prefix
        assert_eq!(b, vec![0x09]);
    }

    /// A benign HTTP/3 probe (a `GET /` with no `connect-udp` marker) must get a
    /// well-formed nginx 404 - never the silent hang that fingerprints the
    /// bridge (F11-M).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn h3_benign_probe_gets_404() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ep = h3_server_endpoint("127.0.0.1:0".parse().unwrap(), "h3.test", None).unwrap();
        let addr = ep.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let incoming = ep.accept().await.expect("incoming");
            let conn = incoming.await.expect("server handshake");
            let res = h3_server_accept_conn(conn).await;
            assert!(
                matches!(res, Err(TransportError::Auth(_))),
                "a benign probe must not authenticate as a Mirage session"
            );
            // Hold the endpoint until the client has read its response.
            tokio::time::sleep(Duration::from_millis(400)).await;
        });

        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_quinn_config().unwrap());
        let conn = endpoint
            .connect(addr, "h3.test")
            .unwrap()
            .await
            .expect("client connect");
        // Bind the control stream so it stays open for the whole test (dropping
        // it would finish the critical stream, RFC 9114 §6.2.1).
        let _control = send_control_settings(&conn)
            .await
            .expect("control settings");
        let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");

        // A stock GET / request - well-formed HEADERS with no CONNECT-UDP marker.
        let mut qpack = vec![0x00, 0x00];
        qpack_lit(&mut qpack, ":method", "GET");
        qpack_lit(&mut qpack, ":path", "/");
        qpack_lit(&mut qpack, ":scheme", "https");
        qpack_lit(&mut qpack, ":authority", "h3.test");
        assert!(
            !contains_subsequence(&qpack, CONNECT_UDP_MARKER),
            "the benign request must not carry the marker"
        );
        let mut hdr = Vec::new();
        put_varint(&mut hdr, FRAME_HEADERS);
        put_varint(&mut hdr, qpack.len() as u64);
        hdr.extend_from_slice(&qpack);
        send.write_all(&hdr).await.expect("write benign headers");

        // Response: HEADERS(:status 404) then DATA(nginx body).
        let rtype = read_varint(&mut recv).await.expect("resp frame type");
        assert_eq!(rtype, FRAME_HEADERS, "response must open with HEADERS");
        let rlen = read_varint(&mut recv).await.expect("resp headers len") as usize;
        let mut rhdr = vec![0u8; rlen];
        recv.read_exact(&mut rhdr).await.expect("read resp headers");
        assert_eq!(&rhdr[..3], &[0x00, 0x00, 0xC0 | 27], "must be :status 404");
        // F36: a real nginx origin always sends `server` + `date`; the cover
        // must too, and the date must be an RFC 7231 GMT fixdate.
        assert!(
            contains_subsequence(&rhdr, b"nginx"),
            "response must carry `server: nginx`"
        );
        assert!(
            contains_subsequence(&rhdr, b"date"),
            "response must carry a `date` header (F36)"
        );
        assert!(
            contains_subsequence(&rhdr, b"GMT"),
            "date must be an RFC 7231 IMF-fixdate"
        );

        let dtype = read_varint(&mut recv).await.expect("data frame type");
        assert_eq!(dtype, FRAME_DATA, "body must be a DATA frame");
        let dlen = read_varint(&mut recv).await.expect("data len") as usize;
        let mut body = vec![0u8; dlen];
        recv.read_exact(&mut body).await.expect("read body");
        assert_eq!(
            body,
            BENIGN_404_BODY.as_bytes(),
            "body must be the nginx 404"
        );

        server.await.unwrap();
        drop(endpoint);
    }

    /// Full QUIC + HTTP/3 client<->server roundtrip carrying a large payload
    /// (exercises DATA-frame splitting + the incremental reader).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn h3_roundtrip_large_payload() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ep = h3_server_endpoint("127.0.0.1:0".parse().unwrap(), "h3.test", None).unwrap();
        let addr = ep.local_addr().unwrap();

        let up: Vec<u8> = (0..50_000usize).map(|i| (i % 251) as u8).collect();
        let down: Vec<u8> = (0..50_000usize)
            .map(|i| ((i * 5 + 1) % 251) as u8)
            .collect();
        let up_c = up.clone();
        let down_c = down.clone();

        let server = tokio::spawn(async move {
            let incoming = ep.accept().await.expect("incoming");
            let conn = incoming.await.expect("server handshake");
            let mut s = h3_server_accept_conn(conn).await.expect("accept h3");
            let mut got = vec![0u8; up_c.len()];
            s.read_exact(&mut got).await.expect("server read");
            assert_eq!(got, up_c, "server payload mismatch");
            s.write_all(&down_c).await.expect("server write");
            s.flush().await.expect("server flush");
            // hold until client done
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let mut c = h3_client_connect(
            addr,
            "h3.test",
            "h3.test",
            "/.well-known/masque/udp/bridge.example/4433/",
            Duration::from_secs(5),
            None,
        )
        .await
        .expect("client connect");
        c.write_all(&up).await.expect("client write");
        c.flush().await.expect("client flush");
        let mut got = vec![0u8; down.len()];
        c.read_exact(&mut got).await.expect("client read");
        assert_eq!(got, down, "client payload mismatch");

        server.await.unwrap();
    }
}
