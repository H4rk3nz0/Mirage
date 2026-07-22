//! HTTP SDP signaling - a concrete [`Signaling`] rendezvous plus the bridge-side
//! offer/answer HTTP helpers, so the WebRTC carrier is usable by a daemon
//! without inventing a broker.
//!
//! The exchange is one HTTP round trip shaped like a real WHIP (RFC 9725)
//! `application/sdp` POST from a browser `fetch()`:
//!
//! ```text
//!   client --> POST <path> HTTP/1.1  (Chrome persona; body = SDP) --> bridge
//!   client <-- 200 OK               (body = SDP)                   <-- bridge
//! ```
//!
//! Two fidelity properties matter here (#13):
//!   * The request carries a full Chromium-family persona (`User-Agent`,
//!     `Accept`, `Sec-Fetch-*`, client hints, `Accept-Encoding/-Language`) -
//!     a bare, UA-less POST is itself the tell the meek carrier fixed.
//!   * The `Content-Type: application/sdp` body actually PARSES as SDP. Since
//!     red-team #10 the payload is a sealed AEAD blob, not cleartext SDP, so we
//!     carry its base64 inside a minimal SDP session description ([`encode_sdp_envelope`])
//!     rather than shipping opaque bytes under a media type that claims SDP.
//!
//! Hand-rolled HTTP over the workspace's plain sockets (no reqwest/hyper), the
//! same discipline meek/crtsh use. The ICE/DTLS/SCTP data channel itself flows
//! separately over UDP once both sides hold each other's SDP.

// HTTP header/body slicing at computed CRLFCRLF offsets - same allow the other
// hand-rolled-HTTP parsers use.
#![allow(clippy::indexing_slicing)]

use std::net::SocketAddr;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
// No-pad base64 for the SDP `ice-pwd` payload: `=` is NOT an ICE character
// (RFC 5245 `ice-char = ALPHA / DIGIT / "+" / "/"`), but the rest of the base64
// alphabet is, so a padless base64 value is a syntactically-valid ice-pwd.
use base64::engine::general_purpose::STANDARD_NO_PAD as B64_NP;
use base64::Engine as _;
use mirage_crypto::chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use mirage_crypto::x25519_dalek::{PublicKey, StaticSecret};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::imp::{Signaling, WebRtcError};

/// Content type for the signaling body. Kept as `application/sdp` for three
/// reasons: (1) it is a genuinely realistic shape - real WHIP (RFC 9725) clients
/// POST `application/sdp` offers; (2) the bridge's protocol-mux routes WebRTC by
/// peeking for this exact media type (`application/octet-stream` would fall
/// through to the meek handler); (3) it lets the body parse as SDP. The body is
/// a SEALED AEAD blob (red-team #10) - a censor cannot read the ICE ufrag/pwd +
/// DTLS cert fingerprint out of the POST to correlate it to the UDP/DTLS flow -
/// so #13 wraps that blob's base64 in a minimal SDP session description
/// ([`encode_sdp_envelope`]) so a semantic DPI that parses the declared media
/// type finds SDP, not opaque bytes under a false `application/sdp` claim.
const SIGNALING_CONTENT_TYPE: &str = "application/sdp";
/// Hard cap on a signaling body we'll read - offers/answers are a few KiB, and
/// the SDP envelope's base64 inflates that ~1.33x, still far under this bound.
const MAX_SDP_BYTES: usize = 64 * 1024;

/// SDP attribute line that carries the base64 of the sealed signaling blob. The
/// envelope is a minimal, syntactically-valid session description; this is the
/// one line the peer reads the payload back out of ([`decode_sdp_envelope`]).
const SDP_PAYLOAD_ATTR: &str = "a=x-webrtc-session:";

/// blake3 context for the ephemeral-static ECDH -> SDP-seal-key KDF (#10 v2).
const SDP_SEAL_CONTEXT: &str = "mirage webrtc sdp seal v2";

/// Derive the SDP-seal key from an X25519 ECDH shared secret.
///
/// The seal key is bound to a per-exchange **ephemeral-static** DH: the client
/// generates a fresh ephemeral X25519 keypair and DHs against the bridge's
/// static public key; the bridge DHs its static secret against the transmitted
/// ephemeral public key. The shared secret - and therefore this key - is known
/// only to the two endpoints. This is the fix for red-team #10: the earlier
/// `blake3(bridge_public_pk)` scheme let any discovery-watcher who knew the
/// bridge's *public* key recompute the seal key and read the ICE ufrag/pwd +
/// DTLS fingerprint out of the SDP, then correlate it to the UDP/DTLS flow.
fn seal_key_from_shared(shared: &[u8; 32]) -> [u8; 32] {
    mirage_crypto::blake3::derive_key(SDP_SEAL_CONTEXT, shared)
}

/// Length of the cleartext ephemeral X25519 public key prepended to a sealed
/// offer body. A bare Curve25519 point is uniform-random-looking on the wire.
const EPH_PK_LEN: usize = 32;

/// Seal an SDP body: `nonce(12) || ChaCha20-Poly1305(sdp)`. A fresh random nonce
/// per exchange (signaling is low-volume; 96-bit random nonces are collision-safe
/// far beyond any session's handful of offers).
fn seal_sdp(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, WebRtcError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| WebRtcError::Signaling("seal key".into()))?;
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).map_err(|_| WebRtcError::Signaling("csprng".into()))?;
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| WebRtcError::Signaling("sdp seal".into()))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a sealed SDP body produced by [`seal_sdp`]. Auth failure (wrong key /
/// tamper) is rejected.
fn open_sdp(key: &[u8; 32], blob: &[u8]) -> Result<String, WebRtcError> {
    if blob.len() < 12 {
        return Err(WebRtcError::Signaling("sealed SDP too short".into()));
    }
    let (nonce, ct) = blob.split_at(12);
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| WebRtcError::Signaling("open key".into()))?;
    let pt = cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| WebRtcError::Signaling("sealed SDP auth failed".into()))?;
    String::from_utf8(pt).map_err(|_| WebRtcError::Signaling("SDP not UTF-8".into()))
}

/// Wrap an opaque sealed blob as a minimal, syntactically-valid SDP body (#13).
///
/// `Content-Type: application/sdp` claims the body is SDP; a semantic DPI that
/// parses the declared media type would find non-SDP bytes if we shipped the raw
/// sealed blob (a zero-false-positive selector). So the blob's base64 rides in a
/// minimal SDP session description that begins `v=0` and parses as SDP.
///
/// The skeleton is deliberately session-level only: it carries NO `a=ice-ufrag`
/// / `a=ice-pwd` / `a=fingerprint`, because those are exactly the values #10
/// stripped from the wire (a passive watcher could otherwise correlate them to
/// the STUN/DTLS UDP flow). Faking them would either re-leak real values or
/// mismatch the actual flow, so they stay out - the residual is that a deep
/// WHIP-offer validator would see a session-only description, not a full offer.
fn encode_sdp_envelope(blob: &[u8]) -> String {
    // A random 63-bit session id for the `o=` line, like a real origin field.
    let mut sid = [0u8; 8];
    let _ = getrandom::fill(&mut sid);
    let sess_id = u64::from_be_bytes(sid) >> 1;

    // Emit a STRUCTURALLY-REAL WebRTC data-channel offer, and carry the sealed
    // signaling blob as the value of the STANDARD `a=ice-pwd` attribute rather
    // than a Mirage-unique `a=x-...` line a censor can zero-false-positive grep
    // for. base64-no-pad keeps the value inside the ICE character set. A short
    // random ufrag + a plausible sha-256 fingerprint round out an offer that
    // parses as an ordinary data-channel offer.
    let payload = B64_NP.encode(blob);
    let mut ufrag = [0u8; 3];
    let _ = getrandom::fill(&mut ufrag);
    let ufrag = B64_NP.encode(ufrag); // ~4 ICE chars, like a real ufrag
    let mut fp = [0u8; 32];
    let _ = getrandom::fill(&mut fp);
    let fingerprint = fp
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    format!(
        "v=0\r\n\
         o=- {sess_id} 2 IN IP4 0.0.0.0\r\n\
         s=-\r\n\
         t=0 0\r\n\
         a=group:BUNDLE 0\r\n\
         m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
         c=IN IP4 0.0.0.0\r\n\
         a=setup:actpass\r\n\
         a=mid:0\r\n\
         a=sctp-port:5000\r\n\
         a=ice-ufrag:{ufrag}\r\n\
         a=ice-pwd:{payload}\r\n\
         a=fingerprint:sha-256 {fingerprint}\r\n"
    )
}

/// Recover the sealed blob from a body produced by [`encode_sdp_envelope`].
fn decode_sdp_envelope(body: &[u8]) -> Result<Vec<u8>, WebRtcError> {
    let sdp = String::from_utf8_lossy(body);
    // The sealed blob rides the standard `a=ice-pwd:` attribute (base64-no-pad).
    // Accept the legacy `a=x-webrtc-session:` line too so an in-flight peer on the
    // old format still interoperates during upgrade.
    let payload = sdp
        .lines()
        .find_map(|l| {
            let l = l.trim();
            l.strip_prefix("a=ice-pwd:")
                .or_else(|| l.strip_prefix(SDP_PAYLOAD_ATTR))
        })
        .ok_or_else(|| WebRtcError::Signaling("SDP payload attribute missing".into()))?;
    // Try no-pad first (new), then padded (legacy x- line).
    B64_NP
        .decode(payload)
        .or_else(|_| B64.decode(payload))
        .map_err(|_| WebRtcError::Signaling("SDP payload not base64".into()))
}

/// A realistic, internally-consistent Chromium-family request persona for the
/// signaling POST (#13). A real browser `fetch()` that POSTs an SDP offer (WHIP)
/// emits the full client-hint + `Sec-Fetch-*` + `Accept-*` block, not a bare (or
/// absent) `User-Agent`. Mirrors the persona the meek carrier renders in its
/// `do_http_post`; one is chosen per exchange so the identity varies across
/// connections without changing mid-flow. All entries are Chromium-family so the
/// single render path in [`render_signaling_post`] is byte-consistent.
struct ClientPersona {
    user_agent: &'static str,
    sec_ch_ua: &'static str,
    platform: &'static str,
    mobile: &'static str,
    accept_language: &'static str,
    accept_encoding: &'static str,
}

/// `sec-ch-ua` brand string shared by the plain-Chrome personas.
const CH_UA_CHROME: &str =
    "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"";

/// Per-connection rotation pool, all Chromium-family (matches the meek pool).
const CLIENT_PERSONAS: &[ClientPersona] = &[
    ClientPersona {
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        sec_ch_ua: CH_UA_CHROME,
        platform: "\"Windows\"",
        mobile: "?0",
        accept_language: "en-US,en;q=0.9",
        accept_encoding: "gzip, deflate, br, zstd",
    },
    ClientPersona {
        user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        sec_ch_ua: CH_UA_CHROME,
        platform: "\"macOS\"",
        mobile: "?0",
        accept_language: "en-US,en;q=0.9",
        accept_encoding: "gzip, deflate, br, zstd",
    },
    ClientPersona {
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
        sec_ch_ua: "\"Microsoft Edge\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
        platform: "\"Windows\"",
        mobile: "?0",
        accept_language: "en-US,en;q=0.9",
        accept_encoding: "gzip, deflate, br, zstd",
    },
    ClientPersona {
        user_agent: "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
        sec_ch_ua: CH_UA_CHROME,
        platform: "\"Android\"",
        mobile: "?1",
        accept_language: "en-US,en;q=0.9",
        accept_encoding: "gzip, deflate, br, zstd",
    },
];

impl ClientPersona {
    /// Choose a persona for one exchange (unbiased over the 4-entry pool).
    fn pick() -> &'static ClientPersona {
        let mut b = [0u8; 1];
        let _ = getrandom::fill(&mut b);
        &CLIENT_PERSONAS[(b[0] as usize) % CLIENT_PERSONAS.len()]
    }
}

/// Render the WHIP-shaped signaling POST header block for `persona`. The header
/// set + order mirror a real Chromium `fetch()` POST (see meek's `do_http_post`);
/// `Accept: application/sdp` is the WHIP client's real expectation of an SDP
/// answer. Split out so it can be asserted in a unit test.
fn render_signaling_post(
    path: &str,
    host: &str,
    persona: &ClientPersona,
    content_len: usize,
) -> String {
    let ua = persona.user_agent;
    let sec_ch_ua = persona.sec_ch_ua;
    let mobile = persona.mobile;
    let platform = persona.platform;
    let accept_encoding = persona.accept_encoding;
    let accept_language = persona.accept_language;
    format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Connection: keep-alive\r\n\
         Content-Length: {content_len}\r\n\
         sec-ch-ua: {sec_ch_ua}\r\n\
         sec-ch-ua-mobile: {mobile}\r\n\
         sec-ch-ua-platform: {platform}\r\n\
         User-Agent: {ua}\r\n\
         Content-Type: {SIGNALING_CONTENT_TYPE}\r\n\
         Accept: {SIGNALING_CONTENT_TYPE}\r\n\
         Origin: https://{host}\r\n\
         Sec-Fetch-Site: same-origin\r\n\
         Sec-Fetch-Mode: cors\r\n\
         Sec-Fetch-Dest: empty\r\n\
         Referer: https://{host}/\r\n\
         Accept-Encoding: {accept_encoding}\r\n\
         Accept-Language: {accept_language}\r\n\r\n",
    )
}

/// A plausible per-exchange `Server` header for the signaling response. WHIP
/// answers come back from an HTTPS edge, so a frozen `Server:` is itself a tell;
/// response headers are far less fingerprinted than the client request, so a
/// small pool suffices.
const SERVER_PERSONAS: &[&str] = &["cloudflare", "nginx", "Apache"];

/// Choose a `Server` header value for one response.
fn pick_server_persona() -> &'static str {
    let mut b = [0u8; 1];
    let _ = getrandom::fill(&mut b);
    SERVER_PERSONAS[(b[0] as usize) % SERVER_PERSONAS.len()]
}

/// Client-side [`Signaling`] that POSTs the offer to a bridge's HTTP signaling
/// endpoint and reads back the answer. `host` is the `Host:` header (a CDN front
/// domain is fine); `addr` is the actual TCP dial target.
pub struct HttpSignaling {
    /// TCP dial target (the bridge, or a fronting reflector).
    pub addr: SocketAddr,
    /// HTTP `Host` header value.
    pub host: String,
    /// Request path the bridge routes to its WebRTC signaling handler.
    pub path: String,
    /// Bridge X25519 static public key (from the invite). Each `exchange`
    /// derives a fresh SDP-seal key by `DHing` a per-exchange ephemeral secret
    /// against this, so the seal key is secret from a discovery-watcher (#10).
    bridge_static_pk: [u8; 32],
}

impl HttpSignaling {
    /// Construct a signaling client. `bridge_static_pk` is the bridge's X25519
    /// static public key (from the invite); each SDP exchange DHs a fresh
    /// ephemeral secret against it to derive a per-exchange seal key, so the
    /// offer/answer bodies are opaque AND unrecoverable by a passive watcher
    /// who only knows the bridge's public key (red-team #10).
    #[must_use]
    pub fn new(
        addr: SocketAddr,
        host: impl Into<String>,
        path: impl Into<String>,
        bridge_static_pk: &[u8; 32],
    ) -> Self {
        Self {
            addr,
            host: host.into(),
            path: path.into(),
            bridge_static_pk: *bridge_static_pk,
        }
    }
}

#[async_trait]
impl Signaling for HttpSignaling {
    async fn exchange(&self, offer_sdp: String) -> Result<String, WebRtcError> {
        // Fresh ephemeral X25519 keypair for THIS exchange. DH against the
        // bridge's static pk yields a seal key a discovery-watcher can't
        // recompute from the (public) bridge key alone (#10).
        let mut eph_seed = [0u8; 32];
        getrandom::fill(&mut eph_seed).map_err(|_| WebRtcError::Signaling("csprng".into()))?;
        let eph_sk = StaticSecret::from(eph_seed);
        let eph_pk = PublicKey::from(&eph_sk);
        let shared = eph_sk.diffie_hellman(&PublicKey::from(self.bridge_static_pk));
        let seal_key = seal_key_from_shared(shared.as_bytes());

        let mut sock = TcpStream::connect(self.addr)
            .await
            .map_err(|e| WebRtcError::Signaling(format!("connect: {e}")))?;
        // Seal the offer so the POST body carries no cleartext SDP (no ICE
        // ufrag/pwd or DTLS cert fingerprint on the wire) - #10. Sealed payload =
        // ephemeral pk (a bare Curve25519 point) || nonce || ct. That opaque blob
        // is then base64-wrapped in a minimal SDP session description so the body
        // actually parses as SDP under its `application/sdp` content type (#13).
        let sealed = seal_sdp(&seal_key, offer_sdp.as_bytes())?;
        let mut payload = Vec::with_capacity(EPH_PK_LEN + sealed.len());
        payload.extend_from_slice(eph_pk.as_bytes());
        payload.extend_from_slice(&sealed);
        let body = encode_sdp_envelope(&payload).into_bytes();
        // Full Chromium `fetch()` persona (#13): a bare/absent User-Agent POSTing
        // to a signaling endpoint is itself the tell meek fixed.
        let req = render_signaling_post(&self.path, &self.host, ClientPersona::pick(), body.len());
        sock.write_all(req.as_bytes())
            .await
            .map_err(|e| WebRtcError::Signaling(format!("write: {e}")))?;
        sock.write_all(&body)
            .await
            .map_err(|e| WebRtcError::Signaling(format!("write body: {e}")))?;
        sock.flush()
            .await
            .map_err(|e| WebRtcError::Signaling(format!("flush: {e}")))?;

        // Content-Length-delimited read (NOT read-to-close): the bridge keeps
        // the signaling socket open while its data channel establishes, so
        // waiting for EOF here would deadlock against our own answer.
        let (head, body) = read_http(&mut sock).await?;
        let status = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|c| c.parse::<u16>().ok())
            .ok_or_else(|| WebRtcError::Signaling("bad status line".into()))?;
        if !(200..300).contains(&status) {
            return Err(WebRtcError::Signaling(format!("HTTP {status} from broker")));
        }
        // Answer is the same shape as the offer: an SDP envelope whose payload is
        // the sealed answer, sealed under the same per-exchange key (#10/#13).
        let sealed_answer = decode_sdp_envelope(&body)?;
        open_sdp(&seal_key, &sealed_answer)
    }
}

/// Read one HTTP request off `stream` and return `(path, offer_sdp, seal_key)`.
/// Bridge side. Bounds the body at [`MAX_SDP_BYTES`].
///
/// The POST body is an SDP envelope ([`encode_sdp_envelope`]) whose base64
/// payload decodes to `ephemeral_pk(32) || nonce || ciphertext`. We DH our
/// static secret against the client's ephemeral public key to recover the
/// per-exchange seal key (#10), then open the offer. The returned `seal_key`
/// MUST be passed to [`write_answer_response`] so the answer is sealed under the
/// same key.
pub async fn read_offer_request<S>(
    stream: &mut S,
    bridge_static_sk: &StaticSecret,
) -> Result<(String, String, [u8; 32]), WebRtcError>
where
    S: AsyncRead + Unpin,
{
    let (head, body) = read_http(stream).await?;
    let path = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_string();
    // Unwrap the SDP envelope back to the sealed payload (#13), then recover the
    // per-exchange seal key via ephemeral-static ECDH (#10).
    let payload = decode_sdp_envelope(&body)?;
    if payload.len() < EPH_PK_LEN {
        return Err(WebRtcError::Signaling(
            "offer body missing ephemeral key".into(),
        ));
    }
    let mut eph_pk = [0u8; EPH_PK_LEN];
    eph_pk.copy_from_slice(&payload[..EPH_PK_LEN]);
    let shared = bridge_static_sk.diffie_hellman(&PublicKey::from(eph_pk));
    let seal_key = seal_key_from_shared(shared.as_bytes());
    let offer = open_sdp(&seal_key, &payload[EPH_PK_LEN..])?;
    Ok((path, offer, seal_key))
}

/// Read one HTTP message (request or response): headers to the blank line, then
/// exactly `Content-Length` body bytes. Content-Length-delimited so it never
/// waits on connection close.
async fn read_http<S>(stream: &mut S) -> Result<(String, Vec<u8>), WebRtcError>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > MAX_SDP_BYTES {
            return Err(WebRtcError::Signaling("http headers too large".into()));
        }
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|e| WebRtcError::Signaling(format!("read: {e}")))?;
        if n == 0 {
            return Err(WebRtcError::Signaling("closed before headers".into()));
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let content_len = header_value(&head, "content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    if content_len > MAX_SDP_BYTES {
        return Err(WebRtcError::Signaling("http body too large".into()));
    }
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_len {
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|e| WebRtcError::Signaling(format!("read body: {e}")))?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_len);
    Ok((head, body))
}

/// Write the answer SDP back as a `200 OK`. Bridge side.
///
/// Symmetric with the request (#13): the answer is sealed (#10), then its base64
/// wrapped in an SDP envelope so this direction, too, carries SDP under the
/// `application/sdp` content type rather than opaque bytes - and a per-exchange
/// `Server` header so the response is not a frozen tell.
pub async fn write_answer_response<S>(
    stream: &mut S,
    seal_key: &[u8; 32],
    answer_sdp: &str,
) -> Result<(), WebRtcError>
where
    S: AsyncWrite + Unpin,
{
    let sealed = seal_sdp(seal_key, answer_sdp.as_bytes())?;
    let body = encode_sdp_envelope(&sealed).into_bytes();
    let server = pick_server_persona();
    let resp = format!(
        "HTTP/1.1 200 OK\r\nServer: {server}\r\nContent-Type: {SIGNALING_CONTENT_TYPE}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len(),
    );
    stream
        .write_all(resp.as_bytes())
        .await
        .map_err(|e| WebRtcError::Signaling(format!("write resp: {e}")))?;
    stream
        .write_all(&body)
        .await
        .map_err(|e| WebRtcError::Signaling(format!("write answer: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| WebRtcError::Signaling(format!("flush: {e}")))?;
    Ok(())
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imp::{webrtc_answer, webrtc_dial};
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn http_message_framing_is_content_length_delimited() {
        // Parses head + exactly Content-Length body, WITHOUT waiting on close
        // (trailing bytes after the body are ignored, no EOF needed).
        let resp =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/sdp\r\nContent-Length: 3\r\n\r\nabcEXTRA";
        let mut s: &[u8] = resp;
        let (head, body) = read_http(&mut s).await.unwrap();
        assert!(head.starts_with("HTTP/1.1 200"));
        assert_eq!(body, b"abc");
    }

    #[tokio::test]
    async fn http_signaling_drives_a_real_webrtc_connection() {
        // A tiny bridge: accept one TCP conn, read the offer POST, run
        // webrtc_answer, write the answer, then establish the data channel.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_slot: Arc<Mutex<Option<crate::imp::WebRtcStream>>> = Arc::new(Mutex::new(None));
        let slot = server_slot.clone();
        // Bridge static keypair: the client knows the public half (from the
        // invite); the bridge holds the secret and recovers the per-exchange
        // seal key via ECDH against the client's ephemeral pk (#10).
        let bridge_sk = StaticSecret::from([0x5Au8; 32]);
        let bridge_pk = *PublicKey::from(&bridge_sk).as_bytes();

        let bridge = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let (_path, offer, seal_key) = read_offer_request(&mut sock, &bridge_sk).await.unwrap();
            let (answer, accept) = webrtc_answer(offer, &[], false, Duration::from_secs(20))
                .await
                .unwrap();
            write_answer_response(&mut sock, &seal_key, &answer)
                .await
                .unwrap();
            let stream = accept.established(Duration::from_secs(20)).await.unwrap();
            *slot.lock().unwrap() = Some(stream);
        });

        let signaling = HttpSignaling::new(addr, "bridge.local", "/webrtc/offer", &bridge_pk);
        let mut client = webrtc_dial(&signaling, &[], "data", false, Duration::from_secs(20))
            .await
            .unwrap();
        bridge.await.unwrap();

        let mut server = server_slot.lock().unwrap().take().unwrap();
        let msg = b"tunneled via http-signaled webrtc";
        client.write_all(msg).await.unwrap();
        client.flush().await.unwrap();
        let mut got = vec![0u8; msg.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(got, msg);
    }
}
