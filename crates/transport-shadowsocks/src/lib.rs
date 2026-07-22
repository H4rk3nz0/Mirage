//! Shadowsocks-2022 (`2022-blake3-chacha20-poly1305`) carrier transport
//! for Mirage.
//!
//! # Overview
//!
//! This crate implements the SS-2022 wire protocol as a **carrier** for
//! Mirage session bytes. It is *not* a general-purpose SOCKS proxy; it uses
//! SS-2022's AEAD-chunked framing to carry opaque Mirage session frames after
//! a short fixed-format handshake that establishes per-session subkeys.
//!
//! The variant implemented is `2022-blake3-chacha20-poly1305`:
//!
//! - **Key derivation:** BLAKE3 `derive_key` with the label
//!   `"shadowsocks 2022 session subkey"` over a 48-byte KDF input
//!   (`psk[32] || salt[16]`).
//! - **AEAD:** ChaCha20-Poly1305 with 96-bit counter nonces.
//! - **Chunk format:** length-AEAD (2 B encrypted) + payload-AEAD;
//!   counter increments by 2 per chunk (one increment per AEAD call).
//!
//! # Wire format (client -> bridge)
//!
//! ```text
//! +- Handshake ----------------------------------------------------------+
//! | request_salt[16]                                                      |
//! | encrypted_header = encrypt_chunk(session_subkey, ctr=0,              |
//! |   type[1]=0x00 | timestamp[8] | atyp[1]=0x01 |                       |
//! |   addr[4]=magic | port[2]=magic |                                    |
//! |   padding_len[2] | padding[N])                                        |
//! |   (magic addr/port are derived per-bridge from the PSK - see          |
//! |    `derive_ss2022_magic` - NOT a fixed cross-bridge constant.)        |
//! +-----------------------------------------------------------------------+
//! +- Response ------------------------------------------------------------+
//! | response_salt[16]                                                     |
//! | encrypted_response = encrypt_chunk(resp_subkey, ctr=0,               |
//! |   type[1]=0x01 | timestamp[8] | request_salt[16] | padding_len[2]=0) |
//! +-----------------------------------------------------------------------+
//! +- Data ----------------------------------------------------------------+
//! | Bidirectional AEAD-chunked stream; counter per side, starts at 2.    |
//! +-----------------------------------------------------------------------+
//! ```
//!
//! # Threat model fit
//!
//! - **T1 (signature DPI):** [ok] - The wire looks like uniform random bytes
//!   from byte 0; no distinguishable header, no TLS `ClientHello`, no HTTP.
//! - **T2 (active prober):** [ok] - Without the PSK an active prober cannot
//!   forge the first AEAD-encrypted chunk; the server simply closes on
//!   decryption failure.
//! - **T3 (ML on flow shape):** partial - AEAD chunking adds 18 bytes of
//!   overhead per chunk but does not shape the flow. Compose with a
//!   traffic-shaping layer for full T3 coverage.
//!
//! # Spec reference
//!
//! Shadowsocks 2022 edition specification:
//! <https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-1-shadowsocks-2022-edition.md>
//!
//! # Framing fidelity (NOT spec-interoperable) - audit #21
//!
//! This is a Mirage-only AEAD **carrier**: it borrows SS-2022's
//! `2022-blake3-chacha20-poly1305` chunk cipher (salt-derived subkey, counter
//! nonces, length-AEAD + payload-AEAD chunks) but **not** SS-2022's exact
//! request handshake framing. The spec's request stream is two distinct header
//! chunks - a fixed-length header chunk (`type | timestamp | length`, no length
//! prefix) followed by a separate variable-length header chunk. Mirage instead
//! seals the whole header as ONE generic data chunk via [`encrypt_chunk`] (an
//! 18-byte encrypted length field then the payload) and reads it back
//! symmetrically. Client and bridge agree, and nothing is passively visible
//! (all AEAD from byte 0), but a real SS-2022 parser will NOT interoperate with
//! this handshake. Do not mistake this crate for a spec-conformant SS-2022
//! implementation. (The full two-chunk framing was judged too invasive to
//! retrofit safely through the 0-RTT deferred-response state machine for a
//! LOW-severity, passively-invisible gap.)
//!
//! Capability bit: `SS2022_CAPABILITY_BIT` (bit 3, Mirage transport registry).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use async_trait::async_trait;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use mirage_discovery::wire::Endpoint;
use mirage_transport::{ClientTransport, DialInputs, DuplexStream, SeenNonceSet, TransportError};
use std::pin::Pin;
use std::sync::OnceLock;
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

// Constants

/// Capability bit for the Shadowsocks-2022 transport in the Mirage transport
/// registry (bit 3).
pub const SS2022_CAPABILITY_BIT: u32 = 1 << 3;

/// Length of the per-session salt used in key derivation.
const SALT_LEN: usize = 16;

/// BLAKE3 KDF label for session subkey derivation (SS-2022 §2.3).
const SESSION_SUBKEY_LABEL: &str = "shadowsocks 2022 session subkey";

/// BLAKE3 domain-separation label for the per-bridge magic destination KDF.
const MAGIC_DEST_LABEL: &str = "mirage ss2022 magic dest v1";

/// Address type byte for IPv4 in the SS-2022 header.
const ATYP_IPV4: u8 = 0x01;

/// Request header type byte (client -> bridge).
const HEADER_TYPE_REQUEST: u8 = 0x00;

/// Response header type byte (bridge -> client).
const HEADER_TYPE_RESPONSE: u8 = 0x01;

/// AEAD tag length for ChaCha20-Poly1305 (bytes).
const TAG_LEN: usize = 16;

/// Length of the encrypted length prefix field on the wire: 2 plaintext bytes
/// plus a 16-byte Poly1305 tag.
const ENC_LEN_FIELD: usize = 2 + TAG_LEN; // 18 bytes

/// Maximum number of bytes allowed in the request-header padding (0-64). Bounded by
/// the mux's single 192-byte non-consuming peek (`auth_buf`): salt, length chunk, fixed
/// header, and tag total ~68 bytes, so the padded header must stay well under 192 or the
/// peek returns NeedMoreBytes and the connection falls through to cover. Reference
/// SS-2022 clients pad wider (~900); matching that needs the mux peek to re-read on
/// NeedMoreBytes first (a larger change), so this stays capped for now.
const MAX_PADDING: u16 = 64;

/// Maximum plaintext payload per SS-2022 data chunk. The on-wire length field
/// is 2 bytes, so a single chunk can carry at most 0xFFFF; the Shadowsocks-2022
/// spec caps it at 0x3FFF. Writes larger than this MUST be split across
/// multiple chunks - otherwise the `len as u16` field overflows/truncates and
/// the peer desyncs (this is why large transfers over SS-2022 silently broke
/// while small ones worked).
const MAX_PAYLOAD_CHUNK: usize = 0x3FFF;

/// Timestamp drift tolerance in seconds. Requests whose timestamp differs
/// from the server's clock by more than this value are rejected.
const TIMESTAMP_TOLERANCE_SECS: u64 = 30;

/// TTL for the process-wide request-salt replay set (audit #10).
///
/// A captured request still passes the `+/-TIMESTAMP_TOLERANCE_SECS` check for a
/// window that can start up to one tolerance *before* the entry is first seen,
/// so an entry must live at least `2 * TIMESTAMP_TOLERANCE_SECS` to cover the
/// whole replayable period; 300s (matching the bridge's other replay sets)
/// leaves wide margin. Past the window a replay is rejected by the timestamp
/// check anyway, so a larger TTL only wastes memory (the set is capacity-capped
/// regardless).
const REPLAY_TTL_SECS: u64 = 300;

// Key derivation

/// Derive a 32-byte session subkey from a pre-shared key and a per-session
/// salt using BLAKE3's key-derivation function.
///
/// Both the client and bridge independently derive the same subkey from the
/// same `(psk, salt)` pair. The salt is transmitted in the clear as the first
/// 16 bytes of each direction's stream.
///
/// Key material layout: `psk[32] || salt[16]` -> 48 bytes fed to
/// `blake3::derive_key("shadowsocks 2022 session subkey", ...)`.
pub fn derive_session_key(psk: &[u8; 32], salt: &[u8; 16]) -> [u8; 32] {
    // Zeroized on drop - never leave a verbatim copy of the long-lived PSK in
    // freed stack memory after each session-key derivation.
    let mut key_material = Zeroizing::new([0u8; 48]); // 32 + 16
    key_material[..32].copy_from_slice(psk);
    key_material[32..].copy_from_slice(salt);
    blake3::derive_key(SESSION_SUBKEY_LABEL, &key_material[..])
}

/// Proteus pace seed from the request-salt session subkey. Both endpoints derive the
/// same subkey (`derive_session_key(psk, request_salt)`), so both get the same seed.
fn ss_pace_seed(subkey: &[u8; 32]) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&subkey[..8]);
    u64::from_le_bytes(b)
}

/// Derive the per-bridge "magic" destination (IPv4 address + port) that the
/// SS-2022 request header carries where a real SS-2022/SOCKS request carries the
/// client's varying target host:port (audit #27).
///
/// A Mirage carrier has no real target, so it embeds a sentinel the bridge
/// recognizes. A hard-coded constant (the former `127.0.0.2:8192`) was an
/// exact-match value *identical across every bridge*: after any outer-layer
/// compromise it is a cross-bridge Mirage fingerprint. Deriving it from the
/// shared PSK gives each bridge a distinct value while both ends still agree
/// (client and bridge share the PSK). The value never appears in cleartext (it
/// lives inside the AEAD-sealed header) and the bridge never dials it - it is
/// only a sentinel - so it is mapped into the non-routable RFC 2544 benchmarking
/// range `198.18.0.0/15`, which can never escape to a real host.
///
/// Deterministic: the same PSK always yields the same `(addr, port)`, so the
/// client-embed and server-verify sides match without any extra wire exchange.
fn derive_ss2022_magic(psk: &[u8; 32]) -> ([u8; 4], u16) {
    // Array-destructure (no indexing) the first bytes of the KDF output.
    let [b0, b1, b2, b3, b4, ..] = blake3::derive_key(MAGIC_DEST_LABEL, psk);
    // 198.18.0.0/15 (RFC 2544, non-routable): 2 * 256 * 256 distinct addresses.
    let addr = [198, 18 | (b0 & 0x01), b1, b2];
    // Port in 1024..=65535: non-zero and unprivileged (a plausible dest port).
    let port = 1024 + (u16::from_be_bytes([b3, b4]) % (65535 - 1024 + 1));
    (addr, port)
}

// Counter nonce

/// Build a 12-byte ChaCha20-Poly1305 nonce from a 64-bit counter.
///
/// Layout: `[0x00, 0x00, 0x00, 0x00] || counter.to_be_bytes()[8]`.
/// The four zero bytes are the "constant" half of the standard IETF nonce
/// format (RFC 8439 §2.3); the counter occupies the low 8 bytes in
/// big-endian order.
pub fn counter_nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

// AEAD helpers

/// Encrypt a single SS-2022 chunk.
///
/// Each chunk consists of two AEAD operations:
/// 1. Encrypt the 2-byte big-endian payload length -> 18-byte ciphertext.
/// 2. Encrypt the payload -> `len + 16` bytes ciphertext.
///
/// The counter increments by 2 across the two calls so that the nonces
/// used by the length and payload encryptions are never reused within a
/// session.
///
/// Returns `len_ct || pay_ct`.
fn encrypt_chunk(subkey: &[u8; 32], counter: u64, plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(subkey));

    let len_bytes = (plaintext.len() as u16).to_be_bytes();
    let len_nonce = Nonce::from(counter_nonce(counter));
    let len_ct = cipher
        .encrypt(&len_nonce, len_bytes.as_ref())
        .expect("ChaCha20-Poly1305 encrypt length: infallible for valid key/nonce");

    let pay_nonce = Nonce::from(counter_nonce(counter + 1));
    let pay_ct = cipher
        .encrypt(&pay_nonce, plaintext)
        .expect("ChaCha20-Poly1305 encrypt payload: infallible for valid key/nonce");

    let mut out = Vec::with_capacity(len_ct.len() + pay_ct.len());
    out.extend_from_slice(&len_ct);
    out.extend_from_slice(&pay_ct);
    out
}

/// Decrypt a single SS-2022 chunk from a flat byte slice.
///
/// Expects `buf` to be exactly `ENC_LEN_FIELD + payload_len + TAG_LEN` bytes
/// where `payload_len` is decoded from the first `ENC_LEN_FIELD` bytes.
///
/// Returns an error if either AEAD open fails.
///
/// Used in unit tests for roundtrip verification; the streaming path uses
/// `read_chunk` and the peek path inlines its own two-nonce decrypt.
#[cfg(test)]
fn decrypt_chunk_from_slice(
    subkey: &[u8; 32],
    counter: u64,
    len_ct: &[u8; ENC_LEN_FIELD],
    pay_ct: &[u8],
) -> Result<Vec<u8>, TransportError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(subkey));

    let len_nonce = Nonce::from(counter_nonce(counter));
    let len_plain = cipher
        .decrypt(&len_nonce, len_ct.as_ref())
        .map_err(|_| TransportError::Auth("SS-2022: AEAD open failed on length field"))?;

    let expected_len = u16::from_be_bytes(
        len_plain
            .as_slice()
            .try_into()
            .expect("AEAD output is always 2 bytes for 2-byte plaintext"),
    ) as usize;
    if pay_ct.len() != expected_len + TAG_LEN {
        return Err(TransportError::Wire(
            "SS-2022: payload ciphertext length does not match decrypted length field",
        ));
    }

    let pay_nonce = Nonce::from(counter_nonce(counter + 1));
    let payload = cipher
        .decrypt(&pay_nonce, pay_ct)
        .map_err(|_| TransportError::Auth("SS-2022: AEAD open failed on payload"))?;

    Ok(payload)
}

/// Result of a non-consuming SS-2022 freshness peek ([`ss2022_peek_verify_fresh`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ss2022PeekVerdict {
    /// The peeked bytes decrypt to a well-formed, in-window request header.
    /// Safe to commit to the consuming [`ss2022_server_auth`].
    Fresh,
    /// Not enough bytes peeked yet to decrypt the whole header. The caller
    /// should treat this like "not SS-2022" and fall through to cover rather
    /// than commit (a genuine client sends the full header promptly).
    NeedMoreBytes,
    /// Decrypts but is NOT a fresh, well-formed request (bad AEAD, wrong type,
    /// or a stale/replayed timestamp outside +/-30s). The caller MUST fall
    /// through to cover, NOT commit - committing would reach the consuming
    /// handshake whose failure path is a bridge distinguisher (red-team round 2).
    Reject,
}

/// NON-CONSUMING freshness check for the SS-2022 opening (red-team round 2).
///
/// The mux's cheap peek only AEAD-decrypts the length chunk, so a passively
/// captured `salt||header` still passes it after the mux's salt-replay entry
/// expires; committing to the consuming server handshake then fails on the now
/// stale timestamp and drops the socket SILENTLY - which diverges from every
/// other auth-failure path (they fall through to the cover site), fingerprinting
/// the bridge. This validates the timestamp on the PEEKED bytes (no consumption),
/// so a stale replay is caught here and the caller falls through to cover exactly
/// like garbage does.
///
/// `now_secs` is the current Unix time. Returns [`Ss2022PeekVerdict`].
pub fn ss2022_peek_verify_fresh(psk: &[u8; 32], peeked: &[u8], now_secs: u64) -> Ss2022PeekVerdict {
    if peeked.len() < SALT_LEN + ENC_LEN_FIELD {
        return Ss2022PeekVerdict::NeedMoreBytes;
    }
    let salt: [u8; SALT_LEN] = match peeked[..SALT_LEN].try_into() {
        Ok(s) => s,
        Err(_) => return Ss2022PeekVerdict::Reject,
    };
    let subkey = derive_session_key(psk, &salt);

    // Length chunk (counter 0) -> header plaintext length.
    let len_ct: [u8; ENC_LEN_FIELD] = match peeked[SALT_LEN..SALT_LEN + ENC_LEN_FIELD].try_into() {
        Ok(c) => c,
        Err(_) => return Ss2022PeekVerdict::Reject,
    };
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&subkey));
    let len_plain = match cipher.decrypt(&Nonce::from(counter_nonce(0)), len_ct.as_ref()) {
        Ok(p) => p,
        // Not a valid SS-2022 opening under this PSK at all.
        Err(_) => return Ss2022PeekVerdict::Reject,
    };
    let header_len = {
        let b: [u8; 2] = match len_plain.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => return Ss2022PeekVerdict::Reject,
        };
        u16::from_be_bytes(b) as usize
    };

    // Need the full payload chunk (header_len + tag) in the peek buffer.
    let payload_start = SALT_LEN + ENC_LEN_FIELD;
    let payload_end = payload_start + header_len + TAG_LEN;
    if peeked.len() < payload_end {
        return Ss2022PeekVerdict::NeedMoreBytes;
    }
    // Payload chunk uses counter 1.
    let header = match cipher.decrypt(
        &Nonce::from(counter_nonce(1)),
        &peeked[payload_start..payload_end],
    ) {
        Ok(h) => h,
        Err(_) => return Ss2022PeekVerdict::Reject,
    };

    // type[1]=0x00 (request) | timestamp[8] | ...
    if header.len() < 1 + 8 || header[0] != 0x00 {
        return Ss2022PeekVerdict::Reject;
    }
    let ts_bytes: [u8; 8] = match header[1..9].try_into() {
        Ok(b) => b,
        Err(_) => return Ss2022PeekVerdict::Reject,
    };
    let req_ts = u64::from_be_bytes(ts_bytes);
    if now_secs.abs_diff(req_ts) > TIMESTAMP_TOLERANCE_SECS {
        return Ss2022PeekVerdict::Reject;
    }
    Ss2022PeekVerdict::Fresh
}

// Stream-level chunk I/O

/// Read one AEAD chunk from `stream` and advance `counter` by 2.
async fn read_chunk<S>(
    stream: &mut S,
    subkey: &[u8; 32],
    counter: &mut u64,
) -> Result<Vec<u8>, TransportError>
where
    S: AsyncRead + Unpin,
{
    // Read the encrypted length field (2 plaintext + 16-byte tag = 18 bytes).
    let mut len_ct = [0u8; ENC_LEN_FIELD];
    stream
        .read_exact(&mut len_ct)
        .await
        .map_err(TransportError::Io)?;

    // Decrypt the length to learn how many bytes of payload ciphertext follow.
    let cipher = ChaCha20Poly1305::new(Key::from_slice(subkey));
    let len_nonce = Nonce::from(counter_nonce(*counter));
    let len_plain = cipher
        .decrypt(&len_nonce, len_ct.as_ref())
        .map_err(|_| TransportError::Auth("SS-2022: AEAD open failed on length field"))?;
    let payload_len = u16::from_be_bytes(
        len_plain
            .as_slice()
            .try_into()
            .expect("AEAD output is always 2 bytes for 2-byte plaintext"),
    ) as usize;

    // Read the payload ciphertext.
    let mut pay_ct = vec![0u8; payload_len + TAG_LEN];
    stream
        .read_exact(&mut pay_ct)
        .await
        .map_err(TransportError::Io)?;

    // Decrypt the payload.
    let pay_nonce = Nonce::from(counter_nonce(*counter + 1));
    let payload = cipher
        .decrypt(&pay_nonce, pay_ct.as_slice())
        .map_err(|_| TransportError::Auth("SS-2022: AEAD open failed on payload"))?;

    *counter = counter.wrapping_add(2);
    Ok(payload)
}

// Timestamp helper

/// Return the current Unix timestamp in whole seconds.
///
/// Falls back to 0 on platforms where `SystemTime::now()` fails (should never
/// happen on supported targets; returning 0 causes the bridge to reject the
/// connection on timestamp check, which is safe-fail).
fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

// Random helper

/// Fill a buffer with cryptographically random bytes using `getrandom`.
fn fill_random(buf: &mut [u8]) -> Result<(), TransportError> {
    getrandom::fill(buf).map_err(|_| TransportError::Other("CSPRNG failure".into()))
}

// Public config and transport types

/// Pre-shared key configuration for the SS-2022 transport.
///
/// The PSK is a 32-byte secret shared between client and bridge out-of-band
/// (embedded in the bridge invite). It is used as the base key for per-session
/// subkey derivation and never sent on the wire.
pub struct Ss2022Config {
    /// 32-byte pre-shared key. Zeroized on drop.
    pub psk: Zeroizing<[u8; 32]>,
}

/// Client-side Shadowsocks-2022 transport.
///
/// Stateless and cheap to clone; safe to share via `Arc` across tasks. The
/// actual TCP socket and per-session state live only inside the returned
/// [`Ss2022Stream`].
pub struct Ss2022ClientTransport {
    config: Ss2022Config,
}

impl Ss2022ClientTransport {
    /// Construct a new client transport from a 32-byte PSK.
    pub fn new(psk: [u8; 32]) -> Self {
        Self {
            config: Ss2022Config {
                psk: Zeroizing::new(psk),
            },
        }
    }
}

// ClientTransport impl

#[async_trait]
impl ClientTransport for Ss2022ClientTransport {
    fn name(&self) -> &'static str {
        "ss2022-chacha20"
    }

    fn capability_bit(&self) -> u32 {
        SS2022_CAPABILITY_BIT
    }

    async fn dial(&self, inputs: &DialInputs<'_>) -> Result<DuplexStream, TransportError> {
        let socket_addr = endpoint_to_socket_addr(inputs.endpoint)?;

        // TCP connect under deadline.
        let stream = tokio::time::timeout(inputs.deadline, TcpStream::connect(socket_addr))
            .await
            .map_err(|_| TransportError::Timeout(inputs.deadline))?
            .map_err(TransportError::Io)?;

        // Perform the SS-2022 handshake and wrap in Ss2022Stream.
        let psk = *self.config.psk;
        let ss_stream =
            tokio::time::timeout(inputs.deadline, perform_client_handshake(stream, psk))
                .await
                .map_err(|_| TransportError::Timeout(inputs.deadline))??;

        Ok(Box::pin(ss_stream))
    }
}

// Client handshake

/// Perform the SS-2022 client-side handshake on an already-connected stream,
/// consuming it and returning an owned `Ss2022Stream` ready for bidirectional
/// data.
///
/// The function:
/// 1. Generates a random `request_salt` and derives the session subkey.
/// 2. Builds and encrypts the fixed request header (magic addr/port, timestamp,
///    random padding).
/// 3. Sends `request_salt || encrypted_header` to the bridge.
/// 4. Returns immediately - the bridge's response (`response_salt` + encrypted
///    response header) is NOT read here (F14 0-RTT). The caller may write its
///    request bytes right away; the first [`Ss2022Stream::poll_read`] reads and
///    validates the response (deriving the read subkey) before yielding data.
pub async fn perform_client_handshake<S>(
    mut stream: S,
    psk: [u8; 32],
) -> Result<Ss2022Stream<S>, TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // --- Step 1: generate salt and derive session subkey ---
    let mut request_salt = [0u8; SALT_LEN];
    fill_random(&mut request_salt)?;
    let session_subkey = derive_session_key(&psk, &request_salt);
    let session_subkey = Zeroizing::new(session_subkey);

    let timestamp = unix_now_secs();

    // --- Step 2: build request header plaintext ---
    // type[1] | timestamp[8] | atyp[1] | addr[4] | port[2] | padding_len[2] | padding[N]
    // NOTE (audit #21): the whole header is sealed below as ONE generic AEAD
    // chunk (`encrypt_chunk`), NOT the spec's two-chunk (fixed + variable)
    // request framing. This is a Mirage-only carrier - client and bridge agree,
    // but it is not wire-interoperable with a real SS-2022 parser. See the
    // crate-level "Framing fidelity" note.
    let (magic_addr, magic_port) = derive_ss2022_magic(&psk);
    let mut padding_len_bytes = [0u8; 2];
    fill_random(&mut padding_len_bytes)?;
    let padding_len = (u16::from_be_bytes(padding_len_bytes) % (MAX_PADDING + 1)) as usize;

    // Build using push/extend so there are no index-bounds-panic paths.
    let mut header = Vec::with_capacity(1 + 8 + 1 + 4 + 2 + 2 + padding_len);
    header.push(HEADER_TYPE_REQUEST);
    header.extend_from_slice(&timestamp.to_be_bytes());
    header.push(ATYP_IPV4);
    header.extend_from_slice(&magic_addr);
    header.extend_from_slice(&magic_port.to_be_bytes());
    header.extend_from_slice(&(padding_len as u16).to_be_bytes());
    // Append random padding bytes.
    let old_len = header.len();
    header.resize(old_len + padding_len, 0u8);
    if padding_len > 0 {
        fill_random(
            header
                .get_mut(old_len..old_len + padding_len)
                .expect("just resized to this length"),
        )?;
    }

    // --- Step 3: encrypt header as chunk 0 and send ---
    let mut write_counter: u64 = 0;
    let enc_header = encrypt_chunk(&session_subkey, write_counter, &header);
    write_counter = write_counter.wrapping_add(2);

    let mut handshake_bytes = Vec::with_capacity(SALT_LEN + enc_header.len());
    handshake_bytes.extend_from_slice(&request_salt);
    handshake_bytes.extend_from_slice(&enc_header);

    stream
        .write_all(&handshake_bytes)
        .await
        .map_err(TransportError::Io)?;
    stream.flush().await.map_err(TransportError::Io)?;

    // --- Step 4 (F14, 0-RTT): DEFER the server-response read ---
    // Real SS-2022 is 0-RTT: the client sends its request (+ payload) and the
    // server's response header rides with the first downstream data. Blocking
    // here for a standalone `response_salt || header` before the caller could
    // send anything created a client-hello -> server-hello -> client-data
    // ping-pong (an extra RTT + a lone server-first record) - a distinctive
    // flow signature. Instead we return immediately; the first `poll_read`
    // reads + validates the response (deriving the read subkey from the
    // server's salt) before yielding data. The caller can write its request
    // bytes right now, so client hello + request go out together.

    // --- Step 5: construct the session stream ---
    // write_counter is already 2 after the header chunk. The read side starts
    // in the deferred-response state; its subkey/counter are set when the first
    // poll_read consumes the server's `response_salt`.
    Ok(Ss2022Stream {
        inner: stream,
        read_subkey: [0u8; 32], // placeholder until the deferred response read
        write_subkey: *session_subkey,
        pace_seed: ss_pace_seed(&session_subkey),
        read_counter: 0,
        write_counter,
        read_buf: Vec::new(),
        stage_buf: Vec::new(),
        stage_phase: 0,
        stage_payload_len: 0,
        write_buf: Vec::new(),
        write_off: 0,
        resp_pending: true,
        psk,
        request_salt,
        resp_phase: 0,
        resp_stage: Vec::new(),
        resp_payload_len: 0,
    })
}

// Client-side convenience wrapper

/// Client-side: perform the SS-2022 handshake within `deadline`.
///
/// Thin wrapper around [`perform_client_handshake`] that adds a
/// `tokio::time::timeout` so callers do not need to wrap themselves.
///
/// # Errors
///
/// - [`TransportError::Timeout`] if `deadline` expires before the handshake
///   completes.
/// - Any error that [`perform_client_handshake`] can return.
pub async fn ss2022_client_dial<S>(
    stream: S,
    psk: &[u8; 32],
    deadline: Duration,
) -> Result<Ss2022Stream<S>, TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::time::timeout(deadline, perform_client_handshake(stream, *psk))
        .await
        .map_err(|_| TransportError::Timeout(deadline))?
}

// Server-side auth

/// Authenticate an incoming SS-2022 connection from `stream`.
///
/// The function reads `request_salt[16]` followed by the first AEAD chunk
/// (the request header), validates the header type, timestamp (+/-30s), and
/// magic address/port, then sends back the SS-2022 response header.
///
/// On success returns an [`Ss2022Stream`] positioned past the handshake and
/// ready for bidirectional Mirage session data.
///
/// A repeated `request_salt` seen within [`REPLAY_TTL_SECS`] is dropped exactly
/// like a failed AEAD tag (audit #10): [`TransportError::Auth`], no server
/// response written, so a replayer cannot draw the confirming reply. This
/// overload uses a process-wide default replay set; use
/// [`ss2022_server_auth_with_replay`] to inject your own (e.g. a set the caller
/// already maintains).
///
/// # Errors
///
/// - [`TransportError::Auth`] if the timestamp is outside +/-30s, the AEAD
///   tag is wrong, the magic address/port does not match, or the request salt
///   is a replay.
/// - [`TransportError::Wire`] if the header is structurally malformed.
/// - [`TransportError::Io`] on underlying I/O failures.
/// - [`TransportError::Timeout`] if `deadline` expires.
pub async fn ss2022_server_auth<S>(
    stream: S,
    psk: &[u8; 32],
    deadline: Duration,
) -> Result<Ss2022Stream<S>, TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    ss2022_server_auth_with_replay(stream, psk, deadline, default_replay_set()).await
}

/// [`ss2022_server_auth`] with a caller-supplied request-salt replay set.
///
/// The `seen_salts` set records each accepted `request_salt`; a repeat within
/// its TTL is rejected identically to a bad AEAD tag (audit #10). Share ONE set
/// across all SS-2022 accepts on a bridge so replay protection is global (a
/// per-connection set would be useless - each connection sees its own salt only
/// once). The set is bounded + TTL'd, so it cannot grow without limit.
///
/// # Errors
///
/// Same as [`ss2022_server_auth`].
pub async fn ss2022_server_auth_with_replay<S>(
    mut stream: S,
    psk: &[u8; 32],
    deadline: Duration,
    seen_salts: &SeenNonceSet,
) -> Result<Ss2022Stream<S>, TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::time::timeout(deadline, do_server_auth(&mut stream, psk, seen_salts))
        .await
        .map_err(|_| TransportError::Timeout(deadline))?
        .map(|state| Ss2022Stream {
            inner: stream,
            pace_seed: ss_pace_seed(&state.read_subkey),
            read_subkey: state.read_subkey,
            write_subkey: state.write_subkey,
            read_counter: state.read_counter,
            write_counter: state.write_counter,
            read_buf: Vec::new(),
            stage_buf: Vec::new(),
            stage_phase: 0,
            stage_payload_len: 0,
            write_buf: Vec::new(),
            write_off: 0,
            // Server read the request inline; no deferred response on this side.
            resp_pending: false,
            psk: [0u8; 32],
            request_salt: [0u8; SALT_LEN],
            resp_phase: 3,
            resp_stage: Vec::new(),
            resp_payload_len: 0,
        })
}

/// Process-wide default SS-2022 request-salt replay filter (audit #10).
///
/// Bounded (capacity-capped) and TTL'd so it can never grow without limit.
/// Shared across every default-path [`ss2022_server_auth`] so a captured
/// (`salt || header`) record cannot be replayed within the timestamp window to
/// draw the confirming server response.
fn default_replay_set() -> &'static SeenNonceSet {
    static REPLAY: OnceLock<SeenNonceSet> = OnceLock::new();
    REPLAY.get_or_init(|| SeenNonceSet::new(Duration::from_secs(REPLAY_TTL_SECS)))
}

/// Internal state produced by a successful server auth before the stream is
/// wrapped. Fields match [`Ss2022Stream`] fields.
struct ServerAuthState {
    read_subkey: [u8; 32],
    write_subkey: [u8; 32],
    read_counter: u64,
    write_counter: u64,
}

impl std::fmt::Debug for ServerAuthState {
    /// Redacts key material - subkeys are never printed (matches
    /// [`Ss2022Stream`]'s `Debug`).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerAuthState")
            .field("read_subkey", &"[redacted]")
            .field("write_subkey", &"[redacted]")
            .field("read_counter", &self.read_counter)
            .field("write_counter", &self.write_counter)
            .finish()
    }
}

/// Core server-auth logic, called inside a `timeout` wrapper.
///
/// `seen_salts` is the request-salt replay filter (audit #10): a repeat within
/// its TTL is rejected identically to a bad AEAD tag.
async fn do_server_auth<S>(
    stream: &mut S,
    psk: &[u8; 32],
    seen_salts: &SeenNonceSet,
) -> Result<ServerAuthState, TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // --- Read request_salt and derive client-side subkey ---
    let mut request_salt = [0u8; SALT_LEN];
    stream
        .read_exact(&mut request_salt)
        .await
        .map_err(TransportError::Io)?;

    let client_subkey = derive_session_key(psk, &request_salt);
    let client_subkey = Zeroizing::new(client_subkey);

    // --- Read and decrypt the request header chunk (audit #21: this reads the
    // whole header back as ONE generic AEAD chunk, symmetric with the client's
    // `encrypt_chunk` - NOT the spec's two-chunk request framing). ---
    let mut read_counter: u64 = 0;
    let header = read_chunk(stream, &client_subkey, &mut read_counter).await?;

    // Validate header structure:
    // type[1] | timestamp[8] | atyp[1] | addr[4] | port[2] | padding_len[2] | padding[N]
    let min_header_len = 1 + 8 + 1 + 4 + 2 + 2; // 18
    if header.len() < min_header_len {
        return Err(TransportError::Wire("SS-2022: request header too short"));
    }

    let hdr_type = header
        .first()
        .ok_or(TransportError::Wire("SS-2022: request header too short"))?;
    if *hdr_type != HEADER_TYPE_REQUEST {
        return Err(TransportError::Auth(
            "SS-2022: request header type byte is not 0x00",
        ));
    }

    let req_ts_bytes: [u8; 8] = header
        .get(1..9)
        .ok_or(TransportError::Wire("SS-2022: request header too short"))?
        .try_into()
        .expect("get(1..9) is exactly 8 bytes");
    let req_ts = u64::from_be_bytes(req_ts_bytes);
    let now = unix_now_secs();
    let drift = now.abs_diff(req_ts);
    if drift > TIMESTAMP_TOLERANCE_SECS {
        return Err(TransportError::Auth(
            "SS-2022: request timestamp outside +/-30s window",
        ));
    }

    let atyp = header
        .get(9)
        .ok_or(TransportError::Wire("SS-2022: request header too short"))?;
    if *atyp != ATYP_IPV4 {
        return Err(TransportError::Auth(
            "SS-2022: unsupported address type (expected IPv4 magic addr)",
        ));
    }

    // Magic addr/port are derived per-bridge from the PSK (audit #27), not a
    // fixed cross-bridge constant. Both ends share the PSK, so the values agree.
    let (magic_addr, magic_port) = derive_ss2022_magic(psk);

    let addr: [u8; 4] = header
        .get(10..14)
        .ok_or(TransportError::Wire("SS-2022: request header too short"))?
        .try_into()
        .expect("get(10..14) is exactly 4 bytes");
    if addr != magic_addr {
        return Err(TransportError::Auth(
            "SS-2022: destination address is not the derived Mirage magic address",
        ));
    }

    let port = u16::from_be_bytes(
        header
            .get(14..16)
            .ok_or(TransportError::Wire("SS-2022: request header too short"))?
            .try_into()
            .expect("get(14..16) is exactly 2 bytes"),
    );
    if port != magic_port {
        return Err(TransportError::Auth(
            "SS-2022: destination port is not the derived Mirage magic port",
        ));
    }

    // --- Replay defense (audit #10) ---
    // A captured (request_salt || encrypted_header) record is a genuine,
    // in-window request: without a seen-salt set the bridge would re-derive the
    // subkey, decrypt, pass every check above, and emit the confirming server
    // response - a replay/confirmation oracle for an active prober. Record each
    // request_salt on first sight and drop a repeat EXACTLY like a failed AEAD
    // tag: return `Auth` (the same variant every check above returns) so the
    // caller closes the stream with NO response written. The observable wire
    // behavior of a rejected replay is therefore identical to a bad tag or a
    // wrong-magic probe - a silent close, indistinguishable from "not a bridge".
    // Placed AFTER the timestamp/addr/port checks so only genuine in-window
    // records populate the (bounded, TTL'd) set; a stale/garbage record is
    // rejected earlier and never inserted.
    let mut salt_key = [0u8; 32];
    salt_key
        .get_mut(..SALT_LEN)
        .expect("salt_key is 32 bytes and SALT_LEN is 16")
        .copy_from_slice(&request_salt);
    if !seen_salts.check_and_insert(salt_key, Instant::now()) {
        return Err(TransportError::Auth(
            "SS-2022: request salt replay within window",
        ));
    }

    // --- Generate response salt, derive response subkey ---
    let mut response_salt = [0u8; SALT_LEN];
    fill_random(&mut response_salt)?;

    let resp_subkey = derive_session_key(psk, &response_salt);
    let resp_subkey = Zeroizing::new(resp_subkey);

    // --- Build and send response header ---
    // type[1]=0x01 | timestamp[8] | request_salt[16] | padding_len[2] | padding[N]
    // Random 0..=MAX_PADDING padding mirrors the request so the response is NOT
    // a fixed 77-byte standalone hello - that constant size was a passive flow
    // tell (F13). The client validates by minimum length + fixed offsets, so
    // trailing padding is transparent to it.
    let mut resp_padding_len_bytes = [0u8; 2];
    fill_random(&mut resp_padding_len_bytes)?;
    let resp_padding_len =
        (u16::from_be_bytes(resp_padding_len_bytes) % (MAX_PADDING + 1)) as usize;
    // Use push/extend so no index-bounds panics are possible.
    let mut resp_header = Vec::with_capacity(1 + 8 + SALT_LEN + 2 + resp_padding_len);
    resp_header.push(HEADER_TYPE_RESPONSE);
    resp_header.extend_from_slice(&req_ts.to_be_bytes());
    resp_header.extend_from_slice(&request_salt);
    resp_header.extend_from_slice(&(resp_padding_len as u16).to_be_bytes());
    let resp_pad_start = resp_header.len();
    resp_header.resize(resp_pad_start + resp_padding_len, 0u8);
    if resp_padding_len > 0 {
        fill_random(
            resp_header
                .get_mut(resp_pad_start..resp_pad_start + resp_padding_len)
                .expect("padding region just resized in"),
        )?;
    }

    let mut write_counter: u64 = 0;
    let enc_resp = encrypt_chunk(&resp_subkey, write_counter, &resp_header);
    write_counter = write_counter.wrapping_add(2);

    let mut response_wire = Vec::with_capacity(SALT_LEN + enc_resp.len());
    response_wire.extend_from_slice(&response_salt);
    response_wire.extend_from_slice(&enc_resp);

    stream
        .write_all(&response_wire)
        .await
        .map_err(TransportError::Io)?;
    stream.flush().await.map_err(TransportError::Io)?;

    // --- Return state for wrapping in Ss2022Stream ---
    // Server reads using the client_subkey (client wrote with it).
    // Server writes using the resp_subkey (client will read with it).
    Ok(ServerAuthState {
        read_subkey: *client_subkey,
        write_subkey: *resp_subkey,
        read_counter,
        write_counter,
    })
}

// Ss2022Stream

/// Framed async stream over SS-2022 AEAD chunking.
///
/// Implements `AsyncRead + AsyncWrite` so it can be pinned and returned as a
/// [`DuplexStream`]. Each direction maintains its own subkey and monotonically
/// increasing counter; the counter advances by 2 per chunk (one increment per
/// AEAD call: length encryption + payload encryption).
///
/// Reading buffers decrypted plaintext internally so that `poll_read` can
/// satisfy partial reads without re-decrypting.
pub struct Ss2022Stream<S> {
    /// Underlying byte stream (TCP socket, `tokio::io::DuplexStream`, etc.).
    inner: S,
    /// Subkey used to decrypt data arriving from the peer.
    read_subkey: [u8; 32],
    /// Subkey used to encrypt data sent to the peer.
    write_subkey: [u8; 32],
    /// Per-session Proteus pace seed, derived from the request-salt session subkey
    /// (identical on both endpoints, so a shared pacer picks the same envelope).
    pace_seed: u64,
    /// Counter for the next read-side AEAD operation (length field).
    read_counter: u64,
    /// Counter for the next write-side AEAD operation (length field).
    write_counter: u64,
    /// Buffered decrypted PLAINTEXT not yet consumed by `poll_read` callers.
    /// Holds decrypted bytes only - never ciphertext - so a caller-visible
    /// plaintext byte can never be confused with framing state.
    read_buf: Vec<u8>,
    /// Raw ciphertext accumulated across polls for the chunk currently being
    /// read. Kept in a DEDICATED buffer (separate from `read_buf`) so decrypted
    /// plaintext is never reinterpreted as staging state: an earlier design
    /// tagged staging inside `read_buf` with a `0xF0` sentinel byte and assumed
    /// plaintext never starts with `0xF0`, which is false - decrypted session
    /// frames are arbitrary bytes, so ~1/256 of partial-delivery boundaries
    /// misparsed leftover plaintext as a ciphertext length field and deadlocked.
    stage_buf: Vec<u8>,
    /// Phase of the in-progress chunk read: 0 = accumulating the encrypted
    /// length field, 1 = accumulating the payload ciphertext. Reset to 0 (with
    /// `stage_buf` emptied) after each completed chunk.
    stage_phase: u8,
    /// Payload length learned after the phase-0 length field decrypts; drives
    /// the phase-1 target (`stage_payload_len + TAG_LEN`).
    stage_payload_len: usize,
    /// Encrypted chunk bytes awaiting write to `inner`. `poll_write` drains
    /// this fully before encrypting the next chunk, so a partial inner write
    /// (TCP backpressure) never truncates a chunk on the wire.
    write_buf: Vec<u8>,
    /// Offset of the next unwritten byte in `write_buf`.
    write_off: usize,

    // ---- F14 (0-RTT): deferred server-response read ----
    /// When true, the server's response header (`response_salt` + encrypted
    /// header chunk) has not yet been consumed. The client handshake returns
    /// WITHOUT blocking on it, so the caller can pipeline its first request
    /// bytes (0-RTT - no client stall, no standalone client-hello-then-wait
    /// pattern). The first `poll_read` reads + validates the response before
    /// yielding any data. Always false on the server side.
    resp_pending: bool,
    /// PSK, kept only until the deferred response is read (to derive the read
    /// subkey from the server's `response_salt`).
    psk: [u8; 32],
    /// The client's request salt, echoed back in the response header - kept to
    /// validate that echo during the deferred read.
    request_salt: [u8; SALT_LEN],
    /// Sub-phase of the deferred response read: 0 = reading `response_salt`,
    /// 1 = reading the encrypted length field, 2 = reading the header payload,
    /// 3 = done. Unused once `resp_pending` is false.
    resp_phase: u8,
    /// Raw bytes accumulated for the current `resp_phase` across polls.
    resp_stage: Vec<u8>,
    /// Payload length of the response header chunk, learned after phase 1.
    resp_payload_len: usize,
}

impl<S> Ss2022Stream<S> {
    /// Per-session Proteus pace seed (identical on both endpoints). Feed to
    /// `mirage_transport_reality::maybe_pace_stream` so the SS carrier wears the same
    /// replayed envelope in both directions.
    #[must_use]
    pub fn pace_seed(&self) -> u64 {
        self.pace_seed
    }
}

impl<S> std::fmt::Debug for Ss2022Stream<S> {
    /// Debug representation that redacts key material.
    ///
    /// Subkeys are never printed - even in test output - to avoid accidentally
    /// leaking them into CI logs or error messages.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ss2022Stream")
            .field("read_subkey", &"[redacted]")
            .field("write_subkey", &"[redacted]")
            .field("read_counter", &self.read_counter)
            .field("write_counter", &self.write_counter)
            .field("read_buf_len", &self.read_buf.len())
            .finish_non_exhaustive()
    }
}

/// State machine for the internal read-side of `Ss2022Stream`.
///
/// Because `poll_read` cannot `.await`, we use a layered polling approach:
/// we store buffered decrypted bytes in `read_buf` and only attempt a new
/// chunk read when the buffer is empty. The chunk read itself is driven by
/// polling the underlying stream byte-by-byte until enough data is present.
///
/// To keep the implementation simple and correct (no unsafe pinned self-
/// referential futures), we buffer at the chunk level using a dedicated
/// reading state stored inline in `Ss2022Stream`.
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Ss2022Stream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // F14 (0-RTT): before any data, consume + validate the deferred server
        // response header (response_salt + encrypted header chunk). On success
        // we fall through to normal chunk reading in the same call so we never
        // return a spurious 0-byte read (which the caller would treat as EOF).
        if this.resp_pending {
            match poll_read_response(this, cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => { /* response consumed; continue below */ }
            }
        }

        // Drain any decrypted plaintext left over from a previous chunk. This
        // buffer holds plaintext ONLY (ciphertext staging lives in `stage_buf`),
        // so there is never any ambiguity between "bytes to hand the caller" and
        // "framing state" - the class of bug that a first-byte sentinel had.
        if !this.read_buf.is_empty() {
            let to_copy = this.read_buf.len().min(buf.remaining());
            let filled = this
                .read_buf
                .get(..to_copy)
                .expect("to_copy <= read_buf.len()");
            buf.put_slice(filled);
            this.read_buf.drain(..to_copy);
            return Poll::Ready(Ok(()));
        }

        // No buffered plaintext: accumulate + decrypt the next chunk. State
        // persists across polls in `stage_buf`/`stage_phase`/`stage_payload_len`
        // (a fresh chunk starts at phase 0 with an empty `stage_buf`).
        poll_staged_read(this, cx, buf)
    }
}

/// Validate an SS-2022 response header plaintext: `type == RESPONSE`, timestamp
/// within tolerance, and the echoed request salt matches. Shared by the
/// (historical) blocking path and the deferred poll-based read.
fn validate_response_header(
    payload: &[u8],
    request_salt: &[u8; SALT_LEN],
) -> Result<(), &'static str> {
    let min_resp_len = 1 + 8 + SALT_LEN + 2;
    if payload.len() < min_resp_len {
        return Err("SS-2022: response header too short");
    }
    let resp_type = *payload
        .first()
        .ok_or("SS-2022: response header too short")?;
    if resp_type != HEADER_TYPE_RESPONSE {
        return Err("SS-2022: response header type mismatch");
    }
    let resp_ts_bytes: [u8; 8] = payload
        .get(1..9)
        .ok_or("SS-2022: response header too short")?
        .try_into()
        .expect("get(1..9) is exactly 8 bytes");
    let resp_ts = u64::from_be_bytes(resp_ts_bytes);
    if unix_now_secs().abs_diff(resp_ts) > TIMESTAMP_TOLERANCE_SECS {
        return Err("SS-2022: response timestamp outside +/-30s window");
    }
    let echoed = payload
        .get(9..9 + SALT_LEN)
        .ok_or("SS-2022: response header too short")?;
    if echoed != request_salt.as_slice() {
        return Err("SS-2022: response did not echo the correct request salt");
    }
    Ok(())
}

/// Drive the deferred server-response read for `Ss2022Stream::poll_read`
/// (F14 0-RTT). A small non-blocking state machine across polls:
///   phase 0: read `response_salt` (`SALT_LEN`) -> derive the read subkey
///   phase 1: read the encrypted length field (`ENC_LEN_FIELD`) -> `payload_len`
///   phase 2: read the header payload (`payload_len + TAG_LEN`) -> decrypt + validate
///
/// On success `resp_pending` is cleared and the read subkey/counter are set for
/// subsequent data chunks; the caller then falls through to normal chunk reads.
fn poll_read_response<S: AsyncRead + AsyncWrite + Unpin>(
    this: &mut Ss2022Stream<S>,
    cx: &mut Context<'_>,
) -> Poll<std::io::Result<()>> {
    loop {
        let target = match this.resp_phase {
            0 => SALT_LEN,
            1 => ENC_LEN_FIELD,
            2 => this.resp_payload_len + TAG_LEN,
            _ => return Poll::Ready(Ok(())),
        };

        // Accumulate raw bytes for the current phase (never over-reads: `tmp`
        // is sized to exactly the remaining need).
        if this.resp_stage.len() < target {
            let need = target - this.resp_stage.len();
            let mut tmp = vec![0u8; need];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let filled = rb.filled();
                    if filled.is_empty() {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "SS-2022: EOF during response header",
                        )));
                    }
                    this.resp_stage.extend_from_slice(filled);
                }
            }
            if this.resp_stage.len() < target {
                continue;
            }
        }

        match this.resp_phase {
            0 => {
                let mut response_salt = [0u8; SALT_LEN];
                response_salt.copy_from_slice(this.resp_stage.as_slice());
                this.read_subkey = derive_session_key(&this.psk, &response_salt);
                this.read_counter = 0;
                this.resp_stage.clear();
                this.resp_phase = 1;
            }
            1 => {
                let cipher = ChaCha20Poly1305::new(Key::from_slice(&this.read_subkey));
                let nonce = Nonce::from(counter_nonce(this.read_counter));
                let len_plain = cipher
                    .decrypt(&nonce, this.resp_stage.as_ref())
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "SS-2022: AEAD open failed on response length",
                        )
                    })?;
                let payload_len = u16::from_be_bytes(
                    len_plain
                        .as_slice()
                        .try_into()
                        .expect("AEAD output is 2 bytes for 2-byte plaintext"),
                ) as usize;
                this.resp_payload_len = payload_len;
                this.resp_stage.clear();
                this.resp_phase = 2;
            }
            2 => {
                let cipher = ChaCha20Poly1305::new(Key::from_slice(&this.read_subkey));
                let nonce = Nonce::from(counter_nonce(this.read_counter + 1));
                let payload = cipher
                    .decrypt(&nonce, this.resp_stage.as_ref())
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "SS-2022: AEAD open failed on response header",
                        )
                    })?;
                validate_response_header(&payload, &this.request_salt)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                this.read_counter = this.read_counter.wrapping_add(2);
                this.resp_stage.clear();
                this.resp_phase = 3;
                this.resp_pending = false;
                return Poll::Ready(Ok(()));
            }
            _ => return Poll::Ready(Ok(())),
        }
    }
}

/// Continue or start a staged chunk read for `Ss2022Stream::poll_read`.
///
/// Ciphertext is accumulated across polls in the dedicated `stage_buf`
/// (never mixed with the plaintext `read_buf`), with `stage_phase` selecting:
/// - phase 0: accumulating the `ENC_LEN_FIELD` (18) encrypted length bytes
/// - phase 1: accumulating the `stage_payload_len + TAG_LEN` payload bytes
///
/// On a completed chunk the decrypted plaintext is moved into `read_buf`, the
/// staging state is reset (`stage_buf` emptied, `stage_phase = 0`), and the
/// caller is served. All slice accesses go through `.get()` to avoid panics.
fn poll_staged_read<S: AsyncRead + AsyncWrite + Unpin>(
    this: &mut Ss2022Stream<S>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
) -> Poll<std::io::Result<()>> {
    loop {
        if this.stage_phase == 0 {
            // Phase 0: accumulate `ENC_LEN_FIELD` (18) bytes of encrypted length.
            let need = ENC_LEN_FIELD.saturating_sub(this.stage_buf.len());

            if need > 0 {
                // Size the scratch buffer to the remaining need so a single
                // sized read can drain the whole phase in one syscall, rather
                // than trickling one byte at a time (mirrors `poll_read_response`).
                let mut tmp = vec![0u8; need];
                let mut tmp_buf = ReadBuf::new(&mut tmp);
                match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        if tmp_buf.filled().is_empty() {
                            // EOF from peer.
                            return Poll::Ready(Ok(()));
                        }
                        this.stage_buf.extend_from_slice(tmp_buf.filled());
                    }
                }
                // Loop back to re-evaluate how many bytes we still need.
            } else {
                // We have all `ENC_LEN_FIELD` bytes. Decrypt the length.
                let len_ct: [u8; ENC_LEN_FIELD] = match this.stage_buf.get(..ENC_LEN_FIELD) {
                    Some(s) => s
                        .try_into()
                        .expect("get(..ENC_LEN_FIELD) is ENC_LEN_FIELD bytes"),
                    None => {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "SS-2022: staged len-ct shorter than expected (internal error)",
                        )))
                    }
                };

                let cipher = ChaCha20Poly1305::new(Key::from_slice(&this.read_subkey));
                let len_nonce = Nonce::from(counter_nonce(this.read_counter));
                let Ok(len_plain) = cipher.decrypt(&len_nonce, len_ct.as_ref()) else {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "SS-2022: AEAD open failed on length field",
                    )));
                };
                let payload_len = u16::from_be_bytes(
                    len_plain
                        .as_slice()
                        .try_into()
                        .expect("AEAD output is 2 bytes for 2-byte plaintext"),
                ) as usize;

                // Transition to phase 1: reset the staging buffer for payload.
                this.stage_payload_len = payload_len;
                this.stage_buf.clear();
                this.stage_phase = 1;
                // Continue loop to immediately start accumulating payload bytes.
            }
        } else {
            // Phase 1: accumulate `stage_payload_len + TAG_LEN` payload bytes.
            let total_pay_ct = this.stage_payload_len + TAG_LEN;
            let need = total_pay_ct.saturating_sub(this.stage_buf.len());

            if need > 0 {
                // Size the scratch buffer to the remaining need so a single
                // sized read can drain the whole phase in one syscall, rather
                // than trickling one byte at a time (mirrors `poll_read_response`).
                let mut tmp = vec![0u8; need];
                let mut tmp_buf = ReadBuf::new(&mut tmp);
                match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        if tmp_buf.filled().is_empty() {
                            return Poll::Ready(Ok(()));
                        }
                        this.stage_buf.extend_from_slice(tmp_buf.filled());
                    }
                }
                // Loop back to re-evaluate.
            } else {
                // We have all the payload ciphertext. Decrypt.
                let pay_ct = match this.stage_buf.get(..total_pay_ct) {
                    Some(s) => s,
                    None => {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "SS-2022: staged payload shorter than expected (internal error)",
                        )))
                    }
                };
                let cipher = ChaCha20Poly1305::new(Key::from_slice(&this.read_subkey));
                let pay_nonce = Nonce::from(counter_nonce(this.read_counter + 1));
                let Ok(payload) = cipher.decrypt(&pay_nonce, pay_ct) else {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "SS-2022: AEAD open failed on payload",
                    )));
                };
                this.read_counter = this.read_counter.wrapping_add(2);

                // Chunk complete: reset staging state and hold the plaintext.
                this.stage_buf.clear();
                this.stage_phase = 0;
                this.read_buf = payload;

                // Copy into caller's buffer; any remainder stays in `read_buf`
                // (plaintext) and is drained by the next `poll_read`.
                let to_copy = this.read_buf.len().min(buf.remaining());
                let filled = this
                    .read_buf
                    .get(..to_copy)
                    .expect("to_copy <= read_buf.len()");
                buf.put_slice(filled);
                this.read_buf.drain(..to_copy);
                return Poll::Ready(Ok(()));
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Ss2022Stream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        // Drain any chunk still in flight first, so a partial inner write never
        // truncates a chunk and we never interleave two chunks on the wire.
        while this.write_off < this.write_buf.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_off..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "ss2022: inner stream accepted 0 bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => this.write_off += n,
            }
        }
        this.write_buf.clear();
        this.write_off = 0;

        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Cap each chunk at the 2-byte-length-safe maximum; the caller writes
        // the remainder in subsequent calls.
        let take = data.len().min(MAX_PAYLOAD_CHUNK);
        this.write_buf = encrypt_chunk(&this.write_subkey, this.write_counter, &data[..take]);
        this.write_off = 0;
        this.write_counter = this.write_counter.wrapping_add(2);

        // Best-effort drain within this call; the chunk persists in write_buf
        // if the inner stream isn't fully ready, draining on the next call.
        while this.write_off < this.write_buf.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_off..]) {
                Poll::Pending => break,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "ss2022: inner stream accepted 0 bytes",
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

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // Drain any buffered chunk before flushing the inner stream, or a
        // backpressured chunk would sit unsent across a flush.
        while this.write_off < this.write_buf.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_off..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "ss2022: inner stream accepted 0 bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => this.write_off += n,
            }
        }
        this.write_buf.clear();
        this.write_off = 0;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// Endpoint helper (shared with obfs transport pattern)

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
            "ss2022 does not resolve domains at transport layer; use IP endpoints".into(),
        )),
        Endpoint::OnionV3 { .. } => Err(TransportError::Other(
            "ss2022 does not speak onion; use a Tor SOCKS forwarder".into(),
        )),
    }
}

// Tests

#[cfg(test)]
#[allow(clippy::indexing_slicing)] // test helpers slice encrypt_chunk output at known offsets
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    /// Build a valid SS-2022 opening (`salt || encrypt_chunk(header)`) for a
    /// given psk/salt/timestamp - the exact bytes a client sends first.
    fn build_opening(psk: &[u8; 32], salt: &[u8; 16], ts: u64) -> Vec<u8> {
        let subkey = derive_session_key(psk, salt);
        let (magic_addr, magic_port) = derive_ss2022_magic(psk);
        let mut header = Vec::new();
        header.push(HEADER_TYPE_REQUEST);
        header.extend_from_slice(&ts.to_be_bytes());
        header.push(ATYP_IPV4);
        header.extend_from_slice(&magic_addr);
        header.extend_from_slice(&magic_port.to_be_bytes());
        header.extend_from_slice(&0u16.to_be_bytes()); // padding_len = 0
        let mut wire = salt.to_vec();
        wire.extend_from_slice(&encrypt_chunk(&subkey, 0, &header));
        wire
    }

    #[test]
    fn peek_verify_fresh_accepts_fresh_and_rejects_stale() {
        // Red-team round 2: the non-consuming freshness peek must accept an
        // in-window opening and REJECT a stale (replayed) one, so the mux falls
        // through to cover instead of the consuming handshake's silent-drop path.
        let psk = [0x33u8; 32];
        let salt = [0x44u8; 16];
        let now = 1_700_000_000u64;
        let wire = build_opening(&psk, &salt, now);

        assert_eq!(
            ss2022_peek_verify_fresh(&psk, &wire, now),
            Ss2022PeekVerdict::Fresh
        );
        // Within +/-30s tolerance.
        assert_eq!(
            ss2022_peek_verify_fresh(&psk, &wire, now + 20),
            Ss2022PeekVerdict::Fresh
        );
        // Stale replay (5 min later, past the mux salt-TTL) -> reject -> cover.
        assert_eq!(
            ss2022_peek_verify_fresh(&psk, &wire, now + 301),
            Ss2022PeekVerdict::Reject
        );
        // Wrong PSK -> the length chunk AEAD fails -> reject.
        assert_eq!(
            ss2022_peek_verify_fresh(&[0x99u8; 32], &wire, now),
            Ss2022PeekVerdict::Reject
        );
        // Truncated before the salt+length chunk, and before the full header.
        assert_eq!(
            ss2022_peek_verify_fresh(&psk, &wire[..10], now),
            Ss2022PeekVerdict::NeedMoreBytes
        );
        assert_eq!(
            ss2022_peek_verify_fresh(&psk, &wire[..40], now),
            Ss2022PeekVerdict::NeedMoreBytes
        );
    }

    // 1. derive_session_key_deterministic

    #[test]
    fn derive_session_key_deterministic() {
        let psk = [0x42u8; 32];
        let salt = [0x13u8; 16];
        let k1 = derive_session_key(&psk, &salt);
        let k2 = derive_session_key(&psk, &salt);
        assert_eq!(k1, k2, "same psk+salt must produce same subkey");
    }

    #[test]
    fn derive_session_key_differs_on_salt() {
        let psk = [0x42u8; 32];
        let k1 = derive_session_key(&psk, &[0xAAu8; 16]);
        let k2 = derive_session_key(&psk, &[0xBBu8; 16]);
        assert_ne!(k1, k2, "different salts must produce different subkeys");
    }

    #[test]
    fn derive_session_key_differs_on_psk() {
        let salt = [0x13u8; 16];
        let k1 = derive_session_key(&[0x01u8; 32], &salt);
        let k2 = derive_session_key(&[0x02u8; 32], &salt);
        assert_ne!(k1, k2, "different PSKs must produce different subkeys");
    }

    // 2. counter_nonce_monotonic

    #[test]
    fn counter_nonce_monotonic() {
        let n0 = counter_nonce(0);
        let n1 = counter_nonce(1);
        let n2 = counter_nonce(2);
        assert_ne!(n0, n1);
        assert_ne!(n1, n2);
        assert_ne!(n0, n2);
    }

    #[test]
    fn counter_nonce_zero_prefix() {
        // First 4 bytes are always 0x00.
        let n = counter_nonce(0xDEAD_BEEF_CAFE_1234);
        assert_eq!(&n[..4], &[0u8; 4]);
    }

    #[test]
    fn counter_nonce_encodes_counter() {
        let n = counter_nonce(1);
        let expected: [u8; 8] = 1u64.to_be_bytes();
        assert_eq!(&n[4..], &expected);
    }

    // 3. encrypt_decrypt_chunk_roundtrip

    #[test]
    fn encrypt_decrypt_chunk_roundtrip() {
        let key = [0x55u8; 32];
        let plaintext = b"hello mirage shadowsocks world";
        let ct = encrypt_chunk(&key, 0, plaintext);

        // Split ct into len_ct and pay_ct.
        let len_ct: [u8; ENC_LEN_FIELD] = ct[..ENC_LEN_FIELD]
            .try_into()
            .expect("slice is ENC_LEN_FIELD bytes");
        let pay_ct = &ct[ENC_LEN_FIELD..];

        let recovered = decrypt_chunk_from_slice(&key, 0, &len_ct, pay_ct)
            .expect("decrypt_chunk should succeed with correct key");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn encrypt_decrypt_chunk_wrong_key_fails() {
        let key = [0x55u8; 32];
        let wrong_key = [0x56u8; 32];
        let ct = encrypt_chunk(&key, 0, b"secret");

        let len_ct: [u8; ENC_LEN_FIELD] = ct[..ENC_LEN_FIELD]
            .try_into()
            .expect("slice is ENC_LEN_FIELD bytes");
        let pay_ct = &ct[ENC_LEN_FIELD..];

        let result = decrypt_chunk_from_slice(&wrong_key, 0, &len_ct, pay_ct);
        assert!(
            matches!(result, Err(TransportError::Auth(_))),
            "wrong key must return Auth error"
        );
    }

    #[test]
    fn encrypt_decrypt_chunk_counter_increments() {
        let key = [0x77u8; 32];
        // Each chunk uses counter and counter+1; next chunk starts at counter+2.
        let ct0 = encrypt_chunk(&key, 0, b"chunk0");
        let ct2 = encrypt_chunk(&key, 2, b"chunk2");

        let len_ct0: [u8; ENC_LEN_FIELD] = ct0[..ENC_LEN_FIELD].try_into().expect("18 bytes");
        let pay_ct0 = &ct0[ENC_LEN_FIELD..];
        let len_ct2: [u8; ENC_LEN_FIELD] = ct2[..ENC_LEN_FIELD].try_into().expect("18 bytes");
        let pay_ct2 = &ct2[ENC_LEN_FIELD..];

        let p0 = decrypt_chunk_from_slice(&key, 0, &len_ct0, pay_ct0).expect("chunk0");
        let p2 = decrypt_chunk_from_slice(&key, 2, &len_ct2, pay_ct2).expect("chunk2");
        assert_eq!(p0, b"chunk0");
        assert_eq!(p2, b"chunk2");
    }

    // 4. auth_fail_wrong_psk

    #[tokio::test]
    async fn auth_fail_wrong_psk() {
        let (client_half, server_half) = duplex(65536);

        let client_psk = [0xAAu8; 32];
        let server_psk = [0xBBu8; 32]; // different!

        let deadline = Duration::from_secs(5);

        let client_task = tokio::spawn(async move {
            // Perform client handshake with client_psk; function consumes the stream.
            perform_client_handshake(client_half, client_psk).await
        });

        let server_result = ss2022_server_auth(server_half, &server_psk, deadline).await;

        // Server should fail with Auth because the AEAD tag won't verify.
        assert!(
            matches!(server_result, Err(TransportError::Auth(_))),
            "wrong PSK must produce Auth error, got: {server_result:?}"
        );

        // Client task may error too (EOF from server drop); just join it.
        let _ = client_task.await;
    }

    // 5. auth_fail_old_timestamp

    #[tokio::test(start_paused = true)]
    async fn auth_fail_old_timestamp() {
        // Build a request header with a timestamp 60s in the past and verify
        // the server rejects it.
        let psk = [0xCCu8; 32];
        let (mut client_half, server_half) = duplex(65536);

        let deadline = Duration::from_secs(5);

        // Build a stale header manually.
        let mut request_salt = [0u8; SALT_LEN];
        request_salt[0] = 0x01;
        let session_subkey = derive_session_key(&psk, &request_salt);

        let stale_ts = unix_now_secs().saturating_sub(60); // 60s ago
        let (magic_addr, magic_port) = derive_ss2022_magic(&psk);

        let mut header = vec![0u8; 1 + 8 + 1 + 4 + 2 + 2];
        header[0] = HEADER_TYPE_REQUEST;
        header[1..9].copy_from_slice(&stale_ts.to_be_bytes());
        header[9] = ATYP_IPV4;
        header[10..14].copy_from_slice(&magic_addr);
        header[14..16].copy_from_slice(&magic_port.to_be_bytes());
        // padding_len = 0

        let enc = encrypt_chunk(&session_subkey, 0, &header);
        let mut wire = Vec::with_capacity(SALT_LEN + enc.len());
        wire.extend_from_slice(&request_salt);
        wire.extend_from_slice(&enc);

        client_half
            .write_all(&wire)
            .await
            .expect("write stale handshake");
        client_half.flush().await.expect("flush");

        let result = ss2022_server_auth(server_half, &psk, deadline).await;
        assert!(
            matches!(result, Err(TransportError::Auth(_))),
            "stale timestamp must produce Auth error, got: {result:?}"
        );
    }

    // 6. full_handshake_roundtrip

    #[tokio::test]
    async fn full_handshake_roundtrip() {
        let psk = [0x42u8; 32];
        let (client_io, server_io) = duplex(65536);

        let deadline = Duration::from_secs(5);

        // Run client and server concurrently.
        let server_task =
            tokio::spawn(async move { ss2022_server_auth(server_io, &psk, deadline).await });

        // Client side: handshake then send some data.
        // perform_client_handshake consumes client_io and returns an owned Ss2022Stream.
        let mut client_stream = perform_client_handshake(client_io, psk)
            .await
            .expect("client handshake");

        // Server finishes handshake.
        let mut server_stream = server_task
            .await
            .expect("server task did not panic")
            .expect("server auth");

        // Client writes; server reads.
        let msg = b"hello from mirage client";
        client_stream.write_all(msg).await.expect("client write");
        client_stream.flush().await.expect("client flush");

        let mut recv = vec![0u8; msg.len()];
        server_stream
            .read_exact(&mut recv)
            .await
            .expect("server read");
        assert_eq!(recv.as_slice(), msg.as_ref());

        // Server writes; client reads.
        let reply = b"hello from mirage bridge";
        server_stream.write_all(reply).await.expect("server write");
        server_stream.flush().await.expect("server flush");

        let mut client_recv = vec![0u8; reply.len()];
        client_stream
            .read_exact(&mut client_recv)
            .await
            .expect("client read reply");
        assert_eq!(client_recv.as_slice(), reply.as_ref());
    }

    /// Regression: decrypted plaintext bytes that happen to equal `0xF0` must
    /// NOT be reinterpreted as read-staging state. An earlier design tagged the
    /// ciphertext staging buffer with a leading `0xF0` sentinel and assumed
    /// decrypted plaintext never begins with `0xF0`; that assumption is false
    /// (plaintext is arbitrary). When a partially-delivered chunk left a
    /// remainder starting with `0xF0`, the next `poll_read` parsed that
    /// plaintext as a ciphertext length field, computed a bogus payload length,
    /// and blocked forever waiting for bytes that were never sent (~1/256 per
    /// partial-delivery boundary -> an intermittent e2e deadlock). Here the
    /// server sends an all-`0xF0` payload and the client reads it one byte at a
    /// time, so every read after the first has a `0xF0`-leading remainder.
    #[tokio::test]
    async fn plaintext_0xf0_is_not_confused_with_staging_state() {
        let psk = [0x37u8; 32];
        let (client_io, server_io) = duplex(65536);
        let deadline = Duration::from_secs(5);

        let server_task =
            tokio::spawn(async move { ss2022_server_auth(server_io, &psk, deadline).await });
        let mut client_stream = perform_client_handshake(client_io, psk)
            .await
            .expect("client handshake");
        let mut server_stream = server_task
            .await
            .expect("server task did not panic")
            .expect("server auth");

        // Payload of all-0xF0 bytes: after the first byte is delivered, every
        // subsequent leftover remainder starts with 0xF0 - the exact trigger.
        let payload = vec![0xF0u8; 96];
        server_stream
            .write_all(&payload)
            .await
            .expect("server write");
        server_stream.flush().await.expect("server flush");

        // Read one byte per call so partial delivery leaves a 0xF0 remainder.
        let got = tokio::time::timeout(Duration::from_secs(5), async {
            let mut out = Vec::with_capacity(payload.len());
            let mut one = [0u8; 1];
            while out.len() < payload.len() {
                let n = client_stream.read(&mut one).await.expect("client read");
                assert_ne!(n, 0, "unexpected EOF before full payload");
                out.extend_from_slice(&one[..n]);
            }
            out
        })
        .await
        .expect("byte-by-byte read must not deadlock on 0xF0 plaintext");
        assert_eq!(got, payload, "0xF0 payload round-trips intact");
    }

    /// F14 (0-RTT): the client handshake must return WITHOUT reading the
    /// server's response, so the caller can write request bytes before the
    /// response has been consumed. The deferred response is read + validated
    /// transparently on the first `poll_read`. A bad server response therefore
    /// surfaces as a read error, not a handshake error.
    #[tokio::test]
    async fn client_handshake_is_0rtt_and_defers_response() {
        let psk = [0x37u8; 32];
        let (client_io, server_io) = duplex(65536);
        let deadline = Duration::from_secs(5);

        let server = tokio::spawn(async move {
            let mut s = ss2022_server_auth(server_io, &psk, deadline)
                .await
                .expect("server auth");
            // Server reads the client's 0-RTT request bytes first.
            let mut early = vec![0u8; 10];
            s.read_exact(&mut early).await.expect("server read early");
            assert_eq!(&early, b"early-data");
            s.write_all(b"reply").await.expect("server write");
            s.flush().await.expect("server flush");
        });

        // Client handshake returns immediately (does NOT block on a response).
        let mut c = perform_client_handshake(client_io, psk)
            .await
            .expect("client handshake");
        assert!(c.resp_pending, "response must be deferred after handshake");
        // Write BEFORE any read - the 0-RTT property.
        c.write_all(b"early-data").await.expect("client write");
        c.flush().await.expect("client flush");
        // First read transparently consumes + validates the deferred response.
        let mut buf = vec![0u8; 5];
        c.read_exact(&mut buf).await.expect("client read");
        assert_eq!(&buf, b"reply");
        assert!(!c.resp_pending, "response consumed on first read");

        server.await.expect("server task");
    }

    // 7. magic_addr_rejection

    #[tokio::test]
    async fn magic_addr_rejection() {
        let psk = [0xDDu8; 32];
        let (mut client_half, server_half) = duplex(65536);

        let deadline = Duration::from_secs(5);

        // Build a request header pointing at the WRONG address.
        let mut request_salt = [0u8; SALT_LEN];
        request_salt[0] = 0x02;
        let session_subkey = derive_session_key(&psk, &request_salt);

        let ts = unix_now_secs();
        let (_magic_addr, magic_port) = derive_ss2022_magic(&psk);
        let wrong_addr = [1u8, 2, 3, 4]; // not the derived magic addr (198.18.x.x)

        let mut header = vec![0u8; 1 + 8 + 1 + 4 + 2 + 2];
        header[0] = HEADER_TYPE_REQUEST;
        header[1..9].copy_from_slice(&ts.to_be_bytes());
        header[9] = ATYP_IPV4;
        header[10..14].copy_from_slice(&wrong_addr);
        header[14..16].copy_from_slice(&magic_port.to_be_bytes());

        let enc = encrypt_chunk(&session_subkey, 0, &header);
        let mut wire = Vec::with_capacity(SALT_LEN + enc.len());
        wire.extend_from_slice(&request_salt);
        wire.extend_from_slice(&enc);

        client_half
            .write_all(&wire)
            .await
            .expect("write wrong-addr handshake");
        client_half.flush().await.expect("flush");

        let result = ss2022_server_auth(server_half, &psk, deadline).await;
        assert!(
            matches!(result, Err(TransportError::Auth(_))),
            "wrong magic addr must produce Auth error, got: {result:?}"
        );
    }

    // Additional: wrong magic port

    #[tokio::test]
    async fn magic_port_rejection() {
        let psk = [0xEEu8; 32];
        let (mut client_half, server_half) = duplex(65536);

        let deadline = Duration::from_secs(5);

        let mut request_salt = [0u8; SALT_LEN];
        request_salt[0] = 0x03;
        let session_subkey = derive_session_key(&psk, &request_salt);

        let ts = unix_now_secs();
        let (magic_addr, _magic_port) = derive_ss2022_magic(&psk);
        // 443 < 1024, so it can never equal a derived magic port (always >=1024).
        let wrong_port: u16 = 443;

        let mut header = vec![0u8; 1 + 8 + 1 + 4 + 2 + 2];
        header[0] = HEADER_TYPE_REQUEST;
        header[1..9].copy_from_slice(&ts.to_be_bytes());
        header[9] = ATYP_IPV4;
        header[10..14].copy_from_slice(&magic_addr);
        header[14..16].copy_from_slice(&wrong_port.to_be_bytes());

        let enc = encrypt_chunk(&session_subkey, 0, &header);
        let mut wire = Vec::with_capacity(SALT_LEN + enc.len());
        wire.extend_from_slice(&request_salt);
        wire.extend_from_slice(&enc);

        client_half
            .write_all(&wire)
            .await
            .expect("write wrong-port handshake");
        client_half.flush().await.expect("flush");

        let result = ss2022_server_auth(server_half, &psk, deadline).await;
        assert!(
            matches!(result, Err(TransportError::Auth(_))),
            "wrong magic port must produce Auth error, got: {result:?}"
        );
    }

    // Audit #27: per-bridge derived magic destination

    /// The magic destination is derived per-bridge (per-PSK), not a fixed
    /// cross-bridge constant: it differs across PSKs, is deterministic for one
    /// PSK, and lands in the non-routable 198.18.0.0/15 range. Client-embed and
    /// server-verify agree (both derive from the shared PSK) - the round-trip
    /// tests already exercise that agreement end-to-end.
    #[test]
    fn magic_dest_is_per_bridge_derived_and_nonroutable() {
        let (a_addr, a_port) = derive_ss2022_magic(&[0x01u8; 32]);
        let (a_addr2, a_port2) = derive_ss2022_magic(&[0x01u8; 32]);
        let (b_addr, b_port) = derive_ss2022_magic(&[0x02u8; 32]);
        // Deterministic for one PSK.
        assert_eq!((a_addr, a_port), (a_addr2, a_port2));
        // Different PSKs -> different magic (addr and/or port differ).
        assert_ne!((a_addr, a_port), (b_addr, b_port));
        // Non-routable 198.18.0.0/15 and unprivileged non-zero port.
        for (addr, port) in [(a_addr, a_port), (b_addr, b_port)] {
            assert_eq!(addr[0], 198);
            assert!(addr[1] == 18 || addr[1] == 19, "must be within /15");
            assert!(port >= 1024, "port must be unprivileged/non-zero");
        }
        // NOT the old fixed loopback constant.
        assert_ne!(a_addr, [127, 0, 0, 2]);
    }

    // Audit #10: request-salt replay rejected like a bad AEAD tag

    /// Build a valid client handshake wire (`salt || encrypt_chunk(header)`)
    /// with the per-PSK derived magic destination.
    fn build_valid_handshake(psk: &[u8; 32], salt: &[u8; 16], ts: u64) -> Vec<u8> {
        let subkey = derive_session_key(psk, salt);
        let (magic_addr, magic_port) = derive_ss2022_magic(psk);
        let mut header = Vec::new();
        header.push(HEADER_TYPE_REQUEST);
        header.extend_from_slice(&ts.to_be_bytes());
        header.push(ATYP_IPV4);
        header.extend_from_slice(&magic_addr);
        header.extend_from_slice(&magic_port.to_be_bytes());
        header.extend_from_slice(&0u16.to_be_bytes()); // padding_len = 0
        let enc = encrypt_chunk(&subkey, 0, &header);
        let mut wire = Vec::with_capacity(SALT_LEN + enc.len());
        wire.extend_from_slice(salt);
        wire.extend_from_slice(&enc);
        wire
    }

    /// A replayed request salt within the window is rejected with the SAME
    /// error variant AND the same wire behavior (no server response) as a bad
    /// AEAD tag - so an active prober cannot use a captured (salt||header)
    /// record to draw a confirming reply. A fresh salt still authenticates.
    #[tokio::test]
    async fn replayed_salt_rejected_indistinguishably_from_bad_tag() {
        let psk = [0x5Au8; 32];
        let seen = SeenNonceSet::new(Duration::from_secs(REPLAY_TTL_SECS));
        let salt = [0x11u8; 16];
        let wire = build_valid_handshake(&psk, &salt, unix_now_secs());

        // 1. First sighting: fresh salt authenticates AND draws a response.
        let (mut client1, mut server1) = duplex(65536);
        client1.write_all(&wire).await.expect("write handshake");
        client1.flush().await.expect("flush");
        let first = do_server_auth(&mut server1, &psk, &seen).await;
        assert!(first.is_ok(), "fresh salt must authenticate: {first:?}");
        let mut one = [0u8; 1];
        let got = client1.read(&mut one).await.expect("read resp");
        assert_eq!(got, 1, "a genuine accept sends a server response");

        // 2. Replay the SAME salt: rejected as Auth, and NO response written.
        let (mut client2, mut server2) = duplex(65536);
        client2.write_all(&wire).await.expect("write replay");
        client2.flush().await.expect("flush");
        let replay = do_server_auth(&mut server2, &psk, &seen).await;
        assert!(
            matches!(replay, Err(TransportError::Auth(_))),
            "replay must be rejected as Auth like a bad tag; got {replay:?}"
        );
        drop(server2); // the caller drops the stream on Err
        let mut buf = [0u8; 1];
        let n = client2.read(&mut buf).await.expect("read after replay");
        assert_eq!(n, 0, "a replay must draw NO response (EOF), like a bad tag");

        // 3. Reference bad-tag path: garbage record -> same Auth + EOF behavior.
        let (mut client3, mut server3) = duplex(65536);
        let mut garbage = Vec::with_capacity(SALT_LEN + ENC_LEN_FIELD);
        garbage.extend_from_slice(&[0x33u8; SALT_LEN]);
        garbage.extend_from_slice(&[0xAAu8; ENC_LEN_FIELD]); // invalid AEAD tag
        client3.write_all(&garbage).await.expect("write garbage");
        client3.flush().await.expect("flush");
        let badtag = do_server_auth(&mut server3, &psk, &seen).await;
        assert!(
            matches!(badtag, Err(TransportError::Auth(_))),
            "bad tag must be Auth; got {badtag:?}"
        );
        drop(server3);
        let n = client3.read(&mut buf).await.expect("read after bad tag");
        assert_eq!(n, 0, "a bad tag draws NO response (EOF)");

        // 4. A DIFFERENT fresh salt still authenticates (filter is salt-scoped).
        let salt4 = [0x22u8; 16];
        let wire4 = build_valid_handshake(&psk, &salt4, unix_now_secs());
        let (mut client4, mut server4) = duplex(65536);
        client4.write_all(&wire4).await.expect("write fresh");
        client4.flush().await.expect("flush");
        let fresh = do_server_auth(&mut server4, &psk, &seen).await;
        assert!(
            fresh.is_ok(),
            "a fresh salt must still authenticate: {fresh:?}"
        );
    }

    // Smoke: name and capability bit

    #[test]
    fn transport_name_and_cap_bit() {
        let t = Ss2022ClientTransport::new([0u8; 32]);
        assert_eq!(t.name(), "ss2022-chacha20");
        assert_eq!(t.capability_bit(), SS2022_CAPABILITY_BIT);
        assert_eq!(SS2022_CAPABILITY_BIT, 1 << 3);
    }
}
