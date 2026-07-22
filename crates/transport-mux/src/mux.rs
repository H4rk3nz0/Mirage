//! Core protocol mux: single-port dispatcher that detects and routes
//! any supported Mirage transport protocol to the appropriate accept
//! handler.

use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tracing::{debug, trace, warn};

use mirage_transport::DuplexStream;
use mirage_transport_obfs::obfs_auth_verify_with_secret;
use mirage_transport_vless::{vless_server_peek_auth, VlessConfig, VLESS_CLIENT_FRAME_LEN};

// Public types

/// What protocol was detected on the wire from the first peeked bytes.
///
/// The `Opaque*` variants indicate the bytes are not recognisable as a
/// plaintext-application-layer protocol and need further auth probing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolKind {
    /// TLS `ClientHello` record header (`0x16 0x03 ...`).
    Tls,
    /// HTTP request (GET, POST, HEAD, PUT, CONNECT, DELETE, OPTIONS).
    Http,
    /// Opaque bytes consistent with an obfs-tcp handshake (high entropy,
    /// 64-byte auth header).
    OpaqueObfsTcp,
    /// Opaque bytes consistent with a Shadowsocks-2022 request (salt +
    /// encrypted length chunk).
    OpaqueShadowsocks,
    /// Opaque bytes that did not match any known pattern.
    OpaqueUnknown,
}

/// Outcome of a [`ProtocolMux::accept`] call.
///
/// Each variant carries the stream in the state appropriate for the
/// caller's next action. Callers MUST NOT re-read/re-peek the stream
/// for already-consumed auth material; for TLS and HTTP the bytes are
/// still in the socket buffer (peek was non-consuming).
pub enum MuxResult {
    /// TLS `ClientHello` detected. Bytes **not** consumed (still in
    /// `TcpStream` buffer via `peek`). Caller should hand the stream
    /// to the REALITY/TLS accept handler.
    Tls(TcpStream),

    /// HTTP request detected. Bytes **not** consumed. Caller should
    /// inspect for WebSocket `Upgrade` header or meek `POST`.
    Http(TcpStream),

    /// Authenticated as `obfs-tcp`. The 64 auth bytes have been
    /// consumed from the stream. Caller hands directly to
    /// `session::accept`.
    AuthenticatedObfsTcp(TcpStream),

    /// Authenticated as Shadowsocks-2022. Returns a [`DuplexStream`]
    /// wrapping the SS-2022 AEAD framing. Caller hands to
    /// `session::accept`.
    AuthenticatedShadowsocks(DuplexStream),

    /// Authenticated as VLESS. The 26-byte VLESS auth frame has been
    /// consumed; no standalone server response header is sent (F21 0-RTT -
    /// the session's first server flight IS the response). The raw
    /// [`TcpStream`] is ready for Mirage session bytes. Caller hands
    /// directly to `session::accept`.
    AuthenticatedVless(TcpStream),

    /// No transport matched or the connection timed out before enough
    /// bytes arrived. Caller should proxy to a cover address.
    Unknown(TcpStream),
}

impl std::fmt::Debug for MuxResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tls(_) => write!(f, "MuxResult::Tls(..)"),
            Self::Http(_) => write!(f, "MuxResult::Http(..)"),
            Self::AuthenticatedObfsTcp(_) => write!(f, "MuxResult::AuthenticatedObfsTcp(..)"),
            Self::AuthenticatedShadowsocks(_) => {
                write!(f, "MuxResult::AuthenticatedShadowsocks(..)")
            }
            Self::AuthenticatedVless(_) => write!(f, "MuxResult::AuthenticatedVless(..)"),
            Self::Unknown(_) => write!(f, "MuxResult::Unknown(..)"),
        }
    }
}

/// Bridge-side configuration for the protocol mux.
///
/// Pass this to [`ProtocolMux::new`] once at bridge startup. The mux
/// is immutable after construction and safe to share via `Arc`.
#[derive(Clone)]
pub struct MuxConfig {
    /// Bridge X25519 static public key (from the announcement). Used
    /// as the BLAKE3 keying material for obfs-tcp auth verification.
    pub bridge_static_pk: [u8; 32],

    /// Optional per-bridge obfuscation SECRET (the same value embedded in
    /// invites as `INVITE_EXT_QUIC_OBFS_SECRET`). When `Some`, obfs-tcp knocks
    /// are verified against the secret-keyed tag (audit #9), so a prober who
    /// only scraped the announcement pubkey can no longer forge a valid knock.
    /// `None` falls back to the legacy pubkey-derived verification.
    pub obfs_secret: Option<[u8; 32]>,

    /// Bridge X25519 static SECRET key. Used by the WebRTC signaling handler
    /// to run ephemeral-static ECDH against the client's per-exchange ephemeral
    /// public key, deriving an SDP-seal key that a discovery-watcher who only
    /// knows `bridge_static_pk` cannot recompute (red-team #10).
    pub bridge_static_sk: [u8; 32],

    /// Shadowsocks-2022 pre-shared key. `None` disables SS-2022
    /// detection entirely (no AEAD-decrypt attempt on opaque bytes).
    pub ss_psk: Option<[u8; 32]>,

    /// SECOND SS-2022 PSK accepted only for inbound bridge<->bridge RELAY legs
    /// (C1). A relay dialer wraps its Mirage session in SS-2022 keyed by a PSK
    /// deterministically derived from THIS bridge's public key, so the session's
    /// cleartext `MI` handshake magic never appears on the wire between bridges.
    /// The peek+auth machinery is identical to `ss_psk`; this is just a second
    /// key the mux also tries. `None` when the node is not a relay target. The
    /// key is public-derivable (auth is the inner session), so it authenticates
    /// nothing - it only de-obfuscates the relay leg.
    pub relay_ss_psk: Option<[u8; 32]>,

    /// Whether obfs-tcp detection is enabled. When `false` the mux
    /// skips the BLAKE3 verify step and falls straight through to
    /// `MuxResult::Unknown` for opaque bytes.
    pub obfs_enabled: bool,

    /// VLESS UUID credential. `None` disables VLESS detection. When
    /// `Some`, the mux attempts to validate the VLESS auth frame for
    /// opaque connections whose structural bytes (version=0x00 at offset 0,
    /// addon_len=0x00 at 17, command=0x01 at 18) match the VLESS header pattern.
    pub vless_uuid: Option<[u8; 16]>,
}

/// Single-port protocol dispatcher for Mirage bridges.
///
/// One [`ProtocolMux`] instance is shared across all accepted
/// connections (typically via `Arc`). It peeks the first bytes of each
/// connection to classify the protocol, then attempts transport-level
/// authentication for opaque (non-TLS, non-HTTP) streams.
///
/// # Protocol classification order
///
/// 1. TLS `ClientHello` (`0x16 0x03 ...`) - returned immediately,
///    bytes not consumed.
/// 2. HTTP verb prefix - returned immediately, bytes not consumed.
/// 3. obfs-tcp BLAKE3 auth (if enabled) - 64 auth bytes consumed on
///    success.
/// 4. Shadowsocks-2022 AEAD header (if PSK configured) - delegated to
///    [`ss2022_peek_verify_fresh`](mirage_transport_shadowsocks::ss2022_peek_verify_fresh).
/// 5. VLESS auth frame (if UUID configured) - 26 auth bytes consumed; no
///    standalone server response (F21 0-RTT), the session handles the rest.
/// 6. Fallthrough -> `Unknown`.
pub struct ProtocolMux {
    config: MuxConfig,
}

impl ProtocolMux {
    /// Construct a new mux from the given bridge configuration.
    ///
    /// Cheap: does no I/O and allocates nothing.
    pub fn new(config: MuxConfig) -> Self {
        Self { config }
    }

    /// Detect the protocol and attempt auth for opaque transports.
    ///
    /// Uses non-consuming `peek` for classification; inline consuming
    /// reads only for opaque auth material that the session layer does
    /// not need to see.
    ///
    /// # Arguments
    ///
    /// * `stream` - accepted TCP connection (not yet read from).
    /// * `deadline` - total time budget for detection **and** auth.
    ///   The function applies the deadline to every I/O call; if it
    ///   expires the connection is returned as `Unknown`.
    ///
    /// # Errors
    ///
    /// Returns `Err` only on irrecoverable I/O errors (e.g. the peer
    /// RST'd the connection). Classification failures (wrong auth, no
    /// bytes) are signalled via [`MuxResult::Unknown`], not `Err`.
    pub async fn accept(
        &self,
        mut stream: TcpStream,
        deadline: Duration,
        seen_salts: &mirage_transport::SeenNonceSet,
    ) -> Result<MuxResult, std::io::Error> {
        // Step 1: peek first 8 bytes (non-consuming) for fast classification.
        let mut peek_buf = [0u8; 8];
        let n = match tokio::time::timeout(deadline, stream.peek(&mut peek_buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                debug!("mux: peek(8) timed out - returning Unknown");
                return Ok(MuxResult::Unknown(stream));
            }
        };

        if n < 1 {
            trace!("mux: peer closed before sending any bytes - Unknown");
            return Ok(MuxResult::Unknown(stream));
        }

        // n <= peek_buf.len() (8) by construction from peek().
        #[allow(clippy::indexing_slicing)]
        let kind = detect_kind(&peek_buf[..n]);
        trace!("mux: detected kind={kind:?} from {n} peeked bytes");

        match kind {
            ProtocolKind::Tls => {
                debug!("mux: TLS ClientHello - handing off to REALITY handler");
                return Ok(MuxResult::Tls(stream));
            }
            ProtocolKind::Http => {
                debug!("mux: HTTP request - handing off to HTTP handler");
                return Ok(MuxResult::Http(stream));
            }
            _ => {} // opaque - fall through to auth attempts
        }

        // Step 2: For opaque bytes, peek 64 bytes and try each transport.
        // 192 bytes: enough for the obfs (64) / VLESS (26) prefixes AND the full
        // SS-2022 opening - salt(16) + length chunk(18) + header chunk (up to
        // type/ts/atyp/addr/port/padlen = 18 + up to 64 padding + 16 tag) - so the
        // freshness peek (red-team round 2) can decrypt the whole header
        // non-consumingly.
        let mut auth_buf = [0u8; 192];
        let n = match tokio::time::timeout(deadline, stream.peek(&mut auth_buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                debug!("mux: peek(64) timed out - returning Unknown");
                return Ok(MuxResult::Unknown(stream));
            }
        };

        // Try obfs-tcp first: cheapest (one BLAKE3 verify, no I/O).
        if self.config.obfs_enabled && n >= 64 {
            // SAFETY: slices are exactly 32 bytes - try_into() cannot fail.
            #[allow(clippy::indexing_slicing)]
            let nonce: &[u8; 32] = auth_buf[..32]
                .try_into()
                .expect("slice is 32 bytes; infallible");
            #[allow(clippy::indexing_slicing)]
            let presented_tag: &[u8; 32] = auth_buf[32..64]
                .try_into()
                .expect("slice is 32 bytes; infallible");

            if obfs_auth_verify_with_secret(
                &self.config.bridge_static_pk,
                self.config.obfs_secret.as_ref(),
                nonce,
                presented_tag,
            ) {
                // Active-probe defense (mirrors the SS-2022 branch below): the
                // obfs auth tag is a deterministic function of (bridge_static_pk,
                // nonce) with NO timestamp/freshness, so a captured 64-byte knock
                // replays byte-for-byte and would draw the confirming
                // AuthenticatedObfsTcp path - a bridge confirmation for an active
                // prober. The 32-byte nonce is per-connection random; reject a
                // previously-seen nonce and fall through to the next transport /
                // cover (bytes intact, no confirmation). A legitimate client
                // never reuses its nonce.
                if seen_salts.check_and_insert(*nonce, std::time::Instant::now()) {
                    debug!("mux: obfs-tcp auth verified - consuming 64 auth bytes");
                    // Consume the 64 auth bytes so the session layer sees
                    // application data at byte 0.
                    let mut consume_buf = [0u8; 64];
                    stream.read_exact(&mut consume_buf).await?;
                    return Ok(MuxResult::AuthenticatedObfsTcp(stream));
                }
                trace!("mux: obfs-tcp nonce replay - falling through to next transport");
            } else {
                trace!("mux: obfs-tcp BLAKE3 verify failed - trying next transport");
            }
        }

        // Try Shadowsocks-2022 (if PSK is configured).
        // SS-2022 needs at least 34 bytes: 16-byte salt + 18-byte
        // encrypted length chunk. The auth attempt is non-consuming (peek).
        // Candidate SS-2022 PSKs: the operator's client PSK, then the relay-leg
        // PSK (C1). AEAD makes at most one verify Fresh, so trying both on the
        // same non-consuming peek is safe; the winner (if any) is auth'd once
        // AFTER the loop so `stream` is moved exactly once.
        let ss_psks: [Option<[u8; 32]>; 2] = [self.config.ss_psk, self.config.relay_ss_psk];
        let ss_psks: Vec<[u8; 32]> = ss_psks.into_iter().flatten().collect();
        if !ss_psks.is_empty() {
            if n >= 34 {
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let mut winner: Option<[u8; 32]> = None;
                for psk in &ss_psks {
                    #[allow(clippy::indexing_slicing)]
                    match mirage_transport_shadowsocks::ss2022_peek_verify_fresh(
                        psk,
                        &auth_buf[..n],
                        now_secs,
                    ) {
                        mirage_transport_shadowsocks::Ss2022PeekVerdict::Fresh => {
                            // Fresh under THIS psk (no other psk can also be Fresh).
                            // Reject a REPLAYED salt within the timestamp window.
                            #[allow(clippy::indexing_slicing)]
                            let salt_key = {
                                let mut k = [0u8; 32];
                                k[..16].copy_from_slice(&auth_buf[..16]);
                                k
                            };
                            if seen_salts.check_and_insert(salt_key, std::time::Instant::now()) {
                                winner = Some(*psk);
                            } else {
                                trace!("mux: SS-2022 salt replay - falling through to cover");
                            }
                            break;
                        }
                        mirage_transport_shadowsocks::Ss2022PeekVerdict::Reject => continue,
                        mirage_transport_shadowsocks::Ss2022PeekVerdict::NeedMoreBytes => {
                            trace!(
                                "mux: SS-2022 header not fully peeked - falling through to cover"
                            );
                            break;
                        }
                    }
                }
                if let Some(psk) = winner {
                    debug!("mux: Shadowsocks-2022 fresh peek ok - running server handshake");
                    // The peek was non-consuming, so the salt + encrypted header are
                    // still in the kernel buffer; the full server handshake re-reads
                    // them, replies, and yields the decrypted carrier.
                    let ss_stream =
                        mirage_transport_shadowsocks::ss2022_server_auth(stream, &psk, deadline)
                            .await
                            .map_err(|e| {
                                std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    format!("ss2022 server auth: {e}"),
                                )
                            })?;
                    return Ok(MuxResult::AuthenticatedShadowsocks(Box::pin(ss_stream)));
                }
            } else {
                trace!(
                    "mux: only {n} bytes peeked - too few for SS-2022 ({} needed)",
                    34
                );
            }
        }

        // Try VLESS (if UUID is configured).
        // VLESS header is 26 bytes. Probabilistic pre-filter on the fixed
        // structural bytes (spec-faithful order: version=0x00 at offset 0,
        // addon_len=0x00 at 17, command=0x01 at 18) avoids a full read_exact on
        // non-VLESS connections. The full auth (UUID + all fields) is validated
        // by vless_server_auth.
        if let Some(vless_uuid) = self.config.vless_uuid {
            // Need at least 26 bytes in the peek buffer and a 64-byte buffer
            // only has 64 bytes, but VLESS header is 26 - within range.
            // Re-peek with a 26-byte window if the earlier peek was short.
            let vless_peek = if n >= 26 {
                // n <= auth_buf.len() (64), so auth_buf[..26] is always valid.
                #[allow(clippy::indexing_slicing)]
                Some(&auth_buf[..26])
            } else {
                None
            };

            if let Some(peeked26) = vless_peek {
                // Probabilistic filter: check structural bytes before doing
                // the consuming read. This avoids the read_exact for the vast
                // majority of non-VLESS opaque streams.
                #[allow(clippy::indexing_slicing)]
                let looks_like_vless = peeked26[0] == 0x00   // version (spec order)
                    && peeked26[17] == 0x00                  // addon_len
                    && peeked26[18] == 0x01; // command CONNECT

                if looks_like_vless {
                    let vless_config = VlessConfig {
                        authorized_uuids: vec![vless_uuid],
                    };
                    // RT #2: validate the FULL VLESS frame on the PEEKED bytes
                    // (non-consuming) and only consume on success. Previously
                    // `vless_server_auth` consumed the 26-byte frame even on
                    // failure, so a probe with a wrong UUID left the stream
                    // truncated - uncover-forwardable, and the decoy then saw a
                    // mangled prefix. Now a failed probe falls through with all
                    // bytes intact.
                    #[allow(clippy::indexing_slicing)]
                    let vless_ok = n >= VLESS_CLIENT_FRAME_LEN
                        && vless_server_peek_auth(&vless_config, &auth_buf[..n]);
                    if vless_ok {
                        // Consume exactly the validated frame. F21 (0-RTT): do
                        // NOT emit a standalone 2-byte VLESS server response -
                        // even enveloped in the outer transport it read as a
                        // distinctive tiny server-first record + an extra RTT.
                        // The client pipelined Noise msg1 right after its header
                        // (client speaks first); we go straight to the session,
                        // whose msg2 is the server's first flight.
                        let mut consume = [0u8; VLESS_CLIENT_FRAME_LEN];
                        stream.read_exact(&mut consume).await?;
                        debug!("mux: VLESS authenticated - 0-RTT, no standalone response");
                        return Ok(MuxResult::AuthenticatedVless(stream));
                    }
                    trace!("mux: VLESS peek-auth failed - falling through to cover (bytes intact)");
                }
            } else {
                trace!(
                    "mux: only {n} bytes peeked - too few for VLESS ({} needed)",
                    26
                );
            }
        }

        warn!("mux: no transport matched - proxying to cover destination");
        Ok(MuxResult::Unknown(stream))
    }
}

// Protocol detection

/// Classify the first bytes of an incoming connection.
///
/// This function is pure and allocation-free. It examines up to 8 bytes
/// and returns the most specific classification it can make. It errs on
/// the side of `OpaqueUnknown` rather than mis-classifying.
///
/// Called on the result of a `TcpStream::peek` so bytes remain in the
/// kernel socket buffer and will be re-read by the downstream handler.
pub fn detect_kind(bytes: &[u8]) -> ProtocolKind {
    // TLS record layer: content-type=0x16 (Handshake), version major=0x03.
    // Bounds-checked explicitly above via len() >= 2.
    #[allow(clippy::indexing_slicing)]
    if bytes.len() >= 2 && bytes[0] == 0x16 && bytes[1] == 0x03 {
        return ProtocolKind::Tls;
    }

    // HTTP/1.x request methods. We match the first 4 bytes (sufficient to
    // distinguish all common verbs unambiguously within 8 bytes).
    let http_prefixes: &[&[u8]] = &[
        b"GET ", // GET  (4)
        b"POST", // POST (4)
        b"HEAD", // HEAD (4)
        b"PUT ", // PUT  (4)
        b"CONN", // CONNECT (4 of 7)
        b"DELE", // DELETE  (4 of 6)
        b"OPTI", // OPTIONS (4 of 7)
    ];
    for prefix in http_prefixes {
        // Bounds-checked explicitly via len() >= prefix.len().
        #[allow(clippy::indexing_slicing)]
        if bytes.len() >= prefix.len() && &bytes[..prefix.len()] == *prefix {
            return ProtocolKind::Http;
        }
    }

    ProtocolKind::OpaqueUnknown
}

// Unit tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_tls_record_header() {
        // TLS 1.0 ClientHello record header (version 0x0301)
        let bytes = [0x16u8, 0x03, 0x01, 0x00, 0x5a, 0x01, 0x00, 0x00];
        assert_eq!(detect_kind(&bytes), ProtocolKind::Tls);
    }

    #[test]
    fn detect_tls_12_record_header() {
        // TLS 1.2 version field in the outer record
        let bytes = [0x16u8, 0x03, 0x03, 0x00, 0x5a, 0x01, 0x00, 0x00];
        assert_eq!(detect_kind(&bytes), ProtocolKind::Tls);
    }

    #[test]
    fn detect_http_get() {
        let bytes = b"GET /path HTTP/1.1";
        assert_eq!(detect_kind(bytes), ProtocolKind::Http);
    }

    #[test]
    fn detect_http_post() {
        let bytes = b"POST /api HTTP/1.1";
        assert_eq!(detect_kind(bytes), ProtocolKind::Http);
    }

    #[test]
    fn detect_http_head() {
        let bytes = b"HEAD / HTTP/1.1\r\n";
        assert_eq!(detect_kind(bytes), ProtocolKind::Http);
    }

    #[test]
    fn detect_http_connect() {
        let bytes = b"CONNECT example.com:443";
        assert_eq!(detect_kind(bytes), ProtocolKind::Http);
    }

    #[test]
    fn detect_opaque_unknown() {
        // Random-looking high-entropy bytes (e.g. obfs handshake or noise)
        let bytes = [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe];
        assert_eq!(detect_kind(&bytes), ProtocolKind::OpaqueUnknown);
    }

    #[test]
    fn detect_opaque_unknown_all_zeros() {
        let bytes = [0u8; 8];
        assert_eq!(detect_kind(&bytes), ProtocolKind::OpaqueUnknown);
    }

    #[test]
    fn detect_short_slice_not_tls() {
        // Only 1 byte - not enough for TLS check (needs 2).
        let bytes = [0x16u8];
        // bytes[1] doesn't exist so we can't confirm TLS - should be Unknown.
        assert_eq!(detect_kind(&bytes), ProtocolKind::OpaqueUnknown);
    }

    #[test]
    fn detect_empty_slice() {
        assert_eq!(detect_kind(&[]), ProtocolKind::OpaqueUnknown);
    }
}
