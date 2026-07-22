//! Wire format for discovery announcements, revocations, and master invites.
//!
//! All multi-byte integers big-endian. Signatures are verified against the
//! serialized bytes preceding the signature field.

use crate::error::DiscoveryError;

// Magic + doc types (§5.1, §7.1, §9.2)

/// Protocol magic (`"MI"`) at offset 0 of every discovery document.
pub const MAGIC: [u8; 2] = *b"MI";

/// `doc_type` for a master invite.
pub const DOC_TYPE_INVITE: u8 = 0x10;
/// `doc_type` for an announcement.
pub const DOC_TYPE_ANNOUNCEMENT: u8 = 0x20;
/// `doc_type` for a revocation.
pub const DOC_TYPE_REVOCATION: u8 = 0x30;
/// `doc_type` for a key-rotation announcement (§9.2). v0.1 parse-only.
pub const DOC_TYPE_ROTATION: u8 = 0x40;
/// `doc_type` for a mother-key-signed rotation (§9.3). v0.1 parse-only.
pub const DOC_TYPE_ROTATION_MOTHER: u8 = 0x41;

/// Version byte for v0.1 invites.
pub const INVITE_VERSION_V0_1: u8 = 0x01;
/// Version byte for v0.1 announcements.
pub const ANNOUNCEMENT_VERSION_V0_1: u8 = 0x01;
/// Version byte for v0.1t multi-endpoint announcements.
///
/// Wire layout matches v0.1 up through `primary_endpoint`, then
/// adds `extras_count: u8` (0..=15) followed by `extras_count`
/// additional endpoints encoded via [`Endpoint::encode`]. Signature
/// covers the entire prefix including extras.
///
/// v0.1 parsers reject this version with "unsupported version";
/// v0.1t parsers accept both `0x01` (single-endpoint) and `0x02`
/// (multi-endpoint).
pub const ANNOUNCEMENT_VERSION_V0_1T: u8 = 0x02;
/// Hard cap on number of extra endpoints in a v0.1t announcement.
/// Bounds DHT BEP-44 and DNS-TXT chunking budgets; 15 IPv6 entries
/// total (1 primary + 14 extras) fits comfortably under the 768 B
/// announcement size cap.
pub const ANNOUNCEMENT_MAX_EXTRA_ENDPOINTS: u8 = 14;

/// Compute the wire length of an endpoint at offset `pos` in `buf`,
/// without committing the parse. Used by `decode_prefix` to walk
/// past N endpoints. Errors mirror `Endpoint::decode`.
fn endpoint_wire_len_at(buf: &[u8], pos: usize) -> Result<usize, DiscoveryError> {
    if buf.len() <= pos {
        return Err(DiscoveryError::Wire("endpoint: empty"));
    }
    match buf[pos] {
        0x01 => Ok(1 + 4 + 2),
        0x02 => Ok(1 + 16 + 2),
        0x03 => {
            if buf.len() <= pos + 1 {
                return Err(DiscoveryError::Wire("endpoint: domain truncated"));
            }
            // Validate the claimed domain length against the
            // remaining buffer BEFORE returning the wire-length -
            // otherwise a hostile announcement claims a
            // domain length larger than what fits, and the caller
            // (cohort decoder, ann decoder) walks past the buffer
            // boundary on subsequent slicing. Closes [RT-S4].
            let dlen = buf[pos + 1] as usize;
            // 1 (kind) + 1 (length-byte) + dlen + 2 (port) <= remaining.
            let total = 1usize
                .checked_add(1)
                .and_then(|x| x.checked_add(dlen))
                .and_then(|x| x.checked_add(2))
                .ok_or(DiscoveryError::Wire("endpoint: domain length overflow"))?;
            if pos.checked_add(total).is_none_or(|end| end > buf.len()) {
                return Err(DiscoveryError::Wire(
                    "endpoint: domain length exceeds remaining buffer",
                ));
            }
            Ok(total)
        }
        0x04 => Ok(1 + 56 + 2),
        _ => Err(DiscoveryError::Wire("endpoint: unknown kind")),
    }
}
/// Version byte for v0.1 revocations.
pub const REVOCATION_VERSION_V0_1: u8 = 0x01;

/// Ed25519 signature length.
pub const SIG_LEN: usize = 64;
/// Ed25519 public-key length.
pub const ED25519_PK_LEN: usize = 32;
/// X25519 public-key length.
pub const X25519_PK_LEN: usize = 32;

// Endpoint encoding (§5.2)

/// Endpoint kinds (§5.2).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointKind {
    /// IPv4 + port (6 B body).
    Ipv4 = 0x01,
    /// IPv6 + port (18 B body).
    Ipv6 = 0x02,
    /// Length-prefixed domain + port.
    Domain = 0x03,
    /// Onion v3 (56 B ASCII) + port.
    OnionV3 = 0x04,
}

/// Bridge endpoint (§5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Endpoint {
    /// IPv4 socket address.
    Ipv4 { addr: [u8; 4], port: u16 },
    /// IPv6 socket address.
    Ipv6 { addr: [u8; 16], port: u16 },
    /// Domain-name address (UTF-8 DNS name).
    Domain { domain: String, port: u16 },
    /// Onion v3 ASCII + port.
    OnionV3 { ascii: [u8; 56], port: u16 },
}

impl Endpoint {
    /// Wire-format length of this endpoint including the 1-byte kind tag.
    pub fn wire_len(&self) -> usize {
        1 + match self {
            Endpoint::Ipv4 { .. } => 6,
            Endpoint::Ipv6 { .. } => 18,
            Endpoint::Domain { domain, .. } => 1 + domain.len() + 2,
            Endpoint::OnionV3 { .. } => 58,
        }
    }

    /// Encode to `out`, starting at `pos`. Returns the new position.
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Endpoint::Ipv4 { addr, port } => {
                out.push(EndpointKind::Ipv4 as u8);
                out.extend_from_slice(addr);
                out.extend_from_slice(&port.to_be_bytes());
            }
            Endpoint::Ipv6 { addr, port } => {
                out.push(EndpointKind::Ipv6 as u8);
                out.extend_from_slice(addr);
                out.extend_from_slice(&port.to_be_bytes());
            }
            Endpoint::Domain { domain, port } => {
                out.push(EndpointKind::Domain as u8);
                out.push(domain.len() as u8);
                out.extend_from_slice(domain.as_bytes());
                out.extend_from_slice(&port.to_be_bytes());
            }
            Endpoint::OnionV3 { ascii, port } => {
                out.push(EndpointKind::OnionV3 as u8);
                out.extend_from_slice(ascii);
                out.extend_from_slice(&port.to_be_bytes());
            }
        }
    }

    /// Decode starting at `buf[pos..]`. Returns `(endpoint, bytes_consumed)`.
    fn decode(buf: &[u8]) -> Result<(Self, usize), DiscoveryError> {
        if buf.is_empty() {
            return Err(DiscoveryError::Wire("endpoint: empty"));
        }
        match buf[0] {
            x if x == EndpointKind::Ipv4 as u8 => {
                if buf.len() < 7 {
                    return Err(DiscoveryError::Wire("endpoint: ipv4 truncated"));
                }
                let mut addr = [0u8; 4];
                addr.copy_from_slice(&buf[1..5]);
                let port = u16::from_be_bytes([buf[5], buf[6]]);
                Ok((Endpoint::Ipv4 { addr, port }, 7))
            }
            x if x == EndpointKind::Ipv6 as u8 => {
                if buf.len() < 19 {
                    return Err(DiscoveryError::Wire("endpoint: ipv6 truncated"));
                }
                let mut addr = [0u8; 16];
                addr.copy_from_slice(&buf[1..17]);
                let port = u16::from_be_bytes([buf[17], buf[18]]);
                Ok((Endpoint::Ipv6 { addr, port }, 19))
            }
            x if x == EndpointKind::Domain as u8 => {
                if buf.len() < 2 {
                    return Err(DiscoveryError::Wire("endpoint: domain truncated"));
                }
                let dlen = buf[1] as usize;
                if dlen == 0 || dlen > 253 {
                    return Err(DiscoveryError::Wire("endpoint: domain length invalid"));
                }
                let total = 2 + dlen + 2;
                if buf.len() < total {
                    return Err(DiscoveryError::Wire("endpoint: domain truncated"));
                }
                let domain_bytes = &buf[2..2 + dlen];
                validate_hostname(domain_bytes)?;
                let domain = std::str::from_utf8(domain_bytes)
                    .map_err(|_| DiscoveryError::Wire("endpoint: domain not UTF-8"))?
                    .to_string();
                let port = u16::from_be_bytes([buf[2 + dlen], buf[3 + dlen]]);
                if port == 0 {
                    return Err(DiscoveryError::Wire("endpoint: port 0 reserved"));
                }
                // domain endpoint kind is DEPRECATED in
                // v0.1t. Operators using domain endpoints expose a
                // registrar-level seizure vector and a trivial
                // DNS-block target. We still parse for backward
                // compatibility (older invites in the wild) and
                // surface a one-time tracing warning per process so
                // operators see the deprecation in their logs
                // without spamming.
                tracing::warn!(
                    target: "mirage_discovery::deprecation",
                    domain = %domain,
                    "announcement uses DEPRECATED domain endpoint; \
                     prefer IP/onion endpoints + multi-endpoint extension"
                );
                Ok((Endpoint::Domain { domain, port }, total))
            }
            x if x == EndpointKind::OnionV3 as u8 => {
                if buf.len() < 59 {
                    return Err(DiscoveryError::Wire("endpoint: onion truncated"));
                }
                let mut ascii = [0u8; 56];
                ascii.copy_from_slice(&buf[1..57]);
                let port = u16::from_be_bytes([buf[57], buf[58]]);
                Ok((Endpoint::OnionV3 { ascii, port }, 59))
            }
            _ => Err(DiscoveryError::Wire("endpoint: unknown kind")),
        }
    }
}

/// Validate an ASCII hostname per spec §5.2 (RFC 1123 LDH + §5.2 length caps).
///
/// Rules enforced:
/// - Total length in `[1, 253]`.
/// - Each label in `[1, 63]`.
/// - Each label starts and ends with `[A-Za-z0-9]`.
/// - Interior bytes `[A-Za-z0-9-]`.
/// - No trailing dot.
/// - No Unicode (bytes > 0x7F rejected).
fn validate_hostname(bytes: &[u8]) -> Result<(), DiscoveryError> {
    if bytes.is_empty() || bytes.len() > 253 {
        return Err(DiscoveryError::Wire("domain: invalid total length"));
    }
    // Trailing dot not permitted on the wire.
    if *bytes.last().unwrap() == b'.' {
        return Err(DiscoveryError::Wire("domain: trailing dot not allowed"));
    }
    let mut label_start = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        // All bytes must be ASCII LDH (letter, digit, hyphen) or `.` label sep.
        let ascii_alnum = b.is_ascii_alphanumeric();
        let hyphen = b == b'-';
        let dot = b == b'.';
        if !(ascii_alnum || hyphen || dot) {
            return Err(DiscoveryError::Wire("domain: invalid byte"));
        }
        if dot {
            let label = &bytes[label_start..i];
            validate_label(label)?;
            label_start = i + 1;
        }
    }
    // Final label (after last dot, or the whole string if no dots).
    let final_label = &bytes[label_start..];
    validate_label(final_label)?;
    Ok(())
}

fn validate_label(label: &[u8]) -> Result<(), DiscoveryError> {
    if label.is_empty() || label.len() > 63 {
        return Err(DiscoveryError::Wire("domain: invalid label length"));
    }
    if !label.first().unwrap().is_ascii_alphanumeric() {
        return Err(DiscoveryError::Wire("domain: label must start with alnum"));
    }
    if !label.last().unwrap().is_ascii_alphanumeric() {
        return Err(DiscoveryError::Wire("domain: label must end with alnum"));
    }
    Ok(())
}

// Transport capability bitfield (§5.3)

/// Transport capability bits.
pub mod transport_caps {
    /// REALITY-v2 transport (TLS 1.3 carrier with auth-probe in
    /// `session_id`). Spec §04.
    pub const REALITY_V2: u32 = 1 << 0;
    /// QUIC-MASQUE transport (HTTP/3 CONNECT-UDP / CONNECT-IP via
    /// a CDN-fronted endpoint). Wire format scaffolded in v0.1t;
    /// real `quinn` integration is v0.2.
    pub const QUIC_MASQUE: u32 = 1 << 1;
    /// WebRTC data channel (v0.2).
    pub const WEBRTC: u32 = 1 << 2;
    /// Shadowsocks-2022 (v0.2).
    pub const SHADOWSOCKS_2022: u32 = 1 << 3;
    /// DoH-tunnel (v0.2).
    pub const DOH_TUNNEL: u32 = 1 << 4;
    /// `obfs-tcp`: TCP + BLAKE3-keyed handshake, no TLS layer.
    /// T1-grade signature-DPI
    /// bypass; complementary to REALITY-v2 when the latter's
    /// signature is locally flagged. SHIPPED in v0.1t.
    pub const OBFS_TCP: u32 = 1 << 5;
    /// obfs4: DEPRECATED/RESERVED - the obfs4 transport was removed; this bit
    /// is kept reserved (never reused) for wire compatibility. Never advertised.
    pub const OBFS4: u32 = 1 << 6;
    /// HTTP/WebSocket tunnel: Mirage session over binary WebSocket frames.
    /// Enables CDN-fronted bridge deployment.
    pub const WS_TUNNEL: u32 = 1 << 7;
    /// Hysteria2: QUIC transport with BRUTAL congestion control (v0.2 implementation).
    pub const HYSTERIA2: u32 = 1 << 8;
    /// VLESS framing: UUID-auth layer over Reality TLS or WebSocket.
    pub const VLESS: u32 = 1 << 9;
    /// Meek: domain-fronted HTTP long-polling transport.
    pub const MEEK: u32 = 1 << 10;
    /// Circuit relay: this bridge accepts multi-hop circuit sessions
    /// (CMD_CREATE / CMD_EXTEND / CMD_RELAY) in addition to, or instead
    /// of, SOCKS5-over-Mirage. Phase 2H feature bit.
    pub const CIRCUIT_RELAY: u32 = 1 << 11;
    /// RESERVED (HLS transport was removed - bit kept reserved so it is never
    /// reused; bit 6 is similarly poisoned). Never advertised.
    pub const HLS: u32 = 1 << 12;
    /// Mask of all bits defined for v0.1.
    pub const MASK_V0_1: u32 = REALITY_V2 | QUIC_MASQUE | OBFS_TCP;
    /// Mask of all bits defined for any v0.x.
    pub const MASK_DEFINED: u32 = REALITY_V2
        | QUIC_MASQUE
        | WEBRTC
        | SHADOWSOCKS_2022
        | DOH_TUNNEL
        | OBFS_TCP
        | OBFS4
        | WS_TUNNEL
        | HYSTERIA2
        | VLESS
        | MEEK
        | CIRCUIT_RELAY
        | HLS;

    /// Stable transport names, in bit order. Indexes match the
    /// per-bit `1 << k` shift exactly so a bitfield can be mapped
    /// to names via [`names_for_caps`].
    ///
    /// Names match `mirage_transport::ClientTransport::name`
    /// return values so [`mirage_router::BridgeCandidate.transports`]
    /// can be populated directly from a parsed announcement.
    pub const NAME_REALITY_V2: &str = "reality-v2";
    /// See [`NAME_REALITY_V2`].
    pub const NAME_QUIC_MASQUE: &str = "quic-masque";
    /// See [`NAME_REALITY_V2`].
    pub const NAME_WEBRTC: &str = "webrtc";
    /// See [`NAME_REALITY_V2`].
    pub const NAME_SHADOWSOCKS_2022: &str = "shadowsocks-2022";
    /// See [`NAME_REALITY_V2`].
    pub const NAME_DOH_TUNNEL: &str = "doh-tunnel";
    /// See [`NAME_REALITY_V2`].
    pub const NAME_OBFS_TCP: &str = "obfs-tcp";
    /// See [`NAME_REALITY_V2`].
    pub const NAME_OBFS4: &str = "obfs4";
    /// See [`NAME_REALITY_V2`].
    pub const NAME_WS_TUNNEL: &str = "ws-tunnel";
    /// See [`NAME_REALITY_V2`].
    pub const NAME_HYSTERIA2: &str = "hysteria2";
    /// See [`NAME_REALITY_V2`].
    pub const NAME_VLESS: &str = "vless";
    /// See [`NAME_REALITY_V2`].
    pub const NAME_MEEK: &str = "meek";
    /// See [`NAME_REALITY_V2`].
    pub const NAME_CIRCUIT_RELAY: &str = "circuit-relay";
    /// See [`NAME_REALITY_V2`].
    pub const NAME_HLS: &str = "hls";

    /// Convert a `transport_caps` bitfield to a list of stable
    /// transport names. Order matches bit order; unknown bits are
    /// silently dropped (so a future bit added in a newer
    /// announcement won't crash an older parser).
    pub fn names_for_caps(caps: u32) -> Vec<&'static str> {
        let mut out = Vec::new();
        if caps & REALITY_V2 != 0 {
            out.push(NAME_REALITY_V2);
        }
        if caps & QUIC_MASQUE != 0 {
            out.push(NAME_QUIC_MASQUE);
        }
        if caps & WEBRTC != 0 {
            out.push(NAME_WEBRTC);
        }
        if caps & SHADOWSOCKS_2022 != 0 {
            out.push(NAME_SHADOWSOCKS_2022);
        }
        if caps & DOH_TUNNEL != 0 {
            out.push(NAME_DOH_TUNNEL);
        }
        if caps & OBFS_TCP != 0 {
            out.push(NAME_OBFS_TCP);
        }
        if caps & OBFS4 != 0 {
            out.push(NAME_OBFS4);
        }
        if caps & WS_TUNNEL != 0 {
            out.push(NAME_WS_TUNNEL);
        }
        if caps & HYSTERIA2 != 0 {
            out.push(NAME_HYSTERIA2);
        }
        if caps & VLESS != 0 {
            out.push(NAME_VLESS);
        }
        if caps & MEEK != 0 {
            out.push(NAME_MEEK);
        }
        if caps & CIRCUIT_RELAY != 0 {
            out.push(NAME_CIRCUIT_RELAY);
        }
        if caps & HLS != 0 {
            out.push(NAME_HLS);
        }
        out
    }
}

/// Derive a stable 16-byte operator id from the operator's
/// Ed25519 public key. The operator id is what
/// `mirage_router::HopSelector` uses for anti-affinity - bridges
/// run by the same operator share an id, so the selector never
/// places two of them on the same circuit.
///
/// Closes [RT-H2/H3] at the discovery layer: the verifier of an
/// announcement signature already has the operator pk; calling
/// this gives the canonical id for the bridge candidate.
///
/// Domain-separated label so the id can never collide with any
/// other BLAKE3-of-pk derivation in the protocol.
pub fn operator_id_from_pk(operator_pk: &[u8; ED25519_PK_LEN]) -> [u8; 16] {
    let mut h = mirage_crypto::blake3::Hasher::new();
    h.update(b"mirage-operator-id-v1");
    h.update(operator_pk);
    let full = *h.finalize().as_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

// Announcement (§5.1)

/// A bridge announcement, signed by the operator.
#[derive(Debug, Clone)]
pub struct Announcement {
    /// Unix time of signing.
    pub issued_at: u64,
    /// Unix time when this announcement expires.
    pub expires_at: u64,
    /// Bridge long-term Ed25519 identity.
    pub bridge_ed25519_pk: [u8; ED25519_PK_LEN],
    /// Bridge X25519 static (used in Noise-XX handshake).
    pub bridge_x25519_pk: [u8; X25519_PK_LEN],
    /// Transport capabilities bitfield.
    pub transport_caps: u32,
    /// Primary endpoint at which the bridge accepts connections.
    pub endpoint: Endpoint,
    /// Additional endpoints (v0.1t multi-endpoint extension).
    /// Empty for backward
    /// compatibility with v0.1 single-endpoint announcements.
    /// Operators advertise the same bridge reachable on multiple
    /// IPs / port-hopped addresses; clients pick at random per
    /// connect attempt.
    pub extra_endpoints: Vec<Endpoint>,
    /// Ed25519 signature by the operator over the preceding bytes.
    pub signature: [u8; SIG_LEN],
}

impl Announcement {
    /// Byte offset of the last field before the signature (= signed prefix length).
    pub fn signed_prefix_len(&self) -> usize {
        let base = 4 + 8 + 8 + ED25519_PK_LEN + X25519_PK_LEN + 4 + self.endpoint.wire_len();
        if self.extra_endpoints.is_empty() {
            base
        } else {
            base + 1
                + self
                    .extra_endpoints
                    .iter()
                    .map(|e| e.wire_len())
                    .sum::<usize>()
        }
    }

    /// True if this announcement uses the v0.1t multi-endpoint
    /// extension (i.e., advertises any additional endpoints).
    pub fn is_v0_1t(&self) -> bool {
        !self.extra_endpoints.is_empty()
    }

    /// Iterate every endpoint (primary first, then extras in order).
    /// Caller-friendly accessor for clients selecting a connect target.
    pub fn endpoints(&self) -> impl Iterator<Item = &Endpoint> {
        std::iter::once(&self.endpoint).chain(self.extra_endpoints.iter())
    }

    /// Serialize to wire bytes (includes signature).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.signed_prefix_len() + SIG_LEN);
        self.encode_signed_prefix(&mut out);
        out.extend_from_slice(&self.signature);
        out
    }

    /// Serialize only the signed prefix (for signing or verifying).
    ///
    /// Closes [RT-CN-9] (Phase 2I): always emits version
    /// `ANNOUNCEMENT_VERSION_V0_1T` (multi-endpoint format), with
    /// `extras_count = 0` for the single-endpoint case. The
    /// previous encoder picked `V0_1` for single-endpoint and
    /// `V0_1T` for multi-endpoint - leaking each operator's
    /// redundancy strategy to a passive observer of the discovery
    /// channel (Nostr, DHT, DNS-TXT). With universal V0_1T, an
    /// observer cannot distinguish "operator with single bridge"
    /// from "operator with N bridges" by version byte alone.
    /// V0_1 decoders are accepted on the read path for legacy
    /// announcements that were minted before this change.
    pub fn encode_signed_prefix(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&MAGIC);
        out.push(DOC_TYPE_ANNOUNCEMENT);
        out.push(ANNOUNCEMENT_VERSION_V0_1T);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.bridge_ed25519_pk);
        out.extend_from_slice(&self.bridge_x25519_pk);
        out.extend_from_slice(&self.transport_caps.to_be_bytes());
        self.endpoint.encode(out);
        // Always emit `extras_count` (0 for the single-endpoint
        // case). Bound enforced at construction.
        debug_assert!(self.extra_endpoints.len() <= ANNOUNCEMENT_MAX_EXTRA_ENDPOINTS as usize);
        out.push(self.extra_endpoints.len() as u8);
        for ep in &self.extra_endpoints {
            ep.encode(out);
        }
    }

    /// Like [`Self::decode`] but accepts trailing bytes after the
    /// announcement. Returns the number of bytes consumed so the
    /// caller can continue parsing whatever follows (used by
    /// invite-extension parsing, where the announcement is
    /// followed by TLV extensions).
    pub fn decode_prefix(buf: &[u8]) -> Result<(Self, usize), DiscoveryError> {
        if buf.len() < 89 {
            return Err(DiscoveryError::Wire("announcement: too short for prefix"));
        }
        // Read endpoint(s) span without committing - the resulting
        // total tells decode_prefix exactly how many bytes belong
        // to this announcement so its caller can continue parsing.
        let version = buf[3];
        let mut cursor = 88; // start of primary endpoint
                             // Primary endpoint length.
        let primary_len = endpoint_wire_len_at(buf, cursor)?;
        cursor += primary_len;
        if version == ANNOUNCEMENT_VERSION_V0_1T {
            if buf.len() < cursor + 1 {
                return Err(DiscoveryError::Wire("announcement: truncated extras_count"));
            }
            let extras_count = buf[cursor];
            // Enforce the same cap `decode` does, so a hostile prefix is
            // rejected early rather than after summing up to 255 endpoint spans.
            if extras_count > ANNOUNCEMENT_MAX_EXTRA_ENDPOINTS {
                return Err(DiscoveryError::Wire(
                    "announcement: extras_count exceeds cap",
                ));
            }
            cursor += 1;
            for _ in 0..extras_count as usize {
                let len = endpoint_wire_len_at(buf, cursor)?;
                cursor += len;
            }
        }
        let total = cursor + SIG_LEN;
        if buf.len() < total {
            return Err(DiscoveryError::Wire("announcement: truncated"));
        }
        let ann = Self::decode(&buf[..total])?;
        Ok((ann, total))
    }

    /// Decode from wire bytes. Does NOT verify the signature (caller must).
    pub fn decode(buf: &[u8]) -> Result<Self, DiscoveryError> {
        if buf.len() < 4 + 8 + 8 + 32 + 32 + 4 + 1 + SIG_LEN {
            return Err(DiscoveryError::Wire("announcement: too short"));
        }
        if buf[0..2] != MAGIC {
            return Err(DiscoveryError::Wire("announcement: bad magic"));
        }
        if buf[2] != DOC_TYPE_ANNOUNCEMENT {
            return Err(DiscoveryError::Wire("announcement: wrong doc_type"));
        }
        let version = buf[3];
        if version != ANNOUNCEMENT_VERSION_V0_1 && version != ANNOUNCEMENT_VERSION_V0_1T {
            return Err(DiscoveryError::Wire("announcement: unsupported version"));
        }
        let issued_at = u64::from_be_bytes(buf[4..12].try_into().unwrap());
        let expires_at = u64::from_be_bytes(buf[12..20].try_into().unwrap());
        if expires_at <= issued_at {
            return Err(DiscoveryError::Wire(
                "announcement: expires_at <= issued_at",
            ));
        }
        let mut bridge_ed25519_pk = [0u8; ED25519_PK_LEN];
        bridge_ed25519_pk.copy_from_slice(&buf[20..52]);
        let mut bridge_x25519_pk = [0u8; X25519_PK_LEN];
        bridge_x25519_pk.copy_from_slice(&buf[52..84]);
        let transport_caps = u32::from_be_bytes(buf[84..88].try_into().unwrap());
        if transport_caps & !transport_caps::MASK_DEFINED != 0 {
            return Err(DiscoveryError::Wire("announcement: reserved caps bit set"));
        }
        if transport_caps == 0 {
            return Err(DiscoveryError::Wire("announcement: no caps advertised"));
        }
        let (endpoint, endpoint_len) = Endpoint::decode(&buf[88..])?;
        let mut cursor = 88 + endpoint_len;
        let mut extra_endpoints: Vec<Endpoint> = Vec::new();
        if version == ANNOUNCEMENT_VERSION_V0_1T {
            if buf.len() < cursor + 1 + SIG_LEN {
                return Err(DiscoveryError::Wire(
                    "announcement: truncated v0.1t extras_count",
                ));
            }
            let extras_count = buf[cursor];
            if extras_count > ANNOUNCEMENT_MAX_EXTRA_ENDPOINTS {
                return Err(DiscoveryError::Wire(
                    "announcement: extras_count exceeds cap",
                ));
            }
            cursor += 1;
            for _ in 0..extras_count {
                let (ep, len) = Endpoint::decode(&buf[cursor..])?;
                cursor += len;
                extra_endpoints.push(ep);
            }
        }
        if buf.len() != cursor + SIG_LEN {
            return Err(DiscoveryError::Wire("announcement: length mismatch"));
        }
        let mut signature = [0u8; SIG_LEN];
        signature.copy_from_slice(&buf[cursor..cursor + SIG_LEN]);
        Ok(Self {
            issued_at,
            expires_at,
            bridge_ed25519_pk,
            bridge_x25519_pk,
            transport_caps,
            endpoint,
            extra_endpoints,
            signature,
        })
    }

    /// Verify the signature against the given operator Ed25519 public key.
    pub fn verify(&self, operator_pk: &[u8; ED25519_PK_LEN]) -> Result<(), DiscoveryError> {
        use mirage_crypto::ed25519_dalek::{Signature, VerifyingKey};
        let vk = VerifyingKey::from_bytes(operator_pk)
            .map_err(|_| DiscoveryError::Ed25519("invalid operator pubkey"))?;
        let sig = Signature::from_bytes(&self.signature);
        let mut prefix = Vec::with_capacity(self.signed_prefix_len());
        self.encode_signed_prefix(&mut prefix);
        vk.verify_strict(&prefix, &sig)
            .map_err(|_| DiscoveryError::Signature("verification failed"))
    }
}

// Revocation (§7.1)

/// Reason for revoking a bridge.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationReason {
    /// Bridge key material is believed compromised.
    Compromised = 1,
    /// Bridge decommissioned by operator.
    Decommissioned = 2,
    /// Bridge key rotating; old key revoked in favor of new.
    Rotating = 3,
    /// Bridge credentials expired.
    Expired = 4,
}

impl RevocationReason {
    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Compromised,
            2 => Self::Decommissioned,
            3 => Self::Rotating,
            4 => Self::Expired,
            _ => return None,
        })
    }
}

/// A revocation, signed by the operator.
#[derive(Debug, Clone)]
pub struct Revocation {
    /// Bridge being revoked.
    pub target_ed25519_pk: [u8; ED25519_PK_LEN],
    /// Reason for revocation.
    pub reason: RevocationReason,
    /// Unix time of signing.
    pub issued_at: u64,
    /// Ed25519 signature by the operator over the preceding bytes.
    pub signature: [u8; SIG_LEN],
}

/// Fixed wire length of a revocation.
pub const REVOCATION_LEN: usize = 4 + ED25519_PK_LEN + 1 + 8 + SIG_LEN; // 109

impl Revocation {
    /// Serialize to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(REVOCATION_LEN);
        self.encode_signed_prefix(&mut out);
        out.extend_from_slice(&self.signature);
        out
    }

    /// Serialize the signed prefix (everything except the signature). Used
    /// both internally for `encode()` and by callers that need to sign or
    /// verify outside the struct.
    pub fn encode_signed_prefix(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&MAGIC);
        out.push(DOC_TYPE_REVOCATION);
        out.push(REVOCATION_VERSION_V0_1);
        out.extend_from_slice(&self.target_ed25519_pk);
        out.push(self.reason as u8);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
    }

    /// Decode from wire bytes. Does NOT verify signature.
    pub fn decode(buf: &[u8]) -> Result<Self, DiscoveryError> {
        if buf.len() != REVOCATION_LEN {
            return Err(DiscoveryError::Wire("revocation: wrong length"));
        }
        if buf[0..2] != MAGIC {
            return Err(DiscoveryError::Wire("revocation: bad magic"));
        }
        if buf[2] != DOC_TYPE_REVOCATION {
            return Err(DiscoveryError::Wire("revocation: wrong doc_type"));
        }
        if buf[3] != REVOCATION_VERSION_V0_1 {
            return Err(DiscoveryError::Wire("revocation: unsupported version"));
        }
        let mut target_ed25519_pk = [0u8; ED25519_PK_LEN];
        target_ed25519_pk.copy_from_slice(&buf[4..36]);
        let reason = RevocationReason::from_u8(buf[36])
            .ok_or(DiscoveryError::Wire("revocation: unknown reason"))?;
        let issued_at = u64::from_be_bytes(buf[37..45].try_into().unwrap());
        let mut signature = [0u8; SIG_LEN];
        signature.copy_from_slice(&buf[45..109]);
        Ok(Self {
            target_ed25519_pk,
            reason,
            issued_at,
            signature,
        })
    }

    /// Verify the signature against the given operator Ed25519 public key.
    pub fn verify(&self, operator_pk: &[u8; ED25519_PK_LEN]) -> Result<(), DiscoveryError> {
        use mirage_crypto::ed25519_dalek::{Signature, VerifyingKey};
        let vk = VerifyingKey::from_bytes(operator_pk)
            .map_err(|_| DiscoveryError::Ed25519("invalid operator pubkey"))?;
        let sig = Signature::from_bytes(&self.signature);
        let mut prefix = Vec::with_capacity(45);
        self.encode_signed_prefix(&mut prefix);
        vk.verify_strict(&prefix, &sig)
            .map_err(|_| DiscoveryError::Signature("verification failed"))
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_crypto::ed25519_dalek::{Signer, SigningKey};

    fn op_keypair() -> SigningKey {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        SigningKey::from_bytes(&seed)
    }

    fn fixed_ed25519_pk() -> [u8; 32] {
        [0x11u8; 32]
    }
    fn fixed_x25519_pk() -> [u8; 32] {
        [0x22u8; 32]
    }

    #[test]
    fn endpoint_ipv4_roundtrip() {
        let ep = Endpoint::Ipv4 {
            addr: [1, 2, 3, 4],
            port: 443,
        };
        let mut buf = Vec::new();
        ep.encode(&mut buf);
        assert_eq!(buf.len(), 7);
        let (dec, consumed) = Endpoint::decode(&buf).unwrap();
        assert_eq!(consumed, 7);
        assert_eq!(dec, ep);
    }

    #[test]
    fn endpoint_domain_roundtrip() {
        let ep = Endpoint::Domain {
            domain: "example.com".into(),
            port: 443,
        };
        let mut buf = Vec::new();
        ep.encode(&mut buf);
        let (dec, _) = Endpoint::decode(&buf).unwrap();
        assert_eq!(dec, ep);
    }

    #[test]
    fn endpoint_rejects_zero_length_domain() {
        let buf = vec![EndpointKind::Domain as u8, 0x00, 0x00, 0x01];
        assert!(Endpoint::decode(&buf).is_err());
    }

    fn encoded_domain(domain: &str, port: u16) -> Vec<u8> {
        let mut b = vec![EndpointKind::Domain as u8, domain.len() as u8];
        b.extend_from_slice(domain.as_bytes());
        b.extend_from_slice(&port.to_be_bytes());
        b
    }

    #[test]
    fn hostname_accepts_valid_ldh() {
        for name in [
            "example.com",
            "sub.example.com",
            "x",
            "a-b.c-d.eee",
            "xn--fiq228c.test",
        ] {
            let b = encoded_domain(name, 443);
            assert!(
                Endpoint::decode(&b).is_ok(),
                "valid hostname rejected: {}",
                name
            );
        }
    }

    #[test]
    fn hostname_rejects_unicode() {
        // U+00E9 "é" as UTF-8 0xC3 0xA9.
        let b = encoded_domain("café.com", 443);
        assert!(Endpoint::decode(&b).is_err(), "unicode must be rejected");
    }

    #[test]
    fn hostname_rejects_underscore() {
        let b = encoded_domain("foo_bar.com", 443);
        assert!(Endpoint::decode(&b).is_err(), "underscore must be rejected");
    }

    #[test]
    fn hostname_rejects_leading_hyphen() {
        let b = encoded_domain("-x.com", 443);
        assert!(Endpoint::decode(&b).is_err());
    }

    #[test]
    fn hostname_rejects_trailing_hyphen_in_label() {
        let b = encoded_domain("x-.com", 443);
        assert!(Endpoint::decode(&b).is_err());
    }

    #[test]
    fn hostname_rejects_trailing_dot() {
        let b = encoded_domain("example.com.", 443);
        assert!(Endpoint::decode(&b).is_err());
    }

    #[test]
    fn hostname_rejects_consecutive_dots() {
        let b = encoded_domain("a..b", 443);
        assert!(Endpoint::decode(&b).is_err());
    }

    #[test]
    fn hostname_rejects_oversized_label() {
        let label = "a".repeat(64);
        let name = format!("{}.com", label);
        let b = encoded_domain(&name, 443);
        assert!(Endpoint::decode(&b).is_err());
    }

    #[test]
    fn hostname_rejects_port_zero() {
        let b = encoded_domain("example.com", 0);
        assert!(Endpoint::decode(&b).is_err());
    }

    #[test]
    fn announcement_sign_verify_roundtrip() {
        let op = op_keypair();
        let op_pk: [u8; 32] = op.verifying_key().to_bytes();

        let mut ann = Announcement {
            issued_at: 1_000_000,
            expires_at: 1_003_600,
            bridge_ed25519_pk: fixed_ed25519_pk(),
            bridge_x25519_pk: fixed_x25519_pk(),
            transport_caps: transport_caps::REALITY_V2 | transport_caps::QUIC_MASQUE,
            endpoint: Endpoint::Ipv4 {
                addr: [93, 184, 216, 34],
                port: 443,
            },
            extra_endpoints: Vec::new(),
            signature: [0u8; SIG_LEN],
        };
        let mut prefix = Vec::new();
        ann.encode_signed_prefix(&mut prefix);
        let sig = op.sign(&prefix);
        ann.signature = sig.to_bytes();

        let encoded = ann.encode();
        let decoded = Announcement::decode(&encoded).expect("decode");
        assert_eq!(decoded.issued_at, ann.issued_at);
        assert_eq!(decoded.endpoint, ann.endpoint);
        assert_eq!(decoded.signature, ann.signature);
        decoded.verify(&op_pk).expect("verify");
    }

    #[test]
    fn announcement_rejects_reserved_caps_bit() {
        let mut buf = vec![0u8; 88];
        buf[0..2].copy_from_slice(&MAGIC);
        buf[2] = DOC_TYPE_ANNOUNCEMENT;
        buf[3] = ANNOUNCEMENT_VERSION_V0_1;
        buf[4..12].copy_from_slice(&1_000_000u64.to_be_bytes());
        buf[12..20].copy_from_slice(&1_003_600u64.to_be_bytes());
        buf[84..88].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes()); // reserved bits
        buf.push(EndpointKind::Ipv4 as u8);
        buf.extend_from_slice(&[1, 2, 3, 4]);
        buf.extend_from_slice(&443u16.to_be_bytes());
        buf.extend_from_slice(&[0u8; SIG_LEN]);
        assert!(Announcement::decode(&buf).is_err());
    }

    #[test]
    fn announcement_rejects_zero_caps() {
        let mut buf = vec![0u8; 88];
        buf[0..2].copy_from_slice(&MAGIC);
        buf[2] = DOC_TYPE_ANNOUNCEMENT;
        buf[3] = ANNOUNCEMENT_VERSION_V0_1;
        buf[4..12].copy_from_slice(&1_000_000u64.to_be_bytes());
        buf[12..20].copy_from_slice(&1_003_600u64.to_be_bytes());
        buf[84..88].copy_from_slice(&0u32.to_be_bytes());
        buf.push(EndpointKind::Ipv4 as u8);
        buf.extend_from_slice(&[1, 2, 3, 4]);
        buf.extend_from_slice(&443u16.to_be_bytes());
        buf.extend_from_slice(&[0u8; SIG_LEN]);
        assert!(Announcement::decode(&buf).is_err());
    }

    #[test]
    fn announcement_rejects_bad_expiry_order() {
        let op = op_keypair();
        let ann = Announcement {
            issued_at: 2_000_000,
            expires_at: 1_000_000, // older than issued - rejected
            bridge_ed25519_pk: fixed_ed25519_pk(),
            bridge_x25519_pk: fixed_x25519_pk(),
            transport_caps: transport_caps::REALITY_V2,
            endpoint: Endpoint::Ipv4 {
                addr: [1, 2, 3, 4],
                port: 443,
            },
            extra_endpoints: Vec::new(),
            signature: [0u8; SIG_LEN],
        };
        let mut prefix = Vec::new();
        ann.encode_signed_prefix(&mut prefix);
        let sig = op.sign(&prefix);
        let mut ann = ann;
        ann.signature = sig.to_bytes();
        let encoded = ann.encode();
        assert!(Announcement::decode(&encoded).is_err());
    }

    #[test]
    fn announcement_verify_rejects_tampered_body() {
        let op = op_keypair();
        let op_pk: [u8; 32] = op.verifying_key().to_bytes();

        let mut ann = Announcement {
            issued_at: 1_000_000,
            expires_at: 1_003_600,
            bridge_ed25519_pk: fixed_ed25519_pk(),
            bridge_x25519_pk: fixed_x25519_pk(),
            transport_caps: transport_caps::REALITY_V2,
            endpoint: Endpoint::Ipv4 {
                addr: [1, 2, 3, 4],
                port: 443,
            },
            extra_endpoints: Vec::new(),
            signature: [0u8; SIG_LEN],
        };
        let mut prefix = Vec::new();
        ann.encode_signed_prefix(&mut prefix);
        ann.signature = op.sign(&prefix).to_bytes();

        // Tamper with the endpoint port after signing.
        ann.endpoint = Endpoint::Ipv4 {
            addr: [1, 2, 3, 4],
            port: 8080,
        };
        assert!(ann.verify(&op_pk).is_err());
    }

    #[test]
    fn announcement_verify_rejects_wrong_operator_key() {
        let op = op_keypair();
        let other_op = op_keypair();
        let other_pk: [u8; 32] = other_op.verifying_key().to_bytes();

        let mut ann = Announcement {
            issued_at: 1_000_000,
            expires_at: 1_003_600,
            bridge_ed25519_pk: fixed_ed25519_pk(),
            bridge_x25519_pk: fixed_x25519_pk(),
            transport_caps: transport_caps::REALITY_V2,
            endpoint: Endpoint::Ipv4 {
                addr: [1, 2, 3, 4],
                port: 443,
            },
            extra_endpoints: Vec::new(),
            signature: [0u8; SIG_LEN],
        };
        let mut prefix = Vec::new();
        ann.encode_signed_prefix(&mut prefix);
        ann.signature = op.sign(&prefix).to_bytes();

        assert!(ann.verify(&other_pk).is_err());
    }

    #[test]
    fn revocation_sign_verify_roundtrip() {
        let op = op_keypair();
        let op_pk: [u8; 32] = op.verifying_key().to_bytes();

        let mut rev = Revocation {
            target_ed25519_pk: [0xAAu8; 32],
            reason: RevocationReason::Compromised,
            issued_at: 1_234_567,
            signature: [0u8; SIG_LEN],
        };
        let mut prefix = Vec::new();
        rev.encode_signed_prefix(&mut prefix);
        rev.signature = op.sign(&prefix).to_bytes();

        let encoded = rev.encode();
        assert_eq!(encoded.len(), REVOCATION_LEN);
        let decoded = Revocation::decode(&encoded).expect("decode");
        assert_eq!(decoded.target_ed25519_pk, rev.target_ed25519_pk);
        assert_eq!(decoded.reason, rev.reason);
        decoded.verify(&op_pk).expect("verify");
    }

    #[test]
    fn revocation_rejects_unknown_reason() {
        let mut buf = vec![0u8; REVOCATION_LEN];
        buf[0..2].copy_from_slice(&MAGIC);
        buf[2] = DOC_TYPE_REVOCATION;
        buf[3] = REVOCATION_VERSION_V0_1;
        buf[36] = 99; // unknown reason
        assert!(Revocation::decode(&buf).is_err());
    }

    // -- v0.1t multi-endpoint announcement (A13) --

    #[test]
    fn multi_endpoint_announcement_roundtrip() {
        // Verify a v0.1t multi-endpoint announcement signs, encodes,
        // decodes, and verifies. Three endpoints (primary IPv4 + two
        // extras: IPv6 and a second IPv4 on a different port).
        let op = op_keypair();
        let op_pk: [u8; 32] = op.verifying_key().to_bytes();

        let mut ann = Announcement {
            issued_at: 1_000_000,
            expires_at: 1_003_600,
            bridge_ed25519_pk: fixed_ed25519_pk(),
            bridge_x25519_pk: fixed_x25519_pk(),
            transport_caps: transport_caps::REALITY_V2,
            endpoint: Endpoint::Ipv4 {
                addr: [93, 184, 216, 34],
                port: 443,
            },
            extra_endpoints: vec![
                Endpoint::Ipv6 {
                    addr: [
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
                    ],
                    port: 443,
                },
                Endpoint::Ipv4 {
                    addr: [93, 184, 216, 35],
                    port: 8443,
                },
            ],
            signature: [0u8; SIG_LEN],
        };
        let mut prefix = Vec::new();
        ann.encode_signed_prefix(&mut prefix);
        ann.signature = op.sign(&prefix).to_bytes();

        // Wire-level: version byte must be V0_1T.
        let encoded = ann.encode();
        assert_eq!(encoded[3], ANNOUNCEMENT_VERSION_V0_1T);
        // Decode + verify: round-trips, signature matches.
        let decoded = Announcement::decode(&encoded).expect("decode");
        assert!(decoded.is_v0_1t());
        assert_eq!(decoded.extra_endpoints.len(), 2);
        decoded.verify(&op_pk).expect("verify");
        // endpoints() iterator yields primary + extras in order.
        let eps: Vec<_> = decoded.endpoints().cloned().collect();
        assert_eq!(eps.len(), 3);
    }

    #[test]
    fn announcement_always_uses_v0_1t_format() {
        // RT-CN-9 closure (Phase 2I): the encoder always emits
        // V0_1T, even for single-endpoint announcements. Closes
        // the operator-redundancy leak that distinguished
        // single-bridge operators from multi-bridge ones via the
        // version byte alone.
        //
        // V0_1 announcements are still ACCEPTED on decode for
        // legacy compatibility - older signed announcements still
        // verify - but newly-minted ones are uniformly V0_1T.
        let op = op_keypair();
        let mut ann = Announcement {
            issued_at: 1_000_000,
            expires_at: 1_003_600,
            bridge_ed25519_pk: fixed_ed25519_pk(),
            bridge_x25519_pk: fixed_x25519_pk(),
            transport_caps: transport_caps::REALITY_V2,
            endpoint: Endpoint::Ipv4 {
                addr: [93, 184, 216, 34],
                port: 443,
            },
            extra_endpoints: Vec::new(),
            signature: [0u8; SIG_LEN],
        };
        let mut prefix = Vec::new();
        ann.encode_signed_prefix(&mut prefix);
        ann.signature = op.sign(&prefix).to_bytes();
        let encoded = ann.encode();
        assert_eq!(
            encoded[3], ANNOUNCEMENT_VERSION_V0_1T,
            "RT-CN-9: encoder must always emit V0_1T regardless of extras count"
        );
        // Decoder still treats this as logically "no extras"
        // since extras_count is 0.
        assert_eq!(ann.extra_endpoints.len(), 0);
        // Round-trip - even though we always encode V0_1T, the
        // decoder accepts it.
        let decoded = Announcement::decode(&encoded).unwrap();
        assert_eq!(decoded.extra_endpoints.len(), 0);
    }

    #[test]
    fn multi_endpoint_decode_rejects_oversize_extras() {
        // A v0.1t announcement claiming more extras than the cap
        // MUST be refused at decode (defense against allocation
        // amplification on a hostile relay).
        // Build a hand-crafted prefix ending with a too-large
        // extras_count byte and assert decode errors.
        let mut buf = Vec::new();
        buf.extend_from_slice(&MAGIC);
        buf.push(DOC_TYPE_ANNOUNCEMENT);
        buf.push(ANNOUNCEMENT_VERSION_V0_1T);
        buf.extend_from_slice(&1_000_000u64.to_be_bytes());
        buf.extend_from_slice(&1_003_600u64.to_be_bytes());
        buf.extend_from_slice(&[0x11u8; 32]);
        buf.extend_from_slice(&[0x22u8; 32]);
        buf.extend_from_slice(&transport_caps::REALITY_V2.to_be_bytes());
        // Primary endpoint: IPv4
        buf.push(EndpointKind::Ipv4 as u8);
        buf.extend_from_slice(&[1, 2, 3, 4]);
        buf.extend_from_slice(&443u16.to_be_bytes());
        // extras_count exceeds cap.
        buf.push(ANNOUNCEMENT_MAX_EXTRA_ENDPOINTS + 1);
        // Pad with zero signature bytes; decode fails before reaching them.
        buf.extend_from_slice(&[0u8; SIG_LEN]);
        let err = Announcement::decode(&buf).expect_err("must reject oversize extras");
        // Only the message text matters here.
        assert!(format!("{err:?}").contains("extras_count"));
    }
}
