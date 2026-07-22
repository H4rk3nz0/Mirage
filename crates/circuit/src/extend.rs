//! `EXTEND` / `EXTENDED` cell-body wire format.
//!
//! Inside a `CMD_EXTEND` or `CMD_EXTENDED` cell's body, the actual
//! handshake bytes are length-prefixed alongside the next-hop's
//! identity / endpoint.
//!
//! ```text
//!  EXTEND body:
//!    next_hop_pk    [u8; 32]              X25519 static of the new hop
//!    endpoint       Endpoint              Ipv4/Ipv6/OnionV3; Domain DEPRECATED
//!    hs_msg1_len    u16 BE
//!    hs_msg1        [hs_msg1_len]         Mirage session msg1 (1221 B fixed in v0.1)
//!
//!  EXTENDED body:
//!    hs_msg2_len    u16 BE
//!    hs_msg2        [hs_msg2_len]         Mirage session msg2 (1189 B fixed in v0.1)
//! ```
//!
//! The endpoint encoding mirrors [`mirage_discovery::wire::Endpoint`]
//! exactly so circuit code can re-use the discovery wire form. We
//! re-encode here rather than depending on `mirage-discovery` to
//! keep the circuit crate's dep graph small (circuit doesn't need
//! the full discovery layer).

use thiserror::Error;

/// Endpoint kinds recognized in EXTEND bodies. Matches
/// [`mirage_discovery::wire::EndpointKind`] but enumerated locally
/// to avoid a discovery-crate dep at this layer.
///
/// `Domain` (kind `0x03`) is intentionally NOT supported here:
/// it is deprecated, and a circuit hop's address SHOULD
/// always be an IP or onion-v3 (the client doesn't trust the local
/// resolver between hops).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum HopEndpoint {
    /// IPv4 + port.
    Ipv4 { addr: [u8; 4], port: u16 },
    /// IPv6 + port.
    Ipv6 { addr: [u8; 16], port: u16 },
    /// Onion v3 ASCII + port.
    OnionV3 { ascii: [u8; 56], port: u16 },
}

impl HopEndpoint {
    /// Wire-format byte length including the 1-byte kind tag.
    pub fn wire_len(&self) -> usize {
        1 + match self {
            HopEndpoint::Ipv4 { .. } => 6,
            HopEndpoint::Ipv6 { .. } => 18,
            HopEndpoint::OnionV3 { .. } => 58,
        }
    }

    /// Encode to `out`. Returns `Err` for inputs the decoder would
    /// reject (e.g., IPv4-mapped IPv6 supplied as `Ipv6` variant).
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), ExtendError> {
        match self {
            HopEndpoint::Ipv4 { addr, port } => {
                if *port == 0 {
                    return Err(ExtendError::Wire("port 0 reserved"));
                }
                out.push(0x01);
                out.extend_from_slice(addr);
                out.extend_from_slice(&port.to_be_bytes());
            }
            HopEndpoint::Ipv6 { addr, port } => {
                if *port == 0 {
                    return Err(ExtendError::Wire("port 0 reserved"));
                }
                if addr[..10] == [0u8; 10] && addr[10] == 0xff && addr[11] == 0xff {
                    return Err(ExtendError::Wire(
                        "IPv4-mapped IPv6 must be encoded as IPv4 (kind 0x01)",
                    ));
                }
                out.push(0x02);
                out.extend_from_slice(addr);
                out.extend_from_slice(&port.to_be_bytes());
            }
            HopEndpoint::OnionV3 { ascii, port } => {
                if *port == 0 {
                    return Err(ExtendError::Wire("port 0 reserved"));
                }
                out.push(0x04);
                out.extend_from_slice(ascii);
                out.extend_from_slice(&port.to_be_bytes());
            }
        }
        Ok(())
    }

    /// Decode starting at `buf[0..]`. Returns `(endpoint, bytes_consumed)`.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), ExtendError> {
        if buf.is_empty() {
            return Err(ExtendError::Wire("endpoint empty"));
        }
        match buf[0] {
            0x01 => {
                if buf.len() < 7 {
                    return Err(ExtendError::Wire("ipv4 truncated"));
                }
                let mut addr = [0u8; 4];
                addr.copy_from_slice(&buf[1..5]);
                let port = u16::from_be_bytes([buf[5], buf[6]]);
                if port == 0 {
                    return Err(ExtendError::Wire("port 0 reserved"));
                }
                Ok((HopEndpoint::Ipv4 { addr, port }, 7))
            }
            0x02 => {
                if buf.len() < 19 {
                    return Err(ExtendError::Wire("ipv6 truncated"));
                }
                let mut addr = [0u8; 16];
                addr.copy_from_slice(&buf[1..17]);
                // RFC 4291 §2.5.5.2: IPv4-mapped form (::ffff:0:0/96)
                // MUST be encoded as IPv4 (kind 0x01). Without this
                // check, two endpoints that point at the same host
                // would have different wire forms - equality
                // comparisons, ACL match, and dedup logic would all
                // diverge from network reality.
                if addr[..10] == [0u8; 10] && addr[10] == 0xff && addr[11] == 0xff {
                    return Err(ExtendError::Wire(
                        "IPv4-mapped IPv6 must be encoded as IPv4 (kind 0x01)",
                    ));
                }
                let port = u16::from_be_bytes([buf[17], buf[18]]);
                if port == 0 {
                    return Err(ExtendError::Wire("port 0 reserved"));
                }
                Ok((HopEndpoint::Ipv6 { addr, port }, 19))
            }
            0x03 => Err(ExtendError::Wire(
                "domain endpoint kind not allowed in EXTEND (deprecated, A14)",
            )),
            0x04 => {
                if buf.len() < 59 {
                    return Err(ExtendError::Wire("onion truncated"));
                }
                let mut ascii = [0u8; 56];
                ascii.copy_from_slice(&buf[1..57]);
                let port = u16::from_be_bytes([buf[57], buf[58]]);
                if port == 0 {
                    return Err(ExtendError::Wire("port 0 reserved"));
                }
                Ok((HopEndpoint::OnionV3 { ascii, port }, 59))
            }
            _ => Err(ExtendError::Wire("unknown endpoint kind")),
        }
    }
}

/// Errors produced by EXTEND/EXTENDED wire encoding/decoding.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExtendError {
    /// Wire format violation.
    #[error("wire: {0}")]
    Wire(&'static str),
    /// Handshake-bytes length over the cell-body cap.
    #[error("handshake bytes too large ({len})")]
    TooLarge {
        /// The offending length.
        len: usize,
    },
}

/// Body of a `CMD_EXTEND` cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendBody {
    /// Static X25519 public key of the next hop. Used by the
    /// **already-established hop** to validate the new hop's
    /// identity matches the announcement the client provided.
    pub next_hop_pk: [u8; 32],
    /// Network endpoint of the next hop.
    pub endpoint: HopEndpoint,
    /// Mirage session message 1 destined for the new hop. The
    /// already-established hop forwards these bytes verbatim to
    /// the new hop over a freshly-opened transport.
    pub hs_msg1: Vec<u8>,
}

impl ExtendBody {
    /// Encode to bytes suitable for placing in a [`Cell`]'s body.
    /// **Will fail with [`ExtendError::TooLarge`] if the encoded
    /// body exceeds the cell-payload cap** - for `hs_msg1` >
    /// ~975 B (typical Mirage handshake `msg_1` = 1221 B), use
    /// [`Self::encode_fragmented`] instead.
    ///
    /// Closes [RT-O3] (Phase 2G+): the previous spec said EXTEND
    /// fits in one cell, but Mirage's handshake `msg_1` (1221 B
    /// with ML-KEM-768) does not. `encode_fragmented` splits
    /// across `CMD_EXTEND` (first chunk + header) plus N
    /// `CMD_EXTEND_CONT` cells.
    pub fn encode(&self) -> Result<Vec<u8>, ExtendError> {
        if self.hs_msg1.len() > u16::MAX as usize {
            return Err(ExtendError::TooLarge {
                len: self.hs_msg1.len(),
            });
        }
        let mut out = Vec::with_capacity(32 + self.endpoint.wire_len() + 2 + self.hs_msg1.len());
        out.extend_from_slice(&self.next_hop_pk);
        self.endpoint.encode(&mut out)?;
        out.extend_from_slice(&(self.hs_msg1.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.hs_msg1);
        Ok(out)
    }

    /// Encode into a sequence of cell bodies, fragmenting `hs_msg1`
    /// across `CMD_EXTEND` (first cell, with header) plus zero or
    /// more `CMD_EXTEND_CONT` continuation cells. Closes [RT-O3].
    ///
    /// Returns `(extend_body, cont_bodies)` where:
    ///
    /// - `extend_body` carries `next_hop_pk + endpoint + total_len + first_chunk`
    ///   and is destined for a `CMD_EXTEND` cell.
    /// - Each entry in `cont_bodies` is a continuation chunk and
    ///   is destined for a `CMD_EXTEND_CONT` cell.
    ///
    /// `max_cell_body` is the per-cell body cap (typically
    /// [`crate::MAX_CELL_PAYLOAD`] = 1017). Caller MUST pass the
    /// same value the cell encoder will enforce.
    pub fn encode_fragmented(
        &self,
        max_cell_body: usize,
    ) -> Result<(Vec<u8>, Vec<Vec<u8>>), ExtendError> {
        if self.hs_msg1.len() > u16::MAX as usize {
            return Err(ExtendError::TooLarge {
                len: self.hs_msg1.len(),
            });
        }
        let header_len = 32 + self.endpoint.wire_len() + 2; // pk + ep + total_len
        if header_len > max_cell_body {
            return Err(ExtendError::TooLarge { len: header_len });
        }
        let first_chunk_cap = max_cell_body - header_len;
        let first_chunk_len = first_chunk_cap.min(self.hs_msg1.len());

        let mut extend_body = Vec::with_capacity(header_len + first_chunk_len);
        extend_body.extend_from_slice(&self.next_hop_pk);
        self.endpoint.encode(&mut extend_body)?;
        extend_body.extend_from_slice(&(self.hs_msg1.len() as u16).to_be_bytes());
        extend_body.extend_from_slice(&self.hs_msg1[..first_chunk_len]);

        let mut cont_bodies = Vec::new();
        let mut cursor = first_chunk_len;
        while cursor < self.hs_msg1.len() {
            let take = max_cell_body.min(self.hs_msg1.len() - cursor);
            cont_bodies.push(self.hs_msg1[cursor..cursor + take].to_vec());
            cursor += take;
        }
        Ok((extend_body, cont_bodies))
    }

    /// Decode from cell body bytes. Strict: rejects truncated
    /// inputs, including the case where `hs_msg1` is shorter than
    /// the declared `total_len` (which would mean continuation
    /// chunks are still in flight - caller MUST instead use
    /// [`ExtendHeader::decode_partial`] to parse the header
    /// without enforcing `total_len` consumption).
    pub fn decode(buf: &[u8]) -> Result<Self, ExtendError> {
        let (header, after_header) = ExtendHeader::decode_partial(buf)?;
        if after_header.len() != header.total_hs_msg1_len {
            return Err(ExtendError::Wire(
                "extend body hs_msg1 length mismatch (expected single-cell encode; \
                 use ExtendHeader::decode_partial for fragmented decode)",
            ));
        }
        Ok(Self {
            next_hop_pk: header.next_hop_pk,
            endpoint: header.endpoint,
            hs_msg1: after_header.to_vec(),
        })
    }
}

/// The fixed-size header at the front of every `CMD_EXTEND` cell
/// body (closes [RT-O3] Phase 2G+ fragmentation). Followed by the
/// first chunk of `hs_msg1`. Subsequent chunks ride in
/// `CMD_EXTEND_CONT` cells (no header - chunk bytes only,
/// in-order).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendHeader {
    /// Next hop's static x25519 pk.
    pub next_hop_pk: [u8; 32],
    /// Next hop's endpoint.
    pub endpoint: HopEndpoint,
    /// Total `hs_msg1` length across all chunks. Bridge uses this
    /// as the reassembly target.
    pub total_hs_msg1_len: usize,
}

/// Hard upper bound on declared `hs_msg1` size accepted by the
/// reassembly path. Closes [RT-P2G-1] (Phase 2G re-scan): without
/// this cap, a malicious peer can claim `total_hs_msg1_len =
/// u16::MAX = 65535` per circuit, holding ~64 KB of bridge memory
/// per inflight EXTEND. With `BridgePolicy::max_circuits = 10000`
/// that's 640 MB - a cheap `DoS`.
///
/// Bound is `2 * MSG_1_LEN` where `MSG_1_LEN = 1221` (Mirage v0.1
/// with ML-KEM-768). The 2x margin allows future PQ KEMs (e.g.,
/// ML-KEM-1024 has a slightly larger ek) without bumping the cap;
/// anything beyond is a protocol violation.
pub const MAX_HS_MSG1_LEN: usize = 2 * 1221;

/// Hard upper bound on declared `hs_msg2` size. Mirrors
/// [`MAX_HS_MSG1_LEN`] for the reverse direction. `MSG_2_LEN =
/// 1189` x 2 = 2378.
pub const MAX_HS_MSG2_LEN: usize = 2 * 1189;

impl ExtendHeader {
    /// Decode the header from the start of a `CMD_EXTEND` cell
    /// body. Returns the parsed header and a slice over the
    /// remaining bytes (the first `hs_msg1` chunk). Caller is
    /// responsible for accumulating subsequent `CMD_EXTEND_CONT`
    /// chunks until total bytes equal `total_hs_msg1_len`.
    ///
    /// Closes [RT-P2G-1]: rejects `total_hs_msg1_len >
    /// MAX_HS_MSG1_LEN` so a malicious peer cannot pin large
    /// reassembly buffers.
    pub fn decode_partial(buf: &[u8]) -> Result<(Self, &[u8]), ExtendError> {
        if buf.len() < 32 {
            return Err(ExtendError::Wire("extend header too short for pk"));
        }
        let mut next_hop_pk = [0u8; 32];
        next_hop_pk.copy_from_slice(&buf[0..32]);
        let (endpoint, ep_len) = HopEndpoint::decode(&buf[32..])?;
        let cursor = 32 + ep_len;
        if buf.len() < cursor + 2 {
            return Err(ExtendError::Wire("extend header truncated at hs len"));
        }
        let total_hs_msg1_len = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]) as usize;
        if total_hs_msg1_len > MAX_HS_MSG1_LEN {
            return Err(ExtendError::Wire(
                "extend header: total_hs_msg1_len exceeds MAX_HS_MSG1_LEN",
            ));
        }
        let after = &buf[cursor + 2..];
        if after.len() > total_hs_msg1_len {
            return Err(ExtendError::Wire(
                "extend header: first chunk longer than declared total",
            ));
        }
        Ok((
            Self {
                next_hop_pk,
                endpoint,
                total_hs_msg1_len,
            },
            after,
        ))
    }
}

/// Body of a `CMD_EXTENDED` cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedBody {
    /// Mirage session message 2 from the new hop. Forwarded
    /// verbatim by the already-established hop back to the client.
    pub hs_msg2: Vec<u8>,
}

impl ExtendedBody {
    /// Encode (single-cell - fails if `hs_msg2` doesn't fit).
    /// For real Mirage handshakes (`hs_msg2 = 1189 B`) use
    /// [`Self::encode_fragmented`] instead. Closes [RT-O3] reverse.
    pub fn encode(&self) -> Result<Vec<u8>, ExtendError> {
        if self.hs_msg2.len() > u16::MAX as usize {
            return Err(ExtendError::TooLarge {
                len: self.hs_msg2.len(),
            });
        }
        let mut out = Vec::with_capacity(2 + self.hs_msg2.len());
        out.extend_from_slice(&(self.hs_msg2.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.hs_msg2);
        Ok(out)
    }

    /// Encode into `(extended_body, cont_bodies)` for fragmented
    /// transmission. Mirrors [`ExtendBody::encode_fragmented`].
    pub fn encode_fragmented(
        &self,
        max_cell_body: usize,
    ) -> Result<(Vec<u8>, Vec<Vec<u8>>), ExtendError> {
        if self.hs_msg2.len() > u16::MAX as usize {
            return Err(ExtendError::TooLarge {
                len: self.hs_msg2.len(),
            });
        }
        let header_len = 2; // total_len u16
        if header_len > max_cell_body {
            return Err(ExtendError::TooLarge { len: header_len });
        }
        let first_chunk_cap = max_cell_body - header_len;
        let first_chunk_len = first_chunk_cap.min(self.hs_msg2.len());

        let mut extended_body = Vec::with_capacity(header_len + first_chunk_len);
        extended_body.extend_from_slice(&(self.hs_msg2.len() as u16).to_be_bytes());
        extended_body.extend_from_slice(&self.hs_msg2[..first_chunk_len]);

        let mut cont_bodies = Vec::new();
        let mut cursor = first_chunk_len;
        while cursor < self.hs_msg2.len() {
            let take = max_cell_body.min(self.hs_msg2.len() - cursor);
            cont_bodies.push(self.hs_msg2[cursor..cursor + take].to_vec());
            cursor += take;
        }
        Ok((extended_body, cont_bodies))
    }

    /// Decode the EXTENDED first cell body. Returns the parsed
    /// `total_hs_msg2_len` plus the bytes of the first chunk.
    /// Caller is responsible for accumulating subsequent
    /// `CMD_EXTENDED_CONT` chunks until total is reached.
    ///
    /// Closes [RT-P2G-5]: rejects `total > MAX_HS_MSG2_LEN` so a
    /// malicious bridge cannot stall the client by claiming a
    /// huge total and dribbling chunks until the global handshake
    /// timeout fires.
    pub fn decode_partial(buf: &[u8]) -> Result<(usize, &[u8]), ExtendError> {
        if buf.len() < 2 {
            return Err(ExtendError::Wire("extended body too short"));
        }
        let hs_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        if hs_len > MAX_HS_MSG2_LEN {
            return Err(ExtendError::Wire(
                "extended body: total_hs_msg2_len exceeds MAX_HS_MSG2_LEN",
            ));
        }
        let after = &buf[2..];
        if after.len() > hs_len {
            return Err(ExtendError::Wire(
                "extended body: first chunk longer than declared total",
            ));
        }
        Ok((hs_len, after))
    }

    /// Decode (single-cell strict - rejects fragmented inputs).
    pub fn decode(buf: &[u8]) -> Result<Self, ExtendError> {
        let (total, chunk) = Self::decode_partial(buf)?;
        if chunk.len() != total {
            return Err(ExtendError::Wire(
                "extended body length mismatch (use decode_partial for fragmented)",
            ));
        }
        Ok(Self {
            hs_msg2: chunk.to_vec(),
        })
    }
}

/// Compact inner-cell format used inside an onion-peeled
/// `CMD_RELAY` body. Phase 2G addition.
///
/// Wire shape:
///
/// ```text
/// [ cmd: u8, body_len: u16 BE, body: [u8; body_len] ]
/// ```
///
/// 3-byte header + body, no padding. The full [`crate::Cell`]
/// encoding is fixed at 1024 bytes which won't fit in another
/// cell's payload (1017 B max minus AEAD overhead). Inner control
/// cells (`CMD_EXTEND`, `CMD_EXTEND_FINISH`, `CMD_DESTROY`) and stream
/// sub-cells (`CMD_BEGIN`, `CMD_DATA`, `CMD_END`, ...) carried inside an
/// onion-encrypted RELAY all use this format.
///
/// `circ_id` is omitted: the bridge dispatches inner cells using
/// the OUTER RELAY's `circ_id`, so no per-inner-cell `circ_id` is
/// needed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySubCell {
    /// Inner command byte. Must be non-zero (0x00 reserved).
    pub command: u8,
    /// Inner body, length-prefixed.
    pub body: Vec<u8>,
}

/// Header overhead of a [`RelaySubCell`] on the wire.
pub const RELAY_SUBCELL_HEADER_LEN: usize = 1 + 2;

/// Maximum body size that fits in a `RelaySubCell` carried inside
/// the smallest plausible RELAY cell. Conservative bound used for
/// length validation.
pub const RELAY_SUBCELL_MAX_BODY: usize = u16::MAX as usize;

impl RelaySubCell {
    /// Encode.
    pub fn encode(&self) -> Result<Vec<u8>, ExtendError> {
        if self.body.len() > RELAY_SUBCELL_MAX_BODY {
            return Err(ExtendError::TooLarge {
                len: self.body.len(),
            });
        }
        let mut out = Vec::with_capacity(RELAY_SUBCELL_HEADER_LEN + self.body.len());
        out.push(self.command);
        out.extend_from_slice(&(self.body.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.body);
        Ok(out)
    }

    /// Decode. Strict on length: rejects trailing garbage so a
    /// malicious peer can't smuggle extra bytes the bridge would
    /// silently ignore.
    pub fn decode(buf: &[u8]) -> Result<Self, ExtendError> {
        if buf.len() < RELAY_SUBCELL_HEADER_LEN {
            return Err(ExtendError::Wire("relay subcell header too short"));
        }
        let command = buf[0];
        if command == 0 {
            return Err(ExtendError::Wire("relay subcell reserved command 0x00"));
        }
        let body_len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
        if buf.len() != RELAY_SUBCELL_HEADER_LEN + body_len {
            return Err(ExtendError::Wire("relay subcell length mismatch"));
        }
        let body = buf[RELAY_SUBCELL_HEADER_LEN..].to_vec();
        Ok(Self { command, body })
    }
}

/// Body of a `CMD_CREATE` or `CMD_CREATED` cell. Phase 2I
/// addition.
///
/// Carries the per-hop handshake message bytes (`hs_msg1` for
/// CREATE, `hs_msg2` for CREATED). Like `ExtendedBody`, it
/// supports fragmentation - `hs_msg` exceeds the 1017 B cell
/// payload cap (1221 B `msg_1`, 1189 B `msg_2` in v0.1), so the
/// first cell carries `[total_len: u16] + first_chunk` and
/// subsequent `CMD_CREATE_CONT` / `CMD_CREATED_CONT` cells
/// carry chunk-only continuations in arrival order.
///
/// Mirrors [`ExtendedBody`]'s codec, with the same length cap
/// for symmetric `DoS` protection ([`MAX_HS_MSG1_LEN`] for
/// CREATE-direction, [`MAX_HS_MSG2_LEN`] for CREATED-direction;
/// the body itself bounds against the larger of the two so a
/// single codec serves both directions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeBody {
    /// The handshake message bytes.
    pub hs_msg: Vec<u8>,
}

/// Hard upper bound for `HandshakeBody` length. Equals
/// `max(MAX_HS_MSG1_LEN, MAX_HS_MSG2_LEN)` - the wire format is
/// shared between CREATE and CREATED, so the bound has to admit
/// the larger of the two. Both directions in v0.1 are within
/// `MAX_HS_MSG1_LEN` since msg1 is the bigger one.
pub const MAX_HANDSHAKE_BODY_LEN: usize = MAX_HS_MSG1_LEN;

impl HandshakeBody {
    /// Encode for a single-cell body. Errors with `TooLarge`
    /// when `hs_msg` exceeds the cell-payload cap (typically
    /// 1015 B = 1017 - 2 for the length prefix). Use
    /// [`Self::encode_fragmented`] for the realistic case.
    pub fn encode(&self) -> Result<Vec<u8>, ExtendError> {
        if self.hs_msg.len() > u16::MAX as usize {
            return Err(ExtendError::TooLarge {
                len: self.hs_msg.len(),
            });
        }
        let mut out = Vec::with_capacity(2 + self.hs_msg.len());
        out.extend_from_slice(&(self.hs_msg.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.hs_msg);
        Ok(out)
    }

    /// Encode into `(first_body, cont_bodies)`. Mirrors
    /// [`ExtendedBody::encode_fragmented`].
    pub fn encode_fragmented(
        &self,
        max_cell_body: usize,
    ) -> Result<(Vec<u8>, Vec<Vec<u8>>), ExtendError> {
        if self.hs_msg.len() > MAX_HANDSHAKE_BODY_LEN {
            return Err(ExtendError::TooLarge {
                len: self.hs_msg.len(),
            });
        }
        let header_len = 2;
        if header_len > max_cell_body {
            return Err(ExtendError::TooLarge { len: header_len });
        }
        let first_chunk_cap = max_cell_body - header_len;
        let first_chunk_len = first_chunk_cap.min(self.hs_msg.len());

        let mut first = Vec::with_capacity(header_len + first_chunk_len);
        first.extend_from_slice(&(self.hs_msg.len() as u16).to_be_bytes());
        first.extend_from_slice(&self.hs_msg[..first_chunk_len]);

        let mut conts = Vec::new();
        let mut cursor = first_chunk_len;
        while cursor < self.hs_msg.len() {
            let take = max_cell_body.min(self.hs_msg.len() - cursor);
            conts.push(self.hs_msg[cursor..cursor + take].to_vec());
            cursor += take;
        }
        Ok((first, conts))
    }

    /// Parse the first cell body, returning
    /// `(total_hs_msg_len, first_chunk_slice)`. Caller
    /// accumulates subsequent CMD_*_CONT chunks until total is
    /// reached. Bounds on `total_hs_msg_len` close the
    /// reassembly-DoS attack vector (RT-P2G-1 family).
    pub fn decode_partial(buf: &[u8]) -> Result<(usize, &[u8]), ExtendError> {
        if buf.len() < 2 {
            return Err(ExtendError::Wire("handshake body too short"));
        }
        let total = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        if total > MAX_HANDSHAKE_BODY_LEN {
            return Err(ExtendError::Wire(
                "handshake body: total exceeds MAX_HS_MSG_LEN",
            ));
        }
        let after = &buf[2..];
        if after.len() > total {
            return Err(ExtendError::Wire(
                "handshake body: first chunk longer than declared total",
            ));
        }
        Ok((total, after))
    }
}

/// Body of a `CMD_EXTEND_FINISH` cell. Phase 2G addition (closes
/// [RT-O2]).
///
/// Carries the third Mirage handshake message for the new hop.
/// The intermediate bridge forwards the bytes verbatim onto the
/// next-hop transport - it does NOT inspect or rewrite them.
///
/// Wire shape mirrors `ExtendedBody`: `u16 BE length` + bytes.
/// Length validation refuses `> u16::MAX` payloads (in practice
/// `msg_3` is fixed at 203 bytes for token-bearing handshakes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendFinishBody {
    /// Mirage session message 3 from the initiator. The bridge
    /// forwards this to the responder; the responder runs
    /// `HandshakeResponder::read_message_3` on it.
    pub hs_msg3: Vec<u8>,
}

impl ExtendFinishBody {
    /// Encode.
    pub fn encode(&self) -> Result<Vec<u8>, ExtendError> {
        if self.hs_msg3.len() > u16::MAX as usize {
            return Err(ExtendError::TooLarge {
                len: self.hs_msg3.len(),
            });
        }
        let mut out = Vec::with_capacity(2 + self.hs_msg3.len());
        out.extend_from_slice(&(self.hs_msg3.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.hs_msg3);
        Ok(out)
    }

    /// Decode.
    pub fn decode(buf: &[u8]) -> Result<Self, ExtendError> {
        if buf.len() < 2 {
            return Err(ExtendError::Wire("extend_finish body too short"));
        }
        let hs_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        if buf.len() < 2 + hs_len {
            return Err(ExtendError::Wire("extend_finish body truncated"));
        }
        let hs_msg3 = buf[2..2 + hs_len].to_vec();
        Ok(Self { hs_msg3 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extend_roundtrip_ipv4() {
        let body = ExtendBody {
            next_hop_pk: [0xCCu8; 32],
            endpoint: HopEndpoint::Ipv4 {
                addr: [203, 0, 113, 1],
                port: 4433,
            },
            hs_msg1: vec![0x42u8; 1221], // realistic Mirage msg1 size
        };
        let encoded = body.encode().unwrap();
        let parsed = ExtendBody::decode(&encoded).unwrap();
        assert_eq!(parsed, body);
    }

    #[test]
    fn extend_roundtrip_ipv6() {
        let body = ExtendBody {
            next_hop_pk: [0xCCu8; 32],
            endpoint: HopEndpoint::Ipv6 {
                addr: [
                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x01,
                ],
                port: 4433,
            },
            hs_msg1: vec![0u8; 100],
        };
        let encoded = body.encode().unwrap();
        let parsed = ExtendBody::decode(&encoded).unwrap();
        assert_eq!(parsed, body);
    }

    #[test]
    fn extend_roundtrip_onion() {
        let body = ExtendBody {
            next_hop_pk: [0xCCu8; 32],
            endpoint: HopEndpoint::OnionV3 {
                ascii: *b"abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx",
                port: 4433,
            },
            hs_msg1: vec![0u8; 100],
        };
        let encoded = body.encode().unwrap();
        let parsed = ExtendBody::decode(&encoded).unwrap();
        assert_eq!(parsed, body);
    }

    #[test]
    fn extend_rejects_domain_endpoint() {
        // Domain endpoint kind (0x03) MUST be refused per A14.
        let mut buf = vec![0u8; 32]; // pk
        buf.push(0x03); // kind = Domain
        buf.push(11); // domain_len
        buf.extend_from_slice(b"example.com");
        buf.extend_from_slice(&443u16.to_be_bytes());
        buf.extend_from_slice(&[0u8; 2]); // hs_len = 0
        let err = ExtendBody::decode(&buf).unwrap_err();
        assert!(matches!(err, ExtendError::Wire(s) if s.contains("domain")));
    }

    #[test]
    fn extended_roundtrip() {
        let body = ExtendedBody {
            hs_msg2: vec![0x99u8; 1189], // realistic Mirage msg2 size
        };
        let encoded = body.encode().unwrap();
        let parsed = ExtendedBody::decode(&encoded).unwrap();
        assert_eq!(parsed, body);
    }

    #[test]
    fn extend_decode_truncated_at_hs_len() {
        let mut buf = vec![0u8; 32]; // pk
        buf.push(0x01); // ipv4
        buf.extend_from_slice(&[127, 0, 0, 1]);
        buf.extend_from_slice(&443u16.to_be_bytes());
        // Missing hs_len bytes.
        let err = ExtendBody::decode(&buf).unwrap_err();
        assert!(matches!(err, ExtendError::Wire(_)));
    }

    #[test]
    fn extend_decode_truncated_hs_payload() {
        let mut buf = vec![0u8; 32]; // pk
        buf.push(0x01); // ipv4
        buf.extend_from_slice(&[127, 0, 0, 1]);
        buf.extend_from_slice(&443u16.to_be_bytes());
        buf.extend_from_slice(&100u16.to_be_bytes()); // hs_len = 100
                                                      // but provide only 10 bytes.
        buf.extend_from_slice(&[0u8; 10]);
        let err = ExtendBody::decode(&buf).unwrap_err();
        assert!(matches!(err, ExtendError::Wire(_)));
    }

    #[test]
    fn endpoint_rejects_ipv4_mapped_ipv6_on_decode() {
        let mut buf = vec![0x02u8];
        buf.extend_from_slice(&[0u8; 10]);
        buf.extend_from_slice(&[0xff, 0xff]);
        buf.extend_from_slice(&[203, 0, 113, 5]);
        buf.extend_from_slice(&443u16.to_be_bytes());
        let err = HopEndpoint::decode(&buf).unwrap_err();
        assert!(matches!(err, ExtendError::Wire(s) if s.contains("IPv4-mapped")));
    }

    #[test]
    fn endpoint_rejects_ipv4_mapped_ipv6_on_encode() {
        let bad = HopEndpoint::Ipv6 {
            addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 203, 0, 113, 5],
            port: 443,
        };
        let mut out = Vec::new();
        let err = bad.encode(&mut out).unwrap_err();
        assert!(matches!(err, ExtendError::Wire(s) if s.contains("IPv4-mapped")));
    }

    #[test]
    fn endpoint_rejects_zero_port() {
        let mut buf = vec![0x01u8]; // ipv4
        buf.extend_from_slice(&[127, 0, 0, 1]);
        buf.extend_from_slice(&0u16.to_be_bytes());
        assert!(
            matches!(HopEndpoint::decode(&buf), Err(ExtendError::Wire(s)) if s.contains("port 0"))
        );
    }

    // --- Phase 2G: ExtendFinishBody (closes [RT-O2]) ---

    #[test]
    fn extend_finish_roundtrip() {
        let body = ExtendFinishBody {
            // Realistic msg_3 size for token-bearing handshake (203 B).
            hs_msg3: vec![0x33u8; 203],
        };
        let encoded = body.encode().unwrap();
        let parsed = ExtendFinishBody::decode(&encoded).unwrap();
        assert_eq!(parsed, body);
    }

    #[test]
    fn extend_finish_roundtrip_no_token_size() {
        let body = ExtendFinishBody {
            // Test-only msg_3 size (67 B, no capability token).
            hs_msg3: vec![0xAA; 67],
        };
        let encoded = body.encode().unwrap();
        let parsed = ExtendFinishBody::decode(&encoded).unwrap();
        assert_eq!(parsed.hs_msg3, body.hs_msg3);
    }

    #[test]
    fn extend_finish_decode_too_short() {
        let buf = vec![0u8]; // only 1 byte; need >= 2 for length prefix
        let err = ExtendFinishBody::decode(&buf).unwrap_err();
        assert!(matches!(err, ExtendError::Wire(s) if s.contains("too short")));
    }

    #[test]
    fn extend_finish_decode_truncated_payload() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&100u16.to_be_bytes()); // claim 100 bytes
        buf.extend_from_slice(&[0u8; 10]); // provide only 10
        let err = ExtendFinishBody::decode(&buf).unwrap_err();
        assert!(matches!(err, ExtendError::Wire(s) if s.contains("truncated")));
    }

    #[test]
    fn extend_finish_decode_empty_msg() {
        // hs_msg3 with len=0 is malformed at the protocol level
        // (the responder's read_message_3 rejects it), but the
        // body codec MUST NOT panic - it just produces an empty
        // Vec which the consumer handles.
        let buf = vec![0u8, 0u8]; // len = 0
        let parsed = ExtendFinishBody::decode(&buf).unwrap();
        assert!(parsed.hs_msg3.is_empty());
    }

    // --- Phase 2G+: fragmentation bounds (closes [RT-P2G-1] / [RT-P2G-5]) ---

    #[test]
    fn extend_header_rejects_total_len_above_max() {
        // Construct a wire buffer that claims total_hs_msg1_len =
        // u16::MAX (> MAX_HS_MSG1_LEN). The decoder must reject
        // before allocating any reassembly buffer.
        let mut buf = vec![0u8; 32]; // pk
        buf.push(0x01); // ipv4 kind
        buf.extend_from_slice(&[127, 0, 0, 1]);
        buf.extend_from_slice(&443u16.to_be_bytes());
        buf.extend_from_slice(&u16::MAX.to_be_bytes()); // total_len = 65535
                                                        // No first chunk bytes (the bound check fires before
                                                        // the chunk-vs-total check).
        let err = ExtendHeader::decode_partial(&buf).unwrap_err();
        assert!(matches!(err, ExtendError::Wire(s) if s.contains("MAX_HS_MSG1_LEN")));
    }

    #[test]
    fn extend_header_accepts_total_len_at_max() {
        // Sanity: MAX_HS_MSG1_LEN itself MUST be accepted.
        let mut buf = vec![0u8; 32];
        buf.push(0x01);
        buf.extend_from_slice(&[127, 0, 0, 1]);
        buf.extend_from_slice(&443u16.to_be_bytes());
        buf.extend_from_slice(&(MAX_HS_MSG1_LEN as u16).to_be_bytes());
        // Empty first chunk (caller will accumulate via CONT).
        let (header, after) = ExtendHeader::decode_partial(&buf).unwrap();
        assert_eq!(header.total_hs_msg1_len, MAX_HS_MSG1_LEN);
        assert!(after.is_empty());
    }

    #[test]
    fn extended_decode_partial_rejects_total_len_above_max() {
        let mut buf = u16::MAX.to_be_bytes().to_vec();
        buf.push(0u8); // single byte of "first chunk"
        let err = ExtendedBody::decode_partial(&buf).unwrap_err();
        assert!(matches!(err, ExtendError::Wire(s) if s.contains("MAX_HS_MSG2_LEN")));
    }

    #[test]
    fn extended_decode_partial_accepts_total_len_at_max() {
        let buf = (MAX_HS_MSG2_LEN as u16).to_be_bytes().to_vec();
        let (total, after) = ExtendedBody::decode_partial(&buf).unwrap();
        assert_eq!(total, MAX_HS_MSG2_LEN);
        assert!(after.is_empty());
    }

    // --- Phase 2I: HandshakeBody fragmentation (CREATE/CREATED) ---

    #[test]
    fn handshake_body_fragmentation_create_path() {
        // hs_msg1 = 1221 B doesn't fit in 1017 B cell payload -
        // exercise the same fragmentation as ExtendedBody.
        let body = HandshakeBody {
            hs_msg: vec![0x77u8; 1221],
        };
        let (first, conts) = body
            .encode_fragmented(crate::cell::MAX_CELL_PAYLOAD)
            .unwrap();
        // First cell: 2 B header + ~1015 B chunk.
        assert_eq!(first.len(), crate::cell::MAX_CELL_PAYLOAD);
        // One continuation: ~206 B.
        assert_eq!(conts.len(), 1);
        let total: usize = first.len() - 2 + conts[0].len();
        assert_eq!(total, 1221);
    }

    #[test]
    fn handshake_body_decode_partial_round_trip() {
        let body = HandshakeBody {
            hs_msg: vec![0x99u8; 1189],
        };
        let (first, conts) = body
            .encode_fragmented(crate::cell::MAX_CELL_PAYLOAD)
            .unwrap();
        let (total_len, first_chunk) = HandshakeBody::decode_partial(&first).unwrap();
        assert_eq!(total_len, 1189);
        let mut accumulated = first_chunk.to_vec();
        for c in conts {
            accumulated.extend_from_slice(&c);
        }
        assert_eq!(accumulated, vec![0x99u8; 1189]);
    }

    #[test]
    fn handshake_body_fragmentation_fits_in_one_cell_when_small() {
        let body = HandshakeBody {
            hs_msg: vec![0x11u8; 100],
        };
        let (first, conts) = body
            .encode_fragmented(crate::cell::MAX_CELL_PAYLOAD)
            .unwrap();
        assert!(conts.is_empty(), "100 B msg fits in one cell");
        let (total_len, chunk) = HandshakeBody::decode_partial(&first).unwrap();
        assert_eq!(total_len, 100);
        assert_eq!(chunk.len(), 100);
    }

    #[test]
    fn handshake_body_decode_rejects_oversized_total_len() {
        let mut buf = u16::MAX.to_be_bytes().to_vec();
        buf.push(0u8);
        let err = HandshakeBody::decode_partial(&buf).unwrap_err();
        assert!(matches!(err, ExtendError::Wire(s) if s.contains("MAX_HS_MSG")));
    }
}
