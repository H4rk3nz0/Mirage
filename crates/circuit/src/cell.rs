//! Circuit cell wire format.
//!
//! Cells are the multiplexing primitive inside a Mirage session
//! that carries circuit traffic. They are fixed-size to defeat
//! length-based traffic analysis at the per-cell layer (the outer
//! session-frame layer is plaintext-driven; the cell layer is the
//! one that actually pads).
//!
//! See `lib.rs` for the wire-format diagram. This module contains
//! the encoder, decoder, and command constants.

use thiserror::Error;

/// Fixed cell length on the wire. 1024 bytes matches Tor's cell
/// size and fits comfortably inside a Mirage session frame
/// (`MAX_FRAME_PLAINTEXT = 16384`), allowing up to 16 cells
/// per session frame for batching.
pub const CIRCUIT_CELL_LEN: usize = 1024;

/// Header bytes preceding the payload: `circ_id(4)` + cmd(1) +
/// `pad_len(2)` = 7 bytes.
pub const CELL_HEADER_LEN: usize = 4 + 1 + 2;

/// Maximum payload bytes (cell length minus header). The decoder
/// returns the unpadded slice via [`Cell::body`].
pub const MAX_CELL_PAYLOAD: usize = CIRCUIT_CELL_LEN - CELL_HEADER_LEN;

// Command bytes

/// Reserved; an all-zero cell is invalid.
pub const CMD_RESERVED: u8 = 0x00;

/// `CREATE`: client -> first hop. Carries Mirage handshake message
/// 1 (Noise-XX `e` + ML-KEM-768 `ek`) destined for that hop.
pub const CMD_CREATE: u8 = 0x01;

/// `CREATED`: first hop -> client. Carries Mirage handshake message
/// 2 (Noise-XX `e` + `ee` + `s` + `es` + ML-KEM-768 `ct`).
pub const CMD_CREATED: u8 = 0x02;

/// `EXTEND`: client -> already-established hop. Body contains the
/// next hop's address + handshake message 1 to be relayed.
pub const CMD_EXTEND: u8 = 0x03;

/// `EXTENDED`: already-established hop -> client. Body contains
/// the next hop's handshake message 2.
pub const CMD_EXTENDED: u8 = 0x04;

/// `RELAY`: onion-encrypted application traffic. Inner payload is
/// itself a sub-frame with command + body for the destination hop.
pub const CMD_RELAY: u8 = 0x05;

/// `RELAY` sub-command: `BEGIN` opens a stream to a destination
/// (host:port via SOCKS5-style addressing) at the exit hop.
pub const CMD_BEGIN: u8 = 0x06;

/// `RELAY` sub-command: `DATA` carries application payload bytes
/// for an open stream.
pub const CMD_DATA: u8 = 0x07;

/// `RELAY` sub-command: `END` closes a stream cleanly.
pub const CMD_END: u8 = 0x08;

/// `DESTROY`: tear down a circuit. Bidirectional. Receiver MUST
/// drop circuit state and forward the destroy to the next hop if
/// any.
pub const CMD_DESTROY: u8 = 0x09;

/// `RELAY` sub-command: `PADDING` cell carries no application
/// data - used to pad otherwise-idle circuits to a fixed cadence.
pub const CMD_PADDING: u8 = 0x0A;

/// `RESOLVE`: client -> second-to-last hop ("R") in a split-exit
/// circuit. Body = [`crate::split_exit::ResolveBody`] -
/// `(stream_id, host, port)`. R performs DNS, then issues a
/// [`CMD_HANDOFF`] cell to the last hop ("F") carrying only the
/// resolved IP. The byte stream itself flows via the existing
/// [`CMD_RELAY`] / `RELAY_DATA` path with F as the terminating hop.
///
/// This is the v0.2 "split-exit" primitive: no single relay holds
/// both the destination hostname (R has it) and the application
/// bytes (F has them).
pub const CMD_RESOLVE: u8 = 0x0B;

/// `HANDOFF`: R -> F on the inter-hop link inside a split-exit
/// circuit. Body = [`crate::split_exit::HandoffBody`] -
/// `(stream_id, ip, port)`. The body deliberately does NOT carry
/// the original hostname - F's view of the destination is reduced
/// to an IP literal. Codec rejects domain ATYPs at the type level.
pub const CMD_HANDOFF: u8 = 0x0C;

/// `HANDOFF_RESULT`: F -> R on the same inter-hop link, signalling
/// whether F's TCP connect to the resolved IP succeeded. Body =
/// [`crate::split_exit::HandoffResultBody`] - `(stream_id, status)`.
/// On `Ok` R forwards a stream-open notification back to the
/// client (via existing `BEGIN_OK`-style RELAY traffic); on any
/// failure R tears down the stream.
pub const CMD_HANDOFF_RESULT: u8 = 0x0D;

/// `EXTENDED_CONT`: established hop -> client, continuation chunk
/// of `hs_msg2` when the EXTENDED body is too large to fit in a
/// single cell. Phase 2G addition (closes [RT-O3] in the reverse
/// direction). Mirrors `CMD_EXTEND_CONT`.
pub const CMD_EXTENDED_CONT: u8 = 0x10;

/// `CREATE_CONT`: client -> first hop (or bridge-to-bridge),
/// continuation chunk of `hs_msg1` for an in-flight `CMD_CREATE`
/// fragmentation. Phase 2I addition - symmetric to
/// `CMD_EXTEND_CONT` for the **initial** per-hop handshake.
///
/// Why CREATE also fragments: the bridge-daemon's outbound link
/// to the next hop carries `CMD_CREATE` (with the client's
/// `hs_msg1`) inside a session - same 1024 B cell cap as the
/// client->hop-0 EXTEND. Without CONT support, the daemon would
/// fail to forward EXTEND-derived CREATEs to the next bridge.
///
/// Wire shape: stream-oriented (no `chunk_idx`). Cells arrive in
/// order; receiver accumulates until total declared length is
/// reached.
pub const CMD_CREATE_CONT: u8 = 0x11;

/// `CREATED_CONT`: bridge -> client (or bridge-to-bridge),
/// continuation chunk of `hs_msg2` for an in-flight `CMD_CREATED`
/// fragmentation. Phase 2I addition - symmetric to
/// `CMD_EXTENDED_CONT` for the initial per-hop handshake.
pub const CMD_CREATED_CONT: u8 = 0x12;

/// `EXTEND_CONT`: client -> established hop, continuation chunk
/// of `hs_msg1` when the EXTEND body is too large to fit in a
/// single cell. Body = [`crate::extend::ExtendContBody`] -
/// `chunk_data`.
///
/// Phase 2G addition (closes [RT-O3]). Mirage's session
/// handshake `msg_1` is 1221 B (Noise-XX `msg_1` + ML-KEM-768 ek);
/// adding the EXTEND header pushes the wire body to ~1262 B,
/// which does not fit in the 1017 B cell payload. Fragmentation
/// across `CMD_EXTEND` (first chunk + header) + N `CMD_EXTEND_CONT`
/// (subsequent chunks) preserves the fixed-size cell invariant.
///
/// The bridge accumulates chunks IN ORDER (cells arrive in order
/// over the session) until `accumulated.len() ==
/// total_hs_msg1_len`, then dispatches as if a single EXTEND had
/// arrived. Order-dependence is acceptable because the underlying
/// session-frame layer guarantees ordered, non-duplicated delivery.
pub const CMD_EXTEND_CONT: u8 = 0x0F;

/// `EXTEND_FINISH`: client -> established hop, third Mirage
/// handshake message for the new hop. Body =
/// [`crate::extend::ExtendFinishBody`] - `hs_msg3`.
///
/// Phase 2G addition (closes [RT-O2]). The original
/// EXTEND/EXTENDED protocol carried only `msg_1` / `msg_2` - but
/// Mirage's session-layer handshake is 3-message (Noise-XX +
/// ML-KEM with capability-token in `msg_3`), so the responder
/// needs `msg_3` to verify the token and reach transport mode.
///
/// Wire path:
///
/// - 2-hop case: client sends `CMD_EXTEND_FINISH` directly to
///   hop-0 on the established session. Hop-0 detects the command
///   (via `BridgeCircuitState::process_inbound_from_prev`) and
///   forwards the `hs_msg3` bytes to hop-1's transport as a
///   `CMD_EXTEND_FINISH` on the next-hop link.
/// - 3+ hop case: client onion-seals the cell with the existing
///   forward layers, sends as `CMD_RELAY`, the destination
///   bridge's `handle_relay_from_prev` peels and detects the
///   inner `CMD_EXTEND_FINISH`, then forwards as above.
///
/// Added in Phase 2G.
pub const CMD_EXTEND_FINISH: u8 = 0x0E;

// Errors

/// Errors produced by cell encoding/decoding.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CellError {
    /// Caller-supplied buffer is not exactly [`CIRCUIT_CELL_LEN`].
    #[error("wrong cell length (got {got}, expected {CIRCUIT_CELL_LEN})")]
    WrongLength {
        /// Actual length of the buffer.
        got: usize,
    },
    /// Decoded cell uses a reserved command byte (`0x00`).
    #[error("reserved command byte 0x00")]
    ReservedCommand,
    /// Decoded cell's `pad_len` field exceeds the payload area.
    #[error("pad_len {pad_len} exceeds payload {MAX_CELL_PAYLOAD}")]
    PadLenTooLarge {
        /// The offending value.
        pad_len: u16,
    },
    /// Caller asked to encode a body larger than the payload area.
    #[error("body too large ({len} > {MAX_CELL_PAYLOAD})")]
    BodyTooLarge {
        /// The offending body length.
        len: usize,
    },
    /// `circ_id` of zero is reserved.
    #[error("circ_id 0 is reserved")]
    ZeroCircuitId,
    /// CSPRNG failed when filling pad bytes. Cells fail-closed
    /// because deterministic-zero padding would broadcast "this is
    /// a Mirage cell" if a downstream cipher flaw ever leaked the
    /// pad area. Caller MUST refuse to send rather than transmit
    /// a non-randomized cell.
    #[error("CSPRNG failure during cell pad fill")]
    Csprng,
}

// Cell struct

/// A parsed circuit cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cell {
    /// Circuit identifier on the wire this cell came from. Per-hop
    /// independent: Hop A's view of a circuit has a different
    /// `circ_id` than Hop B's view, even for the same logical
    /// client-side circuit.
    pub circ_id: u32,
    /// Command byte ([`CMD_*`]).
    pub command: u8,
    /// Unpadded body bytes. Length 0..=[`MAX_CELL_PAYLOAD`] - 0
    /// (because the [`pad_len`] suffix is removed at decode).
    pub body: Vec<u8>,
}

impl Cell {
    /// Construct a new cell. `body` is the unpadded payload; the
    /// encoder pads to [`CIRCUIT_CELL_LEN`].
    pub fn new(circ_id: u32, command: u8, body: Vec<u8>) -> Result<Self, CellError> {
        if circ_id == 0 {
            return Err(CellError::ZeroCircuitId);
        }
        if body.len() > MAX_CELL_PAYLOAD {
            return Err(CellError::BodyTooLarge { len: body.len() });
        }
        if command == CMD_RESERVED {
            return Err(CellError::ReservedCommand);
        }
        Ok(Self {
            circ_id,
            command,
            body,
        })
    }

    /// Encode to a fixed-size 1024-byte buffer. Trailing bytes are
    /// random padding so the cell on the wire reveals no length
    /// information.
    pub fn encode(&self) -> Result<[u8; CIRCUIT_CELL_LEN], CellError> {
        if self.body.len() > MAX_CELL_PAYLOAD {
            return Err(CellError::BodyTooLarge {
                len: self.body.len(),
            });
        }
        let pad_len = (MAX_CELL_PAYLOAD - self.body.len()) as u16;
        let mut out = [0u8; CIRCUIT_CELL_LEN];
        out[0..4].copy_from_slice(&self.circ_id.to_be_bytes());
        out[4] = self.command;
        out[5..7].copy_from_slice(&pad_len.to_be_bytes());
        out[CELL_HEADER_LEN..CELL_HEADER_LEN + self.body.len()].copy_from_slice(&self.body);
        // Random pad fill is fail-closed: CSPRNG failure aborts the
        // encode rather than emit a deterministic-zero cell that
        // would identify itself as Mirage if any downstream cipher
        // flaw ever surfaced the pad bytes.
        let pad_start = CELL_HEADER_LEN + self.body.len();
        if pad_start < CIRCUIT_CELL_LEN {
            getrandom::fill(&mut out[pad_start..]).map_err(|_| CellError::Csprng)?;
        }
        Ok(out)
    }

    /// Encode to the supplied buffer slice. Caller MUST provide a
    /// slice of exactly [`CIRCUIT_CELL_LEN`] bytes.
    pub fn encode_into(&self, buf: &mut [u8]) -> Result<(), CellError> {
        if buf.len() != CIRCUIT_CELL_LEN {
            return Err(CellError::WrongLength { got: buf.len() });
        }
        if self.body.len() > MAX_CELL_PAYLOAD {
            return Err(CellError::BodyTooLarge {
                len: self.body.len(),
            });
        }
        let pad_len = (MAX_CELL_PAYLOAD - self.body.len()) as u16;
        buf[0..4].copy_from_slice(&self.circ_id.to_be_bytes());
        buf[4] = self.command;
        buf[5..7].copy_from_slice(&pad_len.to_be_bytes());
        buf[CELL_HEADER_LEN..CELL_HEADER_LEN + self.body.len()].copy_from_slice(&self.body);
        let pad_start = CELL_HEADER_LEN + self.body.len();
        if pad_start < CIRCUIT_CELL_LEN {
            getrandom::fill(&mut buf[pad_start..]).map_err(|_| CellError::Csprng)?;
        }
        Ok(())
    }

    /// Parse a wire buffer. Strict about length - input MUST be
    /// exactly [`CIRCUIT_CELL_LEN`] bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, CellError> {
        if buf.len() != CIRCUIT_CELL_LEN {
            return Err(CellError::WrongLength { got: buf.len() });
        }
        let circ_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if circ_id == 0 {
            return Err(CellError::ZeroCircuitId);
        }
        let command = buf[4];
        if command == CMD_RESERVED {
            return Err(CellError::ReservedCommand);
        }
        let pad_len = u16::from_be_bytes([buf[5], buf[6]]);
        if (pad_len as usize) > MAX_CELL_PAYLOAD {
            return Err(CellError::PadLenTooLarge { pad_len });
        }
        let body_end = CIRCUIT_CELL_LEN - (pad_len as usize);
        let body = buf[CELL_HEADER_LEN..body_end].to_vec();
        Ok(Self {
            circ_id,
            command,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn cell_encode_decode_roundtrip() {
        let body = b"hello mirage circuit".to_vec();
        let cell = Cell::new(0xC0DEF00D, CMD_RELAY, body.clone()).unwrap();
        let buf = cell.encode().unwrap();
        assert_eq!(buf.len(), CIRCUIT_CELL_LEN);
        let parsed = Cell::decode(&buf).unwrap();
        assert_eq!(parsed.circ_id, 0xC0DEF00D);
        assert_eq!(parsed.command, CMD_RELAY);
        assert_eq!(parsed.body, body);
    }

    #[test]
    fn empty_body_roundtrips_with_full_padding() {
        let cell = Cell::new(1, CMD_CREATED, vec![]).unwrap();
        let buf = cell.encode().unwrap();
        let parsed = Cell::decode(&buf).unwrap();
        assert_eq!(parsed.body.len(), 0);
        assert_eq!(parsed.command, CMD_CREATED);
    }

    #[test]
    fn max_body_roundtrips_with_zero_padding() {
        let body = vec![0xABu8; MAX_CELL_PAYLOAD];
        let cell = Cell::new(1, CMD_DATA, body.clone()).unwrap();
        let buf = cell.encode().unwrap();
        let parsed = Cell::decode(&buf).unwrap();
        assert_eq!(parsed.body, body);
    }

    #[test]
    fn body_over_cap_rejected_at_construct() {
        let body = vec![0u8; MAX_CELL_PAYLOAD + 1];
        let err = Cell::new(1, CMD_DATA, body).unwrap_err();
        assert!(matches!(err, CellError::BodyTooLarge { .. }));
    }

    #[test]
    fn zero_circ_id_rejected() {
        let err = Cell::new(0, CMD_DATA, vec![]).unwrap_err();
        assert!(matches!(err, CellError::ZeroCircuitId));
        let mut buf = [0u8; CIRCUIT_CELL_LEN];
        // circ_id = 0, command = CMD_DATA
        buf[4] = CMD_DATA;
        assert!(matches!(Cell::decode(&buf), Err(CellError::ZeroCircuitId)));
    }

    #[test]
    fn reserved_command_rejected() {
        let err = Cell::new(1, CMD_RESERVED, vec![]).unwrap_err();
        assert!(matches!(err, CellError::ReservedCommand));
        let mut buf = [0u8; CIRCUIT_CELL_LEN];
        buf[0..4].copy_from_slice(&1u32.to_be_bytes()); // valid circ_id
                                                        // command stays 0x00 = reserved
                                                        // pad_len = MAX_CELL_PAYLOAD
        buf[5..7].copy_from_slice(&(MAX_CELL_PAYLOAD as u16).to_be_bytes());
        assert!(matches!(
            Cell::decode(&buf),
            Err(CellError::ReservedCommand)
        ));
    }

    #[test]
    fn pad_len_overflow_rejected() {
        let mut buf = [0u8; CIRCUIT_CELL_LEN];
        buf[0..4].copy_from_slice(&1u32.to_be_bytes());
        buf[4] = CMD_DATA;
        buf[5..7].copy_from_slice(&((MAX_CELL_PAYLOAD as u16) + 1).to_be_bytes());
        let err = Cell::decode(&buf).unwrap_err();
        assert!(matches!(err, CellError::PadLenTooLarge { .. }));
    }

    #[test]
    fn wrong_length_rejected() {
        assert!(matches!(
            Cell::decode(&[0u8; CIRCUIT_CELL_LEN - 1]),
            Err(CellError::WrongLength { .. })
        ));
        assert!(matches!(
            Cell::decode(&[0u8; CIRCUIT_CELL_LEN + 1]),
            Err(CellError::WrongLength { .. })
        ));
    }

    #[test]
    fn padding_is_random_not_zero() {
        // Two encodings of the same short cell MUST have different
        // padding (CSPRNG-driven). If they don't, the encoder is
        // emitting deterministic padding - a length oracle.
        let cell = Cell::new(1, CMD_RELAY, vec![0xAA; 16]).unwrap();
        let a = cell.encode().unwrap();
        let b = cell.encode().unwrap();
        // Header + body are deterministic, padding region differs.
        let pad_start = CELL_HEADER_LEN + 16;
        assert_eq!(a[..pad_start], b[..pad_start]);
        assert_ne!(
            a[pad_start..],
            b[pad_start..],
            "padding must be random per encode()"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn cell_proptest_roundtrips_arbitrary_bodies(
            circ_id in 1u32..u32::MAX,
            command in 1u8..=255,
            body in prop::collection::vec(any::<u8>(), 0..=MAX_CELL_PAYLOAD),
        ) {
            let cell = Cell::new(circ_id, command, body.clone()).unwrap();
            let buf = cell.encode().unwrap();
            let parsed = Cell::decode(&buf).unwrap();
            prop_assert_eq!(parsed.circ_id, circ_id);
            prop_assert_eq!(parsed.command, command);
            prop_assert_eq!(parsed.body, body);
        }

        #[test]
        fn cell_proptest_arbitrary_buffer_never_panics(
            buf in prop::collection::vec(any::<u8>(), 0..=2048)
        ) {
            let _ = Cell::decode(&buf);
        }
    }
}
