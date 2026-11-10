//! Mux frame wire format.

use thiserror::Error;

/// Maximum total mux-frame bytes including the 7-byte header.
///
/// 16384 = `mirage_session::MAX_FRAME_PLAINTEXT`. A mux frame that
/// fills a whole Mirage session frame's plaintext budget is the
/// upper bound; smaller frames let the framer batch multiple mux
/// frames into one session frame.
pub const MAX_MUX_FRAME_LEN: usize = 16384;

/// Bytes of header preceding the body: 2 (`frame_len`) + 4 (`stream_id`) +
/// 1 (cmd) = 7. Body length = `frame_len - MUX_HEADER_LEN`.
pub const MUX_HEADER_LEN: usize = 2 + 4 + 1;

/// Maximum body bytes in a single mux frame.
pub const MAX_MUX_FRAME_BODY: usize = MAX_MUX_FRAME_LEN - MUX_HEADER_LEN;

/// Mux frame command byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MuxCmd {
    /// Open a new stream. Body = serialized [`crate::MuxTarget`].
    Begin = 0x01,
    /// Acknowledge a Begin from the peer; data may now flow.
    BeginOk = 0x02,
    /// Application bytes.
    Data = 0x03,
    /// Per-direction credit grant. Body = `u32 BE` byte count to add.
    WindowUpdate = 0x04,
    /// Sender half-closes write side. Receiver may still send.
    EndLocal = 0x05,
    /// Hard abort. Body = 1-byte error code.
    Reset = 0x06,
}

impl MuxCmd {
    /// Parse from a wire byte. `Err` for unknown commands.
    pub fn from_byte(b: u8) -> Result<Self, MuxFrameError> {
        match b {
            0x01 => Ok(Self::Begin),
            0x02 => Ok(Self::BeginOk),
            0x03 => Ok(Self::Data),
            0x04 => Ok(Self::WindowUpdate),
            0x05 => Ok(Self::EndLocal),
            0x06 => Ok(Self::Reset),
            _ => Err(MuxFrameError::UnknownCommand(b)),
        }
    }
}

/// Errors produced by mux frame encoding/decoding.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MuxFrameError {
    /// `frame_len` field claims more bytes than the input contains.
    #[error("truncated: frame_len {claimed} exceeds buffer {buf_len}")]
    Truncated {
        /// Claimed length.
        claimed: usize,
        /// Actual buffer length.
        buf_len: usize,
    },
    /// `frame_len` exceeds [`MAX_MUX_FRAME_LEN`].
    #[error("frame too large ({0} > {MAX_MUX_FRAME_LEN})")]
    TooLarge(usize),
    /// `frame_len` smaller than the 7-byte header.
    #[error("frame too small ({0} < {MUX_HEADER_LEN})")]
    TooSmall(usize),
    /// Body bytes don't match the header's `frame_len`.
    #[error("body length mismatch")]
    BodyLength,
    /// Unknown command byte.
    #[error("unknown command 0x{0:02x}")]
    UnknownCommand(u8),
    /// `stream_id == 0` outside its reserved use.
    #[error("stream_id 0 reserved for connection-level frames")]
    ReservedStreamId,
}

/// A parsed mux frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuxFrame {
    /// Stream this frame applies to. ID `0` is reserved.
    pub stream_id: u32,
    /// Command.
    pub command: MuxCmd,
    /// Body bytes (no header).
    pub body: Vec<u8>,
}

impl MuxFrame {
    /// Construct. Errors if body too large or `stream_id` == 0.
    pub fn new(stream_id: u32, command: MuxCmd, body: Vec<u8>) -> Result<Self, MuxFrameError> {
        if stream_id == 0 {
            return Err(MuxFrameError::ReservedStreamId);
        }
        if MUX_HEADER_LEN + body.len() > MAX_MUX_FRAME_LEN {
            return Err(MuxFrameError::TooLarge(MUX_HEADER_LEN + body.len()));
        }
        Ok(Self {
            stream_id,
            command,
            body,
        })
    }

    /// Total wire size of this frame (header + body).
    pub fn wire_size(&self) -> usize {
        MUX_HEADER_LEN + self.body.len()
    }

    /// Serialize to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let total = self.wire_size();
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&(total as u16).to_be_bytes());
        out.extend_from_slice(&self.stream_id.to_be_bytes());
        out.push(self.command as u8);
        out.extend_from_slice(&self.body);
        out
    }

    /// Encode into a caller-provided buffer. Returns the byte count
    /// written. `buf` MUST be at least [`Self::wire_size`] bytes.
    pub fn encode_into(&self, buf: &mut [u8]) -> Result<usize, MuxFrameError> {
        let total = self.wire_size();
        if buf.len() < total {
            return Err(MuxFrameError::Truncated {
                claimed: total,
                buf_len: buf.len(),
            });
        }
        buf[0..2].copy_from_slice(&(total as u16).to_be_bytes());
        buf[2..6].copy_from_slice(&self.stream_id.to_be_bytes());
        buf[6] = self.command as u8;
        buf[MUX_HEADER_LEN..total].copy_from_slice(&self.body);
        Ok(total)
    }

    /// Parse one mux frame from the start of `buf`. Returns the
    /// frame and the number of bytes consumed. Trailing bytes are
    /// left for the caller (typical pattern: a TCP / session-frame
    /// reader holds a buffer that can contain multiple mux frames
    /// back-to-back).
    pub fn decode_one(buf: &[u8]) -> Result<(Self, usize), MuxFrameError> {
        if buf.len() < MUX_HEADER_LEN {
            return Err(MuxFrameError::Truncated {
                claimed: MUX_HEADER_LEN,
                buf_len: buf.len(),
            });
        }
        let frame_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        if frame_len < MUX_HEADER_LEN {
            return Err(MuxFrameError::TooSmall(frame_len));
        }
        if frame_len > MAX_MUX_FRAME_LEN {
            return Err(MuxFrameError::TooLarge(frame_len));
        }
        if buf.len() < frame_len {
            return Err(MuxFrameError::Truncated {
                claimed: frame_len,
                buf_len: buf.len(),
            });
        }
        let stream_id = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
        if stream_id == 0 {
            return Err(MuxFrameError::ReservedStreamId);
        }
        let command = MuxCmd::from_byte(buf[6])?;
        let body = buf[MUX_HEADER_LEN..frame_len].to_vec();
        Ok((
            Self {
                stream_id,
                command,
                body,
            },
            frame_len,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn frame_encode_decode_roundtrip() {
        let f = MuxFrame::new(42, MuxCmd::Data, b"hello mux".to_vec()).unwrap();
        let buf = f.encode();
        assert_eq!(buf.len(), f.wire_size());
        let (back, consumed) = MuxFrame::decode_one(&buf).unwrap();
        assert_eq!(back, f);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn empty_body_roundtrip() {
        let f = MuxFrame::new(1, MuxCmd::EndLocal, Vec::new()).unwrap();
        let buf = f.encode();
        let (back, _) = MuxFrame::decode_one(&buf).unwrap();
        assert_eq!(back.body.len(), 0);
        assert_eq!(back.command, MuxCmd::EndLocal);
    }

    #[test]
    fn max_body_size_roundtrip() {
        let body = vec![0xABu8; MAX_MUX_FRAME_BODY];
        let f = MuxFrame::new(1, MuxCmd::Data, body.clone()).unwrap();
        let buf = f.encode();
        let (back, _) = MuxFrame::decode_one(&buf).unwrap();
        assert_eq!(back.body, body);
    }

    #[test]
    fn body_over_cap_rejected_at_construct() {
        let body = vec![0u8; MAX_MUX_FRAME_BODY + 1];
        let err = MuxFrame::new(1, MuxCmd::Data, body).unwrap_err();
        assert!(matches!(err, MuxFrameError::TooLarge(_)));
    }

    #[test]
    fn stream_id_zero_rejected() {
        assert_eq!(
            MuxFrame::new(0, MuxCmd::Data, vec![]).unwrap_err(),
            MuxFrameError::ReservedStreamId
        );
        // Decoding a hand-built frame with stream_id=0 also rejects.
        let mut buf = vec![0u8; MUX_HEADER_LEN];
        buf[0..2].copy_from_slice(&(MUX_HEADER_LEN as u16).to_be_bytes());
        // stream_id stays 0
        buf[6] = MuxCmd::Data as u8;
        assert_eq!(
            MuxFrame::decode_one(&buf).unwrap_err(),
            MuxFrameError::ReservedStreamId
        );
    }

    #[test]
    fn unknown_command_rejected() {
        let mut buf = vec![0u8; MUX_HEADER_LEN];
        buf[0..2].copy_from_slice(&(MUX_HEADER_LEN as u16).to_be_bytes());
        buf[2..6].copy_from_slice(&1u32.to_be_bytes());
        buf[6] = 0xFE;
        assert!(matches!(
            MuxFrame::decode_one(&buf),
            Err(MuxFrameError::UnknownCommand(0xFE))
        ));
    }

    #[test]
    fn truncated_buffer_rejected() {
        let f = MuxFrame::new(1, MuxCmd::Data, vec![0u8; 100]).unwrap();
        let buf = f.encode();
        for cut in 0..buf.len() {
            assert!(MuxFrame::decode_one(&buf[..cut]).is_err());
        }
    }

    #[test]
    fn frame_len_too_small_rejected() {
        let mut buf = vec![0u8; MUX_HEADER_LEN];
        buf[0..2].copy_from_slice(&(MUX_HEADER_LEN as u16 - 1).to_be_bytes());
        buf[2..6].copy_from_slice(&1u32.to_be_bytes());
        buf[6] = MuxCmd::Data as u8;
        assert!(matches!(
            MuxFrame::decode_one(&buf),
            Err(MuxFrameError::TooSmall(_))
        ));
    }

    #[test]
    fn frame_len_over_cap_rejected() {
        let mut buf = vec![0u8; MUX_HEADER_LEN];
        buf[0..2].copy_from_slice(&((MAX_MUX_FRAME_LEN + 1) as u16).to_be_bytes());
        buf[2..6].copy_from_slice(&1u32.to_be_bytes());
        buf[6] = MuxCmd::Data as u8;
        assert!(matches!(
            MuxFrame::decode_one(&buf),
            Err(MuxFrameError::TooLarge(_))
        ));
    }

    #[test]
    fn back_to_back_frames_decoded_separately() {
        // Concat two frames; decode_one consumes the first, leaves
        // the second in the trailing bytes.
        let f1 = MuxFrame::new(1, MuxCmd::Data, vec![1, 2, 3]).unwrap();
        let f2 = MuxFrame::new(2, MuxCmd::Data, vec![4, 5, 6]).unwrap();
        let mut buf = f1.encode();
        buf.extend_from_slice(&f2.encode());
        let (back1, c1) = MuxFrame::decode_one(&buf).unwrap();
        assert_eq!(back1, f1);
        let (back2, c2) = MuxFrame::decode_one(&buf[c1..]).unwrap();
        assert_eq!(back2, f2);
        assert_eq!(c1 + c2, buf.len());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[test]
        fn proptest_frame_roundtrips(
            stream_id in 1u32..u32::MAX,
            cmd_byte in prop_oneof![Just(0x01u8), Just(0x02), Just(0x03), Just(0x04), Just(0x05), Just(0x06)],
            body in prop::collection::vec(any::<u8>(), 0..1024),
        ) {
            let cmd = MuxCmd::from_byte(cmd_byte).unwrap();
            let f = MuxFrame::new(stream_id, cmd, body.clone()).unwrap();
            let encoded = f.encode();
            let (back, consumed) = MuxFrame::decode_one(&encoded).unwrap();
            prop_assert_eq!(back.stream_id, stream_id);
            prop_assert_eq!(back.command, cmd);
            prop_assert_eq!(back.body, body);
            prop_assert_eq!(consumed, encoded.len());
        }

        #[test]
        fn proptest_arbitrary_buffer_never_panics(
            buf in prop::collection::vec(any::<u8>(), 0..2048)
        ) {
            let _ = MuxFrame::decode_one(&buf);
        }
    }
}
