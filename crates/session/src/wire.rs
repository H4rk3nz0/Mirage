//! Wire format for handshake messages 1, 2, 3 and cleartext alerts.
//!
//! All messages use fixed-size layouts. Parsers reject wrong-length input
//! immediately, before any field-level inspection, to minimize adversary-
//! driven allocation and make fuzzing tractable.

use crate::error::SessionError;

// ---------- constants from §02 ----------

/// Protocol magic bytes ("MI") at offset 0 of every handshake message.
pub const MAGIC: [u8; 2] = *b"MI";

/// Message type discriminator at offset 2.
pub const MSG_TYPE_1: u8 = 0x01;
/// Message type discriminator for message 2.
pub const MSG_TYPE_2: u8 = 0x02;
/// Message type discriminator for message 3.
pub const MSG_TYPE_3: u8 = 0x03;
/// Message type discriminator for the forward-secure-token form of message 3.
///
/// A distinct cleartext type byte is required (not just a length) because the
/// padded-frame reader ([`crate::tunnel::read_padded_handshake_m3`]) must strip
/// random padding to the correct message length, and the legacy (203) and FS
/// (315) padded-length windows overlap (`HS_PAD_MAX` ~1 KB). The type byte lets
/// the reader pick 203 vs 315 before stripping; it is bound to the FS length in
/// [`Message3::decode`] so a type/length mismatch is rejected pre-Noise.
pub const MSG_TYPE_3_FS: u8 = 0x04;
/// Message type discriminator for cleartext alert frames.
pub const MSG_TYPE_ALERT: u8 = 0xFE;

/// Noise-XX message 1 length: the `e` token (32 B) followed by the initiator's
/// ML-KEM-768 encapsulation key carried as the message-1 Noise PAYLOAD.
///
/// Carrying `mlkem_ek` inside the Noise message (rather than appended beside it
/// outside the AEAD) folds it into the Noise transcript hash `h` via `MixHash`
/// (I24). Message 1 is not yet keyed, so the payload rides in cleartext with no
/// AEAD tag - its integrity is the transcript binding: an active MITM that
/// substitutes the ek diverges the peers' `h`, so message 2's `s`/payload AEAD
/// then fails to authenticate, aborting the handshake instead of surfacing as a
/// first-frame outer-layer decrypt error.
pub const NOISE_MSG_1_LEN: usize = 32 + MLKEM_EK_LEN; // 1216
/// Noise-XX message 2 length: `e` (32) + encrypted responder static `s`
/// (32 + 16 tag = 48) + the ML-KEM-768 ciphertext carried as the message-2
/// Noise PAYLOAD, AEAD-encrypted (1088 + 16 tag = 1104).
///
/// Message 2 IS keyed (after `ee`/`es`), so the ct payload gets a real Noise
/// AEAD tag (I24): tampering with the ct on the wire fails the peer's
/// `read_message` with an authentication error during the handshake.
pub const NOISE_MSG_2_LEN: usize = 32 + 48 + MLKEM_CT_LEN + 16; // 1184

/// Noise-XX message 3 length, test-only no-payload form (encrypted `s` +
/// empty payload tag). Kept for state-machine smoke tests; not on the
/// production wire.
pub const NOISE_MSG_3_LEN_NO_TOKEN: usize = 64;
/// Noise-XX message 3 length, conformant form carrying a 136-byte
/// capability-token payload (spec §11.2). `32 + 16 + 136 + 16 = 200`.
pub const NOISE_MSG_3_LEN_WITH_TOKEN: usize = 200;

/// Noise-XX message 3 length, forward-secure-token form. Carries a 248-byte
/// [`FS_TOKEN_PAYLOAD_LEN`] payload: `32 + 16 + 248 + 16 = 312`.
pub const NOISE_MSG_3_LEN_WITH_FS_TOKEN: usize = 312;

/// Capability-token plaintext length, carried inside the Noise msg 3
/// payload (spec §11.1).
pub const TOKEN_PAYLOAD_LEN: usize = 136;

/// Forward-secure capability-token plaintext length, carried inside the Noise
/// msg 3 payload. Larger than [`TOKEN_PAYLOAD_LEN`] because the token embeds an
/// inline epoch-subkey certificate. MUST equal
/// `mirage_discovery::token_fs::FS_TOKEN_LEN`.
pub const FS_TOKEN_PAYLOAD_LEN: usize = 248;

/// ML-KEM-768 encapsulation key length.
pub const MLKEM_EK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length.
pub const MLKEM_CT_LEN: usize = 1088;

/// Message 1 wire length (fixed). Identical to the pre-I24 layout: the
/// `mlkem_ek` bytes moved from a separate trailing field into the Noise
/// message-1 payload (now part of [`NOISE_MSG_1_LEN`]), so the total is
/// unchanged.
pub const MSG_1_LEN: usize = 2 + 1 + 2 + NOISE_MSG_1_LEN; // 1221
/// Message 2 wire length (fixed). Identical to the pre-I24 layout: the
/// `mlkem_ct` bytes moved into the Noise message-2 payload (reusing the former
/// empty-payload AEAD tag as the ct's tag, now part of [`NOISE_MSG_2_LEN`]), so
/// the total is unchanged.
pub const MSG_2_LEN: usize = 2 + 1 + 2 + NOISE_MSG_2_LEN; // 1189
/// Message 3 wire length, test-only no-token form.
pub const MSG_3_LEN_NO_TOKEN: usize = 2 + 1 + NOISE_MSG_3_LEN_NO_TOKEN; // 67
/// Message 3 wire length, conformant token-bearing form.
pub const MSG_3_LEN_WITH_TOKEN: usize = 2 + 1 + NOISE_MSG_3_LEN_WITH_TOKEN; // 203
/// Message 3 wire length, forward-secure-token-bearing form.
pub const MSG_3_LEN_WITH_FS_TOKEN: usize = 2 + 1 + NOISE_MSG_3_LEN_WITH_FS_TOKEN; // 315

/// Maximum length of a cleartext alert reason string (UTF-8 bytes).
pub const ALERT_REASON_MAX: usize = 1024;

// ---------- alert codes (§6.3) ----------

/// Peer's wire version outside supported range.
pub const ALERT_VERSION_MISMATCH: u16 = 0x0001;
/// Noise message parse / ML-KEM parse / bad msg_type / etc.
pub const ALERT_HANDSHAKE_FAILED: u16 = 0x0002;
/// Capability token check failed (reserved for when tokens are wired in).
pub const ALERT_AUTH_FAILED: u16 = 0x0003;
/// AEAD tag verification failed post-handshake.
pub const ALERT_DECRYPT_FAILED: u16 = 0x0004;
/// Frame for epoch outside grace window.
pub const ALERT_EPOCH_SKEW: u16 = 0x0005;
/// Local error (state machine, IO, OOM).
pub const ALERT_INTERNAL_ERROR: u16 = 0x0006;
/// Peer is closing normally.
pub const ALERT_GRACEFUL_CLOSE: u16 = 0x0007;
/// Invariant violation (bad frame lengths, seq gap).
pub const ALERT_PROTOCOL_VIOLATION: u16 = 0x0008;

// ---------- Message 1 ----------

/// Handshake message 1: initiator -> responder. Fixed 1221 bytes.
///
/// `noise_msg_1` is the complete Noise-XX message 1: the `e` token followed by
/// the initiator's ML-KEM-768 encapsulation key carried as the Noise PAYLOAD
/// (so the ek is bound into the transcript hash - see [`NOISE_MSG_1_LEN`] and
/// I24). The on-wire bytes are byte-for-byte identical to the pre-I24 layout
/// (`e || mlkem_ek`), only the framing responsibility moved into the Noise
/// message.
#[derive(Clone)]
pub struct Message1 {
    /// Protocol wire version.
    pub wire_version: u16,
    /// Full Noise-XX message 1: `e` (32 B) || ML-KEM ek payload (1184 B).
    pub noise_msg_1: [u8; NOISE_MSG_1_LEN],
}

impl Message1 {
    /// Encode into a fresh heap-allocated buffer of exactly [`MSG_1_LEN`] bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![0u8; MSG_1_LEN];
        buf[0..2].copy_from_slice(&MAGIC);
        buf[2] = MSG_TYPE_1;
        buf[3..5].copy_from_slice(&self.wire_version.to_be_bytes());
        buf[5..5 + NOISE_MSG_1_LEN].copy_from_slice(&self.noise_msg_1);
        buf
    }

    /// Parse a wire buffer. Rejects wrong-length input up front.
    pub fn decode(buf: &[u8]) -> Result<Self, SessionError> {
        if buf.len() != MSG_1_LEN {
            return Err(SessionError::Wire("message 1: wrong length"));
        }
        if buf[0..2] != MAGIC {
            return Err(SessionError::Wire("message 1: bad magic"));
        }
        if buf[2] != MSG_TYPE_1 {
            return Err(SessionError::Wire("message 1: wrong msg_type"));
        }
        let wire_version = u16::from_be_bytes([buf[3], buf[4]]);
        let mut noise_msg_1 = [0u8; NOISE_MSG_1_LEN];
        noise_msg_1.copy_from_slice(&buf[5..5 + NOISE_MSG_1_LEN]);
        Ok(Self {
            wire_version,
            noise_msg_1,
        })
    }
}

// ---------- Message 2 ----------

/// Handshake message 2: responder -> initiator. Fixed 1189 bytes.
///
/// `noise_msg_2` is the complete Noise-XX message 2: `e`, the encrypted
/// responder static `s`, and the ML-KEM-768 ciphertext carried as the
/// AEAD-encrypted Noise PAYLOAD (bound into the transcript and integrity-
/// protected - see [`NOISE_MSG_2_LEN`] and I24). The total on-wire length is
/// unchanged from the pre-I24 layout.
#[derive(Clone)]
pub struct Message2 {
    /// Protocol wire version (MUST equal initiator's).
    pub wire_version: u16,
    /// Full Noise-XX message 2: `e` (32) || encrypted `s` (48) ||
    /// AEAD-encrypted ML-KEM ct payload (1104).
    pub noise_msg_2: [u8; NOISE_MSG_2_LEN],
}

impl Message2 {
    /// Encode into a fresh heap-allocated buffer of exactly [`MSG_2_LEN`] bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![0u8; MSG_2_LEN];
        buf[0..2].copy_from_slice(&MAGIC);
        buf[2] = MSG_TYPE_2;
        buf[3..5].copy_from_slice(&self.wire_version.to_be_bytes());
        buf[5..5 + NOISE_MSG_2_LEN].copy_from_slice(&self.noise_msg_2);
        buf
    }

    /// Parse a wire buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, SessionError> {
        if buf.len() != MSG_2_LEN {
            return Err(SessionError::Wire("message 2: wrong length"));
        }
        if buf[0..2] != MAGIC {
            return Err(SessionError::Wire("message 2: bad magic"));
        }
        if buf[2] != MSG_TYPE_2 {
            return Err(SessionError::Wire("message 2: wrong msg_type"));
        }
        let wire_version = u16::from_be_bytes([buf[3], buf[4]]);
        let mut noise_msg_2 = [0u8; NOISE_MSG_2_LEN];
        noise_msg_2.copy_from_slice(&buf[5..5 + NOISE_MSG_2_LEN]);
        Ok(Self {
            wire_version,
            noise_msg_2,
        })
    }
}

// ---------- Message 3 ----------

/// Handshake message 3: initiator -> responder.
///
/// Variable length: `MSG_3_LEN_NO_TOKEN` (67 B) for state-machine smoke
/// tests, `MSG_3_LEN_WITH_TOKEN` (203 B) for the conformant capability-
/// token-bearing form (spec §11.2), or `MSG_3_LEN_WITH_FS_TOKEN` (315 B) for
/// the forward-secure token form (embeds an inline epoch-subkey cert).
#[derive(Clone, Debug)]
pub struct Message3 {
    /// Noise-XX message 3 bytes. Length is one of
    /// [`NOISE_MSG_3_LEN_NO_TOKEN`], [`NOISE_MSG_3_LEN_WITH_TOKEN`], or
    /// [`NOISE_MSG_3_LEN_WITH_FS_TOKEN`].
    pub noise_msg_3: Vec<u8>,
}

impl Message3 {
    /// Encode into a fresh heap-allocated buffer. Output length is 3 +
    /// `noise_msg_3.len()` bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(3 + self.noise_msg_3.len());
        buf.extend_from_slice(&MAGIC);
        // The FS-token form carries a distinct cleartext type byte so the
        // padded-frame reader can strip padding to the right length (312-byte FS
        // noise vs 200-byte legacy noise are indistinguishable once random
        // padding is appended). See tunnel::read_padded_handshake_m3.
        if self.noise_msg_3.len() == NOISE_MSG_3_LEN_WITH_FS_TOKEN {
            buf.push(MSG_TYPE_3_FS);
        } else {
            buf.push(MSG_TYPE_3);
        }
        buf.extend_from_slice(&self.noise_msg_3);
        buf
    }

    /// Parse a wire buffer. Accepts [`MSG_3_LEN_NO_TOKEN`],
    /// [`MSG_3_LEN_WITH_TOKEN`], or [`MSG_3_LEN_WITH_FS_TOKEN`].
    pub fn decode(buf: &[u8]) -> Result<Self, SessionError> {
        if buf.len() != MSG_3_LEN_NO_TOKEN
            && buf.len() != MSG_3_LEN_WITH_TOKEN
            && buf.len() != MSG_3_LEN_WITH_FS_TOKEN
        {
            return Err(SessionError::Wire("message 3: wrong length"));
        }
        if buf[0..2] != MAGIC {
            return Err(SessionError::Wire("message 3: bad magic"));
        }
        // The FS-token form uses a distinct type byte; bind it to the FS length
        // so a type/length mismatch is rejected before the Noise layer. The
        // exact-length check above guarantees buf.len() is one of the three
        // canonical values, so this is an exhaustive type<->length pairing.
        let type_ok = if buf.len() == MSG_3_LEN_WITH_FS_TOKEN {
            buf[2] == MSG_TYPE_3_FS
        } else {
            buf[2] == MSG_TYPE_3
        };
        if !type_ok {
            return Err(SessionError::Wire("message 3: wrong msg_type"));
        }
        Ok(Self {
            noise_msg_3: buf[3..].to_vec(),
        })
    }
}

// ---------- Cleartext alert ----------

/// Cleartext alert sent before both sides have session keys (§6.1).
///
/// **DEPRECATED in v0.1t**.
///
/// The cleartext form `MI \xFE alert_code reason_len reason` is a
/// passive distinguisher: any failed handshake under raw-TCP
/// transport (i.e., not Reality-wrapped) reveals the bridge identity
/// to a passive observer who recognises `MI` magic. v0.1t conformant
/// bridges MUST close the TCP connection without sending application
/// bytes on pre-handshake failure (matches a real TLS server's
/// behaviour on a malformed ClientHello).
///
/// The encoder is therefore gated on plain `cfg(test)`, with deliberately no
/// cargo feature able to re-enable it - no shipped build can emit these bytes.
/// The decoder is retained to validate received bytes (e.g., from a
/// misbehaving peer or a v0.1 client sending one) and is unconditionally
/// compiled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleartextAlert {
    /// Alert code (see `ALERT_*` constants).
    pub code: u16,
    /// UTF-8 reason string, <= [`ALERT_REASON_MAX`] bytes.
    pub reason: String,
}

impl CleartextAlert {
    /// Encode into a fresh heap-allocated buffer. Reason is truncated if too long.
    ///
    /// **DEPRECATED, test-only.** Production code MUST NOT call this.
    /// See type-level docs for the rationale (A11).
    ///
    /// Gated on plain `cfg(test)` - there is deliberately NO cargo feature that
    /// can re-enable it, so no shipped build can emit the cleartext `MI \xFE`
    /// alert (a passive bridge distinguisher). The DECODER stays always-compiled
    /// so we can still parse bytes sent by a v0.1 peer.
    #[cfg(test)]
    pub fn encode(&self) -> Vec<u8> {
        let mut reason_bytes = self.reason.as_bytes();
        if reason_bytes.len() > ALERT_REASON_MAX {
            reason_bytes = &reason_bytes[..ALERT_REASON_MAX];
        }
        let reason_len = reason_bytes.len() as u16;
        let mut buf = Vec::with_capacity(7 + reason_bytes.len());
        buf.extend_from_slice(&MAGIC);
        buf.push(MSG_TYPE_ALERT);
        buf.extend_from_slice(&self.code.to_be_bytes());
        buf.extend_from_slice(&reason_len.to_be_bytes());
        buf.extend_from_slice(reason_bytes);
        buf
    }

    /// Parse a wire buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, SessionError> {
        if buf.len() < 7 {
            return Err(SessionError::Wire("alert: too short"));
        }
        if buf[0..2] != MAGIC {
            return Err(SessionError::Wire("alert: bad magic"));
        }
        if buf[2] != MSG_TYPE_ALERT {
            return Err(SessionError::Wire("alert: wrong msg_type"));
        }
        let code = u16::from_be_bytes([buf[3], buf[4]]);
        let reason_len = u16::from_be_bytes([buf[5], buf[6]]) as usize;
        if reason_len > ALERT_REASON_MAX {
            return Err(SessionError::Wire("alert: reason_len exceeds max"));
        }
        if buf.len() != 7 + reason_len {
            return Err(SessionError::Wire("alert: length mismatch"));
        }
        let reason = std::str::from_utf8(&buf[7..7 + reason_len])
            .map_err(|_| SessionError::Wire("alert: reason not UTF-8"))?
            .to_string();
        Ok(Self { code, reason })
    }
}

// ---------- tests ----------

#[cfg(test)]
mod tests {
    use super::*;

    fn rand_bytes<const N: usize>() -> [u8; N] {
        let mut b = [0u8; N];
        getrandom::fill(&mut b).expect("getrandom");
        b
    }

    #[test]
    fn lengths_match_spec() {
        assert_eq!(MSG_1_LEN, 1221, "spec §3.2");
        assert_eq!(MSG_2_LEN, 1189, "spec §3.3");
        // I24: mlkem_ek / mlkem_ct now ride inside the Noise messages, so the
        // NOISE_MSG_* lengths grew to include them while the total MSG_* wire
        // lengths above are unchanged.
        assert_eq!(NOISE_MSG_1_LEN, 1216, "e(32) + mlkem_ek payload(1184)");
        assert_eq!(
            NOISE_MSG_2_LEN, 1184,
            "e(32) + enc s(48) + mlkem_ct(1088) + tag(16)"
        );
        assert_eq!(
            MSG_3_LEN_NO_TOKEN, 67,
            "spec §3.4 (test-only no-token form)"
        );
        assert_eq!(
            MSG_3_LEN_WITH_TOKEN, 203,
            "spec §11.2 (conformant token form)"
        );
        assert_eq!(TOKEN_PAYLOAD_LEN, 136, "spec §11.1");
        assert_eq!(MSG_3_LEN_WITH_FS_TOKEN, 315, "forward-secure token form");
        assert_eq!(NOISE_MSG_3_LEN_WITH_FS_TOKEN, 32 + 16 + 248 + 16);
    }

    #[test]
    fn fs_token_payload_len_matches_discovery() {
        // The wire constant MUST track the discovery crate's FS token length,
        // or the responder will mis-slice the decrypted payload.
        assert_eq!(
            FS_TOKEN_PAYLOAD_LEN,
            mirage_discovery::token_fs::FS_TOKEN_LEN,
            "wire FS_TOKEN_PAYLOAD_LEN must equal token_fs::FS_TOKEN_LEN"
        );
    }

    #[test]
    fn message3_roundtrip_with_fs_token() {
        let noise_msg_3: [u8; NOISE_MSG_3_LEN_WITH_FS_TOKEN] = rand_bytes();
        let m = Message3 {
            noise_msg_3: noise_msg_3.to_vec(),
        };
        let encoded = m.encode();
        assert_eq!(encoded.len(), MSG_3_LEN_WITH_FS_TOKEN);
        let decoded = Message3::decode(&encoded).expect("decode");
        assert_eq!(decoded.noise_msg_3, m.noise_msg_3);
    }

    #[test]
    fn message1_roundtrip() {
        let m = Message1 {
            wire_version: 1,
            noise_msg_1: rand_bytes(),
        };
        let encoded = m.encode();
        assert_eq!(encoded.len(), MSG_1_LEN);
        let decoded = Message1::decode(&encoded).expect("decode");
        assert_eq!(decoded.wire_version, m.wire_version);
        assert_eq!(decoded.noise_msg_1, m.noise_msg_1);
    }

    #[test]
    fn message2_roundtrip() {
        let m = Message2 {
            wire_version: 1,
            noise_msg_2: rand_bytes(),
        };
        let encoded = m.encode();
        assert_eq!(encoded.len(), MSG_2_LEN);
        let decoded = Message2::decode(&encoded).expect("decode");
        assert_eq!(decoded.wire_version, m.wire_version);
        assert_eq!(decoded.noise_msg_2, m.noise_msg_2);
    }

    #[test]
    fn message3_roundtrip_no_token() {
        let noise_msg_3: [u8; NOISE_MSG_3_LEN_NO_TOKEN] = rand_bytes();
        let m = Message3 {
            noise_msg_3: noise_msg_3.to_vec(),
        };
        let encoded = m.encode();
        assert_eq!(encoded.len(), MSG_3_LEN_NO_TOKEN);
        let decoded = Message3::decode(&encoded).expect("decode");
        assert_eq!(decoded.noise_msg_3, m.noise_msg_3);
    }

    #[test]
    fn message3_roundtrip_with_token() {
        let noise_msg_3: [u8; NOISE_MSG_3_LEN_WITH_TOKEN] = rand_bytes();
        let m = Message3 {
            noise_msg_3: noise_msg_3.to_vec(),
        };
        let encoded = m.encode();
        assert_eq!(encoded.len(), MSG_3_LEN_WITH_TOKEN);
        let decoded = Message3::decode(&encoded).expect("decode");
        assert_eq!(decoded.noise_msg_3, m.noise_msg_3);
    }

    #[test]
    fn message3_rejects_intermediate_length() {
        // Any length other than the two canonical ones is rejected.
        let mut buf = vec![0u8; 100];
        buf[0..2].copy_from_slice(&MAGIC);
        buf[2] = MSG_TYPE_3;
        assert!(Message3::decode(&buf).is_err());
    }

    #[test]
    fn alert_roundtrip() {
        let a = CleartextAlert {
            code: ALERT_VERSION_MISMATCH,
            reason: "supported: 1..=1".into(),
        };
        let encoded = a.encode();
        let decoded = CleartextAlert::decode(&encoded).expect("decode");
        assert_eq!(decoded, a);
    }

    #[test]
    fn alert_empty_reason() {
        let a = CleartextAlert {
            code: ALERT_GRACEFUL_CLOSE,
            reason: String::new(),
        };
        let encoded = a.encode();
        assert_eq!(encoded.len(), 7);
        let decoded = CleartextAlert::decode(&encoded).expect("decode");
        assert_eq!(decoded, a);
    }

    #[test]
    fn alert_truncates_long_reason() {
        let a = CleartextAlert {
            code: 0,
            reason: "x".repeat(ALERT_REASON_MAX + 500),
        };
        let encoded = a.encode();
        // 7 header + ALERT_REASON_MAX payload
        assert_eq!(encoded.len(), 7 + ALERT_REASON_MAX);
        let decoded = CleartextAlert::decode(&encoded).expect("decode");
        assert_eq!(decoded.reason.len(), ALERT_REASON_MAX);
    }

    #[test]
    fn rejects_wrong_length() {
        let mut buf = vec![0u8; MSG_1_LEN - 1];
        buf[0..2].copy_from_slice(&MAGIC);
        buf[2] = MSG_TYPE_1;
        assert!(Message1::decode(&buf).is_err());

        let mut buf = vec![0u8; MSG_1_LEN + 1];
        buf[0..2].copy_from_slice(&MAGIC);
        buf[2] = MSG_TYPE_1;
        assert!(Message1::decode(&buf).is_err());
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = vec![0u8; MSG_1_LEN];
        buf[0..2].copy_from_slice(b"XX");
        buf[2] = MSG_TYPE_1;
        assert!(Message1::decode(&buf).is_err());
    }

    #[test]
    fn rejects_wrong_msg_type() {
        let mut buf = vec![0u8; MSG_1_LEN];
        buf[0..2].copy_from_slice(&MAGIC);
        buf[2] = 0xAB;
        assert!(Message1::decode(&buf).is_err());
    }

    #[test]
    fn alert_rejects_length_mismatch() {
        let mut buf = vec![0u8; 8];
        buf[0..2].copy_from_slice(&MAGIC);
        buf[2] = MSG_TYPE_ALERT;
        buf[3..5].copy_from_slice(&0u16.to_be_bytes());
        buf[5..7].copy_from_slice(&100u16.to_be_bytes()); // claims 100 bytes, only 1 present
        assert!(CleartextAlert::decode(&buf).is_err());
    }

    #[test]
    fn alert_rejects_oversized_reason_len() {
        let mut buf = vec![0u8; 7];
        buf[0..2].copy_from_slice(&MAGIC);
        buf[2] = MSG_TYPE_ALERT;
        buf[3..5].copy_from_slice(&0u16.to_be_bytes());
        buf[5..7].copy_from_slice(&((ALERT_REASON_MAX + 1) as u16).to_be_bytes());
        assert!(CleartextAlert::decode(&buf).is_err());
    }
}
