//! TLS 1.3 record-layer framer for the Reality carrier.
//!
//! After the synthesized handshake completes, both peers wrap
//! Mirage session frames inside TLS 1.3 `application_data` records.
//! To a passive DPI observer, each record looks like:
//!
//! ```text
//! 0x17           -- ContentType.application_data
//! 0x03 0x03      -- legacy_record_version = TLS 1.2
//! uint16 length  -- total bytes that follow
//! ... payload (opaque) ...
//! ```
//!
//! This is precisely the shape of a TLS 1.3 encrypted record. In a
//! real TLS 1.3 session, the payload is AEAD ciphertext under the
//! traffic keys; in v0.1a Reality we stuff Mirage-session-framer
//! ciphertext there instead. Since a passive observer has no way
//! to distinguish AEAD cipher streams from each other, this is
//! indistinguishable at the record layer.
//!
//! # Safety caps
//!
//! RFC 8446 §5.1 caps TLSCiphertext.length at 2^14 + 256. We
//! enforce `MAX_INNER_PAYLOAD` to bound the bytes we're willing to
//! read in one record (attacker-controlled length prefix).

use crate::error::RealityError;

/// TLS 1.3 record `content_type` for application_data.
const RECORD_TYPE_APP_DATA: u8 = 0x17;
/// TLS 1.2/1.3 legacy record version.
const LEGACY_RECORD_VERSION: [u8; 2] = [0x03, 0x03];

/// Fixed record header size.
pub const RECORD_HEADER_LEN: usize = 5;

/// Maximum payload bytes a single record carries. RFC 8446 §5.1 caps
/// TLSCiphertext.length at 2^14 + 256 (16640). We clamp to 2^14 so
/// a single Mirage frame (<= 16384 B plaintext + 2x16 B AEAD tags
/// = 16416 B) comfortably fits.
pub const MAX_INNER_PAYLOAD: usize = 16_384;

/// Build a single application_data record wrapping `payload`.
pub fn wrap_app_data(payload: &[u8]) -> Result<Vec<u8>, RealityError> {
    if payload.is_empty() {
        return Err(RealityError::TagMismatch);
    }
    if payload.len() > MAX_INNER_PAYLOAD {
        return Err(RealityError::TagMismatch);
    }
    let mut out = Vec::with_capacity(RECORD_HEADER_LEN + payload.len());
    out.push(RECORD_TYPE_APP_DATA);
    out.extend_from_slice(&LEGACY_RECORD_VERSION);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Result of parsing one record from a wire buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unwrapped<'a> {
    /// The payload bytes inside the record.
    pub payload: &'a [u8],
    /// Total bytes consumed from the input (`RECORD_HEADER_LEN +
    /// payload.len()`).
    pub consumed: usize,
}

/// Parse one application_data record from `buf`. Returns `None` if
/// the buffer does not yet hold a complete record (caller should
/// read more bytes). Returns an error only if the record header
/// parses successfully but the content type is wrong or the length
/// is over cap - those are terminal, not "read more."
pub fn unwrap_app_data(buf: &[u8]) -> Result<Option<Unwrapped<'_>>, RealityError> {
    if buf.len() < RECORD_HEADER_LEN {
        return Ok(None);
    }
    if buf[0] != RECORD_TYPE_APP_DATA {
        return Err(RealityError::TagMismatch);
    }
    // legacy_version is advisory; RFC 8446 says MUST be 0x0303 but
    // "receivers MUST ignore" - we accept 0x03xx for leniency.
    if buf[1] != 0x03 {
        return Err(RealityError::TagMismatch);
    }
    let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if len == 0 {
        return Err(RealityError::TagMismatch);
    }
    if len > MAX_INNER_PAYLOAD {
        return Err(RealityError::TagMismatch);
    }
    let end = RECORD_HEADER_LEN + len;
    if buf.len() < end {
        return Ok(None);
    }
    Ok(Some(Unwrapped {
        payload: &buf[RECORD_HEADER_LEN..end],
        consumed: end,
    }))
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let payload = b"hello mirage";
        let wire = wrap_app_data(payload).unwrap();
        assert_eq!(wire[0], 0x17);
        assert_eq!(&wire[1..3], &[0x03, 0x03]);
        let un = unwrap_app_data(&wire).unwrap().unwrap();
        assert_eq!(un.payload, payload);
        assert_eq!(un.consumed, wire.len());
    }

    #[test]
    fn unwrap_incomplete_returns_none() {
        let wire = wrap_app_data(&[1, 2, 3, 4, 5]).unwrap();
        for cut in 0..wire.len() {
            let r = unwrap_app_data(&wire[..cut]).unwrap();
            assert!(r.is_none(), "cut={cut} should be incomplete");
        }
    }

    #[test]
    fn rejects_empty_payload() {
        assert!(wrap_app_data(&[]).is_err());
    }

    #[test]
    fn rejects_oversized_payload() {
        let big = vec![0u8; MAX_INNER_PAYLOAD + 1];
        assert!(wrap_app_data(&big).is_err());
    }

    #[test]
    fn unwrap_rejects_wrong_content_type() {
        let mut wire = wrap_app_data(b"x").unwrap();
        wire[0] = 0x16; // handshake
        assert!(unwrap_app_data(&wire).is_err());
    }

    #[test]
    fn unwrap_rejects_wrong_version_major() {
        let mut wire = wrap_app_data(b"x").unwrap();
        wire[1] = 0x04;
        assert!(unwrap_app_data(&wire).is_err());
    }

    #[test]
    fn unwrap_rejects_declared_len_over_cap() {
        let mut wire = vec![0x17, 0x03, 0x03];
        let over = (MAX_INNER_PAYLOAD + 1) as u16;
        wire.extend_from_slice(&over.to_be_bytes());
        wire.resize(5 + MAX_INNER_PAYLOAD + 1, 0);
        assert!(unwrap_app_data(&wire).is_err());
    }

    #[test]
    fn streaming_multiple_records() {
        let p1 = b"first";
        let p2 = b"second payload";
        let mut stream = Vec::new();
        stream.extend_from_slice(&wrap_app_data(p1).unwrap());
        stream.extend_from_slice(&wrap_app_data(p2).unwrap());
        let r1 = unwrap_app_data(&stream).unwrap().unwrap();
        assert_eq!(r1.payload, p1);
        let rest = &stream[r1.consumed..];
        let r2 = unwrap_app_data(rest).unwrap().unwrap();
        assert_eq!(r2.payload, p2);
    }

    #[test]
    fn fuzz_arbitrary_bytes_never_panic() {
        use proptest::prelude::*;
        proptest!(ProptestConfig::with_cases(256), |(b in prop::collection::vec(any::<u8>(), 0..8192))| {
            let _ = unwrap_app_data(&b);
        });
    }
}
