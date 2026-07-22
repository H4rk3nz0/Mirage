//! Mirage onion address codec.
//!
//! ```text
//!   <base32(pk(32) || checksum(2))>.mirage
//! ```
//!
//! - `pk` - 32-byte Ed25519 public key of the service.
//! - `checksum` - 2 bytes from BLAKE3-keyed over pk with a fixed
//!   label, truncated. Catches typos.
//! - base32 - RFC 4648 lowercase, no padding. 32+2 = 34 bytes ->
//!   `ceil(34*8/5)` = 55 chars (the encoder emits exactly 55 when
//!   padding is disabled).
//!
//! Total label length on the wire: `55 + ".mirage".len() = 62`
//! characters, comfortably under the 253-byte DNS-name cap (so a
//! Mirage address can be embedded in DNS or HTTP `Host:` headers
//! when needed for ecosystem integrations).
//!
//! # Example
//!
//! ```text
//!   abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.mirage
//! ```

use thiserror::Error;

/// Suffix appended after the base32 body. Always `.mirage`.
pub const ONION_ADDRESS_SUFFIX: &str = ".mirage";

/// Domain separator for the address checksum - keeps the 16-bit
/// checksum from colliding with any other BLAKE3-keyed output over
/// the same input.
const ADDRESS_CHECKSUM_LABEL: &[u8] = b"mirage-onion-address-checksum-v1";

/// Total bytes encoded as base32 (pk + checksum).
const ENCODED_BYTES: usize = 32 + 2;

/// Base32 length of [`ENCODED_BYTES`] (RFC 4648 no-padding).
/// 34 bytes x 8 bits / 5 bits/char = 54.4 -> 55 chars.
const ENCODED_LEN_CHARS: usize = 55;

/// Errors produced by address encode/decode.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AddressError {
    /// Input doesn't end with `.mirage`.
    #[error("address missing {ONION_ADDRESS_SUFFIX} suffix")]
    BadSuffix,
    /// Encoded body has the wrong base32 length.
    #[error("address body wrong length (got {got}, expected {ENCODED_LEN_CHARS})")]
    WrongLength {
        /// Actual char count of the body before the suffix.
        got: usize,
    },
    /// Base32 decoding failed (invalid char or padding).
    #[error("address base32 decode failed")]
    Base32,
    /// Decoded bytes had the wrong length (impossible with our
    /// fixed encoding, but defended for completeness).
    #[error("decoded byte length mismatch")]
    DecodedLength,
    /// Checksum mismatch - almost always a typo.
    #[error("address checksum mismatch")]
    ChecksumMismatch,
}

/// Encode a service's 32-byte public key as a `.mirage` address.
pub fn pk_to_onion_address(pk: &[u8; 32]) -> String {
    let mut buf = [0u8; ENCODED_BYTES];
    buf[0..32].copy_from_slice(pk);
    let cksum = checksum(pk);
    buf[32..34].copy_from_slice(&cksum);
    let body = base32::encode(base32::Alphabet::Rfc4648Lower { padding: false }, &buf);
    debug_assert_eq!(body.len(), ENCODED_LEN_CHARS);
    format!("{body}{ONION_ADDRESS_SUFFIX}")
}

/// Parse a `.mirage` address, returning the 32-byte public key on
/// success.
pub fn onion_address_to_pk(addr: &str) -> Result<[u8; 32], AddressError> {
    let lower = addr.to_ascii_lowercase();
    let body = lower
        .strip_suffix(ONION_ADDRESS_SUFFIX)
        .ok_or(AddressError::BadSuffix)?;
    if body.len() != ENCODED_LEN_CHARS {
        return Err(AddressError::WrongLength { got: body.len() });
    }
    let bytes = base32::decode(base32::Alphabet::Rfc4648Lower { padding: false }, body)
        .ok_or(AddressError::Base32)?;
    if bytes.len() != ENCODED_BYTES {
        return Err(AddressError::DecodedLength);
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&bytes[0..32]);
    let mut cksum = [0u8; 2];
    cksum.copy_from_slice(&bytes[32..34]);
    let expected = checksum(&pk);
    if cksum != expected {
        return Err(AddressError::ChecksumMismatch);
    }
    Ok(pk)
}

fn checksum(pk: &[u8; 32]) -> [u8; 2] {
    let mut h = mirage_crypto::blake3::Hasher::new_keyed(pk);
    h.update(ADDRESS_CHECKSUM_LABEL);
    let full = *h.finalize().as_bytes();
    [full[0], full[1]]
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn encode_decode_roundtrip() {
        let pk = [0x42u8; 32];
        let addr = pk_to_onion_address(&pk);
        assert!(addr.ends_with(".mirage"));
        let back = onion_address_to_pk(&addr).unwrap();
        assert_eq!(back, pk);
    }

    #[test]
    fn case_insensitive_decode() {
        let pk = [0x42u8; 32];
        let addr = pk_to_onion_address(&pk).to_ascii_uppercase();
        let back = onion_address_to_pk(&addr).unwrap();
        assert_eq!(back, pk);
    }

    #[test]
    fn missing_suffix_rejected() {
        let pk = [0x42u8; 32];
        let addr = pk_to_onion_address(&pk);
        let no_suffix = addr.trim_end_matches(".mirage");
        let err = onion_address_to_pk(no_suffix).unwrap_err();
        assert_eq!(err, AddressError::BadSuffix);
    }

    #[test]
    fn wrong_length_rejected() {
        let err = onion_address_to_pk("short.mirage").unwrap_err();
        assert!(matches!(err, AddressError::WrongLength { .. }));
    }

    #[test]
    fn checksum_mismatch_rejected() {
        let pk = [0x42u8; 32];
        let addr = pk_to_onion_address(&pk);
        // Tamper the FIRST base32 char so a bit flip is guaranteed
        // to propagate into the decoded pk bytes - the encoder/
        // decoder bit alignment is such that the leading char's
        // bits land squarely in the first decoded byte.
        let mut chars: Vec<char> = addr.chars().collect();
        chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
        let tampered: String = chars.into_iter().collect();
        let err = onion_address_to_pk(&tampered).unwrap_err();
        // Either Base32 (invalid char) or ChecksumMismatch
        // (decoded pk doesn't match the carried checksum).
        assert!(matches!(
            err,
            AddressError::ChecksumMismatch | AddressError::Base32
        ));
    }

    #[test]
    fn invalid_base32_rejected() {
        // 56 chars but with an invalid base32 char (`9` is not in
        // RFC 4648 lowercase alphabet).
        let body: String = "9".repeat(ENCODED_LEN_CHARS);
        let addr = format!("{body}.mirage");
        let err = onion_address_to_pk(&addr).unwrap_err();
        assert_eq!(err, AddressError::Base32);
    }

    #[test]
    fn checksum_is_pk_dependent() {
        let a = checksum(&[1u8; 32]);
        let b = checksum(&[2u8; 32]);
        assert_ne!(a, b, "different pks must produce different checksums");
    }

    #[test]
    fn address_is_dns_compatible_length() {
        let pk = [0x42u8; 32];
        let addr = pk_to_onion_address(&pk);
        // Total label length must fit in a DNS name (cap 253 bytes).
        assert!(addr.len() <= 253);
        assert_eq!(addr.len(), ENCODED_LEN_CHARS + ONION_ADDRESS_SUFFIX.len());
    }

    #[test]
    fn canonical_reencode_matches_input() {
        // Every encoder-produced address MUST equal the result of
        // decoding then re-encoding. Catches accidental encoder
        // drift (e.g., padding, alphabet, suffix capitalization).
        for tag in [0u8, 1, 0x42, 0xFE] {
            let pk = [tag; 32];
            let addr = pk_to_onion_address(&pk);
            let back = onion_address_to_pk(&addr).unwrap();
            let reencoded = pk_to_onion_address(&back);
            assert_eq!(addr, reencoded, "non-canonical encode for tag {tag:#04x}");
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[test]
        fn proptest_pk_roundtrips(pk in prop::array::uniform32(any::<u8>())) {
            let addr = pk_to_onion_address(&pk);
            let back = onion_address_to_pk(&addr).unwrap();
            prop_assert_eq!(back, pk);
        }

        #[test]
        fn proptest_canonical_reencode(pk in prop::array::uniform32(any::<u8>())) {
            // Stronger property than roundtrip: decoder + encoder
            // composes to identity on encoder output.
            let addr = pk_to_onion_address(&pk);
            let pk2 = onion_address_to_pk(&addr).unwrap();
            let addr2 = pk_to_onion_address(&pk2);
            prop_assert_eq!(addr, addr2);
        }
    }
}
