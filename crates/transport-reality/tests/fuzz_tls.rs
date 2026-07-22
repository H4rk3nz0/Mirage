//! Property-based fuzz tests for the TLS 1.3 ClientHello parser.
//!
//! The parser reads bytes directly off the network from any peer - a
//! scanner, a garbage-generator, a real browser, anything. It must:
//!
//! 1. Never panic on any byte sequence.
//! 2. Never allocate unboundedly.
//! 3. Either return a valid `ParsedClientHello` (clean extraction) or
//!    return an `Err` (hand off to cover-service forwarding).

use mirage_transport_reality::tls_client_hello::{
    parse_client_hello_record, MAX_CLIENT_HELLO_SIZE,
};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// Completely random input bytes.
    #[test]
    fn parse_arbitrary_bytes_never_panics(
        bytes in prop::collection::vec(any::<u8>(), 0..MAX_CLIENT_HELLO_SIZE + 16),
    ) {
        let _ = parse_client_hello_record(&bytes);
    }

    /// Bytes that LOOK like a TLS record header (valid type + version) but
    /// have arbitrary body. Catches bugs where the parser trusts the
    /// record header and then panics inside the handshake body.
    #[test]
    fn parse_valid_record_header_arbitrary_body_never_panics(
        body in prop::collection::vec(any::<u8>(), 0..MAX_CLIENT_HELLO_SIZE),
    ) {
        let len = body.len().min(u16::MAX as usize);
        let mut wire = vec![0x16, 0x03, 0x01];
        wire.extend_from_slice(&(len as u16).to_be_bytes());
        wire.extend_from_slice(&body[..len]);
        let _ = parse_client_hello_record(&wire);
    }

    /// Bytes with valid record + handshake header.
    #[test]
    fn parse_valid_handshake_header_arbitrary_body_never_panics(
        body in prop::collection::vec(any::<u8>(), 0..MAX_CLIENT_HELLO_SIZE),
    ) {
        let hs_body = &body[..body.len().min(u16::MAX as usize - 4)];
        let hs_len = hs_body.len() as u32;
        let mut wire = vec![0x16, 0x03, 0x01];
        wire.extend_from_slice(&((hs_body.len() + 4) as u16).to_be_bytes());
        wire.push(0x01); // handshake type
        wire.extend_from_slice(&hs_len.to_be_bytes()[1..]); // u24 BE
        wire.extend_from_slice(hs_body);
        let _ = parse_client_hello_record(&wire);
    }

    /// Structurally-plausible CH with arbitrary session_id length byte and
    /// arbitrary following bytes. Checks the session_id length validation.
    #[test]
    fn parse_arbitrary_session_id_length(
        sid_len_byte in any::<u8>(),
        rest in prop::collection::vec(any::<u8>(), 0..1024),
    ) {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0xAAu8; 32]); // random
        body.push(sid_len_byte);
        body.extend_from_slice(&rest);

        let mut hs = vec![0x01];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut wire = vec![0x16, 0x03, 0x01];
        wire.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        wire.extend_from_slice(&hs);
        let _ = parse_client_hello_record(&wire);
    }

    /// Structurally valid CH up through extensions with arbitrary extensions body.
    /// Checks extension-walking bounds.
    #[test]
    fn parse_arbitrary_extensions_body(
        ext_len_claim in any::<u16>(),
        ext_body in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        let random = [0xAAu8; 32];
        let session_id = [0xBBu8; 32];

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&random);
        body.push(0x20);
        body.extend_from_slice(&session_id);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.extend_from_slice(&ext_len_claim.to_be_bytes());
        body.extend_from_slice(&ext_body);

        let mut hs = vec![0x01];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut wire = vec![0x16, 0x03, 0x01];
        wire.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        wire.extend_from_slice(&hs);
        let _ = parse_client_hello_record(&wire);
    }

    /// Structurally valid CH with a key_share extension containing
    /// arbitrary entries. Checks the list-walking loop.
    #[test]
    fn parse_arbitrary_keyshare_entries(
        ks_entries_body in prop::collection::vec(any::<u8>(), 0..1024),
    ) {
        let random = [0xAAu8; 32];
        let session_id = [0xBBu8; 32];

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&random);
        body.push(0x20);
        body.extend_from_slice(&session_id);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);

        // key_share ext: type(0x0033) + len + list_len + entries
        let list_len = ks_entries_body.len().min(u16::MAX as usize - 2);
        let ks_bytes = &ks_entries_body[..list_len];

        let mut ext = Vec::new();
        ext.extend_from_slice(&[0x00, 0x33]);
        ext.extend_from_slice(&((2 + list_len) as u16).to_be_bytes());
        ext.extend_from_slice(&(list_len as u16).to_be_bytes());
        ext.extend_from_slice(ks_bytes);

        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut hs = vec![0x01];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut wire = vec![0x16, 0x03, 0x01];
        wire.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        wire.extend_from_slice(&hs);
        let _ = parse_client_hello_record(&wire);
    }
}
