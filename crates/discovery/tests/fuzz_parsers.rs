//! Property-based fuzz tests for discovery-layer parsers and the
//! seal/open ciphertext path.
//!
//! The discovery layer is the FIRST code path that touches bytes from a
//! third-party relay or DHT node. Parsers here MUST survive adversarial
//! input without panic, unbounded allocation, or undefined middle state.
//! A single `unwrap` on a malformed announcement, at deploy time, could
//! hang every client fetching from a compromised Nostr relay.

use mirage_discovery::derive::{info_hash, NAMESPACE_CLIENT_TO_BRIDGE};
use mirage_discovery::seal::{open, open_with_skew_tolerance, seal};
use mirage_discovery::token::CapabilityToken;
use mirage_discovery::wire::{Announcement, Endpoint, Revocation, REVOCATION_LEN};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    // ----- wire parsers -----

    #[test]
    fn announcement_decode_never_panics(buf in prop::collection::vec(any::<u8>(), 0..2048)) {
        let _ = Announcement::decode(&buf);
    }

    #[test]
    fn revocation_decode_never_panics(buf in prop::collection::vec(any::<u8>(), 0..2048)) {
        let _ = Revocation::decode(&buf);
    }

    #[test]
    fn endpoint_decode_never_panics(buf in prop::collection::vec(any::<u8>(), 0..512)) {
        // Endpoint::decode is exercised by Announcement::decode; expose
        // directly via public path to get its own fuzz coverage. We do
        // that by attempting to parse as an announcement of any length,
        // which internally invokes Endpoint::decode.
        let _ = Announcement::decode(&buf);
    }

    #[test]
    fn token_decode_never_panics(buf in prop::collection::vec(any::<u8>(), 0..2048)) {
        let _ = CapabilityToken::decode(&buf);
    }

    // ----- wire parsers with valid-looking prefix -----

    #[test]
    fn announcement_with_valid_header_never_panics(
        body in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        let mut buf = Vec::with_capacity(4 + body.len());
        buf.extend_from_slice(b"MI");
        buf.push(0x20); // announcement doc_type
        buf.push(0x01); // version
        buf.extend_from_slice(&body);
        let _ = Announcement::decode(&buf);
    }

    #[test]
    fn revocation_with_valid_header_never_panics(
        body in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        let mut buf = Vec::with_capacity(4 + body.len());
        buf.extend_from_slice(b"MI");
        buf.push(0x30); // revocation doc_type
        buf.push(0x01); // version
        buf.extend_from_slice(&body);
        let _ = Revocation::decode(&buf);
    }

    #[test]
    fn revocation_exact_length_never_panics(
        buf in prop::collection::vec(any::<u8>(), REVOCATION_LEN..=REVOCATION_LEN),
    ) {
        let _ = Revocation::decode(&buf);
    }

    /// Fuzz the domain-endpoint sub-parser specifically: bytes that LOOK
    /// like a domain endpoint (kind=0x03) with arbitrary length-prefix
    /// and arbitrary body bytes. Catches RFC 1123 validator edge cases.
    #[test]
    fn endpoint_domain_never_panics(
        dlen in 0u8..=255,
        domain in prop::collection::vec(any::<u8>(), 0..300),
        port in any::<u16>(),
    ) {
        let mut body = Vec::with_capacity(1 + 1 + domain.len() + 2);
        body.push(0x03); // domain kind
        body.push(dlen);
        body.extend_from_slice(&domain);
        body.extend_from_slice(&port.to_be_bytes());
        // Wrap in an announcement-looking prefix so Announcement::decode
        // reaches Endpoint::decode.
        let mut ann_buf = vec![0u8; 88];
        ann_buf[0..2].copy_from_slice(b"MI");
        ann_buf[2] = 0x20;
        ann_buf[3] = 0x01;
        // Valid-looking issued_at < expires_at.
        ann_buf[4..12].copy_from_slice(&1u64.to_be_bytes());
        ann_buf[12..20].copy_from_slice(&2u64.to_be_bytes());
        ann_buf[84..88].copy_from_slice(&1u32.to_be_bytes()); // caps=REALITY_V2
        ann_buf.extend_from_slice(&body);
        ann_buf.extend_from_slice(&[0u8; 64]); // signature placeholder
        let _ = Announcement::decode(&ann_buf);
    }
}

// seal::open fuzz - the crypto boundary

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// An attacker who controls the channel can inject arbitrary bytes as
    /// "ciphertext". `open` must never panic; it must return `Err` on
    /// anything other than a correctly-sealed blob.
    #[test]
    fn open_arbitrary_ciphertext_never_panics(
        ct in prop::collection::vec(any::<u8>(), 0..2048),
        epoch in any::<u64>(),
    ) {
        let salt = [0x42u8; 32];
        let _ = open(&salt, NAMESPACE_CLIENT_TO_BRIDGE, epoch, &ct);
    }

    #[test]
    fn open_with_skew_arbitrary_ciphertext_never_panics(
        ct in prop::collection::vec(any::<u8>(), 0..2048),
        epoch in any::<u64>(),
    ) {
        let salt = [0x42u8; 32];
        let _ = open_with_skew_tolerance(&salt, NAMESPACE_CLIENT_TO_BRIDGE, epoch, &ct);
    }

    /// Attacker chooses the salt too (invite leak -> attacker knows salt).
    /// Confirms open is still robust with valid key material + garbage ct.
    #[test]
    fn open_arbitrary_salt_and_ciphertext(
        salt_bytes in prop::array::uniform32(any::<u8>()),
        ct in prop::collection::vec(any::<u8>(), 0..2048),
        epoch in any::<u64>(),
    ) {
        let _ = open(&salt_bytes, NAMESPACE_CLIENT_TO_BRIDGE, epoch, &ct);
    }

    /// Roundtrip at arbitrary epoch + arbitrary plaintext: seal then open
    /// must recover plaintext OR return an error. MUST NEVER panic.
    #[test]
    fn seal_open_arbitrary_plaintext(
        plaintext in prop::collection::vec(any::<u8>(), 0..1024),
        epoch in any::<u64>().prop_filter("epoch not at max", |&e| e < u64::MAX),
    ) {
        let salt = [0x33u8; 32];
        let ct = seal(&salt, NAMESPACE_CLIENT_TO_BRIDGE, epoch, &plaintext)
            .expect("seal should succeed for any plaintext");
        let recovered = open(&salt, NAMESPACE_CLIENT_TO_BRIDGE, epoch, &ct)
            .expect("roundtrip must recover");
        prop_assert_eq!(recovered, plaintext);
    }
}

// info_hash derivation fuzz - pure hash function, still check panic-safety

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn info_hash_deterministic(
        salt in prop::array::uniform32(any::<u8>()),
        epoch in any::<u64>(),
    ) {
        let a = info_hash(&salt, NAMESPACE_CLIENT_TO_BRIDGE, epoch);
        let b = info_hash(&salt, NAMESPACE_CLIENT_TO_BRIDGE, epoch);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn info_hash_differs_on_epoch_change(
        salt in prop::array::uniform32(any::<u8>()),
        epoch in any::<u64>().prop_filter("not u64::MAX", |&e| e < u64::MAX),
    ) {
        let a = info_hash(&salt, NAMESPACE_CLIENT_TO_BRIDGE, epoch);
        let b = info_hash(&salt, NAMESPACE_CLIENT_TO_BRIDGE, epoch + 1);
        prop_assert_ne!(a, b);
    }
}

// Endpoint struct sanity smoke tests (proves valid-path after fuzz)

#[test]
fn endpoint_ipv4_smoke() {
    let ep = Endpoint::Ipv4 {
        addr: [1, 2, 3, 4],
        port: 443,
    };
    // Construct a valid announcement by encoding and decoding - uses
    // endpoint encoding internally.
    let ann = Announcement {
        issued_at: 1_000_000,
        expires_at: 1_003_600,
        bridge_ed25519_pk: [0x11u8; 32],
        bridge_x25519_pk: [0x22u8; 32],
        transport_caps: 1,
        endpoint: ep,
        extra_endpoints: Vec::new(),
        signature: [0u8; 64],
    };
    let encoded = ann.encode();
    let decoded = Announcement::decode(&encoded).expect("smoke decode");
    assert!(matches!(decoded.endpoint, Endpoint::Ipv4 { .. }));
}
