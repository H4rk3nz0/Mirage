//! Property-based fuzz tests for session-layer parsers.
//!
//! Every parser that reads adversary-controlled bytes MUST:
//! 1. Never panic on ANY input (no unwrap, no array out-of-bounds).
//! 2. Never allocate unboundedly on any input.
//! 3. Return a clean `Err` or a valid parsed struct - no undefined middle state.
//!
//! `proptest` generates random byte sequences and runs each parser against
//! them. A panic or assertion failure fails the test and proptest
//! auto-shrinks to a minimal reproducer. The adversarial stakes (lives at
//! risk if a malformed packet crashes an operator's bridge) make this
//! fuzzing non-negotiable; see spec §01 §6 (non-negotiables).

use mirage_session::wire::{
    CleartextAlert, Message1, Message2, Message3, MSG_1_LEN, MSG_2_LEN, MSG_3_LEN_WITH_TOKEN,
};
use proptest::prelude::*;

// Property: parsers never panic on arbitrary input

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn message1_decode_never_panics(buf in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = Message1::decode(&buf);
    }

    #[test]
    fn message2_decode_never_panics(buf in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = Message2::decode(&buf);
    }

    #[test]
    fn message3_decode_never_panics(buf in prop::collection::vec(any::<u8>(), 0..1024)) {
        let _ = Message3::decode(&buf);
    }

    #[test]
    fn alert_decode_never_panics(buf in prop::collection::vec(any::<u8>(), 0..2048)) {
        let _ = CleartextAlert::decode(&buf);
    }

    /// Fuzz "looks like a valid wire frame but with corrupted fields":
    /// valid magic + msg_type but arbitrary body. Catches bugs where the
    /// parser trusts the header then panics on the body.
    #[test]
    fn message1_with_valid_header_never_panics(body in prop::collection::vec(any::<u8>(), 0..4096)) {
        let mut buf = Vec::with_capacity(3 + body.len());
        buf.extend_from_slice(b"MI");
        buf.push(0x01);
        buf.extend_from_slice(&body);
        let _ = Message1::decode(&buf);
    }

    #[test]
    fn message2_with_valid_header_never_panics(body in prop::collection::vec(any::<u8>(), 0..4096)) {
        let mut buf = Vec::with_capacity(3 + body.len());
        buf.extend_from_slice(b"MI");
        buf.push(0x02);
        buf.extend_from_slice(&body);
        let _ = Message2::decode(&buf);
    }

    #[test]
    fn message3_with_valid_header_never_panics(body in prop::collection::vec(any::<u8>(), 0..1024)) {
        let mut buf = Vec::with_capacity(3 + body.len());
        buf.extend_from_slice(b"MI");
        buf.push(0x03);
        buf.extend_from_slice(&body);
        let _ = Message3::decode(&buf);
    }

    #[test]
    fn alert_with_valid_header_never_panics(
        code in any::<u16>(),
        claimed_len in any::<u16>(),
        body in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        let mut buf = Vec::with_capacity(7 + body.len());
        buf.extend_from_slice(b"MI");
        buf.push(0xFE);
        buf.extend_from_slice(&code.to_be_bytes());
        buf.extend_from_slice(&claimed_len.to_be_bytes());
        buf.extend_from_slice(&body);
        let _ = CleartextAlert::decode(&buf);
    }

    /// Exact-length-boundary fuzz: inputs are exactly at the valid length
    /// for the parser, but bytes are random. Catches off-by-one errors
    /// in length-validated parsers.
    #[test]
    fn message1_exact_length_never_panics(buf in prop::array::uniform32(any::<u8>()).prop_flat_map(|_| prop::collection::vec(any::<u8>(), MSG_1_LEN..=MSG_1_LEN))) {
        let _ = Message1::decode(&buf);
    }

    #[test]
    fn message2_exact_length_never_panics(buf in prop::array::uniform32(any::<u8>()).prop_flat_map(|_| prop::collection::vec(any::<u8>(), MSG_2_LEN..=MSG_2_LEN))) {
        let _ = Message2::decode(&buf);
    }

    #[test]
    fn message3_exact_length_never_panics(buf in prop::array::uniform32(any::<u8>()).prop_flat_map(|_| prop::collection::vec(any::<u8>(), MSG_3_LEN_WITH_TOKEN..=MSG_3_LEN_WITH_TOKEN))) {
        let _ = Message3::decode(&buf);
    }
}

/// Smoke-test: a minimal encoded-then-decoded valid Message1 roundtrips.
/// Complements the fuzz tests above by proving the "valid path" still works
/// after all the adversarial testing.
#[test]
fn message1_valid_roundtrip_smoke() {
    // Post-I24: message 1 carries the full Noise message (`e` || mlkem_ek
    // payload) in a single field. The first 32 bytes are the `e` token, the
    // remaining 1184 the ek payload.
    let mut noise_msg_1 = [0u8; 1216];
    noise_msg_1[..32].fill(0xAB);
    noise_msg_1[32..].fill(0xCD);
    let m = Message1 {
        wire_version: 1,
        noise_msg_1,
    };
    let encoded = m.encode();
    let decoded = Message1::decode(&encoded).expect("decode");
    assert_eq!(decoded.wire_version, 1);
    assert_eq!(decoded.noise_msg_1, noise_msg_1);
}
