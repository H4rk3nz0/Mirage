//! Property-based fuzz tests for the post-handshake session framer.
//!
//! Once a session is established, `SessionFramer::recv` reads bytes from
//! an adversary-controlled transport. Adversary capabilities:
//!   - Inject arbitrary bytes (no auth required by transport layer).
//!   - Modify bytes in transit.
//!   - Duplicate / drop / reorder frames.
//!
//! `recv` MUST return a clean `Err` for every non-valid frame and never
//! panic. Under the "lives at stake" framing, a panic on the receive
//! path is a denial-of-service against the user's only link out of a
//! hostile network.

use mirage_crypto::ed25519_dalek::SigningKey;
use mirage_crypto::x25519_dalek::{PublicKey, StaticSecret};
use mirage_discovery::replay::ReplaySet;
use mirage_discovery::token::{sign_token, CapabilityToken};
use mirage_session::handshake::TokenVerifier;
use mirage_session::wire::{MSG_1_LEN, MSG_2_LEN, MSG_3_LEN_WITH_TOKEN};
use mirage_session::{HandshakeInitiator, HandshakeResponder, Role, SessionFramer};
use proptest::prelude::*;

// Helpers: produce a live framer pair

fn rand_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    getrandom::fill(&mut s).unwrap();
    s
}

fn gen_x25519() -> ([u8; 32], [u8; 32]) {
    let sk = StaticSecret::from(rand_seed());
    let pk = PublicKey::from(&sk);
    (sk.to_bytes(), *pk.as_bytes())
}

fn gen_ed25519() -> (SigningKey, [u8; 32]) {
    let sk = SigningKey::from_bytes(&rand_seed());
    let pk = sk.verifying_key().to_bytes();
    (sk, pk)
}

fn run_handshake_pair() -> (SessionFramer, SessionFramer) {
    let (init_sk, _) = gen_x25519();
    let (resp_sk, resp_pk) = gen_x25519();
    let (_, bridge_id_pk) = gen_ed25519();
    let (op_sk, op_pk) = gen_ed25519();
    let token: CapabilityToken = sign_token([0x01u8; 32], bridge_id_pk, 2_000_000_000, &op_sk);

    let mut i = HandshakeInitiator::new(&init_sk, &resp_pk, &token).unwrap();
    let mut r = HandshakeResponder::new(&resp_sk, &bridge_id_pk, &op_pk).unwrap();

    let m1 = i.write_message_1().unwrap();
    assert_eq!(m1.len(), MSG_1_LEN);
    r.read_message_1(&m1).unwrap();

    let m2 = r.write_message_2().unwrap();
    assert_eq!(m2.len(), MSG_2_LEN);
    i.read_message_2(&m2).unwrap();

    let (m3, i_keys) = i.write_message_3().unwrap();
    assert_eq!(m3.len(), MSG_3_LEN_WITH_TOKEN);

    let mut rs = ReplaySet::new(16);
    let mut v = TokenVerifier::new(&mut rs, 1_700_000_000);
    let r_keys = r.read_message_3(&m3, &mut v).unwrap();

    let i_framer = SessionFramer::from_session_keys(i_keys, Role::Initiator).unwrap();
    let r_framer = SessionFramer::from_session_keys(r_keys, Role::Responder).unwrap();
    (i_framer, r_framer)
}

// Fuzz: SessionFramer::recv over arbitrary garbage

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Arbitrary bytes handed to recv. MUST NEVER panic. MUST return Err for
    /// all non-legitimate frames.
    #[test]
    fn framer_recv_arbitrary_bytes_never_panics(
        wire in prop::collection::vec(any::<u8>(), 0..20_000),
    ) {
        let (_, mut r) = run_handshake_pair();
        let _ = r.recv(&wire);
    }

    /// Frames with a valid-looking u16 length prefix but arbitrary body.
    #[test]
    fn framer_recv_valid_prefix_arbitrary_body_never_panics(
        claimed_len in any::<u16>(),
        body in prop::collection::vec(any::<u8>(), 0..20_000),
    ) {
        let (_, mut r) = run_handshake_pair();
        let mut wire = claimed_len.to_be_bytes().to_vec();
        wire.extend_from_slice(&body);
        let _ = r.recv(&wire);
    }

    /// Replayed frame: capture a real-encrypted frame, then replay it.
    /// The replay MUST be rejected (seq already advanced) - never panic.
    #[test]
    fn framer_replay_rejected_never_panics(
        plaintext in prop::collection::vec(any::<u8>(), 1..1024),
    ) {
        let (mut i, mut r) = run_handshake_pair();
        let wire = i.send(&plaintext).unwrap();
        let _ = r.recv(&wire);
        // Replay: must return Err, not panic.
        prop_assert!(r.recv(&wire).is_err());
    }

    /// Tampered wire bytes - single-bit flip at random offset.
    #[test]
    fn framer_recv_bitflipped_wire_never_panics(
        plaintext in prop::collection::vec(any::<u8>(), 1..512),
        flip_offset in 0usize..1024,
    ) {
        let (mut i, mut r) = run_handshake_pair();
        let mut wire = i.send(&plaintext).unwrap();
        if flip_offset < wire.len() {
            wire[flip_offset] ^= 0x01;
        }
        // Must return Err or (on zero flip at length-prefix) Ok. Never panic.
        let _ = r.recv(&wire);
    }

    /// Send arbitrary plaintext through the framer. Must roundtrip OR reject
    /// at send boundary (e.g., empty or oversized). Never panic at either end.
    #[test]
    fn framer_send_arbitrary_plaintext_never_panics(
        plaintext in prop::collection::vec(any::<u8>(), 0..20_000),
    ) {
        let (mut i, mut r) = run_handshake_pair();
        if let Ok(wire) = i.send(&plaintext) {
            // If send accepted it, recv MUST accept too - this is the happy
            // path roundtrip property.
            let got = r.recv(&wire).expect("valid framer send must decode");
            prop_assert_eq!(got, plaintext);
        }
    }
}

// Fuzz: ratchet boundary behavior

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Advance epochs arbitrarily (up to a cap) on both sides. Roundtrip
    /// MUST work within each epoch and fail cleanly across misaligned epochs.
    #[test]
    fn ratchet_advance_arbitrary_times_preserves_liveness(
        advances in 0u32..16,
        plaintext in prop::collection::vec(any::<u8>(), 1..512),
    ) {
        let (mut i, mut r) = run_handshake_pair();
        for _ in 0..advances {
            i.advance_epoch().unwrap();
            r.advance_epoch().unwrap();
        }
        let wire = i.send(&plaintext).unwrap();
        let got = r.recv(&wire).expect("aligned epochs must decrypt");
        prop_assert_eq!(got, plaintext);
    }

    /// Misaligned ratchet, sender ahead. The skew-tolerant receiver follows a
    /// peer that is exactly ONE epoch ahead (grace window / reactive follow);
    /// a peer more than one epoch ahead is outside the window and fails
    /// cleanly. Neither case may panic.
    #[test]
    fn ratchet_sender_ahead_follows_by_one_else_clean_fail(
        ahead in 1u32..6,
        plaintext in prop::collection::vec(any::<u8>(), 1..512),
    ) {
        let (mut i, mut r) = run_handshake_pair();
        for _ in 0..ahead {
            i.advance_epoch().unwrap();
        }
        let wire = i.send(&plaintext).unwrap();
        let out = r.recv(&wire);
        if ahead == 1 {
            // Receiver reactively adopts the peer's epoch and decrypts.
            prop_assert_eq!(out.expect("follow-by-one must decrypt"), plaintext);
            prop_assert_eq!(r.current_epoch(), 1);
        } else {
            // More than one epoch ahead: outside the window, clean Err.
            prop_assert!(out.is_err());
        }
    }
}
