//! Property-based fuzz tests for the Nostr discovery adapter.
//!
//! Nostr events arrive from adversary-controlled relays. Every parser and
//! verification path MUST survive arbitrary JSON input without panic,
//! unbounded allocation, or undefined middle state.

use mirage_discovery_nostr::event::{NostrEvent, NostrEventParts, MIRAGE_EVENT_KIND};
use mirage_discovery_nostr::signing::{verify_schnorr, NostrSigningKey};
use mirage_discovery_nostr::wrap::{
    build_announcement_event, unpack_announcement_event, TAG_D, TAG_EXPIRATION,
};
use proptest::prelude::*;

// JSON deserialization fuzz

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Arbitrary bytes interpreted as UTF-8 JSON. MUST NEVER panic.
    #[test]
    fn nostr_event_json_parse_never_panics(
        raw in prop::collection::vec(any::<u8>(), 0..4096),
    ) {
        if let Ok(s) = std::str::from_utf8(&raw) {
            let _: Result<NostrEvent, _> = serde_json::from_str(s);
        }
    }

    /// Crafted JSON with spec-shape-but-malformed fields.
    #[test]
    fn nostr_event_crafted_json_never_panics(
        id_chars in "[0-9a-fA-F]{0,128}",
        pubkey_chars in "[0-9a-fA-F]{0,128}",
        created_at in any::<u64>(),
        kind in any::<u64>(),
        content in ".*",
        sig_chars in "[0-9a-fA-F]{0,256}",
    ) {
        let event = NostrEvent {
            id: id_chars,
            pubkey: pubkey_chars,
            created_at,
            kind,
            tags: vec![],
            content,
            sig: sig_chars,
        };
        let _ = event.id_bytes();
        let _ = event.pubkey_bytes();
        let _ = event.sig_bytes();
        let _ = event.compute_id();
        let _ = event.verify();
    }

    /// Arbitrary content strings - NIP-01 canonicalization uses serde_json
    /// which must escape correctly for any valid UTF-8 input.
    #[test]
    fn compute_id_arbitrary_content_never_panics(
        content in ".*",
    ) {
        let parts = NostrEventParts::mirage_event(1_700_000_000, content);
        let pk = "a".repeat(64);
        let _ = parts.compute_id(&pk);
    }

    /// Arbitrary tag structures - nested arbitrary UTF-8 strings.
    #[test]
    fn compute_id_arbitrary_tags_never_panics(
        tags in prop::collection::vec(
            prop::collection::vec(".*", 0..8),
            0..16,
        ),
    ) {
        let mut parts = NostrEventParts::mirage_event(1, String::from("c"));
        parts.tags = tags;
        let pk = "b".repeat(64);
        let _ = parts.compute_id(&pk);
    }
}

// unpack_announcement_event fuzz

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Arbitrary NostrEvent struct - unpack MUST return Err or Ok, never panic.
    /// Includes adversarial oversized content/tags (to exercise R43/R44 caps).
    #[test]
    fn unpack_arbitrary_event_never_panics(
        id in "[0-9a-fA-F]{0,256}",
        pubkey in "[0-9a-fA-F]{0,256}",
        created_at in any::<u64>(),
        kind in any::<u64>(),
        content in prop::collection::vec(any::<u8>(), 0..8192).prop_map(|b| {
            // base64 alphabet subset to occasionally be valid
            b.into_iter().map(|c| (c % 64).wrapping_add(b'A')).collect::<Vec<_>>()
        }).prop_map(|b| String::from_utf8_lossy(&b).to_string()),
        tag_count in 0usize..32,
        sig in "[0-9a-fA-F]{0,256}",
    ) {
        let tags: Vec<Vec<String>> = (0..tag_count)
            .map(|i| vec![format!("tag{}", i), format!("val{}", i)])
            .collect();
        let event = NostrEvent {
            id,
            pubkey,
            created_at,
            kind,
            tags,
            content,
            sig,
        };
        let _ = unpack_announcement_event(&event, None);
    }

    /// Attacker-crafted event with valid Mirage kind but garbage everything else.
    /// Tests that bouncing the `kind` check isn't the only gatekeeper.
    #[test]
    fn unpack_mirage_kind_with_garbage(
        content in ".*",
        tag_name in ".*",
        tag_val in ".*",
    ) {
        let event = NostrEvent {
            id: "00".repeat(32),
            pubkey: "00".repeat(32),
            created_at: 0,
            kind: MIRAGE_EVENT_KIND,
            tags: vec![vec![tag_name, tag_val]],
            content,
            sig: "00".repeat(64),
        };
        let _ = unpack_announcement_event(&event, None);
    }
}

// Schnorr verify fuzz

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// verify_schnorr MUST NEVER panic on arbitrary pubkey / msg / sig bytes.
    #[test]
    fn verify_schnorr_arbitrary_never_panics(
        pubkey in prop::array::uniform32(any::<u8>()),
        msg in prop::collection::vec(any::<u8>(), 0..256),
        sig in prop::array::uniform(any::<u8>()).prop_map(|arr: [u8; 32]| {
            let mut full = [0u8; 64];
            full[..32].copy_from_slice(&arr);
            full[32..].copy_from_slice(&arr);
            full
        }),
    ) {
        let _ = verify_schnorr(&pubkey, &msg, &sig);
    }
}

// Full build/unpack roundtrip with arbitrary ciphertext content

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Attacker chooses the "sealed ciphertext" bytes. Build MUST produce a
    /// valid-signing event regardless. Unpack MUST recover the same bytes.
    #[test]
    fn build_unpack_arbitrary_ciphertext(
        ct in prop::collection::vec(any::<u8>(), 0..1024),
        created_at in any::<u64>().prop_filter("cap", |&c| c < i64::MAX as u64),
        expires_at in any::<u64>().prop_filter("cap", |&c| c < i64::MAX as u64),
    ) {
        let sk = NostrSigningKey::from_seed(&[0x42u8; 32]).unwrap();
        let info_hash = [0x11u8; 20];
        let event = build_announcement_event(&info_hash, &ct, created_at, expires_at, &sk, None)
            .expect("build");
        let unpacked = unpack_announcement_event(&event, None).expect("unpack");
        prop_assert_eq!(unpacked.ciphertext, ct);
        prop_assert_eq!(unpacked.info_hash, info_hash);
    }
}

// Smoke tests for sanity

#[test]
fn roundtrip_smoke_after_fuzz() {
    let sk = NostrSigningKey::from_seed(&[0xAAu8; 32]).unwrap();
    let ct = b"sealed mirage blob";
    let event = build_announcement_event(&[0x01u8; 20], ct, 1, 2, &sk, None).expect("build");
    let unpacked = unpack_announcement_event(&event, None).expect("unpack");
    assert_eq!(unpacked.ciphertext, ct);
}

#[test]
fn tag_constants_match_spec() {
    assert_eq!(TAG_D, "d");
    assert_eq!(TAG_EXPIRATION, "expiration");
}
