//! Mirage-sealed-blob <-> Nostr-event conversion.
//!
//! - Event `kind` = per-epoch derived (`mirage_event_kind(info_hash)`, in the
//!   parametric-replaceable `30000`-`39999` window) - no single enumerable constant.
//! - Tag `d` = hex-encoded `info_hash` for the epoch (NIP-01 `d` tag is the
//!   uniqueness key for parametric-replaceable events).
//! - Tag `expiration` = unix-seconds at which relays SHOULD drop this event
//!   (NIP-40). We set it to `current_epoch_end + 600s` so relays drop stale
//!   announcements an epoch after their validity window closes.
//! - `content` = base64-encoded Mirage sealed ciphertext.
//!
//! This module does NOT decrypt or verify the Mirage payload; that's
//! [`mirage_discovery::seal`]'s job. What we do here:
//! - **Publish direction**: pack (`info_hash`, ciphertext, expiration) into
//!   a signed Nostr event ready to send to a relay.
//! - **Subscribe direction**: unpack a received Nostr event into
//!   (`info_hash`, ciphertext). The Mirage layer above verifies the operator
//!   signature on the decrypted blob.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

use crate::error::NostrError;
use crate::event::{
    mirage_event_kind, NostrEvent, NostrEventParts, MIRAGE_EVENT_KIND_BASE, MIRAGE_EVENT_KIND_SPAN,
};
use crate::signing::{sign_event_id, NostrSigningKey};

/// Tag name for the NIP-33/NIP-01 `d` replaceability key (= hex `info_hash`).
pub const TAG_D: &str = "d";
/// Tag name for NIP-40 event expiration.
pub const TAG_EXPIRATION: &str = "expiration";

/// Maximum base64-encoded content length accepted when unpacking. The NIP-44
/// framing expands the sealed blob: a raw `ct` becomes
/// `1 + 32 + (2 + calc_padded_len(ct)) + 32` bytes, then base64 grows it ~4/3.
/// A 768 B announcement lands at ~1.1 KB; even a `ct` near the publish cap
/// (~4 KB) frames+base64s to ~5.6 KB, so 8192 accepts every legitimate
/// announcement while still capping memory amplification from a malicious relay.
pub const MAX_CONTENT_LEN: usize = 8192;

/// NIP-44 v2 payload version byte.
const NIP44_VERSION: u8 = 0x02;

/// NIP-44 v2 `calc_padded_len` scheme: bucket an unpadded length so the on-wire
/// content length reveals only a coarse bucket, exactly as a real NIP-44
/// encrypted DM does.
fn nip44_padded_len(unpadded: usize) -> usize {
    if unpadded <= 32 {
        return 32;
    }
    let nextpower = 1usize << (usize::BITS - (unpadded - 1).leading_zeros());
    let chunk = if nextpower <= 256 { 32 } else { nextpower / 8 };
    chunk * ((unpadded - 1) / chunk + 1)
}

/// Keystream (2 bytes) that masks the length prefix so it reads as random on the
/// wire (red-team). In a genuine NIP-44 v2 payload the whole nonce..mac region is
/// ChaCha20 ciphertext, so those two bytes are uniformly random; writing the
/// cleartext length there lets a passive relay scraper (who has the frame + the
/// public `info_hash` but NOT the invite) confirm `nip44_padded_len(len) ==
/// total-67` deterministically for every Mirage frame vs ~1/512 for a real DM -
/// enumerating announcements across all operators. `mask_key` is derived from
/// the cohort `shared_salt`, which the scraper does not hold, so the masked
/// bytes are unpredictable to it; both publisher and invite-holding fetcher
/// derive the same mask from `(key, nonce)`.
fn nip44_len_mask(mask_key: &[u8; 32], nonce: &[u8]) -> [u8; 2] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"mirage-nip44-len-mask-v1");
    h.update(mask_key);
    h.update(nonce);
    let d = h.finalize();
    [d[0], d[1]]
}

#[cfg(test)]
mod frame_mask_tests {
    use super::*;

    #[test]
    fn masked_frame_hides_length_but_round_trips() {
        let key = [0x5au8; 32];
        // A ct_len whose exact value would otherwise pass the scraper's
        // consistency test at bytes 33..35.
        let ct = vec![0x11u8; 700];
        let masked = nip44_frame(&ct, Some(&key));
        let unmasked = nip44_frame(&ct, None);

        // Same total size (bucket is a function of ct_len either way) ...
        assert_eq!(masked.len(), unmasked.len());
        // ... but the length prefix bytes (33..35) differ: masked reads as
        // random, so the `padded_len(be16(33..35)) == total-67` test fails.
        assert_ne!(&masked[33..35], &unmasked[33..35]);
        let claimed = u16::from_be_bytes([masked[33], masked[34]]) as usize;
        assert_ne!(
            nip44_padded_len(claimed),
            masked.len() - 67,
            "masked length must NOT satisfy the scraper's consistency test"
        );

        // The invite-holder (same key) recovers the exact ciphertext.
        assert_eq!(nip44_unframe(&masked, Some(&key)).unwrap(), ct);
        // The wrong key does NOT recover it (length decodes to garbage -> either
        // an overflow error or a different byte string).
        let wrong = [0x11u8; 32];
        if let Ok(v) = nip44_unframe(&masked, Some(&wrong)) {
            assert_ne!(v, ct);
        }
        // Legacy None round-trips too (back-compat).
        assert_eq!(nip44_unframe(&unmasked, None).unwrap(), ct);
    }
}

/// Wrap `ciphertext` in a NIP-44-v2-SHAPED frame so the Nostr `content` looks
/// like a common encrypted DM (red-team #15):
/// `version(1) || nonce(32) || [u16 ct_len][ct][RANDOM pad to calc_padded_len(ct_len)] || mac(32)`.
///
/// Real NIP-44 pads the PLAINTEXT length via `calc_padded_len` and then encrypts
/// `[u16 len][plaintext][pad]`, so its whole nonce..mac region is uniform-random
/// ciphertext. We mimic that shape: the length is bucketed on the plaintext
/// length (matching real NIP-44's bucket set), the padding is CSPRNG bytes, and
/// the length prefix is masked with a `shared_salt`-keyed keystream (see
/// [`nip44_len_mask`]) so it too reads as random to a scraper. The Mirage blob
/// (`ct`) is itself AEAD output, and the nonce + mac are random, so the whole
/// region reads as encrypted. Mirage's own seal provides the real
/// authentication; this is pure mimicry.
fn nip44_frame(ciphertext: &[u8], mask_key: Option<&[u8; 32]>) -> Vec<u8> {
    // Guard the u16 length prefix. Announcements are ~768 B (well under the
    // publish cap), so this cap is never hit in practice.
    let ct_len = ciphertext.len().min(u16::MAX as usize);
    let ct = &ciphertext[..ct_len];
    // Encrypted region = 2-byte length prefix + plaintext padded to the NIP-44
    // bucket for the plaintext length.
    let region = 2 + nip44_padded_len(ct_len);
    let total = 1 + 32 + region + 32;
    let mut out = vec![0u8; total];
    // CSPRNG-fill everything first so nonce, padding, and mac all read as
    // encrypted; then overlay the version byte + length + ct.
    let _ = getrandom::fill(&mut out);
    out[0] = NIP44_VERSION;
    let body = 1 + 32; // after version + nonce
    let mut len_be = (ct_len as u16).to_be_bytes();
    if let Some(key) = mask_key {
        // XOR the length with a secret-keyed keystream over the (random) nonce so
        // it is indistinguishable from ciphertext to a scraper.
        let mask = nip44_len_mask(key, &out[1..33]);
        len_be[0] ^= mask[0];
        len_be[1] ^= mask[1];
    }
    out[body..body + 2].copy_from_slice(&len_be);
    out[body + 2..body + 2 + ct_len].copy_from_slice(ct);
    out
}

/// Recover the ciphertext from a [`nip44_frame`]. `mask_key` MUST match what
/// framing used (the cohort `shared_salt`-derived key, or `None` for legacy).
fn nip44_unframe(bytes: &[u8], mask_key: Option<&[u8; 32]>) -> Result<Vec<u8>, NostrError> {
    if bytes.len() < 1 + 32 + 2 + 32 || bytes[0] != NIP44_VERSION {
        return Err(NostrError::Wire("content not a NIP-44 v2 frame"));
    }
    let nonce = &bytes[1..33];
    let body = &bytes[33..bytes.len() - 32]; // between nonce and mac
    let mut len_be = [body[0], body[1]];
    if let Some(key) = mask_key {
        let mask = nip44_len_mask(key, nonce);
        len_be[0] ^= mask[0];
        len_be[1] ^= mask[1];
    }
    let len = u16::from_be_bytes(len_be) as usize;
    if 2 + len > body.len() {
        return Err(NostrError::Wire("NIP-44 frame length overflow"));
    }
    Ok(body[2..2 + len].to_vec())
}

/// Maximum total byte budget across all tags (sum of all bytes in all tag
/// elements) accepted when unpacking. Same `DoS` rationale as content cap.
pub const MAX_TAGS_TOTAL_BYTES: usize = 4096;

/// Build a signed Nostr event announcing `ciphertext` under `info_hash`.
///
/// - `info_hash` - 20-byte epoch info-hash (hex-encoded into the `d` tag).
/// - `ciphertext` - Mirage sealed blob (base64-encoded into `content`).
/// - `created_at` - unix seconds; the relay uses this for ordering.
/// - `expires_at` - unix seconds; relays SHOULD drop past this.
/// - `signing_key` - operator's disposable Nostr Schnorr key.
pub fn build_announcement_event(
    info_hash: &[u8; 20],
    ciphertext: &[u8],
    created_at: u64,
    expires_at: u64,
    signing_key: &NostrSigningKey,
    frame_key: Option<&[u8; 32]>,
) -> Result<NostrEvent, NostrError> {
    let info_hash_hex = hex::encode(info_hash);
    // NIP-44-shaped, bucket-padded content (red-team #15); `frame_key` (cohort
    // shared_salt) masks the length so a scraper can't enumerate frames.
    let content = B64.encode(nip44_frame(ciphertext, frame_key));
    let mut parts = NostrEventParts::mirage_event(created_at, content)
        .with_tag(TAG_D, &info_hash_hex)
        .with_tag(TAG_EXPIRATION, expires_at.to_string());
    // Per-epoch kind derived from the info_hash (no single enumerable constant).
    // Set BEFORE compute_id so the event id covers the real kind.
    parts.kind = crate::event::mirage_event_kind(info_hash);

    let pubkey_bytes = signing_key.verifying_key_bytes();
    let pubkey_hex = hex::encode(pubkey_bytes);
    let event_id = parts.compute_id(&pubkey_hex)?;
    let sig = sign_event_id(signing_key, &event_id);

    Ok(NostrEvent {
        id: hex::encode(event_id),
        pubkey: pubkey_hex,
        created_at: parts.created_at,
        kind: parts.kind,
        tags: parts.tags,
        content: parts.content,
        sig: hex::encode(sig),
    })
}

/// Unpacked, verified contents of a Mirage-announcement Nostr event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnpackedAnnouncement {
    /// Epoch info-hash that this event's `d` tag claims.
    pub info_hash: [u8; 20],
    /// Mirage sealed ciphertext.
    pub ciphertext: Vec<u8>,
    /// Event's `created_at` (unix seconds).
    pub created_at: u64,
    /// Parsed NIP-40 expiration, if present.
    pub expiration: Option<u64>,
    /// The Nostr-key pubkey that signed the event. Useful for operators that
    /// publish through multiple relays and want to dedupe.
    pub nostr_pubkey: [u8; 32],
}

/// Parse and fully verify a received Nostr event:
/// 1. NIP-01 ID matches SHA-256 of canonical fields.
/// 2. BIP-340 Schnorr signature verifies.
/// 3. `kind` is the Mirage event kind.
/// 4. `d` tag is 40 hex chars (20-byte `info_hash`).
/// 5. `content` decodes as valid base64.
///
/// Does NOT verify the Mirage operator signature on the decrypted payload.
/// The caller runs the sealed blob through [`mirage_discovery::seal::open`]
/// and then verifies the decoded [`mirage_discovery::wire::Announcement`]
/// signature with the operator's Ed25519 key.
pub fn unpack_announcement_event(
    event: &NostrEvent,
    frame_key: Option<&[u8; 32]>,
) -> Result<UnpackedAnnouncement, NostrError> {
    // 0. DoS caps (R43/R44). Enforced BEFORE expensive verification so a
    //    junk event fails cheap.
    if event.content.len() > MAX_CONTENT_LEN {
        return Err(NostrError::Wire("content exceeds cap"));
    }
    let tag_bytes: usize = event
        .tags
        .iter()
        .flat_map(|t| t.iter())
        .map(std::string::String::len)
        .sum();
    if tag_bytes > MAX_TAGS_TOTAL_BYTES {
        return Err(NostrError::Wire("tags exceed total-bytes cap"));
    }

    // 1. Kind - cheap range pre-filter (must be in the parametric-replaceable
    //    30000-39999 window). The EXACT per-epoch kind is derived from the
    //    info_hash and can only be checked after the `d` tag is parsed (step 3a).
    if !(MIRAGE_EVENT_KIND_BASE..MIRAGE_EVENT_KIND_BASE + MIRAGE_EVENT_KIND_SPAN)
        .contains(&event.kind)
    {
        return Err(NostrError::Wire(
            "event kind outside parametric-replaceable range",
        ));
    }

    // 2. Verify id + signature (delegated to NostrEvent).
    event.verify()?;

    // 3. `d` tag -> info_hash.
    let d_val = event
        .first_tag_value(TAG_D)
        .ok_or(NostrError::Tag("d tag missing"))?;
    if d_val.len() != 40 {
        return Err(NostrError::Tag("d tag is not 20-byte hex"));
    }
    let info_hash_bytes = hex::decode(d_val).map_err(|_| NostrError::Tag("d tag not hex"))?;
    let mut info_hash = [0u8; 20];
    info_hash.copy_from_slice(&info_hash_bytes);

    // 3a. Kind must be the per-epoch kind derived from THIS event's info_hash -
    //     a signed event whose kind doesn't match its own `d` tag is malformed.
    if event.kind != mirage_event_kind(&info_hash) {
        return Err(NostrError::Wire("event kind does not match its info_hash"));
    }

    // 4. `expiration` tag (optional).
    let expiration = event
        .first_tag_value(TAG_EXPIRATION)
        .and_then(|s| s.parse::<u64>().ok());

    // 5. Content -> NIP-44 frame -> ciphertext.
    let frame = B64
        .decode(event.content.as_bytes())
        .map_err(|_| NostrError::Base64("content"))?;
    let ciphertext = nip44_unframe(&frame, frame_key)?;

    Ok(UnpackedAnnouncement {
        info_hash,
        ciphertext,
        created_at: event.created_at,
        expiration,
        nostr_pubkey: event.pubkey_bytes()?,
    })
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_sk() -> NostrSigningKey {
        NostrSigningKey::from_seed(&[0x42u8; 32]).unwrap()
    }

    #[test]
    fn build_then_unpack_roundtrip() {
        let sk = fixed_sk();
        let info_hash = [0xAAu8; 20];
        let ciphertext = b"an opaque sealed mirage blob".to_vec();

        let event = build_announcement_event(
            &info_hash,
            &ciphertext,
            1_700_000_000,
            1_700_003_600,
            &sk,
            None,
        )
        .unwrap();

        // Event survives a JSON roundtrip (relay transmission).
        let json = serde_json::to_string(&event).unwrap();
        let back: NostrEvent = serde_json::from_str(&json).unwrap();

        let unpacked = unpack_announcement_event(&back, None).unwrap();
        assert_eq!(unpacked.info_hash, info_hash);
        assert_eq!(unpacked.ciphertext, ciphertext);
        assert_eq!(unpacked.created_at, 1_700_000_000);
        assert_eq!(unpacked.expiration, Some(1_700_003_600));
        assert_eq!(unpacked.nostr_pubkey, sk.verifying_key_bytes());
    }

    #[test]
    fn event_kind_is_derived_per_epoch() {
        let sk = fixed_sk();
        // The kind is derived from the info_hash and lands in 30000-39999; it is
        // NOT the old fixed 30303, and two different info_hashes generally differ.
        let e0 = build_announcement_event(&[0u8; 20], b"x", 0, 1, &sk, None).unwrap();
        let e1 = build_announcement_event(&[0x11u8; 20], b"x", 0, 1, &sk, None).unwrap();
        assert_eq!(e0.kind, mirage_event_kind(&[0u8; 20]));
        assert!((30000..40000).contains(&e0.kind));
        assert!((30000..40000).contains(&e1.kind));
        assert_ne!(
            e0.kind, e1.kind,
            "distinct info_hashes should map to distinct kinds here"
        );
    }

    #[test]
    fn d_tag_is_hex_of_info_hash() {
        let sk = fixed_sk();
        let info_hash = [0x11u8; 20];
        let event = build_announcement_event(&info_hash, b"x", 0, 1, &sk, None).unwrap();
        assert_eq!(event.first_tag_value(TAG_D), Some(&"11".repeat(20)[..]));
    }

    #[test]
    fn expiration_tag_present() {
        let sk = fixed_sk();
        let event = build_announcement_event(&[0u8; 20], b"x", 0, 12345, &sk, None).unwrap();
        assert_eq!(event.first_tag_value(TAG_EXPIRATION), Some("12345"));
    }

    #[test]
    fn unpack_rejects_wrong_kind() {
        let sk = fixed_sk();
        let mut event = build_announcement_event(&[0u8; 20], b"x", 0, 1, &sk, None).unwrap();
        // Tamper with kind - also breaks ID, but we test kind first.
        event.kind = 1;
        assert!(unpack_announcement_event(&event, None).is_err());
    }

    #[test]
    fn unpack_rejects_tampered_content() {
        let sk = fixed_sk();
        let mut event = build_announcement_event(&[0u8; 20], b"original", 0, 1, &sk, None).unwrap();
        event.content = B64.encode(b"tampered");
        // Signature is over the ORIGINAL event ID (computed with original
        // content). Changing content -> recomputed ID differs from event.id
        // -> IdMismatch OR signature-invalid depending on order. `verify`
        // checks id equality first, so IdMismatch is expected.
        let err = unpack_announcement_event(&event, None).unwrap_err();
        assert!(matches!(
            err,
            NostrError::IdMismatch | NostrError::SignatureInvalid
        ));
    }

    #[test]
    fn unpack_rejects_missing_d_tag() {
        let sk = fixed_sk();
        let mut event = build_announcement_event(&[0u8; 20], b"x", 0, 1, &sk, None).unwrap();
        // Drop the `d` tag, keep signature intact (it won't be - id changes).
        // This test exercises the tag-missing path; we re-sign after removing.
        event
            .tags
            .retain(|t| t.first().map(std::string::String::as_str) != Some("d"));
        // Re-sign so id + sig match the new canonical form.
        let pubkey_hex = &event.pubkey;
        let parts = NostrEventParts {
            created_at: event.created_at,
            kind: event.kind,
            tags: event.tags.clone(),
            content: event.content.clone(),
        };
        let new_id = parts.compute_id(pubkey_hex).unwrap();
        let new_sig = sign_event_id(&sk, &new_id);
        event.id = hex::encode(new_id);
        event.sig = hex::encode(new_sig);

        match unpack_announcement_event(&event, None) {
            Err(NostrError::Tag(_)) => {}
            Ok(_) => panic!("must reject missing d tag"),
            Err(e) => panic!("expected Tag error, got {e:?}"),
        }
    }

    #[test]
    fn unpack_rejects_malformed_d_tag() {
        let sk = fixed_sk();
        // Publish with a malformed d tag: non-hex string. We build by hand.
        let parts = NostrEventParts::mirage_event(0, B64.encode(b"x"))
            .with_tag(TAG_D, "not-hex-at-all!!")
            .with_tag(TAG_EXPIRATION, "1");
        let pubkey_hex = hex::encode(sk.verifying_key_bytes());
        let id = parts.compute_id(&pubkey_hex).unwrap();
        let event = NostrEvent {
            id: hex::encode(id),
            pubkey: pubkey_hex,
            created_at: parts.created_at,
            kind: parts.kind,
            tags: parts.tags,
            content: parts.content,
            sig: hex::encode(sign_event_id(&sk, &id)),
        };
        match unpack_announcement_event(&event, None) {
            Err(NostrError::Tag(_)) => {}
            other => panic!("expected Tag error, got {other:?}"),
        }
    }

    #[test]
    fn unpack_rejects_short_d_tag() {
        let sk = fixed_sk();
        let parts = NostrEventParts::mirage_event(0, B64.encode(b"x"))
            .with_tag(TAG_D, "aabbcc") // too short
            .with_tag(TAG_EXPIRATION, "1");
        let pubkey_hex = hex::encode(sk.verifying_key_bytes());
        let id = parts.compute_id(&pubkey_hex).unwrap();
        let event = NostrEvent {
            id: hex::encode(id),
            pubkey: pubkey_hex,
            created_at: parts.created_at,
            kind: parts.kind,
            tags: parts.tags,
            content: parts.content,
            sig: hex::encode(sign_event_id(&sk, &id)),
        };
        match unpack_announcement_event(&event, None) {
            Err(NostrError::Tag(_)) => {}
            other => panic!("expected Tag error, got {other:?}"),
        }
    }

    #[test]
    fn unpack_rejects_malformed_base64_content() {
        let sk = fixed_sk();
        // Content that is not valid base64. Use the correct per-epoch kind so
        // unpack reaches the base64 step (not the kind check).
        let info_hash = [0xaau8; 20];
        let mut parts = NostrEventParts::mirage_event(0, "not-base64-!!".to_string())
            .with_tag(TAG_D, hex::encode(info_hash))
            .with_tag(TAG_EXPIRATION, "1");
        parts.kind = mirage_event_kind(&info_hash);
        let pubkey_hex = hex::encode(sk.verifying_key_bytes());
        let id = parts.compute_id(&pubkey_hex).unwrap();
        let event = NostrEvent {
            id: hex::encode(id),
            pubkey: pubkey_hex,
            created_at: parts.created_at,
            kind: parts.kind,
            tags: parts.tags,
            content: parts.content,
            sig: hex::encode(sign_event_id(&sk, &id)),
        };
        match unpack_announcement_event(&event, None) {
            Err(NostrError::Base64(_)) => {}
            other => panic!("expected Base64 error, got {other:?}"),
        }
    }

    /// R43: a relay feeding an oversized `content` must be cheap-rejected
    /// before expensive signature verification.
    #[test]
    fn unpack_rejects_oversized_content() {
        let sk = fixed_sk();
        let event = NostrEvent {
            id: "aa".repeat(32),
            pubkey: hex::encode(sk.verifying_key_bytes()),
            created_at: 0,
            kind: 30303, // in-range; these tests reject at the DoS caps before the kind check
            tags: vec![vec!["d".into(), "aa".repeat(20)]],
            content: "x".repeat(MAX_CONTENT_LEN + 1),
            sig: "00".repeat(64),
        };
        match unpack_announcement_event(&event, None) {
            Err(NostrError::Wire(m)) if m.contains("content") => {}
            other => panic!("expected Wire(content cap), got {other:?}"),
        }
    }

    /// R44: a relay feeding a huge tag forest must be cheap-rejected.
    #[test]
    fn unpack_rejects_oversized_tags() {
        let sk = fixed_sk();
        // Build enough tag bytes to exceed MAX_TAGS_TOTAL_BYTES.
        let big = "y".repeat(MAX_TAGS_TOTAL_BYTES / 4 + 1);
        let event = NostrEvent {
            id: "aa".repeat(32),
            pubkey: hex::encode(sk.verifying_key_bytes()),
            created_at: 0,
            kind: 30303, // in-range; these tests reject at the DoS caps before the kind check
            tags: vec![
                vec!["d".into(), "aa".repeat(20)],
                vec!["x".into(), big.clone()],
                vec!["y".into(), big.clone()],
                vec!["z".into(), big.clone()],
                vec!["w".into(), big],
            ],
            content: "x".to_string(),
            sig: "00".repeat(64),
        };
        match unpack_announcement_event(&event, None) {
            Err(NostrError::Wire(m)) if m.contains("tags") => {}
            other => panic!("expected Wire(tags cap), got {other:?}"),
        }
    }

    #[test]
    fn unpack_rejects_forged_signature() {
        let sk_real = fixed_sk();
        let sk_impostor = NostrSigningKey::from_seed(&[0x77u8; 32]).unwrap();

        // Build event signed by impostor but pubkey claims real signer.
        let info_hash = [0xBBu8; 20];
        let content = B64.encode(b"ciphertext");
        let parts = NostrEventParts::mirage_event(0, content)
            .with_tag(TAG_D, hex::encode(info_hash))
            .with_tag(TAG_EXPIRATION, "1");
        let real_pubkey_hex = hex::encode(sk_real.verifying_key_bytes());
        // id is computed with real_pubkey baked in, but signed by impostor.
        let id = parts.compute_id(&real_pubkey_hex).unwrap();
        let forged_sig = sign_event_id(&sk_impostor, &id);
        let event = NostrEvent {
            id: hex::encode(id),
            pubkey: real_pubkey_hex,
            created_at: parts.created_at,
            kind: parts.kind,
            tags: parts.tags,
            content: parts.content,
            sig: hex::encode(forged_sig),
        };
        match unpack_announcement_event(&event, None) {
            Err(NostrError::SignatureInvalid) => {}
            other => panic!("forged sig must be rejected, got {other:?}"),
        }
    }
}
