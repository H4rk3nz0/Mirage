//! TLS 1.3 key schedule - HKDF-Expand-Label + handshake/traffic secrets.
//!
//! Implements the derivation defined in RFC 8446 §7.1. Used by the
//! Reality v0.1c carrier to bind traffic keys to the handshake
//! transcript hash, so an active prober that completes a full
//! TLS 1.3 handshake reaches the same keys we do.
//!
//! # Scope
//!
//! We implement only what the Reality bridge + client exchange:
//!
//! - `early_secret` (with no PSK; IKM and salt both zeroed).
//! - `derived_secret` / `handshake_secret` / `master_secret`.
//! - Per-direction `handshake_traffic_secret` and
//!   `application_traffic_secret_0`.
//! - `finished_key` and `resumption_master_secret` (latter unused
//!   but computed so future PSK mode is a drop-in).
//!
//! Exporter secrets and 0-RTT are out of scope.

use mirage_crypto::hkdf::Hkdf;
use mirage_crypto::sha2::{Digest, Sha256};
use mirage_crypto::zeroize::Zeroizing;

/// SHA-256 hash length (TLS 1.3's only v1 requirement is HKDF with
/// a hash that is part of the cipher suite; we use SHA-256 because
/// our declared suite is `TLS_CHACHA20_POLY1305_SHA256`).
pub const HASH_LEN: usize = 32;

/// AEAD key length (ChaCha20-Poly1305 and AES-128-GCM both have a 32-
/// or 16-byte key depending on cipher). For ChaCha20-Poly1305 it is
/// 32 bytes.
pub const CHACHA_KEY_LEN: usize = 32;

/// AEAD IV length (same across ChaCha20-Poly1305 and AES-GCM).
pub const AEAD_IV_LEN: usize = 12;

/// Running SHA-256 transcript hash. TLS 1.3 §4.4.1:
///
/// > Transcript-Hash(M1, M2, ..., Mn) = Hash(M1 || M2 || ... || Mn)
///
/// where each M_i is a complete handshake message INCLUDING the
/// 4-byte handshake header.
#[derive(Debug, Clone)]
pub struct TranscriptHash {
    inner: Sha256,
}

impl TranscriptHash {
    /// Start an empty transcript.
    pub fn new() -> Self {
        Self {
            inner: Sha256::new(),
        }
    }

    /// Append a complete handshake message (with its 4-byte header).
    pub fn update(&mut self, handshake_msg: &[u8]) {
        self.inner.update(handshake_msg);
    }

    /// Current transcript hash without consuming.
    pub fn snapshot(&self) -> [u8; HASH_LEN] {
        let out = self.inner.clone().finalize();
        let mut o = [0u8; HASH_LEN];
        o.copy_from_slice(&out);
        o
    }
}

impl Default for TranscriptHash {
    fn default() -> Self {
        Self::new()
    }
}

// HKDF-Expand-Label

/// HkdfLabel per RFC 8446 §7.1:
/// ```text
/// struct {
///     uint16 length = Length;
///     opaque label<7..255> = "tls13 " + Label;
///     opaque context<0..255> = Context;
/// } HkdfLabel;
/// ```
fn hkdf_label(length: u16, label: &str, context: &[u8]) -> Vec<u8> {
    let full_label = format!("tls13 {label}");
    let full_label_bytes = full_label.as_bytes();
    debug_assert!(full_label_bytes.len() >= 7 && full_label_bytes.len() <= 255);
    debug_assert!(context.len() <= 255);
    let mut out = Vec::with_capacity(2 + 1 + full_label_bytes.len() + 1 + context.len());
    out.extend_from_slice(&length.to_be_bytes());
    out.push(full_label_bytes.len() as u8);
    out.extend_from_slice(full_label_bytes);
    out.push(context.len() as u8);
    out.extend_from_slice(context);
    out
}

/// Full HKDF-Expand-Label: PRK is the 32-byte secret; output is
/// `length` bytes.
pub fn hkdf_expand_label(
    secret: &[u8; HASH_LEN],
    label: &str,
    context: &[u8],
    length: u16,
) -> Vec<u8> {
    let info = hkdf_label(length, label, context);
    let hk = Hkdf::<Sha256>::from_prk(secret).expect("HKDF from_prk with 32-byte PRK");
    let mut out = vec![0u8; length as usize];
    hk.expand(&info, &mut out)
        .expect("HKDF expand within bounds");
    out
}

/// Shorthand: expand and return a fixed-size array.
pub fn hkdf_expand_label_fixed<const N: usize>(
    secret: &[u8; HASH_LEN],
    label: &str,
    context: &[u8],
) -> [u8; N] {
    let v = hkdf_expand_label(secret, label, context, N as u16);
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    out
}

/// TLS 1.3 `Derive-Secret(Secret, Label, Messages)`:
/// `HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)`.
pub fn derive_secret(
    secret: &[u8; HASH_LEN],
    label: &str,
    transcript: &[u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    hkdf_expand_label_fixed::<HASH_LEN>(secret, label, transcript)
}

// Key schedule stages

/// SHA-256 of the empty string - RFC 8446 §4.4.1 requires this as
/// the context for the first `Derived` step. We inline it as a
/// constant because recomputing is trivial but annoying.
pub const EMPTY_HASH: [u8; HASH_LEN] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// Early-secret = HKDF-Extract(salt=0, IKM=0). With no PSK the IKM
/// is a 32-byte zero block; the salt for the first Extract per
/// RFC 8446 §7.1 is also "all-zeros".
pub fn early_secret_no_psk() -> [u8; HASH_LEN] {
    let zero = [0u8; HASH_LEN];
    let (prk, _) = Hkdf::<Sha256>::extract(Some(&zero), &zero);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&prk);
    out
}

/// `handshake_secret = HKDF-Extract(Derive-Secret(Early, "derived", ""), (EC)DHE)`.
///
/// `ecdh_shared` is used verbatim as the HKDF IKM: 32 bytes for plain X25519, or
/// the 64-byte `ML-KEM-768 ss || X25519 ss` concatenation for the
/// X25519MLKEM768 hybrid group.
pub fn handshake_secret(early: &[u8; HASH_LEN], ecdh_shared: &[u8]) -> [u8; HASH_LEN] {
    let derived = derive_secret(early, "derived", &EMPTY_HASH);
    let (prk, _) = Hkdf::<Sha256>::extract(Some(&derived), ecdh_shared);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&prk);
    out
}

/// `master_secret = HKDF-Extract(Derive-Secret(Handshake, "derived", ""), 0)`.
pub fn master_secret(handshake: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    let derived = derive_secret(handshake, "derived", &EMPTY_HASH);
    let zero = [0u8; HASH_LEN];
    let (prk, _) = Hkdf::<Sha256>::extract(Some(&derived), &zero);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&prk);
    out
}

/// Per-direction handshake traffic secret. Label is "c hs traffic"
/// or "s hs traffic" per RFC 8446 §7.1.
pub fn handshake_traffic_secret(
    handshake: &[u8; HASH_LEN],
    direction_label: &str,
    transcript_ch_sh: &[u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    derive_secret(handshake, direction_label, transcript_ch_sh)
}

/// Per-direction application traffic secret (epoch 0). Label is
/// "c ap traffic" or "s ap traffic" per RFC 8446 §7.1.
pub fn application_traffic_secret_0(
    master: &[u8; HASH_LEN],
    direction_label: &str,
    transcript_ch_sf: &[u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    derive_secret(master, direction_label, transcript_ch_sf)
}

/// Traffic key + IV from a traffic secret. Per RFC 8446 §7.3:
///
/// ```text
///   key = HKDF-Expand-Label(Secret, "key", "", key_length)
///   iv  = HKDF-Expand-Label(Secret, "iv",  "", iv_length)
/// ```
pub fn traffic_keys_chacha(
    secret: &[u8; HASH_LEN],
) -> (Zeroizing<[u8; CHACHA_KEY_LEN]>, [u8; AEAD_IV_LEN]) {
    let key = hkdf_expand_label_fixed::<CHACHA_KEY_LEN>(secret, "key", &[]);
    let iv = hkdf_expand_label_fixed::<AEAD_IV_LEN>(secret, "iv", &[]);
    (Zeroizing::new(key), iv)
}

/// AES-128 key length (bytes).
pub const AES128_KEY_LEN: usize = 16;

/// Derive `(key, iv)` for the `TLS_AES_128_GCM_SHA256` record cipher:
/// `HKDF-Expand-Label(Secret, "key", "", 16)` + `..("iv", "", 12)`. Identical
/// schedule to [`traffic_keys_chacha`] but a 16-byte key, so the bridge can
/// mirror the AES-128-GCM a real CDN selects for a Chrome/Firefox ClientHello.
pub fn traffic_keys_aes128(
    secret: &[u8; HASH_LEN],
) -> (Zeroizing<[u8; AES128_KEY_LEN]>, [u8; AEAD_IV_LEN]) {
    let key = hkdf_expand_label_fixed::<AES128_KEY_LEN>(secret, "key", &[]);
    let iv = hkdf_expand_label_fixed::<AEAD_IV_LEN>(secret, "iv", &[]);
    (Zeroizing::new(key), iv)
}

/// `finished_key = HKDF-Expand-Label(Secret, "finished", "", Hash.length)`.
pub fn finished_key(traffic_secret: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    hkdf_expand_label_fixed::<HASH_LEN>(traffic_secret, "finished", &[])
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_hash_is_sha256_of_empty() {
        let mut h = Sha256::new();
        h.update(b"");
        let out = h.finalize();
        assert_eq!(&EMPTY_HASH[..], &out[..]);
    }

    #[test]
    fn transcript_snapshot_matches_direct_sha256() {
        let msgs: &[&[u8]] = &[b"hello", b"world"];
        let mut t = TranscriptHash::new();
        for m in msgs {
            t.update(m);
        }
        let snap = t.snapshot();

        let mut h = Sha256::new();
        for m in msgs {
            h.update(m);
        }
        let out = h.finalize();
        assert_eq!(snap, out[..]);
    }

    #[test]
    fn early_secret_no_psk_is_deterministic() {
        // RFC 8446 A.4 first row: HKDF-Extract(0, 0) with SHA-256.
        // Expected value (hex): 33ad0a1c607ec03b 09e6cd9893680ce2 10adf300aa1f2660 e1b22e10f170f92a
        let e = early_secret_no_psk();
        assert_eq!(
            hex_of(&e),
            "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"
        );
    }

    #[test]
    fn hkdf_expand_label_matches_rfc_shape() {
        // Smoke-test: expand a 16-byte output with a known PRK. Not a
        // named RFC vector; just checks the label-wrapping path.
        let prk = [0xABu8; HASH_LEN];
        let out16 = hkdf_expand_label(&prk, "key", b"", 16);
        assert_eq!(out16.len(), 16);
        // And a different label should produce different bytes.
        let iv12 = hkdf_expand_label(&prk, "iv", b"", 12);
        assert_ne!(&out16[..12], &iv12[..]);
    }

    #[test]
    fn handshake_traffic_secrets_differ_by_direction() {
        let early = early_secret_no_psk();
        let dh = [0x11u8; 32];
        let hs = handshake_secret(&early, &dh);
        let mut th = TranscriptHash::new();
        th.update(b"ClientHello-ish");
        th.update(b"ServerHello-ish");
        let snap = th.snapshot();
        let cs = handshake_traffic_secret(&hs, "c hs traffic", &snap);
        let ss = handshake_traffic_secret(&hs, "s hs traffic", &snap);
        assert_ne!(cs, ss);
    }

    #[test]
    fn traffic_keys_chacha_have_correct_shape() {
        let secret = [0x55u8; HASH_LEN];
        let (key, iv) = traffic_keys_chacha(&secret);
        assert_eq!(key.as_ref().len(), CHACHA_KEY_LEN);
        assert_eq!(iv.len(), AEAD_IV_LEN);
    }

    fn hex_of(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for x in b {
            use std::fmt::Write;
            write!(&mut s, "{x:02x}").unwrap();
        }
        s
    }
}
