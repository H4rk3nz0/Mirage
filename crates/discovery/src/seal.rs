//! Per-epoch encrypt/decrypt of discovery blobs.
//!
//! Uses ChaCha20-Poly1305 with the per-epoch `cipher_key` derived from
//! `(shared_salt, namespace, epoch)` via [`crate::derive`], and a **fresh
//! random 96-bit nonce drawn per seal** that is prefixed to the ciphertext.
//!
//! # Why a random nonce (not a derived one)
//!
//! ChaCha20-Poly1305 catastrophically fails under `(key, nonce)` reuse:
//! two messages encrypted with the same pair leak their XOR (keystream
//! reuse) and allow Poly1305 forgery. An earlier design derived the nonce
//! *also* from `(shared_salt, namespace, epoch)` - but the cipher key is
//! fixed by those same coordinates, so any two distinct plaintexts sealed
//! in one epoch under one namespace shared a single `(key, nonce)`. That is
//! routine: an operator publishes an announcement AND a revocation in the
//! same epoch, both under `NAMESPACE_CLIENT_TO_BRIDGE` (see
//! [`crate::pipeline`]). A per-seal random nonce removes the reuse: the key
//! is reused across messages (safe), the nonce is unique per message.
//! Envelope on the wire is `nonce(12) || ciphertext||tag`.

use mirage_crypto::chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use mirage_crypto::zeroize::Zeroizing;

use crate::derive::cipher_key;
use crate::error::DiscoveryError;

/// Length of the random ChaCha20-Poly1305 nonce prefixed to every sealed
/// blob. 96 bits - a random nonce collides only after ~2^48 seals under one
/// epoch key, far beyond any realistic discovery-publish volume.
pub const SEAL_NONCE_LEN: usize = 12;

/// AAD prefix tag - bumped if the seal envelope ever changes shape.
/// Bound into the AEAD AAD on every seal/open so a future v2 seal
/// (different AAD, same key derivation) cannot be confused with v1.
const SEAL_AAD_TAG: &[u8] = b"mirage-seal-v1";

/// Build the AEAD AAD: `tag || namespace || epoch_be`.
/// Defense-in-depth: the cipher key already domain-separates by
/// (namespace, epoch), but binding them as AAD as well means a
/// future codepath that ever derives a colliding cipher key (key
/// reuse bug, hash truncation regression) still cannot lift a
/// ciphertext into a different namespace or epoch.
fn build_aad(namespace: &[u8], epoch: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SEAL_AAD_TAG.len() + namespace.len() + 8);
    aad.extend_from_slice(SEAL_AAD_TAG);
    aad.extend_from_slice(namespace);
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad
}

/// Encrypt a discovery blob for `(shared_salt, namespace, epoch)`.
///
/// Only holders of `shared_salt` can decrypt. Output is
/// `SEAL_NONCE_LEN + plaintext.len() + 16` bytes (12-byte random nonce
/// prefix + ciphertext + Poly1305 tag). Each call draws a fresh nonce, so
/// sealing the same plaintext twice yields different ciphertext - this is
/// required for correctness, not just privacy (see the module docs on
/// `(key, nonce)` reuse).
///
/// Wraps the derived per-epoch cipher key in [`Zeroizing`] so it is
/// erased from stack memory when the call returns, even on panic.
pub fn seal(
    shared_salt: &[u8; 32],
    namespace: &[u8],
    epoch: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, DiscoveryError> {
    let key_bytes = Zeroizing::new(cipher_key(shared_salt, namespace, epoch));
    // Fresh random nonce per seal - never derived from the (key-determining)
    // coordinates. See the module-level security note.
    let mut nonce_bytes = [0u8; SEAL_NONCE_LEN];
    getrandom::fill(&mut nonce_bytes)
        .map_err(|_| DiscoveryError::Decrypt("seal nonce rng failed"))?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes.as_ref()));
    let aad = build_aad(namespace, epoch);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| DiscoveryError::Decrypt("chacha20poly1305 encrypt failed"))?;
    let mut out = Vec::with_capacity(SEAL_NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a discovery blob with `(shared_salt, namespace, epoch)`.
///
/// Expects the [`seal`] envelope: a `SEAL_NONCE_LEN`-byte nonce prefix
/// followed by ciphertext+tag. Returns `Err(DiscoveryError::Decrypt)` if the
/// blob is too short, or the tag does not verify (wrong salt, wrong epoch,
/// tampered ciphertext, or a tampered nonce prefix - the nonce is not
/// authenticated directly, but altering it yields a wrong keystream so the
/// Poly1305 tag fails).
///
/// The derived per-epoch cipher key is zeroized when the call returns.
pub fn open(
    shared_salt: &[u8; 32],
    namespace: &[u8],
    epoch: u64,
    blob: &[u8],
) -> Result<Vec<u8>, DiscoveryError> {
    if blob.len() < SEAL_NONCE_LEN + 16 {
        return Err(DiscoveryError::Decrypt("sealed blob too short"));
    }
    let (nonce_bytes, ciphertext) = blob.split_at(SEAL_NONCE_LEN);
    let key_bytes = Zeroizing::new(cipher_key(shared_salt, namespace, epoch));
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes.as_ref()));
    let aad = build_aad(namespace, epoch);
    cipher
        .decrypt(
            Nonce::from_slice(nonce_bytes),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| DiscoveryError::Decrypt("chacha20poly1305 decrypt failed"))
}

/// Decrypt with tolerance for one epoch of clock skew on each side (spec §4.4).
///
/// Tries `epoch`, then `epoch - 1`, then `epoch + 1`. Returns the first
/// success. If all three fail, returns the last error.
pub fn open_with_skew_tolerance(
    shared_salt: &[u8; 32],
    namespace: &[u8],
    epoch: u64,
    ciphertext: &[u8],
) -> Result<(Vec<u8>, u64), DiscoveryError> {
    if let Ok(pt) = open(shared_salt, namespace, epoch, ciphertext) {
        return Ok((pt, epoch));
    }
    if let Some(prev) = epoch.checked_sub(1) {
        if let Ok(pt) = open(shared_salt, namespace, prev, ciphertext) {
            return Ok((pt, prev));
        }
    }
    // Why checked_add: epoch is u64 but a malicious clock-skew or
    // crafted message could land us at u64::MAX; +1 would panic.
    let Some(next) = epoch.checked_add(1) else {
        return open(shared_salt, namespace, epoch, ciphertext).map(|pt| (pt, epoch));
    };
    open(shared_salt, namespace, next, ciphertext).map(|pt| (pt, next))
}

/// AAD tag for the forward-secret seal envelope. Distinct from [`SEAL_AAD_TAG`]
/// so an FS ciphertext can never be opened as a baseline one (or vice versa).
const SEAL_AAD_TAG_FS: &[u8] = b"mirage-seal-fs-v1";

/// Build the FS AAD: `fs_tag || namespace || anchor_epoch_be || epoch_be`.
fn build_aad_fs(namespace: &[u8], anchor_epoch: u64, epoch: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SEAL_AAD_TAG_FS.len() + namespace.len() + 16);
    aad.extend_from_slice(SEAL_AAD_TAG_FS);
    aad.extend_from_slice(namespace);
    aad.extend_from_slice(&anchor_epoch.to_be_bytes());
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad
}

/// Forward-secret [`seal`]: key from the one-way [`crate::ratchet`] chain
/// anchored at `anchor_epoch` rather than directly from the salt, so a party
/// that discards the salt/anchor after seeding cannot later recompute this
/// epoch's key. Envelope shape is identical to [`seal`]
/// (`nonce(12) || ciphertext||tag`); only the key derivation and AAD differ.
///
/// Returns `Err` if `epoch < anchor_epoch` or the forward delta exceeds
/// [`crate::ratchet::MAX_RATCHET_STEPS`].
pub fn seal_fs(
    shared_salt: &[u8; 32],
    namespace: &[u8],
    anchor_epoch: u64,
    epoch: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, DiscoveryError> {
    let key_bytes = crate::ratchet::fs_cipher_key(shared_salt, namespace, anchor_epoch, epoch)
        .ok_or(DiscoveryError::Decrypt(
            "fs seal epoch out of ratchet range",
        ))?;
    let mut nonce_bytes = [0u8; SEAL_NONCE_LEN];
    getrandom::fill(&mut nonce_bytes)
        .map_err(|_| DiscoveryError::Decrypt("seal nonce rng failed"))?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes.as_ref()));
    let aad = build_aad_fs(namespace, anchor_epoch, epoch);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| DiscoveryError::Decrypt("chacha20poly1305 encrypt failed"))?;
    let mut out = Vec::with_capacity(SEAL_NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Forward-secret [`open`]: counterpart to [`seal_fs`].
pub fn open_fs(
    shared_salt: &[u8; 32],
    namespace: &[u8],
    anchor_epoch: u64,
    epoch: u64,
    blob: &[u8],
) -> Result<Vec<u8>, DiscoveryError> {
    if blob.len() < SEAL_NONCE_LEN + 16 {
        return Err(DiscoveryError::Decrypt("sealed blob too short"));
    }
    let (nonce_bytes, ciphertext) = blob.split_at(SEAL_NONCE_LEN);
    let key_bytes = crate::ratchet::fs_cipher_key(shared_salt, namespace, anchor_epoch, epoch)
        .ok_or(DiscoveryError::Decrypt(
            "fs open epoch out of ratchet range",
        ))?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes.as_ref()));
    let aad = build_aad_fs(namespace, anchor_epoch, epoch);
    cipher
        .decrypt(
            Nonce::from_slice(nonce_bytes),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| DiscoveryError::Decrypt("chacha20poly1305 decrypt failed"))
}

/// Forward-secret [`open_with_skew_tolerance`]: tries `epoch`, `epoch-1`,
/// `epoch+1` (each clamped to the ratchet's valid range).
pub fn open_fs_with_skew_tolerance(
    shared_salt: &[u8; 32],
    namespace: &[u8],
    anchor_epoch: u64,
    epoch: u64,
    ciphertext: &[u8],
) -> Result<(Vec<u8>, u64), DiscoveryError> {
    if let Ok(pt) = open_fs(shared_salt, namespace, anchor_epoch, epoch, ciphertext) {
        return Ok((pt, epoch));
    }
    if let Some(prev) = epoch.checked_sub(1) {
        if let Ok(pt) = open_fs(shared_salt, namespace, anchor_epoch, prev, ciphertext) {
            return Ok((pt, prev));
        }
    }
    let Some(next) = epoch.checked_add(1) else {
        return open_fs(shared_salt, namespace, anchor_epoch, epoch, ciphertext)
            .map(|pt| (pt, epoch));
    };
    open_fs(shared_salt, namespace, anchor_epoch, next, ciphertext).map(|pt| (pt, next))
}

/// Forward-secret seal using a directly-provided per-epoch `cipher_key` (from a
/// [`crate::ratchet::RendezvousRatchet`]) instead of the salt.
///
/// This is the PRODUCER-side path that realizes forward secrecy: a publisher
/// driving a ratchet holds only the current chain state (having zeroized the
/// salt), so it CANNOT recompute past keys even if seized. The `cipher_key` must
/// be the ratchet's key for `epoch`; the AAD binds `(anchor_epoch, epoch)`
/// identically to [`seal_fs`], so a salt-holding fetcher opens it with
/// [`open_fs`].
pub fn seal_fs_with_key(
    cipher_key: &[u8; 32],
    namespace: &[u8],
    anchor_epoch: u64,
    epoch: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, DiscoveryError> {
    let mut nonce_bytes = [0u8; SEAL_NONCE_LEN];
    getrandom::fill(&mut nonce_bytes)
        .map_err(|_| DiscoveryError::Decrypt("seal nonce rng failed"))?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(cipher_key));
    let aad = build_aad_fs(namespace, anchor_epoch, epoch);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| DiscoveryError::Decrypt("chacha20poly1305 encrypt failed"))?;
    let mut out = Vec::with_capacity(SEAL_NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::NAMESPACE_CLIENT_TO_BRIDGE;

    fn salt() -> [u8; 32] {
        *b"0123456789abcdef0123456789abcdef"
    }

    #[test]
    fn seal_open_roundtrip() {
        let s = salt();
        let plaintext = b"hello mirage";
        let ct = seal(&s, NAMESPACE_CLIENT_TO_BRIDGE, 100, plaintext).unwrap();
        let pt = open(&s, NAMESPACE_CLIENT_TO_BRIDGE, 100, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn seal_fs_roundtrip_and_isolation() {
        let s = salt();
        let plaintext = b"forward-secret announcement";
        // Anchor at epoch 1000; seal at epoch 1005.
        let ct = seal_fs(&s, NAMESPACE_CLIENT_TO_BRIDGE, 1000, 1005, plaintext).unwrap();
        let pt = open_fs(&s, NAMESPACE_CLIENT_TO_BRIDGE, 1000, 1005, &ct).unwrap();
        assert_eq!(pt, plaintext);

        // An FS ciphertext MUST NOT open as a baseline one (distinct key + AAD).
        assert!(open(&s, NAMESPACE_CLIENT_TO_BRIDGE, 1005, &ct).is_err());
        // Wrong epoch fails the tag.
        assert!(open_fs(&s, NAMESPACE_CLIENT_TO_BRIDGE, 1000, 1006, &ct).is_err());
        // Wrong anchor fails the tag.
        assert!(open_fs(&s, NAMESPACE_CLIENT_TO_BRIDGE, 999, 1005, &ct).is_err());
        // Skew tolerance recovers a +/-1 epoch mismatch.
        let (pt2, ep) =
            open_fs_with_skew_tolerance(&s, NAMESPACE_CLIENT_TO_BRIDGE, 1000, 1004, &ct).unwrap();
        assert_eq!(pt2, plaintext);
        assert_eq!(ep, 1005);
    }

    #[test]
    fn seal_fs_rejects_pre_anchor_epoch() {
        let s = salt();
        assert!(seal_fs(&s, NAMESPACE_CLIENT_TO_BRIDGE, 1000, 999, b"x").is_err());
    }

    #[test]
    fn ciphertext_is_longer_than_plaintext_by_nonce_and_tag() {
        let s = salt();
        let plaintext = b"x";
        let ct = seal(&s, NAMESPACE_CLIENT_TO_BRIDGE, 0, plaintext).unwrap();
        assert_eq!(ct.len(), SEAL_NONCE_LEN + plaintext.len() + 16);
    }

    /// Regression for the CRITICAL nonce-reuse finding: sealing the SAME
    /// plaintext under the SAME (salt, namespace, epoch) twice MUST yield
    /// distinct ciphertext (distinct random nonces), and both MUST open.
    #[test]
    fn repeated_seal_uses_distinct_nonces() {
        let s = salt();
        let pt = b"same plaintext, same epoch";
        let a = seal(&s, NAMESPACE_CLIENT_TO_BRIDGE, 42, pt).unwrap();
        let b = seal(&s, NAMESPACE_CLIENT_TO_BRIDGE, 42, pt).unwrap();
        assert_ne!(a, b, "two seals must not share a (key, nonce)");
        assert_ne!(
            &a[..SEAL_NONCE_LEN],
            &b[..SEAL_NONCE_LEN],
            "nonces must differ"
        );
        assert_eq!(open(&s, NAMESPACE_CLIENT_TO_BRIDGE, 42, &a).unwrap(), pt);
        assert_eq!(open(&s, NAMESPACE_CLIENT_TO_BRIDGE, 42, &b).unwrap(), pt);
    }

    /// The concrete attack the fix closes: an announcement and a revocation
    /// sealed in the same epoch under the same namespace must NOT share a
    /// keystream. Distinct nonce prefixes are the observable guarantee.
    #[test]
    fn announcement_and_revocation_same_epoch_no_keystream_reuse() {
        let s = salt();
        let announce = seal(&s, NAMESPACE_CLIENT_TO_BRIDGE, 7, b"ANNOUNCE bridge A").unwrap();
        let revoke = seal(&s, NAMESPACE_CLIENT_TO_BRIDGE, 7, b"REVOKE bridge B!!").unwrap();
        assert_ne!(&announce[..SEAL_NONCE_LEN], &revoke[..SEAL_NONCE_LEN]);
    }

    #[test]
    fn open_rejects_blob_shorter_than_nonce_plus_tag() {
        let s = salt();
        assert!(open(
            &s,
            NAMESPACE_CLIENT_TO_BRIDGE,
            0,
            &[0u8; SEAL_NONCE_LEN + 15]
        )
        .is_err());
        assert!(open(&s, NAMESPACE_CLIENT_TO_BRIDGE, 0, &[]).is_err());
    }

    #[test]
    fn tampered_nonce_prefix_fails_to_decrypt() {
        let s = salt();
        let mut ct = seal(&s, NAMESPACE_CLIENT_TO_BRIDGE, 0, b"secret").unwrap();
        ct[0] ^= 0x01; // flip a nonce byte -> wrong keystream -> tag fails
        assert!(open(&s, NAMESPACE_CLIENT_TO_BRIDGE, 0, &ct).is_err());
    }

    #[test]
    fn wrong_salt_fails_to_decrypt() {
        let s1 = salt();
        let mut s2 = salt();
        s2[0] ^= 0x01;
        let ct = seal(&s1, NAMESPACE_CLIENT_TO_BRIDGE, 0, b"secret").unwrap();
        assert!(open(&s2, NAMESPACE_CLIENT_TO_BRIDGE, 0, &ct).is_err());
    }

    #[test]
    fn wrong_namespace_fails_to_decrypt() {
        let s = salt();
        let ct = seal(&s, NAMESPACE_CLIENT_TO_BRIDGE, 0, b"secret").unwrap();
        assert!(open(&s, b"mirage-namespace-b2b-v1", 0, &ct).is_err());
    }

    #[test]
    fn wrong_epoch_fails_to_decrypt() {
        let s = salt();
        let ct = seal(&s, NAMESPACE_CLIENT_TO_BRIDGE, 100, b"secret").unwrap();
        assert!(open(&s, NAMESPACE_CLIENT_TO_BRIDGE, 101, &ct).is_err());
        assert!(open(&s, NAMESPACE_CLIENT_TO_BRIDGE, 99, &ct).is_err());
    }

    #[test]
    fn tampered_ct_fails_to_decrypt() {
        let s = salt();
        let mut ct = seal(&s, NAMESPACE_CLIENT_TO_BRIDGE, 0, b"secret").unwrap();
        ct[0] ^= 0x01;
        assert!(open(&s, NAMESPACE_CLIENT_TO_BRIDGE, 0, &ct).is_err());
    }

    #[test]
    fn skew_tolerance_accepts_adjacent_epochs() {
        let s = salt();
        let ct_prev = seal(&s, NAMESPACE_CLIENT_TO_BRIDGE, 99, b"prev").unwrap();
        let ct_curr = seal(&s, NAMESPACE_CLIENT_TO_BRIDGE, 100, b"curr").unwrap();
        let ct_next = seal(&s, NAMESPACE_CLIENT_TO_BRIDGE, 101, b"next").unwrap();

        let (pt_prev, e_prev) =
            open_with_skew_tolerance(&s, NAMESPACE_CLIENT_TO_BRIDGE, 100, &ct_prev).unwrap();
        assert_eq!(pt_prev, b"prev");
        assert_eq!(e_prev, 99);

        let (pt_curr, e_curr) =
            open_with_skew_tolerance(&s, NAMESPACE_CLIENT_TO_BRIDGE, 100, &ct_curr).unwrap();
        assert_eq!(pt_curr, b"curr");
        assert_eq!(e_curr, 100);

        let (pt_next, e_next) =
            open_with_skew_tolerance(&s, NAMESPACE_CLIENT_TO_BRIDGE, 100, &ct_next).unwrap();
        assert_eq!(pt_next, b"next");
        assert_eq!(e_next, 101);
    }

    #[test]
    fn skew_tolerance_rejects_out_of_window() {
        let s = salt();
        let ct_far = seal(&s, NAMESPACE_CLIENT_TO_BRIDGE, 102, b"far").unwrap();
        assert!(open_with_skew_tolerance(&s, NAMESPACE_CLIENT_TO_BRIDGE, 100, &ct_far).is_err());
    }
}
