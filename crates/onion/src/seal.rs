//! Descriptor sealing - the mandatory prerequisite before any live descriptor
//! publication (see the crate root docs).
//!
//! An encoded [`crate::descriptor::OnionDescriptor`] begins with the fixed ASCII
//! magic `"MI"` and a fixed-layout header. Published verbatim to a public
//! channel (a CT log dead-drop, a DHT, a pastebin front, ...), that magic +
//! structure is a passive-scraper fingerprint: anyone sweeping the channel can
//! flag "this blob is a Mirage onion descriptor" and enumerate services without
//! ever resolving one.
//!
//! Sealing wraps the encoded descriptor so it is indistinguishable from random
//! to anyone who does not already know the service's `.mirage` address:
//!
//! ```text
//! sealed = [nonce(12)] [ChaCha20-Poly1305_{seal_key}(descriptor_bytes) + tag(16)]
//! seal_key = BLAKE3-keyed(service_pk, "mirage-onion-seal-v1" || epoch_be)
//! ```
//!
//! # Why a service-public-key-derived key is the right choice (no client-auth)
//!
//! The descriptor's publication LOCATION is its per-epoch info-hash,
//! `BLAKE3-keyed(service_pk, ...)`, which is a one-way function of `service_pk`.
//! A scraper who finds the sealed blob at that location holds only the info-hash
//! and CANNOT invert it to recover `service_pk`, so it cannot derive `seal_key`
//! and the blob stays opaque and unfingerprintable. A legitimate client, by
//! contrast, learns `service_pk` directly from the `.mirage` address it is
//! resolving (`crate::address::onion_address_to_pk`), so it derives BOTH the
//! info-hash (to find the blob) AND the `seal_key` (to open it). This mirrors a
//! Tor v3 onion service WITHOUT client authorization: the address itself is the
//! decryption capability. Per-CLIENT authorization (only specific clients may
//! resolve) is a separate, additive layer and is deliberately out of scope here.
//!
//! This provides UNLINKABILITY / INDISTINGUISHABILITY against a passive channel
//! observer, not confidentiality against someone who already knows the address -
//! which is exactly the property a public descriptor needs.

use mirage_crypto::blake3;
use mirage_crypto::chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};

/// Domain-separation label for the seal-key derivation.
const SEAL_KEY_LABEL: &[u8] = b"mirage-onion-seal-v1";
/// AAD domain label (binds the ciphertext to the seal purpose).
const SEAL_AAD: &[u8] = b"mirage-onion-seal-aad-v1";
/// ChaCha20-Poly1305 nonce length.
const NONCE_LEN: usize = 12;
/// Poly1305 tag length.
const TAG_LEN: usize = 16;

/// Errors from [`unseal_descriptor`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SealError {
    /// Sealed blob shorter than `nonce + tag` - cannot possibly be valid.
    #[error("sealed descriptor too short ({0} < {min})", min = NONCE_LEN + TAG_LEN)]
    TooShort(usize),
    /// AEAD authentication failed: wrong `service_pk`/`epoch`, or a corrupt /
    /// non-Mirage blob.
    #[error("seal authentication failed (wrong service key/epoch or not a sealed descriptor)")]
    AuthFailed,
    /// The OS CSPRNG failed while generating the nonce (seal path only).
    #[error("csprng failure generating seal nonce")]
    Rng,
}

/// Derive the per-service, per-epoch symmetric seal key. Keyed on `service_pk`
/// so only a holder of the `.mirage` address can compute it.
fn seal_key(service_pk: &[u8; 32], epoch: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(service_pk);
    h.update(SEAL_KEY_LABEL);
    h.update(&epoch.to_be_bytes());
    *h.finalize().as_bytes()
}

/// Seal an encoded descriptor for publication. Output layout:
/// `[nonce(12)][ciphertext + tag(16)]`, indistinguishable from random without
/// `service_pk` + `epoch`.
///
/// # Errors
/// [`SealError::Rng`] if the OS CSPRNG fails.
pub fn seal_descriptor(
    plaintext: &[u8],
    service_pk: &[u8; 32],
    epoch: u64,
) -> Result<Vec<u8>, SealError> {
    let key = seal_key(service_pk, epoch);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| SealError::Rng)?;
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: SEAL_AAD,
            },
        )
        .map_err(|_| SealError::AuthFailed)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a sealed descriptor. The caller supplies `service_pk` (from the
/// `.mirage` address it is resolving) and `epoch` (the info-hash epoch the blob
/// was fetched at).
///
/// # Errors
/// [`SealError::TooShort`] or [`SealError::AuthFailed`] on a malformed / wrong /
/// non-Mirage blob. AuthFailed is the expected result for any blob NOT sealed
/// for this exact `(service_pk, epoch)`, which is what makes the scheme
/// unfingerprintable.
pub fn unseal_descriptor(
    sealed: &[u8],
    service_pk: &[u8; 32],
    epoch: u64,
) -> Result<Vec<u8>, SealError> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(SealError::TooShort(sealed.len()));
    }
    let key = seal_key(service_pk, epoch);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let (nonce, ct) = sealed.split_at(NONCE_LEN);
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: SEAL_AAD,
            },
        )
        .map_err(|_| SealError::AuthFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(tag: u8) -> [u8; 32] {
        [tag; 32]
    }

    #[test]
    fn seal_then_unseal_roundtrips() {
        let msg = b"MI\x60 an encoded descriptor with the MI magic and structure";
        let sealed = seal_descriptor(msg, &pk(1), 7).unwrap();
        let opened = unseal_descriptor(&sealed, &pk(1), 7).unwrap();
        assert_eq!(opened, msg);
    }

    #[test]
    fn sealed_output_hides_the_mi_magic() {
        // The plaintext starts with the "MI" fingerprint; the sealed blob must
        // NOT - that is the whole point.
        let msg = b"MImirage-descriptor-payload";
        let sealed = seal_descriptor(msg, &pk(2), 1).unwrap();
        assert_ne!(
            &sealed[..2],
            b"MI",
            "sealed blob must not leak the MI magic"
        );
        assert!(
            !sealed.windows(2).any(|w| w == b"MI"),
            "no MI substring should survive sealing"
        );
    }

    #[test]
    fn wrong_service_pk_fails_to_unseal() {
        let msg = b"payload";
        let sealed = seal_descriptor(msg, &pk(3), 5).unwrap();
        assert_eq!(
            unseal_descriptor(&sealed, &pk(4), 5),
            Err(SealError::AuthFailed)
        );
    }

    #[test]
    fn wrong_epoch_fails_to_unseal() {
        let msg = b"payload";
        let sealed = seal_descriptor(msg, &pk(5), 10).unwrap();
        assert_eq!(
            unseal_descriptor(&sealed, &pk(5), 11),
            Err(SealError::AuthFailed)
        );
    }

    #[test]
    fn nonce_randomization_makes_seals_unlinkable() {
        // Two seals of the SAME plaintext under the SAME key must differ (fresh
        // nonce), so an observer can't link re-publications of one descriptor.
        let msg = b"same descriptor bytes";
        let a = seal_descriptor(msg, &pk(6), 2).unwrap();
        let b = seal_descriptor(msg, &pk(6), 2).unwrap();
        assert_ne!(a, b, "distinct nonces must yield distinct sealed blobs");
        // Both still open to the same plaintext.
        assert_eq!(unseal_descriptor(&a, &pk(6), 2).unwrap(), msg);
        assert_eq!(unseal_descriptor(&b, &pk(6), 2).unwrap(), msg);
    }

    #[test]
    fn too_short_blob_rejected() {
        assert_eq!(
            unseal_descriptor(&[0u8; 10], &pk(7), 1),
            Err(SealError::TooShort(10))
        );
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let mut sealed = seal_descriptor(b"payload", &pk(8), 3).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert_eq!(
            unseal_descriptor(&sealed, &pk(8), 3),
            Err(SealError::AuthFailed)
        );
    }
}
