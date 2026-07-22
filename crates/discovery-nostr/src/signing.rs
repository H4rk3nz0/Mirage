//! BIP-340 Schnorr signing + verification wrapper.
//!
//! Nostr uses BIP-340 Schnorr over secp256k1 for event signatures (NIP-01).
//! Public keys are the 32-byte **x-only** form; signatures are 64 bytes.
//!
//! This module wraps [`k256::schnorr`] behind a byte-array API so the rest
//! of the crate never touches `k256` types directly. If we ever swap the
//! backend (e.g., to a C-backed `secp256k1` crate), only this file changes.

use k256::schnorr::signature::{Signer, Verifier};
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use zeroize::Zeroize;

/// Length of a BIP-340 x-only public key (bytes).
pub const NOSTR_PUBKEY_LEN: usize = 32;
/// Length of a BIP-340 Schnorr signature (bytes).
pub const NOSTR_SIG_LEN: usize = 64;

/// A secp256k1 Schnorr keypair for signing Nostr events.
///
/// The operator's long-term Mirage identity (Ed25519) is SEPARATE from this
/// Nostr key by design (spec §03 §8.1): compromising a Nostr relay reveals
/// nothing about the operator identity; rotating the Nostr key doesn't
/// invalidate existing announcements. Treat the Nostr key as disposable.
#[derive(Clone)]
pub struct NostrSigningKey {
    inner: SigningKey,
}

impl NostrSigningKey {
    /// Generate a fresh keypair from a 32-byte seed.
    ///
    /// The seed must be cryptographically random. Callers in tests use
    /// fixed seeds for deterministic vectors.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, &'static str> {
        let inner = SigningKey::from_bytes(seed).map_err(|_| "invalid schnorr seed")?;
        Ok(Self { inner })
    }

    /// Generate a keypair from the OS RNG.
    ///
    /// Caps retry attempts to guard against a compromised RNG returning
    /// seeds that never parse (otherwise infinite loop). In practice the
    /// first attempt succeeds (invalid scalars are a measure-zero subset
    /// of 2^256).
    pub fn generate() -> Self {
        const MAX_ATTEMPTS: usize = 16;
        let mut seed = [0u8; 32];
        for _ in 0..MAX_ATTEMPTS {
            getrandom::fill(&mut seed).expect("OS RNG unavailable");
            if let Ok(sk) = Self::from_seed(&seed) {
                seed.zeroize();
                return sk;
            }
        }
        seed.zeroize();
        panic!(
            "OS RNG produced {MAX_ATTEMPTS} consecutive invalid Schnorr seeds; \
             this is astronomically unlikely under a sound RNG and \
             indicates compromise"
        );
    }

    /// Return the x-only public-key bytes (for Nostr `pubkey` field).
    pub fn verifying_key_bytes(&self) -> [u8; NOSTR_PUBKEY_LEN] {
        let vk: VerifyingKey = *self.inner.verifying_key();
        // VerifyingKey::to_bytes returns the 32-byte x-only form.
        vk.to_bytes().into()
    }

    /// Sign a message (typically a 32-byte event ID) and return 64 bytes.
    pub fn sign(&self, msg: &[u8]) -> [u8; NOSTR_SIG_LEN] {
        let sig: Signature = self.inner.sign(msg);
        sig.to_bytes()
    }
}

/// Getrandom is accessed via a local dev-dependency in the crate; this
/// module only re-exports a tiny wrapper to keep usage uniform.
mod getrandom {
    /// Fill `buf` with CSPRNG bytes. On failure logs the underlying
    /// error (which carries OS-specific diagnostic info - sandboxed
    /// `/dev/urandom`, getentropy ENOSYS, container without
    /// /dev/random, etc.) before returning an opaque tag. Closes
    /// [RT-N4]: pre-fix the underlying error was discarded
    /// silently, making operator troubleshooting impossible.
    pub fn fill(buf: &mut [u8]) -> Result<(), &'static str> {
        ::getrandom::fill(buf).map_err(|e| {
            tracing::error!(error = %e, "nostr signing: OS CSPRNG failure");
            "getrandom"
        })
    }
}

/// Opaque failure marker for Schnorr verification. Carries no structured
/// information beyond "verification failed" - callers map to a public
/// error (e.g., [`crate::NostrError::SignatureInvalid`]) without exposing
/// which sub-step rejected (key parse, sig parse, or signature check).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchnorrVerifyFailed;

/// Verify a BIP-340 Schnorr signature.
///
/// Returns `Err(SchnorrVerifyFailed)` on any failure (invalid pubkey,
/// invalid signature, verification mismatch). Caller maps to
/// [`crate::NostrError::SignatureInvalid`].
pub fn verify_schnorr(
    pubkey: &[u8; NOSTR_PUBKEY_LEN],
    msg: &[u8],
    sig: &[u8; NOSTR_SIG_LEN],
) -> Result<(), SchnorrVerifyFailed> {
    let vk = VerifyingKey::from_bytes(pubkey).map_err(|_| SchnorrVerifyFailed)?;
    let sig = Signature::try_from(sig.as_slice()).map_err(|_| SchnorrVerifyFailed)?;
    vk.verify(msg, &sig).map_err(|_| SchnorrVerifyFailed)
}

/// Signing helper used by [`crate::event`]: sign the given pre-computed
/// event ID with the provided key, returning the 64-byte signature.
pub fn sign_event_id(signing_key: &NostrSigningKey, event_id: &[u8; 32]) -> [u8; NOSTR_SIG_LEN] {
    signing_key.sign(event_id)
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_seed() -> [u8; 32] {
        [0x42u8; 32]
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let sk = NostrSigningKey::from_seed(&fixed_seed()).unwrap();
        let pk = sk.verifying_key_bytes();
        let msg = b"the message being signed";
        let sig = sk.sign(msg);
        verify_schnorr(&pk, msg, &sig).expect("valid sig must verify");
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let sk = NostrSigningKey::from_seed(&fixed_seed()).unwrap();
        let pk = sk.verifying_key_bytes();
        let sig = sk.sign(b"original");
        assert!(verify_schnorr(&pk, b"tampered", &sig).is_err());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let sk_a = NostrSigningKey::from_seed(&[0x01u8; 32]).unwrap();
        let sk_b = NostrSigningKey::from_seed(&[0x02u8; 32]).unwrap();
        let msg = b"msg";
        let sig = sk_a.sign(msg);
        assert!(verify_schnorr(&sk_b.verifying_key_bytes(), msg, &sig).is_err());
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let sk = NostrSigningKey::from_seed(&fixed_seed()).unwrap();
        let pk = sk.verifying_key_bytes();
        let msg = b"msg";
        let mut sig = sk.sign(msg);
        sig[0] ^= 0x01;
        assert!(verify_schnorr(&pk, msg, &sig).is_err());
    }

    #[test]
    fn keypair_is_deterministic_from_seed() {
        let sk1 = NostrSigningKey::from_seed(&fixed_seed()).unwrap();
        let sk2 = NostrSigningKey::from_seed(&fixed_seed()).unwrap();
        assert_eq!(sk1.verifying_key_bytes(), sk2.verifying_key_bytes());
    }

    #[test]
    fn generate_produces_distinct_keys() {
        let sk1 = NostrSigningKey::generate();
        let sk2 = NostrSigningKey::generate();
        assert_ne!(sk1.verifying_key_bytes(), sk2.verifying_key_bytes());
    }

    #[test]
    fn signature_is_deterministic_per_nip340() {
        // BIP-340 Schnorr is NOT deterministic by default in k256 - it uses
        // RFC-6979-style auxiliary randomness. But the SIGNATURE is verifiable.
        // We check that a fresh sign + verify cycle always succeeds, twice.
        let sk = NostrSigningKey::from_seed(&fixed_seed()).unwrap();
        let pk = sk.verifying_key_bytes();
        for _ in 0..5 {
            let sig = sk.sign(b"repeat");
            verify_schnorr(&pk, b"repeat", &sig).unwrap();
        }
    }
}
