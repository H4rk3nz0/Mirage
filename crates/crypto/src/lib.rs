//! Cryptographic primitives used across Mirage.
//!
//! This crate wraps audited upstream primitives. **It does not implement any
//! cryptography from scratch.** If you are adding a primitive, either find an
//! audited crate or don't add it. This is a non-negotiable.
//!
//! # Re-exports
//!
//! - [`snow`] - Noise Protocol Framework (handshake state machine, §L3 S1)
//! - [`ml_kem`] - ML-KEM-768 (post-quantum KEM, hybrid-mode peer of X25519)
//! - [`ed25519_dalek`] - Ed25519 signatures (discovery announcements, §L1 D2)
//! - [`x25519_dalek`] - X25519 Diffie-Hellman (classical KEM half)
//! - [`blake3`] - hashing (discovery info-hashes, transcript hashing)
//! - [`chacha20poly1305`] - AEAD for session frames
//! - [`hkdf`] / [`sha2`] - key derivation
//! - [`zeroize`] - memory hygiene
//! - [`subtle`] - constant-time comparison
//!
//! # Hybrid KEM rationale
//!
//! Spec §3 assumption 2: PQ lead time. Every key agreement combines X25519 and
//! ML-KEM-768 so that an adversary must break both to compromise a session.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use aes_gcm;
pub use blake3;
pub use chacha20poly1305;
pub use curve25519_dalek;
pub use ed25519_dalek;
pub use hkdf;
pub use ml_kem;
pub use rand_core;
pub use sha2;
pub use snow;
pub use subtle;
pub use x25519_dalek;
pub use zeroize;

pub mod dvs;
pub mod hybrid_kem;

/// Hybrid KEM: classical X25519 plus post-quantum ML-KEM-768.
///
/// The combined shared secret is `BLAKE3(x25519_ss || mlkem_ss)`. Breaking
/// either primitive alone is insufficient to compromise a session.
///
/// Concrete implementation lives in `mirage-session` handshake machinery; this
/// trait documents the contract. Implementations MUST zeroize decapsulation
/// keys and shared secrets on drop.
pub trait HybridKem {
    /// Encapsulation key (public, sent to peer).
    type EncapsulationKey;
    /// Decapsulation key (private, retained by self).
    type DecapsulationKey;
    /// Ciphertext (encapsulation output).
    type Ciphertext;
    /// Shared secret (32 bytes; caller-owned lifetime, zeroized on drop).
    type SharedSecret;

    /// Generate a new `(ek, dk)` keypair.
    fn keygen(
        rng: &mut impl rand_core::CryptoRng,
    ) -> (Self::EncapsulationKey, Self::DecapsulationKey);

    /// Encapsulate against `ek`, producing `(ct, ss)`.
    fn encapsulate(
        ek: &Self::EncapsulationKey,
        rng: &mut impl rand_core::CryptoRng,
    ) -> (Self::Ciphertext, Self::SharedSecret);

    /// Decapsulate `ct` with `dk`, recovering `ss`.
    fn decapsulate(dk: &Self::DecapsulationKey, ct: &Self::Ciphertext) -> Self::SharedSecret;
}

#[cfg(test)]
mod tests {
    //! Smoke tests: verify each upstream primitive is reachable.

    #[test]
    fn blake3_reachable() {
        let h = super::blake3::hash(b"mirage");
        assert_eq!(h.as_bytes().len(), 32);
    }

    #[test]
    fn x25519_reachable() {
        // Use getrandom directly - our workspace rand_core is feature-lean.
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("getrandom");
        let s = super::x25519_dalek::StaticSecret::from(seed);
        let _p = super::x25519_dalek::PublicKey::from(&s);
    }

    #[test]
    fn ed25519_reachable() {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("getrandom");
        let _sk = super::ed25519_dalek::SigningKey::from_bytes(&seed);
    }
}
