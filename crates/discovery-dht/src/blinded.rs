//! Tor-v3-style key blinding for the DHT rendezvous read/write split
//! (audit CRIT #17/#18).
//!
//! # The problem
//!
//! The original scheme derived the BEP-44 signing key straight from the
//! invite's `shared_salt`:
//!
//! ```text
//! sk_epoch = KDF(shared_salt, info_hash)          // BOTH sign and verify
//! ```
//!
//! `shared_salt` is handed to every cohort member in the invite, so *any*
//! invite-holder could reconstruct the full signing key and **forge / poison
//! the operator's rendezvous record** - a write-authority collapse. (It was
//! done this way to keep the operator's long-term identity pubkey off the wire;
//! see the note below on why blinding keeps that property.)
//!
//! # The fix
//!
//! Split *read* authority from *write* authority with additive Ed25519 key
//! blinding, exactly as Tor v3 onion services blind their identity key per time
//! period:
//!
//! - The operator holds a long-term identity Ed25519 secret (the announcement
//!   signing key `mirage-publish` already loads). Its **public** half
//!   `A_id = pk_id` is already in the invite (`operator_ed25519_pk`).
//! - Both sides derive a public per-epoch blinding scalar
//!   `t = H(pk_id || info_hash)`. `info_hash` is itself keyed on the secret
//!   `shared_salt`, so it is only predictable to invite-holders - but `t`
//!   depends on nothing secret beyond what a cohort member already has.
//! - The blinded keypair is `A_blind = t * A_id`, `a_blind = t * a_id (mod L)`.
//!
//! A client holding only `pk_id` computes `A_blind` (to locate the BEP-44
//! target and verify signatures) but **cannot** compute `a_blind` - that needs
//! the identity secret scalar `a_id`, which never leaves the operator. So an
//! invite-holder can *read* the rendezvous yet can no longer *write* a forged
//! PUT under it.
//!
//! # Why the operator pubkey still does not leak
//!
//! The on-wire BEP-44 `k` field is `A_blind = t * A_id`, not `A_id`. Recovering
//! `A_id` from `A_blind` needs `t`, which needs `info_hash`, which needs
//! `shared_salt`. A passive DHT observer without the invite therefore cannot
//! link a blinded key back to the operator identity or across epochs - the same
//! unlinkability the salt-derived scheme provided, now *without* surrendering
//! write authority.
//!
//! # Interop
//!
//! Signatures are produced over the blinded key with the standard RFC-8032
//! challenge `k = SHA512(R || A_blind || M)`, so a stock Ed25519 verifier
//! (the mainline DHT nodes' and our own [`crate::bep44::SignedItem::verify`]
//! via `verify_strict`) accepts them unchanged. No DHT fork.

use mirage_crypto::curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use mirage_crypto::curve25519_dalek::scalar::Scalar;
use mirage_crypto::ed25519_dalek::SigningKey;
use mirage_crypto::sha2::{Digest, Sha512};
use mirage_crypto::zeroize::{Zeroize, Zeroizing};

/// Domain separator for the per-epoch blinding scalar `t`.
const BLIND_FACTOR_CONTEXT: &[u8] = b"mirage-dht-blind-factor-v1";
/// Domain separator for the per-epoch blinded deterministic-nonce prefix.
const BLIND_PREFIX_CONTEXT: &[u8] = b"mirage-dht-blind-prefix-v1";

/// Derive the per-epoch blinding scalar `t = H(ctx || pk_id || info_hash)`.
/// Operator and client compute this identically from public inputs.
fn blinding_factor(pk_id: &[u8; 32], info_hash: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(BLIND_FACTOR_CONTEXT);
    h.update(pk_id);
    h.update(info_hash);
    Scalar::from_bytes_mod_order_wide(&h.finalize().into())
}

/// The operator's long-term DHT identity (the write secret). Expands the
/// Ed25519 seed into the identity scalar `a_id` and deterministic-nonce prefix.
/// NOT derivable from any invite - only the operator, who holds the seed, can
/// build one.
pub struct DhtWriteIdentity {
    a_id: Scalar,
    prefix: Zeroizing<[u8; 32]>,
    pk_id: [u8; 32],
}

impl DhtWriteIdentity {
    /// Expand a 32-byte operator Ed25519 seed (the announcement signing key)
    /// into the blinding identity. Uses the standard RFC-8032 secret expansion
    /// so `public()` is byte-identical to
    /// `SigningKey::from_bytes(seed).verifying_key()` - i.e. the invite's
    /// `operator_ed25519_pk`.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let mut hh = Sha512::new();
        hh.update(seed);
        // The 64-byte SHA-512 digest holds the secret scalar AND the nonce
        // prefix; keep it only inside a `Zeroizing` so it is wiped on drop
        // rather than left resident (red-team hygiene finding).
        let mut digest = Zeroizing::new([0u8; 64]);
        digest.copy_from_slice(&hh.finalize());
        let mut a_bytes = [0u8; 32];
        a_bytes.copy_from_slice(&digest[0..32]);
        // Standard Ed25519 clamp of the low half.
        a_bytes[0] &= 248;
        a_bytes[31] &= 127;
        a_bytes[31] |= 64;
        let a_id = Scalar::from_bytes_mod_order(a_bytes);
        a_bytes.zeroize();
        let mut prefix = Zeroizing::new([0u8; 32]);
        prefix.copy_from_slice(&digest[32..64]);
        // Derive pk_id via the standard path so it equals the invite pubkey.
        let pk_id = SigningKey::from_bytes(seed).verifying_key().to_bytes();
        Self {
            a_id,
            prefix,
            pk_id,
        }
    }

    /// The public identity key clients derive the blinded key from
    /// (== the invite's `operator_ed25519_pk`).
    pub fn public(&self) -> [u8; 32] {
        self.pk_id
    }

    /// Build the per-epoch blinded signer for `info_hash`.
    pub fn blinded_signer(&self, info_hash: &[u8]) -> BlindedSigner {
        let t = blinding_factor(&self.pk_id, info_hash);
        let a_blind = t * self.a_id;
        let pk_blind = EdwardsPoint::mul_base(&a_blind).compress().to_bytes();
        // Domain-separated blinded nonce prefix: keeps the deterministic nonce
        // independent per epoch and unrelated to the identity prefix.
        let mut ph = Sha512::new();
        ph.update(BLIND_PREFIX_CONTEXT);
        ph.update(&self.prefix[..]);
        ph.update(info_hash);
        let pd = ph.finalize();
        let mut prefix_blind = Zeroizing::new([0u8; 32]);
        prefix_blind.copy_from_slice(&pd[0..32]);
        BlindedSigner {
            a_blind,
            prefix_blind,
            pk_blind,
        }
    }
}

impl Drop for DhtWriteIdentity {
    fn drop(&mut self) {
        self.a_id.zeroize();
    }
}

/// A per-epoch blinded signer. Signs over the RFC-8032 challenge so the output
/// verifies with a stock Ed25519 verifier.
pub struct BlindedSigner {
    a_blind: Scalar,
    prefix_blind: Zeroizing<[u8; 32]>,
    pk_blind: [u8; 32],
}

impl BlindedSigner {
    /// The blinded public key: the BEP-44 `k` field / publisher key for this
    /// epoch. Clients derive the same value via [`blinded_public`].
    pub fn public(&self) -> [u8; 32] {
        self.pk_blind
    }

    /// Sign `msg` with the blinded secret. Returns a standard 64-byte Ed25519
    /// signature `R || S` verifiable against `public()`.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        // Deterministic nonce r = SHA512(prefix_blind || msg) mod L. The prefix
        // is secret (expanded from the operator seed), so r is unpredictable.
        let mut rh = Sha512::new();
        rh.update(&self.prefix_blind[..]);
        rh.update(msg);
        let r = Scalar::from_bytes_mod_order_wide(&rh.finalize().into());
        let rr = EdwardsPoint::mul_base(&r).compress();
        // RFC-8032 challenge k = SHA512(R || A_blind || msg) mod L. MUST match
        // the stock verifier so mainline DHT nodes accept the PUT.
        let mut kh = Sha512::new();
        kh.update(rr.as_bytes());
        kh.update(self.pk_blind);
        kh.update(msg);
        let k = Scalar::from_bytes_mod_order_wide(&kh.finalize().into());
        let s = r + k * self.a_blind;
        let mut sig = [0u8; 64];
        sig[0..32].copy_from_slice(rr.as_bytes());
        sig[32..64].copy_from_slice(s.as_bytes());
        sig
    }
}

impl Drop for BlindedSigner {
    fn drop(&mut self) {
        self.a_blind.zeroize();
    }
}

/// CLIENT side: derive the per-epoch blinded public key from the operator's
/// public identity key (`operator_ed25519_pk`, from the invite) and the
/// per-epoch `info_hash`. Returns `None` iff `pk_id` is not a valid Ed25519
/// point. Yields only the public key - never the signing scalar.
pub fn blinded_public(pk_id: &[u8; 32], info_hash: &[u8]) -> Option<[u8; 32]> {
    let a_point = CompressedEdwardsY(*pk_id).decompress()?;
    let t = blinding_factor(pk_id, info_hash);
    Some((t * a_point).compress().to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bep44::{sign_item_blinded, SignedItem};
    use mirage_crypto::ed25519_dalek::{Signature, Verifier, VerifyingKey};

    fn seed(n: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[0] = n;
        s[7] = 0x5a;
        s
    }

    #[test]
    fn blinded_pub_matches_between_operator_and_client() {
        let id = DhtWriteIdentity::from_seed(&seed(1));
        // public() equals the stock verifying key (the invite pubkey).
        let vk = SigningKey::from_bytes(&seed(1)).verifying_key().to_bytes();
        assert_eq!(id.public(), vk);

        for epoch in [b"epoch-a".as_slice(), b"epoch-bbbb", b"\x00\x01\x02"] {
            let signer = id.blinded_signer(epoch);
            let client = blinded_public(&id.public(), epoch).unwrap();
            // Operator and client derive the SAME blinded pubkey / target.
            assert_eq!(signer.public(), client);
        }
    }

    #[test]
    fn blinded_signature_verifies_with_stock_ed25519() {
        let id = DhtWriteIdentity::from_seed(&seed(2));
        let info = b"info-hash-xyz";
        let signer = id.blinded_signer(info);
        let msg = b"3:seqi7e1:v5:hello";
        let sig = signer.sign(msg);

        // The blinded pubkey the CLIENT derives must verify the signature.
        let pk = blinded_public(&id.public(), info).unwrap();
        let vk = VerifyingKey::from_bytes(&pk).unwrap();
        assert!(vk.verify(msg, &Signature::from_bytes(&sig)).is_ok());
        // Strict verification (what SignedItem::verify uses) must also pass.
        assert!(vk.verify_strict(msg, &Signature::from_bytes(&sig)).is_ok());
    }

    #[test]
    fn tampered_message_or_sig_is_rejected() {
        let id = DhtWriteIdentity::from_seed(&seed(3));
        let info = b"ih";
        let signer = id.blinded_signer(info);
        let msg = b"authentic";
        let sig = signer.sign(msg);
        let pk = blinded_public(&id.public(), info).unwrap();
        let vk = VerifyingKey::from_bytes(&pk).unwrap();

        assert!(vk
            .verify(b"different", &Signature::from_bytes(&sig))
            .is_err());
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(vk.verify(msg, &Signature::from_bytes(&bad)).is_err());
        // A signature under the WRONG epoch's blinded key must not verify.
        let other = id.blinded_signer(b"other-epoch").sign(msg);
        assert!(vk.verify(msg, &Signature::from_bytes(&other)).is_err());
    }

    #[test]
    fn different_epochs_yield_unlinkable_keys() {
        let id = DhtWriteIdentity::from_seed(&seed(4));
        let a = id.blinded_signer(b"epoch-1").public();
        let b = id.blinded_signer(b"epoch-2").public();
        assert_ne!(a, b, "per-epoch blinded keys must differ");
        assert_ne!(a, id.public(), "blinded key must not equal identity key");
    }

    #[test]
    fn signed_item_roundtrips_via_blinded_signer() {
        // End-to-end: a blinded-signed BEP-44 item verifies and is keyed under
        // the client-derivable blinded pubkey.
        let id = DhtWriteIdentity::from_seed(&seed(5));
        let info = b"per-epoch-info-hash-\x99";
        let signer = id.blinded_signer(info);
        let item = sign_item_blinded(&signer, Some(info), 42, b"sealed-descriptor").unwrap();
        assert!(item.verify().is_ok());
        assert_eq!(item.k, blinded_public(&id.public(), info).unwrap());
        // A different identity cannot have produced it.
        let other = DhtWriteIdentity::from_seed(&seed(6));
        assert_ne!(item.k, other.blinded_signer(info).public());
        let _ = SignedItem::info_hash(&item);
    }

    #[test]
    fn client_cannot_derive_a_forgeable_signer() {
        // The client only has pk_id; there is no API path from a public key to a
        // BlindedSigner. This test documents that the ONLY constructor of a
        // signer, `DhtWriteIdentity::from_seed`, requires the secret seed.
        let id = DhtWriteIdentity::from_seed(&seed(7));
        let info = b"ih";
        let pk = blinded_public(&id.public(), info).unwrap();
        // A forger who guesses a seed produces a DIFFERENT blinded key, so their
        // signature is keyed under a target no client will look up.
        let forger = DhtWriteIdentity::from_seed(&seed(8));
        assert_ne!(forger.blinded_signer(info).public(), pk);
    }
}
