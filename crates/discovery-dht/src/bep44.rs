//! BEP-44 mutable-item encode, sign, and verify.
//!
//! Reference: <https://www.bittorrent.org/beps/bep_0044.html>
//!
//! A BEP-44 mutable item is a signed record stored on the `BitTorrent`
//! mainline DHT at a key derived from the publisher's public key.
//! Mirage uses one item per (namespace, epoch) pair - the operator's
//! Ed25519 pubkey as `k`, Mirage's per-epoch info-hash as `salt`,
//! and the sealed announcement ciphertext as `v`.
//!
//! # Wire summary
//!
//! - **Target info-hash (20 B, SHA-1):** `SHA-1(pubkey || salt)` when
//!   salt is present; `SHA-1(pubkey)` otherwise. This is the DHT
//!   address the item is stored at. Mainline DHT is Kademlia over a
//!   160-bit ID space, so SHA-1 is load-bearing - we cannot
//!   substitute SHA-256 without forking the DHT.
//! - **`v`:** opaque value, up to 1000 bytes (per BEP-44 §Limits).
//! - **`seq`:** monotonically non-decreasing integer. A DHT node
//!   rejects a put whose `seq` is strictly less than the stored
//!   value's `seq`. Mirage uses the announcement's epoch number.
//! - **Signing input:** a bencode fragment of the form
//!   `3:salt<len>:<salt>3:seqi<seq>e1:v<len>:<v>` (the `3:salt...`
//!   prefix is omitted when no salt).
//! - **Signature:** Ed25519 over the signing input, verified against
//!   `k`.
//!
//! This module is I/O-free: it operates on bytes only. The DHT
//! network layer consumes [`SignedItem`] via the [`DhtClient`]
//! trait in [`crate::lib`].
//!
//! [`DhtClient`]: crate::DhtClient

use mirage_crypto::ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha1::{Digest, Sha1};

/// Hard cap on the `v` (value) field: BEP-44 caps at 1000 bytes.
pub const BEP44_MAX_VALUE_BYTES: usize = 1000;
/// Hard cap on the optional `salt` field: BEP-44 caps at 64 bytes.
pub const BEP44_MAX_SALT_BYTES: usize = 64;
/// Length of a DHT info-hash (SHA-1, 20 bytes).
pub const DHT_INFO_HASH_LEN: usize = 20;
/// Length of an Ed25519 public key (32 bytes).
pub const ED25519_PK_LEN: usize = 32;
/// Length of an Ed25519 signature (64 bytes).
pub const ED25519_SIG_LEN: usize = 64;

/// Errors that can arise while packing or verifying a BEP-44 item.
#[derive(Debug, thiserror::Error)]
pub enum Bep44Error {
    /// `v` exceeded [`BEP44_MAX_VALUE_BYTES`].
    #[error("value exceeds 1000-byte BEP-44 limit ({0} bytes)")]
    ValueTooLarge(usize),
    /// `salt` exceeded [`BEP44_MAX_SALT_BYTES`].
    #[error("salt exceeds 64-byte BEP-44 limit ({0} bytes)")]
    SaltTooLarge(usize),
    /// Ed25519 pubkey failed to decode.
    #[error("invalid Ed25519 public key")]
    BadPublicKey,
    /// Signature verification failed.
    #[error("signature verification failed")]
    BadSignature,
}

/// An item stored under a DHT info-hash: the value, sequence number,
/// pubkey, optional salt, and signature. This is the canonical form
/// a `DhtClient` publishes and retrieves.
#[derive(Debug, Clone)]
pub struct SignedItem {
    /// Publisher's Ed25519 public key (`k` field).
    pub k: [u8; ED25519_PK_LEN],
    /// Optional salt (Mirage uses the per-epoch info-hash). Up to 64 B.
    pub salt: Option<Vec<u8>>,
    /// Monotonically non-decreasing sequence number.
    pub seq: i64,
    /// Opaque value, up to 1000 B. Mirage stores a sealed
    /// announcement ciphertext here.
    pub v: Vec<u8>,
    /// Ed25519 signature over the signing input, by `k`.
    pub sig: [u8; ED25519_SIG_LEN],
}

impl SignedItem {
    /// Compute the DHT info-hash (the 20-byte key this item is
    /// stored at): `SHA-1(k || salt)` if salt present, else
    /// `SHA-1(k)`.
    pub fn info_hash(&self) -> [u8; DHT_INFO_HASH_LEN] {
        info_hash_for(&self.k, self.salt.as_deref())
    }

    /// Verify the Ed25519 signature on this item's canonical
    /// signing input.
    pub fn verify(&self) -> Result<(), Bep44Error> {
        if self.v.len() > BEP44_MAX_VALUE_BYTES {
            return Err(Bep44Error::ValueTooLarge(self.v.len()));
        }
        if let Some(s) = &self.salt {
            if s.len() > BEP44_MAX_SALT_BYTES {
                return Err(Bep44Error::SaltTooLarge(s.len()));
            }
        }
        let vk = VerifyingKey::from_bytes(&self.k).map_err(|_| Bep44Error::BadPublicKey)?;
        let input = signing_input(self.salt.as_deref(), self.seq, &self.v);
        vk.verify_strict(&input, &Signature::from_bytes(&self.sig))
            .map_err(|_| Bep44Error::BadSignature)
    }
}

/// Build + sign a mutable BEP-44 item. The resulting [`SignedItem`]
/// is ready for a DHT `put`.
pub fn sign_item(
    signing_key: &SigningKey,
    salt: Option<&[u8]>,
    seq: i64,
    v: &[u8],
) -> Result<SignedItem, Bep44Error> {
    if v.len() > BEP44_MAX_VALUE_BYTES {
        return Err(Bep44Error::ValueTooLarge(v.len()));
    }
    if let Some(s) = salt {
        if s.len() > BEP44_MAX_SALT_BYTES {
            return Err(Bep44Error::SaltTooLarge(s.len()));
        }
    }
    let input = signing_input(salt, seq, v);
    let sig = signing_key.sign(&input);
    Ok(SignedItem {
        k: signing_key.verifying_key().to_bytes(),
        salt: salt.map(<[u8]>::to_vec),
        seq,
        v: v.to_vec(),
        sig: sig.to_bytes(),
    })
}

/// Build + sign a mutable BEP-44 item under a per-epoch **blinded** key
/// (audit CRIT #17/#18). Unlike [`sign_item`], the signer is derived from the
/// operator's identity secret via [`crate::blinded::DhtWriteIdentity`], so an
/// invite-holder (who has only the identity *public* key) cannot reproduce it.
/// The resulting signature is a standard Ed25519 signature keyed under the
/// blinded pubkey and verifies exactly like any other [`SignedItem`].
pub fn sign_item_blinded(
    signer: &crate::blinded::BlindedSigner,
    salt: Option<&[u8]>,
    seq: i64,
    v: &[u8],
) -> Result<SignedItem, Bep44Error> {
    if v.len() > BEP44_MAX_VALUE_BYTES {
        return Err(Bep44Error::ValueTooLarge(v.len()));
    }
    if let Some(s) = salt {
        if s.len() > BEP44_MAX_SALT_BYTES {
            return Err(Bep44Error::SaltTooLarge(s.len()));
        }
    }
    let input = signing_input(salt, seq, v);
    let sig = signer.sign(&input);
    Ok(SignedItem {
        k: signer.public(),
        salt: salt.map(<[u8]>::to_vec),
        seq,
        v: v.to_vec(),
        sig,
    })
}

/// Compute the BEP-44 info-hash for a `(k, salt)` pair without
/// needing a full [`SignedItem`].
pub fn info_hash_for(k: &[u8; ED25519_PK_LEN], salt: Option<&[u8]>) -> [u8; DHT_INFO_HASH_LEN] {
    let mut h = Sha1::new();
    h.update(k);
    if let Some(s) = salt {
        h.update(s);
    }
    let d = h.finalize();
    let mut out = [0u8; DHT_INFO_HASH_LEN];
    out.copy_from_slice(&d);
    out
}

/// Build the BEP-44 signing input bytes per the spec:
///
/// ```text
///   [3:saltLEN:SALT]3:seqiSEQe1:vLEN:VALUE
/// ```
///
/// The `3:saltLEN:SALT` prefix is omitted when `salt` is `None`.
pub fn signing_input(salt: Option<&[u8]>, seq: i64, v: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + v.len());
    if let Some(s) = salt {
        // BEP-44 §Signature: `4:salt<len>:<bytes>` where `4:salt` is
        // the bencoded key "salt" (4 chars -> length prefix 4), followed
        // by the bytestring length prefix and value. No nested bencode.
        out.extend_from_slice(b"4:salt");
        out.extend_from_slice(s.len().to_string().as_bytes());
        out.push(b':');
        out.extend_from_slice(s);
    }
    out.extend_from_slice(b"3:seqi");
    out.extend_from_slice(seq.to_string().as_bytes());
    out.extend_from_slice(b"e1:v");
    out.extend_from_slice(v.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(v);
    out
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    fn op_key() -> SigningKey {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        SigningKey::from_bytes(&seed)
    }

    #[test]
    fn signing_input_matches_bep44_with_salt() {
        // BEP-44 §Signature: key "salt" (4 chars) -> prefix "4:salt".
        // salt = "foo" (3 bytes), seq = 1, v = "12:Hello World!" (15 bytes).
        // Expected: 4:salt3:foo3:seqi1e1:v15:12:Hello World!
        let salt = b"foo";
        let seq = 1i64;
        let v = b"12:Hello World!";
        let got = signing_input(Some(salt), seq, v);
        let expected = b"4:salt3:foo3:seqi1e1:v15:12:Hello World!";
        assert_eq!(got.as_slice(), expected);
    }

    #[test]
    fn signing_input_matches_bep44_without_salt() {
        let seq = 3i64;
        let v = b"hi";
        let got = signing_input(None, seq, v);
        assert_eq!(got.as_slice(), b"3:seqi3e1:v2:hi");
    }

    #[test]
    fn signing_input_negative_seq_is_allowed_formally() {
        // BEP-44 uses bencoded integers, which serialize negatives as
        // `i-5e`. Mirage will never issue a negative seq, but a
        // verifier MUST accept one if signed, so the helper handles it.
        let out = signing_input(None, -5, b"x");
        assert_eq!(out.as_slice(), b"3:seqi-5e1:v1:x");
    }

    #[test]
    fn info_hash_changes_with_salt() {
        let pk = [0xAAu8; 32];
        let ih1 = info_hash_for(&pk, None);
        let ih2 = info_hash_for(&pk, Some(b"salt"));
        let ih3 = info_hash_for(&pk, Some(b"other"));
        assert_ne!(ih1, ih2);
        assert_ne!(ih2, ih3);
    }

    #[test]
    fn info_hash_no_salt_is_sha1_of_pk() {
        let pk = [0u8; 32];
        let ih = info_hash_for(&pk, None);
        // SHA-1 of 32 zero bytes - value pinned so a future change
        // to the hash input (e.g., accidentally including salt
        // when None) produces a loud test failure.
        assert_eq!(hex::encode(ih), "de8a847bff8c343d69b853a215e6ee775ef2ef96");
    }

    #[test]
    fn sign_verify_roundtrip() {
        let sk = op_key();
        let item =
            sign_item(&sk, Some(b"epoch-1"), 42, b"sealed-announcement-ciphertext").expect("sign");
        item.verify().expect("verify");
    }

    #[test]
    fn verify_rejects_mutated_value() {
        let sk = op_key();
        let mut item = sign_item(&sk, Some(b"s"), 1, b"original").unwrap();
        item.v[0] ^= 1;
        assert!(matches!(item.verify(), Err(Bep44Error::BadSignature)));
    }

    #[test]
    fn verify_rejects_mutated_salt() {
        let sk = op_key();
        let mut item = sign_item(&sk, Some(b"sa"), 1, b"val").unwrap();
        // Flip a byte in the salt -> info_hash AND signing input change.
        item.salt.as_mut().unwrap()[0] ^= 1;
        assert!(matches!(item.verify(), Err(Bep44Error::BadSignature)));
    }

    #[test]
    fn verify_rejects_mutated_seq() {
        let sk = op_key();
        let mut item = sign_item(&sk, None, 7, b"v").unwrap();
        item.seq = 8;
        assert!(matches!(item.verify(), Err(Bep44Error::BadSignature)));
    }

    #[test]
    fn verify_rejects_mutated_pubkey() {
        let sk = op_key();
        let other = op_key();
        let mut item = sign_item(&sk, None, 0, b"v").unwrap();
        item.k = other.verifying_key().to_bytes();
        assert!(matches!(item.verify(), Err(Bep44Error::BadSignature)));
    }

    #[test]
    fn sign_rejects_oversize_value() {
        let sk = op_key();
        let big = vec![0u8; BEP44_MAX_VALUE_BYTES + 1];
        assert!(matches!(
            sign_item(&sk, None, 0, &big),
            Err(Bep44Error::ValueTooLarge(_))
        ));
    }

    #[test]
    fn sign_rejects_oversize_salt() {
        let sk = op_key();
        let big = vec![0u8; BEP44_MAX_SALT_BYTES + 1];
        assert!(matches!(
            sign_item(&sk, Some(&big), 0, b"v"),
            Err(Bep44Error::SaltTooLarge(_))
        ));
    }

    #[test]
    fn item_at_max_value_and_salt_verifies() {
        let sk = op_key();
        let salt = [0xAAu8; BEP44_MAX_SALT_BYTES];
        let v = vec![0xBBu8; BEP44_MAX_VALUE_BYTES];
        let item = sign_item(&sk, Some(&salt), 10_000, &v).expect("sign");
        item.verify().expect("verify");
    }

    #[test]
    fn info_hash_length_is_twenty_bytes() {
        let pk = [0u8; 32];
        let ih = info_hash_for(&pk, Some(b"x"));
        assert_eq!(ih.len(), DHT_INFO_HASH_LEN);
    }

    #[test]
    fn fuzz_verify_never_panics_on_arbitrary_bytes() {
        use proptest::prelude::*;
        proptest!(
            ProptestConfig::with_cases(128),
            |(
                k_vec in prop::collection::vec(any::<u8>(), 32..=32),
                salt in prop::option::of(prop::collection::vec(any::<u8>(), 0..100)),
                seq in any::<i64>(),
                v in prop::collection::vec(any::<u8>(), 0..1200),
                sig_vec in prop::collection::vec(any::<u8>(), 64..=64),
            )| {
                let mut k = [0u8; 32];
                k.copy_from_slice(&k_vec);
                let mut sig = [0u8; 64];
                sig.copy_from_slice(&sig_vec);
                let item = SignedItem { k, salt, seq, v, sig };
                let _ = item.verify();
            }
        );
    }
}
