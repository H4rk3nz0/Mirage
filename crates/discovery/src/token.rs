//! Capability tokens used at session-handshake time.
//!
//! A token is a 136-byte operator-signed capability scoped to a specific
//! bridge identity. At handshake time the client places this inside the
//! Noise message 3 payload; the bridge decrypts via its Noise state machine
//! and verifies (bridge-pinning, signature, expiry, replay).

use crate::error::DiscoveryError;
use crate::wire::{ED25519_PK_LEN, SIG_LEN};

/// Wire length of a capability token.
pub const TOKEN_LEN: usize = 32 + ED25519_PK_LEN + 8 + SIG_LEN; // 136

/// The signed-prefix length (everything but the signature).
pub const TOKEN_SIGNED_PREFIX_LEN: usize = TOKEN_LEN - SIG_LEN; // 72

/// A capability token. See spec §11.1.
#[derive(Debug, Clone)]
pub struct CapabilityToken {
    /// Unique token identifier. Used for the bridge-side replay set.
    pub token_id: [u8; 32],
    /// Ed25519 identity of the bridge this token authorizes.
    pub bridge_ed25519_pk: [u8; ED25519_PK_LEN],
    /// Unix time (seconds) when this token ceases to be accepted.
    pub expires_at: u64,
    /// Ed25519 signature by operator over the preceding bytes.
    pub signature: [u8; SIG_LEN],
}

impl CapabilityToken {
    /// Serialize the signed prefix (bytes `[0..72]`). Used to sign or verify.
    pub fn encode_signed_prefix(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.token_id);
        out.extend_from_slice(&self.bridge_ed25519_pk);
        out.extend_from_slice(&self.expires_at.to_be_bytes());
    }

    /// Serialize the full 136-byte token (prefix + signature).
    pub fn encode(&self) -> [u8; TOKEN_LEN] {
        let mut out = [0u8; TOKEN_LEN];
        out[0..32].copy_from_slice(&self.token_id);
        out[32..64].copy_from_slice(&self.bridge_ed25519_pk);
        out[64..72].copy_from_slice(&self.expires_at.to_be_bytes());
        out[72..136].copy_from_slice(&self.signature);
        out
    }

    /// Parse from wire bytes. Does NOT verify the signature or check expiry.
    pub fn decode(buf: &[u8]) -> Result<Self, DiscoveryError> {
        if buf.len() != TOKEN_LEN {
            return Err(DiscoveryError::Wire("token: wrong length"));
        }
        let mut token_id = [0u8; 32];
        token_id.copy_from_slice(&buf[0..32]);
        let mut bridge_ed25519_pk = [0u8; ED25519_PK_LEN];
        bridge_ed25519_pk.copy_from_slice(&buf[32..64]);
        let expires_at = u64::from_be_bytes(buf[64..72].try_into().unwrap());
        let mut signature = [0u8; SIG_LEN];
        signature.copy_from_slice(&buf[72..136]);
        Ok(Self {
            token_id,
            bridge_ed25519_pk,
            expires_at,
            signature,
        })
    }

    /// Verify the operator's signature over this token. Does NOT check
    /// bridge-pinning or expiry.
    pub fn verify_signature(
        &self,
        operator_pk: &[u8; ED25519_PK_LEN],
    ) -> Result<(), DiscoveryError> {
        use mirage_crypto::ed25519_dalek::{Signature, VerifyingKey};
        let vk = VerifyingKey::from_bytes(operator_pk)
            .map_err(|_| DiscoveryError::Ed25519("invalid operator pubkey"))?;
        let sig = Signature::from_bytes(&self.signature);
        let mut prefix = Vec::with_capacity(TOKEN_SIGNED_PREFIX_LEN);
        self.encode_signed_prefix(&mut prefix);
        // verify_strict: rejects non-canonical S and small-subgroup A,
        // closing the malleability path that lets an attacker re-sign
        // a captured signature into a byte-distinct but valid record.
        vk.verify_strict(&prefix, &sig)
            .map_err(|_| DiscoveryError::Signature("token: verification failed"))
    }

    /// Return whether this token is bound to `bridge_pk`. Constant-time.
    pub fn is_for_bridge(&self, bridge_pk: &[u8; ED25519_PK_LEN]) -> bool {
        use mirage_crypto::subtle::ConstantTimeEq;
        self.bridge_ed25519_pk.ct_eq(bridge_pk).unwrap_u8() == 1
    }

    /// Return `true` if this token has expired at `now_unix`, allowing
    /// `grace_seconds` of negative-clock-skew slack.
    pub fn is_expired(&self, now_unix: u64, grace_seconds: u64) -> bool {
        // A token valid until T is accepted up to T + grace; an attacker
        // presenting an expired token gets grace before we reject.
        now_unix > self.expires_at.saturating_add(grace_seconds)
    }
}

/// Sign `(token_id, bridge_ed25519_pk, expires_at)` with the operator key.
///
/// Helper for token issuance. Caller supplies the operator `SigningKey`;
/// returns a fully populated [`CapabilityToken`].
pub fn sign_token(
    token_id: [u8; 32],
    bridge_ed25519_pk: [u8; ED25519_PK_LEN],
    expires_at: u64,
    operator_sk: &mirage_crypto::ed25519_dalek::SigningKey,
) -> CapabilityToken {
    use mirage_crypto::ed25519_dalek::Signer;
    let mut token = CapabilityToken {
        token_id,
        bridge_ed25519_pk,
        expires_at,
        signature: [0u8; SIG_LEN],
    };
    let mut prefix = Vec::with_capacity(TOKEN_SIGNED_PREFIX_LEN);
    token.encode_signed_prefix(&mut prefix);
    token.signature = operator_sk.sign(&prefix).to_bytes();
    token
}

/// Mint a batch of tokens with **randomly jittered** expiry
/// times. Closes [RT-CN-11]: a fixed-TTL mint produces tokens
/// whose `expires_at` cluster within seconds of each other -
/// after a leak, the censor can correlate the cluster to the
/// operator's mint timestamp ("invites rotated Tuesday 3 PM
/// UTC"). Per-token jitter `[0, jitter_seconds)` smears the
/// cluster across a window so the rotation moment can't be
/// recovered from a leaked subset.
///
/// Recommended `jitter_seconds`: half the nominal TTL. For a
/// 24-hour token, pass `12 * 3600 = 43200` so individual tokens
/// expire anywhere in `[24h, 36h)` from `issued_at`.
///
/// Falls back to fixed `nominal_expires_at` if the OS CSPRNG
/// returns an error (logged as a warning) - better fixed-TTL
/// than panic. CSPRNG failure is otherwise extremely rare.
pub fn sign_token_jittered(
    token_id: [u8; 32],
    bridge_ed25519_pk: [u8; ED25519_PK_LEN],
    nominal_expires_at: u64,
    jitter_seconds: u64,
    operator_sk: &mirage_crypto::ed25519_dalek::SigningKey,
) -> CapabilityToken {
    let jitter = if jitter_seconds == 0 {
        0u64
    } else {
        let mut buf = [0u8; 8];
        match getrandom::fill(&mut buf) {
            Ok(()) => u64::from_le_bytes(buf) % jitter_seconds,
            Err(_) => {
                tracing::warn!(
                    "sign_token_jittered: getrandom failed, falling back to nominal expiry"
                );
                0
            }
        }
    };
    let expires_at = nominal_expires_at.saturating_add(jitter);
    sign_token(token_id, bridge_ed25519_pk, expires_at, operator_sk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_crypto::ed25519_dalek::SigningKey;

    fn op_keypair() -> SigningKey {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        SigningKey::from_bytes(&seed)
    }

    #[test]
    fn token_encode_decode_roundtrip() {
        let op = op_keypair();
        let tok = sign_token([0x11u8; 32], [0x22u8; 32], 1_700_000_000, &op);
        let bytes = tok.encode();
        assert_eq!(bytes.len(), TOKEN_LEN);
        let dec = CapabilityToken::decode(&bytes).unwrap();
        assert_eq!(dec.token_id, tok.token_id);
        assert_eq!(dec.bridge_ed25519_pk, tok.bridge_ed25519_pk);
        assert_eq!(dec.expires_at, tok.expires_at);
        assert_eq!(dec.signature, tok.signature);
    }

    #[test]
    fn token_verify_roundtrip() {
        let op = op_keypair();
        let op_pk: [u8; 32] = op.verifying_key().to_bytes();
        let tok = sign_token([0xAAu8; 32], [0xBBu8; 32], 1_700_000_000, &op);
        tok.verify_signature(&op_pk).unwrap();
    }

    // --- RT-CN-11: jittered token expiry ---

    #[test]
    fn jittered_token_expiry_within_window() {
        let op = op_keypair();
        let nominal = 1_700_000_000u64;
        let jitter = 3600u64; // 1 hour
        let tok = sign_token_jittered([0x77u8; 32], [0x88u8; 32], nominal, jitter, &op);
        // expires_at must be in [nominal, nominal + jitter).
        assert!(
            tok.expires_at >= nominal && tok.expires_at < nominal + jitter,
            "expires_at {} outside window [{}..{})",
            tok.expires_at,
            nominal,
            nominal + jitter
        );
    }

    #[test]
    fn jittered_token_zero_jitter_is_fixed() {
        let op = op_keypair();
        let nominal = 1_700_000_000u64;
        let tok = sign_token_jittered([0x77u8; 32], [0x88u8; 32], nominal, 0, &op);
        assert_eq!(tok.expires_at, nominal);
    }

    #[test]
    fn jittered_token_batch_smears_expiries() {
        // RT-CN-11 closure check: a batch of 100 tokens minted
        // back-to-back with the same nominal expiry MUST produce
        // a smeared distribution, not all the same expires_at.
        let op = op_keypair();
        let nominal = 1_700_000_000u64;
        let jitter = 3600u64;
        let mut expiries = std::collections::HashSet::new();
        for i in 0..100 {
            let tok = sign_token_jittered(
                {
                    let mut id = [0u8; 32];
                    id[0] = i as u8;
                    id
                },
                [0x88u8; 32],
                nominal,
                jitter,
                &op,
            );
            expiries.insert(tok.expires_at);
        }
        // With 100 random draws over a 3600-second window, we
        // expect well over 50 unique values. A failed CSPRNG
        // would give us 1 value (everything == nominal).
        assert!(
            expiries.len() > 50,
            "RT-CN-11: expected smeared expiries, got {} unique of 100",
            expiries.len()
        );
    }

    #[test]
    fn jittered_token_signature_still_verifies() {
        let op = op_keypair();
        let op_pk: [u8; 32] = op.verifying_key().to_bytes();
        let tok = sign_token_jittered([0x77u8; 32], [0x88u8; 32], 1_700_000_000, 3600, &op);
        tok.verify_signature(&op_pk).unwrap();
    }

    #[test]
    fn token_verify_rejects_wrong_operator() {
        let op = op_keypair();
        let other = op_keypair();
        let other_pk: [u8; 32] = other.verifying_key().to_bytes();
        let tok = sign_token([0xAAu8; 32], [0xBBu8; 32], 1_700_000_000, &op);
        assert!(tok.verify_signature(&other_pk).is_err());
    }

    #[test]
    fn token_verify_rejects_tampered_fields() {
        let op = op_keypair();
        let op_pk: [u8; 32] = op.verifying_key().to_bytes();
        let mut tok = sign_token([0xAAu8; 32], [0xBBu8; 32], 1_700_000_000, &op);
        // Flip a byte in the bridge pubkey - signature no longer matches prefix.
        tok.bridge_ed25519_pk[0] ^= 0x01;
        assert!(tok.verify_signature(&op_pk).is_err());
    }

    #[test]
    fn token_rejects_wrong_length() {
        assert!(CapabilityToken::decode(&[0u8; TOKEN_LEN - 1]).is_err());
        assert!(CapabilityToken::decode(&[0u8; TOKEN_LEN + 1]).is_err());
    }

    #[test]
    fn is_for_bridge_checks_identity() {
        let op = op_keypair();
        let tok = sign_token([0u8; 32], [0xAAu8; 32], 1, &op);
        assert!(tok.is_for_bridge(&[0xAAu8; 32]));
        assert!(!tok.is_for_bridge(&[0xBBu8; 32]));
    }

    #[test]
    fn is_expired_respects_grace() {
        let op = op_keypair();
        let tok = sign_token([0u8; 32], [0u8; 32], 100, &op);
        assert!(!tok.is_expired(100, 0), "at exact expiry still valid");
        assert!(!tok.is_expired(90, 0), "before expiry valid");
        assert!(tok.is_expired(101, 0), "one second past expiry expired");
        assert!(!tok.is_expired(105, 10), "within grace still valid");
        assert!(tok.is_expired(111, 10), "past grace expired");
    }
}
