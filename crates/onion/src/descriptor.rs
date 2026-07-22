//! Service descriptor: the document a hidden service publishes to
//! tell clients how to reach it.
//!
//! The descriptor lists introduction-point bridges (hops the
//! service maintains long-lived circuits to). A client builds a
//! circuit, sends an `INTRODUCE` cell to one of these bridges; the
//! bridge forwards the introduction request through its
//! pre-established service-side circuit; the service then connects
//! back to a client-specified rendezvous point.
//!
//! # Wire format
//!
//! ```text
//!  Offset  Size   Field
//!  ------  ----   -----
//!  0       2      magic = "MI"
//!  2       1      doc_type = 0x60 (DOC_TYPE_ONION_DESCRIPTOR)
//!  3       1      version = 0x01
//!  4       8      issued_at  (u64 BE Unix time)
//!  12      8      expires_at (u64 BE Unix time)
//!  20      32     service_ed25519_pk (long-term identity)
//!  52      1      intro_count (u8, 1..=MAX_INTRO_POINTS)
//!  53      var    intro_points
//!  ...     64     signature (Ed25519 over [0..len-64])
//! ```
//!
//! Each intro-point entry:
//!
//! ```text
//!  Offset  Size   Field
//!  ------  ----   -----
//!  0       32     bridge_ed25519_pk
//!  32      32     bridge_x25519_pk
//!  64      32     intro_auth_key (per-intro Ed25519, used to
//!                  authenticate INTRODUCE cells)
//! ```
//!
//! # Discovery info-hash
//!
//! Clients fetch the descriptor by computing:
//!
//! ```text
//!   info_hash = BLAKE3-keyed(service_pk, "mirage-onion-desc-v1" || epoch_be)[0..20]
//! ```
//!
//! The service publishes the descriptor under this info-hash via
//! the regular discovery channel mesh ([`mirage_discovery`]). Per-
//! epoch rotation prevents long-term descriptor caching by
//! adversaries.

use mirage_crypto::blake3;
use mirage_crypto::ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use thiserror::Error;

/// `doc_type` for an onion descriptor. Allocated at the next free slot.
pub const DOC_TYPE_ONION_DESCRIPTOR: u8 = 0x60;

const ONION_DESC_VERSION_V1: u8 = 0x01;
const MAGIC: [u8; 2] = *b"MI";
const SIG_LEN: usize = 64;
const INTRO_POINT_LEN: usize = 32 + 32 + 32; // 96
/// Hard cap on number of introduction points per descriptor.
/// Keeps the descriptor compact (under the BEP-44 1000-byte budget)
/// while permitting redundancy.
pub const MAX_INTRO_POINTS: u8 = 8;

/// Domain separator for the descriptor info-hash derivation.
const DESC_INFO_HASH_LABEL: &[u8] = b"mirage-onion-desc-v1";

/// One introduction-point entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntroPoint {
    /// Bridge's long-term Ed25519 identity (matches the bridge's
    /// announcement). Used to verify the introduction-point bridge
    /// against the discovery layer's bridge directory.
    pub bridge_ed25519_pk: [u8; 32],
    /// Bridge's static X25519. Used by the client to dial the
    /// bridge for the introduction request.
    pub bridge_x25519_pk: [u8; 32],
    /// Per-introduction Ed25519 key. The client signs the INTRODUCE
    /// cell payload with this key; the introduction-point bridge
    /// verifies before forwarding to the service.
    pub intro_auth_key: [u8; 32],
}

/// A signed onion service descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnionDescriptor {
    /// Unix time of issuance.
    pub issued_at: u64,
    /// Unix time after which clients reject this descriptor.
    pub expires_at: u64,
    /// Service's long-term Ed25519 identity (the same key encoded
    /// in the `.mirage` address).
    pub service_ed25519_pk: [u8; 32],
    /// Introduction points (1..=[`MAX_INTRO_POINTS`]).
    pub intro_points: Vec<IntroPoint>,
    /// Ed25519 signature by `service_ed25519_pk` over the wire
    /// bytes preceding the signature.
    pub signature: [u8; SIG_LEN],
}

/// Errors produced by descriptor encoding/decoding/signing.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ServiceDescError {
    /// Wire-format violation (bad magic, `doc_type`, or length).
    #[error("wire: {0}")]
    Wire(&'static str),
    /// `intro_points` count outside the allowed range.
    #[error("intro_count {count} out of range")]
    BadIntroCount {
        /// The offending value.
        count: usize,
    },
    /// `expires_at <= issued_at`.
    #[error("expires_at must be > issued_at")]
    BadExpiry,
    /// Ed25519 signature verification failed.
    #[error("signature invalid")]
    BadSignature,
    /// Caller-supplied service pk doesn't match the descriptor's
    /// embedded `service_ed25519_pk`.
    #[error("service pk mismatch")]
    PkMismatch,
}

impl OnionDescriptor {
    /// Construct an unsigned descriptor. Caller must call
    /// [`Self::sign`] before encoding.
    pub fn new(
        issued_at: u64,
        expires_at: u64,
        service_ed25519_pk: [u8; 32],
        intro_points: Vec<IntroPoint>,
    ) -> Result<Self, ServiceDescError> {
        if expires_at <= issued_at {
            return Err(ServiceDescError::BadExpiry);
        }
        if intro_points.is_empty() || intro_points.len() > MAX_INTRO_POINTS as usize {
            return Err(ServiceDescError::BadIntroCount {
                count: intro_points.len(),
            });
        }
        Ok(Self {
            issued_at,
            expires_at,
            service_ed25519_pk,
            intro_points,
            signature: [0u8; SIG_LEN],
        })
    }

    /// Sign in place. `service_sk` must correspond to
    /// `self.service_ed25519_pk` - caller's responsibility.
    pub fn sign(&mut self, service_sk: &SigningKey) -> Result<(), ServiceDescError> {
        let pk_from_sk = service_sk.verifying_key().to_bytes();
        if pk_from_sk != self.service_ed25519_pk {
            return Err(ServiceDescError::PkMismatch);
        }
        let mut prefix = Vec::new();
        self.encode_signed_prefix(&mut prefix);
        self.signature = service_sk.sign(&prefix).to_bytes();
        Ok(())
    }

    /// Verify the descriptor's signature against
    /// `self.service_ed25519_pk`.
    pub fn verify(&self) -> Result<(), ServiceDescError> {
        let vk = VerifyingKey::from_bytes(&self.service_ed25519_pk)
            .map_err(|_| ServiceDescError::BadSignature)?;
        let mut prefix = Vec::new();
        self.encode_signed_prefix(&mut prefix);
        vk.verify_strict(&prefix, &Signature::from_bytes(&self.signature))
            .map_err(|_| ServiceDescError::BadSignature)
    }

    /// True iff `now` is in `[issued_at, expires_at)`.
    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.issued_at && now < self.expires_at
    }

    /// Encode to wire bytes (including signature).
    pub fn encode(&self) -> Result<Vec<u8>, ServiceDescError> {
        if self.intro_points.is_empty() || self.intro_points.len() > MAX_INTRO_POINTS as usize {
            return Err(ServiceDescError::BadIntroCount {
                count: self.intro_points.len(),
            });
        }
        let mut out = Vec::with_capacity(self.signed_prefix_len() + SIG_LEN);
        self.encode_signed_prefix(&mut out);
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    fn signed_prefix_len(&self) -> usize {
        2 + 1 + 1 + 8 + 8 + 32 + 1 + self.intro_points.len() * INTRO_POINT_LEN
    }

    fn encode_signed_prefix(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&MAGIC);
        out.push(DOC_TYPE_ONION_DESCRIPTOR);
        out.push(ONION_DESC_VERSION_V1);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.service_ed25519_pk);
        out.push(self.intro_points.len() as u8);
        for ip in &self.intro_points {
            out.extend_from_slice(&ip.bridge_ed25519_pk);
            out.extend_from_slice(&ip.bridge_x25519_pk);
            out.extend_from_slice(&ip.intro_auth_key);
        }
    }

    /// Decode from wire bytes. Does NOT verify the signature; call
    /// [`Self::verify`] after if you need authenticity.
    pub fn decode(buf: &[u8]) -> Result<Self, ServiceDescError> {
        if buf.len() < 2 + 1 + 1 + 8 + 8 + 32 + 1 + INTRO_POINT_LEN + SIG_LEN {
            return Err(ServiceDescError::Wire("descriptor too short"));
        }
        if buf[0..2] != MAGIC {
            return Err(ServiceDescError::Wire("bad magic"));
        }
        if buf[2] != DOC_TYPE_ONION_DESCRIPTOR {
            return Err(ServiceDescError::Wire("wrong doc_type"));
        }
        if buf[3] != ONION_DESC_VERSION_V1 {
            return Err(ServiceDescError::Wire("unsupported version"));
        }
        let issued_at = u64::from_be_bytes(buf[4..12].try_into().unwrap());
        let expires_at = u64::from_be_bytes(buf[12..20].try_into().unwrap());
        if expires_at <= issued_at {
            return Err(ServiceDescError::BadExpiry);
        }
        let mut service_ed25519_pk = [0u8; 32];
        service_ed25519_pk.copy_from_slice(&buf[20..52]);
        let intro_count = buf[52] as usize;
        if intro_count == 0 || intro_count > MAX_INTRO_POINTS as usize {
            return Err(ServiceDescError::BadIntroCount { count: intro_count });
        }
        let intro_block_len = intro_count * INTRO_POINT_LEN;
        let cursor = 53;
        if buf.len() != cursor + intro_block_len + SIG_LEN {
            return Err(ServiceDescError::Wire("length mismatch"));
        }
        let mut intro_points = Vec::with_capacity(intro_count);
        for i in 0..intro_count {
            let off = cursor + i * INTRO_POINT_LEN;
            let mut bridge_ed25519_pk = [0u8; 32];
            bridge_ed25519_pk.copy_from_slice(&buf[off..off + 32]);
            let mut bridge_x25519_pk = [0u8; 32];
            bridge_x25519_pk.copy_from_slice(&buf[off + 32..off + 64]);
            let mut intro_auth_key = [0u8; 32];
            intro_auth_key.copy_from_slice(&buf[off + 64..off + 96]);
            intro_points.push(IntroPoint {
                bridge_ed25519_pk,
                bridge_x25519_pk,
                intro_auth_key,
            });
        }
        let sig_off = cursor + intro_block_len;
        let mut signature = [0u8; SIG_LEN];
        signature.copy_from_slice(&buf[sig_off..sig_off + SIG_LEN]);
        Ok(Self {
            issued_at,
            expires_at,
            service_ed25519_pk,
            intro_points,
            signature,
        })
    }
}

/// Compute the discovery info-hash that a client uses to fetch a
/// service's current-epoch descriptor.
///
/// `info_hash = BLAKE3-keyed(service_pk, "mirage-onion-desc-v1" || epoch_be)[0..20]`
///
/// 20 bytes for `BitTorrent` DHT compatibility (matches the bridge
/// announcement info-hash).
pub fn onion_descriptor_info_hash(service_pk: &[u8; 32], epoch: u64) -> [u8; 20] {
    let mut h = blake3::Hasher::new_keyed(service_pk);
    h.update(DESC_INFO_HASH_LABEL);
    h.update(&epoch.to_be_bytes());
    let full = *h.finalize().as_bytes();
    let mut out = [0u8; 20];
    out.copy_from_slice(&full[..20]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (SigningKey, [u8; 32]) {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        let sk = SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn intro(tag: u8) -> IntroPoint {
        IntroPoint {
            bridge_ed25519_pk: [tag; 32],
            bridge_x25519_pk: [tag.wrapping_add(1); 32],
            intro_auth_key: [tag.wrapping_add(2); 32],
        }
    }

    #[test]
    fn descriptor_sign_verify_roundtrip() {
        let (sk, pk) = keypair();
        let mut desc =
            OnionDescriptor::new(1_000_000, 1_003_600, pk, vec![intro(1), intro(2)]).unwrap();
        desc.sign(&sk).unwrap();
        let bytes = desc.encode().unwrap();
        let back = OnionDescriptor::decode(&bytes).unwrap();
        assert_eq!(back, desc);
        back.verify().unwrap();
    }

    #[test]
    fn verify_rejects_tampered_intro() {
        let (sk, pk) = keypair();
        let mut desc = OnionDescriptor::new(1_000_000, 1_003_600, pk, vec![intro(1)]).unwrap();
        desc.sign(&sk).unwrap();
        let mut bytes = desc.encode().unwrap();
        // Flip a byte in the intro-point block.
        bytes[60] ^= 0x01;
        let back = OnionDescriptor::decode(&bytes).unwrap();
        assert_eq!(back.verify().unwrap_err(), ServiceDescError::BadSignature);
    }

    #[test]
    fn descriptor_rejects_zero_intros() {
        let (_, pk) = keypair();
        let err = OnionDescriptor::new(1, 2, pk, vec![]).unwrap_err();
        assert!(matches!(err, ServiceDescError::BadIntroCount { count: 0 }));
    }

    #[test]
    fn descriptor_rejects_too_many_intros() {
        let (_, pk) = keypair();
        let many: Vec<_> = (0..MAX_INTRO_POINTS as usize + 1)
            .map(|i| intro(i as u8))
            .collect();
        let err = OnionDescriptor::new(1, 2, pk, many).unwrap_err();
        assert!(matches!(err, ServiceDescError::BadIntroCount { .. }));
    }

    #[test]
    fn descriptor_rejects_bad_expiry() {
        let (_, pk) = keypair();
        let err = OnionDescriptor::new(2, 1, pk, vec![intro(1)]).unwrap_err();
        assert_eq!(err, ServiceDescError::BadExpiry);
    }

    #[test]
    fn sign_rejects_pk_mismatch() {
        let (sk, _pk) = keypair();
        let (_, other_pk) = keypair();
        let mut desc = OnionDescriptor::new(1, 2, other_pk, vec![intro(1)]).unwrap();
        let err = desc.sign(&sk).unwrap_err();
        assert_eq!(err, ServiceDescError::PkMismatch);
    }

    #[test]
    fn info_hash_per_epoch_rotates() {
        let pk = [0x42u8; 32];
        let h1 = onion_descriptor_info_hash(&pk, 1);
        let h2 = onion_descriptor_info_hash(&pk, 2);
        assert_ne!(h1, h2, "info-hash MUST rotate per epoch");
    }

    #[test]
    fn info_hash_is_pk_dependent() {
        let h1 = onion_descriptor_info_hash(&[1u8; 32], 1);
        let h2 = onion_descriptor_info_hash(&[2u8; 32], 1);
        assert_ne!(h1, h2);
    }

    #[test]
    fn info_hash_is_deterministic() {
        let pk = [0x42u8; 32];
        assert_eq!(
            onion_descriptor_info_hash(&pk, 1234),
            onion_descriptor_info_hash(&pk, 1234)
        );
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let mut buf = vec![0xFFu8; 200];
        buf[0..2].copy_from_slice(b"NO");
        assert!(matches!(
            OnionDescriptor::decode(&buf),
            Err(ServiceDescError::Wire(_))
        ));
    }
}
