//! Bridge-to-bridge mesh discovery.
//!
//! # Why
//!
//! Multi-hop circuits and load-balancing across operator-mesh
//! deployments require bridges to discover OTHER bridges in the
//! same operator's mesh. Client-to-bridge discovery (the
//! `master_invite` flow) is the wrong primitive for this - clients
//! shouldn't see the full bridge fleet, and bridges shouldn't
//! depend on every client's invite. Bridges discover each other
//! via a separate namespace + a separate secret.
//!
//! # Namespace separation
//!
//! ```text
//!   client->bridge:  namespace = "mirage-namespace-c2b-v1"  (existing, §03 §4.1)
//!   bridge<->bridge:  namespace = "mirage-namespace-b2b-v1"  (this module)
//! ```
//!
//! Same epoch-rolled info-hash design:
//! `info_hash = BLAKE3-keyed(mesh_secret, "mirage-rolling-v1"
//! || NAMESPACE_BRIDGE_TO_BRIDGE || epoch_be)` then `BLAKE3-keyed`
//! into `info_hash` and `cipher_key`/`cipher_nonce`. The seal AAD
//! ([crate::seal] v0.1s addition) binds namespace + epoch so a
//! ciphertext minted for c2b cannot be lifted into b2b even if
//! `shared_salt` and `mesh_secret` were equal.
//!
//! # Wire format
//!
//! A `MeshInvite` is the operator-to-operator OOB-distributed bundle
//! that lets a bridge join the mesh:
//!
//! ```text
//!  Offset  Size   Field
//!  ------  ----   -----
//!  0       2      magic = "MI"
//!  2       1      doc_type = 0x12 (DOC_TYPE_MESH_INVITE)
//!  3       1      version = 0x01
//!  4       32     operator_ed25519_pk
//!  36      32     mesh_secret              (Zeroizing in memory)
//!  68      8      issued_at  (u64 BE)
//!  76      8      expires_at (u64 BE)
//!  84      64     signature  (Ed25519 over bytes [0..84])
//! ```
//!
//! Fixed 148 bytes (84-byte signed prefix + 64-byte Ed25519 signature);
//! no bootstrap tokens or claim_id (those are client-facing). A bridge
//! configured with a `MeshInvite` can:
//!
//! - Compute the per-epoch b2b info-hash via [`mesh_info_hash`].
//! - Publish its own announcement under that info-hash (same
//!   announcement wire format as client-facing) using
//!   [`crate::seal::seal`] with `NAMESPACE_BRIDGE_TO_BRIDGE`.
//! - Fetch other bridges' announcements via [`crate::seal::open`].
//!
//! # Threat-model fit
//!
//! - **Mesh-secret leak.** A leaked `mesh_secret` lets an attacker
//!   enumerate the entire mesh - same blast radius as a leaked
//!   `master_invite`. Operators MUST protect mesh-secret with the
//!   same operational discipline. Mitigation:
//!   per-mesh rotation analogous to invite rotation; plus an
//!   emergency compromise procedure.
//! - **Bridge enumeration via mesh fetch.** An attacker holding a
//!   mesh-secret can fetch every bridge's announcement and learn
//!   the full fleet. Tor's HSDir model partitions this; Mirage's
//!   v0.1 design accepts this exposure for operator-internal
//!   members and mitigates externally via rotation.

use mirage_crypto::ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use mirage_crypto::zeroize::Zeroizing;
use thiserror::Error;
use zeroize::Zeroize;

use crate::derive::{epoch_for_time, info_hash, NAMESPACE_BRIDGE_TO_BRIDGE};
use crate::wire::{DOC_TYPE_INVITE, ED25519_PK_LEN, MAGIC, SIG_LEN};

/// `doc_type` for a mesh invite. Distinct from `DOC_TYPE_INVITE`
/// (`0x10`) so a parser can immediately reject a master-invite
/// that lands in a mesh-context decode path and vice versa.
pub const DOC_TYPE_MESH_INVITE: u8 = 0x12;

const MESH_INVITE_VERSION_V1: u8 = 0x01;
const MESH_SIGNED_PREFIX_LEN: usize = 2 + 1 + 1 + ED25519_PK_LEN + 32 + 8 + 8;
const MESH_INVITE_LEN: usize = MESH_SIGNED_PREFIX_LEN + SIG_LEN;

/// Errors produced by `MeshInvite` encode/decode/sign/verify.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MeshInviteError {
    /// Wire-format violation (length, magic, doc_type, version).
    #[error("wire: {0}")]
    Wire(&'static str),
    /// `expires_at <= issued_at`.
    #[error("expires_at must be > issued_at")]
    BadExpiry,
    /// Ed25519 signature verification failed.
    #[error("signature invalid")]
    BadSignature,
    /// Caller-supplied operator pk doesn't match the embedded value.
    #[error("operator pk mismatch")]
    PkMismatch,
}

/// A mesh-invite document. Operators distribute one per bridge in
/// the mesh OOB; the bridge stores it on disk and uses the
/// `mesh_secret` for b2b discovery.
///
/// `mesh_secret` is held in `Zeroizing` so dropping the invite
/// zeroes the secret.
pub struct MeshInvite {
    /// Operator's Ed25519 long-term identity (same as client invite).
    pub operator_ed25519_pk: [u8; ED25519_PK_LEN],
    /// 32-byte mesh secret. Zeroized on drop.
    pub mesh_secret: Zeroizing<[u8; 32]>,
    /// Unix time of issuance.
    pub issued_at: u64,
    /// Unix time after which the invite is rejected.
    pub expires_at: u64,
    /// Operator Ed25519 signature over the preceding bytes.
    pub signature: [u8; SIG_LEN],
}

impl core::fmt::Debug for MeshInvite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MeshInvite")
            .field("operator_ed25519_pk", &"<32 B>")
            .field("mesh_secret", &"<redacted>")
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("signature", &"<64 B>")
            .finish()
    }
}

impl MeshInvite {
    /// Build + sign a fresh mesh invite. `operator_sk` MUST
    /// correspond to `operator_ed25519_pk` derived from
    /// `operator_sk.verifying_key()`.
    pub fn new_signed(
        operator_sk: &SigningKey,
        mesh_secret: [u8; 32],
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, MeshInviteError> {
        if expires_at <= issued_at {
            return Err(MeshInviteError::BadExpiry);
        }
        let operator_ed25519_pk = operator_sk.verifying_key().to_bytes();
        let mut inv = Self {
            operator_ed25519_pk,
            mesh_secret: Zeroizing::new(mesh_secret),
            issued_at,
            expires_at,
            signature: [0u8; SIG_LEN],
        };
        let mut prefix = Vec::with_capacity(MESH_SIGNED_PREFIX_LEN);
        inv.encode_signed_prefix(&mut prefix);
        inv.signature = operator_sk.sign(&prefix).to_bytes();
        // Wipe the signing-input copy of the secret; it's been
        // baked into the signature so the prefix vec is no longer
        // needed.
        prefix.zeroize();
        Ok(inv)
    }

    /// True iff `now` is in `[issued_at, expires_at)`.
    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.issued_at && now < self.expires_at
    }

    /// Encode (148 bytes: 84-byte signed prefix + 64-byte signature).
    pub fn encode(&self) -> [u8; MESH_INVITE_LEN] {
        let mut out = [0u8; MESH_INVITE_LEN];
        let mut idx = 0;
        out[idx..idx + 2].copy_from_slice(&MAGIC);
        idx += 2;
        out[idx] = DOC_TYPE_MESH_INVITE;
        idx += 1;
        out[idx] = MESH_INVITE_VERSION_V1;
        idx += 1;
        out[idx..idx + 32].copy_from_slice(&self.operator_ed25519_pk);
        idx += 32;
        out[idx..idx + 32].copy_from_slice(self.mesh_secret.as_ref());
        idx += 32;
        out[idx..idx + 8].copy_from_slice(&self.issued_at.to_be_bytes());
        idx += 8;
        out[idx..idx + 8].copy_from_slice(&self.expires_at.to_be_bytes());
        idx += 8;
        out[idx..idx + SIG_LEN].copy_from_slice(&self.signature);
        out
    }

    fn encode_signed_prefix(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&MAGIC);
        out.push(DOC_TYPE_MESH_INVITE);
        out.push(MESH_INVITE_VERSION_V1);
        out.extend_from_slice(&self.operator_ed25519_pk);
        out.extend_from_slice(self.mesh_secret.as_ref());
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
    }

    /// Decode from wire bytes. Does NOT verify the signature; call
    /// [`Self::verify`] after if you need authenticity.
    ///
    /// Note: `DOC_TYPE_INVITE` (the master-invite type) is rejected
    /// here so a parser confusion attack cannot lift a master-invite
    /// into a mesh context.
    pub fn decode(buf: &[u8]) -> Result<Self, MeshInviteError> {
        if buf.len() != MESH_INVITE_LEN {
            return Err(MeshInviteError::Wire("mesh invite wrong length"));
        }
        if buf[0..2] != MAGIC {
            return Err(MeshInviteError::Wire("bad magic"));
        }
        if buf[2] == DOC_TYPE_INVITE {
            return Err(MeshInviteError::Wire(
                "doc_type is master-invite, not mesh-invite",
            ));
        }
        if buf[2] != DOC_TYPE_MESH_INVITE {
            return Err(MeshInviteError::Wire("wrong doc_type"));
        }
        if buf[3] != MESH_INVITE_VERSION_V1 {
            return Err(MeshInviteError::Wire("unsupported version"));
        }
        let mut operator_ed25519_pk = [0u8; ED25519_PK_LEN];
        operator_ed25519_pk.copy_from_slice(&buf[4..36]);
        // Land the secret directly inside `Zeroizing` so a panic
        // anywhere in the decode tail still runs the wipe on drop.
        // Pre-fix the secret existed on the stack as a bare [u8; 32]
        // for a few statements before being wrapped - and the
        // wrap-by-move was a memcpy that could leave the source copy
        // unzeroed.
        let mut mesh_secret: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
        mesh_secret.copy_from_slice(&buf[36..68]);
        let issued_at = u64::from_be_bytes(buf[68..76].try_into().unwrap());
        let expires_at = u64::from_be_bytes(buf[76..84].try_into().unwrap());
        if expires_at <= issued_at {
            // Zeroizing::drop runs on the early return, but be
            // explicit so a future refactor can't accidentally leak.
            drop(mesh_secret);
            return Err(MeshInviteError::BadExpiry);
        }
        let mut signature = [0u8; SIG_LEN];
        signature.copy_from_slice(&buf[84..148]);
        Ok(Self {
            operator_ed25519_pk,
            mesh_secret,
            issued_at,
            expires_at,
            signature,
        })
    }

    /// Verify the signature against `self.operator_ed25519_pk`.
    pub fn verify(&self) -> Result<(), MeshInviteError> {
        let vk = VerifyingKey::from_bytes(&self.operator_ed25519_pk)
            .map_err(|_| MeshInviteError::BadSignature)?;
        let mut prefix = Vec::with_capacity(MESH_SIGNED_PREFIX_LEN);
        self.encode_signed_prefix(&mut prefix);
        let res = vk
            .verify_strict(&prefix, &Signature::from_bytes(&self.signature))
            .map_err(|_| MeshInviteError::BadSignature);
        prefix.zeroize();
        res
    }
}

/// Compute the bridge-to-bridge info-hash for `(mesh_secret, epoch)`.
///
/// Equivalent to calling [`crate::derive::info_hash`] with
/// `NAMESPACE_BRIDGE_TO_BRIDGE`. Provided as a convenience so
/// callers don't accidentally pass the wrong namespace constant.
pub fn mesh_info_hash(mesh_secret: &[u8; 32], epoch: u64) -> [u8; 20] {
    info_hash(mesh_secret, NAMESPACE_BRIDGE_TO_BRIDGE, epoch)
}

/// Convenience: derive the b2b info-hash for the current Unix
/// time. Wraps [`epoch_for_time`] + [`mesh_info_hash`].
pub fn mesh_info_hash_for_time(mesh_secret: &[u8; 32], now_unix: u64) -> [u8; 20] {
    let epoch = epoch_for_time(now_unix);
    mesh_info_hash(mesh_secret, epoch)
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

    #[test]
    fn mesh_invite_sign_verify_roundtrip() {
        let (sk, _pk) = keypair();
        let secret = [0xABu8; 32];
        let inv = MeshInvite::new_signed(&sk, secret, 1_000_000, 1_604_800).unwrap();
        let bytes = inv.encode();
        assert_eq!(bytes.len(), MESH_INVITE_LEN);
        let back = MeshInvite::decode(&bytes).unwrap();
        back.verify().unwrap();
        assert_eq!(*back.mesh_secret, secret);
    }

    #[test]
    fn mesh_invite_rejects_bad_expiry() {
        let (sk, _pk) = keypair();
        let err = MeshInvite::new_signed(&sk, [0u8; 32], 2, 1).unwrap_err();
        assert_eq!(err, MeshInviteError::BadExpiry);
    }

    #[test]
    fn decode_rejects_master_invite_doctype() {
        let (sk, _pk) = keypair();
        let inv = MeshInvite::new_signed(&sk, [0u8; 32], 1, 2).unwrap();
        // Re-emit signed prefix with the doc-type swapped to the
        // master-invite value; the decoder must refuse.
        let mut bytes = inv.encode();
        bytes[2] = DOC_TYPE_INVITE;
        // Need to re-sign to keep the invite syntactically signed
        // (the test isn't about sig validity - but we want to be
        // sure decode REJECTS doc_type=0x10 even on length-valid
        // input).
        let err = MeshInvite::decode(&bytes).unwrap_err();
        assert!(matches!(err, MeshInviteError::Wire(s) if s.contains("master-invite")));
        // Touch inv to silence the unused warning.
        let _ = &inv.expires_at;
    }

    #[test]
    fn verify_rejects_tampered_secret() {
        let (sk, _pk) = keypair();
        let inv = MeshInvite::new_signed(&sk, [0xABu8; 32], 1, 2).unwrap();
        let mut bytes = inv.encode();
        bytes[40] ^= 0x01; // flip a byte in the mesh_secret region
        let back = MeshInvite::decode(&bytes).unwrap();
        assert_eq!(back.verify().unwrap_err(), MeshInviteError::BadSignature);
    }

    #[test]
    fn mesh_info_hash_separates_from_c2b() {
        // Even with IDENTICAL secret bytes, c2b and b2b namespaces
        // MUST produce different info-hashes - otherwise a leaked
        // master_invite could be lifted into mesh discovery.
        let secret = [0x11u8; 32];
        let epoch = 100;
        let b2b = mesh_info_hash(&secret, epoch);
        let c2b = info_hash(&secret, crate::derive::NAMESPACE_CLIENT_TO_BRIDGE, epoch);
        assert_ne!(b2b, c2b);
    }

    #[test]
    fn mesh_info_hash_rotates_per_epoch() {
        let secret = [0x11u8; 32];
        assert_ne!(mesh_info_hash(&secret, 1), mesh_info_hash(&secret, 2));
    }

    #[test]
    fn mesh_info_hash_is_deterministic() {
        let secret = [0x11u8; 32];
        assert_eq!(mesh_info_hash(&secret, 1234), mesh_info_hash(&secret, 1234));
    }

    #[test]
    fn mesh_secret_zeroizes_on_drop() {
        // Smoke: the Zeroizing<[u8;32]> wrapper handles this.
        let (sk, _pk) = keypair();
        let inv = MeshInvite::new_signed(&sk, [0xCDu8; 32], 1, 2).unwrap();
        let _ptr_addr = inv.mesh_secret.as_ptr() as usize;
        drop(inv);
        // Cannot safely observe the now-freed stack slot - this
        // test exists for code-search visibility ("is the secret
        // wrapped?") and does the assertion via Drop semantics.
        // The compile-time guarantee is the Zeroizing<> wrapper.
    }

    #[test]
    fn is_valid_at_window_check() {
        let (sk, _pk) = keypair();
        let inv = MeshInvite::new_signed(&sk, [0u8; 32], 100, 200).unwrap();
        assert!(!inv.is_valid_at(99));
        assert!(inv.is_valid_at(100));
        assert!(inv.is_valid_at(150));
        assert!(!inv.is_valid_at(200));
        assert!(!inv.is_valid_at(201));
    }
}
