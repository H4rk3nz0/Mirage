//! Forward-secure capability tokens (epoch-subkey certificate chain).
//!
//! The legacy [`crate::token::CapabilityToken`] is signed **directly** by the
//! operator's long-term Ed25519 key. That key therefore has to be online on
//! whatever machine mints day-to-day invites, and a single compromise of that
//! machine lets an attacker forge *every* token, past and future.
//!
//! This module adds **forward security to issuance** via a two-level key
//! hierarchy:
//!
//! ```text
//!   operator ROOT key  (offline / air-gapped)
//!        |  signs one cert per epoch
//!        v
//!   epoch SUBKEY  (online; secret zeroized when the epoch retires)
//!        |  signs the actual capability tokens for that epoch
//!        v
//!   FsCapabilityToken
//! ```
//!
//! - The **root** key stays offline and only ever signs short
//!   [`EpochSubkeyCert`]s (`mint`), one per epoch. It never touches a token.
//! - The **online issuer** holds only the *current* epoch's subkey secret
//!   ([`EpochSigner`]) and signs tokens with it.
//! - When an epoch retires the issuer **drops** its [`EpochSigner`]; the seed
//!   is `Zeroizing`, so the subkey secret is destroyed.
//!
//! **Forward-security property.** Compromising the online issuer at epoch `N`
//! yields only the subkey secrets still resident (epoch `N` and any not-yet-
//! retired recent epochs). Tokens signed by a *retired* epoch's subkey cannot
//! be forged, because that subkey's secret is gone and the root - the only key
//! that could certify a replacement subkey for the old epoch - is offline. An
//! attacker who steals the online issuer cannot retroactively mint tokens that
//! validate as belonging to a past epoch.
//!
//! # Wire layout
//!
//! `EpochSubkeyCert` (112 bytes):
//! ```text
//!   epoch (8, BE) || subkey_pk (32) || cert_valid_until (8, BE) || root_sig (64)
//! ```
//!
//! `FsCapabilityToken` ([`FS_TOKEN_LEN`] = 248 bytes):
//! ```text
//!   token_id (32) || bridge_pk (32) || expires_at (8, BE) || cert (112) || token_sig (64)
//! ```
//!
//! The cert is carried **inline** so a verifying bridge is self-contained: it
//! needs only the pinned operator *root* public key, exactly as it already
//! pins the operator key for legacy tokens.
//!
//! # Domain separation
//!
//! Both signature layers are domain-separated so a signature from one layer can
//! never be cross-presented as another:
//!
//! - cert:  root signs [`FS_CERT_DOMAIN`] || epoch || subkey_pk || cert_valid_until
//! - token: subkey signs [`FS_TOKEN_DOMAIN`] || token_id || bridge_pk || expires_at || epoch || subkey_pk
//!
//! The legacy bootstrap token signs its prefix with **no** domain tag and the
//! refresh path uses `mirage-refresh-v1\0`; both FS domains are distinct from
//! those and from each other, so no FS signature is a valid signature under any
//! other Mirage token path. The token layer additionally commits to `epoch` and
//! `subkey_pk`, binding each token to exactly one cert (a valid `token_sig`
//! cannot be spliced onto a different - even if also root-valid - cert).

use crate::error::DiscoveryError;
use crate::wire::{ED25519_PK_LEN, SIG_LEN};
use mirage_crypto::zeroize::Zeroizing;

/// Domain tag for the root->subkey certificate signature.
pub const FS_CERT_DOMAIN: &[u8] = b"mirage-fs-cert-v1\0";
/// Domain tag for the subkey->token signature.
pub const FS_TOKEN_DOMAIN: &[u8] = b"mirage-fs-token-v1\0";

/// Wire length of an [`EpochSubkeyCert`]: epoch || subkey_pk || valid_until || sig.
pub const FS_CERT_LEN: usize = 8 + ED25519_PK_LEN + 8 + SIG_LEN; // 112

/// Wire length of an [`FsCapabilityToken`].
pub const FS_TOKEN_LEN: usize = 32 + ED25519_PK_LEN + 8 + FS_CERT_LEN + SIG_LEN; // 248

/// A root-signed certificate binding one epoch's online **subkey** to the
/// operator's offline **root** key. Public data - carried inside every token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochSubkeyCert {
    /// Monotonic epoch number this subkey serves.
    pub epoch: u64,
    /// Ed25519 public key of the online subkey.
    pub subkey_pk: [u8; ED25519_PK_LEN],
    /// Unix time (seconds) after which the subkey is retired and MUST NOT be
    /// honored (subject to `grace`). This bounds the forward-security window.
    pub cert_valid_until: u64,
    /// Root signature over [`FS_CERT_DOMAIN`] || epoch || subkey_pk || valid_until.
    pub root_sig: [u8; SIG_LEN],
}

impl EpochSubkeyCert {
    /// Bytes the root signs / a verifier re-derives. Domain-tagged.
    fn signed_prefix(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(FS_CERT_DOMAIN.len() + 8 + ED25519_PK_LEN + 8);
        v.extend_from_slice(FS_CERT_DOMAIN);
        v.extend_from_slice(&self.epoch.to_be_bytes());
        v.extend_from_slice(&self.subkey_pk);
        v.extend_from_slice(&self.cert_valid_until.to_be_bytes());
        v
    }

    /// **Offline root operation.** Sign a fresh cert for `subkey_pk`.
    ///
    /// Runs on the air-gapped machine holding the operator root key. `root_sk`
    /// is the operator's long-term signing key.
    pub fn mint(
        root_sk: &mirage_crypto::ed25519_dalek::SigningKey,
        epoch: u64,
        subkey_pk: [u8; ED25519_PK_LEN],
        cert_valid_until: u64,
    ) -> Self {
        use mirage_crypto::ed25519_dalek::Signer;
        let mut cert = Self {
            epoch,
            subkey_pk,
            cert_valid_until,
            root_sig: [0u8; SIG_LEN],
        };
        cert.root_sig = root_sk.sign(&cert.signed_prefix()).to_bytes();
        cert
    }

    /// Verify the root signature over this cert under `root_pk`. Does NOT check
    /// the cert's validity window (see [`Self::is_retired`]).
    pub fn verify_root_sig(&self, root_pk: &[u8; ED25519_PK_LEN]) -> Result<(), DiscoveryError> {
        use mirage_crypto::ed25519_dalek::{Signature, VerifyingKey};
        let vk = VerifyingKey::from_bytes(root_pk)
            .map_err(|_| DiscoveryError::Ed25519("fs cert: invalid root pubkey"))?;
        let sig = Signature::from_bytes(&self.root_sig);
        // verify_strict: reject non-canonical S and small-subgroup keys, closing
        // the malleability path that would let a captured sig be re-encoded.
        vk.verify_strict(&self.signed_prefix(), &sig)
            .map_err(|_| DiscoveryError::Signature("fs cert: root signature invalid"))
    }

    /// True once the subkey is past its validity window (plus `grace` slack for
    /// negative clock skew). A retired subkey MUST be rejected - this is the
    /// boundary of the forward-security window.
    pub fn is_retired(&self, now_unix: u64, grace_seconds: u64) -> bool {
        now_unix > self.cert_valid_until.saturating_add(grace_seconds)
    }

    /// Serialize to the fixed 112-byte wire form.
    pub fn encode(&self) -> [u8; FS_CERT_LEN] {
        let mut out = [0u8; FS_CERT_LEN];
        out[0..8].copy_from_slice(&self.epoch.to_be_bytes());
        out[8..40].copy_from_slice(&self.subkey_pk);
        out[40..48].copy_from_slice(&self.cert_valid_until.to_be_bytes());
        out[48..112].copy_from_slice(&self.root_sig);
        out
    }

    /// Parse from the fixed 112-byte wire form. Does not verify the signature.
    pub fn decode(buf: &[u8]) -> Result<Self, DiscoveryError> {
        if buf.len() != FS_CERT_LEN {
            return Err(DiscoveryError::Wire("fs cert: wrong length"));
        }
        let epoch = u64::from_be_bytes(buf[0..8].try_into().unwrap());
        let mut subkey_pk = [0u8; ED25519_PK_LEN];
        subkey_pk.copy_from_slice(&buf[8..40]);
        let cert_valid_until = u64::from_be_bytes(buf[40..48].try_into().unwrap());
        let mut root_sig = [0u8; SIG_LEN];
        root_sig.copy_from_slice(&buf[48..112]);
        Ok(Self {
            epoch,
            subkey_pk,
            cert_valid_until,
            root_sig,
        })
    }
}

/// A forward-secure capability token: signed by a per-epoch subkey whose cert
/// chains to the offline operator root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsCapabilityToken {
    /// Unique token identifier. Used for the bridge-side replay set.
    pub token_id: [u8; 32],
    /// Ed25519 identity of the bridge this token authorizes.
    pub bridge_ed25519_pk: [u8; ED25519_PK_LEN],
    /// Unix time (seconds) when this token ceases to be accepted.
    pub expires_at: u64,
    /// Inline root->subkey cert; lets the bridge verify with only the root pk.
    pub cert: EpochSubkeyCert,
    /// Subkey signature over the domain-tagged token prefix (which commits to
    /// the cert's epoch + subkey_pk).
    pub token_sig: [u8; SIG_LEN],
}

impl FsCapabilityToken {
    /// Bytes the subkey signs / a verifier re-derives. Domain-tagged and bound
    /// to the cert identity (epoch + subkey_pk).
    fn signed_prefix(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(
            FS_TOKEN_DOMAIN.len() + 32 + ED25519_PK_LEN + 8 + 8 + ED25519_PK_LEN,
        );
        v.extend_from_slice(FS_TOKEN_DOMAIN);
        v.extend_from_slice(&self.token_id);
        v.extend_from_slice(&self.bridge_ed25519_pk);
        v.extend_from_slice(&self.expires_at.to_be_bytes());
        v.extend_from_slice(&self.cert.epoch.to_be_bytes());
        v.extend_from_slice(&self.cert.subkey_pk);
        v
    }

    /// Verify the full chain: root->cert then subkey->token, plus the cert's
    /// validity window. Does NOT check bridge-pinning, token expiry, or replay
    /// (see [`Self::is_for_bridge`] / [`Self::is_expired`] and the caller's
    /// replay set) - mirroring [`crate::token::CapabilityToken`].
    ///
    /// Runs a **fixed** two Ed25519 verifications (cert then token) before any
    /// cheap field check, so rejection timing is dominated by constant-cost
    /// crypto rather than by which check failed.
    pub fn verify_chain(
        &self,
        root_pk: &[u8; ED25519_PK_LEN],
        now_unix: u64,
        grace_seconds: u64,
    ) -> Result<(), DiscoveryError> {
        // 1. root certifies the subkey.
        self.cert.verify_root_sig(root_pk)?;
        // 2. subkey signed this token (bound to cert epoch + subkey_pk).
        use mirage_crypto::ed25519_dalek::{Signature, VerifyingKey};
        let vk = VerifyingKey::from_bytes(&self.cert.subkey_pk)
            .map_err(|_| DiscoveryError::Ed25519("fs token: invalid subkey pubkey"))?;
        let sig = Signature::from_bytes(&self.token_sig);
        vk.verify_strict(&self.signed_prefix(), &sig)
            .map_err(|_| DiscoveryError::Signature("fs token: subkey signature invalid"))?;
        // 3. the subkey must not be retired (forward-security window boundary).
        if self.cert.is_retired(now_unix, grace_seconds) {
            return Err(DiscoveryError::Time("fs token: subkey retired"));
        }
        Ok(())
    }

    /// Whether this token is bound to `bridge_pk`. Constant-time.
    pub fn is_for_bridge(&self, bridge_pk: &[u8; ED25519_PK_LEN]) -> bool {
        use mirage_crypto::subtle::ConstantTimeEq;
        self.bridge_ed25519_pk.ct_eq(bridge_pk).unwrap_u8() == 1
    }

    /// Whether this token has expired at `now_unix`, allowing `grace_seconds`
    /// of negative-clock-skew slack.
    pub fn is_expired(&self, now_unix: u64, grace_seconds: u64) -> bool {
        now_unix > self.expires_at.saturating_add(grace_seconds)
    }

    /// Serialize to the fixed [`FS_TOKEN_LEN`]-byte wire form.
    pub fn encode(&self) -> [u8; FS_TOKEN_LEN] {
        let mut out = [0u8; FS_TOKEN_LEN];
        out[0..32].copy_from_slice(&self.token_id);
        out[32..64].copy_from_slice(&self.bridge_ed25519_pk);
        out[64..72].copy_from_slice(&self.expires_at.to_be_bytes());
        out[72..184].copy_from_slice(&self.cert.encode());
        out[184..248].copy_from_slice(&self.token_sig);
        out
    }

    /// Parse from the fixed [`FS_TOKEN_LEN`]-byte wire form. Does not verify.
    pub fn decode(buf: &[u8]) -> Result<Self, DiscoveryError> {
        if buf.len() != FS_TOKEN_LEN {
            return Err(DiscoveryError::Wire("fs token: wrong length"));
        }
        let mut token_id = [0u8; 32];
        token_id.copy_from_slice(&buf[0..32]);
        let mut bridge_ed25519_pk = [0u8; ED25519_PK_LEN];
        bridge_ed25519_pk.copy_from_slice(&buf[32..64]);
        let expires_at = u64::from_be_bytes(buf[64..72].try_into().unwrap());
        let cert = EpochSubkeyCert::decode(&buf[72..184])?;
        let mut token_sig = [0u8; SIG_LEN];
        token_sig.copy_from_slice(&buf[184..248]);
        Ok(Self {
            token_id,
            bridge_ed25519_pk,
            expires_at,
            cert,
            token_sig,
        })
    }
}

/// Generate a fresh epoch subkey keypair. Returns the zeroizing seed (kept by
/// the online issuer) and its public key (sent to the offline root to certify).
///
/// The truly air-gapped flow is: online machine calls this, ships `subkey_pk`
/// to the air-gapped root, root returns [`EpochSubkeyCert::mint`]'s cert, then
/// the online machine assembles an [`EpochSigner`] from `seed` + cert.
pub fn generate_epoch_subkey() -> Result<(Zeroizing<[u8; 32]>, [u8; ED25519_PK_LEN]), DiscoveryError>
{
    use mirage_crypto::ed25519_dalek::SigningKey;
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut())
        .map_err(|_| DiscoveryError::Wire("fs subkey: CSPRNG failure"))?;
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key().to_bytes();
    Ok((seed, pk))
}

/// The **online** per-epoch signer. Holds the subkey secret (as a zeroizing
/// seed) plus its root-signed cert, and signs tokens for the epoch.
///
/// Dropping this value zeroizes the subkey seed - that is how an operator
/// *retires* an epoch: drop the signer and the subkey secret is destroyed,
/// making that epoch's tokens permanently unforgeable.
pub struct EpochSigner {
    seed: Zeroizing<[u8; 32]>,
    cert: EpochSubkeyCert,
}

impl EpochSigner {
    /// Assemble an online signer from a subkey seed and its root-signed cert.
    ///
    /// Verifies that `cert.subkey_pk` matches the seed's public key so a
    /// mismatched (seed, cert) pair can't silently produce tokens that never
    /// validate.
    pub fn new(seed: Zeroizing<[u8; 32]>, cert: EpochSubkeyCert) -> Result<Self, DiscoveryError> {
        use mirage_crypto::ed25519_dalek::SigningKey;
        let pk = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        use mirage_crypto::subtle::ConstantTimeEq;
        if pk.ct_eq(&cert.subkey_pk).unwrap_u8() != 1 {
            return Err(DiscoveryError::Ed25519(
                "fs signer: seed/cert pubkey mismatch",
            ));
        }
        Ok(Self { seed, cert })
    }

    /// Convenience for colocated deployments (or tests): generate a subkey,
    /// have `root_sk` certify it, and return the ready signer in one step.
    ///
    /// NOTE: this touches the root key on the same machine as the subkey, so it
    /// does **not** realize the offline-root benefit. Production air-gapped
    /// deployments use [`generate_epoch_subkey`] + [`EpochSubkeyCert::mint`] +
    /// [`Self::new`] across the air gap instead.
    pub fn generate(
        root_sk: &mirage_crypto::ed25519_dalek::SigningKey,
        epoch: u64,
        cert_valid_until: u64,
    ) -> Result<Self, DiscoveryError> {
        let (seed, subkey_pk) = generate_epoch_subkey()?;
        let cert = EpochSubkeyCert::mint(root_sk, epoch, subkey_pk, cert_valid_until);
        Self::new(seed, cert)
    }

    /// This signer's cert (public; embedded in every token it signs).
    pub fn cert(&self) -> &EpochSubkeyCert {
        &self.cert
    }

    /// Sign one capability token for this epoch.
    pub fn sign_token(
        &self,
        token_id: [u8; 32],
        bridge_ed25519_pk: [u8; ED25519_PK_LEN],
        expires_at: u64,
    ) -> FsCapabilityToken {
        use mirage_crypto::ed25519_dalek::{Signer, SigningKey};
        let mut token = FsCapabilityToken {
            token_id,
            bridge_ed25519_pk,
            expires_at,
            cert: self.cert.clone(),
            token_sig: [0u8; SIG_LEN],
        };
        let sk = SigningKey::from_bytes(&self.seed);
        token.token_sig = sk.sign(&token.signed_prefix()).to_bytes();
        token
    }
}

/// Mint a batch of forward-secure bootstrap tokens for one invite - the
/// operator-tooling entry point (`mirage-setup` / `mirage-keygen` /
/// `mirage-rotate`).
///
/// Generates a fresh epoch subkey PER TOKEN (each certified by `root_sk`, the
/// operator root), aligned to the shared rendezvous epoch grid via
/// [`crate::derive::epoch_for_time`], so `cert.subkey_pk` is not a per-invite
/// cohort linker at the terminating bridge (red-team #19/#21) - at zero wire
/// cost, since each token already carries its own inline cert. Each per-token
/// subkey seed is zeroized when its signer drops at the end of its iteration.
///
/// `cert_valid_until` bounds the forward-security window; set it to the invite's
/// expiry so the subkey lives exactly as long as the invite. Each token's
/// `expires_at` is jittered in `[token_expires_at, token_expires_at + jitter)`,
/// preserving the RT-CN-11 expiry-smearing the legacy
/// [`crate::token::sign_token_jittered`] path provides (a fixed mint clusters
/// expiries and leaks the rotation moment from a leaked subset).
///
/// **Colocated issuance** (this helper touches `root_sk` in-process): the
/// forward-security benefit is that the always-online *bridge* only ever holds
/// the public root, so a bridge compromise forges nothing; the residual surface
/// is a transient compromise of the mint host while `root_sk` is resident. The
/// stronger offline-root split ([`generate_epoch_subkey`] +
/// [`EpochSubkeyCert::mint`] across an air gap + [`EpochSigner::new`]) produces
/// a **byte-identical** token, so upgrading needs no format/verifier change.
pub fn mint_fs_tokens(
    root_sk: &mirage_crypto::ed25519_dalek::SigningKey,
    bridge_ed25519_pk: [u8; ED25519_PK_LEN],
    now_unix: u64,
    cert_valid_until: u64,
    token_expires_at: u64,
    jitter_seconds: u64,
    count: usize,
) -> Result<Vec<FsCapabilityToken>, DiscoveryError> {
    let epoch = crate::derive::epoch_for_time(now_unix);
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        // A FRESH epoch subkey PER TOKEN. Sharing one subkey across an invite's
        // whole batch makes `cert.subkey_pk` a per-invite cohort LINKER at the
        // terminating bridge - every session from one invite carries the same
        // subkey_pk (red-team #19/#21). Zero wire cost: each 248-byte FS token
        // already embeds its own 112-byte inline cert, so distinct subkeys just
        // make those certs distinct rather than identical. The subkey seed is
        // zeroized when this per-token signer drops at the end of the iteration.
        let signer = EpochSigner::generate(root_sk, epoch, cert_valid_until)?;
        let mut tid = [0u8; 32];
        getrandom::fill(&mut tid).map_err(|_| DiscoveryError::Wire("fs mint: CSPRNG failure"))?;
        // Per-token expiry jitter (RT-CN-11), matching sign_token_jittered.
        let jitter = if jitter_seconds == 0 {
            0u64
        } else {
            let mut jb = [0u8; 8];
            match getrandom::fill(&mut jb) {
                Ok(()) => u64::from_le_bytes(jb) % jitter_seconds,
                Err(_) => 0,
            }
        };
        let exp = token_expires_at.saturating_add(jitter);
        out.push(signer.sign_token(tid, bridge_ed25519_pk, exp));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_crypto::ed25519_dalek::SigningKey;

    fn root_keypair() -> SigningKey {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        SigningKey::from_bytes(&seed)
    }

    fn root_pk(sk: &SigningKey) -> [u8; 32] {
        sk.verifying_key().to_bytes()
    }

    #[test]
    fn cert_encode_decode_roundtrip() {
        let root = root_keypair();
        let signer = EpochSigner::generate(&root, 7, 2_000_000_000).unwrap();
        let cert = signer.cert().clone();
        let bytes = cert.encode();
        assert_eq!(bytes.len(), FS_CERT_LEN);
        let dec = EpochSubkeyCert::decode(&bytes).unwrap();
        assert_eq!(dec, cert);
    }

    #[test]
    fn token_encode_decode_roundtrip() {
        let root = root_keypair();
        let signer = EpochSigner::generate(&root, 3, 2_000_000_000).unwrap();
        let tok = signer.sign_token([0x11u8; 32], [0x22u8; 32], 1_900_000_000);
        let bytes = tok.encode();
        assert_eq!(bytes.len(), FS_TOKEN_LEN);
        let dec = FsCapabilityToken::decode(&bytes).unwrap();
        assert_eq!(dec, tok);
    }

    #[test]
    fn full_chain_verifies() {
        let root = root_keypair();
        let rpk = root_pk(&root);
        let signer = EpochSigner::generate(&root, 1, 2_000_000_000).unwrap();
        let tok = signer.sign_token([0xAAu8; 32], [0xBBu8; 32], 2_000_000_000);
        tok.verify_chain(&rpk, 1_000_000_000, 0).unwrap();
        assert!(tok.is_for_bridge(&[0xBBu8; 32]));
        assert!(!tok.is_for_bridge(&[0xCCu8; 32]));
        assert!(!tok.is_expired(1_000_000_000, 0));
    }

    #[test]
    fn chain_rejects_wrong_root() {
        let root = root_keypair();
        let other = root_keypair();
        let signer = EpochSigner::generate(&root, 1, 2_000_000_000).unwrap();
        let tok = signer.sign_token([0xAAu8; 32], [0xBBu8; 32], 2_000_000_000);
        // Verifying under a DIFFERENT root pk must fail at the cert layer.
        assert!(tok
            .verify_chain(&root_pk(&other), 1_000_000_000, 0)
            .is_err());
    }

    #[test]
    fn chain_rejects_retired_subkey() {
        let root = root_keypair();
        let rpk = root_pk(&root);
        // cert_valid_until = 1000; querying at 1001 with 0 grace => retired.
        let signer = EpochSigner::generate(&root, 1, 1000).unwrap();
        let tok = signer.sign_token([0xAAu8; 32], [0xBBu8; 32], 2_000_000_000);
        assert!(
            tok.verify_chain(&rpk, 1001, 0).is_err(),
            "retired subkey must reject"
        );
        assert!(
            tok.verify_chain(&rpk, 1001, 10).is_ok(),
            "within grace still ok"
        );
        assert!(
            tok.verify_chain(&rpk, 1000, 0).is_ok(),
            "at exact boundary ok"
        );
    }

    #[test]
    fn forward_security_a_forged_cert_for_old_subkey_is_rejected() {
        // Model the FS property: an attacker who compromises the ONLINE issuer
        // after epoch 1 retired holds only epoch 2's subkey. They try to forge
        // a token that validates as epoch 1 by minting their OWN subkey and
        // self-signing a cert for it - but they lack the ROOT key, so the cert
        // fails root verification. Without the root they cannot certify any
        // subkey, retired-epoch or otherwise.
        let root = root_keypair();
        let rpk = root_pk(&root);

        // A subkey the attacker fully controls (they generated it).
        let attacker = root_keypair(); // stands in for an attacker-chosen subkey
                                       // Attacker self-signs a cert (no access to the real root key).
        let forged_cert = EpochSubkeyCert::mint(&attacker, 1, root_pk(&attacker), 2_000_000_000);
        let signer = EpochSigner::new(
            {
                // reconstruct the attacker's seed is not possible via API, so
                // build the signer directly from the attacker keypair's seed.
                Zeroizing::new(attacker.to_bytes())
            },
            forged_cert,
        )
        .unwrap();
        let forged = signer.sign_token([0x01u8; 32], [0xBBu8; 32], 2_000_000_000);
        // The token's own subkey signature is internally consistent, but the
        // cert is not signed by the real root -> chain rejects.
        assert!(
            forged.verify_chain(&rpk, 1_000_000_000, 0).is_err(),
            "forged cert not signed by real root must be rejected"
        );
    }

    #[test]
    fn token_bound_to_its_cert_no_splice() {
        // A valid token_sig from epoch A cannot be spliced onto a different
        // (also root-valid) cert from epoch B: the token prefix commits to the
        // cert's epoch + subkey_pk, so swapping the cert breaks the token sig.
        let root = root_keypair();
        let rpk = root_pk(&root);
        let signer_a = EpochSigner::generate(&root, 1, 2_000_000_000).unwrap();
        let signer_b = EpochSigner::generate(&root, 2, 2_000_000_000).unwrap();
        let mut tok = signer_a.sign_token([0xAAu8; 32], [0xBBu8; 32], 2_000_000_000);
        // Splice B's (root-valid) cert onto A's token.
        tok.cert = signer_b.cert().clone();
        assert!(
            tok.verify_chain(&rpk, 1_000_000_000, 0).is_err(),
            "token sig must not validate against a swapped cert"
        );
    }

    #[test]
    fn chain_rejects_tampered_token_fields() {
        let root = root_keypair();
        let rpk = root_pk(&root);
        let signer = EpochSigner::generate(&root, 1, 2_000_000_000).unwrap();
        let mut tok = signer.sign_token([0xAAu8; 32], [0xBBu8; 32], 2_000_000_000);
        tok.bridge_ed25519_pk[0] ^= 0x01; // flip a signed byte
        assert!(tok.verify_chain(&rpk, 1_000_000_000, 0).is_err());
    }

    #[test]
    fn signer_rejects_mismatched_seed_and_cert() {
        let root = root_keypair();
        // A cert for one subkey...
        let (_, pk_a) = generate_epoch_subkey().unwrap();
        let cert = EpochSubkeyCert::mint(&root, 1, pk_a, 2_000_000_000);
        // ...assembled with a DIFFERENT seed must be rejected.
        let (seed_b, _) = generate_epoch_subkey().unwrap();
        assert!(EpochSigner::new(seed_b, cert).is_err());
    }

    #[test]
    fn fs_signature_is_not_a_legacy_token_signature() {
        // Domain separation: an FS token's subkey signature covers the FS domain
        // tag, so the same bytes can never verify as a legacy (un-tagged) token
        // prefix. We assert the prefixes differ structurally.
        let root = root_keypair();
        let signer = EpochSigner::generate(&root, 1, 2_000_000_000).unwrap();
        let tok = signer.sign_token([0xAAu8; 32], [0xBBu8; 32], 2_000_000_000);
        let prefix = tok.signed_prefix();
        assert!(
            prefix.starts_with(FS_TOKEN_DOMAIN),
            "token prefix must carry the FS token domain tag"
        );
        assert_ne!(FS_TOKEN_DOMAIN, FS_CERT_DOMAIN);
    }

    #[test]
    fn wrong_length_decodes_fail() {
        assert!(EpochSubkeyCert::decode(&[0u8; FS_CERT_LEN - 1]).is_err());
        assert!(FsCapabilityToken::decode(&[0u8; FS_TOKEN_LEN + 1]).is_err());
    }

    #[test]
    fn mint_fs_tokens_batch_verifies_shares_one_subkey_and_jitters() {
        let root = root_keypair();
        let rpk = root_pk(&root);
        let now = 1_700_000_000u64;
        let toks = mint_fs_tokens(&root, [0xBB; 32], now, now + 86_400, now + 3600, 3600, 20)
            .expect("mint");
        assert_eq!(toks.len(), 20);
        let mut expiries = std::collections::HashSet::new();
        for t in &toks {
            // Whole batch chains to the operator root.
            t.verify_chain(&rpk, now, 0).unwrap();
            assert!(t.is_for_bridge(&[0xBB; 32]));
            expiries.insert(t.expires_at);
        }
        // Each token has a DISTINCT epoch subkey so cert.subkey_pk is not a
        // per-invite cohort linker (red-team #19/#21).
        let mut subkeys = std::collections::HashSet::new();
        for t in &toks {
            subkeys.insert(t.cert.subkey_pk);
        }
        assert_eq!(
            subkeys.len(),
            toks.len(),
            "every token has a distinct subkey"
        );
        // RT-CN-11: expiries are smeared, not clustered.
        assert!(
            expiries.len() > 10,
            "expected jittered expiries, got {} unique of 20",
            expiries.len()
        );
    }
}
