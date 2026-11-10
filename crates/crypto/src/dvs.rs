//! Designated-verifier signatures for **receipt-free invite vouching**.
//!
//! # STATUS: EXPERIMENTAL - built, verified, and deliberately NOT WIRED
//!
//! This is a complete, adversarially-reviewed cryptographic primitive with no
//! live caller. It is retained as experimental groundwork, not shipped
//! functionality. It does NOT fit Mirage's CURRENT threat model: invites are a
//! deliberate operator->user *star* (the operator's Ed25519 key is public in
//! every invite, so the only "vouch" edge is already public), and wiring this
//! would fight the shipped `claim_id` + leak-detector attribution feature, whose
//! goal is the *opposite* of receipt-freeness. It only becomes useful if Mirage
//! adopts a peer-to-peer (Salmon/rBridge-style) invite social graph - a
//! strategic pivot, not a wiring task. Kept because the crypto is correct and
//! reusable if that pivot ever happens; do not read it as a live capability.
//!
//! # What this is for
//!
//! Every trust-graph bridge distributor (rBridge, Salmon, ...) protects a
//! *different* privacy target and leaves one open: a seized invitee's device
//! carries a **mathematically non-repudiable proof of who vouched for them**. A
//! censor who scrapes or seizes many invite bundles can reconstruct the whole
//! vouching DAG, and a court can treat the artifact as evidence. This module
//! removes that artifact.
//!
//! A **designated-verifier signature** (Jakobsson-Sako-Impagliazzo, EUROCRYPT
//! 1996) convinces exactly ONE verifier - the invitee - that the inviter
//! vouched, while being **worthless to anyone else**: the invitee can forge a
//! signature indistinguishable from a genuine one, so a third party (who cannot
//! rule out that the invitee forged it) learns nothing. The construction here is
//! the standard Cramer-Damgård-Schoenmakers OR-proof (CRYPTO 1994): a
//! non-interactive proof of knowledge of *the inviter's secret OR the invitee's
//! secret*, bound to the invite via Fiat-Shamir.
//!
//! - **Genuine vouch** ([`vouch`]) - the inviter proves the OR using its own
//!   secret (real inviter branch, simulated invitee branch).
//! - **Forged vouch** ([`forge_vouch`]) - the invitee proves the SAME OR using
//!   its own secret (simulated inviter branch, real invitee branch). It
//!   [`verify_vouch`]s identically.
//!
//! Because the two are perfectly indistinguishable, a genuine vouch is not
//! transferable evidence. The invitee is still convinced (it knows it did not
//! forge this one), but no one else can be.
//!
//! # HONEST framing - what this does and does NOT buy
//!
//! It is NOT coercion resistance: under duress the invitee can simply name the
//! inviter. The real value is:
//! - **Anti-scaled-attribution.** A censor that harvests many invite bundles
//!   can no longer auto-build the vouching graph - every edge is forgeable by
//!   its own endpoint, so real and invitee-fabricated edges are identical.
//! - **Anti-legal-proof.** There is no court-grade artifact tying an inviter to
//!   an invitee.
//!
//! Two design constraints the CALLER must respect (they live in the invite
//! layer, not here):
//! 1. **Deniability requires the whole population to carry a proof.** If a vouch
//!    proof is optional, *carrying one* is itself the receipt. The invite format
//!    must make it default-on, or this buys nothing (the classic PGP/OTR
//!    "using-it-flags-you" trap).
//! 2. **Deniability covers the vouch, never the capability.** This proof must
//!    NOT be the thing that grants bridge access - an all-forgeable edge would
//!    let an invitee fabricate a whole upstream chain. Access must be gated by a
//!    separate, NON-deniable capability (Mirage already separates bootstrap
//!    tokens / the claim secret from the vouch signature; keep that split).
//!
//! # Not hand-rolled primitive crypto
//!
//! This composes the standard CDS OR-proof over `curve25519-dalek`'s audited
//! Ristretto prime-order group (no cofactor pitfalls) and SHA-512 for
//! Fiat-Shamir. No field/curve arithmetic is implemented here; only the
//! well-known protocol wiring.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Domain-separation label for the vouch-secret KDF.
const VOUCH_KEY_CONTEXT: &[u8] = b"mirage designated-verifier vouch key v1";
/// Domain-separation label for the Fiat-Shamir challenge hash.
const VOUCH_CHALLENGE_CONTEXT: &[u8] = b"mirage designated-verifier vouch challenge v1";

/// A vouching keypair over the Ristretto group. The secret scalar is derived
/// deterministically from a 32-byte seed (e.g. a party's discovery secret), so
/// no new key material has to be provisioned - the vouch public key is published
/// alongside the party's existing identity.
pub struct VouchKeypair {
    secret: Scalar,
    /// Compressed public point `secret * G`.
    pub public: [u8; 32],
}

impl VouchKeypair {
    /// Derive a keypair from a 32-byte seed. The seed is hashed (domain
    /// separated) into a scalar, so any high-entropy secret can seed it.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let secret = scalar_from_seed(seed);
        let public = (RISTRETTO_BASEPOINT_POINT * secret).compress().to_bytes();
        Self { secret, public }
    }
}

impl Drop for VouchKeypair {
    fn drop(&mut self) {
        // Wipe the long-term vouch secret on drop so it doesn't linger in freed
        // memory (defence-in-depth against local disclosure).
        self.secret.zeroize();
    }
}

/// A non-interactive OR-proof: knowledge of the dlog of `p0` OR `p1`, bound to a
/// message. 128 bytes on the wire (`c0 || c1 || s0 || s1`, each a 32-byte
/// canonical scalar). The verifier recomputes the commitments, so they are not
/// transmitted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VouchProof {
    c0: [u8; 32],
    c1: [u8; 32],
    s0: [u8; 32],
    s1: [u8; 32],
}

/// Wire length of a serialized [`VouchProof`].
pub const VOUCH_PROOF_LEN: usize = 128;

impl VouchProof {
    /// Serialize to 128 wire bytes: `c0 || c1 || s0 || s1`.
    pub fn to_bytes(&self) -> [u8; VOUCH_PROOF_LEN] {
        let mut out = [0u8; VOUCH_PROOF_LEN];
        out[0..32].copy_from_slice(&self.c0);
        out[32..64].copy_from_slice(&self.c1);
        out[64..96].copy_from_slice(&self.s0);
        out[96..128].copy_from_slice(&self.s1);
        out
    }

    /// Parse from wire bytes. Does not validate scalar canonicality here; that
    /// happens in [`verify_vouch`], which rejects a non-canonical proof.
    pub fn from_bytes(b: &[u8; VOUCH_PROOF_LEN]) -> Self {
        let mut p = Self {
            c0: [0u8; 32],
            c1: [0u8; 32],
            s0: [0u8; 32],
            s1: [0u8; 32],
        };
        p.c0.copy_from_slice(&b[0..32]);
        p.c1.copy_from_slice(&b[32..64]);
        p.s0.copy_from_slice(&b[64..96]);
        p.s1.copy_from_slice(&b[96..128]);
        p
    }
}

/// Produce a **genuine** designated-verifier vouch: the inviter attests, to the
/// designated verifier (invitee), that it vouches for `binding` (an
/// invite-specific message, e.g. a hash of the invite's non-deniable fields).
///
/// `binding` MUST commit the proof to this specific invite so a vouch can't be
/// lifted onto another invite. The proof [`verify_vouch`]s under
/// `(inviter.public, invitee_public)`; the invitee can also [`forge_vouch`] an
/// indistinguishable one, which is exactly why the genuine proof is not
/// transferable evidence.
pub fn vouch(
    inviter: &VouchKeypair,
    invitee_public: &[u8; 32],
    binding: &[u8],
) -> Option<VouchProof> {
    let p_inviter = decompress(&inviter.public)?;
    let p_invitee = decompress(invitee_public)?;
    Some(or_prove(
        &inviter.secret,
        0,
        &p_inviter,
        &p_invitee,
        binding,
    ))
}

/// Produce a **forged** vouch as the invitee: proves the SAME statement using
/// the invitee's own secret. Indistinguishable from [`vouch`] to everyone except
/// the invitee itself - the property that makes a genuine vouch non-transferable.
pub fn forge_vouch(
    invitee: &VouchKeypair,
    inviter_public: &[u8; 32],
    binding: &[u8],
) -> Option<VouchProof> {
    let p_inviter = decompress(inviter_public)?;
    let p_invitee = decompress(&invitee.public)?;
    Some(or_prove(
        &invitee.secret,
        1,
        &p_inviter,
        &p_invitee,
        binding,
    ))
}

/// Verify a vouch proof against `(inviter_public, invitee_public, binding)`.
/// Returns `true` iff the proof is a valid OR-proof for one of the two secrets.
/// A genuine vouch and an invitee-forged vouch both verify - that is the point.
pub fn verify_vouch(
    inviter_public: &[u8; 32],
    invitee_public: &[u8; 32],
    binding: &[u8],
    proof: &VouchProof,
) -> bool {
    let (Some(p0), Some(p1)) = (decompress(inviter_public), decompress(invitee_public)) else {
        return false;
    };
    or_verify(&p0, &p1, binding, proof)
}

// Core CDS OR-proof over Ristretto

/// Prove knowledge of the dlog of `p[witness_index]`, where `witness` is that
/// dlog, bound to `msg`. The other branch is simulated. Standard CDS OR-proof.
fn or_prove(
    witness: &Scalar,
    witness_index: u8,
    p0: &RistrettoPoint,
    p1: &RistrettoPoint,
    msg: &[u8],
) -> VouchProof {
    let g = RISTRETTO_BASEPOINT_POINT;
    let p_sim = if witness_index == 0 { p1 } else { p0 };

    // Simulated branch: choose (c_sim, s_sim) freely, back out its commitment
    // R_sim = s_sim*G - c_sim*P_sim so the verification equation holds.
    let mut c_sim = random_scalar();
    let mut s_sim = random_scalar();
    let r_sim = g * s_sim - p_sim * c_sim;

    // Real branch: honest Schnorr commitment R_real = k*G.
    let mut k = random_scalar();
    let r_real = g * k;

    // Order the commitments (R0, R1) for the transcript, then derive the total
    // challenge and split it so c0 + c1 == c.
    let (r0, r1) = if witness_index == 0 {
        (r_real, r_sim)
    } else {
        (r_sim, r_real)
    };
    let c = challenge(p0, p1, msg, &r0, &r1);
    let mut c_real = c - c_sim;
    let mut s_real = k + c_real * witness;

    let (c0, c1, s0, s1) = if witness_index == 0 {
        (c_real, c_sim, s_real, s_sim)
    } else {
        (c_sim, c_real, s_sim, s_real)
    };
    let proof = VouchProof {
        c0: c0.to_bytes(),
        c1: c1.to_bytes(),
        s0: s0.to_bytes(),
        s1: s1.to_bytes(),
    };
    // Wipe the secret-bearing scalars. `k` is the Schnorr nonce and `s_real`
    // the real response; together they reveal the witness `x = (s_real-k)/c_real`,
    // so both MUST be cleared. `Scalar` is `Copy`, so this only wipes these
    // bindings (best-effort defence-in-depth against local memory disclosure).
    k.zeroize();
    s_real.zeroize();
    c_real.zeroize();
    c_sim.zeroize();
    s_sim.zeroize();
    proof
}

/// Verify the CDS OR-proof: recompute both commitments and check the challenge
/// split. Constant-time on the final scalar comparison.
fn or_verify(p0: &RistrettoPoint, p1: &RistrettoPoint, msg: &[u8], proof: &VouchProof) -> bool {
    let g = RISTRETTO_BASEPOINT_POINT;
    let (Some(c0), Some(c1), Some(s0), Some(s1)) = (
        canonical_scalar(&proof.c0),
        canonical_scalar(&proof.c1),
        canonical_scalar(&proof.s0),
        canonical_scalar(&proof.s1),
    ) else {
        // Non-canonical scalar encoding: reject (malleability guard).
        return false;
    };
    // R_i = s_i*G - c_i*P_i must reproduce the commitments the challenge hashed.
    let r0 = g * s0 - p0 * c0;
    let r1 = g * s1 - p1 * c1;
    let c = challenge(p0, p1, msg, &r0, &r1);
    // Accept iff c0 + c1 == c (constant-time).
    (c0 + c1).to_bytes().ct_eq(&c.to_bytes()).into()
}

/// Fiat-Shamir challenge: `H(ctx || P0 || P1 || len(msg) || msg || R0 || R1)`
/// reduced mod the group order. The message is length-prefixed so the transcript
/// is unambiguous.
fn challenge(
    p0: &RistrettoPoint,
    p1: &RistrettoPoint,
    msg: &[u8],
    r0: &RistrettoPoint,
    r1: &RistrettoPoint,
) -> Scalar {
    let mut h = Sha512::new();
    h.update(VOUCH_CHALLENGE_CONTEXT);
    h.update(p0.compress().as_bytes());
    h.update(p1.compress().as_bytes());
    h.update((msg.len() as u64).to_le_bytes());
    h.update(msg);
    h.update(r0.compress().as_bytes());
    h.update(r1.compress().as_bytes());
    Scalar::from_bytes_mod_order_wide(&h.finalize().into())
}

/// Derive a scalar from a 32-byte seed via a domain-separated SHA-512, reduced
/// mod the group order (wide reduction -> negligible bias).
fn scalar_from_seed(seed: &[u8; 32]) -> Scalar {
    let mut h = Sha512::new();
    h.update(VOUCH_KEY_CONTEXT);
    h.update(seed);
    Scalar::from_bytes_mod_order_wide(&h.finalize().into())
}

/// A uniformly random scalar from the OS CSPRNG (64 bytes -> wide reduction).
fn random_scalar() -> Scalar {
    let mut wide = [0u8; 64];
    // getrandom is the same OS CSPRNG the rest of the crate uses. A failure here
    // is unrecoverable for a proof, so panic rather than emit a weak proof.
    getrandom::fill(&mut wide).expect("OS CSPRNG for vouch proof");
    let s = Scalar::from_bytes_mod_order_wide(&wide);
    wide.zeroize();
    s
}

/// Parse a 32-byte canonical scalar, rejecting non-canonical encodings (which a
/// malleability attacker could otherwise use to produce a second valid form).
fn canonical_scalar(b: &[u8; 32]) -> Option<Scalar> {
    Scalar::from_canonical_bytes(*b).into()
}

/// Decompress a Ristretto public point, rejecting invalid encodings AND the
/// identity point. The identity has dlog 0, so anyone could satisfy its OR
/// branch; rejecting it here means neither `vouch`/`forge_vouch` nor
/// `verify_vouch` will ever treat an all-zero (identity) key as a valid party,
/// even if an attacker publishes one as their own.
fn decompress(b: &[u8; 32]) -> Option<RistrettoPoint> {
    let p = CompressedRistretto(*b).decompress()?;
    if p == RistrettoPoint::identity() {
        return None;
    }
    Some(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn genuine_vouch_verifies() {
        let inviter = VouchKeypair::from_seed(&seed(1));
        let invitee = VouchKeypair::from_seed(&seed(2));
        let proof = vouch(&inviter, &invitee.public, b"invite-binding").unwrap();
        assert!(verify_vouch(
            &inviter.public,
            &invitee.public,
            b"invite-binding",
            &proof
        ));
    }

    #[test]
    fn invitee_forged_vouch_also_verifies() {
        // The whole point: the designated verifier (invitee) can forge a proof
        // indistinguishable from a genuine one -> the genuine one is not evidence.
        let inviter = VouchKeypair::from_seed(&seed(1));
        let invitee = VouchKeypair::from_seed(&seed(2));
        let forged = forge_vouch(&invitee, &inviter.public, b"invite-binding").unwrap();
        assert!(verify_vouch(
            &inviter.public,
            &invitee.public,
            b"invite-binding",
            &forged
        ));
    }

    #[test]
    fn genuine_and_forged_are_observationally_equivalent() {
        // Both proofs are the same 128-byte object type and both verify under
        // the same statement, so a third party cannot tell them apart by shape.
        // (PERFECT witness-indistinguishability - that the two are drawn from the
        // IDENTICAL distribution - is a proven property of the CDS construction,
        // not something a finite test can establish; see the module docs.) They
        // ARE distinct objects (independent randomness), so neither is a
        // degenerate constant.
        let inviter = VouchKeypair::from_seed(&seed(7));
        let invitee = VouchKeypair::from_seed(&seed(8));
        let g = vouch(&inviter, &invitee.public, b"m").unwrap();
        let f = forge_vouch(&invitee, &inviter.public, b"m").unwrap();
        assert_eq!(g.to_bytes().len(), f.to_bytes().len());
        assert_ne!(g, f, "independent randomness => distinct proofs");
        assert!(verify_vouch(&inviter.public, &invitee.public, b"m", &g));
        assert!(verify_vouch(&inviter.public, &invitee.public, b"m", &f));
    }

    #[test]
    fn pair_swap_does_not_verify() {
        // Binding to the ORDERED pair: a proof for (inviter, invitee) must not
        // verify under the swapped pair (invitee, inviter).
        let inviter = VouchKeypair::from_seed(&seed(1));
        let invitee = VouchKeypair::from_seed(&seed(2));
        let proof = vouch(&inviter, &invitee.public, b"m").unwrap();
        assert!(!verify_vouch(
            &invitee.public,
            &inviter.public,
            b"m",
            &proof
        ));
    }

    #[test]
    fn transposed_proof_rejected() {
        // Swapping c0<->c1 and s0<->s1 must not yield a second valid proof for
        // the same (ordered) statement - the challenge binds each branch to its
        // own P and R.
        let inviter = VouchKeypair::from_seed(&seed(1));
        let invitee = VouchKeypair::from_seed(&seed(2));
        let good = vouch(&inviter, &invitee.public, b"m").unwrap();
        let transposed = VouchProof {
            c0: good.c1,
            c1: good.c0,
            s0: good.s1,
            s1: good.s0,
        };
        assert!(!verify_vouch(
            &inviter.public,
            &invitee.public,
            b"m",
            &transposed
        ));
    }

    #[test]
    fn non_canonical_scalar_rejected() {
        // A non-canonical scalar encoding (>= group order) must be rejected, so a
        // malleability attacker can't present a second wire form of a valid proof.
        let inviter = VouchKeypair::from_seed(&seed(1));
        let invitee = VouchKeypair::from_seed(&seed(2));
        let good = vouch(&inviter, &invitee.public, b"m").unwrap();
        let mut mauled = good;
        mauled.c0 = [0xFFu8; 32]; // > L, non-canonical
        assert!(!verify_vouch(
            &inviter.public,
            &invitee.public,
            b"m",
            &mauled
        ));
    }

    #[test]
    fn identity_pubkey_rejected() {
        // The Ristretto identity (all-zero encoding) has dlog 0; it must never be
        // accepted as a party (else its OR branch is trivially satisfiable).
        let real = VouchKeypair::from_seed(&seed(1));
        let identity = [0u8; 32];
        assert!(vouch(&real, &identity, b"m").is_none());
        assert!(forge_vouch(&real, &identity, b"m").is_none());
        let proof = vouch(&real, &real.public, b"m").unwrap();
        assert!(!verify_vouch(&identity, &real.public, b"m", &proof));
        assert!(!verify_vouch(&real.public, &identity, b"m", &proof));
    }

    #[test]
    fn tampered_binding_fails() {
        let inviter = VouchKeypair::from_seed(&seed(1));
        let invitee = VouchKeypair::from_seed(&seed(2));
        let proof = vouch(&inviter, &invitee.public, b"binding-A").unwrap();
        assert!(!verify_vouch(
            &inviter.public,
            &invitee.public,
            b"binding-B",
            &proof
        ));
    }

    #[test]
    fn wrong_keys_fail() {
        let inviter = VouchKeypair::from_seed(&seed(1));
        let invitee = VouchKeypair::from_seed(&seed(2));
        let stranger = VouchKeypair::from_seed(&seed(3));
        let proof = vouch(&inviter, &invitee.public, b"m").unwrap();
        // Neither public key matches -> must not verify.
        assert!(!verify_vouch(
            &stranger.public,
            &invitee.public,
            b"m",
            &proof
        ));
        assert!(!verify_vouch(
            &inviter.public,
            &stranger.public,
            b"m",
            &proof
        ));
    }

    #[test]
    fn soundness_random_proof_fails() {
        // A party holding NEITHER secret cannot forge: a random 128-byte proof
        // must not verify (overwhelming probability; deterministic seeds here).
        let inviter = VouchKeypair::from_seed(&seed(1));
        let invitee = VouchKeypair::from_seed(&seed(2));
        let junk = VouchProof::from_bytes(&[0x11u8; VOUCH_PROOF_LEN]);
        assert!(!verify_vouch(&inviter.public, &invitee.public, b"m", &junk));
    }

    #[test]
    fn bit_flip_in_proof_fails() {
        let inviter = VouchKeypair::from_seed(&seed(4));
        let invitee = VouchKeypair::from_seed(&seed(5));
        let good = vouch(&inviter, &invitee.public, b"m").unwrap();
        let mut b = good.to_bytes();
        b[100] ^= 0x01;
        let bad = VouchProof::from_bytes(&b);
        assert!(!verify_vouch(&inviter.public, &invitee.public, b"m", &bad));
    }

    #[test]
    fn proof_roundtrips_through_bytes() {
        let inviter = VouchKeypair::from_seed(&seed(1));
        let invitee = VouchKeypair::from_seed(&seed(2));
        let proof = vouch(&inviter, &invitee.public, b"m").unwrap();
        let back = VouchProof::from_bytes(&proof.to_bytes());
        assert_eq!(proof, back);
        assert!(verify_vouch(&inviter.public, &invitee.public, b"m", &back));
    }

    #[test]
    fn keypair_is_deterministic_from_seed() {
        let a = VouchKeypair::from_seed(&seed(9));
        let b = VouchKeypair::from_seed(&seed(9));
        assert_eq!(a.public, b.public);
        let c = VouchKeypair::from_seed(&seed(10));
        assert_ne!(a.public, c.public);
    }
}
