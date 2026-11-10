//! Forward-secret rendezvous ratchet.
//!
//! # The gap this closes
//!
//! The baseline discovery derivation ([`crate::derive`]) computes each epoch's
//! `info_hash` + `cipher_key` DIRECTLY from the long-term `shared_salt`:
//! `key(epoch) = KDF(salt, namespace, epoch)`. An adversary who later
//! compromises the salt (a seized device, a leaked invite) can therefore
//! recompute EVERY past epoch's rendezvous point and decrypt every archived
//! announcement - there is no forward secrecy across epochs.
//!
//! # The ratchet
//!
//! This module derives the per-epoch secret from a one-way forward hash chain
//! instead of directly from the salt:
//!
//! ```text
//! c(e0)   = KDF(salt, namespace, e0)          // anchor at a chosen epoch e0
//! c(n)    = H("step" || c(n-1))               // one forward step per epoch
//! prk(n)  = c(n)                              // per-epoch root secret
//! ```
//!
//! `H` is preimage-resistant (BLAKE3), so from `c(n)` you cannot recover
//! `c(n-1)`. A party that advances the chain and ZEROIZES the consumed states
//! (and the salt/anchor) can no longer recompute past epochs even if its current
//! state is seized - **forward secrecy for the rendezvous**.
//!
//! # Interop
//!
//! The per-epoch key is a pure function of `(salt, namespace, anchor_epoch,
//! epoch)` ([`fs_prk`]), so a publisher driving a stateful [`RendezvousRatchet`]
//! (holding only the current chain state) and a fetcher re-deriving from the
//! salt compute IDENTICAL keys and interoperate. Forward secrecy is gained only
//! by a party that discards the salt/anchor after seeding; the ratchet type
//! enables that discipline but does not force it, so a fetcher that keeps the
//! invite still decrypts correctly.
//!
//! Anchoring at the invite's issue epoch bounds the fetcher's catch-up iteration
//! to the invite lifetime (weeks -> at most a few thousand steps), so re-derivation
//! stays sub-millisecond.

use mirage_crypto::blake3;
use mirage_crypto::zeroize::{Zeroize, Zeroizing};

use crate::derive::{CIPHER_KEY_LEN, CIPHER_NONCE_LEN, INFO_HASH_LEN};

/// `derive_key` context for the ratchet anchor. Domain-separated from every
/// baseline `mirage-*-v1` derivation so a ratchet key can never collide with a
/// direct-derivation key for the same coordinates.
const FS_ANCHOR_CTX: &str = "mirage rendezvous fs anchor v1";
/// Per-step hashing prefix.
const FS_STEP_CTX: &[u8] = b"mirage-rendezvous-fs-step-v1";
/// Output-shaping tags (distinct from the baseline `-v1` tags).
const FS_INFO_HASH_CTX: &[u8] = b"mirage-info-hash-fs-v1";
const FS_CIPHER_KEY_CTX: &[u8] = b"mirage-cipher-key-fs-v1";
const FS_CIPHER_NONCE_CTX: &[u8] = b"mirage-cipher-nonce-fs-v1";

/// Maximum forward catch-up steps in a single [`fs_prk`] re-derivation. Invites
/// are time-bounded (weeks), so a real `epoch - anchor_epoch` delta is at most a
/// few thousand; this generous ceiling (~11 years of hourly epochs) only guards
/// against an absurd/hostile epoch value turning a derivation into a DoS.
pub const MAX_RATCHET_STEPS: u64 = 100_000;

/// Derive the anchor chain state `c(e0)` for `(salt, namespace, anchor_epoch)`.
fn fs_anchor(shared_salt: &[u8; 32], namespace: &[u8], anchor_epoch: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(FS_ANCHOR_CTX);
    h.update(shared_salt);
    h.update(namespace);
    h.update(&anchor_epoch.to_be_bytes());
    *h.finalize().as_bytes()
}

/// One forward ratchet step: `c(n+1) = H(step_ctx || c(n))`.
fn fs_step(chain: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(FS_STEP_CTX);
    h.update(chain);
    *h.finalize().as_bytes()
}

/// Advance `chain` forward `steps` times in place, zeroizing each consumed
/// intermediate so no past state lingers on the stack.
fn advance_chain(chain: &mut [u8; 32], steps: u64) {
    for _ in 0..steps {
        let mut next = fs_step(chain);
        chain.copy_from_slice(&next);
        next.zeroize();
    }
}

/// Per-epoch root secret (the chain state at `epoch`), re-derived from the salt.
///
/// Returns `None` if `epoch < anchor_epoch` (the chain has no past) or the
/// forward delta exceeds [`MAX_RATCHET_STEPS`]. The result is zeroized on drop.
pub fn fs_prk(
    shared_salt: &[u8; 32],
    namespace: &[u8],
    anchor_epoch: u64,
    epoch: u64,
) -> Option<Zeroizing<[u8; 32]>> {
    let steps = epoch.checked_sub(anchor_epoch)?;
    if steps > MAX_RATCHET_STEPS {
        return None;
    }
    let mut chain = Zeroizing::new(fs_anchor(shared_salt, namespace, anchor_epoch));
    advance_chain(&mut chain, steps);
    Some(chain)
}

/// Info-hash for a ratchet chain state (matches the 20-byte baseline shape).
fn info_hash_from_prk(prk: &[u8; 32]) -> [u8; INFO_HASH_LEN] {
    let mut h = blake3::Hasher::new_keyed(prk);
    h.update(FS_INFO_HASH_CTX);
    let full = h.finalize();
    let mut out = [0u8; INFO_HASH_LEN];
    out.copy_from_slice(&full.as_bytes()[..INFO_HASH_LEN]);
    out
}

/// ChaCha20-Poly1305 key for a ratchet chain state.
fn cipher_key_from_prk(prk: &[u8; 32]) -> [u8; CIPHER_KEY_LEN] {
    let mut h = blake3::Hasher::new_keyed(prk);
    h.update(FS_CIPHER_KEY_CTX);
    *h.finalize().as_bytes()
}

/// ChaCha20-Poly1305 nonce for a ratchet chain state.
fn cipher_nonce_from_prk(prk: &[u8; 32]) -> [u8; CIPHER_NONCE_LEN] {
    let mut h = blake3::Hasher::new_keyed(prk);
    h.update(FS_CIPHER_NONCE_CTX);
    let full = h.finalize();
    let mut out = [0u8; CIPHER_NONCE_LEN];
    out.copy_from_slice(&full.as_bytes()[..CIPHER_NONCE_LEN]);
    out
}

/// Forward-secret per-epoch `info_hash`, re-derived from the salt. `None` for a
/// pre-anchor or out-of-range epoch (see [`fs_prk`]).
pub fn fs_info_hash(
    shared_salt: &[u8; 32],
    namespace: &[u8],
    anchor_epoch: u64,
    epoch: u64,
) -> Option<[u8; INFO_HASH_LEN]> {
    fs_prk(shared_salt, namespace, anchor_epoch, epoch).map(|prk| info_hash_from_prk(&prk))
}

/// Forward-secret per-epoch ChaCha20-Poly1305 key, re-derived from the salt.
pub fn fs_cipher_key(
    shared_salt: &[u8; 32],
    namespace: &[u8],
    anchor_epoch: u64,
    epoch: u64,
) -> Option<Zeroizing<[u8; CIPHER_KEY_LEN]>> {
    fs_prk(shared_salt, namespace, anchor_epoch, epoch)
        .map(|prk| Zeroizing::new(cipher_key_from_prk(&prk)))
}

/// A live forward-secret rendezvous ratchet holding ONLY the current epoch's
/// chain state.
///
/// A publisher seeds one at startup, immediately zeroizes its own copy of the
/// salt, and calls [`Self::advance_to`] each epoch. Because a consumed state
/// cannot be inverted, a seizure of the ratchet at epoch `n` cannot recompute
/// the `info_hash`/`cipher_key` of any epoch `< n` - the publisher's past
/// announcements (which a censor may have archived) stay confidential.
pub struct RendezvousRatchet {
    anchor_epoch: u64,
    epoch: u64,
    chain: Zeroizing<[u8; 32]>,
}

/// Error advancing a [`RendezvousRatchet`].
#[derive(Debug, PartialEq, Eq)]
pub enum RatchetError {
    /// Requested a target epoch before the ratchet's current epoch. A one-way
    /// ratchet cannot go backward - that is the whole forward-secrecy point.
    Backward,
    /// The forward delta exceeded [`MAX_RATCHET_STEPS`].
    TooFar,
}

impl RendezvousRatchet {
    /// Seed a ratchet at `anchor_epoch` from `shared_salt`. The caller SHOULD
    /// zeroize its own salt copy afterwards to gain forward secrecy; the ratchet
    /// never retains the salt.
    pub fn seed(shared_salt: &[u8; 32], namespace: &[u8], anchor_epoch: u64) -> Self {
        // The namespace is folded into the anchor here and not retained: the
        // chain is namespace-specific from seeding onward.
        Self {
            anchor_epoch,
            epoch: anchor_epoch,
            chain: Zeroizing::new(fs_anchor(shared_salt, namespace, anchor_epoch)),
        }
    }

    /// Advance forward to `target`, zeroizing every consumed state. A no-op if
    /// `target == epoch`. Refuses to move backward or beyond the step ceiling.
    pub fn advance_to(&mut self, target: u64) -> Result<(), RatchetError> {
        if target < self.epoch {
            return Err(RatchetError::Backward);
        }
        let steps = target - self.epoch;
        if steps > MAX_RATCHET_STEPS {
            return Err(RatchetError::TooFar);
        }
        advance_chain(&mut self.chain, steps);
        self.epoch = target;
        Ok(())
    }

    /// The epoch this ratchet is currently positioned at.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The anchor epoch this ratchet was seeded at.
    pub fn anchor_epoch(&self) -> u64 {
        self.anchor_epoch
    }

    /// Current epoch's `info_hash`.
    pub fn info_hash(&self) -> [u8; INFO_HASH_LEN] {
        info_hash_from_prk(&self.chain)
    }

    /// Current epoch's ChaCha20-Poly1305 key (zeroized on drop).
    pub fn cipher_key(&self) -> Zeroizing<[u8; CIPHER_KEY_LEN]> {
        Zeroizing::new(cipher_key_from_prk(&self.chain))
    }

    /// Current epoch's ChaCha20-Poly1305 nonce base.
    pub fn cipher_nonce(&self) -> [u8; CIPHER_NONCE_LEN] {
        cipher_nonce_from_prk(&self.chain)
    }

    /// Peek the `(info_hash, cipher_key)` for a current-or-FUTURE `epoch`
    /// (`>= self.epoch`) WITHOUT advancing the ratchet.
    ///
    /// A publisher advances its floor to the current epoch (deleting past state)
    /// and must ALSO seal for the next epoch; this walks a transient forward copy
    /// (zeroized) to that epoch. Returns `None` for a PAST epoch (a one-way
    /// ratchet has no past - that is the forward-secrecy guarantee) or an epoch
    /// beyond [`MAX_RATCHET_STEPS`]. The peeked key equals what a salt-holding
    /// fetcher derives via [`fs_cipher_key`], so producer and consumer agree.
    pub fn key_at(
        &self,
        epoch: u64,
    ) -> Option<([u8; INFO_HASH_LEN], Zeroizing<[u8; CIPHER_KEY_LEN]>)> {
        let steps = epoch.checked_sub(self.epoch)?;
        if steps > MAX_RATCHET_STEPS {
            return None;
        }
        let mut chain = Zeroizing::new(*self.chain);
        advance_chain(&mut chain, steps);
        Some((
            info_hash_from_prk(&chain),
            Zeroizing::new(cipher_key_from_prk(&chain)),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NS: &[u8] = b"mirage-namespace-c2b-v1";

    fn salt() -> [u8; 32] {
        *b"0123456789abcdef0123456789abcdef"
    }

    #[test]
    fn ratchet_and_rederivation_agree() {
        // A stateful ratchet advanced to epoch e must produce the SAME key a
        // fetcher gets by re-deriving from the salt - else they can't rendezvous.
        let mut r = RendezvousRatchet::seed(&salt(), NS, 1000);
        r.advance_to(1005).unwrap();
        assert_eq!(r.epoch(), 1005);
        let via_salt = fs_info_hash(&salt(), NS, 1000, 1005).unwrap();
        assert_eq!(r.info_hash(), via_salt);
        assert_eq!(
            *r.cipher_key(),
            *fs_cipher_key(&salt(), NS, 1000, 1005).unwrap()
        );
    }

    #[test]
    fn each_epoch_key_is_distinct() {
        let e5 = fs_info_hash(&salt(), NS, 1000, 1005).unwrap();
        let e6 = fs_info_hash(&salt(), NS, 1000, 1006).unwrap();
        assert_ne!(
            e5, e6,
            "consecutive epochs must have independent rendezvous"
        );
    }

    #[test]
    fn forward_secrecy_current_state_cannot_reach_past() {
        // The core FS property: from the ratchet state at epoch n there is no
        // API (and no algorithm - H is one-way) to obtain epoch n-1's key. We
        // assert the ratchet REFUSES to go backward, and that the forward-only
        // state at n differs from the (separately salt-derived) n-1 key.
        let mut r = RendezvousRatchet::seed(&salt(), NS, 1000);
        r.advance_to(1010).unwrap();
        assert_eq!(r.advance_to(1009), Err(RatchetError::Backward));
        // The current state's key is not the past key (sanity: forward != back).
        let past = fs_cipher_key(&salt(), NS, 1000, 1009).unwrap();
        assert_ne!(*r.cipher_key(), *past);
    }

    #[test]
    fn namespaces_do_not_cross_contaminate() {
        let c2b = fs_info_hash(&salt(), b"mirage-namespace-c2b-v1", 1000, 1005).unwrap();
        let b2b = fs_info_hash(&salt(), b"mirage-namespace-b2b-v1", 1000, 1005).unwrap();
        assert_ne!(c2b, b2b);
    }

    #[test]
    fn fs_keys_differ_from_baseline_direct_derivation() {
        // The ratchet is domain-separated from the baseline direct derivation:
        // for the same coordinates the two derivations MUST differ, so enabling
        // FS mode is an unambiguous, non-colliding wire change.
        let fs = fs_info_hash(&salt(), NS, 1000, 1000).unwrap();
        let base = crate::derive::info_hash(&salt(), NS, 1000);
        assert_ne!(fs, base);
    }

    #[test]
    fn pre_anchor_and_too_far_are_rejected() {
        assert!(fs_prk(&salt(), NS, 1000, 999).is_none(), "pre-anchor");
        assert!(
            fs_prk(&salt(), NS, 0, MAX_RATCHET_STEPS + 1).is_none(),
            "beyond step ceiling"
        );
        let mut r = RendezvousRatchet::seed(&salt(), NS, 0);
        assert_eq!(
            r.advance_to(MAX_RATCHET_STEPS + 1),
            Err(RatchetError::TooFar)
        );
    }

    #[test]
    fn advance_is_incremental_and_idempotent_at_same_epoch() {
        // Advancing in two hops lands on the same state as one hop.
        let mut a = RendezvousRatchet::seed(&salt(), NS, 100);
        a.advance_to(103).unwrap();
        a.advance_to(107).unwrap();
        let mut b = RendezvousRatchet::seed(&salt(), NS, 100);
        b.advance_to(107).unwrap();
        assert_eq!(a.info_hash(), b.info_hash());
        // Re-advancing to the current epoch is a no-op.
        a.advance_to(107).unwrap();
        assert_eq!(a.info_hash(), b.info_hash());
    }
}
