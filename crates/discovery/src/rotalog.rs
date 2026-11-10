//! RotaLog - ledger-anchored operator key-transparency log.
//!
//! # Why this exists (anti-takedown, no node disclosure)
//!
//! Mirage's discovery channels are explicitly **untrusted** (see
//! [`crate::channel`]): a hostile or coerced relay can withhold, reorder,
//! or inject blobs. The one blob a censor most wants to forge is an
//! **operator key rotation** - if a client can be tricked into accepting
//! an attacker-controlled `operator_ed25519_pk`, the attacker can then
//! sign malicious announcements and route the user to hostile bridges.
//! Today the only defense is the mother-key pin
//! ([`crate::invite::SIGNING_POLICY_MOTHER_PINNED`]); but that still
//! leaves two gaps a powerful adversary exploits:
//!
//! - **Equivocation / split view.** A censor feeds different clients
//!   different "current" operator keys (a fork), or feeds an isolated
//!   client a fabricated rotation it never shows anyone else.
//! - **Rollback.** A censor replays an *old, since-compromised* rotation
//!   to walk a client back to a key the attacker has the secret for.
//!
//! RotaLog closes both by combining **two independent roots of trust**:
//!
//! - **Authenticity comes from a signature**, NOT from the ledger. Every
//!   checkpoint is signed by the operator's **mother key**, pinned
//!   out-of-band in the invite
//!   ([`crate::invite::SIGNING_POLICY_MOTHER_PINNED`] /
//!   [`crate::invite::INVITE_EXT_MOTHER_ED25519_PK`]). An adversary
//!   without the mother secret cannot produce a checkpoint a client will
//!   accept, *no matter what it writes on-chain* - and cannot re-package
//!   an old rotation at a new sequence number, because the signature
//!   covers the sequence number.
//! - **Ordering + non-equivocation come from the ledger.** Per operator
//!   the chain stores a single rolling 32-byte **head commitment** - the
//!   tip of a hash-chain of checkpoints. Because the ledger is globally
//!   consistent, a (possibly compromised) operator cannot equivocate -
//!   show different clients different signed rotations at the same
//!   sequence - without the off-chain document failing to match the one
//!   anchored head, and a censor cannot roll a client back because the
//!   signed sequence number only ever moves forward.
//!
//! Neither root alone suffices: the signature without the ledger permits
//! equivocation/rollback by a compromised operator; the ledger without
//! the signature permits a ledger-writing censor to forge any head
//! (a hash of attacker-chosen bytes is not authentication). **Both are
//! required**, and `check` enforces signature-first, then ledger.
//!
//! # The no-node-disclosure invariant
//!
//! **Nothing in the on-chain data model is a node address, a bridge key,
//! or a cleartext operator key.** A checkpoint head is
//! `BLAKE3(prev_head || seq || commitment)`, where `commitment` is a hash
//! of the *sealed* (already-encrypted) rotation document. A ledger
//! observer sees an opaque 32-byte value per operator-epoch and learns
//! only "some operator rotated" - never where any bridge is. This is the
//! BORROW-realism path: ride a real chain's availability + immutability +
//! global consistency; put only ciphertext and commitments on it.
//!
//! # What this module is (and is not, yet)
//!
//! This is the substrate-agnostic **core**: the checkpoint hash-chain,
//! the [`AnchorBackend`] trait with an in-memory implementation for
//! tests, and the [`RotaLogState`] verifier that returns an advisory
//! [`RotaVerdict`]. It is deliberately I/O-free on the hot path and is
//! NOT yet wired into the live rotation-acceptance flow. Follow-ups
//! (each its own increment): a real `AnchorBackend` over an EVM L2 /
//! Bitcoin-anchor; relayer-based anonymized publishing; and binding the
//! verifier into the [`crate::wire::DOC_TYPE_ROTATION_MOTHER`] (0x41)
//! acceptance path, gated on `SIGNING_POLICY_MOTHER_PINNED`.

use async_trait::async_trait;
use mirage_crypto::blake3;
use mirage_crypto::ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

/// Domain tag for the checkpoint head derivation.
const HEAD_DOMAIN: &[u8] = b"mirage-rotalog-head-v1";
/// Domain tag for the bytes the mother key signs (binds seq+chain+doc).
const SIGN_DOMAIN: &[u8] = b"mirage-rotalog-checkpoint-sig-v1";
/// Domain tag for the commitment over a sealed rotation document.
const COMMIT_DOMAIN: &[u8] = b"mirage-rotalog-doc-commit-v1";
/// Domain tag for the per-operator anchor key (the ledger lookup key).
const ANCHOR_KEY_DOMAIN: &[u8] = b"mirage-rotalog-anchor-v1";

/// The predecessor of the very first checkpoint (`seq == 0`): all-zero.
pub const GENESIS_PREV_HEAD: [u8; 32] = [0u8; 32];

/// Per-operator ledger lookup key, derived from the operator's invite
/// `shared_salt`. This is the only stable identifier the ledger holds;
/// it identifies an operator's key-transparency log, never a node. It is
/// derived the same way as [`crate::derive::rotation_info_hash`] so it
/// aligns with the existing static rotation-poll rendezvous.
pub fn anchor_key(shared_salt: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(shared_salt);
    h.update(ANCHOR_KEY_DOMAIN);
    *h.finalize().as_bytes()
}

/// Commitment to a sealed (already-encrypted) rotation document. Binding
/// (a different document yields a different commitment) and hiding (the
/// input is ciphertext, opaque to anyone without the per-epoch seal key).
pub fn commit_doc(sealed_doc: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(COMMIT_DOMAIN);
    h.update(&(sealed_doc.len() as u64).to_be_bytes());
    h.update(sealed_doc);
    *h.finalize().as_bytes()
}

/// One link in an operator's rotation hash-chain. The fields are carried
/// inside the (signed, sealed) rotation document distributed off-chain;
/// the *head* is what gets anchored on-chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    /// Strictly increasing rotation sequence number. The first rotation
    /// is `seq == 0` with `prev_head == GENESIS_PREV_HEAD`.
    pub seq: u64,
    /// The head of the immediately preceding checkpoint (chains the log).
    pub prev_head: [u8; 32],
    /// Commitment to this rotation's sealed document ([`commit_doc`]).
    pub doc_commitment: [u8; 32],
}

impl Checkpoint {
    /// Build the checkpoint that commits to `sealed_doc` at `seq`,
    /// following `prev_head`.
    pub fn new(seq: u64, prev_head: [u8; 32], sealed_doc: &[u8]) -> Self {
        Self {
            seq,
            prev_head,
            doc_commitment: commit_doc(sealed_doc),
        }
    }

    /// The anchored head value: `BLAKE3(domain || prev_head || seq_be ||
    /// doc_commitment)`. This 32-byte value - and nothing else - is what
    /// the operator writes to the ledger for this rotation.
    pub fn head(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(HEAD_DOMAIN);
        h.update(&self.prev_head);
        h.update(&self.seq.to_be_bytes());
        h.update(&self.doc_commitment);
        *h.finalize().as_bytes()
    }

    /// The canonical bytes the operator's mother key signs. Binds the
    /// sequence number, the predecessor head, and the document commitment
    /// together, so a signature cannot be lifted onto a different
    /// sequence number or a different rotation document.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SIGN_DOMAIN.len() + 8 + 32 + 32);
        out.extend_from_slice(SIGN_DOMAIN);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.prev_head);
        out.extend_from_slice(&self.doc_commitment);
        out
    }
}

/// A [`Checkpoint`] endorsed by the operator's mother key. This is what a
/// client actually receives off-chain (inside the sealed rotation
/// document); the signature is the **authenticity** root, the on-chain
/// head is the **ordering/non-equivocation** root.
#[derive(Debug, Clone)]
pub struct SignedCheckpoint {
    /// The checkpoint being attested.
    pub checkpoint: Checkpoint,
    /// Ed25519 signature by the operator's mother key over
    /// [`Checkpoint::signing_bytes`].
    pub signature: [u8; 64],
}

impl SignedCheckpoint {
    /// Sign `checkpoint` with the operator's mother signing key
    /// (operator side; clients only verify).
    pub fn sign(checkpoint: Checkpoint, mother_sk: &SigningKey) -> Self {
        let signature = mother_sk.sign(&checkpoint.signing_bytes()).to_bytes();
        Self {
            checkpoint,
            signature,
        }
    }

    /// Verify the signature against `mother_pk`. Returns `true` iff the
    /// pinned mother key endorsed exactly these checkpoint bytes.
    pub fn verify(&self, mother_pk: &[u8; 32]) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(mother_pk) else {
            return false;
        };
        let sig = mirage_crypto::ed25519_dalek::Signature::from_bytes(&self.signature);
        vk.verify(&self.checkpoint.signing_bytes(), &sig).is_ok()
    }
}

/// The head currently anchored on the ledger for an operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchoredHead {
    /// The 32-byte head commitment.
    pub head: [u8; 32],
    /// The sequence number of the checkpoint that produced `head`.
    pub seq: u64,
}

/// Errors a ledger backend can raise. These are transport/availability
/// failures; a *missing* head is `Ok(None)`, not an error (mirrors
/// [`crate::channel::DiscoveryChannel::fetch`]).
#[derive(Debug, thiserror::Error)]
pub enum AnchorError {
    /// The ledger could not be reached (RPC down, timeout, etc.).
    #[error("anchor transport: {0}")]
    Transport(String),
    /// The backend refused a write (under-funded relayer, rate-limited).
    #[error("anchor refused: {0}")]
    Refused(String),
}

/// A pluggable ledger backend that stores one rolling head per
/// [`anchor_key`]. Object-safe so the client can hold a
/// `dyn AnchorBackend` chosen at runtime (in-memory for tests, an EVM L2
/// or Bitcoin anchor in production).
///
/// **Trust model:** the backend is NOT trusted to enforce monotonicity
/// or chaining - a real public ledger just stores whatever was written.
/// All continuity checks live client-side in [`RotaLogState::check`], so
/// a malicious or buggy backend cannot make a client accept a bad key; at
/// worst it returns a stale or absent head (-> `Regression`/`Unverifiable`).
#[async_trait]
pub trait AnchorBackend: Send + Sync {
    /// Read the currently-anchored head for `anchor_key`, or `None` if
    /// the operator has never anchored (or the entry is not yet visible).
    async fn get_head(&self, anchor_key: &[u8; 32]) -> Result<Option<AnchoredHead>, AnchorError>;

    /// Write `head` as the operator's current anchor. Operator/relayer
    /// side only; clients never call this.
    async fn put_head(&self, anchor_key: &[u8; 32], head: AnchoredHead) -> Result<(), AnchorError>;

    /// Stable identifier for diagnostics/metrics.
    fn name(&self) -> &'static str;
}

/// The advisory outcome of verifying a candidate rotation against the
/// ledger. Like [`mirage` adversary verdicts](crate), RotaLog never
/// silently trusts and never hard-blocks on its own - the caller decides
/// (e.g. refuse the rotation and alert the operator on `Equivocation` /
/// `Regression`; fetch intermediate checkpoints on `Gap`; fall back to
/// the existing mother-pin path on `Unverifiable`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotaVerdict {
    /// The rotation chains to the anchored head and the sequence number
    /// advances by exactly one. Safe to accept.
    Accept,
    /// The checkpoint is not signed by the pinned operator mother key (or
    /// the signature does not cover these exact bytes). The strongest
    /// attack signal: a fabricated rotation, regardless of what the
    /// ledger anchors. Checked FIRST, before any ledger comparison.
    Forged(String),
    /// The sequence number did not advance (`<=` last accepted). A
    /// rollback/replay to an older - possibly compromised - key.
    Regression(String),
    /// The candidate does not match what the ledger anchored, or claims
    /// to follow our last head but does not. A fork / split-view / forged
    /// rotation.
    Equivocation(String),
    /// The sequence number jumped forward by more than one: intermediate
    /// checkpoints are missing, so chain continuity cannot be confirmed
    /// yet. Not necessarily hostile - fetch the intermediates and retry.
    Gap(String),
    /// The ledger reported no head (operator never anchored, or the
    /// backend was unreachable). Cannot confirm; caller falls back.
    Unverifiable(String),
}

impl RotaVerdict {
    /// True iff the rotation may be accepted.
    pub fn is_accept(&self) -> bool {
        matches!(self, RotaVerdict::Accept)
    }
    /// True iff the verdict is an active attack signal (forgery,
    /// rollback, or fork).
    pub fn is_attack(&self) -> bool {
        matches!(
            self,
            RotaVerdict::Forged(_) | RotaVerdict::Regression(_) | RotaVerdict::Equivocation(_)
        )
    }
}

/// A client's persistent view of one operator's rotation log. Holds the
/// highest checkpoint it has accepted; consult/persist this across
/// restarts (mirroring the append-only discipline of
/// [`crate::replay_log`]) so a rollback after a restart is still caught.
#[derive(Debug, Clone)]
pub struct RotaLogState {
    /// The operator's mother public key, pinned out-of-band from the
    /// invite. This is the authenticity root: every accepted checkpoint
    /// MUST carry a valid signature under this key.
    mother_pk: [u8; 32],
    /// Sequence of the last accepted checkpoint, or `None` before the
    /// first (trust-on-first-use) acceptance.
    last_seq: Option<u64>,
    /// Head of the last accepted checkpoint (`GENESIS_PREV_HEAD` before
    /// the first acceptance).
    last_head: [u8; 32],
}

impl RotaLogState {
    /// A fresh client for an operator whose mother key is `mother_pk`
    /// (pinned from the invite), having accepted nothing yet.
    pub fn genesis(mother_pk: [u8; 32]) -> Self {
        Self {
            mother_pk,
            last_seq: None,
            last_head: GENESIS_PREV_HEAD,
        }
    }

    /// Reconstruct from the pinned `mother_pk` plus persisted `(seq,
    /// head)` of the last accepted checkpoint (e.g. loaded from disk on
    /// startup). Rollback resistance survives a restart only when this
    /// is restored faithfully.
    pub fn from_persisted(mother_pk: [u8; 32], last_seq: u64, last_head: [u8; 32]) -> Self {
        Self {
            mother_pk,
            last_seq: Some(last_seq),
            last_head,
        }
    }

    /// The last accepted sequence number, if any.
    pub fn last_seq(&self) -> Option<u64> {
        self.last_seq
    }

    /// The last accepted head (`GENESIS_PREV_HEAD` if none accepted yet).
    pub fn last_head(&self) -> [u8; 32] {
        self.last_head
    }

    /// Verify a candidate `signed` checkpoint (parsed from an off-chain
    /// rotation document) against (0) the pinned mother key, (a) this
    /// client's last accepted state, and (b) the head the ledger reports
    /// for the operator.
    ///
    /// `anchored` is the ledger's current head, or `None` if the backend
    /// returned nothing. Verification order is deliberate:
    /// **signature first** (authenticity - an unsigned/forged checkpoint
    /// is rejected no matter what the attacker anchored on-chain), then
    /// the ledger head (non-equivocation), then sequence continuity
    /// (ordering / rollback resistance).
    pub fn check(&self, signed: &SignedCheckpoint, anchored: Option<&AnchoredHead>) -> RotaVerdict {
        let checkpoint = &signed.checkpoint;

        // 0. Authenticity. The pinned mother key MUST have signed exactly
        //    these checkpoint bytes (seq + prev_head + doc_commitment).
        //    This is what defeats a ledger-writing censor: it can anchor
        //    any head it likes, but cannot forge this signature, and
        //    cannot lift an old signature onto a new seq (the seq is
        //    signed). Checked before any ledger comparison.
        if !signed.verify(&self.mother_pk) {
            return RotaVerdict::Forged(
                "checkpoint not signed by the pinned operator mother key".into(),
            );
        }

        // 1. The ledger must have something to anchor against.
        let Some(anchored) = anchored else {
            return RotaVerdict::Unverifiable(
                "ledger reported no anchored head for this operator".into(),
            );
        };

        // 2. Non-equivocation: the (now-authentic) document must be the
        //    one the ledger anchored. This catches a compromised operator
        //    equivocating (signing two rotations at one seq) or a censor
        //    feeding a stale-but-signed rotation that is not the current
        //    anchored one.
        if checkpoint.seq != anchored.seq {
            return RotaVerdict::Equivocation(format!(
                "document seq {} != anchored seq {} (split view / equivocation)",
                checkpoint.seq, anchored.seq
            ));
        }
        if checkpoint.head() != anchored.head {
            return RotaVerdict::Equivocation(
                "signed document does not match the anchored head (equivocation)".into(),
            );
        }

        // 3. Continuity against our own last-accepted state.
        match self.last_seq {
            // First sight of this operator's log: adopt the anchored
            // checkpoint as our baseline. This is safe even on first use
            // because the checkpoint is already proven mother-signed
            // (step 0) and matches the globally-anchored head (step 2) -
            // so a channel-and-ledger-controlling censor reaching the
            // client first STILL cannot pin a forged key (it lacks the
            // mother secret). We cannot verify the chain back to genesis
            // without every intermediate document, so continuity is
            // enforced from here forward - the standard transparency-log
            // client model, rooted in the out-of-band mother-key pin.
            None => RotaVerdict::Accept,
            Some(last) => {
                if checkpoint.seq <= last {
                    RotaVerdict::Regression(format!(
                        "rotation seq {} <= last accepted {} (rollback to an old key)",
                        checkpoint.seq, last
                    ))
                } else if checkpoint.seq > last + 1 {
                    RotaVerdict::Gap(format!(
                        "rotation seq {} skips ahead of last accepted {} (fetch intermediates)",
                        checkpoint.seq, last
                    ))
                } else if checkpoint.prev_head != self.last_head {
                    // seq == last + 1 but it does not chain our head: a
                    // fork that reuses our sequence space.
                    RotaVerdict::Equivocation(
                        "rotation claims to follow our last head but its prev_head differs (fork)"
                            .into(),
                    )
                } else {
                    RotaVerdict::Accept
                }
            }
        }
    }

    /// Advance the state after an [`RotaVerdict::Accept`]. Idempotent for
    /// a re-applied checkpoint; never moves the sequence backward.
    ///
    /// Takes the [`SignedCheckpoint`] (not a bare `Checkpoint`) so callers
    /// cannot advance state on an unverified checkpoint by mistake - only
    /// [`Self::check_and_accept`], or a caller that has already seen an
    /// `Accept`, should reach here. Advancing on an unsigned checkpoint
    /// would be meaningless: a later genuine rotation would then be seen
    /// as a fork. Callers MUST only call this after an `Accept` verdict.
    pub fn accept(&mut self, signed: &SignedCheckpoint) {
        let cp = &signed.checkpoint;
        if self.last_seq.map(|s| cp.seq > s).unwrap_or(true) {
            self.last_seq = Some(cp.seq);
            self.last_head = cp.head();
        }
    }

    /// Convenience: [`Self::check`] then, on `Accept`, [`Self::accept`].
    /// Returns the verdict. This is the recommended entry point - it
    /// guarantees state only advances on a fully-verified checkpoint.
    pub fn check_and_accept(
        &mut self,
        signed: &SignedCheckpoint,
        anchored: Option<&AnchoredHead>,
    ) -> RotaVerdict {
        let verdict = self.check(signed, anchored);
        if verdict.is_accept() {
            self.accept(signed);
        }
        verdict
    }
}

/// In-memory [`AnchorBackend`] for tests and single-process simulation.
///
/// A faithful model of a *dumb* public ledger: `put_head` overwrites
/// whatever is stored (it does NOT enforce monotonicity or chaining - a
/// real chain wouldn't), so the client-side verifier is exercised exactly
/// as it would be against a hostile or naive ledger.
#[derive(Debug, Default)]
pub struct InMemoryAnchor {
    heads: std::sync::Mutex<std::collections::HashMap<[u8; 32], AnchoredHead>>,
}

impl InMemoryAnchor {
    /// Construct an empty anchor.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AnchorBackend for InMemoryAnchor {
    async fn get_head(&self, anchor_key: &[u8; 32]) -> Result<Option<AnchoredHead>, AnchorError> {
        Ok(self
            .heads
            .lock()
            .map_err(|_| AnchorError::Transport("poisoned".into()))?
            .get(anchor_key)
            .copied())
    }

    async fn put_head(&self, anchor_key: &[u8; 32], head: AnchoredHead) -> Result<(), AnchorError> {
        self.heads
            .lock()
            .map_err(|_| AnchorError::Transport("poisoned".into()))?
            .insert(*anchor_key, head);
        Ok(())
    }

    fn name(&self) -> &'static str {
        "in-memory"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mother_key() -> SigningKey {
        SigningKey::from_bytes(b"rotalog-mother-key-seed-01234567")
    }

    fn attacker_key() -> SigningKey {
        SigningKey::from_bytes(b"the-censors-own-forgery-key-9999")
    }

    fn mother_pk(sk: &SigningKey) -> [u8; 32] {
        sk.verifying_key().to_bytes()
    }

    /// A test operator that builds a rotation hash-chain, signs each
    /// checkpoint with its mother key, and anchors each head - exactly as
    /// a real operator + relayer would.
    struct TestOperator {
        salt: [u8; 32],
        sk: SigningKey,
        seq: u64,
        prev_head: [u8; 32],
    }

    impl TestOperator {
        fn new(salt: [u8; 32], sk: SigningKey) -> Self {
            Self {
                salt,
                sk,
                seq: 0,
                prev_head: GENESIS_PREV_HEAD,
            }
        }

        /// Produce + sign the next checkpoint committing to `sealed_doc`,
        /// advance the operator's chain, and return it to anchor.
        fn rotate(&mut self, sealed_doc: &[u8]) -> SignedCheckpoint {
            let cp = Checkpoint::new(self.seq, self.prev_head, sealed_doc);
            self.prev_head = cp.head();
            self.seq += 1;
            SignedCheckpoint::sign(cp, &self.sk)
        }

        async fn anchor(&self, anchor: &InMemoryAnchor, signed: &SignedCheckpoint) {
            anchor
                .put_head(
                    &anchor_key(&self.salt),
                    AnchoredHead {
                        head: signed.checkpoint.head(),
                        seq: signed.checkpoint.seq,
                    },
                )
                .await
                .unwrap();
        }
    }

    fn salt() -> [u8; 32] {
        *b"rotalog-test-salt-0123456789abcd"
    }

    #[test]
    fn head_is_deterministic_and_chains() {
        let cp0 = Checkpoint::new(0, GENESIS_PREV_HEAD, b"doc-0");
        let cp0b = Checkpoint::new(0, GENESIS_PREV_HEAD, b"doc-0");
        assert_eq!(cp0.head(), cp0b.head(), "head must be deterministic");
        let cp1 = Checkpoint::new(1, cp0.head(), b"doc-1");
        assert_ne!(cp0.head(), cp1.head());
        // Different document => different commitment => different head.
        let cp0_alt = Checkpoint::new(0, GENESIS_PREV_HEAD, b"doc-0-altered");
        assert_ne!(cp0.head(), cp0_alt.head());
    }

    #[test]
    fn anchor_key_is_per_salt_and_not_an_address() {
        let a = anchor_key(&salt());
        let b = anchor_key(&[0x99u8; 32]);
        assert_ne!(a, b);
        assert_eq!(anchor_key(&salt()), a, "deterministic");
    }

    #[test]
    fn signature_binds_seq_and_doc() {
        let sk = mother_key();
        let pk = mother_pk(&sk);
        let signed = SignedCheckpoint::sign(Checkpoint::new(2, [0x11u8; 32], b"doc"), &sk);
        assert!(signed.verify(&pk));
        // Tamper the seq: signature must no longer verify (defeats lifting
        // an old signature onto a new sequence number).
        let mut t = signed.clone();
        t.checkpoint.seq = 3;
        assert!(!t.verify(&pk));
        // Tamper the document commitment: must not verify.
        let mut t2 = signed.clone();
        t2.checkpoint.doc_commitment = [0xFF; 32];
        assert!(!t2.verify(&pk));
        // Wrong key: must not verify.
        assert!(!signed.verify(&mother_pk(&attacker_key())));
    }

    #[tokio::test]
    async fn valid_progression_is_accepted() {
        let anchor = InMemoryAnchor::new();
        let sk = mother_key();
        let mut op = TestOperator::new(salt(), sk.clone());
        let mut client = RotaLogState::genesis(mother_pk(&sk));
        let ak = anchor_key(&salt());

        for i in 0..5u64 {
            let cp = op.rotate(format!("rotation-doc-{i}").as_bytes());
            op.anchor(&anchor, &cp).await;
            let anchored = anchor.get_head(&ak).await.unwrap();
            let verdict = client.check_and_accept(&cp, anchored.as_ref());
            assert_eq!(verdict, RotaVerdict::Accept, "seq {i} should accept");
            assert_eq!(client.last_seq(), Some(i));
        }
    }

    #[tokio::test]
    async fn forged_checkpoint_is_rejected_even_when_ledger_is_attacker_controlled() {
        // RT-RL-1 (CRITICAL regression): the censor controls the discovery
        // channel AND can overwrite the ledger. It builds a fully self-
        // consistent checkpoint (head matches what it anchors) but cannot
        // sign with the mother key. The client MUST reject it as Forged,
        // NOT accept it - even on first use (TOFU).
        let anchor = InMemoryAnchor::new();
        let sk = mother_key();
        let client = RotaLogState::genesis(mother_pk(&sk)); // fresh, TOFU
        let ak = anchor_key(&salt());

        // Attacker signs with its OWN key and anchors a matching head.
        let cp = Checkpoint::new(0, GENESIS_PREV_HEAD, b"attacker-key-doc");
        let forged = SignedCheckpoint::sign(cp, &attacker_key());
        anchor
            .put_head(
                &ak,
                AnchoredHead {
                    head: cp.head(),
                    seq: 0,
                },
            )
            .await
            .unwrap();

        let verdict = client.check(&forged, anchor.get_head(&ak).await.unwrap().as_ref());
        assert!(matches!(verdict, RotaVerdict::Forged(_)), "got {verdict:?}");
        assert!(verdict.is_attack());
    }

    #[tokio::test]
    async fn attacker_cannot_lift_signature_onto_a_new_sequence() {
        // RT-RL-2 (CRITICAL regression): the censor holds an OLD genuine
        // signed checkpoint (seq 0) whose key it has since compromised. It
        // tries to present it at a fresh seq to dodge rollback detection.
        // Changing the seq invalidates the signature -> Forged.
        let anchor = InMemoryAnchor::new();
        let sk = mother_key();
        let mut op = TestOperator::new(salt(), sk.clone());
        let mut client = RotaLogState::genesis(mother_pk(&sk));
        let ak = anchor_key(&salt());

        let cp0 = op.rotate(b"old-doc-0");
        op.anchor(&anchor, &cp0).await;
        client.check_and_accept(&cp0, anchor.get_head(&ak).await.unwrap().as_ref());

        // Repackage cp0's signature onto a seq-1 checkpoint.
        let mut lifted = cp0.clone();
        lifted.checkpoint.seq = 1;
        anchor
            .put_head(
                &ak,
                AnchoredHead {
                    head: lifted.checkpoint.head(),
                    seq: 1,
                },
            )
            .await
            .unwrap();
        let verdict = client.check(&lifted, anchor.get_head(&ak).await.unwrap().as_ref());
        assert!(matches!(verdict, RotaVerdict::Forged(_)), "got {verdict:?}");
    }

    #[tokio::test]
    async fn rollback_to_old_key_is_regression() {
        let anchor = InMemoryAnchor::new();
        let sk = mother_key();
        let mut op = TestOperator::new(salt(), sk.clone());
        let mut client = RotaLogState::genesis(mother_pk(&sk));
        let ak = anchor_key(&salt());

        let cp0 = op.rotate(b"doc-0");
        op.anchor(&anchor, &cp0).await;
        client.check_and_accept(&cp0, anchor.get_head(&ak).await.unwrap().as_ref());

        let cp1 = op.rotate(b"doc-1");
        op.anchor(&anchor, &cp1).await;
        client.check_and_accept(&cp1, anchor.get_head(&ak).await.unwrap().as_ref());
        assert_eq!(client.last_seq(), Some(1));

        // Censor replays the OLD (genuinely-signed) checkpoint seq 0 and
        // re-anchors its old head. Rejected as a rollback by seq.
        anchor
            .put_head(
                &ak,
                AnchoredHead {
                    head: cp0.checkpoint.head(),
                    seq: 0,
                },
            )
            .await
            .unwrap();
        let verdict = client.check(&cp0, anchor.get_head(&ak).await.unwrap().as_ref());
        assert!(
            matches!(verdict, RotaVerdict::Regression(_)),
            "got {verdict:?}"
        );
        assert!(verdict.is_attack());
    }

    #[tokio::test]
    async fn equivocation_doc_not_matching_anchor() {
        let anchor = InMemoryAnchor::new();
        let sk = mother_key();
        let mut op = TestOperator::new(salt(), sk.clone());
        let client = RotaLogState::genesis(mother_pk(&sk));
        let ak = anchor_key(&salt());

        let cp0 = op.rotate(b"genuine-doc-0");
        op.anchor(&anchor, &cp0).await;

        // A compromised operator signs a DIFFERENT seq-0 rotation (valid
        // signature) but only one head is on the global-consistency
        // ledger - so this equivocating document fails to match.
        let other = SignedCheckpoint::sign(
            Checkpoint::new(0, GENESIS_PREV_HEAD, b"equivocating-doc-0"),
            &sk,
        );
        let verdict = client.check(&other, anchor.get_head(&ak).await.unwrap().as_ref());
        assert!(
            matches!(verdict, RotaVerdict::Equivocation(_)),
            "got {verdict:?}"
        );
        assert!(verdict.is_attack());
    }

    #[tokio::test]
    async fn fork_reusing_sequence_is_equivocation() {
        let anchor = InMemoryAnchor::new();
        let sk = mother_key();
        let mut op = TestOperator::new(salt(), sk.clone());
        let mut client = RotaLogState::genesis(mother_pk(&sk));
        let ak = anchor_key(&salt());

        let cp0 = op.rotate(b"doc-0");
        op.anchor(&anchor, &cp0).await;
        client.check_and_accept(&cp0, anchor.get_head(&ak).await.unwrap().as_ref());

        // A signed fork at seq 1 that does NOT chain the accepted head.
        let forked = SignedCheckpoint::sign(Checkpoint::new(1, [0xAAu8; 32], b"forked-doc-1"), &sk);
        anchor
            .put_head(
                &ak,
                AnchoredHead {
                    head: forked.checkpoint.head(),
                    seq: 1,
                },
            )
            .await
            .unwrap();
        let verdict = client.check(&forked, anchor.get_head(&ak).await.unwrap().as_ref());
        assert!(
            matches!(verdict, RotaVerdict::Equivocation(_)),
            "got {verdict:?}"
        );
    }

    #[tokio::test]
    async fn sequence_gap_is_flagged_not_accepted() {
        let anchor = InMemoryAnchor::new();
        let sk = mother_key();
        let mut op = TestOperator::new(salt(), sk.clone());
        let mut client = RotaLogState::genesis(mother_pk(&sk));
        let ak = anchor_key(&salt());

        let cp0 = op.rotate(b"doc-0");
        op.anchor(&anchor, &cp0).await;
        client.check_and_accept(&cp0, anchor.get_head(&ak).await.unwrap().as_ref());

        // Jump to a genuine, signed seq-3 checkpoint (missing 1 and 2).
        let _cp1 = op.rotate(b"doc-1");
        let _cp2 = op.rotate(b"doc-2");
        let cp3 = op.rotate(b"doc-3");
        anchor
            .put_head(
                &ak,
                AnchoredHead {
                    head: cp3.checkpoint.head(),
                    seq: 3,
                },
            )
            .await
            .unwrap();
        let verdict = client.check(&cp3, anchor.get_head(&ak).await.unwrap().as_ref());
        assert!(matches!(verdict, RotaVerdict::Gap(_)), "got {verdict:?}");
        assert!(!verdict.is_attack(), "a gap is not (yet) an attack");
    }

    #[tokio::test]
    async fn missing_anchor_is_unverifiable() {
        let sk = mother_key();
        let client = RotaLogState::genesis(mother_pk(&sk));
        // A correctly-signed checkpoint, but the ledger has nothing.
        let signed = SignedCheckpoint::sign(Checkpoint::new(0, GENESIS_PREV_HEAD, b"doc-0"), &sk);
        let verdict = client.check(&signed, None);
        assert!(
            matches!(verdict, RotaVerdict::Unverifiable(_)),
            "got {verdict:?}"
        );
        assert!(!verdict.is_attack());
    }

    #[test]
    fn accept_never_moves_sequence_backward() {
        let sk = mother_key();
        let mut client = RotaLogState::genesis(mother_pk(&sk));
        let cp5 = SignedCheckpoint::sign(Checkpoint::new(5, GENESIS_PREV_HEAD, b"doc-5"), &sk);
        client.accept(&cp5);
        assert_eq!(client.last_seq(), Some(5));
        let cp2 = SignedCheckpoint::sign(Checkpoint::new(2, GENESIS_PREV_HEAD, b"doc-2"), &sk);
        client.accept(&cp2);
        assert_eq!(
            client.last_seq(),
            Some(5),
            "stale accept must not regress state"
        );
    }

    #[tokio::test]
    async fn persisted_state_still_catches_rollback_after_restart() {
        // A client that persisted (seq=3, head) and restarts must still
        // reject a replayed seq-2 rotation - rollback resistance survives
        // a process restart. The replayed doc is genuinely signed (old).
        let anchor = InMemoryAnchor::new();
        let sk = mother_key();
        let ak = anchor_key(&salt());
        let cp3 = Checkpoint::new(3, [0x11u8; 32], b"doc-3");
        let client = RotaLogState::from_persisted(mother_pk(&sk), 3, cp3.head());

        let cp2 = SignedCheckpoint::sign(Checkpoint::new(2, [0x22u8; 32], b"old-doc-2"), &sk);
        anchor
            .put_head(
                &ak,
                AnchoredHead {
                    head: cp2.checkpoint.head(),
                    seq: 2,
                },
            )
            .await
            .unwrap();
        let verdict = client.check(&cp2, anchor.get_head(&ak).await.unwrap().as_ref());
        assert!(
            matches!(verdict, RotaVerdict::Regression(_)),
            "got {verdict:?}"
        );
    }
}
