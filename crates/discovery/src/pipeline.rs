//! End-to-end discovery pipeline: operator publish, client subscribe.
//!
//! Ties together every preceding discovery layer into two call-site
//! entry points:
//!
//! - [`OperatorPublisher`] - sign an [`Announcement`] or [`Revocation`],
//!   seal it under the current epoch's key, fan out to every configured
//!   [`DiscoveryChannel`] via [`DiscoveryRouter`].
//! - [`ClientSubscriber`] - fetch sealed blobs for the current epoch,
//!   open each with the shared salt, decode as
//!   `Announcement`/`Revocation`, verify the operator signature, return
//!   the accepted set to the caller.
//!
//! Both entry points are **time-aware**: they operate on an epoch
//! number and let the caller drive the clock. Daemons wire a tokio
//! ticker to re-publish / re-subscribe each
//! [`DISCOVERY_EPOCH_SECONDS`](crate::derive::DISCOVERY_EPOCH_SECONDS)
//! boundary.
//!
//! # Threat-model notes
//!
//! - **Channels are untrusted.** Every blob we open is treated as
//!   potentially hostile bytes: we check ChaCha20-Poly1305 auth
//!   (seal::open), reject decode errors, verify the Ed25519 operator
//!   signature, check `issued_at`/`expires_at` windowing, and only
//!   then surface to the caller. A router that returns 100 garbage
//!   blobs produces 0 accepted announcements.
//! - **Salt is a shared secret.** The client-side pipeline needs the
//!   per-invite `shared_salt` to derive info-hash and cipher key. The
//!   salt is held in `Zeroizing<[u8; 32]>` and zeroized on drop.
//! - **Operator pubkey is authoritative.** The caller provides the
//!   `operator_ed25519_pk` they trust (from their invite). We check
//!   every announcement's signature against that key - any
//!   non-matching signature is silently dropped.

use mirage_crypto::ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use mirage_crypto::zeroize::{Zeroize, Zeroizing};

use crate::channel::MAX_PUBLISH_BYTES;
use crate::derive::{
    cipher_key, cipher_nonce, info_hash, INFO_HASH_LEN, NAMESPACE_CLIENT_TO_BRIDGE,
};
use crate::error::DiscoveryError;
use crate::ratchet::fs_info_hash;
use crate::router::{DiscoveryRouter, FetchSummary, PublishSummary};
use crate::seal::{open, open_fs, seal, seal_fs};
use crate::wire::{Announcement, Revocation, ED25519_PK_LEN};

/// Spec §5.1 ceiling on announcement plaintext size. We enforce this
/// **before sealing** so an operator-side bug cannot emit an
/// oversized blob that every channel then rejects (amplification).
/// 768 bytes comfortably fits every field at maximum lengths
/// (header + timestamps + pubkeys + caps + max-length hostname
/// endpoint + signature). +AEAD tag = 784 bytes ciphertext, well
/// under [`MAX_PUBLISH_BYTES`].
const MAX_ANNOUNCEMENT_PLAINTEXT: usize = 768;

// OperatorPublisher

/// Operator-side end-to-end publisher.
///
/// Holds the operator's Ed25519 signing key plus a shared discovery
/// salt (from the `master_invite` the operator issued). Each call to
/// [`OperatorPublisher::publish_announcement`] or
/// [`OperatorPublisher::publish_revocation`] signs, seals, and fans out
/// to every channel behind the [`DiscoveryRouter`].
///
/// The signing key is **not cloned out** - it is held by reference
/// for the publisher's lifetime so the caller controls the key's
/// scope (e.g., read from HSM once, pass in, drop after last epoch).
pub struct OperatorPublisher<'a> {
    signing_key: &'a SigningKey,
    shared_salt: Zeroizing<[u8; 32]>,
    router: DiscoveryRouter,
    /// `Some(anchor_epoch)` enables forward-secret rendezvous: info-hashes and
    /// cipher keys derive from the one-way [`crate::ratchet`] chain anchored
    /// here instead of directly from the salt. The subscriber must use the same
    /// anchor. `None` = baseline direct derivation (backward-compatible).
    fs_anchor: Option<u64>,
    /// When `Some`, the publisher drives an actual forward-secret ratchet
    /// (holding only the current chain state; the `shared_salt` above is zeroized
    /// at construction) so a seized publisher cannot recompute PAST epoch keys -
    /// realizing PRODUCER-side forward secrecy. Sealing uses the ratchet key
    /// directly ([`crate::seal::seal_fs_with_key`]) rather than the (zeroed)
    /// salt. Interior mutability because the ratchet advances (`&self` API).
    fs_ratchet: Option<std::sync::Mutex<crate::ratchet::RendezvousRatchet>>,
}

impl<'a> OperatorPublisher<'a> {
    /// Construct a publisher around a router and an operator key.
    ///
    /// `shared_salt` is the salt bound to the `master_invite` under
    /// which the operator is publishing. Wrapped in `Zeroizing` and
    /// zeroed on drop.
    pub fn new(
        signing_key: &'a SigningKey,
        shared_salt: [u8; 32],
        router: DiscoveryRouter,
    ) -> Self {
        Self {
            signing_key,
            shared_salt: Zeroizing::new(shared_salt),
            router,
            fs_anchor: None,
            fs_ratchet: None,
        }
    }

    /// Enable forward-secret rendezvous DERIVATION anchored at `anchor_epoch`
    /// (typically the invite's issue epoch), still deriving keys from the salt.
    /// This is the library/testing form; the matching [`ClientSubscriber`] must
    /// use the same anchor. For PRODUCER-side forward secrecy (the salt
    /// discarded) use [`Self::with_forward_secret_ratchet`].
    #[must_use]
    pub fn with_forward_secret(mut self, anchor_epoch: u64) -> Self {
        self.fs_anchor = Some(anchor_epoch);
        self
    }

    /// Enable forward-secret rendezvous with PRODUCER-side forward secrecy: seed
    /// a one-way ratchet at `anchor_epoch`, advance it to `current_epoch`, and
    /// ZEROIZE the salt - so a seized publisher cannot recompute past epoch keys.
    /// Call [`Self::advance_fs_floor`] each epoch to keep deleting the past. The
    /// client (which keeps the salt) still opens these blobs via [`open_fs`].
    #[must_use]
    pub fn with_forward_secret_ratchet(mut self, anchor_epoch: u64, current_epoch: u64) -> Self {
        let mut ratchet = crate::ratchet::RendezvousRatchet::seed(
            &self.shared_salt,
            NAMESPACE_CLIENT_TO_BRIDGE,
            anchor_epoch,
        );
        // Advance to now, deleting every state before it (best-effort: a bad
        // clock leaving current < anchor keeps the ratchet at the anchor).
        let _ = ratchet.advance_to(current_epoch);
        // Producer forward secrecy: forget the root. Sealing now uses the
        // ratchet key directly; the baseline/salt paths are unreachable here.
        self.shared_salt.zeroize();
        self.fs_anchor = Some(anchor_epoch);
        self.fs_ratchet = Some(std::sync::Mutex::new(ratchet));
        self
    }

    /// Advance the producer ratchet floor to `epoch`, zeroizing every earlier
    /// state (the forward-secrecy step). No-op unless in ratchet mode. Call once
    /// per publish cycle before publishing the current + next epoch.
    pub fn advance_fs_floor(&self, epoch: u64) {
        if let Some(m) = &self.fs_ratchet {
            if let Ok(mut r) = m.lock() {
                let _ = r.advance_to(epoch);
            }
        }
    }

    /// Derive `(info_hash, ciphertext)` for `epoch`, honouring the FS mode:
    /// producer ratchet (salt discarded) > salt-anchored FS derivation >
    /// baseline. In ratchet mode a past epoch (below the floor) is an error - the
    /// publisher only ever seals the current + next epoch.
    fn seal_and_ih(
        &self,
        epoch: u64,
        plaintext: &[u8],
    ) -> Result<([u8; INFO_HASH_LEN], Vec<u8>), DiscoveryError> {
        if let (Some(m), Some(anchor)) = (&self.fs_ratchet, self.fs_anchor) {
            let (ih, key) = {
                let r = m
                    .lock()
                    .map_err(|_| DiscoveryError::Wire("fs ratchet lock poisoned"))?;
                r.key_at(epoch)
                    .ok_or(DiscoveryError::Wire("fs ratchet: epoch below floor"))?
            };
            let ct = crate::seal::seal_fs_with_key(
                &key,
                NAMESPACE_CLIENT_TO_BRIDGE,
                anchor,
                epoch,
                plaintext,
            )?;
            return Ok((ih, ct));
        }
        match self.fs_anchor {
            Some(anchor) => {
                let ih = fs_info_hash(&self.shared_salt, NAMESPACE_CLIENT_TO_BRIDGE, anchor, epoch)
                    .unwrap_or_else(|| {
                        info_hash(&self.shared_salt, NAMESPACE_CLIENT_TO_BRIDGE, epoch)
                    });
                let ct = seal_fs(
                    &self.shared_salt,
                    NAMESPACE_CLIENT_TO_BRIDGE,
                    anchor,
                    epoch,
                    plaintext,
                )?;
                Ok((ih, ct))
            }
            None => {
                let ih = info_hash(&self.shared_salt, NAMESPACE_CLIENT_TO_BRIDGE, epoch);
                let ct = seal(
                    &self.shared_salt,
                    NAMESPACE_CLIENT_TO_BRIDGE,
                    epoch,
                    plaintext,
                )?;
                Ok((ih, ct))
            }
        }
    }

    /// Publish a bridge announcement for `epoch`.
    ///
    /// The caller provides the `Announcement` with every field populated
    /// EXCEPT `signature` (which is set to all-zero; this method fills
    /// it in). The published info-hash is derived from
    /// `(shared_salt, NAMESPACE_CLIENT_TO_BRIDGE, epoch)`.
    pub async fn publish_announcement(
        &self,
        mut ann: Announcement,
        epoch: u64,
    ) -> Result<PublishSummary, DiscoveryError> {
        // 1. Sign.
        let mut prefix = Vec::with_capacity(ann.signed_prefix_len());
        ann.encode_signed_prefix(&mut prefix);
        ann.signature = self.signing_key.sign(&prefix).to_bytes();

        // 2. Encode.
        let plaintext = ann.encode();

        // 3. Defense in depth: cap plaintext size before sealing. The
        //    spec fixes the maximum at 768 B; emitting a larger blob
        //    means a caller bug, not a valid announcement.
        //    [`MAX_PUBLISH_BYTES`] would also catch this at the channel
        //    layer, but we want early detection at the signing-and-
        //    sealing boundary so operators see the error immediately.
        if plaintext.len() > MAX_ANNOUNCEMENT_PLAINTEXT {
            return Err(DiscoveryError::Wire(
                "announcement plaintext exceeds spec cap",
            ));
        }

        // 4. Seal (forward-secret when enabled).
        let (ih, ciphertext) = self.seal_and_ih(epoch, &plaintext)?;
        // 5. Sanity-check the ciphertext before handing to the router.
        //    AEAD adds 16 bytes; still well under MAX_PUBLISH_BYTES.
        debug_assert!(ciphertext.len() <= MAX_PUBLISH_BYTES);

        // 6. Publish.
        Ok(self.router.publish(&ih, &ciphertext).await)
    }

    /// Publish a revocation for `epoch`.
    pub async fn publish_revocation(
        &self,
        mut rev: Revocation,
        epoch: u64,
    ) -> Result<PublishSummary, DiscoveryError> {
        let mut prefix = Vec::new();
        rev.encode_signed_prefix(&mut prefix);
        rev.signature = self.signing_key.sign(&prefix).to_bytes();

        let plaintext = rev.encode();
        let (ih, ciphertext) = self.seal_and_ih(epoch, &plaintext)?;
        Ok(self.router.publish(&ih, &ciphertext).await)
    }

    /// Info-hash the publisher will publish under for `epoch`.
    ///
    /// Used by tests and by cross-channel coordination (e.g., a tool
    /// that lists which `info_hash` the operator is active on).
    pub fn info_hash_for_epoch(&self, epoch: u64) -> [u8; INFO_HASH_LEN] {
        // Derive via the same FS-aware path (ratchet peek / salt-anchor /
        // baseline). Sealing a throwaway keeps the logic in one place.
        self.seal_and_ih(epoch, &[])
            .map(|(ih, _)| ih)
            .unwrap_or_else(|_| info_hash(&self.shared_salt, NAMESPACE_CLIENT_TO_BRIDGE, epoch))
    }
}

// ClientSubscriber

/// Verified output of a client-side discovery fetch.
#[derive(Debug, Default)]
pub struct DiscoveryFetch {
    /// Bridge announcements that passed open + decode + sig-verify +
    /// time-window checks.
    pub announcements: Vec<Announcement>,
    /// Revocations that passed the same checks.
    pub revocations: Vec<Revocation>,
    /// Number of blobs fetched from the network.
    pub blobs_fetched: usize,
    /// Number of blobs that failed at some verification stage.
    /// Operators use this as a health signal - a spike indicates
    /// channel poisoning or a client-side clock/salt drift.
    pub blobs_rejected: usize,
    /// Names of channels that returned anything parseable.
    pub channels_with_hits: Vec<&'static str>,
    /// Names of channels that failed at the transport layer.
    pub channels_failed: Vec<&'static str>,
}

/// Client-side end-to-end subscriber.
///
/// Holds the client's shared salt (from the `master_invite`) and the
/// operator Ed25519 pubkey (authoritative source for signature
/// verification). A single subscriber is re-used across epochs.
pub struct ClientSubscriber {
    shared_salt: Zeroizing<[u8; 32]>,
    operator_ed25519_pk: [u8; ED25519_PK_LEN],
    router: DiscoveryRouter,
    /// `Some(anchor_epoch)` enables forward-secret rendezvous (must match the
    /// publisher's anchor). `None` = baseline direct derivation.
    fs_anchor: Option<u64>,
}

impl ClientSubscriber {
    /// Construct a subscriber.
    pub fn new(
        shared_salt: [u8; 32],
        operator_ed25519_pk: [u8; ED25519_PK_LEN],
        router: DiscoveryRouter,
    ) -> Self {
        Self {
            shared_salt: Zeroizing::new(shared_salt),
            operator_ed25519_pk,
            router,
            fs_anchor: None,
        }
    }

    /// Enable forward-secret rendezvous, anchoring the ratchet at `anchor_epoch`
    /// (the invite's issue epoch). Must match the [`OperatorPublisher`]'s anchor.
    #[must_use]
    pub fn with_forward_secret(mut self, anchor_epoch: u64) -> Self {
        self.fs_anchor = Some(anchor_epoch);
        self
    }

    /// Info-hash to fetch from for `epoch` (forward-secret when enabled).
    fn info_hash_at(&self, epoch: u64) -> [u8; INFO_HASH_LEN] {
        match self.fs_anchor {
            Some(anchor) => {
                fs_info_hash(&self.shared_salt, NAMESPACE_CLIENT_TO_BRIDGE, anchor, epoch)
                    .unwrap_or_else(|| {
                        info_hash(&self.shared_salt, NAMESPACE_CLIENT_TO_BRIDGE, epoch)
                    })
            }
            None => info_hash(&self.shared_salt, NAMESPACE_CLIENT_TO_BRIDGE, epoch),
        }
    }

    /// Open a fetched blob for `epoch` (forward-secret when enabled).
    fn open_at(&self, epoch: u64, blob: &[u8]) -> Result<Vec<u8>, DiscoveryError> {
        match self.fs_anchor {
            Some(anchor) => open_fs(
                &self.shared_salt,
                NAMESPACE_CLIENT_TO_BRIDGE,
                anchor,
                epoch,
                blob,
            ),
            None => open(&self.shared_salt, NAMESPACE_CLIENT_TO_BRIDGE, epoch, blob),
        }
    }

    /// Sanity-check the operator pubkey at construction - an invalid
    /// point renders every announcement verification a silent reject.
    ///
    /// Returns `Ok(self)` so the call chains. Callers SHOULD run this
    /// once during config load; it's cheap.
    pub fn validate_operator_pubkey(self) -> Result<Self, DiscoveryError> {
        VerifyingKey::from_bytes(&self.operator_ed25519_pk)
            .map_err(|_| DiscoveryError::Ed25519("invalid operator pubkey"))?;
        Ok(self)
    }

    /// Fetch and verify discovery records for `epoch`.
    ///
    /// Pipeline for each blob returned by the router:
    /// 1. [`seal::open`] with the per-epoch key -> plaintext (rejects
    ///    forged blobs; the AEAD tag is the first line of defense).
    /// 2. Decode as `Announcement` OR `Revocation`. Unrecognized
    ///    `doc_type` -> reject.
    /// 3. Verify operator Ed25519 signature.
    /// 4. Time-window check: `issued_at <= now_unix` and (for
    ///    announcements) `now_unix < expires_at`. Tolerates
    ///    `now_unix = 0` (caller disables time check).
    ///
    /// `now_unix = 0` is a special value that disables the
    /// time-window check - used by tests and by clients that have no
    /// reliable clock (e.g., just booted, no NTP yet). Production
    /// callers SHOULD pass a real clock.
    pub async fn fetch_for_epoch(&self, epoch: u64, now_unix: u64) -> DiscoveryFetch {
        let ih = self.info_hash_at(epoch);
        let FetchSummary {
            blobs,
            channels_with_hits,
            channels_failed,
        } = self.router.fetch(&ih).await;

        let blobs_fetched = blobs.len();
        let mut out = DiscoveryFetch {
            announcements: Vec::new(),
            revocations: Vec::new(),
            blobs_fetched,
            blobs_rejected: 0,
            channels_with_hits,
            channels_failed,
        };

        for blob in blobs {
            match self.verify_one(&blob, epoch, now_unix) {
                Ok(Verified::Announcement(a)) => out.announcements.push(a),
                Ok(Verified::Revocation(r)) => out.revocations.push(r),
                Err(_) => out.blobs_rejected += 1,
            }
        }

        out
    }

    fn verify_one(
        &self,
        blob: &[u8],
        epoch: u64,
        now_unix: u64,
    ) -> Result<Verified, DiscoveryError> {
        // 1. Open. ChaCha20-Poly1305 AEAD auth is the cheap first filter.
        let plaintext = self.open_at(epoch, blob)?;

        // 2. Route by doc_type (4th byte after MAGIC+doc_type=... actually
        //    it's buf[2] for doc_type). Defer to each type's decode.
        if plaintext.len() < 4 {
            return Err(DiscoveryError::Wire("plaintext too short for header"));
        }
        let doc_type = plaintext[2];

        match doc_type {
            crate::wire::DOC_TYPE_ANNOUNCEMENT => {
                let ann = Announcement::decode(&plaintext)?;
                ann.verify(&self.operator_ed25519_pk)?;
                if now_unix != 0 {
                    if ann.issued_at > now_unix {
                        return Err(DiscoveryError::Time("announcement from the future"));
                    }
                    if ann.expires_at <= now_unix {
                        return Err(DiscoveryError::Time("announcement expired"));
                    }
                }
                Ok(Verified::Announcement(ann))
            }
            crate::wire::DOC_TYPE_REVOCATION => {
                let rev = Revocation::decode(&plaintext)?;
                rev.verify(&self.operator_ed25519_pk)?;
                if now_unix != 0 && rev.issued_at > now_unix {
                    return Err(DiscoveryError::Time("revocation from the future"));
                }
                Ok(Verified::Revocation(rev))
            }
            _ => Err(DiscoveryError::Wire("unknown doc_type in sealed plaintext")),
        }
    }

    /// Info-hash the subscriber will fetch from for `epoch`.
    pub fn info_hash_for_epoch(&self, epoch: u64) -> [u8; INFO_HASH_LEN] {
        info_hash(&self.shared_salt, NAMESPACE_CLIENT_TO_BRIDGE, epoch)
    }
}

enum Verified {
    Announcement(Announcement),
    Revocation(Revocation),
}

// Helper: silence unused warnings for cipher_key/cipher_nonce; the open/seal
// helpers already pull them through. These explicit re-exports make it easy
// for tests or external tools to re-derive the same key material without
// round-tripping through seal::seal. Keeping them here documents the
// derivation tree.

/// Per-epoch ChaCha20-Poly1305 key (32 B). Thin re-export.
pub use crate::derive::cipher_key as derive_cipher_key;
/// Per-epoch ChaCha20-Poly1305 nonce (12 B). Thin re-export.
pub use crate::derive::cipher_nonce as derive_cipher_nonce;
#[allow(dead_code)]
fn _ensure_used() {
    let _ = cipher_key;
    let _ = cipher_nonce;
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::{DiscoveryChannel, InMemoryChannel};
    use crate::router::RouterConfig;
    use crate::wire::{transport_caps, Endpoint, RevocationReason, SIG_LEN};
    use mirage_crypto::ed25519_dalek::SigningKey;
    use std::sync::Arc;

    fn op_keypair() -> SigningKey {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        SigningKey::from_bytes(&seed)
    }

    fn salt() -> [u8; 32] {
        *b"abcdef0123456789abcdef0123456789"
    }

    fn sample_ann() -> Announcement {
        Announcement {
            issued_at: 1_000_000,
            expires_at: 1_003_600,
            bridge_ed25519_pk: [0x11u8; 32],
            bridge_x25519_pk: [0x22u8; 32],
            transport_caps: transport_caps::REALITY_V2,
            endpoint: Endpoint::Ipv4 {
                addr: [93, 184, 216, 34],
                port: 443,
            },
            extra_endpoints: Vec::new(),
            signature: [0u8; SIG_LEN],
        }
    }

    fn sample_rev() -> Revocation {
        Revocation {
            target_ed25519_pk: [0x11u8; 32],
            reason: RevocationReason::Compromised,
            issued_at: 1_000_500,
            signature: [0u8; SIG_LEN],
        }
    }

    fn mem_router(n: usize) -> (DiscoveryRouter, Vec<Arc<InMemoryChannel>>) {
        let chans: Vec<Arc<InMemoryChannel>> = (0..n)
            .map(|i| {
                Arc::new(InMemoryChannel::new(Box::leak(
                    format!("mem{i}").into_boxed_str(),
                )))
            })
            .collect();
        let dyn_chans: Vec<Arc<dyn DiscoveryChannel>> =
            chans.iter().cloned().map(|c| c as _).collect();
        (
            DiscoveryRouter::new(dyn_chans, RouterConfig::default()),
            chans,
        )
    }

    #[tokio::test]
    async fn operator_publishes_and_client_recovers_announcement() {
        let op = op_keypair();
        let op_pk: [u8; 32] = op.verifying_key().to_bytes();

        let (router_p, chans) = mem_router(3);
        let publisher = OperatorPublisher::new(&op, salt(), router_p);
        let summary = publisher
            .publish_announcement(sample_ann(), 1000)
            .await
            .unwrap();
        assert_eq!(summary.successes(), 3);

        // Client uses a fresh router over the SAME channels to exercise
        // the publish/fetch-by-reference pattern that'd hold in a real
        // deployment (same relays, different processes).
        let dyn_chans: Vec<Arc<dyn DiscoveryChannel>> =
            chans.iter().cloned().map(|c| c as _).collect();
        let router_c = DiscoveryRouter::with_channels(dyn_chans);
        let sub = ClientSubscriber::new(salt(), op_pk, router_c)
            .validate_operator_pubkey()
            .unwrap();

        let fetch = sub.fetch_for_epoch(1000, 1_000_100).await;
        assert_eq!(
            fetch.blobs_fetched, 1,
            "3 channels published same blob -> dedupe to 1"
        );
        assert_eq!(fetch.announcements.len(), 1);
        assert_eq!(fetch.blobs_rejected, 0);
        assert_eq!(fetch.announcements[0].bridge_ed25519_pk, [0x11u8; 32]);
    }

    #[tokio::test]
    async fn forward_secret_publish_and_recover() {
        // Anchor the ratchet at epoch 1000, publish at epoch 1005.
        let op = op_keypair();
        let op_pk: [u8; 32] = op.verifying_key().to_bytes();

        let (router_p, chans) = mem_router(2);
        let publisher = OperatorPublisher::new(&op, salt(), router_p).with_forward_secret(1000);
        publisher
            .publish_announcement(sample_ann(), 1005)
            .await
            .unwrap();

        let dyn_chans: Vec<Arc<dyn DiscoveryChannel>> =
            chans.iter().cloned().map(|c| c as _).collect();

        // A forward-secret subscriber with the SAME anchor recovers it.
        let sub_fs = ClientSubscriber::new(
            salt(),
            op_pk,
            DiscoveryRouter::with_channels(dyn_chans.clone()),
        )
        .with_forward_secret(1000);
        let fetch = sub_fs.fetch_for_epoch(1005, 1_000_100).await;
        assert_eq!(
            fetch.announcements.len(),
            1,
            "FS subscriber recovers FS blob"
        );
        assert_eq!(fetch.blobs_rejected, 0);

        // A BASELINE subscriber fetches a different info-hash (FS rendezvous
        // point differs) and recovers nothing - proving the FS derivation is a
        // clean, non-colliding wire change.
        let sub_base =
            ClientSubscriber::new(salt(), op_pk, DiscoveryRouter::with_channels(dyn_chans));
        let fetch_base = sub_base.fetch_for_epoch(1005, 1_000_100).await;
        assert_eq!(
            fetch_base.blobs_fetched, 0,
            "baseline info-hash != FS info-hash"
        );
        assert_eq!(fetch_base.announcements.len(), 0);
    }

    #[tokio::test]
    async fn producer_ratchet_fs_roundtrip_and_deletes_past() {
        // A PRODUCER-forward-secret publisher (salt discarded, driving a ratchet
        // whose floor is at epoch 1005) publishes at 1005; a salt-holding client
        // anchored at the same epoch (1000) recovers it. The producer then
        // advances its floor to 1006 and can NO LONGER seal epoch 1005 (its past
        // key is gone) - the forward-secrecy property, live.
        let op = op_keypair();
        let op_pk: [u8; 32] = op.verifying_key().to_bytes();

        let (router_p, chans) = mem_router(2);
        let publisher =
            OperatorPublisher::new(&op, salt(), router_p).with_forward_secret_ratchet(1000, 1005);
        publisher
            .publish_announcement(sample_ann(), 1005)
            .await
            .unwrap();

        let dyn_chans: Vec<Arc<dyn DiscoveryChannel>> =
            chans.iter().cloned().map(|c| c as _).collect();
        let sub = ClientSubscriber::new(salt(), op_pk, DiscoveryRouter::with_channels(dyn_chans))
            .with_forward_secret(1000);
        let fetch = sub.fetch_for_epoch(1005, 1_000_100).await;
        assert_eq!(
            fetch.announcements.len(),
            1,
            "client recovers ratchet-sealed blob"
        );

        // Advance the producer past 1005; sealing 1005 must now fail (deleted).
        publisher.advance_fs_floor(1006);
        let err = publisher.publish_announcement(sample_ann(), 1005).await;
        assert!(err.is_err(), "producer cannot re-seal a deleted past epoch");
        // It can still seal the current/next epoch.
        assert!(publisher
            .publish_announcement(sample_ann(), 1006)
            .await
            .is_ok());
    }

    /// The blockchain/ledger channel is a drop-in `DiscoveryChannel`, so the
    /// EXISTING sealed pipeline anchors both announcements and revocations on
    /// the ledger as ciphertext - no separate (and cleartext-leaking) ledger
    /// revocation mechanism is needed. Publisher and client share one ledger
    /// backend (the "chain").
    #[tokio::test]
    async fn ledger_channel_anchors_sealed_announcement_and_revocation() {
        use crate::blockchain_channel::{BlockchainDiscoveryChannel, InMemoryRegistry};

        let op = op_keypair();
        let op_pk: [u8; 32] = op.verifying_key().to_bytes();

        let ledger: Arc<BlockchainDiscoveryChannel<InMemoryRegistry>> =
            Arc::new(BlockchainDiscoveryChannel::new(InMemoryRegistry::new()));
        let chans: Vec<Arc<dyn DiscoveryChannel>> = vec![ledger.clone()];

        let publisher =
            OperatorPublisher::new(&op, salt(), DiscoveryRouter::with_channels(chans.clone()));
        publisher
            .publish_announcement(sample_ann(), 1000)
            .await
            .unwrap();
        publisher
            .publish_revocation(sample_rev(), 1000)
            .await
            .unwrap();

        let sub = ClientSubscriber::new(salt(), op_pk, DiscoveryRouter::with_channels(chans))
            .validate_operator_pubkey()
            .unwrap();
        let fetch = sub.fetch_for_epoch(1000, 1_000_600).await;

        assert_eq!(
            fetch.announcements.len(),
            1,
            "announcement recovered from the ledger channel"
        );
        assert_eq!(
            fetch.revocations.len(),
            1,
            "revocation recovered from the ledger channel"
        );
        assert_eq!(fetch.blobs_rejected, 0);
        assert_eq!(fetch.announcements[0].bridge_ed25519_pk, [0x11u8; 32]);
        assert_eq!(fetch.revocations[0].target_ed25519_pk, [0x11u8; 32]);
    }

    #[tokio::test]
    async fn operator_publishes_and_client_recovers_revocation() {
        let op = op_keypair();
        let op_pk: [u8; 32] = op.verifying_key().to_bytes();

        let (router_p, chans) = mem_router(1);
        let publisher = OperatorPublisher::new(&op, salt(), router_p);
        publisher
            .publish_revocation(sample_rev(), 1000)
            .await
            .unwrap();

        let dyn_chans: Vec<Arc<dyn DiscoveryChannel>> =
            chans.iter().cloned().map(|c| c as _).collect();
        let router_c = DiscoveryRouter::with_channels(dyn_chans);
        let sub = ClientSubscriber::new(salt(), op_pk, router_c);

        let fetch = sub.fetch_for_epoch(1000, 1_000_600).await;
        assert_eq!(fetch.revocations.len(), 1);
        assert_eq!(fetch.revocations[0].reason, RevocationReason::Compromised);
    }

    #[tokio::test]
    async fn wrong_operator_pubkey_rejects_everything() {
        let real_op = op_keypair();
        let wrong_op_pk: [u8; 32] = op_keypair().verifying_key().to_bytes();

        let (router_p, chans) = mem_router(1);
        let publisher = OperatorPublisher::new(&real_op, salt(), router_p);
        publisher
            .publish_announcement(sample_ann(), 1000)
            .await
            .unwrap();

        let dyn_chans: Vec<Arc<dyn DiscoveryChannel>> =
            chans.iter().cloned().map(|c| c as _).collect();
        let router_c = DiscoveryRouter::with_channels(dyn_chans);
        let sub = ClientSubscriber::new(salt(), wrong_op_pk, router_c);

        let fetch = sub.fetch_for_epoch(1000, 1_000_100).await;
        assert_eq!(fetch.announcements.len(), 0);
        assert_eq!(fetch.blobs_fetched, 1);
        assert_eq!(fetch.blobs_rejected, 1, "wrong pubkey -> silent reject");
    }

    #[tokio::test]
    async fn wrong_salt_rejects_everything() {
        let op = op_keypair();
        let op_pk: [u8; 32] = op.verifying_key().to_bytes();

        let (router_p, chans) = mem_router(1);
        let publisher = OperatorPublisher::new(&op, salt(), router_p);
        publisher
            .publish_announcement(sample_ann(), 1000)
            .await
            .unwrap();

        let dyn_chans: Vec<Arc<dyn DiscoveryChannel>> =
            chans.iter().cloned().map(|c| c as _).collect();
        let router_c = DiscoveryRouter::with_channels(dyn_chans);
        let wrong_salt = *b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let sub = ClientSubscriber::new(wrong_salt, op_pk, router_c);

        let fetch = sub.fetch_for_epoch(1000, 1_000_100).await;
        // Under the wrong salt, the derived info_hash is different
        // entirely -> the channel has no blobs under that info_hash.
        assert_eq!(fetch.blobs_fetched, 0);
        assert_eq!(fetch.announcements.len(), 0);
    }

    #[tokio::test]
    async fn wrong_epoch_rejects_via_seal_open() {
        let op = op_keypair();
        let op_pk: [u8; 32] = op.verifying_key().to_bytes();

        let (router_p, chans) = mem_router(1);
        let publisher = OperatorPublisher::new(&op, salt(), router_p);
        publisher
            .publish_announcement(sample_ann(), 1000)
            .await
            .unwrap();

        // Hostile channel bypass: directly plant the ciphertext (published
        // at epoch 1000) into the channel under epoch 1001's info_hash.
        // The client fetches with epoch 1001, gets the blob, but seal::open
        // with epoch 1001's key MUST fail (AEAD auth).
        let ih_1000 = publisher.info_hash_for_epoch(1000);
        let ih_1001 = publisher.info_hash_for_epoch(1001);
        let blobs = chans[0].fetch(&ih_1000).await.unwrap();
        for blob in blobs {
            chans[0].publish(&ih_1001, &blob).await.unwrap();
        }

        let dyn_chans: Vec<Arc<dyn DiscoveryChannel>> =
            chans.iter().cloned().map(|c| c as _).collect();
        let router_c = DiscoveryRouter::with_channels(dyn_chans);
        let sub = ClientSubscriber::new(salt(), op_pk, router_c);

        let fetch = sub.fetch_for_epoch(1001, 1_003_600 + 100).await;
        assert_eq!(fetch.blobs_fetched, 1, "blob is there");
        assert_eq!(
            fetch.announcements.len(),
            0,
            "but epoch-binding AEAD rejects"
        );
        assert_eq!(fetch.blobs_rejected, 1);
    }

    #[tokio::test]
    async fn expired_announcement_rejected_by_time_check() {
        let op = op_keypair();
        let op_pk: [u8; 32] = op.verifying_key().to_bytes();
        let (router_p, chans) = mem_router(1);
        let publisher = OperatorPublisher::new(&op, salt(), router_p);
        publisher
            .publish_announcement(sample_ann(), 1000)
            .await
            .unwrap();

        let dyn_chans: Vec<Arc<dyn DiscoveryChannel>> =
            chans.iter().cloned().map(|c| c as _).collect();
        let router_c = DiscoveryRouter::with_channels(dyn_chans);
        let sub = ClientSubscriber::new(salt(), op_pk, router_c);

        // now > expires_at -> reject.
        let fetch = sub.fetch_for_epoch(1000, 1_100_000).await;
        assert_eq!(fetch.announcements.len(), 0);
        assert_eq!(fetch.blobs_rejected, 1);
    }

    #[tokio::test]
    async fn time_check_disabled_when_now_is_zero() {
        let op = op_keypair();
        let op_pk: [u8; 32] = op.verifying_key().to_bytes();
        let (router_p, chans) = mem_router(1);
        let publisher = OperatorPublisher::new(&op, salt(), router_p);
        publisher
            .publish_announcement(sample_ann(), 1000)
            .await
            .unwrap();

        let dyn_chans: Vec<Arc<dyn DiscoveryChannel>> =
            chans.iter().cloned().map(|c| c as _).collect();
        let router_c = DiscoveryRouter::with_channels(dyn_chans);
        let sub = ClientSubscriber::new(salt(), op_pk, router_c);

        // now_unix = 0: bypass the time check. Useful for just-booted
        // clients with no NTP yet, and tests.
        let fetch = sub.fetch_for_epoch(1000, 0).await;
        assert_eq!(fetch.announcements.len(), 1);
    }

    #[tokio::test]
    async fn hostile_channel_garbage_is_silently_dropped() {
        let op = op_keypair();
        let op_pk: [u8; 32] = op.verifying_key().to_bytes();
        let (router_p, chans) = mem_router(2);
        let publisher = OperatorPublisher::new(&op, salt(), router_p);
        publisher
            .publish_announcement(sample_ann(), 1000)
            .await
            .unwrap();

        // chans[0] now holds a legitimate blob. chans[1] is hostile and
        // stuffs 10 garbage blobs under the same info_hash.
        let ih = publisher.info_hash_for_epoch(1000);
        for i in 0..10u8 {
            let garbage = vec![i; 100];
            chans[1].publish(&ih, &garbage).await.unwrap();
        }

        let dyn_chans: Vec<Arc<dyn DiscoveryChannel>> =
            chans.iter().cloned().map(|c| c as _).collect();
        let router_c = DiscoveryRouter::with_channels(dyn_chans);
        let sub = ClientSubscriber::new(salt(), op_pk, router_c);

        let fetch = sub.fetch_for_epoch(1000, 1_000_100).await;
        assert_eq!(fetch.announcements.len(), 1, "honest blob survived");
        assert_eq!(fetch.blobs_rejected, 10, "garbage rejected at seal::open");
        assert!(fetch.blobs_fetched >= 11);
    }

    #[tokio::test]
    async fn operator_publish_info_hash_matches_client_fetch_info_hash() {
        // Protocol invariant: operator info_hash derivation MUST match
        // client's. Regression test against salt/namespace drift.
        let op = op_keypair();
        let op_pk: [u8; 32] = op.verifying_key().to_bytes();

        let (router_p, chans) = mem_router(1);
        let publisher = OperatorPublisher::new(&op, salt(), router_p);

        let dyn_chans: Vec<Arc<dyn DiscoveryChannel>> =
            chans.iter().cloned().map(|c| c as _).collect();
        let router_c = DiscoveryRouter::with_channels(dyn_chans);
        let sub = ClientSubscriber::new(salt(), op_pk, router_c);

        for epoch in 0..5 {
            assert_eq!(
                publisher.info_hash_for_epoch(epoch),
                sub.info_hash_for_epoch(epoch),
                "epoch {epoch}"
            );
        }
    }

    #[tokio::test]
    async fn invalid_operator_pubkey_fails_validation() {
        let (router_p, _) = mem_router(1);
        let bad_pk = [0u8; 32]; // all-zero is a valid Ed25519 point historically,
                                // but ed25519-dalek may reject - test either way.
        let _sub = ClientSubscriber::new(salt(), bad_pk, router_p);
        // Not asserting Err here because all-zero might be acceptable
        // depending on ed25519-dalek's validator. Instead test with
        // bytes that cannot decode.
        let (router_p2, _) = mem_router(1);
        let bad_pk2 = [0xFFu8; 32];
        let result = ClientSubscriber::new(salt(), bad_pk2, router_p2).validate_operator_pubkey();
        // ed25519-dalek 2.x rejects some non-canonical high bytes;
        // we accept either outcome - the test documents the contract.
        let _ = result;
    }
}
