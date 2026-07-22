//! BEP-44 DHT channel adapter for the Mirage discovery layer.
//!
//! # Status (v0.1g)
//!
//! This crate ships the BEP-44 DHT discovery channel end to end, including real
//! `BitTorrent` mainline network I/O ([`MainlineDhtClient`], always compiled). It
//! provides:
//!
//! - The BEP-44 mutable-item wire format - encode, sign, verify -
//!   in [`bep44`]. Covered by unit tests including spec-exact
//!   signing-input vectors (BEP-44 text example) and a proptest
//!   fuzz harness.
//! - An async [`DhtClient`] trait with a minimal `get` / `put_item`
//!   surface: ~20 lines of interface, nothing DHT-specific leaks.
//! - [`InMemoryDht`] - a test adapter for exercising the full
//!   Mirage `DiscoveryRouter` round-trip without touching the
//!   network.
//! - [`DhtChannel`] - implements [`mirage_discovery::DiscoveryChannel`]
//!   on top of any [`DhtClient`]. Drop it into a `DiscoveryRouter`
//!   alongside the existing Nostr channel and Mirage
//!   automatically fans out.
//!
//! Real network I/O is [`MainlineDhtClient`] (backed by the `mainline` crate).
//! The [`DhtClient`] trait boundary keeps the channel logic independent of the
//! backend, so tests use [`InMemoryDht`] and production uses the real client.
//!
//! # Threat-model notes
//!
//! - **DHT nodes are untrusted.** BEP-44 requires the signature check
//!   at the storage node, but an off-path passive observer or a
//!   Sybil Kademlia region can still serve stale / withheld values.
//!   The router's fan-out over multiple channels is the mitigation.
//! - **No operator-key exposure in puts, and read/write split.** The BEP-44
//!   signing pubkey `k` stored with every put is NOT the operator's long-term
//!   identity key. It is a per-epoch *blinding* of the operator identity key
//!   keyed on `info_hash` (see [`blinded`]); the operator (holding the identity
//!   secret) can sign, and the invite-holding fetcher can independently derive
//!   the same blinded pubkey from the operator's *public* identity key to
//!   locate and verify the record - but cannot recover the signing key, so it
//!   cannot forge a PUT (audit CRIT #17/#18). A Sybil node that observes a put
//!   cannot link `k` to the operator identity, cannot cluster an operator's
//!   puts across epochs (every epoch's `k` is unrelated), and cannot recognise
//!   it without the secret `shared_salt` (which gates `info_hash`).
//! - **Enumeration via DHT scraping.** An attacker WITHOUT the invite cannot
//!   compute the per-epoch info-hash or the derived `k`, so cannot locate or
//!   enumerate rendezvous points. An invite-holder can (that is inherent to any
//!   shared-secret rendezvous); the per-epoch rotation still means historical
//!   scraping does not yield current bridge locations.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod bep44;
pub mod blinded;

pub mod mainline_client;
pub use mainline_client::MainlineDhtClient;

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use mirage_discovery::channel::{ChannelError, DiscoveryChannel, MAX_PUBLISH_BYTES};
use mirage_discovery::derive::INFO_HASH_LEN;

pub use bep44::{
    info_hash_for, sign_item, signing_input, Bep44Error, SignedItem, BEP44_MAX_SALT_BYTES,
    BEP44_MAX_VALUE_BYTES, DHT_INFO_HASH_LEN, ED25519_PK_LEN, ED25519_SIG_LEN,
};

/// Errors produced by a [`DhtClient`] implementation. Wrapped into
/// [`ChannelError`] when the client is adapted into a
/// [`DiscoveryChannel`].
#[derive(Debug, thiserror::Error)]
pub enum DhtClientError {
    /// Transport-level failure (socket closed, timeout, Kademlia
    /// lookup failure).
    #[error("transport: {0}")]
    Transport(String),
    /// Peer refused - rate-limited, over-quota, or rejected a
    /// lower-`seq` put.
    #[error("refused: {0}")]
    Refused(String),
    /// Timed out.
    #[error("timeout")]
    Timeout,
    /// Underlying client is shut down or not yet initialized.
    #[error("unavailable")]
    Unavailable,
    /// A returned item failed BEP-44 verification. Returned by
    /// `get` implementations that choose to pre-filter; most
    /// clients will return everything and let the channel adapter
    /// filter.
    #[error("bep-44: {0}")]
    Bep44(#[from] Bep44Error),
}

impl From<DhtClientError> for ChannelError {
    fn from(e: DhtClientError) -> Self {
        match e {
            DhtClientError::Transport(s) => ChannelError::Transport(s),
            DhtClientError::Refused(s) => ChannelError::Refused(s),
            DhtClientError::Timeout => ChannelError::Timeout(0),
            DhtClientError::Unavailable => ChannelError::Unavailable("dht client"),
            DhtClientError::Bep44(_) => ChannelError::Invalid("bep-44 verification failed"),
        }
    }
}

/// Abstraction over a BitTorrent mainline DHT client that speaks
/// BEP-44.
///
/// Implementations are expected to be thin wrappers around an
/// existing Kademlia crate. The trait is minimal on purpose - only
/// the operations Mirage actually needs.
///
/// ## Object-safety
///
/// Object-safe so [`DhtChannel`] can hold an `Arc<dyn DhtClient>`.
#[async_trait]
pub trait DhtClient: Send + Sync {
    /// Publish (or refresh) a BEP-44 mutable item. Mainline DHT
    /// nodes reject a put whose `seq` is less than the stored
    /// value's; implementations SHOULD surface that as
    /// [`DhtClientError::Refused`] so the caller can bump and retry.
    async fn put_item(&self, item: &SignedItem) -> Result<(), DhtClientError>;

    /// Fetch all items for the given `(public_key, salt)` pair.
    ///
    /// The DHT target info-hash is `SHA-1(public_key || salt)`.
    /// Passing both components (rather than the pre-computed hash)
    /// lets implementations query real DHT nodes via `get_mutable(pk,
    /// salt)` without having to invert the SHA-1.
    ///
    /// In practice mainline returns at most one item per
    /// (pubkey, salt) tuple; implementations MAY return duplicates -
    /// the channel adapter dedups.
    async fn get(
        &self,
        public_key: &[u8; ED25519_PK_LEN],
        salt: Option<&[u8]>,
    ) -> Result<Vec<SignedItem>, DhtClientError>;

    /// Best-effort identifier for diagnostics.
    fn name(&self) -> &'static str;

    /// True iff the underlying client has at least one live
    /// bootstrap peer. Default: always up.
    fn is_healthy(&self) -> bool {
        true
    }
}

/// A [`DiscoveryChannel`] that stores Mirage announcement
/// ciphertexts as BEP-44 mutable items on a DHT.
///
/// ## Info-hash mapping
///
/// Mirage's per-epoch info-hash (`[u8; 20]`, spec §4) is used as
/// the BEP-44 `salt`. The DHT key (also `[u8; 20]`) is
/// `SHA-1(pubkey || salt)`. This means two different operators
/// asking for the same Mirage-level info-hash land at different
/// DHT keys - consistent with BEP-44's design and Mirage's
/// operator-isolated discovery.
///
/// ## Sequence numbers
///
/// Mainline rejects a put whose `seq` is strictly less than the
/// stored value's. Mirage callers pass the epoch number as `seq` -
/// monotonically increasing for a given (namespace, epoch)
/// slot.
pub struct DhtChannel<C: DhtClient> {
    client: C,
    /// Operator identity Ed25519 seed (the announcement signing key). The
    /// per-epoch BEP-44 key is a *blinding* of this identity keyed on the
    /// per-epoch info-hash (audit CRIT #17/#18), so the published pubkey `k` is
    /// DIFFERENT every epoch and is NOT the operator's long-term identity key -
    /// yet an invite-holder, who has only the identity *public* key, cannot
    /// reproduce the signing key and therefore cannot forge a PUT. See
    /// [`blinded`].
    operator_seed: mirage_crypto::zeroize::Zeroizing<[u8; 32]>,
    /// Seq counter provider. Callers typically fix this to the
    /// announcement's epoch; exposed here so pure-test adapters
    /// can override.
    seq_supplier: Box<dyn Fn() -> i64 + Send + Sync>,
}

impl<C: DhtClient> DhtChannel<C> {
    /// Construct a read-write DHT channel that signs PUTs with a per-epoch
    /// *blinding* of the operator identity key (`operator_seed`). Only a holder
    /// of the operator seed can publish; invite-holders (who have only the
    /// identity public key) can read but not forge. See [`blinded`].
    pub fn new<F>(client: C, operator_seed: [u8; 32], seq_supplier: F) -> Self
    where
        F: Fn() -> i64 + Send + Sync + 'static,
    {
        Self {
            client,
            operator_seed: mirage_crypto::zeroize::Zeroizing::new(operator_seed),
            seq_supplier: Box::new(seq_supplier),
        }
    }
}

#[async_trait]
impl<C: DhtClient + 'static> DiscoveryChannel for DhtChannel<C> {
    async fn publish(
        &self,
        info_hash: &[u8; INFO_HASH_LEN],
        ciphertext: &[u8],
    ) -> Result<(), ChannelError> {
        if ciphertext.len() > MAX_PUBLISH_BYTES {
            return Err(ChannelError::Invalid("publish over MAX_PUBLISH_BYTES"));
        }
        if ciphertext.len() > BEP44_MAX_VALUE_BYTES {
            return Err(ChannelError::Invalid(
                "publish over BEP-44 1000-byte value cap",
            ));
        }
        let seq = (self.seq_supplier)();
        let signer =
            blinded::DhtWriteIdentity::from_seed(&self.operator_seed).blinded_signer(info_hash);
        let item = bep44::sign_item_blinded(&signer, Some(info_hash), seq, ciphertext)
            .map_err(|_| ChannelError::Invalid("bep-44 sign"))?;
        self.client.put_item(&item).await.map_err(Into::into)
    }

    async fn fetch(&self, info_hash: &[u8; INFO_HASH_LEN]) -> Result<Vec<Vec<u8>>, ChannelError> {
        // The Mirage per-epoch info-hash is used as the BEP-44 salt.
        // We pass (pubkey, salt) separately so the DhtClient can
        // call mainline's get_mutable(pubkey, salt) directly without
        // needing to invert SHA-1(pubkey || salt).
        let identity = blinded::DhtWriteIdentity::from_seed(&self.operator_seed);
        let pubkey = blinded::blinded_public(&identity.public(), info_hash)
            .ok_or(ChannelError::Invalid("blinded pubkey"))?;
        let items = self
            .client
            .get(&pubkey, Some(info_hash))
            .await
            .map_err(ChannelError::from)?;
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            // Verify signature BEFORE returning bytes. A malicious
            // DHT node cannot plant a forged announcement; at worst
            // it can serve an old (but genuinely signed) one, which
            // the caller's epoch / freshness check catches.
            if item.verify().is_err() {
                continue;
            }
            // Also verify the item's declared key matches the
            // signing key we published under - defense-in-depth
            // against a node returning an item for the same
            // info-hash but a different publisher.
            if item.k != pubkey {
                continue;
            }
            out.push(item.v);
        }
        Ok(out)
    }

    fn name(&self) -> &'static str {
        self.client.name()
    }

    fn is_healthy(&self) -> bool {
        self.client.is_healthy()
    }
}

// Fetch-only DHT channel for clients who only hold the operator pubkey

/// A read-only [`DiscoveryChannel`] for clients that hold the discovery
/// `shared_salt` (from the invite) but never publish.
///
/// Publishing returns [`ChannelError::Unavailable`] - clients never write to
/// the DHT; only operators do (via `DhtChannel`). It derives the per-epoch
/// BEP-44 pubkey the operator published under by *blinding* the operator's
/// public identity key (`operator_ed25519_pk`, from the invite) with the
/// per-epoch info-hash (see [`blinded::blinded_public`]). It therefore holds
/// only the operator's PUBLIC key - never a signing key - so a compromised or
/// malicious client cannot forge a rendezvous PUT (audit CRIT #17/#18).
pub struct DhtFetchChannel<C: DhtClient> {
    client: C,
    operator_pk: [u8; 32],
    name: &'static str,
}

impl<C: DhtClient> DhtFetchChannel<C> {
    /// Construct a fetch-only DHT channel keyed by the operator's public
    /// identity key (`operator_ed25519_pk` from the invite).
    pub fn new(client: C, operator_pk: [u8; 32], name: &'static str) -> Self {
        Self {
            client,
            operator_pk,
            name,
        }
    }
}

#[async_trait]
impl<C: DhtClient + 'static> DiscoveryChannel for DhtFetchChannel<C> {
    async fn publish(
        &self,
        _info_hash: &[u8; INFO_HASH_LEN],
        _ciphertext: &[u8],
    ) -> Result<(), ChannelError> {
        Err(ChannelError::Unavailable("DhtFetchChannel is read-only"))
    }

    async fn fetch(&self, info_hash: &[u8; INFO_HASH_LEN]) -> Result<Vec<Vec<u8>>, ChannelError> {
        let pubkey = blinded::blinded_public(&self.operator_pk, info_hash)
            .ok_or(ChannelError::Invalid("blinded pubkey"))?;
        let items = self
            .client
            .get(&pubkey, Some(info_hash))
            .await
            .map_err(ChannelError::from)?;
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            if item.verify().is_err() {
                continue;
            }
            if item.k != pubkey {
                continue;
            }
            out.push(item.v);
        }
        Ok(out)
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn is_healthy(&self) -> bool {
        self.client.is_healthy()
    }
}

// In-memory mock for tests

/// In-memory DHT mock. Per-instance storage; `put_item` stores the
/// latest item per (`info_hash`) slot, mirroring mainline's "one
/// value per (pubkey, salt)" behavior.
///
/// Rejects a put whose `seq` is strictly less than the stored
/// value's - matches mainline's freshness rule so integration
/// tests catch the common "did you bump seq?" bug before it ever
/// reaches a real DHT.
pub struct InMemoryDht {
    storage: Mutex<HashMap<[u8; DHT_INFO_HASH_LEN], SignedItem>>,
}

impl InMemoryDht {
    /// Empty mock.
    pub fn new() -> Self {
        Self {
            storage: Mutex::new(HashMap::new()),
        }
    }

    /// Snapshot count of stored items. Metrics-only.
    pub fn len(&self) -> usize {
        self.storage.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// True iff nothing is stored.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for InMemoryDht {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DhtClient for InMemoryDht {
    async fn put_item(&self, item: &SignedItem) -> Result<(), DhtClientError> {
        // Verify on the way in - a real DHT node does this, and
        // the mock catching "operator produced an item that
        // doesn't verify" is useful for integration tests.
        item.verify().map_err(DhtClientError::Bep44)?;
        let key = item.info_hash();
        let mut m = self
            .storage
            .lock()
            .map_err(|_| DhtClientError::Transport("poisoned mutex".into()))?;
        if let Some(existing) = m.get(&key) {
            if item.seq < existing.seq {
                return Err(DhtClientError::Refused(format!(
                    "put seq={} < stored seq={}",
                    item.seq, existing.seq
                )));
            }
        }
        m.insert(key, item.clone());
        Ok(())
    }

    async fn get(
        &self,
        public_key: &[u8; ED25519_PK_LEN],
        salt: Option<&[u8]>,
    ) -> Result<Vec<SignedItem>, DhtClientError> {
        let key = info_hash_for(public_key, salt);
        let m = self
            .storage
            .lock()
            .map_err(|_| DhtClientError::Transport("poisoned mutex".into()))?;
        Ok(m.get(&key).cloned().into_iter().collect())
    }

    fn name(&self) -> &'static str {
        "in-memory-dht"
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_crypto::ed25519_dalek::SigningKey;

    fn op_key() -> SigningKey {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        SigningKey::from_bytes(&seed)
    }

    #[tokio::test]
    async fn publish_then_fetch_roundtrip() {
        let sk = op_key();
        let chan = DhtChannel::new(InMemoryDht::new(), sk.to_bytes(), || 1);
        let info_hash = [0xAAu8; INFO_HASH_LEN];
        let ct = b"announcement-ciphertext";
        chan.publish(&info_hash, ct).await.unwrap();
        let got = chan.fetch(&info_hash).await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(&got[0], ct);
    }

    #[test]
    fn per_epoch_key_is_deterministic_and_unlinkable() {
        use blinded::{blinded_public, DhtWriteIdentity};
        let seed = [0x11u8; 32];
        let pk = DhtWriteIdentity::from_seed(&seed).public();
        let ih1 = [0xAAu8; INFO_HASH_LEN];
        let ih2 = [0xBBu8; INFO_HASH_LEN];
        // Deterministic: operator (from seed) and client (from pubkey) derive
        // the SAME per-epoch blinded key.
        let op1 = DhtWriteIdentity::from_seed(&seed)
            .blinded_signer(&ih1)
            .public();
        let cl1 = blinded_public(&pk, &ih1).unwrap();
        assert_eq!(op1, cl1);
        // Unlinkable across epochs: a different info-hash -> a different pubkey,
        // so a Sybil cannot cluster an operator's puts across epochs.
        let op2 = DhtWriteIdentity::from_seed(&seed)
            .blinded_signer(&ih2)
            .public();
        assert_ne!(op1, op2);
        // Per-deployment: a different operator identity -> a different key.
        let pk_other = DhtWriteIdentity::from_seed(&[0x22u8; 32]).public();
        assert_ne!(op1, blinded_public(&pk_other, &ih1).unwrap());
        // The blinded key never equals the bare identity key on the wire.
        assert_ne!(op1, pk);
    }

    #[tokio::test]
    async fn fetch_channel_reads_publisher_puts_via_derived_key() {
        // A read-only client channel holding ONLY the operator PUBLIC key
        // derives the same per-epoch blinded key the publisher signed under
        // (from the operator seed) and reads its records - without ever holding
        // a signing key.
        let seed = [0x44u8; 32];
        let op_pk = blinded::DhtWriteIdentity::from_seed(&seed).public();
        let dht = std::sync::Arc::new(InMemoryDht::new());
        let publisher = DhtChannel::new(AsyncArc(dht.clone()), seed, || 1);
        let client = DhtFetchChannel::new(AsyncArc(dht.clone()), op_pk, "dht:test");
        let ih1 = [0x01u8; INFO_HASH_LEN];
        let ih2 = [0x02u8; INFO_HASH_LEN];
        publisher.publish(&ih1, b"epoch-1").await.unwrap();
        publisher.publish(&ih2, b"epoch-2").await.unwrap();
        assert_eq!(client.fetch(&ih1).await.unwrap(), vec![b"epoch-1".to_vec()]);
        assert_eq!(client.fetch(&ih2).await.unwrap(), vec![b"epoch-2".to_vec()]);
        // A client with the WRONG operator pubkey derives a different key -> reads
        // nothing (and could never have forged one either).
        let wrong_pk = blinded::DhtWriteIdentity::from_seed(&[0x99u8; 32]).public();
        let wrong = DhtFetchChannel::new(AsyncArc(dht.clone()), wrong_pk, "dht:wrong");
        assert!(wrong.fetch(&ih1).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn fetch_missing_returns_empty() {
        let sk = op_key();
        let chan = DhtChannel::new(InMemoryDht::new(), sk.to_bytes(), || 1);
        let got = chan.fetch(&[0u8; INFO_HASH_LEN]).await.unwrap();
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn publish_rejected_over_bep44_size() {
        let sk = op_key();
        let chan = DhtChannel::new(InMemoryDht::new(), sk.to_bytes(), || 1);
        let big = vec![0u8; BEP44_MAX_VALUE_BYTES + 1];
        let err = chan.publish(&[0u8; INFO_HASH_LEN], &big).await.unwrap_err();
        assert!(matches!(err, ChannelError::Invalid(_)));
    }

    #[tokio::test]
    async fn publish_rejected_over_mirage_size() {
        let sk = op_key();
        let chan = DhtChannel::new(InMemoryDht::new(), sk.to_bytes(), || 1);
        // The Mirage channel cap is stricter on paper but MAX_PUBLISH_BYTES
        // today (4 KiB) exceeds BEP-44's 1000-byte cap. The BEP-44 cap
        // is the binding constraint here - verify that by feeding
        // ~2 KiB which Mirage would accept on Nostr but DHT rejects.
        let mid = vec![0u8; 2048];
        let err = chan.publish(&[0u8; INFO_HASH_LEN], &mid).await.unwrap_err();
        assert!(matches!(err, ChannelError::Invalid(_)));
    }

    #[tokio::test]
    async fn lower_seq_put_is_refused_by_mock() {
        let sk = op_key();
        let dht = InMemoryDht::new();
        // Publish seq=5.
        let item5 = sign_item(&sk, Some(b"salt"), 5, b"v5").unwrap();
        dht.put_item(&item5).await.unwrap();
        // Lower seq should be refused.
        let item3 = sign_item(&sk, Some(b"salt"), 3, b"v3").unwrap();
        let err = dht.put_item(&item3).await.unwrap_err();
        assert!(matches!(err, DhtClientError::Refused(_)));
        // Equal seq is accepted (matches mainline behavior - updates
        // don't require strictly greater).
        let item5b = sign_item(&sk, Some(b"salt"), 5, b"v5b").unwrap();
        dht.put_item(&item5b).await.unwrap();
    }

    #[tokio::test]
    async fn publish_over_same_info_hash_overwrites() {
        let sk = op_key();
        let chan = DhtChannel::new(InMemoryDht::new(), sk.to_bytes(), || 1);
        let info_hash = [0xCCu8; INFO_HASH_LEN];
        chan.publish(&info_hash, b"first").await.unwrap();
        // Same seq (supplier returns 1 every time); the mock accepts
        // equal-seq updates. Mirage callers bump seq across epochs so
        // this is only exercised intra-epoch.
        chan.publish(&info_hash, b"second").await.unwrap();
        let got = chan.fetch(&info_hash).await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(&got[0], b"second");
    }

    #[tokio::test]
    async fn forged_item_does_not_verify_on_store() {
        // A malicious caller of the mock that hand-crafts a
        // SignedItem with a broken signature is caught by put_item.
        let sk = op_key();
        let mut item = sign_item(&sk, Some(b"s"), 1, b"v").unwrap();
        item.v[0] ^= 1;
        let err = InMemoryDht::new().put_item(&item).await.unwrap_err();
        assert!(matches!(err, DhtClientError::Bep44(_)));
    }

    #[tokio::test]
    async fn channel_filters_wrong_pubkey_on_fetch() {
        // Construct two channels with DIFFERENT signing keys on top
        // of a SHARED in-memory DHT. Channel A publishes. Channel B
        // fetching would see Channel A's item at the `(kB, salt)`
        // DHT slot - but only if the DHT somehow returned it. Our
        // mock is keyed by info_hash so the slot is empty for B.
        // This test codifies the intended isolation property.
        let dht = std::sync::Arc::new(InMemoryDht::new());
        let ska = op_key();
        let skb = op_key();
        let chan_a_dht = AsyncArc(dht.clone());
        let chan_b_dht = AsyncArc(dht.clone());
        let chan_a = DhtChannel::new(chan_a_dht, ska.to_bytes(), || 1);
        let chan_b = DhtChannel::new(chan_b_dht, skb.to_bytes(), || 1);
        let info_hash = [0xDDu8; INFO_HASH_LEN];
        chan_a.publish(&info_hash, b"A's record").await.unwrap();
        let got_b = chan_b.fetch(&info_hash).await.unwrap();
        assert!(
            got_b.is_empty(),
            "operator B must not see operator A's record under B's derived key"
        );
        let got_a = chan_a.fetch(&info_hash).await.unwrap();
        assert_eq!(got_a.len(), 1);
    }

    /// Tiny wrapper so we can hand an Arc<InMemoryDht> to
    /// `DhtChannel::new`, which takes the client by value.
    struct AsyncArc(std::sync::Arc<InMemoryDht>);

    #[async_trait]
    impl DhtClient for AsyncArc {
        async fn put_item(&self, item: &SignedItem) -> Result<(), DhtClientError> {
            self.0.put_item(item).await
        }
        async fn get(
            &self,
            public_key: &[u8; ED25519_PK_LEN],
            salt: Option<&[u8]>,
        ) -> Result<Vec<SignedItem>, DhtClientError> {
            self.0.get(public_key, salt).await
        }
        fn name(&self) -> &'static str {
            "in-memory-dht"
        }
    }

    /// Drop a `DhtChannel` into a `DiscoveryRouter` alongside an
    /// in-memory channel and verify fan-out: publishing to the
    /// router fans out to both channels; fetching collects from
    /// both and dedups. Proves the router doesn't need any
    /// DHT-specific knowledge - the trait boundary holds.
    #[tokio::test]
    async fn dht_channel_integrates_with_discovery_router() {
        use mirage_discovery::channel::InMemoryChannel;
        use mirage_discovery::router::{DiscoveryRouter, RouterConfig};
        use std::sync::Arc;

        let sk = op_key();
        let dht_chan: Arc<dyn DiscoveryChannel> =
            Arc::new(DhtChannel::new(InMemoryDht::new(), sk.to_bytes(), || 1));
        let mem_chan: Arc<dyn DiscoveryChannel> = Arc::new(InMemoryChannel::new("mem"));

        let router = DiscoveryRouter::new(
            vec![Arc::clone(&dht_chan), Arc::clone(&mem_chan)],
            RouterConfig::default(),
        );

        let info_hash = [0xE7u8; INFO_HASH_LEN];
        let payload = b"sealed-announcement";

        // Router publishes to every channel.
        let summary = router.publish(&info_hash, payload).await;
        assert!(summary.any_success(), "at least one channel must accept");

        // Router fetches from every channel, dedups.
        let got = router.fetch(&info_hash).await;
        assert!(!got.blobs.is_empty(), "router must return the blob");
        assert!(got.blobs.iter().any(|b| b.as_slice() == payload));
    }
}
