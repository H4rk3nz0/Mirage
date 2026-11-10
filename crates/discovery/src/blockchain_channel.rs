//! Blockchain-anchored discovery channel - encrypted bridge-descriptor
//! registry on a high-collateral public ledger.
//!
//! # Why a ledger
//!
//! Nostr relays, DHTs, and DNS-TXT records can each be taken down or have a
//! poisoned view fed to one client (eclipse). A public ledger adds three
//! properties the others lack: **availability** (immutable, can't be deleted),
//! **global consistency** (every reader sees the same state - a censor cannot
//! hand one client a forged bridge list without forging it for everyone, which
//! a high-collateral chain makes ruinously expensive), and **high collateral
//! to block** (blocking reads of a popular chain's RPC carries broad fallout).
//! This is the [`DiscoveryChannel`] sibling to Nostr/DHT/DNS-TXT.
//!
//! # The non-negotiable safety property: CIPHERTEXT ONLY
//!
//! A public ledger is permanent + globally readable, so putting a cleartext
//! bridge address on it would hand the censor a perfect, un-takedownable
//! blocklist - the immutability would work *against* us. This channel stores
//! ONLY what the discovery layer already sealed: [`DiscoveryChannel::publish`]
//! takes `ciphertext` (the output of [`crate::seal::seal`], a per-epoch AEAD
//! blob decryptable only by holders of the cohort `shared_salt`). The ledger
//! sees opaque bytes. Ciphertext-only is therefore inherent to the trait -
//! this adapter never sees, derives, or logs a node address.
//!
//! # Authenticity comes from the operator signature, NEVER the ledger
//!
//! A ledger gives you ordering + non-equivocation; it does NOT authenticate
//! content (anyone who can write the ledger can write *a* blob). Authenticity
//! is the operator's Ed25519 signature INSIDE the sealed announcement
//! ([`crate::wire::Announcement::verify`]), which the discovery pipeline checks
//! against the operator key pinned out-of-band in the invite. A hostile ledger
//! that serves a forged blob fails one of: decryption (wrong salt) or the inner
//! signature - and is rejected upstream. This channel inherits that safety; it
//! deliberately does NOT trust the ledger for anything but availability.
//!
//! # Substrate-agnostic backend
//!
//! [`RegistryBackend`] abstracts the ledger so the on-chain mechanism (an EVM
//! L2 sealed-blob contract, a Bitcoin commitment, ...) can be swapped without
//! touching the channel. [`InMemoryRegistry`] is the offline backend for tests
//! and single-host cohorts - no chain dependency. A real chain backend (with
//! anonymized publishing and private reads - the two halves of "don't disclose
//! the reader/writer") is a separate, heavier crate; this module is the
//! offline-testable core.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;
use thiserror::Error;

use crate::channel::{ChannelError, DiscoveryChannel, MAX_PUBLISH_BYTES};
use crate::derive::INFO_HASH_LEN;

/// Error from a [`RegistryBackend`] ledger operation.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// The backend (chain RPC, contract call, local store) failed.
    #[error("registry backend: {0}")]
    Backend(String),
    /// The backend is currently unreachable (e.g. RPC down).
    #[error("registry unavailable: {0}")]
    Unavailable(String),
}

/// Substrate-agnostic append-only blob ledger.
///
/// An implementation anchors `blob`s on a real ledger (EVM contract storage /
/// event log, Bitcoin commitment, ...). It stores ONLY the bytes it is given -
/// which the [`BlockchainDiscoveryChannel`] guarantees are already-sealed
/// ciphertext - and MUST NOT attempt to interpret, log, or derive cleartext
/// from them.
#[async_trait]
pub trait RegistryBackend: Send + Sync {
    /// Append `blob` under `key`. Append-only: multiple blobs may accumulate
    /// under one key (e.g. successive epochs, or several bridges).
    async fn append(&self, key: &[u8; INFO_HASH_LEN], blob: Vec<u8>) -> Result<(), RegistryError>;

    /// Read every blob stored under `key`. Empty is NOT an error.
    async fn read(&self, key: &[u8; INFO_HASH_LEN]) -> Result<Vec<Vec<u8>>, RegistryError>;

    /// Stable identifier for diagnostics.
    fn name(&self) -> &'static str;

    /// Whether the backend believes it can currently serve.
    fn is_healthy(&self) -> bool {
        true
    }
}

/// Default cap on blobs retained per key by [`InMemoryRegistry`] - bounds
/// memory if a hostile writer appends many blobs under one key. Oldest are
/// dropped first.
pub const DEFAULT_REGISTRY_BLOBS_PER_KEY: usize = 64;

/// Offline in-memory ledger: an append-only `key -> [blob]` map. For tests and
/// single-host cohorts. No chain dependency, no network. Models the *behaviour*
/// of a real ledger (append-only, globally consistent within the process) so
/// the channel + pipeline can be exercised end-to-end without a live chain.
pub struct InMemoryRegistry {
    store: Mutex<HashMap<[u8; INFO_HASH_LEN], Vec<Vec<u8>>>>,
    blobs_per_key: usize,
}

impl Default for InMemoryRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryRegistry {
    /// Construct with the default per-key blob cap.
    pub fn new() -> Self {
        Self::with_blobs_per_key(DEFAULT_REGISTRY_BLOBS_PER_KEY)
    }

    /// Construct with an explicit per-key blob cap.
    pub fn with_blobs_per_key(blobs_per_key: usize) -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
            blobs_per_key: blobs_per_key.max(1),
        }
    }
}

#[async_trait]
impl RegistryBackend for InMemoryRegistry {
    async fn append(&self, key: &[u8; INFO_HASH_LEN], blob: Vec<u8>) -> Result<(), RegistryError> {
        let Ok(mut g) = self.store.lock() else {
            return Err(RegistryError::Backend("registry mutex poisoned".into()));
        };
        let entry = g.entry(*key).or_default();
        // Dedup exact-duplicate blobs (a re-publish of an identical sealed blob
        // is a no-op rather than an accumulating duplicate).
        if !entry.iter().any(|b| b == &blob) {
            entry.push(blob);
            if entry.len() > self.blobs_per_key {
                let overflow = entry.len() - self.blobs_per_key;
                entry.drain(0..overflow);
            }
        }
        Ok(())
    }

    async fn read(&self, key: &[u8; INFO_HASH_LEN]) -> Result<Vec<Vec<u8>>, RegistryError> {
        let Ok(g) = self.store.lock() else {
            return Err(RegistryError::Backend("registry mutex poisoned".into()));
        };
        Ok(g.get(key).cloned().unwrap_or_default())
    }

    fn name(&self) -> &'static str {
        "in-memory-registry"
    }
}

/// A [`DiscoveryChannel`] backed by a ledger ([`RegistryBackend`]).
///
/// Stores already-sealed ciphertext blobs under their `info_hash` and reads
/// them back. Ciphertext-only and authenticity-via-operator-signature are
/// enforced by the layers above/inside (see the module docs); this adapter
/// only bridges the channel trait to the ledger backend.
pub struct BlockchainDiscoveryChannel<B: RegistryBackend> {
    backend: B,
    max_blob: usize,
}

impl<B: RegistryBackend> BlockchainDiscoveryChannel<B> {
    /// Wrap `backend` with the default per-blob size cap
    /// ([`MAX_PUBLISH_BYTES`]).
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            max_blob: MAX_PUBLISH_BYTES,
        }
    }

    /// Borrow the underlying backend (diagnostics / advanced wiring).
    pub fn backend(&self) -> &B {
        &self.backend
    }
}

#[async_trait]
impl<B: RegistryBackend> DiscoveryChannel for BlockchainDiscoveryChannel<B> {
    async fn publish(
        &self,
        info_hash: &[u8; INFO_HASH_LEN],
        ciphertext: &[u8],
    ) -> Result<(), ChannelError> {
        // A ledger write is expensive and size-bounded; reject anything over
        // the publish cap before paying for it. (A valid sealed announcement is
        // well under this - see `crate::pipeline`.)
        if ciphertext.len() > self.max_blob {
            return Err(ChannelError::Invalid("blob exceeds ledger publish cap"));
        }
        self.backend
            .append(info_hash, ciphertext.to_vec())
            .await
            .map_err(|e| ChannelError::Transport(e.to_string()))
    }

    async fn fetch(&self, info_hash: &[u8; INFO_HASH_LEN]) -> Result<Vec<Vec<u8>>, ChannelError> {
        self.backend
            .read(info_hash)
            .await
            .map_err(|e| ChannelError::Transport(e.to_string()))
    }

    fn name(&self) -> &'static str {
        "blockchain"
    }

    fn is_healthy(&self) -> bool {
        self.backend.is_healthy()
    }
}

// Revocations on the ledger are NOT a separate mechanism here: the existing
// `OperatorPublisher::publish_revocation` (crate::pipeline) already signs AND
// **seals** a `wire::Revocation` and fans it out over the router's channels,
// and `ClientSubscriber` fetches + verifies it. Using a
// `BlockchainDiscoveryChannel` as one of those channels anchors sealed
// revocations on the ledger for free - keeping ciphertext-only intact (a raw
// `Revocation` carries the bridge identity key in cleartext, so it must never
// be published unsealed). Do NOT add an unsealed revocation log here.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::NAMESPACE_CLIENT_TO_BRIDGE;
    use crate::seal::{open, seal};

    fn ih(n: u8) -> [u8; INFO_HASH_LEN] {
        [n; INFO_HASH_LEN]
    }

    #[tokio::test]
    async fn publish_then_fetch_round_trips() {
        let ch = BlockchainDiscoveryChannel::new(InMemoryRegistry::new());
        let key = ih(1);
        assert!(
            ch.fetch(&key).await.unwrap().is_empty(),
            "empty key -> empty"
        );
        ch.publish(&key, b"blob-a").await.unwrap();
        ch.publish(&key, b"blob-b").await.unwrap();
        let got = ch.fetch(&key).await.unwrap();
        assert_eq!(got.len(), 2);
        assert!(got.contains(&b"blob-a".to_vec()));
        assert!(got.contains(&b"blob-b".to_vec()));
    }

    #[tokio::test]
    async fn duplicate_publish_is_idempotent() {
        let ch = BlockchainDiscoveryChannel::new(InMemoryRegistry::new());
        let key = ih(2);
        ch.publish(&key, b"same").await.unwrap();
        ch.publish(&key, b"same").await.unwrap();
        assert_eq!(ch.fetch(&key).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn distinct_keys_are_independent() {
        let ch = BlockchainDiscoveryChannel::new(InMemoryRegistry::new());
        ch.publish(&ih(3), b"x").await.unwrap();
        assert!(ch.fetch(&ih(4)).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn oversized_blob_rejected() {
        let ch = BlockchainDiscoveryChannel::new(InMemoryRegistry::new());
        let big = vec![0u8; MAX_PUBLISH_BYTES + 1];
        assert!(ch.publish(&ih(5), &big).await.is_err());
    }

    #[tokio::test]
    async fn per_key_blob_cap_bounds_memory() {
        let ch = BlockchainDiscoveryChannel::new(InMemoryRegistry::with_blobs_per_key(4));
        let key = ih(6);
        for i in 0..20u8 {
            ch.publish(&key, &[i]).await.unwrap();
        }
        assert!(ch.fetch(&key).await.unwrap().len() <= 4);
    }

    /// End-to-end of the intended flow: a SEALED announcement is the only thing
    /// that ever reaches the ledger; a holder of the cohort salt fetches and
    /// OPENS it. Proves the channel carries ciphertext-only and round-trips the
    /// real seal layer (the nonce-randomised one).
    #[tokio::test]
    async fn seal_publish_fetch_open_round_trip() {
        let salt = *b"0123456789abcdef0123456789abcdef";
        let epoch = 100u64;
        let plaintext = b"ANNOUNCE bridge descriptor (would carry an address)";
        let ciphertext = seal(&salt, NAMESPACE_CLIENT_TO_BRIDGE, epoch, plaintext).unwrap();

        let ch = BlockchainDiscoveryChannel::new(InMemoryRegistry::new());
        let key = ih(7);
        ch.publish(&key, &ciphertext).await.unwrap();

        let blobs = ch.fetch(&key).await.unwrap();
        assert_eq!(blobs.len(), 1);
        // The blob on the "ledger" is opaque ciphertext, not the plaintext.
        assert_ne!(&blobs[0], plaintext);
        // A salt holder recovers the descriptor.
        let recovered = open(&salt, NAMESPACE_CLIENT_TO_BRIDGE, epoch, &blobs[0]).unwrap();
        assert_eq!(recovered, plaintext);
    }
}
