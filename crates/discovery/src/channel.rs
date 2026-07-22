//! Pluggable discovery-channel trait and in-memory test adapter.
//!
//! Implements the `DiscoveryChannel` contract. A channel is any mechanism by which an
//! operator can publish an opaque encrypted blob keyed by a 20-byte
//! `info_hash`, and a client can fetch all blobs published under that
//! `info_hash`.
//!
//! The protocol layer is I/O-free: Mirage does not own the transport for
//! a channel (WebSocket to a Nostr relay, UDP for DHT, HTTPS for a
//! domain-fronted broker, etc.). Channels live behind the trait so the
//! router above them is agnostic.
//!
//! # Threat-model notes
//!
//! - **Channels are untrusted.** A compromised or hostile relay can
//!   return arbitrary bytes, withhold some announcements, re-order, or
//!   inject gibberish. The router MUST fan out to multiple channels and
//!   the caller MUST verify every blob end-to-end (`seal::open` +
//!   operator-signature check) before trusting it.
//! - **Fetch is a linkability signal.** A client subscribing to an
//!   `info_hash` tells the relay "I'm probably a Mirage client looking
//!   for this epoch's bridges." Bootstrap-privacy mitigations live at
//!   the router layer; the trait itself is agnostic.
//! - **Publish is a linkability signal for operators.** The relay learns
//!   the operator's Nostr pubkey via event signature. Operators SHOULD
//!   rotate their Nostr identity (operator mother key attestations make
//!   this cheap).

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;
use thiserror::Error;

use crate::derive::INFO_HASH_LEN;

/// Errors produced by a [`DiscoveryChannel`].
///
/// These are **transport-level** failures. Protocol-level issues
/// (signature invalid, decryption failed, stale epoch) are not surfaced
/// here - those live in [`crate::DiscoveryError`] and are handled by
/// the caller after fetching bytes.
#[derive(Debug, Error)]
pub enum ChannelError {
    /// Transport-level failure (socket closed, TLS handshake, HTTP 5xx).
    #[error("transport: {0}")]
    Transport(String),

    /// The channel refused the publish (rate-limited, over-quota, banned).
    /// Distinct from `Transport` because retry policy differs - we do
    /// NOT retry on `Refused`, to avoid DoS'ing a failing relay.
    #[error("refused: {0}")]
    Refused(String),

    /// Timed out before the operation completed.
    #[error("timeout after {0}ms")]
    Timeout(u64),

    /// The channel is shut down or otherwise unavailable.
    #[error("unavailable: {0}")]
    Unavailable(&'static str),

    /// Operator mis-use of the channel (exceeds size budget, etc).
    #[error("invalid: {0}")]
    Invalid(&'static str),
}

/// A pluggable discovery channel.
///
/// Implementations are **object-safe** (`dyn DiscoveryChannel`) so the
/// router can hold a heterogeneous `Vec<Arc<dyn DiscoveryChannel>>`.
/// Every method is `&self` - implementations MUST use interior
/// mutability for their connection state.
///
/// ## Sizing constraints
///
/// Announcement ciphertexts (spec §5.1) are bounded at ~768 bytes
/// plaintext; after ChaCha20-Poly1305 and base64 (where applicable)
/// they are well under 2 KiB. Implementations MUST reject blobs
/// larger than [`MAX_PUBLISH_BYTES`] to protect against memory
/// exhaustion from hostile callers of `publish`.
#[async_trait]
pub trait DiscoveryChannel: Send + Sync {
    /// Publish `ciphertext` under `info_hash`.
    ///
    /// Completion semantics: returns `Ok(())` once at least one relay
    /// has acknowledged storage. The caller MAY publish to multiple
    /// channels in parallel for redundancy (see [`super::router::DiscoveryRouter`]).
    async fn publish(
        &self,
        info_hash: &[u8; INFO_HASH_LEN],
        ciphertext: &[u8],
    ) -> Result<(), ChannelError>;

    /// Fetch all blobs published under `info_hash`.
    ///
    /// Returns an empty vector if the channel has no records - this is
    /// NOT an error. Returns [`ChannelError::Transport`] only on actual
    /// connectivity failures. The router treats an empty return and a
    /// transport failure differently: empty means "I looked and found
    /// nothing" (satisfies redundancy); transport failure means "I
    /// couldn't look" (does not satisfy redundancy).
    async fn fetch(&self, info_hash: &[u8; INFO_HASH_LEN]) -> Result<Vec<Vec<u8>>, ChannelError>;

    /// Stable identifier for diagnostics and metrics labels.
    fn name(&self) -> &'static str;

    /// True iff the channel currently believes it can serve requests.
    /// Used by the router to short-circuit calls to a known-dead channel.
    /// Default: always up.
    fn is_healthy(&self) -> bool {
        true
    }

    /// Per-channel liveness snapshot: last-success timestamp and a
    /// per-channel error class for the last failed call. Used by
    /// the router to skip channels whose last_success is too stale
    /// and to surface diagnostics.
    ///
    /// Default: returns "always-fresh, no-error" so channels that
    /// don't track liveness internally keep working unchanged.
    fn liveness(&self) -> ChannelLiveness {
        ChannelLiveness::default()
    }

    /// Per-channel rate budget: max queries-per-minute the router
    /// will issue against this channel. The router caps its own
    /// query rate at this value to avoid pestering a partially-
    /// failed channel.
    ///
    /// Default: 60 (= one query per second average), tuned for
    /// Nostr / DHT relays. Channels with tighter or looser budgets
    /// override.
    fn rate_budget_per_minute(&self) -> u32 {
        60
    }
}

/// Per-channel liveness snapshot, returned by
/// [`DiscoveryChannel::liveness`].
#[derive(Debug, Clone, Default)]
pub struct ChannelLiveness {
    /// Last-success Unix time, or `None` if the channel has never
    /// succeeded since process start. The router treats `None` and
    /// "very old" as equivalent for skipping decisions.
    pub last_success_unix: Option<u64>,
    /// Last-error class (if any). Used for diagnostics, not for
    /// skipping decisions - a channel that errored once but
    /// recovered should still be queried.
    pub last_error_class: Option<ChannelErrorClass>,
}

/// Coarse-grained classification of the last channel error.
/// Diagnostics-only; the router doesn't make policy decisions
/// based on error class alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelErrorClass {
    /// Transport-layer failure (network unreachable, TCP RST, TLS
    /// handshake failed).
    Transport,
    /// Channel refused (rate-limited, banned, over-quota).
    Refused,
    /// Operation timed out.
    Timeout,
    /// Channel reported itself unavailable.
    Unavailable,
    /// Caller mis-use (invalid input, exceeded budget).
    Invalid,
}

impl From<&ChannelError> for ChannelErrorClass {
    fn from(e: &ChannelError) -> Self {
        match e {
            ChannelError::Transport(_) => ChannelErrorClass::Transport,
            ChannelError::Refused(_) => ChannelErrorClass::Refused,
            ChannelError::Timeout(_) => ChannelErrorClass::Timeout,
            ChannelError::Unavailable(_) => ChannelErrorClass::Unavailable,
            ChannelError::Invalid(_) => ChannelErrorClass::Invalid,
        }
    }
}

/// Hard cap on a single published blob, enforced before handing bytes
/// to the network layer. The per-channel protocol will enforce its own
/// cap too (Nostr: [`mirage_discovery_nostr::wrap::MAX_CONTENT_LEN`]
/// = 2048; DHT BEP-44: 1000). 4 KiB is generous relative to the
/// announcement wire max (~800 B) and keeps worst-case sends bounded.
pub const MAX_PUBLISH_BYTES: usize = 4096;

/// In-memory, single-process [`DiscoveryChannel`] for tests and local
/// dev rigs.
///
/// Stores everything in a `Mutex<HashMap<info_hash, Vec<ciphertext>>>`.
/// Publishes append; fetches return a clone of the stored vector.
/// Deliberately keeps **all** ciphertexts for an `info_hash` so the
/// client-side dedupe logic (identical blobs from multiple channels)
/// can be exercised end-to-end.
///
/// Optional fault injection: set [`InMemoryChannel::set_healthy`] to
/// `false` to simulate a dead relay; all calls return
/// [`ChannelError::Unavailable`].
pub struct InMemoryChannel {
    name: &'static str,
    store: Mutex<HashMap<[u8; INFO_HASH_LEN], Vec<Vec<u8>>>>,
    // `std::sync::atomic::AtomicBool` would be cleaner but we already pay
    // the mutex cost elsewhere; using a bool under the same mutex keeps
    // state coherent without extra primitives.
    healthy: Mutex<bool>,
}

impl InMemoryChannel {
    /// Construct a new healthy channel with the given diagnostic name.
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            store: Mutex::new(HashMap::new()),
            healthy: Mutex::new(true),
        }
    }

    /// Flip the simulated health state. `false` -> all calls return
    /// [`ChannelError::Unavailable`].
    pub fn set_healthy(&self, healthy: bool) {
        if let Ok(mut g) = self.healthy.lock() {
            *g = healthy;
        }
    }

    /// Total number of stored ciphertexts across all info-hashes.
    /// Test-observability only; never a security predicate.
    pub fn total_stored(&self) -> usize {
        self.store
            .lock()
            .map(|g| g.values().map(Vec::len).sum())
            .unwrap_or(0)
    }
}

#[async_trait]
impl DiscoveryChannel for InMemoryChannel {
    async fn publish(
        &self,
        info_hash: &[u8; INFO_HASH_LEN],
        ciphertext: &[u8],
    ) -> Result<(), ChannelError> {
        if !self.is_healthy() {
            return Err(ChannelError::Unavailable("fault-injected"));
        }
        if ciphertext.len() > MAX_PUBLISH_BYTES {
            return Err(ChannelError::Invalid("ciphertext exceeds publish cap"));
        }
        match self.store.lock() {
            Ok(mut g) => {
                g.entry(*info_hash).or_default().push(ciphertext.to_vec());
                Ok(())
            }
            Err(_) => Err(ChannelError::Unavailable("store mutex poisoned")),
        }
    }

    async fn fetch(&self, info_hash: &[u8; INFO_HASH_LEN]) -> Result<Vec<Vec<u8>>, ChannelError> {
        if !self.is_healthy() {
            return Err(ChannelError::Unavailable("fault-injected"));
        }
        match self.store.lock() {
            Ok(g) => Ok(g.get(info_hash).cloned().unwrap_or_default()),
            Err(_) => Err(ChannelError::Unavailable("store mutex poisoned")),
        }
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn is_healthy(&self) -> bool {
        self.healthy.lock().map(|g| *g).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ih(n: u8) -> [u8; INFO_HASH_LEN] {
        [n; INFO_HASH_LEN]
    }

    #[tokio::test]
    async fn publish_then_fetch_roundtrip() {
        let ch = InMemoryChannel::new("mem");
        ch.publish(&ih(1), b"hello").await.unwrap();
        let got = ch.fetch(&ih(1)).await.unwrap();
        assert_eq!(got, vec![b"hello".to_vec()]);
    }

    #[tokio::test]
    async fn fetch_missing_returns_empty_not_error() {
        let ch = InMemoryChannel::new("mem");
        let got = ch.fetch(&ih(42)).await.unwrap();
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn publish_accumulates_under_same_info_hash() {
        let ch = InMemoryChannel::new("mem");
        ch.publish(&ih(1), b"a").await.unwrap();
        ch.publish(&ih(1), b"b").await.unwrap();
        ch.publish(&ih(1), b"c").await.unwrap();
        let got = ch.fetch(&ih(1)).await.unwrap();
        assert_eq!(
            got,
            vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()],
            "publish order preserved for test observability"
        );
    }

    #[tokio::test]
    async fn different_info_hashes_independent() {
        let ch = InMemoryChannel::new("mem");
        ch.publish(&ih(1), b"a").await.unwrap();
        ch.publish(&ih(2), b"b").await.unwrap();
        assert_eq!(ch.fetch(&ih(1)).await.unwrap(), vec![b"a".to_vec()]);
        assert_eq!(ch.fetch(&ih(2)).await.unwrap(), vec![b"b".to_vec()]);
    }

    #[tokio::test]
    async fn fault_injected_channel_is_unavailable() {
        let ch = InMemoryChannel::new("mem");
        ch.set_healthy(false);
        assert!(matches!(
            ch.publish(&ih(1), b"x").await.unwrap_err(),
            ChannelError::Unavailable(_)
        ));
        assert!(matches!(
            ch.fetch(&ih(1)).await.unwrap_err(),
            ChannelError::Unavailable(_)
        ));
        assert!(!ch.is_healthy());
    }

    #[tokio::test]
    async fn recovers_from_fault_injection() {
        let ch = InMemoryChannel::new("mem");
        ch.set_healthy(false);
        assert!(ch.publish(&ih(1), b"x").await.is_err());
        ch.set_healthy(true);
        ch.publish(&ih(1), b"x").await.unwrap();
        assert_eq!(ch.fetch(&ih(1)).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn publish_over_cap_is_rejected() {
        let ch = InMemoryChannel::new("mem");
        let huge = vec![0u8; MAX_PUBLISH_BYTES + 1];
        match ch.publish(&ih(1), &huge).await {
            Err(ChannelError::Invalid(_)) => {}
            other => panic!("expected Invalid, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn dyn_discovery_channel_is_object_safe() {
        // Compile-time property: we can hold the channel behind a trait object.
        let ch: std::sync::Arc<dyn DiscoveryChannel> =
            std::sync::Arc::new(InMemoryChannel::new("mem"));
        ch.publish(&ih(1), b"x").await.unwrap();
        assert_eq!(ch.fetch(&ih(1)).await.unwrap().len(), 1);
        assert_eq!(ch.name(), "mem");
    }
}
