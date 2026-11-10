//! Real `BitTorrent` mainline DHT client backed by the `mainline` crate.
//!
//! Always compiled - `mainline` is a hard dependency of this crate and this
//! module is `pub mod` unconditionally (there is no `mainline` feature flag; an
//! earlier version of this note claimed one). Implements [`DhtClient`] so it
//! slots into a [`DhtChannel`] - no changes to the upper layers.
//!
//! # Bootstrap
//!
//! [`MainlineDhtClient::new`] starts the DHT node immediately. The node
//! bootstraps from the global list of well-known `BitTorrent` bootstrap
//! servers (`dht.transmissionbt.com:6881`, `router.bittorrent.com:6881`,
//! etc.) unless overridden by [`MainlineDhtClient::new_with_bootstrap`].
//!
//! # Thread safety
//!
//! `mainline::AsyncDht` is `Clone + Send + Sync`; this wrapper is
//! `Send + Sync + Clone`. Wrap in `Arc<dyn DhtClient>` to share across
//! tasks (the `Arc` is cheap - the underlying DHT node runs one actor
//! thread regardless of clone count).
//!
//! # Threat model
//!
//! Real DHT nodes are untrusted. Items returned by `get_mutable` are
//! BEP-44-verified by the network layer; we additionally verify them in
//! `DhtChannel::fetch` before handing bytes up to `ClientSubscriber`.
//! A Sybil-attacked DHT region can withhold announcements but cannot
//! forge them. Multi-channel fan-out (Nostr + DNS TXT + DHT) is the
//! mitigation.

use async_trait::async_trait;
use mainline::{async_dht::AsyncDht, Dht, MutableItem};
use tracing::debug;

use crate::{DhtClient, DhtClientError, SignedItem, ED25519_PK_LEN};

/// Real mainline DHT client.
pub struct MainlineDhtClient {
    dht: AsyncDht,
    name: &'static str,
}

impl MainlineDhtClient {
    /// Start a DHT node using the default bootstrap servers.
    pub fn new() -> Result<Self, DhtClientError> {
        let dht = Dht::builder()
            .build()
            .map_err(|e| DhtClientError::Transport(format!("dht build: {e}")))?
            .as_async();
        Ok(Self {
            dht,
            name: "mainline-dht",
        })
    }

    /// Start a DHT node using a custom set of bootstrap addresses.
    ///
    /// `bootstrap_addrs` should be `"host:port"` strings. Useful for
    /// testing against a private testnet or for censorship-resistant
    /// bootstrap via a pre-obtained peer list.
    pub fn new_with_bootstrap(bootstrap_addrs: &[String]) -> Result<Self, DhtClientError> {
        let parsed: Vec<&str> = bootstrap_addrs
            .iter()
            .map(std::string::String::as_str)
            .collect();
        let dht = Dht::builder()
            .bootstrap(&parsed)
            .build()
            .map_err(|e| DhtClientError::Transport(format!("dht build: {e}")))?
            .as_async();
        Ok(Self {
            dht,
            name: "mainline-dht",
        })
    }
}

impl Clone for MainlineDhtClient {
    fn clone(&self) -> Self {
        Self {
            dht: self.dht.clone(),
            name: self.name,
        }
    }
}

#[async_trait]
impl DhtClient for MainlineDhtClient {
    async fn put_item(&self, item: &SignedItem) -> Result<(), DhtClientError> {
        // Convert our SignedItem to mainline's MutableItem using the
        // pre-computed signature - no re-signing. Both use the same
        // BEP-44 signing input format so DHT nodes will verify it.
        let mutable = MutableItem::new_signed_unchecked(
            item.k,
            item.sig,
            &item.v,
            item.seq,
            item.salt.as_deref(),
        );
        self.dht
            .put_mutable(mutable, None)
            .await
            .map(|_| ())
            .map_err(|e| DhtClientError::Transport(format!("put_mutable: {e}")))
    }

    async fn get(
        &self,
        public_key: &[u8; ED25519_PK_LEN],
        salt: Option<&[u8]>,
    ) -> Result<Vec<SignedItem>, DhtClientError> {
        // DHT stores one item per (pubkey, salt) slot; fetch the
        // highest-seq one from across all responding nodes.
        let maybe = self.dht.get_mutable_most_recent(public_key, salt).await;
        let Some(item) = maybe else {
            return Ok(Vec::new());
        };
        debug!(
            target: "mirage_discovery_dht",
            seq = item.seq(),
            "mainline: got mutable item"
        );
        // Convert mainline's MutableItem back to our SignedItem.
        // Signature bytes use the same BEP-44 format - `verify` will accept.
        let signed = SignedItem {
            k: *item.key(),
            salt: item.salt().map(<[u8]>::to_vec),
            seq: item.seq(),
            v: item.value().to_vec(),
            sig: *item.signature(),
        };
        Ok(vec![signed])
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn is_healthy(&self) -> bool {
        // AsyncDht doesn't expose a direct "is bootstrapped" check
        // without async. Return true conservatively; operators can
        // observe the DHT's health via logs if needed.
        true
    }
}
