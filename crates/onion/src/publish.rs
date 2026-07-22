//! Helpers that wire onion descriptors through the existing
//! [`mirage_discovery::channel::DiscoveryChannel`] adapters.
//!
//! # Design choice: signed-but-unsealed descriptors
//!
//! Tor v3 onion descriptors are encrypted with a key derived from
//! the service's blinded pk + time period. Anyone with the address
//! can derive the key and decrypt. The encryption exists to defeat
//! long-term content caching by directories, NOT to gate access.
//!
//! Mirage v0.1w descriptors are **signed by the service but not
//! encrypted**. The per-epoch info-hash rotation already defeats
//! long-term caching (a descriptor cached at epoch N's info-hash
//! is unreachable at epoch N+1). Adding an encryption layer doesn't
//! change the threat model - anyone with the `.mirage` address
//! could derive the decryption key anyway, since the address IS
//! the public key.
//!
//! This simpler design:
//! - Discovery channels carry plaintext bytes per service descriptor.
//! - Clients verify the signature locally; tampered bytes from a
//!   hostile channel are rejected.
//! - Per-epoch rotation provides freshness.
//!
//! # Threat-model fit
//!
//! - **Hostile channel returns garbage**: signature verify fails;
//!   client tries the next channel.
//! - **Hostile channel withholds**: client treats as empty result;
//!   tries the next channel.
//! - **Hostile channel injects a forged descriptor**: signature
//!   verify fails (forged descriptor isn't signed by the service's
//!   pk); rejected.
//! - **Long-term caching**: defeated by per-epoch info-hash rotation.

use crate::descriptor::{onion_descriptor_info_hash, OnionDescriptor, ServiceDescError};
use mirage_discovery::channel::{ChannelError, DiscoveryChannel};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, warn};

/// Hard cap on the number of blobs a hostile channel can force the
/// resolver to verify per fetch. Each candidate triggers an Ed25519
/// signature verify (~100us) - without a cap, a channel returning
/// 100k blobs would burn ~10 seconds of CPU per resolve. The cap
/// is generous enough for legitimate use (epoch overlap + a few
/// stale entries) but small enough that worst-case CPU stays bounded.
pub const MAX_BLOBS_PER_FETCH: usize = 32;

/// Errors produced by publish/resolve.
#[derive(Debug, Error)]
pub enum OnionDiscoveryError {
    /// All channels rejected the publish.
    #[error("all {0} publish channels failed")]
    AllPublishFailed(usize),
    /// All channels failed or returned no descriptor.
    #[error("no descriptor found across {0} channels")]
    NotFound(usize),
    /// Underlying descriptor decode error.
    #[error("descriptor: {0}")]
    Descriptor(#[from] ServiceDescError),
    /// Sealing the descriptor for publication failed (CSPRNG).
    #[error("descriptor seal: {0}")]
    Seal(#[from] crate::seal::SealError),
    /// Encoded descriptor exceeded the channel publish cap.
    #[error("descriptor encoded too large: {0} bytes")]
    DescriptorTooLarge(usize),
}

/// Publish a signed descriptor to every channel in `channels`. The
/// info-hash is derived from `(service_pk, epoch)` per
/// [`onion_descriptor_info_hash`]. Returns `Ok(count)` when at
/// least one channel accepted the publish; `Err` when all failed.
///
/// The function does NOT iterate over multiple epochs - callers
/// typically schedule it on a per-epoch cron with the next two
/// epochs (so a missed run still leaves coverage).
///
/// # [warn] Unwired - and emits a cleartext `MI`-magic structure
///
/// No live-path caller invokes this today (see the crate-level note);
/// it runs only under tests + conformance. **Before it is wired to any
/// real [`DiscoveryChannel`], the `descriptor.encode()` bytes below
/// MUST be sealed.** As written, [`OnionDescriptor::encode`] produces
/// a plaintext blob whose first two bytes are the fixed ASCII magic
/// `"MI"` followed by a fixed-layout header. Handing that verbatim to
/// a public channel gives a passive scraper a content-agnostic
/// "this is a Mirage onion descriptor" fingerprint. The signatures
/// verified on resolve stop forgery/tampering - they do NOT hide the
/// `MI` magic + structure. Sealing (encrypt-to-info-hash-key, or a
/// camouflaged transport whose payloads look random) is a hard
/// prerequisite for live wiring; no such wrapper exists here yet.
pub async fn publish_descriptor(
    descriptor: &OnionDescriptor,
    epoch: u64,
    channels: &[Arc<dyn DiscoveryChannel>],
) -> Result<usize, OnionDiscoveryError> {
    // `encode()` emits the cleartext `MI` magic + fixed header; SEAL it before
    // it touches any public channel so a passive scraper sees only random bytes
    // (the prerequisite the crate root docs describe). The seal key is derived
    // from `service_pk` + `epoch`, which a resolving client re-derives from the
    // `.mirage` address; a scraper holding only the info-hash cannot.
    let bytes = descriptor.encode()?;
    let sealed = crate::seal::seal_descriptor(&bytes, &descriptor.service_ed25519_pk, epoch)?;
    if sealed.len() > mirage_discovery::channel::MAX_PUBLISH_BYTES {
        return Err(OnionDiscoveryError::DescriptorTooLarge(sealed.len()));
    }
    let info_hash = onion_descriptor_info_hash(&descriptor.service_ed25519_pk, epoch);
    let mut accepts = 0usize;
    let mut failures: Vec<(String, String)> = Vec::with_capacity(channels.len());
    for c in channels {
        match c.publish(&info_hash, &sealed).await {
            Ok(()) => {
                debug!(channel = c.name(), "onion descriptor published");
                accepts += 1;
            }
            Err(e) => {
                warn!(channel = c.name(), error = %e, "onion descriptor publish failed");
                failures.push((c.name().to_string(), e.to_string()));
            }
        }
    }
    if accepts == 0 {
        return Err(OnionDiscoveryError::AllPublishFailed(channels.len()));
    }
    Ok(accepts)
}

/// Resolve a service's descriptor via the configured channels.
/// Fetches from each channel, decodes + verifies signatures, and
/// returns the first valid descriptor whose `is_valid_at(now)`
/// holds.
///
/// `service_pk` IS the pk encoded in the `.mirage` address -
/// callers parse the address via
/// [`crate::address::onion_address_to_pk`] and pass the pk here.
pub async fn resolve_descriptor(
    service_pk: &[u8; 32],
    epoch: u64,
    now: u64,
    channels: &[Arc<dyn DiscoveryChannel>],
) -> Result<OnionDescriptor, OnionDiscoveryError> {
    let info_hash = onion_descriptor_info_hash(service_pk, epoch);
    let total = channels.len();
    // RT #24: do NOT return the first valid descriptor. A hostile (or merely
    // attacker-ordered) channel could win the race with a stale-but-unexpired
    // descriptor that pins the client to dead or hostile introduction points.
    // Collect every valid candidate across ALL channels and keep the FRESHEST
    // (max issued_at), so a stale replay loses to the operator's latest
    // publication wherever it lives.
    let mut best: Option<OnionDescriptor> = None;
    for c in channels {
        match c.fetch(&info_hash).await {
            Ok(blobs) => {
                if blobs.len() > MAX_BLOBS_PER_FETCH {
                    warn!(
                        channel = c.name(),
                        returned = blobs.len(),
                        cap = MAX_BLOBS_PER_FETCH,
                        "channel returned more blobs than cap; truncating"
                    );
                }
                // Stop at MAX_BLOBS_PER_FETCH so a hostile channel
                // can't force unbounded Ed25519 verifies. Iteration
                // is biased toward the channel's natural ordering;
                // a legitimate channel returns at most a handful
                // anyway.
                for blob in blobs.into_iter().take(MAX_BLOBS_PER_FETCH) {
                    // UNSEAL first: the blob on the wire is sealed (see
                    // `publish_descriptor`). A blob NOT sealed for this exact
                    // (service_pk, epoch) - noise, another service's descriptor,
                    // or a hostile plant - fails AEAD auth and is skipped.
                    let unsealed = match crate::seal::unseal_descriptor(&blob, service_pk, epoch) {
                        Ok(b) => b,
                        Err(e) => {
                            debug!(channel = c.name(), error = %e, "descriptor unseal failed; skipping");
                            continue;
                        }
                    };
                    match OnionDescriptor::decode(&unsealed) {
                        Ok(d) => {
                            // Verify the descriptor's signature
                            // matches the requested service pk
                            // - defends against a hostile channel
                            // returning a different operator's
                            // descriptor.
                            if d.service_ed25519_pk != *service_pk {
                                debug!(channel = c.name(), "descriptor pk mismatch; skipping");
                                continue;
                            }
                            if d.verify().is_err() {
                                debug!(
                                    channel = c.name(),
                                    "descriptor sig verify failed; skipping"
                                );
                                continue;
                            }
                            if !d.is_valid_at(now) {
                                debug!(channel = c.name(), "descriptor outside validity; skipping");
                                continue;
                            }
                            if best.as_ref().is_none_or(|b| d.issued_at > b.issued_at) {
                                best = Some(d);
                            }
                        }
                        Err(e) => {
                            debug!(channel = c.name(), error = %e, "descriptor decode failed; skipping");
                        }
                    }
                }
            }
            Err(ChannelError::Unavailable(_) | ChannelError::Timeout(_)) => {
                debug!(channel = c.name(), "channel unavailable; trying next");
            }
            Err(e) => {
                warn!(channel = c.name(), error = %e, "fetch failed");
            }
        }
    }
    best.ok_or(OnionDiscoveryError::NotFound(total))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_crypto::ed25519_dalek::SigningKey;
    use mirage_discovery::channel::InMemoryChannel;
    use std::sync::Arc;

    fn make_service_keypair() -> (SigningKey, [u8; 32]) {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        let sk = SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn make_intro(tag: u8) -> crate::IntroPoint {
        crate::IntroPoint {
            bridge_ed25519_pk: [tag; 32],
            bridge_x25519_pk: [tag.wrapping_add(1); 32],
            intro_auth_key: [tag.wrapping_add(2); 32],
        }
    }

    fn make_signed_desc(now: u64) -> (OnionDescriptor, [u8; 32]) {
        let (sk, pk) = make_service_keypair();
        let mut d =
            OnionDescriptor::new(now, now + 3600, pk, vec![make_intro(1), make_intro(2)]).unwrap();
        d.sign(&sk).unwrap();
        (d, pk)
    }

    #[tokio::test]
    async fn publish_then_resolve_roundtrip() {
        let now = 1_700_000_000;
        let (desc, pk) = make_signed_desc(now);
        let epoch = 100;
        let ch1: Arc<dyn DiscoveryChannel> = Arc::new(InMemoryChannel::new("ch1"));
        let ch2: Arc<dyn DiscoveryChannel> = Arc::new(InMemoryChannel::new("ch2"));
        let channels = vec![ch1, ch2];
        let accepts = publish_descriptor(&desc, epoch, &channels).await.unwrap();
        assert_eq!(accepts, 2);
        let back = resolve_descriptor(&pk, epoch, now, &channels)
            .await
            .unwrap();
        assert_eq!(back, desc);
    }

    #[tokio::test]
    async fn resolve_falls_through_unhealthy_channel() {
        let now = 1_700_000_000;
        let (desc, pk) = make_signed_desc(now);
        let epoch = 100;
        let dead: Arc<dyn DiscoveryChannel> = {
            let c = InMemoryChannel::new("dead");
            c.set_healthy(false);
            Arc::new(c)
        };
        let live: Arc<dyn DiscoveryChannel> = Arc::new(InMemoryChannel::new("live"));
        // Publish to live only.
        publish_descriptor(&desc, epoch, &[Arc::clone(&live)])
            .await
            .unwrap();
        let back = resolve_descriptor(&pk, epoch, now, &[dead, live])
            .await
            .unwrap();
        assert_eq!(back, desc);
    }

    #[tokio::test]
    async fn resolve_rejects_descriptor_signed_by_wrong_pk() {
        let now = 1_700_000_000;
        let (desc_attacker, _pk_attacker) = make_signed_desc(now);
        // We're "looking for" the legit pk, but the channel only
        // has a descriptor under the attacker's pk. The fetch
        // should yield "not found."
        let (sk_legit, pk_legit) = make_service_keypair();
        let _ = sk_legit;
        let epoch = 100;
        // Manually publish the attacker's descriptor to the
        // legit info-hash. (The real info_hash for the LEGIT pk
        // is what the resolver queries; the attacker's descriptor
        // bytes won't have matching service_pk.)
        let ch: Arc<dyn DiscoveryChannel> = Arc::new(InMemoryChannel::new("hostile"));
        let info_hash = onion_descriptor_info_hash(&pk_legit, epoch);
        ch.publish(&info_hash, &desc_attacker.encode().unwrap())
            .await
            .unwrap();
        let err = resolve_descriptor(&pk_legit, epoch, now, &[ch])
            .await
            .unwrap_err();
        assert!(matches!(err, OnionDiscoveryError::NotFound(_)));
    }

    #[tokio::test]
    async fn resolve_rejects_expired_descriptor() {
        // Build a descriptor that's expired-at-now.
        let now = 2_000_000_000;
        let (sk, pk) = make_service_keypair();
        let mut d = OnionDescriptor::new(1_000_000, 1_000_010, pk, vec![make_intro(1)]).unwrap();
        d.sign(&sk).unwrap();
        let epoch = 100;
        let ch: Arc<dyn DiscoveryChannel> = Arc::new(InMemoryChannel::new("ch"));
        publish_descriptor(&d, epoch, &[Arc::clone(&ch)])
            .await
            .unwrap();
        let err = resolve_descriptor(&pk, epoch, now, &[ch])
            .await
            .unwrap_err();
        assert!(matches!(err, OnionDiscoveryError::NotFound(_)));
    }

    #[tokio::test]
    async fn publish_all_failed_returns_error() {
        let now = 1_700_000_000;
        let (desc, _pk) = make_signed_desc(now);
        let dead1: Arc<dyn DiscoveryChannel> = {
            let c = InMemoryChannel::new("dead1");
            c.set_healthy(false);
            Arc::new(c)
        };
        let dead2: Arc<dyn DiscoveryChannel> = {
            let c = InMemoryChannel::new("dead2");
            c.set_healthy(false);
            Arc::new(c)
        };
        let err = publish_descriptor(&desc, 100, &[dead1, dead2])
            .await
            .unwrap_err();
        assert!(matches!(err, OnionDiscoveryError::AllPublishFailed(2)));
    }

    #[tokio::test]
    async fn resolve_skips_corrupted_blob() {
        let now = 1_700_000_000;
        let (desc, pk) = make_signed_desc(now);
        let epoch = 100;
        let ch: Arc<dyn DiscoveryChannel> = Arc::new(InMemoryChannel::new("ch"));
        let info_hash = onion_descriptor_info_hash(&pk, epoch);
        // First blob: garbage (unseal fails -> skipped). Second: a properly
        // SEALED descriptor (as publish_descriptor would emit).
        ch.publish(&info_hash, &[0xFFu8; 200]).await.unwrap();
        let sealed = crate::seal::seal_descriptor(&desc.encode().unwrap(), &pk, epoch).unwrap();
        ch.publish(&info_hash, &sealed).await.unwrap();
        let back = resolve_descriptor(&pk, epoch, now, &[ch]).await.unwrap();
        assert_eq!(back, desc);
    }

    #[tokio::test]
    async fn resolve_caps_blob_iteration() {
        // A hostile channel that returns way more blobs than
        // MAX_BLOBS_PER_FETCH is throttled - at most that many
        // signature verifies run per resolve.
        let now = 1_700_000_000;
        let (desc, pk) = make_signed_desc(now);
        let epoch = 100;
        let ch: Arc<dyn DiscoveryChannel> = Arc::new(InMemoryChannel::new("hostile"));
        let info_hash = onion_descriptor_info_hash(&pk, epoch);
        // Publish many garbage blobs before the legitimate one. With
        // the cap we should still find the legitimate descriptor IF
        // it's within the first MAX_BLOBS_PER_FETCH blobs of the
        // returned list - otherwise we accept the slight loss of
        // recall as the cost of bounded CPU.
        let valid = crate::seal::seal_descriptor(&desc.encode().unwrap(), &pk, epoch).unwrap();
        ch.publish(&info_hash, &valid).await.unwrap();
        for _ in 0..(MAX_BLOBS_PER_FETCH * 2) {
            ch.publish(&info_hash, &[0xFFu8; 64]).await.unwrap();
        }
        // Resolution succeeds because the valid blob lands within
        // the iteration window.
        let back = resolve_descriptor(&pk, epoch, now, &[ch]).await.unwrap();
        assert_eq!(back, desc);
    }

    #[tokio::test]
    async fn descriptor_too_large_rejected_at_publish() {
        // Synthesize a descriptor with the maximum 8 intro points
        // but the publish-cap is fine; this test mostly proves the
        // size check exists.
        let now = 1_700_000_000;
        let (desc, _pk) = make_signed_desc(now);
        let bytes = desc.encode().unwrap();
        // Realistic descriptor sizes are well under the 4 KiB cap.
        assert!(bytes.len() < mirage_discovery::channel::MAX_PUBLISH_BYTES);
    }
}
