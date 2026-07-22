//! **Attack**: announcement version-byte leak.
//!
//! A passive observer of the discovery channel (Nostr / DHT / DNS-
//! TXT) collects every Mirage announcement and buckets them by
//! operator-key. For each operator, the observer counts
//! announcements with version byte `0x01` (`V0_1`, single-endpoint)
//! vs `0x02` (`V0_1T`, multi-endpoint). The mix reveals the
//! operator's redundancy strategy - fewer-bridge operators look
//! visibly different from multi-bridge operators.
//!
//! **Defense being tested**: universal `V0_1T` encoding regardless
//! of `extras_count` (RT-CN-9 closure).
//!
//! **Distinguisher we look for**: any announcement produced by
//! the encoder bears version `0x01`.

use crate::{AdversaryError, AdversaryResult, DetectionVerdict};
use mirage_crypto::ed25519_dalek::{Signer, SigningKey};
use mirage_discovery::wire::{
    transport_caps, Announcement, Endpoint, ANNOUNCEMENT_VERSION_V0_1T, SIG_LEN,
};

fn rand_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    getrandom::fill(&mut s).expect("CSPRNG");
    s
}

/// Run the version-byte leak attack. Mints two test announcements
/// (one with a single endpoint, one with multiple) and inspects
/// the encoded version bytes. Pre-RT-CN-9, the first would be
/// `0x01` and the second `0x02` - distinguishable. Post-RT-CN-9,
/// both are `0x02`.
pub async fn announcement_version_tag_leak() -> AdversaryResult {
    let op = SigningKey::from_bytes(&rand_seed());
    let bridge_ed = [0x11u8; 32];
    let bridge_x = [0x22u8; 32];
    let now = 1_700_000_000u64;

    let mut single = Announcement {
        issued_at: now,
        expires_at: now + 3600,
        bridge_ed25519_pk: bridge_ed,
        bridge_x25519_pk: bridge_x,
        transport_caps: transport_caps::REALITY_V2,
        endpoint: Endpoint::Ipv4 {
            addr: [10, 0, 0, 1],
            port: 443,
        },
        extra_endpoints: Vec::new(),
        signature: [0u8; SIG_LEN],
    };
    let mut prefix = Vec::new();
    single.encode_signed_prefix(&mut prefix);
    single.signature = op.sign(&prefix).to_bytes();
    let single_bytes = single.encode();

    let mut multi = Announcement {
        issued_at: now,
        expires_at: now + 3600,
        bridge_ed25519_pk: bridge_ed,
        bridge_x25519_pk: bridge_x,
        transport_caps: transport_caps::REALITY_V2,
        endpoint: Endpoint::Ipv4 {
            addr: [10, 0, 0, 2],
            port: 443,
        },
        extra_endpoints: vec![Endpoint::Ipv4 {
            addr: [10, 0, 0, 3],
            port: 443,
        }],
        signature: [0u8; SIG_LEN],
    };
    let mut prefix = Vec::new();
    multi.encode_signed_prefix(&mut prefix);
    multi.signature = op.sign(&prefix).to_bytes();
    let multi_bytes = multi.encode();

    // Defense check: both announcements MUST share the same
    // version byte. Pre-RT-CN-9 fix this returned (0x01, 0x02).
    if single_bytes[3] != multi_bytes[3] {
        return Ok(DetectionVerdict::Distinguished(format!(
            "single-endpoint announcement has version {:#04x}, multi-\
             endpoint has {:#04x} - operator redundancy strategy leaks. \
             Check `Announcement::encode_signed_prefix`.",
            single_bytes[3], multi_bytes[3]
        )));
    }
    // Sanity: the shared version MUST be V0_1T (not V0_1) so
    // legacy decoders treat the wire as "multi-endpoint capable."
    if single_bytes[3] != ANNOUNCEMENT_VERSION_V0_1T {
        return Ok(DetectionVerdict::Distinguished(format!(
            "encoded version {:#04x} != ANNOUNCEMENT_VERSION_V0_1T ({:#04x})",
            single_bytes[3], ANNOUNCEMENT_VERSION_V0_1T
        )));
    }
    Ok(DetectionVerdict::Defended)
}

/// Boxed [`Adversary`] wrapper.
pub struct AnnouncementVersionTagLeak;

#[async_trait::async_trait]
impl crate::Adversary for AnnouncementVersionTagLeak {
    async fn run(&self) -> Result<DetectionVerdict, AdversaryError> {
        announcement_version_tag_leak().await
    }
    fn name(&self) -> &'static str {
        "announcement_version_tag_leak"
    }
    fn defense(&self) -> &'static str {
        "RT-CN-9: universal V0_1T encoding in Announcement::encode_signed_prefix"
    }
}
