//! Mirage discovery layer.
//!
//! Implements the epoch-rotated rendezvous scheme.
//!
//! # Module layout
//!
//! - [`derive`] - rolling info-hash / cipher-key derivation (§4)
//! - [`wire`] - announcement / revocation codecs (§5, §7)
//! - [`seal`] - per-epoch ChaCha20-Poly1305 seal/open (§5.5)
//! - [`error`] - discovery-layer errors
//!
//! Channel adapters (Nostr, DHT) land in follow-up modules once their wire
//! plumbing is spec'd and implemented.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod blockchain_channel;
pub mod channel;
pub mod claim;
pub mod claim_client;
pub mod cohort;
pub mod cohort_client;
pub mod cohort_gossip;
pub mod cohort_gossip_tcp;
pub mod cohort_persist;
pub mod derive;
pub mod error;
pub mod invite;
pub mod mesh;
pub mod pipeline;
pub mod pool;
pub mod ratchet;
pub mod refresh;
pub mod refresh_client;
pub mod replay;
pub mod replay_log;
pub mod rotalog;
pub mod router;
pub mod seal;
pub mod token;
pub mod token_fs;
pub mod wire;

pub use channel::{ChannelError, DiscoveryChannel, InMemoryChannel, MAX_PUBLISH_BYTES};
pub use claim::{
    ClaimRequest, ClaimResponse, CLAIM_CMD_REDEEM, CLAIM_MAGIC_HOSTNAME, CLAIM_MAGIC_PORT,
    CLAIM_REQUEST_LEN, CLAIM_STATUS_ALREADY_CLAIMED, CLAIM_STATUS_BAD_REQUEST,
    CLAIM_STATUS_CAPACITY, CLAIM_STATUS_OK, CLAIM_STATUS_POLICY, CLAIM_VERSION,
};
pub use claim_client::{redeem_invite_claim, ClaimClientError, ClaimOutcome};
pub use cohort::{
    CohortRequest, CohortResponse, InMemoryRevealStore, RevealStore, COHORT_CMD_LIST,
    COHORT_MAGIC_HOSTNAME, COHORT_MAGIC_PORT, COHORT_MAX_N_PER_REQUEST, COHORT_STATUS_EMPTY,
    COHORT_STATUS_EXHAUSTED, COHORT_STATUS_OK, COHORT_VERSION, DEFAULT_PER_TOKEN_REVEAL_CAP,
};
pub use cohort_client::{refresh_cohort, CohortClientError, CohortRefresh};
pub use cohort_gossip::{
    CohortGossip, GossipEvent, MemoryGossip, SignedGossipEvent, GOSSIP_SIGN_DOMAIN,
    GOSSIP_WIRE_MAGIC, MAX_GOSSIP_EVENT_WIRE_LEN,
};
pub use cohort_gossip_tcp::{TcpCohortGossip, TcpCohortGossipConfig};
pub use cohort_persist::{FileRevealStore, FileRevealStoreError};
pub use derive::{derive_port, DERIVED_PORT_MIN};
pub use error::DiscoveryError;
pub use invite::{
    BootstrapToken, MasterInvite, BOOTSTRAP_TOKEN_LEN, DOC_TYPE_INVITE, INVITE_VERSION_V0_1,
    MAX_BOOTSTRAP_TOKENS, MAX_CHANNEL_HINTS_BYTES, MAX_INVITE_BYTES,
};
pub use pipeline::{ClientSubscriber, DiscoveryFetch, OperatorPublisher};
pub use pool::{ApplyReport, BridgeEntry, BridgePool, EvictReason, SelectionPolicy};
pub use refresh::{
    sign_refresh_token, RefreshRequest, RefreshResponse, SessionRefreshToken,
    DEFAULT_REFRESH_PER_ROOT_CAP, DEFAULT_REFRESH_TTL_SECONDS, REFRESH_CMD_ISSUE,
    REFRESH_MAGIC_HOSTNAME, REFRESH_MAGIC_PORT, REFRESH_MAX_PER_REQUEST, REFRESH_SIGN_DOMAIN,
    REFRESH_STATUS_BAD_REQUEST, REFRESH_STATUS_EXHAUSTED, REFRESH_STATUS_INTERNAL,
    REFRESH_STATUS_OK, REFRESH_STATUS_POLICY, REFRESH_VERSION,
};
pub use refresh_client::{refresh_session_tokens, RefreshBatch, RefreshClientError};
pub use replay_log::{
    PersistentReplayLog, ReplayLogError, MRRL_HEADER_LEN, MRRL_MAGIC, MRRL_RECORD_LEN, MRRL_VERSION,
};
pub use router::{DiscoveryRouter, FetchSummary, PublishReport, PublishSummary, RouterConfig};

/// Spec §4.4 epoch-skew grace window (seconds).
pub const CLOCK_SKEW_GRACE_SECONDS: u64 = 60;

#[cfg(test)]
mod integration_tests {
    //! End-to-end round-trips that cross module boundaries.

    use super::derive::{info_hash, NAMESPACE_CLIENT_TO_BRIDGE};
    use super::seal::{open, seal};
    use super::wire::{
        transport_caps, Announcement, Endpoint, Revocation, RevocationReason, SIG_LEN,
    };
    use mirage_crypto::ed25519_dalek::{Signer, SigningKey};

    fn op_keypair() -> SigningKey {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        SigningKey::from_bytes(&seed)
    }

    fn salt() -> [u8; 32] {
        *b"abcdef0123456789abcdef0123456789"
    }

    #[test]
    fn announcement_sign_seal_open_verify() {
        let op = op_keypair();
        let op_pk: [u8; 32] = op.verifying_key().to_bytes();
        let s = salt();
        let epoch = 1000;

        // Build + sign an announcement.
        let mut ann = Announcement {
            issued_at: 1_000_000,
            expires_at: 1_003_600,
            bridge_ed25519_pk: [0x11u8; 32],
            bridge_x25519_pk: [0x22u8; 32],
            transport_caps: transport_caps::REALITY_V2 | transport_caps::QUIC_MASQUE,
            endpoint: Endpoint::Ipv4 {
                addr: [93, 184, 216, 34],
                port: 443,
            },
            extra_endpoints: Vec::new(),
            signature: [0u8; SIG_LEN],
        };
        let mut prefix = Vec::new();
        ann.encode_signed_prefix(&mut prefix);
        ann.signature = op.sign(&prefix).to_bytes();
        let plaintext = ann.encode();

        // Seal for this epoch.
        let ciphertext = seal(&s, NAMESPACE_CLIENT_TO_BRIDGE, epoch, &plaintext).unwrap();
        let _ih = info_hash(&s, NAMESPACE_CLIENT_TO_BRIDGE, epoch);

        // Open and verify.
        let recovered = open(&s, NAMESPACE_CLIENT_TO_BRIDGE, epoch, &ciphertext).unwrap();
        assert_eq!(recovered, plaintext);
        let parsed = Announcement::decode(&recovered).unwrap();
        parsed.verify(&op_pk).unwrap();
    }

    #[test]
    fn revocation_sign_seal_open_verify() {
        let op = op_keypair();
        let op_pk: [u8; 32] = op.verifying_key().to_bytes();
        let s = salt();
        let epoch = 1000;

        let mut rev = Revocation {
            target_ed25519_pk: [0xAAu8; 32],
            reason: RevocationReason::Compromised,
            issued_at: 1_000_500,
            signature: [0u8; SIG_LEN],
        };
        let mut prefix = Vec::new();
        rev.encode_signed_prefix(&mut prefix);
        rev.signature = op.sign(&prefix).to_bytes();

        let plaintext = rev.encode();
        let ciphertext = seal(&s, NAMESPACE_CLIENT_TO_BRIDGE, epoch, &plaintext).unwrap();
        let recovered = open(&s, NAMESPACE_CLIENT_TO_BRIDGE, epoch, &ciphertext).unwrap();
        let parsed = Revocation::decode(&recovered).unwrap();
        parsed.verify(&op_pk).unwrap();
    }
}
