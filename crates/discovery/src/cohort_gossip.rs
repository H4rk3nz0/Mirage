//! Cohort gossip: real entry-node-to-entry-node cooperation.
//!
//! # Why
//!
//! Multi-entry cooperative routing establishes that cohort members
//! share an operator key and a
//! [`crate::RevealStore`]. That's necessary but not sufficient
//! cooperation. Real cooperation means **entry nodes talk to
//! each other** about live operational state - not just sharing
//! a backing database.
//!
//! Specifically:
//!
//! - Entry A sees a probe scan from IP X -> entry B should
//!   refuse traffic from IP X within seconds.
//! - Entry A burns a token (msg_3 accepted) -> entry B should
//!   refuse the same token (within propagation delay).
//! - Entry A is being DDoSed -> entry B should absorb traffic
//!   so the client experience doesn't degrade.
//!
//! Without gossip, each entry runs its replay-set + abuse
//! detection independently. A censor probing 3 entries with the
//! same scan pattern sees 3 independent "first-time-this-IP"
//! responses, even though it's the same scan.
//!
//! # Model
//!
//! [`CohortGossip`] is the trait operators implement. The
//! reference implementation [`MemoryGossip`] is for in-process
//! tests + single-host cohorts. Production multi-host cohorts
//! plug in a network-backed implementation (Redis pub/sub,
//! Nostr relay, custom UDP multicast, peer-to-peer libp2p,
//! etc.) - out of scope here; the trait is the contract.
//!
//! # Events
//!
//! - [`GossipEvent::TokenBurned`]: token_id was just consumed
//!   at the publishing entry. Peers add to their replay-set.
//! - [`GossipEvent::ProbeScanDetected`]: source IP showed a
//!   probe pattern. Peers add to their soft-block list.
//! - [`GossipEvent::EntryDistressed`]: the publishing entry is
//!   overloaded (CPU / mem / connection count near cap). Peers
//!   pre-emptively absorb traffic if they can.
//! - [`GossipEvent::CohortMembership`]: list of currently-alive
//!   cohort members from the publisher's view. Used for
//!   in-cohort consensus on which peers are reachable.
//! - [`GossipEvent::ClaimObserved`]: the publisher just accepted a
//!   first-use invite-claim. Carries only a cohort-keyed *tag* of
//!   the claim id (never the id itself). Peers' leak detector flags
//!   the tag when it is seen from two or more DISTINCT publishers -
//!   cross-bridge claim equivocation, i.e. a leaked/shared invite.
//!   This closes the cross-bridge gap documented in
//!   [`crate::claim`] (a leaked invite claimed at bridge A *and*
//!   bridge B). Detection, not prevention: the output is for
//!   operator review, since a roaming user re-claiming legitimately
//!   on a new device can also produce the signal.
//!
//! Events are signed by the publishing entry's Ed25519 identity
//! key (which the operator's announcement names) so a censor
//! who taps the gossip channel can't inject false events.

use crate::error::DiscoveryError;
use mirage_crypto::ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

/// Gossip-domain separator for Ed25519 signatures.
pub const GOSSIP_SIGN_DOMAIN: &[u8] = b"mirage-cohort-gossip-v1";

/// Hard cap on a single gossip event's wire length, including
/// header. 4 KiB is well above any legitimate event size
/// (`CohortMembership` with 64 peers is ~2.2 KiB) and protects
/// readers from a malicious peer sending a 4-GiB length prefix.
pub const MAX_GOSSIP_EVENT_WIRE_LEN: usize = 4096;

/// Wire-format magic + version. 4 bytes so the wire codec can
/// be sniffed on a wireshark capture.
pub const GOSSIP_WIRE_MAGIC: &[u8; 4] = b"MGv1";

/// One gossip event published by an entry to its peers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GossipEvent {
    /// A capability token was just consumed at the publishing
    /// entry. Peers add it to their replay-set so the same
    /// token can't be re-used elsewhere.
    TokenBurned {
        /// 32-byte token id from `CapabilityToken::token_id`.
        token_id: [u8; 32],
        /// Unix-second timestamp of the burn at the publisher.
        burned_at: u64,
    },
    /// The publisher detected a probe scan from this source IP.
    /// Peers SHOULD apply soft-block (tarpit-style fast close,
    /// no real accept) to subsequent connections from this IP
    /// for `expire_secs`.
    ProbeScanDetected {
        /// Source IP of the probe.
        source_ip: IpAddr,
        /// How long (seconds) peers should soft-block.
        expire_secs: u32,
        /// Unix-second timestamp of detection.
        detected_at: u64,
    },
    /// Publisher is at high load. Peers SHOULD pre-emptively
    /// absorb traffic destined for this publisher if they can
    /// reach the same downstream relay.
    EntryDistressed {
        /// Publisher's bridge Ed25519 pk (so peers can correlate).
        publisher_ed_pk: [u8; 32],
        /// Severity from 0 (light) to 255 (saturated).
        severity: u8,
        /// Unix-second timestamp.
        observed_at: u64,
    },
    /// Periodic heartbeat: publisher's view of which cohort
    /// members it can currently reach. Peers reconcile with
    /// their own view to detect partitions.
    CohortMembership {
        /// Publisher's Ed25519 pk.
        publisher_ed_pk: [u8; 32],
        /// Peers the publisher believes are alive (their
        /// Ed25519 pks).
        alive: Vec<[u8; 32]>,
        /// Unix-second timestamp.
        observed_at: u64,
    },
    /// The publisher just accepted a first-use invite-claim
    /// ([`crate::claim::CLAIM_STATUS_OK`]). Peers correlate the
    /// `claim_tag` across publishers to detect a leaked invite
    /// claimed at more than one bridge (cross-bridge equivocation).
    ///
    /// The payload is deliberately minimal - only an opaque,
    /// cohort-keyed tag of the claim id (see
    /// [`crate::claim::claim_observation_tag`]) and a timestamp. The
    /// raw claim id is NEVER gossiped: it is itself an
    /// authentication credential, and a third-party observer of the
    /// gossip channel must not learn which invites are in use. Two
    /// cohort bridges that observe the same claim id independently
    /// derive the *same* tag (the key is cohort-wide), so the
    /// correlation works without ever exposing the id.
    ClaimObserved {
        /// Cohort-keyed BLAKE3 tag of the claim id (privacy-
        /// preserving; the same claim id maps to the same tag at
        /// every cohort bridge).
        claim_tag: [u8; 32],
        /// Unix-second timestamp the claim was accepted.
        observed_at: u64,
    },
}

impl GossipEvent {
    /// The Unix-seconds timestamp embedded in the event
    /// (`burned_at` / `detected_at` / `observed_at`). Used by
    /// the replay-protection check (RT-GS-7).
    pub fn timestamp(&self) -> u64 {
        match self {
            GossipEvent::TokenBurned { burned_at, .. } => *burned_at,
            GossipEvent::ProbeScanDetected { detected_at, .. } => *detected_at,
            GossipEvent::EntryDistressed { observed_at, .. } => *observed_at,
            GossipEvent::CohortMembership { observed_at, .. } => *observed_at,
            GossipEvent::ClaimObserved { observed_at, .. } => *observed_at,
        }
    }

    /// Serialise the event to a deterministic byte form for
    /// signing. Wire-format-stable: implementations across
    /// versions MUST produce the same bytes for the same
    /// event.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(GOSSIP_SIGN_DOMAIN);
        match self {
            GossipEvent::TokenBurned {
                token_id,
                burned_at,
            } => {
                out.push(0x01);
                out.extend_from_slice(token_id);
                out.extend_from_slice(&burned_at.to_be_bytes());
            }
            GossipEvent::ProbeScanDetected {
                source_ip,
                expire_secs,
                detected_at,
            } => {
                out.push(0x02);
                match source_ip {
                    IpAddr::V4(v4) => {
                        out.push(0x01);
                        out.extend_from_slice(&v4.octets());
                    }
                    IpAddr::V6(v6) => {
                        out.push(0x02);
                        out.extend_from_slice(&v6.octets());
                    }
                }
                out.extend_from_slice(&expire_secs.to_be_bytes());
                out.extend_from_slice(&detected_at.to_be_bytes());
            }
            GossipEvent::EntryDistressed {
                publisher_ed_pk,
                severity,
                observed_at,
            } => {
                out.push(0x03);
                out.extend_from_slice(publisher_ed_pk);
                out.push(*severity);
                out.extend_from_slice(&observed_at.to_be_bytes());
            }
            GossipEvent::CohortMembership {
                publisher_ed_pk,
                alive,
                observed_at,
            } => {
                out.push(0x04);
                out.extend_from_slice(publisher_ed_pk);
                out.extend_from_slice(&(alive.len() as u32).to_be_bytes());
                for pk in alive {
                    out.extend_from_slice(pk);
                }
                out.extend_from_slice(&observed_at.to_be_bytes());
            }
            GossipEvent::ClaimObserved {
                claim_tag,
                observed_at,
            } => {
                out.push(0x05);
                out.extend_from_slice(claim_tag);
                out.extend_from_slice(&observed_at.to_be_bytes());
            }
        }
        out
    }
}

/// A signed gossip event ready for wire transmission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedGossipEvent {
    /// The event payload.
    pub event: GossipEvent,
    /// Publisher's Ed25519 pk.
    pub publisher_ed_pk: [u8; 32],
    /// Ed25519 signature over `(GOSSIP_SIGN_DOMAIN || event.signing_bytes())`.
    pub signature: [u8; 64],
}

impl SignedGossipEvent {
    /// Sign a `GossipEvent` with the publisher's signing key.
    pub fn sign(event: GossipEvent, signing_key: &SigningKey) -> Self {
        let bytes = event.signing_bytes();
        let signature = signing_key.sign(&bytes).to_bytes();
        Self {
            event,
            publisher_ed_pk: signing_key.verifying_key().to_bytes(),
            signature,
        }
    }

    /// Verify against `expected_publisher_pk`. Returns Ok iff
    /// the publisher matches AND the signature verifies AND the
    /// event's own `publisher_ed_pk` (for events that contain
    /// one) matches.
    pub fn verify(&self, expected_publisher_pk: &[u8; 32]) -> Result<(), DiscoveryError> {
        if &self.publisher_ed_pk != expected_publisher_pk {
            return Err(DiscoveryError::Wire("gossip: publisher pk mismatch"));
        }
        // Event-specific consistency.
        match &self.event {
            GossipEvent::EntryDistressed {
                publisher_ed_pk, ..
            }
            | GossipEvent::CohortMembership {
                publisher_ed_pk, ..
            } => {
                if publisher_ed_pk != expected_publisher_pk {
                    return Err(DiscoveryError::Wire(
                        "gossip: embedded publisher pk doesn't match outer",
                    ));
                }
            }
            // TokenBurned / ProbeScanDetected / ClaimObserved carry NO
            // embedded publisher pk by design - there is nothing to
            // cross-check against the outer signature. In particular
            // ClaimObserved MUST stay this way: the leak detector counts
            // distinct *outer* (authenticated) publisher pks, so a tag
            // is correctly attributed without the event carrying one.
            // Do not "consistency-fix" these into the arm above.
            _ => {}
        }
        let vk = VerifyingKey::from_bytes(&self.publisher_ed_pk)
            .map_err(|_| DiscoveryError::Wire("gossip: bad publisher pk"))?;
        let sig = mirage_crypto::ed25519_dalek::Signature::from_bytes(&self.signature);
        // verify_strict (D4-01): reject non-canonical / malleable signatures,
        // matching the rest of the codebase. `verify()` does NOT dedup replays -
        // freshness alone lets a captured, still-fresh frame be re-injected
        // repeatedly. Dedup is the IMPLEMENTOR's obligation: every
        // [`CohortGossip::publish`] MUST feed [`Self::replay_key`] into a bounded
        // expiring seen-set before acting on / re-broadcasting the event. Strict
        // verification is what makes that key sound: without it a captured
        // signature could be mauled into a distinct (fresh-looking) one that
        // hashes differently and slips past the seen-set.
        vk.verify_strict(&self.event.signing_bytes(), &sig)
            .map_err(|_| DiscoveryError::Wire("gossip: signature verify failed"))
    }

    /// Replay-dedup key for this signed event: `blake3(signature)`.
    ///
    /// The signature covers the event's (timestamped) `signing_bytes`, so a
    /// byte-identical replay of a captured frame yields the SAME key, while two
    /// genuinely distinct events (distinct timestamps) yield different keys.
    /// Implementors of [`CohortGossip`] MUST feed this into a bounded, expiring
    /// seen-set (e.g. [`mirage_common::SeenNonceSet`]) keyed on it, and drop an
    /// already-seen key BEFORE acting on or re-broadcasting the event.
    /// [`Self::is_fresh`] alone is insufficient: it only bounds the window in
    /// which a captured frame can be replayed, not the number of replays inside
    /// it. [`Self::verify`]'s strict check guarantees a captured signature can't
    /// be re-shaped into a colliding-but-distinct key.
    pub fn replay_key(&self) -> [u8; 32] {
        *mirage_crypto::blake3::hash(&self.signature).as_bytes()
    }

    /// Check that the event's embedded timestamp is within
    /// `max_skew_secs` of `now_unix` (past OR future). Closes
    /// RT-GS-7 - without this check, a captured signed event
    /// can be replayed indefinitely (a censor records a
    /// `ProbeScanDetected` flagging a Tor exit, replays it
    /// every hour to keep the cohort soft-blocking that IP
    /// forever).
    pub fn is_fresh(&self, now_unix: u64, max_skew_secs: u64) -> bool {
        let ts = self.event.timestamp();
        let skew = if ts > now_unix {
            ts - now_unix
        } else {
            now_unix - ts
        };
        skew <= max_skew_secs
    }

    /// Serialise to the on-wire form for transport over TCP /
    /// UDP / Nostr / etc. Format:
    ///
    /// ```text
    /// [4]  GOSSIP_WIRE_MAGIC ("MGv1")
    /// [4]  payload_len (BE, u32) - does NOT include the magic
    /// [32] publisher_ed_pk
    /// [64] signature
    /// [var] event body (signing_bytes() minus the domain
    ///       prefix)
    /// ```
    ///
    /// Receivers MUST cap reads at
    /// [`MAX_GOSSIP_EVENT_WIRE_LEN`].
    pub fn wire_encode(&self) -> Vec<u8> {
        let signing = self.event.signing_bytes();
        let body = &signing[GOSSIP_SIGN_DOMAIN.len()..];
        let payload_len = 32 + 64 + body.len();
        let mut out = Vec::with_capacity(8 + payload_len);
        out.extend_from_slice(GOSSIP_WIRE_MAGIC);
        out.extend_from_slice(&(payload_len as u32).to_be_bytes());
        out.extend_from_slice(&self.publisher_ed_pk);
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(body);
        out
    }

    /// Decode from the on-wire form. Returns the parsed event
    /// AND the number of bytes consumed (so stream readers can
    /// advance past it). Does NOT verify the signature - caller
    /// runs [`Self::verify`] afterwards.
    pub fn wire_decode(buf: &[u8]) -> Result<(Self, usize), DiscoveryError> {
        if buf.len() < 8 {
            return Err(DiscoveryError::Wire("gossip wire: short header"));
        }
        if &buf[0..4] != GOSSIP_WIRE_MAGIC {
            return Err(DiscoveryError::Wire("gossip wire: bad magic"));
        }
        let payload_len = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
        if payload_len > MAX_GOSSIP_EVENT_WIRE_LEN {
            return Err(DiscoveryError::Wire("gossip wire: payload too long"));
        }
        let total = 8 + payload_len;
        if buf.len() < total {
            return Err(DiscoveryError::Wire("gossip wire: truncated payload"));
        }
        if payload_len < 32 + 64 + 1 {
            return Err(DiscoveryError::Wire("gossip wire: payload too short"));
        }
        let mut publisher_ed_pk = [0u8; 32];
        publisher_ed_pk.copy_from_slice(&buf[8..40]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&buf[40..104]);
        let body = &buf[104..total];
        let event = GossipEvent::decode_body(body)?;
        Ok((
            Self {
                event,
                publisher_ed_pk,
                signature,
            },
            total,
        ))
    }
}

impl GossipEvent {
    /// Decode the post-signing-domain body bytes into a
    /// `GossipEvent`. Used by [`SignedGossipEvent::wire_decode`].
    pub fn decode_body(buf: &[u8]) -> Result<Self, DiscoveryError> {
        if buf.is_empty() {
            return Err(DiscoveryError::Wire("gossip body: empty"));
        }
        let kind = buf[0];
        let rest = &buf[1..];
        match kind {
            0x01 => {
                if rest.len() != 32 + 8 {
                    return Err(DiscoveryError::Wire("gossip body: TokenBurned bad length"));
                }
                let mut token_id = [0u8; 32];
                token_id.copy_from_slice(&rest[0..32]);
                let burned_at = u64::from_be_bytes([
                    rest[32], rest[33], rest[34], rest[35], rest[36], rest[37], rest[38], rest[39],
                ]);
                Ok(GossipEvent::TokenBurned {
                    token_id,
                    burned_at,
                })
            }
            0x02 => {
                if rest.is_empty() {
                    return Err(DiscoveryError::Wire(
                        "gossip body: ProbeScanDetected missing addr family",
                    ));
                }
                let (source_ip, addr_len) = match rest[0] {
                    0x01 => {
                        if rest.len() < 1 + 4 {
                            return Err(DiscoveryError::Wire(
                                "gossip body: ProbeScanDetected v4 truncated",
                            ));
                        }
                        let mut o = [0u8; 4];
                        o.copy_from_slice(&rest[1..5]);
                        (IpAddr::V4(std::net::Ipv4Addr::from(o)), 5usize)
                    }
                    0x02 => {
                        if rest.len() < 1 + 16 {
                            return Err(DiscoveryError::Wire(
                                "gossip body: ProbeScanDetected v6 truncated",
                            ));
                        }
                        let mut o = [0u8; 16];
                        o.copy_from_slice(&rest[1..17]);
                        (IpAddr::V6(std::net::Ipv6Addr::from(o)), 17usize)
                    }
                    _ => {
                        return Err(DiscoveryError::Wire(
                            "gossip body: ProbeScanDetected unknown addr family",
                        ))
                    }
                };
                let tail = &rest[addr_len..];
                if tail.len() != 4 + 8 {
                    return Err(DiscoveryError::Wire(
                        "gossip body: ProbeScanDetected tail length",
                    ));
                }
                let expire_secs = u32::from_be_bytes([tail[0], tail[1], tail[2], tail[3]]);
                let detected_at = u64::from_be_bytes([
                    tail[4], tail[5], tail[6], tail[7], tail[8], tail[9], tail[10], tail[11],
                ]);
                Ok(GossipEvent::ProbeScanDetected {
                    source_ip,
                    expire_secs,
                    detected_at,
                })
            }
            0x03 => {
                if rest.len() != 32 + 1 + 8 {
                    return Err(DiscoveryError::Wire(
                        "gossip body: EntryDistressed bad length",
                    ));
                }
                let mut publisher_ed_pk = [0u8; 32];
                publisher_ed_pk.copy_from_slice(&rest[0..32]);
                let severity = rest[32];
                let observed_at = u64::from_be_bytes([
                    rest[33], rest[34], rest[35], rest[36], rest[37], rest[38], rest[39], rest[40],
                ]);
                Ok(GossipEvent::EntryDistressed {
                    publisher_ed_pk,
                    severity,
                    observed_at,
                })
            }
            0x04 => {
                if rest.len() < 32 + 4 + 8 {
                    return Err(DiscoveryError::Wire(
                        "gossip body: CohortMembership too short",
                    ));
                }
                let mut publisher_ed_pk = [0u8; 32];
                publisher_ed_pk.copy_from_slice(&rest[0..32]);
                let n = u32::from_be_bytes([rest[32], rest[33], rest[34], rest[35]]) as usize;
                // RT-GS-9: cap n BEFORE computing alive_end so
                // `n * 32` can't overflow `usize` on 32-bit
                // targets when n = u32::MAX.
                if n > 64 {
                    return Err(DiscoveryError::Wire(
                        "gossip body: CohortMembership too many peers",
                    ));
                }
                let alive_start = 36;
                let alive_end = alive_start + n * 32;
                if rest.len() < alive_end + 8 {
                    return Err(DiscoveryError::Wire(
                        "gossip body: CohortMembership alive truncated",
                    ));
                }
                let mut alive = Vec::with_capacity(n);
                for i in 0..n {
                    let mut pk = [0u8; 32];
                    pk.copy_from_slice(&rest[alive_start + 32 * i..alive_start + 32 * (i + 1)]);
                    alive.push(pk);
                }
                let tail = &rest[alive_end..alive_end + 8];
                let observed_at = u64::from_be_bytes([
                    tail[0], tail[1], tail[2], tail[3], tail[4], tail[5], tail[6], tail[7],
                ]);
                Ok(GossipEvent::CohortMembership {
                    publisher_ed_pk,
                    alive,
                    observed_at,
                })
            }
            0x05 => {
                if rest.len() != 32 + 8 {
                    return Err(DiscoveryError::Wire(
                        "gossip body: ClaimObserved bad length",
                    ));
                }
                let mut claim_tag = [0u8; 32];
                claim_tag.copy_from_slice(&rest[0..32]);
                let observed_at = u64::from_be_bytes([
                    rest[32], rest[33], rest[34], rest[35], rest[36], rest[37], rest[38], rest[39],
                ]);
                Ok(GossipEvent::ClaimObserved {
                    claim_tag,
                    observed_at,
                })
            }
            _ => Err(DiscoveryError::Wire("gossip body: unknown event kind")),
        }
    }
}

/// Cohort-wide gossip channel. Operators implement this for
/// their chosen transport (Redis pub/sub / Nostr / libp2p / UDP
/// multicast / etc.).
#[async_trait::async_trait]
pub trait CohortGossip: Send + Sync {
    /// Publish a signed event to all cohort peers. MUST NOT
    /// block on slow peers; an unreachable peer should be
    /// silently dropped (peer health is the cohort
    /// orchestrator's concern).
    ///
    /// Implementations that ACT on inbound events (soft-block an IP, burn a
    /// token, etc.) MUST dedup replays: verify the signature, check
    /// [`SignedGossipEvent::is_fresh`], AND drop events whose
    /// [`SignedGossipEvent::replay_key`] has already been seen within the
    /// freshness window (use a bounded, expiring seen-set such as
    /// [`mirage_common::SeenNonceSet`] with TTL >= 2x the skew window). Freshness
    /// alone lets a captured, still-fresh frame be re-injected repeatedly to keep
    /// re-applying its effect (e.g. holding a soft-block on an attacker-chosen
    /// IP). Both [`MemoryGossip`] and the TCP transport enforce this.
    async fn publish(&self, event: SignedGossipEvent);

    /// Subscribe to inbound gossip from peers. The returned
    /// receiver yields events the trait implementation has
    /// validated (signature verified, sender is a known cohort
    /// member). One subscriber per consumer is typical; the
    /// reference impl supports many.
    async fn subscribe(&self) -> broadcast::Receiver<SignedGossipEvent>;

    /// True iff the gossip transport is currently reachable.
    /// Used by the bridge daemon to decide whether to publish
    /// (offline -> save events to retry queue).
    async fn is_connected(&self) -> bool;
}

/// Default tolerance (seconds) for inbound gossip event
/// timestamps relative to the local clock. Events outside this
/// window are dropped as replays (RT-GS-7). 5 minutes
/// accommodates moderate clock skew across cohort hosts while
/// being tight enough to defeat any captured-replay attempt.
pub const DEFAULT_GOSSIP_MAX_SKEW_SECS: u64 = 300;

/// In-memory gossip channel for tests + single-host cohorts.
/// Verifies signatures against a static set of authorized
/// publisher pks; events with unknown publisher pks or stale
/// timestamps are dropped.
pub struct MemoryGossip {
    inner: Arc<Mutex<MemoryGossipInner>>,
    tx: broadcast::Sender<SignedGossipEvent>,
    max_skew_secs: u64,
    /// Replay-dedup seen-set (finding #25). Keyed on `blake3(signature)` via
    /// [`SignedGossipEvent::replay_key`]; TTL = 2x the freshness window so an
    /// entry outlives the window in which its frame would still pass
    /// `is_fresh`. Without this, a captured still-fresh event could be
    /// re-injected repeatedly inside the skew window to keep re-applying its
    /// effect (e.g. holding a soft-block on an attacker-chosen IP).
    replay: mirage_common::SeenNonceSet,
}

struct MemoryGossipInner {
    /// Authorized publisher pks. Events with publisher_ed_pk
    /// not in this set are dropped at `publish` time.
    authorized: HashSet<[u8; 32]>,
}

impl Default for MemoryGossip {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryGossip {
    /// Construct an empty channel with the default freshness
    /// window ([`DEFAULT_GOSSIP_MAX_SKEW_SECS`]).
    pub fn new() -> Self {
        Self::with_max_skew(DEFAULT_GOSSIP_MAX_SKEW_SECS)
    }

    /// Construct with an explicit freshness window. Set this
    /// generously (~5 min) to tolerate clock skew across cohort
    /// hosts.
    pub fn with_max_skew(max_skew_secs: u64) -> Self {
        let (tx, _) = broadcast::channel(256);
        Self {
            inner: Arc::new(Mutex::new(MemoryGossipInner {
                authorized: HashSet::new(),
            })),
            tx,
            max_skew_secs,
            // TTL = 2x skew so a seen key outlives the window in which its frame
            // would still pass `is_fresh` (mirrors the TCP transport).
            replay: mirage_common::SeenNonceSet::new(std::time::Duration::from_secs(
                max_skew_secs.saturating_mul(2).max(1),
            )),
        }
    }

    /// Add a publisher to the authorized set. Operators wire
    /// every cohort member's Ed25519 pk here.
    pub async fn authorize(&self, publisher_ed_pk: [u8; 32]) {
        self.inner.lock().await.authorized.insert(publisher_ed_pk);
    }
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[async_trait::async_trait]
impl CohortGossip for MemoryGossip {
    async fn publish(&self, event: SignedGossipEvent) {
        // Authorization check.
        {
            let g = self.inner.lock().await;
            if !g.authorized.contains(&event.publisher_ed_pk) {
                tracing::debug!("MemoryGossip: dropping event from unauthorized publisher");
                return;
            }
        }
        // RT-GS-7: replay protection. Drop events whose
        // embedded timestamp is more than `max_skew_secs` from
        // the local clock. A passive observer who captures a
        // valid event can no longer replay it indefinitely.
        if !event.is_fresh(unix_now_secs(), self.max_skew_secs) {
            tracing::debug!(
                event_ts = event.event.timestamp(),
                now = unix_now_secs(),
                "MemoryGossip: dropping stale/future event"
            );
            return;
        }
        // Signature verification.
        if event.verify(&event.publisher_ed_pk).is_err() {
            tracing::debug!("MemoryGossip: dropping event with bad signature");
            return;
        }
        // Finding #25: replay dedup. A captured, still-fresh event has the SAME
        // signature every time, so its replay_key collides in the seen-set and is
        // dropped here - a passive observer can't re-inject it repeatedly inside
        // the freshness window to keep re-applying its effect. Distinct genuine
        // events (distinct signed timestamps) have distinct keys, so this never
        // drops a legitimate event.
        if !self
            .replay
            .check_and_insert(event.replay_key(), std::time::Instant::now())
        {
            tracing::debug!("MemoryGossip: dropping replayed event");
            return;
        }
        // Broadcast. `send` errors if no receivers - fine, drop.
        let _ = self.tx.send(event);
    }

    async fn subscribe(&self) -> broadcast::Receiver<SignedGossipEvent> {
        self.tx.subscribe()
    }

    async fn is_connected(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_crypto::ed25519_dalek::SigningKey;
    use std::net::Ipv4Addr;

    fn rand_seed() -> [u8; 32] {
        let mut s = [0u8; 32];
        getrandom::fill(&mut s).unwrap();
        s
    }

    fn fresh_signing_key() -> SigningKey {
        SigningKey::from_bytes(&rand_seed())
    }

    fn fresh_ts() -> u64 {
        super::unix_now_secs()
    }

    #[test]
    fn sign_and_verify_token_burned() {
        let sk = fresh_signing_key();
        let event = GossipEvent::TokenBurned {
            token_id: [0xAA; 32],
            burned_at: 1_700_000_000,
        };
        let signed = SignedGossipEvent::sign(event.clone(), &sk);
        let pk = sk.verifying_key().to_bytes();
        signed.verify(&pk).unwrap();
    }

    #[test]
    fn sign_and_verify_probe_scan() {
        let sk = fresh_signing_key();
        let event = GossipEvent::ProbeScanDetected {
            source_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
            expire_secs: 3600,
            detected_at: 1_700_000_000,
        };
        let signed = SignedGossipEvent::sign(event, &sk);
        let pk = sk.verifying_key().to_bytes();
        signed.verify(&pk).unwrap();
    }

    #[test]
    fn sign_and_verify_claim_observed() {
        let sk = fresh_signing_key();
        let event = GossipEvent::ClaimObserved {
            claim_tag: [0x5A; 32],
            observed_at: 1_700_000_000,
        };
        let signed = SignedGossipEvent::sign(event.clone(), &sk);
        let pk = sk.verifying_key().to_bytes();
        signed.verify(&pk).unwrap();
        // ClaimObserved embeds no publisher pk, so verify must not
        // impose the inner-pk consistency check (which would always
        // fail). The successful verify above already proves that.
    }

    #[test]
    fn claim_observed_wire_round_trips() {
        let sk = fresh_signing_key();
        let event = GossipEvent::ClaimObserved {
            claim_tag: [0xC1; 32],
            observed_at: 1_700_000_123,
        };
        let signed = SignedGossipEvent::sign(event.clone(), &sk);
        let wire = signed.wire_encode();
        let (decoded, consumed) = SignedGossipEvent::wire_decode(&wire).unwrap();
        assert_eq!(consumed, wire.len());
        assert_eq!(decoded.event, event);
        decoded.verify(&sk.verifying_key().to_bytes()).unwrap();
    }

    #[test]
    fn claim_observed_decode_rejects_bad_length() {
        // 32-byte tag + 7 bytes (one short of the 8-byte timestamp).
        let mut body = vec![0x05u8];
        body.extend_from_slice(&[0u8; 32 + 7]);
        let err = GossipEvent::decode_body(&body).unwrap_err();
        assert!(matches!(err, DiscoveryError::Wire(s) if s.contains("ClaimObserved")));
    }

    #[test]
    fn verify_rejects_wrong_publisher_pk() {
        let sk = fresh_signing_key();
        let other_sk = fresh_signing_key();
        let event = GossipEvent::TokenBurned {
            token_id: [0xAA; 32],
            burned_at: 1_700_000_000,
        };
        let signed = SignedGossipEvent::sign(event, &sk);
        let other_pk = other_sk.verifying_key().to_bytes();
        let err = signed.verify(&other_pk).unwrap_err();
        assert!(matches!(err, DiscoveryError::Wire(s) if s.contains("pk")));
    }

    #[test]
    fn verify_rejects_tampered_event() {
        let sk = fresh_signing_key();
        let event = GossipEvent::TokenBurned {
            token_id: [0xAA; 32],
            burned_at: 1_700_000_000,
        };
        let mut signed = SignedGossipEvent::sign(event, &sk);
        // Tamper with the embedded event.
        signed.event = GossipEvent::TokenBurned {
            token_id: [0xBB; 32], // changed
            burned_at: 1_700_000_000,
        };
        let pk = sk.verifying_key().to_bytes();
        assert!(signed.verify(&pk).is_err());
    }

    #[test]
    fn verify_rejects_distressed_with_mismatched_inner_pk() {
        // The EntryDistressed event embeds publisher_ed_pk in
        // its body. If that doesn't match the outer signature's
        // publisher_ed_pk, reject.
        let sk = fresh_signing_key();
        let other = fresh_signing_key();
        let event = GossipEvent::EntryDistressed {
            publisher_ed_pk: other.verifying_key().to_bytes(),
            severity: 100,
            observed_at: 1_700_000_000,
        };
        let signed = SignedGossipEvent::sign(event, &sk);
        let pk = sk.verifying_key().to_bytes();
        let err = signed.verify(&pk).unwrap_err();
        assert!(matches!(err, DiscoveryError::Wire(s) if s.contains("embedded")));
    }

    #[tokio::test]
    async fn memory_gossip_routes_authorized_events() {
        let gossip = MemoryGossip::new();
        let sk = fresh_signing_key();
        let pk = sk.verifying_key().to_bytes();
        gossip.authorize(pk).await;

        let mut rx = gossip.subscribe().await;
        let event = GossipEvent::TokenBurned {
            token_id: [0xCC; 32],
            burned_at: fresh_ts(),
        };
        let signed = SignedGossipEvent::sign(event.clone(), &sk);
        gossip.publish(signed.clone()).await;

        // The subscriber receives the event.
        let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("timed out")
            .unwrap();
        assert_eq!(received.event, event);
    }

    #[tokio::test]
    async fn memory_gossip_drops_unauthorized_events() {
        let gossip = MemoryGossip::new();
        // DON'T authorize the publisher.
        let sk = fresh_signing_key();
        let event = GossipEvent::TokenBurned {
            token_id: [0xCC; 32],
            burned_at: fresh_ts(),
        };
        let signed = SignedGossipEvent::sign(event, &sk);
        let mut rx = gossip.subscribe().await;
        gossip.publish(signed).await;
        // Receiver should NOT see the event.
        let result = tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await;
        assert!(result.is_err(), "unauthorized event should be dropped");
    }

    #[tokio::test]
    async fn memory_gossip_drops_bad_signature() {
        let gossip = MemoryGossip::new();
        let sk = fresh_signing_key();
        let pk = sk.verifying_key().to_bytes();
        gossip.authorize(pk).await;
        let event = GossipEvent::TokenBurned {
            token_id: [0xCC; 32],
            burned_at: fresh_ts(),
        };
        let mut signed = SignedGossipEvent::sign(event, &sk);
        // Corrupt the signature.
        signed.signature[0] ^= 0xFF;
        let mut rx = gossip.subscribe().await;
        gossip.publish(signed).await;
        let result = tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await;
        assert!(result.is_err(), "bad-sig event should be dropped");
    }

    #[tokio::test]
    async fn memory_gossip_drops_stale_events() {
        // RT-GS-7 explicit positive: a stale (replay-window-out)
        // event is dropped even when authorized + signed.
        let gossip = MemoryGossip::with_max_skew(60);
        let sk = fresh_signing_key();
        let pk = sk.verifying_key().to_bytes();
        gossip.authorize(pk).await;
        let event = GossipEvent::TokenBurned {
            token_id: [0xDE; 32],
            burned_at: 1_000_000, // long-stale
        };
        let signed = SignedGossipEvent::sign(event, &sk);
        let mut rx = gossip.subscribe().await;
        gossip.publish(signed).await;
        let result = tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await;
        assert!(result.is_err(), "stale event must be dropped");
    }

    #[test]
    fn wire_codec_round_trips_token_burned() {
        let sk = fresh_signing_key();
        let event = GossipEvent::TokenBurned {
            token_id: [0xAA; 32],
            burned_at: 1_700_000_000,
        };
        let signed = SignedGossipEvent::sign(event.clone(), &sk);
        let wire = signed.wire_encode();
        let (decoded, n) = SignedGossipEvent::wire_decode(&wire).unwrap();
        assert_eq!(n, wire.len(), "consumed bytes match wire length");
        assert_eq!(decoded, signed);
        let pk = sk.verifying_key().to_bytes();
        decoded.verify(&pk).unwrap();
    }

    #[test]
    fn wire_codec_round_trips_probe_scan_v4_and_v6() {
        let sk = fresh_signing_key();
        for ip in [
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
            IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        ] {
            let event = GossipEvent::ProbeScanDetected {
                source_ip: ip,
                expire_secs: 3600,
                detected_at: 1_700_000_000,
            };
            let signed = SignedGossipEvent::sign(event, &sk);
            let wire = signed.wire_encode();
            let (decoded, _) = SignedGossipEvent::wire_decode(&wire).unwrap();
            assert_eq!(decoded, signed);
        }
    }

    #[test]
    fn wire_codec_round_trips_cohort_membership() {
        let sk = fresh_signing_key();
        let pk = sk.verifying_key().to_bytes();
        let event = GossipEvent::CohortMembership {
            publisher_ed_pk: pk,
            alive: vec![[0x01; 32], [0x02; 32], [0x03; 32]],
            observed_at: 1_700_000_000,
        };
        let signed = SignedGossipEvent::sign(event, &sk);
        let wire = signed.wire_encode();
        let (decoded, _) = SignedGossipEvent::wire_decode(&wire).unwrap();
        assert_eq!(decoded, signed);
        decoded.verify(&pk).unwrap();
    }

    #[test]
    fn wire_codec_rejects_bad_magic() {
        let sk = fresh_signing_key();
        let event = GossipEvent::TokenBurned {
            token_id: [0; 32],
            burned_at: 0,
        };
        let signed = SignedGossipEvent::sign(event, &sk);
        let mut wire = signed.wire_encode();
        wire[0] = b'X';
        assert!(SignedGossipEvent::wire_decode(&wire).is_err());
    }

    #[test]
    fn wire_codec_rejects_oversize_payload_len() {
        let mut buf = Vec::new();
        buf.extend_from_slice(GOSSIP_WIRE_MAGIC);
        buf.extend_from_slice(&(u32::MAX).to_be_bytes());
        // No actual payload; length-prefix check should reject
        // before trying to consume bytes.
        assert!(SignedGossipEvent::wire_decode(&buf).is_err());
    }

    #[test]
    fn wire_codec_rejects_truncated_payload() {
        let sk = fresh_signing_key();
        let event = GossipEvent::TokenBurned {
            token_id: [0; 32],
            burned_at: 0,
        };
        let signed = SignedGossipEvent::sign(event, &sk);
        let wire = signed.wire_encode();
        // Lop off the last 10 bytes.
        let truncated = &wire[..wire.len() - 10];
        assert!(SignedGossipEvent::wire_decode(truncated).is_err());
    }

    #[tokio::test]
    async fn memory_gossip_dedups_replayed_event() {
        // Finding #25: the same signed event, published twice within the
        // freshness window, must be delivered only ONCE. Without the seen-set a
        // captured still-fresh ProbeScanDetected could be re-injected repeatedly
        // to keep the cohort soft-blocking an attacker-chosen IP.
        let gossip = MemoryGossip::new();
        let sk = fresh_signing_key();
        let pk = sk.verifying_key().to_bytes();
        gossip.authorize(pk).await;

        let event = GossipEvent::ProbeScanDetected {
            source_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            expire_secs: 300,
            detected_at: fresh_ts(),
        };
        let signed = SignedGossipEvent::sign(event.clone(), &sk);
        let mut rx = gossip.subscribe().await;

        // First publish is delivered.
        gossip.publish(signed.clone()).await;
        let first = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("timed out")
            .unwrap();
        assert_eq!(first.event, event);

        // Re-inject the identical captured frame: deduped, no second delivery.
        gossip.publish(signed).await;
        let second = tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await;
        assert!(second.is_err(), "replayed event must be deduped");
    }

    #[tokio::test]
    async fn memory_gossip_fan_out_to_multiple_subscribers() {
        let gossip = MemoryGossip::new();
        let sk = fresh_signing_key();
        let pk = sk.verifying_key().to_bytes();
        gossip.authorize(pk).await;
        let mut rx_a = gossip.subscribe().await;
        let mut rx_b = gossip.subscribe().await;
        let event = GossipEvent::TokenBurned {
            token_id: [0xCC; 32],
            burned_at: fresh_ts(),
        };
        let signed = SignedGossipEvent::sign(event.clone(), &sk);
        gossip.publish(signed).await;
        let recv_a = rx_a.recv().await.unwrap();
        let recv_b = rx_b.recv().await.unwrap();
        assert_eq!(recv_a.event, event);
        assert_eq!(recv_b.event, event);
    }
}
