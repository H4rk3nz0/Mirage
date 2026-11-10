//! Bridge cohort protocol: lazy, server-rationed bridge distribution.
//!
//! # Problem
//!
//! Previously, a valid [`crate::MasterInvite`] gave its holder
//! unrestricted knowledge of every bridge the operator publishes
//! (full-mesh enumeration via the discovery channel). Under the
//! "lives at stake" threat model, a single invite capture
//! compromises the entire bridge topology.
//!
//! # Solution
//!
//! After a client establishes a Mirage session with a bridge, it
//! can make a **cohort request** - asking for a rationed subset of
//! *other* bridges this bridge knows about. The bridge:
//!
//! 1. Tracks, per-token, how many distinct bridges it has revealed.
//! 2. Returns at most `max_n` announcements in one response
//!    ([`COHORT_MAX_N_PER_REQUEST`]), chosen to maximize novelty
//!    (bridges the client has not been told about yet) while
//!    respecting a per-token lifetime cap
//!    ([`DEFAULT_PER_TOKEN_REVEAL_CAP`]).
//!
//! The client cannot enumerate the whole mesh via any single
//! invite - at most
//! `token_count x DEFAULT_PER_TOKEN_REVEAL_CAP` unique bridges are
//! ever revealed, and that includes bridges the client already
//! knew about (so the effective cap is strictly tighter).
//!
//! # Transport
//!
//! Cohort requests ride **inside an established Mirage session**
//! as a SOCKS5 CONNECT to a reserved magic hostname
//! ([`COHORT_MAGIC_HOSTNAME`]). The bridge intercepts CONNECT
//! requests for this hostname and handles them internally rather
//! than opening an upstream TCP connection. The Mirage session's
//! hybrid-PQ encryption protects the exchange; the Reality carrier
//! (if active) hides it on the wire.
//!
//! # Wire format
//!
//! Request (client -> bridge), 3 bytes:
//!
//! ```text
//!   u8 version   = 0x01
//!   u8 cmd       = 0x01 (LIST)
//!   u8 max_n     = 1..=COHORT_MAX_N_PER_REQUEST
//! ```
//!
//! Response (bridge -> client):
//!
//! ```text
//!   u8  version  = 0x01
//!   u8  status   = 0x00 (OK) or error code
//!   u16 count    = number of announcements that follow (BE)
//!   N x Announcement.encode()
//! ```
//!
//! # Threat-model notes
//!
//! - **Rationing is at the bridge's discretion.** A hostile bridge
//!   could hand out the whole mesh in one request; we can't force a
//!   bridge to honor the cap. Operators are trusted; bridges are
//!   trusted to the extent that the operator signed their
//!   announcement. Non-operator-run bridges should never enter the
//!   cohort list.
//! - **Per-token tracking is in-memory.** A bridge restart resets
//!   the per-token reveal counter; a motivated client could force
//!   restarts via a DoS vector to re-exhaust the cap. Documented
//!   as a known limitation; persistent rationing lands with
//!   operator-tooling.
//! - **Novelty heuristic**: the bridge doesn't know which bridges
//!   the client already knows about. The client can, if it wants,
//!   send an optional "exclude" list in future versions. For v0.1
//!   the bridge just rotates through its cohort list to avoid
//!   always returning the same N.

use crate::error::DiscoveryError;
use crate::wire::Announcement;

/// Reserved SOCKS5 hostname that routes to the cohort service
/// instead of opening an upstream TCP connection. Structured as a
/// domain name so it survives SOCKS5 DOMAIN-type CONNECT without
/// any special handling; deliberately uses an underscore-prefix
/// segment (`_mirage_cohort`) so it cannot collide with a real
/// RFC 1035 hostname.
pub const COHORT_MAGIC_HOSTNAME: &str = "_mirage_cohort._internal";

/// Reserved port used with [`COHORT_MAGIC_HOSTNAME`]. Value is
/// arbitrary; the bridge dispatches on the hostname, not the port.
pub const COHORT_MAGIC_PORT: u16 = 1;

/// Wire version for the cohort protocol.
pub const COHORT_VERSION: u8 = 0x01;

/// `cmd` byte: list some of my known cohort.
pub const COHORT_CMD_LIST: u8 = 0x01;

/// Response status: OK.
pub const COHORT_STATUS_OK: u8 = 0x00;
/// Response status: bridge rate-limited or exhausted its per-token
/// cap for this caller.
pub const COHORT_STATUS_EXHAUSTED: u8 = 0x01;
/// Response status: bridge is intentionally returning no cohort
/// members (e.g., single-bridge operator deployment).
pub const COHORT_STATUS_EMPTY: u8 = 0x02;
/// Response status: wire-format error in the request.
pub const COHORT_STATUS_BAD_REQUEST: u8 = 0x03;

/// Maximum announcements returned in one response. Caps a single
/// response at ~800 x N bytes; at N=4 the whole response is well
/// under one MAX_FRAME_PLAINTEXT frame.
pub const COHORT_MAX_N_PER_REQUEST: u8 = 4;

/// Default per-token lifetime reveal cap. A single bootstrap
/// token, across every cohort request it supports, never reveals
/// more than this many unique bridges. Operators can lower this
/// in config for tighter rationing; raising beyond 16 defeats the
/// point.
pub const DEFAULT_PER_TOKEN_REVEAL_CAP: u8 = 8;

/// Persistent per-token reveal counter. Closes [RT-CN-10]
/// (cohort cap reset on bridge restart).
///
/// **Threat**: a censor running a bridge in the cohort can
/// request `DEFAULT_PER_TOKEN_REVEAL_CAP = 8` announcements, hit
/// the cap, then DoS the bridge to force a restart. With the
/// counter in-memory only, the restart resets it to zero; the
/// censor requests 8 more announcements with the same token. By
/// repeated restart-induced resets, a single token can exhaust
/// the entire cohort.
///
/// **Mitigation**: persist per-token reveal counters across
/// restarts. This trait lets operators plug in a backing store -
/// SQLite, RocksDB, JSON-on-disk, or anything else - without
/// hard-coding storage choice into the protocol.
///
/// **Concurrency**: implementations MUST be safe to call from
/// multiple async tasks. The bridge daemon dispatches one
/// `RevealStore` per accepted cohort request; under burst load
/// many calls may overlap.
///
/// **Atomicity**: `record_reveals` MUST be atomic - partial
/// updates on crash/poweroff are acceptable as long as the
/// stored count is `<=` the actual number of bridges revealed
/// (under-count -> operator gives a few more reveals next
/// restart; over-count -> operator under-serves, which is the
/// safe direction for capped state).
#[async_trait::async_trait]
pub trait RevealStore: Send + Sync {
    /// Lookup how many bridges (by `bridge_pk`) have already been
    /// revealed to `token_id`. Returns 0 if unknown.
    async fn reveal_count(&self, token_id: &[u8; 32]) -> u8;

    /// Test whether `bridge_pk` has already been revealed to
    /// `token_id`.
    async fn has_revealed(&self, token_id: &[u8; 32], bridge_pk: &[u8; 32]) -> bool;

    /// Record that `bridge_pks` were revealed to `token_id`.
    /// Implementations MUST persist before returning so a crash
    /// after the call has the new state on disk.
    async fn record_reveals(&self, token_id: &[u8; 32], bridge_pks: &[[u8; 32]]);
}

/// In-memory reveal store. Resets on bridge restart - **does NOT
/// close [RT-CN-10]** by itself. Provided for tests and
/// short-lived deployments. Operators in adversarial environments
/// MUST use a persistent backing store (file, SQLite, ...).
pub struct InMemoryRevealStore {
    inner: tokio::sync::Mutex<
        std::collections::HashMap<[u8; 32], std::collections::HashSet<[u8; 32]>>,
    >,
}

impl Default for InMemoryRevealStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryRevealStore {
    /// Construct an empty store.
    pub fn new() -> Self {
        Self {
            inner: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl RevealStore for InMemoryRevealStore {
    async fn reveal_count(&self, token_id: &[u8; 32]) -> u8 {
        let g = self.inner.lock().await;
        g.get(token_id)
            .map(|set| u8::try_from(set.len()).unwrap_or(u8::MAX))
            .unwrap_or(0)
    }

    async fn has_revealed(&self, token_id: &[u8; 32], bridge_pk: &[u8; 32]) -> bool {
        let g = self.inner.lock().await;
        g.get(token_id).is_some_and(|set| set.contains(bridge_pk))
    }

    async fn record_reveals(&self, token_id: &[u8; 32], bridge_pks: &[[u8; 32]]) {
        let mut g = self.inner.lock().await;
        let entry = g.entry(*token_id).or_default();
        for pk in bridge_pks {
            entry.insert(*pk);
        }
    }
}

/// A parsed cohort request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CohortRequest {
    /// Protocol version (validated on parse).
    pub version: u8,
    /// Command byte.
    pub cmd: u8,
    /// Maximum number of announcements the client will accept.
    /// Bridge may return fewer (including zero).
    pub max_n: u8,
}

impl CohortRequest {
    /// Build a LIST request asking for up to `max_n` bridges.
    pub fn list(max_n: u8) -> Result<Self, DiscoveryError> {
        if max_n == 0 || max_n > COHORT_MAX_N_PER_REQUEST {
            return Err(DiscoveryError::Wire("cohort: max_n out of range"));
        }
        Ok(Self {
            version: COHORT_VERSION,
            cmd: COHORT_CMD_LIST,
            max_n,
        })
    }

    /// Serialize to wire bytes (3 B).
    pub fn encode(&self) -> [u8; 3] {
        [self.version, self.cmd, self.max_n]
    }

    /// Parse from wire bytes. Strict length + version + cmd.
    pub fn decode(buf: &[u8]) -> Result<Self, DiscoveryError> {
        if buf.len() != 3 {
            return Err(DiscoveryError::Wire("cohort: request length"));
        }
        if buf[0] != COHORT_VERSION {
            return Err(DiscoveryError::Wire("cohort: unsupported version"));
        }
        if buf[1] != COHORT_CMD_LIST {
            return Err(DiscoveryError::Wire("cohort: unknown cmd"));
        }
        if buf[2] == 0 || buf[2] > COHORT_MAX_N_PER_REQUEST {
            return Err(DiscoveryError::Wire("cohort: max_n out of range"));
        }
        Ok(Self {
            version: buf[0],
            cmd: buf[1],
            max_n: buf[2],
        })
    }
}

/// A built cohort response ready to ship. The announcements are
/// presumed to be already-signed by the operator - the bridge
/// stores them in their canonical encoded form and just forwards
/// bytes.
#[derive(Debug, Clone)]
pub struct CohortResponse {
    /// Status byte.
    pub status: u8,
    /// Announcements included in the response (may be empty).
    pub announcements: Vec<Announcement>,
}

impl CohortResponse {
    /// Empty OK response (bridge has nothing more to reveal).
    pub fn empty(status: u8) -> Self {
        Self {
            status,
            announcements: Vec::new(),
        }
    }

    /// OK response with the given announcements.
    pub fn ok(announcements: Vec<Announcement>) -> Self {
        Self {
            status: COHORT_STATUS_OK,
            announcements,
        }
    }

    /// Serialize to wire bytes: `[version][status][count_be u16][N x Announcement]`.
    pub fn encode(&self) -> Vec<u8> {
        let n = self.announcements.len() as u16;
        let mut out = Vec::with_capacity(4 + n as usize * 200);
        out.push(COHORT_VERSION);
        out.push(self.status);
        out.extend_from_slice(&n.to_be_bytes());
        for ann in &self.announcements {
            out.extend_from_slice(&ann.encode());
        }
        out
    }

    /// Parse from wire bytes. Strict: version must match and every
    /// announcement must decode.
    pub fn decode(buf: &[u8]) -> Result<Self, DiscoveryError> {
        if buf.len() < 4 {
            return Err(DiscoveryError::Wire("cohort: response header too short"));
        }
        if buf[0] != COHORT_VERSION {
            return Err(DiscoveryError::Wire("cohort: unsupported version"));
        }
        let status = buf[1];
        let count = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        // Bound the claimed count against the actual remaining buffer
        // before allocating. An announcement is at minimum
        // FIXED_PREFIX (88) + 1-byte endpoint-kind + 1 endpoint byte +
        // SIG_LEN (64) = ~154 bytes. A hostile peer claiming
        // count = u16::MAX with only 4 bytes of body would otherwise
        // trigger a 65535-entry Vec::with_capacity. Closes [RT-N1].
        const MIN_ANNOUNCEMENT_BYTES: usize = 154;
        let body_bytes = buf.len() - 4;
        let max_possible = body_bytes / MIN_ANNOUNCEMENT_BYTES;
        if count > max_possible {
            return Err(DiscoveryError::Wire(
                "cohort: count exceeds buffer capacity",
            ));
        }
        let mut announcements = Vec::with_capacity(count);
        let mut rest = &buf[4..];
        for _ in 0..count {
            // Each Announcement is variable-length. Figure out how
            // much of `rest` the next one consumes by probing with
            // `decode` on successively larger prefixes. The decoder
            // rejects trailing bytes, so we grow until it accepts.
            let consumed = find_next_announcement_length(rest)?;
            let ann = Announcement::decode(&rest[..consumed])?;
            announcements.push(ann);
            rest = &rest[consumed..];
        }
        if !rest.is_empty() {
            return Err(DiscoveryError::Wire("cohort: trailing bytes"));
        }
        Ok(Self {
            status,
            announcements,
        })
    }
}

/// Bound on how many bytes we try before declaring an announcement
/// is unparseable. Spec §5.1 fixes the announcement max plaintext
/// at 768 B; we use a generous multiplier as a bounds check.
const MAX_ANNOUNCEMENT_SCAN: usize = 1024;

/// Compute the exact length of the first announcement in `rest`.
///
/// Uses the announcement header to read the endpoint-kind byte and
/// derive the full record size without re-running `decode` on each
/// prefix. Matches `Announcement::signed_prefix_len` + SIG_LEN.
fn find_next_announcement_length(rest: &[u8]) -> Result<usize, DiscoveryError> {
    // Fixed prefix before endpoint: magic(2) + doc(1) + ver(1) +
    // issued(8) + expires(8) + bridge_ed(32) + bridge_x(32) + caps(4) = 88
    const FIXED_PREFIX: usize = 88;
    const SIG_LEN: usize = 64;
    if rest.len() < FIXED_PREFIX + 1 {
        return Err(DiscoveryError::Wire("cohort: truncated announcement"));
    }
    let version = rest[3];
    let mut cursor = FIXED_PREFIX;
    // Primary endpoint.
    cursor += endpoint_field_len(rest, cursor, "primary endpoint")?;
    // V0_1T (and now also single-endpoint V0_1T per RT-CN-9
    // closure): read extras_count + walk extras.
    if version == crate::wire::ANNOUNCEMENT_VERSION_V0_1T {
        if rest.len() < cursor + 1 {
            return Err(DiscoveryError::Wire("cohort: truncated extras_count"));
        }
        let extras_count = rest[cursor] as usize;
        cursor += 1;
        for _ in 0..extras_count {
            cursor += endpoint_field_len(rest, cursor, "extra endpoint")?;
        }
    }
    let total = cursor + SIG_LEN;
    if total > MAX_ANNOUNCEMENT_SCAN {
        return Err(DiscoveryError::Wire(
            "cohort: announcement exceeds scan cap",
        ));
    }
    if rest.len() < total {
        return Err(DiscoveryError::Wire("cohort: truncated announcement"));
    }
    Ok(total)
}

fn endpoint_field_len(
    rest: &[u8],
    cursor: usize,
    where_: &'static str,
) -> Result<usize, DiscoveryError> {
    if rest.len() < cursor + 1 {
        return Err(match where_ {
            "primary endpoint" => DiscoveryError::Wire("cohort: truncated announcement"),
            _ => DiscoveryError::Wire("cohort: truncated extra endpoint"),
        });
    }
    let kind = rest[cursor];
    let len = match kind {
        0x01 => 1 + 4 + 2,
        0x02 => 1 + 16 + 2,
        0x03 => {
            let name_len_idx = cursor + 1;
            if rest.len() < name_len_idx + 1 {
                return Err(DiscoveryError::Wire("cohort: truncated domain length"));
            }
            let nl = rest[name_len_idx] as usize;
            1 + 1 + nl + 2
        }
        0x04 => 1 + 56 + 2,
        _ => return Err(DiscoveryError::Wire("cohort: unknown endpoint kind")),
    };
    Ok(len)
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{transport_caps, Endpoint};

    fn sample_ann(tag: u8) -> Announcement {
        Announcement {
            issued_at: 1_000_000,
            expires_at: 1_003_600,
            bridge_ed25519_pk: [tag; 32],
            bridge_x25519_pk: [tag.wrapping_add(1); 32],
            transport_caps: transport_caps::REALITY_V2,
            endpoint: Endpoint::Ipv4 {
                addr: [192, 0, 2, tag],
                port: 443,
            },
            extra_endpoints: Vec::new(),
            signature: [0xAAu8; 64],
        }
    }

    fn sample_ann_domain(tag: u8) -> Announcement {
        let mut a = sample_ann(tag);
        a.endpoint = Endpoint::Domain {
            domain: "bridge.example.com".to_string(),
            port: 443,
        };
        a
    }

    #[test]
    fn request_roundtrip() {
        let r = CohortRequest::list(3).unwrap();
        let bytes = r.encode();
        assert_eq!(bytes, [COHORT_VERSION, COHORT_CMD_LIST, 3]);
        let back = CohortRequest::decode(&bytes).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn request_rejects_zero_and_over_cap() {
        assert!(CohortRequest::list(0).is_err());
        assert!(CohortRequest::list(COHORT_MAX_N_PER_REQUEST + 1).is_err());
        assert!(CohortRequest::decode(&[COHORT_VERSION, COHORT_CMD_LIST, 0]).is_err());
        assert!(CohortRequest::decode(&[
            COHORT_VERSION,
            COHORT_CMD_LIST,
            COHORT_MAX_N_PER_REQUEST + 1
        ])
        .is_err());
    }

    #[test]
    fn request_rejects_wrong_length() {
        assert!(CohortRequest::decode(&[]).is_err());
        assert!(CohortRequest::decode(&[COHORT_VERSION, COHORT_CMD_LIST]).is_err());
        assert!(CohortRequest::decode(&[COHORT_VERSION, COHORT_CMD_LIST, 1, 0xFF]).is_err());
    }

    #[test]
    fn request_rejects_bad_version() {
        assert!(CohortRequest::decode(&[0x02, COHORT_CMD_LIST, 1]).is_err());
    }

    #[test]
    fn request_rejects_unknown_cmd() {
        assert!(CohortRequest::decode(&[COHORT_VERSION, 0x99, 1]).is_err());
    }

    #[test]
    fn response_empty_roundtrip() {
        let r = CohortResponse::empty(COHORT_STATUS_EXHAUSTED);
        let bytes = r.encode();
        let back = CohortResponse::decode(&bytes).unwrap();
        assert_eq!(back.status, COHORT_STATUS_EXHAUSTED);
        assert!(back.announcements.is_empty());
    }

    #[test]
    fn response_multi_roundtrip_ipv4() {
        let anns = vec![sample_ann(1), sample_ann(2), sample_ann(3)];
        let r = CohortResponse::ok(anns.clone());
        let bytes = r.encode();
        let back = CohortResponse::decode(&bytes).unwrap();
        assert_eq!(back.status, COHORT_STATUS_OK);
        assert_eq!(back.announcements.len(), 3);
        for (i, a) in back.announcements.iter().enumerate() {
            assert_eq!(a.bridge_ed25519_pk, anns[i].bridge_ed25519_pk);
        }
    }

    #[test]
    fn response_roundtrip_domain_endpoint() {
        let r = CohortResponse::ok(vec![sample_ann_domain(7)]);
        let bytes = r.encode();
        let back = CohortResponse::decode(&bytes).unwrap();
        match &back.announcements[0].endpoint {
            Endpoint::Domain { domain, port } => {
                assert_eq!(domain, "bridge.example.com");
                assert_eq!(*port, 443);
            }
            _ => panic!("expected domain"),
        }
    }

    #[test]
    fn response_rejects_trailing_bytes() {
        let mut bytes = CohortResponse::ok(vec![sample_ann(1)]).encode();
        bytes.push(0xAB);
        assert!(CohortResponse::decode(&bytes).is_err());
    }

    #[test]
    fn response_rejects_short_header() {
        assert!(CohortResponse::decode(&[]).is_err());
        assert!(CohortResponse::decode(&[COHORT_VERSION, 0]).is_err());
    }

    #[test]
    fn response_rejects_wrong_count() {
        let mut bytes = CohortResponse::ok(vec![sample_ann(1)]).encode();
        // Overstate count -> parser tries to read another ann but
        // finds only trailing bytes of the existing one.
        bytes[2] = 0;
        bytes[3] = 2;
        assert!(CohortResponse::decode(&bytes).is_err());
    }

    #[test]
    fn response_decode_rejects_count_far_exceeding_buffer() {
        // RT-N1 closure: a hostile cohort server returns
        // count = u16::MAX with no actual announcement bytes.
        // Pre-fix this triggered a 65535-entry Vec::with_capacity.
        // Post-fix the decoder rejects up front.
        let mut buf = Vec::new();
        buf.push(COHORT_VERSION);
        buf.push(0u8); // status
        buf.extend_from_slice(&u16::MAX.to_be_bytes()); // count
                                                        // No announcement body.
        let err = CohortResponse::decode(&buf).unwrap_err();
        assert!(matches!(err, DiscoveryError::Wire(s) if s.contains("exceeds buffer")));
    }

    #[test]
    fn fuzz_arbitrary_bytes_never_panic() {
        use proptest::prelude::*;
        proptest!(ProptestConfig::with_cases(256), |(b in prop::collection::vec(any::<u8>(), 0..2048))| {
            let _ = CohortRequest::decode(&b);
            let _ = CohortResponse::decode(&b);
        });
    }

    // --- RT-CN-10: RevealStore trait + in-memory impl ---

    #[tokio::test]
    async fn in_memory_reveal_store_starts_empty() {
        let store = InMemoryRevealStore::new();
        assert_eq!(store.reveal_count(&[1u8; 32]).await, 0);
        assert!(!store.has_revealed(&[1u8; 32], &[2u8; 32]).await);
    }

    #[tokio::test]
    async fn in_memory_reveal_store_records_and_counts() {
        let store = InMemoryRevealStore::new();
        let token = [0xCC; 32];
        let bridges = [[0x01; 32], [0x02; 32], [0x03; 32]];
        store.record_reveals(&token, &bridges).await;
        assert_eq!(store.reveal_count(&token).await, 3);
        for pk in &bridges {
            assert!(store.has_revealed(&token, pk).await);
        }
        // A different bridge isn't revealed.
        assert!(!store.has_revealed(&token, &[0x99; 32]).await);
    }

    #[tokio::test]
    async fn in_memory_reveal_store_is_idempotent_on_duplicate_record() {
        let store = InMemoryRevealStore::new();
        let token = [0xAA; 32];
        store.record_reveals(&token, &[[0x01; 32]]).await;
        store.record_reveals(&token, &[[0x01; 32]]).await;
        // HashSet semantics: duplicate insertions don't double-count.
        assert_eq!(store.reveal_count(&token).await, 1);
    }

    #[tokio::test]
    async fn in_memory_reveal_store_isolates_different_tokens() {
        let store = InMemoryRevealStore::new();
        let token_a = [0x01; 32];
        let token_b = [0x02; 32];
        store
            .record_reveals(&token_a, &[[0xAA; 32], [0xBB; 32]])
            .await;
        store.record_reveals(&token_b, &[[0xCC; 32]]).await;
        assert_eq!(store.reveal_count(&token_a).await, 2);
        assert_eq!(store.reveal_count(&token_b).await, 1);
        // Cross-contamination check.
        assert!(!store.has_revealed(&token_a, &[0xCC; 32]).await);
        assert!(!store.has_revealed(&token_b, &[0xAA; 32]).await);
    }

    #[tokio::test]
    async fn in_memory_reveal_store_does_not_close_rt_cn_10() {
        // Documented expectation: in-memory store DOES NOT
        // persist across "restarts" - simulated by dropping the
        // store and constructing a new one. RT-CN-10's full
        // closure requires a persistent backing store; this test
        // pins the in-memory limitation so operators can't
        // accidentally rely on it for adversarial deployments.
        let store1 = InMemoryRevealStore::new();
        store1
            .record_reveals(&[0xCC; 32], &[[0xAA; 32], [0xBB; 32]])
            .await;
        assert_eq!(store1.reveal_count(&[0xCC; 32]).await, 2);
        drop(store1);
        // "Restart": fresh store has no memory of the previous reveals.
        let store2 = InMemoryRevealStore::new();
        assert_eq!(store2.reveal_count(&[0xCC; 32]).await, 0);
    }
}
