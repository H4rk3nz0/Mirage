//! Per-invite claim protocol (v0.1e) - one-time invite redemption.
//!
//! # Problem
//!
//! A `MasterInvite` is a shared-secret blob. Anyone holding it can
//! present bootstrap tokens, decrypt operator announcements, and
//! otherwise act as a legitimate user until the invite expires or
//! the bootstrap tokens are exhausted. A leaked invite means the
//! user's entire bridge fleet is reachable by the attacker, for
//! the full invite TTL.
//!
//! # Solution
//!
//! The invite carries a 32-byte **claim secret** (a TLV extension,
//! [`crate::invite::INVITE_EXT_CLAIM_ID`]). The secret is NEVER sent on the
//! wire. On first connection to bridge `b` the client derives a per-bridge
//! id `claim_id_b = `[`derive_claim_id`]`(secret, b_ed25519_pk)` and presents
//! THAT through the [`CLAIM_MAGIC_HOSTNAME`] magic hostname. The bridge records
//! the (opaque) id in a local `claimed_invites` set. Any subsequent CLAIM
//! attempt with the same id at that bridge fails with
//! [`CLAIM_STATUS_ALREADY_CLAIMED`]. Because the id is per-bridge, no two
//! bridges ever receive the same value for one invite (see [`derive_claim_id`]
//! for the anti-tracking-cookie rationale).
//!
//! The response piggybacks a batch of
//! [`crate::refresh::SessionRefreshToken`]s so the client receives
//! continuation credentials in the same round-trip; from that
//! point on it never needs to consume its remaining bootstrap
//! tokens at that bridge.
//!
//! # Effect on a leaked invite
//!
//! - If the attacker claims FIRST, the legitimate user's claim
//!   later fails - the legitimate user learns their invite is
//!   compromised (actionable signal).
//! - If the legitimate user claims first, the attacker's later
//!   claim fails at the same bridge - attacker can still burn
//!   individual bootstrap tokens but cannot redeem the invite as
//!   a "first use" persona.
//! - Bridges log duplicate-claim attempts; operators can alert on
//!   repeated collisions as evidence of an invite-distribution
//!   compromise.
//!
//! An attacker can still claim at bridge A while the legitimate user claims at
//! bridge B (per-bridge first-use is enforced only locally); preventing that
//! entirely requires operator-global claim state - tracked as a v0.2 item. What
//! the per-bridge derivation DOES close is the cross-mesh *tracking cookie*: a
//! single raw `claim_id` was previously sent verbatim to every bridge, so any
//! two hostile bridges could compare `claimed_invites` sets and link one user
//! across the mesh. With [`derive_claim_id`] each bridge receives a distinct id
//! and cannot recover the shared invite. See [`derive_claim_id`].
//!
//! # Wire format
//!
//! Transport: inside an established Mirage session, SOCKS5 CONNECT
//! to [`CLAIM_MAGIC_HOSTNAME`]. The session handshake has already
//! consumed a bootstrap token, so CLAIM is pre-authenticated.
//!
//! Request (client -> bridge): 36 bytes fixed.
//!
//! ```text
//!   u8  version     = 0x01
//!   u8  cmd         = 0x01 (REDEEM)
//!   u8  refresh_cnt (0..=REFRESH_MAX_PER_REQUEST; 0 = no refresh piggyback)
//!   u8  _reserved   = 0x00
//!   [u8; 32] claim_id
//! ```
//!
//! Response (bridge -> client): 3-byte header + optional refresh
//! tokens.
//!
//! ```text
//!   u8  version       = 0x01
//!   u8  status        (see CLAIM_STATUS_*)
//!   u8  token_count
//!   N x 136 B         SessionRefreshToken bytes
//! ```

use crate::error::DiscoveryError;
use crate::refresh::{SessionRefreshToken, REFRESH_MAX_PER_REQUEST};
use crate::token::TOKEN_LEN;

/// Reserved SOCKS5 hostname that routes to the claim service
/// instead of opening an upstream TCP connection.
pub const CLAIM_MAGIC_HOSTNAME: &str = "_mirage_claim._internal";

/// Reserved port used with [`CLAIM_MAGIC_HOSTNAME`]. Value is
/// arbitrary; the bridge dispatches on hostname.
pub const CLAIM_MAGIC_PORT: u16 = 1;

/// Wire version byte for the claim protocol.
pub const CLAIM_VERSION: u8 = 0x01;

/// `cmd`: one-time redemption of the invite's claim id.
pub const CLAIM_CMD_REDEEM: u8 = 0x01;

/// Status: claim accepted; refresh tokens may follow.
pub const CLAIM_STATUS_OK: u8 = 0x00;
/// Status: this claim id was already claimed at this bridge.
pub const CLAIM_STATUS_ALREADY_CLAIMED: u8 = 0x01;
/// Status: bridge has no room in its claimed-set (administrative
/// limit reached). Rare; defense against DoS by claim-spam.
pub const CLAIM_STATUS_CAPACITY: u8 = 0x02;
/// Status: bridge policy disables claim (operator opt-out).
pub const CLAIM_STATUS_POLICY: u8 = 0x03;
/// Status: wire-format error in the request.
pub const CLAIM_STATUS_BAD_REQUEST: u8 = 0x04;
/// Status: bridge-internal failure (claim log write error, etc.).
/// Distinct from `CAPACITY` so the client can distinguish "bridge
/// is administratively full" (don't retry) from "bridge had a
/// transient I/O error" (retry once).
pub const CLAIM_STATUS_INTERNAL: u8 = 0x05;

/// BLAKE3 `derive_key` context for the cohort claim-observation tag.
/// Domain-separates the cohort tag key from any other use of the
/// same key material.
pub const CLAIM_OBSERVATION_KDF_CONTEXT: &str = "mirage cohort claim-observation tag v1 2026-06-02";

/// Derive the cohort-wide, privacy-preserving **observation tag** for
/// a `claim_id`, used by the cross-bridge leak detector
/// ([`crate::cohort_gossip::GossipEvent::ClaimObserved`]).
///
/// The tag is `keyed_hash(derive_key(CONTEXT, cohort_key), claim_id)`.
/// Two properties make it the right primitive for leak attribution:
///
/// - **Deterministic across the cohort.** Every bridge sharing
///   `cohort_key` maps a given `claim_id` to the *same* tag, so the
///   detector can recognise "this invite was claimed at bridge A
///   *and* bridge B" without any bridge ever transmitting the raw id.
/// - **Unforgeable without the cohort key.** An adversary who has
///   scraped a set of leaked invites (claim ids) but does NOT hold
///   the cohort key cannot precompute tags to watch the gossip
///   channel and learn which of their stolen invites are live or
///   where. A keyed hash defeats this; a plain hash would not.
///
/// The cohort key is an operator-managed 32-byte secret shared by
/// every bridge in a cohort (see the bridge's `cohort_claim_tag_key`
/// configuration). It is independent of the per-bridge gossip
/// signing key.
pub fn claim_observation_tag(cohort_key: &[u8; 32], claim_id: &[u8; 32]) -> [u8; 32] {
    let subkey = mirage_crypto::blake3::derive_key(CLAIM_OBSERVATION_KDF_CONTEXT, cohort_key);
    *mirage_crypto::blake3::keyed_hash(&subkey, claim_id).as_bytes()
}

/// BLAKE3 `derive_key` context for the per-bridge claim id. Domain-separates
/// the derivation from the cohort observation tag and any other keyed use of
/// the invite secret.
pub const CLAIM_ID_KDF_CONTEXT: &str = "mirage per-bridge claim-id v1 2026-07-11";

/// Derive the **per-bridge** claim id the client presents to a specific bridge.
///
/// The invite carries a per-invite 32-byte *secret* (the value historically
/// called `claim_id`); it is NEVER sent on the wire. Instead the client sends
/// `derive_claim_id(secret, bridge_ed25519_pk)` to each bridge, so:
///
/// - **No cross-mesh tracking cookie.** Two colluding / seized / censor-run
///   bridges that compare their `claimed_invites` sets see two *unrelated*
///   32-byte ids for the same user. Recovering the shared invite would require
///   inverting a keyed hash to the secret, which they never receive. This
///   closes the linkage that cohort rationing exists to prevent under the
///   "lives at stake" model.
/// - **First-use semantics preserved.** The value is still deterministic per
///   (invite, bridge), so a duplicate claim at the *same* bridge still collides
///   and is rejected - the leaked-invite race defense is unchanged.
///
/// Tradeoff (documented, accepted): because each bridge now receives a distinct
/// id, the cohort leak detector can no longer correlate "same invite claimed at
/// bridge A *and* B" from claim ids - that cross-bridge correlation WAS the
/// tracking cookie. Cross-bridge invite-leak detection, if reintroduced, needs
/// a mechanism that does not hand every bridge an invariant plaintext id.
pub fn derive_claim_id(claim_secret: &[u8; 32], bridge_ed25519_pk: &[u8; 32]) -> [u8; 32] {
    let subkey = mirage_crypto::blake3::derive_key(CLAIM_ID_KDF_CONTEXT, claim_secret);
    *mirage_crypto::blake3::keyed_hash(&subkey, bridge_ed25519_pk).as_bytes()
}

/// Wire length of a [`ClaimRequest`] (fixed).
pub const CLAIM_REQUEST_LEN: usize = 4 + 32;

/// A parsed claim request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimRequest {
    /// Protocol version.
    pub version: u8,
    /// Command byte.
    pub cmd: u8,
    /// Number of refresh tokens to piggyback on success. 0 means
    /// "just claim, no tokens"; values above
    /// [`REFRESH_MAX_PER_REQUEST`] are clamped.
    pub refresh_count: u8,
    /// The 32-byte claim id from the invite.
    pub claim_id: [u8; 32],
}

impl ClaimRequest {
    /// Build a REDEEM request for `claim_id`, asking for
    /// `refresh_count` refresh tokens on success.
    pub fn redeem(claim_id: [u8; 32], refresh_count: u8) -> Self {
        Self {
            version: CLAIM_VERSION,
            cmd: CLAIM_CMD_REDEEM,
            refresh_count: refresh_count.min(REFRESH_MAX_PER_REQUEST),
            claim_id,
        }
    }

    /// Serialize to 36 wire bytes.
    pub fn encode(&self) -> [u8; CLAIM_REQUEST_LEN] {
        let mut out = [0u8; CLAIM_REQUEST_LEN];
        out[0] = self.version;
        out[1] = self.cmd;
        out[2] = self.refresh_count;
        out[3] = 0; // reserved
        out[4..36].copy_from_slice(&self.claim_id);
        out
    }

    /// Parse from wire bytes. Strict length + version + cmd.
    pub fn decode(buf: &[u8]) -> Result<Self, DiscoveryError> {
        if buf.len() != CLAIM_REQUEST_LEN {
            return Err(DiscoveryError::Wire("claim: request length"));
        }
        if buf[0] != CLAIM_VERSION {
            return Err(DiscoveryError::Wire("claim: unsupported version"));
        }
        if buf[1] != CLAIM_CMD_REDEEM {
            return Err(DiscoveryError::Wire("claim: unknown cmd"));
        }
        if buf[2] > REFRESH_MAX_PER_REQUEST {
            return Err(DiscoveryError::Wire("claim: refresh_count over cap"));
        }
        if buf[3] != 0 {
            return Err(DiscoveryError::Wire("claim: reserved byte nonzero"));
        }
        let mut claim_id = [0u8; 32];
        claim_id.copy_from_slice(&buf[4..36]);
        Ok(Self {
            version: buf[0],
            cmd: buf[1],
            refresh_count: buf[2],
            claim_id,
        })
    }
}

/// A claim response.
#[derive(Debug, Clone)]
pub struct ClaimResponse {
    /// Status byte.
    pub status: u8,
    /// Refresh tokens issued alongside the claim on success. Empty
    /// on any non-OK status.
    pub tokens: Vec<SessionRefreshToken>,
}

impl ClaimResponse {
    /// Empty response with a status byte set.
    pub fn empty(status: u8) -> Self {
        Self {
            status,
            tokens: Vec::new(),
        }
    }

    /// OK response with the given piggybacked refresh tokens.
    pub fn ok(tokens: Vec<SessionRefreshToken>) -> Self {
        Self {
            status: CLAIM_STATUS_OK,
            tokens,
        }
    }

    /// Serialize to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let n = self.tokens.len().min(u8::MAX as usize) as u8;
        let mut out = Vec::with_capacity(3 + n as usize * TOKEN_LEN);
        out.push(CLAIM_VERSION);
        out.push(self.status);
        out.push(n);
        for t in self.tokens.iter().take(n as usize) {
            out.extend_from_slice(&t.as_wire_bytes());
        }
        out
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, DiscoveryError> {
        if buf.len() < 3 {
            return Err(DiscoveryError::Wire("claim: response header too short"));
        }
        if buf[0] != CLAIM_VERSION {
            return Err(DiscoveryError::Wire("claim: unsupported version"));
        }
        let status = buf[1];
        let count = buf[2] as usize;
        if count > REFRESH_MAX_PER_REQUEST as usize {
            return Err(DiscoveryError::Wire("claim: token count over cap"));
        }
        let expected = 3 + count * TOKEN_LEN;
        if buf.len() != expected {
            return Err(DiscoveryError::Wire("claim: response body length"));
        }
        let mut tokens = Vec::with_capacity(count);
        let mut i = 3;
        for _ in 0..count {
            tokens.push(SessionRefreshToken::decode(&buf[i..i + TOKEN_LEN])?);
            i += TOKEN_LEN;
        }
        Ok(Self { status, tokens })
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refresh::sign_refresh_token;
    use mirage_crypto::ed25519_dalek::SigningKey;

    fn bridge_key() -> SigningKey {
        let mut s = [0u8; 32];
        getrandom::fill(&mut s).unwrap();
        SigningKey::from_bytes(&s)
    }

    #[test]
    fn observation_tag_is_deterministic_per_cohort_key() {
        let key = [0x11u8; 32];
        let cid = [0x22u8; 32];
        // Same key + same id => same tag (cross-bridge correlation).
        assert_eq!(
            claim_observation_tag(&key, &cid),
            claim_observation_tag(&key, &cid)
        );
    }

    #[test]
    fn observation_tag_separates_ids_and_keys() {
        let key_a = [0x11u8; 32];
        let key_b = [0x99u8; 32];
        let cid_1 = [0x22u8; 32];
        let cid_2 = [0x33u8; 32];
        // Different claim ids under the same key => different tags.
        assert_ne!(
            claim_observation_tag(&key_a, &cid_1),
            claim_observation_tag(&key_a, &cid_2)
        );
        // Same claim id under different cohort keys => different tags
        // (a foreign cohort can't recognise our claims, and a leaked
        // claim id alone can't be turned into our tag).
        assert_ne!(
            claim_observation_tag(&key_a, &cid_1),
            claim_observation_tag(&key_b, &cid_1)
        );
    }

    #[test]
    fn observation_tag_is_not_the_raw_id_or_a_plain_hash() {
        let key = [0x44u8; 32];
        let cid = [0x55u8; 32];
        let tag = claim_observation_tag(&key, &cid);
        // The tag must not equal the claim id (the id is a credential
        // and must never appear on the wire).
        assert_ne!(tag, cid);
        // ...nor the unkeyed BLAKE3 of the id (which a key-less
        // observer could compute). Keying is load-bearing.
        assert_ne!(tag, *mirage_crypto::blake3::hash(&cid).as_bytes());
    }

    #[test]
    fn derive_claim_id_is_per_bridge_and_deterministic() {
        let secret = [0x77u8; 32];
        let bridge_a = [0x01u8; 32];
        let bridge_b = [0x02u8; 32];
        // Deterministic for a fixed (secret, bridge): the bridge's first-use
        // dedup depends on the same client re-deriving the same id.
        assert_eq!(
            derive_claim_id(&secret, &bridge_a),
            derive_claim_id(&secret, &bridge_a)
        );
        // Per-bridge: the SAME invite yields DIFFERENT ids at different bridges,
        // so two hostile bridges comparing claimed-invite sets cannot link the
        // user (#2). This is the load-bearing property.
        assert_ne!(
            derive_claim_id(&secret, &bridge_a),
            derive_claim_id(&secret, &bridge_b)
        );
    }

    #[test]
    fn derive_claim_id_hides_the_secret_and_separates_invites() {
        let secret_1 = [0x33u8; 32];
        let secret_2 = [0x44u8; 32];
        let bridge = [0x09u8; 32];
        // The wire id must not equal the secret (the secret never leaves the
        // client) nor a plain hash a key-less bridge could invert to compare.
        let id = derive_claim_id(&secret_1, &bridge);
        assert_ne!(id, secret_1);
        assert_ne!(id, *mirage_crypto::blake3::hash(&bridge).as_bytes());
        // Different invites => different ids at the same bridge.
        assert_ne!(
            derive_claim_id(&secret_1, &bridge),
            derive_claim_id(&secret_2, &bridge)
        );
    }

    #[test]
    fn request_roundtrip() {
        let r = ClaimRequest::redeem([0xAAu8; 32], 3);
        let bytes = r.encode();
        assert_eq!(bytes.len(), CLAIM_REQUEST_LEN);
        let back = ClaimRequest::decode(&bytes).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn request_clamps_refresh_count_on_build() {
        let r = ClaimRequest::redeem([0u8; 32], REFRESH_MAX_PER_REQUEST + 10);
        assert_eq!(r.refresh_count, REFRESH_MAX_PER_REQUEST);
    }

    #[test]
    fn request_rejects_bad_version_cmd_or_reserved() {
        let ok = ClaimRequest::redeem([0u8; 32], 1).encode();
        let mut bad_ver = ok;
        bad_ver[0] = 0x02;
        assert!(ClaimRequest::decode(&bad_ver).is_err());
        let mut bad_cmd = ok;
        bad_cmd[1] = 0x99;
        assert!(ClaimRequest::decode(&bad_cmd).is_err());
        let mut bad_reserved = ok;
        bad_reserved[3] = 0xFF;
        assert!(ClaimRequest::decode(&bad_reserved).is_err());
    }

    #[test]
    fn request_rejects_over_cap_refresh_count() {
        let mut bad = ClaimRequest::redeem([0u8; 32], 1).encode();
        bad[2] = REFRESH_MAX_PER_REQUEST + 1;
        assert!(ClaimRequest::decode(&bad).is_err());
    }

    #[test]
    fn request_rejects_wrong_length() {
        assert!(ClaimRequest::decode(&[]).is_err());
        assert!(ClaimRequest::decode(&[0u8; CLAIM_REQUEST_LEN - 1]).is_err());
        assert!(ClaimRequest::decode(&[0u8; CLAIM_REQUEST_LEN + 1]).is_err());
    }

    #[test]
    fn response_empty_roundtrip() {
        let r = ClaimResponse::empty(CLAIM_STATUS_ALREADY_CLAIMED);
        let bytes = r.encode();
        let back = ClaimResponse::decode(&bytes).unwrap();
        assert_eq!(back.status, CLAIM_STATUS_ALREADY_CLAIMED);
        assert!(back.tokens.is_empty());
    }

    #[test]
    fn response_with_tokens_roundtrip() {
        let sk = bridge_key();
        let pk = sk.verifying_key().to_bytes();
        let tokens = vec![
            sign_refresh_token([0x01u8; 32], &sk, 1_700_000_000),
            sign_refresh_token([0x02u8; 32], &sk, 1_700_000_000),
        ];
        let r = ClaimResponse::ok(tokens);
        let bytes = r.encode();
        let back = ClaimResponse::decode(&bytes).unwrap();
        assert_eq!(back.status, CLAIM_STATUS_OK);
        assert_eq!(back.tokens.len(), 2);
        for t in &back.tokens {
            t.verify_signature(&pk).unwrap();
        }
    }

    #[test]
    fn response_rejects_length_mismatch() {
        // Declare 2 tokens, supply 1's worth of bytes.
        let sk = bridge_key();
        let t = sign_refresh_token([0x01u8; 32], &sk, 1_700_000_000);
        let mut bytes = vec![CLAIM_VERSION, CLAIM_STATUS_OK, 2];
        bytes.extend_from_slice(&t.as_wire_bytes());
        assert!(ClaimResponse::decode(&bytes).is_err());
    }

    #[test]
    fn response_rejects_over_cap() {
        let bytes = vec![CLAIM_VERSION, CLAIM_STATUS_OK, REFRESH_MAX_PER_REQUEST + 1];
        assert!(ClaimResponse::decode(&bytes).is_err());
    }

    #[test]
    fn fuzz_arbitrary_bytes_never_panic() {
        use proptest::prelude::*;
        proptest!(ProptestConfig::with_cases(256), |(b in prop::collection::vec(any::<u8>(), 0..2048))| {
            let _ = ClaimRequest::decode(&b);
            let _ = ClaimResponse::decode(&b);
        });
    }
}
