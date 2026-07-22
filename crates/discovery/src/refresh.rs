//! Session-scoped refresh tokens - in-band token reissue.
//!
//! # Problem
//!
//! A bootstrap `CapabilityToken` is single-use: after it's consumed in
//! one handshake it's recorded in the bridge's replay set and cannot
//! be reused. A [`MasterInvite`] carries a bounded number (spec §6.1:
//! 0..=16) of bootstrap tokens, so a long-lived `mirage-client`
//! process runs out of handshake credentials after N reconnects and
//! the user has to paste in a fresh invite.
//!
//! # Solution
//!
//! After a client has authenticated with a bootstrap token, it can
//! ask the bridge to mint a **session refresh token** - a single-use
//! credential signed by the bridge's own Ed25519 key (not the
//! operator's) that the client can present on the NEXT handshake to
//! that same bridge. A refresh token:
//!
//! - Is usable only at the bridge that issued it (bound by the
//!   `bridge_ed25519_pk` field and the signer).
//! - Is single-use (same replay-set semantics as bootstrap tokens).
//! - Has a short TTL (default 6 h - this is session continuity, not
//!   offline long-term reuse).
//! - Is signed by the bridge with a **domain-separated prefix** so
//!   it cannot be confused with an operator-issued bootstrap token
//!   by any implementation that accidentally swaps verification
//!   keys.
//!
//! # Trust story
//!
//! Q: Why is it safe for the bridge to sign its own continuation
//! credentials?
//!
//! A: The bridge ALREADY authenticated this session via an operator-
//! signed bootstrap token at handshake time. A refresh token does
//! NOT grant the client access to the bridge fleet - it grants
//! continuation at ONE bridge. If the bridge's identity key is
//! compromised, the attacker already has the Noise static SK and
//! can decrypt all tunnel traffic; minting forged refresh tokens is
//! strictly less harmful than what they can already do.
//!
//! The narrow trust boundary is what makes this safe without
//! extending the operator's signing authority.
//!
//! # Wire format
//!
//! Transport: inside an established Mirage session, SOCKS5 CONNECT
//! to [`REFRESH_MAGIC_HOSTNAME`]. Bridge intercepts before the SOCKS5
//! forwarder runs.
//!
//! Request (client -> bridge), 3 bytes:
//!
//! ```text
//!   u8 version   = 0x01
//!   u8 cmd       = 0x01 (ISSUE)
//!   u8 count     = 1..=REFRESH_MAX_PER_REQUEST
//! ```
//!
//! Response (bridge -> client):
//!
//! ```text
//!   u8  version  = 0x01
//!   u8  status   = 0x00 (OK) or error code
//!   u8  count    = number of tokens that follow
//!   N x 136 B    = SessionRefreshToken bytes
//! ```

use crate::error::DiscoveryError;
use crate::token::{CapabilityToken, TOKEN_LEN, TOKEN_SIGNED_PREFIX_LEN};
use crate::wire::{ED25519_PK_LEN, SIG_LEN};

/// Reserved SOCKS5 hostname that routes to the refresh-token
/// issuer instead of opening an upstream TCP connection.
pub const REFRESH_MAGIC_HOSTNAME: &str = "_mirage_refresh._internal";

/// Reserved port used with [`REFRESH_MAGIC_HOSTNAME`]. Value is
/// arbitrary; dispatch is on hostname.
pub const REFRESH_MAGIC_PORT: u16 = 1;

/// Wire version byte for the refresh protocol.
pub const REFRESH_VERSION: u8 = 0x01;

/// `cmd`: request issuance of one or more refresh tokens.
pub const REFRESH_CMD_ISSUE: u8 = 0x01;

/// Response status: OK, tokens follow.
pub const REFRESH_STATUS_OK: u8 = 0x00;
/// Response status: bridge has hit the per-root-token cap for this
/// caller (see [`DEFAULT_REFRESH_PER_ROOT_CAP`]).
pub const REFRESH_STATUS_EXHAUSTED: u8 = 0x01;
/// Response status: bridge policy disables refresh (operator opt-out).
pub const REFRESH_STATUS_POLICY: u8 = 0x02;
/// Response status: wire-format error in the request.
pub const REFRESH_STATUS_BAD_REQUEST: u8 = 0x03;
/// Response status: bridge-side internal error (CSPRNG failure,
/// unavailable signing key, etc.). No tokens follow.
pub const REFRESH_STATUS_INTERNAL: u8 = 0x04;

/// Maximum tokens a bridge will return in one response. Keeps the
/// response well under the session frame cap.
pub const REFRESH_MAX_PER_REQUEST: u8 = 4;

/// Default per-root-token lifetime issue cap. A single bootstrap or
/// refresh-root token, across every refresh request it supports,
/// never mints more than this many descendants. Prevents a
/// single-bootstrap-token invite from being parlayed into an
/// unlimited refresh chain.
pub const DEFAULT_REFRESH_PER_ROOT_CAP: u8 = 16;

/// Default TTL (seconds) on a newly-minted refresh token. Short by
/// design - the use-case is client-session continuity, not offline
/// reuse. A compromised refresh token expires quickly.
pub const DEFAULT_REFRESH_TTL_SECONDS: u64 = 6 * 3600;

/// Domain-separation tag prepended to the signed prefix of a
/// [`SessionRefreshToken`]. Ensures that even if the bridge's
/// Ed25519 signing key somehow matches the operator's (bad op-sec
/// but possible), an operator-signed token cannot be reinterpreted
/// as a refresh token or vice versa.
pub const REFRESH_SIGN_DOMAIN: &[u8] = b"mirage-refresh-v1\x00";

// Refresh request / response wire types

/// A parsed refresh-issuance request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefreshRequest {
    /// Protocol version (validated on parse).
    pub version: u8,
    /// Command byte.
    pub cmd: u8,
    /// Number of tokens requested. Bridge may return fewer.
    pub count: u8,
}

impl RefreshRequest {
    /// Build an ISSUE request asking for up to `count` tokens.
    pub fn issue(count: u8) -> Result<Self, DiscoveryError> {
        if count == 0 || count > REFRESH_MAX_PER_REQUEST {
            return Err(DiscoveryError::Wire("refresh: count out of range"));
        }
        Ok(Self {
            version: REFRESH_VERSION,
            cmd: REFRESH_CMD_ISSUE,
            count,
        })
    }

    /// Serialize to wire bytes (3 B).
    pub fn encode(&self) -> [u8; 3] {
        [self.version, self.cmd, self.count]
    }

    /// Parse from wire bytes. Strict length + version + cmd.
    pub fn decode(buf: &[u8]) -> Result<Self, DiscoveryError> {
        if buf.len() != 3 {
            return Err(DiscoveryError::Wire("refresh: request length"));
        }
        if buf[0] != REFRESH_VERSION {
            return Err(DiscoveryError::Wire("refresh: unsupported version"));
        }
        if buf[1] != REFRESH_CMD_ISSUE {
            return Err(DiscoveryError::Wire("refresh: unknown cmd"));
        }
        if buf[2] == 0 || buf[2] > REFRESH_MAX_PER_REQUEST {
            return Err(DiscoveryError::Wire("refresh: count out of range"));
        }
        Ok(Self {
            version: buf[0],
            cmd: buf[1],
            count: buf[2],
        })
    }
}

/// A built refresh response.
#[derive(Debug, Clone)]
pub struct RefreshResponse {
    /// Status byte.
    pub status: u8,
    /// Tokens included in the response (may be empty).
    pub tokens: Vec<SessionRefreshToken>,
}

impl RefreshResponse {
    /// Empty response with a status byte set.
    pub fn empty(status: u8) -> Self {
        Self {
            status,
            tokens: Vec::new(),
        }
    }

    /// OK response with the given tokens.
    pub fn ok(tokens: Vec<SessionRefreshToken>) -> Self {
        Self {
            status: REFRESH_STATUS_OK,
            tokens,
        }
    }

    /// Serialize to wire bytes: `[version][status][count u8][N x 136B token]`.
    pub fn encode(&self) -> Vec<u8> {
        let n = self.tokens.len().min(u8::MAX as usize) as u8;
        let mut out = Vec::with_capacity(3 + n as usize * TOKEN_LEN);
        out.push(REFRESH_VERSION);
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
            return Err(DiscoveryError::Wire("refresh: response header too short"));
        }
        if buf[0] != REFRESH_VERSION {
            return Err(DiscoveryError::Wire("refresh: unsupported version"));
        }
        let status = buf[1];
        let count = buf[2] as usize;
        if count > REFRESH_MAX_PER_REQUEST as usize {
            return Err(DiscoveryError::Wire("refresh: count over cap"));
        }
        let expected = 3 + count * TOKEN_LEN;
        if buf.len() != expected {
            return Err(DiscoveryError::Wire("refresh: response body length"));
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

// SessionRefreshToken - bridge-signed capability

/// A refresh token: 136-byte bridge-issued capability the client
/// presents at a subsequent handshake to re-authenticate without
/// consuming a bootstrap token.
///
/// Wire bytes are identical in layout to [`CapabilityToken`] - this
/// lets the session-handshake message 3 payload handle both forms
/// with a single codec. The distinguishing bit is the signer:
/// refresh tokens are signed by `bridge_ed25519_sk` over a
/// domain-separated prefix ([`REFRESH_SIGN_DOMAIN`]), so a
/// verifier that tries operator-sig first falls through to
/// refresh-sig without any wire-level disambiguation.
#[derive(Debug, Clone)]
pub struct SessionRefreshToken {
    /// Inner capability token - same fields as [`CapabilityToken`],
    /// just with a different signer.
    pub inner: CapabilityToken,
}

impl SessionRefreshToken {
    /// Serialize to 136 wire bytes.
    pub fn as_wire_bytes(&self) -> [u8; TOKEN_LEN] {
        self.inner.encode()
    }

    /// Parse from 136 wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, DiscoveryError> {
        Ok(Self {
            inner: CapabilityToken::decode(buf)?,
        })
    }

    /// Verify this token's signature against `bridge_ed25519_pk`
    /// using the [`REFRESH_SIGN_DOMAIN`] prefix.
    pub fn verify_signature(
        &self,
        bridge_ed25519_pk: &[u8; ED25519_PK_LEN],
    ) -> Result<(), DiscoveryError> {
        use mirage_crypto::ed25519_dalek::{Signature, VerifyingKey};
        let vk = VerifyingKey::from_bytes(bridge_ed25519_pk)
            .map_err(|_| DiscoveryError::Ed25519("invalid bridge pubkey"))?;
        let sig = Signature::from_bytes(&self.inner.signature);
        let mut prefix = Vec::with_capacity(REFRESH_SIGN_DOMAIN.len() + TOKEN_SIGNED_PREFIX_LEN);
        prefix.extend_from_slice(REFRESH_SIGN_DOMAIN);
        self.inner.encode_signed_prefix(&mut prefix);
        vk.verify_strict(&prefix, &sig)
            .map_err(|_| DiscoveryError::Signature("refresh: verification failed"))
    }

    /// True iff this token is bound to `bridge_pk`. Constant-time.
    pub fn is_for_bridge(&self, bridge_pk: &[u8; ED25519_PK_LEN]) -> bool {
        self.inner.is_for_bridge(bridge_pk)
    }

    /// True iff expired at `now_unix` (with `grace_seconds` skew).
    pub fn is_expired(&self, now_unix: u64, grace_seconds: u64) -> bool {
        self.inner.is_expired(now_unix, grace_seconds)
    }
}

/// Mint + sign a fresh refresh token.
///
/// The caller supplies the bridge's Ed25519 signing key; the token's
/// `bridge_ed25519_pk` field will be set to that key's public half,
/// and the signature covers `REFRESH_SIGN_DOMAIN || token_id ||
/// bridge_pk || expires_at`.
pub fn sign_refresh_token(
    token_id: [u8; 32],
    bridge_sk: &mirage_crypto::ed25519_dalek::SigningKey,
    expires_at: u64,
) -> SessionRefreshToken {
    use mirage_crypto::ed25519_dalek::Signer;
    let bridge_pk = bridge_sk.verifying_key().to_bytes();
    let mut inner = CapabilityToken {
        token_id,
        bridge_ed25519_pk: bridge_pk,
        expires_at,
        signature: [0u8; SIG_LEN],
    };
    let mut prefix = Vec::with_capacity(REFRESH_SIGN_DOMAIN.len() + TOKEN_SIGNED_PREFIX_LEN);
    prefix.extend_from_slice(REFRESH_SIGN_DOMAIN);
    inner.encode_signed_prefix(&mut prefix);
    inner.signature = bridge_sk.sign(&prefix).to_bytes();
    SessionRefreshToken { inner }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_crypto::ed25519_dalek::SigningKey;

    fn bridge_key() -> SigningKey {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        SigningKey::from_bytes(&seed)
    }

    #[test]
    fn request_roundtrip() {
        let r = RefreshRequest::issue(2).unwrap();
        let bytes = r.encode();
        assert_eq!(bytes, [REFRESH_VERSION, REFRESH_CMD_ISSUE, 2]);
        let back = RefreshRequest::decode(&bytes).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn request_rejects_zero_and_over_cap() {
        assert!(RefreshRequest::issue(0).is_err());
        assert!(RefreshRequest::issue(REFRESH_MAX_PER_REQUEST + 1).is_err());
        assert!(RefreshRequest::decode(&[REFRESH_VERSION, REFRESH_CMD_ISSUE, 0]).is_err());
        assert!(RefreshRequest::decode(&[
            REFRESH_VERSION,
            REFRESH_CMD_ISSUE,
            REFRESH_MAX_PER_REQUEST + 1
        ])
        .is_err());
    }

    #[test]
    fn request_rejects_bad_version_or_cmd() {
        assert!(RefreshRequest::decode(&[0x02, REFRESH_CMD_ISSUE, 1]).is_err());
        assert!(RefreshRequest::decode(&[REFRESH_VERSION, 0x99, 1]).is_err());
    }

    #[test]
    fn refresh_token_sign_verify_roundtrip() {
        let sk = bridge_key();
        let pk = sk.verifying_key().to_bytes();
        let tok = sign_refresh_token([0x33u8; 32], &sk, 1_700_000_000);
        tok.verify_signature(&pk).unwrap();
    }

    #[test]
    fn refresh_token_rejects_wrong_bridge_key() {
        let sk = bridge_key();
        let other = bridge_key();
        let other_pk = other.verifying_key().to_bytes();
        let tok = sign_refresh_token([0x33u8; 32], &sk, 1_700_000_000);
        assert!(tok.verify_signature(&other_pk).is_err());
    }

    #[test]
    fn refresh_token_wire_roundtrip() {
        let sk = bridge_key();
        let pk = sk.verifying_key().to_bytes();
        let tok = sign_refresh_token([0xCCu8; 32], &sk, 1_700_000_000);
        let bytes = tok.as_wire_bytes();
        assert_eq!(bytes.len(), TOKEN_LEN);
        let back = SessionRefreshToken::decode(&bytes).unwrap();
        back.verify_signature(&pk).unwrap();
        assert!(back.is_for_bridge(&pk));
    }

    #[test]
    fn domain_separator_prevents_cross_interpretation() {
        // A bridge that minted a refresh token must NOT be able to
        // have that token accepted as an operator-signed bootstrap
        // token even if someone points the operator verifier at the
        // bridge's pubkey (misconfiguration). The domain separator
        // in the refresh prefix is what blocks this.
        let sk = bridge_key();
        let pk = sk.verifying_key().to_bytes();
        let tok = sign_refresh_token([0xDDu8; 32], &sk, 1_700_000_000);
        // Feed the bridge pubkey as if it were the operator pk to
        // the operator-verify path. It MUST reject.
        assert!(
            tok.inner.verify_signature(&pk).is_err(),
            "refresh signature must not verify as operator signature"
        );
    }

    #[test]
    fn response_empty_roundtrip() {
        let r = RefreshResponse::empty(REFRESH_STATUS_EXHAUSTED);
        let bytes = r.encode();
        let back = RefreshResponse::decode(&bytes).unwrap();
        assert_eq!(back.status, REFRESH_STATUS_EXHAUSTED);
        assert!(back.tokens.is_empty());
    }

    #[test]
    fn response_multi_roundtrip() {
        let sk = bridge_key();
        let pk = sk.verifying_key().to_bytes();
        let t1 = sign_refresh_token([0x01u8; 32], &sk, 1_700_000_000);
        let t2 = sign_refresh_token([0x02u8; 32], &sk, 1_700_000_000);
        let r = RefreshResponse::ok(vec![t1, t2]);
        let bytes = r.encode();
        let back = RefreshResponse::decode(&bytes).unwrap();
        assert_eq!(back.status, REFRESH_STATUS_OK);
        assert_eq!(back.tokens.len(), 2);
        for t in &back.tokens {
            t.verify_signature(&pk).unwrap();
        }
    }

    #[test]
    fn response_rejects_over_cap() {
        // Forge a response claiming more tokens than the cap.
        let bytes = vec![
            REFRESH_VERSION,
            REFRESH_STATUS_OK,
            REFRESH_MAX_PER_REQUEST + 1,
        ];
        assert!(RefreshResponse::decode(&bytes).is_err());
    }

    #[test]
    fn response_rejects_length_mismatch() {
        // Declare 1 token but supply no body.
        let bytes = vec![REFRESH_VERSION, REFRESH_STATUS_OK, 1];
        assert!(RefreshResponse::decode(&bytes).is_err());
    }

    #[test]
    fn fuzz_arbitrary_bytes_never_panic() {
        use proptest::prelude::*;
        proptest!(ProptestConfig::with_cases(256), |(b in prop::collection::vec(any::<u8>(), 0..2048))| {
            let _ = RefreshRequest::decode(&b);
            let _ = RefreshResponse::decode(&b);
            if b.len() == TOKEN_LEN {
                let _ = SessionRefreshToken::decode(&b);
            }
        });
    }
}
