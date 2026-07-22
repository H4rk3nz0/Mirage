//! `PATH_CHALLENGE` / `PATH_RESPONSE` - anti-spoofing handshake
//! before migrating to a new path.
//!
//! Modeled on QUIC RFC 9000 §8.2. When peer A wants to validate
//! that path P is genuinely operated by peer B (and not an
//! attacker spoofing source IPs), A sends `PATH_CHALLENGE(8 random
//! bytes)`. B sends back `PATH_RESPONSE(same 8 bytes)`. If A
//! receives the response within `validation_timeout`, the path
//! is validated and migration completes.
//!
//! 8 bytes = 64 bits is enough to make a blind-spoofing attacker's
//! probability of guessing the response trivially small (`2^-64`).

use mirage_crypto::subtle::ConstantTimeEq;

/// Path-challenge byte length.
pub const CHALLENGE_LEN: usize = 8;

/// Wire-formatted `PATH_CHALLENGE` payload. 8 random bytes.
///
/// Intentionally does NOT derive `PartialEq`/`Eq`: any equality check
/// against a `PathChallenge` is part of an authentication decision,
/// and the only correct method is constant-time. Callers compare via
/// [`PathResponse::matches`].
#[derive(Debug, Clone, Copy)]
pub struct PathChallenge(pub [u8; CHALLENGE_LEN]);

impl PathChallenge {
    /// Generate a fresh challenge from CSPRNG.
    pub fn random() -> Option<Self> {
        let mut b = [0u8; CHALLENGE_LEN];
        getrandom::fill(&mut b).ok()?;
        Some(Self(b))
    }

    /// Construct from raw bytes (used at decode).
    pub fn from_bytes(bytes: [u8; CHALLENGE_LEN]) -> Self {
        Self(bytes)
    }

    /// Build the matching `PathResponse`. The responder typically
    /// constructs this on receiving a `PathChallenge`, then sends
    /// it back.
    pub fn to_response(self) -> PathResponse {
        PathResponse(self.0)
    }
}

/// Wire-formatted `PATH_RESPONSE` payload. Echoes the challenge.
///
/// Same constant-time-only equality discipline as [`PathChallenge`] -
/// derived `PartialEq` is omitted so callers can't accidentally
/// short-circuit-compare via `==`.
#[derive(Debug, Clone, Copy)]
pub struct PathResponse(pub [u8; CHALLENGE_LEN]);

impl PathResponse {
    /// Construct from raw bytes.
    pub fn from_bytes(bytes: [u8; CHALLENGE_LEN]) -> Self {
        Self(bytes)
    }

    /// Constant-time match against an outstanding challenge.
    pub fn matches(&self, challenge: &PathChallenge) -> bool {
        self.0.ct_eq(&challenge.0).unwrap_u8() == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_challenges_are_distinct() {
        let a = PathChallenge::random().expect("rng");
        let b = PathChallenge::random().expect("rng");
        // PartialEq is intentionally not derived; compare via the
        // constant-time matcher on PathResponse.
        assert!(
            !a.to_response().matches(&b),
            "two random challenges collided"
        );
    }

    #[test]
    fn correct_response_matches() {
        let c = PathChallenge::random().expect("rng");
        let r = c.to_response();
        assert!(r.matches(&c));
    }

    #[test]
    fn wrong_response_does_not_match() {
        let c = PathChallenge::random().expect("rng");
        let other = PathChallenge::random().expect("rng");
        let r = other.to_response();
        assert!(!r.matches(&c));
    }

    #[test]
    fn ct_eq_handles_one_byte_difference() {
        let c = PathChallenge::from_bytes([0xAA; CHALLENGE_LEN]);
        let mut wrong = [0xAA; CHALLENGE_LEN];
        wrong[3] ^= 0x01;
        let r = PathResponse::from_bytes(wrong);
        assert!(!r.matches(&c));
    }
}
