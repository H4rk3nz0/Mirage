//! `INTRODUCE` cell payload - the first message a client sends to
//! reach a hidden service.
//!
//! # Flow (informative)
//!
//! ```text
//!  Client                                     IntroPoint                      Service
//!  ------                                     ----------                      -------
//!  1. Build circuit C1 to introduction point bridge (already in descriptor).
//!  2. Build separate circuit C2 to a chosen rendezvous point bridge.
//!  3. Send INTRODUCE cell via C1, payload = (rendezvous bridge id, rendezvous
//!     cookie, ephemeral pk for C2 -> service handshake), signed with the
//!     intro_auth_key from the descriptor.
//!  4. IntroPoint forwards the INTRODUCE payload to the service over its
//!     pre-established service-side circuit.
//!  5. Service builds circuit C3 to the rendezvous point.
//!  6. Service sends RENDEZVOUS_REQUEST through C3 carrying the cookie.
//!  7. Rendezvous point matches the cookie to C2; client + service now share
//!     a 6-hop circuit (C2 + C3) with the rendezvous as the meeting hop.
//! ```
//!
//! This module specifies only step 3's payload: the `INTRODUCE`
//! cell body. Steps 1, 4-7 live in `mirage-circuit` (circuit
//! construction) and the bridge runtime (introduction-side accept
//! logic) - both deferred-real-impl items in v0.1u.
//!
//! # Wire format
//!
//! ```text
//!  Offset  Size   Field
//!  ------  ----   -----
//!  0       32     rendezvous_bridge_pk (Ed25519 of the rendezvous bridge)
//!  32      32     rendezvous_cookie    (random, opaque to IntroPoint and service)
//!  64      32     client_eph_x25519_pk (client's ephemeral X25519 public for the
//!                                       circuit-extension handshake to the service)
//!  96      64     signature            (Ed25519 by the descriptor's intro_auth_key
//!                                       over bytes [0..96])
//!  Total: 160 bytes.
//! ```
//!
//! The signature binds the introduction request to the client's
//! choice of rendezvous + cookie + ephemeral key. An `IntroPoint`
//! that forwards a tampered INTRODUCE cell is detectable: the
//! service verifies the signature against the descriptor's
//! `intro_auth_key` (which the service published).

use mirage_crypto::ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use thiserror::Error;

// rendezvous_bridge_pk[32] + rendezvous_cookie[32] + client_eph_x25519_pk[32]
// + issued_at[8] + service_ed25519_pk[32] + signature[64].
const INTRODUCE_BODY_LEN: usize = 32 + 32 + 32 + 8 + 32 + 64;

/// Default validity window (seconds) for an INTRODUCE cell relative to its
/// `issued_at`. A captured cell older than this is rejected by
/// [`IntroduceCell::is_fresh`]; the service's replay cache need only remember
/// a cell's [`IntroduceCell::replay_key`] for this long (RT #31).
pub const INTRODUCE_VALIDITY_SECS: u64 = 120;

/// Domain-separator prefix mixed into the INTRODUCE signing input.
/// Without this, the same Ed25519 verifier could be tricked into
/// accepting a signature minted for a different Mirage payload type
/// (e.g., a hidden-service descriptor) - Ed25519 alone has no
/// notion of "what is being signed." The prefix binds the signature
/// to (protocol, document type, version) so cross-protocol replay
/// is impossible.
///
/// Layout: `b"mirage/introduce/v1\0"` (20 bytes incl. NUL terminator
/// to keep length fixed and self-delimited from the body that
/// follows).
const INTRODUCE_SIG_DOMAIN: &[u8; 20] = b"mirage/introduce/v1\0";

/// Errors produced by `IntroduceCell` encode/decode/sign/verify.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IntroduceError {
    /// Wire-format violation.
    #[error("wire: {0}")]
    Wire(&'static str),
    /// Caller-supplied auth key doesn't match the signature.
    #[error("signature invalid")]
    BadSignature,
}

/// Parsed INTRODUCE cell body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntroduceCell {
    /// Rendezvous bridge's Ed25519 long-term identity.
    pub rendezvous_bridge_pk: [u8; 32],
    /// 32-byte random cookie. Opaque to the introduction point;
    /// matched at the rendezvous point.
    pub rendezvous_cookie: [u8; 32],
    /// Client's ephemeral X25519 public for the service-side
    /// circuit-extension handshake. The service uses this to
    /// derive shared secrets when extending its half of the
    /// rendezvous circuit.
    pub client_eph_x25519_pk: [u8; 32],
    /// Unix-seconds the cell was minted (RT #31). Bounds the replay window:
    /// the service rejects a cell outside `+/-INTRODUCE_VALIDITY_SECS` and need
    /// only remember its [`Self::replay_key`] for that long.
    pub issued_at: u64,
    /// The target service's Ed25519 identity (RT #31). Binding it into the
    /// signature stops a coerced introduction point from replaying a captured
    /// cell to a *different* service - the signature is valid only for the
    /// service the client addressed.
    pub service_ed25519_pk: [u8; 32],
    /// Ed25519 signature by the descriptor's `intro_auth_key`
    /// over the preceding fields (domain-separated).
    pub signature: [u8; 64],
}

impl IntroduceCell {
    /// Construct an unsigned INTRODUCE cell. Caller MUST sign
    /// before encoding.
    pub fn new(
        rendezvous_bridge_pk: [u8; 32],
        rendezvous_cookie: [u8; 32],
        client_eph_x25519_pk: [u8; 32],
        issued_at: u64,
        service_ed25519_pk: [u8; 32],
    ) -> Self {
        Self {
            rendezvous_bridge_pk,
            rendezvous_cookie,
            client_eph_x25519_pk,
            issued_at,
            service_ed25519_pk,
            signature: [0u8; 64],
        }
    }

    /// Whether the cell's `issued_at` is within `+/-INTRODUCE_VALIDITY_SECS` of
    /// `now_unix`. The service MUST check this AND record [`Self::replay_key`]
    /// in a replay cache (e.g. `mirage_common::SeenNonceSet`) so a captured
    /// cell can neither be replayed late (fails freshness) nor twice within
    /// the window (fails the cache) - RT #31.
    pub fn is_fresh(&self, now_unix: u64) -> bool {
        let skew = now_unix.max(self.issued_at) - now_unix.min(self.issued_at);
        skew <= INTRODUCE_VALIDITY_SECS
    }

    /// Stable per-introduction key for the service's replay cache: the
    /// signature uniquely identifies this introduction (it signs the random
    /// cookie + `issued_at`), so a verbatim replay shares this key.
    pub fn replay_key(&self) -> [u8; 32] {
        *mirage_crypto::blake3::hash(&self.signature).as_bytes()
    }

    /// Sign in place with the descriptor's `intro_auth_key` SK.
    pub fn sign(&mut self, intro_auth_sk: &SigningKey) -> Result<(), IntroduceError> {
        let mut prefix = Vec::with_capacity(INTRODUCE_SIG_DOMAIN.len() + 96);
        self.encode_signed_prefix(&mut prefix);
        self.signature = intro_auth_sk.sign(&prefix).to_bytes();
        Ok(())
    }

    /// Verify the signature against `intro_auth_pk` (which the
    /// service published in its descriptor).
    pub fn verify(&self, intro_auth_pk: &[u8; 32]) -> Result<(), IntroduceError> {
        let vk =
            VerifyingKey::from_bytes(intro_auth_pk).map_err(|_| IntroduceError::BadSignature)?;
        let mut prefix = Vec::with_capacity(INTRODUCE_SIG_DOMAIN.len() + 96);
        self.encode_signed_prefix(&mut prefix);
        vk.verify_strict(&prefix, &Signature::from_bytes(&self.signature))
            .map_err(|_| IntroduceError::BadSignature)
    }

    fn encode_signed_prefix(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(INTRODUCE_SIG_DOMAIN);
        out.extend_from_slice(&self.rendezvous_bridge_pk);
        out.extend_from_slice(&self.rendezvous_cookie);
        out.extend_from_slice(&self.client_eph_x25519_pk);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.service_ed25519_pk);
    }

    /// Encode the full cell body ([`INTRODUCE_BODY_LEN`] bytes).
    pub fn encode(&self) -> [u8; INTRODUCE_BODY_LEN] {
        let mut out = [0u8; INTRODUCE_BODY_LEN];
        out[0..32].copy_from_slice(&self.rendezvous_bridge_pk);
        out[32..64].copy_from_slice(&self.rendezvous_cookie);
        out[64..96].copy_from_slice(&self.client_eph_x25519_pk);
        out[96..104].copy_from_slice(&self.issued_at.to_be_bytes());
        out[104..136].copy_from_slice(&self.service_ed25519_pk);
        out[136..200].copy_from_slice(&self.signature);
        out
    }

    /// Decode from cell body bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, IntroduceError> {
        if buf.len() != INTRODUCE_BODY_LEN {
            return Err(IntroduceError::Wire("introduce body wrong length"));
        }
        let mut rendezvous_bridge_pk = [0u8; 32];
        rendezvous_bridge_pk.copy_from_slice(&buf[0..32]);
        let mut rendezvous_cookie = [0u8; 32];
        rendezvous_cookie.copy_from_slice(&buf[32..64]);
        let mut client_eph_x25519_pk = [0u8; 32];
        client_eph_x25519_pk.copy_from_slice(&buf[64..96]);
        let issued_at = u64::from_be_bytes([
            buf[96], buf[97], buf[98], buf[99], buf[100], buf[101], buf[102], buf[103],
        ]);
        let mut service_ed25519_pk = [0u8; 32];
        service_ed25519_pk.copy_from_slice(&buf[104..136]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&buf[136..200]);
        Ok(Self {
            rendezvous_bridge_pk,
            rendezvous_cookie,
            client_eph_x25519_pk,
            issued_at,
            service_ed25519_pk,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (SigningKey, [u8; 32]) {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        let sk = SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    #[test]
    fn introduce_sign_verify_roundtrip() {
        let (sk, pk) = keypair();
        let mut cell = IntroduceCell::new(
            [0xAAu8; 32],
            [0xBBu8; 32],
            [0xCCu8; 32],
            1_700_000_000,
            [0xDDu8; 32],
        );
        cell.sign(&sk).unwrap();
        let bytes = cell.encode();
        let back = IntroduceCell::decode(&bytes).unwrap();
        assert_eq!(back, cell);
        back.verify(&pk).unwrap();
    }

    #[test]
    fn verify_rejects_wrong_auth_key() {
        let (sk, _pk) = keypair();
        let (_, other_pk) = keypair();
        let mut cell = IntroduceCell::new(
            [0xAAu8; 32],
            [0xBBu8; 32],
            [0xCCu8; 32],
            1_700_000_000,
            [0xDDu8; 32],
        );
        cell.sign(&sk).unwrap();
        let err = cell.verify(&other_pk).unwrap_err();
        assert_eq!(err, IntroduceError::BadSignature);
    }

    #[test]
    fn verify_rejects_tampered_cookie() {
        let (sk, pk) = keypair();
        let mut cell = IntroduceCell::new(
            [0xAAu8; 32],
            [0xBBu8; 32],
            [0xCCu8; 32],
            1_700_000_000,
            [0xDDu8; 32],
        );
        cell.sign(&sk).unwrap();
        let mut bytes = cell.encode();
        bytes[40] ^= 0x01;
        let back = IntroduceCell::decode(&bytes).unwrap();
        assert_eq!(back.verify(&pk).unwrap_err(), IntroduceError::BadSignature);
    }

    #[test]
    fn signature_bound_to_introduce_domain() {
        // Ed25519 has no built-in notion of "what is being signed."
        // A signature minted over the bare 96-byte body would
        // verify against any other 96-byte input. The domain prefix
        // ensures `sign` produces a different signature than a
        // raw-body sign would, so cross-protocol replay is blocked.
        let (sk, _pk) = keypair();
        let mut cell = IntroduceCell::new(
            [0xAAu8; 32],
            [0xBBu8; 32],
            [0xCCu8; 32],
            1_700_000_000,
            [0xDDu8; 32],
        );
        cell.sign(&sk).unwrap();
        // Manually sign the bare body (no domain prefix) - should
        // produce a different signature.
        let mut bare = Vec::with_capacity(96);
        bare.extend_from_slice(&cell.rendezvous_bridge_pk);
        bare.extend_from_slice(&cell.rendezvous_cookie);
        bare.extend_from_slice(&cell.client_eph_x25519_pk);
        let bare_sig = sk.sign(&bare).to_bytes();
        assert_ne!(cell.signature, bare_sig);
    }

    /// RT #31: the signature now covers `issued_at` and the target
    /// `service_ed25519_pk`, so tampering with either is detected - a coerced
    /// intro point cannot re-time or re-target a captured cell.
    #[test]
    fn verify_rejects_tampered_issued_at_or_service_pk() {
        let (sk, pk) = keypair();
        let mut cell = IntroduceCell::new(
            [0xAAu8; 32],
            [0xBBu8; 32],
            [0xCCu8; 32],
            1_700_000_000,
            [0xDDu8; 32],
        );
        cell.sign(&sk).unwrap();

        // Flip a byte of issued_at (offset 96..104).
        let mut t1 = cell.encode();
        t1[100] ^= 0x01;
        assert_eq!(
            IntroduceCell::decode(&t1).unwrap().verify(&pk).unwrap_err(),
            IntroduceError::BadSignature
        );
        // Flip a byte of service_ed25519_pk (offset 104..136).
        let mut t2 = cell.encode();
        t2[110] ^= 0x01;
        assert_eq!(
            IntroduceCell::decode(&t2).unwrap().verify(&pk).unwrap_err(),
            IntroduceError::BadSignature
        );
    }

    /// RT #31: freshness window + replay-key give the service a bounded,
    /// reliable replay defense.
    #[test]
    fn freshness_window_and_replay_key() {
        let (sk, _pk) = keypair();
        let mut cell = IntroduceCell::new(
            [0xAAu8; 32],
            [0xBBu8; 32],
            [0xCCu8; 32],
            1_700_000_000,
            [0xDDu8; 32],
        );
        cell.sign(&sk).unwrap();

        assert!(cell.is_fresh(1_700_000_000));
        assert!(cell.is_fresh(1_700_000_000 + INTRODUCE_VALIDITY_SECS));
        assert!(!cell.is_fresh(1_700_000_000 + INTRODUCE_VALIDITY_SECS + 1));
        assert!(!cell.is_fresh(1_700_000_000 - INTRODUCE_VALIDITY_SECS - 1));

        // A verbatim replay shares the replay key; a distinct cookie does not.
        let key = cell.replay_key();
        assert_eq!(cell.replay_key(), key, "stable per cell");
        let seen = mirage_common::SeenNonceSet::new(std::time::Duration::from_secs(
            INTRODUCE_VALIDITY_SECS,
        ));
        assert!(seen.check_and_insert(key, std::time::Instant::now()));
        assert!(
            !seen.check_and_insert(key, std::time::Instant::now()),
            "a replayed introduction is rejected by the service replay cache"
        );
    }

    #[test]
    fn decode_rejects_wrong_length() {
        assert!(matches!(
            IntroduceCell::decode(&[0u8; INTRODUCE_BODY_LEN - 1]),
            Err(IntroduceError::Wire(_))
        ));
        assert!(matches!(
            IntroduceCell::decode(&[0u8; INTRODUCE_BODY_LEN + 1]),
            Err(IntroduceError::Wire(_))
        ));
    }
}
