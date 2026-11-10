//! End-to-end keys for a client and a hidden service that have met.
//!
//! # The gap this closes
//!
//! Two circuits joined at a rendezvous point carry bytes (see
//! `mirage_bridge::rendezvous_router`), and until now those bytes were readable
//! by the bridge hosting the meeting. Both halves of the material needed to fix
//! that were already on the wire and nothing consumed them: the client's
//! ephemeral rides in the sealed INTRODUCE
//! ([`crate::introduce_sealed::Introduction`]), and the service's comes back in
//! [`mirage_circuit::rendezvous::RendezvousBody`], forwarded to the client by the
//! rendezvous point precisely so the two can key past it.
//!
//! # Why not just run a Mirage session over the circuit
//!
//! That was the obvious answer and it does not fit. `mirage_session`
//! authenticates a BRIDGE against an operator key and a capability token. A
//! public hidden service has neither: there is no operator vouching for it and
//! no token to present, and inventing one would turn every hidden service into
//! an invite-gated one. The trust model here is different in kind, not in
//! parameters.
//!
//! What a client actually needs to know is that it is talking to the holder of
//! the `.mirage` address it typed, and nothing else. That is one signature.
//!
//! # The exchange
//!
//! ```text
//!   client                     rendezvous point                    service
//!   ------                     ----------------                    -------
//!   eph_c ---- sealed INTRODUCE (via introduction point) ---------->
//!         <--- RENDEZVOUS (eph_s, forwarded verbatim) -------------- eph_s
//!         <--- AUTH: Ed25519(identity) over the transcript ---------
//!   verify against the .mirage address; both derive directional keys
//! ```
//!
//! - **Shared secret**: X25519 between the two fresh ephemerals. Both are new per
//!   rendezvous, so this is forward-secret - compromising the service's long-term
//!   identity later does not decrypt a recorded session. The sealed INTRODUCE is
//!   deliberately not forward-secret (see [`crate::introduce_sealed`]); this is,
//!   and this is what carries the traffic.
//! - **Transcript**: both ephemerals, the service identity, and the rendezvous
//!   cookie. Binding the cookie is what stops a signature captured from one
//!   meeting being replayed into another.
//! - **Authentication is one-sided, on purpose.** The service proves it holds the
//!   key the address names. The client proves nothing, because a public hidden
//!   service must accept strangers - that is what makes it public. Per-client
//!   authorization is an additive layer, not a change here.
//!
//! # What this module is not
//!
//! Keys and a transcript, with no I/O and no state machine, so the decisions are
//! testable without a cluster. Applying them to a byte stream is the caller's
//! (see `mirage_runtime::circuit_stream` for the stream, and the session layer of
//! the caller's choosing above it).

use mirage_crypto::blake3;
use mirage_crypto::ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use mirage_crypto::x25519_dalek::{PublicKey, StaticSecret};
use thiserror::Error;

/// Domain separation for the transcript hash.
const TRANSCRIPT_LABEL: &[u8] = b"mirage-onion-rendezvous-transcript-v1";
/// Domain separation for the directional key derivation.
const KEY_LABEL: &[u8] = b"mirage-onion-rendezvous-keys-v1";
/// What the service signs, separated from the transcript hash itself so the
/// signature can never be confused with a key.
const AUTH_LABEL: &[u8] = b"mirage-onion-rendezvous-auth-v1";

/// Errors from the rendezvous key exchange.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum E2eError {
    /// The service's authentication did not verify against the address's key.
    ///
    /// This is the one that matters: it means whatever answered at the
    /// rendezvous point does not hold the key the `.mirage` address names.
    #[error("service authentication failed - not the holder of this .mirage address")]
    NotTheService,
    /// The service's Ed25519 identity is not a valid point.
    #[error("malformed service identity key")]
    BadIdentity,
}

/// Directional keys for a joined rendezvous circuit.
///
/// Separate per direction so the two sides never encrypt under the same key with
/// the same nonce space, which is the classic way a symmetric channel loses
/// confidentiality without anyone touching the cipher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RendezvousKeys {
    /// Client -> service.
    pub c2s: [u8; 32],
    /// Service -> client.
    pub s2c: [u8; 32],
}

impl RendezvousKeys {
    /// This side's sending key, given whether we are the client.
    #[must_use]
    pub fn send_key(&self, is_client: bool) -> [u8; 32] {
        if is_client {
            self.c2s
        } else {
            self.s2c
        }
    }

    /// This side's receiving key.
    #[must_use]
    pub fn recv_key(&self, is_client: bool) -> [u8; 32] {
        if is_client {
            self.s2c
        } else {
            self.c2s
        }
    }
}

/// Everything both sides must agree on, hashed.
///
/// Anything a party could vary without the other noticing belongs in here, or a
/// signature over it proves less than it appears to.
#[must_use]
pub fn transcript(
    client_eph_pk: &[u8; 32],
    service_eph_pk: &[u8; 32],
    service_ed25519_pk: &[u8; 32],
    rendezvous_cookie: &[u8; 32],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(TRANSCRIPT_LABEL);
    h.update(client_eph_pk);
    h.update(service_eph_pk);
    h.update(service_ed25519_pk);
    h.update(rendezvous_cookie);
    *h.finalize().as_bytes()
}

/// Derive both directional keys from a shared secret and the transcript.
fn keys_from(shared: &[u8; 32], transcript: &[u8; 32]) -> RendezvousKeys {
    let mut h = blake3::Hasher::new();
    h.update(KEY_LABEL);
    h.update(shared);
    h.update(transcript);
    let mut xof = h.finalize_xof();
    let mut out = [0u8; 64];
    xof.fill(&mut out);
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    c2s.copy_from_slice(&out[..32]);
    s2c.copy_from_slice(&out[32..]);
    RendezvousKeys { c2s, s2c }
}

/// SERVICE side: derive keys and produce the authentication the client checks.
///
/// `service_eph_sk` must be fresh per rendezvous - it is what makes the session
/// forward-secret against later compromise of the identity key.
#[must_use]
pub fn service_side(
    service_eph_sk: &[u8; 32],
    client_eph_pk: &[u8; 32],
    service_id_sk: &SigningKey,
    rendezvous_cookie: &[u8; 32],
) -> (RendezvousKeys, [u8; 64]) {
    let eph = StaticSecret::from(*service_eph_sk);
    let service_eph_pk = *PublicKey::from(&eph).as_bytes();
    let shared = *eph
        .diffie_hellman(&PublicKey::from(*client_eph_pk))
        .as_bytes();
    let id_pk = service_id_sk.verifying_key().to_bytes();
    let t = transcript(client_eph_pk, &service_eph_pk, &id_pk, rendezvous_cookie);

    let mut signed = Vec::with_capacity(AUTH_LABEL.len() + 32);
    signed.extend_from_slice(AUTH_LABEL);
    signed.extend_from_slice(&t);
    let sig = service_id_sk.sign(&signed).to_bytes();

    (keys_from(&shared, &t), sig)
}

/// CLIENT side: verify the service, then derive the same keys.
///
/// `service_ed25519_pk` comes from the `.mirage` address the user typed, NOT from
/// the descriptor - a descriptor is fetched from a public channel, and trusting
/// its self-declared identity would let whoever published it substitute their
/// own. The address is the root of trust and this is where that matters.
///
/// # Errors
/// [`E2eError::NotTheService`] if the signature does not verify, which means
/// whatever answered does not hold the address's key.
pub fn client_side(
    client_eph_sk: &[u8; 32],
    service_eph_pk: &[u8; 32],
    service_ed25519_pk: &[u8; 32],
    rendezvous_cookie: &[u8; 32],
    service_auth: &[u8; 64],
) -> Result<RendezvousKeys, E2eError> {
    let vk = VerifyingKey::from_bytes(service_ed25519_pk).map_err(|_| E2eError::BadIdentity)?;
    let eph = StaticSecret::from(*client_eph_sk);
    let client_eph_pk = *PublicKey::from(&eph).as_bytes();
    let t = transcript(
        &client_eph_pk,
        service_eph_pk,
        service_ed25519_pk,
        rendezvous_cookie,
    );

    let mut signed = Vec::with_capacity(AUTH_LABEL.len() + 32);
    signed.extend_from_slice(AUTH_LABEL);
    signed.extend_from_slice(&t);
    // verify_strict: rejects the small-order and non-canonical keys that make
    // "a signature verifies" mean less than it should.
    vk.verify_strict(&signed, &Signature::from_bytes(service_auth))
        .map_err(|_| E2eError::NotTheService)?;

    let shared = *eph
        .diffie_hellman(&PublicKey::from(*service_eph_pk))
        .as_bytes();
    Ok(keys_from(&shared, &t))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> ([u8; 32], [u8; 32], SigningKey, [u8; 32]) {
        (
            StaticSecret::from([1u8; 32]).to_bytes(),
            StaticSecret::from([2u8; 32]).to_bytes(),
            SigningKey::from_bytes(&[3u8; 32]),
            [4u8; 32],
        )
    }

    #[test]
    fn both_sides_agree_and_the_client_authenticates_the_service() {
        let (c_sk, s_sk, id, cookie) = setup();
        let c_pk = *PublicKey::from(&StaticSecret::from(c_sk)).as_bytes();
        let s_pk = *PublicKey::from(&StaticSecret::from(s_sk)).as_bytes();

        let (svc_keys, auth) = service_side(&s_sk, &c_pk, &id, &cookie);
        let cli_keys = client_side(&c_sk, &s_pk, &id.verifying_key().to_bytes(), &cookie, &auth)
            .expect("the real service authenticates");

        assert_eq!(svc_keys, cli_keys, "both sides must derive the same keys");
        // Directional: what one sends, the other receives, and never the same key
        // in both directions.
        assert_eq!(cli_keys.send_key(true), svc_keys.recv_key(false));
        assert_eq!(svc_keys.send_key(false), cli_keys.recv_key(true));
        assert_ne!(cli_keys.c2s, cli_keys.s2c);
    }

    #[test]
    fn an_impostor_at_the_rendezvous_point_is_caught() {
        // THE property. Anyone can park a cookie and answer - the rendezvous
        // point does not know who the service is and cannot. What stops a
        // man-in-the-middle is the client checking the answer against the key its
        // ADDRESS names.
        let (c_sk, s_sk, real_id, cookie) = setup();
        let c_pk = *PublicKey::from(&StaticSecret::from(c_sk)).as_bytes();
        let s_pk = *PublicKey::from(&StaticSecret::from(s_sk)).as_bytes();

        let impostor = SigningKey::from_bytes(&[99u8; 32]);
        let (_keys, forged) = service_side(&s_sk, &c_pk, &impostor, &cookie);

        assert_eq!(
            client_side(
                &c_sk,
                &s_pk,
                &real_id.verifying_key().to_bytes(),
                &cookie,
                &forged
            ),
            Err(E2eError::NotTheService),
            "a signature by anyone else must not pass"
        );
    }

    #[test]
    fn an_auth_from_another_meeting_cannot_be_replayed() {
        // The cookie is in the transcript specifically so a signature captured
        // from one rendezvous is worthless at another - otherwise an adversary
        // who observed one successful meeting could impersonate the service in
        // every later one.
        let (c_sk, s_sk, id, cookie) = setup();
        let c_pk = *PublicKey::from(&StaticSecret::from(c_sk)).as_bytes();
        let s_pk = *PublicKey::from(&StaticSecret::from(s_sk)).as_bytes();
        let (_k, auth) = service_side(&s_sk, &c_pk, &id, &cookie);

        let other_cookie = [0xAAu8; 32];
        assert_eq!(
            client_side(
                &c_sk,
                &s_pk,
                &id.verifying_key().to_bytes(),
                &other_cookie,
                &auth
            ),
            Err(E2eError::NotTheService),
            "an auth bound to a different cookie must not transfer"
        );
    }

    #[test]
    fn a_substituted_ephemeral_breaks_the_authentication() {
        // A rendezvous point sits between the two and forwards the service's
        // ephemeral. If it swapped in its own to read the traffic, the transcript
        // the client signs over no longer matches the one the service signed.
        let (c_sk, s_sk, id, cookie) = setup();
        let c_pk = *PublicKey::from(&StaticSecret::from(c_sk)).as_bytes();
        let (_k, auth) = service_side(&s_sk, &c_pk, &id, &cookie);

        let attacker_eph = *PublicKey::from(&StaticSecret::from([0x77u8; 32])).as_bytes();
        assert_eq!(
            client_side(
                &c_sk,
                &attacker_eph,
                &id.verifying_key().to_bytes(),
                &cookie,
                &auth
            ),
            Err(E2eError::NotTheService),
            "swapping the service's ephemeral must be detected"
        );
    }

    #[test]
    fn each_rendezvous_gets_unrelated_keys() {
        // Fresh ephemerals per meeting are what make this forward-secret: a later
        // compromise of the identity key must not decrypt a recorded session.
        let (c_sk, s_sk, id, cookie) = setup();
        let c_pk = *PublicKey::from(&StaticSecret::from(c_sk)).as_bytes();
        let (k1, _) = service_side(&s_sk, &c_pk, &id, &cookie);

        let s_sk2 = StaticSecret::from([0x5Au8; 32]).to_bytes();
        let (k2, _) = service_side(&s_sk2, &c_pk, &id, &cookie);
        assert_ne!(k1, k2, "a fresh service ephemeral must change the keys");

        let c_pk2 = *PublicKey::from(&StaticSecret::from([0x6Bu8; 32])).as_bytes();
        let (k3, _) = service_side(&s_sk, &c_pk2, &id, &cookie);
        assert_ne!(k1, k3, "a fresh client ephemeral must change the keys");
    }

    #[test]
    fn a_malformed_identity_is_rejected_rather_than_panicking() {
        // This key arrives from a `.mirage` address a user typed or pasted, so a
        // malformed one must ERROR rather than panic. Which error is not the
        // point and is not asserted: `VerifyingKey::from_bytes` is deliberately
        // lenient - it accepts anything decodable and leaves the real work to
        // `verify_strict`, which is what rejects small-order and non-canonical
        // points. So most junk surfaces as NotTheService rather than
        // BadIdentity, and both are correct refusals.
        let (c_sk, s_sk, _id, cookie) = setup();
        let s_pk = *PublicKey::from(&StaticSecret::from(s_sk)).as_bytes();
        for bad in [[0xFFu8; 32], [0u8; 32], [1u8; 32]] {
            assert!(
                client_side(&c_sk, &s_pk, &bad, &cookie, &[0u8; 64]).is_err(),
                "a malformed identity must be refused, not trusted"
            );
        }
    }
}
