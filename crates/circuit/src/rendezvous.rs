//! The two bridge roles that make hidden services reachable.
//!
//! `mirage-onion` already had addresses, service descriptors, descriptor
//! sealing and the INTRODUCE body format. What it did not have - and what this
//! module is - is the interactive plane: the **introduction point** and the
//! **rendezvous point**, without which a published descriptor points at nothing.
//!
//! # The meeting
//!
//! ```text
//!   service                    I (intro point)      R (rendezvous)      client
//!      |                             |                    |               |
//!      |--- circuit + ESTABLISH_INTRO->                    |               |
//!      |<-- ESTABLISH_INTRO_OK -------|                    |               |
//!      |                             |  <- circuit + ESTABLISH_RENDEZVOUS -|
//!      |                             |   -- RENDEZVOUS_OK --------------->  |
//!      |                             |<--- circuit + INTRODUCE ------------|
//!      |<-- INTRODUCE (forwarded) ---|                    |               |
//!      |------------- circuit + RENDEZVOUS ------------->  |               |
//!      |                                          [JOIN: cookie matched]   |
//!      |<========== relayed cells both ways ==============>|<=============>|
//! ```
//!
//! # What each bridge learns
//!
//! Deliberately, almost nothing. `I` sees a circuit that registered an
//! introduction key and a circuit that sent an INTRODUCE for it; it forwards an
//! opaque body. `R` sees two circuits and a 32-byte cookie it cannot link to any
//! identity - the cookie is the client's own random value, and `R` never sees
//! the service's address, the client's address, or the descriptor. Neither can
//! locate the other party, which is the entire point of the design.
//!
//! # Why this is a state machine and not a task
//!
//! It mirrors [`crate::bridge_circuit`]: pure state plus an action list, no I/O.
//! The bridge runtime owns the sockets and performs the actions. That keeps the
//! security-relevant transitions - who may register, when a cookie matches, when
//! a join happens - testable exhaustively without a network.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use mirage_crypto::ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use thiserror::Error;

/// Length of a rendezvous cookie. 32 bytes: the client picks it at random and it
/// is the only thing linking two circuits at `R`, so it must be far too large to
/// guess or collide.
pub const COOKIE_LEN: usize = 32;

/// Length of an ESTABLISH_INTRO body: `intro_auth_pk || signature`.
pub const ESTABLISH_INTRO_BODY_LEN: usize = 32 + 64;

/// Length of a RENDEZVOUS body: `cookie || service_eph_x25519_pk`.
pub const RENDEZVOUS_BODY_LEN: usize = COOKIE_LEN + 32;

/// Domain separator for the ESTABLISH_INTRO signature.
const ESTABLISH_INTRO_CONTEXT: &[u8] = b"mirage-onion-establish-intro-v1";

/// How long an unmatched rendezvous cookie is held before being dropped.
///
/// The client parks its cookie, then has to build a second circuit and get an
/// INTRODUCE all the way through it before the service can answer, so this must
/// cover two circuit builds and a round trip. It also bounds how long a hostile
/// client can pin table space by parking cookies nobody will ever match.
pub const RENDEZVOUS_COOKIE_TTL: Duration = Duration::from_secs(120);

/// How long an introduction-point registration survives without renewal.
///
/// Longer than a cookie by design: a service keeps its introduction circuits up
/// for as long as it is published, and re-registering constantly would be a
/// distinctive traffic pattern of its own.
pub const INTRO_REGISTRATION_TTL: Duration = Duration::from_secs(30 * 60);

/// Cap on simultaneous introduction registrations at one bridge.
pub const MAX_INTRO_REGISTRATIONS: usize = 512;

/// Cap on simultaneous parked rendezvous cookies at one bridge.
pub const MAX_PARKED_COOKIES: usize = 4096;

/// A circuit, identified uniquely across the whole bridge.
///
/// Circuit ids are allocated **per session**, so two unrelated clients routinely
/// both hold a circuit 1. The rendezvous tables span sessions by definition (the
/// service registers on its session and the client introduces on a different
/// one), so keying them on a bare `circ_id` would let one client's circuit
/// collide with another's: the second would be refused as already-busy, and
/// forgetting one would evict the other's role. The session handle disambiguates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CircuitRef {
    /// Bridge-unique handle for the session the circuit belongs to.
    pub session: u64,
    /// Circuit id within that session. This is what a peer signs over, because
    /// it is the only half the peer can see.
    pub circ_id: u32,
}

impl CircuitRef {
    /// A reference to `circ_id` within `session`.
    #[must_use]
    pub fn new(session: u64, circ_id: u32) -> Self {
        Self { session, circ_id }
    }
}

/// Errors from the rendezvous/introduction roles.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RendezvousError {
    /// Body was not the exact length its command requires.
    #[error("{what} body must be {want} bytes, got {got}")]
    BadLength {
        /// Which body.
        what: &'static str,
        /// Required length.
        want: usize,
        /// Supplied length.
        got: usize,
    },
    /// The ESTABLISH_INTRO signature did not verify against the offered key, or
    /// was made over a different circuit.
    #[error("establish-intro signature did not verify")]
    BadSignature,
    /// The offered key was not a valid Ed25519 point.
    #[error("malformed introduction key")]
    BadKey,
    /// This circuit already registered, or already parked a cookie. One circuit
    /// has one role; re-using it is a protocol error, not a renewal.
    #[error("circuit {0} already has a rendezvous role")]
    CircuitBusy(u32),
    /// Another circuit already registered this introduction key. First
    /// registration wins for its TTL, so a hostile circuit cannot displace a
    /// live service by re-registering its key.
    #[error("introduction key already registered on another circuit")]
    IntroKeyTaken,
    /// Cookie already parked by another circuit.
    #[error("rendezvous cookie already parked")]
    CookieTaken,
    /// No service circuit is registered for the addressed introduction key.
    #[error("no introduction point registered for that key")]
    NoSuchIntro,
    /// The table is full.
    #[error("{0} table is full")]
    TableFull(&'static str),
}

/// Body of a [`crate::CMD_ESTABLISH_INTRO`] cell.
///
/// The signature covers the introduction key AND the circuit id it is being
/// registered on, so a captured registration cannot be replayed onto a
/// different circuit to hijack a service's introductions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstablishIntroBody {
    /// Per-introduction-point Ed25519 key, as published in the descriptor.
    pub intro_auth_pk: [u8; 32],
    /// Ed25519 signature over `context || circ_id_be || intro_auth_pk`.
    pub signature: [u8; 64],
}

impl EstablishIntroBody {
    /// Sign a registration for `circ_id` with the per-intro key.
    #[must_use]
    pub fn new(signing: &SigningKey, circ_id: u32) -> Self {
        let intro_auth_pk = signing.verifying_key().to_bytes();
        let sig = signing.sign(&Self::signing_input(circ_id, &intro_auth_pk));
        Self {
            intro_auth_pk,
            signature: sig.to_bytes(),
        }
    }

    fn signing_input(circ_id: u32, intro_auth_pk: &[u8; 32]) -> Vec<u8> {
        let mut v = Vec::with_capacity(ESTABLISH_INTRO_CONTEXT.len() + 4 + intro_auth_pk.len());
        v.extend_from_slice(ESTABLISH_INTRO_CONTEXT);
        v.extend_from_slice(&circ_id.to_be_bytes());
        v.extend_from_slice(intro_auth_pk);
        v
    }

    /// Serialize to the wire body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(ESTABLISH_INTRO_BODY_LEN);
        v.extend_from_slice(&self.intro_auth_pk);
        v.extend_from_slice(&self.signature);
        v
    }

    /// Parse a wire body.
    ///
    /// # Errors
    /// [`RendezvousError::BadLength`] if `b` is not exactly
    /// [`ESTABLISH_INTRO_BODY_LEN`].
    pub fn decode(b: &[u8]) -> Result<Self, RendezvousError> {
        if b.len() != ESTABLISH_INTRO_BODY_LEN {
            return Err(RendezvousError::BadLength {
                what: "establish-intro",
                want: ESTABLISH_INTRO_BODY_LEN,
                got: b.len(),
            });
        }
        let mut intro_auth_pk = [0u8; 32];
        intro_auth_pk.copy_from_slice(&b[..32]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&b[32..]);
        Ok(Self {
            intro_auth_pk,
            signature,
        })
    }

    /// Check the signature binds this key to `circ_id`.
    ///
    /// # Errors
    /// [`RendezvousError::BadKey`] if the key is not a valid Ed25519 point,
    /// [`RendezvousError::BadSignature`] if the signature does not verify.
    pub fn verify(&self, circ_id: u32) -> Result<(), RendezvousError> {
        let vk =
            VerifyingKey::from_bytes(&self.intro_auth_pk).map_err(|_| RendezvousError::BadKey)?;
        let sig = Signature::from_bytes(&self.signature);
        vk.verify_strict(&Self::signing_input(circ_id, &self.intro_auth_pk), &sig)
            .map_err(|_| RendezvousError::BadSignature)
    }
}

/// Body of a [`crate::CMD_RENDEZVOUS`] cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RendezvousBody {
    /// The cookie the client published in its INTRODUCE cell.
    pub cookie: [u8; COOKIE_LEN],
    /// The service's ephemeral X25519 public key, forwarded verbatim to the
    /// client so the two can finish a handshake the rendezvous point cannot read.
    pub service_eph_x25519_pk: [u8; 32],
}

impl RendezvousBody {
    /// Serialize to the wire body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(RENDEZVOUS_BODY_LEN);
        v.extend_from_slice(&self.cookie);
        v.extend_from_slice(&self.service_eph_x25519_pk);
        v
    }

    /// Parse a wire body.
    ///
    /// # Errors
    /// [`RendezvousError::BadLength`] if `b` is not exactly
    /// [`RENDEZVOUS_BODY_LEN`].
    pub fn decode(b: &[u8]) -> Result<Self, RendezvousError> {
        if b.len() != RENDEZVOUS_BODY_LEN {
            return Err(RendezvousError::BadLength {
                what: "rendezvous",
                want: RENDEZVOUS_BODY_LEN,
                got: b.len(),
            });
        }
        let mut cookie = [0u8; COOKIE_LEN];
        cookie.copy_from_slice(&b[..COOKIE_LEN]);
        let mut service_eph_x25519_pk = [0u8; 32];
        service_eph_x25519_pk.copy_from_slice(&b[COOKIE_LEN..]);
        Ok(Self {
            cookie,
            service_eph_x25519_pk,
        })
    }
}

/// What the runtime should do after feeding a cell to [`RendezvousState`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RendezvousAction {
    /// Acknowledge on the circuit the request arrived on.
    Ack {
        /// Circuit to answer.
        circ: CircuitRef,
        /// Cell command to send back.
        cmd: u8,
    },
    /// Forward an INTRODUCE body to the service's registered circuit.
    ForwardIntroduce {
        /// The service's introduction circuit.
        to_circ: CircuitRef,
        /// The INTRODUCE body, verbatim - the bridge does not interpret it.
        body: Vec<u8>,
    },
    /// Two circuits matched a cookie. Relay cells between them from now on.
    Join {
        /// The client's circuit (parked the cookie).
        client_circ: CircuitRef,
        /// The service's circuit (presented the cookie).
        service_circ: CircuitRef,
        /// The service's ephemeral key, to hand the client so it can finish the
        /// end-to-end handshake.
        service_eph_x25519_pk: [u8; 32],
    },
    /// A parked cookie or registration aged out; drop the circuit.
    Expire {
        /// Circuit to tear down.
        circ: CircuitRef,
    },
}

#[derive(Debug)]
struct IntroReg {
    circ: CircuitRef,
    at: Instant,
}

#[derive(Debug)]
struct ParkedCookie {
    circ: CircuitRef,
    at: Instant,
}

/// Introduction-point and rendezvous-point tables for one bridge.
///
/// Both roles live in one struct because a bridge plays both, often at once, and
/// they share the invariant that a circuit has exactly one rendezvous role.
#[derive(Debug, Default)]
pub struct RendezvousState {
    /// `intro_auth_pk -> service circuit`.
    intros: HashMap<[u8; 32], IntroReg>,
    /// `cookie -> waiting client circuit`.
    cookies: HashMap<[u8; COOKIE_LEN], ParkedCookie>,
    /// Circuits already holding a role, so one circuit cannot hold two.
    roles: HashMap<CircuitRef, Role>,
    /// Joined pairs, both directions, so a relayed cell finds its partner in one
    /// lookup regardless of which side it arrived on.
    joined: HashMap<CircuitRef, CircuitRef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Intro([u8; 32]),
    Cookie([u8; COOKIE_LEN]),
    Joined,
}

impl RendezvousState {
    /// A bridge with no registrations and no parked cookies.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of live introduction registrations.
    #[must_use]
    pub fn intro_count(&self) -> usize {
        self.intros.len()
    }

    /// Number of parked, unmatched cookies.
    #[must_use]
    pub fn parked_count(&self) -> usize {
        self.cookies.len()
    }

    /// The circuit a joined circuit is paired with, if any.
    #[must_use]
    pub fn partner(&self, circ: CircuitRef) -> Option<CircuitRef> {
        self.joined.get(&circ).copied()
    }

    /// Handle `ESTABLISH_INTRO` from a service.
    ///
    /// # Errors
    /// Rejects a malformed or unverifiable body, a circuit that already holds a
    /// role, a key already registered elsewhere, or a full table.
    pub fn establish_intro(
        &mut self,
        circ: CircuitRef,
        body: &[u8],
        now: Instant,
    ) -> Result<RendezvousAction, RendezvousError> {
        let parsed = EstablishIntroBody::decode(body)?;
        // Verify BEFORE any table mutation, so a bad signature costs nothing and
        // cannot be used to probe or evict live registrations. The signature
        // binds the LOCAL circuit id, which is the only half the service can see.
        parsed.verify(circ.circ_id)?;
        if self.roles.contains_key(&circ) {
            return Err(RendezvousError::CircuitBusy(circ.circ_id));
        }
        if let Some(existing) = self.intros.get(&parsed.intro_auth_pk) {
            // Same circuit renewing is fine; a DIFFERENT circuit is an attempt to
            // steal a live service's introductions and must be refused even
            // though it presents a valid signature - the key holder is whoever
            // registered first, for as long as that registration lives.
            if existing.circ != circ && now.duration_since(existing.at) < INTRO_REGISTRATION_TTL {
                return Err(RendezvousError::IntroKeyTaken);
            }
        }
        if self.intros.len() >= MAX_INTRO_REGISTRATIONS {
            return Err(RendezvousError::TableFull("introduction"));
        }
        self.intros
            .insert(parsed.intro_auth_pk, IntroReg { circ, at: now });
        self.roles.insert(circ, Role::Intro(parsed.intro_auth_pk));
        Ok(RendezvousAction::Ack {
            circ,
            cmd: crate::CMD_ESTABLISH_INTRO_OK,
        })
    }

    /// Handle `ESTABLISH_RENDEZVOUS` from a client.
    ///
    /// # Errors
    /// Rejects a wrong-length cookie, a circuit that already holds a role, a
    /// cookie already parked, or a full table.
    pub fn establish_rendezvous(
        &mut self,
        circ: CircuitRef,
        cookie_bytes: &[u8],
        now: Instant,
    ) -> Result<RendezvousAction, RendezvousError> {
        if cookie_bytes.len() != COOKIE_LEN {
            return Err(RendezvousError::BadLength {
                what: "rendezvous cookie",
                want: COOKIE_LEN,
                got: cookie_bytes.len(),
            });
        }
        if self.roles.contains_key(&circ) {
            return Err(RendezvousError::CircuitBusy(circ.circ_id));
        }
        let mut cookie = [0u8; COOKIE_LEN];
        cookie.copy_from_slice(cookie_bytes);
        if self.cookies.contains_key(&cookie) {
            return Err(RendezvousError::CookieTaken);
        }
        if self.cookies.len() >= MAX_PARKED_COOKIES {
            return Err(RendezvousError::TableFull("rendezvous"));
        }
        self.cookies.insert(cookie, ParkedCookie { circ, at: now });
        self.roles.insert(circ, Role::Cookie(cookie));
        Ok(RendezvousAction::Ack {
            circ,
            cmd: crate::CMD_RENDEZVOUS_OK,
        })
    }

    /// Handle `INTRODUCE` from a client: hand the body to the service circuit.
    ///
    /// The body is forwarded verbatim and deliberately not parsed here - the
    /// introduction point is not entitled to read it, and parsing it would only
    /// create an opportunity to leak what it saw.
    ///
    /// # Errors
    /// [`RendezvousError::NoSuchIntro`] when nothing is registered for the key.
    pub fn introduce(
        &mut self,
        intro_auth_pk: &[u8; 32],
        body: &[u8],
        now: Instant,
    ) -> Result<RendezvousAction, RendezvousError> {
        let reg = self
            .intros
            .get(intro_auth_pk)
            .filter(|r| now.duration_since(r.at) < INTRO_REGISTRATION_TTL)
            .ok_or(RendezvousError::NoSuchIntro)?;
        Ok(RendezvousAction::ForwardIntroduce {
            to_circ: reg.circ,
            body: body.to_vec(),
        })
    }

    /// Handle `RENDEZVOUS` from a service: match the cookie and join.
    ///
    /// # Errors
    /// Rejects a malformed body, a circuit already holding a role, or a cookie
    /// nobody parked (which is also what an expired cookie looks like).
    pub fn rendezvous(
        &mut self,
        service_circ: CircuitRef,
        body: &[u8],
        now: Instant,
    ) -> Result<RendezvousAction, RendezvousError> {
        let parsed = RendezvousBody::decode(body)?;
        if self.roles.contains_key(&service_circ) {
            return Err(RendezvousError::CircuitBusy(service_circ.circ_id));
        }
        let parked = self
            .cookies
            .get(&parsed.cookie)
            .filter(|p| now.duration_since(p.at) < RENDEZVOUS_COOKIE_TTL)
            .ok_or(RendezvousError::CookieTaken)?;
        let client_circ = parked.circ;

        // Consume the cookie on the join. A cookie is a one-time meeting token:
        // leaving it parked would let a second party join the same client, and
        // that second party would be indistinguishable from the first.
        self.cookies.remove(&parsed.cookie);
        self.roles.insert(client_circ, Role::Joined);
        self.roles.insert(service_circ, Role::Joined);
        self.joined.insert(client_circ, service_circ);
        self.joined.insert(service_circ, client_circ);

        Ok(RendezvousAction::Join {
            client_circ,
            service_circ,
            service_eph_x25519_pk: parsed.service_eph_x25519_pk,
        })
    }

    /// Drop every registration and cookie past its TTL, returning the circuits
    /// the runtime should tear down.
    pub fn tick(&mut self, now: Instant) -> Vec<RendezvousAction> {
        let mut out = Vec::new();
        self.cookies.retain(|_, p| {
            let live = now.duration_since(p.at) < RENDEZVOUS_COOKIE_TTL;
            if !live {
                out.push(RendezvousAction::Expire { circ: p.circ });
            }
            live
        });
        self.intros.retain(|_, r| {
            let live = now.duration_since(r.at) < INTRO_REGISTRATION_TTL;
            if !live {
                out.push(RendezvousAction::Expire { circ: r.circ });
            }
            live
        });
        for a in &out {
            if let RendezvousAction::Expire { circ } = a {
                self.roles.remove(circ);
            }
        }
        out
    }

    /// Forget a circuit and, if it was joined, its partner too.
    ///
    /// Returns the partner when there was one, so the runtime can tear down both
    /// halves: a joined pair that loses one side is a half-open meeting nobody
    /// can use, and leaving it up would keep a circuit alive as a distinctive
    /// long-lived idle flow.
    pub fn forget(&mut self, circ: CircuitRef) -> Option<CircuitRef> {
        match self.roles.remove(&circ) {
            Some(Role::Intro(pk)) => {
                if self.intros.get(&pk).is_some_and(|r| r.circ == circ) {
                    self.intros.remove(&pk);
                }
                None
            }
            Some(Role::Cookie(c)) => {
                if self.cookies.get(&c).is_some_and(|p| p.circ == circ) {
                    self.cookies.remove(&c);
                }
                None
            }
            Some(Role::Joined) => {
                let partner = self.joined.remove(&circ);
                if let Some(p) = partner {
                    self.joined.remove(&p);
                    self.roles.remove(&p);
                }
                partner
            }
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn now() -> Instant {
        Instant::now()
    }

    /// All single-session tests share one handle; the cross-session collision
    /// case below is the one that varies it.
    fn c(id: u32) -> CircuitRef {
        CircuitRef::new(1, id)
    }

    #[test]
    fn a_service_registers_and_a_client_reaches_it() {
        let mut st = RendezvousState::new();
        let t = now();
        let sk = key(1);

        let body = EstablishIntroBody::new(&sk, 7).encode();
        assert_eq!(
            st.establish_intro(c(7), &body, t).expect("register"),
            RendezvousAction::Ack {
                circ: c(7),
                cmd: crate::CMD_ESTABLISH_INTRO_OK
            }
        );
        assert_eq!(st.intro_count(), 1);

        // A client's INTRODUCE for that key reaches the service's circuit, and
        // the body crosses the bridge untouched.
        let pk = sk.verifying_key().to_bytes();
        let payload = b"opaque introduce body".to_vec();
        assert_eq!(
            st.introduce(&pk, &payload, t).expect("forward"),
            RendezvousAction::ForwardIntroduce {
                to_circ: c(7),
                body: payload
            }
        );
    }

    #[test]
    fn an_establish_intro_cannot_be_replayed_onto_another_circuit() {
        // The signature binds the registration to its circuit. Without that, a
        // bridge that saw one registration could replay it on a circuit it
        // controls and receive a service's introductions in its place.
        let mut st = RendezvousState::new();
        let t = now();
        let sk = key(2);
        let body = EstablishIntroBody::new(&sk, 11).encode();

        assert_eq!(
            st.establish_intro(c(99), &body, t),
            Err(RendezvousError::BadSignature)
        );
        assert_eq!(
            st.intro_count(),
            0,
            "a rejected registration leaves no trace"
        );
    }

    #[test]
    fn a_live_registration_cannot_be_stolen_by_another_circuit() {
        // Even holding the real key, a second circuit must not displace a live
        // service - otherwise anyone who learns a published intro key can
        // silently take over its introductions.
        let mut st = RendezvousState::new();
        let t = now();
        let sk = key(3);
        st.establish_intro(c(1), &EstablishIntroBody::new(&sk, 1).encode(), t)
            .expect("first");
        assert_eq!(
            st.establish_intro(c(2), &EstablishIntroBody::new(&sk, 2).encode(), t),
            Err(RendezvousError::IntroKeyTaken)
        );
        // The original service still owns it.
        let pk = sk.verifying_key().to_bytes();
        assert!(matches!(
            st.introduce(&pk, b"x", t).expect("still registered"),
            RendezvousAction::ForwardIntroduce { to_circ, .. } if to_circ == c(1)
        ));
    }

    #[test]
    fn a_cookie_joins_exactly_two_circuits_once() {
        let mut st = RendezvousState::new();
        let t = now();
        let cookie = [9u8; COOKIE_LEN];

        st.establish_rendezvous(c(20), &cookie, t).expect("park");
        assert_eq!(st.parked_count(), 1);

        let body = RendezvousBody {
            cookie,
            service_eph_x25519_pk: [4u8; 32],
        }
        .encode();
        assert_eq!(
            st.rendezvous(c(21), &body, t).expect("join"),
            RendezvousAction::Join {
                client_circ: c(20),
                service_circ: c(21),
                service_eph_x25519_pk: [4u8; 32],
            }
        );
        assert_eq!(st.partner(c(20)), Some(c(21)));
        assert_eq!(st.partner(c(21)), Some(c(20)));

        // The cookie is consumed: a second party presenting it must not be able
        // to join the same client, since the client could not tell them apart.
        assert_eq!(st.parked_count(), 0);
        assert_eq!(
            st.rendezvous(c(22), &body, t),
            Err(RendezvousError::CookieTaken)
        );
    }

    #[test]
    fn one_circuit_cannot_hold_two_roles() {
        let mut st = RendezvousState::new();
        let t = now();
        st.establish_rendezvous(c(5), &[1u8; COOKIE_LEN], t)
            .expect("park");
        let sk = key(4);
        assert_eq!(
            st.establish_intro(c(5), &EstablishIntroBody::new(&sk, 5).encode(), t),
            Err(RendezvousError::CircuitBusy(5))
        );
    }

    #[test]
    fn expired_cookies_are_reaped_and_their_circuits_reported() {
        let mut st = RendezvousState::new();
        let t0 = now();
        st.establish_rendezvous(c(30), &[7u8; COOKIE_LEN], t0)
            .expect("park");
        let later = t0 + RENDEZVOUS_COOKIE_TTL + Duration::from_secs(1);
        let acts = st.tick(later);
        assert_eq!(acts, vec![RendezvousAction::Expire { circ: c(30) }]);
        assert_eq!(st.parked_count(), 0);
        // And the role is released, so the circuit id can be reused.
        assert!(st
            .establish_rendezvous(c(30), &[8u8; COOKIE_LEN], later)
            .is_ok());
    }

    #[test]
    fn a_stale_cookie_does_not_join() {
        let mut st = RendezvousState::new();
        let t0 = now();
        let cookie = [3u8; COOKIE_LEN];
        st.establish_rendezvous(c(40), &cookie, t0).expect("park");
        let body = RendezvousBody {
            cookie,
            service_eph_x25519_pk: [0u8; 32],
        }
        .encode();
        let late = t0 + RENDEZVOUS_COOKIE_TTL + Duration::from_secs(1);
        assert_eq!(
            st.rendezvous(c(41), &body, late),
            Err(RendezvousError::CookieTaken)
        );
    }

    #[test]
    fn dropping_one_side_of_a_join_reports_the_other() {
        let mut st = RendezvousState::new();
        let t = now();
        let cookie = [5u8; COOKIE_LEN];
        st.establish_rendezvous(c(50), &cookie, t).expect("park");
        let body = RendezvousBody {
            cookie,
            service_eph_x25519_pk: [1u8; 32],
        }
        .encode();
        st.rendezvous(c(51), &body, t).expect("join");

        assert_eq!(
            st.forget(c(50)),
            Some(c(51)),
            "partner reported for teardown"
        );
        assert_eq!(st.partner(c(51)), None, "both halves released");
        assert_eq!(st.forget(c(51)), None);
    }

    #[test]
    fn circuits_from_different_sessions_do_not_collide() {
        // Circuit ids are per-session, so two unrelated clients routinely both
        // hold circuit 1 - and the rendezvous tables span sessions by design.
        // Keyed on a bare circ_id, the second client's request would be refused
        // as already-busy and forgetting one would evict the other's role.
        let mut st = RendezvousState::new();
        let t = now();
        let alice = CircuitRef::new(100, 1);
        let bob = CircuitRef::new(200, 1); // same circ_id, different session

        st.establish_rendezvous(alice, &[1u8; COOKIE_LEN], t)
            .expect("alice parks");
        st.establish_rendezvous(bob, &[2u8; COOKIE_LEN], t)
            .expect("bob must not be refused as busy");
        assert_eq!(st.parked_count(), 2);

        // And forgetting one leaves the other's parking intact.
        st.forget(alice);
        assert_eq!(st.parked_count(), 1);
        let body = RendezvousBody {
            cookie: [2u8; COOKIE_LEN],
            service_eph_x25519_pk: [0u8; 32],
        }
        .encode();
        assert!(
            matches!(
                st.rendezvous(CircuitRef::new(300, 1), &body, t),
                Ok(RendezvousAction::Join { client_circ, .. }) if client_circ == bob
            ),
            "bob's cookie must still join after alice's circuit went away"
        );
    }

    #[test]
    fn bodies_round_trip_and_reject_wrong_lengths() {
        let sk = key(6);
        let b = EstablishIntroBody::new(&sk, 3);
        assert_eq!(EstablishIntroBody::decode(&b.encode()).expect("rt"), b);
        assert!(matches!(
            EstablishIntroBody::decode(&[0u8; 10]),
            Err(RendezvousError::BadLength { .. })
        ));

        let r = RendezvousBody {
            cookie: [2u8; COOKIE_LEN],
            service_eph_x25519_pk: [3u8; 32],
        };
        assert_eq!(RendezvousBody::decode(&r.encode()).expect("rt"), r);
        assert!(matches!(
            RendezvousBody::decode(&[0u8; 3]),
            Err(RendezvousError::BadLength { .. })
        ));
    }

    #[test]
    fn tables_are_bounded() {
        // A bridge must not be forced to hold unbounded state by a client that
        // parks cookies it will never match.
        let mut st = RendezvousState::new();
        let t = now();
        for i in 0..MAX_PARKED_COOKIES {
            let mut ck = [0u8; COOKIE_LEN];
            ck[..8].copy_from_slice(&(i as u64).to_be_bytes());
            st.establish_rendezvous(CircuitRef::new(1, i as u32), &ck, t)
                .expect("park");
        }
        let mut over = [0xFFu8; COOKIE_LEN];
        over[0] = 0xAB;
        assert_eq!(
            st.establish_rendezvous(c(u32::MAX), &over, t),
            Err(RendezvousError::TableFull("rendezvous"))
        );
    }
}
