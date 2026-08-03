//! Service-side lifecycle: introduction points, descriptor freshness, and
//! answering an INTRODUCE.
//!
//! The bridge roles ([`mirage_circuit::rendezvous`]) and the routing beneath
//! them (`mirage_bridge::rendezvous_router`) let a client and a service meet.
//! This is the decision half of the service end: which introduction points to
//! hold, when the published descriptor has to be renewed, and whether a given
//! INTRODUCE deserves an answer.
//!
//! It is a pure state machine with no I/O, for the same reason
//! `mirage_circuit::rendezvous` is: the parts that decide whether to answer a
//! stranger, and whether a descriptor is about to expire out from under a live
//! service, are the parts that must be testable exhaustively rather than
//! observed on a cluster. The driver that builds circuits and speaks to bridges
//! sits on top.
//!
//! # The two failures this exists to prevent
//!
//! **A service that silently vanishes.** A descriptor is published per epoch
//! and expires. If republication waits until expiry, there is a window where
//! clients resolve nothing and the service looks gone - to them, indistinguishable
//! from being blocked. [`ServiceState::needs_republish`] renews EARLY, by a
//! margin, rather than on expiry.
//!
//! **A replayed introduction.** An INTRODUCE cell is signed but a signature is
//! replayable, so a captured one could make the service build a circuit to an
//! attacker-chosen rendezvous point, repeatedly, for free.
//! [`ServiceState::accept_introduce`] enforces freshness AND remembers
//! [`IntroduceCell::replay_key`] for the validity window, which is exactly as
//! long as a cell can be replayed.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use mirage_crypto::ed25519_dalek::SigningKey;

use crate::descriptor::{IntroPoint, OnionDescriptor, MAX_INTRO_POINTS};
use crate::introduce::{IntroduceCell, INTRODUCE_VALIDITY_SECS};

/// How many introduction points a service tries to hold.
///
/// More than one because losing the only one takes the service offline until a
/// new descriptor propagates; not many more because each is a long-lived
/// circuit whose existence is itself observable at that bridge.
pub const TARGET_INTRO_POINTS: usize = 3;

/// Renew the descriptor this long before it expires.
///
/// The gap has to cover publishing to several discovery channels and those
/// channels propagating, or the renewal lands after clients have already
/// started failing to resolve.
pub const REPUBLISH_MARGIN: Duration = Duration::from_secs(10 * 60);

/// Why an INTRODUCE was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntroduceRefusal {
    /// Signature did not verify against the intro key it claims.
    BadSignature,
    /// Outside the validity window - too old, or too far in the future.
    Stale,
    /// Seen before. A signature is replayable; this is what stops one captured
    /// cell driving unlimited rendezvous circuits.
    Replay,
    /// Not addressed to an introduction point this service holds.
    UnknownIntroPoint,
}

/// One introduction point the service is holding or trying to hold.
#[derive(Debug, Clone)]
pub struct HeldIntro {
    /// Bridge identity.
    pub bridge_ed25519_pk: [u8; 32],
    /// Bridge static X25519.
    pub bridge_x25519_pk: [u8; 32],
    /// Where a client dials this bridge. Published in the descriptor, because a
    /// bare identity is not dialable and there is no global directory.
    pub endpoint: String,
    /// Per-introduction signing key, published in the descriptor as its public
    /// half.
    ///
    /// What it genuinely authenticates is the REGISTRATION: the service signs
    /// its own circuit id with it in `EstablishIntroBody`, and the bridge checks
    /// that against the key being claimed, so nobody can register an
    /// introduction point they do not hold the key for.
    ///
    /// It is ALSO what [`ServiceState::accept_introduce`] verifies an INTRODUCE
    /// signature against, and that half cannot work - only this service holds
    /// the private key, so no client can produce a cell that passes. Pinned by
    /// `no_client_can_produce_an_acceptable_introduce_cell`; see the crate
    /// header for the two ways out.
    pub intro_sk: SigningKey,
    /// Whether the bridge has acknowledged the registration.
    pub established: bool,
}

impl HeldIntro {
    /// The descriptor entry for this introduction point.
    #[must_use]
    pub fn to_descriptor_entry(&self) -> IntroPoint {
        IntroPoint {
            bridge_ed25519_pk: self.bridge_ed25519_pk,
            bridge_x25519_pk: self.bridge_x25519_pk,
            intro_auth_key: self.intro_sk.verifying_key().to_bytes(),
            endpoint: self.endpoint.clone(),
        }
    }
}

/// Service-side decision state.
pub struct ServiceState {
    intros: Vec<HeldIntro>,
    /// `replay_key -> when it was seen`, pruned on each acceptance.
    seen: HashMap<[u8; 32], Instant>,
    /// Expiry of the descriptor currently published, if any.
    published_expires_at: Option<u64>,
}

impl Default for ServiceState {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceState {
    /// A service holding nothing yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            intros: Vec::new(),
            seen: HashMap::new(),
            published_expires_at: None,
        }
    }

    /// Introduction points currently held.
    #[must_use]
    pub fn intros(&self) -> &[HeldIntro] {
        &self.intros
    }

    /// How many more introduction points to establish.
    #[must_use]
    pub fn intros_wanted(&self) -> usize {
        TARGET_INTRO_POINTS.saturating_sub(self.intros.iter().filter(|i| i.established).count())
    }

    /// Start holding an introduction point. Ignored past [`MAX_INTRO_POINTS`],
    /// which is the descriptor's own limit - holding more than can be published
    /// would be work no client could ever use.
    pub fn add_intro(&mut self, intro: HeldIntro) {
        if self.intros.len() < MAX_INTRO_POINTS as usize
            && !self
                .intros
                .iter()
                .any(|i| i.bridge_ed25519_pk == intro.bridge_ed25519_pk)
        {
            self.intros.push(intro);
        }
    }

    /// Mark an introduction point acknowledged by its bridge.
    pub fn mark_established(&mut self, bridge_ed25519_pk: &[u8; 32]) {
        if let Some(i) = self
            .intros
            .iter_mut()
            .find(|i| &i.bridge_ed25519_pk == bridge_ed25519_pk)
        {
            i.established = true;
        }
    }

    /// Drop an introduction point whose circuit died.
    ///
    /// Returns whether the descriptor now misrepresents reality - if a
    /// published descriptor still lists this bridge, clients will keep
    /// introducing through a circuit that is gone, and every one of those
    /// attempts fails silently from their side.
    pub fn drop_intro(&mut self, bridge_ed25519_pk: &[u8; 32]) -> bool {
        let before = self.intros.len();
        self.intros
            .retain(|i| &i.bridge_ed25519_pk != bridge_ed25519_pk);
        let dropped = self.intros.len() != before;
        dropped && self.published_expires_at.is_some()
    }

    /// Record that a descriptor expiring at `expires_at` was published.
    pub fn mark_published(&mut self, expires_at: u64) {
        self.published_expires_at = Some(expires_at);
    }

    /// Should the descriptor be republished now?
    ///
    /// True when nothing is published, or when expiry is within
    /// [`REPUBLISH_MARGIN`]. Early on purpose: renewing on expiry leaves a
    /// window where clients resolve nothing, and a service that cannot be
    /// resolved is indistinguishable from a blocked one.
    #[must_use]
    pub fn needs_republish(&self, now_unix: u64) -> bool {
        match self.published_expires_at {
            None => !self.intros.is_empty(),
            Some(exp) => now_unix.saturating_add(REPUBLISH_MARGIN.as_secs()) >= exp,
        }
    }

    /// Build the descriptor for the introduction points currently established.
    ///
    /// # Errors
    /// Propagates a descriptor encoding/signing failure.
    pub fn build_descriptor(
        &self,
        service_sk: &SigningKey,
        service_x25519_pk: [u8; 32],
        issued_at: u64,
        expires_at: u64,
    ) -> Result<OnionDescriptor, crate::descriptor::ServiceDescError> {
        let points: Vec<IntroPoint> = self
            .intros
            .iter()
            .filter(|i| i.established)
            .map(HeldIntro::to_descriptor_entry)
            .collect();
        let mut d = OnionDescriptor::new(
            issued_at,
            expires_at,
            service_sk.verifying_key().to_bytes(),
            service_x25519_pk,
            points,
        )?;
        d.sign(service_sk)?;
        Ok(d)
    }

    /// Decide whether to answer an INTRODUCE.
    ///
    /// # Errors
    /// One of [`IntroduceRefusal`]. A refusal is never fatal - it is one
    /// stranger's bad cell, and the service keeps serving.
    pub fn accept_introduce(
        &mut self,
        cell: &IntroduceCell,
        intro_auth_pk: &[u8; 32],
        now_unix: u64,
        now: Instant,
    ) -> Result<(), IntroduceRefusal> {
        let held = self
            .intros
            .iter()
            .find(|i| &i.intro_sk.verifying_key().to_bytes() == intro_auth_pk)
            .ok_or(IntroduceRefusal::UnknownIntroPoint)?;
        let verify_key = held.intro_sk.verifying_key().to_bytes();

        // Freshness BEFORE signature: a stale cell is cheap to reject and this
        // is a path a stranger can drive.
        if !cell.is_fresh(now_unix) {
            return Err(IntroduceRefusal::Stale);
        }
        cell.verify(&verify_key)
            .map_err(|_| IntroduceRefusal::BadSignature)?;

        // Prune before inserting so the cache cannot grow without bound under a
        // replay flood. Entries older than the validity window can never be
        // accepted again anyway - `is_fresh` would reject them first.
        let ttl = Duration::from_secs(INTRODUCE_VALIDITY_SECS);
        self.seen
            .retain(|_, seen_at| now.duration_since(*seen_at) < ttl);

        let key = cell.replay_key();
        if self.seen.contains_key(&key) {
            return Err(IntroduceRefusal::Replay);
        }
        self.seen.insert(key, now);
        Ok(())
    }

    /// Decide whether to answer a SEALED introduction - the form a client can
    /// actually produce.
    ///
    /// Supersedes [`Self::accept_introduce`], which verifies a signature against
    /// a key only this service holds and therefore accepts nobody but itself.
    /// Here the client seals to the service's X25519 key
    /// ([`crate::introduce_sealed`]), so any holder of the address can connect
    /// and the introduction point still cannot read what it forwards.
    ///
    /// Same two defences as before, both independent of how the cell is
    /// authenticated: a freshness window, and a replay cache keyed on the
    /// ciphertext.
    ///
    /// # Errors
    /// [`IntroduceRefusal::BadSignature`] when the seal does not open or names
    /// another service, [`IntroduceRefusal::Stale`] outside the window,
    /// [`IntroduceRefusal::Replay`] for a cell already seen.
    pub fn accept_sealed_introduce(
        &mut self,
        sealed: &[u8],
        service_x25519_sk: &[u8; 32],
        service_ed25519_pk: &[u8; 32],
        now_unix: u64,
        now: Instant,
    ) -> Result<crate::introduce_sealed::Introduction, IntroduceRefusal> {
        // Replay FIRST, on the ciphertext, so a flood of repeats is rejected
        // without an X25519 operation each - the cheap check guards the
        // expensive one on a path a stranger can drive.
        let key = crate::introduce_sealed::replay_key(sealed);
        let ttl = Duration::from_secs(INTRODUCE_VALIDITY_SECS);
        self.seen
            .retain(|_, seen_at| now.duration_since(*seen_at) < ttl);
        if self.seen.contains_key(&key) {
            return Err(IntroduceRefusal::Replay);
        }

        let intro =
            crate::introduce_sealed::open_introduce(sealed, service_x25519_sk, service_ed25519_pk)
                .map_err(|_| IntroduceRefusal::BadSignature)?;
        if !intro.is_fresh(now_unix) {
            return Err(IntroduceRefusal::Stale);
        }
        self.seen.insert(key, now);
        Ok(intro)
    }

    /// Number of remembered introductions, for diagnostics and tests.
    #[must_use]
    pub fn replay_cache_len(&self) -> usize {
        self.seen.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intro(seed: u8) -> HeldIntro {
        HeldIntro {
            bridge_ed25519_pk: [seed; 32],
            bridge_x25519_pk: [seed.wrapping_add(1); 32],
            intro_sk: SigningKey::from_bytes(&[seed.wrapping_add(2); 32]),
            endpoint: format!("198.51.100.{seed}:443"),
            established: false,
        }
    }

    fn signed_cell(sk: &SigningKey, issued_at: u64, cookie: u8) -> IntroduceCell {
        let mut c = IntroduceCell {
            rendezvous_bridge_pk: [1u8; 32],
            rendezvous_cookie: [cookie; 32],
            client_eph_x25519_pk: [2u8; 32],
            issued_at,
            service_ed25519_pk: [3u8; 32],
            signature: [0u8; 64],
        };
        c.sign(sk).expect("sign");
        c
    }

    #[test]
    fn a_client_with_only_the_descriptor_is_now_accepted() {
        // The counterpart to `no_client_can_produce_an_acceptable_introduce_cell`
        // below, which pins the OLD signed path's defect. This is the path that
        // works: the client seals to the service's X25519 key, which the
        // descriptor publishes, and needs nothing the service issued it.
        use mirage_crypto::x25519_dalek::{PublicKey, StaticSecret};
        let svc_x_sk = StaticSecret::from([5u8; 32]);
        let svc_x_pk = *PublicKey::from(&svc_x_sk).as_bytes();
        let svc_ed = [0xEEu8; 32];
        let mut st = ServiceState::new();

        let intro = crate::introduce_sealed::Introduction {
            rendezvous_bridge_pk: [3u8; 32],
            rendezvous_cookie: [4u8; 32],
            issued_at: 5_000,
            service_ed25519_pk: svc_ed,
        };
        let sealed =
            crate::introduce_sealed::seal_introduce(&intro, &svc_x_pk, &[77u8; 32], &[1u8; 12])
                .expect("a client can seal from public info alone");

        let got = st
            .accept_sealed_introduce(
                &sealed,
                &svc_x_sk.to_bytes(),
                &svc_ed,
                5_000,
                Instant::now(),
            )
            .expect("service accepts a stranger's introduction");
        assert_eq!(got.rendezvous_cookie, [4u8; 32]);

        // Replayed: refused, so one captured cell cannot drive unlimited
        // rendezvous circuits at the service's expense.
        assert_eq!(
            st.accept_sealed_introduce(
                &sealed,
                &svc_x_sk.to_bytes(),
                &svc_ed,
                5_000,
                Instant::now()
            ),
            Err(IntroduceRefusal::Replay)
        );

        // Stale: refused on freshness even though it is a valid seal.
        let old = crate::introduce_sealed::seal_introduce(
            &crate::introduce_sealed::Introduction {
                issued_at: 1,
                ..intro
            },
            &svc_x_pk,
            &[78u8; 32],
            &[2u8; 12],
        )
        .unwrap();
        assert_eq!(
            st.accept_sealed_introduce(&old, &svc_x_sk.to_bytes(), &svc_ed, 5_000, Instant::now()),
            Err(IntroduceRefusal::Stale)
        );
    }

    #[test]
    fn no_client_can_produce_an_acceptable_introduce_cell() {
        // DEFECT PIN, not a property anyone wants. See the crate header.
        //
        // `IntroduceCell` is authenticated by a signature that `accept_introduce`
        // verifies against `intro_auth_key`, and `intro_auth_key` is the PUBLIC
        // half of a key whose private half exists only on the service. So the
        // party the protocol asks to sign is the one party that cannot: a client
        // holds the descriptor, and a descriptor carries verifying keys.
        //
        // This test asserts the broken state deliberately, so the defect cannot
        // be quietly forgotten and cannot be quietly "fixed" without a test
        // turning red and pointing whoever did it at the header. When the
        // authentication is redesigned, this test should be REPLACED by one
        // showing a descriptor-holder succeeding - not deleted.
        let mut st = ServiceState::new();
        let held = intro(9);
        let published = held.to_descriptor_entry();
        st.add_intro(held);
        st.mark_established(&[9u8; 32]);

        // The service's own key, which a client by definition does not have.
        let service_key = SigningKey::from_bytes(&[11u8; 32]);
        assert_eq!(
            service_key.verifying_key().to_bytes(),
            published.intro_auth_key,
            "sanity: this IS the key the descriptor publishes the public half of"
        );

        // Every key a client could actually hold is refused.
        for (what, client_key) in [
            (
                "a fresh key of its own",
                SigningKey::from_bytes(&[77u8; 32]),
            ),
            (
                "a key from another service",
                SigningKey::from_bytes(&[42u8; 32]),
            ),
        ] {
            let cell = signed_cell(&client_key, 1_000, 1);
            assert_eq!(
                st.accept_introduce(&cell, &published.intro_auth_key, 1_000, Instant::now()),
                Err(IntroduceRefusal::BadSignature),
                "a client signing with {what} is refused"
            );
        }

        // The cell is accepted only when signed by the key the service kept -
        // so the only party who can introduce to this service is the service.
        let insider = signed_cell(&service_key, 1_000, 2);
        assert_eq!(
            st.accept_introduce(&insider, &published.intro_auth_key, 1_000, Instant::now()),
            Ok(()),
            "the service's own key is the only one that works, which is the defect"
        );
    }

    #[test]
    fn a_replayed_introduction_is_refused() {
        // The signature is valid forever, so without a replay cache one captured
        // cell drives unlimited rendezvous circuits at the service's expense.
        let mut st = ServiceState::new();
        let i = intro(5);
        let sk = i.intro_sk.clone();
        st.add_intro(i);
        let pk = sk.verifying_key().to_bytes();
        let cell = signed_cell(&sk, 1_000, 9);
        let now = Instant::now();

        assert_eq!(st.accept_introduce(&cell, &pk, 1_000, now), Ok(()));
        assert_eq!(
            st.accept_introduce(&cell, &pk, 1_000, now),
            Err(IntroduceRefusal::Replay),
            "the identical cell must not be answered twice"
        );
    }

    #[test]
    fn a_stale_or_forged_introduction_is_refused() {
        let mut st = ServiceState::new();
        let i = intro(6);
        let sk = i.intro_sk.clone();
        st.add_intro(i);
        let pk = sk.verifying_key().to_bytes();
        let now = Instant::now();

        // Far outside the validity window, in both directions.
        let old = signed_cell(&sk, 1_000, 1);
        assert_eq!(
            st.accept_introduce(&old, &pk, 1_000 + INTRODUCE_VALIDITY_SECS + 60, now),
            Err(IntroduceRefusal::Stale)
        );
        assert_eq!(
            st.accept_introduce(&old, &pk, 500, now),
            Err(IntroduceRefusal::Stale),
            "a cell from the future is as suspect as one from the past"
        );

        // Signed by a different key entirely.
        let other = SigningKey::from_bytes(&[99u8; 32]);
        let forged = signed_cell(&other, 1_000, 2);
        assert_eq!(
            st.accept_introduce(&forged, &pk, 1_000, now),
            Err(IntroduceRefusal::BadSignature)
        );

        // Addressed to an intro point this service does not hold.
        let stranger = SigningKey::from_bytes(&[77u8; 32])
            .verifying_key()
            .to_bytes();
        assert_eq!(
            st.accept_introduce(&old, &stranger, 1_000, now),
            Err(IntroduceRefusal::UnknownIntroPoint)
        );
    }

    #[test]
    fn the_replay_cache_cannot_grow_without_bound() {
        // A replay flood must not be a memory attack. Entries past the validity
        // window can never be accepted anyway, so they are dropped.
        let mut st = ServiceState::new();
        let i = intro(7);
        let sk = i.intro_sk.clone();
        st.add_intro(i);
        let pk = sk.verifying_key().to_bytes();
        let t0 = Instant::now();

        for n in 0..8u8 {
            let c = signed_cell(&sk, 2_000, n);
            assert_eq!(st.accept_introduce(&c, &pk, 2_000, t0), Ok(()));
        }
        assert_eq!(st.replay_cache_len(), 8);

        // Well past the window: the next acceptance prunes everything stale.
        let later = t0 + Duration::from_secs(INTRODUCE_VALIDITY_SECS + 5);
        let fresh = signed_cell(&sk, 3_000, 200);
        assert_eq!(st.accept_introduce(&fresh, &pk, 3_000, later), Ok(()));
        assert_eq!(st.replay_cache_len(), 1, "stale entries pruned");
    }

    #[test]
    fn the_descriptor_is_renewed_early_not_on_expiry() {
        // Renewing at expiry leaves a window where clients resolve nothing, and
        // a service that cannot be resolved looks blocked.
        let mut st = ServiceState::new();
        assert!(!st.needs_republish(1_000), "nothing to publish yet");

        let i = intro(8);
        st.add_intro(i);
        assert!(
            st.needs_republish(1_000),
            "holding an intro, nothing published"
        );

        let expires = 100_000u64;
        st.mark_published(expires);
        assert!(!st.needs_republish(expires - REPUBLISH_MARGIN.as_secs() - 60));
        assert!(
            st.needs_republish(expires - REPUBLISH_MARGIN.as_secs() + 1),
            "renewal must start BEFORE expiry, with room to propagate"
        );
        assert!(st.needs_republish(expires + 1));
    }

    #[test]
    fn only_established_intro_points_are_published() {
        // Publishing one the bridge never acknowledged sends every client to a
        // circuit that does not exist, and each of those failures is invisible
        // from the service's side.
        let mut st = ServiceState::new();
        st.add_intro(intro(10));
        st.add_intro(intro(20));
        st.mark_established(&[10u8; 32]);

        let svc = SigningKey::from_bytes(&[1u8; 32]);
        let d = st
            .build_descriptor(&svc, [0xC5u8; 32], 1_000, 5_000)
            .expect("descriptor");
        assert_eq!(d.intro_points.len(), 1);
        assert_eq!(d.intro_points[0].bridge_ed25519_pk, [10u8; 32]);
        assert_eq!(st.intros_wanted(), TARGET_INTRO_POINTS - 1);
    }

    #[test]
    fn losing_an_intro_point_invalidates_a_published_descriptor() {
        let mut st = ServiceState::new();
        st.add_intro(intro(11));
        st.mark_established(&[11u8; 32]);
        // Nothing published yet: dropping it is not a descriptor problem.
        assert!(!st.drop_intro(&[11u8; 32]));

        st.add_intro(intro(12));
        st.mark_established(&[12u8; 32]);
        st.mark_published(9_999);
        assert!(
            st.drop_intro(&[12u8; 32]),
            "clients are still being sent to a circuit that is gone"
        );
    }

    #[test]
    fn duplicate_and_excess_intro_points_are_ignored() {
        let mut st = ServiceState::new();
        for n in 0..(MAX_INTRO_POINTS + 4) {
            st.add_intro(intro(n));
        }
        assert_eq!(st.intros().len(), MAX_INTRO_POINTS as usize);
        let before = st.intros().len();
        st.add_intro(intro(0)); // same bridge again
        assert_eq!(st.intros().len(), before, "a bridge is held once");
    }
}
