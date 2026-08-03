//! Cross-session cell routing for hidden services.
//!
//! This is the piece `mirage-onion` named as its blocker. The rendezvous state
//! machine in [`mirage_circuit::rendezvous`] decides *what* should happen - who
//! may register an introduction point, when a cookie matches, when two circuits
//! join. It cannot move a cell, because the two circuits involved live in
//! **different session tasks**: a service registers its introduction point on
//! its own session, and a client introduces on another one entirely.
//!
//! Every session task owns its circuits privately, which is correct for
//! everything else the bridge does and fatal here. This router is the one place
//! that spans them: sessions register a delivery channel when they start, and
//! the router hands a cell from one session to another by looking up the
//! owner's channel.
//!
//! # What it deliberately does not do
//!
//! It does not inspect payloads. An introduction point forwards an INTRODUCE
//! body verbatim because it is not entitled to read it, and a rendezvous point
//! relays between two joined circuits without knowing what either is carrying.
//! The router's whole job is addressing.
//!
//! # Locking
//!
//! The table is a plain `std::sync::Mutex` and the lock is never held across an
//! `await`. Delivery uses `try_send` on a bounded channel: a session that has
//! stopped draining must not be able to stall the router for every other
//! session, and a rendezvous peer that cannot keep up is a dead peer, not a
//! reason to block.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use mirage_circuit::rendezvous::{CircuitRef, RendezvousAction, RendezvousError, RendezvousState};
use tokio::sync::mpsc::{error::TrySendError, Sender};

/// How many cells may be queued toward one session before delivery fails.
///
/// Small on purpose. This carries rendezvous control cells and relayed traffic
/// for joined circuits; a peer that is more than this far behind is not going to
/// catch up, and buffering for it would cost memory the bridge owes to every
/// other session.
pub const DELIVERY_QUEUE: usize = 64;

/// One cell addressed to a circuit within some session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    /// Circuit within the destination session.
    pub circ_id: u32,
    /// Cell command.
    pub cmd: u8,
    /// Cell body, forwarded verbatim.
    pub body: Vec<u8>,
}

/// Why a delivery could not be made.
#[derive(Debug, PartialEq, Eq)]
pub enum RouteError {
    /// The destination session is gone.
    NoSuchSession,
    /// The destination is not draining its queue.
    Backlogged,
    /// The rendezvous state machine refused the request.
    Rendezvous(RendezvousError),
}

impl From<RendezvousError> for RouteError {
    fn from(e: RendezvousError) -> Self {
        Self::Rendezvous(e)
    }
}

/// Bridge-wide rendezvous routing table.
#[derive(Default)]
pub struct RendezvousRouter {
    inner: Mutex<Inner>,
    next_session: AtomicU64,
}

#[derive(Default)]
struct Inner {
    state: RendezvousState,
    sessions: HashMap<u64, Sender<Delivery>>,
}

impl RendezvousRouter {
    /// An empty router.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a session and get its bridge-unique handle.
    ///
    /// The handle is what makes [`CircuitRef`] unique: circuit ids are allocated
    /// per session, so two unrelated clients routinely both hold a circuit 1.
    pub fn register_session(&self, tx: Sender<Delivery>) -> u64 {
        let h = self.next_session.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut g) = self.inner.lock() {
            g.sessions.insert(h, tx);
        }
        h
    }

    /// Forget a session and every rendezvous role its circuits held.
    ///
    /// Returns the partner circuits of any joined pairs, so the runtime can tear
    /// down the other half: a joined pair that loses one side is a meeting
    /// nobody can use, and leaving it up keeps a circuit alive as a distinctive
    /// long-lived idle flow.
    pub fn forget_session(&self, handle: u64, circ_ids: &[u32]) -> Vec<CircuitRef> {
        let mut orphans = Vec::new();
        if let Ok(mut g) = self.inner.lock() {
            g.sessions.remove(&handle);
            for &c in circ_ids {
                if let Some(p) = g.state.forget(CircuitRef::new(handle, c)) {
                    orphans.push(p);
                }
            }
        }
        orphans
    }

    /// Number of registered sessions.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.inner.lock().map(|g| g.sessions.len()).unwrap_or(0)
    }

    /// The circuit a joined circuit is paired with.
    #[must_use]
    pub fn partner(&self, circ: CircuitRef) -> Option<CircuitRef> {
        self.inner.lock().ok().and_then(|g| g.state.partner(circ))
    }

    /// Handle `ESTABLISH_INTRO` from a service.
    ///
    /// # Errors
    /// Propagates the state machine's refusal (bad signature, key already
    /// registered elsewhere, circuit already holding a role, table full).
    pub fn establish_intro(
        &self,
        circ: CircuitRef,
        body: &[u8],
        now: Instant,
    ) -> Result<RendezvousAction, RouteError> {
        let mut g = self.inner.lock().map_err(|_| RouteError::NoSuchSession)?;
        Ok(g.state.establish_intro(circ, body, now)?)
    }

    /// Handle `ESTABLISH_RENDEZVOUS` from a client.
    ///
    /// # Errors
    /// Propagates the state machine's refusal.
    pub fn establish_rendezvous(
        &self,
        circ: CircuitRef,
        cookie: &[u8],
        now: Instant,
    ) -> Result<RendezvousAction, RouteError> {
        let mut g = self.inner.lock().map_err(|_| RouteError::NoSuchSession)?;
        Ok(g.state.establish_rendezvous(circ, cookie, now)?)
    }

    /// Handle `INTRODUCE`: look up the service's circuit and hand it the body.
    ///
    /// This is the cross-session hop that could not exist before - the client's
    /// session and the service's session are different tasks.
    ///
    /// # Errors
    /// [`RouteError::NoSuchSession`] if the service's session has gone,
    /// [`RouteError::Backlogged`] if it is not draining, or the state machine's
    /// refusal when no introduction point is registered for the key.
    pub fn introduce(
        &self,
        intro_auth_pk: &[u8; 32],
        body: &[u8],
        now: Instant,
    ) -> Result<CircuitRef, RouteError> {
        // Decide and deliver under ONE lock acquisition, so a session cannot be
        // torn down between the lookup and the send and leave the caller
        // believing it delivered.
        let mut g = self.inner.lock().map_err(|_| RouteError::NoSuchSession)?;
        let action = g.state.introduce(intro_auth_pk, body, now)?;
        let RendezvousAction::ForwardIntroduce { to_circ, body } = action else {
            return Err(RouteError::NoSuchSession);
        };
        let tx = g
            .sessions
            .get(&to_circ.session)
            .ok_or(RouteError::NoSuchSession)?;
        tx.try_send(Delivery {
            circ_id: to_circ.circ_id,
            cmd: mirage_circuit::CMD_INTRODUCE,
            body,
        })
        .map_err(|e| match e {
            TrySendError::Full(_) => RouteError::Backlogged,
            TrySendError::Closed(_) => RouteError::NoSuchSession,
        })?;
        Ok(to_circ)
    }

    /// Handle `RENDEZVOUS` from a service: match the cookie and join.
    ///
    /// On a match the client is told its meeting happened, carrying the
    /// service's ephemeral key so the two can finish a handshake the rendezvous
    /// point cannot read.
    ///
    /// # Errors
    /// As [`Self::introduce`], plus the state machine's refusal on an unmatched
    /// or expired cookie.
    pub fn rendezvous(
        &self,
        service_circ: CircuitRef,
        body: &[u8],
        now: Instant,
    ) -> Result<CircuitRef, RouteError> {
        let mut g = self.inner.lock().map_err(|_| RouteError::NoSuchSession)?;
        let action = g.state.rendezvous(service_circ, body, now)?;
        let RendezvousAction::Join {
            client_circ,
            service_eph_x25519_pk,
            ..
        } = action
        else {
            return Err(RouteError::NoSuchSession);
        };
        let tx = g
            .sessions
            .get(&client_circ.session)
            .ok_or(RouteError::NoSuchSession)?;
        tx.try_send(Delivery {
            circ_id: client_circ.circ_id,
            cmd: mirage_circuit::CMD_RENDEZVOUS,
            body: service_eph_x25519_pk.to_vec(),
        })
        .map_err(|e| match e {
            TrySendError::Full(_) => RouteError::Backlogged,
            TrySendError::Closed(_) => RouteError::NoSuchSession,
        })?;
        Ok(client_circ)
    }

    /// Relay a cell from one half of a joined pair to the other.
    ///
    /// # Errors
    /// [`RouteError::NoSuchSession`] when the circuit is not joined or its
    /// partner's session has gone; [`RouteError::Backlogged`] when the partner
    /// is not draining.
    pub fn relay_to_partner(
        &self,
        from: CircuitRef,
        cmd: u8,
        body: Vec<u8>,
    ) -> Result<CircuitRef, RouteError> {
        let g = self.inner.lock().map_err(|_| RouteError::NoSuchSession)?;
        let partner = g.state.partner(from).ok_or(RouteError::NoSuchSession)?;
        let tx = g
            .sessions
            .get(&partner.session)
            .ok_or(RouteError::NoSuchSession)?;
        tx.try_send(Delivery {
            circ_id: partner.circ_id,
            cmd,
            body,
        })
        .map_err(|e| match e {
            TrySendError::Full(_) => RouteError::Backlogged,
            TrySendError::Closed(_) => RouteError::NoSuchSession,
        })?;
        Ok(partner)
    }

    /// Sweep expired registrations and cookies.
    pub fn tick(&self, now: Instant) -> Vec<RendezvousAction> {
        self.inner
            .lock()
            .map(|mut g| g.state.tick(now))
            .unwrap_or_default()
    }
}

/// Shared handle for the bridge runtime.
pub type SharedRendezvousRouter = Arc<RendezvousRouter>;

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_circuit::rendezvous::{EstablishIntroBody, RendezvousBody, COOKIE_LEN};
    use mirage_crypto::ed25519_dalek::SigningKey;

    fn chan() -> (Sender<Delivery>, tokio::sync::mpsc::Receiver<Delivery>) {
        tokio::sync::mpsc::channel(DELIVERY_QUEUE)
    }

    #[tokio::test]
    async fn an_introduce_crosses_from_one_session_to_another() {
        // The whole reason this module exists: the service registered on ITS
        // session and the client introduces on a different one, so no session
        // task can deliver this on its own.
        let r = RendezvousRouter::new();
        let (svc_tx, mut svc_rx) = chan();
        let (cli_tx, _cli_rx) = chan();
        let svc = r.register_session(svc_tx);
        let cli = r.register_session(cli_tx);
        assert_ne!(svc, cli, "sessions get distinct handles");
        let t = Instant::now();

        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let svc_circ = CircuitRef::new(svc, 1);
        r.establish_intro(svc_circ, &EstablishIntroBody::new(&sk, 1).encode(), t)
            .expect("register");

        // The client's circuit id is ALSO 1 - the collision that a bare circ_id
        // table would have mishandled.
        let pk = sk.verifying_key().to_bytes();
        let to = r
            .introduce(&pk, b"opaque introduce body", t)
            .expect("forwarded");
        assert_eq!(to, svc_circ);

        let got = svc_rx.try_recv().expect("service received it");
        assert_eq!(got.circ_id, 1);
        assert_eq!(got.cmd, mirage_circuit::CMD_INTRODUCE);
        assert_eq!(got.body, b"opaque introduce body".to_vec());
    }

    #[tokio::test]
    async fn a_cookie_join_notifies_the_waiting_client() {
        let r = RendezvousRouter::new();
        let (cli_tx, mut cli_rx) = chan();
        let (svc_tx, _svc_rx) = chan();
        let cli = r.register_session(cli_tx);
        let svc = r.register_session(svc_tx);
        let t = Instant::now();
        let cookie = [3u8; COOKIE_LEN];

        r.establish_rendezvous(CircuitRef::new(cli, 9), &cookie, t)
            .expect("park");
        let body = RendezvousBody {
            cookie,
            service_eph_x25519_pk: [42u8; 32],
        }
        .encode();
        let client_circ = r
            .rendezvous(CircuitRef::new(svc, 4), &body, t)
            .expect("join");
        assert_eq!(client_circ, CircuitRef::new(cli, 9));

        let got = cli_rx.try_recv().expect("client told about the meeting");
        assert_eq!(got.cmd, mirage_circuit::CMD_RENDEZVOUS);
        assert_eq!(got.body, [42u8; 32].to_vec(), "service key handed over");
    }

    #[tokio::test]
    async fn joined_circuits_relay_both_ways() {
        let r = RendezvousRouter::new();
        let (cli_tx, mut cli_rx) = chan();
        let (svc_tx, mut svc_rx) = chan();
        let cli = r.register_session(cli_tx);
        let svc = r.register_session(svc_tx);
        let t = Instant::now();
        let cookie = [5u8; COOKIE_LEN];
        let client_circ = CircuitRef::new(cli, 2);
        let service_circ = CircuitRef::new(svc, 2);

        r.establish_rendezvous(client_circ, &cookie, t)
            .expect("park");
        r.rendezvous(
            service_circ,
            &RendezvousBody {
                cookie,
                service_eph_x25519_pk: [0u8; 32],
            }
            .encode(),
            t,
        )
        .expect("join");
        let _ = cli_rx.try_recv(); // the join notification

        r.relay_to_partner(client_circ, mirage_circuit::CMD_RELAY, b"c2s".to_vec())
            .expect("client -> service");
        assert_eq!(svc_rx.try_recv().expect("service got it").body, b"c2s");

        r.relay_to_partner(service_circ, mirage_circuit::CMD_RELAY, b"s2c".to_vec())
            .expect("service -> client");
        assert_eq!(cli_rx.try_recv().expect("client got it").body, b"s2c");
    }

    #[tokio::test]
    async fn dropping_a_session_reports_orphaned_partners() {
        let r = RendezvousRouter::new();
        let (cli_tx, _cli_rx) = chan();
        let (svc_tx, _svc_rx) = chan();
        let cli = r.register_session(cli_tx);
        let svc = r.register_session(svc_tx);
        let t = Instant::now();
        let cookie = [8u8; COOKIE_LEN];
        r.establish_rendezvous(CircuitRef::new(cli, 1), &cookie, t)
            .expect("park");
        r.rendezvous(
            CircuitRef::new(svc, 1),
            &RendezvousBody {
                cookie,
                service_eph_x25519_pk: [0u8; 32],
            }
            .encode(),
            t,
        )
        .expect("join");

        let orphans = r.forget_session(cli, &[1]);
        assert_eq!(orphans, vec![CircuitRef::new(svc, 1)]);
        assert_eq!(r.session_count(), 1);
        // And the survivor is no longer joined to a corpse.
        assert_eq!(r.partner(CircuitRef::new(svc, 1)), None);
    }

    #[tokio::test]
    async fn a_backlogged_peer_fails_instead_of_stalling_the_router() {
        // A rendezvous peer that stopped draining must not be able to block
        // every other session behind it.
        let r = RendezvousRouter::new();
        let (svc_tx, svc_rx) = tokio::sync::mpsc::channel(1);
        let (cli_tx, _cli_rx) = chan();
        let svc = r.register_session(svc_tx);
        let _cli = r.register_session(cli_tx);
        let t = Instant::now();
        let sk = SigningKey::from_bytes(&[11u8; 32]);
        r.establish_intro(
            CircuitRef::new(svc, 1),
            &EstablishIntroBody::new(&sk, 1).encode(),
            t,
        )
        .expect("register");
        let pk = sk.verifying_key().to_bytes();

        r.introduce(&pk, b"first", t).expect("fits");
        assert_eq!(
            r.introduce(&pk, b"second", t),
            Err(RouteError::Backlogged),
            "a full queue is a dead peer, not a reason to block"
        );
        drop(svc_rx);
        assert_eq!(
            r.introduce(&pk, b"third", t),
            Err(RouteError::NoSuchSession)
        );
    }

    #[tokio::test]
    async fn a_vanished_service_session_is_not_a_panic() {
        let r = RendezvousRouter::new();
        let (svc_tx, svc_rx) = chan();
        let svc = r.register_session(svc_tx);
        let t = Instant::now();
        let sk = SigningKey::from_bytes(&[13u8; 32]);
        r.establish_intro(
            CircuitRef::new(svc, 1),
            &EstablishIntroBody::new(&sk, 1).encode(),
            t,
        )
        .expect("register");
        drop(svc_rx);
        r.forget_session(svc, &[1]);
        let pk = sk.verifying_key().to_bytes();
        assert!(matches!(
            r.introduce(&pk, b"x", t),
            Err(RouteError::Rendezvous(_)) | Err(RouteError::NoSuchSession)
        ));
    }
}
