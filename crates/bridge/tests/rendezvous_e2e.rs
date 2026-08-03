//! End-to-end test: two Mirage sessions meet through one bridge.
//!
//! This is the hidden-service rendezvous plane driven the way a real service and
//! a real client drive it, over real sessions, real circuit handshakes and real
//! onion encryption:
//!
//! ```text
//! service session                bridge                 client session
//!   -- ESTABLISH_INTRO --------->  register
//!   <-- ESTABLISH_INTRO_OK ------  (reverse-sealed)
//!                                  park cookie  <------- ESTABLISH_RENDEZVOUS --
//!                                  (reverse-sealed) ---> RENDEZVOUS_OK ---------
//!                                  forward       <------ INTRODUCE -------------
//!   <-- INTRODUCE ---------------  (reverse-sealed)
//!   -- RENDEZVOUS (cookie) ----->  match + JOIN
//!                                  (reverse-sealed) ---> RENDEZVOUS (eph pk) ---
//!   -- DATA ------------------->   relay to partner ---> DATA ----------------->
//!   <-- DATA -------------------   relay to partner <--- DATA ------------------
//! ```
//!
//! Two properties are under test, and both were broken:
//!
//! 1. **Every reverse rendezvous cell is onion-sealed.** They used to be written
//!    to the wire in the clear, which no conforming peer can read - a peer opens
//!    every reverse `CMD_RELAY` with the circuit's reverse key. The test opens
//!    them exactly as a peer does, so an unsealed cell fails it.
//! 2. **A joined pair actually carries data.** `relay_to_partner` existed and was
//!    called from nothing, so two circuits could complete a rendezvous and then
//!    sit inert. The DATA exchange at the end is what a hidden service is for.
//!
//! The introduction point and the rendezvous point are the same bridge here.
//! That is a legitimate deployment (and the one a two-container test can stand
//! up); the routing table is keyed by `CircuitRef`, which spans sessions, so
//! nothing about the path depends on them being distinct.

use std::sync::Arc;
use std::time::Duration;

use mirage_bridge::rendezvous_router::RendezvousRouter;
use mirage_bridge::{BridgeCircuitExecutor, BridgeCircuitKeys, SessionTask, SessionTaskConfig};
use mirage_circuit::rendezvous::{EstablishIntroBody, RendezvousBody, COOKIE_LEN};
use mirage_circuit::{
    cell::Cell,
    circuit::{DIR_CLIENT_TO_HOP, DIR_HOP_TO_CLIENT},
    derive_hop_keys_from_handshake, onion_open, onion_seal, HandshakeBody, HopKeys, RelaySubCell,
    CMD_CREATE, CMD_CREATED, CMD_CREATED_CONT, CMD_CREATE_CONT, CMD_DATA, CMD_ESTABLISH_INTRO,
    CMD_ESTABLISH_INTRO_OK, CMD_ESTABLISH_RENDEZVOUS, CMD_INTRODUCE, CMD_RELAY, CMD_RENDEZVOUS,
    CMD_RENDEZVOUS_OK, MAX_CELL_PAYLOAD,
};
use mirage_crypto::ed25519_dalek::SigningKey;
use mirage_crypto::x25519_dalek::{PublicKey, StaticSecret};
use mirage_discovery::replay::ReplaySet;
use mirage_discovery::token::sign_token;
use mirage_runtime::cell_io::{read_cell, write_cell};
use mirage_session::{accept, connect, HandshakeInitiator};
use tokio::net::{TcpListener, TcpStream};

const NOW_UNIX: u64 = 1_700_000_000;

fn rand_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    getrandom::fill(&mut s).unwrap();
    s
}

/// One end of a circuit, with the sequence counters a peer has to keep.
struct Peer<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    session: mirage_session::SessionStream<S>,
    keys: HopKeys,
    circ_id: u32,
    fwd_seq: u64,
    rev_seq: u64,
}

impl<S> Peer<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    /// Run the circuit CREATE handshake and return a ready peer.
    async fn open(
        mut session: mirage_session::SessionStream<S>,
        bridge_x_pk: &[u8; 32],
        circ_id: u32,
    ) -> Self {
        let circ_x_sk = StaticSecret::from(rand_seed()).to_bytes();
        let mut initiator = HandshakeInitiator::_danger_new_without_token(&circ_x_sk, bridge_x_pk)
            .expect("circuit initiator");
        let msg1 = initiator.write_message_1().expect("msg1");

        let (first, conts) = HandshakeBody { hs_msg: msg1 }
            .encode_fragmented(MAX_CELL_PAYLOAD)
            .expect("encode CREATE");
        write_cell(
            &mut session,
            &Cell::new(circ_id, CMD_CREATE, first).unwrap(),
        )
        .await
        .unwrap();
        for c in conts {
            write_cell(
                &mut session,
                &Cell::new(circ_id, CMD_CREATE_CONT, c).unwrap(),
            )
            .await
            .unwrap();
        }

        let first = read_one(&mut session).await;
        assert_eq!(first.command, CMD_CREATED, "expected CMD_CREATED");
        let total = u16::from_be_bytes([first.body[0], first.body[1]]) as usize;
        let mut msg2 = first.body[2..].to_vec();
        while msg2.len() < total {
            let cont = read_one(&mut session).await;
            assert_eq!(cont.command, CMD_CREATED_CONT);
            msg2.extend_from_slice(&cont.body);
        }

        initiator.read_message_2(&msg2).expect("msg2");
        let (ss, binding) = initiator.circuit_hop_binding().expect("hop binding");
        Self {
            session,
            keys: derive_hop_keys_from_handshake(&ss, &binding),
            circ_id,
            fwd_seq: 0,
            rev_seq: 0,
        }
    }

    /// Onion-seal one sub-cell and write it, exactly as a client does.
    async fn send(&mut self, command: u8, body: Vec<u8>) {
        let sub = RelaySubCell { command, body }.encode().expect("encode sub");
        let sealed = onion_seal(
            &[self.keys.forward.clone()],
            &sub,
            DIR_CLIENT_TO_HOP,
            0,
            self.fwd_seq,
        )
        .expect("seal");
        self.fwd_seq += 1;
        write_cell(
            &mut self.session,
            &Cell::new(self.circ_id, CMD_RELAY, sealed).unwrap(),
        )
        .await
        .unwrap();
    }

    /// Read the next reverse cell and open it with the circuit's reverse key.
    ///
    /// This is the assertion that matters for property 1: a cell the bridge
    /// wrote unsealed does not open here, and the test fails on it.
    async fn recv(&mut self) -> RelaySubCell {
        let cell = read_one(&mut self.session).await;
        assert_eq!(cell.command, CMD_RELAY, "expected a reverse CMD_RELAY");
        let plain = onion_open(
            &[self.keys.reverse.clone()],
            &cell.body,
            DIR_HOP_TO_CLIENT,
            0,
            self.rev_seq,
        )
        .expect("reverse cell did not open - was it written unsealed?");
        self.rev_seq += 1;
        RelaySubCell::decode(&plain).expect("decode reverse sub-cell")
    }
}

async fn read_one<S>(session: &mut mirage_session::SessionStream<S>) -> Cell
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    tokio::time::timeout(Duration::from_secs(10), read_cell(session))
        .await
        .expect("timeout reading cell")
        .expect("read_cell error")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_service_and_a_client_meet_and_exchange_data_through_a_rendezvous_point() {
    // -- Bridge identity ------------------------------------------------
    let bsk_seed = rand_seed();
    let bridge_x_sk = StaticSecret::from(bsk_seed).to_bytes();
    let bridge_x_pk = *PublicKey::from(&StaticSecret::from(bsk_seed)).as_bytes();
    let bridge_ed_pk = SigningKey::from_bytes(&rand_seed())
        .verifying_key()
        .to_bytes();
    let op_sk = SigningKey::from_bytes(&rand_seed());
    let op_pk = op_sk.verifying_key().to_bytes();

    // ONE router shared by every session on this bridge. That sharing is the
    // whole point: the service registers on one session and the client
    // introduces on another, and nothing else spans the two.
    let router: Arc<RendezvousRouter> = Arc::new(RendezvousRouter::new());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_addr = listener.local_addr().unwrap();
    {
        let router = Arc::clone(&router);
        tokio::spawn(async move {
            // Three sessions: the service's introduction session, the client's,
            // and the service's separate session for the rendezvous leg (a real
            // service meets at a DIFFERENT bridge, so it is a different session).
            loop {
                let (sock, _) = listener.accept().await.unwrap();
                sock.set_nodelay(true).ok();
                let router = Arc::clone(&router);
                tokio::spawn(async move {
                    let mut rs = ReplaySet::new(64);
                    let mut v = mirage_session::TokenVerifier::new(&mut rs, NOW_UNIX);
                    let session = accept(sock, &bridge_x_sk, &bridge_ed_pk, &op_pk, &mut v)
                        .await
                        .unwrap();
                    let (executor, exit_rx) = BridgeCircuitExecutor::new(
                        BridgeCircuitKeys {
                            bridge_x25519_sk: bridge_x_sk,
                            bridge_ed25519_pk: bridge_ed_pk,
                            operator_ed25519_pk: op_pk,
                        },
                        false,
                        false,
                    );
                    SessionTask::new(
                        session,
                        Arc::new(executor),
                        SessionTaskConfig {
                            cell_read_timeout: Some(Duration::from_secs(20)),
                            ..Default::default()
                        },
                    )
                    .with_exit_events(exit_rx)
                    .with_rendezvous(router)
                    .run()
                    .await
                    .ok();
                });
            }
        });
    }

    let dial = || async {
        let client_x_sk = StaticSecret::from(rand_seed()).to_bytes();
        let token = sign_token([0xCC; 32], bridge_ed_pk, NOW_UNIX + 3600, &op_sk);
        let sock = TcpStream::connect(bridge_addr).await.unwrap();
        sock.set_nodelay(true).ok();
        connect(sock, &client_x_sk, &bridge_x_pk, &token)
            .await
            .unwrap()
    };

    // -- 1. Service registers an introduction point ----------------------
    // The service holds a per-introduction signing key; its public half is what
    // a client names in INTRODUCE, and it is published in the descriptor.
    let intro_sk = SigningKey::from_bytes(&rand_seed());
    let intro_pk = intro_sk.verifying_key().to_bytes();

    let mut svc_intro = Peer::open(dial().await, &bridge_x_pk, 11).await;
    svc_intro
        .send(
            CMD_ESTABLISH_INTRO,
            EstablishIntroBody::new(&intro_sk, svc_intro.circ_id).encode(),
        )
        .await;
    let ack = svc_intro.recv().await;
    assert_eq!(
        ack.command, CMD_ESTABLISH_INTRO_OK,
        "the bridge must acknowledge the registration"
    );

    // -- 2. Client parks a cookie at the rendezvous point ----------------
    let cookie: [u8; COOKIE_LEN] = rand_seed();
    let mut cli = Peer::open(dial().await, &bridge_x_pk, 22).await;
    cli.send(CMD_ESTABLISH_RENDEZVOUS, cookie.to_vec()).await;
    let ack = cli.recv().await;
    assert_eq!(
        ack.command, CMD_RENDEZVOUS_OK,
        "the bridge must acknowledge the parked cookie"
    );

    // -- 3. Client introduces ---------------------------------------------
    // Body is `intro_auth_pk || opaque`. Everything past the key is forwarded
    // verbatim - an introduction point is not entitled to read it - so the test
    // uses a stand-in payload and checks it arrives byte-identical.
    let opaque = b"sealed-introduce-cell-the-bridge-cannot-read".to_vec();
    let mut introduce = intro_pk.to_vec();
    introduce.extend_from_slice(&opaque);
    cli.send(CMD_INTRODUCE, introduce).await;

    let fwd = svc_intro.recv().await;
    assert_eq!(fwd.command, CMD_INTRODUCE, "service must receive INTRODUCE");
    assert_eq!(
        fwd.body, opaque,
        "the introduction point must forward the body verbatim, key stripped"
    );

    // -- 4. Service meets the client at the rendezvous point --------------
    // A SECOND circuit: the introduction circuit keeps its registration role, and
    // a circuit may hold only one role.
    let service_eph = *PublicKey::from(&StaticSecret::from(rand_seed())).as_bytes();
    let mut svc_rv = Peer::open(dial().await, &bridge_x_pk, 33).await;
    svc_rv
        .send(
            CMD_RENDEZVOUS,
            RendezvousBody {
                cookie,
                service_eph_x25519_pk: service_eph,
            }
            .encode(),
        )
        .await;

    let joined = cli.recv().await;
    assert_eq!(
        joined.command, CMD_RENDEZVOUS,
        "the client learns of the join on its own circuit"
    );
    assert_eq!(
        joined.body, service_eph,
        "the service's ephemeral key must reach the client so they can key \
         end-to-end past the rendezvous point"
    );

    // -- 5. The joined pair carries traffic -------------------------------
    // The property `relay_to_partner` existed for and nothing exercised.
    let c2s = b"client-to-service-over-the-rendezvous".to_vec();
    cli.send(CMD_DATA, c2s.clone()).await;
    let got = svc_rv.recv().await;
    assert_eq!(got.command, CMD_DATA);
    assert_eq!(
        got.body, c2s,
        "client -> service payload must arrive intact"
    );

    let s2c = b"service-to-client-over-the-rendezvous".to_vec();
    svc_rv.send(CMD_DATA, s2c.clone()).await;
    let got = cli.recv().await;
    assert_eq!(got.command, CMD_DATA);
    assert_eq!(
        got.body, s2c,
        "service -> client payload must arrive intact"
    );

    eprintln!(
        "[ok] rendezvous: two sessions registered, introduced, joined on a cookie \
         and exchanged {} + {} bytes end-to-end through the meeting point",
        c2s.len(),
        s2c.len()
    );
}
