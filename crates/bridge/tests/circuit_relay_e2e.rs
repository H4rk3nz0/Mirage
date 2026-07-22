//! End-to-end test: BridgeCircuitExecutor + SessionTask + real TCP echo.
//!
//! Validates the complete circuit return path:
//!
//! ```text
//! client (Mirage session)
//!   --- CMD_CREATE (fragmented, real Noise XX + ML-KEM-768) --> bridge
//!                                                               (SessionTask + BridgeCircuitExecutor)
//!   <-- CMD_CREATED (fragmented, real hs_msg2) ----------------
//!
//!   --- CMD_RELAY (BEGIN, onion-sealed) --------------------->
//!                                                             TCP->echo server
//!   --- CMD_RELAY (DATA "hello", onion-sealed) -------------->
//!                                                             echo replies
//!                                                             StreamEvent::Data
//!   <-- CMD_RELAY (DATA "hello", reverse-sealed) ------------
//! ```
//!
//! Proves that the full Phase 2H wiring works: real cryptographic
//! handshake, real onion-layer encryption in both directions, real
//! TCP exit, real StreamEvent->inject_exit_response return path.

use std::time::Duration;

use mirage_bridge::stream_dispatcher::{BeginBody, DataBody};
use mirage_bridge::{BridgeCircuitExecutor, BridgeCircuitKeys, SessionTask, SessionTaskConfig};
use mirage_circuit::CMD_BEGIN;
use mirage_circuit::{
    cell::Cell,
    circuit::{DIR_CLIENT_TO_HOP, DIR_HOP_TO_CLIENT},
    derive_hop_keys_from_handshake, onion_open, onion_seal, HandshakeBody, RelaySubCell,
    CMD_CREATE, CMD_CREATED, CMD_CREATED_CONT, CMD_CREATE_CONT, CMD_DATA, CMD_RELAY,
    MAX_CELL_PAYLOAD,
};
use mirage_crypto::ed25519_dalek::SigningKey;
use mirage_crypto::x25519_dalek::{PublicKey, StaticSecret};
use mirage_discovery::replay::ReplaySet;
use mirage_discovery::token::sign_token;
use mirage_runtime::cell_io::{read_cell, write_cell};
use mirage_session::{accept, connect, HandshakeInitiator};
use tokio::net::{TcpListener, TcpStream};

fn rand_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    getrandom::fill(&mut s).unwrap();
    s
}

async fn echo_server(listener: TcpListener) {
    while let Ok((mut sock, _)) = listener.accept().await {
        sock.set_nodelay(true).ok();
        tokio::spawn(async move {
            let (mut r, mut w) = sock.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
    }
}

/// Send a fragmented CMD_CREATE (hs_msg1 won't fit in one cell).
/// Returns after all fragments are written.
async fn send_create<S>(
    session: &mut mirage_session::SessionStream<S>,
    circ_id: u32,
    hs_msg1: Vec<u8>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let (first_body, cont_bodies) = HandshakeBody { hs_msg: hs_msg1 }
        .encode_fragmented(MAX_CELL_PAYLOAD)
        .expect("encode CREATE");
    write_cell(
        session,
        &Cell::new(circ_id, CMD_CREATE, first_body).unwrap(),
    )
    .await
    .unwrap();
    for cont in cont_bodies {
        write_cell(session, &Cell::new(circ_id, CMD_CREATE_CONT, cont).unwrap())
            .await
            .unwrap();
    }
}

/// Read CMD_CREATED + CMD_CREATED_CONT cells until the declared
/// total length is assembled. Returns the complete hs_msg2 bytes.
async fn recv_created<S>(session: &mut mirage_session::SessionStream<S>) -> Vec<u8>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let first = tokio::time::timeout(Duration::from_secs(5), read_cell(session))
        .await
        .expect("timeout reading CMD_CREATED")
        .expect("read_cell error");
    assert_eq!(
        first.command, CMD_CREATED,
        "expected CMD_CREATED, got {}",
        first.command
    );

    // HandshakeBody wire: [u16 BE total_len][first_chunk...]
    assert!(first.body.len() >= 2, "CMD_CREATED body too short");
    let total_len = u16::from_be_bytes([first.body[0], first.body[1]]) as usize;
    let mut hs_msg2 = first.body[2..].to_vec();

    while hs_msg2.len() < total_len {
        let cont = tokio::time::timeout(Duration::from_secs(5), read_cell(session))
            .await
            .expect("timeout reading CMD_CREATED_CONT")
            .expect("read_cell error");
        assert_eq!(
            cont.command, CMD_CREATED_CONT,
            "expected CMD_CREATED_CONT, got {}",
            cont.command
        );
        hs_msg2.extend_from_slice(&cont.body);
    }
    assert_eq!(hs_msg2.len(), total_len, "hs_msg2 length mismatch");
    hs_msg2
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn circuit_relay_exit_response_round_trip() {
    // -- 1. Echo TCP server ---------------------------------------
    let echo_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo_l.local_addr().unwrap().port();
    tokio::spawn(echo_server(echo_l));

    // -- 2. Bridge keys -------------------------------------------
    let bsk_seed = rand_seed();
    let bridge_x_sk = StaticSecret::from(bsk_seed).to_bytes();
    let bridge_x_pk = *PublicKey::from(&StaticSecret::from(bsk_seed)).as_bytes();
    let bridge_id_sk = SigningKey::from_bytes(&rand_seed());
    let bridge_ed_pk = bridge_id_sk.verifying_key().to_bytes();
    let op_sk = SigningKey::from_bytes(&rand_seed());
    let op_pk = op_sk.verifying_key().to_bytes();

    // -- 3. Bridge listener + SessionTask spawn --------------------
    let bridge_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_addr = bridge_l.local_addr().unwrap();
    let bridge_x_sk_c = bridge_x_sk;
    let bridge_ed_pk_c = bridge_ed_pk;
    let op_pk_c = op_pk;
    let now_unix = 1_700_000_000u64;

    tokio::spawn(async move {
        let (sock, _) = bridge_l.accept().await.unwrap();
        sock.set_nodelay(true).ok();
        let mut rs = ReplaySet::new(64);
        let mut v = mirage_session::TokenVerifier::new(&mut rs, now_unix);
        let session = accept(sock, &bridge_x_sk_c, &bridge_ed_pk_c, &op_pk_c, &mut v)
            .await
            .unwrap();
        let (executor, exit_events_rx) = BridgeCircuitExecutor::new(
            BridgeCircuitKeys {
                bridge_x25519_sk: bridge_x_sk_c,
                bridge_ed25519_pk: bridge_ed_pk_c,
                operator_ed25519_pk: op_pk_c,
            },
            true, // allow private (loopback echo server)
            true, // allow loopback (loopback echo server)
        );
        SessionTask::new(
            session,
            std::sync::Arc::new(executor),
            SessionTaskConfig {
                cell_read_timeout: Some(Duration::from_secs(5)),
                ..Default::default()
            },
        )
        .with_exit_events(exit_events_rx)
        .run()
        .await
        .ok();
    });

    // -- 4. Client: establish Mirage session -----------------------
    let client_x_seed = rand_seed();
    let client_x_sk = StaticSecret::from(client_x_seed).to_bytes();
    let token = sign_token([0xCC; 32], bridge_ed_pk, now_unix + 3600, &op_sk);
    let sock = TcpStream::connect(bridge_addr).await.unwrap();
    sock.set_nodelay(true).ok();
    let mut session = connect(sock, &client_x_sk, &bridge_x_pk, &token)
        .await
        .unwrap();

    // -- 5. Circuit CREATE handshake -------------------------------
    // Client uses a fresh X25519 ephemeral for the circuit-level
    // Noise XX handshake (separate from the transport session keys).
    let circ_x_seed = rand_seed();
    let circ_x_sk = StaticSecret::from(circ_x_seed).to_bytes();
    let circ_id: u32 = 1;

    let mut initiator =
        HandshakeInitiator::_danger_new_without_token(&circ_x_sk, &bridge_x_pk).expect("initiator");
    let msg1 = initiator.write_message_1().expect("write_message_1");

    send_create(&mut session, circ_id, msg1).await;
    let msg2 = recv_created(&mut session).await;

    initiator.read_message_2(&msg2).expect("read_message_2");
    let (mlkem_ss, circuit_binding) = initiator
        .circuit_hop_binding()
        .expect("circuit_hop_binding");
    let hop_keys = derive_hop_keys_from_handshake(&mlkem_ss, &circuit_binding);

    // -- 6. CMD_RELAY BEGIN ----------------------------------------
    let stream_id: u16 = 7;
    let begin_body = BeginBody {
        stream_id,
        host: "127.0.0.1".to_string(),
        port: echo_port,
    }
    .encode()
    .unwrap();
    let begin_sub = RelaySubCell {
        command: CMD_BEGIN,
        body: begin_body,
    }
    .encode()
    .unwrap();
    let begin_sealed = onion_seal(
        &[hop_keys.forward.clone()],
        &begin_sub,
        DIR_CLIENT_TO_HOP,
        0,
        0,
    )
    .expect("seal BEGIN");
    write_cell(
        &mut session,
        &Cell::new(circ_id, CMD_RELAY, begin_sealed).unwrap(),
    )
    .await
    .unwrap();

    // -- 7. CMD_RELAY DATA -----------------------------------------
    let payload = b"mirage-circuit-relay-round-trip";
    let data_body = DataBody {
        stream_id,
        bytes: payload.to_vec(),
    }
    .encode();
    let data_sub = RelaySubCell {
        command: CMD_DATA,
        body: data_body,
    }
    .encode()
    .unwrap();
    let data_sealed = onion_seal(
        &[hop_keys.forward.clone()],
        &data_sub,
        DIR_CLIENT_TO_HOP,
        0,
        1,
    )
    .expect("seal DATA");
    write_cell(
        &mut session,
        &Cell::new(circ_id, CMD_RELAY, data_sealed).unwrap(),
    )
    .await
    .unwrap();

    // -- 8. Read echoed CMD_RELAY DATA back ------------------------
    // The bridge peels BEGIN/DATA, dispatches to echo TCP, then gets
    // StreamEvent::Data, calls inject_exit_response (which seals with
    // the reverse key), and writes CMD_RELAY back. We may receive
    // the data across multiple CMD_RELAY cells (each carries one
    // StreamEvent::Data emission from the dispatcher), so collect
    // until we have all bytes.
    let mut got: Vec<u8> = Vec::new();
    let mut reverse_seq: u64 = 0;
    while got.len() < payload.len() {
        let cell = tokio::time::timeout(Duration::from_secs(5), read_cell(&mut session))
            .await
            .expect("timeout reading echoed CMD_RELAY")
            .expect("read_cell error");
        assert_eq!(
            cell.command, CMD_RELAY,
            "expected CMD_RELAY back, got {}",
            cell.command
        );

        let plaintext = onion_open(
            &[hop_keys.reverse.clone()],
            &cell.body,
            DIR_HOP_TO_CLIENT,
            0,
            reverse_seq,
        )
        .expect("onion_open failed on reverse relay");
        reverse_seq += 1;

        let sub = RelaySubCell::decode(&plaintext).expect("decode reverse RelaySubCell");
        if sub.command == CMD_DATA {
            let d = DataBody::decode(&sub.body).expect("decode DataBody");
            assert_eq!(d.stream_id, stream_id, "stream_id mismatch in echoed DATA");
            got.extend_from_slice(&d.bytes);
        }
        // Ignore non-DATA sub-cells (e.g., bridge-side control messages).
    }
    assert_eq!(
        got,
        payload,
        "echoed payload mismatch: got {} bytes, expected {}",
        got.len(),
        payload.len()
    );

    eprintln!(
        "[ok] circuit relay round-trip: {} bytes flowed through Noise XX + ML-KEM-768 circuit \
         handshake, onion encryption, TCP exit, and reverse return path",
        payload.len()
    );
}
