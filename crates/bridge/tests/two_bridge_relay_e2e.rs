//! End-to-end **two-bridge multi-hop** relay: the definitive "works for
//! deployments" proof. A client builds a real 2-hop onion circuit through two
//! independent bridge daemons and round-trips application data end-to-end.
//!
//! ```text
//! client --Mirage session (entry_client_token)--> ENTRY bridge
//!    |  CMD_CREATE / CREATED  (hop-0 circuit handshake, no per-hop token)
//!    |  CMD_EXTEND(exit) -------------------------> ENTRY dials EXIT:
//!    |                                               SessionNextHopDialer
//!    |                                               (entry_relay_token) opens
//!    |                                               a RELAY LEG to EXIT, relays
//!    |                                               CMD_CREATE, returns CREATED
//!    |  <---------------------------- CMD_EXTENDED (hop-1 hs_msg2)
//!    |  CMD_EXTEND_FINISH(msg3+exit_client_token) -> ENTRY forwards -> EXIT
//!    |                                               verify_extend_finish OK
//!    |  CMD_RELAY BEGIN  (onion-sealed x2) --------> ENTRY peels L0 -> EXIT
//!    |  CMD_RELAY DATA   (onion-sealed x2) --------> peels L1 -> TCP echo
//!    |  <-------------- CMD_RELAY DATA (reverse-sealed back through both hops)
//! ```
//!
//! This is the composition that the daemon wiring performs per session:
//! * ENTRY: direct-client session (`accept_with_peer_static` sees the CLIENT
//!   key, not a relay peer) + relay-capable executor (`with_relay` +
//!   `SessionNextHopDialer`). NON-relay mode.
//! * EXIT: the inbound peer IS the entry bridge (its static key is in EXIT's
//!   relay-peer allowlist) -> relay mode (`with_relay_mode`) + per-hop token
//!   verification (`with_token_verification`) sharing EXIT's replay set.
//!
//! What this proves that the constituent tests don't: the FULL 2-hop DATA path
//! (forward onion peel at each hop + reverse onion re-encryption at each hop)
//! across two real authenticated bridge sessions, plus the per-hop token gate
//! on the extended (exit) hop.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use mirage_bridge::stream_dispatcher::{BeginBody, DataBody};
use mirage_bridge::{
    BridgeCircuitExecutor, BridgeCircuitKeys, SessionNextHopDialer, SessionTask, SessionTaskConfig,
};
use mirage_circuit::{
    cell::Cell, circuit::Circuit, derive_hop_keys_from_handshake, ExtendBody, ExtendFinishBody,
    HandshakeBody, HopEndpoint, RelaySubCell, CMD_BEGIN, CMD_CREATE, CMD_CREATED, CMD_CREATED_CONT,
    CMD_CREATE_CONT, CMD_DATA, CMD_EXTEND, CMD_EXTENDED, CMD_EXTENDED_CONT, CMD_EXTEND_CONT,
    CMD_EXTEND_FINISH, CMD_RELAY, MAX_CELL_PAYLOAD,
};
use mirage_crypto::ed25519_dalek::SigningKey;
use mirage_crypto::x25519_dalek::{PublicKey, StaticSecret};
use mirage_discovery::replay::{ReplaySet, SyncReplaySet};
use mirage_discovery::token::{sign_token, CapabilityToken};
use mirage_runtime::cell_io::{read_cell, write_cell};
use mirage_session::{accept_with_peer_static, connect, HandshakeInitiator, TokenVerifier};
use tokio::net::{TcpListener, TcpStream};

/// Wall-clock seconds. The exit's `verify_extend_finish` reads the REAL system
/// clock (production-correct - token expiry is the sole per-hop freshness
/// control), so the test's tokens and transport verifiers must agree with it
/// rather than a fixed epoch.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn rand_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    getrandom::fill(&mut s).unwrap();
    s
}

/// A bridge's key set (X25519 transport + Ed25519 identity pubkey).
struct BridgeKeys {
    x_sk: [u8; 32],
    x_pk: [u8; 32],
    ed_pk: [u8; 32],
}

fn fresh_bridge_keys() -> BridgeKeys {
    let x = StaticSecret::from(rand_seed());
    let ed_sk = SigningKey::from_bytes(&rand_seed());
    BridgeKeys {
        x_sk: x.to_bytes(),
        x_pk: *PublicKey::from(&x).as_bytes(),
        ed_pk: ed_sk.verifying_key().to_bytes(),
    }
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

fn ip_endpoint(addr: std::net::SocketAddr) -> HopEndpoint {
    match addr {
        std::net::SocketAddr::V4(v4) => HopEndpoint::Ipv4 {
            addr: v4.ip().octets(),
            port: v4.port(),
        },
        std::net::SocketAddr::V6(v6) => HopEndpoint::Ipv6 {
            addr: v6.ip().octets(),
            port: v6.port(),
        },
    }
}

/// Client helper: fragmented CMD_CREATE.
async fn send_create<S>(session: &mut mirage_session::SessionStream<S>, circ_id: u32, msg1: Vec<u8>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let (first, conts) = HandshakeBody { hs_msg: msg1 }
        .encode_fragmented(MAX_CELL_PAYLOAD)
        .unwrap();
    write_cell(session, &Cell::new(circ_id, CMD_CREATE, first).unwrap())
        .await
        .unwrap();
    for c in conts {
        write_cell(session, &Cell::new(circ_id, CMD_CREATE_CONT, c).unwrap())
            .await
            .unwrap();
    }
}

/// Client helper: reassemble CMD_CREATED/CMD_EXTENDED-style [u16 len][chunks..].
async fn recv_len_prefixed<S>(
    session: &mut mirage_session::SessionStream<S>,
    circ_id: u32,
    first_cmd: u8,
    cont_cmd: u8,
) -> Vec<u8>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let first = tokio::time::timeout(Duration::from_secs(5), read_cell(session))
        .await
        .expect("timeout")
        .expect("read");
    assert_eq!(first.command, first_cmd, "unexpected first cmd");
    assert_eq!(first.circ_id, circ_id);
    assert!(first.body.len() >= 2);
    let total = u16::from_be_bytes([first.body[0], first.body[1]]) as usize;
    let mut buf = first.body[2..].to_vec();
    while buf.len() < total {
        let cont = tokio::time::timeout(Duration::from_secs(5), read_cell(session))
            .await
            .expect("timeout")
            .expect("read");
        assert_eq!(cont.command, cont_cmd, "unexpected cont cmd");
        buf.extend_from_slice(&cont.body);
    }
    buf
}

/// Run the EXIT bridge: accept the relay leg, detect it as a relay peer, and
/// drive a relay-mode + token-verifying SessionTask (mirrors the daemon).
async fn run_exit_bridge(
    listener: TcpListener,
    keys: Arc<BridgeKeys>,
    op_pk: [u8; 32],
    now: u64,
    relay_allowlist: Arc<std::collections::HashSet<[u8; 32]>>,
    shared_replay: Arc<SyncReplaySet>,
) {
    let (sock, _) = listener.accept().await.unwrap();
    sock.set_nodelay(true).ok();
    // C1: the relay leg is SS-2022-wrapped by the dialer (so the session's
    // cleartext `MI` magic never rides the inter-bridge wire). Unwrap it with the
    // relay PSK derived from THIS bridge's pubkey - the identical key the dialer
    // derived from the next-hop pubkey it dialed. In production the protocol mux
    // does this via `MuxConfig::relay_ss_psk`.
    let relay_psk = mirage_bridge::next_hop_link::derive_relay_ss_psk(&keys.x_pk);
    let sock =
        mirage_transport_shadowsocks::ss2022_server_auth(sock, &relay_psk, Duration::from_secs(10))
            .await
            .expect("exit: ss2022 unwrap relay leg");
    // Transport accept, capturing the initiator (entry bridge) static key.
    let (session, peer_static) = {
        let mut v = TokenVerifier::new_shared(shared_replay.as_ref(), now);
        accept_with_peer_static(sock, &keys.x_sk, &keys.ed_pk, &op_pk, &mut v)
            .await
            .expect("exit: accept relay leg")
    };
    let inbound_is_relay = relay_allowlist.contains(&peer_static);
    assert!(
        inbound_is_relay,
        "exit must recognize the entry as an authorized relay peer"
    );

    let ckeys = BridgeCircuitKeys {
        bridge_x25519_sk: keys.x_sk,
        bridge_ed25519_pk: keys.ed_pk,
        operator_ed25519_pk: op_pk,
    };
    // Terminal exit: exit-only executor + per-hop token verification, relay mode.
    let (executor, exit_events_rx) = BridgeCircuitExecutor::new(
        ckeys, /* allow_private */ true, /* allow_loopback */ true,
    );
    let executor = executor.with_token_verification(shared_replay, None);
    SessionTask::new(session, Arc::new(executor), SessionTaskConfig::default())
        .with_exit_events(exit_events_rx)
        .with_relay_mode()
        .run()
        .await
        .ok();
}

/// Run the ENTRY bridge: accept the client, build a relay-capable (extend)
/// executor with a real dialer to the exit (mirrors the daemon's entry path).
async fn run_entry_bridge(
    listener: TcpListener,
    keys: Arc<BridgeKeys>,
    op_pk: [u8; 32],
    now: u64,
    exit_pk: [u8; 32],
    entry_relay_token: CapabilityToken,
) {
    let (sock, _) = listener.accept().await.unwrap();
    sock.set_nodelay(true).ok();
    let mut replay = ReplaySet::new(64);
    let (session, _peer_static) = {
        let mut v = TokenVerifier::new(&mut replay, now);
        accept_with_peer_static(sock, &keys.x_sk, &keys.ed_pk, &op_pk, &mut v)
            .await
            .expect("entry: accept client")
    };

    let ckeys = BridgeCircuitKeys {
        bridge_x25519_sk: keys.x_sk,
        bridge_ed25519_pk: keys.ed_pk,
        operator_ed25519_pk: op_pk,
    };
    let mut peer_tokens = HashMap::new();
    peer_tokens.insert(exit_pk, entry_relay_token);
    let dialer = SessionNextHopDialer::new(keys.x_sk, peer_tokens, Duration::from_secs(10))
        .allow_private_destinations();
    let (executor, exit_events_rx, next_hop_rx) = BridgeCircuitExecutor::with_relay(
        ckeys,
        /* allow_private */ true,
        /* allow_loopback */ true,
        Arc::new(dialer),
    );
    // Direct-client session: NON-relay mode, no token verification at this hop.
    SessionTask::new(session, Arc::new(executor), SessionTaskConfig::default())
        .with_exit_events(exit_events_rx)
        .with_next_hop_events(next_hop_rx)
        .run()
        .await
        .ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn two_bridge_circuit_data_round_trip() {
    // Opt-in debug logging: RUST_LOG=mirage_bridge=debug,mirage_circuit=debug
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("off")),
        )
        .with_test_writer()
        .try_init();

    // -- Trust anchor + bridge identities ---------------------------------
    let op_sk = SigningKey::from_bytes(&rand_seed());
    let op_pk = op_sk.verifying_key().to_bytes();
    let entry = Arc::new(fresh_bridge_keys());
    let exit = Arc::new(fresh_bridge_keys());

    // -- Echo target ------------------------------------------------------
    let echo_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_l.local_addr().unwrap();
    tokio::spawn(echo_server(echo_l));

    // -- Bridge listeners -------------------------------------------------
    let entry_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let entry_addr = entry_l.local_addr().unwrap();
    let exit_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let exit_addr = exit_l.local_addr().unwrap();

    // -- Tokens (all operator-signed, distinct ids so no replay collision) -
    // Signed against the real clock so the exit's real-clock per-hop verify
    // accepts them (see `now_unix`).
    let now = now_unix();
    let entry_client_token = sign_token([0x01; 32], entry.ed_pk, now + 3600, &op_sk);
    let entry_relay_token = sign_token([0x02; 32], exit.ed_pk, now + 3600, &op_sk);
    let exit_client_token = sign_token([0x03; 32], exit.ed_pk, now + 3600, &op_sk);

    // Exit shares one replay set across its transport accept AND per-hop verify.
    let exit_replay = Arc::new(SyncReplaySet::new(128));
    let exit_allowlist: Arc<std::collections::HashSet<[u8; 32]>> =
        Arc::new([entry.x_pk].into_iter().collect());

    // -- Spawn the two bridges --------------------------------------------
    let exit_task = tokio::spawn(run_exit_bridge(
        exit_l,
        exit.clone(),
        op_pk,
        now,
        exit_allowlist,
        exit_replay,
    ));
    let entry_task = tokio::spawn(run_entry_bridge(
        entry_l,
        entry.clone(),
        op_pk,
        now,
        exit.x_pk,
        entry_relay_token,
    ));

    // -- Client -----------------------------------------------------------
    let client_x_sk = StaticSecret::from(rand_seed()).to_bytes();
    let sock = TcpStream::connect(entry_addr).await.unwrap();
    sock.set_nodelay(true).ok();
    let mut session = connect(sock, &client_x_sk, &entry.x_pk, &entry_client_token)
        .await
        .expect("client connect to entry");

    // Circuit id.
    let circ_id: u32 = 0x1234_5678;

    // hop-0 CREATE (no per-hop token; the transport session already authed us).
    let circ_x_sk = StaticSecret::from(rand_seed()).to_bytes();
    let mut initiator =
        HandshakeInitiator::new_for_circuit_hop(&circ_x_sk, &entry.x_pk).expect("hop0 initiator");
    let msg1 = initiator.write_message_1().unwrap();
    send_create(&mut session, circ_id, msg1).await;
    let msg2 = recv_len_prefixed(&mut session, circ_id, CMD_CREATED, CMD_CREATED_CONT).await;
    initiator.read_message_2(&msg2).unwrap();
    let (mlkem_ss, binding) = initiator.circuit_hop_binding().unwrap();
    let entry_hop_keys = derive_hop_keys_from_handshake(&mlkem_ss, &binding);

    let mut circuit = Circuit::new();
    circuit.extend(entry_hop_keys).unwrap();

    // hop-1 EXTEND to the exit (full 3-message handshake; token in msg3).
    let hop1_client_sk = StaticSecret::from(rand_seed()).to_bytes();
    let mut ext = HandshakeInitiator::new(&hop1_client_sk, &exit.x_pk, &exit_client_token)
        .expect("hop1 initiator");
    let ext_msg1 = ext.write_message_1().unwrap();
    let (first, conts) = ExtendBody {
        next_hop_pk: exit.x_pk,
        endpoint: ip_endpoint(exit_addr),
        hs_msg1: ext_msg1,
    }
    .encode_fragmented(MAX_CELL_PAYLOAD)
    .unwrap();
    write_cell(
        &mut session,
        &Cell::new(circ_id, CMD_EXTEND, first).unwrap(),
    )
    .await
    .unwrap();
    for c in conts {
        write_cell(
            &mut session,
            &Cell::new(circ_id, CMD_EXTEND_CONT, c).unwrap(),
        )
        .await
        .unwrap();
    }
    let ext_msg2 = recv_len_prefixed(&mut session, circ_id, CMD_EXTENDED, CMD_EXTENDED_CONT).await;
    ext.read_message_2(&ext_msg2).unwrap();
    let (mlkem_ss1, binding1) = ext.circuit_hop_binding().unwrap();
    let (msg3, _keys) = ext.write_message_3().unwrap();
    let finish = ExtendFinishBody { hs_msg3: msg3 }.encode().unwrap();
    write_cell(
        &mut session,
        &Cell::new(circ_id, CMD_EXTEND_FINISH, finish).unwrap(),
    )
    .await
    .unwrap();
    let hop1_keys = derive_hop_keys_from_handshake(&mlkem_ss1, &binding1);
    circuit.extend(hop1_keys).unwrap();
    assert_eq!(circuit.hop_count(), 2, "2-hop circuit built");

    // -- BEGIN (onion-sealed across both hops) ----------------------------
    let stream_id: u16 = 42;
    let begin_sub = RelaySubCell {
        command: CMD_BEGIN,
        body: BeginBody {
            stream_id,
            host: "127.0.0.1".to_string(),
            port: echo_addr.port(),
        }
        .encode()
        .unwrap(),
    }
    .encode()
    .unwrap();
    let sealed = circuit.relay_seal(&begin_sub).unwrap();
    write_cell(
        &mut session,
        &Cell::new(circ_id, CMD_RELAY, sealed).unwrap(),
    )
    .await
    .unwrap();

    // -- DATA (onion-sealed across both hops) -----------------------------
    // Multi-KiB payload spanning many cells IN BOTH directions: exercises the
    // client's forward chunking AND the exit's reverse chunking. A single-cell
    // test hid a real bug - the exit dispatcher reads up to 4 KiB per read and
    // an unchunked reverse sub-cell blew MAX_CELL_PAYLOAD and was silently
    // dropped. Distinct byte values catch any misordering.
    let payload: Vec<u8> = (0..9000u32).map(|i| (i % 251) as u8).collect();
    // Forward chunk bound: cell cap minus one AEAD tag PER HOP minus sub-cell
    // header (3) + stream_id (2). Mirrors the client's `max_data_bytes`.
    let fwd_max = MAX_CELL_PAYLOAD - circuit.hop_count() * 16 - 3 - 2;
    for chunk in payload.chunks(fwd_max) {
        let data_sub = RelaySubCell {
            command: CMD_DATA,
            body: DataBody {
                stream_id,
                bytes: chunk.to_vec(),
            }
            .encode(),
        }
        .encode()
        .unwrap();
        let sealed = circuit.relay_seal(&data_sub).unwrap();
        write_cell(
            &mut session,
            &Cell::new(circ_id, CMD_RELAY, sealed).unwrap(),
        )
        .await
        .unwrap();
    }

    // -- Read the echo back through BOTH reverse onion layers -------------
    let mut got = Vec::new();
    while got.len() < payload.len() {
        let cell = tokio::time::timeout(Duration::from_secs(10), read_cell(&mut session))
            .await
            .expect("timeout waiting for echoed DATA")
            .expect("read echoed cell");
        if cell.command != CMD_RELAY || cell.circ_id != circ_id {
            continue;
        }
        let plaintext = circuit
            .relay_open(&cell.body)
            .expect("relay_open reverse x2");
        let sub = RelaySubCell::decode(&plaintext).expect("decode reverse sub-cell");
        if sub.command == CMD_DATA {
            let d = DataBody::decode(&sub.body).unwrap();
            assert_eq!(d.stream_id, stream_id);
            got.extend_from_slice(&d.bytes);
        }
    }
    assert_eq!(
        got,
        payload,
        "echoed {}-byte payload must survive the 2-hop onion in both directions",
        payload.len()
    );

    eprintln!(
        "[ok] 2-hop deployment proof: {} bytes (multi-cell both directions) flowed \
         client -> ENTRY (relay) -> EXIT (relay-mode + per-hop token verify) -> TCP \
         echo -> back through both reverse onion layers",
        payload.len()
    );

    // Tidy: drop the client so the bridges' loops exit.
    drop(session);
    let _ = tokio::time::timeout(Duration::from_secs(2), entry_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), exit_task).await;
}

// 3-hop telescoping: client -> ENTRY -> MIDDLE -> EXIT

/// Run the MIDDLE bridge: an interior hop that is BOTH an inbound relay leg
/// (from the entry -> relay mode + per-hop token verify) AND outbound
/// extend-capable (dials the exit -> `with_relay`). This is the case-4 daemon
/// configuration.
#[allow(clippy::too_many_arguments)]
async fn run_middle_bridge(
    listener: TcpListener,
    keys: Arc<BridgeKeys>,
    op_pk: [u8; 32],
    now: u64,
    inbound_allowlist: Arc<std::collections::HashSet<[u8; 32]>>,
    shared_replay: Arc<SyncReplaySet>,
    exit_pk: [u8; 32],
    middle_relay_token: CapabilityToken,
) {
    let (sock, _) = listener.accept().await.unwrap();
    sock.set_nodelay(true).ok();
    // C1: unwrap the SS-2022-wrapped relay leg (see run_exit_bridge).
    let relay_psk = mirage_bridge::next_hop_link::derive_relay_ss_psk(&keys.x_pk);
    let sock =
        mirage_transport_shadowsocks::ss2022_server_auth(sock, &relay_psk, Duration::from_secs(10))
            .await
            .expect("middle: ss2022 unwrap relay leg");
    let (session, peer_static) = {
        let mut v = TokenVerifier::new_shared(shared_replay.as_ref(), now);
        accept_with_peer_static(sock, &keys.x_sk, &keys.ed_pk, &op_pk, &mut v)
            .await
            .expect("middle: accept relay leg")
    };
    assert!(
        inbound_allowlist.contains(&peer_static),
        "middle must recognize the entry as an authorized relay peer"
    );

    let ckeys = BridgeCircuitKeys {
        bridge_x25519_sk: keys.x_sk,
        bridge_ed25519_pk: keys.ed_pk,
        operator_ed25519_pk: op_pk,
    };
    let mut peer_tokens = HashMap::new();
    peer_tokens.insert(exit_pk, middle_relay_token);
    let dialer = SessionNextHopDialer::new(keys.x_sk, peer_tokens, Duration::from_secs(10))
        .allow_private_destinations();
    let (executor, exit_events_rx, next_hop_rx) = BridgeCircuitExecutor::with_relay(
        ckeys,
        /* allow_private */ true,
        /* allow_loopback */ true,
        Arc::new(dialer),
    );
    // Inbound relay leg -> relay mode + per-hop token verification; AND
    // outbound extend-capable via the dialer + next-hop events.
    let executor = executor.with_token_verification(shared_replay, None);
    SessionTask::new(session, Arc::new(executor), SessionTaskConfig::default())
        .with_exit_events(exit_events_rx)
        .with_next_hop_events(next_hop_rx)
        .with_relay_mode()
        .run()
        .await
        .ok();
}

/// Client helper: onion-seal a control sub-cell across `circuit` and write it as
/// a `CMD_RELAY` cell (the deep-hop EXTEND / EXTEND_FINISH transport).
async fn send_relay_sub<S>(
    session: &mut mirage_session::SessionStream<S>,
    circuit: &mut Circuit,
    circ_id: u32,
    command: u8,
    body: Vec<u8>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let sub = RelaySubCell { command, body }.encode().unwrap();
    let sealed = circuit.relay_seal(&sub).unwrap();
    write_cell(session, &Cell::new(circ_id, CMD_RELAY, sealed).unwrap())
        .await
        .unwrap();
}

/// Client helper: read an onion-wrapped EXTENDED flight and reassemble hs_msg2.
async fn recv_relay_extended<S>(
    session: &mut mirage_session::SessionStream<S>,
    circuit: &mut Circuit,
    circ_id: u32,
) -> Vec<u8>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let mut msg2: Vec<u8> = Vec::new();
    let mut total: Option<usize> = None;
    loop {
        let cell = tokio::time::timeout(Duration::from_secs(5), read_cell(session))
            .await
            .expect("EXTENDED(relay) timeout")
            .expect("read");
        if cell.command != CMD_RELAY || cell.circ_id != circ_id {
            continue;
        }
        let plaintext = circuit.relay_open(&cell.body).expect("relay_open EXTENDED");
        let sub = RelaySubCell::decode(&plaintext).expect("decode EXTENDED sub-cell");
        match sub.command {
            CMD_EXTENDED => {
                total = Some(u16::from_be_bytes([sub.body[0], sub.body[1]]) as usize);
                msg2.extend_from_slice(&sub.body[2..]);
            }
            CMD_EXTENDED_CONT => msg2.extend_from_slice(&sub.body),
            other => panic!("unexpected inner EXTENDED cmd {other}"),
        }
        if let Some(t) = total {
            if msg2.len() >= t {
                msg2.truncate(t);
                break;
            }
        }
    }
    msg2
}

/// Client helper: raw hop-1 EXTEND (entry is the direct session peer). Sends
/// CMD_EXTEND(+CONT), reads raw CMD_EXTENDED, sends raw CMD_EXTEND_FINISH, and
/// returns the new hop's onion keys.
async fn extend_raw<S>(
    session: &mut mirage_session::SessionStream<S>,
    circ_id: u32,
    target_pk: [u8; 32],
    target_addr: std::net::SocketAddr,
    client_sk: &[u8; 32],
    token: &CapabilityToken,
) -> mirage_circuit::HopKeys
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let mut init = HandshakeInitiator::new(client_sk, &target_pk, token).expect("initiator");
    let msg1 = init.write_message_1().unwrap();
    let (first, conts) = ExtendBody {
        next_hop_pk: target_pk,
        endpoint: ip_endpoint(target_addr),
        hs_msg1: msg1,
    }
    .encode_fragmented(MAX_CELL_PAYLOAD)
    .unwrap();
    write_cell(session, &Cell::new(circ_id, CMD_EXTEND, first).unwrap())
        .await
        .unwrap();
    for c in conts {
        write_cell(session, &Cell::new(circ_id, CMD_EXTEND_CONT, c).unwrap())
            .await
            .unwrap();
    }
    let msg2 = recv_len_prefixed(session, circ_id, CMD_EXTENDED, CMD_EXTENDED_CONT).await;
    init.read_message_2(&msg2).unwrap();
    let (ss, binding) = init.circuit_hop_binding().unwrap();
    let (msg3, _k) = init.write_message_3().unwrap();
    let finish = ExtendFinishBody { hs_msg3: msg3 }.encode().unwrap();
    write_cell(
        session,
        &Cell::new(circ_id, CMD_EXTEND_FINISH, finish).unwrap(),
    )
    .await
    .unwrap();
    derive_hop_keys_from_handshake(&ss, &binding)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn three_bridge_circuit_data_round_trip() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("off")),
        )
        .with_test_writer()
        .try_init();

    let op_sk = SigningKey::from_bytes(&rand_seed());
    let op_pk = op_sk.verifying_key().to_bytes();
    let entry = Arc::new(fresh_bridge_keys());
    let middle = Arc::new(fresh_bridge_keys());
    let exit = Arc::new(fresh_bridge_keys());

    let echo_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_l.local_addr().unwrap();
    tokio::spawn(echo_server(echo_l));

    let entry_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let entry_addr = entry_l.local_addr().unwrap();
    let middle_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let middle_addr = middle_l.local_addr().unwrap();
    let exit_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let exit_addr = exit_l.local_addr().unwrap();

    let now = now_unix();
    // Transport / relay-leg tokens.
    let entry_client_token = sign_token([0x01; 32], entry.ed_pk, now + 3600, &op_sk);
    let entry_relay_token = sign_token([0x02; 32], middle.ed_pk, now + 3600, &op_sk); // entry->middle
    let middle_relay_token = sign_token([0x03; 32], exit.ed_pk, now + 3600, &op_sk); // middle->exit
                                                                                     // Per-hop client tokens (ride in EXTEND_FINISH; verified at each extended hop).
    let middle_client_token = sign_token([0x04; 32], middle.ed_pk, now + 3600, &op_sk);
    let exit_client_token = sign_token([0x05; 32], exit.ed_pk, now + 3600, &op_sk);

    let middle_replay = Arc::new(SyncReplaySet::new(128));
    let exit_replay = Arc::new(SyncReplaySet::new(128));
    let middle_allow: Arc<std::collections::HashSet<[u8; 32]>> =
        Arc::new([entry.x_pk].into_iter().collect());
    let exit_allow: Arc<std::collections::HashSet<[u8; 32]>> =
        Arc::new([middle.x_pk].into_iter().collect());

    let exit_task = tokio::spawn(run_exit_bridge(
        exit_l,
        exit.clone(),
        op_pk,
        now,
        exit_allow,
        exit_replay,
    ));
    let middle_task = tokio::spawn(run_middle_bridge(
        middle_l,
        middle.clone(),
        op_pk,
        now,
        middle_allow,
        middle_replay,
        exit.x_pk,
        middle_relay_token,
    ));
    let entry_task = tokio::spawn(run_entry_bridge(
        entry_l,
        entry.clone(),
        op_pk,
        now,
        middle.x_pk, // entry dials the MIDDLE
        entry_relay_token,
    ));

    // -- Client -----------------------------------------------------------
    let client_x_sk = StaticSecret::from(rand_seed()).to_bytes();
    let sock = TcpStream::connect(entry_addr).await.unwrap();
    sock.set_nodelay(true).ok();
    let mut session = connect(sock, &client_x_sk, &entry.x_pk, &entry_client_token)
        .await
        .expect("client connect to entry");
    let circ_id: u32 = 0x0BAD_F00D;

    // hop-0 CREATE (entry).
    let circ_x_sk = StaticSecret::from(rand_seed()).to_bytes();
    let mut initiator =
        HandshakeInitiator::new_for_circuit_hop(&circ_x_sk, &entry.x_pk).expect("hop0 init");
    let msg1 = initiator.write_message_1().unwrap();
    send_create(&mut session, circ_id, msg1).await;
    let msg2 = recv_len_prefixed(&mut session, circ_id, CMD_CREATED, CMD_CREATED_CONT).await;
    initiator.read_message_2(&msg2).unwrap();
    let (ss0, b0) = initiator.circuit_hop_binding().unwrap();
    let mut circuit = Circuit::new();
    circuit
        .extend(derive_hop_keys_from_handshake(&ss0, &b0))
        .unwrap();

    // hop-1 EXTEND to the MIDDLE (raw on the hop-0 session).
    let mid_sk = StaticSecret::from(rand_seed()).to_bytes();
    let hop1_keys = extend_raw(
        &mut session,
        circ_id,
        middle.x_pk,
        middle_addr,
        &mid_sk,
        &middle_client_token,
    )
    .await;
    circuit.extend(hop1_keys).unwrap();
    assert_eq!(circuit.hop_count(), 2);

    // hop-2 EXTEND to the EXIT (RELAY-wrapped across entry+middle).
    let exit_hs_sk = StaticSecret::from(rand_seed()).to_bytes();
    let mut ext =
        HandshakeInitiator::new(&exit_hs_sk, &exit.x_pk, &exit_client_token).expect("hop2 init");
    let ext_msg1 = ext.write_message_1().unwrap();
    let inner_max =
        MAX_CELL_PAYLOAD - circuit.hop_count() * 16 - mirage_circuit::RELAY_SUBCELL_HEADER_LEN;
    let (efirst, econts) = ExtendBody {
        next_hop_pk: exit.x_pk,
        endpoint: ip_endpoint(exit_addr),
        hs_msg1: ext_msg1,
    }
    .encode_fragmented(inner_max)
    .unwrap();
    send_relay_sub(&mut session, &mut circuit, circ_id, CMD_EXTEND, efirst).await;
    for c in econts {
        send_relay_sub(&mut session, &mut circuit, circ_id, CMD_EXTEND_CONT, c).await;
    }
    let ext_msg2 = recv_relay_extended(&mut session, &mut circuit, circ_id).await;
    ext.read_message_2(&ext_msg2).unwrap();
    let (ss2, b2) = ext.circuit_hop_binding().unwrap();
    let (msg3, _k) = ext.write_message_3().unwrap();
    let finish = ExtendFinishBody { hs_msg3: msg3 }.encode().unwrap();
    send_relay_sub(
        &mut session,
        &mut circuit,
        circ_id,
        CMD_EXTEND_FINISH,
        finish,
    )
    .await;
    circuit
        .extend(derive_hop_keys_from_handshake(&ss2, &b2))
        .unwrap();
    assert_eq!(circuit.hop_count(), 3, "3-hop circuit built");

    // -- BEGIN + DATA (onion-sealed across all THREE hops) ----------------
    let stream_id: u16 = 77;
    let begin_sub = RelaySubCell {
        command: CMD_BEGIN,
        body: BeginBody {
            stream_id,
            host: "127.0.0.1".to_string(),
            port: echo_addr.port(),
        }
        .encode()
        .unwrap(),
    }
    .encode()
    .unwrap();
    let sealed = circuit.relay_seal(&begin_sub).unwrap();
    write_cell(
        &mut session,
        &Cell::new(circ_id, CMD_RELAY, sealed).unwrap(),
    )
    .await
    .unwrap();

    let payload: Vec<u8> = (0..7000u32).map(|i| (i % 251) as u8).collect();
    let fwd_max = MAX_CELL_PAYLOAD - circuit.hop_count() * 16 - 3 - 2;
    for chunk in payload.chunks(fwd_max) {
        let data_sub = RelaySubCell {
            command: CMD_DATA,
            body: DataBody {
                stream_id,
                bytes: chunk.to_vec(),
            }
            .encode(),
        }
        .encode()
        .unwrap();
        let sealed = circuit.relay_seal(&data_sub).unwrap();
        write_cell(
            &mut session,
            &Cell::new(circ_id, CMD_RELAY, sealed).unwrap(),
        )
        .await
        .unwrap();
    }

    let mut got = Vec::new();
    while got.len() < payload.len() {
        let cell = tokio::time::timeout(Duration::from_secs(10), read_cell(&mut session))
            .await
            .expect("timeout waiting for echoed DATA (3-hop)")
            .expect("read echoed cell");
        if cell.command != CMD_RELAY || cell.circ_id != circ_id {
            continue;
        }
        let plaintext = circuit
            .relay_open(&cell.body)
            .expect("relay_open reverse x3");
        let sub = RelaySubCell::decode(&plaintext).expect("decode reverse sub-cell");
        if sub.command == CMD_DATA {
            let d = DataBody::decode(&sub.body).unwrap();
            assert_eq!(d.stream_id, stream_id);
            got.extend_from_slice(&d.bytes);
        }
    }
    assert_eq!(got, payload, "echoed payload must survive the 3-hop onion");

    eprintln!(
        "[ok] 3-hop deployment proof: {} bytes flowed client -> ENTRY -> MIDDLE \
         (relay+extend) -> EXIT (relay+per-hop verify) -> TCP echo -> back through \
         THREE reverse onion layers",
        payload.len()
    );

    drop(session);
    let _ = tokio::time::timeout(Duration::from_secs(2), entry_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), middle_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), exit_task).await;
}
