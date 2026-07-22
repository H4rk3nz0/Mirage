//! Phase 2H integration test: drive a real `SessionTask` against
//! a real `mirage_session::SessionStream` to prove the daemon's
//! circuit-aware loop dispatches CMD_CREATE / CMD_EXTEND /
//! CMD_EXTEND_FINISH / CMD_DESTROY correctly via the
//! `NextHopExecutor` callback.
//!
//! Topology:
//!
//! ```text
//! client (raw cells over Mirage session)
//!    <-> SessionTask (BridgeCircuitState + executor)
//!    <-> MockExecutor (records dispatched actions)
//! ```
//!
//! The executor is a Mutex-recording mock; no real next-hop link
//! exists. We assert on the BridgeAction sequence the state
//! machine emits in response to a scripted client cell stream.

use std::sync::Arc;
use std::time::Duration;

use mirage_bridge::session_task::{NextHopExecutor, SessionTask, SessionTaskConfig};
use mirage_circuit::cell::Cell;
use mirage_circuit::{
    derive_hop_keys, ExtendBody, ExtendFinishBody, HopEndpoint, HopKeys, CMD_CREATE, CMD_DESTROY,
    CMD_EXTEND, CMD_EXTEND_FINISH, MAX_CELL_PAYLOAD,
};
use mirage_crypto::ed25519_dalek::SigningKey;
use mirage_crypto::x25519_dalek::{PublicKey, StaticSecret};
use mirage_discovery::replay::ReplaySet;
use mirage_discovery::token::sign_token;
use mirage_runtime::cell_io::write_cell;
use mirage_session::handshake::TokenVerifier;

fn rand_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    getrandom::fill(&mut s).unwrap();
    s
}

#[derive(Default)]
struct RecorderInner {
    calls: Vec<String>,
}

struct MockExecutor {
    inner: tokio::sync::Mutex<RecorderInner>,
}

impl MockExecutor {
    fn new() -> Self {
        Self {
            inner: tokio::sync::Mutex::new(RecorderInner::default()),
        }
    }
    async fn calls(&self) -> Vec<String> {
        self.inner.lock().await.calls.clone()
    }
}

#[async_trait::async_trait]
impl NextHopExecutor for MockExecutor {
    async fn open_next_hop(
        &self,
        in_circ_id: u32,
        out_circ_id: u32,
        next_hop_pk: [u8; 32],
        _endpoint: HopEndpoint,
        hs_msg1: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        self.inner.lock().await.calls.push(format!(
            "open_next_hop(circ={in_circ_id}, out={out_circ_id}, pk[0]={}, msg1_len={})",
            next_hop_pk[0],
            hs_msg1.len()
        ));
        // Small canned hs_msg2 (Phase 2H scope - see comment on
        // perform_handshake for why we don't use 1189 B here).
        Ok(vec![0xAB; 200])
    }
    async fn send_to_next(&self, out_circ_id: u32, _cell: Cell) -> Result<(), String> {
        self.inner
            .lock()
            .await
            .calls
            .push(format!("send_to_next(out={out_circ_id})"));
        Ok(())
    }
    async fn forward_extend_finish(
        &self,
        out_circ_id: u32,
        hs_msg3: Vec<u8>,
    ) -> Result<(), String> {
        self.inner.lock().await.calls.push(format!(
            "forward_extend_finish(out={out_circ_id}, msg3_len={})",
            hs_msg3.len()
        ));
        Ok(())
    }
    async fn destroy_next_link(&self, out_circ_id: u32) -> Result<(), String> {
        self.inner
            .lock()
            .await
            .calls
            .push(format!("destroy_next_link(out={out_circ_id})"));
        Ok(())
    }
    async fn handle_exit_payload(&self, in_circ_id: u32, payload: Vec<u8>) -> Result<(), String> {
        self.inner.lock().await.calls.push(format!(
            "handle_exit_payload(circ={in_circ_id}, len={})",
            payload.len()
        ));
        Ok(())
    }
    async fn perform_handshake(
        &self,
        in_circ_id: u32,
        _hs_msg1: Vec<u8>,
    ) -> Result<(HopKeys, Vec<u8>), String> {
        self.inner
            .lock()
            .await
            .calls
            .push(format!("perform_handshake(circ={in_circ_id})"));
        // Canned keys + small msg2.
        //
        // Note: production hs_msg2 is 1189 B, which won't fit in
        // a single CMD_CREATED cell (1017 B body cap). Real
        // CREATE/CREATED fragmentation is Phase 2I work. For Phase
        // 2H, the test exercises
        // dispatch sequencing only, with a small placeholder
        // msg2 that fits.
        let keys = derive_hop_keys(&[1u8; 32], &[2u8; 32]);
        Ok((keys, vec![0xCD; 200]))
    }
    async fn verify_extend_finish(&self, in_circ_id: u32, _hs_msg3: Vec<u8>) -> Result<(), String> {
        self.inner
            .lock()
            .await
            .calls
            .push(format!("verify_extend_finish(circ={in_circ_id})"));
        Ok(())
    }
}

/// Spawn a `SessionTask` driven by a Mirage session established
/// over `tokio::io::duplex`. Returns the client side of the
/// duplex (so the test can write cells into the session) and the
/// task handle (for awaiting completion).
async fn spawn_session_task() -> (
    mirage_session::SessionStream<tokio::io::DuplexStream>,
    Arc<MockExecutor>,
    tokio::task::JoinHandle<Result<(), mirage_bridge::DaemonError>>,
) {
    let op_sk = SigningKey::from_bytes(&rand_seed());
    let op_pk = op_sk.verifying_key().to_bytes();
    let client_sk_bytes = StaticSecret::from(rand_seed()).to_bytes();
    let bsk = StaticSecret::from(rand_seed());
    let bridge_pk = *PublicKey::from(&bsk).as_bytes();
    let bridge_sk = bsk.to_bytes();
    let bridge_id_sk = SigningKey::from_bytes(&rand_seed());
    let bridge_ed_pk = bridge_id_sk.verifying_key().to_bytes();
    let now = 1_700_000_000u64;
    let token = sign_token([0xCC; 32], bridge_ed_pk, now + 3600, &op_sk);

    let (client_a, client_b) = tokio::io::duplex(64 * 1024);

    // Spawn the bridge-side accept + SessionTask.
    let exec = Arc::new(MockExecutor::new());
    let exec_for_task = exec.clone();
    let task_handle = tokio::spawn(async move {
        let mut replay = ReplaySet::new(64);
        let mut verifier = TokenVerifier::new(&mut replay, now);
        let session =
            mirage_session::accept(client_b, &bridge_sk, &bridge_ed_pk, &op_pk, &mut verifier)
                .await
                .expect("accept");
        let task = SessionTask::new(
            session,
            exec_for_task,
            SessionTaskConfig {
                cell_read_timeout: Some(Duration::from_secs(2)),
                ..Default::default()
            },
        );
        task.run().await
    });

    // Client side: run connect to establish the session, then
    // hand the SessionStream back to the test.
    let session = mirage_session::connect(client_a, &client_sk_bytes, &bridge_pk, &token)
        .await
        .expect("client connect");
    (session, exec, task_handle)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_task_dispatches_create_to_perform_handshake() {
    let (mut session, exec, task) = spawn_session_task().await;

    // Write CMD_CREATE with a small hs_msg1 placeholder.
    let create = Cell::new(
        7,
        CMD_CREATE,
        mirage_circuit::HandshakeBody {
            hs_msg: vec![0x01; 100],
        }
        .encode()
        .unwrap(),
    )
    .unwrap();
    write_cell(&mut session, &create).await.unwrap();

    // Wait for the perform_handshake call to register before
    // closing the session - otherwise the bridge's CMD_CREATED
    // write races against our drop and the task may exit with
    // BrokenPipe (acceptable in production; noisy in tests).
    for _ in 0..50 {
        let calls = exec.calls().await;
        if !calls.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // Now read the CMD_CREATED reply so the bridge's write
    // succeeds, then drop.
    let _ = mirage_runtime::cell_io::read_cell(&mut session).await;
    drop(session);
    let _ = task.await.expect("task panicked");

    let calls = exec.calls().await;
    assert_eq!(
        calls,
        vec!["perform_handshake(circ=7)".to_string()],
        "expected single perform_handshake call, got {calls:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_task_dispatches_extend_chain_to_open_next_hop() {
    let (mut session, exec, task) = spawn_session_task().await;

    // 1) CMD_CREATE -> triggers PerformHandshake -> state machine
    //    transitions to Open.
    let create = Cell::new(
        7,
        CMD_CREATE,
        mirage_circuit::HandshakeBody {
            hs_msg: vec![0x01; 100],
        }
        .encode()
        .unwrap(),
    )
    .unwrap();
    write_cell(&mut session, &create).await.unwrap();

    // 2) CMD_EXTEND (fragmented if hs_msg1 is large; small here).
    let extend_body = ExtendBody {
        next_hop_pk: [0x99u8; 32],
        endpoint: HopEndpoint::Ipv4 {
            addr: [10, 0, 0, 1],
            port: 4433,
        },
        hs_msg1: vec![0xCD; 100],
    };
    let (extend_cell_body, cont_bodies) = extend_body
        .encode_fragmented(MAX_CELL_PAYLOAD)
        .expect("encode");
    assert!(cont_bodies.is_empty(), "100 B hs_msg1 must fit in one cell");
    let extend = Cell::new(7, CMD_EXTEND, extend_cell_body).unwrap();
    write_cell(&mut session, &extend).await.unwrap();

    // Closes [RT-H17]: poll for the dispatch to register
    // instead of a fixed sleep - robust across slow CI / fast
    // dev machines.
    for _ in 0..100 {
        let calls = exec.calls().await;
        if calls.iter().any(|c| c.starts_with("perform_handshake"))
            && calls.iter().any(|c| c.starts_with("open_next_hop"))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    drop(session);
    let _ = task.await.expect("task panicked");

    let calls = exec.calls().await;
    // Expect: perform_handshake (for CREATE) -> open_next_hop (for
    // EXTEND, which transitions to Extending and emits OpenNextHop).
    // After open_next_hop returns canned hs_msg2, the bridge's
    // record_extend_complete fires SendToPrev (CMD_EXTENDED) which
    // is written back to the session - but our test session is
    // already dropped, so the write may or may not succeed. We
    // tolerate both.
    assert!(
        calls.iter().any(|c| c.starts_with("perform_handshake")),
        "expected perform_handshake call: {calls:?}"
    );
    assert!(
        calls.iter().any(|c| c.starts_with("open_next_hop(circ=7")),
        "expected open_next_hop call: {calls:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_task_dispatches_extend_finish_to_forward() {
    let (mut session, exec, task) = spawn_session_task().await;

    // Drive CREATE -> EXTEND -> EXTEND_FINISH chain.
    let create = Cell::new(
        7,
        CMD_CREATE,
        mirage_circuit::HandshakeBody {
            hs_msg: vec![0x01; 100],
        }
        .encode()
        .unwrap(),
    )
    .unwrap();
    write_cell(&mut session, &create).await.unwrap();
    let extend_body = ExtendBody {
        next_hop_pk: [0x99u8; 32],
        endpoint: HopEndpoint::Ipv4 {
            addr: [10, 0, 0, 1],
            port: 4433,
        },
        hs_msg1: vec![0xCD; 100],
    };
    let (extend_body_bytes, _) = extend_body.encode_fragmented(MAX_CELL_PAYLOAD).unwrap();
    let extend = Cell::new(7, CMD_EXTEND, extend_body_bytes).unwrap();
    write_cell(&mut session, &extend).await.unwrap();

    // EXTEND_FINISH carrying a canned hs_msg3 (203 B token form).
    let finish_body = ExtendFinishBody {
        hs_msg3: vec![0x33u8; 203],
    };
    let finish = Cell::new(7, CMD_EXTEND_FINISH, finish_body.encode().unwrap()).unwrap();
    write_cell(&mut session, &finish).await.unwrap();

    // Poll for forward_extend_finish to register.
    for _ in 0..100 {
        let calls = exec.calls().await;
        if calls.iter().any(|c| c.starts_with("forward_extend_finish")) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    drop(session);
    let _ = task.await.expect("task panicked");

    let calls = exec.calls().await;
    assert!(
        calls.iter().any(|c| c.starts_with("forward_extend_finish")),
        "expected forward_extend_finish call: {calls:?}"
    );
    // Verify the msg3 length surfaced correctly through the
    // bridge state machine.
    assert!(
        calls.iter().any(|c| c.contains("msg3_len=203")),
        "expected msg3_len=203 in calls: {calls:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_task_handles_destroy_cleanly() {
    let (mut session, exec, task) = spawn_session_task().await;

    // CMD_DESTROY without prior CREATE: the state machine
    // tolerates it (handle_destroy_from_prev silently no-ops on
    // unknown circuits - the prev side already initiated the
    // destroy).
    let destroy = Cell::new(7, CMD_DESTROY, vec![]).unwrap();
    write_cell(&mut session, &destroy).await.unwrap();

    drop(session);
    let result = task.await.expect("task panicked");
    assert!(
        result.is_ok(),
        "destroy on unknown circuit should not error"
    );
    // No actions emitted.
    let calls = exec.calls().await;
    assert!(
        calls.is_empty(),
        "DESTROY on unknown should not dispatch: {calls:?}"
    );
}
