//! Real-crypto integration test for per-hop capability-token verification at
//! an EXTENDED (relay) hop.
//!
//! This drives the actual client-side circuit-hop handshake (real Noise-XX +
//! ML-KEM + a real operator-signed [`CapabilityToken`]) against a relay-mode
//! [`BridgeCircuitExecutor`], and asserts:
//!
//! - `perform_handshake` (retaining the responder) + `verify_extend_finish`
//!   ACCEPTS a valid per-hop token bound to this bridge.
//! - A token for a DIFFERENT bridge is REJECTED (`is_for_bridge` gate).
//! - A no-token msg-3 (the `new_for_circuit_hop` form) is REJECTED
//!   (`require_token`), closing the "extend to a bridge with no token" bypass.
//! - A replayed token is REJECTED the second time (shared replay set).
//!
//! Together with the state-machine gate tests in `mirage_circuit`, this proves
//! the extended-hop authorization is enforced with the real cryptographic
//! machinery - not just the mock.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use mirage_bridge::circuit_executor::{BridgeCircuitExecutor, BridgeCircuitKeys};
use mirage_bridge::session_task::NextHopExecutor;
use mirage_crypto::ed25519_dalek::SigningKey;
use mirage_crypto::x25519_dalek::{PublicKey, StaticSecret};
use mirage_discovery::replay::SyncReplaySet;
use mirage_discovery::token::{sign_token, CapabilityToken};
use mirage_session::HandshakeInitiator;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Fixed test key set: operator + one bridge (transport x25519 + ed25519 id).
struct Fixture {
    operator_sk: SigningKey,
    operator_pk: [u8; 32],
    bridge_x_sk: [u8; 32],
    bridge_x_pk: [u8; 32],
    bridge_ed_pk: [u8; 32],
}

fn fixture(op_seed: u8, x_seed: u8, id_seed: u8) -> Fixture {
    let operator_sk = SigningKey::from_bytes(&[op_seed; 32]);
    let operator_pk = operator_sk.verifying_key().to_bytes();
    let x = StaticSecret::from([x_seed; 32]);
    let bridge_x_pk = *PublicKey::from(&x).as_bytes();
    let bridge_ed_pk = SigningKey::from_bytes(&[id_seed; 32])
        .verifying_key()
        .to_bytes();
    Fixture {
        operator_sk,
        operator_pk,
        bridge_x_sk: x.to_bytes(),
        bridge_x_pk,
        bridge_ed_pk,
    }
}

/// Build a relay-mode executor for `fx` sharing `replay`.
fn relay_executor(fx: &Fixture, replay: Arc<SyncReplaySet>) -> BridgeCircuitExecutor {
    let keys = BridgeCircuitKeys {
        bridge_x25519_sk: fx.bridge_x_sk,
        bridge_ed25519_pk: fx.bridge_ed_pk,
        operator_ed25519_pk: fx.operator_pk,
    };
    let (exec, _exit_rx) = BridgeCircuitExecutor::new(keys, true, true);
    exec.with_token_verification(replay, None)
}

/// Run the client-side circuit-hop handshake against `exec` for `circ_id`,
/// presenting `token`, and return the msg-3 the client would send in
/// CMD_EXTEND_FINISH. Drives `perform_handshake` on the executor (which retains
/// the responder) exactly as the real relay flow does.
async fn client_extend_msg3(
    exec: &BridgeCircuitExecutor,
    circ_id: u32,
    client_sk: &[u8; 32],
    bridge_x_pk: &[u8; 32],
    token: &CapabilityToken,
) -> Vec<u8> {
    let mut initiator = HandshakeInitiator::new(client_sk, bridge_x_pk, token).unwrap();
    let msg1 = initiator.write_message_1().unwrap();
    // Bridge responder side: derives HopKeys + retains the responder.
    let (_hop_keys, hs_msg2) = exec.perform_handshake(circ_id, msg1).await.unwrap();
    initiator.read_message_2(&hs_msg2).unwrap();
    let _ = initiator.circuit_hop_binding().unwrap();
    let (msg3, _keys) = initiator.write_message_3().unwrap();
    msg3
}

#[tokio::test]
async fn valid_per_hop_token_is_accepted() {
    let fx = fixture(0x11, 0x22, 0x33);
    let replay = Arc::new(SyncReplaySet::new(64));
    let exec = relay_executor(&fx, replay);
    let client_sk = StaticSecret::from([0x44; 32]).to_bytes();
    let token = sign_token(
        [0x01; 32],
        fx.bridge_ed_pk,
        now_unix() + 3600,
        &fx.operator_sk,
    );

    let msg3 = client_extend_msg3(&exec, 7, &client_sk, &fx.bridge_x_pk, &token).await;
    exec.verify_extend_finish(7, msg3)
        .await
        .expect("valid per-hop token must verify at the extended hop");
}

#[tokio::test]
async fn token_for_a_different_bridge_is_rejected() {
    let fx = fixture(0x11, 0x22, 0x33);
    let other = fixture(0x11, 0x77, 0x88); // same operator, DIFFERENT bridge id
    let replay = Arc::new(SyncReplaySet::new(64));
    let exec = relay_executor(&fx, replay);
    let client_sk = StaticSecret::from([0x44; 32]).to_bytes();
    // Token names `other`, not `fx` - must fail is_for_bridge at fx.
    let token = sign_token(
        [0x02; 32],
        other.bridge_ed_pk,
        now_unix() + 3600,
        &fx.operator_sk,
    );

    let msg3 = client_extend_msg3(&exec, 8, &client_sk, &fx.bridge_x_pk, &token).await;
    let err = exec
        .verify_extend_finish(8, msg3)
        .await
        .expect_err("a token minted for another bridge must be rejected");
    assert!(err.contains("token verify failed"), "got: {err}");
}

#[tokio::test]
async fn no_token_msg3_is_rejected() {
    // The `new_for_circuit_hop` (no-token) form must NOT authorize an extended
    // hop - this is exactly the bypass the fix closes.
    let fx = fixture(0x11, 0x22, 0x33);
    let replay = Arc::new(SyncReplaySet::new(64));
    let exec = relay_executor(&fx, replay);
    let client_sk = StaticSecret::from([0x44; 32]).to_bytes();

    let mut initiator =
        HandshakeInitiator::new_for_circuit_hop(&client_sk, &fx.bridge_x_pk).unwrap();
    let msg1 = initiator.write_message_1().unwrap();
    let (_keys, hs_msg2) = exec.perform_handshake(9, msg1).await.unwrap();
    initiator.read_message_2(&hs_msg2).unwrap();
    let _ = initiator.circuit_hop_binding().unwrap();
    let (msg3, _k) = initiator.write_message_3().unwrap();

    let err = exec
        .verify_extend_finish(9, msg3)
        .await
        .expect_err("no-token msg-3 must be rejected at an extended hop");
    assert!(err.contains("token verify failed"), "got: {err}");
}

#[tokio::test]
async fn replayed_token_is_rejected_second_time() {
    let fx = fixture(0x11, 0x22, 0x33);
    let replay = Arc::new(SyncReplaySet::new(64));
    let exec = relay_executor(&fx, replay);
    let client_sk = StaticSecret::from([0x44; 32]).to_bytes();
    let token = sign_token(
        [0x03; 32],
        fx.bridge_ed_pk,
        now_unix() + 3600,
        &fx.operator_sk,
    );

    // First extend with the token: accepted.
    let msg3a = client_extend_msg3(&exec, 10, &client_sk, &fx.bridge_x_pk, &token).await;
    exec.verify_extend_finish(10, msg3a).await.unwrap();

    // Second extend re-presenting the SAME token: the shared replay set rejects it.
    let msg3b = client_extend_msg3(&exec, 11, &client_sk, &fx.bridge_x_pk, &token).await;
    let err = exec
        .verify_extend_finish(11, msg3b)
        .await
        .expect_err("a replayed per-hop token must be rejected");
    assert!(err.contains("token verify failed"), "got: {err}");
}

#[tokio::test]
async fn verify_without_prior_handshake_errors() {
    // verify_extend_finish with no retained responder (no perform_handshake)
    // must error, not panic.
    let fx = fixture(0x11, 0x22, 0x33);
    let replay = Arc::new(SyncReplaySet::new(64));
    let exec = relay_executor(&fx, replay);
    let err = exec
        .verify_extend_finish(999, vec![0u8; 315])
        .await
        .expect_err("missing responder must error");
    assert!(err.contains("no pending responder"), "got: {err}");
}

#[tokio::test]
async fn forget_pending_responder_frees_retained_responder() {
    // Memory-DoS fix: a relay circuit torn down BEFORE its EXTEND_FINISH must
    // have its retained handshake responder freed. After perform_handshake
    // retains one, forget_pending_responder drops it, so a later
    // verify_extend_finish finds no responder (proving the leak is closed -
    // the DestroyPrevLink teardown path calls forget in the daemon).
    let fx = fixture(0x11, 0x22, 0x33);
    let replay = Arc::new(SyncReplaySet::new(64));
    let exec = relay_executor(&fx, replay);
    let client_sk = StaticSecret::from([0x44; 32]).to_bytes();

    // Drive CREATE -> perform_handshake retains a responder for circ 42.
    let mut initiator =
        HandshakeInitiator::new_for_circuit_hop(&client_sk, &fx.bridge_x_pk).unwrap();
    let msg1 = initiator.write_message_1().unwrap();
    let _ = exec.perform_handshake(42, msg1).await.unwrap();

    // Tear down before EXTEND_FINISH.
    exec.forget_pending_responder(42).await;

    // The responder is gone -> verify errors with "no pending responder".
    let err = exec
        .verify_extend_finish(42, vec![0u8; 315])
        .await
        .expect_err("responder must have been freed on teardown");
    assert!(err.contains("no pending responder"), "got: {err}");
}
