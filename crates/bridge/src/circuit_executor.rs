//! Real-I/O [`NextHopExecutor`] for Phase 2H.
//!
//! [`BridgeCircuitExecutor`] is constructed once per accepted session
//! (when `circuit_relay_enabled = true`) and shared across all circuits
//! on that session via `Arc`. It implements:
//!
//! - **`perform_handshake`**: runs the bridge-side 2-message circuit
//!   handshake (read msg1 -> write msg2 -> derive HopKeys using
//!   noise_h_after_msg2, matching the client's
//!   `circuit_hop_binding()` call in `extend_hop`). No token
//!   verification at the circuit layer; the session was already
//!   token-authenticated at the transport layer.
//!
//! - **`handle_exit_payload`**: dispatches peeled-at-exit sub-cells
//!   (BEGIN/DATA/END) to real TCP sockets via
//!   [`TcpStreamDispatcher`].
//!
//! - **`open_next_hop`**: when built via [`BridgeCircuitExecutor::with_relay`],
//!   dials the next hop through the injected [`NextHopDialer`], sends the
//!   (fragmented) relayed CMD_CREATE, reassembles the CREATED reply into the
//!   raw `hs_msg2`, and spawns a pump feeding the link's later inbound cells
//!   into the session loop. Relay-disabled executors (`new`) error here.
//!
//! - **`send_to_next`** / **`forward_extend_finish`** / **`destroy_next_link`**:
//!   frame the cell and write it on the `out_circ_id`'s link.
//!
//! The transport + bridge-to-bridge auth model lives behind the injected
//! `NextHopDialer`; the link I/O lives in [`crate::next_hop_link`].

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use mirage_circuit::cell::{Cell, MAX_CELL_PAYLOAD};
use mirage_circuit::{
    ExtendFinishBody, HandshakeBody, HopEndpoint, HopKeys, CMD_CREATE, CMD_CREATED,
    CMD_CREATED_CONT, CMD_CREATE_CONT, CMD_DESTROY, CMD_EXTEND_FINISH,
};
use mirage_crypto::zeroize::Zeroizing;
use mirage_discovery::replay::SyncReplaySet;
use mirage_session::{HandshakeResponder, SessionError, TokenVerifier};
use tokio::sync::{mpsc, Mutex as AsyncMutex};

use crate::next_hop_link::{NextHopDialer, NextHopLink};
use crate::session_task::NextHopExecutor;
use crate::stream_dispatcher::{StreamDispatcher, TcpStreamDispatcher, TcpStreamDispatcherConfig};

/// Buffer for next-hop-inbound cells (CREATED is consumed synchronously by
/// `open_next_hop`; this carries post-extend RELAY/DESTROY traffic from the
/// next hop back into the session loop). Bounded for backpressure.
pub const NEXT_HOP_INBOUND_CAP: usize = 256;

/// Hard deadline on the whole next-hop dial + relayed-CREATE + CREATED
/// reassembly. `open_next_hop` is awaited inline in the session loop, so a
/// next hop that accepts the TCP/transport connection and then stalls
/// mid-handshake would otherwise freeze the entire multiplexed session (and
/// bypass the state-machine's `pending_created` tick reaper, since the bytes
/// never reach the state machine). Bounds it to a finite window.
const RELAY_DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// An established outbound link plus the handle of its inbound-pump task, so
/// teardown can both close the link AND abort the pump (otherwise the pump
/// blocks forever on `link.recv()`, holding the read half + fd alive - a
/// task/socket leak per extended circuit).
type OutLink = (Arc<dyn NextHopLink>, tokio::task::JoinHandle<()>);

/// Bridge keys needed by the executor for per-hop handshakes.
#[derive(Clone)]
pub struct BridgeCircuitKeys {
    /// Bridge X25519 static secret (32 bytes).
    pub bridge_x25519_sk: [u8; 32],
    /// Bridge Ed25519 identity pubkey (32 bytes).
    pub bridge_ed25519_pk: [u8; 32],
    /// Operator Ed25519 verifying key (32 bytes).
    pub operator_ed25519_pk: [u8; 32],
}

/// Phase 2H executor: handles CREATE + exit relay for a single
/// accepted circuit session.
pub struct BridgeCircuitExecutor {
    keys: BridgeCircuitKeys,
    /// Exit-hop TCP dispatcher. Shared across circuits on this
    /// session. Each circuit's stream IDs are globally unique so
    /// there are no cross-circuit collisions in the dispatch map.
    dispatcher: Arc<TcpStreamDispatcher>,
    /// Dials outbound links to next-hop bridges. `None` => relay
    /// disabled (single-hop / exit-only); `open_next_hop` errors.
    dialer: Option<Arc<dyn NextHopDialer>>,
    /// Established outbound links (+ their pump task handles), keyed by
    /// `out_circ_id`. Each carries one extended circuit toward the next hop.
    links: Arc<AsyncMutex<HashMap<u32, OutLink>>>,
    /// Sender feeding next-hop-inbound cells (post-extend RELAY /
    /// DESTROY) into the session loop's `process_inbound_from_next`.
    /// `None` when relay is disabled.
    inbound_tx: Option<mpsc::Sender<Cell>>,
    /// Per-hop token verification (extended-hop / relay sessions only). When
    /// `Some`, `perform_handshake` retains the handshake responder keyed by
    /// circ_id so a later `CMD_EXTEND_FINISH` can be token-verified via
    /// `read_message_3`; `None` (direct-client entry sessions) drops the
    /// responder after msg-2 as before. Enabled by [`Self::with_token_verification`].
    token_verify: Option<TokenVerifyCtx>,
    /// Responders retained between `perform_handshake` (msg-2) and
    /// `verify_extend_finish` (msg-3), keyed by in_circ_id. Only populated
    /// when `token_verify` is `Some`.
    pending_responders: Arc<AsyncMutex<HashMap<u32, HandshakeResponder>>>,
}

/// Context an extended-hop executor needs to verify a client's per-hop
/// capability token in `CMD_EXTEND_FINISH`.
#[derive(Clone)]
struct TokenVerifyCtx {
    /// Shared token-replay set (the SAME set the bridge's direct-client
    /// sessions use, so a token can't be replayed across the two paths).
    replay_set: Arc<SyncReplaySet>,
    /// Previous operator Ed25519 key accepted during a mother-key rotation
    /// overlap window (mirrors the transport handshake's Path A').
    operator_pk_prev: Option<[u8; 32]>,
}

/// Build the exit dispatcher policy from the two *independent* opt-ins.
/// Loopback and RFC1918/private are gated separately (RT-SD-5 / #32) so an
/// operator who enables one never silently re-admits the other, and
/// always-forbidden ranges (link-local / cloud metadata / multicast) are
/// rejected regardless of either flag.
fn exit_dispatcher_cfg(allow_private: bool, allow_loopback: bool) -> TcpStreamDispatcherConfig {
    TcpStreamDispatcherConfig {
        allow_private_destinations: allow_private,
        allow_loopback_destinations: allow_loopback,
        ..TcpStreamDispatcherConfig::default()
    }
}

impl BridgeCircuitExecutor {
    /// Construct a single-hop / exit-only executor (relay disabled).
    ///
    /// Returns `(executor, exit_events_rx)`. Pass `exit_events_rx` to
    /// [`crate::session_task::SessionTask::with_exit_events`] so upstream TCP
    /// responses route back to the circuit client.
    pub fn new(
        keys: BridgeCircuitKeys,
        allow_private: bool,
        allow_loopback: bool,
    ) -> (
        Self,
        tokio::sync::mpsc::Receiver<crate::stream_dispatcher::StreamEvent>,
    ) {
        let cfg = exit_dispatcher_cfg(allow_private, allow_loopback);
        let (dispatcher, events_rx) = TcpStreamDispatcher::with_config(cfg);
        let executor = Self {
            keys,
            dispatcher: Arc::new(dispatcher),
            dialer: None,
            links: Arc::new(AsyncMutex::new(HashMap::new())),
            inbound_tx: None,
            token_verify: None,
            pending_responders: Arc::new(AsyncMutex::new(HashMap::new())),
        };
        (executor, events_rx)
    }

    /// Enable per-hop capability-token verification (extended-hop / relay
    /// sessions). When set, `perform_handshake` retains the handshake responder
    /// so a later `CMD_EXTEND_FINISH` is token-verified against `replay_set` +
    /// the executor's operator key (and `operator_pk_prev` during a rotation
    /// overlap). Consuming builder - apply before wrapping the executor in `Arc`.
    #[must_use]
    pub fn with_token_verification(
        mut self,
        replay_set: Arc<SyncReplaySet>,
        operator_pk_prev: Option<[u8; 32]>,
    ) -> Self {
        self.token_verify = Some(TokenVerifyCtx {
            replay_set,
            operator_pk_prev,
        });
        self
    }

    /// Construct a RELAY-capable executor backed by `dialer`.
    ///
    /// Returns `(executor, exit_events_rx, next_hop_inbound_rx)`. Wire
    /// `exit_events_rx` via `with_exit_events` (if this hop can also be an
    /// exit) and `next_hop_inbound_rx` via
    /// [`crate::session_task::SessionTask::with_next_hop_events`] so cells the
    /// next hop sends back reach `process_inbound_from_next`.
    pub fn with_relay(
        keys: BridgeCircuitKeys,
        allow_private: bool,
        allow_loopback: bool,
        dialer: Arc<dyn NextHopDialer>,
    ) -> (
        Self,
        tokio::sync::mpsc::Receiver<crate::stream_dispatcher::StreamEvent>,
        mpsc::Receiver<Cell>,
    ) {
        let cfg = exit_dispatcher_cfg(allow_private, allow_loopback);
        let (dispatcher, events_rx) = TcpStreamDispatcher::with_config(cfg);
        let (inbound_tx, inbound_rx) = mpsc::channel(NEXT_HOP_INBOUND_CAP);
        let executor = Self {
            keys,
            dispatcher: Arc::new(dispatcher),
            dialer: Some(dialer),
            links: Arc::new(AsyncMutex::new(HashMap::new())),
            inbound_tx: Some(inbound_tx),
            token_verify: None,
            pending_responders: Arc::new(AsyncMutex::new(HashMap::new())),
        };
        (executor, events_rx, inbound_rx)
    }
}

#[async_trait]
impl NextHopExecutor for BridgeCircuitExecutor {
    /// This executor verifies per-hop tokens iff it was built with
    /// [`Self::with_token_verification`]. `SessionTask::run` couples this to the
    /// state machine's relay mode and fails closed on a mismatch (#5).
    fn supports_token_verification(&self) -> bool {
        self.token_verify.is_some()
    }

    /// Run the bridge-side circuit-hop handshake: read msg1 -> write msg2 ->
    /// derive HopKeys from noise_h_after_msg2.
    ///
    /// # Per-hop token verification
    ///
    /// This derives HopKeys at msg-2, but the client's capability token rides in
    /// msg-3 (delivered later as `CMD_EXTEND_FINISH`). On an EXTENDED-hop / relay
    /// session (`with_token_verification` enabled), the handshake responder is
    /// RETAINED here in `AwaitMessage3` state so [`Self::verify_extend_finish`]
    /// can run `read_message_3` against that msg-3 and verify the per-hop token
    /// before the circuit is allowed to serve traffic (the state machine gates
    /// exit/extend on [`BridgeCircuitState::record_token_verified`]). On a direct-
    /// client entry session the responder is dropped after msg-2 as before - the
    /// transport handshake already token-authenticated that client.
    async fn perform_handshake(
        &self,
        in_circ_id: u32,
        hs_msg1: Vec<u8>,
    ) -> Result<(HopKeys, Vec<u8>), String> {
        // create_responder is cheap (in-memory) so it's OK to
        // construct fresh per call.
        let mut responder = HandshakeResponder::new(
            &self.keys.bridge_x25519_sk,
            &self.keys.bridge_ed25519_pk,
            &self.keys.operator_ed25519_pk,
        )
        .map_err(|e: SessionError| {
            format!("circuit handshake (circ={in_circ_id}): responder init: {e}")
        })?;

        responder
            .read_message_1(&hs_msg1)
            .map_err(|e| format!("circuit handshake (circ={in_circ_id}): read_msg1: {e}"))?;

        // write_message_2_for_circuit_hop returns (hs_msg2, mlkem_ss,
        // circuit_binding) where circuit_binding uses noise_h_after_msg2 -
        // the same point HandshakeInitiator::circuit_hop_binding uses on
        // the client side. Both parties derive identical HopKeys.
        let (hs_msg2, mlkem_ss, circuit_binding) = responder
            .write_message_2_for_circuit_hop()
            .map_err(|e| format!("circuit handshake (circ={in_circ_id}): write_msg2: {e}"))?;

        // Zeroize mlkem_ss after use. The binding already captures its
        // entropy; holding the raw SS post-derive leaks nothing material
        // but zero-on-drop is defense-in-depth.
        let mlkem_ss_z = Zeroizing::new(mlkem_ss);
        let hop_keys =
            mirage_circuit::derive_hop_keys_from_handshake(&mlkem_ss_z, &circuit_binding);

        // On a relay / extended-hop session, retain the responder (still in
        // AwaitMessage3) so the forthcoming CMD_EXTEND_FINISH msg-3 can be
        // token-verified. On a direct-client session the responder drops here.
        if self.token_verify.is_some() {
            self.pending_responders
                .lock()
                .await
                .insert(in_circ_id, responder);
        }

        tracing::debug!(
            circ_id = in_circ_id,
            "circuit handshake complete: hop keys derived"
        );
        Ok((hop_keys, hs_msg2))
    }

    /// Verify a terminal relay-session circuit's per-hop capability token from
    /// its `CMD_EXTEND_FINISH` msg-3. Pops the responder retained by
    /// `perform_handshake` and runs `read_message_3` with a `TokenVerifier`
    /// (operator key + optional prev-operator key + the shared replay set). A
    /// missing responder, an absent/short (no-token) msg-3, a bad signature, a
    /// wrong-bridge/expired token, or a replay all yield `Err`.
    async fn verify_extend_finish(&self, in_circ_id: u32, hs_msg3: Vec<u8>) -> Result<(), String> {
        let ctx = self
            .token_verify
            .as_ref()
            .ok_or_else(|| format!("circuit {in_circ_id}: token verification not enabled"))?;
        let responder = self
            .pending_responders
            .lock()
            .await
            .remove(&in_circ_id)
            .ok_or_else(|| {
                format!("circuit {in_circ_id}: no pending responder for EXTEND_FINISH")
            })?;

        // Fail CLOSED on a broken clock, matching the transport handshake path.
        // A pre-UNIX_EPOCH clock would yield now_unix=0, and 0 < every token's
        // expires_at, so is_expired() would accept EVERY expired per-hop token -
        // disabling the sole freshness control on this hop's authorization.
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_| {
                format!(
                    "circuit {in_circ_id}: bridge clock before UNIX_EPOCH; refusing \
                     per-hop token verify (would disable token expiry)"
                )
            })?;
        let mut verifier = TokenVerifier::new_shared(&ctx.replay_set, now_unix);
        if let Some(prev) = ctx.operator_pk_prev.as_ref() {
            verifier = verifier.with_prev_operator(prev);
        }
        // Circuit hops do NOT accept bridge-self-signed refresh tokens - only
        // operator-signed bootstrap/cohort tokens authorize an extended hop.
        responder
            .read_message_3(&hs_msg3, &mut verifier)
            .map(|_session_keys| ())
            .map_err(|e| format!("circuit {in_circ_id}: per-hop token verify failed: {e}"))
    }

    /// Drop a retained responder for a circuit reaped before its
    /// `CMD_EXTEND_FINISH` arrived (idle/timeout teardown), so relay sessions
    /// don't accumulate pending responders for the session's lifetime.
    async fn forget_pending_responder(&self, in_circ_id: u32) {
        if self.token_verify.is_some() {
            self.pending_responders.lock().await.remove(&in_circ_id);
        }
    }

    /// Dispatch a peeled exit-hop sub-cell payload to a TCP socket.
    async fn handle_exit_payload(&self, in_circ_id: u32, payload: Vec<u8>) -> Result<(), String> {
        self.dispatcher
            .dispatch(&payload)
            .await
            .map_err(|e| format!("exit dispatch (circ={in_circ_id}): {e}"))
    }

    /// Dial the next hop, relay the (fragmented) CREATE, and reassemble the
    /// CREATED into the raw `hs_msg2` returned to the caller. After the
    /// handshake the link's inbound cells (RELAY/DESTROY) are pumped into the
    /// session loop via the next-hop-inbound channel.
    ///
    /// `out_circ_id` stamps every cell on the Bridge->next-hop link and keys
    /// the link in `self.links`, matching `SendToNext`/`DestroyNextLink`.
    async fn open_next_hop(
        &self,
        in_circ_id: u32,
        out_circ_id: u32,
        next_hop_pk: [u8; 32],
        endpoint: HopEndpoint,
        hs_msg1: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        let dialer = self
            .dialer
            .as_ref()
            .ok_or_else(|| format!("open_next_hop: relay disabled (circ={in_circ_id})"))?;
        let inbound_tx = self
            .inbound_tx
            .clone()
            .ok_or_else(|| "open_next_hop: missing inbound channel".to_string())?;

        // The whole dial + relayed-CREATE + CREATED reassembly is awaited
        // inline in the session loop, so it MUST be bounded - a next hop that
        // connects then stalls would freeze every sibling circuit otherwise.
        let dial_and_handshake = async {
            let link = dialer.dial(next_hop_pk, endpoint).await?;

            // Send the relayed CREATE, fragmenting hs_msg1 (it exceeds one cell).
            let (first, conts) = HandshakeBody { hs_msg: hs_msg1 }
                .encode_fragmented(MAX_CELL_PAYLOAD)
                .map_err(|e| format!("open_next_hop: encode CREATE (circ={in_circ_id}): {e}"))?;
            let create = Cell::new(out_circ_id, CMD_CREATE, first)
                .map_err(|e| format!("open_next_hop: CREATE cell: {e}"))?;
            link.send(create).await?;
            for cont in conts {
                let c = Cell::new(out_circ_id, CMD_CREATE_CONT, cont)
                    .map_err(|e| format!("open_next_hop: CREATE_CONT cell: {e}"))?;
                link.send(c).await?;
            }

            // Read + reassemble the CREATED reply into raw hs_msg2.
            let hs_msg2 = read_created(&link, out_circ_id).await?;
            Ok::<(Arc<dyn NextHopLink>, Vec<u8>), String>((link, hs_msg2))
        };
        let (link, hs_msg2) = tokio::time::timeout(RELAY_DIAL_TIMEOUT, dial_and_handshake)
            .await
            .map_err(|_| {
                format!("open_next_hop: relay dial/handshake timed out (circ={in_circ_id})")
            })??;

        // Pump the link's remaining inbound cells (post-extend RELAY/DESTROY)
        // into the session loop. Keep the handle so `destroy_next_link` can
        // abort it - otherwise the pump blocks on `recv()` forever, leaking
        // the task + read half + fd after the circuit is torn down.
        let pump_link = link.clone();
        let pump = tokio::spawn(async move {
            while let Some(cell) = pump_link.recv().await {
                if inbound_tx.send(cell).await.is_err() {
                    break; // session gone
                }
            }
        });
        self.links.lock().await.insert(out_circ_id, (link, pump));

        Ok(hs_msg2)
    }

    async fn send_to_next(&self, out_circ_id: u32, cell: Cell) -> Result<(), String> {
        let link = {
            let g = self.links.lock().await;
            g.get(&out_circ_id).map(|(l, _)| l.clone())
        };
        let link =
            link.ok_or_else(|| format!("send_to_next: no link for out_circ={out_circ_id}"))?;
        link.send(cell).await
    }

    async fn forward_extend_finish(
        &self,
        out_circ_id: u32,
        hs_msg3: Vec<u8>,
    ) -> Result<(), String> {
        let link = {
            let g = self.links.lock().await;
            g.get(&out_circ_id).map(|(l, _)| l.clone())
        };
        let link = link
            .ok_or_else(|| format!("forward_extend_finish: no link for out_circ={out_circ_id}"))?;
        let body = ExtendFinishBody { hs_msg3 }
            .encode()
            .map_err(|e| format!("forward_extend_finish: encode (out_circ={out_circ_id}): {e}"))?;
        let cell = Cell::new(out_circ_id, CMD_EXTEND_FINISH, body)
            .map_err(|e| format!("forward_extend_finish: cell: {e}"))?;
        link.send(cell).await
    }

    async fn destroy_next_link(&self, out_circ_id: u32) -> Result<(), String> {
        let entry = self.links.lock().await.remove(&out_circ_id);
        if let Some((link, pump)) = entry {
            // Best-effort DESTROY then close; ignore errors (peer may be gone).
            if let Ok(cell) = Cell::new(out_circ_id, CMD_DESTROY, vec![]) {
                let _ = link.send(cell).await;
            }
            link.close().await;
            // Abort the pump so it stops blocking on `recv()` and releases the
            // link's read half; dropping the last Arc here closes the fd.
            pump.abort();
        }
        Ok(())
    }
}

/// Read a `CMD_CREATED` (+ `CMD_CREATED_CONT`) flight from `link` and
/// reassemble the raw `hs_msg2`. Mirrors the bridge state machine's inbound
/// CREATED reassembly so the caller hands `record_extend_complete` the decoded
/// bytes.
async fn read_created(link: &Arc<dyn NextHopLink>, out_circ_id: u32) -> Result<Vec<u8>, String> {
    let first = link
        .recv()
        .await
        .ok_or_else(|| format!("read_created: link closed before CREATED (out={out_circ_id})"))?;
    if first.command != CMD_CREATED {
        return Err(format!(
            "read_created: expected CMD_CREATED, got cmd={} (out={out_circ_id})",
            first.command
        ));
    }
    let (total_len, first_chunk) = HandshakeBody::decode_partial(&first.body)
        .map_err(|e| format!("read_created: decode CREATED (out={out_circ_id}): {e}"))?;
    let mut hs_msg2 = first_chunk.to_vec();
    while hs_msg2.len() < total_len {
        let cont = link.recv().await.ok_or_else(|| {
            format!("read_created: link closed mid-fragmentation (out={out_circ_id})")
        })?;
        if cont.command != CMD_CREATED_CONT {
            return Err(format!(
                "read_created: expected CMD_CREATED_CONT, got cmd={} (out={out_circ_id})",
                cont.command
            ));
        }
        if hs_msg2.len() + cont.body.len() > total_len {
            return Err(format!(
                "read_created: CREATED overflow (out={out_circ_id})"
            ));
        }
        hs_msg2.extend_from_slice(&cont.body);
    }
    Ok(hs_msg2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_circuit::CMD_RELAY;
    use std::collections::VecDeque;

    /// In-memory next-hop link: records what the executor sends, and
    /// delivers a pre-loaded queue of inbound cells via `recv`.
    struct MockLink {
        sent: AsyncMutex<Vec<Cell>>,
        inbound: AsyncMutex<VecDeque<Cell>>,
    }

    #[async_trait]
    impl NextHopLink for MockLink {
        async fn send(&self, cell: Cell) -> Result<(), String> {
            self.sent.lock().await.push(cell);
            Ok(())
        }
        async fn recv(&self) -> Option<Cell> {
            self.inbound.lock().await.pop_front()
        }
        async fn close(&self) {}
    }

    struct MockDialer {
        link: Arc<MockLink>,
    }

    #[async_trait]
    impl NextHopDialer for MockDialer {
        async fn dial(
            &self,
            _next_hop_pk: [u8; 32],
            _endpoint: HopEndpoint,
        ) -> Result<Arc<dyn NextHopLink>, String> {
            Ok(self.link.clone())
        }
    }

    fn fake_keys() -> BridgeCircuitKeys {
        BridgeCircuitKeys {
            bridge_x25519_sk: [1u8; 32],
            bridge_ed25519_pk: [2u8; 32],
            operator_ed25519_pk: [3u8; 32],
        }
    }

    #[test]
    fn supports_token_verification_reflects_builder() {
        // #5: the exit-only / relay-without-tokens executors report NO token
        // verification; only with_token_verification flips it on. SessionTask
        // couples this to relay mode and fails closed on a mismatch.
        let (exit_only, _rx) = BridgeCircuitExecutor::new(fake_keys(), true, true);
        assert!(!exit_only.supports_token_verification());

        let dialer = Arc::new(MockDialer {
            link: Arc::new(MockLink {
                sent: AsyncMutex::new(Vec::new()),
                inbound: AsyncMutex::new(VecDeque::new()),
            }),
        });
        let (relay_no_tokens, _rx2, _rx3) =
            BridgeCircuitExecutor::with_relay(fake_keys(), true, true, dialer);
        assert!(!relay_no_tokens.supports_token_verification());

        let (verifying, _rx4) = BridgeCircuitExecutor::new(fake_keys(), true, true);
        let verifying = verifying.with_token_verification(Arc::new(SyncReplaySet::new(128)), None);
        assert!(verifying.supports_token_verification());
    }

    #[tokio::test]
    async fn relay_open_next_hop_reassembles_fragmented_created_and_pumps_inbound() {
        let out = 99u32;
        // hop2's hs_msg2, sized to force CREATED fragmentation.
        let hs_msg2: Vec<u8> = (0..1189u32)
            .map(|i| (i.wrapping_mul(7) % 251) as u8)
            .collect();
        let (first, conts) = HandshakeBody {
            hs_msg: hs_msg2.clone(),
        }
        .encode_fragmented(MAX_CELL_PAYLOAD)
        .unwrap();
        assert!(!conts.is_empty(), "test must exercise fragmentation");

        // Pre-load the link's inbound: the CREATED flight, then one
        // post-extend RELAY cell the pump should forward.
        let mut inbound = VecDeque::new();
        inbound.push_back(Cell::new(out, CMD_CREATED, first).unwrap());
        for c in conts {
            inbound.push_back(Cell::new(out, CMD_CREATED_CONT, c).unwrap());
        }
        inbound.push_back(Cell::new(out, CMD_RELAY, vec![0xEE; 32]).unwrap());

        let link = Arc::new(MockLink {
            sent: AsyncMutex::new(Vec::new()),
            inbound: AsyncMutex::new(inbound),
        });
        let dialer = Arc::new(MockDialer { link: link.clone() });
        let (executor, _exit_rx, mut inbound_rx) =
            BridgeCircuitExecutor::with_relay(fake_keys(), true, true, dialer);

        // Dial + relay CREATE + reassemble CREATED.
        let hs_msg1 = vec![0xABu8; 1200]; // also fragments on the way out
        let endpoint = HopEndpoint::Ipv4 {
            addr: [127, 0, 0, 1],
            port: 443,
        };
        let got = executor
            .open_next_hop(7, out, [0x42u8; 32], endpoint, hs_msg1)
            .await
            .expect("open_next_hop");
        assert_eq!(got, hs_msg2, "executor recovers the exact hs_msg2");

        // The relayed CREATE was sent, fragmented, stamped with out_circ_id.
        let sent = link.sent.lock().await;
        assert_eq!(sent[0].command, CMD_CREATE);
        assert_eq!(sent[0].circ_id, out);
        assert!(
            sent.iter().any(|c| c.command == CMD_CREATE_CONT),
            "large hs_msg1 must fragment on the CREATE path"
        );
        drop(sent);

        // The pump forwards the post-extend RELAY cell into the session loop.
        let pumped = inbound_rx.recv().await.expect("pumped cell");
        assert_eq!(pumped.command, CMD_RELAY);
        assert_eq!(pumped.circ_id, out);

        // send_to_next writes onto the same link.
        executor
            .send_to_next(out, Cell::new(out, CMD_RELAY, vec![1, 2, 3]).unwrap())
            .await
            .unwrap();
        assert!(link
            .sent
            .lock()
            .await
            .iter()
            .any(|c| c.command == CMD_RELAY));
    }

    #[tokio::test]
    async fn relay_disabled_executor_errors_on_open_next_hop() {
        let (executor, _exit_rx) = BridgeCircuitExecutor::new(fake_keys(), true, true);
        let endpoint = HopEndpoint::Ipv4 {
            addr: [127, 0, 0, 1],
            port: 443,
        };
        let err = executor
            .open_next_hop(7, 99, [0x42u8; 32], endpoint, vec![0u8; 10])
            .await
            .unwrap_err();
        assert!(err.contains("relay disabled"));
    }
}
