//! Per-session circuit-aware task (Phase 2H).
//!
//! Once an inbound `mirage_session::SessionStream` is established
//! (via `mirage_session::accept` against a Reality-v2 / obfs-tcp
//! transport), the daemon hands it to a [`SessionTask`]. The
//! task:
//!
//! 1. Owns a [`mirage_circuit::bridge_circuit::BridgeCircuitState`].
//! 2. Loops reading cells from the session.
//! 3. Dispatches each cell to the state machine.
//! 4. Executes emitted [`mirage_circuit::bridge_circuit::BridgeAction`]s
//!    against the prev-hop session and (via a runtime callback)
//!    next-hop transports.
//! 5. Periodically calls `state.tick(now)` to sweep idle / stuck
//!    circuits.
//!
//! Phase 2H ships the framework + a tested in-process
//! integration. Phase 2I adds:
//!
//! - Real next-hop dialing via [`mirage_runtime`].
//! - Stream dispatch (`RelayPayloadAtExit` -> TCP socket I/O).
//! - The `Daemon` top-level that owns many `SessionTask`s.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use mirage_circuit::bridge_circuit::{
    BridgeAction, BridgeCircuitError, BridgeCircuitState, BridgePolicy,
};
use mirage_circuit::cell::Cell;
use mirage_circuit::{CMD_BEGIN, CMD_DATA, CMD_END};
use mirage_runtime::cell_io::{read_cell, write_cell, CellIoError};
use mirage_session::SessionStream;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc::Receiver;

use crate::stream_dispatcher::{BeginBody, DataBody, EndBody, StreamEvent};

/// Configuration for a [`SessionTask`].
#[derive(Debug, Clone)]
pub struct SessionTaskConfig {
    /// Bridge-side state-machine policy. Caps + timeouts.
    pub policy: BridgePolicy,
    /// Period between automatic `state.tick()` sweeps. Default
    /// 1 s - short enough to reap stuck reassemblies (which use
    /// `pending_extend_timeout` >= 10 s by default) within one
    /// sweep window of the timeout, long enough to keep tick
    /// overhead negligible.
    pub tick_interval: Duration,
    /// Per-cell read deadline. The session-level handshake
    /// already has its own timeout; this guards against a peer
    /// that establishes a session and then stalls without
    /// sending cells. `None` = wait forever (rely on
    /// `policy.idle_ttl` to reap on a longer horizon).
    pub cell_read_timeout: Option<Duration>,
}

impl Default for SessionTaskConfig {
    fn default() -> Self {
        Self {
            policy: BridgePolicy::default(),
            tick_interval: Duration::from_secs(1),
            cell_read_timeout: Some(Duration::from_secs(60)),
        }
    }
}

/// Errors produced by a `SessionTask`.
#[derive(Debug, Error)]
pub enum DaemonError {
    /// Inbound cell I/O failure (truncated cell, transport
    /// reset, etc.).
    #[error("cell I/O: {0}")]
    Io(#[from] CellIoError),
    /// State-machine rejected an inbound cell. The task tears
    /// down the session - peer protocol violation.
    #[error("bridge state: {0}")]
    Bridge(#[from] BridgeCircuitError),
    /// Read deadline elapsed.
    #[error("cell read deadline elapsed")]
    ReadTimeout,
    /// `NextHopExecutor` rejected an action (transport dial
    /// failed, etc.).
    #[error("next-hop dispatch: {0}")]
    NextHop(String),
    /// Relay mode and the executor's token-verification capability disagree
    /// (#5). Fail-closed at startup rather than serve circuits with an
    /// unenforced per-hop token gate.
    #[error("relay misconfigured: relay_mode={relay_mode} but executor token-verification={token_verify}; they must match")]
    RelayMisconfigured {
        /// State-machine relay mode.
        relay_mode: bool,
        /// Whether the executor verifies per-hop tokens.
        token_verify: bool,
    },
}

/// Trait the runtime implements to execute next-hop-side actions
/// emitted by the state machine. Tests inject a mock impl; the real
/// implementation is [`crate::circuit_executor::BridgeCircuitExecutor`]
/// (exit-only via `new`, or relay-capable via `with_relay`, which dials
/// the next hop and forwards cells over a [`crate::next_hop_link::NextHopLink`]).
#[async_trait::async_trait]
pub trait NextHopExecutor: Send + Sync {
    /// Dial a fresh outbound link to `next_hop_pk` at `endpoint`
    /// using `transport`, run the per-hop Mirage handshake, and
    /// send `hs_msg1` as a `CMD_CREATE` cell. The implementation
    /// reads `CMD_CREATED` back and calls
    /// `state.record_extend_complete(in_circ_id, hs_msg2, now)`
    /// - but Phase 2H tests cheat: the executor synthesises a
    /// canned `hs_msg2` for state-machine drive-through.
    async fn open_next_hop(
        &self,
        in_circ_id: u32,
        out_circ_id: u32,
        next_hop_pk: [u8; 32],
        endpoint: mirage_circuit::HopEndpoint,
        hs_msg1: Vec<u8>,
    ) -> Result<Vec<u8>, String>;

    /// Send `cell` on the next-hop link for `out_circ_id`.
    async fn send_to_next(&self, out_circ_id: u32, cell: Cell) -> Result<(), String>;

    /// Forward `hs_msg3` to the next-hop link for `out_circ_id`
    /// as a `CMD_EXTEND_FINISH` cell. Phase 2G addition (closes
    /// [RT-O2]).
    async fn forward_extend_finish(&self, out_circ_id: u32, hs_msg3: Vec<u8>)
        -> Result<(), String>;

    /// Tear down the next-hop link for `out_circ_id`.
    async fn destroy_next_link(&self, out_circ_id: u32) -> Result<(), String>;

    /// Dispatch payload at the exit (terminal) hop. Phase 2I
    /// wires this to TCP socket I/O via a stream dispatcher.
    /// Phase 2H tests record-only.
    async fn handle_exit_payload(&self, in_circ_id: u32, payload: Vec<u8>) -> Result<(), String>;

    /// Run the responder side of the per-hop handshake at THIS
    /// bridge (when this is the first hop and `BridgeAction::PerformHandshake`
    /// is emitted). Phase 2H tests provide canned keys.
    async fn perform_handshake(
        &self,
        in_circ_id: u32,
        hs_msg1: Vec<u8>,
    ) -> Result<(mirage_circuit::HopKeys, Vec<u8>), String>;

    /// Verify the client's `CMD_EXTEND_FINISH` message-3 for a TERMINAL
    /// relay-session circuit (this bridge is an extended hop). The executor
    /// runs the retained handshake responder's `read_message_3` against
    /// `hs_msg3` with a `TokenVerifier`, checking the per-hop capability
    /// token's signature, bridge-binding, expiry, and replay. `Ok(())` means
    /// the token is valid - the driver then calls
    /// `state.record_token_verified` to unlock the circuit. `Err(_)` (bad /
    /// absent / replayed token) means the circuit must be torn down.
    async fn verify_extend_finish(&self, in_circ_id: u32, hs_msg3: Vec<u8>) -> Result<(), String>;

    /// Drop any handshake responder retained for `in_circ_id` when the circuit
    /// is reaped before its `CMD_EXTEND_FINISH` arrives. Default: no-op (only
    /// token-verifying relay executors retain responders).
    async fn forget_pending_responder(&self, _in_circ_id: u32) {}

    /// Whether this executor enforces per-hop capability-token verification on
    /// `CMD_EXTEND_FINISH` (i.e. it was built with
    /// [`crate::circuit_executor::BridgeCircuitExecutor::with_token_verification`]).
    ///
    /// [`SessionTask::run`] fails closed unless this MATCHES the state
    /// machine's relay mode (#5): a relay-mode session whose executor does not
    /// verify tokens, OR a token-verifying executor driven in non-relay mode
    /// (where circuits start `token_verified = true` and the executor's
    /// verification is silently bypassed), is a per-hop-authorization hole and
    /// must never run. Default `false` (a non-verifying executor).
    fn supports_token_verification(&self) -> bool {
        false
    }
}

/// Fail-closed coupling check (#5): a relay-mode session MUST be paired with a
/// token-verifying executor, and a token-verifying executor MUST be driven in
/// relay mode. `with_relay_mode` (state machine) and `with_token_verification`
/// (executor) are set independently, and either mismatch is a per-hop
/// authorization hole: relay mode without verification lets an extended hop
/// exit/extend un-authorized; a verifying executor in non-relay mode has every
/// circuit start `token_verified = true`, silently bypassing the gate. Called
/// once at [`SessionTask::run`] startup so the session refuses to serve rather
/// than run with the gate unenforced.
fn check_relay_token_coupling(relay_mode: bool, token_verify: bool) -> Result<(), DaemonError> {
    if relay_mode != token_verify {
        return Err(DaemonError::RelayMisconfigured {
            relay_mode,
            token_verify,
        });
    }
    Ok(())
}

/// One-tokio-task-per-session circuit-aware actor.
///
/// Runs `Self::run` to completion: returns `Ok(())` on clean
/// session close (peer dropped the connection), `Err(_)` on
/// protocol violation or I/O failure.
pub struct SessionTask<S, E>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    E: NextHopExecutor,
{
    state: BridgeCircuitState,
    session: SessionStream<S>,
    executor: Arc<E>,
    config: SessionTaskConfig,
    /// Upstream TCP events from the exit-hop stream dispatcher.
    /// `None` in relay-only mode (no TCP exit). Set via
    /// [`Self::with_exit_events`] when this is an exit hop.
    exit_events: Option<Receiver<StreamEvent>>,
    /// Maps `stream_id -> in_circ_id` for the exit return path.
    /// Updated in `execute_actions` as BEGIN/END sub-cells flow
    /// through `RelayPayloadAtExit` actions.
    stream_to_circ: HashMap<u16, u32>,
    /// Next-hop-inbound cells (post-extend RELAY/DESTROY the next hop
    /// sent back). `None` in single-hop / exit-only mode. Fed by the
    /// relay executor's per-link pump; drained by the run loop into
    /// `process_inbound_from_next`.
    next_hop_events: Option<Receiver<Cell>>,
}

impl<S, E> SessionTask<S, E>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    E: NextHopExecutor,
{
    /// Construct.
    pub fn new(session: SessionStream<S>, executor: Arc<E>, config: SessionTaskConfig) -> Self {
        let state = BridgeCircuitState::new(config.policy.clone());
        Self {
            state,
            session,
            executor,
            config,
            exit_events: None,
            stream_to_circ: HashMap::new(),
            next_hop_events: None,
        }
    }

    /// Attach the next-hop-inbound receiver so cells the next hop sends back
    /// (post-extend) are relayed to the client. Call after [`new`] when this
    /// session is relay-capable (its executor was built with
    /// [`crate::circuit_executor::BridgeCircuitExecutor::with_relay`]).
    pub fn with_next_hop_events(mut self, rx: Receiver<Cell>) -> Self {
        self.next_hop_events = Some(rx);
        self
    }

    /// Attach the exit-hop event receiver so upstream TCP responses are
    /// routed back to the circuit client. Call immediately after [`new`]
    /// when this session acts as an exit hop (1-hop circuit mode).
    pub fn with_exit_events(mut self, rx: Receiver<StreamEvent>) -> Self {
        self.exit_events = Some(rx);
        self
    }

    /// Mark this session as a RELAY link (this bridge is an EXTENDED hop
    /// reached through another bridge). Circuits created on it require per-hop
    /// capability-token verification (via `CMD_EXTEND_FINISH`) before they may
    /// exit-dispatch or extend further. The executor MUST have been built with
    /// `BridgeCircuitExecutor::with_token_verification` so the msg-3 responder
    /// is retained + verified. Call immediately after [`new`].
    pub fn with_relay_mode(mut self) -> Self {
        self.state.set_relay_mode(true);
        self
    }

    /// Run the session loop to completion. Returns when:
    /// - The peer closes the session cleanly (read returns EOF).
    /// - A cell read times out past `cell_read_timeout`.
    /// - A protocol violation surfaces from the state machine.
    /// - A next-hop dispatch fails fatally.
    pub async fn run(mut self) -> Result<(), DaemonError> {
        // Fail-closed coupling (#5): relay mode and the executor's
        // token-verification capability MUST agree. `with_relay_mode` (state
        // machine) and `with_token_verification` (executor) are set
        // independently, so a misconfiguration - relay mode without a verifying
        // executor, OR a verifying executor left in non-relay mode where every
        // circuit starts `token_verified = true` and the gate is bypassed - is
        // a per-hop-authorization hole. Refuse to start rather than serve
        // circuits with an unenforced token gate.
        check_relay_token_coupling(
            self.state.is_relay_mode(),
            self.executor.supports_token_verification(),
        )?;

        let mut tick_interval = tokio::time::interval(self.config.tick_interval);
        // Closes [RT-H12]: default `MissedTickBehavior::Burst`
        // would replay missed ticks back-to-back if
        // `execute_actions` ever overruns one period - useless
        // (tick is idempotent) and bursty in CPU profiles.
        // `Delay` skips missed ticks and rephases to "now + period".
        tick_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // `interval()` fires immediately; skip the first tick so
        // we don't redundantly sweep at startup.
        tick_interval.tick().await;

        loop {
            tokio::select! {
                cell_result = read_cell_with_timeout(&mut self.session, self.config.cell_read_timeout) => {
                    match cell_result {
                        Ok(Some(cell)) => {
                            let now = std::time::Instant::now();
                            let circ_id = cell.circ_id;
                            // RT #3: a per-circuit state-machine error (bad onion
                            // cell, BadState, ExtendOverflow, SeqExhausted, ...) is
                            // circuit-LOCAL, not session-fatal. Propagating it here
                            // killed the whole multiplexed session - a cross-circuit
                            // DoS (one bad cell drops every sibling circuit) and an
                            // active-probe tell (one malformed cell instantly RSTs
                            // the TCP connection, unlike a real TLS/HTTP server).
                            // Reap only the offending circuit and keep serving.
                            match self.state.process_inbound_from_prev(cell, now) {
                                Ok(actions) => self.execute_actions(actions).await?,
                                Err(e) => {
                                    tracing::debug!(
                                        circ_id,
                                        error = %e,
                                        "per-circuit error; reaping circuit, session continues"
                                    );
                                    let actions = self.state.reap_circuit(circ_id, now);
                                    self.execute_actions(actions).await?;
                                }
                            }
                        }
                        Ok(None) => {
                            // EOF - peer closed cleanly.
                            return Ok(());
                        }
                        Err(DaemonError::ReadTimeout) => {
                            return Err(DaemonError::ReadTimeout);
                        }
                        Err(e) => return Err(e),
                    }
                }
                // Exit-hop return path: upstream TCP data -> sealed
                // RELAY cell -> client. `recv_exit_event` is a no-op
                // future when exit_events is None (relay-only mode).
                Some(event) = recv_exit_event(&mut self.exit_events) => {
                    self.handle_exit_event(event).await?;
                }
                // Relay return path: a cell the NEXT hop sent back
                // (post-extend RELAY/DESTROY) -> state machine -> SendToPrev
                // to the client. No-op future when next_hop_events is None.
                Some(cell) = recv_next_hop_cell(&mut self.next_hop_events) => {
                    let now = std::time::Instant::now();
                    let out_circ_id = cell.circ_id;
                    match self.state.process_inbound_from_next(cell, now) {
                        Ok(actions) => self.execute_actions(actions).await?,
                        Err(e) => {
                            tracing::debug!(out_circ_id, error = %e,
                                "next-hop cell error; reaping out-side circuit");
                            self.reap_circuit_by_out_id(out_circ_id).await?;
                        }
                    }
                }
                _ = tick_interval.tick() => {
                    let actions = self.state.tick(std::time::Instant::now());
                    self.execute_actions(actions).await?;
                }
            }
        }
    }

    /// Execute a sequence of `BridgeAction`s.
    ///
    /// **Recursion**: bounded to depth 2. Only `PerformHandshake`
    /// and `OpenNextHop` recurse via `Box::pin(execute_actions(
    /// follow_up))`, and the state machine guarantees the
    /// follow-up sequence contains only terminal actions
    /// (`SendToPrev`). Documented invariant per [RT-H10].
    ///
    /// **Per-circuit error isolation** (closes [RT-H13]):
    /// `NextHopExecutor` failures are circuit-local. Instead of
    /// returning `Err(_)` and tearing down the entire prev-hop
    /// session (which in Phase 2I will multiplex many circuits),
    /// the failure is logged and the offending circuit is reaped
    /// via `BridgeCircuitState::handle_destroy_from_prev`. Other
    /// circuits on the same session continue to flow.
    ///
    /// **Session-fatal errors** (still return `Err(_)`):
    /// - `write_cell` failures on the prev-hop session - the
    ///   session itself is dead, no point continuing.
    ///
    /// **Per-circuit errors are NOT session-fatal** (RT #3): a
    /// `BridgeCircuitError` from `process_inbound_from_prev` reaps only the
    /// offending circuit (`reap_circuit`) and the loop continues. A single
    /// peer's bad cell must not drop sibling circuits (cross-circuit DoS) or
    /// trigger an instant whole-connection RST (active-probe distinguisher).
    async fn execute_actions(&mut self, actions: Vec<BridgeAction>) -> Result<(), DaemonError> {
        for action in actions {
            match action {
                BridgeAction::PerformHandshake {
                    in_circ_id,
                    hs_msg1,
                } => match self.executor.perform_handshake(in_circ_id, hs_msg1).await {
                    Ok((keys, hs_msg2)) => {
                        let now = std::time::Instant::now();
                        let follow_up = self
                            .state
                            .record_create_complete(in_circ_id, keys, hs_msg2, now)?;
                        Box::pin(self.execute_actions(follow_up)).await?;
                    }
                    Err(e) => {
                        tracing::warn!(circ_id = in_circ_id, error = %e,
                            "perform_handshake failed; reaping circuit");
                        self.reap_circuit(in_circ_id).await?;
                    }
                },
                BridgeAction::SendToPrev { cell, .. } => {
                    // Session-fatal: a write failure on the
                    // prev-hop link means the session is broken
                    // for ALL circuits, not just this one.
                    write_cell(&mut self.session, &cell).await?;
                }
                BridgeAction::OpenNextHop {
                    in_circ_id,
                    out_circ_id,
                    next_hop_pk,
                    endpoint,
                    hs_msg1,
                } => {
                    match self
                        .executor
                        .open_next_hop(in_circ_id, out_circ_id, next_hop_pk, endpoint, hs_msg1)
                        .await
                    {
                        Ok(hs_msg2) => {
                            let now = std::time::Instant::now();
                            let follow_up = self
                                .state
                                .record_extend_complete(in_circ_id, hs_msg2, now)?;
                            Box::pin(self.execute_actions(follow_up)).await?;
                        }
                        Err(e) => {
                            tracing::warn!(circ_id = in_circ_id, error = %e,
                                "open_next_hop failed; reaping circuit");
                            self.reap_circuit(in_circ_id).await?;
                        }
                    }
                }
                BridgeAction::SendToNext { out_circ_id, cell } => {
                    if let Err(e) = self.executor.send_to_next(out_circ_id, cell).await {
                        tracing::warn!(out_circ_id, error = %e,
                            "send_to_next failed; reaping out-side circuit");
                        // Mirror via destroy - the bridge state
                        // machine will surface DestroyNextLink for
                        // the prev side too via the reaper.
                        self.reap_circuit_by_out_id(out_circ_id).await?;
                    }
                }
                BridgeAction::ForwardExtendFinishToNext {
                    out_circ_id,
                    hs_msg3,
                } => {
                    if let Err(e) = self
                        .executor
                        .forward_extend_finish(out_circ_id, hs_msg3)
                        .await
                    {
                        tracing::warn!(out_circ_id, error = %e,
                            "forward_extend_finish failed; reaping out-side circuit");
                        self.reap_circuit_by_out_id(out_circ_id).await?;
                    }
                }
                BridgeAction::VerifyExtendFinish {
                    in_circ_id,
                    hs_msg3,
                } => match self
                    .executor
                    .verify_extend_finish(in_circ_id, hs_msg3)
                    .await
                {
                    Ok(()) => {
                        // Token verified - unlock the circuit for exit/extend.
                        self.state.record_token_verified(in_circ_id)?;
                        tracing::debug!(
                            circ_id = in_circ_id,
                            "per-hop capability token verified; circuit authorized"
                        );
                    }
                    Err(e) => {
                        // Bad/absent/replayed per-hop token: this hop was reached
                        // without valid authorization. Reap the circuit.
                        tracing::warn!(circ_id = in_circ_id, error = %e,
                            "per-hop token verification failed; reaping circuit");
                        self.reap_circuit(in_circ_id).await?;
                    }
                },
                BridgeAction::DestroyPrevLink { in_circ_id } => {
                    // Best-effort: the prev side already initiated
                    // the destroy (or a tick reaped a stuck
                    // circuit). We don't write a CMD_DESTROY back.
                    //
                    // Free any handshake responder retained for a relay-session
                    // circuit that was torn down BEFORE its CMD_EXTEND_FINISH
                    // (the Unauthorized gate, a client-sent DESTROY, or an idle
                    // reap all funnel through here). Without this, an unauthorized
                    // client could churn CREATE-then-DESTROY to grow the
                    // executor's pending_responders map unbounded (memory DoS).
                    // Idempotent + a no-op on direct-client executors.
                    self.executor.forget_pending_responder(in_circ_id).await;
                }
                BridgeAction::DestroyNextLink { out_circ_id } => {
                    // Tear-down is best-effort per-circuit; an
                    // executor failure here doesn't justify
                    // closing the whole session.
                    if let Err(e) = self.executor.destroy_next_link(out_circ_id).await {
                        tracing::debug!(out_circ_id, error = %e,
                            "destroy_next_link failed (best-effort, circuit already gone)");
                    }
                }
                BridgeAction::RelayPayloadAtExit {
                    in_circ_id,
                    payload,
                } => {
                    // Track stream->circ mapping for the return path.
                    // Parse the sub-cell command to detect BEGIN (new stream)
                    // and END (stream close). Errors are ignored - the
                    // dispatcher will reject malformed payloads independently.
                    if let Ok(sub) = mirage_circuit::RelaySubCell::decode(&payload) {
                        match sub.command {
                            CMD_BEGIN => {
                                if let Ok(begin) = BeginBody::decode(&sub.body) {
                                    self.stream_to_circ.insert(begin.stream_id, in_circ_id);
                                }
                            }
                            CMD_END => {
                                if let Ok(end) = EndBody::decode(&sub.body) {
                                    self.stream_to_circ.remove(&end.stream_id);
                                }
                            }
                            _ => {}
                        }
                    }
                    if let Err(e) = self.executor.handle_exit_payload(in_circ_id, payload).await {
                        tracing::warn!(circ_id = in_circ_id, error = %e,
                            "handle_exit_payload failed; reaping circuit");
                        self.reap_circuit(in_circ_id).await?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Tear down a single circuit on per-circuit-error path.
    /// Closes [RT-H13]: replaces session-fatal `Err(_)` returns
    /// with a circuit-local destroy that keeps the rest of the
    /// session flowing.
    async fn reap_circuit(&mut self, in_circ_id: u32) -> Result<(), DaemonError> {
        let now = std::time::Instant::now();
        // Purge all stream->circ entries for this circuit so orphaned
        // StreamEvents from still-open TCP sockets don't accumulate
        // in the map after the circuit is gone.
        self.stream_to_circ.retain(|_, &mut v| v != in_circ_id);
        // Drop any handshake responder retained for a not-yet-verified
        // relay-session circuit (no-op on direct-client sessions).
        self.executor.forget_pending_responder(in_circ_id).await;
        // The state machine's handle_destroy_from_prev is
        // idempotent and tolerates unknown circuits - calling it
        // here cleanly removes any state we hold (and emits a
        // DestroyNextLink action if appropriate).
        let actions = self
            .state
            .process_inbound_from_prev(
                Cell::new(in_circ_id, mirage_circuit::CMD_DESTROY, vec![])
                    .map_err(|e| DaemonError::NextHop(format!("synth DESTROY cell: {e}")))?,
                now,
            )
            .unwrap_or_default();
        Box::pin(self.execute_actions(actions)).await
    }

    /// Route an exit TCP event back to the circuit client.
    ///
    /// Encodes the `StreamEvent` as an onion-sealed `CMD_RELAY`
    /// cell via `BridgeCircuitState::inject_exit_response` and
    /// writes it to the prev-hop session. Circuit-local failures
    /// (unknown or destroyed circuit) are logged and skipped -
    /// they don't justify tearing down the whole session.
    async fn handle_exit_event(&mut self, event: StreamEvent) -> Result<(), DaemonError> {
        let stream_id = match &event {
            StreamEvent::Data { stream_id, .. } => *stream_id,
            StreamEvent::End { stream_id } => *stream_id,
        };
        let in_circ_id = match self.stream_to_circ.get(&stream_id) {
            Some(&id) => id,
            None => {
                // Stream was cleaned up (END already processed or
                // circuit reaped). Silently discard.
                return Ok(());
            }
        };
        // Encode as one-or-more RelaySubCell payloads for inject_exit_response.
        // A DATA event carrying more than `MAX_REVERSE_RELAY_DATA_BYTES` MUST be
        // split: each reverse cell gains an onion layer at every upstream hop,
        // and an oversized single sub-cell would blow `MAX_CELL_PAYLOAD` at
        // `Cell::new` and be silently DROPPED (reverse bulk transfer was broken
        // before this - the exit dispatcher reads up to 4 KiB per read).
        let payloads = encode_exit_event_chunked(event).map_err(|e| {
            DaemonError::NextHop(format!("exit event encode (stream={stream_id}): {e}"))
        })?;
        let now = std::time::Instant::now();
        for payload in payloads {
            match self.state.inject_exit_response(in_circ_id, &payload, now) {
                Ok(actions) => {
                    self.execute_actions(actions).await?;
                }
                Err(e) => {
                    // Circuit was reaped or destroyed between the BEGIN and
                    // this DATA/END - log and discard, don't kill the session.
                    tracing::debug!(circ_id = in_circ_id, stream_id, error = %e,
                        "inject_exit_response failed (circuit likely reaped); discarding event");
                    break;
                }
            }
        }
        Ok(())
    }

    /// Tear down a circuit by its `out_circ_id`. The state
    /// machine maps this to the in-side `circ_id` internally.
    async fn reap_circuit_by_out_id(&mut self, out_circ_id: u32) -> Result<(), DaemonError> {
        let now = std::time::Instant::now();
        // Mirror the stream_to_circ purge from reap_circuit: look up
        // the in-side id so we can clean orphaned stream entries.
        if let Some(in_circ_id) = self.state.in_circ_id_for(out_circ_id) {
            self.stream_to_circ.retain(|_, &mut v| v != in_circ_id);
        }
        let actions = self
            .state
            .process_inbound_from_next(
                Cell::new(out_circ_id, mirage_circuit::CMD_DESTROY, vec![])
                    .map_err(|e| DaemonError::NextHop(format!("synth DESTROY cell: {e}")))?,
                now,
            )
            .unwrap_or_default();
        Box::pin(self.execute_actions(actions)).await
    }
}

/// Poll the exit-events channel if one is present. Used in the
/// `select!` arm - returns a future that yields `Option<StreamEvent>`
/// (None when the channel is closed or not connected).
async fn recv_exit_event(rx: &mut Option<Receiver<StreamEvent>>) -> Option<StreamEvent> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

/// Poll the next-hop-inbound channel if present; `pending()` forever when
/// absent (single-hop / exit-only mode) so the `select!` arm is inert.
async fn recv_next_hop_cell(rx: &mut Option<Receiver<Cell>>) -> Option<Cell> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

/// Encode a `StreamEvent` as a `RelaySubCell` payload suitable for
/// `BridgeCircuitState::inject_exit_response`. The result is a
/// length-prefixed CMD_DATA or CMD_END sub-cell body.
/// Encode an exit `StreamEvent` into one-or-more `RelaySubCell` payloads,
/// fragmenting a DATA event so each reverse cell survives onion re-wrapping at
/// every upstream hop (see [`mirage_circuit::MAX_REVERSE_RELAY_DATA_BYTES`]).
/// END events are tiny and never fragment.
fn encode_exit_event_chunked(event: StreamEvent) -> Result<Vec<Vec<u8>>, String> {
    match event {
        StreamEvent::Data { stream_id, bytes } => {
            let max = mirage_circuit::MAX_REVERSE_RELAY_DATA_BYTES.max(1);
            let mut out = Vec::with_capacity(bytes.len() / max + 1);
            // An empty DATA event carries no bytes; nothing to send.
            for chunk in bytes.chunks(max) {
                let sub = mirage_circuit::RelaySubCell {
                    command: CMD_DATA,
                    body: DataBody {
                        stream_id,
                        bytes: chunk.to_vec(),
                    }
                    .encode(),
                };
                out.push(
                    sub.encode()
                        .map_err(|e| format!("encode_exit_event: data: {e}"))?,
                );
            }
            Ok(out)
        }
        StreamEvent::End { stream_id } => {
            let sub = mirage_circuit::RelaySubCell {
                command: CMD_END,
                body: EndBody { stream_id }.encode().to_vec(),
            };
            Ok(vec![sub
                .encode()
                .map_err(|e| format!("encode_exit_event: end: {e}"))?])
        }
    }
}

/// Read one cell with optional timeout. Returns:
/// - `Ok(Some(cell))` on success.
/// - `Ok(None)` on clean EOF.
/// - `Err(DaemonError::ReadTimeout)` if the deadline fires.
/// - `Err(DaemonError::Io(_))` on other I/O / parse failures.
async fn read_cell_with_timeout<S>(
    session: &mut SessionStream<S>,
    timeout: Option<Duration>,
) -> Result<Option<Cell>, DaemonError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let read_fut = read_cell(session);
    let result = match timeout {
        Some(t) => match tokio::time::timeout(t, read_fut).await {
            Ok(r) => r,
            Err(_) => return Err(DaemonError::ReadTimeout),
        },
        None => read_fut.await,
    };
    match result {
        Ok(cell) => Ok(Some(cell)),
        Err(CellIoError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(DaemonError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_circuit::cell::CIRCUIT_CELL_LEN;
    use mirage_circuit::HopKeys;
    use std::sync::Mutex;

    /// Recording executor: stores every call so tests can assert
    /// on the dispatch sequence without driving real I/O.
    // Retained test double for `NextHopExecutor`; kept (compiler-checked against
    // the trait) for dispatch-loop tests even while not currently constructed.
    #[allow(dead_code)]
    #[derive(Default)]
    struct RecordingExecutor {
        calls: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl NextHopExecutor for RecordingExecutor {
        async fn open_next_hop(
            &self,
            in_circ_id: u32,
            out_circ_id: u32,
            _next_hop_pk: [u8; 32],
            _endpoint: mirage_circuit::HopEndpoint,
            _hs_msg1: Vec<u8>,
        ) -> Result<Vec<u8>, String> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("open_next_hop({in_circ_id},{out_circ_id})"));
            // Canned hs_msg2.
            Ok(vec![0xAB; 200])
        }
        async fn send_to_next(&self, out_circ_id: u32, _cell: Cell) -> Result<(), String> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("send_to_next({out_circ_id})"));
            Ok(())
        }
        async fn forward_extend_finish(
            &self,
            out_circ_id: u32,
            _hs_msg3: Vec<u8>,
        ) -> Result<(), String> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("forward_extend_finish({out_circ_id})"));
            Ok(())
        }
        async fn destroy_next_link(&self, out_circ_id: u32) -> Result<(), String> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("destroy_next_link({out_circ_id})"));
            Ok(())
        }
        async fn handle_exit_payload(
            &self,
            in_circ_id: u32,
            payload: Vec<u8>,
        ) -> Result<(), String> {
            self.calls.lock().unwrap().push(format!(
                "handle_exit_payload({in_circ_id}, {})",
                payload.len()
            ));
            Ok(())
        }
        async fn perform_handshake(
            &self,
            in_circ_id: u32,
            _hs_msg1: Vec<u8>,
        ) -> Result<(HopKeys, Vec<u8>), String> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("perform_handshake({in_circ_id})"));
            // Canned keys + msg2. The test doesn't drive
            // post-handshake encrypted RELAY traffic, so the
            // values are placeholders.
            let keys = mirage_circuit::derive_hop_keys(&[1u8; 32], &[2u8; 32]);
            Ok((keys, vec![0xCD; 200]))
        }
        async fn verify_extend_finish(
            &self,
            in_circ_id: u32,
            _hs_msg3: Vec<u8>,
        ) -> Result<(), String> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("verify_extend_finish({in_circ_id})"));
            Ok(())
        }
    }

    #[test]
    fn cell_size_constant_smoke() {
        // Sanity check: cell-size constant is what we expect.
        assert_eq!(CIRCUIT_CELL_LEN, 1024);
    }

    #[test]
    fn relay_token_coupling_fails_closed_on_mismatch() {
        // #5: relay mode and executor token-verification must agree.
        // Aligned pairs run.
        assert!(check_relay_token_coupling(false, false).is_ok());
        assert!(check_relay_token_coupling(true, true).is_ok());
        // Relay mode without a verifying executor: refuse.
        assert!(matches!(
            check_relay_token_coupling(true, false),
            Err(DaemonError::RelayMisconfigured {
                relay_mode: true,
                token_verify: false
            })
        ));
        // Verifying executor left in non-relay mode (circuits would start
        // token_verified=true, bypassing the gate): refuse.
        assert!(matches!(
            check_relay_token_coupling(false, true),
            Err(DaemonError::RelayMisconfigured {
                relay_mode: false,
                token_verify: true
            })
        ));
    }

    #[test]
    fn config_default_has_sane_values() {
        let c = SessionTaskConfig::default();
        assert!(c.tick_interval >= Duration::from_millis(100));
        assert!(c.cell_read_timeout.is_some());
        // Tick must be shorter than the pending-extend timeout
        // so a stuck reassembly is reaped within at most
        // 2x `pending_extend_timeout`.
        assert!(c.tick_interval < c.policy.pending_extend_timeout);
    }
}
