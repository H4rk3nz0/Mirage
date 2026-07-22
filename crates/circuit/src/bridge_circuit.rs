//! Bridge-side circuit handler - I/O-free state machine.
//!
//! The bridge daemon's per-connection circuit state. Handles
//! inbound CREATE / EXTEND / DESTROY cells, allocates `circ_id`
//! translations between prev-hop and next-hop links, drives the
//! responder side of per-hop handshakes via the runtime, and
//! reaps idle / failed / destroyed circuits on a periodic sweep.
//!
//! Same I/O-free discipline as `mirage-mux::state`,
//! `mirage-circuit::split_exit`, `mirage-router::pool`,
//! `mirage-runtime::driver`. The state machine emits
//! [`BridgeAction`]s; the runtime executes them.
//!
//! # Phase 2C scope
//!
//! - CREATE / CREATED handling
//! - EXTEND / EXTENDED handling with `circ_id` translation
//! - DESTROY (both directions, idempotent)
//! - Anti-DoS caps + idle timeout sweep
//!
//! Phase 2D adds:
//! - Onion-peel for RELAY cells
//! - Exit-stream dispatch (BEGIN / DATA / END -> TCP socket)
//! - Split-exit RESOLVE / HANDOFF wiring on the bridge side

use crate::cell::{
    Cell, CellError, CMD_CREATE, CMD_CREATED, CMD_CREATED_CONT, CMD_CREATE_CONT, CMD_DESTROY,
    CMD_EXTEND, CMD_EXTENDED, CMD_EXTENDED_CONT, CMD_EXTEND_CONT, CMD_EXTEND_FINISH, CMD_PADDING,
    CMD_RELAY,
};
use crate::circuit::{DIR_CLIENT_TO_HOP, DIR_HOP_TO_CLIENT};
use crate::extend::{
    ExtendError, ExtendFinishBody, ExtendHeader, ExtendedBody, HopEndpoint, RelaySubCell,
};
use crate::keys::HopKeys;
use crate::onion::{onion_open, onion_seal, OnionError};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use thiserror::Error;

// Policy

/// Per-connection limits + timeouts.
#[derive(Debug, Clone)]
pub struct BridgePolicy {
    /// Max simultaneous circuits this bridge accepts from one
    /// prev-hop connection. Bounds memory under load.
    pub max_circuits: u32,
    /// Max simultaneous Creating + Extending entries per
    /// connection. Bounds CPU budget for handshakes.
    pub max_pending_handshakes: u32,
    /// Idle timeout - circuits with no activity in this window
    /// are reaped on `tick()`.
    pub idle_ttl: Duration,
    /// Per-state timeouts for stuck Creating / Extending entries
    /// (the runtime never called record_*_complete).
    pub creating_timeout: Duration,
    /// See [`creating_timeout`].
    pub extending_timeout: Duration,
    /// Phase 2G+ (closes [RT-P2G-2]): timeout for in-flight EXTEND
    /// fragmentation. Once `CMD_EXTEND` arrives but the
    /// `pending_extend` reassembly hasn't completed within this
    /// window, the bridge tears down the half-finished state. Set
    /// substantially shorter than `idle_ttl` so a partial-EXTEND
    /// `DoS` doesn't pin reassembly buffers for the full idle
    /// window. Default 10 s (twice `creating_timeout`'s 15 s / 1.5
    /// - generous for normal latency, tight for an attacker).
    pub pending_extend_timeout: Duration,
}

impl Default for BridgePolicy {
    fn default() -> Self {
        Self {
            max_circuits: 64,
            max_pending_handshakes: 16,
            idle_ttl: Duration::from_secs(10 * 60),
            creating_timeout: Duration::from_secs(15),
            extending_timeout: Duration::from_secs(30),
            pending_extend_timeout: Duration::from_secs(10),
        }
    }
}

// Error taxonomy

/// Errors produced by the bridge-circuit state machine.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BridgeCircuitError {
    /// Wire-format violation in an inbound cell or body.
    #[error("wire: {0}")]
    Wire(&'static str),
    /// Inbound cell's command is unknown / unexpected for this
    /// state (e.g., CREATE for an already-established `circ_id`).
    #[error("circuit {circ_id} in state {state:?} can't accept {cmd:#04x}")]
    BadState {
        /// Offending `circ_id`.
        circ_id: u32,
        /// Current state.
        state: CircuitEntryState,
        /// Cell command byte.
        cmd: u8,
    },
    /// Per-connection cap reached.
    #[error("circuit cap {0} reached")]
    CircuitCap(u32),
    /// Per-state pending-handshake cap reached.
    #[error("pending-handshake cap {0} reached")]
    PendingCap(u32),
    /// Caller's record_*_complete referenced an unknown `circ_id`.
    #[error("unknown circuit id {0}")]
    UnknownCircuit(u32),
    /// Caller's record_*_complete fired in the wrong state.
    #[error("circuit {circ_id} in state {state:?} can't accept this completion")]
    WrongState {
        /// Offending `circ_id`.
        circ_id: u32,
        /// Current state.
        state: CircuitEntryState,
    },
    /// Allocation of a fresh `out_circ_id` exhausted the search
    /// budget (hostile peer or near-impossible random collision).
    #[error("out_circ_id allocation exhausted after {0} tries")]
    OutCircIdExhausted(u32),
    /// Underlying cell encode/decode error.
    #[error("cell: {0}")]
    Cell(#[from] CellError),
    /// EXTEND body parse error.
    #[error("extend: {0}")]
    Extend(#[from] ExtendError),
    /// Onion AEAD seal/open failed for a RELAY cell (peer
    /// tampering, sequence-counter desync, or programmer error).
    #[error("onion: {0}")]
    Onion(#[from] OnionError),
    /// RELAY cell arrived for a circuit that hasn't completed its
    /// CREATE handshake - we have no `prev_keys` to peel with.
    /// Indicates a peer protocol violation.
    #[error("circuit {0} has no prev_keys; can't peel RELAY")]
    NoPrevKeys(u32),
    /// Per-circuit sequence counter exhausted (`u64::MAX` cells
    /// in one direction). Closes [RT-S1/S2]: peer's counter
    /// would wrap independently and AEAD nonces would silently
    /// mis-match. Bridge tears the circuit down on overflow so
    /// the resulting failures are loud and bounded.
    #[error("circuit {0} sequence counter exhausted; tearing down")]
    SeqExhausted(u32),
    /// `CMD_EXTEND_CONT` carried more bytes than the in-flight
    /// EXTEND's `total_hs_msg1_len` declared. Closes [RT-O3]
    /// fragmentation safety: a malicious peer cannot stuff extra
    /// bytes past the declared length.
    #[error("circuit {circ_id} extend reassembly overflow: got {got} bytes, expected {expected}")]
    ExtendOverflow {
        /// Circuit being extended.
        circ_id: u32,
        /// Bytes received including the offending CONT chunk.
        got: usize,
        /// Total declared in the original `CMD_EXTEND` header.
        expected: usize,
    },
    /// A relay-session circuit tried to use the hop (exit dispatch or a
    /// further EXTEND) before its per-hop capability token was verified via
    /// `CMD_EXTEND_FINISH`. Closes the extended-hop authorization bypass: a
    /// client holding a token for the ENTRY bridge must ALSO hold a valid
    /// token for each extended hop, verified at that hop, before it serves
    /// any traffic.
    #[error("circuit {0}: hop used before per-hop token verified")]
    Unauthorized(u32),
}

// State enum + entry

/// Per-circuit lifecycle state on the bridge side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitEntryState {
    /// CREATE received; runtime running responder handshake.
    Creating,
    /// Handshake complete; circuit accepts cells.
    Open,
    /// EXTEND received; runtime opening next-hop session +
    /// awaiting CREATED back.
    Extending,
    /// Tearing down; will be reaped by `tick()`.
    Destroyed,
}

#[derive(Debug)]
struct CircuitEntry {
    /// Same value as the `HashMap` key; kept for diagnostic clarity
    /// when handing entry references around. Suppress dead-code
    /// warning explicitly - it's part of the entry's logical
    /// identity even when not read.
    #[allow(dead_code)]
    in_circ_id: u32,
    /// Out-circ_id allocated when EXTEND completes. `None` for
    /// circuits that are still middle-hop-incomplete or are
    /// terminal (last hop).
    out_circ_id: Option<u32>,
    state: CircuitEntryState,
    /// Onion keys for cells to/from the previous hop. Set after
    /// CREATE completes. Phase 2D uses these to peel inbound
    /// RELAY cells (forward dir) and seal outbound reverse cells.
    prev_keys: Option<HopKeys>,
    /// Forward-direction sequence counter (cells received from
    /// prev-hop). Mirrors the prev-hop's `c2h_seq` exactly; used
    /// as the AEAD nonce input for `onion_open`. Phase 2D.
    forward_seq: u64,
    /// Reverse-direction sequence counter (cells sent to prev-hop).
    /// Mirrors the prev-hop's `h2c_seq` exactly; used as the AEAD
    /// nonce input for `onion_seal` when wrapping back-traffic.
    /// Phase 2D.
    reverse_seq: u64,
    /// When the entry transitioned to its current state. Used by
    /// `tick()` for state-specific timeouts.
    state_entered: Instant,
    /// Last activity timestamp. Updated on every cell received
    /// or sent for this circuit. Used by `tick()` for the idle
    /// timeout.
    last_activity: Instant,
    /// In-flight EXTEND reassembly. Phase 2G+ (closes [RT-O3]):
    /// `CMD_EXTEND` carries the header + first `hs_msg1` chunk;
    /// subsequent `CMD_EXTEND_CONT` cells deliver the rest.
    /// `Some(_)` from `CMD_EXTEND` through the last `CMD_EXTEND_CONT`;
    /// cleared (back to `None`) once the full message is dispatched.
    pending_extend: Option<PendingExtend>,
    /// In-flight CREATE reassembly. Phase 2I (symmetric closure
    /// of RT-O3 for the initial dial). `CMD_CREATE` carries the
    /// length prefix + first chunk of `hs_msg1`; subsequent
    /// `CMD_CREATE_CONT` cells deliver the rest. Live only
    /// during `CircuitEntryState::Creating`.
    pending_create: Option<PendingCreate>,
    /// In-flight CREATED reassembly on the next-hop link. Live
    /// only during `CircuitEntryState::Extending` while the next
    /// hop's fragmented `hs_msg2` is still arriving.
    pending_created: Option<PendingCreated>,
    /// Whether this circuit's per-hop capability token has been verified.
    ///
    /// - On a DIRECT client session (`relay_mode == false`), the client was
    ///   already token-authenticated by the transport handshake, so entry
    ///   circuits start `true` - the gate below is a no-op.
    /// - On a RELAY session (`relay_mode == true`, i.e. this bridge is an
    ///   EXTENDED hop reached through another bridge), a circuit starts
    ///   `false` and only flips `true` after the client's `CMD_EXTEND_FINISH`
    ///   msg-3 token is verified ([`BridgeCircuitState::record_token_verified`]).
    ///   Until then the hop refuses to exit-dispatch or extend further -
    ///   closing the "one entry token unlocks every bridge" bypass.
    token_verified: bool,
    /// Provenance of this circuit's outbound EXTEND: `true` when the EXTEND
    /// arrived RELAY-wrapped (peeled from a `CMD_RELAY` inner sub-cell - this
    /// bridge is a DEEP hop, hop index >= 2, reached through the onion), `false`
    /// when it arrived as a top-level `CMD_EXTEND` from a direct-facing prev
    /// (hop index 1). Governs how the EXTENDED reply is returned: a deep hop
    /// MUST wrap it as a reverse `CMD_RELAY` sub-cell so intermediate hops can
    /// onion-forward it back to the client, whereas a hop-1 bridge replies with
    /// a raw `CMD_EXTENDED` the client reads directly. Set in `handle_extend`.
    extend_via_relay: bool,
}

/// In-flight CREATE reassembly state. Smaller than
/// `PendingExtend` (no `next_hop_pk` / endpoint header - those
/// don't apply to the initial CREATE). Closes [RT-O3]
/// symmetric: `started_at` allows `tick()` to reap stuck
/// CREATE reassembly under `pending_extend_timeout`.
#[derive(Debug)]
struct PendingCreate {
    total_hs_msg1_len: usize,
    accumulated: Vec<u8>,
    started_at: Instant,
}

/// In-flight CREATED reassembly on the NEXT-hop link. Symmetric to
/// [`PendingCreate`] but for the return direction: the next hop's
/// `CMD_CREATED` carries `[u16 total][first chunk]` of `hs_msg2`, and
/// `CMD_CREATED_CONT` cells deliver the rest. A real `hs_msg2`
/// (Noise msg2 + ML-KEM-768 ~ 1189 B) exceeds one cell, so this is the
/// common case, not an edge case. Live only during
/// `CircuitEntryState::Extending`.
#[derive(Debug)]
struct PendingCreated {
    total_hs_msg2_len: usize,
    accumulated: Vec<u8>,
    started_at: Instant,
}

/// In-flight EXTEND reassembly state. Holds the parsed header and
/// the bytes accumulated so far. Stays in [`CircuitEntry`] while
/// `accumulated.len() < total_hs_msg1_len`. Closes [RT-P2G-2]:
/// `started_at` lets `tick()` reap stuck reassembly past
/// `pending_extend_timeout` without waiting for the full
/// `idle_ttl`.
#[derive(Debug)]
struct PendingExtend {
    next_hop_pk: [u8; 32],
    endpoint: HopEndpoint,
    total_hs_msg1_len: usize,
    accumulated: Vec<u8>,
    /// When the pending state was first established (on the
    /// initial `CMD_EXTEND`). Subsequent `CMD_EXTEND_CONT` cells do
    /// NOT reset this - the tear-down clock starts at the
    /// earliest stall.
    started_at: Instant,
}

// Action enum

/// One I/O action the runtime must execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeAction {
    /// Run the responder side of the per-hop Mirage handshake
    /// against `hs_msg1`. On success call
    /// [`BridgeCircuitState::record_create_complete`] with the
    /// derived `HopKeys` and the handshake's `hs_msg2` reply.
    PerformHandshake {
        /// Circuit being created.
        in_circ_id: u32,
        /// Mirage handshake message 1 from the client.
        hs_msg1: Vec<u8>,
    },
    /// Send `cell` on the prev-hop link.
    SendToPrev {
        /// Circuit the cell belongs to (for diagnostics; `circ_id`
        /// is also encoded in the cell).
        in_circ_id: u32,
        /// Cell to write.
        cell: Cell,
    },
    /// Open an outbound transport+session connection to
    /// `endpoint`, authenticating against `next_hop_pk`, and
    /// send `hs_msg1` as a CREATE cell on it. The runtime will
    /// receive a CREATED back; call
    /// [`BridgeCircuitState::record_extend_complete`] with the
    /// outbound `circ_id` (allocated by the next hop) and the
    /// `hs_msg2` from the CREATED reply.
    OpenNextHop {
        /// Circuit being extended.
        in_circ_id: u32,
        /// Out-circ_id allocated for the Bridge->next-hop link. The
        /// executor stamps the relayed `CMD_CREATE` cell (and all
        /// subsequent next-hop cells) with this id, and keys its
        /// outbound link by it - `out_to_in` maps it back on the
        /// return path.
        out_circ_id: u32,
        /// Next hop's static x25519 public key.
        next_hop_pk: [u8; 32],
        /// Endpoint to dial.
        endpoint: HopEndpoint,
        /// Handshake message 1 to forward.
        hs_msg1: Vec<u8>,
    },
    /// Send `cell` on the next-hop link.
    SendToNext {
        /// Out-circ_id (next hop's view).
        out_circ_id: u32,
        /// Cell to write.
        cell: Cell,
    },
    /// Best-effort: tear down the prev-hop link's circuit state
    /// (send DESTROY back, close the session if appropriate).
    DestroyPrevLink {
        /// Circuit's in-circ_id.
        in_circ_id: u32,
    },
    /// Best-effort: tear down the next-hop link's circuit state.
    DestroyNextLink {
        /// Circuit's out-circ_id.
        out_circ_id: u32,
    },
    /// **Phase 2D.** This circuit reached its exit (last) hop and
    /// the inbound RELAY cell's payload has been onion-peeled.
    /// `payload` is the original sub-cell (BEGIN, DATA, END, etc.)
    /// that the client encoded. The runtime parses the RELAY
    /// sub-command and dispatches to TCP socket I/O (BEGIN ->
    /// `connect`, DATA -> write, END -> close). For split-exit
    /// circuits the payload may instead be a `CMD_RESOLVE` body
    /// (handled via `mirage_circuit::split_exit::ResolverState`) -
    /// Phase 2D ships the action; the runtime's exit-stream
    /// dispatch is in `mirage-runtime` (Phase 2E).
    RelayPayloadAtExit {
        /// Circuit on which the RELAY arrived.
        in_circ_id: u32,
        /// Onion-peeled payload bytes.
        payload: Vec<u8>,
    },
    /// **Phase 2G.** Forward `hs_msg3` to the next-hop link as a
    /// `CMD_EXTEND_FINISH` cell. Closes [RT-O2]: the responder
    /// (next hop) needs `msg_3` to verify the capability token and
    /// transition to transport mode.
    ///
    /// The bridge does NOT inspect `hs_msg3` - it forwards bytes
    /// verbatim. After dispatch the bridge has no further state
    /// change to make for this EXTEND chain; the next hop will
    /// either reach transport mode (silent success on its side)
    /// or eventually time out.
    ForwardExtendFinishToNext {
        /// Out-circ_id on the next-hop link.
        out_circ_id: u32,
        /// `hs_msg3` bytes to forward.
        hs_msg3: Vec<u8>,
    },
    /// **Per-hop token verification.** This bridge is the TERMINAL hop of an
    /// extend (a relay-session circuit with no next hop), so the client's
    /// `CMD_EXTEND_FINISH` msg-3 is addressed to US, not to be forwarded. The
    /// runtime MUST run the retained handshake responder's `read_message_3`
    /// against `hs_msg3` with a `TokenVerifier`. On success it calls
    /// [`BridgeCircuitState::record_token_verified`] to unlock the circuit; on
    /// failure (bad/absent/replayed token) it tears the circuit down via
    /// [`BridgeCircuitState::handle_destroy_from_prev`] / `DestroyPrevLink`.
    ///
    /// This is the fix for the extended-hop authorization bypass: without it a
    /// client holding a token for the ENTRY bridge could extend to - and use -
    /// any bridge with no token for it.
    VerifyExtendFinish {
        /// Circuit whose per-hop token is being verified.
        in_circ_id: u32,
        /// `hs_msg3` (the client's Noise message-3 bearing the capability
        /// token for THIS hop) to feed to `read_message_3`.
        hs_msg3: Vec<u8>,
    },
}

// BridgeCircuitState

/// Per-connection circuit state. One instance per inbound
/// prev-hop connection.
pub struct BridgeCircuitState {
    /// Circuits keyed by `in_circ_id`.
    circuits: HashMap<u32, CircuitEntry>,
    /// `out_circ_id` -> `in_circ_id` reverse lookup. Maintained
    /// in lockstep with `circuits[].out_circ_id`.
    out_to_in: HashMap<u32, u32>,
    policy: BridgePolicy,
    /// Caller-pluggable allocator for fresh `out_circ_ids`. Default
    /// uses a deterministic counter; production swaps in a CSPRNG-
    /// backed picker via [`Self::set_out_circ_id_picker`].
    out_circ_id_picker: fn(seq: u64) -> u32,
    out_circ_id_seq: u64,
    /// Whether this state machine serves a RELAY session (this bridge is an
    /// EXTENDED hop reached through another bridge) rather than a direct
    /// client session. In relay mode, circuits require per-hop capability-
    /// token verification (via `CMD_EXTEND_FINISH`) before they may
    /// exit-dispatch or extend - see [`CircuitEntry::token_verified`]. Set at
    /// accept time by the daemon from the relay peer's authenticated identity.
    relay_mode: bool,
}

impl BridgeCircuitState {
    /// Construct a state machine for a DIRECT client session (the default:
    /// the client is token-authenticated by the transport handshake, so
    /// entry circuits are implicitly authorized).
    pub fn new(policy: BridgePolicy) -> Self {
        Self {
            circuits: HashMap::new(),
            out_to_in: HashMap::new(),
            policy,
            out_circ_id_picker: deterministic_out_circ_id_picker,
            // SECURITY (#14): seed the sequence from the OS CSPRNG so each
            // session's out_circ_id schedule is unpredictable. With a fixed 0
            // start, the golden-ratio picker assigned the SAME k-th out_circ_id
            // on every relay session, letting a next-hop bridge precompute the
            // whole schedule and fingerprint how many circuits an upstream relay
            // had extended. A random 64-bit start makes the (still
            // collision-free, deterministic-per-session) walk unguessable. Tests
            // that need reproducible ids call `set_out_circ_id_picker`, which
            // resets the seq to 0.
            out_circ_id_seq: random_seq_seed(),
            relay_mode: false,
        }
    }

    /// Construct a state machine for a RELAY session - this bridge is an
    /// EXTENDED hop reached through another bridge, so every circuit created
    /// here MUST present a valid per-hop capability token (verified via
    /// `CMD_EXTEND_FINISH`) before it exit-dispatches or extends further.
    pub fn new_relay(policy: BridgePolicy) -> Self {
        let mut me = Self::new(policy);
        me.relay_mode = true;
        me
    }

    /// Whether this state machine is in relay mode (extended-hop) and thus
    /// enforces per-hop token verification.
    #[must_use]
    pub fn is_relay_mode(&self) -> bool {
        self.relay_mode
    }

    /// Set relay mode after construction (preserving any configured picker).
    /// Used by the daemon when an accepted session is identified as a relay
    /// link. See [`Self::new_relay`] for the security semantics.
    pub fn set_relay_mode(&mut self, relay_mode: bool) {
        self.relay_mode = relay_mode;
    }

    /// Override the `out_circ_id` picker AND reset the sequence counter to 0.
    /// Tests pin this to make `circ_id` values trivially predictable; resetting
    /// the seq gives them a known starting point despite the CSPRNG-seeded
    /// default (#14). Production does NOT call this - the default constructor is
    /// already unpredictable-by-default.
    pub fn set_out_circ_id_picker(&mut self, picker: fn(seq: u64) -> u32) {
        self.out_circ_id_picker = picker;
        self.out_circ_id_seq = 0;
    }

    /// Diagnostics: number of active circuits (any state).
    pub fn circuit_count(&self) -> usize {
        self.circuits.len()
    }

    /// Diagnostics: state of a specific circuit by `in_circ_id`.
    pub fn circuit_state(&self, in_circ_id: u32) -> Option<CircuitEntryState> {
        self.circuits.get(&in_circ_id).map(|e| e.state)
    }

    /// Diagnostics: `out_circ_id` mapped from `in_circ_id` (after EXTEND).
    pub fn out_circ_id_for(&self, in_circ_id: u32) -> Option<u32> {
        self.circuits.get(&in_circ_id).and_then(|e| e.out_circ_id)
    }

    /// Diagnostics: `in_circ_id` mapped from `out_circ_id`.
    pub fn in_circ_id_for(&self, out_circ_id: u32) -> Option<u32> {
        self.out_to_in.get(&out_circ_id).copied()
    }

    // Inbound from prev-hop

    /// Process an inbound cell from the prev-hop link.
    pub fn process_inbound_from_prev(
        &mut self,
        cell: Cell,
        now: Instant,
    ) -> Result<Vec<BridgeAction>, BridgeCircuitError> {
        let circ_id = cell.circ_id;
        let command = cell.command;
        let body = cell.body;
        match command {
            CMD_CREATE => self.handle_create(circ_id, &body, now),
            CMD_CREATE_CONT => self.handle_create_cont(circ_id, &body, now),
            // Top-level EXTEND: this bridge faces the client's prev directly
            // (hop 1), so `relayed = false` - the EXTENDED reply is raw.
            CMD_EXTEND => self.handle_extend(circ_id, &body, now, false),
            CMD_EXTEND_CONT => self.handle_extend_cont(circ_id, &body, now),
            CMD_EXTEND_FINISH => self.handle_extend_finish(circ_id, &body, now),
            CMD_DESTROY => Ok(self.handle_destroy_from_prev(circ_id, now)),
            CMD_RELAY => self.handle_relay_from_prev(circ_id, &body, now),
            other => {
                let entry = self
                    .circuits
                    .get(&circ_id)
                    .ok_or(BridgeCircuitError::UnknownCircuit(circ_id))?;
                Err(BridgeCircuitError::BadState {
                    circ_id,
                    state: entry.state,
                    cmd: other,
                })
            }
        }
    }

    /// Process an inbound cell from the next-hop link. The bridge
    /// rewrites `circ_id` from `out` to `in` and forwards back to
    /// the prev-hop link.
    ///
    /// **Phase 2D**: RELAY cells get an additional onion layer
    /// added with `prev_keys.reverse` before forwarding, so the
    /// client (which holds all reverse keys) can peel them in
    /// order.
    pub fn process_inbound_from_next(
        &mut self,
        cell: Cell,
        now: Instant,
    ) -> Result<Vec<BridgeAction>, BridgeCircuitError> {
        let out_circ_id = cell.circ_id;
        let command = cell.command;
        let body = cell.body;
        let in_circ_id = *self
            .out_to_in
            .get(&out_circ_id)
            .ok_or(BridgeCircuitError::UnknownCircuit(out_circ_id))?;
        match command {
            CMD_CREATED => self.handle_created_from_next(in_circ_id, &body, now),
            CMD_CREATED_CONT => self.handle_created_cont_from_next(in_circ_id, &body, now),
            CMD_DESTROY => Ok(self.handle_destroy_from_next(in_circ_id, now)),
            CMD_RELAY => self.handle_relay_from_next(in_circ_id, &body, now),
            _ => {
                // SECURITY (#15): a next-hop cell with an unexpected command
                // must NEVER be blind-forwarded to the client. This arm used to
                // rewrite only the circ_id and emit SendToPrev WITHOUT adding
                // the prev-hop reverse onion layer and without any
                // authentication - so a malicious or compromised next-hop bridge
                // could inject attacker-chosen bytes that reach the client as if
                // they had come from the sealed reverse stream. The only valid
                // reverse commands are CREATED / CREATED_CONT / DESTROY / RELAY
                // (all handled above); anything else is a protocol violation
                // from the next hop. Reject it so the caller reaps the circuit
                // rather than relaying unauthenticated bytes upstream.
                let state = self
                    .circuits
                    .get(&in_circ_id)
                    .map(|e| e.state)
                    .ok_or(BridgeCircuitError::UnknownCircuit(in_circ_id))?;
                Err(BridgeCircuitError::BadState {
                    circ_id: in_circ_id,
                    state,
                    cmd: command,
                })
            }
        }
    }

    // Caller-driven completion / failure

    /// Caller's responder Mirage handshake completed. The bridge
    /// stores the per-hop keys and emits the CREATED cell back
    /// to the prev-hop link.
    pub fn record_create_complete(
        &mut self,
        in_circ_id: u32,
        prev_keys: HopKeys,
        hs_msg2: Vec<u8>,
        now: Instant,
    ) -> Result<Vec<BridgeAction>, BridgeCircuitError> {
        let entry = self
            .circuits
            .get_mut(&in_circ_id)
            .ok_or(BridgeCircuitError::UnknownCircuit(in_circ_id))?;
        if entry.state != CircuitEntryState::Creating {
            return Err(BridgeCircuitError::WrongState {
                circ_id: in_circ_id,
                state: entry.state,
            });
        }
        entry.state = CircuitEntryState::Open;
        entry.state_entered = now;
        entry.last_activity = now;
        entry.prev_keys = Some(prev_keys);
        // Phase 2I: fragment hs_msg2 across CMD_CREATED +
        // CMD_CREATED_CONT cells. Closes [RT-O3] symmetric for
        // the initial dial - hs_msg2 (1189 B in v0.1) doesn't
        // fit in a single 1024 B cell.
        let (first_body, cont_bodies) = crate::extend::HandshakeBody { hs_msg: hs_msg2 }
            .encode_fragmented(crate::cell::MAX_CELL_PAYLOAD)?;
        let mut actions = Vec::with_capacity(1 + cont_bodies.len());
        actions.push(BridgeAction::SendToPrev {
            in_circ_id,
            cell: Cell::new(in_circ_id, CMD_CREATED, first_body)?,
        });
        for body in cont_bodies {
            actions.push(BridgeAction::SendToPrev {
                in_circ_id,
                cell: Cell::new(in_circ_id, CMD_CREATED_CONT, body)?,
            });
        }
        Ok(actions)
    }

    /// Caller's responder Mirage handshake failed (bad msg, ML-KEM
    /// decap, etc.). Mark Destroyed; emit prev-link teardown.
    pub fn record_create_failure(
        &mut self,
        in_circ_id: u32,
        now: Instant,
    ) -> Result<Vec<BridgeAction>, BridgeCircuitError> {
        let entry = self
            .circuits
            .get_mut(&in_circ_id)
            .ok_or(BridgeCircuitError::UnknownCircuit(in_circ_id))?;
        if entry.state != CircuitEntryState::Creating {
            return Err(BridgeCircuitError::WrongState {
                circ_id: in_circ_id,
                state: entry.state,
            });
        }
        entry.state = CircuitEntryState::Destroyed;
        entry.state_entered = now;
        Ok(vec![BridgeAction::DestroyPrevLink { in_circ_id }])
    }

    /// Caller's outbound dial + CREATE -> CREATED roundtrip
    /// completed. The bridge wires up the in<->out translation
    /// table and emits the EXTENDED cell back to the prev-hop link.
    pub fn record_extend_complete(
        &mut self,
        in_circ_id: u32,
        hs_msg2: Vec<u8>,
        now: Instant,
    ) -> Result<Vec<BridgeAction>, BridgeCircuitError> {
        let entry = self
            .circuits
            .get_mut(&in_circ_id)
            .ok_or(BridgeCircuitError::UnknownCircuit(in_circ_id))?;
        if entry.state != CircuitEntryState::Extending {
            return Err(BridgeCircuitError::WrongState {
                circ_id: in_circ_id,
                state: entry.state,
            });
        }
        // Route through `emit_extended` so a real (>1017 B) hs_msg2 is
        // fragmented across CMD_EXTENDED + CMD_EXTENDED_CONT. The previous
        // single-cell `ExtendedBody::encode()` errored on any hs_msg2 that
        // didn't fit one cell - i.e. every real ML-KEM handshake.
        self.emit_extended(in_circ_id, hs_msg2, now)
    }

    /// Caller's outbound extend failed (next-hop dial, handshake,
    /// or CREATED-roundtrip timeout). Tear down both directions.
    pub fn record_extend_failure(
        &mut self,
        in_circ_id: u32,
        now: Instant,
    ) -> Result<Vec<BridgeAction>, BridgeCircuitError> {
        let entry = self
            .circuits
            .get_mut(&in_circ_id)
            .ok_or(BridgeCircuitError::UnknownCircuit(in_circ_id))?;
        if entry.state != CircuitEntryState::Extending {
            return Err(BridgeCircuitError::WrongState {
                circ_id: in_circ_id,
                state: entry.state,
            });
        }
        let out = entry.out_circ_id;
        entry.state = CircuitEntryState::Destroyed;
        entry.state_entered = now;
        let mut actions = Vec::new();
        actions.push(BridgeAction::DestroyPrevLink { in_circ_id });
        if let Some(o) = out {
            actions.push(BridgeAction::DestroyNextLink { out_circ_id: o });
        }
        Ok(actions)
    }

    // Exit-hop return path

    /// Seal a response payload (from the exit TCP dispatcher) with the
    /// circuit's reverse onion layer and surface it as `SendToPrev` for
    /// transmission back to the prev-hop client.
    ///
    /// Call when `TcpStreamDispatcher` delivers a `StreamEvent` (DATA or
    /// END) for a circuit operating in exit mode (no next hop). The
    /// `payload` must be a `RelaySubCell`-encoded body:
    /// - `StreamEvent::Data` -> encode with [`DataBody`] + `CMD_DATA`
    /// - `StreamEvent::End`  -> encode with [`EndBody`]  + `CMD_END`
    ///
    /// Returns an error if `in_circ_id` is unknown or the circuit is
    /// not in `Open` state; callers should log and skip, NOT tear down
    /// the session.
    pub fn inject_exit_response(
        &mut self,
        in_circ_id: u32,
        payload: &[u8],
        now: Instant,
    ) -> Result<Vec<BridgeAction>, BridgeCircuitError> {
        self.handle_relay_from_next(in_circ_id, payload, now)
    }

    // Periodic sweep

    /// Reap stuck / idle / destroyed entries.
    pub fn tick(&mut self, now: Instant) -> Vec<BridgeAction> {
        let mut victims: Vec<(u32, CircuitEntryState)> = Vec::new();
        for (&id, entry) in &self.circuits {
            let state_age = now.saturating_duration_since(entry.state_entered);
            let idle_age = now.saturating_duration_since(entry.last_activity);
            // Closes [RT-P2G-2]: in-flight EXTEND fragmentation
            // older than `pending_extend_timeout` is reaped here
            // - without this check, stuck reassembly buffers
            // pin memory until `idle_ttl` (default 10 min).
            if let Some(p) = entry.pending_extend.as_ref() {
                let pending_age = now.saturating_duration_since(p.started_at);
                if pending_age >= self.policy.pending_extend_timeout {
                    victims.push((id, entry.state));
                    continue;
                }
            }
            // Phase 2I: same protection for in-flight CREATE
            // reassembly. Reuses the same timeout knob -
            // operators tuning one tune both.
            if let Some(p) = entry.pending_create.as_ref() {
                let pending_age = now.saturating_duration_since(p.started_at);
                if pending_age >= self.policy.pending_extend_timeout {
                    victims.push((id, entry.state));
                    continue;
                }
            }
            // Same protection for in-flight CREATED reassembly on the
            // next-hop link - a peer that sends CMD_CREATED then stalls
            // mid-fragmentation must not pin the circuit indefinitely.
            if let Some(p) = entry.pending_created.as_ref() {
                let pending_age = now.saturating_duration_since(p.started_at);
                if pending_age >= self.policy.pending_extend_timeout {
                    victims.push((id, entry.state));
                    continue;
                }
            }
            match entry.state {
                CircuitEntryState::Creating if state_age >= self.policy.creating_timeout => {
                    victims.push((id, entry.state));
                }
                CircuitEntryState::Extending if state_age >= self.policy.extending_timeout => {
                    victims.push((id, entry.state));
                }
                CircuitEntryState::Open if idle_age >= self.policy.idle_ttl => {
                    victims.push((id, entry.state));
                }
                CircuitEntryState::Destroyed => {
                    victims.push((id, entry.state));
                }
                _ => {}
            }
        }
        let mut actions = Vec::new();
        for (id, state) in victims {
            // Build teardown actions BEFORE removing - we need
            // out_circ_id from the entry.
            if state != CircuitEntryState::Destroyed {
                actions.push(BridgeAction::DestroyPrevLink { in_circ_id: id });
            }
            if let Some(entry) = self.circuits.get(&id) {
                if let Some(out) = entry.out_circ_id {
                    if state != CircuitEntryState::Destroyed {
                        actions.push(BridgeAction::DestroyNextLink { out_circ_id: out });
                    }
                    self.out_to_in.remove(&out);
                }
            }
            self.circuits.remove(&id);
        }
        actions
    }

    // Internal handlers

    fn handle_create(
        &mut self,
        circ_id: u32,
        body: &[u8],
        now: Instant,
    ) -> Result<Vec<BridgeAction>, BridgeCircuitError> {
        if self.circuits.contains_key(&circ_id) {
            // Duplicate CREATE for an existing id is a peer-protocol
            // violation. Tear down prev link.
            return Err(BridgeCircuitError::BadState {
                circ_id,
                state: self.circuits[&circ_id].state,
                cmd: CMD_CREATE,
            });
        }
        if self.circuits.len() as u32 >= self.policy.max_circuits {
            return Err(BridgeCircuitError::CircuitCap(self.policy.max_circuits));
        }
        let pending = self.pending_count();
        if pending >= self.policy.max_pending_handshakes {
            return Err(BridgeCircuitError::PendingCap(
                self.policy.max_pending_handshakes,
            ));
        }
        // Phase 2I: parse via HandshakeBody::decode_partial so
        // CMD_CREATE bodies > one cell are accepted (with
        // CMD_CREATE_CONT continuations). Closes [RT-O3]
        // symmetric for the initial dial.
        let (total_len, first_chunk) = crate::extend::HandshakeBody::decode_partial(body)?;
        let pending_create = if first_chunk.len() < total_len {
            Some(PendingCreate {
                total_hs_msg1_len: total_len,
                accumulated: first_chunk.to_vec(),
                started_at: now,
            })
        } else {
            None
        };
        let complete_now = pending_create.is_none();
        let hs_msg1_complete = if complete_now {
            first_chunk.to_vec()
        } else {
            Vec::new()
        };

        self.circuits.insert(
            circ_id,
            CircuitEntry {
                in_circ_id: circ_id,
                out_circ_id: None,
                state: CircuitEntryState::Creating,
                prev_keys: None,
                forward_seq: 0,
                reverse_seq: 0,
                state_entered: now,
                last_activity: now,
                pending_extend: None,
                pending_create,
                pending_created: None,
                // Relay-session (extended-hop) circuits are unauthorized until
                // their CMD_EXTEND_FINISH token is verified; direct-client
                // (entry) circuits are already transport-authenticated.
                token_verified: !self.relay_mode,
                // Set at EXTEND time from how the EXTEND cell arrived.
                extend_via_relay: false,
            },
        );
        if complete_now {
            Ok(vec![BridgeAction::PerformHandshake {
                in_circ_id: circ_id,
                hs_msg1: hs_msg1_complete,
            }])
        } else {
            // Wait for CMD_CREATE_CONT chunks.
            Ok(vec![])
        }
    }

    fn handle_create_cont(
        &mut self,
        circ_id: u32,
        body: &[u8],
        now: Instant,
    ) -> Result<Vec<BridgeAction>, BridgeCircuitError> {
        let entry = self
            .circuits
            .get_mut(&circ_id)
            .ok_or(BridgeCircuitError::UnknownCircuit(circ_id))?;
        if entry.state != CircuitEntryState::Creating {
            return Err(BridgeCircuitError::BadState {
                circ_id,
                state: entry.state,
                cmd: CMD_CREATE_CONT,
            });
        }
        let mut pending = entry
            .pending_create
            .take()
            .ok_or(BridgeCircuitError::BadState {
                circ_id,
                state: entry.state,
                cmd: CMD_CREATE_CONT,
            })?;
        let new_total = pending.accumulated.len().saturating_add(body.len());
        if new_total > pending.total_hs_msg1_len {
            return Err(BridgeCircuitError::ExtendOverflow {
                circ_id,
                got: new_total,
                expected: pending.total_hs_msg1_len,
            });
        }
        pending.accumulated.extend_from_slice(body);
        entry.last_activity = now;
        if pending.accumulated.len() == pending.total_hs_msg1_len {
            // Complete - dispatch handshake.
            let hs_msg1 = pending.accumulated;
            return Ok(vec![BridgeAction::PerformHandshake {
                in_circ_id: circ_id,
                hs_msg1,
            }]);
        }
        entry.pending_create = Some(pending);
        Ok(vec![])
    }

    /// `relayed` records how the EXTEND arrived: `false` for a top-level
    /// `CMD_EXTEND` (this bridge faces the client's prev directly - hop 1),
    /// `true` when peeled from a `CMD_RELAY` inner sub-cell (this bridge is a
    /// deep hop). It is stored on the circuit so `emit_extended` knows whether
    /// to return the EXTENDED raw or reverse-onion-wrapped.
    fn handle_extend(
        &mut self,
        circ_id: u32,
        body: &[u8],
        now: Instant,
        relayed: bool,
    ) -> Result<Vec<BridgeAction>, BridgeCircuitError> {
        let relay_mode = self.relay_mode;
        let entry = self
            .circuits
            .get_mut(&circ_id)
            .ok_or(BridgeCircuitError::UnknownCircuit(circ_id))?;
        if entry.state != CircuitEntryState::Open {
            return Err(BridgeCircuitError::BadState {
                circ_id,
                state: entry.state,
                cmd: CMD_EXTEND,
            });
        }
        // Gate: a relay-session hop must verify its own per-hop token (via
        // CMD_EXTEND_FINISH) before it may be told to extend to a further hop.
        if relay_mode && !entry.token_verified {
            return Err(BridgeCircuitError::Unauthorized(circ_id));
        }
        if entry.out_circ_id.is_some() {
            // Already extended once - Mirage v0.1 doesn't permit
            // re-extending the same circuit.
            return Err(BridgeCircuitError::BadState {
                circ_id,
                state: entry.state,
                cmd: CMD_EXTEND,
            });
        }
        if entry.pending_extend.is_some() {
            // EXTEND already in progress (waiting for CONT chunks).
            return Err(BridgeCircuitError::BadState {
                circ_id,
                state: entry.state,
                cmd: CMD_EXTEND,
            });
        }
        let pending = self.pending_count();
        if pending >= self.policy.max_pending_handshakes {
            return Err(BridgeCircuitError::PendingCap(
                self.policy.max_pending_handshakes,
            ));
        }
        // Phase 2G+: parse only the fixed-size header + first
        // chunk (closes [RT-O3]). If `accumulated.len() ==
        // total_hs_msg1_len`, dispatch immediately (single-cell
        // EXTEND, no continuation needed). Otherwise stash and
        // wait for CMD_EXTEND_CONT.
        let (header, first_chunk) = ExtendHeader::decode_partial(body)?;
        let entry = self.circuits.get_mut(&circ_id).expect("just verified");
        // Record how this EXTEND arrived so the eventual EXTENDED reply is
        // returned the matching way (raw for hop-1, reverse-wrapped for a deep
        // hop). Set here - after all validation, once we commit to extending.
        entry.extend_via_relay = relayed;
        let pending_extend = PendingExtend {
            next_hop_pk: header.next_hop_pk,
            endpoint: header.endpoint,
            total_hs_msg1_len: header.total_hs_msg1_len,
            accumulated: first_chunk.to_vec(),
            started_at: now,
        };
        entry.last_activity = now;

        if pending_extend.accumulated.len() == pending_extend.total_hs_msg1_len {
            // Complete in one cell - dispatch directly.
            return self.dispatch_pending_extend(circ_id, pending_extend, now);
        }
        // Stash and wait for CMD_EXTEND_CONT.
        entry.pending_extend = Some(pending_extend);
        Ok(vec![])
    }

    fn handle_extend_cont(
        &mut self,
        circ_id: u32,
        body: &[u8],
        now: Instant,
    ) -> Result<Vec<BridgeAction>, BridgeCircuitError> {
        let entry = self
            .circuits
            .get_mut(&circ_id)
            .ok_or(BridgeCircuitError::UnknownCircuit(circ_id))?;
        if entry.state != CircuitEntryState::Open {
            return Err(BridgeCircuitError::BadState {
                circ_id,
                state: entry.state,
                cmd: CMD_EXTEND_CONT,
            });
        }
        // Take the pending out so we can mutate without borrowing
        // entry across the dispatch call below.
        let mut pending = entry
            .pending_extend
            .take()
            .ok_or(BridgeCircuitError::BadState {
                circ_id,
                state: entry.state,
                cmd: CMD_EXTEND_CONT,
            })?;
        let new_total = pending.accumulated.len().saturating_add(body.len());
        if new_total > pending.total_hs_msg1_len {
            // Overflow: client sent more bytes than declared.
            // Tear down the pending state - caller MAY retry with
            // a fresh EXTEND.
            return Err(BridgeCircuitError::ExtendOverflow {
                circ_id,
                got: new_total,
                expected: pending.total_hs_msg1_len,
            });
        }
        pending.accumulated.extend_from_slice(body);
        entry.last_activity = now;

        if pending.accumulated.len() == pending.total_hs_msg1_len {
            // Complete - dispatch.
            return self.dispatch_pending_extend(circ_id, pending, now);
        }
        // More chunks expected - restash.
        entry.pending_extend = Some(pending);
        Ok(vec![])
    }

    /// Helper: complete an in-flight EXTEND reassembly. Allocates
    /// `out_circ_id`, transitions to Extending, emits `OpenNextHop`.
    fn dispatch_pending_extend(
        &mut self,
        circ_id: u32,
        pending: PendingExtend,
        now: Instant,
    ) -> Result<Vec<BridgeAction>, BridgeCircuitError> {
        let out_circ_id = self.allocate_out_circ_id()?;
        let entry = self
            .circuits
            .get_mut(&circ_id)
            .ok_or(BridgeCircuitError::UnknownCircuit(circ_id))?;
        entry.state = CircuitEntryState::Extending;
        entry.state_entered = now;
        entry.last_activity = now;
        entry.out_circ_id = Some(out_circ_id);
        entry.pending_extend = None;
        self.out_to_in.insert(out_circ_id, circ_id);
        Ok(vec![BridgeAction::OpenNextHop {
            in_circ_id: circ_id,
            out_circ_id,
            next_hop_pk: pending.next_hop_pk,
            endpoint: pending.endpoint,
            hs_msg1: pending.accumulated,
        }])
    }

    /// Phase 2G: handle a `CMD_EXTEND_FINISH` cell from the
    /// prev-hop link. Forwards the carried `hs_msg3` to the
    /// next-hop link verbatim. Closes [RT-O2].
    ///
    /// Validity rules:
    ///
    /// - The circuit MUST be in `Open` state with an
    ///   `out_circ_id` populated (i.e., already extended at least
    ///   once via `EXTEND`/`EXTENDED`).
    /// - The bridge does NOT inspect `hs_msg3`. Length is bounded
    ///   by the cell payload cap (~1018 B), and `hs_msg3` is
    ///   AEAD-checked end-to-end by the responder's Noise state.
    fn handle_extend_finish(
        &mut self,
        circ_id: u32,
        body: &[u8],
        now: Instant,
    ) -> Result<Vec<BridgeAction>, BridgeCircuitError> {
        let relay_mode = self.relay_mode;
        let entry = self
            .circuits
            .get_mut(&circ_id)
            .ok_or(BridgeCircuitError::UnknownCircuit(circ_id))?;
        if entry.state != CircuitEntryState::Open {
            return Err(BridgeCircuitError::BadState {
                circ_id,
                state: entry.state,
                cmd: CMD_EXTEND_FINISH,
            });
        }
        let parsed = ExtendFinishBody::decode(body)?;
        entry.last_activity = now;
        match entry.out_circ_id {
            // RELAY role: a next hop exists, so this msg-3 is the client's
            // handshake for that next hop - forward it verbatim.
            Some(out_circ_id) => Ok(vec![BridgeAction::ForwardExtendFinishToNext {
                out_circ_id,
                hs_msg3: parsed.hs_msg3,
            }]),
            // TERMINAL role: no next hop, so this msg-3 is addressed to US.
            None => {
                if relay_mode {
                    // Extended-hop reached via relay: verify the per-hop token.
                    Ok(vec![BridgeAction::VerifyExtendFinish {
                        in_circ_id: circ_id,
                        hs_msg3: parsed.hs_msg3,
                    }])
                } else {
                    // Direct-client entry circuit: a terminal EXTEND_FINISH is
                    // a protocol violation (a client never extend-finishes to
                    // its own already-authenticated entry hop).
                    Err(BridgeCircuitError::BadState {
                        circ_id,
                        state: entry.state,
                        cmd: CMD_EXTEND_FINISH,
                    })
                }
            }
        }
    }

    /// Mark a relay-session circuit's per-hop token as verified, unlocking it
    /// for exit dispatch / further extension. Called by the runtime after the
    /// [`BridgeAction::VerifyExtendFinish`] responder step succeeds.
    pub fn record_token_verified(&mut self, circ_id: u32) -> Result<(), BridgeCircuitError> {
        let entry = self
            .circuits
            .get_mut(&circ_id)
            .ok_or(BridgeCircuitError::UnknownCircuit(circ_id))?;
        entry.token_verified = true;
        Ok(())
    }

    fn handle_created_from_next(
        &mut self,
        in_circ_id: u32,
        body: &[u8],
        now: Instant,
    ) -> Result<Vec<BridgeAction>, BridgeCircuitError> {
        // CREATED on the next-hop link carries `hs_msg2` in HandshakeBody
        // framing (`[u16 total][chunk]`), fragmented across CMD_CREATED +
        // CMD_CREATED_CONT when it exceeds one cell (the common case: a real
        // hs_msg2 ~ 1189 B). Decode to the RAW hs_msg2 here - the previous
        // code re-wrapped the still-encoded body, double-prefixing the length
        // and silently dropping every continuation. Once fully reassembled the
        // bridge re-frames it as EXTENDED (+ EXTENDED_CONT) for the prev hop.
        let (total_len, first_chunk) = crate::extend::HandshakeBody::decode_partial(body)?;
        let first_chunk = first_chunk.to_vec();

        let entry = self
            .circuits
            .get_mut(&in_circ_id)
            .ok_or(BridgeCircuitError::UnknownCircuit(in_circ_id))?;
        if entry.state != CircuitEntryState::Extending {
            return Err(BridgeCircuitError::WrongState {
                circ_id: in_circ_id,
                state: entry.state,
            });
        }
        entry.last_activity = now;
        if first_chunk.len() < total_len {
            // More CMD_CREATED_CONT chunks expected - stash and wait.
            entry.pending_created = Some(PendingCreated {
                total_hs_msg2_len: total_len,
                accumulated: first_chunk,
                started_at: now,
            });
            return Ok(vec![]);
        }
        // Complete in a single cell. (entry borrow ends here.)
        self.emit_extended(in_circ_id, first_chunk, now)
    }

    /// Accumulate a `CMD_CREATED_CONT` chunk into the in-flight CREATED
    /// reassembly. Mirrors [`Self::handle_create_cont`] for the return
    /// direction. On completion, emits the EXTENDED(+CONT) flight.
    fn handle_created_cont_from_next(
        &mut self,
        in_circ_id: u32,
        body: &[u8],
        now: Instant,
    ) -> Result<Vec<BridgeAction>, BridgeCircuitError> {
        let complete = {
            let entry = self
                .circuits
                .get_mut(&in_circ_id)
                .ok_or(BridgeCircuitError::UnknownCircuit(in_circ_id))?;
            if entry.state != CircuitEntryState::Extending {
                return Err(BridgeCircuitError::WrongState {
                    circ_id: in_circ_id,
                    state: entry.state,
                });
            }
            let mut pending =
                entry
                    .pending_created
                    .take()
                    .ok_or(BridgeCircuitError::WrongState {
                        circ_id: in_circ_id,
                        state: entry.state,
                    })?;
            let new_total = pending.accumulated.len().saturating_add(body.len());
            if new_total > pending.total_hs_msg2_len {
                return Err(BridgeCircuitError::ExtendOverflow {
                    circ_id: in_circ_id,
                    got: new_total,
                    expected: pending.total_hs_msg2_len,
                });
            }
            pending.accumulated.extend_from_slice(body);
            entry.last_activity = now;
            if pending.accumulated.len() == pending.total_hs_msg2_len {
                Some(std::mem::take(&mut pending.accumulated))
            } else {
                entry.pending_created = Some(pending);
                None
            }
        };
        match complete {
            Some(hs_msg2) => self.emit_extended(in_circ_id, hs_msg2, now),
            None => Ok(vec![]),
        }
    }

    /// Transition a fully-reassembled extend to `Open` and emit the EXTENDED
    /// flight carrying the raw `hs_msg2` back to the prev hop.
    ///
    /// The return framing depends on this circuit's [`CircuitEntry::extend_via_relay`]:
    ///
    /// - **Hop-1 (`false`)**: the prev is the direct-facing client, so emit raw
    ///   `CMD_EXTENDED` (+ `CMD_EXTENDED_CONT`) cells the client reads directly.
    /// - **Deep hop (`true`)**: the prev is an upstream RELAY, so the EXTENDED
    ///   must ride the onion home. Each fragment is wrapped as a
    ///   `RelaySubCell{CMD_EXTENDED/CMD_EXTENDED_CONT}`, sealed with this hop's
    ///   reverse onion key (advancing `reverse_seq` exactly as
    ///   `handle_relay_from_next` does), and emitted as a `CMD_RELAY` cell.
    ///   Each upstream hop then adds its own reverse layer (via its
    ///   `handle_relay_from_next`) and the client peels all of them with
    ///   `Circuit::relay_open`. Fragments reserve `MAX_CIRCUIT_HOPS` onion
    ///   layers + the `RelaySubCell` header so the cell still fits
    ///   `MAX_CELL_PAYLOAD` after the deepest possible re-wrapping (this hop
    ///   cannot know the true circuit depth).
    fn emit_extended(
        &mut self,
        in_circ_id: u32,
        hs_msg2: Vec<u8>,
        now: Instant,
    ) -> Result<Vec<BridgeAction>, BridgeCircuitError> {
        let entry = self
            .circuits
            .get_mut(&in_circ_id)
            .ok_or(BridgeCircuitError::UnknownCircuit(in_circ_id))?;
        entry.state = CircuitEntryState::Open;
        entry.state_entered = now;
        entry.last_activity = now;
        entry.pending_created = None;

        if !entry.extend_via_relay {
            // Hop-1: raw EXTENDED straight to the direct-facing client.
            let (extended_body, cont_bodies) =
                ExtendedBody { hs_msg2 }.encode_fragmented(crate::cell::MAX_CELL_PAYLOAD)?;
            let mut actions = Vec::with_capacity(1 + cont_bodies.len());
            actions.push(BridgeAction::SendToPrev {
                in_circ_id,
                cell: Cell::new(in_circ_id, CMD_EXTENDED, extended_body)?,
            });
            for cont in cont_bodies {
                actions.push(BridgeAction::SendToPrev {
                    in_circ_id,
                    cell: Cell::new(in_circ_id, CMD_EXTENDED_CONT, cont)?,
                });
            }
            return Ok(actions);
        }

        // Deep hop: wrap the EXTENDED as reverse RELAY sub-cells.
        let reverse = entry
            .prev_keys
            .as_ref()
            .ok_or(BridgeCircuitError::NoPrevKeys(in_circ_id))?
            .reverse
            .clone();
        let inner_max = crate::cell::MAX_CELL_PAYLOAD.saturating_sub(
            crate::circuit::MAX_CIRCUIT_HOPS * 16 + crate::extend::RELAY_SUBCELL_HEADER_LEN,
        );
        let (ext_first, ext_conts) = ExtendedBody { hs_msg2 }.encode_fragmented(inner_max)?;
        let mut inner: Vec<(u8, Vec<u8>)> = Vec::with_capacity(1 + ext_conts.len());
        inner.push((CMD_EXTENDED, ext_first));
        for c in ext_conts {
            inner.push((CMD_EXTENDED_CONT, c));
        }

        let mut actions = Vec::with_capacity(inner.len());
        for (cmd, body) in inner {
            let sub = RelaySubCell { command: cmd, body }.encode()?;
            let sealed = onion_seal(
                std::slice::from_ref(&reverse),
                &sub,
                DIR_HOP_TO_CLIENT,
                0,
                entry.reverse_seq,
            )?;
            // Advance the SAME reverse counter DATA uses, so the client's
            // sequential relay_open stays in lockstep across EXTENDED then DATA.
            entry.reverse_seq = entry
                .reverse_seq
                .checked_add(1)
                .ok_or(BridgeCircuitError::SeqExhausted(in_circ_id))?;
            actions.push(BridgeAction::SendToPrev {
                in_circ_id,
                cell: Cell::new(in_circ_id, CMD_RELAY, sealed)?,
            });
        }
        Ok(actions)
    }

    fn handle_relay_from_prev(
        &mut self,
        circ_id: u32,
        body: &[u8],
        now: Instant,
    ) -> Result<Vec<BridgeAction>, BridgeCircuitError> {
        let relay_mode = self.relay_mode;
        let entry = self
            .circuits
            .get_mut(&circ_id)
            .ok_or(BridgeCircuitError::UnknownCircuit(circ_id))?;
        if entry.state != CircuitEntryState::Open {
            return Err(BridgeCircuitError::BadState {
                circ_id,
                state: entry.state,
                cmd: CMD_RELAY,
            });
        }
        let prev_keys = entry
            .prev_keys
            .as_ref()
            .ok_or(BridgeCircuitError::NoPrevKeys(circ_id))?;
        // Peel one onion layer (forward direction).
        let peeled = onion_open(
            std::slice::from_ref(&prev_keys.forward),
            body,
            DIR_CLIENT_TO_HOP,
            0,
            entry.forward_seq,
        )?;
        // checked_add (closes [RT-S1]): a silent u64 wrap would
        // desync our AEAD nonce vs the prev-hop's. Tear down on
        // overflow rather than corrupt subsequent cells.
        entry.forward_seq = entry
            .forward_seq
            .checked_add(1)
            .ok_or(BridgeCircuitError::SeqExhausted(circ_id))?;
        entry.last_activity = now;
        let out_circ_id = entry.out_circ_id;
        // Per-hop authorization gate: on a relay session, a circuit may not be
        // used to reach the network (exit dispatch) or extend further until its
        // capability token has been verified via CMD_EXTEND_FINISH. Only the
        // token-bearing (EXTEND_FINISH) and teardown (DESTROY) control
        // sub-cells are allowed through while unverified.
        let unauthorized = relay_mode && !entry.token_verified;
        //
        // Phase 2G: inner-cell dispatch.
        //
        // After peeling, the bytes may be a [`RelaySubCell`] -
        // compact inner-cell format, 3-byte header - carrying a
        // control sub-command (CMD_EXTEND / CMD_EXTEND_FINISH /
        // CMD_DESTROY) or a stream sub-command (CMD_BEGIN /
        // CMD_DATA / CMD_END / ...).
        //
        // Control sub-commands dispatch INTERNALLY at this hop
        // regardless of `out_circ_id`:
        //
        //   - CMD_EXTEND: client wants this hop to extend further.
        //     Only valid when out_circ_id == None (the bridge's
        //     own handler enforces this; re-extending an
        //     already-extended circuit is rejected).
        //   - CMD_EXTEND_FINISH: client's msg_3 for the next hop.
        //     Only valid when out_circ_id == Some (we need a
        //     next-hop link to forward to). Closes [RT-O2].
        //   - CMD_DESTROY: tear-down through the onion.
        //
        // Other parses (stream sub-commands or non-RelaySubCell
        // payloads) follow the original semantics:
        //
        //   - If out_circ_id Some: forward as RELAY to next hop.
        //   - Else: surface as RelayPayloadAtExit.
        if let Ok(sub) = RelaySubCell::decode(&peeled) {
            match sub.command {
                // Inner EXTEND peeled from a RELAY cell: this bridge is a DEEP
                // hop, so `relayed = true` - the EXTENDED reply must be wrapped
                // as a reverse RELAY sub-cell to reach the client through the
                // onion (a raw CMD_EXTENDED would be rejected by the upstream
                // hop's next-hop handler).
                CMD_EXTEND => return self.handle_extend(circ_id, &sub.body, now, true),
                CMD_EXTEND_CONT => {
                    // Closes [RT-P2G-3]: an inner CMD_EXTEND_CONT
                    // dispatched as a control sub-cell continues
                    // an in-flight EXTEND on THIS hop's
                    // pending_extend state. Forward via the same
                    // handler the top-level path uses; if no
                    // pending reassembly exists, the handler
                    // errors with BadState (right behaviour). The
                    // alternative - falling through to "stream
                    // sub-command" - would silently misdispatch
                    // CONT bytes to the runtime's stream
                    // dispatcher.
                    return self.handle_extend_cont(circ_id, &sub.body, now);
                }
                CMD_EXTEND_FINISH => return self.handle_extend_finish(circ_id, &sub.body, now),
                CMD_DESTROY => return Ok(self.handle_destroy_from_prev(circ_id, now)),
                CMD_PADDING => {
                    // H4: circuit padding-machine cover cell, onion-addressed to
                    // THIS hop by the client. It carries no application data - drop
                    // it silently: never forward, never open/relay a stream. This
                    // adds timing/volume cover on the legs up to this hop without
                    // touching real traffic (flow-correlation resistance for the
                    // multi-hop path). A padding cell for a DEEPER hop stays onion-
                    // wrapped here, fails RelaySubCell::decode, and is forwarded.
                    return Ok(vec![]);
                }
                _ => {
                    // Stream sub-command - fall through to
                    // forward-or-exit logic below.
                }
            }
        }
        // Gate: a relay-session circuit whose per-hop token hasn't been verified
        // may NOT reach the network. Stream sub-cells (exit dispatch) and
        // forwarding are refused until CMD_EXTEND_FINISH verifies the token.
        // (CMD_EXTEND/EXTEND_FINISH/DESTROY returned above; EXTEND is separately
        // gated in `handle_extend`.)
        if unauthorized {
            return Err(BridgeCircuitError::Unauthorized(circ_id));
        }
        if let Some(out) = out_circ_id {
            let new_cell = Cell::new(out, CMD_RELAY, peeled)?;
            return Ok(vec![BridgeAction::SendToNext {
                out_circ_id: out,
                cell: new_cell,
            }]);
        }
        Ok(vec![BridgeAction::RelayPayloadAtExit {
            in_circ_id: circ_id,
            payload: peeled,
        }])
    }

    fn handle_relay_from_next(
        &mut self,
        in_circ_id: u32,
        body: &[u8],
        now: Instant,
    ) -> Result<Vec<BridgeAction>, BridgeCircuitError> {
        let entry = self
            .circuits
            .get_mut(&in_circ_id)
            .ok_or(BridgeCircuitError::UnknownCircuit(in_circ_id))?;
        // Closes [RT-C6] (Phase 2E re-scan): symmetric with
        // `handle_relay_from_prev`, reject reverse RELAYs unless
        // the circuit is fully Open. Without this check, a RELAY
        // arriving during Creating/Extending would still increment
        // `reverse_seq` (line below) - desynchronising the AEAD
        // nonce vs the client's view of the circuit and
        // corrupting all subsequent reverse traffic.
        if entry.state != CircuitEntryState::Open {
            return Err(BridgeCircuitError::BadState {
                circ_id: in_circ_id,
                state: entry.state,
                cmd: CMD_RELAY,
            });
        }
        let prev_keys = entry
            .prev_keys
            .as_ref()
            .ok_or(BridgeCircuitError::NoPrevKeys(in_circ_id))?;
        // Wrap body with our reverse-direction onion layer so the
        // client (holding all reverse keys) can peel sequentially.
        let wrapped = onion_seal(
            std::slice::from_ref(&prev_keys.reverse),
            body,
            DIR_HOP_TO_CLIENT,
            0,
            entry.reverse_seq,
        )?;
        // See [RT-S2] in handle_relay_from_prev for rationale.
        entry.reverse_seq = entry
            .reverse_seq
            .checked_add(1)
            .ok_or(BridgeCircuitError::SeqExhausted(in_circ_id))?;
        entry.last_activity = now;
        let new_cell = Cell::new(in_circ_id, CMD_RELAY, wrapped)?;
        Ok(vec![BridgeAction::SendToPrev {
            in_circ_id,
            cell: new_cell,
        }])
    }

    fn handle_destroy_from_prev(&mut self, circ_id: u32, now: Instant) -> Vec<BridgeAction> {
        let mut actions = Vec::new();
        if let Some(entry) = self.circuits.get_mut(&circ_id) {
            let already_destroyed = entry.state == CircuitEntryState::Destroyed;
            entry.state = CircuitEntryState::Destroyed;
            entry.state_entered = now;
            if !already_destroyed {
                if let Some(out) = entry.out_circ_id {
                    actions.push(BridgeAction::DestroyNextLink { out_circ_id: out });
                }
                // Emit DestroyPrevLink so the executor frees any handshake
                // responder retained for a relay circuit torn down before its
                // EXTEND_FINISH (memory-DoS fix). The DestroyPrevLink handler
                // does NOT write a CMD_DESTROY back to the prev hop, so the
                // deliberate "silent close, don't echo DESTROY" semantics hold.
                actions.push(BridgeAction::DestroyPrevLink {
                    in_circ_id: circ_id,
                });
            }
        }
        actions
    }

    /// Reap a single circuit after a per-circuit fault (a bad/garbage RELAY,
    /// a state violation, sequence exhaustion, an extend overflow). Infallible
    /// best-effort cleanup the session loop calls instead of propagating a
    /// `BridgeCircuitError`, so one circuit's fault never tears down the whole
    /// multiplexed prev-hop session or instantly RSTs the TCP connection
    /// (cross-circuit `DoS` + active-probe distinguisher - RT #3).
    ///
    /// Marks the circuit `Destroyed` (the periodic `tick` removes the
    /// tombstone) and emits DESTROY toward BOTH the next hop (if linked) and
    /// the prev hop - the client did NOT initiate this teardown, so it must be
    /// told this one circuit died while its siblings keep flowing. A no-op for
    /// an unknown `circ_id`.
    pub fn reap_circuit(&mut self, in_circ_id: u32, now: Instant) -> Vec<BridgeAction> {
        let mut actions = Vec::new();
        if let Some(entry) = self.circuits.get_mut(&in_circ_id) {
            let already_destroyed = entry.state == CircuitEntryState::Destroyed;
            entry.state = CircuitEntryState::Destroyed;
            entry.state_entered = now;
            if !already_destroyed {
                if let Some(out) = entry.out_circ_id {
                    actions.push(BridgeAction::DestroyNextLink { out_circ_id: out });
                }
                actions.push(BridgeAction::DestroyPrevLink { in_circ_id });
            }
        }
        actions
    }

    fn handle_destroy_from_next(&mut self, in_circ_id: u32, now: Instant) -> Vec<BridgeAction> {
        let mut actions = Vec::new();
        if let Some(entry) = self.circuits.get_mut(&in_circ_id) {
            let already_destroyed = entry.state == CircuitEntryState::Destroyed;
            entry.state = CircuitEntryState::Destroyed;
            entry.state_entered = now;
            if !already_destroyed {
                actions.push(BridgeAction::DestroyPrevLink { in_circ_id });
            }
        }
        actions
    }

    fn pending_count(&self) -> u32 {
        self.circuits
            .values()
            .filter(|e| {
                matches!(
                    e.state,
                    CircuitEntryState::Creating | CircuitEntryState::Extending
                )
            })
            .count() as u32
    }

    fn allocate_out_circ_id(&mut self) -> Result<u32, BridgeCircuitError> {
        // Try up to 256 picks before giving up. With a 32-bit
        // namespace and bounded `max_circuits`, the probability
        // of 256 consecutive collisions is astronomically small.
        for _ in 0..256u32 {
            self.out_circ_id_seq = self.out_circ_id_seq.wrapping_add(1);
            let candidate = (self.out_circ_id_picker)(self.out_circ_id_seq);
            if candidate == 0 {
                continue; // 0 is reserved
            }
            if !self.out_to_in.contains_key(&candidate) {
                return Ok(candidate);
            }
        }
        Err(BridgeCircuitError::OutCircIdExhausted(256))
    }
}

// Default out_circ_id picker

/// Draw a random 64-bit starting value for `out_circ_id_seq` (#14). On the
/// astronomically-rare OS RNG failure, fall back to 0 (no worse than the old
/// fixed start) rather than panicking a bridge accept path.
fn random_seq_seed() -> u64 {
    let mut b = [0u8; 8];
    match getrandom::fill(&mut b) {
        Ok(()) => u64::from_le_bytes(b),
        Err(_) => 0,
    }
}

/// Deterministic per-seq picker - a golden-ratio mix over the seq counter. The
/// counter itself is CSPRNG-seeded per session (see [`BridgeCircuitState::new`]),
/// so the emitted schedule is unpredictable in production; tests pin this picker
/// AND reset the seq via [`BridgeCircuitState::set_out_circ_id_picker`] for
/// reproducible assertions.
pub fn deterministic_out_circ_id_picker(seq: u64) -> u32 {
    const PHI_FIX: u64 = 0x9E37_79B9_7F4A_7C15;
    let mix = seq.wrapping_mul(PHI_FIX);
    // Top bits give better distribution than low bits.
    let top = (mix >> 32) as u32;
    if top == 0 {
        1
    } else {
        top
    }
}

/// Sequential picker - `seq + 1`. Used in tests to make
/// `circ_id` values trivially predictable for assertions.
pub fn sequential_out_circ_id_picker(seq: u64) -> u32 {
    (seq as u32).wrapping_add(1).max(1)
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cell::CMD_DATA;
    use crate::extend::ExtendBody;
    use crate::keys::derive_hop_keys;

    fn fake_keys(tag: u8) -> HopKeys {
        derive_hop_keys(&[tag; 32], &[tag.wrapping_add(0x10); 32])
    }

    fn create_cell(circ_id: u32) -> Cell {
        // Phase 2I: hs_msg1 is now wrapped in HandshakeBody for
        // fragmentation. 100 B fits in one cell, so the
        // continuation list is empty.
        let body = crate::extend::HandshakeBody {
            hs_msg: vec![0xAB; 100],
        }
        .encode()
        .unwrap();
        Cell::new(circ_id, CMD_CREATE, body).unwrap()
    }

    fn extend_cell(circ_id: u32, next_hop_tag: u8) -> Cell {
        let body = ExtendBody {
            next_hop_pk: [next_hop_tag; 32],
            endpoint: HopEndpoint::Ipv4 {
                addr: [10, 0, 0, next_hop_tag],
                port: 4433,
            },
            hs_msg1: vec![0xCD; 100],
        }
        .encode()
        .unwrap();
        Cell::new(circ_id, CMD_EXTEND, body).unwrap()
    }

    fn destroy_cell(circ_id: u32) -> Cell {
        Cell::new(circ_id, CMD_DESTROY, vec![]).unwrap()
    }

    fn state_with(seq_picker: bool) -> BridgeCircuitState {
        let mut s = BridgeCircuitState::new(BridgePolicy::default());
        if seq_picker {
            s.set_out_circ_id_picker(sequential_out_circ_id_picker);
        }
        s
    }

    // --- CREATE / CREATED ---

    #[test]
    fn create_emits_perform_handshake() {
        let mut s = state_with(true);
        let now = Instant::now();
        let actions = s.process_inbound_from_prev(create_cell(7), now).unwrap();
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            BridgeAction::PerformHandshake {
                in_circ_id,
                hs_msg1,
            } => {
                assert_eq!(*in_circ_id, 7);
                assert_eq!(hs_msg1.len(), 100);
            }
            _ => panic!("expected PerformHandshake"),
        }
        assert_eq!(s.circuit_state(7), Some(CircuitEntryState::Creating));
    }

    #[test]
    fn record_create_complete_emits_created_cell_and_opens() {
        let mut s = state_with(true);
        let now = Instant::now();
        s.process_inbound_from_prev(create_cell(7), now).unwrap();
        let actions = s
            .record_create_complete(7, fake_keys(1), vec![0xEF; 200], now)
            .unwrap();
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            BridgeAction::SendToPrev { in_circ_id, cell } => {
                assert_eq!(*in_circ_id, 7);
                assert_eq!(cell.command, CMD_CREATED);
                assert_eq!(cell.circ_id, 7);
                // Phase 2I: CREATED body is now [u16 total_len]
                // + first chunk. 200 B msg2 -> 202 B body.
                assert_eq!(cell.body.len(), 200 + 2);
            }
            _ => panic!("expected SendToPrev"),
        }
        assert_eq!(s.circuit_state(7), Some(CircuitEntryState::Open));
    }

    /// RT #3: reaping one circuit after a per-circuit fault destroys ONLY
    /// that circuit; siblings on the same session keep flowing.
    #[test]
    fn reap_circuit_is_local_to_one_circuit() {
        let mut s = state_with(true);
        let now = Instant::now();
        // Open two independent circuits on the same session.
        s.process_inbound_from_prev(create_cell(7), now).unwrap();
        s.record_create_complete(7, fake_keys(1), vec![0xEF; 200], now)
            .unwrap();
        s.process_inbound_from_prev(create_cell(9), now).unwrap();
        s.record_create_complete(9, fake_keys(2), vec![0xEF; 200], now)
            .unwrap();
        assert_eq!(s.circuit_state(7), Some(CircuitEntryState::Open));
        assert_eq!(s.circuit_state(9), Some(CircuitEntryState::Open));

        // Reap circuit 7 (as the session loop does on a per-circuit error).
        let actions = s.reap_circuit(7, now);
        assert_eq!(s.circuit_state(7), Some(CircuitEntryState::Destroyed));
        // The sibling is untouched - no cross-circuit teardown.
        assert_eq!(s.circuit_state(9), Some(CircuitEntryState::Open));
        // The client is told this one circuit died.
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, BridgeAction::DestroyPrevLink { in_circ_id: 7 })),
            "reap must signal the prev hop for the reaped circuit"
        );
        // Reaping an unknown circuit is a harmless no-op.
        assert!(s.reap_circuit(999, now).is_empty());
    }

    #[test]
    fn record_create_failure_destroys_prev_link() {
        let mut s = state_with(true);
        let now = Instant::now();
        s.process_inbound_from_prev(create_cell(7), now).unwrap();
        let actions = s.record_create_failure(7, now).unwrap();
        assert!(actions
            .iter()
            .any(|a| matches!(a, BridgeAction::DestroyPrevLink { in_circ_id: 7 })));
        assert_eq!(s.circuit_state(7), Some(CircuitEntryState::Destroyed));
    }

    #[test]
    fn duplicate_create_for_same_circ_id_rejected() {
        let mut s = state_with(true);
        let now = Instant::now();
        s.process_inbound_from_prev(create_cell(7), now).unwrap();
        let err = s
            .process_inbound_from_prev(create_cell(7), now)
            .unwrap_err();
        assert!(matches!(err, BridgeCircuitError::BadState { .. }));
    }

    // --- EXTEND / EXTENDED ---

    fn open_circuit(s: &mut BridgeCircuitState, circ_id: u32, now: Instant) {
        s.process_inbound_from_prev(create_cell(circ_id), now)
            .unwrap();
        s.record_create_complete(circ_id, fake_keys(circ_id as u8), vec![0; 200], now)
            .unwrap();
    }

    #[test]
    fn extend_on_open_circuit_emits_open_next_hop() {
        let mut s = state_with(true);
        let now = Instant::now();
        open_circuit(&mut s, 7, now);
        let actions = s
            .process_inbound_from_prev(extend_cell(7, 0x42), now)
            .unwrap();
        match actions.first().unwrap() {
            BridgeAction::OpenNextHop {
                in_circ_id,
                out_circ_id,
                next_hop_pk,
                endpoint,
                hs_msg1,
            } => {
                assert_eq!(*in_circ_id, 7);
                assert_eq!(*next_hop_pk, [0x42u8; 32]);
                assert!(matches!(endpoint, HopEndpoint::Ipv4 { .. }));
                assert_eq!(hs_msg1.len(), 100);
                // The action carries the same out_circ_id the state
                // machine registered for the return-path mapping.
                assert_eq!(s.out_circ_id_for(7), Some(*out_circ_id));
            }
            _ => panic!("expected OpenNextHop"),
        }
        assert_eq!(s.circuit_state(7), Some(CircuitEntryState::Extending));
        // out_circ_id has been allocated and registered.
        let out = s.out_circ_id_for(7).unwrap();
        assert_eq!(s.in_circ_id_for(out), Some(7));
    }

    #[test]
    fn fragmented_created_from_next_reassembles_to_extended_round_trip() {
        // The deanonymization-critical path: a real hs_msg2 (~1189 B with
        // ML-KEM-768) exceeds one cell, so the next hop sends CMD_CREATED +
        // CMD_CREATED_CONT. The relay must reassemble it and re-emit
        // CMD_EXTENDED + CMD_EXTENDED_CONT such that the client recovers the
        // EXACT bytes hop2 produced - no truncation, no double-encoding.
        let mut s = state_with(true);
        let now = Instant::now();
        open_circuit(&mut s, 7, now);
        s.process_inbound_from_prev(extend_cell(7, 0x42), now)
            .unwrap();
        let out = s.out_circ_id_for(7).unwrap();
        assert_eq!(s.circuit_state(7), Some(CircuitEntryState::Extending));

        // hop2's hs_msg2, sized to force fragmentation, with a recognisable
        // non-trivial byte pattern.
        let hs_msg2: Vec<u8> = (0..1189u32)
            .map(|i| (i.wrapping_mul(31) % 251) as u8)
            .collect();
        let (first, conts) = crate::extend::HandshakeBody {
            hs_msg: hs_msg2.clone(),
        }
        .encode_fragmented(crate::cell::MAX_CELL_PAYLOAD)
        .unwrap();
        assert!(
            !conts.is_empty(),
            "test is only meaningful if hs_msg2 actually fragments"
        );

        // Feed the wire cells the next hop would send.
        let mut acts = s
            .process_inbound_from_next(Cell::new(out, CMD_CREATED, first).unwrap(), now)
            .unwrap();
        for c in conts {
            acts.extend(
                s.process_inbound_from_next(Cell::new(out, CMD_CREATED_CONT, c).unwrap(), now)
                    .unwrap(),
            );
        }
        assert_eq!(
            s.circuit_state(7),
            Some(CircuitEntryState::Open),
            "circuit opens once the full CREATED is reassembled"
        );

        // Reassemble the EXTENDED(+CONT) cells the prev-hop client receives.
        let cells: Vec<&Cell> = acts
            .iter()
            .filter_map(|a| match a {
                BridgeAction::SendToPrev { cell, .. } => Some(cell),
                _ => None,
            })
            .collect();
        assert!(!cells.is_empty(), "must emit at least one EXTENDED");
        assert_eq!(cells[0].command, CMD_EXTENDED);
        for c in &cells[1..] {
            assert_eq!(c.command, CMD_EXTENDED_CONT);
        }
        let (total, chunk0) = ExtendedBody::decode_partial(&cells[0].body).unwrap();
        let mut recovered = chunk0.to_vec();
        for c in &cells[1..] {
            recovered.extend_from_slice(&c.body);
        }
        assert_eq!(recovered.len(), total, "reassembled length matches header");
        assert_eq!(
            recovered, hs_msg2,
            "client must recover the EXACT hs_msg2 the next hop produced"
        );
    }

    #[test]
    fn record_extend_complete_fragments_large_hs_msg2() {
        // A real ML-KEM hs_msg2 exceeds one cell; record_extend_complete must
        // fragment it across EXTENDED + EXTENDED_CONT, not error.
        let mut s = state_with(true);
        let now = Instant::now();
        open_circuit(&mut s, 7, now);
        s.process_inbound_from_prev(extend_cell(7, 0x42), now)
            .unwrap();
        let hs_msg2: Vec<u8> = (0..1189u32).map(|i| (i % 251) as u8).collect();
        let actions = s.record_extend_complete(7, hs_msg2.clone(), now).unwrap();
        let cells: Vec<&Cell> = actions
            .iter()
            .filter_map(|a| match a {
                BridgeAction::SendToPrev { cell, .. } => Some(cell),
                _ => None,
            })
            .collect();
        assert!(cells.len() >= 2, "large hs_msg2 must fragment");
        assert_eq!(cells[0].command, CMD_EXTENDED);
        let (total, chunk0) = ExtendedBody::decode_partial(&cells[0].body).unwrap();
        let mut recovered = chunk0.to_vec();
        for c in &cells[1..] {
            assert_eq!(c.command, CMD_EXTENDED_CONT);
            recovered.extend_from_slice(&c.body);
        }
        assert_eq!(recovered.len(), total);
        assert_eq!(recovered, hs_msg2);
        assert_eq!(s.circuit_state(7), Some(CircuitEntryState::Open));
    }

    #[test]
    fn record_extend_complete_emits_extended_and_opens() {
        let mut s = state_with(true);
        let now = Instant::now();
        open_circuit(&mut s, 7, now);
        s.process_inbound_from_prev(extend_cell(7, 0x42), now)
            .unwrap();
        // Runtime reports CREATED with hs_msg2.
        let actions = s.record_extend_complete(7, vec![0xAA; 150], now).unwrap();
        match actions.first().unwrap() {
            BridgeAction::SendToPrev { in_circ_id, cell } => {
                assert_eq!(*in_circ_id, 7);
                assert_eq!(cell.command, CMD_EXTENDED);
                assert_eq!(cell.circ_id, 7);
            }
            _ => panic!("expected SendToPrev"),
        }
        assert_eq!(s.circuit_state(7), Some(CircuitEntryState::Open));
    }

    #[test]
    fn record_extend_failure_destroys_both_directions() {
        let mut s = state_with(true);
        let now = Instant::now();
        open_circuit(&mut s, 7, now);
        s.process_inbound_from_prev(extend_cell(7, 0x42), now)
            .unwrap();
        let out = s.out_circ_id_for(7).unwrap();
        let actions = s.record_extend_failure(7, now).unwrap();
        assert!(actions
            .iter()
            .any(|a| matches!(a, BridgeAction::DestroyPrevLink { in_circ_id: 7 })));
        assert!(actions.iter().any(|a| matches!(
            a,
            BridgeAction::DestroyNextLink { out_circ_id: o } if *o == out
        )));
        assert_eq!(s.circuit_state(7), Some(CircuitEntryState::Destroyed));
    }

    #[test]
    fn extend_on_creating_circuit_rejected() {
        let mut s = state_with(true);
        let now = Instant::now();
        s.process_inbound_from_prev(create_cell(7), now).unwrap();
        // Don't call record_create_complete; circuit is Creating.
        let err = s
            .process_inbound_from_prev(extend_cell(7, 0x42), now)
            .unwrap_err();
        assert!(matches!(err, BridgeCircuitError::BadState { .. }));
    }

    #[test]
    fn extend_twice_on_same_circuit_rejected() {
        let mut s = state_with(true);
        let now = Instant::now();
        open_circuit(&mut s, 7, now);
        s.process_inbound_from_prev(extend_cell(7, 0x42), now)
            .unwrap();
        s.record_extend_complete(7, vec![0; 100], now).unwrap();
        // Second EXTEND: rejected (out_circ_id already set).
        let err = s
            .process_inbound_from_prev(extend_cell(7, 0x43), now)
            .unwrap_err();
        assert!(matches!(err, BridgeCircuitError::BadState { .. }));
    }

    // --- DESTROY ---

    #[test]
    fn destroy_from_prev_destroys_circuit_and_next_link() {
        let mut s = state_with(true);
        let now = Instant::now();
        open_circuit(&mut s, 7, now);
        s.process_inbound_from_prev(extend_cell(7, 0x42), now)
            .unwrap();
        s.record_extend_complete(7, vec![0; 100], now).unwrap();
        let out = s.out_circ_id_for(7).unwrap();
        let actions = s.process_inbound_from_prev(destroy_cell(7), now).unwrap();
        // Should emit DestroyNextLink for the out-link.
        assert!(actions.iter().any(|a| matches!(
            a,
            BridgeAction::DestroyNextLink { out_circ_id: o } if *o == out
        )));
        assert_eq!(s.circuit_state(7), Some(CircuitEntryState::Destroyed));
    }

    #[test]
    fn destroy_from_next_destroys_circuit_and_prev_link() {
        let mut s = state_with(true);
        let now = Instant::now();
        open_circuit(&mut s, 7, now);
        s.process_inbound_from_prev(extend_cell(7, 0x42), now)
            .unwrap();
        s.record_extend_complete(7, vec![0; 100], now).unwrap();
        let out = s.out_circ_id_for(7).unwrap();
        // Inbound DESTROY from next-hop -> bridge sends DestroyPrevLink.
        let actions = s.process_inbound_from_next(destroy_cell(out), now).unwrap();
        assert!(actions
            .iter()
            .any(|a| matches!(a, BridgeAction::DestroyPrevLink { in_circ_id: 7 })));
        assert_eq!(s.circuit_state(7), Some(CircuitEntryState::Destroyed));
    }

    #[test]
    fn destroy_idempotent() {
        let mut s = state_with(true);
        let now = Instant::now();
        open_circuit(&mut s, 7, now);
        s.process_inbound_from_prev(destroy_cell(7), now).unwrap();
        // Second DESTROY: no actions emitted (already destroyed).
        let actions = s.process_inbound_from_prev(destroy_cell(7), now).unwrap();
        assert!(actions.is_empty());
        assert_eq!(s.circuit_state(7), Some(CircuitEntryState::Destroyed));
    }

    // --- Inbound from next-hop (cell forwarding) ---

    #[test]
    fn inbound_from_next_rewrites_circ_id_and_forwards() {
        // After EXTEND completes, an arbitrary cell on the
        // next-hop link gets its circ_id rewritten to in_circ_id
        // and forwarded as SendToPrev.
        let mut s = state_with(true);
        let now = Instant::now();
        open_circuit(&mut s, 7, now);
        s.process_inbound_from_prev(extend_cell(7, 0x42), now)
            .unwrap();
        s.record_extend_complete(7, vec![0; 100], now).unwrap();
        let out = s.out_circ_id_for(7).unwrap();
        // Synthesise a RELAY-ish cell from the next hop
        // (Phase 2D handles RELAY semantics; for Phase 2C the
        // bridge just forwards opaque cells unchanged after
        // circ_id rewrite).
        let inbound = Cell::new(out, crate::cell::CMD_RELAY, vec![0xDE; 50]).unwrap();
        let actions = s.process_inbound_from_next(inbound, now).unwrap();
        match actions.first().unwrap() {
            BridgeAction::SendToPrev { in_circ_id, cell } => {
                assert_eq!(*in_circ_id, 7);
                assert_eq!(cell.circ_id, 7);
                assert_eq!(cell.command, crate::cell::CMD_RELAY);
            }
            _ => panic!("expected SendToPrev"),
        }
    }

    #[test]
    fn inbound_from_next_with_unknown_out_circ_id_errors() {
        let mut s = state_with(true);
        let now = Instant::now();
        let cell = Cell::new(99, crate::cell::CMD_RELAY, vec![0; 50]).unwrap();
        let err = s.process_inbound_from_next(cell, now).unwrap_err();
        assert_eq!(err, BridgeCircuitError::UnknownCircuit(99));
    }

    #[test]
    fn inbound_from_next_with_unexpected_command_is_rejected_not_forwarded() {
        // SECURITY (#15): a next-hop cell whose command is not one of the valid
        // reverse commands (CREATED/CREATED_CONT/DESTROY/RELAY) must be REJECTED,
        // never blind-forwarded to the client. Forwarding it verbatim used to let
        // a malicious next hop inject unauthenticated bytes past the reverse
        // onion layer straight to the client.
        let mut s = state_with(true);
        let now = Instant::now();
        open_circuit(&mut s, 7, now);
        s.process_inbound_from_prev(extend_cell(7, 0x42), now)
            .unwrap();
        s.record_extend_complete(7, vec![0; 100], now).unwrap();
        let out = s.out_circ_id_for(7).unwrap();
        // CMD_CREATE is a forward (prev->bridge) command; arriving FROM the next
        // hop it is a protocol violation and must not reach the client.
        let bogus = Cell::new(out, crate::cell::CMD_CREATE, vec![0xAB; 40]).unwrap();
        let err = s.process_inbound_from_next(bogus, now).unwrap_err();
        assert!(
            matches!(err, BridgeCircuitError::BadState { cmd, .. } if cmd == crate::cell::CMD_CREATE),
            "unexpected next-hop command must be rejected, got {err:?}"
        );
    }

    // --- Caps + sweep ---

    #[test]
    fn max_circuits_cap_enforced() {
        let policy = BridgePolicy {
            max_circuits: 2,
            max_pending_handshakes: 4,
            ..Default::default()
        };
        let mut s = BridgeCircuitState::new(policy);
        s.set_out_circ_id_picker(sequential_out_circ_id_picker);
        let now = Instant::now();
        s.process_inbound_from_prev(create_cell(1), now).unwrap();
        s.process_inbound_from_prev(create_cell(2), now).unwrap();
        let err = s
            .process_inbound_from_prev(create_cell(3), now)
            .unwrap_err();
        assert!(matches!(err, BridgeCircuitError::CircuitCap(2)));
    }

    #[test]
    fn pending_handshakes_cap_enforced() {
        let policy = BridgePolicy {
            max_pending_handshakes: 2,
            ..Default::default()
        };
        let mut s = BridgeCircuitState::new(policy);
        s.set_out_circ_id_picker(sequential_out_circ_id_picker);
        let now = Instant::now();
        s.process_inbound_from_prev(create_cell(1), now).unwrap();
        s.process_inbound_from_prev(create_cell(2), now).unwrap();
        // Both Creating; pending = 2 = cap. Third CREATE rejected.
        let err = s
            .process_inbound_from_prev(create_cell(3), now)
            .unwrap_err();
        assert!(matches!(err, BridgeCircuitError::PendingCap(2)));
    }

    #[test]
    fn tick_sweeps_creating_past_timeout() {
        let policy = BridgePolicy {
            creating_timeout: Duration::from_millis(50),
            ..Default::default()
        };
        let mut s = BridgeCircuitState::new(policy);
        s.set_out_circ_id_picker(sequential_out_circ_id_picker);
        let t0 = Instant::now();
        s.process_inbound_from_prev(create_cell(7), t0).unwrap();
        // Sweep at t0 + 200ms: the Creating entry is past timeout.
        let actions = s.tick(t0 + Duration::from_millis(200));
        assert!(actions
            .iter()
            .any(|a| matches!(a, BridgeAction::DestroyPrevLink { in_circ_id: 7 })));
        assert_eq!(s.circuit_state(7), None);
    }

    #[test]
    fn tick_sweeps_extending_past_timeout() {
        let policy = BridgePolicy {
            extending_timeout: Duration::from_millis(50),
            ..Default::default()
        };
        let mut s = BridgeCircuitState::new(policy);
        s.set_out_circ_id_picker(sequential_out_circ_id_picker);
        let t0 = Instant::now();
        open_circuit(&mut s, 7, t0);
        s.process_inbound_from_prev(extend_cell(7, 0x42), t0)
            .unwrap();
        let out = s.out_circ_id_for(7).unwrap();
        let actions = s.tick(t0 + Duration::from_millis(200));
        // Both prev and next teardown emitted.
        assert!(actions
            .iter()
            .any(|a| matches!(a, BridgeAction::DestroyPrevLink { in_circ_id: 7 })));
        assert!(actions.iter().any(|a| matches!(
            a,
            BridgeAction::DestroyNextLink { out_circ_id: o } if *o == out
        )));
        assert_eq!(s.circuit_state(7), None);
    }

    #[test]
    fn tick_sweeps_idle_open_past_idle_ttl() {
        let policy = BridgePolicy {
            idle_ttl: Duration::from_millis(50),
            ..Default::default()
        };
        let mut s = BridgeCircuitState::new(policy);
        s.set_out_circ_id_picker(sequential_out_circ_id_picker);
        let t0 = Instant::now();
        open_circuit(&mut s, 7, t0);
        // No activity past idle_ttl.
        let actions = s.tick(t0 + Duration::from_millis(200));
        assert!(actions
            .iter()
            .any(|a| matches!(a, BridgeAction::DestroyPrevLink { in_circ_id: 7 })));
        assert_eq!(s.circuit_state(7), None);
    }

    #[test]
    fn tick_removes_destroyed_entries() {
        let mut s = state_with(true);
        let now = Instant::now();
        open_circuit(&mut s, 7, now);
        s.process_inbound_from_prev(destroy_cell(7), now).unwrap();
        assert_eq!(s.circuit_state(7), Some(CircuitEntryState::Destroyed));
        // Sweep (with sufficient time elapsed for any state).
        let _ = s.tick(now);
        assert_eq!(s.circuit_state(7), None);
    }

    // --- Circ-id translation correctness ---

    #[test]
    fn out_circ_id_unique_across_extending_circuits() {
        let mut s = state_with(true);
        let now = Instant::now();
        // Open and extend three circuits simultaneously.
        for cid in [1u32, 2, 3] {
            open_circuit(&mut s, cid, now);
            s.process_inbound_from_prev(extend_cell(cid, 0x42 + cid as u8), now)
                .unwrap();
        }
        let outs: Vec<u32> = (1u32..=3).map(|c| s.out_circ_id_for(c).unwrap()).collect();
        // All distinct.
        let mut sorted = outs.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(outs.len(), sorted.len());
        // Reverse map agrees.
        for (cid, out) in (1u32..=3).zip(outs.iter()) {
            assert_eq!(s.in_circ_id_for(*out), Some(cid));
        }
    }

    #[test]
    fn deterministic_picker_avoids_zero() {
        for seq in 0u64..1000 {
            assert_ne!(deterministic_out_circ_id_picker(seq), 0);
        }
    }

    #[test]
    fn record_extend_complete_unknown_circ_id_errors() {
        let mut s = state_with(true);
        let err = s
            .record_extend_complete(99, vec![0; 50], Instant::now())
            .unwrap_err();
        assert_eq!(err, BridgeCircuitError::UnknownCircuit(99));
    }

    // --- RELAY handling (Phase 2D) ---

    /// Build a cell sealed by the client side of the circuit so
    /// the bridge can peel one layer with `prev_keys.forward`.
    /// Models a 1-hop scenario where the bridge IS the exit.
    fn client_sealed_cell(circ_id: u32, bridge_keys: &HopKeys, seq: u64, payload: &[u8]) -> Cell {
        let body = crate::onion::onion_seal(
            std::slice::from_ref(&bridge_keys.forward),
            payload,
            crate::circuit::DIR_CLIENT_TO_HOP,
            0,
            seq,
        )
        .unwrap();
        Cell::new(circ_id, CMD_RELAY, body).unwrap()
    }

    /// Open a 1-hop circuit (no out-link -> bridge is exit) and
    /// record the keys we used so tests can build matching
    /// sealed cells.
    fn open_exit_circuit(s: &mut BridgeCircuitState, circ_id: u32, now: Instant) -> HopKeys {
        let keys = fake_keys(circ_id as u8);
        s.process_inbound_from_prev(create_cell(circ_id), now)
            .unwrap();
        s.record_create_complete(circ_id, keys.clone(), vec![0; 200], now)
            .unwrap();
        keys
    }

    #[test]
    fn relay_at_exit_emits_relay_payload_at_exit() {
        // Bridge is the LAST hop. Inbound RELAY peels with our
        // forward key; result is the original client payload,
        // surfaced as `RelayPayloadAtExit`.
        let mut s = state_with(true);
        let now = Instant::now();
        let keys = open_exit_circuit(&mut s, 7, now);
        let payload = b"hello exit hop";
        let sealed = client_sealed_cell(7, &keys, 0, payload);
        let actions = s.process_inbound_from_prev(sealed, now).unwrap();
        match actions.first().unwrap() {
            BridgeAction::RelayPayloadAtExit {
                in_circ_id,
                payload: pl,
            } => {
                assert_eq!(*in_circ_id, 7);
                assert_eq!(pl, payload);
            }
            other => panic!("expected RelayPayloadAtExit, got {other:?}"),
        }
    }

    #[test]
    fn padding_sub_cell_is_dropped_at_hop() {
        // H4: an onion-sealed CMD_PADDING cover cell must be CONSUMED (no
        // actions) at the hop that peels it - never forwarded to a next hop,
        // never surfaced at exit as application data. This is the cover traffic
        // that gives the multi-hop path flow-correlation resistance.
        let mut s = state_with(true);
        let now = Instant::now();
        let keys = open_exit_circuit(&mut s, 7, now);
        // The inner payload Circuit::build_padding_payload seals: a CMD_PADDING
        // sub-cell with an empty body.
        let padding = crate::extend::RelaySubCell {
            command: crate::cell::CMD_PADDING,
            body: Vec::new(),
        }
        .encode()
        .unwrap();
        let sealed = client_sealed_cell(7, &keys, 0, &padding);
        let actions = s.process_inbound_from_prev(sealed, now).unwrap();
        assert!(
            actions.is_empty(),
            "a CMD_PADDING cell must be dropped (no bridge actions), got {actions:?}"
        );
    }

    #[test]
    fn relay_forward_seq_increments_per_cell() {
        let mut s = state_with(true);
        let now = Instant::now();
        let keys = open_exit_circuit(&mut s, 7, now);
        // Three sequential RELAYs with seq 0, 1, 2.
        for (seq, msg) in (0u64..3).zip(["one", "two", "three"]) {
            let cell = client_sealed_cell(7, &keys, seq, msg.as_bytes());
            let actions = s.process_inbound_from_prev(cell, now).unwrap();
            match actions.first().unwrap() {
                BridgeAction::RelayPayloadAtExit { payload, .. } => {
                    assert_eq!(payload, msg.as_bytes());
                }
                _ => panic!("expected RelayPayloadAtExit"),
            }
        }
    }

    #[test]
    fn relay_with_wrong_seq_fails_aead() {
        let mut s = state_with(true);
        let now = Instant::now();
        let keys = open_exit_circuit(&mut s, 7, now);
        // Client sealed with seq=5 but bridge expects seq=0.
        let cell = client_sealed_cell(7, &keys, 5, b"bad");
        let err = s.process_inbound_from_prev(cell, now).unwrap_err();
        assert!(matches!(err, BridgeCircuitError::Onion(_)));
    }

    #[test]
    fn relay_at_middle_hop_forwards_with_circ_id_rewrite() {
        // Bridge has prev + next links. Inbound RELAY peels one
        // layer, forwards remaining ciphertext to next hop with
        // out_circ_id.
        let mut s = state_with(true);
        let now = Instant::now();
        let keys = open_exit_circuit(&mut s, 7, now);
        // Now extend so this circuit has an out-link.
        s.process_inbound_from_prev(extend_cell(7, 0x42), now)
            .unwrap();
        s.record_extend_complete(7, vec![0; 100], now).unwrap();
        let out = s.out_circ_id_for(7).unwrap();
        // Client sends RELAY with a 2-layer onion: outer = bridge,
        // inner = next hop. We simulate by sealing once with the
        // bridge's key over an opaque inner ciphertext.
        let inner_ct = b"opaque next-hop ciphertext".to_vec();
        let cell = client_sealed_cell(7, &keys, 0, &inner_ct);
        let actions = s.process_inbound_from_prev(cell, now).unwrap();
        match actions.first().unwrap() {
            BridgeAction::SendToNext { out_circ_id, cell } => {
                assert_eq!(*out_circ_id, out);
                assert_eq!(cell.circ_id, out);
                assert_eq!(cell.command, CMD_RELAY);
                assert_eq!(cell.body, inner_ct);
            }
            other => panic!("expected SendToNext, got {other:?}"),
        }
    }

    #[test]
    fn relay_from_next_wraps_with_reverse_layer_and_forwards_to_prev() {
        // Reverse direction: cell from next-hop link gets wrapped
        // with our reverse layer so the client can peel.
        let mut s = state_with(true);
        let now = Instant::now();
        let keys = open_exit_circuit(&mut s, 7, now);
        s.process_inbound_from_prev(extend_cell(7, 0x42), now)
            .unwrap();
        s.record_extend_complete(7, vec![0; 100], now).unwrap();
        let out = s.out_circ_id_for(7).unwrap();
        let inbound_payload = b"raw bytes from next hop";
        let inbound = Cell::new(out, CMD_RELAY, inbound_payload.to_vec()).unwrap();
        let actions = s.process_inbound_from_next(inbound, now).unwrap();
        match actions.first().unwrap() {
            BridgeAction::SendToPrev { in_circ_id, cell } => {
                assert_eq!(*in_circ_id, 7);
                assert_eq!(cell.circ_id, 7);
                assert_eq!(cell.command, CMD_RELAY);
                // Body is now sealed with bridge's reverse key -
                // verify by peeling it back manually.
                let peeled = crate::onion::onion_open(
                    std::slice::from_ref(&keys.reverse),
                    &cell.body,
                    crate::circuit::DIR_HOP_TO_CLIENT,
                    0,
                    0,
                )
                .unwrap();
                assert_eq!(peeled, inbound_payload);
            }
            other => panic!("expected SendToPrev, got {other:?}"),
        }
    }

    #[test]
    fn relay_on_creating_circuit_rejected() {
        // RELAY before CREATE handshake completes: no prev_keys
        // -> NoPrevKeys error AFTER state check (which returns
        // BadState first because state is Creating, not Open).
        let mut s = state_with(true);
        let now = Instant::now();
        s.process_inbound_from_prev(create_cell(7), now).unwrap();
        // Don't complete handshake; circuit is Creating.
        let cell = Cell::new(7, CMD_RELAY, vec![0; 50]).unwrap();
        let err = s.process_inbound_from_prev(cell, now).unwrap_err();
        assert!(matches!(err, BridgeCircuitError::BadState { .. }));
    }

    #[test]
    fn relay_for_unknown_circ_id_errors() {
        let mut s = state_with(true);
        let now = Instant::now();
        let cell = Cell::new(99, CMD_RELAY, vec![0; 50]).unwrap();
        let err = s.process_inbound_from_prev(cell, now).unwrap_err();
        assert_eq!(err, BridgeCircuitError::UnknownCircuit(99));
    }

    #[test]
    fn forward_seq_at_u64_max_returns_seq_exhausted() {
        // RT-S1 closure: prove the checked_add tears the circuit
        // down rather than wrapping silently.
        let mut s = state_with(true);
        let now = Instant::now();
        let keys = open_exit_circuit(&mut s, 7, now);
        // Manually push the entry's forward_seq to u64::MAX.
        s.circuits.get_mut(&7).unwrap().forward_seq = u64::MAX;
        // Build the cell at seq=u64::MAX (which the bridge will
        // try to peel; the AEAD will succeed since we sealed at
        // the same seq).
        let cell = client_sealed_cell(7, &keys, u64::MAX, b"final");
        let err = s.process_inbound_from_prev(cell, now).unwrap_err();
        assert_eq!(err, BridgeCircuitError::SeqExhausted(7));
    }

    #[test]
    fn reverse_seq_at_u64_max_returns_seq_exhausted() {
        // RT-S2 closure: same property in the reverse direction.
        let mut s = state_with(true);
        let now = Instant::now();
        let _keys = open_exit_circuit(&mut s, 7, now);
        s.process_inbound_from_prev(extend_cell(7, 0x42), now)
            .unwrap();
        s.record_extend_complete(7, vec![0; 100], now).unwrap();
        let out = s.out_circ_id_for(7).unwrap();
        s.circuits.get_mut(&7).unwrap().reverse_seq = u64::MAX;
        let inbound = Cell::new(out, CMD_RELAY, vec![0xAA; 32]).unwrap();
        let err = s.process_inbound_from_next(inbound, now).unwrap_err();
        assert_eq!(err, BridgeCircuitError::SeqExhausted(7));
    }

    #[test]
    fn relay_from_next_seq_increments() {
        let mut s = state_with(true);
        let now = Instant::now();
        let keys = open_exit_circuit(&mut s, 7, now);
        s.process_inbound_from_prev(extend_cell(7, 0x42), now)
            .unwrap();
        s.record_extend_complete(7, vec![0; 100], now).unwrap();
        let out = s.out_circ_id_for(7).unwrap();
        // Send three reverse cells; the bridge seals each with
        // increasing seq.
        for (expected_seq, msg) in (0u64..3).zip(["a", "b", "c"]) {
            let inbound = Cell::new(out, CMD_RELAY, msg.as_bytes().to_vec()).unwrap();
            let actions = s.process_inbound_from_next(inbound, now).unwrap();
            match actions.first().unwrap() {
                BridgeAction::SendToPrev { cell, .. } => {
                    let peeled = crate::onion::onion_open(
                        std::slice::from_ref(&keys.reverse),
                        &cell.body,
                        crate::circuit::DIR_HOP_TO_CLIENT,
                        0,
                        expected_seq,
                    )
                    .unwrap();
                    assert_eq!(peeled, msg.as_bytes());
                }
                _ => panic!("expected SendToPrev"),
            }
        }
    }

    #[test]
    fn relay_from_next_rejected_on_creating_circuit() {
        // RT-C6 closure (Phase 2E re-scan): a RELAY arriving from
        // the next-hop link before record_create_complete must NOT
        // increment reverse_seq - that would desync the AEAD nonce
        // vs the client's view. Symmetric with handle_relay_from_prev.
        let mut s = state_with(true);
        let now = Instant::now();
        // Drive circuit into Creating, then synthesise a fake
        // out_circ_id mapping so process_inbound_from_next can
        // route the cell to the entry. (In reality this can't
        // happen - out_circ_id is only populated post-EXTEND -
        // but we want the regression test to exercise the *guard*
        // in handle_relay_from_next directly, not the routing
        // upstream of it.)
        s.process_inbound_from_prev(create_cell(7), now).unwrap();
        // Force the circuit into Extending (still not Open) AND
        // populate the out_circ_id reverse mapping the next-link
        // dispatcher consults.
        {
            let entry = s.circuits.get_mut(&7).unwrap();
            entry.state = CircuitEntryState::Extending;
            entry.out_circ_id = Some(42);
        }
        s.out_to_in.insert(42, 7);
        let inbound = Cell::new(42, CMD_RELAY, vec![0xAA; 32]).unwrap();
        let err = s.process_inbound_from_next(inbound, now).unwrap_err();
        assert!(matches!(
            err,
            BridgeCircuitError::BadState {
                circ_id: 7,
                cmd: CMD_RELAY,
                ..
            }
        ));
        // And critically: reverse_seq stayed at 0 - no desync.
        assert_eq!(s.circuits.get(&7).unwrap().reverse_seq, 0);
    }

    #[test]
    fn record_create_complete_wrong_state_errors() {
        let mut s = state_with(true);
        let now = Instant::now();
        open_circuit(&mut s, 7, now);
        // Now circuit is Open. Calling record_create_complete is
        // a state-machine bug.
        let err = s
            .record_create_complete(7, fake_keys(1), vec![0; 100], now)
            .unwrap_err();
        assert!(matches!(err, BridgeCircuitError::WrongState { .. }));
    }

    // --- Phase 2G: CMD_EXTEND_FINISH (closes [RT-O2]) ---

    fn extend_finish_cell(circ_id: u32, hs_msg3_len: usize) -> Cell {
        let body = ExtendFinishBody {
            hs_msg3: vec![0x77; hs_msg3_len],
        }
        .encode()
        .unwrap();
        Cell::new(circ_id, CMD_EXTEND_FINISH, body).unwrap()
    }

    /// Drive a circuit to Open + extended (`out_circ_id` allocated)
    /// so we can exercise the `EXTEND_FINISH` path.
    fn open_extended_circuit(s: &mut BridgeCircuitState, circ_id: u32, now: Instant) -> u32 {
        open_circuit(s, circ_id, now);
        s.process_inbound_from_prev(extend_cell(circ_id, 0x42), now)
            .unwrap();
        s.record_extend_complete(circ_id, vec![0xAB; 200], now)
            .unwrap();
        s.out_circ_id_for(circ_id).expect("extend allocated out_id")
    }

    #[test]
    fn extend_finish_emits_forward_to_next() {
        let mut s = state_with(true);
        let now = Instant::now();
        let out = open_extended_circuit(&mut s, 7, now);
        let actions = s
            .process_inbound_from_prev(extend_finish_cell(7, 203), now)
            .unwrap();
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            BridgeAction::ForwardExtendFinishToNext {
                out_circ_id,
                hs_msg3,
            } => {
                assert_eq!(*out_circ_id, out);
                assert_eq!(hs_msg3.len(), 203);
            }
            other => panic!("expected ForwardExtendFinishToNext, got {other:?}"),
        }
    }

    // --- Per-hop token verification (relay / extended-hop sessions) ---

    /// A RELAY-mode state machine (this bridge is an extended hop): circuits
    /// require per-hop token verification before serving.
    fn relay_state() -> BridgeCircuitState {
        let mut s = BridgeCircuitState::new_relay(BridgePolicy::default());
        s.set_out_circ_id_picker(sequential_out_circ_id_picker);
        s
    }

    /// Open a terminal (no next hop) circuit on a RELAY-mode state machine. It
    /// starts UNVERIFIED (`token_verified == false`).
    fn open_relay_exit_circuit(s: &mut BridgeCircuitState, circ_id: u32, now: Instant) -> HopKeys {
        let keys = fake_keys(circ_id as u8);
        s.process_inbound_from_prev(create_cell(circ_id), now)
            .unwrap();
        s.record_create_complete(circ_id, keys.clone(), vec![0; 200], now)
            .unwrap();
        keys
    }

    #[test]
    fn relay_terminal_extend_finish_emits_verify_not_forward() {
        // On a relay session, a terminal (no next hop) EXTEND_FINISH is the
        // client's msg-3 addressed to US -> VerifyExtendFinish, not forward.
        let mut s = relay_state();
        let now = Instant::now();
        open_relay_exit_circuit(&mut s, 7, now);
        let actions = s
            .process_inbound_from_prev(extend_finish_cell(7, 203), now)
            .unwrap();
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            BridgeAction::VerifyExtendFinish {
                in_circ_id,
                hs_msg3,
            } => {
                assert_eq!(*in_circ_id, 7);
                assert_eq!(hs_msg3.len(), 203);
            }
            other => panic!("expected VerifyExtendFinish, got {other:?}"),
        }
    }

    #[test]
    fn relay_unverified_exit_is_unauthorized() {
        // The extended-hop authorization gate: a relay-session circuit must NOT
        // exit-dispatch before its per-hop token is verified. This is the fix
        // for "one entry token unlocks every bridge".
        let mut s = relay_state();
        let now = Instant::now();
        let keys = open_relay_exit_circuit(&mut s, 7, now);
        let sealed = client_sealed_cell(7, &keys, 0, b"unauthorized exit attempt");
        let err = s.process_inbound_from_prev(sealed, now).unwrap_err();
        assert_eq!(err, BridgeCircuitError::Unauthorized(7));
    }

    #[test]
    fn relay_verified_exit_is_allowed() {
        // After record_token_verified unlocks it, the same circuit exit-dispatches.
        let mut s = relay_state();
        let now = Instant::now();
        let keys = open_relay_exit_circuit(&mut s, 7, now);
        s.record_token_verified(7).unwrap();
        let sealed = client_sealed_cell(7, &keys, 0, b"authorized exit");
        let actions = s.process_inbound_from_prev(sealed, now).unwrap();
        match actions.first().unwrap() {
            BridgeAction::RelayPayloadAtExit {
                in_circ_id,
                payload,
            } => {
                assert_eq!(*in_circ_id, 7);
                assert_eq!(payload, b"authorized exit");
            }
            other => panic!("expected RelayPayloadAtExit, got {other:?}"),
        }
    }

    #[test]
    fn relay_unverified_extend_is_unauthorized() {
        // A relay-session hop must not be told to extend further before it has
        // verified its own per-hop token.
        let mut s = relay_state();
        let now = Instant::now();
        open_relay_exit_circuit(&mut s, 7, now);
        let err = s
            .process_inbound_from_prev(extend_cell(7, 0x42), now)
            .unwrap_err();
        assert_eq!(err, BridgeCircuitError::Unauthorized(7));
    }

    #[test]
    fn relay_extend_allowed_after_verify() {
        let mut s = relay_state();
        let now = Instant::now();
        open_relay_exit_circuit(&mut s, 7, now);
        s.record_token_verified(7).unwrap();
        let actions = s
            .process_inbound_from_prev(extend_cell(7, 0x42), now)
            .unwrap();
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, BridgeAction::OpenNextHop { .. })),
            "verified relay hop may extend"
        );
    }

    #[test]
    fn entry_mode_exit_needs_no_per_hop_token() {
        // Direct-client (non-relay) entry circuits are transport-authenticated;
        // the gate is a no-op and exit works immediately (no regression).
        let mut s = state_with(true);
        let now = Instant::now();
        let keys = open_exit_circuit(&mut s, 7, now);
        let sealed = client_sealed_cell(7, &keys, 0, b"entry exit");
        let actions = s.process_inbound_from_prev(sealed, now).unwrap();
        assert!(matches!(
            actions.first().unwrap(),
            BridgeAction::RelayPayloadAtExit { .. }
        ));
    }

    #[test]
    fn nonrelay_terminal_extend_finish_is_bad_state() {
        // On a direct-client session a terminal EXTEND_FINISH (no next hop) is a
        // protocol violation - a client never extend-finishes its own entry hop.
        let mut s = state_with(true);
        let now = Instant::now();
        open_circuit(&mut s, 7, now);
        let err = s
            .process_inbound_from_prev(extend_finish_cell(7, 203), now)
            .unwrap_err();
        assert!(matches!(
            err,
            BridgeCircuitError::BadState {
                circ_id: 7,
                cmd: CMD_EXTEND_FINISH,
                ..
            }
        ));
    }

    #[test]
    fn extend_finish_rejected_on_unknown_circuit() {
        let mut s = state_with(true);
        let now = Instant::now();
        let err = s
            .process_inbound_from_prev(extend_finish_cell(99, 203), now)
            .unwrap_err();
        assert_eq!(err, BridgeCircuitError::UnknownCircuit(99));
    }

    #[test]
    fn extend_finish_rejected_on_creating_circuit() {
        // EXTEND_FINISH before extension completes should fail
        // (state is Creating, no out_circ_id yet).
        let mut s = state_with(true);
        let now = Instant::now();
        s.process_inbound_from_prev(create_cell(7), now).unwrap();
        let err = s
            .process_inbound_from_prev(extend_finish_cell(7, 203), now)
            .unwrap_err();
        assert!(matches!(
            err,
            BridgeCircuitError::BadState {
                circ_id: 7,
                cmd: CMD_EXTEND_FINISH,
                ..
            }
        ));
    }

    #[test]
    fn extend_finish_rejected_on_open_circuit_without_out_link() {
        // A 1-hop circuit that's Open but has never been extended
        // (no out_circ_id) cannot accept EXTEND_FINISH - there's
        // no next hop to forward to.
        let mut s = state_with(true);
        let now = Instant::now();
        open_circuit(&mut s, 7, now);
        // Confirm prerequisites: state == Open, out_circ_id is None.
        assert_eq!(s.circuit_state(7), Some(CircuitEntryState::Open));
        assert!(s.out_circ_id_for(7).is_none());
        let err = s
            .process_inbound_from_prev(extend_finish_cell(7, 203), now)
            .unwrap_err();
        assert!(matches!(
            err,
            BridgeCircuitError::BadState {
                circ_id: 7,
                cmd: CMD_EXTEND_FINISH,
                ..
            }
        ));
    }

    #[test]
    fn extend_finish_updates_last_activity() {
        let mut s = state_with(true);
        let t0 = Instant::now();
        open_extended_circuit(&mut s, 7, t0);
        let t1 = t0 + Duration::from_secs(5);
        s.process_inbound_from_prev(extend_finish_cell(7, 203), t1)
            .unwrap();
        assert_eq!(s.circuits.get(&7).unwrap().last_activity, t1);
    }

    // --- Phase 2G+: pending_extend reassembly timeout (closes [RT-P2G-2]) ---

    fn extend_first_cell_partial(circ_id: u32, total_len: u16, first_chunk: usize) -> Cell {
        // Hand-build a CMD_EXTEND body that claims a larger
        // total_len than first_chunk supplies - i.e., reassembly
        // is incomplete after this single cell.
        let mut body = vec![0u8; 32]; // pk
        body.push(0x01); // ipv4
        body.extend_from_slice(&[10, 0, 0, 1]);
        body.extend_from_slice(&4433u16.to_be_bytes());
        body.extend_from_slice(&total_len.to_be_bytes());
        body.extend(std::iter::repeat_n(0xCD, first_chunk));
        Cell::new(circ_id, CMD_EXTEND, body).unwrap()
    }

    #[test]
    fn pending_extend_reaped_by_tick_past_timeout() {
        // RT-P2G-2: a half-finished EXTEND must be reaped by
        // tick() at pending_extend_timeout, not later (idle_ttl).
        let policy = BridgePolicy {
            pending_extend_timeout: Duration::from_millis(50),
            ..Default::default()
        };
        let mut s = BridgeCircuitState::new(policy);
        s.set_out_circ_id_picker(sequential_out_circ_id_picker);
        let t0 = Instant::now();
        open_circuit(&mut s, 7, t0);
        // Send EXTEND with total_len=1500, first chunk only 100 ->
        // pending_extend stashed, awaiting CONT.
        s.process_inbound_from_prev(extend_first_cell_partial(7, 1500, 100), t0)
            .unwrap();
        assert!(s.circuits.get(&7).unwrap().pending_extend.is_some());
        // Sweep at t0 + 200ms: pending_age (200ms) >
        // pending_extend_timeout (50ms) -> reaped.
        let actions = s.tick(t0 + Duration::from_millis(200));
        assert!(actions
            .iter()
            .any(|a| matches!(a, BridgeAction::DestroyPrevLink { in_circ_id: 7 })));
        assert_eq!(s.circuit_state(7), None);
    }

    #[test]
    fn pending_extend_not_reaped_within_timeout() {
        // Sanity: don't reap if still inside the window.
        let policy = BridgePolicy {
            pending_extend_timeout: Duration::from_secs(60),
            ..Default::default()
        };
        let mut s = BridgeCircuitState::new(policy);
        s.set_out_circ_id_picker(sequential_out_circ_id_picker);
        let t0 = Instant::now();
        open_circuit(&mut s, 7, t0);
        s.process_inbound_from_prev(extend_first_cell_partial(7, 1500, 100), t0)
            .unwrap();
        let actions = s.tick(t0 + Duration::from_secs(5));
        assert!(actions.is_empty());
        assert!(s.circuits.get(&7).unwrap().pending_extend.is_some());
    }

    // --- Phase 2G+: inner CMD_EXTEND_CONT dispatch (closes [RT-P2G-3]) ---

    #[test]
    fn relay_with_inner_extend_cont_dispatches_extend_cont() {
        // An inner CMD_EXTEND_CONT in a RELAY must route to
        // handle_extend_cont, not silently fall through to the
        // stream-payload path. With no pending reassembly, the
        // handler errors with BadState - that's the desired
        // protocol-strictness behaviour.
        let mut s = state_with(true);
        let now = Instant::now();
        let keys = open_exit_circuit(&mut s, 7, now);

        let sub = RelaySubCell {
            command: CMD_EXTEND_CONT,
            body: vec![0xAB; 100],
        };
        let outer = client_sealed_subcell(7, &keys, 0, &sub);

        let err = s.process_inbound_from_prev(outer, now).unwrap_err();
        assert!(matches!(
            err,
            BridgeCircuitError::BadState {
                circ_id: 7,
                cmd: CMD_EXTEND_CONT,
                ..
            }
        ));
    }

    // --- Phase 2I: CMD_CREATE / CMD_CREATE_CONT fragmentation ---

    fn create_first_cell_partial(circ_id: u32, total_len: u16, first_chunk: usize) -> Cell {
        let mut body = Vec::with_capacity(2 + first_chunk);
        body.extend_from_slice(&total_len.to_be_bytes());
        body.extend(std::iter::repeat_n(0xCD, first_chunk));
        Cell::new(circ_id, CMD_CREATE, body).unwrap()
    }

    fn create_cont_cell(circ_id: u32, chunk: usize) -> Cell {
        Cell::new(circ_id, CMD_CREATE_CONT, vec![0xEF; chunk]).unwrap()
    }

    #[test]
    fn create_with_fragmented_body_holds_pending_until_complete() {
        let mut s = state_with(true);
        let now = Instant::now();
        // Total 1500 bytes, first chunk 1000 - incomplete.
        let actions = s
            .process_inbound_from_prev(create_first_cell_partial(7, 1500, 1000), now)
            .unwrap();
        // No PerformHandshake yet - waiting for CONT.
        assert!(
            actions.is_empty(),
            "fragmented CREATE must NOT dispatch handshake until complete: {actions:?}"
        );
        assert_eq!(s.circuit_state(7), Some(CircuitEntryState::Creating));
        assert!(s.circuits.get(&7).unwrap().pending_create.is_some());

        // Send 500 B continuation -> completes 1500.
        let actions = s
            .process_inbound_from_prev(create_cont_cell(7, 500), now)
            .unwrap();
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            BridgeAction::PerformHandshake {
                in_circ_id,
                hs_msg1,
            } => {
                assert_eq!(*in_circ_id, 7);
                assert_eq!(hs_msg1.len(), 1500);
            }
            other => panic!("expected PerformHandshake, got {other:?}"),
        }
        // Pending state cleared.
        assert!(s.circuits.get(&7).unwrap().pending_create.is_none());
    }

    #[test]
    fn create_cont_without_pending_create_rejected() {
        let mut s = state_with(true);
        let now = Instant::now();
        // CONT for unknown circuit.
        let err = s
            .process_inbound_from_prev(create_cont_cell(99, 100), now)
            .unwrap_err();
        assert_eq!(err, BridgeCircuitError::UnknownCircuit(99));
    }

    #[test]
    fn create_cont_overflow_tears_down() {
        let mut s = state_with(true);
        let now = Instant::now();
        s.process_inbound_from_prev(create_first_cell_partial(7, 1500, 1000), now)
            .unwrap();
        // CONT carries 1000 bytes - would push total to 2000, > 1500.
        let err = s
            .process_inbound_from_prev(create_cont_cell(7, 1000), now)
            .unwrap_err();
        assert!(matches!(err, BridgeCircuitError::ExtendOverflow { .. }));
    }

    #[test]
    fn pending_create_reaped_by_tick_past_timeout() {
        // Symmetric of pending_extend_reaped_by_tick_past_timeout.
        // A half-finished CREATE must be reaped.
        let policy = BridgePolicy {
            pending_extend_timeout: Duration::from_millis(50),
            ..Default::default()
        };
        let mut s = BridgeCircuitState::new(policy);
        s.set_out_circ_id_picker(sequential_out_circ_id_picker);
        let t0 = Instant::now();
        s.process_inbound_from_prev(create_first_cell_partial(7, 1500, 100), t0)
            .unwrap();
        assert!(s.circuits.get(&7).unwrap().pending_create.is_some());
        let actions = s.tick(t0 + Duration::from_millis(200));
        // Stuck circuit reaped - both pending_create and the
        // Creating-state circuit go away.
        assert!(actions
            .iter()
            .any(|a| matches!(a, BridgeAction::DestroyPrevLink { in_circ_id: 7 })));
        assert_eq!(s.circuit_state(7), None);
    }

    #[test]
    fn record_create_complete_emits_fragmented_created() {
        // hs_msg2 = 1189 B (realistic) emits CMD_CREATED + N
        // CMD_CREATED_CONT cells.
        let mut s = state_with(true);
        let now = Instant::now();
        s.process_inbound_from_prev(create_cell(7), now).unwrap();
        let actions = s
            .record_create_complete(7, fake_keys(1), vec![0xEF; 1189], now)
            .unwrap();
        // Expect at least 2 cells: 1 CREATED + 1+ CREATED_CONT.
        assert!(
            actions.len() >= 2,
            "expected fragmented CREATED, got {} actions",
            actions.len()
        );
        match &actions[0] {
            BridgeAction::SendToPrev { cell, .. } => {
                assert_eq!(cell.command, CMD_CREATED);
            }
            other => panic!("first action must be SendToPrev(CREATED), got {other:?}"),
        }
        for action in &actions[1..] {
            match action {
                BridgeAction::SendToPrev { cell, .. } => {
                    assert_eq!(cell.command, CMD_CREATED_CONT);
                }
                other => {
                    panic!("continuation action must be SendToPrev(CREATED_CONT), got {other:?}")
                }
            }
        }
    }

    // --- Phase 2G: inner-cell dispatch in handle_relay_from_prev ---
    //
    // When a 3+ hop client onion-wraps a CMD_EXTEND / CMD_EXTEND_FINISH
    // / CMD_DESTROY for a downstream hop, that downstream hop receives
    // it as a CMD_RELAY whose peeled body is itself a full Cell. The
    // dispatcher in handle_relay_from_prev recognises this and routes
    // to the appropriate inner handler.

    fn client_sealed_subcell(
        circ_id_at_bridge: u32,
        bridge_keys: &HopKeys,
        seq: u64,
        sub: &RelaySubCell,
    ) -> Cell {
        let inner_bytes = sub.encode().unwrap();
        let sealed = crate::onion::onion_seal(
            std::slice::from_ref(&bridge_keys.forward),
            &inner_bytes,
            crate::circuit::DIR_CLIENT_TO_HOP,
            0,
            seq,
        )
        .unwrap();
        Cell::new(circ_id_at_bridge, CMD_RELAY, sealed).unwrap()
    }

    #[test]
    fn relay_with_inner_extend_dispatches_extend() {
        // Single-hop circuit (this bridge is the terminal hop).
        // Client wraps a CMD_EXTEND sub-cell in CMD_RELAY.
        let mut s = state_with(true);
        let now = Instant::now();
        let keys = open_exit_circuit(&mut s, 7, now);

        let extend_body = ExtendBody {
            next_hop_pk: [0x99u8; 32],
            endpoint: HopEndpoint::Ipv4 {
                addr: [10, 0, 0, 0x99],
                port: 4433,
            },
            hs_msg1: vec![0xCD; 100],
        }
        .encode()
        .unwrap();
        let sub = RelaySubCell {
            command: CMD_EXTEND,
            body: extend_body,
        };
        let outer = client_sealed_subcell(7, &keys, 0, &sub);

        let actions = s.process_inbound_from_prev(outer, now).unwrap();
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            BridgeAction::OpenNextHop {
                in_circ_id,
                next_hop_pk,
                ..
            } => {
                assert_eq!(*in_circ_id, 7);
                assert_eq!(*next_hop_pk, [0x99u8; 32]);
            }
            other => panic!("expected OpenNextHop, got {other:?}"),
        }
        assert_eq!(s.circuit_state(7), Some(CircuitEntryState::Extending));
    }

    #[test]
    fn relay_with_inner_extend_finish_dispatches_forward() {
        // Set up a 2-hop chain: 7 <-> out. Client sends an inner
        // CMD_EXTEND_FINISH wrapped in RELAY through the bridge.
        // The bridge should forward to the next-hop link.
        let mut s = state_with(true);
        let now = Instant::now();
        let keys = open_exit_circuit(&mut s, 7, now);
        // Force the circuit into "extended once" state by setting
        // an out_circ_id directly. (open_extended_circuit would
        // also work but it generates additional setup actions.)
        s.circuits.get_mut(&7).unwrap().out_circ_id = Some(99);
        s.out_to_in.insert(99, 7);

        let sub = RelaySubCell {
            command: CMD_EXTEND_FINISH,
            body: ExtendFinishBody {
                hs_msg3: vec![0x33; 203],
            }
            .encode()
            .unwrap(),
        };
        let outer = client_sealed_subcell(7, &keys, 0, &sub);

        let actions = s.process_inbound_from_prev(outer, now).unwrap();
        match &actions[0] {
            BridgeAction::ForwardExtendFinishToNext {
                out_circ_id,
                hs_msg3,
            } => {
                assert_eq!(*out_circ_id, 99);
                assert_eq!(hs_msg3.len(), 203);
            }
            other => panic!("expected ForwardExtendFinishToNext, got {other:?}"),
        }
    }

    #[test]
    fn relay_with_inner_destroy_marks_destroyed() {
        // An inner CMD_DESTROY on a terminal hop transitions the circuit to
        // Destroyed and emits a single DestroyPrevLink (the executor's
        // free-retained-responder signal - memory-DoS fix). DestroyPrevLink does
        // NOT write a CMD_DESTROY back to the prev hop, so the deliberate
        // "silent close, don't echo DESTROY" semantics are preserved. A terminal
        // hop has no out_circ_id, so there is no DestroyNextLink.
        let mut s = state_with(true);
        let now = Instant::now();
        let keys = open_exit_circuit(&mut s, 7, now);

        let sub = RelaySubCell {
            command: CMD_DESTROY,
            body: vec![],
        };
        let outer = client_sealed_subcell(7, &keys, 0, &sub);

        let actions = s.process_inbound_from_prev(outer, now).unwrap();
        // Exactly one DestroyPrevLink; no DestroyNextLink (terminal hop).
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            actions[0],
            BridgeAction::DestroyPrevLink { in_circ_id: 7 }
        ));
        // State transitioned to Destroyed.
        assert_eq!(s.circuit_state(7), Some(CircuitEntryState::Destroyed));
    }

    #[test]
    fn relay_with_inner_destroy_at_middle_hop_emits_destroy_next() {
        // A middle hop (out_circ_id Some) receiving an inner
        // CMD_DESTROY emits DestroyNextLink so the rest of the
        // circuit unwinds.
        let mut s = state_with(true);
        let now = Instant::now();
        let keys = open_exit_circuit(&mut s, 7, now);
        // Force the circuit into "extended" state.
        s.circuits.get_mut(&7).unwrap().out_circ_id = Some(99);
        s.out_to_in.insert(99, 7);

        let sub = RelaySubCell {
            command: CMD_DESTROY,
            body: vec![],
        };
        let outer = client_sealed_subcell(7, &keys, 0, &sub);

        let actions = s.process_inbound_from_prev(outer, now).unwrap();
        assert!(actions
            .iter()
            .any(|a| matches!(a, BridgeAction::DestroyNextLink { out_circ_id: 99 })));
        assert_eq!(s.circuit_state(7), Some(CircuitEntryState::Destroyed));
    }

    #[test]
    fn relay_with_stream_subcommand_surfaces_as_exit_payload() {
        // CMD_DATA carried as a sub-cell isn't a control command;
        // surfaces as RelayPayloadAtExit for the runtime's stream
        // dispatcher (Phase 2I).
        let mut s = state_with(true);
        let now = Instant::now();
        let keys = open_exit_circuit(&mut s, 7, now);

        let sub = RelaySubCell {
            command: CMD_DATA,
            body: vec![0x55; 50],
        };
        let outer = client_sealed_subcell(7, &keys, 0, &sub);

        let actions = s.process_inbound_from_prev(outer, now).unwrap();
        match &actions[0] {
            BridgeAction::RelayPayloadAtExit { in_circ_id, .. } => {
                assert_eq!(*in_circ_id, 7);
            }
            other => panic!("expected RelayPayloadAtExit, got {other:?}"),
        }
    }

    #[test]
    fn relay_with_non_subcell_payload_falls_back_to_exit() {
        // A short payload that doesn't parse as a RelaySubCell
        // (legacy or unframed bytes) still surfaces cleanly as
        // RelayPayloadAtExit so legacy paths keep working.
        let mut s = state_with(true);
        let now = Instant::now();
        let keys = open_exit_circuit(&mut s, 7, now);
        let outer = client_sealed_cell(7, &keys, 0, b"x");

        let actions = s.process_inbound_from_prev(outer, now).unwrap();
        match &actions[0] {
            BridgeAction::RelayPayloadAtExit { payload, .. } => {
                assert_eq!(payload, b"x");
            }
            other => panic!("expected RelayPayloadAtExit, got {other:?}"),
        }
    }
}
