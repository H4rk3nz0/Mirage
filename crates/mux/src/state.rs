//! Connection-level mux state machine. I/O-free.
//!
//! `MuxState` tracks open streams, flow-control windows, and the
//! per-stream state machine. It exposes a request-response API:
//! callers feed inbound frames via [`MuxState::recv`], drain
//! outbound frames via [`MuxState::pending_outbound`], and open
//! local streams via [`MuxState::open_local`].
//!
//! The async driver (which moves bytes between a session and the
//! mux state) is a separate concern - typically a tokio task that
//! reads/writes the inner duplex, parses frames, calls `recv`,
//! collects `pending_outbound()`, writes them out. v0.1w ships
//! the state machine + tests; v0.2 will provide the canonical
//! tokio driver that wraps a `mirage_session::SessionFramer`.
//!
//! # Per-stream state machine
//!
//! ```text
//!  Idle -open_local()--> SynSent --recv(BeginOk)--> Open
//!                              |
//!                              +--recv(Reset)--> Closed
//!
//!  Idle -recv(Begin)--> SynReceived --accept()--> Open --[bidirectional Data]--> Open
//!                              |
//!                              +-reject()--> Closed
//!
//!  Open -local end_local()--> HalfClosedLocal
//!  Open -recv(EndLocal)--> HalfClosedRemote
//!  HalfClosedLocal -recv(EndLocal)--> Closed
//!  HalfClosedRemote -local end_local()--> Closed
//!
//!  any -local reset()--> Closed (sends Reset frame)
//!  any -recv(Reset)--> Closed
//! ```

use crate::frame::{MuxCmd, MuxFrame, MuxFrameError};
use crate::policy::MuxPolicy;
use crate::stream::{StreamId, StreamIdAllocator, StreamRole};
use crate::target::{MuxTarget, TargetError};
use std::collections::{HashMap, VecDeque};
use thiserror::Error;

/// Per-stream state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Local side opened a stream; waiting for `BeginOk`.
    SynSent,
    /// Peer opened a stream; local hasn't accepted/rejected yet.
    SynReceived,
    /// Both sides agreed; data flows.
    Open,
    /// Local has half-closed write side.
    HalfClosedLocal,
    /// Peer has half-closed write side.
    HalfClosedRemote,
    /// Stream is closed (graceful or reset).
    Closed,
}

/// Per-stream entry in the state map.
#[derive(Debug, Clone)]
struct Stream {
    state: StreamState,
    /// Bytes the LOCAL side may still send before the peer must
    /// grant a `WindowUpdate`.
    send_credit: u32,
    /// Bytes the LOCAL side has granted the peer (pending peer's
    /// own send-credit accounting). Tracked so we don't grant
    /// runaway credit.
    recv_window: u32,
    /// Target the peer asked to open. Only present on
    /// `SynReceived` so the local side can decide whether to
    /// `accept()` or `reject()`.
    pending_target: Option<MuxTarget>,
}

/// Errors produced by `MuxState` operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MuxStateError {
    /// Inbound frame had a wire-format violation.
    #[error("frame: {0}")]
    Frame(#[from] MuxFrameError),
    /// `Begin` frame's target couldn't be parsed.
    #[error("target: {0}")]
    Target(#[from] TargetError),
    /// Frame referenced an unknown `stream_id`.
    #[error("unknown stream {0}")]
    UnknownStream(u32),
    /// Peer opened a stream in the LOCAL parity space (it must use its own
    /// role's subset). Rejected to prevent collision/clobber of locally
    /// allocated ids (RT #28).
    #[error("peer opened stream {0} in the local id space")]
    ForeignStreamId(u32),
    /// Stream is in a state that disallows the requested op.
    #[error("stream {stream_id} in state {state:?} can't accept op")]
    BadState {
        /// The offending stream's id.
        stream_id: u32,
        /// The current state.
        state: StreamState,
    },
    /// Send would exceed the peer-granted credit.
    #[error("would exceed send credit (asked {asked}, available {available})")]
    InsufficientCredit {
        /// Bytes the caller wanted to send.
        asked: u32,
        /// Bytes actually available.
        available: u32,
    },
    /// `max_concurrent_streams` policy cap reached.
    #[error("concurrent-stream cap reached ({0})")]
    StreamLimit(u32),
    /// Stream-id space exhausted (one local side issued ~2^31 streams
    /// on a single connection). The connection MUST be torn down -
    /// no further local streams can be allocated.
    #[error("stream-id space exhausted; tear down connection")]
    StreamIdExhausted,
    /// Outbound frame queue is full. Caller should drain via
    /// [`MuxState::pending_outbound`] before retrying. The state
    /// machine applies backpressure here rather than allow the
    /// queue to grow without bound.
    #[error("outbound queue full (cap {0}); drain pending_outbound first")]
    OutboundQueueFull(usize),
    /// Internal invariant violation. Indicates a state-machine bug
    /// (the caller did everything legally and we still failed). The
    /// caller should reset the connection.
    #[error("internal invariant: {0}")]
    Internal(&'static str),
}

/// Connection-level mux state.
///
/// One instance per Mirage session. Threading: NOT thread-safe.
/// The async driver typically owns one `MuxState` per session
/// inside a single task; per-stream APIs talk to the driver via
/// channels.
pub struct MuxState {
    /// Local side's role (allocates stream IDs from its parity).
    role: StreamRole,
    policy: MuxPolicy,
    streams: HashMap<u32, Stream>,
    id_allocator: StreamIdAllocator,
    outbound: VecDeque<MuxFrame>,
    /// Count of streams currently in any non-Closed state.
    open_count: u32,
}

impl MuxState {
    /// Construct.
    pub fn new(role: StreamRole, policy: MuxPolicy) -> Self {
        Self {
            id_allocator: StreamIdAllocator::new(role),
            role,
            policy,
            streams: HashMap::new(),
            outbound: VecDeque::new(),
            open_count: 0,
        }
    }

    /// Push a frame onto the outbound queue, respecting the
    /// per-connection cap. Caller MUST handle the resulting error -
    /// typically by tearing the connection down, since a
    /// peer-driven over-fill means the driver isn't draining.
    fn enqueue(&mut self, frame: MuxFrame) -> Result<(), MuxStateError> {
        if self.outbound.len() >= self.policy.max_pending_outbound {
            return Err(MuxStateError::OutboundQueueFull(
                self.policy.max_pending_outbound,
            ));
        }
        self.outbound.push_back(frame);
        Ok(())
    }

    /// Mark a stream Closed and free its entry. Centralises the
    /// "stream is gone" transition so the entry never lingers in
    /// `self.streams` after termination - `Closed` lives in
    /// `StreamState` purely as the result of a final transition,
    /// not as a long-lived map entry. Decrements `open_count` iff
    /// the stream was previously open.
    fn close_stream(&mut self, stream_id: u32) {
        if let Some(s) = self.streams.remove(&stream_id) {
            if s.state != StreamState::Closed {
                self.open_count = self.open_count.saturating_sub(1);
            }
        }
    }

    /// Open a local stream. Allocates a fresh ID, queues a `Begin`
    /// frame, and returns the new stream's id.
    // Takes `MuxTarget` by value to match its sole production caller,
    // `MuxConn::open`, whose own `MuxTarget`-by-value signature is depended on by
    // `.open(..)` call sites in other crates; threading `&MuxTarget` would force
    // edits there for no real gain.
    #[allow(clippy::needless_pass_by_value)]
    pub fn open_local(&mut self, target: MuxTarget) -> Result<StreamId, MuxStateError> {
        if self.open_count >= self.policy.max_concurrent_streams {
            return Err(MuxStateError::StreamLimit(
                self.policy.max_concurrent_streams,
            ));
        }
        let id = self
            .id_allocator
            .next()
            .ok_or(MuxStateError::StreamIdExhausted)?;
        let target_bytes = target.encode().map_err(MuxStateError::Target)?;
        let frame =
            MuxFrame::new(id.raw(), MuxCmd::Begin, target_bytes).map_err(MuxStateError::Frame)?;
        // Reserve queue capacity *before* we mutate map state, so a
        // full outbound queue doesn't leave a half-allocated stream
        // behind.
        self.enqueue(frame)?;
        self.streams.insert(
            id.raw(),
            Stream {
                state: StreamState::SynSent,
                send_credit: self.policy.initial_window,
                recv_window: self.policy.initial_window,
                pending_target: None,
            },
        );
        self.open_count += 1;
        Ok(id)
    }

    /// Accept a peer-opened stream. Transitions `SynReceived` ->
    /// `Open` and queues `BeginOk`.
    pub fn accept(&mut self, stream_id: u32) -> Result<MuxTarget, MuxStateError> {
        let s = self
            .streams
            .get_mut(&stream_id)
            .ok_or(MuxStateError::UnknownStream(stream_id))?;
        if s.state != StreamState::SynReceived {
            return Err(MuxStateError::BadState {
                stream_id,
                state: s.state,
            });
        }
        let target = s.pending_target.take().ok_or(MuxStateError::Internal(
            "SynReceived missing pending_target",
        ))?;
        s.state = StreamState::Open;
        let frame =
            MuxFrame::new(stream_id, MuxCmd::BeginOk, Vec::new()).map_err(MuxStateError::Frame)?;
        self.enqueue(frame)?;
        Ok(target)
    }

    /// Reject a peer-opened stream. Transitions `SynReceived` ->
    /// `Closed` and queues `Reset(0x01 = refused)`.
    pub fn reject(&mut self, stream_id: u32) -> Result<(), MuxStateError> {
        let s = self
            .streams
            .get(&stream_id)
            .ok_or(MuxStateError::UnknownStream(stream_id))?;
        if s.state != StreamState::SynReceived {
            return Err(MuxStateError::BadState {
                stream_id,
                state: s.state,
            });
        }
        let frame =
            MuxFrame::new(stream_id, MuxCmd::Reset, vec![0x01]).map_err(MuxStateError::Frame)?;
        self.enqueue(frame)?;
        self.close_stream(stream_id);
        Ok(())
    }

    /// Send DATA on a local stream. Splits at the mux frame body
    /// cap and credit window; returns the number of bytes consumed
    /// from `payload`. If 0, the caller must wait for a window
    /// update.
    pub fn send_data(&mut self, stream_id: u32, payload: &[u8]) -> Result<usize, MuxStateError> {
        let s = self
            .streams
            .get_mut(&stream_id)
            .ok_or(MuxStateError::UnknownStream(stream_id))?;
        if !matches!(s.state, StreamState::Open | StreamState::HalfClosedRemote) {
            return Err(MuxStateError::BadState {
                stream_id,
                state: s.state,
            });
        }
        if s.send_credit == 0 {
            return Ok(0);
        }
        let max_chunk = (crate::frame::MAX_MUX_FRAME_BODY)
            .min(s.send_credit as usize)
            .min(payload.len());
        if max_chunk == 0 {
            return Ok(0);
        }
        let frame = MuxFrame::new(stream_id, MuxCmd::Data, payload[..max_chunk].to_vec())
            .map_err(MuxStateError::Frame)?;
        self.enqueue(frame)?;
        // Only debit credit AFTER the frame is queued - if the
        // queue is full the caller should retry without losing
        // credit accounting.
        if let Some(s2) = self.streams.get_mut(&stream_id) {
            s2.send_credit = s2.send_credit.saturating_sub(max_chunk as u32);
        }
        Ok(max_chunk)
    }

    /// Send `EndLocal` to half-close the local write side.
    pub fn end_local(&mut self, stream_id: u32) -> Result<(), MuxStateError> {
        let s = self
            .streams
            .get(&stream_id)
            .ok_or(MuxStateError::UnknownStream(stream_id))?;
        let next = match s.state {
            StreamState::Open => StreamState::HalfClosedLocal,
            StreamState::HalfClosedRemote => StreamState::Closed,
            other => {
                return Err(MuxStateError::BadState {
                    stream_id,
                    state: other,
                });
            }
        };
        let frame =
            MuxFrame::new(stream_id, MuxCmd::EndLocal, Vec::new()).map_err(MuxStateError::Frame)?;
        self.enqueue(frame)?;
        if next == StreamState::Closed {
            self.close_stream(stream_id);
        } else if let Some(s2) = self.streams.get_mut(&stream_id) {
            s2.state = next;
        }
        Ok(())
    }

    /// Hard reset a stream. Queues a `Reset` frame and transitions
    /// to `Closed`.
    pub fn reset(&mut self, stream_id: u32, error_code: u8) -> Result<(), MuxStateError> {
        if !self.streams.contains_key(&stream_id) {
            return Err(MuxStateError::UnknownStream(stream_id));
        }
        let frame = MuxFrame::new(stream_id, MuxCmd::Reset, vec![error_code])
            .map_err(MuxStateError::Frame)?;
        self.enqueue(frame)?;
        self.close_stream(stream_id);
        Ok(())
    }

    /// Grant additional receive-window credit to the peer for a
    /// stream. Caller invokes after consuming inbound data; the
    /// state machine queues a `WindowUpdate` frame.
    pub fn grant_credit(&mut self, stream_id: u32, delta: u32) -> Result<(), MuxStateError> {
        let s = self
            .streams
            .get(&stream_id)
            .ok_or(MuxStateError::UnknownStream(stream_id))?;
        if matches!(s.state, StreamState::Closed) {
            return Err(MuxStateError::BadState {
                stream_id,
                state: s.state,
            });
        }
        let frame = MuxFrame::new(
            stream_id,
            MuxCmd::WindowUpdate,
            delta.to_be_bytes().to_vec(),
        )
        .map_err(MuxStateError::Frame)?;
        self.enqueue(frame)?;
        if let Some(s2) = self.streams.get_mut(&stream_id) {
            s2.recv_window = s2.recv_window.saturating_add(delta);
        }
        Ok(())
    }

    /// Process an inbound frame. Returns the parsed-and-classified
    /// "event" the caller should handle (e.g., new-stream-incoming,
    /// data-received, peer-half-closed). The state machine queues
    /// any required outbound frames internally.
    pub fn recv(&mut self, frame: MuxFrame) -> Result<MuxEvent, MuxStateError> {
        let id = frame.stream_id;
        match frame.command {
            MuxCmd::Begin => {
                // RT #28: the peer MUST open streams in ITS OWN parity space
                // (the opposite role's subset). A Begin carrying an id from
                // our LOCAL space could collide with a stream we later
                // allocate (clobbering it) and inflate `open_count`. Reset and
                // reject. (We are `self.role`; the peer is the opposite role -
                // initiator=even, responder=odd.)
                let peer_id_ok = match self.role {
                    StreamRole::Initiator => id % 2 == 1, // peer is responder -> odd
                    StreamRole::Responder => id % 2 == 0, // peer is initiator -> even
                };
                if !peer_id_ok {
                    let f = MuxFrame::new(id, MuxCmd::Reset, vec![0x03])
                        .map_err(MuxStateError::Frame)?;
                    self.enqueue(f)?;
                    return Err(MuxStateError::ForeignStreamId(id));
                }
                let target = MuxTarget::decode(&frame.body).map_err(MuxStateError::Target)?;
                if let Some(existing) = self.streams.get(&id) {
                    return Err(MuxStateError::BadState {
                        stream_id: id,
                        state: existing.state,
                    });
                }
                if self.open_count >= self.policy.max_concurrent_streams {
                    let f = MuxFrame::new(id, MuxCmd::Reset, vec![0x02])
                        .map_err(MuxStateError::Frame)?;
                    self.enqueue(f)?;
                    return Err(MuxStateError::StreamLimit(
                        self.policy.max_concurrent_streams,
                    ));
                }
                self.streams.insert(
                    id,
                    Stream {
                        state: StreamState::SynReceived,
                        send_credit: self.policy.initial_window,
                        recv_window: self.policy.initial_window,
                        pending_target: Some(target.clone()),
                    },
                );
                self.open_count += 1;
                Ok(MuxEvent::Incoming {
                    stream_id: id,
                    target,
                })
            }
            MuxCmd::BeginOk => {
                let s = self
                    .streams
                    .get_mut(&id)
                    .ok_or(MuxStateError::UnknownStream(id))?;
                if s.state != StreamState::SynSent {
                    return Err(MuxStateError::BadState {
                        stream_id: id,
                        state: s.state,
                    });
                }
                s.state = StreamState::Open;
                Ok(MuxEvent::Established { stream_id: id })
            }
            MuxCmd::Data => {
                let s = self
                    .streams
                    .get_mut(&id)
                    .ok_or(MuxStateError::UnknownStream(id))?;
                if !matches!(s.state, StreamState::Open | StreamState::HalfClosedLocal) {
                    return Err(MuxStateError::BadState {
                        stream_id: id,
                        state: s.state,
                    });
                }
                let bytes = frame.body.len() as u32;
                if bytes > s.recv_window {
                    // Peer over-sent. Queue Reset, then close.
                    let rst = MuxFrame::new(id, MuxCmd::Reset, vec![0x03])
                        .map_err(MuxStateError::Frame)?;
                    self.enqueue(rst)?;
                    self.close_stream(id);
                    return Err(MuxStateError::BadState {
                        stream_id: id,
                        state: StreamState::Closed,
                    });
                }
                s.recv_window = s.recv_window.saturating_sub(bytes);
                Ok(MuxEvent::Data {
                    stream_id: id,
                    body: frame.body,
                })
            }
            MuxCmd::WindowUpdate => {
                if frame.body.len() != 4 {
                    return Err(MuxStateError::Frame(MuxFrameError::BodyLength));
                }
                let s = self
                    .streams
                    .get_mut(&id)
                    .ok_or(MuxStateError::UnknownStream(id))?;
                let delta = u32::from_be_bytes([
                    frame.body[0],
                    frame.body[1],
                    frame.body[2],
                    frame.body[3],
                ]);
                s.send_credit = s.send_credit.saturating_add(delta);
                Ok(MuxEvent::WindowUpdate {
                    stream_id: id,
                    delta,
                })
            }
            MuxCmd::EndLocal => {
                let s = self
                    .streams
                    .get_mut(&id)
                    .ok_or(MuxStateError::UnknownStream(id))?;
                let close = match s.state {
                    StreamState::Open => {
                        s.state = StreamState::HalfClosedRemote;
                        false
                    }
                    StreamState::HalfClosedLocal => true,
                    other => {
                        return Err(MuxStateError::BadState {
                            stream_id: id,
                            state: other,
                        });
                    }
                };
                if close {
                    self.close_stream(id);
                }
                Ok(MuxEvent::PeerEndLocal { stream_id: id })
            }
            MuxCmd::Reset => {
                if !self.streams.contains_key(&id) {
                    return Err(MuxStateError::UnknownStream(id));
                }
                self.close_stream(id);
                let code = frame.body.first().copied().unwrap_or(0xFF);
                Ok(MuxEvent::Reset {
                    stream_id: id,
                    error_code: code,
                })
            }
        }
    }

    /// Drain the queued outbound frames. Caller writes each to the
    /// inner session.
    pub fn pending_outbound(&mut self) -> Vec<MuxFrame> {
        self.outbound.drain(..).collect()
    }

    /// Number of frames currently waiting in the outbound queue.
    /// Drivers can use this for backpressure heuristics (e.g.,
    /// stop calling `send_data` when >= 90% of `max_pending_outbound`).
    pub fn pending_outbound_len(&self) -> usize {
        self.outbound.len()
    }

    /// Snapshot a stream's current state. Returns `None` for both
    /// "never existed" and "transitioned to Closed" - closed
    /// streams are evicted from the map to bound state, so a closed
    /// id is indistinguishable from an unknown one. Diagnostics-only.
    pub fn stream_state(&self, stream_id: u32) -> Option<StreamState> {
        self.streams.get(&stream_id).map(|s| s.state)
    }

    /// Number of streams in any non-Closed state. Used by callers
    /// to display "connection load."
    pub fn open_streams(&self) -> u32 {
        self.open_count
    }

    /// Local role.
    pub fn role(&self) -> StreamRole {
        self.role
    }
}

/// Per-frame-receive event the caller acts on. The state machine
/// has already updated internal state and queued any auto-replies;
/// the event tells the caller what application-visible thing
/// happened.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum MuxEvent {
    /// Peer opened a new stream; caller decides accept/reject.
    Incoming { stream_id: u32, target: MuxTarget },
    /// Local stream's `Begin` was acknowledged.
    Established { stream_id: u32 },
    /// Application bytes for a stream.
    Data { stream_id: u32, body: Vec<u8> },
    /// Peer granted additional send-credit.
    WindowUpdate { stream_id: u32, delta: u32 },
    /// Peer half-closed write side.
    PeerEndLocal { stream_id: u32 },
    /// Peer aborted a stream.
    Reset { stream_id: u32, error_code: u8 },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_target() -> MuxTarget {
        MuxTarget::Ipv4 {
            addr: [127, 0, 0, 1],
            port: 80,
        }
    }

    fn other_target() -> MuxTarget {
        MuxTarget::Ipv4 {
            addr: [127, 0, 0, 2],
            port: 8080,
        }
    }

    #[test]
    fn open_local_queues_begin_and_yields_synsent_state() {
        let mut m = MuxState::new(StreamRole::Initiator, MuxPolicy::default());
        let id = m.open_local(ipv4_target()).unwrap();
        assert_eq!(m.stream_state(id.raw()), Some(StreamState::SynSent));
        assert_eq!(m.open_streams(), 1);
        let out = m.pending_outbound();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].command, MuxCmd::Begin);
        assert_eq!(out[0].stream_id, id.raw());
    }

    #[test]
    fn three_way_open_handshake() {
        // Initiator opens, responder accepts, both reach Open.
        let mut init = MuxState::new(StreamRole::Initiator, MuxPolicy::default());
        let mut resp = MuxState::new(StreamRole::Responder, MuxPolicy::default());
        let id = init.open_local(ipv4_target()).unwrap();
        let begin = init.pending_outbound().remove(0);
        // Responder receives Begin.
        let ev = resp.recv(begin).unwrap();
        match ev {
            MuxEvent::Incoming { stream_id, target } => {
                assert_eq!(stream_id, id.raw());
                assert_eq!(target, ipv4_target());
            }
            _ => panic!("expected Incoming"),
        }
        assert_eq!(resp.stream_state(id.raw()), Some(StreamState::SynReceived));
        // Responder accepts.
        let _ = resp.accept(id.raw()).unwrap();
        assert_eq!(resp.stream_state(id.raw()), Some(StreamState::Open));
        let begin_ok = resp.pending_outbound().remove(0);
        assert_eq!(begin_ok.command, MuxCmd::BeginOk);
        // Initiator receives BeginOk.
        let ev = init.recv(begin_ok).unwrap();
        assert!(matches!(ev, MuxEvent::Established { .. }));
        assert_eq!(init.stream_state(id.raw()), Some(StreamState::Open));
    }

    #[test]
    fn data_flow_credit_consumed() {
        let policy = MuxPolicy {
            initial_window: 100,
            ..MuxPolicy::default()
        };
        let mut m = MuxState::new(StreamRole::Initiator, policy);
        let id = m.open_local(ipv4_target()).unwrap();
        m.pending_outbound().clear();
        // Force into Open via a fake BeginOk.
        let ok = MuxFrame::new(id.raw(), MuxCmd::BeginOk, Vec::new()).unwrap();
        m.recv(ok).unwrap();
        // Send 30 bytes; credit drops to 70.
        let n = m.send_data(id.raw(), &[0u8; 30]).unwrap();
        assert_eq!(n, 30);
        // Send 90; only 70 credit available.
        let n = m.send_data(id.raw(), &[0u8; 90]).unwrap();
        assert_eq!(n, 70);
        // Next call returns 0; caller waits for WINDOW_UPDATE.
        let n = m.send_data(id.raw(), &[0u8; 1]).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn window_update_replenishes_credit() {
        let mut m = MuxState::new(StreamRole::Initiator, MuxPolicy::default());
        let id = m.open_local(ipv4_target()).unwrap();
        m.pending_outbound().clear();
        // Open it.
        let ok = MuxFrame::new(id.raw(), MuxCmd::BeginOk, Vec::new()).unwrap();
        m.recv(ok).unwrap();
        // Drain credit fully.
        let policy = MuxPolicy::default();
        let _ = m
            .send_data(id.raw(), &vec![0u8; policy.initial_window as usize])
            .unwrap();
        m.pending_outbound().clear();
        // Peer sends WindowUpdate +10000.
        let wu = MuxFrame::new(
            id.raw(),
            MuxCmd::WindowUpdate,
            10000u32.to_be_bytes().to_vec(),
        )
        .unwrap();
        m.recv(wu).unwrap();
        // Credit available again.
        let n = m.send_data(id.raw(), &[0u8; 5000]).unwrap();
        assert_eq!(n, 5000);
    }

    #[test]
    fn over_send_triggers_reset_and_close() {
        // Receiver tracks recv_window. If peer sends more than the
        // grant, state machine resets the stream.
        let policy = MuxPolicy {
            initial_window: 50,
            ..MuxPolicy::default()
        };
        let mut m = MuxState::new(StreamRole::Initiator, policy);
        // Synthesise a peer-opened stream into Open state.
        let begin = MuxFrame::new(1, MuxCmd::Begin, ipv4_target().encode().unwrap()).unwrap();
        m.recv(begin).unwrap();
        m.accept(1).unwrap();
        m.pending_outbound().clear();
        // Peer sends 100 bytes when only 50 are granted.
        let big = MuxFrame::new(1, MuxCmd::Data, vec![0u8; 100]).unwrap();
        let err = m.recv(big).unwrap_err();
        assert!(matches!(err, MuxStateError::BadState { .. }));
        // Closed streams are evicted from the map.
        assert_eq!(m.stream_state(1), None);
        assert_eq!(m.open_streams(), 0);
        let out = m.pending_outbound();
        assert!(out.iter().any(|f| f.command == MuxCmd::Reset));
    }

    #[test]
    fn end_local_then_peer_end_local_closes() {
        let mut m = MuxState::new(StreamRole::Initiator, MuxPolicy::default());
        let id = m.open_local(ipv4_target()).unwrap();
        m.pending_outbound().clear();
        let ok = MuxFrame::new(id.raw(), MuxCmd::BeginOk, Vec::new()).unwrap();
        m.recv(ok).unwrap();
        // Local end_local first.
        m.end_local(id.raw()).unwrap();
        assert_eq!(m.stream_state(id.raw()), Some(StreamState::HalfClosedLocal));
        // Peer EndLocal closes.
        let pe = MuxFrame::new(id.raw(), MuxCmd::EndLocal, Vec::new()).unwrap();
        m.recv(pe).unwrap();
        assert_eq!(m.stream_state(id.raw()), None);
        assert_eq!(m.open_streams(), 0);
    }

    #[test]
    fn reset_kills_stream_and_decrements_open_count() {
        let mut m = MuxState::new(StreamRole::Initiator, MuxPolicy::default());
        let id = m.open_local(ipv4_target()).unwrap();
        m.reset(id.raw(), 0xFF).unwrap();
        assert_eq!(m.stream_state(id.raw()), None);
        assert_eq!(m.open_streams(), 0);
    }

    #[test]
    fn concurrent_stream_cap_enforced_locally() {
        let policy = MuxPolicy {
            max_concurrent_streams: 2,
            ..MuxPolicy::default()
        };
        let mut m = MuxState::new(StreamRole::Initiator, policy);
        m.open_local(ipv4_target()).unwrap();
        m.open_local(other_target()).unwrap();
        let err = m.open_local(ipv4_target()).unwrap_err();
        assert!(matches!(err, MuxStateError::StreamLimit(_)));
    }

    #[test]
    fn concurrent_stream_cap_enforced_on_inbound() {
        let policy = MuxPolicy {
            max_concurrent_streams: 1,
            ..MuxPolicy::default()
        };
        let mut m = MuxState::new(StreamRole::Responder, policy);
        // Peer opens stream 2 (initiator-allocated, valid for the
        // responder to receive).
        let b1 = MuxFrame::new(2, MuxCmd::Begin, ipv4_target().encode().unwrap()).unwrap();
        m.recv(b1).unwrap();
        // Peer opens stream 4. Cap is 1; reject with Reset.
        let b2 = MuxFrame::new(4, MuxCmd::Begin, ipv4_target().encode().unwrap()).unwrap();
        let err = m.recv(b2).unwrap_err();
        assert!(matches!(err, MuxStateError::StreamLimit(_)));
        let out = m.pending_outbound();
        assert!(out
            .iter()
            .any(|f| f.stream_id == 4 && f.command == MuxCmd::Reset));
    }

    #[test]
    fn unknown_stream_data_rejected() {
        let mut m = MuxState::new(StreamRole::Initiator, MuxPolicy::default());
        let bogus = MuxFrame::new(999, MuxCmd::Data, vec![1, 2, 3]).unwrap();
        let err = m.recv(bogus).unwrap_err();
        assert_eq!(err, MuxStateError::UnknownStream(999));
    }

    #[test]
    fn data_on_synsent_stream_rejected() {
        let mut m = MuxState::new(StreamRole::Initiator, MuxPolicy::default());
        let id = m.open_local(ipv4_target()).unwrap();
        // Stream is in SynSent; Data is illegal.
        let d = MuxFrame::new(id.raw(), MuxCmd::Data, vec![1]).unwrap();
        let err = m.recv(d).unwrap_err();
        assert!(matches!(err, MuxStateError::BadState { .. }));
    }

    #[test]
    fn double_begin_same_id_rejected() {
        let mut m = MuxState::new(StreamRole::Responder, MuxPolicy::default());
        let b1 = MuxFrame::new(2, MuxCmd::Begin, ipv4_target().encode().unwrap()).unwrap();
        m.recv(b1.clone()).unwrap();
        // Second BEGIN with same id is a peer error.
        let err = m.recv(b1).unwrap_err();
        assert!(matches!(err, MuxStateError::BadState { .. }));
    }

    #[test]
    fn grant_credit_emits_window_update() {
        let mut m = MuxState::new(StreamRole::Initiator, MuxPolicy::default());
        let id = m.open_local(ipv4_target()).unwrap();
        m.pending_outbound().clear();
        m.grant_credit(id.raw(), 4096).unwrap();
        let out = m.pending_outbound();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].command, MuxCmd::WindowUpdate);
        assert_eq!(
            u32::from_be_bytes([
                out[0].body[0],
                out[0].body[1],
                out[0].body[2],
                out[0].body[3]
            ]),
            4096
        );
    }

    #[test]
    fn reject_emits_reset_with_code_01() {
        let mut m = MuxState::new(StreamRole::Responder, MuxPolicy::default());
        let b = MuxFrame::new(2, MuxCmd::Begin, ipv4_target().encode().unwrap()).unwrap();
        m.recv(b).unwrap();
        m.reject(2).unwrap();
        let out = m.pending_outbound();
        let rst = out.iter().find(|f| f.command == MuxCmd::Reset).unwrap();
        assert_eq!(rst.body, vec![0x01]);
        assert_eq!(m.stream_state(2), None);
    }

    #[test]
    fn closed_stream_evicted_so_id_can_be_reused() {
        // Confirms the leak fix: after a stream closes, its entry
        // is removed from the internal map so long-running peers
        // don't accumulate dead-stream state forever.
        let mut m = MuxState::new(StreamRole::Responder, MuxPolicy::default());
        let b = MuxFrame::new(2, MuxCmd::Begin, ipv4_target().encode().unwrap()).unwrap();
        m.recv(b.clone()).unwrap();
        m.reject(2).unwrap();
        assert_eq!(m.stream_state(2), None);
        // Peer can re-Begin id=2 because the slot is free.
        m.recv(b).unwrap();
        assert_eq!(m.stream_state(2), Some(StreamState::SynReceived));
    }

    #[test]
    fn outbound_queue_cap_enforced() {
        // Pre-fix the queue could grow unboundedly. After fix the
        // state machine returns OutboundQueueFull instead.
        let policy = MuxPolicy {
            max_pending_outbound: 4,
            max_concurrent_streams: 1024,
            ..MuxPolicy::default()
        };
        let mut m = MuxState::new(StreamRole::Initiator, policy);
        // Each open_local enqueues one Begin; cap is 4 so the 5th
        // call should fail.
        for _ in 0..4 {
            m.open_local(ipv4_target()).unwrap();
        }
        let err = m.open_local(ipv4_target()).unwrap_err();
        assert!(matches!(err, MuxStateError::OutboundQueueFull(4)));
        // Drain releases pressure.
        let drained = m.pending_outbound();
        assert_eq!(drained.len(), 4);
        m.open_local(ipv4_target()).unwrap();
    }
}
