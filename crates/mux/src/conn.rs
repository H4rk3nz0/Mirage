//! Async connection driver over a Mirage session carrier.
//!
//! [`MuxState`](crate::state::MuxState) is I/O-free; this module is the
//! canonical tokio driver the crate docs promised. It owns one carrier
//! (typically a decrypted `SessionStream`), pumps mux frames in both
//! directions, and hands out per-stream [`MuxStream`] duplex handles that
//! implement [`AsyncRead`]/[`AsyncWrite`]. One carrier + one handshake +
//! one capability token now serves many concurrent streams, so a browser's
//! 100-300 parallel connections stop costing 100-300 handshakes/tokens/slots.
//!
//! # Architecture
//!
//! Two tasks share the state machine behind a `std::sync::Mutex` (critical
//! sections are short and never span an `.await`):
//!
//! - **reader** owns the carrier read half: decodes frames, feeds
//!   [`MuxState::recv`], and routes [`MuxEvent`]s to per-stream buffers /
//!   the acceptor / open-waiters.
//! - **writer** owns the carrier write half: on each wake it flushes queued
//!   application bytes (respecting per-stream send credit) plus any control
//!   frames the state machine produced, then writes them to the carrier.
//!
//! Splitting read and write into separate tasks is deliberate: a single
//! task blocked on `write_all().await` (a slow peer) must not stop draining
//! the carrier read side, or the two ends deadlock. Per-stream flow-control
//! windows bound memory; `poll_write` backpressures the app when a stream's
//! staging buffer is full; `poll_shutdown` emits `EndLocal` so TCP
//! half-close propagates end-to-end (the bug the padding layer used to eat).
//!
//! # Lock hierarchy
//!
//! `state`  superset  `streams`  superset  `{out, inb}` (leaves). A task holding a leaf lock
//! never reaches back up for `state`; the handle methods that touch `state`
//! (`open`/`accept`/`reject`/grant) take leaf locks and `state`
//! *sequentially*, never nested leaf-then-state. This is acyclic, so the
//! driver cannot self-deadlock.

// The read/write hot paths index into buffers only after explicit length
// checks (`ReadBuf::remaining()`, `VecDeque` bounds) and use `window / 2` as
// the credit-grant threshold; both are intentional and bounds-safe.
#![allow(clippy::indexing_slicing, clippy::integer_division)]

use std::collections::{HashMap, VecDeque};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, oneshot, Notify};

use crate::frame::{MuxFrame, MuxFrameError};
use crate::policy::MuxPolicy;
use crate::state::{MuxEvent, MuxState, MuxStateError};
use crate::stream::StreamRole;
use crate::target::MuxTarget;

/// Error opening a stream over a mux connection.
#[derive(Debug, thiserror::Error)]
pub enum MuxConnError {
    /// The connection is closed (carrier died or was shut down).
    #[error("mux connection closed")]
    Closed,
    /// The peer refused the stream with the given error code (e.g. the
    /// bridge could not reach the requested target). For the SOCKS path
    /// this becomes a SOCKS5 failure reply to the app.
    #[error("stream refused by peer (code 0x{0:02x})")]
    Rejected(u8),
    /// Local concurrent-stream cap reached; try again or use another carrier.
    #[error("stream limit reached")]
    StreamLimit,
    /// State-machine rejected the open (id space exhausted, bad target, ...).
    #[error("mux state: {0}")]
    State(#[from] MuxStateError),
}

// -- per-stream shared buffers -----------------------------------------------

struct OutBuf {
    /// Application bytes staged for the writer to frame + send.
    buf: VecDeque<u8>,
    /// App requested half-close (`poll_shutdown`).
    ending: bool,
    /// `EndLocal` has been emitted.
    ended_sent: bool,
    /// Stream is terminally closed/reset; further writes error.
    closed: bool,
    /// Woken when the staging buffer drains below its cap.
    write_waker: Option<Waker>,
    /// Woken when a requested half-close has fully flushed + `EndLocal` sent.
    shutdown_waker: Option<Waker>,
}

struct InBuf {
    chunks: VecDeque<Vec<u8>>,
    /// Read offset into `chunks.front()`.
    cursor: usize,
    /// Bytes buffered but not yet consumed by the app (diagnostic).
    buffered: usize,
    /// Bytes consumed since the last `WindowUpdate` grant.
    unacked: u32,
    /// Peer half-closed its write side (`EndLocal`) -> EOF once drained.
    eof: bool,
    /// Peer/connection reset this stream (error code).
    reset: Option<u8>,
    read_waker: Option<Waker>,
}

struct StreamShared {
    id: u32,
    /// Per-direction flow-control window; also the staging-buffer cap.
    window: u32,
    out: Mutex<OutBuf>,
    inb: Mutex<InBuf>,
}

impl StreamShared {
    fn new(id: u32, window: u32) -> Self {
        Self {
            id,
            window,
            out: Mutex::new(OutBuf {
                buf: VecDeque::new(),
                ending: false,
                ended_sent: false,
                closed: false,
                write_waker: None,
                shutdown_waker: None,
            }),
            inb: Mutex::new(InBuf {
                chunks: VecDeque::new(),
                cursor: 0,
                buffered: 0,
                unacked: 0,
                eof: false,
                reset: None,
                read_waker: None,
            }),
        }
    }
}

// -- connection innards (shared by both tasks + all handles) -----------------

struct ConnInner {
    state: Mutex<MuxState>,
    streams: Mutex<HashMap<u32, Arc<StreamShared>>>,
    open_waiters: Mutex<HashMap<u32, oneshot::Sender<Result<(), u8>>>>,
    /// Wakes the writer to perform a drain pass.
    writer_wake: Notify,
    closed: AtomicBool,
    policy: MuxPolicy,
    /// Abort handle for the reader task. `close()` uses it to interrupt the
    /// reader's blocking `rd.read().await` so the carrier is dropped (and a FIN
    /// emitted) promptly on a LOCAL close, instead of waiting for the peer to
    /// close first (MUX-3 / PAD-1). Set once, just after the reader is spawned.
    reader_abort: Mutex<Option<tokio::task::AbortHandle>>,
}

impl ConnInner {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

/// Tear the connection down: fail every live stream and open-waiter, and
/// wake the writer so it exits. Idempotent.
fn close_connection(inner: &Arc<ConnInner>) {
    if inner.closed.swap(true, Ordering::AcqRel) {
        return;
    }
    let streams: Vec<Arc<StreamShared>> = {
        let mut map = inner.streams.lock().expect("streams lock");
        map.drain().map(|(_, v)| v).collect()
    };
    for sh in streams {
        {
            let mut inb = sh.inb.lock().expect("inb lock");
            if inb.reset.is_none() && !inb.eof {
                inb.reset = Some(0xFF);
            }
            if let Some(w) = inb.read_waker.take() {
                w.wake();
            }
        }
        {
            let mut ob = sh.out.lock().expect("out lock");
            ob.closed = true;
            if let Some(w) = ob.write_waker.take() {
                w.wake();
            }
            if let Some(w) = ob.shutdown_waker.take() {
                w.wake();
            }
        }
    }
    // Dropping the senders resolves pending open() futures with Err(Closed).
    inner.open_waiters.lock().expect("waiters lock").clear();
    inner.writer_wake.notify_one();
    // Interrupt the reader's blocking read so it drops its carrier half now.
    // With the writer already exiting (via writer_wake -> is_closed check) and
    // dropping its half, both halves drop and the carrier emits a FIN. Harmless
    // if the reader is the one calling this (on carrier EOF it is already
    // returning) - aborting a finished task is a no-op.
    if let Some(h) = inner.reader_abort.lock().expect("reader_abort lock").take() {
        h.abort();
    }
}

// -- public handles ----------------------------------------------------------

/// A multiplexed connection over one carrier. Cheap to clone; every clone
/// shares the same underlying streams and tasks.
#[derive(Clone)]
pub struct MuxConnection {
    inner: Arc<ConnInner>,
}

/// Receives peer-opened streams (responder side).
pub struct MuxAcceptor {
    rx: mpsc::UnboundedReceiver<IncomingStream>,
}

impl MuxConnection {
    /// Wrap `carrier`, spawn the reader/writer tasks, and return the
    /// connection handle plus an acceptor for peer-opened streams.
    pub fn new<C>(carrier: C, role: StreamRole, policy: MuxPolicy) -> (Self, MuxAcceptor)
    where
        C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let inner = Arc::new(ConnInner {
            state: Mutex::new(MuxState::new(role, policy.clone())),
            streams: Mutex::new(HashMap::new()),
            open_waiters: Mutex::new(HashMap::new()),
            writer_wake: Notify::new(),
            closed: AtomicBool::new(false),
            policy,
            reader_abort: Mutex::new(None),
        });
        let (rd, wr) = tokio::io::split(carrier);
        let (accept_tx, accept_rx) = mpsc::unbounded_channel();
        let reader = tokio::spawn(reader_task(Arc::clone(&inner), rd, accept_tx));
        *inner.reader_abort.lock().expect("reader_abort lock") = Some(reader.abort_handle());
        tokio::spawn(writer_task(Arc::clone(&inner), wr));
        (
            MuxConnection {
                inner: Arc::clone(&inner),
            },
            MuxAcceptor { rx: accept_rx },
        )
    }

    /// Open a new stream to `target`. Resolves once the peer acknowledges
    /// (for the SOCKS path: once the bridge has connected the upstream), or
    /// errors if the peer refuses or the connection dies.
    pub async fn open(&self, target: MuxTarget) -> Result<MuxStream, MuxConnError> {
        if self.inner.is_closed() {
            return Err(MuxConnError::Closed);
        }
        let window = self.inner.policy.initial_window;
        let (id, sh, rx) = {
            let mut st = self.inner.state.lock().expect("state lock");
            let id = st.open_local(target).map_err(map_open_err)?.raw();
            let sh = Arc::new(StreamShared::new(id, window));
            self.inner
                .streams
                .lock()
                .expect("streams lock")
                .insert(id, Arc::clone(&sh));
            let (tx, rx) = oneshot::channel();
            self.inner
                .open_waiters
                .lock()
                .expect("waiters lock")
                .insert(id, tx);
            (id, sh, rx)
        };
        // Nudge the writer to emit the Begin frame.
        self.inner.writer_wake.notify_one();
        // Close-race guard (MUX-1): if the connection closed between the
        // is_closed() check above and inserting our waiter, close_connection
        // already drained the then-empty maps and - being idempotent - will
        // never revisit them, so nothing would ever resolve or drop our Sender
        // and `rx.await` would hang forever. Re-check and self-clean. This is
        // race-free: close_connection sets closed=true (AcqRel) strictly before
        // clearing open_waiters, so either we observe closed here and clean up,
        // or close runs after and drops our Sender (rx resolves to Err).
        if self.inner.is_closed() {
            self.inner
                .open_waiters
                .lock()
                .expect("waiters lock")
                .remove(&id);
            self.inner.streams.lock().expect("streams lock").remove(&id);
            return Err(MuxConnError::Closed);
        }
        match rx.await {
            Ok(Ok(())) => Ok(MuxStream {
                inner: Arc::clone(&self.inner),
                shared: sh,
                id,
            }),
            Ok(Err(code)) => Err(MuxConnError::Rejected(code)),
            Err(_) => Err(MuxConnError::Closed),
        }
    }

    /// Number of streams currently open on this connection.
    pub fn open_stream_count(&self) -> u32 {
        self.inner.state.lock().expect("state lock").open_streams()
    }

    /// Whether the connection has been torn down.
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// Tear the connection down (fails all streams; the carrier is dropped
    /// when both tasks exit).
    pub fn close(&self) {
        close_connection(&self.inner);
    }
}

impl MuxAcceptor {
    /// Await the next peer-opened stream. Returns `None` when the connection
    /// closes. The returned [`IncomingStream`] is not yet acknowledged - the
    /// caller decides `accept()` (connected -> `BeginOk`) or `reject()`.
    pub async fn accept(&mut self) -> Option<IncomingStream> {
        // `None` means the reader task's sender was dropped - the connection
        // is gone.
        self.rx.recv().await
    }
}

/// A peer-opened stream awaiting the local side's accept/reject decision.
pub struct IncomingStream {
    inner: Arc<ConnInner>,
    shared: Arc<StreamShared>,
    target: MuxTarget,
    /// Set once accept/reject has been issued so `Drop` doesn't double-reset.
    decided: bool,
}

impl IncomingStream {
    /// The destination the peer asked to reach.
    pub fn target(&self) -> &MuxTarget {
        &self.target
    }

    /// Accept the stream (emit `BeginOk`); returns the duplex handle.
    pub fn accept(mut self) -> MuxStream {
        self.decided = true;
        {
            let mut st = self.inner.state.lock().expect("state lock");
            // accept() queues BeginOk; ignore an error (stream already gone).
            let _ = st.accept(self.shared.id);
        }
        self.inner.writer_wake.notify_one();
        MuxStream {
            inner: Arc::clone(&self.inner),
            shared: Arc::clone(&self.shared),
            id: self.shared.id,
        }
    }

    /// Reject the stream with an error code (emit `Reset` carrying `code`, so
    /// the initiator can map it to e.g. a SOCKS5 failure reply).
    pub fn reject(mut self, code: u8) {
        self.decided = true;
        {
            let mut st = self.inner.state.lock().expect("state lock");
            let _ = st.reset(self.shared.id, code);
        }
        self.inner
            .streams
            .lock()
            .expect("streams lock")
            .remove(&self.shared.id);
        self.inner.writer_wake.notify_one();
    }
}

impl Drop for IncomingStream {
    fn drop(&mut self) {
        if self.decided {
            return;
        }
        // Dropped without a decision -> refuse it so the peer doesn't hang.
        let mut st = self.inner.state.lock().expect("state lock");
        let _ = st
            .reject(self.shared.id)
            .or_else(|_| st.reset(self.shared.id, 0x01));
        drop(st);
        self.inner
            .streams
            .lock()
            .expect("streams lock")
            .remove(&self.shared.id);
        self.inner.writer_wake.notify_one();
    }
}

/// A bidirectional mux stream. Implements [`AsyncRead`]/[`AsyncWrite`]; a
/// full-duplex byte pipe indistinguishable from a `TcpStream` to callers
/// like `copy_bidirectional`.
pub struct MuxStream {
    inner: Arc<ConnInner>,
    shared: Arc<StreamShared>,
    id: u32,
}

impl MuxStream {
    /// This stream's id (diagnostics).
    pub fn id(&self) -> u32 {
        self.id
    }
}

impl std::fmt::Debug for MuxStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuxStream")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl AsyncRead for MuxStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        rbuf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        let mut inb = me.shared.inb.lock().expect("inb lock");
        let mut copied = 0usize;
        while rbuf.remaining() > 0 {
            // Scope the immutable borrow of `inb.chunks` so the mutations
            // below (cursor/buffered) don't overlap it.
            let (take, chunk_done) = {
                let Some(front) = inb.chunks.front() else {
                    break;
                };
                let start = inb.cursor;
                let avail = front.len() - start;
                let take = avail.min(rbuf.remaining());
                rbuf.put_slice(&front[start..start + take]);
                (take, start + take >= front.len())
            };
            inb.cursor += take;
            inb.buffered -= take;
            copied += take;
            if chunk_done {
                inb.chunks.pop_front();
                inb.cursor = 0;
            }
        }
        if copied > 0 {
            inb.unacked = inb.unacked.saturating_add(copied as u32);
            // Grant back consumed credit once half a window has drained, so
            // the peer's send window stays open without a frame per read.
            let grant = if inb.unacked >= me.shared.window / 2 {
                let g = inb.unacked;
                inb.unacked = 0;
                Some(g)
            } else {
                None
            };
            drop(inb);
            if let Some(g) = grant {
                {
                    let mut st = me.inner.state.lock().expect("state lock");
                    let _ = st.grant_credit(me.id, g);
                }
                me.inner.writer_wake.notify_one();
            }
            return Poll::Ready(Ok(()));
        }
        if inb.reset.is_some() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "mux stream reset",
            )));
        }
        if inb.eof {
            return Poll::Ready(Ok(())); // 0 bytes read == EOF
        }
        inb.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        let mut ob = me.shared.out.lock().expect("out lock");
        if ob.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "mux stream closed",
            )));
        }
        let cap = me.shared.window as usize;
        if ob.buf.len() >= cap {
            ob.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let space = cap - ob.buf.len();
        let n = buf.len().min(space);
        ob.buf.extend(&buf[..n]);
        drop(ob);
        me.inner.writer_wake.notify_one();
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The writer task flushes the carrier after every drain pass; staged
        // bytes are already in its hands. Nudge it and report success.
        self.inner.writer_wake.notify_one();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        let mut ob = me.shared.out.lock().expect("out lock");
        ob.ending = true;
        if ob.closed || (ob.buf.is_empty() && ob.ended_sent) {
            return Poll::Ready(Ok(()));
        }
        // Not yet flushed + EndLocal-sent: park until the writer finishes.
        ob.shutdown_waker = Some(cx.waker().clone());
        drop(ob);
        me.inner.writer_wake.notify_one();
        Poll::Pending
    }
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        // Remove from the routing map and, if the stream is still live in the
        // state machine (i.e. not gracefully closed), Reset it so the peer
        // promptly tears down its upstream. reset() on an already-closed /
        // unknown id is a harmless no-op.
        let was_present = self
            .inner
            .streams
            .lock()
            .expect("streams lock")
            .remove(&self.id)
            .is_some();
        if !was_present {
            return;
        }
        let mut st = self.inner.state.lock().expect("state lock");
        if st.stream_state(self.id).is_some() {
            let _ = st.reset(self.id, 0x00);
            drop(st);
            self.inner.writer_wake.notify_one();
        }
    }
}

fn map_open_err(e: MuxStateError) -> MuxConnError {
    match e {
        MuxStateError::StreamLimit(_) => MuxConnError::StreamLimit,
        other => MuxConnError::State(other),
    }
}

// -- reader task -------------------------------------------------------------

async fn reader_task<R>(
    inner: Arc<ConnInner>,
    mut rd: R,
    accept_tx: mpsc::UnboundedSender<IncomingStream>,
) where
    R: AsyncRead + Unpin,
{
    let mut acc: Vec<u8> = Vec::with_capacity(crate::frame::MAX_MUX_FRAME_LEN);
    let mut tmp = vec![0u8; 16 * 1024];
    'outer: loop {
        let n = match rd.read(&mut tmp).await {
            Ok(n) if n > 0 => n,
            Ok(_) | Err(_) => break, // carrier EOF or error
        };
        acc.extend_from_slice(&tmp[..n]);
        loop {
            match MuxFrame::decode_one(&acc) {
                Ok((frame, consumed)) => {
                    acc.drain(..consumed);
                    if handle_frame(&inner, &accept_tx, frame).is_break() {
                        break 'outer;
                    }
                }
                Err(MuxFrameError::Truncated { .. }) => break, // need more bytes
                Err(_) => break 'outer,                        // wire protocol violation
            }
        }
        // Flush any auto-replies (BeginOk/Reset) and act on credit changes.
        inner.writer_wake.notify_one();
    }
    close_connection(&inner);
}

/// Returns `Break` if the connection must be torn down.
fn handle_frame(
    inner: &Arc<ConnInner>,
    accept_tx: &mpsc::UnboundedSender<IncomingStream>,
    frame: MuxFrame,
) -> std::ops::ControlFlow<()> {
    use std::ops::ControlFlow::Continue;
    let sid = frame.stream_id;
    let ev = {
        let mut st = inner.state.lock().expect("state lock");
        match st.recv(frame) {
            Ok(ev) => ev,
            // Per-stream frame errors are non-fatal: the state machine has
            // already queued any Reset. Foreign-id / over-send are handled
            // this way too; the connection survives, the stream is reset.
            //
            // MUX-2: but if the error CLOSED an app-held stream (e.g. a
            // flow-control over-send, which evicts the stream from the state
            // machine and queues a Reset), we must also fault the local handle
            // - otherwise a task parked in poll_read/poll_write hangs forever,
            // and drain_pass would silently drop the routing entry. Detect the
            // close via stream_state==None and fault the handle so the app sees
            // a clean ConnectionReset.
            Err(_) => {
                let closed = st.stream_state(sid).is_none();
                drop(st);
                if closed {
                    fault_stream(inner, sid, 0xFF);
                }
                return Continue(());
            }
        }
    };
    match ev {
        MuxEvent::Incoming { stream_id, target } => {
            let sh = Arc::new(StreamShared::new(stream_id, inner.policy.initial_window));
            inner
                .streams
                .lock()
                .expect("streams lock")
                .insert(stream_id, Arc::clone(&sh));
            let incoming = IncomingStream {
                inner: Arc::clone(inner),
                shared: sh,
                target,
                decided: false,
            };
            if accept_tx.send(incoming).is_err() {
                // No acceptor (initiator-only side, or acceptor dropped):
                // refuse the stream. The IncomingStream's Drop resets it.
            }
        }
        MuxEvent::Established { stream_id } => {
            if let Some(tx) = inner
                .open_waiters
                .lock()
                .expect("waiters lock")
                .remove(&stream_id)
            {
                let _ = tx.send(Ok(()));
            }
        }
        MuxEvent::Data { stream_id, body } => {
            let sh = inner
                .streams
                .lock()
                .expect("streams lock")
                .get(&stream_id)
                .cloned();
            if let Some(sh) = sh {
                let mut inb = sh.inb.lock().expect("inb lock");
                inb.buffered += body.len();
                inb.chunks.push_back(body);
                if let Some(w) = inb.read_waker.take() {
                    w.wake();
                }
            }
        }
        MuxEvent::WindowUpdate { .. } => {
            // Credit was applied in recv(); wake the writer to send more.
            inner.writer_wake.notify_one();
        }
        MuxEvent::PeerEndLocal { stream_id } => {
            let sh = inner
                .streams
                .lock()
                .expect("streams lock")
                .get(&stream_id)
                .cloned();
            if let Some(sh) = sh {
                let mut inb = sh.inb.lock().expect("inb lock");
                inb.eof = true;
                if let Some(w) = inb.read_waker.take() {
                    w.wake();
                }
            }
            // If that closed the stream (we had already half-closed), evict it.
            if inner
                .state
                .lock()
                .expect("state lock")
                .stream_state(stream_id)
                .is_none()
            {
                inner
                    .streams
                    .lock()
                    .expect("streams lock")
                    .remove(&stream_id);
            }
        }
        MuxEvent::Reset {
            stream_id,
            error_code,
        } => {
            if let Some(tx) = inner
                .open_waiters
                .lock()
                .expect("waiters lock")
                .remove(&stream_id)
            {
                let _ = tx.send(Err(error_code));
            }
            fault_stream(inner, stream_id, error_code);
        }
    }
    Continue(())
}

/// Fault a stream's local handle: mark it reset, wake every parked waiter
/// (read/write/shutdown), and evict it from the routing map. Idempotent - a
/// no-op if there is no live handle for `stream_id` (e.g. a bogus frame for an
/// id we never opened). Shared by the `Reset` event and the recv-error path
/// (MUX-2) so a state-machine-closed stream never orphans a parked task.
fn fault_stream(inner: &Arc<ConnInner>, stream_id: u32, code: u8) {
    let sh = inner
        .streams
        .lock()
        .expect("streams lock")
        .remove(&stream_id);
    if let Some(sh) = sh {
        {
            let mut inb = sh.inb.lock().expect("inb lock");
            if inb.reset.is_none() {
                inb.reset = Some(code);
            }
            if let Some(w) = inb.read_waker.take() {
                w.wake();
            }
        }
        let mut ob = sh.out.lock().expect("out lock");
        ob.closed = true;
        if let Some(w) = ob.write_waker.take() {
            w.wake();
        }
        if let Some(w) = ob.shutdown_waker.take() {
            w.wake();
        }
    }
}

// -- writer task -------------------------------------------------------------

async fn writer_task<W>(inner: Arc<ConnInner>, mut wr: W)
where
    W: AsyncWrite + Unpin,
{
    loop {
        inner.writer_wake.notified().await;
        if inner.is_closed() {
            break;
        }
        let out_bytes = drain_pass(&inner);
        if !out_bytes.is_empty() {
            if wr.write_all(&out_bytes).await.is_err() {
                break;
            }
            if wr.flush().await.is_err() {
                break;
            }
        }
    }
    let _ = wr.shutdown().await;
    close_connection(&inner);
}

/// One writer pass: push staged app bytes through the credit window, emit
/// half-closes, prune dead streams, and serialize all queued frames.
fn drain_pass(inner: &Arc<ConnInner>) -> Vec<u8> {
    let mut st = inner.state.lock().expect("state lock");
    let streams: Vec<Arc<StreamShared>> = inner
        .streams
        .lock()
        .expect("streams lock")
        .values()
        .cloned()
        .collect();
    for sh in &streams {
        let mut ob = sh.out.lock().expect("out lock");
        // Flush as much staged data as credit + frame cap allow.
        loop {
            if ob.buf.is_empty() {
                break;
            }
            let slice = ob.buf.make_contiguous();
            match st.send_data(sh.id, slice) {
                // 0 == no credit (wait for WindowUpdate); Err == not writable.
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    ob.buf.drain(..n);
                }
            }
        }
        // Half-close once the staging buffer is fully flushed.
        if ob.ending && ob.buf.is_empty() && !ob.ended_sent {
            // end_local errors only if the stream is already gone; either way
            // the local write side is done.
            let _ = st.end_local(sh.id);
            ob.ended_sent = true;
        }
        // Wake a writer blocked on a full staging buffer.
        if ob.buf.len() < sh.window as usize {
            if let Some(w) = ob.write_waker.take() {
                w.wake();
            }
        }
        // Wake a completed poll_shutdown.
        if ob.ending && ob.buf.is_empty() && ob.ended_sent {
            if let Some(w) = ob.shutdown_waker.take() {
                w.wake();
            }
        }
    }
    // Prune streams the state machine has retired (fully closed). Their
    // handles keep their own Arc, so already-buffered inbound stays readable.
    {
        let mut map = inner.streams.lock().expect("streams lock");
        map.retain(|id, _| st.stream_state(*id).is_some());
    }
    let frames = st.pending_outbound();
    drop(st);
    let mut bytes = Vec::new();
    for f in frames {
        bytes.extend_from_slice(&f.encode());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn pair(policy: MuxPolicy) -> (MuxConnection, MuxAcceptor, MuxConnection, MuxAcceptor) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (ca, aa) = MuxConnection::new(a, StreamRole::Initiator, policy.clone());
        let (cb, ab) = MuxConnection::new(b, StreamRole::Responder, policy);
        (ca, aa, cb, ab)
    }

    fn dom(host: &str, port: u16) -> MuxTarget {
        MuxTarget::Domain {
            domain: host.to_string(),
            port,
        }
    }

    /// Bridge-style echo: accept every incoming stream and echo bytes back.
    fn spawn_echo_responder(mut acc: MuxAcceptor) {
        tokio::spawn(async move {
            while let Some(inc) = acc.accept().await {
                let mut s = inc.accept();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                if s.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    let _ = s.shutdown().await;
                });
            }
        });
    }

    #[tokio::test]
    async fn open_echo_roundtrip() {
        let (ca, _aa, _cb, ab) = pair(MuxPolicy::default());
        spawn_echo_responder(ab);
        let mut s = ca.open(dom("example.com", 443)).await.unwrap();
        s.write_all(b"hello mux").await.unwrap();
        let mut got = [0u8; 9];
        s.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello mux");
    }

    #[tokio::test]
    async fn many_concurrent_streams() {
        let (ca, _aa, _cb, ab) = pair(MuxPolicy::default());
        spawn_echo_responder(ab);
        let mut handles = Vec::new();
        for i in 0..64u32 {
            let ca = ca.clone();
            handles.push(tokio::spawn(async move {
                let mut s = ca.open(dom("host.example", 80)).await.unwrap();
                let msg = format!("stream-{i}");
                s.write_all(msg.as_bytes()).await.unwrap();
                let mut got = vec![0u8; msg.len()];
                s.read_exact(&mut got).await.unwrap();
                assert_eq!(got, msg.as_bytes());
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    }

    #[tokio::test]
    async fn half_close_propagates_eof() {
        let (ca, _aa, _cb, mut ab) = pair(MuxPolicy::default());
        // Responder: read to EOF (proving the peer's half-close arrived), then reply.
        tokio::spawn(async move {
            let inc = ab.accept().await.unwrap();
            let mut s = inc.accept();
            let mut all = Vec::new();
            s.read_to_end(&mut all).await.unwrap();
            assert_eq!(all, b"request-body");
            s.write_all(b"response").await.unwrap();
            s.shutdown().await.unwrap();
        });
        let mut s = ca.open(dom("a.example", 80)).await.unwrap();
        s.write_all(b"request-body").await.unwrap();
        s.shutdown().await.unwrap(); // half-close our write side
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).await.unwrap();
        assert_eq!(resp, b"response");
    }

    #[tokio::test]
    async fn reject_surfaces_as_error() {
        let (ca, _aa, _cb, mut ab) = pair(MuxPolicy::default());
        tokio::spawn(async move {
            if let Some(inc) = ab.accept().await {
                inc.reject(0x04); // host-unreachable-ish
            }
        });
        let err = ca.open(dom("blocked.example", 443)).await.unwrap_err();
        match err {
            MuxConnError::Rejected(code) => assert_eq!(code, 0x04),
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn large_transfer_across_windows() {
        // 1 MiB through a 64 KiB window exercises WindowUpdate flow control.
        // Read and write concurrently (as a real proxy's copy_bidirectional
        // does) - a write-all-then-read pattern would echo-deadlock at the
        // window limit, which is correct backpressure, not a bug.
        let (ca, _aa, _cb, ab) = pair(MuxPolicy::default());
        spawn_echo_responder(ab);
        let s = ca.open(dom("big.example", 80)).await.unwrap();
        let (mut rd, mut wr) = tokio::io::split(s);
        let payload = vec![0x5au8; 1024 * 1024];
        let wpay = payload.clone();
        let writer = tokio::spawn(async move {
            wr.write_all(&wpay).await.unwrap();
            wr.shutdown().await.unwrap();
        });
        let reader = tokio::spawn(async move {
            let mut back = Vec::new();
            rd.read_to_end(&mut back).await.unwrap();
            back
        });
        writer.await.unwrap();
        let back = reader.await.unwrap();
        assert_eq!(back.len(), payload.len());
        assert_eq!(back, payload);
    }

    #[tokio::test]
    async fn carrier_death_fails_open() {
        let policy = MuxPolicy::default();
        let (a, b) = tokio::io::duplex(1024);
        let (ca, _aa) = MuxConnection::new(a, StreamRole::Initiator, policy.clone());
        // Drop the peer carrier: the connection should tear down and open() err.
        drop(b);
        // Give the reader task a tick to observe EOF.
        tokio::task::yield_now().await;
        let res = ca.open(dom("gone.example", 80)).await;
        assert!(res.is_err(), "open must fail once carrier is dead");
    }

    #[tokio::test]
    async fn drop_stream_resets_peer() {
        let (ca, _aa, _cb, mut ab) = pair(MuxPolicy::default());
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let inc = ab.accept().await.unwrap();
            let mut s = inc.accept();
            let mut buf = [0u8; 16];
            // First read gets data; after the initiator drops, we see reset/eof.
            let _ = s.read(&mut buf).await;
            let second = s.read(&mut buf).await;
            let _ = tx.send(second.unwrap_or(0));
        });
        let mut s = ca.open(dom("drop.example", 80)).await.unwrap();
        s.write_all(b"hi").await.unwrap();
        s.flush().await.unwrap();
        tokio::task::yield_now().await;
        drop(s); // abrupt drop -> Reset to peer
        let second = rx.await.unwrap();
        assert_eq!(second, 0, "peer read returns EOF/err after reset");
    }

    #[tokio::test]
    async fn local_close_faults_streams_and_blocks_new_opens() {
        // A LOCAL close() (e.g. idle-carrier reaping) must promptly fault live
        // streams and reject new opens - without waiting for the peer to close
        // (MUX-3) and without hanging a concurrent open (MUX-1).
        let (ca, _aa, _cb, ab) = pair(MuxPolicy::default());
        spawn_echo_responder(ab);
        let mut s = ca.open(dom("a.example", 80)).await.unwrap();
        s.write_all(b"hi").await.unwrap();
        // Close the whole connection locally.
        ca.close();
        // A parked read on the live stream resolves (reset), not hangs.
        let mut buf = [0u8; 8];
        let r = tokio::time::timeout(std::time::Duration::from_secs(5), s.read(&mut buf)).await;
        assert!(r.is_ok(), "read must resolve after local close, not hang");
        // A new open after close fails fast (not a hang).
        let opened = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            ca.open(dom("b.example", 80)),
        )
        .await
        .expect("open must resolve after close, not hang");
        assert!(opened.is_err(), "open after close must error");
        assert!(ca.is_closed());
    }
}
