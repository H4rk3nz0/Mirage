//! Live envelope pacing: the async engine that paces a carrier stream to a
//! [`crate::pacer`] schedule, both directions.
//!
//! A pump is needed (not inline `poll_write`) because faithful shaping must emit a
//! packet when the schedule says so even when the app is idle, and `poll_write` can't
//! emit a pure-cover packet. [`PacedChannel`] queues app bytes and a spawned pump
//! drains them on schedule, padding every record to the token size and emitting
//! pure-cover records through idle gaps.
//!
//! Frame (sealed opaquely inside each carrier record):
//! `[real_len u16][payload][pad_len u16][pad zeros]`; a pure-cover record has
//! `real_len == 0`. The receiver is a byte-stream reader - the length prefixes, not
//! record boundaries, delimit data from padding.
//!
//! Opt-in (`MIRAGE_REALITY_PACE` / config); off by default the carrier byte path is
//! unchanged. A constant-envelope class carries continuous cover bandwidth while open.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::pacer::{CoverProcess, Dir, ScheduleStream};

/// Carrier record overhead a frame is sealed into: 5-byte TLS record header +
/// 16-byte AEAD tag. A frame of length `L` is `L + 21` on the wire.
const RECORD_OVERHEAD: usize = 5 + 16;
/// Pacer frame header: `real_len` (u16) + `pad_len` (u16).
const FRAME_HEADER: usize = 4;
/// Smallest representable token wire size: an empty frame (`RECORD_OVERHEAD +
/// FRAME_HEADER`). Tokens below this are floored to it.
const MIN_TOKEN: usize = RECORD_OVERHEAD + FRAME_HEADER;
/// App->pump queue bound (backpressure). Keeps the residual small at close and
/// throttles a demand that outruns the cover envelope.
const WRITE_BOUND: usize = 256 * 1024;
/// Per-read chunk pulled from the carrier into the frame reader's scratch.
const READ_CHUNK: usize = 8192;

/// Object-safe alias for a splittable, sendable carrier stream.
trait InnerIo: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> InnerIo for T {}

/// App->pump write queue with backpressure + shutdown signalling.
struct WriteShared {
    buf: VecDeque<u8>,
    /// App called `poll_shutdown`: flush the queue, then close the carrier.
    closed: bool,
    /// Pump hit a carrier error and exited: fail app writes fast.
    broken: bool,
    /// Wake the app's blocked `poll_write` when the queue drops below the bound.
    app_waker: Option<Waker>,
}

impl WriteShared {
    fn new() -> Self {
        Self {
            buf: VecDeque::new(),
            closed: false,
            broken: false,
            app_waker: None,
        }
    }
}

/// Build one pacer frame of length `frame_len`, carrying `real` (already capped to
/// fit) and zero padding for the remainder.
fn build_frame(real: &[u8], frame_len: usize) -> Vec<u8> {
    debug_assert!(frame_len >= FRAME_HEADER + real.len());
    let pad = frame_len - FRAME_HEADER - real.len();
    let mut f = Vec::with_capacity(frame_len);
    f.extend_from_slice(&(real.len() as u16).to_be_bytes());
    f.extend_from_slice(real);
    f.extend_from_slice(&(pad as u16).to_be_bytes());
    f.resize(frame_len, 0);
    f
}

/// The write pump: owns the carrier write half, emits one record per schedule
/// token at its scheduled time, filling from the queue or padding to pure cover.
///
/// Driven by a single CONTINUOUS [`ScheduleStream`] - never re-drawn per window -
/// so the emitted flow is one coherent cover process with no periodic restart (an
/// earlier window-roll design was a spectral fingerprint at AUC ~1.0). The pacing
/// clock is pinned once so the FIRST token fires immediately (the cover's random
/// start-phase would otherwise idle the link past the session-handshake deadline).
async fn write_pump(
    mut wh: WriteHalf<Box<dyn InnerIo>>,
    shared: Arc<Mutex<WriteShared>>,
    notify: Arc<Notify>,
    mut stream: ScheduleStream,
    dir: Dir,
) {
    // Pin the clock so the first token (`first.t`) maps to now: base = now - first.t.
    let first = stream.next_for(dir);
    let now0 = Instant::now();
    let base = now0
        .checked_sub(Duration::from_secs_f64(first.t.max(0.0)))
        .unwrap_or(now0);
    let mut pending = Some(first);
    loop {
        // Clean exit: app closed and the queue is fully drained. Compute the
        // predicate in a scope that releases the guard before any await.
        let drained_and_closed = {
            let s = shared.lock().unwrap();
            s.closed && s.buf.is_empty()
        };
        if drained_and_closed {
            let _ = wh.shutdown().await;
            return;
        }

        let tok = pending.take().unwrap_or_else(|| stream.next_for(dir));
        let deadline = base + Duration::from_secs_f64(tok.t.max(0.0));
        if deadline > Instant::now() {
            // A close nudge interrupts the sleep so shutdown flushes promptly.
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {}
                _ = notify.notified() => {}
            }
        }

        let frame_len = tok.bytes.max(MIN_TOKEN) - RECORD_OVERHEAD;
        let cap = (frame_len - FRAME_HEADER).min(u16::MAX as usize);
        let real_bytes: Vec<u8> = {
            let mut s = shared.lock().unwrap();
            let take = cap.min(s.buf.len());
            let rb: Vec<u8> = s.buf.drain(..take).collect();
            if s.buf.len() < WRITE_BOUND {
                if let Some(w) = s.app_waker.take() {
                    w.wake();
                }
            }
            rb
        };

        let frame = build_frame(&real_bytes, frame_len);
        if wh.write_all(&frame).await.is_err() {
            let mut s = shared.lock().unwrap();
            s.broken = true;
            if let Some(w) = s.app_waker.take() {
                w.wake();
            }
            return;
        }
    }
}

/// Read-side frame parser state (a byte-stream state machine over the carrier).
#[derive(Clone, Copy)]
enum ReadState {
    /// Reading the 2-byte `real_len`.
    RealLen,
    /// Delivering N real payload bytes to the caller.
    Payload(usize),
    /// Reading the 2-byte `pad_len`.
    PadLen,
    /// Discarding N padding bytes.
    Pad(usize),
}

/// A carrier stream wrapped in bidirectional envelope pacing. Implements
/// `AsyncRead`/`AsyncWrite` so it drops in wherever the raw carrier stream went.
///
/// CONTRACT: written bytes sit in the pump's queue until the schedule emits them,
/// so `flush()` does NOT force them onto the wire (that would defeat pacing). Call
/// [`AsyncWriteExt::shutdown`] before dropping to drain the queue; dropping a
/// channel with un-emitted bytes discards them. Production paths close via
/// `copy_bidirectional`, which shuts down, so they are safe.
pub struct PacedChannel {
    read: ReadHalf<Box<dyn InnerIo>>,
    shared: Arc<Mutex<WriteShared>>,
    notify: Arc<Notify>,
    pump: Option<JoinHandle<()>>,
    // Read framing state.
    rstate: ReadState,
    hdr: [u8; 2],
    hdr_got: usize,
    scratch: Vec<u8>,
    scratch_pos: usize,
    read_eof: bool,
}

impl PacedChannel {
    /// Wrap `inner` (the carrier stream, with record passthrough enabled so one
    /// frame maps to one record) and spawn the write pump driven by `stream` (a
    /// generative or replay [`ScheduleStream`]). `dir` is this side's write direction
    /// (client -> `Up`, bridge -> `Down`).
    pub fn spawn<S>(inner: S, stream: ScheduleStream, dir: Dir) -> Self
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let boxed: Box<dyn InnerIo> = Box::new(inner);
        let (rh, wh) = tokio::io::split(boxed);
        let shared = Arc::new(Mutex::new(WriteShared::new()));
        let notify = Arc::new(Notify::new());
        let pump = tokio::spawn(write_pump(wh, shared.clone(), notify.clone(), stream, dir));
        Self {
            read: rh,
            shared,
            notify,
            pump: Some(pump),
            rstate: ReadState::RealLen,
            hdr: [0u8; 2],
            hdr_got: 0,
            scratch: Vec::new(),
            scratch_pos: 0,
            read_eof: false,
        }
    }
}

impl Drop for PacedChannel {
    fn drop(&mut self) {
        if let Some(h) = self.pump.take() {
            h.abort();
        }
    }
}

impl AsyncRead for PacedChannel {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut delivered = false;
        loop {
            // Drive the frame parser over whatever scratch we already hold.
            while this.scratch_pos < this.scratch.len() {
                match this.rstate {
                    ReadState::RealLen | ReadState::PadLen => {
                        let is_real = matches!(this.rstate, ReadState::RealLen);
                        let avail = this.scratch.len() - this.scratch_pos;
                        let n = (2 - this.hdr_got).min(avail);
                        this.hdr[this.hdr_got..this.hdr_got + n]
                            .copy_from_slice(&this.scratch[this.scratch_pos..this.scratch_pos + n]);
                        this.hdr_got += n;
                        this.scratch_pos += n;
                        if this.hdr_got == 2 {
                            let v = u16::from_be_bytes(this.hdr) as usize;
                            this.hdr_got = 0;
                            this.rstate = if is_real {
                                ReadState::Payload(v)
                            } else {
                                ReadState::Pad(v)
                            };
                        }
                    }
                    ReadState::Payload(rem) => {
                        if rem == 0 {
                            this.rstate = ReadState::PadLen;
                            continue;
                        }
                        if buf.remaining() == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        let avail = this.scratch.len() - this.scratch_pos;
                        let n = rem.min(avail).min(buf.remaining());
                        buf.put_slice(&this.scratch[this.scratch_pos..this.scratch_pos + n]);
                        this.scratch_pos += n;
                        delivered = true;
                        this.rstate = if rem - n == 0 {
                            ReadState::PadLen
                        } else {
                            ReadState::Payload(rem - n)
                        };
                    }
                    ReadState::Pad(rem) => {
                        if rem == 0 {
                            this.rstate = ReadState::RealLen;
                            continue;
                        }
                        let avail = this.scratch.len() - this.scratch_pos;
                        let n = rem.min(avail);
                        this.scratch_pos += n;
                        this.rstate = if rem - n == 0 {
                            ReadState::RealLen
                        } else {
                            ReadState::Pad(rem - n)
                        };
                    }
                }
            }
            // Scratch fully consumed.
            this.scratch.clear();
            this.scratch_pos = 0;
            if delivered {
                return Poll::Ready(Ok(()));
            }
            if this.read_eof {
                return Poll::Ready(Ok(()));
            }
            // Pull more from the carrier.
            let mut tmp = [0u8; READ_CHUNK];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.read).poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let filled = rb.filled();
                    if filled.is_empty() {
                        this.read_eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    this.scratch.extend_from_slice(filled);
                }
            }
        }
    }
}

impl AsyncWrite for PacedChannel {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        let mut s = this.shared.lock().unwrap();
        if s.broken {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "paced: carrier pump exited",
            )));
        }
        if s.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "paced: write after shutdown",
            )));
        }
        if s.buf.len() >= WRITE_BOUND {
            s.app_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let space = WRITE_BOUND - s.buf.len();
        let n = buf.len().min(space);
        s.buf.extend(&buf[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The pump emits on the schedule; forcing it now would defeat pacing.
        // Bytes are durably queued, so "flushed" is satisfied. Surface a pump
        // failure so callers do not wait on a dead channel.
        let s = self.shared.lock().unwrap();
        if s.broken {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "paced: carrier pump exited",
            )));
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        {
            let mut s = this.shared.lock().unwrap();
            s.closed = true;
        }
        this.notify.notify_one();
        // Await the pump: it flushes the residual on-schedule, then closes the
        // carrier write half.
        match this.pump.as_mut() {
            Some(h) => match Pin::new(h).poll(cx) {
                Poll::Ready(_) => {
                    this.pump = None;
                    Poll::Ready(Ok(()))
                }
                Poll::Pending => Poll::Pending,
            },
            None => Poll::Ready(Ok(())),
        }
    }
}

/// Either a plain carrier stream or a paced one - the concrete return of
/// [`maybe_pace`], so callers keep a single monomorphic type without boxing twice.
pub enum MaybePaced<S> {
    /// Pacing disabled: the carrier stream verbatim.
    Plain(S),
    /// Pacing enabled: the envelope-paced wrapper.
    Paced(PacedChannel),
}

impl<S: AsyncRead + Unpin> AsyncRead for MaybePaced<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybePaced::Plain(s) => Pin::new(s).poll_read(cx, buf),
            MaybePaced::Paced(p) => Pin::new(p).poll_read(cx, buf),
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for MaybePaced<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MaybePaced::Plain(s) => Pin::new(s).poll_write(cx, buf),
            MaybePaced::Paced(p) => Pin::new(p).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybePaced::Plain(s) => Pin::new(s).poll_flush(cx),
            MaybePaced::Paced(p) => Pin::new(p).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybePaced::Plain(s) => Pin::new(s).poll_shutdown(cx),
            MaybePaced::Paced(p) => Pin::new(p).poll_shutdown(cx),
        }
    }
}

/// Name of the env var that opts a Reality session into envelope pacing and picks
/// the cover class. Recognised values: `video`/`dash`, `browse` (generative), or
/// `replay` (replay a real captured profile - the grounded ladder). Both endpoints
/// must set the same value.
pub const PACE_ENV: &str = "MIRAGE_REALITY_PACE";

/// When `MIRAGE_REALITY_PACE=replay`, the path to a replay trace or a directory
/// library (see [`crate::pacer::MeasuredProfile::from_csv`], `tools/cover-sources`).
/// For a coherent up/down envelope both endpoints load the SAME library; independent
/// libraries still work but lose the (sparse) up/down correlation.
pub const PACE_PROFILE_ENV: &str = "MIRAGE_REALITY_PACE_PROFILE";

/// Config-set pacing, taking precedence over the env vars. A daemon calls
/// [`set_pace_override`] at startup (config / paranoid mode) so pacing is config-driven
/// without threading it through every carrier call site. It is UPDATABLE at runtime:
/// the client's adaptive cover-class loop re-sets it per network as the bandit shifts
/// classes (a new connection reads the current value), so the store is an `RwLock`.
static PACE_OVERRIDE: std::sync::RwLock<Option<(String, Option<String>)>> =
    std::sync::RwLock::new(None);

/// Set (or update) the pacing mode (`video`/`browse`/`replay`) and optional replay
/// profile path. Overrides [`PACE_ENV`] / [`PACE_PROFILE_ENV`]. Safe to call repeatedly
/// (last write wins); the value is read at each carrier handshake.
pub fn set_pace_override(mode: impl Into<String>, profile: Option<String>) {
    if let Ok(mut w) = PACE_OVERRIDE.write() {
        *w = Some((mode.into(), profile));
    }
}

/// Resolve (mode, profile) from the config override if set, else the env vars.
fn pace_settings() -> (Option<String>, Option<String>) {
    if let Ok(g) = PACE_OVERRIDE.read() {
        if let Some((m, p)) = g.as_ref() {
            return (Some(m.clone()), p.clone());
        }
    }
    (
        std::env::var(PACE_ENV).ok(),
        std::env::var(PACE_PROFILE_ENV).ok(),
    )
}

/// Smallest replay trace worth using: below this a trace has so little capacity that
/// any real session loops it (periodicity - a self-signature). ~a few thousand
/// packets of CSV. Selection prefers traces at or above this; falls back to all if
/// none qualify.
const MIN_TRACE_BYTES: u64 = 64 * 1024;

/// Traces chained per session. A single looped trace repeats every ~span seconds (a
/// periodicity tell); chaining several draws a long, non-repeating envelope. Both ends
/// derive the same order from the shared seed, so up/down stays coherent.
const CHAIN_LEN: usize = 8;

/// Deterministic index order for `n` items from `seed` (splitmix64 Fisher-Yates).
/// Identical on both endpoints, so both build the same per-session chain.
fn seeded_order(n: usize, seed: u64) -> Vec<usize> {
    let mut s = seed;
    let mut next = || {
        s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = s;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };
    let mut v: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let j = (next() % (i as u64 + 1)) as usize;
        v.swap(i, j);
    }
    v
}

/// Resolve the replay profile path. A plain file is read directly. A DIRECTORY is a
/// trace library: per session, a seeded shuffle of up to [`CHAIN_LEN`] traces is
/// concatenated into one long envelope, flow-tagged so [`crate::pacer::MeasuredProfile`]
/// chains them in order. Both endpoints derive the SAME chain from the shared `seed`
/// (coherent up/down) yet it varies per session - a diverse library never becomes a
/// fixed signature, and no single clip loops. Volume-aware: prefer traces with real
/// capacity so short clips are not the whole chain.
fn read_profile(path: &str, seed: u64) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_dir() {
        return std::fs::read_to_string(path).ok();
    }
    let mut traces: Vec<(std::path::PathBuf, u64)> = std::fs::read_dir(path)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "csv"))
        .map(|p| {
            let sz = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            (p, sz)
        })
        .collect();
    if traces.is_empty() {
        return None;
    }
    // Deterministic order so both endpoints pick alike.
    traces.sort();
    // Prefer traces big enough to carry a session without looping; both ends compute the
    // same pool (same files, same sizes), so the seed still selects coherently.
    let big: Vec<&std::path::PathBuf> = traces
        .iter()
        .filter(|(_, sz)| *sz >= MIN_TRACE_BYTES)
        .map(|(p, _)| p)
        .collect();
    let pool: Vec<&std::path::PathBuf> = if big.is_empty() {
        traces.iter().map(|(p, _)| p).collect()
    } else {
        big
    };
    // Chain a seeded shuffle of several traces, flow-tagging each row (flow id = chain
    // position) so from_csv concatenates them in order rather than interleaving by time.
    let mut out = String::new();
    for (flow, &i) in seeded_order(pool.len(), seed)
        .iter()
        .take(CHAIN_LEN)
        .enumerate()
    {
        let Ok(content) = std::fs::read_to_string(pool[i]) else {
            continue;
        };
        for line in content.lines() {
            let f: Vec<&str> = line.trim().split(',').collect();
            if f.len() >= 3 {
                let tail = &f[f.len() - 3..]; // t,size,dir (drop any pre-existing flow col)
                out.push_str(&format!("{flow},{},{},{}\n", tail[0], tail[1], tail[2]));
            }
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Read [`PACE_ENV`] and, if it selects a mode, wrap `stream` in an envelope pacer;
/// otherwise return it unchanged. Enables carrier record passthrough on the wrapped
/// stream (one frame -> one record) so the observable is the token wire sizes. `dir`
/// is this side's write direction.
pub fn maybe_pace<S>(
    mut stream: crate::carrier::RealityStream<S>,
    dir: Dir,
) -> MaybePaced<crate::carrier::RealityStream<S>>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let seed = stream.pace_seed();
    match pace_schedule(seed) {
        Some(sched) => {
            stream.set_passthrough(true);
            MaybePaced::Paced(PacedChannel::spawn(stream, sched, dir))
        }
        None => MaybePaced::Plain(stream),
    }
}

/// Build the pacing schedule for this session from the process-wide pace settings,
/// or `None` if pacing is not configured (or a replay profile is missing/empty - the
/// tunnel must never break over a config slip). `seed` MUST be identical on both
/// endpoints so the up/down envelope stays coherent.
pub fn pace_schedule(seed: u64) -> Option<ScheduleStream> {
    let (mode, profile) = pace_settings();
    match mode.as_deref() {
        Some(class @ ("video" | "dash" | "browse")) => Some(ScheduleStream::new(
            CoverProcess::from_class_seed(class, seed),
            seed,
        )),
        // Path may be a single trace file OR a directory library - see [`read_profile`].
        Some("replay") => profile
            .and_then(|p| read_profile(&p, seed))
            .and_then(|s| crate::pacer::MeasuredProfile::from_csv(&s))
            .map(|prof| ScheduleStream::replay(std::sync::Arc::new(prof), seed)),
        _ => None,
    }
}

/// Wrap ANY carrier stream in the envelope pacer if pacing is configured. Unlike
/// [`maybe_pace`], this does not toggle Reality record-passthrough: it is for carriers
/// whose write path already emits one framing unit per write (e.g. SS-2022 seals each
/// `poll_write` as one AEAD chunk), so one pump frame maps to one observable unit for
/// free. `seed` MUST match on both endpoints.
pub fn maybe_pace_stream<S>(stream: S, dir: Dir, seed: u64) -> MaybePaced<S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    match pace_schedule(seed) {
        Some(sched) => MaybePaced::Paced(PacedChannel::spawn(stream, sched, dir)),
        None => MaybePaced::Plain(stream),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn read_profile_file_and_library_dir() {
        use std::sync::atomic::{AtomicU32, Ordering};
        static CTR: AtomicU32 = AtomicU32::new(0);
        let base = std::env::temp_dir().join(format!(
            "proteus_lib_{}_{}",
            std::process::id(),
            CTR.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&base).unwrap();
        // three distinct traces
        for (i, tag) in ["aaa", "bbb", "ccc"].iter().enumerate() {
            std::fs::write(
                base.join(format!("{i}.csv")),
                format!("flow,t,size,dir\n0,0.0,{},1\n", 100 + i),
            )
            .unwrap();
            let _ = tag;
        }
        let dir = base.to_str().unwrap();
        // a plain file is read verbatim (single specified trace, no chaining)
        let one = base.join("0.csv");
        assert_eq!(
            read_profile(one.to_str().unwrap(), 42).unwrap(),
            std::fs::read_to_string(&one).unwrap()
        );

        // Four big traces (each > MIN_TRACE_BYTES) with a distinct size marker, plus the
        // tiny ones above. Chaining should draw only the big traces, several per session.
        let big_trace = |marker: usize| {
            let mut s = String::from("t,size,dir\n");
            for i in 0..6000 {
                s.push_str(&format!("{i}.0,{marker},1\n"));
            }
            assert!(s.len() as u64 > MIN_TRACE_BYTES);
            s
        };
        for marker in [1401usize, 1402, 1403, 1404] {
            std::fs::write(base.join(format!("big{marker}.csv")), big_trace(marker)).unwrap();
        }

        let out = read_profile(dir, 3).unwrap();
        let sizes: std::collections::HashSet<&str> =
            out.lines().filter_map(|l| l.split(',').nth(2)).collect();
        let flows: std::collections::HashSet<&str> =
            out.lines().map(|l| l.split(',').next().unwrap()).collect();
        // volume-aware: tiny traces (markers 100..102) never appear
        for tiny in ["100", "101", "102"] {
            assert!(
                !sizes.contains(tiny),
                "tiny clip {tiny} excluded from the chain"
            );
        }
        // chaining: several big traces are concatenated (multiple markers + flow ids)
        assert!(
            ["1401", "1402", "1403", "1404"]
                .iter()
                .filter(|m| sizes.contains(**m))
                .count()
                >= 2,
            "chain concatenates multiple traces"
        );
        assert!(
            flows.contains("0") && flows.contains("1"),
            "multiple chain positions"
        );

        // determinism (both ends agree) + per-session variation (order differs by seed)
        assert_eq!(
            read_profile(dir, 3),
            read_profile(dir, 3),
            "same seed -> same chain"
        );
        let variants: std::collections::HashSet<String> =
            (0u64..20).filter_map(|s| read_profile(dir, s)).collect();
        assert!(variants.len() >= 2, "different seeds -> different chains");

        // the chained profile parses and spans longer than a single trace (no quick loop)
        let chained = crate::pacer::MeasuredProfile::from_csv(&out).unwrap();
        let single = crate::pacer::MeasuredProfile::from_csv(&big_trace(1401)).unwrap();
        assert!(
            chained.span > single.span,
            "chaining extends the replay span"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn build_frame_targets_wire_size_and_carries_real() {
        let token = 1400usize;
        let frame_len = token - RECORD_OVERHEAD;
        let real = vec![7u8; 100];
        let f = build_frame(&real, frame_len);
        assert_eq!(f.len(), frame_len, "frame is exactly the target length");
        assert_eq!(u16::from_be_bytes([f[0], f[1]]) as usize, 100);
        assert_eq!(&f[2..102], &real[..]);
        let pad = u16::from_be_bytes([f[102], f[103]]) as usize;
        assert_eq!(FRAME_HEADER + real.len() + pad, frame_len);
        assert!(f[104..].iter().all(|&b| b == 0), "pad region is zeros");
    }

    #[test]
    fn build_frame_pure_cover_is_all_header() {
        // A minimum-size token yields an empty (pure-cover) frame.
        let frame_len = MIN_TOKEN - RECORD_OVERHEAD;
        let f = build_frame(&[], frame_len);
        assert_eq!(f.len(), FRAME_HEADER);
        assert_eq!(u16::from_be_bytes([f[0], f[1]]), 0, "real_len 0");
        assert_eq!(u16::from_be_bytes([f[2], f[3]]), 0, "pad_len 0");
    }

    #[test]
    fn build_frame_caps_real_to_budget() {
        // A frame whose real portion is capped: caller passes only what fits, so
        // the remaining budget is padding.
        let frame_len = 100usize;
        let real = vec![1u8; frame_len - FRAME_HEADER]; // exactly fills, zero pad
        let f = build_frame(&real, frame_len);
        assert_eq!(f.len(), frame_len);
        assert_eq!(u16::from_be_bytes([f[frame_len - 2], f[frame_len - 1]]), 0);
    }

    // Wrap BOTH ends of a duplex with a pacer (client=Up, bridge=Down, shared
    // seed) - a faithful loopback of the whole engine (pump + framing + padding +
    // backpressure + shutdown) with no carrier needed. Paused time makes the
    // cover schedule fire instantly.

    #[tokio::test(start_paused = true)]
    async fn paced_download_bulk_roundtrips_exactly() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let seed = 0xABCD_1234_5678_9ABCu64;
        let proc = CoverProcess::from_class_seed("video", seed);
        let mut client = PacedChannel::spawn(a, ScheduleStream::new(proc.clone(), seed), Dir::Up);
        let mut bridge = PacedChannel::spawn(b, ScheduleStream::new(proc, seed), Dir::Down);

        // Bridge -> client bulk (the direction with envelope capacity).
        let payload: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        let expect = payload.clone();
        let writer = tokio::spawn(async move {
            bridge.write_all(&payload).await.unwrap();
            bridge.shutdown().await.unwrap();
        });

        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        writer.await.unwrap();
        assert_eq!(
            got, expect,
            "bulk payload survives pacing + padding exactly"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn paced_bidirectional_small_messages() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let seed = 0x0102_0304_0506_0708u64;
        let proc = CoverProcess::from_class_seed("browse", seed);
        let mut client = PacedChannel::spawn(a, ScheduleStream::new(proc.clone(), seed), Dir::Up);
        let mut bridge = PacedChannel::spawn(b, ScheduleStream::new(proc, seed), Dir::Down);

        let srv = tokio::spawn(async move {
            let mut got = [0u8; 4];
            bridge.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"ping");
            bridge.write_all(b"pong").await.unwrap();
            bridge.flush().await.unwrap();
            // keep the pump alive until the client has read the reply
            let mut tail = [0u8; 1];
            let _ = bridge.read(&mut tail).await;
        });

        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut got = [0u8; 4];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"pong");
        drop(client);
        let _ = srv.await;
    }

    #[tokio::test(start_paused = true)]
    async fn paced_shutdown_flushes_residual() {
        // Everything written before shutdown must arrive - the pump drains the
        // queue on schedule before closing.
        let (a, b) = tokio::io::duplex(64 * 1024);
        let seed = 0xDEAD_BEEF_CAFE_0001u64;
        let proc = CoverProcess::from_class_seed("video", seed);
        let mut client = PacedChannel::spawn(a, ScheduleStream::new(proc.clone(), seed), Dir::Down);
        let mut bridge = PacedChannel::spawn(b, ScheduleStream::new(proc, seed), Dir::Up);

        let msg = vec![0x5au8; 9_000];
        let expect = msg.clone();
        let writer = tokio::spawn(async move {
            client.write_all(&msg).await.unwrap();
            client.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        bridge.read_to_end(&mut got).await.unwrap();
        writer.await.unwrap();
        assert_eq!(got, expect);
    }
}
