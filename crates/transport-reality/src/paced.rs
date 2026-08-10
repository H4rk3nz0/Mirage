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
//! Opt-in (`proteus` in the config, or [`PACE_ENV`]); off by default the carrier byte path is
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

/// Pacer frame header: `real_len` (u16) + `pad_len` (u16).
const FRAME_HEADER: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Framing {
    /// The pacer frame is handed down as-is; nothing is added per record.
    None,
    /// SS-2022 AEAD chunk: sealed length (2 + 16 tag), then payload (+ 16 tag).
    Ss2022,
    /// RFC 6455 binary frame. `masked` is the client -> server direction, which
    /// carries a 4-byte mask key the server direction does not.
    WebSocket { masked: bool },
}

/// One TLS 1.3 record: 5-byte header + 16-byte AEAD tag.
///
/// 21, not the 22 a reading of RFC 8446 would give. Real TLS 1.3 puts the inner
/// content type INSIDE the encryption, so a record costs one more byte than this,
/// and the Reality handshake-reproduction path accounts for exactly that, since
/// the records it reproduces came off a real server. The application-data path
/// does not: `record::wrap_app_data` writes the 5-byte header around the AEAD
/// ciphertext with no inner type byte, so `plaintext + 21` is what goes out.
///
/// Unobservable either way. The byte sits under the AEAD, and a censor sees only
/// wire sizes - every wire size Mirage produces is one a real TLS peer could also
/// produce, for a plaintext one byte longer. It matters HERE only because the
/// pacer replays captured wire sizes and has to land on them exactly.
const TLS_RECORD_OVERHEAD: usize = 5 + 16;

/// Per-record framing overhead the carrier UNDER the pacer adds to every write.
///
/// The pacer's whole job is to make the wire sizes match a captured envelope, so
/// it must size each frame such that `frame + carrier overhead` lands exactly on
/// the token's recorded size. That arithmetic is only correct if the pacer knows
/// what the carrier below it adds, and the carriers do not agree: a TLS record
/// costs 21 bytes, an SS-2022 AEAD chunk costs 34, a WebSocket frame costs 2 to
/// 12 depending on length and direction, and the QUIC carriers add nothing here
/// because their sizes are shaped below the transport instead.
///
/// This used to be a single `RECORD_OVERHEAD = 5 + 16` constant applied to every
/// carrier, which is right only for Reality. On SS-2022 it put every record 13
/// bytes OVER target; a near-MTU token then became 1513 bytes, crossed the path
/// MSS, and TCP split it into a full segment plus a small tail. That bimodal
/// bimodal size distribution is the exact shape a stream of tiny tails produces,
/// and it showed up as one: on the SS-2022 carrier the censor-vantage harness
/// picked `size_entropy_bits` as its winning separator at 0.867 up / 0.877 down.
/// Correcting the overhead moved the winning separator OFF size entirely, onto
/// timing features, at 0.784 / 0.809.
///
/// Read those four numbers as a before/after on one carrier and one harness, and
/// not as absolutes: they were taken before the harness randomised its window
/// assignment, so they sit on an unmeasured floor. They are also not comparable
/// across carriers, because the Reality path target-conditions its profile on
/// the cover host and can therefore be replaying a different trace entirely.
/// What is not in doubt is the arithmetic - see the tests, which need no cluster.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Carrier {
    framing: Framing,
    /// The record is additionally sealed into one TLS 1.3 record on the way out.
    /// Composes with `framing`: the WebSocket carrier can ride a client-originated
    /// TLS session to a terminating front, and then pays both costs.
    tls: bool,
}

impl Carrier {
    /// The pacer frame is sealed into exactly one TLS 1.3 record. Reality, whose
    /// record passthrough gives one record per frame.
    #[must_use]
    pub const fn tls() -> Self {
        Self {
            framing: Framing::None,
            tls: true,
        }
    }

    /// One SS-2022 AEAD chunk per record.
    #[must_use]
    pub const fn ss2022() -> Self {
        Self {
            framing: Framing::Ss2022,
            tls: false,
        }
    }

    /// One RFC 6455 binary frame per record, written by the client (masked).
    #[must_use]
    pub const fn websocket_client() -> Self {
        Self {
            framing: Framing::WebSocket { masked: true },
            tls: false,
        }
    }

    /// One RFC 6455 binary frame per record, written by the server (unmasked).
    #[must_use]
    pub const fn websocket_server() -> Self {
        Self {
            framing: Framing::WebSocket { masked: false },
            tls: false,
        }
    }

    /// The pacer frame IS the wire unit: nothing is added per record. QUIC
    /// carriers (whose sizes are shaped below the transport instead) and any
    /// carrier whose per-record cost is not a fixed function of the record - the
    /// HTTP-mediated ones, where headers and the front's re-framing sit in
    /// between and no local choice can land the frame on a captured size.
    #[must_use]
    pub const fn raw() -> Self {
        Self {
            framing: Framing::None,
            tls: false,
        }
    }

    /// Same carrier, additionally sealed in a TLS record per write - the
    /// client-originated carrier-TLS path (`carrier_tls`).
    #[must_use]
    pub const fn over_tls(self) -> Self {
        Self { tls: true, ..self }
    }

    /// Bytes this carrier puts on the wire beyond a `payload`-byte record.
    ///
    /// Non-decreasing in `payload`, which is what makes [`Self::payload_for_wire`]
    /// terminate quickly.
    #[must_use]
    pub fn overhead(self, payload: usize) -> usize {
        let framing = match self.framing {
            Framing::None => 0,
            Framing::Ss2022 => 2 + 16 + 16,
            Framing::WebSocket { masked } => {
                let mask = usize::from(masked) * 4;
                // opcode + length byte, then the extended length field.
                let ext = if payload < 126 {
                    0
                } else if payload <= usize::from(u16::MAX) {
                    2
                } else {
                    8
                };
                2 + ext + mask
            }
        };
        framing + if self.tls { TLS_RECORD_OVERHEAD } else { 0 }
    }

    /// Largest record payload whose wire footprint fits in `wire` bytes: the
    /// inverse of [`Self::overhead`]. Returns 0 when not even an empty record
    /// fits, so a caller must floor the result to its own minimum frame.
    ///
    /// The step in the WebSocket length field means the naive
    /// `wire - overhead(0)` can overshoot by up to the field's width, so the
    /// guess is walked down; the overhead spans at most 8 bytes across the whole
    /// size range, which bounds the loop.
    #[must_use]
    pub fn payload_for_wire(self, wire: usize) -> usize {
        let mut payload = wire.saturating_sub(self.overhead(0));
        while payload > 0 && payload + self.overhead(payload) > wire {
            payload -= 1;
        }
        payload
    }

    /// Smallest token wire size this carrier can represent: an empty pacer frame
    /// plus its own framing. Tokens below this are floored to it.
    #[must_use]
    fn min_token(self) -> usize {
        FRAME_HEADER + self.overhead(FRAME_HEADER)
    }
}
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

/// How far the pacer may fall behind the schedule before it re-pins the origin
/// instead of catching up at line rate. Generous, so ordinary sub-second jitter
/// and brief backpressure never trip it; only a genuine multi-second carrier
/// stall does, whose line-rate recovery burst would otherwise be a fingerprint.
const MAX_PACING_DRIFT: Duration = Duration::from_millis(1500);

/// Bounded catch-up decision (pure, so it is deterministically testable). Given
/// the current schedule `base`, a token's relative time `tok_t`, and `now`,
/// return the origin to use: unchanged when we are within `max_drift` of the
/// deadline, or re-pinned so the token fires ~`now` when a stall left us further
/// behind (avoiding a stall-then-flood burst).
fn rebase_on_stall(base: Instant, tok_t: f64, now: Instant, max_drift: Duration) -> Instant {
    let offset = Duration::from_secs_f64(tok_t.max(0.0));
    let deadline = base + offset;
    if now > deadline + max_drift {
        now.checked_sub(offset).unwrap_or(now)
    } else {
        base
    }
}

/// Is this replay token so far past its deadline that it must be DROPPED rather
/// than emitted? Pure, so the load-independence property is directly testable.
///
/// Emitting late is not an option in replay mode: re-pinning the origin shifts
/// every later deadline (a busy carrier then emits more tokens per second than an
/// idle one), and firing overdue tokens back-to-back is a catch-up burst. Both
/// make the wire a function of app load. Dropping keeps the schedule an exact
/// function of (origin, trace).
fn drop_if_overdue(base: Instant, tok_t: f64, now: Instant, max_drift: Duration) -> bool {
    now > base + Duration::from_secs_f64(tok_t.max(0.0)) + max_drift
}

/// Pin the pacing clock origin (pure, so the joint up/down behaviour is testable).
/// REPLAY pins to the shared capture origin (`base = now`; the seed-derived start
/// token is t=0 on both ends), preserving the real flow's up/down coupling.
/// GENERATIVE pins to this direction's first token (`base = now - first_t`) so a
/// random start-phase never idles the link. In both cases the first token fires at
/// `base + first_t`.
fn pace_base(now: Instant, first_t: f64, is_replay: bool) -> Instant {
    if is_replay {
        now
    } else {
        now.checked_sub(Duration::from_secs_f64(first_t.max(0.0)))
            .unwrap_or(now)
    }
}

/// How many upcoming tokens the size aligner may choose among.
///
/// 32 measured best in the offline alignment study. Larger windows buy
/// little extra throughput and give the aligner more room to restructure the
/// sequence, which is the thing that costs detectability.
const ALIGN_WINDOW: usize = 32;

/// Fraction of slots the aligner may move off their captured size.
///
/// CALIBRATED, and deliberately not a knob. Detectability is U-SHAPED in this
/// value and the shape is not what anyone would guess: measured against the
/// repo's own distinguisher (1276 flows per class, two independent sets of
/// demand realisations), 0.20 scored 0.602-0.610 and 0.65 scored 0.581-0.594,
/// while 0.35-0.50 sat at the 0.552 floor. Too FEW moves is worse than more,
/// because a handful of maximal swaps leaves isolated outliers that disturb
/// local autocorrelation, whereas many moderate ones resemble the burst
/// clustering real captures already contain.
///
/// So an operator turning this up "to go faster" would make the tunnel MORE
/// detectable while barely gaining, which is why it is a constant.
/// DISABLED (0). Measured on a live cluster, alignment is an ACTIVITY SIGNAL.
///
/// The reasoning that justified it was wrong in a specific and instructive way.
/// A permutation preserves the size multiset, and eleven of the fourteen
/// classifier features are size-marginal, so those features cannot move - GLOBALLY.
/// But a censor does not observe the run globally. It observes WINDOWS, and the
/// harness compares idle windows against active ones.
///
/// Steering large tokens to slots that have data and small ones to slots that do
/// not makes idle windows collect the small records and active windows the big
/// ones. The multiset is preserved over the whole run and systematically skewed
/// inside every window - which is precisely the activity signal the envelope
/// exists to destroy.
///
/// Measured, lean/reality, against a control of 0.536 up / 0.544 down:
///
/// | | up | down |
/// |---|---|---|
/// | unaligned | 0.569 | 0.519 |
/// | aligned (alpha 0.5) | 0.601 | **0.699** |
///
/// with `max_size` and `size_stddev` as the winning separators - both
/// size-marginal, exactly the family the invariance argument claimed was safe.
///
/// The offline study that justified alignment compared pooled aligned
/// sequences against pooled originals and never split them into idle and active
/// windows, so it could not see this and reported the floor. That is the lesson
/// worth keeping: the metric has to be computed the way the ADVERSARY computes
/// it, not the way that is convenient to simulate.
///
/// Left at 0 rather than deleted so the mechanism, the tests and the measurement
/// survive. Any future attempt has to keep the per-window size distribution
/// unchanged, not merely the global multiset - which is a far harder problem,
/// and possibly not one a permutation can solve at all.
const ALIGN_ALPHA_PERMILLE: u64 = 0;

/// Re-assigns captured record sizes to captured emission times, so the big
/// tokens land where the application actually has bytes waiting.
///
/// # Why this is free
///
/// The token capacities arrive on the CAPTURE's timeline and the user's demand
/// arrives on the USER's. They are independent by construction - that
/// independence is the security property - which also means the big tokens land
/// while the user wants nothing and the requests land in the capture's reading
/// gaps. Measured on a live cluster, that costs most of the capacity that was
/// paid for: 10-13 KB/s median with individual transfers ranging 4 to 188 KB/s
/// purely on whether they coincided with a burst.
///
/// This changes NEITHER the emission times NOR the multiset of sizes. Every gap
/// is the captured gap and every size is emitted exactly once, so total bytes,
/// the size distribution and the timing are all preserved exactly. Eleven of the
/// fourteen features in `mirage_adversary::flow_classifier` are size-marginal
/// and therefore provably invariant; only `lag1_autocorr`, `mean_run_length` and
/// `mean_abs_succ_diff` can see this at all.
///
/// Purely local: the frame is self-describing (`real_len` then `pad_len`), so a
/// peer reads whatever arrives and nothing has to be negotiated. Each direction
/// aligns against its own queue.
struct SizeAligner {
    /// Buffered upcoming tokens, in schedule order. Times are emitted from here
    /// unchanged.
    tokens: VecDeque<crate::pacer::EmitToken>,
    /// The sizes of exactly those buffered tokens, sorted. One size leaves per
    /// emission and one enters per refill, so the multiset over the whole run is
    /// preserved.
    pool: Vec<usize>,
    rng: u64,
}

impl SizeAligner {
    fn new(seed: u64) -> Self {
        Self {
            tokens: VecDeque::with_capacity(ALIGN_WINDOW + 1),
            pool: Vec::with_capacity(ALIGN_WINDOW + 1),
            // Any nonzero state; this only decides WHICH slots move, and both
            // ends may differ because the choice never has to be agreed.
            rng: seed | 1,
        }
    }

    fn next_u64(&mut self) -> u64 {
        self.rng = self.rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Take one token, choosing which buffered SIZE rides its captured time.
    ///
    /// `has_data` is whether the application has bytes queued right now.
    fn next(
        &mut self,
        stream: &mut ScheduleStream,
        dir: Dir,
        has_data: bool,
    ) -> crate::pacer::EmitToken {
        while self.tokens.len() < ALIGN_WINDOW {
            let t = stream.next_for(dir);
            self.pool.push(t.bytes);
            self.tokens.push_back(t);
        }
        self.pool.sort_unstable();
        let mut tok = self
            .tokens
            .pop_front()
            .unwrap_or_else(|| stream.next_for(dir));

        // Matched rather than compared: with the constant at 0 (alignment
        // disabled after it measured as an activity signal) any `<` against it is
        // trivially false, and clippy is right to say so.
        let deviate = match ALIGN_ALPHA_PERMILLE {
            0 => false,
            p => self.next_u64() % 1000 < p,
        };
        let idx = if !deviate {
            // Keep the captured assignment: find this token's own size.
            self.pool
                .binary_search(&tok.bytes)
                .unwrap_or_else(|i| i.min(self.pool.len().saturating_sub(1)))
        } else if has_data {
            self.pool.len().saturating_sub(1) // largest available
        } else {
            0 // smallest, so the big ones stay for slots that need them
        };
        if !self.pool.is_empty() {
            tok.bytes = self.pool.remove(idx);
        }
        tok
    }
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
    carrier: Carrier,
) {
    let first = stream.next_for(dir);
    let now0 = Instant::now();
    // REPLAY: pin BOTH directions to the shared capture origin (the seed-derived
    // start token is t=0 on both ends), so the up/down request-response coupling of
    // the real flow is reproduced instead of each direction re-zeroing on its own
    // first token (which shifts the joint timeline by the up/down start gap - a
    // cross-direction timing tell). The first token still fires at now0 + first.t.
    // GENERATIVE: pin to THIS direction's first token so a random cover start-phase
    // never idles the link past the session-handshake deadline.
    let replaying = stream.is_replay();
    let mut base = pace_base(now0, first.t, replaying);
    // How long this direction will sit silent before its FIRST byte can leave.
    // Worth logging because it is invisible otherwise and it gates the session
    // handshake: bytes only leave on a token, so a chain whose first token for
    // this direction sits deep into the capture stalls the handshake for exactly
    // that long, with no error anywhere - the session simply does not progress.
    let first_wait = base
        .saturating_duration_since(now0)
        .saturating_add(Duration::from_secs_f64(first.t.max(0.0)));
    tracing::debug!(
        ?dir,
        replay = replaying,
        first_token_t = first.t,
        first_wait_ms = first_wait.as_millis() as u64,
        "proteus: pump armed"
    );
    let mut dropped: u64 = 0;
    let mut pending = Some(first);
    // Seeded from the pinned origin so a run is reproducible in a test; the peer
    // never needs the same value, because which slots move is a local choice the
    // self-describing frame makes invisible.
    let mut aligner = SizeAligner::new(first.t.to_bits() ^ u64::from(replaying));
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

        let tok = match pending.take() {
            Some(t) => t,
            None => {
                // Does the application have bytes waiting RIGHT NOW? That is the
                // whole input to alignment: a slot with data wants the biggest
                // token available, a slot without wants the smallest so the big
                // ones are still there when data arrives.
                let has_data = {
                    let g = shared.lock().unwrap();
                    !g.buf.is_empty()
                };
                aligner.next(&mut stream, dir, has_data)
            }
        };
        if replaying {
            // REPLAY: the emission schedule must be a function of (origin, trace)
            // ALONE. Re-pinning the origin after a stall shifts every later
            // deadline, so a busy carrier emits MORE tokens per wall-clock second
            // than an idle one - measured at +16% downstream bytes under load,
            // which a censor reads off as "the user is active" (total-bytes
            // separator, AUC 1.0). Firing the overdue tokens back-to-back instead
            // is no better: that is a catch-up burst no real cover produces.
            // So DROP the overdue token. Its queued bytes stay in the buffer for
            // the next on-schedule token, the origin never moves, and the wire
            // rate is capped by the envelope no matter what the app is doing.
            // The envelope is a budget, and this is what paying it looks like.
            if drop_if_overdue(base, tok.t, Instant::now(), MAX_PACING_DRIFT) {
                dropped += 1;
                // Every drop is the envelope going quiet because the carrier
                // stalled. A stall correlates with load, so the drop RATE is the
                // residual activity signal - log it (cheaply, on powers of two)
                // so a capture can be attributed instead of guessed at.
                if dropped.is_power_of_two() {
                    tracing::debug!(
                        ?dir,
                        dropped,
                        "proteus: token dropped (carrier stalled past drift allowance)"
                    );
                }
                continue;
            }
        } else {
            // GENERATIVE: the origin is arbitrary (no captured flow to stay in
            // step with), so re-pinning after a stall is the cheaper fix - it
            // avoids the catch-up flood without a schedule to betray.
            base = rebase_on_stall(base, tok.t, Instant::now(), MAX_PACING_DRIFT);
        }
        let deadline = base + Duration::from_secs_f64(tok.t.max(0.0));
        if deadline > Instant::now() {
            // A close nudge interrupts the sleep so shutdown flushes promptly.
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {}
                _ = notify.notified() => {}
            }
        }

        // Size the frame so that frame + THIS carrier's per-record overhead lands
        // on the token's captured wire size. Using one carrier's overhead for all
        // of them puts every record off target by the difference, and a near-MTU
        // token then splits across the path MSS into a full segment and a tail.
        let frame_len = carrier
            .payload_for_wire(tok.bytes.max(carrier.min_token()))
            .max(FRAME_HEADER);
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
        // Write AND flush, so one token becomes one OBSERVABLE unit rather than
        // one call to `poll_write`. The distinction is the difference between the
        // pacer working and silently doing nothing: a carrier that buffers in
        // `poll_write` and only frames on `poll_flush` (the WebSocket carrier does
        // exactly this) would otherwise accumulate every token and emit them in
        // one lump at shutdown - perfectly paced writes, and an unpaced wire.
        // For carriers where a write already is a unit (raw TLS records, SS-2022
        // AEAD chunks) the flush costs nothing. Making it explicit is what lets
        // the same engine drive framing carriers as well as byte-stream ones.
        let emitted = async {
            wh.write_all(&frame).await?;
            wh.flush().await
        }
        .await;
        if emitted.is_err() {
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
    /// (client -> `Up`, bridge -> `Down`). `carrier` names the framing `inner` adds
    /// per record, which is what the pump sizes its frames against.
    /// Wrap `inner` and drive it from ONE carrier of a heterogeneous set.
    ///
    /// This is the live-path entry point for the multi-carrier work. The caller
    /// holds the [`HeteroCarrierSet`](crate::pacer::HeteroCarrierSet) for the
    /// session, asks it for the carriers serving a stream's class, and spawns one
    /// `PacedChannel` per carrier.
    ///
    /// Every contract the carrier model pins survives this call, because the
    /// schedule is passed as DATA and the channel adds no inputs of its own:
    ///
    /// - no ambient clock enters here - the write pump paces off the schedule's
    ///   own instants, exactly as it does for any other `ScheduleStream`;
    /// - backpressure on `inner` cannot reach the schedule, because the schedule
    ///   is fully determined before the first byte moves;
    /// - the carrier is chosen by the stream's class, which
    ///   [`ClassifiedStream`](crate::pacer::ClassifiedStream) fixes at accept and
    ///   offers no way to change.
    pub fn spawn_for_carrier<S>(
        inner: S,
        schedule: &crate::pacer::CarrierSchedule,
        seed: u64,
        dir: Dir,
        carrier: Carrier,
    ) -> Self
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        Self::spawn(
            inner,
            ScheduleStream::for_carrier(schedule, seed),
            dir,
            carrier,
        )
    }

    /// Wrap `inner` (the carrier stream, with record passthrough enabled so one
    /// frame maps to one record) and spawn the write pump driven by `stream`.
    ///
    /// `dir` is this side's write direction (client -> `Up`, bridge -> `Down`).
    /// `carrier` names the framing `inner` adds per record, which is what the pump
    /// sizes its frames against. For the multi-carrier path use
    /// [`Self::spawn_for_carrier`], which supplies the stream from a capture.
    pub fn spawn<S>(inner: S, stream: ScheduleStream, dir: Dir, carrier: Carrier) -> Self
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let boxed: Box<dyn InnerIo> = Box::new(inner);
        let (rh, wh) = tokio::io::split(boxed);
        let shared = Arc::new(Mutex::new(WriteShared::new()));
        let notify = Arc::new(Notify::new());
        let pump = tokio::spawn(write_pump(
            wh,
            shared.clone(),
            notify.clone(),
            stream,
            dir,
            carrier,
        ));
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

/// Name of the env var that turns **Proteus** on for a session and picks the cover
/// class. Recognised values: `on`/`auto`/`replay` (replay a real captured profile -
/// the grounded ladder, and what you want), or the legacy generative classes
/// `video`/`dash` and `browse`. Both endpoints must set the same value.
///
/// `on` needs nothing else: with no profile configured, the daemon sources its own
/// cover library and keeps it fresh. See [`PACE_PROFILE_ENV`] to point at one you
/// recorded yourself.
pub const PACE_ENV: &str = "MIRAGE_PROTEUS";

/// When Proteus is on, the path to a replay trace or a directory
/// library (see [`crate::pacer::MeasuredProfile::from_csv`], `tools/cover-sources`).
/// For a coherent up/down envelope both endpoints load the SAME library; independent
/// libraries still work but lose the (sparse) up/down correlation.
///
/// TARGET-CONDITIONED replay: if the library is a ROOT that contains a subdir named
/// after the Reality cover host (e.g. `<lib>/www.wikipedia.org/`), a session whose
/// cover SNI is that host wears THAT site's recorded shape instead of a generic
/// class - so the flow matches its claimed destination (measured to reach the
/// size-AUC floor vs the real site, where a generic class stays separable). Record
/// per-site with `mirage-cover-record <lib> --url https://<host>/... --name <host>`,
/// provision it on both ends, and point the profile at `<lib>` (not the subdir).
/// A host with no subdir falls back to the root, so mixing is safe.
pub const PACE_PROFILE_ENV: &str = "MIRAGE_PROTEUS_PROFILE";

/// Optional SEPARATE replay library for the UPSTREAM direction.
///
/// A cover trace is a budget in both directions, and the best downstream cover is
/// often the worst upstream one: a video capture is a client that says almost
/// nothing, measured at 0.26 upstream tokens/s against a browse capture's ~14, and
/// a tunnel's own handshake starves on it. Setting this takes DOWNSTREAM tokens
/// from [`PACE_PROFILE_ENV`] and UPSTREAM tokens from here, so a session can look
/// like someone watching a video while still having the upload capacity to be one.
/// The upstream trace is TILED to cover the downstream span, so a short browse
/// capture pairs with a long video one. Both endpoints must set both paths
/// identically, exactly as for the single-profile case.
pub const PACE_PROFILE_UP_ENV: &str = "MIRAGE_PROTEUS_PROFILE_UP";

/// Config-set pacing, taking precedence over the env vars. A daemon calls
/// [`set_pace_override`] at startup (config / paranoid mode) so pacing is config-driven
/// without threading it through every carrier call site. It is UPDATABLE at runtime:
/// the client's adaptive cover-class loop re-sets it per network as the bandit shifts
/// classes (a new connection reads the current value), so the store is an `RwLock`.
/// `(mode, downstream profile, optional upstream profile)`.
type PaceOverride = (String, Option<String>, Option<String>);

static PACE_OVERRIDE: std::sync::RwLock<Option<PaceOverride>> = std::sync::RwLock::new(None);

/// Set (or update) the pacing mode (`video`/`browse`/`replay`) and optional replay
/// profile path. Overrides [`PACE_ENV`] / [`PACE_PROFILE_ENV`]. Safe to call repeatedly
/// (last write wins); the value is read at each carrier handshake.
pub fn set_pace_override(
    mode: impl Into<String>,
    profile: Option<String>,
    profile_up: Option<String>,
) {
    if let Ok(mut w) = PACE_OVERRIDE.write() {
        *w = Some((mode.into(), profile, profile_up));
    }
}

/// Resolve (mode, profile) from the config override if set, else the env vars.
/// Is envelope pacing configured at all?
///
/// A paced carrier emits continuously for its whole life, so its EXISTENCE and
/// LIFETIME are part of the cover, not incidental. Callers that manage carrier
/// pools use this to stop churning connections: every extra dial is a distinct
/// short-lived flow on the wire, and dial churn tracks user activity, which
/// hands a censor the very signal the envelope is meant to remove.
#[must_use]
pub fn pacing_active() -> bool {
    pace_settings().0.is_some()
}

/// Gated messages to budget for in a session handshake.
///
/// Mirage's handshake is three messages, but each one can be split across
/// several tokens, and the carrier below adds its own exchange. Eight is the
/// number of times a handshake can plausibly find itself waiting on the next
/// token, with slack - it is a budget, and being generous costs a slow connect
/// while being stingy costs a failed one.
const HANDSHAKE_GATED_MESSAGES: u32 = 8;

/// The longest a session handshake can take inside the CONFIGURED cover
/// envelope, or `None` when nothing is configured.
///
/// Handshake bytes leave only on a schedule token, so the envelope's worst gap
/// is the worst per-message latency, and the budget has to be derived from the
/// profile rather than guessed. A fixed 60s floor was the guess, and it was
/// wrong in a way that showed up as flakiness rather than failure: measured on a
/// realistic browse capture the worst four gaps alone total 43 s, so a handshake
/// that happened to land in them ran out of budget while the identical
/// configuration succeeded on the next attempt.
///
/// This is the honest cost of sparse cover. A capture that is 90% silent cannot
/// carry a multi-round-trip handshake quickly, and pretending otherwise would
/// mean either breaking the envelope or failing at random.
#[must_use]
pub fn paced_handshake_budget() -> Option<Duration> {
    let (mode, profile, profile_up) = pace_settings();
    mode.as_deref()?;
    // Any seed: the question is what the LIBRARY's worst gap is, and every
    // chain is drawn from the same pool.
    let down = read_profile(&profile?, 0, None)?;
    let csv = match profile_up.as_deref().and_then(|u| read_profile(u, 0, None)) {
        Some(up) => merge_directional(&down, &up),
        None => down,
    };
    // Concatenated, because a gap is a difference between two times and the raw
    // chain restarts t at every trace boundary - measuring on that would read a
    // seam as a negative gap and the whole chain as one trace's worth of time.
    let rows = concat_flows(parse_rows(&csv));
    if rows.is_empty() {
        return None;
    }
    // Worst gap per direction, because each direction gates its own half of the
    // exchange; a quiet upstream stalls the handshake just as hard as a quiet
    // downstream.
    let worst = [true, false]
        .into_iter()
        .filter_map(|want_down| {
            let ts: Vec<f64> = rows
                .iter()
                .filter(|(_, _, d)| if want_down { *d > 0 } else { *d < 0 })
                .map(|(t, _, _)| *t)
                .collect();
            ts.windows(2)
                .map(|w| w[1] - w[0])
                .fold(None::<f64>, |acc, g| Some(acc.map_or(g, |a: f64| a.max(g))))
        })
        .fold(0.0_f64, f64::max);
    if !worst.is_finite() || worst <= 0.0 {
        return None;
    }
    Some(Duration::from_secs_f64(
        worst * f64::from(HANDSHAKE_GATED_MESSAGES),
    ))
}

/// The replay profile path currently configured, if any.
///
/// Exposed so a daemon can check whether that library actually holds traces
/// before it dials. It matters more than it looks: pacing is a property both
/// ends must agree on, and the session handshake runs INSIDE the paced channel,
/// so a client with an empty library does not connect unpaced - it sends an
/// unframed handshake to a peer reading frame headers and the session dies with
/// zero bytes. Knowing the path is what lets the caller wait for cover instead
/// of dialling into that.
#[must_use]
pub fn pace_profile() -> Option<String> {
    pace_settings().1
}

/// The UPSTREAM replay library currently configured, if any.
///
/// Separate from [`pace_profile`] because the two directions are merged into ONE
/// schedule: an endpoint that sets only the downstream library builds a
/// different schedule from a peer that sets both, and the replay stops being
/// joint. Exposed so an embedder can confirm what it actually applied.
#[must_use]
pub fn pace_profile_up() -> Option<String> {
    pace_settings().2
}

fn pace_settings() -> (Option<String>, Option<String>, Option<String>) {
    let (m, p, u) = raw_pace_settings();
    // An explicit "off" normalises to empty, which must read as NOT SET rather
    // than as a mode nothing matches - otherwise `pacing_active()` reports true
    // for a switch the operator turned off, and every caller that gates on it
    // (handshake budgets, symmetry checks) makes the wrong call.
    let m = m
        .as_deref()
        .map(normalize_mode)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    (m, p, u)
}

fn raw_pace_settings() -> (Option<String>, Option<String>, Option<String>) {
    if let Ok(g) = PACE_OVERRIDE.read() {
        if let Some((m, p, u)) = g.as_ref() {
            return (Some(m.clone()), p.clone(), u.clone());
        }
    }
    (
        std::env::var(PACE_ENV).ok(),
        std::env::var(PACE_PROFILE_ENV).ok(),
        std::env::var(PACE_PROFILE_UP_ENV).ok(),
    )
}

/// Map what someone would plausibly write to turn Proteus on onto the mode that
/// actually does it.
///
/// Proteus is meant to be a switch, not a menu: the answer to "how do I enable
/// this" should be `on`, and `on` should give you the good mode rather than
/// making you know that `replay` is the grounded one and `video`/`browse` are
/// weaker generative leftovers. Anything unrecognised is passed through so an
/// explicit class still works and a typo still shows up as a typo.
#[must_use]
pub fn normalize_mode(mode: &str) -> &str {
    match mode.trim().to_ascii_lowercase().as_str() {
        "on" | "true" | "yes" | "1" | "auto" | "proteus" => "replay",
        "off" | "false" | "no" | "0" | "none" => "",
        _ => mode.trim(),
    }
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

/// Reduce a cover host (possibly `host:port`) to a safe single-component subdir
/// name for the per-site profile library. Strips the port, lowercases, and keeps
/// only hostname characters, so it can never contain a path separator; `.`/`..`
/// are rejected (no alphanumeric) so it can never traverse out of the library.
/// The READER half of target-conditioned replay. Delegates to the shared
/// implementation so it cannot drift from the writer in `mirage-cover`: a
/// mismatch between the two would produce a library whose per-host traces are
/// never found, and that failure looks exactly like having none.
fn sanitize_host(host: &str) -> String {
    mirage_common::proteus_switch::sanitize_cover_host(host)
}

/// Resolve the replay profile path. A plain file is read directly. A DIRECTORY is a
/// trace library: per session, a seeded shuffle of up to [`CHAIN_LEN`] traces is
/// concatenated into one long envelope, flow-tagged so [`crate::pacer::MeasuredProfile`]
/// chains them in order. Both endpoints derive the SAME chain from the shared `seed`
/// (coherent up/down) yet it varies per session - a diverse library never becomes a
/// fixed signature, and no single clip loops. Volume-aware: prefer traces with real
/// capacity so short clips are not the whole chain.
/// Fewest upstream tokens per second a profile must offer to carry a tunnel. A
/// Noise handshake is several round trips and each client message waits for an
/// upstream token, so below roughly this the handshake cannot finish inside any
/// sane budget. Set from measurement: a pure video-download capture sits at 0.26
/// and fails; a browse capture sits near 14 and works.
const MIN_UPSTREAM_TOKENS_PER_SEC: f64 = 1.0;

/// Upstream capacity of a replay profile as `(tokens_per_sec, bytes_per_sec)`,
/// measured on the CONCATENATED timeline the pacer actually replays.
///
/// The concatenation is the whole point. A chained library restarts `t` at zero
/// for every trace in the chain, so dividing a chain-wide token count by
/// `max(t) - min(t)` divides by ONE trace's span - inflating the reported rate by
/// roughly the chain length. That number is logged as `up_tokens_per_sec`, is what
/// the e2e harness prints, and is what gets compared against
/// [`MIN_UPSTREAM_TOKENS_PER_SEC`] - so the starvation guard was gated at roughly
/// an eighth of its stated threshold, and would have stayed quiet on cover far too
/// sparse to carry a handshake.
fn upstream_capacity(csv: &str) -> (f64, f64) {
    let rows = concat_flows(parse_rows(csv));
    if rows.is_empty() {
        return (0.0, 0.0);
    }
    let (mut n, mut bytes) = (0.0f64, 0.0f64);
    let (mut lo, mut hi) = (f64::MAX, f64::MIN);
    for &(t, sz, dir) in &rows {
        lo = lo.min(t);
        hi = hi.max(t);
        if dir < 0 {
            n += 1.0;
            #[allow(clippy::cast_precision_loss)]
            {
                bytes += sz as f64;
            }
        }
    }
    let span = (hi - lo).max(f64::MIN_POSITIVE);
    if span.is_finite() && span > 0.0 && hi > lo {
        (n / span, bytes / span)
    } else {
        (0.0, 0.0)
    }
}

/// Inter-flow gap when chained traces are laid end to end. MUST match
/// `MeasuredProfile::from_csv`'s `GAP`, or the timeline this module reasons about
/// is not the one the pacer replays.
const CHAIN_GAP: f64 = 0.02;

/// Parse `[flow,]t,size,dir` rows into `(flow, t, size, dir)`, skipping a header.
///
/// The flow column is what makes a chained library a CHAIN. [`read_profile`]
/// emits up to `CHAIN_LEN` traces tagged by position, each with its own `t`
/// restarting near zero, and `MeasuredProfile::from_csv` lays them end to end on
/// that tag. Dropping the tag - which this function used to do - superimposes
/// every trace on one trace's timeline instead, which is a different envelope at
/// several times the recorded rate.
fn parse_rows(csv: &str) -> Vec<(u32, f64, i64, i32)> {
    let mut out = Vec::new();
    for line in csv.lines() {
        // A data row must LOOK like one, rather than merely failing to look like
        // a comment. Trace bytes arrive over the network - a client syncs its
        // library from the bridge - so this parser reads remotely supplied input.
        //
        // Relying on "a comment's fields will not parse as numbers" is not enough:
        // `# source_url=https://x/?a=b,0.5,100,1` splits into four fields whose
        // last three parse cleanly, injecting a fabricated record into the
        // replayed envelope, in a file that still looks valid. Skipping `#` lines
        // is not enough either: U+FEFF is not whitespace, so `trim` leaves a
        // byte-order mark in place and a BOM-prefixed comment sails past a
        // `starts_with('#')` check into exactly the same injection.
        //
        // So the rule is positive. Strip the BOM, then require the first
        // character to be one a number can start with. Every real row begins with
        // a flow id or a timestamp; nothing else is data, whatever it contains.
        let line = line.trim_start_matches('\u{FEFF}').trim();
        if !line.starts_with(|c: char| c.is_ascii_digit() || c == '-' || c == '+' || c == '.') {
            continue;
        }
        let f: Vec<&str> = line.split(',').collect();
        if f.len() < 3 {
            continue;
        }
        let tail = &f[f.len() - 3..];
        // A leading field beyond the fixed t,size,dir tail is the flow id; a bare
        // 3-column row is a single unchained trace, i.e. flow 0.
        let flow = if f.len() > 3 {
            f[f.len() - 4].trim().parse::<u32>().unwrap_or(0)
        } else {
            0
        };
        if let (Ok(t), Ok(sz), Ok(d)) = (
            tail[0].parse::<f64>(),
            tail[1].parse::<i64>(),
            tail[2].parse::<i32>(),
        ) {
            out.push((flow, t, sz, d));
        }
    }
    out
}

/// Lay a chained multi-flow trace end to end, returning rows on ONE absolute
/// timeline.
///
/// Mirrors `MeasuredProfile::from_csv` exactly: sort by `(flow, t)`, then start
/// each new flow [`CHAIN_GAP`] after the previous one ended. Anything in this
/// module that needs a span or a rate has to reason on this timeline, because it
/// is the one the pacer actually emits.
fn concat_flows(mut rows: Vec<(u32, f64, i64, i32)>) -> Vec<(f64, i64, i32)> {
    if rows.is_empty() {
        return Vec::new();
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.total_cmp(&b.1)));
    let mut out = Vec::with_capacity(rows.len());
    let mut cur_flow = rows[0].0;
    let mut flow_start = rows[0].1;
    let mut base = 0.0f64;
    let mut last = 0.0f64;
    for (flow, t, sz, dir) in rows {
        if flow != cur_flow {
            base = last + CHAIN_GAP;
            flow_start = t;
            cur_flow = flow;
        }
        let tt = base + (t - flow_start).max(0.0);
        last = tt;
        out.push((tt, sz, dir));
    }
    out
}

/// Build one schedule that wears `down_csv`'s DOWNSTREAM shape and `up_csv`'s
/// UPSTREAM shape.
///
/// The two captures are independent recordings with unrelated spans, so the
/// upstream one is TILED (repeated, each pass offset by its own span) until it
/// covers the downstream span - otherwise the upstream side would fall silent the
/// moment the shorter trace ran out, which is precisely the starvation this exists
/// to avoid.
///
/// BOTH inputs are chained multi-flow libraries, so both are laid end to end
/// ([`concat_flows`]) BEFORE anything is measured or tiled. Merging on the raw
/// text instead superimposes every trace in the chain on one trace's timeline:
/// the same records at several times the recorded rate, over a span several times
/// too short, and - because a global sort by time erases the chain ORDER - byte
/// identical for every session seed, which silently discards the per-session
/// diversity `seeded_order` exists to provide. This runs on the DEFAULT path
/// (both daemons fall back to the recorded `upstream` class), so it was the
/// envelope essentially every paced session wore.
///
/// The merged rows come out on one absolute timeline as a single flow, already
/// concatenated, which is what `MeasuredProfile::from_csv` expects and leaves
/// untouched.
fn merge_directional(down_csv: &str, up_csv: &str) -> String {
    let down = concat_flows(parse_rows(down_csv));
    let up = concat_flows(parse_rows(up_csv));
    if down.is_empty() || up.is_empty() {
        return down_csv.to_string();
    }
    let span_of = |rows: &[(f64, i64, i32)]| -> f64 {
        let (lo, hi) = rows.iter().fold((f64::MAX, f64::MIN), |(lo, hi), r| {
            (lo.min(r.0), hi.max(r.0))
        });
        (hi - lo).max(0.0)
    };
    let down_span = span_of(&down);
    let up_span = span_of(&up);

    let mut rows: Vec<(f64, i64, i32)> = down.iter().copied().filter(|r| r.2 > 0).collect();
    let up_rows: Vec<(f64, i64, i32)> = up.iter().copied().filter(|r| r.2 < 0).collect();
    if up_rows.is_empty() {
        return down_csv.to_string();
    }
    // Tile upstream across the downstream span. A degenerate (zero-span) upstream
    // capture would tile forever, so it is emitted once and left alone.
    if up_span <= f64::EPSILON {
        rows.extend(up_rows.iter().copied());
    } else {
        let mut offset = 0.0f64;
        while offset <= down_span {
            rows.extend(up_rows.iter().map(|&(t, sz, d)| (t + offset, sz, d)));
            offset += up_span;
        }
    }
    rows.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
    let mut out = String::with_capacity(rows.len() * 24);
    for (t, sz, d) in rows {
        out.push_str(&format!("0,{t},{sz},{d}\n"));
    }
    out
}

/// Smallest exact period of a sequence, if it is built from a repeated block.
///
/// KMP failure function: the shortest period is `n - failure[n-1]`, and it is a
/// TRUE period only when it divides `n` evenly. Exact equality is deliberate -
/// this is looking for a block that was literally copied, not for approximate
/// self-similarity, so it cannot fire on real traffic that merely looks regular.
fn smallest_exact_period<T: PartialEq>(xs: &[T]) -> Option<usize> {
    let n = xs.len();
    if n < 4 {
        return None;
    }
    let mut fail = vec![0usize; n];
    let mut k = 0usize;
    for i in 1..n {
        while k > 0 && xs[i] != xs[k] {
            k = fail[k - 1];
        }
        if xs[i] == xs[k] {
            k += 1;
        }
        fail[i] = k;
    }
    let p = n - fail[n - 1];
    (p < n && n % p == 0).then_some(p)
}

/// Does this schedule contain a periodically TILED direction?
///
/// `merge_directional` builds an upstream schedule by repeating a whole capture
/// end to end across the downstream span. That leaves the upstream record-size
/// sequence exactly periodic, which is a **deterministic single-flow signature**:
/// one FFT of upstream inter-record gaps, or one period check like this, finds it
/// with no reference class, no population statistics and no threshold to tune. It
/// is the kind of detector a censor can run at line rate on every flow.
///
/// That makes it a different class of defect from everything else in the shaping
/// design, which are statistical-accumulation problems where the adversary needs
/// N observations and the argument is about the constant. Here N = 1.
///
/// Returns the repeated block length, per direction, when found.
#[must_use]
pub fn tiled_direction(csv: &str) -> Option<(bool, usize)> {
    let rows = concat_flows(parse_rows(csv));
    for want_down in [false, true] {
        let sizes: Vec<i64> = rows
            .iter()
            .filter(|(_, _, d)| if want_down { *d > 0 } else { *d < 0 })
            .map(|(_, sz, _)| *sz)
            .collect();
        if let Some(p) = smallest_exact_period(&sizes) {
            // A block repeated only twice can occur by chance in a short capture;
            // three or more repeats of an identical multi-record block does not.
            if sizes.len() / p >= 3 && p >= 2 {
                return Some((want_down, p));
            }
        }
    }
    None
}

/// The configured cover's sustainable UPSTREAM rate, bytes/sec.
///
/// This is `μ` — the service rate the tunnel actually has, fixed by the envelope
/// rather than by the link. Exposed as a value for the same reason
/// [`crate::pacer::ScheduleStream::replay_position`] is: a caller that needs the
/// rate must read the schedule's real one, not a config constant. The two agree
/// right up until the trace varies, which is exactly when the number matters.
///
/// Callers should throttle to `ρ_max · μ`, not `μ`. Queue delay is `ρ/(μ(1−ρ))`:
/// at ρ=0.85 that is ~5.7/μ, at ρ=0.95 it is ~19/μ and climbing. The last 15% of
/// nominal capacity costs roughly 3× the latency and cannot be sustained anyway.
#[must_use]
pub fn cover_upstream_bps() -> Option<f64> {
    let (mode, profile, profile_up) = pace_settings();
    mode.as_deref()?;
    let down = read_profile(&profile?, 0, None)?;
    let csv = match profile_up.as_deref().and_then(|u| read_profile(u, 0, None)) {
        Some(up) => merge_directional(&down, &up),
        None => down,
    };
    let (_tokens, bps) = upstream_capacity(&csv);
    (bps > 0.0).then_some(bps)
}

/// The configured cover's UPSTREAM inter-record gap at a quantile, in seconds.
///
/// This is the statistic that actually bounds a tunnel's queue delay, and it is
/// the only one of five candidates that survived measurement. Record-size CV,
/// mean rate, duty cycle and idle fraction were each measured across four real
/// cover classes and each ranked them differently - see
/// `docs/proteus-2.0.md`. They are all statements about the cover's
/// DISTRIBUTION; the gap bound is a statement about the tunnel's QUEUE, which is
/// what a user experiences. Buffered video and segmented HLS have similar idle
/// fractions (94% vs 81%) and worst gaps of 15 s versus 0.9 s.
///
/// Quantile rather than max: the maximum is one observation and would size every
/// buffer for an outlier.
#[must_use]
pub fn cover_gap_secs(quantile: f64) -> Option<f64> {
    let (mode, profile, profile_up) = pace_settings();
    mode.as_deref()?;
    let down = read_profile(&profile?, 0, None)?;
    let csv = match profile_up.as_deref().and_then(|u| read_profile(u, 0, None)) {
        Some(up) => merge_directional(&down, &up),
        None => down,
    };
    // Concatenated: the raw chain restarts t at every trace boundary, so a seam
    // would read as a negative gap and the whole chain as one trace's span.
    let rows = concat_flows(parse_rows(&csv));
    let mut gaps: Vec<f64> = Vec::new();
    let mut prev: Option<f64> = None;
    for &(t, _, _) in rows.iter().filter(|(_, _, d)| *d < 0) {
        if let Some(p) = prev {
            let g = t - p;
            if g > 0.0 {
                gaps.push(g);
            }
        }
        prev = Some(t);
    }
    if gaps.is_empty() {
        return None;
    }
    gaps.sort_by(f64::total_cmp);
    let idx = ((quantile.clamp(0.0, 1.0) * gaps.len() as f64) as usize).min(gaps.len() - 1);
    Some(gaps[idx])
}

/// Run [`tiled_direction`] over the schedule a given profile PAIR would produce.
///
/// Pure in its inputs on purpose. The obvious spelling reads the process-global
/// pacing state, and a test against that state is flaky by construction - this
/// file already lost one test that way. The global-reading wrapper is
/// [`configured_schedule_is_tiled`]; the logic under test is here.
#[must_use]
pub fn schedule_is_tiled(down_csv: &str, up_csv: Option<&str>) -> Option<(bool, usize)> {
    let csv = match up_csv {
        Some(up) => merge_directional(down_csv, up),
        None => down_csv.to_string(),
    };
    tiled_direction(&csv)
}

/// [`schedule_is_tiled`] against whatever profile is currently configured.
///
/// Checks the bytes that will actually be replayed, not the config that was
/// requested - the two differ whenever `merge_directional` is involved, which is
/// exactly the case this exists to catch.
#[must_use]
pub fn configured_schedule_is_tiled() -> Option<(bool, usize)> {
    let (mode, profile, profile_up) = pace_settings();
    mode.as_deref()?;
    let down = read_profile(&profile?, 0, None)?;
    let up = profile_up.as_deref().and_then(|u| read_profile(u, 0, None));
    schedule_is_tiled(&down, up.as_deref())
}

/// The replay profile's on-wire record sizes and typical gap for ONE direction.
///
/// This is what a DATAGRAM carrier needs. A byte-stream carrier can be handed a
/// [`ScheduleStream`] and paced record by record, but a QUIC socket cannot be
/// paced that way without delaying real datagrams and disturbing congestion
/// control - so it takes the cover's SIZES (to pad each datagram up to) and its
/// CADENCE (to fill idle gaps) and leaves real traffic alone. See
/// `mirage_quic_obfs::QuicShape`.
///
/// `want_down` selects the direction: a bridge shapes what it SENDS (down), a
/// client shapes what it sends (up). Returns `None` unless replay pacing is
/// configured and the profile actually has records for that direction.
#[must_use]
pub fn pace_wire_sizes(want_down: bool, seed: u64) -> Option<Vec<(u16, Duration)>> {
    let (mode, profile, profile_up) = pace_settings();
    if mode.as_deref() != Some("replay") {
        return None;
    }
    let down_csv = read_profile(&profile?, seed, None)?;
    let csv = match profile_up
        .as_deref()
        .and_then(|u| read_profile(u, seed, None))
    {
        Some(up_csv) => merge_directional(&down_csv, &up_csv),
        None => down_csv,
    };
    // Concatenated first: these are (size, preceding gap) pairs, and a gap read
    // across a chain seam on the raw timeline is meaningless.
    let rows: Vec<(f64, i64, i32)> = concat_flows(parse_rows(&csv))
        .into_iter()
        .filter(|(_, _, d)| if want_down { *d > 0 } else { *d < 0 })
        .collect();
    if rows.is_empty() {
        return None;
    }
    // Size AND the gap that preceded it, kept together: they are one measurement,
    // and real traffic's burstiness lives in the gaps. Collapsing them to a scalar
    // cadence loses the arrangement AND misstates the rate - a median gap is small
    // precisely BECAUSE most gaps sit inside bursts, so it would turn a 60
    // record/s capture into a 1000 datagram/s metronome.
    let mut out: Vec<(u16, Duration)> = Vec::with_capacity(rows.len());
    let mut prev = rows[0].0;
    for &(t, sz, _) in &rows {
        let gap = (t - prev).max(0.0);
        prev = t;
        out.push((
            sz.clamp(1, i64::from(u16::MAX)) as u16,
            Duration::from_secs_f64(gap),
        ));
    }
    Some(out)
}

/// Ceiling above which [`fragment_to_mtu`] stops expanding, so a corrupt or
/// adversarial profile cannot turn a handful of records into millions of tokens.
/// Well above any real capture: a 60 s browse trace runs a few thousand records,
/// and fragmenting 16 KiB TLS records multiplies that by about twelve.
const MAX_FRAGMENTED_TOKENS: usize = 200_000;

/// Re-express a TLS-RECORD envelope as the DATAGRAM envelope it produced.
///
/// A datagram carrier cannot emit a 16 KiB token, so the sizes have to come down
/// to the path MTU. Clamping is the wrong way to do it, and measurably so: a
/// 16 KiB TLS record does not reach the network as one 1452-byte packet, it
/// reaches it as about twelve back-to-back full-MTU packets and a remainder.
/// Clamping keeps one of those twelve, which
///
///   - starves the byte rate to roughly a twelfth of the cover's, so the shaped
///     flow no longer carries the volume it claims to, and
///   - collapses the size distribution: against an upload capture 91% of
///     upstream records are exactly 16384, so 91% of tokens become a constant
///     max-size datagram. A constant is a fingerprint.
///
/// Splitting instead preserves the byte count, the packet count AND the
/// arrangement - a burst of full-MTU packets closed by a short one, which is
/// what a bulk transfer looks like from the outside. Nothing is invented here;
/// this is the transformation the wire itself performs on that record.
///
/// The pieces after the first inherit `burst_gap`, which callers derive from the
/// capture's own smallest observed gap rather than picking a number.
#[must_use]
pub fn fragment_to_mtu(
    tokens: Vec<(u16, Duration)>,
    ceiling: u16,
    burst_gap: Duration,
) -> Vec<(u16, Duration)> {
    let ceiling = ceiling.max(1);
    let mut out: Vec<(u16, Duration)> = Vec::with_capacity(tokens.len());
    for (sz, gap) in tokens {
        if sz <= ceiling {
            out.push((sz, gap));
            continue;
        }
        let mut left = sz;
        let mut first = true;
        while left > 0 && out.len() < MAX_FRAGMENTED_TOKENS {
            let take = left.min(ceiling);
            out.push((take, if first { gap } else { burst_gap }));
            first = false;
            left -= take;
        }
        if out.len() >= MAX_FRAGMENTED_TOKENS {
            break;
        }
    }
    out
}

/// The smallest positive gap in `tokens`: the capture's own evidence of how
/// closely that link spaces back-to-back packets. Used as the intra-burst gap
/// when fragmenting, so the spacing stays a measurement rather than a guess.
/// Falls back to 100 us when a capture has no positive gap at all.
#[must_use]
pub fn min_positive_gap(tokens: &[(u16, Duration)]) -> Duration {
    tokens
        .iter()
        .map(|&(_, g)| g)
        .filter(|g| !g.is_zero())
        .min()
        .unwrap_or(Duration::from_micros(100))
}

/// Stable 64-bit digest of the selected replay profile (FNV-1a over the exact
/// CSV both endpoints feed to the pacer). Equal digests on the two ends mean
/// they really are replaying the two halves of one captured flow; unequal ones
/// mean the "joint" replay is joint in name only. Not security-critical - it is
/// a divergence signal for operators, not an authenticator.
fn profile_digest(csv: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in csv.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// `(path, size)` for every `.csv` directly inside `dir`. Not recursive; see the
/// one-level fall-through in [`read_profile`].
fn csv_traces_in(dir: &std::path::Path) -> Vec<(std::path::PathBuf, u64)> {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "csv"))
        .map(|p| {
            let sz = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            (p, sz)
        })
        .collect()
}

/// Which trace set a replay profile resolves to for a given cover host.
///
/// Exists so the runtime selection and the startup check share ONE
/// implementation. When they were separate, the fallback branch was reachable
/// with nothing reporting it: every measurement taken against this code ran on
/// [`Generic`](ProfileMatch::Generic) - the mode this file's own comment
/// describes as "stays separable" - and neither the config, the diagnostics, nor
/// the logs said so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileMatch {
    /// The profile names a single trace FILE, not a library. Host-matching does
    /// not apply and there is nothing to choose.
    PinnedFile,
    /// No cover host is configured, so there is nothing to match against.
    NoCoverHost,
    /// A subdirectory named for the cover host exists; that site's own recorded
    /// shape is worn.
    HostMatched(std::path::PathBuf),
    /// No subdirectory for the cover host. The generic class is worn instead -
    /// the flow does not match its claimed destination.
    Generic {
        /// The library root actually read.
        root: std::path::PathBuf,
        /// The subdirectory that would have been used had it existed.
        wanted: std::path::PathBuf,
    },
}

impl ProfileMatch {
    /// True when the shaped envelope does not correspond to the cover host the
    /// carrier claims. A prober sees the real site; a passive observer sees a
    /// flow shaped like something else, and no single-layer check finds the
    /// disagreement.
    #[must_use]
    pub fn is_generic(&self) -> bool {
        matches!(self, Self::Generic { .. })
    }

    /// The directory or file the pacer will actually read.
    #[must_use]
    pub fn effective_path(&self, configured: &str) -> std::path::PathBuf {
        match self {
            Self::HostMatched(p) => p.clone(),
            Self::Generic { root, .. } => root.clone(),
            Self::PinnedFile | Self::NoCoverHost => std::path::PathBuf::from(configured),
        }
    }
}

/// Resolve a replay profile against a cover host WITHOUT reading any traces.
///
/// Target-conditioned selection: when `path` is a library ROOT that contains a
/// subdir named after the cover host, wear THAT site's recorded shape so the
/// flow matches its claimed destination. Measured to reach the size-AUC floor
/// vs the real site, where a generic class stays separable. Both endpoints
/// derive the same host from their matching cover config, so up/down stays
/// coherent.
#[must_use]
pub fn resolve_profile_match(path: &str, cover_host: Option<&str>) -> ProfileMatch {
    let base = std::path::Path::new(path);
    if base.is_file() {
        return ProfileMatch::PinnedFile;
    }
    match cover_host.map(sanitize_host).filter(|h| !h.is_empty()) {
        Some(host) => {
            let sub = base.join(&host);
            if sub.is_dir() {
                ProfileMatch::HostMatched(sub)
            } else {
                ProfileMatch::Generic {
                    root: base.to_path_buf(),
                    wanted: sub,
                }
            }
        }
        None => ProfileMatch::NoCoverHost,
    }
}

fn read_profile(path: &str, seed: u64, cover_host: Option<&str>) -> Option<String> {
    // Falls back to `path` unchanged when no per-host subdir exists (backwards
    // compatible with a profile that points straight at a class dir). That
    // fallback is silent HERE by design - it is reported once at startup by
    // `resolve_profile_match`, not per-session on a hot path.
    let effective = resolve_profile_match(path, cover_host).effective_path(path);
    let path = &effective;
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_dir() {
        return std::fs::read_to_string(path).ok();
    }
    let mut traces: Vec<(std::path::PathBuf, u64)> = csv_traces_in(path);
    if traces.is_empty() {
        // A library ROOT holds class subdirs (`video/`, `browse/`), not traces.
        // Without this fall-through, pointing the profile at the root silently
        // yields NO schedule and the tunnel runs unpaced - which is exactly what
        // the self-sourcing default does, so Proteus would have reported itself
        // enabled while pacing nothing. Recurse one level and pool what is there.
        let mut subs: Vec<std::path::PathBuf> = std::fs::read_dir(path)
            .ok()?
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        subs.sort(); // deterministic: both endpoints must build the same pool
                     // The UPSTREAM class is not downstream cover. It is recorded dense and
                     // gap-free on purpose, because a tunnel's flow control rides upstream -
                     // which makes it a 2-3 s page-load burst, the wrong shape to wear as
                     // downstream browsing and far shorter than a session. Pooling it here
                     // also made a session's cover RATE a lottery: the same library gave
                     // 88.7 KiB/s of idle cover in one session and 125.3 KiB/s in another,
                     // purely from which class got drawn, and that variance raises the
                     // separability floor for every measurement taken over it.
                     //
                     // Both endpoints apply the same rule to the same directory names, so
                     // the pools still match.
        let downstream: Vec<std::path::PathBuf> = subs
            .iter()
            .filter(|p| {
                p.file_name().and_then(|n| n.to_str())
                    != Some(mirage_common::proteus_switch::UPSTREAM_COVER_CLASS)
            })
            .cloned()
            .collect();
        // Unless that leaves nothing. A library holding only the upstream class
        // is a bootstrapping state, and pacing with an odd shape beats not
        // pacing at all - an empty schedule does not degrade to unpaced, it
        // HANGS the session with zero bytes through.
        let pool = if downstream.is_empty() {
            subs
        } else {
            downstream
        };
        // ONE class per session, chosen by the shared seed - not a pooled mix.
        //
        // Pooling classes puts traces of very different rates in one chain, and
        // the session's rate then swings phase-to-phase with whichever trace the
        // shuffle drew. That is the same defect that made the UPSTREAM class
        // poisonous above, and it is not specific to upstream: measured on the
        // global pack, realtime browse captures run 494-960 kbit/s over 24-32 s
        // while a realtime video capture runs 330 kbit/s over 360 s, so a mixed
        // chain swings ~2.9x within one session. Rate variance is exactly what
        // raises the separability floor - a censor does not need to identify the
        // class, only to notice that the flow's rate steps in a way a real
        // session's does not.
        //
        // Both endpoints sort the same directory names and derive the same seed,
        // so they select the same class and replay stays joint. Coverage is
        // unaffected: every class is still worn, just whole-session rather than
        // interleaved, which is also what a real user does - they watch a video
        // OR read pages, not both in alternating four-second phases.
        //
        // Falls through to the next class if the chosen one is empty, because an
        // empty schedule does not degrade to unpaced - it HANGS the session.
        for &i in seeded_order(pool.len(), seed).iter() {
            traces.extend(csv_traces_in(&pool[i]));
            if !traces.is_empty() {
                break;
            }
        }
    }
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
    // Target-conditioned replay keys on the Reality cover host (see read_profile).
    let cover_host = stream.cover_host().map(str::to_owned);
    match pace_schedule(seed, cover_host.as_deref()) {
        Some(sched) => {
            stream.set_passthrough(true);
            // Passthrough seals each pump frame into exactly one TLS 1.3 record.
            MaybePaced::Paced(PacedChannel::spawn(stream, sched, dir, Carrier::tls()))
        }
        None => MaybePaced::Plain(stream),
    }
}

/// Build the pacing schedule for this session from the process-wide pace settings,
/// or `None` if pacing is not configured (or a replay profile is missing/empty - the
/// tunnel must never break over a config slip). `seed` MUST be identical on both
/// endpoints so the up/down envelope stays coherent.
pub fn pace_schedule(seed: u64, cover_host: Option<&str>) -> Option<ScheduleStream> {
    let (mode, profile, profile_up) = pace_settings();
    match mode.as_deref() {
        Some(class @ ("video" | "dash" | "browse")) => Some(ScheduleStream::new(
            CoverProcess::from_class_seed(class, seed),
            seed,
        )),
        // Path may be a single trace file OR a directory library (optionally with a
        // per-cover-host subdir for target-conditioned replay) - see [`read_profile`].
        Some("replay") => profile
            .and_then(|p| read_profile(&p, seed, cover_host))
            .map(|down_csv| {
                match profile_up
                    .as_deref()
                    .and_then(|u| read_profile(u, seed, cover_host))
                {
                    // Per-direction cover: downstream shape from one capture, upstream
                    // from another. Without this, the best-looking downstream cover
                    // (video) is unusable because its upstream cannot carry the tunnel.
                    Some(up_csv) => merge_directional(&down_csv, &up_csv),
                    None => down_csv,
                }
            })
            .inspect(|s| {
                // Replay is only JOINT if both endpoints select the SAME trace
                // bytes: the up and down schedules are two halves of one captured
                // flow. Selection reads the LOCAL library (directory listing, file
                // sizes, presence of a per-cover-host subdir), so two independently
                // administered ends can silently diverge - and a pair replaying two
                // UNRELATED real flows has an up/down relationship no real flow has,
                // which is worse than not pacing at all. Nothing on the wire binds
                // the two selections today, so surface the digest: identical values
                // at both ends mean the replay really is joint.
                let (up_rate, up_bps) = upstream_capacity(s);
                tracing::info!(
                    seed,
                    cover_host = cover_host.unwrap_or("-"),
                    profile_digest = %format_args!("{:016x}", profile_digest(s)),
                    up_tokens_per_sec = %format_args!("{up_rate:.2}"),
                    up_bytes_per_sec = %format_args!("{up_bps:.0}"),
                    "proteus: replay profile selected (digests MUST match on both endpoints)"
                );
                // A cover trace is not just a shape, it is a BUDGET, and the
                // tunnel has to fit inside it in BOTH directions. A video-download
                // capture is wildly asymmetric - measured at 0.26 upstream tokens/s
                // and 99 B/s against a browse capture's 13.7/s and 4.5 KB/s - and a
                // multi-round-trip handshake simply cannot complete over the former:
                // the carrier comes up, the handshake starves, and the failure looks
                // like an unreachable bridge rather than a cover-selection mistake.
                // Say so plainly instead of letting the operator debug a phantom.
                if up_rate < MIN_UPSTREAM_TOKENS_PER_SEC {
                    tracing::warn!(
                        up_tokens_per_sec = %format_args!("{up_rate:.2}"),
                        up_bytes_per_sec = %format_args!("{up_bps:.0}"),
                        needed = %format_args!("{MIN_UPSTREAM_TOKENS_PER_SEC:.1}"),
                        "proteus: this cover profile's UPSTREAM is too sparse to carry a \
                         tunnel - handshakes will stall and the bridge will look \
                         unreachable. Record a browse-class trace, or one with real \
                         upload activity; a pure download capture cannot carry the \
                         client's own traffic."
                    );
                }
            })
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
///
/// `carrier` MUST name the framing `stream` adds per record. It is not cosmetic: it
/// is what the pump sizes frames against, and getting it wrong puts every record off
/// the captured envelope by the difference (see [`Carrier`]).
pub fn maybe_pace_stream<S>(stream: S, dir: Dir, seed: u64, carrier: Carrier) -> MaybePaced<S>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    // No cover host on the generic-carrier path (SS-2022 etc.): class/replay only.
    match pace_schedule(seed, None) {
        Some(sched) => MaybePaced::Paced(PacedChannel::spawn(stream, sched, dir, carrier)),
        None => MaybePaced::Plain(stream),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn a_library_root_of_class_dirs_still_yields_a_schedule() {
        // The self-sourcing default points the profile at a library ROOT and
        // records into `<root>/browse` and `<root>/video`. Listing only the
        // root's own *.csv found nothing there, so pace_schedule returned None
        // and the tunnel ran UNPACED while Proteus reported itself enabled -
        // the silently-off failure the whole switch exists to rule out.
        use std::sync::atomic::{AtomicU32, Ordering};
        static CTR: AtomicU32 = AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "proteus_root_{}_{}",
            std::process::id(),
            CTR.fetch_add(1, Ordering::Relaxed)
        ));
        let browse = root.join("browse");
        std::fs::create_dir_all(&browse).expect("mkdir");

        let mut big = String::from("t,size,dir\n");
        for i in 0..6000 {
            big.push_str(&format!("{i}.0,1400,1\n"));
        }
        std::fs::write(browse.join("0.csv"), &big).expect("write");

        let got = read_profile(root.to_str().expect("utf8"), 7, None);
        assert!(
            got.as_ref().is_some_and(|s| !s.is_empty()),
            "a library root holding only class subdirs must still resolve"
        );

        // And an EMPTY root is still None - "no cover yet" must stay honest
        // rather than becoming an empty schedule that paces nothing.
        let empty = root.join("empty");
        std::fs::create_dir_all(empty.join("browse")).expect("mkdir");
        assert!(read_profile(empty.to_str().expect("utf8"), 7, None).is_none());

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn an_active_tunnel_emits_the_same_wire_as_an_idle_one() {
        // The activity signal, simulated at the only layer where activity can
        // reach the wire at all.
        //
        // `SizeAligner::next` is handed `has_data`, and when `deviate` fires it
        // takes the LARGEST buffered size while the app has bytes queued and the
        // SMALLEST while it does not. That is a demand-following rate, and it was
        // measured at 0.699 separability against a 0.544 control - which is why
        // `ALIGN_ALPHA_PERMILLE` is 0 and the branch is unreachable.
        //
        // Unreachable today is not the same as unreachable tomorrow. This drives
        // the real aligner over a real schedule twice - once as a saturated
        // tunnel, once as a silent one - and asserts the emitted size sequence is
        // byte-identical. If anyone re-enables alignment, or makes emission
        // depend on the queue in some new way, this fails instead of shipping an
        // activity signal.
        //
        // Verified to FAIL with ALIGN_ALPHA_PERMILLE set to 1000.
        let csv = (0..400)
            .map(|i| {
                // Sizes that vary enough for "largest" and "smallest" to differ.
                let sz = 200 + (i * 37) % 1200;
                format!("0,{:.3},{sz},1", f64::from(i) * 0.01)
            })
            .collect::<Vec<_>>()
            .join("\n");
        let profile = std::sync::Arc::new(
            crate::pacer::MeasuredProfile::from_csv(&csv).expect("profile from csv"),
        );

        let run = |has_data: bool| -> Vec<usize> {
            let mut stream = ScheduleStream::replay(profile.clone(), 42);
            let mut aligner = SizeAligner::new(42);
            (0..600)
                .map(|_| aligner.next(&mut stream, Dir::Down, has_data).bytes)
                .collect()
        };

        let active = run(true);
        let idle = run(false);
        assert_eq!(
            active.len(),
            idle.len(),
            "an active tunnel emitted a different NUMBER of records than an idle one"
        );
        assert_eq!(
            active, idle,
            "the wire differs between a busy tunnel and a silent one - that is an \
             activity signal, which is the whole thing Proteus exists to remove"
        );
        // Not vacuous: the schedule really does carry varied sizes, so an aligner
        // that steered by demand would have produced a different sequence.
        let distinct: std::collections::HashSet<usize> = active.iter().copied().collect();
        assert!(
            distinct.len() > 8,
            "schedule too flat to detect steering: {} distinct sizes",
            distinct.len()
        );
    }

    #[test]
    fn a_session_wears_one_cover_class_not_a_mixture() {
        // Pooling classes into one chain makes the session's RATE swing
        // phase-to-phase with whichever trace the shuffle drew, and rate variance
        // is what raises the separability floor - a censor need not identify the
        // class, only notice a flow whose rate steps in a way a real session's
        // does not. Measured on the global pack: realtime browse runs 494-960
        // kbit/s over 24-32 s while realtime video runs 330 kbit/s over 360 s, so
        // a mixed chain swung about 2.9x inside one session.
        use std::sync::atomic::{AtomicU32, Ordering};
        static CTR: AtomicU32 = AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "proteus_oneclass_{}_{}",
            std::process::id(),
            CTR.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(root.join("browse")).unwrap();
        std::fs::create_dir_all(root.join("video")).unwrap();
        for i in 0..4 {
            std::fs::write(
                root.join(format!("browse/{i}.csv")),
                "t,size,dir\n0.0,111,1\n1.0,111,1\n",
            )
            .unwrap();
            std::fs::write(
                root.join(format!("video/{i}.csv")),
                "t,size,dir\n0.0,222,1\n1.0,222,1\n",
            )
            .unwrap();
        }
        let root_s = root.to_str().unwrap();

        // Whatever seed is used, a session must be pure: one class, never both.
        let mut saw_browse = false;
        let mut saw_video = false;
        for seed in 0..24u64 {
            let sched = read_profile(root_s, seed, None).expect("a schedule");
            let b = sched.contains(",111,");
            let v = sched.contains(",222,");
            assert!(b || v, "seed {seed} produced no cover at all");
            assert!(
                !(b && v),
                "seed {seed} mixed browse and video into one session"
            );
            saw_browse |= b;
            saw_video |= v;
        }
        // ...and coverage is preserved: every class is still worn across sessions.
        assert!(
            saw_browse && saw_video,
            "both classes must still be reachable - dropping one would narrow cover"
        );

        // Both endpoints derive the same seed, so they must build the SAME schedule.
        for seed in [0u64, 7, 99] {
            assert_eq!(
                read_profile(root_s, seed, None),
                read_profile(root_s, seed, None),
                "selection must be deterministic or replay stops being joint"
            );
        }

        // An empty class must not hand back an empty schedule: that HANGS the
        // session rather than degrading to unpaced.
        std::fs::create_dir_all(root.join("empty")).unwrap();
        for seed in 0..24u64 {
            assert!(
                read_profile(root_s, seed, None).is_some(),
                "seed {seed} fell into the empty class and produced nothing"
            );
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn fragmenting_preserves_bytes_and_leaves_small_records_alone() {
        let ms = Duration::from_millis;
        let tokens = vec![(16384u16, ms(50)), (300, ms(7)), (1452, ms(3))];
        let before: u64 = tokens.iter().map(|&(s, _)| u64::from(s)).sum();

        let out = fragment_to_mtu(tokens, 1452, Duration::from_micros(80));

        // Byte-for-byte identical: the record is re-expressed, not truncated.
        // This is the property clamping broke - it kept 1452 of every 16384.
        let after: u64 = out.iter().map(|&(s, _)| u64::from(s)).sum();
        assert_eq!(before, after, "fragmenting must not lose or add bytes");

        // 16384 = 11 * 1452 + 412, then the two records that already fit.
        assert_eq!(out.len(), 11 + 1 + 2);
        assert!(out[..11].iter().all(|&(s, _)| s == 1452));
        assert_eq!(out[11].0, 412);
        assert_eq!(out[12], (300, ms(7)));
        assert_eq!(out[13], (1452, ms(3)));

        // The original gap stays on the first piece; the rest are back-to-back,
        // so the burst arrives as a burst rather than being stretched out.
        assert_eq!(out[0].1, ms(50));
        assert!(out[1..12]
            .iter()
            .all(|&(_, g)| g == Duration::from_micros(80)));
    }

    #[test]
    fn fragmenting_a_bulk_upload_capture_stops_being_a_constant() {
        // The measured shape of a real upload trace: 91% of upstream records are
        // exactly one maximal TLS record. Clamped, that is a constant max-size
        // datagram 91% of the time, which is a fingerprint. Split, it is a run of
        // full-MTU packets each closed by a short one - what bulk transfer is.
        let tokens: Vec<(u16, Duration)> = (0..100)
            .map(|i| {
                if i % 11 == 0 {
                    (240u16, Duration::from_millis(5))
                } else {
                    (16384, Duration::from_millis(5))
                }
            })
            .collect();

        let clamped: Vec<u16> = tokens.iter().map(|&(s, _)| s.min(1452)).collect();
        let distinct_clamped: std::collections::BTreeSet<_> = clamped.iter().copied().collect();
        assert_eq!(distinct_clamped.len(), 2);
        let at_ceiling = clamped.iter().filter(|&&s| s == 1452).count();
        assert!(
            at_ceiling >= 90,
            "clamping leaves {at_ceiling}% at the ceiling"
        );

        let out = fragment_to_mtu(tokens, 1452, Duration::from_micros(80));
        let remainders = out.iter().filter(|&&(s, _)| s == 412).count();
        assert_eq!(
            remainders, 90,
            "every split record leaves its own remainder"
        );
        // The remainder is now a real recurring size rather than an artifact of
        // where the ceiling happened to fall.
        assert!(out.len() > 1000);
    }

    #[test]
    fn fragmenting_is_bounded_against_a_hostile_profile() {
        // A profile is a file on disk; a corrupt or planted one must not be able
        // to expand into unbounded memory.
        let tokens = vec![(u16::MAX, Duration::from_millis(1)); 5000];
        let out = fragment_to_mtu(tokens, 1, Duration::ZERO);
        assert!(out.len() <= MAX_FRAGMENTED_TOKENS);
    }

    #[test]
    fn min_positive_gap_ignores_zeros_and_has_a_floor() {
        let ms = Duration::from_millis;
        assert_eq!(
            min_positive_gap(&[(100, Duration::ZERO), (100, ms(9)), (100, ms(4))]),
            ms(4)
        );
        // A capture whose gaps are all zero yields the documented fallback rather
        // than a zero gap, which would spin the cover injector.
        assert_eq!(
            min_positive_gap(&[(100, Duration::ZERO)]),
            Duration::from_micros(100)
        );
        assert_eq!(min_positive_gap(&[]), Duration::from_micros(100));
    }

    #[test]
    fn rebase_on_stall_repins_only_past_the_drift_threshold() {
        let base = Instant::now();
        let tok_t = 1.0_f64; // this token is due at base + 1s
        let deadline = base + Duration::from_secs(1);
        let max = Duration::from_millis(1500);

        // On schedule, and small drift under the threshold: origin unchanged, so
        // ordinary jitter/backpressure never perturbs the pacing clock.
        assert_eq!(rebase_on_stall(base, tok_t, deadline, max), base);
        assert_eq!(
            rebase_on_stall(base, tok_t, deadline + Duration::from_millis(900), max),
            base
        );

        // A multi-second stall past the threshold re-pins so the token fires ~now
        // instead of flooding to catch up. The new origin puts this token's
        // deadline at (approximately) the late `now`, not in the past.
        let late = deadline + Duration::from_secs(4);
        let rebased = rebase_on_stall(base, tok_t, late, max);
        assert_ne!(rebased, base, "a large stall must re-pin the origin");
        let new_deadline = rebased + Duration::from_secs_f64(tok_t);
        let diff = new_deadline.saturating_duration_since(late)
            + late.saturating_duration_since(new_deadline);
        assert!(
            diff < Duration::from_millis(1),
            "re-pinned deadline should map to now, not the stale past"
        );
    }

    /// The property that makes an always-on cover envelope actually hide activity:
    /// the emission schedule must depend only on the origin and the trace, never
    /// on how busy the carrier is. Measured on a real cluster, re-pinning after a
    /// stall let a busy carrier emit ~16% more downstream bytes than an idle one,
    /// which a censor separates perfectly on total bytes per window.
    /// A cover trace is a BUDGET the tunnel must fit inside in BOTH directions.
    /// Measured on real captures: a video-download envelope offers 0.26 upstream
    /// tokens/s and a multi-round-trip handshake starves on it (the carrier comes
    /// up, the handshake never finishes, and it presents as an unreachable
    /// bridge); a browse envelope offers ~14/s and carries the tunnel fine. This
    /// pins the arithmetic that tells the two apart.
    /// Per-direction cover: wear a video capture's downstream shape while taking
    /// the upstream from a browse capture, so the session looks like someone
    /// watching a video AND has the upload capacity to actually be one. The
    /// upstream trace is short, so it must be TILED across the whole downstream
    /// span - otherwise upstream falls silent partway through, which is the exact
    /// starvation this exists to prevent.
    #[test]
    fn merging_preserves_the_chain_instead_of_superimposing_it() {
        // THE regression. `read_profile` emits a CHAIN: up to CHAIN_LEN traces
        // tagged by position, each with its own `t` restarting near zero, which
        // `MeasuredProfile::from_csv` lays end to end on that tag.
        // `merge_directional` used to parse rows without the tag and re-emit
        // everything as one flow sorted by raw time, which superimposes the whole
        // chain on ONE trace's timeline: same records, several times the recorded
        // rate, a span several times too short, and - because the global sort
        // erases chain ORDER - the same bytes for every seed, discarding the
        // per-session diversity `seeded_order` exists to give.
        //
        // The pre-existing merge test fed hand-built SINGLE-flow input, so it
        // could not see any of that. This one feeds what the caller really
        // supplies.
        const FLOWS: u32 = 4;
        const PER_FLOW: usize = 50;
        const STEP: f64 = 0.1;
        let mut down = String::new();
        for flow in 0..FLOWS {
            for i in 0..PER_FLOW {
                // Every flow restarts at t=0, exactly as read_profile emits.
                down.push_str(&format!("{flow},{},1400,1\n", i as f64 * STEP));
            }
        }
        let mut up = String::from("0,0.0,300,-1\n");
        up.push_str("0,0.5,300,-1\n");

        let merged = merge_directional(&down, &up);
        let rows = concat_flows(parse_rows(&merged));
        assert!(!rows.is_empty());

        // Span must be the SUM of the per-flow spans, not one flow's.
        let one_flow_span = (PER_FLOW - 1) as f64 * STEP;
        let span = rows.iter().map(|r| r.0).fold(f64::MIN, f64::max);
        assert!(
            span >= one_flow_span * f64::from(FLOWS),
            "chain collapsed: span {span:.2}s is not the {} chained flows' \
             {:.2}s - the traces were superimposed, not concatenated",
            FLOWS,
            one_flow_span * f64::from(FLOWS)
        );

        // Every downstream record survives exactly once: the merge must not drop
        // or duplicate the chain.
        let down_count = rows.iter().filter(|r| r.2 > 0).count();
        assert_eq!(
            down_count,
            PER_FLOW * FLOWS as usize,
            "every chained downstream record must survive the merge exactly once"
        );

        // And the rate must be the RECORDED rate, not the chain length times it.
        let recorded_rate = 1.0 / STEP;
        let actual_rate = down_count as f64 / span;
        assert!(
            (actual_rate - recorded_rate).abs() < recorded_rate * 0.2,
            "replayed downstream rate {actual_rate:.1}/s must match the recorded \
             {recorded_rate:.1}/s; superimposing the chain multiplies it"
        );
    }

    #[test]
    fn directional_merge_keeps_upstream_alive_across_the_whole_span() {
        // Downstream: 60 s of video-ish records, almost nothing upstream.
        let mut down = String::from("t,size,dir\n");
        for i in 0..120 {
            down.push_str(&format!("{},1400,1\n", i as f64 * 0.5));
        }
        down.push_str("0.1,80,-1\n");
        // Upstream donor: a busy 4 s browse capture.
        let mut up = String::from("t,size,dir\n");
        for i in 0..40 {
            up.push_str(&format!("{},300,-1\n", i as f64 * 0.1));
            up.push_str(&format!("{},900,1\n", i as f64 * 0.1));
        }

        let merged = merge_directional(&down, &up);
        let rows = concat_flows(parse_rows(&merged));
        assert!(!rows.is_empty(), "merge produced nothing");
        // Downstream shape is the video's: the donor's downstream is discarded.
        let down_sizes: std::collections::HashSet<i64> =
            rows.iter().filter(|r| r.2 > 0).map(|r| r.1).collect();
        assert_eq!(
            down_sizes,
            std::collections::HashSet::from([1400]),
            "downstream must come only from the downstream capture"
        );
        // Upstream now has real capacity, and clears the starvation threshold the
        // unmerged video trace failed.
        let (rate, _) = upstream_capacity(&merged);
        assert!(
            rate >= MIN_UPSTREAM_TOKENS_PER_SEC,
            "merged profile must be able to carry a tunnel, got {rate:.2}/s"
        );
        // Tiled to the END: upstream tokens must exist in the last quarter, not
        // just where the short donor originally sat.
        let span = rows.iter().map(|r| r.0).fold(f64::MIN, f64::max);
        let late_up = rows.iter().filter(|r| r.2 < 0 && r.0 > span * 0.75).count();
        assert!(
            late_up > 0,
            "upstream must still be alive at the end of the span, not only at the start"
        );
        // Time-ordered, as MeasuredProfile::from_csv expects.
        assert!(
            rows.windows(2).all(|w| w[0].0 <= w[1].0),
            "merged rows must be in time order"
        );
    }

    #[test]
    fn upstream_capacity_separates_usable_cover_from_starving_cover() {
        // Download-shaped: one upstream record per ~4 s, everything else down.
        let mut video = String::from("t,size,dir\n");
        for i in 0..100 {
            video.push_str(&format!("{},1400,1\n", i as f64 * 0.4));
            if i % 10 == 0 {
                video.push_str(&format!("{},80,-1\n", i as f64 * 0.4));
            }
        }
        let (rate, bps) = upstream_capacity(&video);
        assert!(
            rate < MIN_UPSTREAM_TOKENS_PER_SEC,
            "a download-shaped trace must read as too sparse, got {rate:.2}/s ({bps:.0} B/s)"
        );

        // Browse-shaped: upstream requests interleaved throughout.
        let mut browse = String::from("t,size,dir\n");
        for i in 0..100 {
            browse.push_str(&format!("{},300,-1\n", i as f64 * 0.05));
            browse.push_str(&format!("{},1400,1\n", i as f64 * 0.05));
        }
        let (rate2, _) = upstream_capacity(&browse);
        assert!(
            rate2 >= MIN_UPSTREAM_TOKENS_PER_SEC,
            "a browse-shaped trace must read as usable, got {rate2:.2}/s"
        );
        assert!(rate2 > rate, "browse cover must out-carry download cover");
    }

    #[test]
    fn replay_drops_overdue_tokens_instead_of_shifting_the_schedule() {
        let base = Instant::now();
        let max = Duration::from_millis(1500);
        // On time, and within the drift allowance: emit.
        assert!(!drop_if_overdue(
            base,
            10.0,
            base + Duration::from_secs_f64(10.0),
            max
        ));
        assert!(!drop_if_overdue(
            base,
            10.0,
            base + Duration::from_secs_f64(11.4),
            max
        ));
        // Past the allowance (a real carrier stall): drop, do NOT re-pin.
        assert!(drop_if_overdue(
            base,
            10.0,
            base + Duration::from_secs_f64(12.0),
            max
        ));
        // Dropping leaves the origin untouched, so a LATER token still fires at
        // its original absolute deadline - this is what keeps the envelope's rate
        // independent of the stall (and therefore of app load).
        let later_deadline = base + Duration::from_secs_f64(20.0);
        assert!(!drop_if_overdue(base, 20.0, later_deadline, max));
        // Contrast: the generative path re-pins, which MOVES every later deadline.
        let repinned = rebase_on_stall(base, 10.0, base + Duration::from_secs_f64(12.0), max);
        assert_ne!(repinned, base, "generative mode re-pins the origin");
        assert!(
            repinned + Duration::from_secs_f64(20.0) > later_deadline,
            "re-pinning pushes later tokens out, changing the emitted rate"
        );
    }

    #[test]
    fn replay_shared_origin_preserves_up_down_coupling() {
        // Same spawn moment for both directions (skew = 0), to isolate the pinning
        // regime from the unavoidable spawn skew. The captured flow's first upstream
        // token is at t=0.10 and its first downstream token at t=0.40 - a 0.30s
        // request->response coupling that the replay must reproduce.
        let now = Instant::now();
        let (t_up, t_down) = (0.10_f64, 0.40_f64);

        // pace_base: replay pins to the shared origin (ignores first_t); generative
        // subtracts it (re-zeroes on this direction's first token).
        assert_eq!(pace_base(now, t_up, true), now);
        assert_eq!(
            pace_base(now, t_up, false),
            now.checked_sub(Duration::from_secs_f64(t_up)).unwrap()
        );

        // Reproduced first-up -> first-down gap under each regime (deadline = base + t).
        let coupling = |replay: bool| -> f64 {
            let up = pace_base(now, t_up, replay) + Duration::from_secs_f64(t_up);
            let down = pace_base(now, t_down, replay) + Duration::from_secs_f64(t_down);
            down.saturating_duration_since(up).as_secs_f64()
        };
        // Shared origin (the fix): reproduces the real 0.30s coupling.
        assert!(
            (coupling(true) - 0.30).abs() < 1e-6,
            "shared origin preserves the up/down coupling, got {}",
            coupling(true)
        );
        // Per-direction (the old replay behaviour): both first tokens fire at `now`,
        // so the coupling is flattened to 0 - a cross-direction timing tell.
        assert!(
            coupling(false).abs() < 1e-6,
            "per-direction pinning flattens the coupling"
        );
    }

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
            read_profile(one.to_str().unwrap(), 42, None).unwrap(),
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

        let out = read_profile(dir, 3, None).unwrap();
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
            read_profile(dir, 3, None),
            read_profile(dir, 3, None),
            "same seed -> same chain"
        );
        let variants: std::collections::HashSet<String> = (0u64..20)
            .filter_map(|s| read_profile(dir, s, None))
            .collect();
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
    fn a_library_root_pools_downstream_classes_but_not_the_upstream_one() {
        use std::sync::atomic::{AtomicU32, Ordering};
        static CTR: AtomicU32 = AtomicU32::new(0);
        let base = std::env::temp_dir().join(format!(
            "proteus_updir_{}_{}",
            std::process::id(),
            CTR.fetch_add(1, Ordering::Relaxed)
        ));
        let big = |marker: usize| {
            let mut s = String::from("t,size,dir\n");
            for i in 0..6000 {
                s.push_str(&format!("{i}.0,{marker},1\n"));
            }
            assert!(s.len() as u64 > MIN_TRACE_BYTES);
            s
        };
        let browse = base.join("browse");
        let upstream = base.join(mirage_common::proteus_switch::UPSTREAM_COVER_CLASS);
        std::fs::create_dir_all(&browse).unwrap();
        std::fs::create_dir_all(&upstream).unwrap();
        std::fs::write(browse.join("0.csv"), big(1401)).unwrap();
        std::fs::write(browse.join("1.csv"), big(1402)).unwrap();
        // Marker 999 identifies the upstream class, which is recorded dense and
        // gap-free to carry flow control - not to be worn as downstream cover.
        std::fs::write(upstream.join("0.csv"), big(999)).unwrap();

        let dir = base.to_str().unwrap();
        let mut saw_upstream = false;
        for seed in 0u64..24 {
            let out = read_profile(dir, seed, None).unwrap();
            if out.lines().any(|l| l.split(',').nth(2) == Some("999")) {
                saw_upstream = true;
            }
        }
        assert!(
            !saw_upstream,
            "upstream-class traces must never be pooled as DOWNSTREAM cover: \
             they are 2-3s dense bursts, and mixing them makes a session's cover \
             rate a lottery between classes"
        );

        // But a library holding ONLY the upstream class still paces. An empty
        // schedule does not degrade to unpaced - it hangs the session with zero
        // bytes - so the exclusion must never be allowed to empty the pool.
        std::fs::remove_dir_all(&browse).unwrap();
        let only_up = read_profile(dir, 5, None);
        assert!(
            only_up.is_some_and(|s| s.lines().any(|l| l.split(',').nth(2) == Some("999"))),
            "an upstream-only library must still yield a schedule rather than none"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    /// Nothing that is not a data row may become one.
    ///
    /// A client SYNCS ITS TRACE LIBRARY FROM THE BRIDGE, so these bytes come off
    /// the network and this parser is remotely reachable. Two boundary cases,
    /// each one notch past where the previous fix stopped:
    ///
    /// - three commas in a comment splits into 3 fields whose first is
    ///   `# source_url=...` and fails to parse, so the line is skipped BY LUCK;
    ///   four commas splits into 4, the last three parse, and a record is
    ///   injected.
    /// - a `#` check catches both of those and still misses a BOM-prefixed
    ///   comment, because U+FEFF is not whitespace and survives `trim`.
    ///
    /// Hence the positive rule: a row must START like a number. This test pins
    /// the boundary and one past it in both directions.
    #[test]
    fn only_things_that_look_like_records_are_parsed_as_records() {
        // Real rows, both the bare and the flow-tagged shape.
        assert_eq!(parse_rows("0.019482,243,-1").len(), 1, "bare row");
        assert_eq!(parse_rows("3,0.019482,243,-1").len(), 1, "flow-tagged row");

        // Everything a trace file legitimately contains around them.
        for benign in [
            "t,size,dir",
            "flow,t,size,dir",
            "",
            "   ",
            "\t",
            "# mirage-cover-trace v1",
            "# recorded_at=2025-08-07T00:00:00Z",
        ] {
            assert!(
                parse_rows(benign).is_empty(),
                "non-record line must not parse: {benign:?}"
            );
        }

        // The injection boundary: 3 commas (skipped by luck) and 4 (the defect).
        for hostile in [
            "# source_url=https://x/?a=1,2,3",
            "# source_url=https://x/?a=b,0.5,100,1",
            "# source_url=https://x/?a=b,c,0.5,100,1",
            // ...and the same one past a `#`-only check.
            "\u{FEFF}# source_url=https://x/?a=b,0.5,100,1",
            "  \u{FEFF}# source_url=https://x/?a=b,0.5,100,1",
            "\u{00A0}# source_url=https://x/?a=b,0.5,100,1",
        ] {
            assert!(
                parse_rows(hostile).is_empty(),
                "must not inject a record from: {hostile:?}"
            );
        }

        // And a whole file still parses to exactly its data rows.
        let file = "\u{FEFF}# mirage-cover-trace v1\n\
                    # source_url=https://x/?a=b,0.5,100,1\n\
                    t,size,dir\n\
                    0.0,517,1\n\
                    0.25,1200,-1\n";
        let rows = parse_rows(file);
        assert_eq!(rows.len(), 2, "exactly the two real rows, got {rows:?}");
        assert_eq!(rows[0], (0, 0.0, 517, 1));
        assert_eq!(rows[1], (0, 0.25, 1200, -1));
    }

    /// A tiled direction must be detected, and ordinary cover must not trip it.
    ///
    /// This is the one defect in the shaping design that is NOT a statistical
    /// accumulation problem. Every other divergence argument is about how many
    /// observations a censor needs and what the constant is. An exactly repeated
    /// upstream block is a single-flow deterministic signature - one period check
    /// or one FFT, no reference class, no threshold - and it shipped inside the
    /// configuration the operator docs recommended.
    #[test]
    fn a_periodically_tiled_direction_is_detected() {
        // Ordinary two-way cover: no repeated block. Must NOT fire.
        let mut natural = String::from("t,size,dir\n");
        for i in 0..60 {
            natural.push_str(&format!(
                "{:.3},{},1\n",
                i as f64 * 0.05,
                900 + (i * 37) % 400
            ));
            natural.push_str(&format!(
                "{:.3},{},-1\n",
                i as f64 * 0.05 + 0.01,
                60 + (i * 17) % 90
            ));
        }
        assert_eq!(
            tiled_direction(&natural),
            None,
            "natural cover must not be flagged - a false positive here would refuse good profiles"
        );

        // What `merge_directional` produces: one upstream block, repeated.
        let block: [i64; 5] = [120, 88, 143, 99, 210];
        let mut tiled = String::from("t,size,dir\n");
        for i in 0..60 {
            tiled.push_str(&format!(
                "{:.3},{},1\n",
                i as f64 * 0.05,
                900 + (i * 37) % 400
            ));
        }
        for rep in 0..8 {
            for (j, sz) in block.iter().enumerate() {
                let t = rep as f64 * 0.37 + j as f64 * 0.01;
                tiled.push_str(&format!("{t:.3},{sz},-1\n"));
            }
        }
        let hit = tiled_direction(&tiled).expect("a tiled upstream must be detected");
        assert!(!hit.0, "the UPSTREAM is the tiled direction here");
        assert_eq!(hit.1, block.len(), "reports the repeated block length");

        // The period finder itself, at its boundary: two repeats is not enough
        // evidence, three is.
        assert_eq!(smallest_exact_period(&[1, 2, 3, 1, 2, 3]), Some(3));
        assert_eq!(smallest_exact_period(&[1, 2, 3, 4, 5, 6]), None);
        // A period that does not divide the length evenly is not a true period.
        assert_eq!(smallest_exact_period(&[1, 2, 1, 2, 1]), None);
    }

    /// The check must catch what `merge_directional` ACTUALLY builds.
    ///
    /// `a_periodically_tiled_direction_is_detected` tests the detector against a
    /// hand-written tiled sequence - which passes even if `merge_directional`
    /// stops tiling, or tiles differently, or the two are wired together wrongly.
    /// This drives the real merge path, so it fails if the plumbing breaks rather
    /// than only if the mathematics does.
    #[test]
    fn the_real_merge_path_produces_a_schedule_the_check_catches() {
        // A downstream capture with no internal repetition.
        let mut down = String::from("t,size,dir\n");
        for i in 0..80 {
            down.push_str(&format!(
                "{:.3},{},1\n",
                i as f64 * 0.05,
                800 + (i * 53) % 500
            ));
        }
        // A SHORT upstream capture from a different flow - the configuration the
        // operator docs used to recommend. `merge_directional` tiles this across
        // the downstream span.
        let mut up = String::from("t,size,dir\n");
        for (j, sz) in [110i64, 74, 156, 92].iter().enumerate() {
            up.push_str(&format!("{:.3},{sz},-1\n", j as f64 * 0.02));
        }

        // One profile: nothing to tile, must stay clean.
        assert_eq!(
            schedule_is_tiled(&down, None),
            None,
            "a single joint capture must never be flagged"
        );

        // Split profiles: the merge tiles, and the check must see it.
        let hit = schedule_is_tiled(&down, Some(&up))
            .expect("merge_directional tiles the upstream; the check must catch it");
        assert!(!hit.0, "the tiled direction is UPSTREAM");
        assert_eq!(
            hit.1, 4,
            "block length is the upstream capture's record count"
        );
    }

    /// The fallback to generic cover must be REPORTABLE, not merely correct.
    ///
    /// `read_profile` returned a schedule either way, so a missing per-host
    /// directory was indistinguishable from a present one at every layer above
    /// it. Every measurement taken against this code ran on the generic branch -
    /// the one the selection comment calls separable - and no config, log or
    /// diagnostic said which branch was live. Resolving the branch as a VALUE is
    /// what makes the startup warning and the pinned-library refusal possible.
    #[test]
    fn profile_match_distinguishes_generic_from_host_matched() {
        use std::sync::atomic::{AtomicU32, Ordering};
        static CTR: AtomicU32 = AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "proteus_match_{}_{}",
            std::process::id(),
            CTR.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).expect("mkdir");
        std::fs::write(root.join("gen.csv"), "t,size,dir\n0.0,1,1\n").expect("write");
        let root_s = root.to_str().expect("utf8");

        // No per-host subdir: generic, and it names the directory that is missing
        // so an operator can act on it.
        let m = resolve_profile_match(root_s, Some("www.example.org:443"));
        assert!(m.is_generic(), "no per-host dir must resolve as generic");
        match &m {
            ProfileMatch::Generic { wanted, .. } => {
                assert!(wanted.ends_with("www.example.org"), "names what is missing");
            }
            other => panic!("expected Generic, got {other:?}"),
        }
        // And it still reads the generic traces - reporting the branch must not
        // change which bytes get worn.
        assert_eq!(m.effective_path(root_s), root);

        // Per-host subdir present: host-matched.
        std::fs::create_dir_all(root.join("www.example.org")).expect("mkdir host");
        let m = resolve_profile_match(root_s, Some("www.example.org:443"));
        assert!(!m.is_generic());
        assert_eq!(m, ProfileMatch::HostMatched(root.join("www.example.org")));

        // A pinned FILE has no host to match against, and must not be reported as
        // a degraded library.
        assert!(!resolve_profile_match(
            root.join("gen.csv").to_str().expect("utf8"),
            Some("www.example.org")
        )
        .is_generic());
        // Neither must a config with no cover host at all.
        assert!(!resolve_profile_match(root_s, None).is_generic());

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The WRITER (`mirage-cover`) and the READER (here) must derive the same
    /// directory name from the same cover host.
    ///
    /// They live in crates that do not depend on each other and the lookup fails
    /// open, so a divergence would produce a library whose per-host traces are
    /// never found - identical, from outside, to having recorded none. This
    /// asserts agreement through the shared implementation on inputs that differ
    /// in case and port, which is exactly how the two ends receive them: a client
    /// holds `reality_sni` ("www.example.org") and a bridge holds
    /// `reality_cover_addr` ("www.example.org:443").
    #[test]
    fn writer_and_reader_agree_on_the_per_host_directory_name() {
        use mirage_common::proteus_switch::sanitize_cover_host;
        use std::sync::atomic::{AtomicU32, Ordering};
        static CTR: AtomicU32 = AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "proteus_agree_{}_{}",
            std::process::id(),
            CTR.fetch_add(1, Ordering::Relaxed)
        ));
        // Record as the bridge would, from `host:port`.
        let written = root.join(sanitize_cover_host("WWW.Example.ORG:443"));
        std::fs::create_dir_all(&written).expect("mkdir");
        std::fs::write(written.join("0.csv"), "t,size,dir\n0.0,555,1\n").expect("write");
        let root_s = root.to_str().expect("utf8");

        // Look up as the client would, from a bare SNI in different case.
        for host in ["www.example.org", "WWW.Example.ORG", "www.example.org:443"] {
            assert_eq!(
                resolve_profile_match(root_s, Some(host)),
                ProfileMatch::HostMatched(written.clone()),
                "reader must find the directory the writer created, given {host:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn read_profile_target_conditions_on_cover_host_and_is_traversal_safe() {
        use std::sync::atomic::{AtomicU32, Ordering};
        static CTR: AtomicU32 = AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "proteus_site_{}_{}",
            std::process::id(),
            CTR.fetch_add(1, Ordering::Relaxed)
        ));
        // A generic trace in the library ROOT, and a per-site subdir for one host.
        std::fs::create_dir_all(root.join("www.example.org")).unwrap();
        std::fs::write(root.join("gen.csv"), "t,size,dir\n0.0,999,1\n1.0,999,1\n").unwrap();
        std::fs::write(
            root.join("www.example.org/0.csv"),
            "t,size,dir\n0.0,555,1\n1.0,555,1\n",
        )
        .unwrap();
        let root_s = root.to_str().unwrap();

        // Matching cover host -> wears the site's own trace (555), not the generic (999).
        let site = read_profile(root_s, 1, Some("www.example.org:443")).unwrap();
        assert!(
            site.contains(",555,"),
            "target-conditioned: uses the site subdir"
        );
        assert!(
            !site.contains(",999,"),
            "does not fall back to the generic root"
        );

        // No host / unknown host -> falls back to the library root (generic).
        assert!(read_profile(root_s, 1, None).unwrap().contains(",999,"));
        assert!(read_profile(root_s, 1, Some("no.such.host"))
            .unwrap()
            .contains(",999,"));

        // Traversal safety: '/' is stripped so a host is always one path component,
        // and a pure `.`/`..` sanitizes to empty (falls back, never escapes root).
        assert_eq!(sanitize_host("../../etc"), "....etc");
        assert_eq!(sanitize_host(".."), "");
        assert_eq!(sanitize_host("Www.Example.ORG:443"), "www.example.org");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn the_pump_sizes_every_frame_against_the_carrier_it_was_given() {
        // The arithmetic tests above prove `Carrier` is right. This one proves the
        // PUMP uses it: it records what the pump actually hands the carrier and
        // checks each write lands on a token's wire size once that carrier's own
        // framing is added. A regression that reverts the pump to a fixed
        // overhead passes the arithmetic tests and fails this one.
        use std::sync::{Arc, Mutex};

        /// A carrier that records the length of every write and discards it.
        struct Recorder(Arc<Mutex<Vec<usize>>>);
        impl AsyncWrite for Recorder {
            fn poll_write(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                self.0.lock().unwrap().push(buf.len());
                Poll::Ready(Ok(buf.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        impl AsyncRead for Recorder {
            fn poll_read(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                _: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                // Never EOF: an EOF would end the session under test early.
                Poll::Pending
            }
        }

        for carrier in [
            Carrier::tls(),
            Carrier::ss2022(),
            Carrier::websocket_client(),
            Carrier::websocket_client().over_tls(),
            Carrier::raw(),
        ] {
            let seed = 0x5EED_1234_ABCD_0001u64;
            let seen = Arc::new(Mutex::new(Vec::new()));
            let proc = CoverProcess::from_class_seed("browse", seed);
            let ch = PacedChannel::spawn(
                Recorder(Arc::clone(&seen)),
                ScheduleStream::new(proc.clone(), seed),
                Dir::Down,
                carrier,
            );
            // Let the pump emit; the schedule's own gaps decide how many.
            tokio::time::sleep(Duration::from_millis(400)).await;
            drop(ch);

            // The token sizes the same schedule yields, as wire sizes.
            let mut sched = ScheduleStream::new(proc, seed);
            let mut wire_sizes = std::collections::HashSet::new();
            for _ in 0..4096 {
                let t = sched.next_for(Dir::Down);
                wire_sizes.insert(t.bytes.max(carrier.min_token()));
            }

            let frames = seen.lock().unwrap().clone();
            assert!(
                !frames.is_empty(),
                "{carrier:?}: the pump emitted nothing to check"
            );
            for f in frames {
                let wire = f + carrier.overhead(f);
                assert!(
                    wire_sizes.contains(&wire),
                    "{carrier:?}: a {f}-byte frame is {wire} on the wire, which is not \
                     any token size in the schedule (frame was sized for a different carrier)"
                );
            }
        }
    }

    /// A replay profile with a realistically SPREAD size distribution.
    ///
    /// The generative `browse` process emits mostly-1400 sizes, so alignment has
    /// almost nothing to choose between and a test built on it cannot tell a
    /// working aligner from a broken one. Real captures are not like that - the
    /// repo's own show 39-58% of tokens under a tenth of the largest - so these
    /// fixtures use a bimodal mix the way a real page load does.
    fn spread_profile() -> std::sync::Arc<crate::pacer::MeasuredProfile> {
        let mut csv = String::new();
        for i in 0..400 {
            let t = f64::from(i) * 0.05;
            // Two thirds small (reading gaps, acks), one third full records.
            let sz = if i % 3 == 0 { 1400 } else { 60 + (i % 7) * 40 };
            csv.push_str(&format!("{t},{sz},1\n"));
        }
        std::sync::Arc::new(crate::pacer::MeasuredProfile::from_csv(&csv).expect("fixture profile"))
    }

    #[test]
    fn alignment_preserves_the_size_multiset_exactly() {
        // THE property that makes demand alignment free. If it holds, total
        // bytes and every size-marginal feature are unchanged by construction -
        // eleven of the fourteen the flow classifier uses. If it ever breaks,
        // alignment stops being a permutation and becomes a shaper, and the
        // entropy-floor argument no longer covers it.
        //
        // Compared over emitted PLUS still-buffered, because the aligner holds a
        // window in flight: after N emissions it has pulled N + ALIGN_WINDOW.
        let seed = 0xA11_1600_D511_1234u64;
        let profile = spread_profile();

        let mut al = SizeAligner::new(seed);
        let mut aligned = ScheduleStream::replay(profile.clone(), seed);
        let mut emitted: Vec<usize> = Vec::new();
        for i in 0..600 {
            emitted.push(al.next(&mut aligned, Dir::Down, i % 3 != 0).bytes);
        }
        let buffered = al.pool.len();
        let mut got: Vec<usize> = emitted.clone();
        got.extend(al.pool.iter().copied());

        let mut plain = ScheduleStream::replay(profile, seed);
        let mut want: Vec<usize> = Vec::new();
        for _ in 0..(600 + buffered) {
            want.push(plain.next_for(Dir::Down).bytes);
        }

        want.sort_unstable();
        got.sort_unstable();
        assert_eq!(
            want, got,
            "alignment must emit exactly the captured sizes, only in a different order"
        );
        assert_eq!(
            want.iter().sum::<usize>(),
            got.iter().sum::<usize>(),
            "total bytes must be identical - this is what makes alignment free"
        );
    }

    #[test]
    fn alignment_is_disabled_because_it_leaked_activity() {
        // Kept as a REGRESSION GUARD, inverted from what it used to assert.
        //
        // It used to check that data-bearing slots carry more than idle ones -
        // which the aligner did, and which turned out to be the bug. Idle windows
        // then collect the small records and active windows the big ones, so the
        // per-window size distribution tracks user activity even though the
        // global multiset is untouched. Measured on a live cluster: downstream
        // separability 0.699 against a 0.544 control, with `size_stddev` winning.
        //
        // So the property to hold now is the opposite: with alignment off, what a
        // slot carries must NOT depend on whether the application had data.
        let seed = 0x0FFE_1234_5678_9ABCu64;
        let mut stream = ScheduleStream::replay(spread_profile(), seed);
        let mut al = SizeAligner::new(seed);

        let (mut with_data, mut without) = (0usize, 0usize);
        let (mut n_with, mut n_without) = (0usize, 0usize);
        for i in 0..4000 {
            let has = i % 2 == 0;
            let sz = al.next(&mut stream, Dir::Down, has).bytes;
            if has {
                with_data += sz;
                n_with += 1;
            } else {
                without += sz;
                n_without += 1;
            }
        }
        let a = with_data as f64 / n_with as f64;
        let b = without as f64 / n_without as f64;
        let skew = (a - b).abs() / b.max(1.0);
        assert!(
            skew < 0.05,
            "with alignment disabled, a slot's size must not track whether the app \
             had data: {a:.0} with vs {b:.0} without ({:.1}% skew). Any skew here is \
             an activity signal a censor reads straight off the window.",
            skew * 100.0
        );
    }

    #[test]
    fn carrier_overheads_match_the_real_wire_formats() {
        // A mid-size payload, so the WebSocket length field is the 2-byte form.
        let p = 1000;
        assert_eq!(
            Carrier::tls().overhead(p),
            21,
            "5-byte header + 16-byte tag"
        );
        assert_eq!(
            Carrier::ss2022().overhead(p),
            34,
            "sealed length (2 + 16) + payload tag (16)"
        );
        assert_eq!(
            Carrier::websocket_server().overhead(p),
            4,
            "opcode+len+ext16"
        );
        assert_eq!(
            Carrier::websocket_client().overhead(p),
            8,
            "same, plus the 4-byte mask key"
        );
        assert_eq!(Carrier::raw().overhead(p), 0);
        // Composition: the ws carrier over client-originated TLS pays both.
        assert_eq!(Carrier::websocket_client().over_tls().overhead(p), 8 + 21);
        // The WebSocket length field is a step function of the payload.
        assert_eq!(
            Carrier::websocket_server().overhead(125),
            2,
            "1-byte length"
        );
        assert_eq!(
            Carrier::websocket_server().overhead(126),
            4,
            "16-bit length"
        );
        assert_eq!(
            Carrier::websocket_server().overhead(65_536),
            10,
            "64-bit length"
        );
    }

    #[test]
    fn payload_for_wire_is_the_maximal_inverse_of_overhead() {
        // The property the pacer depends on: the frame it builds NEVER exceeds
        // the token's wire size (exceeding is what split a near-MTU record across
        // the path MSS), and is the largest such frame (undershooting wastes
        // envelope and shifts the size distribution the other way).
        let carriers = [
            Carrier::tls(),
            Carrier::ss2022(),
            Carrier::websocket_server(),
            Carrier::websocket_client(),
            Carrier::websocket_client().over_tls(),
            Carrier::raw(),
        ];
        for c in carriers {
            for wire in [c.min_token(), 100, 125, 130, 576, 1400, 1500, 9000, 65_600] {
                let p = c.payload_for_wire(wire);
                assert!(
                    p + c.overhead(p) <= wire,
                    "{c:?} at wire={wire}: {p} + {} exceeds the token",
                    c.overhead(p)
                );
                assert!(
                    p + 1 + c.overhead(p + 1) > wire,
                    "{c:?} at wire={wire}: {} is not maximal",
                    p
                );
            }
        }
    }

    #[test]
    fn a_near_mtu_token_stays_within_the_mtu_on_every_carrier() {
        // The ss2022 regression in one assertion. The pacer used to subtract a
        // fixed 21 (TLS's cost) whatever the carrier was, so an SS-2022 record
        // went out at token + 13 - over a 1500-byte path MTU, which TCP then
        // split into a full segment plus a tail. `size_entropy_bits` separated
        // idle from active at 0.867 on exactly that shape.
        let token = 1500usize;
        for c in [
            Carrier::tls(),
            Carrier::ss2022(),
            Carrier::websocket_server(),
            Carrier::websocket_client(),
            Carrier::websocket_client().over_tls(),
            Carrier::raw(),
        ] {
            let frame = c.payload_for_wire(token);
            assert!(
                frame + c.overhead(frame) <= token,
                "{c:?} puts {} bytes on the wire for a {token}-byte token",
                frame + c.overhead(frame)
            );
        }
        // And specifically: the old arithmetic really did overshoot.
        let old_frame = token - 21;
        assert_eq!(
            old_frame + Carrier::ss2022().overhead(old_frame),
            token + 13,
            "the fixed-21 assumption overshoots SS-2022 by the 34-21 difference"
        );
    }

    #[test]
    fn build_frame_targets_wire_size_and_carries_real() {
        let token = 1400usize;
        let frame_len = Carrier::tls().payload_for_wire(token);
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
        let frame_len = Carrier::tls().payload_for_wire(Carrier::tls().min_token());
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
        let mut client = PacedChannel::spawn(
            a,
            ScheduleStream::new(proc.clone(), seed),
            Dir::Up,
            Carrier::raw(),
        );
        let mut bridge = PacedChannel::spawn(
            b,
            ScheduleStream::new(proc, seed),
            Dir::Down,
            Carrier::raw(),
        );

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
        let mut client = PacedChannel::spawn(
            a,
            ScheduleStream::new(proc.clone(), seed),
            Dir::Up,
            Carrier::raw(),
        );
        let mut bridge = PacedChannel::spawn(
            b,
            ScheduleStream::new(proc, seed),
            Dir::Down,
            Carrier::raw(),
        );

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
        let mut client = PacedChannel::spawn(
            a,
            ScheduleStream::new(proc.clone(), seed),
            Dir::Down,
            Carrier::raw(),
        );
        let mut bridge =
            PacedChannel::spawn(b, ScheduleStream::new(proc, seed), Dir::Up, Carrier::raw());

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
