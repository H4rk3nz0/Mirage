//! Frame-padding and timing-jitter transport layer for Mirage.
//!
//! # Overview
//!
//! Wraps any `AsyncRead + AsyncWrite` transport stream with obfuscation
//! mechanisms that harden it against flow-shape classifiers. **Scope matters**
//! (see *Threat model fit* below): the default, event-driven config defeats
//! MARGINAL length/timing classifiers (the size histogram, the inter-gap
//! distribution) but does NOT morph the ordered direction/burst SEQUENCE that a
//! website-fingerprinting attack (Deep Fingerprinting, Tik-Tok, RF) keys on. The
//! strict constant-bit-rate mode (`cbr_frame_bytes`) is the WF-grade profile -
//! a fixed size at a fixed cadence makes the whole trace destination-independent
//! - but it is opt-in (its latency/bandwidth cost is why it is off by default).
//!
//! - **Size bucketing**: every flush produces exactly one padded frame whose
//!   total wire size is rounded up to the next value in [`PAD_FRAME_BUCKETS`]
//!   (64, 128, 256, ... 65536 bytes). The unused tail is filled with
//!   cryptographically random bytes, collapsing the per-frame length MARGINAL
//!   to at most 11 values. (The ordered *sequence* of buckets, and packet
//!   direction, still leak - only CBR mode hides those.)
//!
//! - **Write jitter**: a uniform-random delay drawn from `[0, max_jitter_ms]`
//!   is inserted before each padded frame is written to the wire. This
//!   decorrelates the marginal inter-frame timing distribution from the
//!   application's natural rhythm. It does NOT hide the coarse burst structure a
//!   timing-based WF classifier uses.
//!
//! - **Chaff frames**: when `chaff_interval_ms` is set, the writer task
//!   emits a zero-payload padded frame at that cadence even during idle
//!   periods. This prevents "silence -> burst" transitions from leaking
//!   session-boundary information.
//!
//! # Wire format
//!
//! ```text
//! +----------------------+-----------------------+----------------------+
//! |  payload_len [u16 LE]|  payload [payload_len]| random padding [*]  |
//! +----------------------+-----------------------+----------------------+
//!  <- 2 bytes ------------------------------------ bucket_size bytes total ->
//! ```
//!
//! `bucket_size = min b  in  PAD_FRAME_BUCKETS s.t. b >= payload_len + 2`.
//! Both sides independently derive `bucket_size` from `payload_len` using
//! the shared bucket table - no extra negotiation required.
//!
//! A `payload_len == 0` is a **chaff frame**; the receiver discards it
//! without delivering any bytes to the session layer.
//!
//! # Threat model fit
//!
//! - **T1 (signature DPI):** [ok] - padding composes on top of an already-
//!   camouflaged transport (Reality, Meek, WS, ...).
//! - **T2 (active prober):** [ok] - the padding layer is fully transparent to
//!   active probers; they see the underlying transport's behaviour.
//! - **T3 (ML on MARGINAL flow shape):** [ok] - size bucketing defeats
//!   length-histogram classifiers, timing jitter decorrelates the inter-gap
//!   distribution, and chaff hides idle->burst transitions.
//! - **T3' (website fingerprinting on the ORDERED trace, e.g. DF/Tik-Tok):**
//!   [partial] - the default config leaves the bucket-sequence + direction
//!   sequence intact, so a WF CNN can still classify the destination on a
//!   single isolated page-load. Two mitigations: (a) strict CBR mode
//!   (`cbr_frame_bytes` + fixed cadence) makes the trace destination-
//!   independent; (b) whole-device TUN mode muxes all apps into one flow, the
//!   open-world condition under which published WF accuracy collapses. Neither
//!   is on by default, so treat WF as an *unmitigated* risk for a SOCKS-proxied
//!   single-page browse unless CBR is enabled.
//!
//! # Usage
//!
//! ```rust,no_run
//! # use mirage_transport_pad::{PaddedStream, PadConfig};
//! # async fn example<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>(transport_stream: S) {
//! // Wrap any transport stream before handing to the Mirage session layer.
//! let padded = PaddedStream::wrap(transport_stream, PadConfig::default());
//! // Use `padded` as a normal AsyncRead + AsyncWrite stream.
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::VecDeque;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

/// Frame size buckets used for payload padding.
///
/// Each flushed payload is padded so the total frame (header + payload +
/// padding) equals the smallest value in this table that is >=
/// `payload_len + 2`. The 2-byte offset accounts for the `payload_len`
/// header.
///
/// The ladder is deliberately NOT a power-of-two comb. An exact `2^n` size on
/// every frame is a zero-false-positive passive signature - no real protocol
/// clusters its record sizes on exact powers of two. Instead the large buckets
/// are multiples of the common Ethernet TCP MSS (1448 B), so bulk transfer looks
/// like ordinary segmented TLS, and the small buckets are non-`2^n` values. Both
/// peers derive the frame size from the payload-length header, so this set MUST
/// stay a shared constant (a per-connection random comb would need a shared seed
/// the pad layer, which sits under the carrier handshake, does not have).
pub const PAD_FRAME_BUCKETS: &[usize] = &[
    96, 208, 400, 720, 1200, 1448, 2896, 5792, 11584, 23168, 46336, 65536,
];

// NOTE: there is no PAD capability bit. Padding is a per-connection size
// transform layered under a carrier, not a negotiated transport, so it is never
// advertised in a discovery announcement. A former `PAD_CAPABILITY_BIT = 1<<11`
// const was dead AND collided with `discovery::wire::transport_caps::CIRCUIT_RELAY`
// (also bit 11); it was removed to avoid the false impression that PAD is a
// registry-allocated capability.

// Configuration

/// Runtime configuration for [`PaddedStream`].
#[derive(Debug, Clone)]
pub struct PadConfig {
    /// Maximum random write-jitter in milliseconds.
    ///
    /// Before each padded frame is written to the wire, the writer waits
    /// for a uniformly-random duration in `[0, max_jitter_ms]`. Set to
    /// `0` to disable jitter (useful in tests or when the underlying
    /// transport already provides timing obfuscation).
    ///
    /// Typical range: 5-50 ms. Values above 100 ms will noticeably impact
    /// interactive latency.
    pub max_jitter_ms: u64,

    /// Chaff frame interval in milliseconds, or `None` to disable chaff.
    ///
    /// When set, the writer emits a zero-payload padded frame at this
    /// cadence during idle periods, preventing silence intervals from
    /// leaking session-state information to a passive observer.
    ///
    /// Overhead: one bucket-minimum (64 bytes) per interval. At 200 ms
    /// this is ~320 bytes/s - negligible on any modern link.
    ///
    /// Ignored when `cbr_frame_bytes` is `Some` (CBR mode supersedes
    /// all event-driven mechanisms).
    pub chaff_interval_ms: Option<u64>,

    /// Constant-bitrate (CBR) mode frame size in bytes.
    ///
    /// When set, the writer runs a strict periodic timer that fires every
    /// `cbr_interval_ms` milliseconds.  On each tick, it emits exactly one
    /// frame of this size, filling any space not occupied by real data with
    /// CSPRNG padding.  This produces a perfectly constant wire bitrate:
    ///
    /// ```text
    /// bitrate_bps = cbr_frame_bytes x 8 / (cbr_interval_ms / 1000)
    ///             = cbr_frame_bytes x 8000 / cbr_interval_ms
    /// ```
    ///
    /// Examples:
    ///
    /// | `cbr_frame_bytes` | `cbr_interval_ms` | Wire bitrate |
    /// |------------------:|------------------:|-------------:|
    /// |               256 |               100 |  ~20 kbit/s  |
    /// |              1024 |                10 | ~819 kbit/s  |
    /// |             65536 |                10 |  ~52 Mbit/s  |
    ///
    /// A passive observer sees a flat bitrate with zero inter-packet
    /// timing variation - immune to all known ML-based flow-shape
    /// classifiers.  Choose `cbr_frame_bytes` <= the effective MTU of
    /// the underlying path to avoid IP fragmentation.
    ///
    /// When `Some`, `max_jitter_ms` and `chaff_interval_ms` are ignored.
    /// `None` (default) - event-driven mode (jitter + chaff).
    pub cbr_frame_bytes: Option<usize>,

    /// Inter-frame interval for CBR mode, in milliseconds.
    ///
    /// Only meaningful when `cbr_frame_bytes` is `Some`.
    /// Default 10 ms.  Smaller values give higher resolution at the cost
    /// of more syscalls; the practical lower bound is the OS scheduler
    /// tick (~1-4 ms on most systems).
    pub cbr_interval_ms: u64,
}

impl Default for PadConfig {
    fn default() -> Self {
        Self {
            max_jitter_ms: 5,
            chaff_interval_ms: Some(200),
            cbr_frame_bytes: None,
            cbr_interval_ms: 10,
        }
    }
}

// PaddedStream

/// Padding and jitter wrapper over any `AsyncRead + AsyncWrite` stream.
///
/// All padding and jitter is handled transparently by two background Tokio
/// tasks (one reader, one writer). The `PaddedStream` itself is a lightweight
/// handle of channel endpoints.
///
/// Create with [`PaddedStream::wrap`].
pub struct PaddedStream {
    inbound_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    inbound_buf: VecDeque<u8>,
    outbound_tx: mpsc::UnboundedSender<Vec<u8>>,
    flush_tx: mpsc::UnboundedSender<()>,
}

impl PaddedStream {
    /// Wrap `inner` with frame padding and timing jitter.
    ///
    /// Spawns two background tasks that own the inner stream's read/write
    /// halves. The returned `PaddedStream` implements
    /// `AsyncRead + AsyncWrite + Unpin + Send + 'static`.
    ///
    /// When `config.cbr_frame_bytes` is `Some`, runs in CBR mode (constant
    /// bitrate, strict periodic timer). Otherwise runs in event-driven mode
    /// (jitter + chaff on demand).
    pub fn wrap<S>(inner: S, config: PadConfig) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (flush_tx, flush_rx) = mpsc::unbounded_channel::<()>();

        let (reader, writer) = tokio::io::split(inner);
        tokio::spawn(pad_reader_driver(
            reader,
            inbound_tx,
            config.cbr_frame_bytes,
        ));
        if let Some(frame_bytes) = config.cbr_frame_bytes {
            tokio::spawn(pad_cbr_writer_driver(
                writer,
                Duration::from_millis(config.cbr_interval_ms),
                frame_bytes,
                outbound_rx,
            ));
        } else {
            tokio::spawn(pad_writer_driver(writer, config, outbound_rx, flush_rx));
        }

        Self {
            inbound_rx,
            inbound_buf: VecDeque::new(),
            outbound_tx,
            flush_tx,
        }
    }
}

impl AsyncRead for PaddedStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        let me = self.get_mut();

        if !me.inbound_buf.is_empty() {
            let n = me.inbound_buf.len().min(buf.remaining());
            let taken: Vec<u8> = me.inbound_buf.drain(..n).collect();
            buf.put_slice(&taken);
            return Poll::Ready(Ok(()));
        }

        match me.inbound_rx.poll_recv(cx) {
            Poll::Ready(Some(chunk)) => {
                let n = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..n]);
                me.inbound_buf.extend(chunk[n..].iter().copied());
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // driver shut down -> EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for PaddedStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        // Surface a dead carrier: if the writer driver has exited (inner stream
        // errored/closed), the receiver is gone and `send` fails. Reporting the
        // error - instead of the old `let _ =` that reported phantom success
        // forever - lets `copy_bidirectional` / the mux writer detect the dead
        // carrier and tear the session down instead of blackholing writes.
        match self.get_mut().outbound_tx.send(buf.to_vec()) {
            Ok(()) => std::task::Poll::Ready(Ok(buf.len())),
            Err(_) => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "padded carrier closed",
            ))),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Best-effort flush hint. The flush channel only has a receiver in
        // event-driven mode; in CBR mode `flush_rx` is never taken, so a send
        // failure here is NORMAL, not a dead carrier - reporting it as an error
        // would break every flush in CBR mode. Dead-carrier detection lives in
        // `poll_write` (whose `outbound_tx` is consumed in both modes).
        let _ = self.get_mut().flush_tx.send(());
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Signal the writer driver to flush what's buffered; dropping this
        // handle then closes `outbound_tx`, and the driver flushes + issues a
        // real FIN on the inner stream (see the writer drivers' clean-exit
        // path), so TCP half-close propagates to the peer instead of being
        // swallowed. Reported ready since the flush completes asynchronously.
        let _ = self.get_mut().flush_tx.send(());
        std::task::Poll::Ready(Ok(()))
    }
}

// Frame helpers

/// Return the smallest bucket large enough to hold a frame with
/// `payload_len` bytes of payload (plus the 2-byte `payload_len` header).
///
/// Falls back to `payload_len + 2` for oversized payloads that exceed
/// every configured bucket.
fn bucket_size(payload_len: usize) -> usize {
    let needed = payload_len + 2;
    PAD_FRAME_BUCKETS
        .iter()
        .copied()
        .find(|&b| b >= needed)
        .unwrap_or(needed)
}

/// Maximum payload bytes per frame. The frame header is a `u16` length, so
/// a single frame can carry at most `u16::MAX - 1` payload bytes (the `- 1`
/// keeps `payload_len + 2` <= `u16::MAX` so the header never aliases a chaff
/// `0`). Larger writes are split across frames.
const MAX_FRAME_PAYLOAD: usize = (u16::MAX as usize) - 1; // 65534

/// Write `payload` to `writer` as one or more padded frames.
///
/// A payload larger than [`MAX_FRAME_PAYLOAD`] is SPLIT across frames: the
/// `payload_len` header is a `u16`, and a previous version cast the full
/// `usize` length to `u16`, silently truncating on >64 KiB bursts and
/// permanently desyncing the stream (the reader then mis-framed every
/// subsequent frame). The peer treats inbound as a byte stream, so
/// re-chunking is transparent. An empty payload emits exactly one chaff
/// frame.
async fn write_padded_frame<W>(writer: &mut W, payload: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if payload.is_empty() {
        return write_one_frame(writer, &[]).await;
    }
    for chunk in payload.chunks(MAX_FRAME_PAYLOAD) {
        write_one_frame(writer, chunk).await?;
    }
    Ok(())
}

/// Write exactly one padded frame: `[u16 LE: payload_len][payload][CSPRNG
/// padding]`, total `bucket_size(payload.len())` bytes. `payload` MUST be
/// <= [`MAX_FRAME_PAYLOAD`].
async fn write_one_frame<W>(writer: &mut W, payload: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    debug_assert!(payload.len() <= MAX_FRAME_PAYLOAD);
    let payload_len = payload.len();
    let frame_size = bucket_size(payload_len);
    let mut frame = vec![0u8; frame_size];

    frame[0..2].copy_from_slice(&(payload_len as u16).to_le_bytes());
    frame[2..2 + payload_len].copy_from_slice(payload);
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut frame[2 + payload_len..]);

    writer.write_all(&frame).await?;
    writer.flush().await
}

// Reader driver task

/// Background task: reads padded frames from `reader`, strips padding,
/// and delivers payload bytes to `inbound_tx`.
///
/// Chaff frames (`payload_len == 0`) are silently discarded.
///
/// In CBR mode (`cbr_frame_bytes = Some(n)`), every frame is exactly `n`
/// bytes total; the bucket derivation is bypassed.  In event-driven mode
/// the frame size is derived from `payload_len` via [`bucket_size`].
async fn pad_reader_driver<R>(
    mut reader: R,
    inbound_tx: mpsc::UnboundedSender<Vec<u8>>,
    cbr_frame_bytes: Option<usize>,
) where
    R: AsyncRead + Unpin + Send + 'static,
{
    loop {
        let mut header = [0u8; 2];
        if reader.read_exact(&mut header).await.is_err() {
            return;
        }
        let payload_len = u16::from_le_bytes(header) as usize;
        let frame_size = cbr_frame_bytes.unwrap_or_else(|| bucket_size(payload_len));
        // A frame must hold at least the 2-byte header. A `cbr_frame_bytes`
        // < 2 (mis-config) would underflow `frame_size - 2`; bail rather
        // than panic/wrap.
        let Some(to_read) = frame_size.checked_sub(2) else {
            return;
        };

        let mut rest = vec![0u8; to_read];
        if reader.read_exact(&mut rest).await.is_err() {
            return;
        }

        if payload_len == 0 {
            continue; // chaff frame - discard
        }

        // SECURITY: `payload_len` is attacker-controlled (it came off the
        // wire). In CBR mode `frame_size` is fixed, so a peer can claim a
        // `payload_len` larger than the frame actually carries; slicing
        // `rest[..payload_len]` would then panic and kill the tunnel. Drop
        // the connection on any frame whose claimed length overflows its
        // body.
        if payload_len > to_read {
            return;
        }

        if inbound_tx.send(rest[..payload_len].to_vec()).is_err() {
            return;
        }
    }
}

// Writer driver task

/// Background task: collects outbound writes, waits for a flush signal or
/// chaff timer, applies jitter, and writes one padded frame per cycle.
async fn pad_writer_driver<W>(
    mut writer: W,
    config: PadConfig,
    mut outbound_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    mut flush_rx: mpsc::UnboundedReceiver<()>,
) where
    W: AsyncWrite + Unpin + Send + 'static,
{
    loop {
        let payload = if let Some(p) = collect_outbound(
            &mut outbound_rx,
            &mut flush_rx,
            config.chaff_interval_ms.map(Duration::from_millis),
        )
        .await
        {
            p
        } else {
            // Session closed (handle dropped): flush a real FIN so the
            // peer observes the half-close instead of a silent stall.
            let _ = writer.shutdown().await;
            return;
        };

        // Jitter: random delay before each write.
        if config.max_jitter_ms > 0 {
            use rand::Rng as _;
            let delay = rand::rng().random_range(0..=config.max_jitter_ms);
            if delay > 0 {
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
        }

        if write_padded_frame(&mut writer, &payload).await.is_err() {
            return;
        }
    }
}

/// Draw a randomized chaff delay centred on `mean`.
///
/// A fixed inter-chaff interval (plus a tiny +/-jitter) is a near-periodic idle
/// beacon: a passive observer can recover the fundamental frequency and use it
/// as a signature. Redrawing the delay every tick from a wide uniform band -
/// `[mean/2, 3*mean/2]`, a 3:1 spread - smears the idle inter-frame gap across
/// a broad range so no single frequency dominates. Combined with the per-frame
/// write jitter, the idle traffic has no stable fundamental frequency.
fn randomized_chaff_delay(mean: Duration) -> Duration {
    use rand::Rng as _;
    let mean_ms = mean.as_millis() as u64;
    if mean_ms == 0 {
        return mean;
    }
    let lo = mean_ms / 2;
    let hi = mean_ms + mean_ms / 2;
    Duration::from_millis(rand::rng().random_range(lo..=hi))
}

/// Collect outbound bytes until a flush signal, the first data chunk, or
/// the chaff timer fires.
///
/// Returns `None` when both channels are closed (session dropped).
async fn collect_outbound(
    outbound_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    flush_rx: &mut mpsc::UnboundedReceiver<()>,
    chaff_interval: Option<Duration>,
) -> Option<Vec<u8>> {
    let mut payload = Vec::new();

    macro_rules! drain_outbound {
        () => {
            while let Ok(chunk) = outbound_rx.try_recv() {
                payload.extend(chunk);
            }
        };
    }

    if let Some(interval) = chaff_interval {
        tokio::select! {
            result = flush_rx.recv() => {
                match result {
                    None => return None,
                    Some(()) => drain_outbound!(),
                }
            }
            result = outbound_rx.recv() => {
                match result {
                    None => return None,
                    Some(chunk) => {
                        payload.extend(chunk);
                        drain_outbound!();
                    }
                }
            }
            () = tokio::time::sleep(randomized_chaff_delay(interval)) => {
                // Chaff tick: send whatever is buffered (may be empty). The
                // delay is redrawn every tick (see `randomized_chaff_delay`) so
                // idle chaff has no stable fundamental frequency for a passive
                // observer to lock onto.
                drain_outbound!();
            }
        }
    } else {
        tokio::select! {
            result = flush_rx.recv() => {
                match result {
                    None => return None,
                    Some(()) => drain_outbound!(),
                }
            }
            result = outbound_rx.recv() => {
                match result {
                    None => return None,
                    Some(chunk) => {
                        payload.extend(chunk);
                        drain_outbound!();
                    }
                }
            }
        }
    }

    Some(payload)
}

// CBR writer driver task

/// Background task: sends exactly one frame of `cbr_frame_bytes` every
/// `interval`, regardless of how much real data is buffered.
///
/// On each tick:
/// 1. Drain all buffered real data from `outbound_rx`.
/// 2. Take up to `cbr_frame_bytes - 2` bytes as payload; queue the rest
///    for the next tick.
/// 3. Build a padded frame of exactly `cbr_frame_bytes`: `[u16 LE:
///    payload_len][payload][CSPRNG random padding to cbr_frame_bytes]`.
/// 4. Write to the wire.
///
/// This produces a wire bitrate of exactly
/// `cbr_frame_bytes x 8 / interval_secs` bits per second.
async fn pad_cbr_writer_driver<W>(
    mut writer: W,
    interval: Duration,
    cbr_frame_bytes: usize,
    mut outbound_rx: mpsc::UnboundedReceiver<Vec<u8>>,
) where
    W: AsyncWrite + Unpin + Send + 'static,
{
    // Clamp to MAX_FRAME_PAYLOAD so `payload_len as u16` (below) can never
    // truncate even if an operator configures a CBR frame larger than 64 KiB
    // (same u16-truncation class as the event-driven writer). Excess frame
    // capacity just becomes padding.
    let max_payload = cbr_frame_bytes.saturating_sub(2).min(MAX_FRAME_PAYLOAD);
    let mut overflow: Vec<u8> = Vec::new(); // carry-over from previous tick
                                            // Jitter each inter-frame gap by +/-25% around `interval` so the wire cadence
                                            // is NOT a zero-variance metronome, which no real cover protocol emits
                                            // (red-team #7). This softens the TIMING tell; frame SIZE stays fixed (the
                                            // reader reads exactly cbr_frame_bytes), so a genuinely cover-accurate shape
                                            // (VBR frame sizes, directional asymmetry) remains future capture-calibrated
                                            // work - which is why strict CBR is no longer shipped enabled by default
                                            // (see client.json/bridge.json).
    let base_ms = (interval.as_millis().max(1)) as u64;

    loop {
        // Integer jitter: gap = base * [75..=125]% (avoids float arithmetic).
        let pct = rand::Rng::random_range(&mut rand::rng(), 75u64..=125);
        let gap_ms = (base_ms.saturating_mul(pct) / 100).max(1);
        tokio::time::sleep(Duration::from_millis(gap_ms)).await;

        // Drain every pending chunk from the channel.
        while let Ok(chunk) = outbound_rx.try_recv() {
            overflow.extend(chunk);
        }

        // Take up to `max_payload` bytes for this frame.
        let payload_len = overflow.len().min(max_payload);
        let payload: Vec<u8> = overflow.drain(..payload_len).collect();

        // Build the fixed-size frame.
        let mut frame = vec![0u8; cbr_frame_bytes];
        frame[0..2].copy_from_slice(&(payload_len as u16).to_le_bytes());
        if payload_len > 0 {
            frame[2..2 + payload_len].copy_from_slice(&payload);
        }
        // Fill remaining bytes with CSPRNG noise (index 2+payload_len onward).
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut frame[2 + payload_len..]);

        if writer.write_all(&frame).await.is_err() {
            return;
        }
        if writer.flush().await.is_err() {
            return;
        }

        // If the channel is closed and no overflow remains, flush a real FIN
        // and shut down so the peer observes the half-close.
        if outbound_rx.is_closed() && overflow.is_empty() {
            let _ = writer.shutdown().await;
            return;
        }
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // 1. bucket_size_correct

    #[test]
    fn bucket_size_correct() {
        // Ladder: 96, 208, 400, 720, 1200, 1448, 2896, ... 65536.
        assert_eq!(bucket_size(0), 96, "chaff (0 bytes) -> smallest bucket");
        assert_eq!(
            bucket_size(94),
            96,
            "94 bytes fits in 96 (with 2-byte header)"
        );
        assert_eq!(bucket_size(95), 208, "95 bytes overflows 96, needs 208");
        assert_eq!(bucket_size(206), 208, "206 bytes fits exactly in 208");
        assert_eq!(bucket_size(207), 400, "207 bytes overflows 208");
        assert!(
            PAD_FRAME_BUCKETS
                .iter()
                .all(|&b| b & (b - 1) != 0 || b == 65536),
            "no bucket except the natural 64 KiB ceiling is an exact power of two"
        );
        assert_eq!(
            bucket_size(65534),
            65536,
            "max payload fits in largest bucket"
        );
        assert_eq!(
            bucket_size(65535),
            65537,
            "oversized payload falls back to payload_len + 2"
        );
    }

    // 2. pad_round_trip - data written through PaddedStream arrives intact.

    #[tokio::test]
    async fn pad_round_trip() {
        let (a, b) = tokio::io::duplex(65536);
        let cfg = PadConfig {
            max_jitter_ms: 0,
            chaff_interval_ms: None,
            ..Default::default()
        };
        let mut pa = PaddedStream::wrap(a, cfg.clone());
        let mut pb = PaddedStream::wrap(b, cfg);

        pa.write_all(b"hello padded world").await.unwrap();
        pa.flush().await.unwrap();

        let mut buf = vec![0u8; 18];
        pb.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello padded world");
    }

    /// Regression for #6: a payload larger than a single u16-framed frame
    /// must split across frames and round-trip intact (previously the
    /// length header truncated as u16 and desynced the stream).
    #[tokio::test]
    async fn pad_large_payload_splits_and_round_trips() {
        let (a, b) = tokio::io::duplex(1 << 20);
        let cfg = PadConfig {
            max_jitter_ms: 0,
            chaff_interval_ms: None,
            ..Default::default()
        };
        let mut pa = PaddedStream::wrap(a, cfg.clone());
        let mut pb = PaddedStream::wrap(b, cfg);

        let big = vec![0xABu8; 200_000]; // > 3x MAX_FRAME_PAYLOAD
        pa.write_all(&big).await.unwrap();
        pa.flush().await.unwrap();

        let mut buf = vec![0u8; big.len()];
        pb.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, big);
    }

    /// Regression for #5: a malicious CBR frame whose header claims a
    /// `payload_len` larger than the frame body must NOT panic the reader -
    /// the driver drops the connection instead.
    #[tokio::test]
    async fn pad_reader_rejects_oversized_payload_len_cbr() {
        let (mut attacker, victim) = tokio::io::duplex(1024);
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let handle = tokio::spawn(pad_reader_driver(victim, tx, Some(64)));

        // Frame: header claims payload_len = 60000 (>> to_read = 62), then
        // 62 body bytes to satisfy the CBR read_exact.
        let mut frame = Vec::new();
        frame.extend_from_slice(&60000u16.to_le_bytes());
        frame.extend_from_slice(&[0u8; 62]);
        attacker.write_all(&frame).await.unwrap();
        attacker.flush().await.unwrap();

        // The driver must drop (no payload delivered, channel closes) and
        // the task must complete without panicking.
        assert!(rx.recv().await.is_none(), "no payload should be delivered");
        handle.await.expect("reader task must not panic");
    }

    // 3. pad_multiple_messages

    #[tokio::test]
    async fn pad_multiple_messages() {
        let (a, b) = tokio::io::duplex(65536);
        let cfg = PadConfig {
            max_jitter_ms: 0,
            chaff_interval_ms: None,
            ..Default::default()
        };
        let mut pa = PaddedStream::wrap(a, cfg.clone());
        let mut pb = PaddedStream::wrap(b, cfg);

        for i in 0u8..8 {
            pa.write_all(&[i; 10]).await.unwrap();
            pa.flush().await.unwrap();
            let mut buf = [0u8; 10];
            pb.read_exact(&mut buf).await.unwrap();
            assert!(
                buf.iter().all(|&b| b == i),
                "message {i} must round-trip intact"
            );
        }
    }

    // 4. pad_wire_frame_size - wire bytes equal the expected bucket size.

    #[tokio::test]
    async fn pad_wire_frame_size() {
        // Intercept raw wire bytes via a raw duplex pair.
        let (client_inner, mut wire_server) = tokio::io::duplex(65536);
        let cfg = PadConfig {
            max_jitter_ms: 0,
            chaff_interval_ms: None,
            ..Default::default()
        };
        let mut padded = PaddedStream::wrap(client_inner, cfg);

        // payload = 2 bytes -> bucket_size(2) = 64 -> frame on wire = 64 bytes
        padded.write_all(b"hi").await.unwrap();
        padded.flush().await.unwrap();

        let mut wire_frame = vec![0u8; 64];
        wire_server.read_exact(&mut wire_frame).await.unwrap();

        let decoded_len = u16::from_le_bytes([wire_frame[0], wire_frame[1]]) as usize;
        assert_eq!(decoded_len, 2, "header must encode payload_len = 2");
        assert_eq!(&wire_frame[2..4], b"hi", "payload bytes must follow header");
        // Padding bytes 4..64 are random - not checked.
    }

    // 5. pad_chaff_not_delivered - chaff does not deliver bytes to the reader.

    #[tokio::test]
    async fn pad_chaff_not_delivered() {
        let (a, b) = tokio::io::duplex(65536);
        // Fast chaff on client side; server has no jitter.
        let client_cfg = PadConfig {
            max_jitter_ms: 0,
            chaff_interval_ms: Some(20),
            ..Default::default()
        };
        let server_cfg = PadConfig {
            max_jitter_ms: 0,
            chaff_interval_ms: None,
            ..Default::default()
        };
        let mut pa = PaddedStream::wrap(a, client_cfg);
        let mut pb = PaddedStream::wrap(b, server_cfg);

        // Wait several chaff intervals.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Now send real data.
        pa.write_all(b"real").await.unwrap();
        pa.flush().await.unwrap();

        // Server must receive exactly "real" and nothing extra.
        let mut buf = vec![0u8; 4];
        pb.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"real");
    }

    // 6. pad_jitter_does_not_corrupt - jitter enabled, data still arrives.

    #[tokio::test]
    async fn pad_jitter_does_not_corrupt() {
        let (a, b) = tokio::io::duplex(65536);
        let cfg = PadConfig {
            max_jitter_ms: 30,
            chaff_interval_ms: None,
            ..Default::default()
        };
        let mut pa = PaddedStream::wrap(a, cfg.clone());
        let mut pb = PaddedStream::wrap(b, cfg);

        pa.write_all(b"jitter payload").await.unwrap();
        pa.flush().await.unwrap();

        let mut buf = vec![0u8; 14];
        pb.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"jitter payload");
    }

    // 7. pad_cbr_round_trip - CBR mode delivers data correctly.

    #[tokio::test(start_paused = true)]
    async fn pad_cbr_round_trip() {
        let (a, b) = tokio::io::duplex(65536);
        let cbr_cfg = PadConfig {
            cbr_frame_bytes: Some(128),
            cbr_interval_ms: 10,
            ..Default::default()
        };
        let mut pa = PaddedStream::wrap(a, cbr_cfg.clone());
        let mut pb = PaddedStream::wrap(b, cbr_cfg);

        pa.write_all(b"cbr payload").await.unwrap();
        // flush() must succeed in CBR mode even though there is no flush
        // receiver (regression guard: poll_flush once wrongly returned
        // BrokenPipe here, breaking every flush).
        pa.flush().await.unwrap();
        // Advance the timer so the CBR tick fires.
        tokio::time::advance(Duration::from_millis(15)).await;

        let mut buf = vec![0u8; 11];
        pb.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"cbr payload");
    }

    // 8. pad_cbr_wire_frame_size - CBR wire frames are exactly cbr_frame_bytes.

    #[tokio::test(start_paused = true)]
    async fn pad_cbr_wire_frame_size() {
        let (client_inner, mut wire_server) = tokio::io::duplex(65536);
        let cbr_cfg = PadConfig {
            cbr_frame_bytes: Some(256),
            cbr_interval_ms: 10,
            ..Default::default()
        };
        let mut padded = PaddedStream::wrap(client_inner, cbr_cfg);

        padded.write_all(b"x").await.unwrap();
        tokio::time::advance(Duration::from_millis(15)).await;

        let mut frame = vec![0u8; 256];
        wire_server.read_exact(&mut frame).await.unwrap();

        let decoded_len = u16::from_le_bytes([frame[0], frame[1]]) as usize;
        assert_eq!(decoded_len, 1, "payload_len header must be 1");
        assert_eq!(frame[2], b'x', "payload byte must be present");
    }

    // 9. pad_cbr_overflow - data exceeding one frame carries over to next tick.

    #[tokio::test(start_paused = true)]
    async fn pad_cbr_overflow() {
        // frame = 64 bytes -> max_payload = 62 bytes per tick.
        // Send 70 bytes; first tick sends 62, second tick sends remaining 8.
        let (a, b) = tokio::io::duplex(65536);
        let cbr_cfg = PadConfig {
            cbr_frame_bytes: Some(64),
            cbr_interval_ms: 10,
            ..Default::default()
        };
        let mut pa = PaddedStream::wrap(a, cbr_cfg.clone());
        let mut pb = PaddedStream::wrap(b, cbr_cfg);

        let big = vec![0xABu8; 70];
        pa.write_all(&big).await.unwrap();

        // First tick
        tokio::time::advance(Duration::from_millis(15)).await;
        let mut buf1 = vec![0u8; 62];
        pb.read_exact(&mut buf1).await.unwrap();
        assert!(
            buf1.iter().all(|&b| b == 0xAB),
            "first chunk must be 62 x 0xAB"
        );

        // Second tick carries the overflow
        tokio::time::advance(Duration::from_millis(15)).await;
        let mut buf2 = vec![0u8; 8];
        pb.read_exact(&mut buf2).await.unwrap();
        assert!(buf2.iter().all(|&b| b == 0xAB), "overflow must be 8 x 0xAB");
    }
}
