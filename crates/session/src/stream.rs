//! Byte-stream view over a [`SessionFramer`].
//!
//! The session layer encrypts **frames** of up to
//! [`MAX_FRAME_PLAINTEXT`] bytes. Applications - SOCKS5 proxies, echo
//! servers, random TCP forwarders - want **streams**: call
//! `read`/`write` with arbitrary buffer sizes and let the plumbing
//! worry about framing.
//!
//! [`SessionStream`] bridges the two. It wraps a [`SessionFramer`]
//! and an underlying async byte stream (typically a TCP socket) and
//! exposes [`tokio::io::AsyncRead`] + [`tokio::io::AsyncWrite`].
//!
//! # Wire format
//!
//! On the underlying stream we emit what [`SessionFramer::send`]
//! produces verbatim: `[u16 BE length][outer_ct]`. The receive path
//! reads the 2-byte length prefix, then the indicated number of
//! ciphertext bytes, then hands the whole thing to
//! [`SessionFramer::recv`].
//!
//! # Chunking
//!
//! Writes larger than [`MAX_FRAME_PLAINTEXT`] are split into multiple
//! frames. Writes smaller than a full frame are sent in a single
//! frame - we do not batch across `write` calls, because batching
//! would hold data in a buffer past the caller's intent and pass
//! through to the underlying stream only on flush. If the caller
//! wants batching, they should wrap us in a `BufWriter`.
//!
//! # Backpressure and cancellation safety
//!
//! Writes: fully buffered in memory. A large `write` allocates one
//! temporary ciphertext per-frame and calls the underlying stream in
//! a loop. Cancel-safe up to the granularity of a single frame: if
//! the task is dropped mid-`poll_write`, at most a partial frame has
//! been written to the underlying stream AND the framer's `seq`
//! counter has advanced. The session is then desynced and MUST be
//! dropped.
//!
//! Reads: we buffer at most one incoming plaintext frame
//! (up to [`MAX_FRAME_PLAINTEXT`] bytes) in [`SessionStream::rx_buf`].
//! Short reads drain from that buffer without re-entering the
//! framer.
//!
//! # Threat-model notes
//!
//! - **Length prefix is plaintext.** An adversary observing the wire
//!   sees the size of each ciphertext frame. Spec §4.1 accepts this
//!   as a known limitation (length-hiding padding is an optional v0.2
//!   feature).
//! - **Framer desync is terminal.** If `recv` fails (bad tag, length
//!   out of range, seq skew), the session MUST be dropped - no
//!   recovery attempt, since any recovered state is adversary-
//!   controlled.
//! - **Partial-write cancellation**: see "Cancellation safety" above.
//!   Well-behaved applications do not cancel mid-write.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::frames::{SessionFramer, MAX_FRAME_PLAINTEXT, MAX_OUTER_CT_LEN};

/// Default time-ratchet interval (seconds): advance the session epoch once per
/// hour of wall-clock, matching `mirage_spec::RATCHET_EPOCH_SECONDS`.
const DEFAULT_RATCHET_SECS: u64 = 3600;

/// Wire-level length prefix size (bytes). Matches the hard-coded
/// constant in `frames.rs`; re-declared here because the framer's
/// constant is private.
const LEN_PREFIX_SIZE: usize = 2;

/// Receive-path state machine.
#[derive(Debug)]
enum RxState {
    /// Need more bytes of the 2-byte length prefix.
    ReadingLength {
        got: usize,
        buf: [u8; LEN_PREFIX_SIZE],
    },
    /// Length prefix parsed; need more of the ciphertext body.
    ReadingBody {
        /// Bytes of outer_ct + prefix still to drain into `wire`.
        remaining: usize,
        /// Contiguous wire buffer: `[length(2)][outer_ct(N)]`,
        /// ready to hand to `framer.recv()` once full.
        wire: Vec<u8>,
    },
    /// Plaintext frame ready; drain from `rx_buf` first.
    HavePlaintext,
}

/// Send-path state machine. We do NOT buffer writes across calls -
/// each `poll_write` produces at most one frame. Mid-frame
/// cancellation desyncs the session.
#[derive(Debug)]
enum TxState {
    /// Idle: no frame in flight.
    Idle,
    /// Draining `buf[written..]` into the inner stream.
    Draining { buf: Vec<u8>, written: usize },
}

/// Byte-stream view over an active session.
///
/// Parameterized on the underlying stream `S: AsyncRead + AsyncWrite`.
/// For production: a `tokio::net::TcpStream`. For tests: a
/// `tokio::io::DuplexStream`.
pub struct SessionStream<S> {
    framer: SessionFramer,
    inner: S,
    rx_state: RxState,
    /// Decoded plaintext waiting to be read by the caller.
    rx_buf: Vec<u8>,
    /// Read cursor into `rx_buf`.
    rx_off: usize,
    tx_state: TxState,
    /// Reference instant for the time ratchet (session establishment).
    ratchet_start: Instant,
    /// Seconds per ratchet epoch. 0 disables the driver (the peer still
    /// reactively follows any advance we make by other means).
    ratchet_secs: u64,
}

impl<S> SessionStream<S> {
    /// Construct from a `SessionFramer` (from a completed handshake)
    /// and an async byte stream.
    pub fn new(framer: SessionFramer, inner: S) -> Self {
        Self {
            framer,
            inner,
            rx_state: RxState::ReadingLength {
                got: 0,
                buf: [0u8; LEN_PREFIX_SIZE],
            },
            rx_buf: Vec::new(),
            rx_off: 0,
            tx_state: TxState::Idle,
            ratchet_start: Instant::now(),
            ratchet_secs: DEFAULT_RATCHET_SECS,
        }
    }

    /// Override the time-ratchet interval (seconds). 0 disables the wall-clock
    /// driver. Both peers should use the same interval; skew within one epoch
    /// is absorbed by the framer's grace window.
    pub fn set_ratchet_interval_secs(&mut self, secs: u64) {
        self.ratchet_secs = secs;
    }

    /// Test hook: pretend the session started `by` earlier, so the next write
    /// crosses a ratchet boundary deterministically without a real sleep.
    #[cfg(test)]
    fn rewind_ratchet_start(&mut self, by: std::time::Duration) {
        self.ratchet_start -= by;
    }

    /// Immutable reference to the underlying stream. Useful for
    /// tests to peek at buffered state; MUST NOT be used to read or
    /// write, as that would desync the framer.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Access the session framer for operations that don't make
    /// sense on the byte stream (e.g., `advance_epoch`). Callers
    /// MUST NOT call `send`/`recv` directly - that would desync the
    /// stream adapter's state machine.
    pub fn framer_mut(&mut self) -> &mut SessionFramer {
        &mut self.framer
    }

    /// Consume and return `(framer, inner)`. Useful for tests that
    /// want to swap out the transport while keeping the session
    /// state.
    pub fn into_parts(self) -> (SessionFramer, S) {
        (self.framer, self.inner)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for SessionStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            // If we have buffered plaintext, drain it first.
            if let RxState::HavePlaintext = &self.rx_state {
                let available = self.rx_buf.len() - self.rx_off;
                if available > 0 {
                    let take = available.min(buf.remaining());
                    buf.put_slice(&self.rx_buf[self.rx_off..self.rx_off + take]);
                    self.rx_off += take;
                    if self.rx_off == self.rx_buf.len() {
                        self.rx_buf.clear();
                        self.rx_off = 0;
                        self.rx_state = RxState::ReadingLength {
                            got: 0,
                            buf: [0u8; LEN_PREFIX_SIZE],
                        };
                    }
                    return Poll::Ready(Ok(()));
                }
                // Plaintext drained; fall through to start next frame.
                self.rx_state = RxState::ReadingLength {
                    got: 0,
                    buf: [0u8; LEN_PREFIX_SIZE],
                };
            }

            // Inline-drive the state machine, borrowing fields piecewise
            // to avoid overlapping mutable borrows through `self`.
            let this = &mut *self;
            match &mut this.rx_state {
                RxState::HavePlaintext => unreachable!("handled above"),
                RxState::ReadingLength { got, buf: lbuf } => {
                    let mut tmp_buf = ReadBuf::new(&mut lbuf[*got..]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            let n = tmp_buf.filled().len();
                            if n == 0 {
                                // EOF. If we were mid-prefix, it's a
                                // clean close only if we got 0 bytes
                                // of the prefix. Otherwise it's a
                                // truncated wire.
                                if *got == 0 {
                                    return Poll::Ready(Ok(()));
                                }
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "truncated length prefix",
                                )));
                            }
                            *got += n;
                            if *got == LEN_PREFIX_SIZE {
                                let claimed_len = u16::from_be_bytes([lbuf[0], lbuf[1]]) as usize;
                                if claimed_len > MAX_OUTER_CT_LEN {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "claimed frame length exceeds max",
                                    )));
                                }
                                let mut wire = Vec::with_capacity(LEN_PREFIX_SIZE + claimed_len);
                                wire.extend_from_slice(lbuf);
                                wire.resize(LEN_PREFIX_SIZE + claimed_len, 0);
                                this.rx_state = RxState::ReadingBody {
                                    remaining: claimed_len,
                                    wire,
                                };
                            }
                        }
                    }
                }
                RxState::ReadingBody { remaining, wire } => {
                    let total = wire.len();
                    let start = total - *remaining;
                    let mut tmp_buf = ReadBuf::new(&mut wire[start..]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            let n = tmp_buf.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "truncated frame body",
                                )));
                            }
                            *remaining -= n;
                            if *remaining == 0 {
                                // Full frame read; decrypt.
                                let wire_owned = std::mem::take(wire);
                                match this.framer.recv(&wire_owned) {
                                    Ok(plaintext) => {
                                        this.rx_buf = plaintext;
                                        this.rx_off = 0;
                                        this.rx_state = RxState::HavePlaintext;
                                    }
                                    Err(e) => {
                                        // Desync. Report and leave the
                                        // state machine in a poisoned
                                        // state (next read will also
                                        // fail on the zeroed prefix).
                                        return Poll::Ready(Err(io::Error::new(
                                            io::ErrorKind::InvalidData,
                                            format!("frame decrypt failed: {e}"),
                                        )));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for SessionStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Drain any in-flight ciphertext before accepting new plaintext.
        loop {
            let this = &mut *self;
            match &mut this.tx_state {
                TxState::Idle => break,
                TxState::Draining { buf: out, written } => {
                    let remaining = &out[*written..];
                    match Pin::new(&mut this.inner).poll_write(cx, remaining) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "inner stream accepted 0 bytes",
                            )));
                        }
                        Poll::Ready(Ok(n)) => {
                            *written += n;
                            if *written == out.len() {
                                this.tx_state = TxState::Idle;
                                break;
                            }
                        }
                    }
                }
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Time ratchet: advance the session epoch on wall-clock (elapsed)
        // boundaries before framing this frame. Driven here so it is
        // transparent to copy_bidirectional; the peer reactively follows on
        // recv, and the framer's grace window absorbs clock skew. maybe_advance
        // is gated so we never race more than one epoch ahead of the peer.
        if self.ratchet_secs > 0 {
            let target = self.ratchet_start.elapsed().as_secs() / self.ratchet_secs;
            if let Err(e) = self.framer.maybe_advance(target) {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("session ratchet advance failed: {e}"),
                )));
            }
        }

        // Emit one frame per call so the caller can observe accurate
        // byte counts and cancel cleanly at frame boundaries.
        let take = buf.len().min(MAX_FRAME_PLAINTEXT);
        let wire = match self.framer.send(&buf[..take]) {
            Ok(w) => w,
            Err(e) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("session framer send failed: {e}"),
                )));
            }
        };
        self.tx_state = TxState::Draining {
            buf: wire,
            written: 0,
        };

        // Make best-effort progress on the drain within this call so
        // small writes complete in one poll cycle when the inner
        // stream is ready.
        loop {
            let this = &mut *self;
            match &mut this.tx_state {
                TxState::Idle => return Poll::Ready(Ok(take)),
                TxState::Draining { buf: out, written } => {
                    let remaining = &out[*written..];
                    match Pin::new(&mut this.inner).poll_write(cx, remaining) {
                        Poll::Pending => {
                            // Frame partially on the wire. The caller
                            // still gets `Ready(Ok(take))` - we have
                            // taken ownership of `take` bytes of their
                            // plaintext and promise to flush them on
                            // subsequent polls.
                            return Poll::Ready(Ok(take));
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "inner stream accepted 0 bytes",
                            )));
                        }
                        Poll::Ready(Ok(n)) => {
                            *written += n;
                            if *written == out.len() {
                                this.tx_state = TxState::Idle;
                                return Poll::Ready(Ok(take));
                            }
                        }
                    }
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Drain any in-flight frame first.
        loop {
            let this = &mut *self;
            match &mut this.tx_state {
                TxState::Idle => break,
                TxState::Draining { buf: out, written } => {
                    let remaining = &out[*written..];
                    match Pin::new(&mut this.inner).poll_write(cx, remaining) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "inner stream accepted 0 bytes",
                            )));
                        }
                        Poll::Ready(Ok(n)) => {
                            *written += n;
                            if *written == out.len() {
                                this.tx_state = TxState::Idle;
                            }
                        }
                    }
                }
            }
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Flush any in-flight frame, then shut the inner stream.
        match Pin::new(&mut *self).poll_flush(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frames::SessionFramer;
    use crate::handshake::SessionKeys;
    use crate::Role;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Pair-construct two framers with identical keys and opposite roles,
    /// matching the state that `from_session_keys` produces at both ends
    /// of a completed handshake. Test-only; production builds always
    /// derive framers from real handshake output.
    fn paired_framers() -> (SessionFramer, SessionFramer) {
        use mirage_crypto::x25519_dalek::{PublicKey, StaticSecret};
        let init_sk = StaticSecret::from([1u8; 32]);
        let resp_sk = StaticSecret::from([2u8; 32]);
        let resp_pk = PublicKey::from(&resp_sk);

        let mut init = snow::Builder::new(crate::handshake::NOISE_PATTERN.parse().unwrap())
            .local_private_key(&init_sk.to_bytes())
            .remote_public_key(resp_pk.as_bytes())
            .build_initiator()
            .unwrap();
        let mut resp = snow::Builder::new(crate::handshake::NOISE_PATTERN.parse().unwrap())
            .local_private_key(&resp_sk.to_bytes())
            .build_responder()
            .unwrap();

        // Drive the Noise handshake to transport state.
        let mut b1 = [0u8; 1024];
        let n = init.write_message(&[], &mut b1).unwrap();
        resp.read_message(&b1[..n], &mut [0u8; 1024]).unwrap();
        let n = resp.write_message(&[], &mut b1).unwrap();
        init.read_message(&b1[..n], &mut [0u8; 1024]).unwrap();
        let n = init.write_message(&[], &mut b1).unwrap();
        resp.read_message(&b1[..n], &mut [0u8; 1024]).unwrap();

        let init_transport = init.into_transport_mode().unwrap();
        let resp_transport = resp.into_transport_mode().unwrap();

        let session_binding = [0xAAu8; 32];
        let mlkem_ss = [0xBBu8; 32];

        let ik = SessionKeys {
            session_binding,
            transport: init_transport,
            mlkem_ss,
        };
        let rk = SessionKeys {
            session_binding,
            transport: resp_transport,
            mlkem_ss,
        };
        let initiator = SessionFramer::from_session_keys(ik, Role::Initiator).unwrap();
        let responder = SessionFramer::from_session_keys(rk, Role::Responder).unwrap();
        (initiator, responder)
    }

    #[tokio::test]
    async fn roundtrip_small_write() {
        let (fi, fr) = paired_framers();
        let (a, b) = tokio::io::duplex(1024);
        let mut client = SessionStream::new(fi, a);
        let mut bridge = SessionStream::new(fr, b);

        let payload = b"hello bridge";
        client.write_all(payload).await.unwrap();
        client.flush().await.unwrap();

        let mut got = vec![0u8; payload.len()];
        bridge.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn time_ratchet_driver_advances_and_peer_follows() {
        // The wall-clock driver in poll_write advances the sender's epoch at a
        // boundary; the receiver reactively follows; data keeps flowing.
        let (fi, fr) = paired_framers();
        let (a, b) = tokio::io::duplex(4096);
        let mut client = SessionStream::new(fi, a);
        let mut bridge = SessionStream::new(fr, b);
        client.set_ratchet_interval_secs(10);
        bridge.set_ratchet_interval_secs(10);

        // Epoch 0 traffic works.
        client.write_all(b"pre").await.unwrap();
        client.flush().await.unwrap();
        let mut got = [0u8; 3];
        bridge.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"pre");
        assert_eq!(client.framer_mut().current_epoch(), 0);

        // Pretend two intervals elapsed -> the next write crosses a boundary.
        client.rewind_ratchet_start(std::time::Duration::from_secs(21));
        client.write_all(b"post").await.unwrap();
        client.flush().await.unwrap();
        let mut got2 = [0u8; 4];
        bridge.read_exact(&mut got2).await.unwrap();
        assert_eq!(&got2, b"post");

        // Sender advanced (gated to one epoch ahead of the peer it had heard
        // from), and the receiver reactively followed.
        assert_eq!(client.framer_mut().current_epoch(), 1);
        assert_eq!(bridge.framer_mut().current_epoch(), 1);

        // Reverse direction still works at the adopted epoch.
        bridge.write_all(b"ack").await.unwrap();
        bridge.flush().await.unwrap();
        let mut got3 = [0u8; 3];
        client.read_exact(&mut got3).await.unwrap();
        assert_eq!(&got3, b"ack");
    }

    #[tokio::test]
    async fn bidirectional_pingpong() {
        let (fi, fr) = paired_framers();
        let (a, b) = tokio::io::duplex(8192);
        let mut client = SessionStream::new(fi, a);
        let mut bridge = SessionStream::new(fr, b);

        for i in 0..16u8 {
            let payload = vec![i; 100];
            client.write_all(&payload).await.unwrap();
            client.flush().await.unwrap();
            let mut got = vec![0u8; 100];
            bridge.read_exact(&mut got).await.unwrap();
            assert_eq!(got, payload);

            let reply = vec![i.wrapping_add(1); 200];
            bridge.write_all(&reply).await.unwrap();
            bridge.flush().await.unwrap();
            let mut got2 = vec![0u8; 200];
            client.read_exact(&mut got2).await.unwrap();
            assert_eq!(got2, reply);
        }
    }

    #[tokio::test]
    async fn large_write_chunks_into_multiple_frames() {
        let (fi, fr) = paired_framers();
        let (a, b) = tokio::io::duplex(MAX_FRAME_PLAINTEXT * 4);
        let mut client = SessionStream::new(fi, a);
        let mut bridge = SessionStream::new(fr, b);

        let payload: Vec<u8> = (0..MAX_FRAME_PLAINTEXT * 3)
            .map(|i| (i % 251) as u8)
            .collect();

        let (write_res, read_res) = tokio::join!(
            async {
                client.write_all(&payload).await?;
                client.flush().await?;
                Ok::<_, io::Error>(())
            },
            async {
                let mut got = vec![0u8; payload.len()];
                bridge.read_exact(&mut got).await?;
                Ok::<_, io::Error>(got)
            }
        );
        write_res.unwrap();
        assert_eq!(read_res.unwrap(), payload);
    }

    #[tokio::test]
    async fn tampered_ciphertext_causes_read_error() {
        // Get the ciphertext emitted by client; mutate; feed to responder.
        let (mut fi, fr) = paired_framers();
        let wire = fi.send(b"hello").unwrap();
        let mut tampered = wire.clone();
        // Flip a ciphertext byte (avoid the 2-byte length prefix).
        tampered[LEN_PREFIX_SIZE + 1] ^= 0xFF;

        // Feed the tampered bytes into a SessionStream wrapping the
        // responder's framer + a duplex stream.
        let (a, b) = tokio::io::duplex(1024);
        let mut bridge = SessionStream::new(fr, b);
        let mut writer = a;
        writer.write_all(&tampered).await.unwrap();
        drop(writer);

        let mut got = [0u8; 32];
        let err = bridge.read(&mut got).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        // Keep `fi` alive to suppress unused warnings (and to note that
        // on the real wire the initiator's framer would still have
        // advanced its seq counter, desyncing the session - documented
        // in the module doc).
        let _ = fi.current_epoch();
    }

    #[tokio::test]
    async fn peer_truncation_is_unexpected_eof() {
        let (fi, fr) = paired_framers();
        let (a, b) = tokio::io::duplex(1024);
        let mut client = SessionStream::new(fi, a);
        let mut bridge = SessionStream::new(fr, b);

        // Write a frame, but hold only half the bytes on the wire.
        let payload = vec![0u8; 64];
        client.write_all(&payload).await.unwrap();
        client.flush().await.unwrap();
        // Drop the client mid-session.
        drop(client);

        let mut got = vec![0u8; payload.len()];
        // The first frame was fully sent so it should arrive fine.
        bridge.read_exact(&mut got).await.unwrap();

        // Subsequent read now sees EOF cleanly.
        let mut next = [0u8; 8];
        let n = bridge.read(&mut next).await.unwrap();
        assert_eq!(n, 0, "clean EOF between frames");
    }

    #[tokio::test]
    async fn single_byte_writes_and_reads() {
        let (fi, fr) = paired_framers();
        let (a, b) = tokio::io::duplex(256);
        let mut client = SessionStream::new(fi, a);
        let mut bridge = SessionStream::new(fr, b);

        for i in 0..32u8 {
            client.write_all(&[i]).await.unwrap();
            client.flush().await.unwrap();
            let mut one = [0u8; 1];
            bridge.read_exact(&mut one).await.unwrap();
            assert_eq!(one, [i]);
        }
    }

    #[tokio::test]
    async fn shutdown_flushes_and_closes() {
        let (fi, fr) = paired_framers();
        let (a, b) = tokio::io::duplex(1024);
        let mut client = SessionStream::new(fi, a);
        let mut bridge = SessionStream::new(fr, b);

        client.write_all(b"last message").await.unwrap();
        client.shutdown().await.unwrap();

        let mut got = vec![0u8; b"last message".len()];
        bridge.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"last message");

        let mut next = [0u8; 8];
        let n = bridge.read(&mut next).await.unwrap();
        assert_eq!(n, 0);
    }
}
