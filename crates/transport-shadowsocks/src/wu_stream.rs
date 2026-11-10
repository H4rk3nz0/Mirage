//! Wu-2023 fully-encrypted-traffic evasion for the Shadowsocks-2022 carrier.
//!
//! SS-2022's wire is uniformly random from byte 0 (`request_salt` then AEAD
//! chunks), which is exactly the signature the GFW's deployed fully-encrypted
//! classifier flags (Wu et al., 2023 - the class that got obfs4 dropped). The
//! client even refuses SS as a sole outer carrier under entropy DPI for this
//! reason.
//!
//! [`WuStream`] wraps the carrier TCP so that the FIRST bytes each side puts on
//! the wire are a printable preamble (see [`mirage_common::wu_preamble`]),
//! giving the flow a >20-byte printable run at the front in both directions -
//! clearing the classifier's exemptions. The wrapper is transparent to the
//! SS-2022 handshake and data framing above it: it prepends its own preamble on
//! the first write and strips the peer's on the first read, then passes bytes
//! through unchanged. Nothing about the AEAD framing changes.
//!
//! [`MaybeWu`] lets a caller pick the wrapped or plain carrier at runtime while
//! keeping one concrete stream type.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use mirage_common::wu_preamble::{is_alphabet, make_preamble, preamble_body_len};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Read-side state: consuming the peer's preamble, then passing through.
enum InState {
    /// Waiting for the 1-byte self-describing length.
    NeedLen,
    /// Consuming the remaining `usize` printable preamble bytes.
    NeedBody(usize),
    /// Preamble fully stripped; deliver app data.
    Done,
}

/// Largest amount of caller payload coalesced into the first flight alongside
/// the preamble. The SS-2022 request (salt + sealed header) is ~150 B, so this
/// covers it with room to spare while keeping the staging buffer bounded.
const MAX_STAGED_PAYLOAD: usize = 4096;

/// A carrier stream that wears a Wu-2023 printable preamble on each direction.
pub struct WuStream<S> {
    inner: S,
    /// First flight: our preamble followed by the first caller payload bytes.
    /// Staged together and handed to the carrier as ONE write so they share a
    /// TCP segment - a peer that classifies on the first segment (the bridge
    /// mux does) must not see a preamble-only segment with no protocol behind
    /// it, which it would cover-forward as unrecognised.
    out_stage: Vec<u8>,
    /// Bytes of `out_stage` already accepted by the carrier.
    out_off: usize,
    /// How many trailing bytes of `out_stage` are caller payload (rest = preamble).
    staged_payload: usize,
    /// True once the staged first flight is fully on the wire.
    out_done: bool,
    /// Peer-preamble strip state.
    in_state: InState,
    /// App bytes read past the peer's preamble in the same segment, awaiting
    /// delivery to the caller.
    in_buf: Vec<u8>,
}

impl<S> WuStream<S> {
    /// Wrap `inner`, staging a fresh outbound preamble.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            out_stage: make_preamble(),
            out_off: 0,
            staged_payload: 0,
            out_done: false,
            in_state: InState::NeedLen,
            in_buf: Vec::new(),
        }
    }

    /// Advance the peer-preamble strip over `data`, stashing any trailing app
    /// bytes into `in_buf`. Errors on a malformed (non-printable / bad-length)
    /// preamble, exactly as the SS handshake would on any corrupt input.
    fn feed_preamble(&mut self, data: &[u8]) -> io::Result<()> {
        let mut i = 0;
        while i < data.len() {
            match self.in_state {
                InState::NeedLen => {
                    let l = preamble_body_len(data[i]).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "wu: bad preamble length")
                    })?;
                    self.in_state = InState::NeedBody(l);
                    i += 1;
                }
                InState::NeedBody(remaining) => {
                    let take = remaining.min(data.len() - i);
                    if data[i..i + take].iter().any(|b| !is_alphabet(*b)) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "wu: preamble byte outside the token alphabet",
                        ));
                    }
                    let left = remaining - take;
                    self.in_state = if left == 0 {
                        InState::Done
                    } else {
                        InState::NeedBody(left)
                    };
                    i += take;
                }
                InState::Done => {
                    self.in_buf.extend_from_slice(&data[i..]);
                    break;
                }
            }
        }
        Ok(())
    }
}

impl<S: AsyncWrite + Unpin> WuStream<S> {
    /// Push the staged first flight (preamble [+ coalesced payload]) to the
    /// carrier; `Ready(Ok(()))` once fully written. Idempotent after completion.
    fn drain_stage(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_off < self.out_stage.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.out_stage[self.out_off..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "wu: inner refused the preamble",
                    )));
                }
                Poll::Ready(Ok(n)) => self.out_off += n,
            }
        }
        if !self.out_done {
            self.out_done = true;
            self.out_stage = Vec::new();
            self.out_off = 0;
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for WuStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        // Strip the peer's preamble before delivering any app data.
        while !matches!(me.in_state, InState::Done) {
            let mut scratch = [0u8; 256];
            let mut rb = ReadBuf::new(&mut scratch);
            match Pin::new(&mut me.inner).poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let filled = rb.filled();
                    if filled.is_empty() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "wu: EOF during preamble",
                        )));
                    }
                    if let Err(e) = me.feed_preamble(filled) {
                        return Poll::Ready(Err(e));
                    }
                }
            }
        }
        // Deliver any app bytes captured alongside the preamble first.
        if !me.in_buf.is_empty() {
            let n = me.in_buf.len().min(buf.remaining());
            buf.put_slice(&me.in_buf[..n]);
            me.in_buf.drain(..n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut me.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WuStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        // `staged_payload > 0` with the stage already drained means an
        // intervening flush/shutdown pushed the first flight out; the payload it
        // carried still has to be reported to the caller here, or the next write
        // would put those bytes on the wire a second time.
        if !me.out_done || me.staged_payload > 0 {
            // Coalesce the caller's first payload into the SAME write as the
            // preamble. Writing them separately puts them in separate TCP
            // segments (the carrier socket sets TCP_NODELAY), and a peer that
            // classifies on the first segment would see a bare preamble.
            if me.staged_payload == 0 && !buf.is_empty() {
                let take = buf.len().min(MAX_STAGED_PAYLOAD);
                me.out_stage.extend_from_slice(&buf[..take]);
                me.staged_payload = take;
            }
            match me.drain_stage(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
            // Report only the payload we actually staged from THIS buffer. The
            // caller re-presents the same bytes after a Pending (the contract
            // `write_all`/`copy` follow), and the min() keeps us from ever
            // over-reporting if a caller shrinks its buffer.
            let consumed = me.staged_payload.min(buf.len());
            me.staged_payload = 0;
            if consumed > 0 {
                return Poll::Ready(Ok(consumed));
            }
        }
        Pin::new(&mut me.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        match me.drain_stage(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        match me.drain_stage(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}

/// A carrier that is either plain or Wu-2023-wrapped, chosen at runtime while
/// keeping one concrete stream type through the SS handshake.
pub enum MaybeWu<S> {
    /// Unwrapped carrier (no preamble).
    Plain(S),
    /// Wu-2023-preamble-wrapped carrier.
    Wu(WuStream<S>),
}

impl<S> MaybeWu<S> {
    /// Wrap `inner` in a [`WuStream`] when `wu`, else pass it through plain.
    pub fn new(inner: S, wu: bool) -> Self {
        if wu {
            MaybeWu::Wu(WuStream::new(inner))
        } else {
            MaybeWu::Plain(inner)
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for MaybeWu<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeWu::Plain(s) => Pin::new(s).poll_read(cx, buf),
            MaybeWu::Wu(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for MaybeWu<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MaybeWu::Plain(s) => Pin::new(s).poll_write(cx, buf),
            MaybeWu::Wu(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeWu::Plain(s) => Pin::new(s).poll_flush(cx),
            MaybeWu::Wu(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeWu::Plain(s) => Pin::new(s).poll_shutdown(cx),
            MaybeWu::Wu(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn wu_stream_roundtrips_both_directions() {
        // Two WuStreams back to back: each prepends its own preamble and strips
        // the peer's, so the app bytes survive in both directions.
        let (a, b) = tokio::io::duplex(8192);
        let mut ca = WuStream::new(a);
        let mut cb = WuStream::new(b);

        let up = b"client-to-server request bytes, high entropy \x00\x01\x02\xff".to_vec();
        let down = b"server-to-client response bytes \xde\xad\xbe\xef".to_vec();
        let up_c = up.clone();
        let down_c = down.clone();

        let server = tokio::spawn(async move {
            let mut got = vec![0u8; up_c.len()];
            cb.read_exact(&mut got).await.expect("server read");
            assert_eq!(got, up_c, "upstream survived");
            cb.write_all(&down_c).await.expect("server write");
            cb.flush().await.expect("server flush");
        });

        ca.write_all(&up).await.expect("client write");
        ca.flush().await.expect("client flush");
        let mut got = vec![0u8; down.len()];
        ca.read_exact(&mut got).await.expect("client read");
        assert_eq!(got, down, "downstream survived");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn wire_prefix_is_a_gfw_exempt_printable_run() {
        // Wrap only the sender; inspect the RAW bytes the peer receives. The
        // wire must open with a self-describing printable run > 20 (Ex4) whose
        // first 6 bytes are printable (Ex2), then the untouched payload.
        let (a, mut raw) = tokio::io::duplex(8192);
        let mut sender = WuStream::new(a);
        let payload: Vec<u8> = (0..300u32).map(|i| (i.wrapping_mul(31)) as u8).collect();
        let payload_c = payload.clone();
        let w = tokio::spawn(async move {
            sender.write_all(&payload_c).await.expect("send");
            sender.flush().await.expect("flush");
        });

        // First byte declares the preamble length.
        let mut lb = [0u8; 1];
        raw.read_exact(&mut lb).await.expect("len byte");
        assert!(is_alphabet(lb[0]), "length byte is printable (part of Ex2)");
        let l = preamble_body_len(lb[0]).expect("valid length byte");
        assert!(1 + l > 20, "printable run exceeds 20 (Ex4)");
        let mut pre = vec![0u8; l];
        raw.read_exact(&mut pre).await.expect("preamble body");
        assert!(
            pre.iter().all(|&b| is_alphabet(b)),
            "preamble is drawn from the token alphabet"
        );
        // The payload follows byte-for-byte.
        let mut body = vec![0u8; payload.len()];
        raw.read_exact(&mut body).await.expect("payload");
        assert_eq!(body, payload, "payload unchanged on the wire");
        w.await.unwrap();
    }

    #[tokio::test]
    async fn maybe_wu_plain_is_a_passthrough() {
        let (a, mut raw) = tokio::io::duplex(1024);
        let mut plain = MaybeWu::Plain(a);
        plain.write_all(b"no preamble here").await.expect("write");
        plain.flush().await.expect("flush");
        let mut got = vec![0u8; 16];
        raw.read_exact(&mut got).await.expect("read");
        assert_eq!(&got, b"no preamble here", "plain mode adds nothing");
    }

    #[tokio::test]
    async fn corrupt_preamble_is_rejected() {
        // A non-printable leading byte (as a plain SS salt often is) must be
        // rejected rather than silently mis-framed.
        let (a, mut feed) = tokio::io::duplex(1024);
        let mut recv = WuStream::new(a);
        feed.write_all(&[0x00, 0x01, 0x02, 0x03])
            .await
            .expect("feed");
        feed.flush().await.expect("flush");
        let mut got = vec![0u8; 4];
        let r = recv.read_exact(&mut got).await;
        assert!(r.is_err(), "a non-preamble stream must not decode");
    }
}
