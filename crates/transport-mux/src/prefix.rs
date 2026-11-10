//! [`PrefixedStream`]: a utility adapter that replays buffered bytes
//! before delegating all further I/O to the inner stream.
//!
//! # Use-case
//!
//! When bytes have already been *consumed* from a socket (e.g. by a
//! prior `read_exact` that was part of a detection attempt), but a
//! downstream handler needs to see them at offset 0, wrap the inner
//! stream in `PrefixedStream` to prepend those bytes transparently.
//!
//! For the TLS and HTTP paths the mux uses `peek()` (non-consuming),
//! so `PrefixedStream` is **not needed** on those paths. It is
//! provided as a utility for callers that perform their own consuming
//! reads before handing a stream to a handler.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A stream that prepends a fixed set of buffered bytes before
/// delegating all further reads to the inner stream.
///
/// Writes are always forwarded directly to the inner stream, unaffected
/// by the prefix buffer.
///
/// # Type parameter
///
/// `S` - the wrapped async stream. Must implement [`AsyncRead`] (and
/// optionally [`AsyncWrite`]) and be [`Unpin`].
pub struct PrefixedStream<S> {
    /// Bytes to replay before the inner stream. Drained as they are
    /// copied into the caller's read buffer.
    prefix: Bytes,
    /// How many bytes of `prefix` have already been consumed.
    offset: usize,
    /// The underlying transport stream.
    inner: S,
}

impl<S> PrefixedStream<S> {
    /// Construct a `PrefixedStream` that will yield `prefix` bytes
    /// first, then delegate all further reads to `inner`.
    ///
    /// `prefix` may be empty, in which case this is a zero-cost
    /// passthrough for reads.
    pub fn new(prefix: impl Into<Bytes>, inner: S) -> Self {
        Self {
            prefix: prefix.into(),
            offset: 0,
            inner,
        }
    }

    /// Returns `true` once all prefix bytes have been delivered to
    /// callers and subsequent reads go directly to `inner`.
    pub fn prefix_exhausted(&self) -> bool {
        self.offset >= self.prefix.len()
    }

    /// Return the number of prefix bytes not yet delivered.
    pub fn prefix_remaining(&self) -> usize {
        self.prefix.len().saturating_sub(self.offset)
    }

    /// Consume this wrapper and return the inner stream.
    ///
    /// Any unread prefix bytes are discarded. Callers SHOULD check
    /// [`Self::prefix_exhausted`] before calling this if they care
    /// about the unconsumed data.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Drain from the prefix buffer first.
        if self.offset < self.prefix.len() {
            // Both slices are bounds-checked: offset < len() and
            // to_copy <= available.len() by construction.
            #[allow(clippy::indexing_slicing)]
            let available = &self.prefix[self.offset..];
            let to_copy = available.len().min(buf.remaining());
            #[allow(clippy::indexing_slicing)]
            buf.put_slice(&available[..to_copy]);
            self.offset += to_copy;
            // We gave the caller data from the prefix; return Ready even
            // if there is still more in `inner` - the caller will come
            // back for the next chunk.
            return Poll::Ready(Ok(()));
        }

        // Prefix exhausted - delegate to the inner stream.
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn prefix_then_inner() {
        let prefix = b"HELLO".as_slice();
        let (mut a, b) = duplex(256);
        // Write inner data from the other side.
        a.write_all(b" WORLD").await.unwrap();
        drop(a); // EOF so the read terminates.

        let mut ps = PrefixedStream::new(Bytes::copy_from_slice(prefix), b);
        let mut out = Vec::new();
        ps.read_to_end(&mut out).await.unwrap();
        assert_eq!(&out, b"HELLO WORLD");
    }

    #[tokio::test]
    async fn empty_prefix_is_passthrough() {
        let (mut a, b) = duplex(256);
        a.write_all(b"DATA").await.unwrap();
        drop(a);

        let mut ps = PrefixedStream::new(Bytes::new(), b);
        let mut out = Vec::new();
        ps.read_to_end(&mut out).await.unwrap();
        assert_eq!(&out, b"DATA");
    }

    #[tokio::test]
    async fn prefix_exhausted_flag() {
        let (_, b) = duplex(256);
        let prefix = Bytes::from_static(b"ABC");
        let mut ps = PrefixedStream::new(prefix, b);

        assert!(!ps.prefix_exhausted());
        assert_eq!(ps.prefix_remaining(), 3);

        let mut tmp = [0u8; 2];
        ps.read_exact(&mut tmp).await.unwrap();
        assert!(!ps.prefix_exhausted());
        assert_eq!(ps.prefix_remaining(), 1);

        ps.read_exact(&mut tmp[..1]).await.unwrap();
        assert!(ps.prefix_exhausted());
        assert_eq!(ps.prefix_remaining(), 0);
    }

    #[tokio::test]
    async fn write_passes_through_prefix() {
        let (mut a, b) = duplex(256);
        let mut ps = PrefixedStream::new(Bytes::new(), b);
        ps.write_all(b"PING").await.unwrap();
        ps.flush().await.unwrap();

        let mut buf = [0u8; 4];
        a.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"PING");
    }
}
