//! Datagram envelope over a Mirage byte-stream session.
//!
//! # Why
//!
//! Mirage's session layer is a reliable, in-order, encrypted
//! bidirectional byte stream. Upper layers today carry SOCKS5
//! TCP CONNECT traffic. To support UDP-based protocols -
//! SOCKS5 UDP ASSOCIATE, QUIC / MASQUE, WireGuard-over-Mirage -
//! we need to preserve **datagram boundaries** while still riding
//! the existing byte stream. This module is that adapter.
//!
//! # Wire shape
//!
//! One datagram on the byte stream:
//!
//! ```text
//!   [u16 BE length][length bytes of datagram payload]
//! ```
//!
//! Repeated back-to-back. `length == 0` is a legal keep-alive
//! datagram but most callers will never emit one; the framer
//! preserves it so upper layers that DO use it still see the
//! zero-byte frame. `length > MAX_UDP_DATAGRAM_BYTES` is
//! rejected at send; on recv it's a hard error (torn stream /
//! malicious peer).
//!
//! # Integrity + authenticity
//!
//! This module does NOT add any extra AEAD or integrity. The
//! underlying Mirage session (`SessionFramer` / `SessionStream`)
//! already provides end-to-end confidentiality, integrity, and
//! replay protection for all bytes on the wire. A tampered
//! length prefix yields a decryption failure at the session
//! layer before it reaches the framer; the framer's failure
//! modes are strictly wire-format ("length field larger than
//! cap") not crypto.
//!
//! # Backpressure
//!
//! `UdpFramer` is `AsyncRead + AsyncWrite`-based and holds the
//! stream exclusively. Callers that need concurrent send/recv
//! should split the underlying stream (e.g., `tokio::io::split`)
//! and give each half to a distinct `UdpFramer` half. A simpler
//! API is on the roadmap once the SOCKS5 UDP ASSOCIATE wiring
//! lands (v0.1m).

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::SessionError;
use crate::frames::MAX_FRAME_PLAINTEXT;

/// Reserved SOCKS5 hostname that routes to the bridge-side UDP
/// relay (v0.1r). Clients open a SOCKS5 CONNECT to this name +
/// [`UDP_RELAY_MAGIC_PORT`] over a Mirage session, then speak the
/// UDP envelope protocol on the resulting stream.
pub const UDP_RELAY_MAGIC_HOSTNAME: &str = "_mirage_udp._internal";

/// Reserved port paired with [`UDP_RELAY_MAGIC_HOSTNAME`]. The
/// bridge dispatches on the hostname; the port is arbitrary.
pub const UDP_RELAY_MAGIC_PORT: u16 = 1;

/// Hard cap on a single datagram carried through the envelope.
/// Bounded by the session framer's per-frame plaintext cap minus
/// the 2-byte length prefix - a single datagram must always fit
/// in a single `SessionFramer::send()` call so the recv side
/// sees it atomically.
pub const MAX_UDP_DATAGRAM_BYTES: usize = MAX_FRAME_PLAINTEXT - 2;

/// Wire length of the length prefix.
pub const UDP_LENGTH_PREFIX_LEN: usize = 2;

/// Bidirectional datagram envelope over any `AsyncRead +
/// AsyncWrite` byte stream.
///
/// The typical substrate is a Mirage [`crate::SessionStream`].
/// Constructed after the session handshake + a magic-hostname
/// negotiation that puts both sides into UDP mode.
pub struct UdpFramer<S> {
    inner: S,
}

impl<S> UdpFramer<S> {
    /// Wrap `stream`. The caller is responsible for having already
    /// negotiated "this session carries UDP datagrams, not byte
    /// stream" with the peer - the framer itself adds no
    /// handshake.
    pub fn new(stream: S) -> Self {
        Self { inner: stream }
    }

    /// Peek at the wrapped stream for diagnostics.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Consume the framer and return the underlying stream.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> UdpFramer<S> {
    /// Send one datagram. Writes the length prefix + body. On the
    /// happy path this is one `write_all`; the writer is free to
    /// coalesce.
    pub async fn send(&mut self, datagram: &[u8]) -> Result<(), SessionError> {
        if datagram.len() > MAX_UDP_DATAGRAM_BYTES {
            return Err(SessionError::State("udp datagram exceeds cap"));
        }
        let prefix = (datagram.len() as u16).to_be_bytes();
        self.inner
            .write_all(&prefix)
            .await
            .map_err(|_| SessionError::State("udp send: prefix write"))?;
        if !datagram.is_empty() {
            self.inner
                .write_all(datagram)
                .await
                .map_err(|_| SessionError::State("udp send: body write"))?;
        }
        self.inner
            .flush()
            .await
            .map_err(|_| SessionError::State("udp send: flush"))?;
        Ok(())
    }
}

impl<S: tokio::io::AsyncRead + Unpin> UdpFramer<S> {
    /// Receive one datagram into a freshly-allocated buffer. On
    /// clean EOF (the peer shut the stream down between
    /// datagrams) returns `Ok(None)`. Partial reads of the length
    /// prefix or body are a hard error - the session's reliable-
    /// byte-stream property means a half-delivered datagram
    /// indicates a bug or malicious peer.
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>, SessionError> {
        let mut prefix = [0u8; UDP_LENGTH_PREFIX_LEN];
        match self.inner.read_exact(&mut prefix).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Clean close between datagrams.
                return Ok(None);
            }
            Err(_) => return Err(SessionError::State("udp recv: prefix read")),
        }
        let len = u16::from_be_bytes(prefix) as usize;
        if len > MAX_UDP_DATAGRAM_BYTES {
            return Err(SessionError::State("udp recv: length over cap"));
        }
        let mut buf = vec![0u8; len];
        if len > 0 {
            self.inner
                .read_exact(&mut buf)
                .await
                .map_err(|_| SessionError::State("udp recv: body read"))?;
        }
        Ok(Some(buf))
    }

    /// Receive one datagram into the caller's buffer. Returns the
    /// number of bytes written. Fails with a `State` error if the
    /// datagram exceeds `buf.len()` - the framer will NOT silently
    /// truncate.
    pub async fn recv_into(&mut self, buf: &mut [u8]) -> Result<Option<usize>, SessionError> {
        let mut prefix = [0u8; UDP_LENGTH_PREFIX_LEN];
        match self.inner.read_exact(&mut prefix).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(None);
            }
            Err(_) => return Err(SessionError::State("udp recv: prefix read")),
        }
        let len = u16::from_be_bytes(prefix) as usize;
        if len > MAX_UDP_DATAGRAM_BYTES {
            return Err(SessionError::State("udp recv: length over cap"));
        }
        if len > buf.len() {
            return Err(SessionError::State(
                "udp recv: buffer too small for datagram",
            ));
        }
        if len > 0 {
            self.inner
                .read_exact(&mut buf[..len])
                .await
                .map_err(|_| SessionError::State("udp recv: body read"))?;
        }
        Ok(Some(len))
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn roundtrip_single_datagram() {
        let (a, b) = duplex(64 * 1024);
        let mut tx = UdpFramer::new(a);
        let mut rx = UdpFramer::new(b);
        tx.send(b"hello udp").await.unwrap();
        let got = rx.recv().await.unwrap().unwrap();
        assert_eq!(got, b"hello udp");
    }

    #[tokio::test]
    async fn roundtrip_many_datagrams_preserves_boundaries() {
        let (a, b) = duplex(64 * 1024);
        let mut tx = UdpFramer::new(a);
        let mut rx = UdpFramer::new(b);
        let payloads: Vec<Vec<u8>> = (0..16)
            .map(|i| (0..=i).map(|j| (i * 16 + j) as u8).collect())
            .collect();
        for p in &payloads {
            tx.send(p).await.unwrap();
        }
        // Drop the sender to signal EOF so recv() eventually returns None.
        drop(tx);
        let mut got = Vec::new();
        while let Some(dg) = rx.recv().await.unwrap() {
            got.push(dg);
        }
        assert_eq!(got, payloads);
    }

    #[tokio::test]
    async fn empty_datagram_is_preserved() {
        let (a, b) = duplex(1024);
        let mut tx = UdpFramer::new(a);
        let mut rx = UdpFramer::new(b);
        tx.send(&[]).await.unwrap();
        let got = rx.recv().await.unwrap().unwrap();
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn oversized_datagram_rejected_on_send() {
        let (a, _b) = duplex(64 * 1024);
        let mut tx = UdpFramer::new(a);
        let big = vec![0u8; MAX_UDP_DATAGRAM_BYTES + 1];
        let err = tx.send(&big).await.unwrap_err();
        assert!(matches!(err, SessionError::State(_)));
    }

    #[tokio::test]
    async fn max_size_datagram_roundtrips() {
        let (a, b) = duplex(2 * (MAX_UDP_DATAGRAM_BYTES + 2));
        let mut tx = UdpFramer::new(a);
        let mut rx = UdpFramer::new(b);
        let max = vec![0xABu8; MAX_UDP_DATAGRAM_BYTES];
        tx.send(&max).await.unwrap();
        let got = rx.recv().await.unwrap().unwrap();
        assert_eq!(got, max);
    }

    #[tokio::test]
    async fn forged_length_prefix_over_cap_rejected() {
        // A malicious peer (or corrupted stream) emits a length
        // prefix claiming more bytes than the cap. The framer MUST
        // reject without reading the body - no unbounded
        // allocation.
        let (a, b) = duplex(16);
        let mut rx = UdpFramer::new(b);
        // Write a bogus prefix (length=0xFFFF) directly.
        {
            let mut writer = a;
            use tokio::io::AsyncWriteExt;
            writer.write_all(&[0xFFu8, 0xFFu8]).await.unwrap();
            writer.flush().await.unwrap();
        }
        let err = rx.recv().await.unwrap_err();
        assert!(matches!(err, SessionError::State(_)));
    }

    #[tokio::test]
    async fn truncated_prefix_returns_ok_none() {
        // Peer closes the stream mid-between-datagrams (zero bytes
        // buffered). recv() reports clean EOF.
        let (a, b) = duplex(16);
        let mut rx = UdpFramer::new(b);
        drop(a);
        assert!(rx.recv().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn truncated_body_is_an_error() {
        // Peer sends a length prefix claiming 10 bytes but only
        // writes 5. The reliable-byte-stream invariant is
        // violated; framer surfaces an error, NOT silent
        // truncation.
        let (a, b) = duplex(32);
        let mut rx = UdpFramer::new(b);
        {
            let mut writer = a;
            use tokio::io::AsyncWriteExt;
            writer.write_all(&[0x00u8, 0x0Au8]).await.unwrap(); // claim 10
            writer.write_all(&[0xCC; 5]).await.unwrap(); // deliver 5
            writer.flush().await.unwrap();
            drop(writer);
        }
        let err = rx.recv().await.unwrap_err();
        assert!(matches!(err, SessionError::State(_)));
    }

    #[tokio::test]
    async fn recv_into_rejects_small_buffer() {
        let (a, b) = duplex(1024);
        let mut tx = UdpFramer::new(a);
        let mut rx = UdpFramer::new(b);
        tx.send(&[0u8; 100]).await.unwrap();
        let mut small = [0u8; 50];
        let err = rx.recv_into(&mut small).await.unwrap_err();
        assert!(matches!(err, SessionError::State(_)));
    }

    #[tokio::test]
    async fn recv_into_happy_path() {
        let (a, b) = duplex(1024);
        let mut tx = UdpFramer::new(a);
        let mut rx = UdpFramer::new(b);
        tx.send(b"abcdef").await.unwrap();
        let mut buf = [0u8; 16];
        let n = rx.recv_into(&mut buf).await.unwrap().unwrap();
        assert_eq!(n, 6);
        assert_eq!(&buf[..n], b"abcdef");
    }

    #[tokio::test]
    async fn fuzz_roundtrip_arbitrary_datagrams() {
        use proptest::prelude::*;
        use proptest::strategy::ValueTree;
        // Property: any sequence of datagrams <= cap round-trips
        // with boundaries preserved.
        let strat = prop::collection::vec(prop::collection::vec(any::<u8>(), 0..=200), 0..16);
        for _ in 0..32 {
            let mut runner = proptest::test_runner::TestRunner::default();
            let payloads = strat.new_tree(&mut runner).unwrap().current();
            let (a, b) = duplex(64 * 1024);
            let mut tx = UdpFramer::new(a);
            let mut rx = UdpFramer::new(b);
            for p in &payloads {
                tx.send(p).await.unwrap();
            }
            drop(tx);
            let mut got = Vec::new();
            while let Some(d) = rx.recv().await.unwrap() {
                got.push(d);
            }
            assert_eq!(got, payloads);
        }
    }
}
