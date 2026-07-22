//! Local-side SOCKS5 termination for the client.
//!
//! Historically the client piped the app's local TCP stream RAW to the
//! bridge's SOCKS5 server. That works for CONNECT but cannot support UDP
//! ASSOCIATE (the client must open a local UDP socket and tell the app its
//! address) and cannot fail over within a connection (the raw stream is
//! committed to one bridge).
//!
//! This module lets the client peek the SOCKS5 *command* by doing the
//! greeting + method-selection locally, then:
//!   - **CONNECT**: wrap the local stream in [`Socks5ReplayStream`] so the
//!     consumed greeting+request bytes are replayed to the bridge and the
//!     bridge's own 2-byte method-selection reply is swallowed - the existing
//!     raw-pipe dial path then works UNCHANGED.
//!   - **UDP ASSOCIATE**: hand control to the UDP-over-tunnel path.
//!
//! Keeping this surgical means the validated CONNECT path is byte-identical on
//! the wire; only the *who terminates the greeting* changes.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

const VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;
pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// The SOCKS5 command the local app requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalCommand {
    Connect,
    UdpAssociate,
}

/// The parsed destination of a SOCKS5 request. For the mux path the client
/// carries this in the mux `Begin` frame instead of replaying raw SOCKS bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    /// A literal IP address + port.
    Ip(std::net::SocketAddr),
    /// A domain name + port (browsers using remote DNS / socks5h send these).
    Domain(String, u16),
}

/// The result of locally negotiating + reading one SOCKS5 request.
pub struct LocalRequest {
    pub command: LocalCommand,
    /// The app's greeting + request bytes, captured verbatim so they can be
    /// replayed to the bridge's SOCKS5 server for a legacy (non-mux) CONNECT.
    pub replay: Vec<u8>,
    /// The parsed destination (present for CONNECT; for UDP ASSOCIATE it is the
    /// app's advertised relay address, which the mux path does not use).
    pub dest: Destination,
}

/// Negotiate SOCKS5 method selection and read the request header on `stream`,
/// returning the command + the bytes to replay. The 2-byte method-selection
/// reply (`05 00`) is written to the app here; the request's BND reply is NOT
/// (the caller sends it - a CONNECT lets the bridge do it via replay, a UDP
/// ASSOCIATE needs the local relay address).
pub async fn read_local_request<S>(stream: &mut S) -> Result<LocalRequest, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut replay = Vec::with_capacity(32);

    // -- greeting: VER NMETHODS METHODS --
    let mut hdr = [0u8; 2];
    stream
        .read_exact(&mut hdr)
        .await
        .map_err(|e| format!("socks5 greeting: {e}"))?;
    if hdr[0] != VERSION {
        return Err(format!("not socks5 (ver=0x{:02x})", hdr[0]));
    }
    replay.extend_from_slice(&hdr);
    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream
        .read_exact(&mut methods)
        .await
        .map_err(|e| format!("socks5 methods: {e}"))?;
    replay.extend_from_slice(&methods);
    if !methods.contains(&METHOD_NO_AUTH) {
        let _ = stream.write_all(&[VERSION, METHOD_NONE_ACCEPTABLE]).await;
        return Err("client offered no NO_AUTH method".to_string());
    }
    // Method-selection reply to the APP (not replayed to the bridge).
    stream
        .write_all(&[VERSION, METHOD_NO_AUTH])
        .await
        .map_err(|e| format!("socks5 method reply: {e}"))?;

    // -- request: VER CMD RSV ATYP DST.ADDR DST.PORT --
    let mut req = [0u8; 4];
    stream
        .read_exact(&mut req)
        .await
        .map_err(|e| format!("socks5 request header: {e}"))?;
    if req[0] != VERSION {
        return Err(format!("bad socks5 request ver=0x{:02x}", req[0]));
    }
    replay.extend_from_slice(&req);
    let cmd = req[1];
    let atyp = req[3];
    // Capture the destination as we parse each ATYP form.
    enum ParsedAddr {
        V4([u8; 4]),
        V6([u8; 16]),
        Domain(String),
    }
    let parsed = match atyp {
        ATYP_IPV4 => {
            let mut a = [0u8; 4];
            stream
                .read_exact(&mut a)
                .await
                .map_err(|e| format!("socks5 ipv4: {e}"))?;
            replay.extend_from_slice(&a);
            ParsedAddr::V4(a)
        }
        ATYP_IPV6 => {
            let mut a = [0u8; 16];
            stream
                .read_exact(&mut a)
                .await
                .map_err(|e| format!("socks5 ipv6: {e}"))?;
            replay.extend_from_slice(&a);
            ParsedAddr::V6(a)
        }
        ATYP_DOMAIN => {
            let mut l = [0u8; 1];
            stream
                .read_exact(&mut l)
                .await
                .map_err(|e| format!("socks5 domain len: {e}"))?;
            replay.push(l[0]);
            let mut name = vec![0u8; l[0] as usize];
            stream
                .read_exact(&mut name)
                .await
                .map_err(|e| format!("socks5 domain: {e}"))?;
            replay.extend_from_slice(&name);
            ParsedAddr::Domain(String::from_utf8_lossy(&name).into_owned())
        }
        other => return Err(format!("unsupported ATYP 0x{other:02x}")),
    };
    let mut port_bytes = [0u8; 2];
    stream
        .read_exact(&mut port_bytes)
        .await
        .map_err(|e| format!("socks5 port: {e}"))?;
    replay.extend_from_slice(&port_bytes);
    let port = u16::from_be_bytes(port_bytes);

    let dest = match parsed {
        ParsedAddr::V4(a) => Destination::Ip(std::net::SocketAddr::from((a, port))),
        ParsedAddr::V6(a) => Destination::Ip(std::net::SocketAddr::from((a, port))),
        ParsedAddr::Domain(d) => Destination::Domain(d, port),
    };

    let command = match cmd {
        CMD_CONNECT => LocalCommand::Connect,
        CMD_UDP_ASSOCIATE => LocalCommand::UdpAssociate,
        other => return Err(format!("unsupported SOCKS5 command 0x{other:02x}")),
    };
    Ok(LocalRequest {
        command,
        replay,
        dest,
    })
}

/// Write a SOCKS5 CONNECT reply to the app: `VER REP RSV ATYP BND.ADDR
/// BND.PORT` with a `0.0.0.0:0` bind address. On the mux path the *client*
/// synthesizes this reply (the bridge no longer speaks SOCKS over the tunnel),
/// so a successful `rep = 0x00` is sent once the bridge confirms the upstream
/// connected, and a failure code is sent if it could not.
pub async fn send_connect_reply<S>(stream: &mut S, rep: u8) -> Result<(), String>
where
    S: AsyncWrite + Unpin,
{
    let reply = [VERSION, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
    stream
        .write_all(&reply)
        .await
        .map_err(|e| format!("socks5 connect reply: {e}"))
}

/// Send the SOCKS5 reply for a UDP ASSOCIATE: `VER REP RSV ATYP BND.ADDR
/// BND.PORT`, where BND is the local relay UDP socket the app should send
/// datagrams to.
pub async fn send_udp_associate_reply<S>(
    stream: &mut S,
    relay: std::net::SocketAddr,
) -> Result<(), String>
where
    S: AsyncWrite + Unpin,
{
    let mut reply = vec![VERSION, 0x00, 0x00]; // VER, REP=succeeded, RSV
    match relay {
        std::net::SocketAddr::V4(a) => {
            reply.push(ATYP_IPV4);
            reply.extend_from_slice(&a.ip().octets());
            reply.extend_from_slice(&a.port().to_be_bytes());
        }
        std::net::SocketAddr::V6(a) => {
            reply.push(ATYP_IPV6);
            reply.extend_from_slice(&a.ip().octets());
            reply.extend_from_slice(&a.port().to_be_bytes());
        }
    }
    stream
        .write_all(&reply)
        .await
        .map_err(|e| format!("socks5 udp-associate reply: {e}"))
}

/// A stream adapter that makes a locally-terminated SOCKS5 CONNECT look, to the
/// downstream raw-pipe dial path, exactly like an un-terminated one:
///   - **reads** first yield `replay` (the app's greeting+request), then the
///     real inner stream - so the bridge's SOCKS5 server sees the full request.
///   - **writes** swallow the first `skip_write` bytes (the bridge's `05 00`
///     method-selection reply, which the app already received locally), then
///     pass through - so the app sees only its CONNECT reply + data.
pub struct Socks5ReplayStream<S> {
    inner: S,
    replay: Vec<u8>,
    replay_pos: usize,
    skip_write: usize,
}

impl<S> Socks5ReplayStream<S> {
    pub fn new(inner: S, replay: Vec<u8>, skip_write: usize) -> Self {
        Self {
            inner,
            replay,
            replay_pos: 0,
            skip_write,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Socks5ReplayStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.replay_pos < self.replay.len() {
            let remaining = &self.replay[self.replay_pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.replay_pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Socks5ReplayStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.skip_write > 0 {
            // Swallow up to skip_write bytes. Reporting them as "written" makes
            // copy_bidirectional advance past them and call again with the rest;
            // by then skip_write has reached 0 and we write through.
            let skip = self.skip_write.min(buf.len());
            self.skip_write -= skip;
            return Poll::Ready(Ok(skip));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn read_local_request_parses_connect_and_captures_replay() {
        let (mut client, server) = tokio::io::duplex(256);
        // App side: greeting (NO_AUTH) + CONNECT 1.2.3.4:443.
        let app = tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut m = [0u8; 2];
            client.read_exact(&mut m).await.unwrap();
            assert_eq!(m, [0x05, 0x00]);
            client
                .write_all(&[0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xBB])
                .await
                .unwrap();
            client
        });
        let mut server = server;
        let req = read_local_request(&mut server).await.unwrap();
        assert_eq!(req.command, LocalCommand::Connect);
        // Replay = greeting (3) + request (4 + 4 + 2) verbatim.
        assert_eq!(
            req.replay,
            vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xBB]
        );
        app.await.unwrap();
    }

    #[tokio::test]
    async fn read_local_request_detects_udp_associate() {
        let (mut client, server) = tokio::io::duplex(256);
        tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut m = [0u8; 2];
            client.read_exact(&mut m).await.unwrap();
            // UDP ASSOCIATE with DST 0.0.0.0:0.
            client
                .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        let mut server = server;
        let req = read_local_request(&mut server).await.unwrap();
        assert_eq!(req.command, LocalCommand::UdpAssociate);
    }

    #[tokio::test]
    async fn replay_stream_replays_then_reads_and_swallows_method_reply() {
        // inner stream simulates the bridge: it will receive the replay on
        // reads-from-us, and emits [05 00] (swallowed) + [aa bb] (passed).
        let (bridge, mut probe) = tokio::io::duplex(256);
        let mut s = Socks5ReplayStream::new(bridge, vec![0xDE, 0xAD], 2);

        // Read side: first two bytes are the replay, then whatever inner has.
        let mut got = [0u8; 2];
        s.read_exact(&mut got).await.unwrap();
        assert_eq!(got, [0xDE, 0xAD], "replay yielded first");

        // Write side: write [05 00 aa bb]; the 05 00 must be swallowed, aa bb
        // delivered to the inner (probe) side.
        s.write_all(&[0x05, 0x00, 0xAA, 0xBB]).await.unwrap();
        s.flush().await.unwrap();
        let mut delivered = [0u8; 2];
        probe.read_exact(&mut delivered).await.unwrap();
        assert_eq!(
            delivered,
            [0xAA, 0xBB],
            "method reply swallowed, rest passed"
        );
    }
}
