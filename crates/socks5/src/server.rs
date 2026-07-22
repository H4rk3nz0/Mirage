//! SOCKS5 CONNECT server: parse negotiation + CONNECT request, open
//! the target TCP connection, emit the reply, and hand the caller
//! the opened upstream so they can bidirectionally copy.
//!
//! This module does NOT run `copy_bidirectional` itself - that
//! belongs to the caller (the `mirage-bridge` binary) so they can
//! bolt on their own instrumentation, logging, or shutdown policy.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::*;

/// SOCKS5 handler errors.
#[derive(Debug, Error)]
pub enum Socks5Error {
    /// Underlying byte-stream I/O failure (peer closed, network, etc.).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Protocol violation from the client.
    #[error("protocol: {0}")]
    Protocol(&'static str),

    /// Client supplied a domain name that is not valid UTF-8.
    #[error("bad domain: {0}")]
    BadDomain(&'static str),

    /// Command the client requested is not supported (BIND, UDP).
    #[error("unsupported command: {0}")]
    UnsupportedCommand(u8),

    /// Address type the client requested is not supported.
    #[error("unsupported address type: {0}")]
    UnsupportedAddressType(u8),

    /// Policy denied the connection (e.g., private-network target).
    #[error("policy: {0}")]
    PolicyDenied(&'static str),

    /// DNS resolution failed for a DOMAIN request.
    #[error("resolve: {0}")]
    Resolve(String),

    /// Upstream TCP connect failed.
    #[error("connect: {0}")]
    Connect(String),
}

/// The target a SOCKS5 client asked us to connect to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectTarget {
    /// Literal IPv4 address.
    Ipv4(Ipv4Addr, u16),
    /// Literal IPv6 address.
    Ipv6(Ipv6Addr, u16),
    /// Domain name - resolved via OS resolver on the bridge.
    Domain(String, u16),
}

impl ConnectTarget {
    /// Port component of the target.
    pub fn port(&self) -> u16 {
        match self {
            Self::Ipv4(_, p) | Self::Ipv6(_, p) | Self::Domain(_, p) => *p,
        }
    }

    /// Host component as a string (for logs / policy checks). Domain
    /// targets return the literal name; IP targets return the
    /// canonical string form.
    pub fn host_str(&self) -> String {
        match self {
            Self::Ipv4(a, _) => a.to_string(),
            Self::Ipv6(a, _) => a.to_string(),
            Self::Domain(d, _) => d.clone(),
        }
    }
}

/// Parsed CONNECT request ready to dial.
#[derive(Debug, Clone)]
pub struct ConnectRequest {
    /// Target the client wants us to reach.
    pub target: ConnectTarget,
}

/// Destination policy: what addresses the bridge is willing to reach
/// on behalf of a SOCKS5 client.
///
/// The default ([`AllowlistPolicy::safe_defaults`]) refuses to
/// connect to loopback, link-local, and RFC 1918 / ULA ranges so a
/// fresh Mirage bridge cannot be weaponized as an internal-network
/// scanner by an attacker with a token.
#[derive(Debug, Clone)]
pub struct AllowlistPolicy {
    /// If true, deny targets that resolve to loopback addresses.
    pub deny_loopback: bool,
    /// If true, deny targets in the RFC 1918 / ULA / link-local
    /// private ranges.
    pub deny_private_networks: bool,
    /// If set, deny connects to ports outside this allowlist.
    /// `None` means all ports are allowed.
    pub allowed_ports: Option<Vec<u16>>,
}

impl AllowlistPolicy {
    /// Recommended safety net for a fresh operator deployment.
    pub fn safe_defaults() -> Self {
        Self {
            deny_loopback: true,
            deny_private_networks: true,
            allowed_ports: None,
        }
    }

    /// Permissive: allows everything. Use only for tests or for a
    /// bridge that intentionally exposes an internal network.
    pub fn permissive() -> Self {
        Self {
            deny_loopback: false,
            deny_private_networks: false,
            allowed_ports: None,
        }
    }

    /// Check a resolved socket address against the policy. Returns
    /// the reason string (stable & short) on denial so the caller
    /// can log it.
    ///
    /// Defense-in-depth coverage for DNS-rebinding-style attacks:
    /// - **IPv4-mapped IPv6** (e.g., `::ffff:127.0.0.1`) is
    ///   canonicalised to its embedded IPv4 before checks. A
    ///   resolver returning the mapped form would otherwise bypass
    ///   `Ipv6Addr::is_loopback()` (which only matches `::1`).
    /// - **IPv4-compatible IPv6** (e.g., `::127.0.0.1`,
    ///   deprecated but still parseable) is also flattened.
    /// - Mirage callers re-resolve per-attempt and check the
    ///   resolved address, which closes the cross-attempt
    ///   rebinding window. Callers MUST also use
    ///   [`Self::check_all`] when a hostname resolves to multiple
    ///   records to refuse the WHOLE attempt if any record is in
    ///   a denied range - a `[public, private]` shuffle from a
    ///   rebinding resolver would otherwise route different
    ///   datagrams of the same session to different IPs.
    pub fn check(&self, addr: &SocketAddr) -> Result<(), &'static str> {
        let ip = canonicalise_ip(addr.ip());
        if self.deny_loopback && ip.is_loopback() {
            return Err("loopback");
        }
        if self.deny_private_networks && is_private(&ip) {
            return Err("private-network");
        }
        if let Some(ports) = &self.allowed_ports {
            if !ports.contains(&addr.port()) {
                return Err("port-not-allowed");
            }
        }
        Ok(())
    }

    /// Check every address in an iterator. Returns `Ok(())` only
    /// if EVERY address passes - a single denied entry fails the
    /// whole resolution.
    ///
    /// Use this on the result of `lookup_host(name).collect()` for
    /// any DNS-resolved destination: a malicious authoritative
    /// nameserver that returns `[public, private]` would otherwise
    /// pass `check(first())` and silently grant internal-network
    /// access on a follow-up datagram.
    pub fn check_all<'a>(
        &self,
        addrs: impl IntoIterator<Item = &'a SocketAddr>,
    ) -> Result<(), &'static str> {
        let mut any = false;
        for a in addrs {
            self.check(a)?;
            any = true;
        }
        if !any {
            return Err("empty-resolution");
        }
        Ok(())
    }
}

/// Normalize IPv6-encoded IPv4 addresses to their canonical IPv4
/// form so the policy's `is_loopback` / `is_private` checks see
/// the right family.
///
/// IPv4-mapped (`::ffff:a.b.c.d`) is flattened to V4. IPv4-compatible
/// (`::a.b.c.d`) is RFC 4291-deprecated and not normalised here -
/// `is_private()`'s `is_unspecified` predicate catches the entire
/// `::/96` range as policy-denied, so the deprecated form fails
/// closed even without flattening. (Earlier versions tried to flatten
/// these too; the boundary check `u128 > 0xff_ffff` had a low-value
/// gap where addresses like `::100` (u128 = 256) escaped both V4
/// canonicalisation and the V6 `is_private` predicate.)
fn canonicalise_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return IpAddr::V4(v4);
            }
            IpAddr::V6(v6)
        }
    }
}

fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            a.is_private()
                || a.is_link_local()
                || a.is_broadcast()
                || a.is_multicast()
                || a.is_unspecified()
                // Carrier-grade NAT 100.64.0.0/10 (RFC 6598)
                || (a.octets()[0] == 100 && (a.octets()[1] & 0xC0) == 0x40)
        }
        IpAddr::V6(a) => {
            // RFC 4291-deprecated IPv4-compatible (`::a.b.c.d`, the
            // upper 96 bits are zero, but the address is non-zero).
            // Modern stacks won't route these but a hostile resolver
            // can return them. Refuse the entire prefix as private.
            let segs = a.segments();
            let v4_compatible_prefix = segs[0] == 0
                && segs[1] == 0
                && segs[2] == 0
                && segs[3] == 0
                && segs[4] == 0
                && segs[5] == 0;
            a.is_loopback()
                || a.is_multicast()
                || a.is_unspecified()
                // Unique-local fc00::/7 per RFC 4193
                || (segs[0] & 0xFE00) == 0xFC00
                // Link-local fe80::/10
                || (segs[0] & 0xFFC0) == 0xFE80
                || v4_compatible_prefix
        }
    }
}

/// Run the SOCKS5 negotiation + request-parse on `stream` and
/// return the parsed request PLUS the stream (method-selection
/// reply has been sent). The caller decides what to do next: open
/// TCP to the target (via [`connect_and_reply`]) or handle the
/// target internally (e.g. a Mirage cohort request).
///
/// The method-selection reply has been written to the stream. The
/// request-reply has NOT - the caller MUST call either
/// [`connect_and_reply`] or [`send_success_reply_for_internal`]
/// before reading app-layer bytes from the client.
pub async fn read_request<S>(mut stream: S) -> Result<(ConnectRequest, S), Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let target = read_request_inner(&mut stream).await?;
    Ok((ConnectRequest { target }, stream))
}

/// Send a SOCKS5 success reply with an all-zero BND address. Use
/// this when the caller is handling the CONNECT target internally
/// (e.g., the Mirage cohort service) and has no upstream socket
/// whose local-addr would be informative.
pub async fn send_success_reply_for_internal<S>(stream: &mut S) -> Result<(), Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    send_reply(stream, REP_SUCCEEDED, &anywhere()).await?;
    Ok(())
}

/// Open the upstream TCP connection for the given request under
/// `policy`, send the appropriate SOCKS5 reply, and return the
/// opened upstream. Mirrors the back-half of the old
/// [`serve_one_connect`].
pub async fn connect_and_reply<S>(
    mut stream: S,
    req: &ConnectRequest,
    policy: &AllowlistPolicy,
    connect_timeout: Duration,
) -> Result<(TcpStream, S), Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let up = connect_to_target(&mut stream, &req.target, policy, connect_timeout).await?;
    let bnd = up
        .local_addr()
        .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
    send_reply(&mut stream, REP_SUCCEEDED, &bnd).await?;
    Ok((up, stream))
}

/// Run one SOCKS5 negotiation + CONNECT on `stream`, returning the
/// opened upstream `TcpStream` ready for bidirectional copy.
///
/// Convenience wrapper around [`read_request`] + [`connect_and_reply`].
pub async fn serve_one_connect<S>(
    stream: S,
    policy: &AllowlistPolicy,
    connect_timeout: Duration,
) -> Result<(ConnectRequest, TcpStream, S), Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (req, stream) = read_request(stream).await?;
    let (up, stream) = connect_and_reply(stream, &req, policy, connect_timeout).await?;
    Ok((req, up, stream))
}

async fn read_request_inner<S>(stream: &mut S) -> Result<ConnectTarget, Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let target = read_request_body(stream).await?;
    Ok(target)
}

async fn read_request_body<S>(stream: &mut S) -> Result<ConnectTarget, Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // --- 1. Method selection (RFC 1928 §3) ---
    //   client -> server: VER | NMETHODS | METHODS
    //   server -> client: VER | METHOD
    let mut hdr = [0u8; 2];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != VERSION {
        // Close without replying; a non-SOCKS5 peer isn't worth
        // spending a reply byte on.
        return Err(Socks5Error::Protocol("bad version in greeting"));
    }
    let nmethods = hdr[1] as usize;
    if nmethods == 0 {
        return Err(Socks5Error::Protocol("nmethods=0"));
    }
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    if !methods.contains(&METHOD_NO_AUTH) {
        stream.write_all(&[VERSION, METHOD_NO_ACCEPTABLE]).await?;
        stream.flush().await?;
        return Err(Socks5Error::Protocol("no acceptable auth method"));
    }
    stream.write_all(&[VERSION, METHOD_NO_AUTH]).await?;
    stream.flush().await?;

    // --- 2. Request (RFC 1928 §4) ---
    //   client -> server: VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
    let mut req_hdr = [0u8; 4];
    stream.read_exact(&mut req_hdr).await?;
    if req_hdr[0] != VERSION {
        return Err(Socks5Error::Protocol("bad version in request"));
    }
    let cmd = req_hdr[1];
    // req_hdr[2] is RSV, ignored per spec.
    let atyp = req_hdr[3];

    if cmd != CMD_CONNECT {
        send_reply(stream, REP_CMD_NOT_SUPPORTED, &anywhere())
            .await
            .ok();
        return Err(Socks5Error::UnsupportedCommand(cmd));
    }

    let target = match atyp {
        ATYP_IPV4 => {
            let mut a = [0u8; 4];
            stream.read_exact(&mut a).await?;
            let mut p = [0u8; 2];
            stream.read_exact(&mut p).await?;
            ConnectTarget::Ipv4(Ipv4Addr::from(a), u16::from_be_bytes(p))
        }
        ATYP_IPV6 => {
            let mut a = [0u8; 16];
            stream.read_exact(&mut a).await?;
            let mut p = [0u8; 2];
            stream.read_exact(&mut p).await?;
            ConnectTarget::Ipv6(Ipv6Addr::from(a), u16::from_be_bytes(p))
        }
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let dlen = len_buf[0] as usize;
            if dlen == 0 {
                return Err(Socks5Error::BadDomain("empty"));
            }
            let mut name = vec![0u8; dlen];
            stream.read_exact(&mut name).await?;
            let name_str = std::str::from_utf8(&name)
                .map_err(|_| Socks5Error::BadDomain("not UTF-8"))?
                .to_string();
            // RFC 1035 §2.3.4 caps label at 63 octets and name at 253.
            if name_str.len() > 253 {
                return Err(Socks5Error::BadDomain("over RFC 1035 length cap"));
            }
            let mut p = [0u8; 2];
            stream.read_exact(&mut p).await?;
            ConnectTarget::Domain(name_str, u16::from_be_bytes(p))
        }
        _ => {
            send_reply(stream, REP_ATYP_NOT_SUPPORTED, &anywhere())
                .await
                .ok();
            return Err(Socks5Error::UnsupportedAddressType(atyp));
        }
    };
    Ok(target)
}

/// Resolve, policy-check, and dial `target`, returning the opened upstream or
/// the SOCKS5 reply code ([`REP_HOST_UNREACHABLE`], [`REP_NOT_ALLOWED`], ...)
/// describing the failure.
///
/// Stream-free so both the classic SOCKS reply path ([`connect_to_target`]) and
/// the mux path (one stream per `MuxTarget`, no SOCKS bytes on the wire) share
/// one resolver/policy/dial implementation. The DNS lookup is bounded by
/// `connect_timeout` so a slow/hung resolver cannot stall the caller unbounded.
pub async fn connect_target(
    target: &ConnectTarget,
    policy: &AllowlistPolicy,
    connect_timeout: Duration,
) -> Result<TcpStream, u8> {
    let resolved: Vec<SocketAddr> = match target {
        ConnectTarget::Ipv4(a, p) => vec![SocketAddr::new(IpAddr::V4(*a), *p)],
        ConnectTarget::Ipv6(a, p) => vec![SocketAddr::new(IpAddr::V6(*a), *p)],
        ConnectTarget::Domain(name, p) => {
            // Any `_mirage_*` magic hostname must be dispatched before here; if
            // one slips through, refuse rather than leak it to the resolver.
            if name.starts_with('_') && name.to_ascii_lowercase().starts_with("_mirage_") {
                return Err(REP_HOST_UNREACHABLE);
            }
            match tokio::time::timeout(
                connect_timeout,
                tokio::net::lookup_host((name.as_str(), *p)),
            )
            .await
            {
                Ok(Ok(iter)) => iter.collect(),
                Ok(Err(_)) => return Err(REP_HOST_UNREACHABLE),
                Err(_) => return Err(REP_HOST_UNREACHABLE), // resolver timed out
            }
        }
    };
    if resolved.is_empty() {
        return Err(REP_HOST_UNREACHABLE);
    }

    // Filter candidates through policy first, then dial each in turn (a name may
    // resolve to both v4 and v6 with only one reachable).
    let mut allowed: Vec<SocketAddr> = Vec::with_capacity(resolved.len());
    for addr in &resolved {
        if policy.check(addr).is_ok() {
            allowed.push(*addr);
        }
    }
    if allowed.is_empty() {
        debug!(
            target = %target.host_str(),
            port = target.port(),
            "socks5: policy denied connect"
        );
        return Err(REP_NOT_ALLOWED);
    }

    let mut last_kind = std::io::ErrorKind::Other;
    for dest in &allowed {
        match tokio::time::timeout(connect_timeout, TcpStream::connect(dest)).await {
            Ok(Ok(s)) => {
                s.set_nodelay(true).ok();
                return Ok(s);
            }
            Ok(Err(e)) => {
                debug!(dest = %dest, error = %e, "socks5: connect attempt failed, trying next");
                last_kind = e.kind();
            }
            Err(_) => last_kind = std::io::ErrorKind::TimedOut,
        }
    }
    Err(match last_kind {
        std::io::ErrorKind::ConnectionRefused => REP_CONN_REFUSED,
        std::io::ErrorKind::NetworkUnreachable => REP_NET_UNREACHABLE,
        std::io::ErrorKind::HostUnreachable => REP_HOST_UNREACHABLE,
        std::io::ErrorKind::TimedOut => REP_HOST_UNREACHABLE,
        _ => REP_GENERAL_FAILURE,
    })
}

async fn connect_to_target<S>(
    stream: &mut S,
    target: &ConnectTarget,
    policy: &AllowlistPolicy,
    connect_timeout: Duration,
) -> Result<TcpStream, Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match connect_target(target, policy, connect_timeout).await {
        Ok(up) => Ok(up),
        Err(rep) => {
            send_reply(stream, rep, &anywhere()).await.ok();
            Err(Socks5Error::Connect(format!(
                "connect to {}:{} failed (rep 0x{rep:02x})",
                target.host_str(),
                target.port()
            )))
        }
    }
}

fn anywhere() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
}

async fn send_reply<S: AsyncWrite + Unpin>(
    stream: &mut S,
    rep: u8,
    bnd: &SocketAddr,
) -> Result<(), std::io::Error> {
    let mut buf = Vec::with_capacity(22);
    buf.push(VERSION);
    buf.push(rep);
    buf.push(0x00); // RSV
    match bnd.ip() {
        IpAddr::V4(a) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&a.octets());
        }
    }
    buf.extend_from_slice(&bnd.port().to_be_bytes());
    if let Err(e) = stream.write_all(&buf).await {
        warn!(error = %e, "socks5: failed to send reply");
        return Err(e);
    }
    stream.flush().await
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    /// Spawn a one-shot echo server on 127.0.0.1 and return its
    /// bound address + port.
    async fn echo_server() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = l.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = sock.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                    let _ = w.shutdown().await;
                });
            }
        });
        addr
    }

    /// Spawn the bridge side running a single `serve_one_connect`
    /// against a TCP listener on localhost.
    async fn spawn_bridge(policy: AllowlistPolicy) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _peer) = l.accept().await.unwrap();
            let timeout = Duration::from_secs(3);
            let (_req, mut up, mut s) = match serve_one_connect(stream, &policy, timeout).await {
                Ok(v) => v,
                Err(_) => return,
            };
            let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
        });
        addr
    }

    #[tokio::test]
    async fn connect_to_loopback_echo_via_domain_lookup() {
        // Use permissive policy because echo_server binds 127.0.0.1.
        let echo = echo_server().await;
        let bridge = spawn_bridge(AllowlistPolicy::permissive()).await;

        let mut c = TcpStream::connect(bridge).await.unwrap();
        // Greeting.
        c.write_all(&[VERSION, 1, METHOD_NO_AUTH]).await.unwrap();
        let mut g = [0u8; 2];
        c.read_exact(&mut g).await.unwrap();
        assert_eq!(g, [VERSION, METHOD_NO_AUTH]);

        // CONNECT to "localhost:echo_port".
        let name = b"localhost";
        let mut req = vec![VERSION, CMD_CONNECT, 0, ATYP_DOMAIN];
        req.push(name.len() as u8);
        req.extend_from_slice(name);
        req.extend_from_slice(&echo.port().to_be_bytes());
        c.write_all(&req).await.unwrap();

        // Reply prefix: VER REP RSV ATYP then BND.ADDR+BND.PORT.
        let mut r = [0u8; 4];
        c.read_exact(&mut r).await.unwrap();
        assert_eq!(r[0], VERSION);
        assert_eq!(r[1], REP_SUCCEEDED);
        // Drain BND by atyp.
        match r[3] {
            ATYP_IPV4 => {
                let mut x = [0u8; 6];
                c.read_exact(&mut x).await.unwrap();
            }
            ATYP_IPV6 => {
                let mut x = [0u8; 18];
                c.read_exact(&mut x).await.unwrap();
            }
            _ => panic!("unexpected BND atyp"),
        }

        c.write_all(b"ping").await.unwrap();
        let mut pong = [0u8; 4];
        c.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"ping");
    }

    #[tokio::test]
    async fn connect_to_ipv4_literal_echo() {
        let echo = echo_server().await;
        let bridge = spawn_bridge(AllowlistPolicy::permissive()).await;

        let mut c = TcpStream::connect(bridge).await.unwrap();
        c.write_all(&[VERSION, 1, METHOD_NO_AUTH]).await.unwrap();
        let mut g = [0u8; 2];
        c.read_exact(&mut g).await.unwrap();

        let ip = match echo.ip() {
            IpAddr::V4(a) => a,
            _ => panic!("echo not ipv4"),
        };
        let mut req = vec![VERSION, CMD_CONNECT, 0, ATYP_IPV4];
        req.extend_from_slice(&ip.octets());
        req.extend_from_slice(&echo.port().to_be_bytes());
        c.write_all(&req).await.unwrap();

        let mut r = [0u8; 4];
        c.read_exact(&mut r).await.unwrap();
        assert_eq!(r[1], REP_SUCCEEDED);
        let mut bnd = [0u8; 6];
        c.read_exact(&mut bnd).await.unwrap();

        c.write_all(b"hi").await.unwrap();
        let mut got = [0u8; 2];
        c.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hi");
    }

    #[tokio::test]
    async fn rejects_wrong_version() {
        let bridge = spawn_bridge(AllowlistPolicy::permissive()).await;
        let mut c = TcpStream::connect(bridge).await.unwrap();
        c.write_all(&[0x04, 1, 0]).await.unwrap(); // SOCKS4, nope.
        let mut tail = [0u8; 2];
        // Bridge closes without replying -> read yields 0 or an error.
        let _ = c.read(&mut tail).await;
    }

    #[tokio::test]
    async fn rejects_no_acceptable_method() {
        let bridge = spawn_bridge(AllowlistPolicy::permissive()).await;
        let mut c = TcpStream::connect(bridge).await.unwrap();
        // Offer only USERNAME/PASSWORD (0x02), no NO_AUTH.
        c.write_all(&[VERSION, 1, 0x02]).await.unwrap();
        let mut reply = [0u8; 2];
        c.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [VERSION, METHOD_NO_ACCEPTABLE]);
    }

    #[tokio::test]
    async fn rejects_unsupported_bind_command() {
        let bridge = spawn_bridge(AllowlistPolicy::permissive()).await;
        let mut c = TcpStream::connect(bridge).await.unwrap();
        c.write_all(&[VERSION, 1, METHOD_NO_AUTH]).await.unwrap();
        let mut g = [0u8; 2];
        c.read_exact(&mut g).await.unwrap();
        // Valid-looking BIND request to 127.0.0.1:80.
        c.write_all(&[VERSION, CMD_BIND, 0, ATYP_IPV4, 127, 0, 0, 1, 0x00, 0x50])
            .await
            .unwrap();
        let mut r = [0u8; 4];
        c.read_exact(&mut r).await.unwrap();
        assert_eq!(r[1], REP_CMD_NOT_SUPPORTED);
    }

    #[tokio::test]
    async fn safe_defaults_deny_loopback_target() {
        let echo = echo_server().await;
        let bridge = spawn_bridge(AllowlistPolicy::safe_defaults()).await;

        let mut c = TcpStream::connect(bridge).await.unwrap();
        c.write_all(&[VERSION, 1, METHOD_NO_AUTH]).await.unwrap();
        let mut g = [0u8; 2];
        c.read_exact(&mut g).await.unwrap();

        let ip = match echo.ip() {
            IpAddr::V4(a) => a,
            _ => panic!(),
        };
        let mut req = vec![VERSION, CMD_CONNECT, 0, ATYP_IPV4];
        req.extend_from_slice(&ip.octets());
        req.extend_from_slice(&echo.port().to_be_bytes());
        c.write_all(&req).await.unwrap();

        let mut r = [0u8; 4];
        c.read_exact(&mut r).await.unwrap();
        assert_eq!(r[1], REP_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn policy_denies_rfc_1918() {
        let policy = AllowlistPolicy::safe_defaults();
        let rfc1918 = "10.0.0.1:80".parse().unwrap();
        assert!(matches!(policy.check(&rfc1918), Err("private-network")));
    }

    #[tokio::test]
    async fn policy_denies_link_local() {
        let policy = AllowlistPolicy::safe_defaults();
        let ll: SocketAddr = "169.254.1.1:80".parse().unwrap();
        assert!(matches!(policy.check(&ll), Err("private-network")));
    }

    #[tokio::test]
    async fn policy_denies_ipv4_mapped_loopback() {
        // ::ffff:127.0.0.1 - IPv4-mapped form of 127.0.0.1.
        // Without canonicalisation, Ipv6Addr::is_loopback() only
        // matches `::1` and this would slip through.
        let policy = AllowlistPolicy::safe_defaults();
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:80".parse().unwrap();
        assert!(
            matches!(policy.check(&mapped), Err("loopback")),
            "::ffff:127.0.0.1 must be denied as loopback"
        );
    }

    #[tokio::test]
    async fn policy_denies_ipv4_mapped_rfc1918() {
        let policy = AllowlistPolicy::safe_defaults();
        let mapped: SocketAddr = "[::ffff:10.0.0.1]:80".parse().unwrap();
        assert!(
            matches!(policy.check(&mapped), Err("private-network")),
            "::ffff:10.0.0.1 must be denied as private"
        );
    }

    #[tokio::test]
    async fn policy_denies_low_value_v4_compatible_v6() {
        // IPv4-compatible (deprecated) `::a.b.c.d`. The pre-fix
        // canonicalise had a `u128 > 0xff_ffff` boundary that
        // skipped low-value addresses like `::100` (u128 = 256).
        // After fix: the entire `::/96` prefix is treated as
        // private at the V6 layer.
        let policy = AllowlistPolicy::safe_defaults();
        // ::100 == 0.0.1.0 in v4-compat form (u128 = 256, was the gap).
        let low: SocketAddr = "[::100]:80".parse().unwrap();
        assert!(
            matches!(policy.check(&low), Err("private-network")),
            "low-value v4-compatible v6 must be denied"
        );
        // Same for `::a.b.c.d` of any non-zero value.
        let mid: SocketAddr = "[::1.2.3.4]:80".parse().unwrap();
        assert!(
            matches!(policy.check(&mid), Err("private-network")),
            "v4-compatible mid-range must be denied"
        );
    }

    #[tokio::test]
    async fn check_all_rejects_if_any_resolution_record_is_private() {
        // Simulates a DNS-rebinding-style multi-record return.
        // Even if the operator wanted to use the public IP, a
        // bundled private one means the resolver's response is
        // suspect - refuse the whole resolution.
        let policy = AllowlistPolicy::safe_defaults();
        let public: SocketAddr = "1.1.1.1:80".parse().unwrap();
        let private: SocketAddr = "10.0.0.1:80".parse().unwrap();
        assert!(matches!(
            policy.check_all(&[public, private]),
            Err("private-network")
        ));
    }

    #[tokio::test]
    async fn check_all_passes_when_all_public() {
        let policy = AllowlistPolicy::safe_defaults();
        let a: SocketAddr = "1.1.1.1:80".parse().unwrap();
        let b: SocketAddr = "8.8.8.8:80".parse().unwrap();
        assert!(policy.check_all(&[a, b]).is_ok());
    }

    #[tokio::test]
    async fn check_all_rejects_empty_resolution() {
        let policy = AllowlistPolicy::safe_defaults();
        let empty: [SocketAddr; 0] = [];
        assert!(matches!(policy.check_all(&empty), Err("empty-resolution")));
    }

    #[tokio::test]
    async fn policy_allowed_ports_are_enforced() {
        let policy = AllowlistPolicy {
            deny_loopback: false,
            deny_private_networks: false,
            allowed_ports: Some(vec![443]),
        };
        let ok: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let nope: SocketAddr = "1.1.1.1:22".parse().unwrap();
        assert!(policy.check(&ok).is_ok());
        assert!(matches!(policy.check(&nope), Err("port-not-allowed")));
    }

    #[tokio::test]
    async fn empty_domain_is_rejected() {
        let bridge = spawn_bridge(AllowlistPolicy::permissive()).await;
        let mut c = TcpStream::connect(bridge).await.unwrap();
        c.write_all(&[VERSION, 1, METHOD_NO_AUTH]).await.unwrap();
        let mut g = [0u8; 2];
        c.read_exact(&mut g).await.unwrap();
        // DOMAIN with len=0.
        c.write_all(&[VERSION, CMD_CONNECT, 0, ATYP_DOMAIN, 0, 0, 80])
            .await
            .unwrap();
        // Server errors out without replying (protocol violation); read 0 or err.
        let mut tail = [0u8; 16];
        let _ = c.read(&mut tail).await;
    }

    #[tokio::test]
    async fn upstream_connection_refused_is_reported() {
        // Policy: permissive. Target: localhost:1 which won't listen.
        let bridge = spawn_bridge(AllowlistPolicy::permissive()).await;
        let mut c = TcpStream::connect(bridge).await.unwrap();
        c.write_all(&[VERSION, 1, METHOD_NO_AUTH]).await.unwrap();
        let mut g = [0u8; 2];
        c.read_exact(&mut g).await.unwrap();

        // Request CONNECT to 127.0.0.1:1.
        c.write_all(&[VERSION, CMD_CONNECT, 0, ATYP_IPV4, 127, 0, 0, 1, 0x00, 0x01])
            .await
            .unwrap();
        let mut r = [0u8; 4];
        c.read_exact(&mut r).await.unwrap();
        assert_eq!(r[0], VERSION);
        // Accept either explicit CONN_REFUSED or GENERAL_FAILURE
        // depending on how the OS reports; both are meaningful.
        assert!(r[1] == REP_CONN_REFUSED || r[1] == REP_GENERAL_FAILURE);
    }
}
