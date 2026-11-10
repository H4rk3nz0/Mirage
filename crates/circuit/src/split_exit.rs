//! Split-exit (resolver/forwarder) protocol.
//!
//! # Why
//!
//! Tor's exit problem isn't that exits are malicious - it's
//! structural. The last hop in a Tor circuit must perform DNS
//! resolution AND open the TCP socket AND pump bytes between the
//! socket and the circuit. A single node holds both the
//! destination hostname (from `BEGIN host:port`) and the
//! application-layer bytes. One compromised exit leaks both.
//!
//! Mirage v0.2's split-exit divides that role across **two
//! cooperating hops** so no single relay holds both halves:
//!
//! - **R (resolver)** - second-to-last hop. Receives `CMD_RESOLVE`
//!   from the client, performs DNS, sends `CMD_HANDOFF(ip:port)` to
//!   F. R sees the destination hostname but is structurally unable
//!   to read application bytes (R does not hold F's onion key for
//!   the inner layer that wraps the bytes).
//! - **F (forwarder)** - last hop. Receives `CMD_HANDOFF` carrying
//!   only an IP literal, opens the TCP socket, and pumps bytes via
//!   the existing `RELAY_DATA` path. F sees bytes but learns only
//!   the IP it was told to dial - never the original hostname.
//!
//! ```text
//!  Client                 A                    B               R                F          dest
//!  ------                 --                   --              --               --         ----
//!  RESOLVE host:port ----------------------------------------->
//!                                                              dns(host) -> ip
//!                                                              HANDOFF(ip,port) ->
//!                                                                                connect()
//!                                                              <- HANDOFF_RESULT(ok)
//!  <-------------------------------------  RELAY_BEGIN_OK
//!  RELAY_DATA(bytes) ------onion-encrypted, F decrypts last layer---------------> socket
//! ```
//!
//! # Property
//!
//! **No single relay simultaneously holds (a) the destination
//! hostname and (b) the application-layer plaintext bytes.**
//!
//! - R has (a), not (b). The bytes stay onion-encrypted past R
//!   because R does not have F's per-stream key.
//! - F has (b), not (a). The hostname is delivered to R; F
//!   receives only an IP literal via [`HandoffBody`].
//! - A passive logger at either hop captures only its half.
//!
//! # Limitations
//!
//! - **F still sees the IP.** For destinations on dedicated IPs,
//!   reverse-DNS recovers the hostname. The split helps most for
//!   shared-hosting / CDN traffic where IP->host is ambiguous.
//! - **R+F collusion = full exposure.** Same n-of-n problem as
//!   any onion network. The split raises the bar from one bad
//!   node to two.
//! - **Plaintext HTTP at F is still plaintext.** F is the one
//!   with the socket. For HTTPS+ECH F sees ciphertext + IP only;
//!   for plain HTTP F sees the request and response. This is
//!   structural - to fix it, the destination has to participate
//!   (see Mirage hidden services for the in-protocol case).
//!
//! # Wire formats
//!
//! See the body codecs in this module:
//! - [`ResolveBody`] - client -> R
//! - [`HandoffBody`] - R -> F
//! - [`HandoffResultBody`] - F -> R
//!
//! All three ride as `CMD_RESOLVE` / `CMD_HANDOFF` /
//! `CMD_HANDOFF_RESULT` cell bodies. See
//! [`crate::cell::CMD_RESOLVE`].
//!
//! # I/O-free state machines
//!
//! [`ResolverState`] and [`ForwarderState`] are pure-logic state
//! machines mirroring the design used in `mirage-mux::state` and
//! `mirage-migration::state`. Callers (the bridge daemon's circuit
//! handler) drive DNS and TCP themselves and feed results back via
//! the `record_*` methods. Phase 1 ships this module; Phase 2 wires
//! it into the bridge runtime.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};
use thiserror::Error;

// Errors

/// Errors produced by split-exit codecs and state machines.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SplitExitError {
    /// Wire-format violation (truncated, bad length, unknown atyp).
    #[error("wire: {0}")]
    Wire(&'static str),
    /// Hostname length out of [1, 253].
    #[error("hostname length {0} out of range")]
    HostLength(usize),
    /// Hostname carries non-LDH bytes.
    #[error("hostname not LDH-conformant")]
    HostNotLdh,
    /// Hostname is not valid UTF-8.
    #[error("hostname not UTF-8")]
    HostEncoding,
    /// Port `0` reserved.
    #[error("port 0 reserved")]
    ZeroPort,
    /// `HandoffBody` carried a domain ATYP. The forwarder MUST
    /// receive only an IP literal - surfacing a hostname here
    /// would defeat the split-exit property by giving F access
    /// to the destination name.
    #[error("HANDOFF body must not carry a hostname")]
    DomainNotAllowedInHandoff,
    /// Status byte in `HandoffResultBody` is not a known value.
    #[error("unknown handoff status {0:#04x}")]
    UnknownStatus(u8),
    /// Stream id `0` reserved (matches RELAY stream-id convention).
    #[error("stream id 0 reserved")]
    ZeroStreamId,
    /// State-machine: stream id already in use on this side.
    #[error("stream {0} already exists")]
    StreamExists(u32),
    /// State-machine: stream id not known to this side.
    #[error("stream {0} unknown")]
    UnknownStream(u32),
    /// State-machine: requested transition isn't legal from the
    /// current per-stream state.
    #[error("stream {stream_id} in state {state:?} can't accept op")]
    BadState {
        /// The offending stream's id.
        stream_id: u32,
        /// The current state.
        state: ResolverStreamState,
    },
    /// State-machine (forwarder side): requested transition isn't
    /// legal from the current per-stream state.
    #[error("forwarder stream {stream_id} in state {state:?} can't accept op")]
    BadForwarderState {
        /// The offending stream's id.
        stream_id: u32,
        /// The current state.
        state: ForwarderStreamState,
    },
    /// R-side rate limit on outstanding RESOLVEs. Without this a
    /// hostile client could keep the resolver pegged on DNS work.
    #[error("resolver pending-resolve cap reached ({0})")]
    ResolverPendingCap(u32),
    /// F-side rate limit on outstanding connects. Without this R
    /// could `DoS` F by issuing handoffs to bogus IPs.
    #[error("forwarder pending-connect cap reached ({0})")]
    ForwarderPendingCap(u32),
    /// R-side cap on TOTAL tracked streams (pending + Open). The
    /// pending cap only bounds pre-Open streams; without this an
    /// Open-and-never-closed stream flood would grow the map
    /// unbounded (memory `DoS`).
    #[error("resolver total-stream cap reached ({0})")]
    ResolverStreamCap(u32),
    /// F-side cap on TOTAL tracked streams (pending + Open). Same
    /// rationale as [`Self::ResolverStreamCap`].
    #[error("forwarder total-stream cap reached ({0})")]
    ForwarderStreamCap(u32),
}

// Wire-format atyp constants

/// `ATYP` byte for IPv4 addresses. Matches RFC 1928 §4.
pub const HANDOFF_ATYP_IPV4: u8 = 0x01;
/// `ATYP` byte for IPv6 addresses. Matches RFC 1928 §4.
pub const HANDOFF_ATYP_IPV6: u8 = 0x04;

/// `ATYP` byte for hostnames in [`ResolveBody`]. Domain only -
/// IP literals in RESOLVE go through the IPv4/IPv6 atyp variants
/// since R has nothing to resolve.
pub const RESOLVE_ATYP_DOMAIN: u8 = 0x03;

// HandoffStatus - F -> R signal

/// Outcome of F's TCP connect to the IP that R handed off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum HandoffStatus {
    /// Connect succeeded; the stream is now open.
    Ok = 0,
    /// F's policy refused the destination (port not in allowlist,
    /// IP in blocklist, etc.).
    PolicyDenied = 1,
    /// Peer refused the TCP connect (RST / EHOSTUNREACH).
    ConnectRefused = 2,
    /// Connect timed out.
    ConnectTimeout = 3,
    /// F's per-stream / per-circuit rate budget is exhausted.
    RateLimited = 4,
    /// Unspecified internal error.
    Internal = 5,
}

impl HandoffStatus {
    /// Decode the status byte. Errors on unknown codepoints.
    pub fn from_byte(b: u8) -> Result<Self, SplitExitError> {
        match b {
            0 => Ok(Self::Ok),
            1 => Ok(Self::PolicyDenied),
            2 => Ok(Self::ConnectRefused),
            3 => Ok(Self::ConnectTimeout),
            4 => Ok(Self::RateLimited),
            5 => Ok(Self::Internal),
            other => Err(SplitExitError::UnknownStatus(other)),
        }
    }

    /// Wire byte.
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// True iff the stream should be considered open after this
    /// status is received.
    pub fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }
}

// ResolveBody - client -> R

/// Body of a `CMD_RESOLVE` cell. Client tells R which destination
/// to look up + dial.
///
/// Wire format (variable, depends on atyp):
///
/// ```text
///  Offset  Size   Field
///  ------  ----   -----
///  0       4      stream_id  (u32 BE; per-circuit-local; zero reserved)
///  4       1      atyp (0x01 IPv4, 0x03 Domain, 0x04 IPv6)
///  5       var    addr (IPv4: 4 B; Domain: u8 len + bytes; IPv6: 16 B)
///  ...     2      port (u16 BE; zero reserved)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum ResolveTarget {
    /// IPv4 literal - R has nothing to resolve, just forwards as
    /// HANDOFF immediately.
    Ipv4 { addr: [u8; 4], port: u16 },
    /// IPv6 literal - same treatment as IPv4.
    Ipv6 { addr: [u8; 16], port: u16 },
    /// Domain - R performs DNS, then HANDOFFs the resolved IP.
    Domain { domain: String, port: u16 },
}

/// `CMD_RESOLVE` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveBody {
    /// Per-circuit stream id allocated by the client. Zero is
    /// reserved.
    pub stream_id: u32,
    /// What to look up + dial.
    pub target: ResolveTarget,
}

impl ResolveBody {
    /// Wire-format byte length.
    pub fn wire_len(&self) -> usize {
        4 + 1
            + match &self.target {
                ResolveTarget::Ipv4 { .. } => 4 + 2,
                ResolveTarget::Ipv6 { .. } => 16 + 2,
                ResolveTarget::Domain { domain, .. } => 1 + domain.len() + 2,
            }
    }

    /// Encode to wire bytes. Validates length, port, and (for
    /// domains) LDH conformance up front so we never serialize
    /// bytes the decoder would refuse.
    pub fn encode(&self) -> Result<Vec<u8>, SplitExitError> {
        if self.stream_id == 0 {
            return Err(SplitExitError::ZeroStreamId);
        }
        let port = match &self.target {
            ResolveTarget::Ipv4 { port, .. }
            | ResolveTarget::Ipv6 { port, .. }
            | ResolveTarget::Domain { port, .. } => *port,
        };
        if port == 0 {
            return Err(SplitExitError::ZeroPort);
        }
        let mut out = Vec::with_capacity(self.wire_len());
        out.extend_from_slice(&self.stream_id.to_be_bytes());
        match &self.target {
            ResolveTarget::Ipv4 { addr, port } => {
                out.push(HANDOFF_ATYP_IPV4);
                out.extend_from_slice(addr);
                out.extend_from_slice(&port.to_be_bytes());
            }
            ResolveTarget::Ipv6 { addr, port } => {
                if is_ipv4_mapped_ipv6(addr) {
                    return Err(SplitExitError::Wire("IPv4-mapped IPv6 must use IPv4 atyp"));
                }
                out.push(HANDOFF_ATYP_IPV6);
                out.extend_from_slice(addr);
                out.extend_from_slice(&port.to_be_bytes());
            }
            ResolveTarget::Domain { domain, port } => {
                if domain.is_empty() || domain.len() > 253 {
                    return Err(SplitExitError::HostLength(domain.len()));
                }
                if !is_ldh_hostname(domain) {
                    return Err(SplitExitError::HostNotLdh);
                }
                out.push(RESOLVE_ATYP_DOMAIN);
                out.push(domain.len() as u8);
                out.extend_from_slice(domain.as_bytes());
                out.extend_from_slice(&port.to_be_bytes());
            }
        }
        Ok(out)
    }

    /// Parse wire bytes. Strict (no trailing bytes accepted).
    pub fn decode(buf: &[u8]) -> Result<Self, SplitExitError> {
        if buf.len() < 4 + 1 {
            return Err(SplitExitError::Wire("RESOLVE body too short"));
        }
        let stream_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if stream_id == 0 {
            return Err(SplitExitError::ZeroStreamId);
        }
        let atyp = buf[4];
        let (target, port_off, expected_total) = match atyp {
            HANDOFF_ATYP_IPV4 => {
                if buf.len() < 4 + 1 + 4 + 2 {
                    return Err(SplitExitError::Wire("RESOLVE ipv4 truncated"));
                }
                let mut addr = [0u8; 4];
                addr.copy_from_slice(&buf[5..9]);
                (ResolveTarget::Ipv4 { addr, port: 0 }, 9, 11)
            }
            HANDOFF_ATYP_IPV6 => {
                if buf.len() < 4 + 1 + 16 + 2 {
                    return Err(SplitExitError::Wire("RESOLVE ipv6 truncated"));
                }
                let mut addr = [0u8; 16];
                addr.copy_from_slice(&buf[5..21]);
                if is_ipv4_mapped_ipv6(&addr) {
                    return Err(SplitExitError::Wire("IPv4-mapped IPv6 must use IPv4 atyp"));
                }
                (ResolveTarget::Ipv6 { addr, port: 0 }, 21, 23)
            }
            RESOLVE_ATYP_DOMAIN => {
                if buf.len() < 4 + 1 + 1 {
                    return Err(SplitExitError::Wire("RESOLVE domain truncated at len"));
                }
                let dlen = buf[5] as usize;
                if dlen == 0 || dlen > 253 {
                    return Err(SplitExitError::HostLength(dlen));
                }
                let domain_end = 6 + dlen;
                if buf.len() < domain_end + 2 {
                    return Err(SplitExitError::Wire("RESOLVE domain truncated"));
                }
                let domain = std::str::from_utf8(&buf[6..domain_end])
                    .map_err(|_| SplitExitError::HostEncoding)?
                    .to_string();
                if !is_ldh_hostname(&domain) {
                    return Err(SplitExitError::HostNotLdh);
                }
                (
                    ResolveTarget::Domain { domain, port: 0 },
                    domain_end,
                    domain_end + 2,
                )
            }
            _ => return Err(SplitExitError::Wire("unknown RESOLVE atyp")),
        };
        if buf.len() != expected_total {
            return Err(SplitExitError::Wire("RESOLVE trailing bytes"));
        }
        let port = u16::from_be_bytes([buf[port_off], buf[port_off + 1]]);
        if port == 0 {
            return Err(SplitExitError::ZeroPort);
        }
        let target = match target {
            ResolveTarget::Ipv4 { addr, .. } => ResolveTarget::Ipv4 { addr, port },
            ResolveTarget::Ipv6 { addr, .. } => ResolveTarget::Ipv6 { addr, port },
            ResolveTarget::Domain { domain, .. } => ResolveTarget::Domain { domain, port },
        };
        Ok(Self { stream_id, target })
    }
}

// HandoffBody - R -> F

/// Body of a `CMD_HANDOFF` cell. R passes F a resolved IP literal
/// + port. Carries NO hostname - that's the split's whole point.
///
/// Wire format:
///
/// ```text
///  Offset  Size   Field
///  ------  ----   -----
///  0       4      stream_id  (u32 BE)
///  4       1      atyp (0x01 IPv4, 0x04 IPv6) - Domain explicitly disallowed
///  5       var    addr (IPv4: 4 B; IPv6: 16 B)
///  ...     2      port (u16 BE; zero reserved)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffBody {
    /// Per-circuit stream id; matches the RESOLVE that triggered.
    pub stream_id: u32,
    /// Resolved destination address.
    pub addr: SocketAddr,
}

impl HandoffBody {
    /// Wire-format byte length.
    pub fn wire_len(&self) -> usize {
        4 + 1
            + match self.addr {
                SocketAddr::V4(_) => 4 + 2,
                SocketAddr::V6(_) => 16 + 2,
            }
    }

    /// Encode to wire bytes.
    pub fn encode(&self) -> Result<Vec<u8>, SplitExitError> {
        if self.stream_id == 0 {
            return Err(SplitExitError::ZeroStreamId);
        }
        if self.addr.port() == 0 {
            return Err(SplitExitError::ZeroPort);
        }
        let mut out = Vec::with_capacity(self.wire_len());
        out.extend_from_slice(&self.stream_id.to_be_bytes());
        match self.addr {
            SocketAddr::V4(v4) => {
                out.push(HANDOFF_ATYP_IPV4);
                out.extend_from_slice(&v4.ip().octets());
                out.extend_from_slice(&v4.port().to_be_bytes());
            }
            SocketAddr::V6(v6) => {
                let octets = v6.ip().octets();
                if is_ipv4_mapped_ipv6(&octets) {
                    return Err(SplitExitError::Wire("IPv4-mapped IPv6 must use IPv4 atyp"));
                }
                out.push(HANDOFF_ATYP_IPV6);
                out.extend_from_slice(&octets);
                out.extend_from_slice(&v6.port().to_be_bytes());
            }
        }
        Ok(out)
    }

    /// Parse wire bytes. Strict; rejects domain ATYP outright.
    pub fn decode(buf: &[u8]) -> Result<Self, SplitExitError> {
        if buf.len() < 4 + 1 {
            return Err(SplitExitError::Wire("HANDOFF body too short"));
        }
        let stream_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if stream_id == 0 {
            return Err(SplitExitError::ZeroStreamId);
        }
        let atyp = buf[4];
        let (addr, expected_total) = match atyp {
            HANDOFF_ATYP_IPV4 => {
                if buf.len() != 4 + 1 + 4 + 2 {
                    return Err(SplitExitError::Wire("HANDOFF ipv4 wrong length"));
                }
                let octets = [buf[5], buf[6], buf[7], buf[8]];
                let port = u16::from_be_bytes([buf[9], buf[10]]);
                (
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port),
                    11,
                )
            }
            HANDOFF_ATYP_IPV6 => {
                if buf.len() != 4 + 1 + 16 + 2 {
                    return Err(SplitExitError::Wire("HANDOFF ipv6 wrong length"));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[5..21]);
                if is_ipv4_mapped_ipv6(&octets) {
                    return Err(SplitExitError::Wire("IPv4-mapped IPv6 must use IPv4 atyp"));
                }
                let port = u16::from_be_bytes([buf[21], buf[22]]);
                (
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port),
                    23,
                )
            }
            RESOLVE_ATYP_DOMAIN => {
                return Err(SplitExitError::DomainNotAllowedInHandoff);
            }
            _ => return Err(SplitExitError::Wire("unknown HANDOFF atyp")),
        };
        if buf.len() != expected_total {
            return Err(SplitExitError::Wire("HANDOFF trailing bytes"));
        }
        if addr.port() == 0 {
            return Err(SplitExitError::ZeroPort);
        }
        Ok(Self { stream_id, addr })
    }
}

// HandoffResultBody - F -> R

/// Body of a `CMD_HANDOFF_RESULT` cell. Five bytes, fixed.
///
/// Wire format:
/// `stream_id (u32 BE) || status (u8)`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandoffResultBody {
    /// Stream this result is for.
    pub stream_id: u32,
    /// Outcome of F's connect attempt.
    pub status: HandoffStatus,
}

impl HandoffResultBody {
    /// Fixed wire size - 5 bytes.
    pub const WIRE_LEN: usize = 5;

    /// Encode to wire bytes.
    pub fn encode(&self) -> Result<[u8; Self::WIRE_LEN], SplitExitError> {
        if self.stream_id == 0 {
            return Err(SplitExitError::ZeroStreamId);
        }
        let mut out = [0u8; Self::WIRE_LEN];
        out[0..4].copy_from_slice(&self.stream_id.to_be_bytes());
        out[4] = self.status.to_byte();
        Ok(out)
    }

    /// Parse wire bytes. Strict on length and status codepoint.
    pub fn decode(buf: &[u8]) -> Result<Self, SplitExitError> {
        if buf.len() != Self::WIRE_LEN {
            return Err(SplitExitError::Wire("HANDOFF_RESULT wrong length"));
        }
        let stream_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if stream_id == 0 {
            return Err(SplitExitError::ZeroStreamId);
        }
        let status = HandoffStatus::from_byte(buf[4])?;
        Ok(Self { stream_id, status })
    }
}

// Resolver-side state machine (R)

/// Per-stream state at the R hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverStreamState {
    /// Client sent RESOLVE; R is performing DNS (or skipping if
    /// the target was already an IP literal).
    Resolving,
    /// DNS done; HANDOFF emitted to F; awaiting `HANDOFF_RESULT`.
    Handing,
    /// `HANDOFF_RESULT(ok)` received; stream open, `RELAY_DATA` flows.
    Open,
    /// Stream finished or aborted.
    Closed,
}

/// Per-connection policy for the R side.
#[derive(Debug, Clone)]
pub struct ResolverPolicy {
    /// Max concurrent streams in `Resolving` or `Handing` state.
    /// A hostile client that holds many streams open in the
    /// pre-Open phases pegs R's DNS budget; bound it.
    pub max_pending: u32,
    /// Max TOTAL tracked streams (pending + Open). `max_pending`
    /// only bounds pre-Open streams; once a stream reaches `Open`
    /// it stops counting toward pending but still occupies the
    /// map until explicitly closed. A hostile client that opens
    /// streams and never closes them would otherwise grow the map
    /// without limit - this caps that leak.
    pub max_streams: u32,
    /// Wall-clock cap on `Resolving` state. After this elapses
    /// without a resolution result, the state machine garbage
    /// collects the entry. (DNS itself is performed by the
    /// caller; the cap exists so a stuck resolver doesn't pile
    /// state forever.)
    pub resolve_timeout: Duration,
    /// Wall-clock cap on `Handing` state.
    pub handoff_timeout: Duration,
}

impl Default for ResolverPolicy {
    fn default() -> Self {
        Self {
            max_pending: 32,
            max_streams: 4096,
            resolve_timeout: Duration::from_secs(10),
            handoff_timeout: Duration::from_secs(15),
        }
    }
}

/// Decision the R-side state machine emits. The bridge daemon
/// translates these into outbound cells / DNS calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolverDecision {
    /// The caller MUST perform a DNS lookup for `host` and feed
    /// the result back via [`ResolverState::record_resolution`].
    NeedDns {
        /// Stream the resolution is for.
        stream_id: u32,
        /// Hostname to look up.
        host: String,
        /// Port (caller carries it forward; not part of DNS).
        port: u16,
    },
    /// The caller MUST emit `CMD_HANDOFF` to F with this body.
    /// IP-literal RESOLVEs short-circuit straight to here.
    EmitHandoff(HandoffBody),
}

#[derive(Debug)]
struct ResolverEntry {
    state: ResolverStreamState,
    /// Port - held during DNS so we can synthesise `HandoffBody`
    /// once the IP comes back.
    port: u16,
    /// Time the entry entered its current state. Used by the
    /// timeout sweep.
    state_entered: Instant,
}

/// I/O-free state machine for the R hop.
pub struct ResolverState {
    policy: ResolverPolicy,
    streams: HashMap<u32, ResolverEntry>,
    pending_count: u32,
}

impl ResolverState {
    /// Construct.
    pub fn new(policy: ResolverPolicy) -> Self {
        Self {
            policy,
            streams: HashMap::new(),
            pending_count: 0,
        }
    }

    /// Process an inbound `RESOLVE` cell from the client. Returns
    /// the immediate next action: DNS lookup (for hostnames) or
    /// HANDOFF emit (for IP literals).
    pub fn observe_resolve(
        &mut self,
        body: ResolveBody,
        now: Instant,
    ) -> Result<ResolverDecision, SplitExitError> {
        if self.streams.contains_key(&body.stream_id) {
            return Err(SplitExitError::StreamExists(body.stream_id));
        }
        if self.streams.len() as u32 >= self.policy.max_streams {
            return Err(SplitExitError::ResolverStreamCap(self.policy.max_streams));
        }
        if self.pending_count >= self.policy.max_pending {
            return Err(SplitExitError::ResolverPendingCap(self.policy.max_pending));
        }
        match body.target {
            ResolveTarget::Domain { domain, port } => {
                self.streams.insert(
                    body.stream_id,
                    ResolverEntry {
                        state: ResolverStreamState::Resolving,
                        port,
                        state_entered: now,
                    },
                );
                self.pending_count += 1;
                Ok(ResolverDecision::NeedDns {
                    stream_id: body.stream_id,
                    host: domain,
                    port,
                })
            }
            ResolveTarget::Ipv4 { addr, port } => {
                let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(addr)), port);
                self.streams.insert(
                    body.stream_id,
                    ResolverEntry {
                        state: ResolverStreamState::Handing,
                        port,
                        state_entered: now,
                    },
                );
                self.pending_count += 1;
                Ok(ResolverDecision::EmitHandoff(HandoffBody {
                    stream_id: body.stream_id,
                    addr: socket,
                }))
            }
            ResolveTarget::Ipv6 { addr, port } => {
                let socket = SocketAddr::new(IpAddr::V6(Ipv6Addr::from(addr)), port);
                self.streams.insert(
                    body.stream_id,
                    ResolverEntry {
                        state: ResolverStreamState::Handing,
                        port,
                        state_entered: now,
                    },
                );
                self.pending_count += 1;
                Ok(ResolverDecision::EmitHandoff(HandoffBody {
                    stream_id: body.stream_id,
                    addr: socket,
                }))
            }
        }
    }

    /// Caller-driven DNS finished. `ip` is the resolved address;
    /// state-machine transitions to `Handing` and emits HANDOFF.
    pub fn record_resolution(
        &mut self,
        stream_id: u32,
        ip: IpAddr,
        now: Instant,
    ) -> Result<HandoffBody, SplitExitError> {
        let entry = self
            .streams
            .get_mut(&stream_id)
            .ok_or(SplitExitError::UnknownStream(stream_id))?;
        if entry.state != ResolverStreamState::Resolving {
            return Err(SplitExitError::BadState {
                stream_id,
                state: entry.state,
            });
        }
        entry.state = ResolverStreamState::Handing;
        entry.state_entered = now;
        Ok(HandoffBody {
            stream_id,
            addr: SocketAddr::new(ip, entry.port),
        })
    }

    /// Caller-driven DNS failed. Marks the stream Closed.
    pub fn record_resolution_failure(&mut self, stream_id: u32) -> Result<(), SplitExitError> {
        self.close_stream(stream_id)
    }

    /// Caller fed an inbound `HANDOFF_RESULT` from F. Transitions
    /// the stream from `Handing` to `Open` (on success) or `Closed`
    /// (on any failure status).
    pub fn observe_handoff_result(
        &mut self,
        body: HandoffResultBody,
    ) -> Result<HandoffStatus, SplitExitError> {
        let entry = self
            .streams
            .get_mut(&body.stream_id)
            .ok_or(SplitExitError::UnknownStream(body.stream_id))?;
        if entry.state != ResolverStreamState::Handing {
            return Err(SplitExitError::BadState {
                stream_id: body.stream_id,
                state: entry.state,
            });
        }
        if body.status.is_ok() {
            entry.state = ResolverStreamState::Open;
            // Stream is now Open; no longer counts toward pending.
            self.pending_count = self.pending_count.saturating_sub(1);
            Ok(body.status)
        } else {
            self.close_stream(body.stream_id)?;
            Ok(body.status)
        }
    }

    /// Close a stream (on `RELAY_END` from client, on failure, etc.).
    pub fn close_stream(&mut self, stream_id: u32) -> Result<(), SplitExitError> {
        if let Some(entry) = self.streams.remove(&stream_id) {
            if matches!(
                entry.state,
                ResolverStreamState::Resolving | ResolverStreamState::Handing
            ) {
                self.pending_count = self.pending_count.saturating_sub(1);
            }
            Ok(())
        } else {
            Err(SplitExitError::UnknownStream(stream_id))
        }
    }

    /// Snapshot a stream's state. Diagnostics-only.
    pub fn stream_state(&self, stream_id: u32) -> Option<ResolverStreamState> {
        self.streams.get(&stream_id).map(|e| e.state)
    }

    /// Number of streams currently in pre-Open state.
    pub fn pending(&self) -> u32 {
        self.pending_count
    }

    /// Garbage-collect stuck `Resolving` / `Handing` entries past
    /// their per-state timeout. Returns the stream ids that were
    /// timed out so the caller can emit `RELAY_END` / cleanup.
    pub fn sweep_timeouts(&mut self, now: Instant) -> Vec<u32> {
        let mut victims = Vec::new();
        for (&id, entry) in &self.streams {
            let cap = match entry.state {
                ResolverStreamState::Resolving => self.policy.resolve_timeout,
                ResolverStreamState::Handing => self.policy.handoff_timeout,
                _ => continue,
            };
            if now.saturating_duration_since(entry.state_entered) >= cap {
                victims.push(id);
            }
        }
        for &id in &victims {
            // Close ignores the `Result` since we just enumerated
            // valid ids above.
            let _ = self.close_stream(id);
        }
        victims
    }
}

// Forwarder-side state machine (F)

/// Per-stream state at the F hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwarderStreamState {
    /// HANDOFF received; F is dialing the destination.
    Connecting,
    /// Connect succeeded; bytes flow via the existing RELAY path.
    Open,
    /// Stream finished or aborted.
    Closed,
}

/// Per-connection policy for the F side.
#[derive(Debug, Clone)]
pub struct ForwarderPolicy {
    /// Max concurrent streams in `Connecting` state.
    pub max_pending: u32,
    /// Max TOTAL tracked streams (pending + Open). See
    /// [`ResolverPolicy::max_streams`] for the rationale.
    pub max_streams: u32,
    /// Wall-clock cap on `Connecting` state.
    pub connect_timeout: Duration,
}

impl Default for ForwarderPolicy {
    fn default() -> Self {
        Self {
            max_pending: 32,
            max_streams: 4096,
            connect_timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Debug)]
struct ForwarderEntry {
    state: ForwarderStreamState,
    /// Destination address F was told to dial. Held for diagnostics
    /// + timeout sweep.
    dest: SocketAddr,
    state_entered: Instant,
}

/// I/O-free state machine for the F hop.
pub struct ForwarderState {
    policy: ForwarderPolicy,
    streams: HashMap<u32, ForwarderEntry>,
    pending_count: u32,
}

impl ForwarderState {
    /// Construct.
    pub fn new(policy: ForwarderPolicy) -> Self {
        Self {
            policy,
            streams: HashMap::new(),
            pending_count: 0,
        }
    }

    /// Process an inbound `HANDOFF` cell from R. Caller MUST then
    /// initiate the TCP connect to `body.addr` and feed the result
    /// back via [`Self::record_connect_result`].
    pub fn observe_handoff(
        &mut self,
        body: &HandoffBody,
        now: Instant,
    ) -> Result<(), SplitExitError> {
        if self.streams.contains_key(&body.stream_id) {
            return Err(SplitExitError::StreamExists(body.stream_id));
        }
        if self.streams.len() as u32 >= self.policy.max_streams {
            return Err(SplitExitError::ForwarderStreamCap(self.policy.max_streams));
        }
        if self.pending_count >= self.policy.max_pending {
            return Err(SplitExitError::ForwarderPendingCap(self.policy.max_pending));
        }
        self.streams.insert(
            body.stream_id,
            ForwarderEntry {
                state: ForwarderStreamState::Connecting,
                dest: body.addr,
                state_entered: now,
            },
        );
        self.pending_count += 1;
        Ok(())
    }

    /// Caller-driven TCP connect finished. State machine transitions
    /// to `Open` (Ok) or `Closed` (any failure) and produces the
    /// `HANDOFF_RESULT` body the caller emits to R.
    pub fn record_connect_result(
        &mut self,
        stream_id: u32,
        status: HandoffStatus,
    ) -> Result<HandoffResultBody, SplitExitError> {
        let entry = self
            .streams
            .get_mut(&stream_id)
            .ok_or(SplitExitError::UnknownStream(stream_id))?;
        if entry.state != ForwarderStreamState::Connecting {
            return Err(SplitExitError::BadForwarderState {
                stream_id,
                state: entry.state,
            });
        }
        if status.is_ok() {
            entry.state = ForwarderStreamState::Open;
            self.pending_count = self.pending_count.saturating_sub(1);
        } else {
            // Failure path: drop the entry. open_count was already
            // counting it as pending; close_stream decrements.
            self.close_stream(stream_id)?;
        }
        Ok(HandoffResultBody { stream_id, status })
    }

    /// Close a stream (graceful end, `RELAY_END` from R, etc.).
    pub fn close_stream(&mut self, stream_id: u32) -> Result<(), SplitExitError> {
        if let Some(entry) = self.streams.remove(&stream_id) {
            if entry.state == ForwarderStreamState::Connecting {
                self.pending_count = self.pending_count.saturating_sub(1);
            }
            Ok(())
        } else {
            Err(SplitExitError::UnknownStream(stream_id))
        }
    }

    /// Snapshot a stream's state.
    pub fn stream_state(&self, stream_id: u32) -> Option<ForwarderStreamState> {
        self.streams.get(&stream_id).map(|e| e.state)
    }

    /// Snapshot a stream's destination. Diagnostics-only.
    pub fn stream_dest(&self, stream_id: u32) -> Option<SocketAddr> {
        self.streams.get(&stream_id).map(|e| e.dest)
    }

    /// Number of streams currently in `Connecting` state.
    pub fn pending(&self) -> u32 {
        self.pending_count
    }

    /// Sweep stuck `Connecting` entries.
    pub fn sweep_timeouts(&mut self, now: Instant) -> Vec<u32> {
        let mut victims = Vec::new();
        for (&id, entry) in &self.streams {
            if entry.state != ForwarderStreamState::Connecting {
                continue;
            }
            if now.saturating_duration_since(entry.state_entered) >= self.policy.connect_timeout {
                victims.push(id);
            }
        }
        for &id in &victims {
            let _ = self.close_stream(id);
        }
        victims
    }
}

// Helpers (validators)

/// True iff `addr` is in the IPv4-mapped IPv6 prefix `::ffff:0:0/96`.
/// Mirrors the canonicalisation rule used in `mirage-mux::target`
/// and `mirage-circuit::extend` - one address <-> one wire form.
fn is_ipv4_mapped_ipv6(addr: &[u8; 16]) -> bool {
    addr[..10] == [0u8; 10] && addr[10] == 0xff && addr[11] == 0xff
}

/// Strict LDH hostname validator (letters/digits/hyphens, label <= 63,
/// total <= 253, no leading/trailing dot, no `..`). Matches the
/// validator in `mirage-mux::target`.
fn is_ldh_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host.starts_with('.') || host.ends_with('.') {
        return false;
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return false;
        }
    }
    true
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_target(port: u16) -> ResolveTarget {
        ResolveTarget::Ipv4 {
            addr: [203, 0, 113, 5],
            port,
        }
    }

    fn v6_target(port: u16) -> ResolveTarget {
        ResolveTarget::Ipv6 {
            addr: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            port,
        }
    }

    fn dom_target(name: &str, port: u16) -> ResolveTarget {
        ResolveTarget::Domain {
            domain: name.to_string(),
            port,
        }
    }

    // --- ResolveBody round-trip ----------------------------------------

    #[test]
    fn resolve_body_ipv4_roundtrip() {
        let body = ResolveBody {
            stream_id: 7,
            target: v4_target(443),
        };
        let bytes = body.encode().unwrap();
        assert_eq!(ResolveBody::decode(&bytes).unwrap(), body);
    }

    #[test]
    fn resolve_body_ipv6_roundtrip() {
        let body = ResolveBody {
            stream_id: 9,
            target: v6_target(443),
        };
        let bytes = body.encode().unwrap();
        assert_eq!(ResolveBody::decode(&bytes).unwrap(), body);
    }

    #[test]
    fn resolve_body_domain_roundtrip() {
        let body = ResolveBody {
            stream_id: 11,
            target: dom_target("example.com", 443),
        };
        let bytes = body.encode().unwrap();
        assert_eq!(ResolveBody::decode(&bytes).unwrap(), body);
    }

    #[test]
    fn resolve_body_rejects_zero_stream() {
        let body = ResolveBody {
            stream_id: 0,
            target: v4_target(443),
        };
        assert_eq!(body.encode().unwrap_err(), SplitExitError::ZeroStreamId);
    }

    #[test]
    fn resolve_body_rejects_zero_port() {
        let body = ResolveBody {
            stream_id: 1,
            target: v4_target(0),
        };
        assert_eq!(body.encode().unwrap_err(), SplitExitError::ZeroPort);
    }

    #[test]
    fn resolve_body_rejects_non_ldh_domain() {
        let body = ResolveBody {
            stream_id: 1,
            target: dom_target("evil.com/?x=", 443),
        };
        assert_eq!(body.encode().unwrap_err(), SplitExitError::HostNotLdh);
    }

    #[test]
    fn resolve_body_rejects_oversized_domain() {
        let body = ResolveBody {
            stream_id: 1,
            target: dom_target(&"a".repeat(254), 443),
        };
        assert_eq!(body.encode().unwrap_err(), SplitExitError::HostLength(254));
    }

    #[test]
    fn resolve_body_rejects_ipv4_mapped_ipv6() {
        let body = ResolveBody {
            stream_id: 1,
            target: ResolveTarget::Ipv6 {
                addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 203, 0, 113, 5],
                port: 443,
            },
        };
        assert!(matches!(
            body.encode().unwrap_err(),
            SplitExitError::Wire(s) if s.contains("IPv4-mapped")
        ));
    }

    #[test]
    fn resolve_decode_rejects_trailing_bytes() {
        let body = ResolveBody {
            stream_id: 1,
            target: v4_target(443),
        };
        let mut bytes = body.encode().unwrap();
        bytes.push(0xFF);
        assert!(matches!(
            ResolveBody::decode(&bytes).unwrap_err(),
            SplitExitError::Wire(_)
        ));
    }

    // --- HandoffBody round-trip ----------------------------------------

    #[test]
    fn handoff_body_ipv4_roundtrip() {
        let body = HandoffBody {
            stream_id: 42,
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 443),
        };
        let bytes = body.encode().unwrap();
        assert_eq!(HandoffBody::decode(&bytes).unwrap(), body);
    }

    #[test]
    fn handoff_body_ipv6_roundtrip() {
        let body = HandoffBody {
            stream_id: 42,
            addr: SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                443,
            ),
        };
        let bytes = body.encode().unwrap();
        assert_eq!(HandoffBody::decode(&bytes).unwrap(), body);
    }

    #[test]
    fn handoff_body_decoder_rejects_domain_atyp() {
        // Manually craft a HANDOFF body with atyp = 0x03 (domain)
        // and verify it's refused at the type level. This is the
        // wire-level enforcement of the split-exit invariant.
        let mut buf = Vec::new();
        buf.extend_from_slice(&42u32.to_be_bytes());
        buf.push(RESOLVE_ATYP_DOMAIN);
        buf.push(11);
        buf.extend_from_slice(b"example.com");
        buf.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(
            HandoffBody::decode(&buf).unwrap_err(),
            SplitExitError::DomainNotAllowedInHandoff
        );
    }

    #[test]
    fn handoff_body_rejects_ipv4_mapped_ipv6() {
        let body = HandoffBody {
            stream_id: 1,
            addr: SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from([
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 203, 0, 113, 5,
                ])),
                443,
            ),
        };
        assert!(matches!(
            body.encode().unwrap_err(),
            SplitExitError::Wire(s) if s.contains("IPv4-mapped")
        ));
    }

    #[test]
    fn handoff_body_rejects_zero_port() {
        let body = HandoffBody {
            stream_id: 1,
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0),
        };
        assert_eq!(body.encode().unwrap_err(), SplitExitError::ZeroPort);
    }

    #[test]
    fn handoff_body_rejects_zero_stream() {
        let body = HandoffBody {
            stream_id: 0,
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443),
        };
        assert_eq!(body.encode().unwrap_err(), SplitExitError::ZeroStreamId);
    }

    // --- HandoffResultBody round-trip ----------------------------------

    #[test]
    fn handoff_result_roundtrip_all_status_codes() {
        for status in [
            HandoffStatus::Ok,
            HandoffStatus::PolicyDenied,
            HandoffStatus::ConnectRefused,
            HandoffStatus::ConnectTimeout,
            HandoffStatus::RateLimited,
            HandoffStatus::Internal,
        ] {
            let body = HandoffResultBody {
                stream_id: 7,
                status,
            };
            let bytes = body.encode().unwrap();
            assert_eq!(HandoffResultBody::decode(&bytes).unwrap(), body);
        }
    }

    #[test]
    fn handoff_result_rejects_unknown_status() {
        let mut bytes = [0u8; HandoffResultBody::WIRE_LEN];
        bytes[0..4].copy_from_slice(&7u32.to_be_bytes());
        bytes[4] = 0xFE;
        assert!(matches!(
            HandoffResultBody::decode(&bytes).unwrap_err(),
            SplitExitError::UnknownStatus(0xFE)
        ));
    }

    #[test]
    fn handoff_result_rejects_wrong_length() {
        assert!(matches!(
            HandoffResultBody::decode(&[0u8; 4]).unwrap_err(),
            SplitExitError::Wire(_)
        ));
        assert!(matches!(
            HandoffResultBody::decode(&[0u8; 6]).unwrap_err(),
            SplitExitError::Wire(_)
        ));
    }

    // --- ResolverState behaviour ---------------------------------------

    #[test]
    fn resolver_domain_target_emits_dns_request() {
        let mut r = ResolverState::new(ResolverPolicy::default());
        let body = ResolveBody {
            stream_id: 7,
            target: dom_target("example.com", 443),
        };
        let dec = r.observe_resolve(body, Instant::now()).unwrap();
        assert!(matches!(
            dec,
            ResolverDecision::NeedDns { stream_id: 7, ref host, port: 443 } if host == "example.com"
        ));
        assert_eq!(r.stream_state(7), Some(ResolverStreamState::Resolving));
        assert_eq!(r.pending(), 1);
    }

    #[test]
    fn resolver_ipv4_target_short_circuits_to_handoff() {
        let mut r = ResolverState::new(ResolverPolicy::default());
        let body = ResolveBody {
            stream_id: 9,
            target: v4_target(443),
        };
        let dec = r.observe_resolve(body, Instant::now()).unwrap();
        match dec {
            ResolverDecision::EmitHandoff(h) => {
                assert_eq!(h.stream_id, 9);
                assert_eq!(h.addr.port(), 443);
            }
            _ => panic!("expected EmitHandoff"),
        }
        assert_eq!(r.stream_state(9), Some(ResolverStreamState::Handing));
    }

    #[test]
    fn resolver_dns_completes_to_handoff() {
        let mut r = ResolverState::new(ResolverPolicy::default());
        let now = Instant::now();
        let body = ResolveBody {
            stream_id: 7,
            target: dom_target("example.com", 443),
        };
        let _ = r.observe_resolve(body, now).unwrap();
        let h = r
            .record_resolution(7, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), now)
            .unwrap();
        assert_eq!(h.stream_id, 7);
        assert_eq!(h.addr.port(), 443);
        assert_eq!(r.stream_state(7), Some(ResolverStreamState::Handing));
    }

    #[test]
    fn resolver_ok_result_marks_open() {
        let mut r = ResolverState::new(ResolverPolicy::default());
        let now = Instant::now();
        r.observe_resolve(
            ResolveBody {
                stream_id: 7,
                target: v4_target(443),
            },
            now,
        )
        .unwrap();
        let _ = r
            .observe_handoff_result(HandoffResultBody {
                stream_id: 7,
                status: HandoffStatus::Ok,
            })
            .unwrap();
        assert_eq!(r.stream_state(7), Some(ResolverStreamState::Open));
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn resolver_failure_result_closes_stream() {
        let mut r = ResolverState::new(ResolverPolicy::default());
        let now = Instant::now();
        r.observe_resolve(
            ResolveBody {
                stream_id: 7,
                target: v4_target(443),
            },
            now,
        )
        .unwrap();
        let status = r
            .observe_handoff_result(HandoffResultBody {
                stream_id: 7,
                status: HandoffStatus::ConnectRefused,
            })
            .unwrap();
        assert!(!status.is_ok());
        assert_eq!(r.stream_state(7), None);
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn resolver_pending_cap_enforced() {
        let policy = ResolverPolicy {
            max_pending: 2,
            ..ResolverPolicy::default()
        };
        let mut r = ResolverState::new(policy);
        let now = Instant::now();
        for sid in [1u32, 2] {
            r.observe_resolve(
                ResolveBody {
                    stream_id: sid,
                    target: v4_target(443),
                },
                now,
            )
            .unwrap();
        }
        let err = r
            .observe_resolve(
                ResolveBody {
                    stream_id: 3,
                    target: v4_target(443),
                },
                now,
            )
            .unwrap_err();
        assert!(matches!(err, SplitExitError::ResolverPendingCap(2)));
    }

    // Regression (R side): the pending cap only bounds pre-Open streams.
    // Drive streams all the way to Open (pending drops back to 0) and
    // confirm the TOTAL-stream cap still refuses new streams so an
    // Open-and-never-closed flood cannot grow the map unbounded.
    #[test]
    fn resolver_total_stream_cap_enforced() {
        let policy = ResolverPolicy {
            max_streams: 3,
            max_pending: 100, // deliberately high so the pending cap is not what trips
            ..ResolverPolicy::default()
        };
        let mut r = ResolverState::new(policy);
        let now = Instant::now();
        for sid in 1u32..=3 {
            r.observe_resolve(
                ResolveBody {
                    stream_id: sid,
                    target: v4_target(443),
                },
                now,
            )
            .unwrap();
            r.observe_handoff_result(HandoffResultBody {
                stream_id: sid,
                status: HandoffStatus::Ok,
            })
            .unwrap();
        }
        assert_eq!(
            r.pending(),
            0,
            "all three streams should be Open, none pending"
        );
        let err = r
            .observe_resolve(
                ResolveBody {
                    stream_id: 4,
                    target: v4_target(443),
                },
                now,
            )
            .unwrap_err();
        assert!(matches!(err, SplitExitError::ResolverStreamCap(3)));
    }

    #[test]
    fn resolver_resolve_timeout_sweeps_stuck_streams() {
        let policy = ResolverPolicy {
            resolve_timeout: Duration::from_millis(50),
            ..ResolverPolicy::default()
        };
        let mut r = ResolverState::new(policy);
        let t0 = Instant::now();
        r.observe_resolve(
            ResolveBody {
                stream_id: 1,
                target: dom_target("never-resolves.example", 443),
            },
            t0,
        )
        .unwrap();
        // Sweep at t0 + 200ms: stuck Resolving entry expires.
        let victims = r.sweep_timeouts(t0 + Duration::from_millis(200));
        assert_eq!(victims, vec![1]);
        assert_eq!(r.stream_state(1), None);
    }

    #[test]
    fn resolver_unknown_stream_rejects_handoff_result() {
        let mut r = ResolverState::new(ResolverPolicy::default());
        let err = r
            .observe_handoff_result(HandoffResultBody {
                stream_id: 999,
                status: HandoffStatus::Ok,
            })
            .unwrap_err();
        assert_eq!(err, SplitExitError::UnknownStream(999));
    }

    // --- ForwarderState behaviour --------------------------------------

    #[test]
    fn forwarder_handoff_then_ok_opens_stream() {
        let mut f = ForwarderState::new(ForwarderPolicy::default());
        let now = Instant::now();
        let h = HandoffBody {
            stream_id: 7,
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 443),
        };
        f.observe_handoff(&h, now).unwrap();
        assert_eq!(f.stream_state(7), Some(ForwarderStreamState::Connecting));
        let result = f.record_connect_result(7, HandoffStatus::Ok).unwrap();
        assert_eq!(result.stream_id, 7);
        assert!(result.status.is_ok());
        assert_eq!(f.stream_state(7), Some(ForwarderStreamState::Open));
        assert_eq!(f.pending(), 0);
    }

    #[test]
    fn forwarder_failure_result_closes_stream() {
        let mut f = ForwarderState::new(ForwarderPolicy::default());
        let now = Instant::now();
        f.observe_handoff(
            &HandoffBody {
                stream_id: 7,
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 443),
            },
            now,
        )
        .unwrap();
        let r = f
            .record_connect_result(7, HandoffStatus::ConnectRefused)
            .unwrap();
        assert!(!r.status.is_ok());
        assert_eq!(f.stream_state(7), None);
    }

    #[test]
    fn forwarder_pending_cap_enforced() {
        let policy = ForwarderPolicy {
            max_pending: 1,
            ..ForwarderPolicy::default()
        };
        let mut f = ForwarderState::new(policy);
        let now = Instant::now();
        f.observe_handoff(
            &HandoffBody {
                stream_id: 1,
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 443),
            },
            now,
        )
        .unwrap();
        let err = f
            .observe_handoff(
                &HandoffBody {
                    stream_id: 2,
                    addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 443),
                },
                now,
            )
            .unwrap_err();
        assert!(matches!(err, SplitExitError::ForwarderPendingCap(1)));
    }

    // Regression (F side): mirror of `resolver_total_stream_cap_enforced`.
    #[test]
    fn forwarder_total_stream_cap_enforced() {
        let policy = ForwarderPolicy {
            max_streams: 3,
            max_pending: 100,
            ..ForwarderPolicy::default()
        };
        let mut f = ForwarderState::new(policy);
        let now = Instant::now();
        for sid in 1u32..=3 {
            f.observe_handoff(
                &HandoffBody {
                    stream_id: sid,
                    addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 443),
                },
                now,
            )
            .unwrap();
            f.record_connect_result(sid, HandoffStatus::Ok).unwrap();
        }
        assert_eq!(
            f.pending(),
            0,
            "all three streams should be Open, none pending"
        );
        let err = f
            .observe_handoff(
                &HandoffBody {
                    stream_id: 4,
                    addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 443),
                },
                now,
            )
            .unwrap_err();
        assert!(matches!(err, SplitExitError::ForwarderStreamCap(3)));
    }

    #[test]
    fn forwarder_connect_timeout_sweeps() {
        let policy = ForwarderPolicy {
            connect_timeout: Duration::from_millis(50),
            ..ForwarderPolicy::default()
        };
        let mut f = ForwarderState::new(policy);
        let t0 = Instant::now();
        f.observe_handoff(
            &HandoffBody {
                stream_id: 1,
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 443),
            },
            t0,
        )
        .unwrap();
        let victims = f.sweep_timeouts(t0 + Duration::from_millis(200));
        assert_eq!(victims, vec![1]);
    }

    #[test]
    fn forwarder_duplicate_handoff_rejected() {
        let mut f = ForwarderState::new(ForwarderPolicy::default());
        let now = Instant::now();
        let h = HandoffBody {
            stream_id: 7,
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 443),
        };
        f.observe_handoff(&h, now).unwrap();
        let err = f.observe_handoff(&h, now).unwrap_err();
        assert_eq!(err, SplitExitError::StreamExists(7));
    }

    // --- End-to-end R+F simulation -------------------------------------

    #[test]
    fn split_exit_full_handshake_simulation() {
        // Simulates the entire RESOLVE -> DNS -> HANDOFF -> connect ->
        // HANDOFF_RESULT -> Open flow across both state machines, end
        // to end, with no real I/O. This is the unit test of the
        // split-exit property: at each step we confirm R has the
        // hostname (only) and F has the IP (only).
        let mut r = ResolverState::new(ResolverPolicy::default());
        let mut f = ForwarderState::new(ForwarderPolicy::default());
        let now = Instant::now();

        // 1. Client sends RESOLVE("example.com:443") to R.
        let resolve = ResolveBody {
            stream_id: 100,
            target: dom_target("example.com", 443),
        };
        let dec = r.observe_resolve(resolve, now).unwrap();
        let host = match dec {
            ResolverDecision::NeedDns { host, .. } => host,
            _ => panic!("expected DNS request"),
        };
        assert_eq!(host, "example.com");
        // R holds the hostname.

        // 2. Caller does DNS -> IP.
        let resolved_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let handoff = r.record_resolution(100, resolved_ip, now).unwrap();
        // R produces a HANDOFF carrying ONLY an IP.
        assert!(matches!(handoff.addr, SocketAddr::V4(_)));

        // 3. R sends the HANDOFF to F via the inter-hop link. F
        // receives it. The wire bytes contain no hostname.
        let wire = handoff.encode().unwrap();
        let received = HandoffBody::decode(&wire).unwrap();
        f.observe_handoff(&received, now).unwrap();
        // F's view of the destination is just the IP.
        assert_eq!(f.stream_dest(100).unwrap().ip(), resolved_ip);

        // 4. F connects (simulated success), emits HANDOFF_RESULT.
        let result = f.record_connect_result(100, HandoffStatus::Ok).unwrap();
        let result_wire = result.encode().unwrap();
        let result_back = HandoffResultBody::decode(&result_wire).unwrap();

        // 5. R observes HANDOFF_RESULT(ok); stream is open.
        let status = r.observe_handoff_result(result_back).unwrap();
        assert!(status.is_ok());
        assert_eq!(r.stream_state(100), Some(ResolverStreamState::Open));
        assert_eq!(f.stream_state(100), Some(ForwarderStreamState::Open));

        // 6. The split-exit invariant: F's body bytes never carried
        // the hostname. Re-decode and assert nothing in there matches.
        assert!(!wire
            .windows(b"example.com".len())
            .any(|w| w == b"example.com"));
    }

    #[test]
    fn split_exit_failure_at_forwarder_propagates() {
        let mut r = ResolverState::new(ResolverPolicy::default());
        let mut f = ForwarderState::new(ForwarderPolicy::default());
        let now = Instant::now();

        let resolve = ResolveBody {
            stream_id: 5,
            target: v4_target(443),
        };
        let dec = r.observe_resolve(resolve, now).unwrap();
        let h = match dec {
            ResolverDecision::EmitHandoff(h) => h,
            _ => panic!("expected handoff"),
        };
        f.observe_handoff(&h, now).unwrap();
        let result = f
            .record_connect_result(5, HandoffStatus::ConnectRefused)
            .unwrap();
        let status = r.observe_handoff_result(result).unwrap();
        assert!(!status.is_ok());
        // Both sides closed.
        assert_eq!(r.stream_state(5), None);
        assert_eq!(f.stream_state(5), None);
    }

    // --- Wire-level invariant: HANDOFF cannot carry a hostname ---------

    #[test]
    fn handoff_wire_format_cannot_carry_hostname() {
        // Encode side: HandoffBody type doesn't have a Domain
        // variant - only SocketAddr. Compile-time guarantee.
        // Decode side: explicit rejection of atyp=0x03 with
        // DomainNotAllowedInHandoff. Both sides enforce the
        // split-exit invariant at the wire boundary.
        let mut hostile_buf = Vec::new();
        hostile_buf.extend_from_slice(&1u32.to_be_bytes());
        hostile_buf.push(RESOLVE_ATYP_DOMAIN);
        hostile_buf.push(11);
        hostile_buf.extend_from_slice(b"example.com");
        hostile_buf.extend_from_slice(&443u16.to_be_bytes());
        // Even a hostile R that crafts a HANDOFF body with an
        // embedded hostname is refused at F's decoder.
        let err = HandoffBody::decode(&hostile_buf).unwrap_err();
        assert_eq!(err, SplitExitError::DomainNotAllowedInHandoff);
    }
}
