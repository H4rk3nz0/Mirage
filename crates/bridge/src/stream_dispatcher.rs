//! Exit-hop stream dispatcher.
//!
//! When the bridge's `BridgeCircuitState` surfaces a
//! [`mirage_circuit::BridgeAction::RelayPayloadAtExit`] action,
//! the payload is the onion-peeled bytes the client onion-sealed
//! for the exit hop. Those bytes are a [`RelaySubCell`] carrying
//! a stream sub-command:
//!
//! - `CMD_BEGIN(stream_id, host, port)` - open a TCP socket.
//! - `CMD_DATA(stream_id, bytes)` - write to the socket.
//! - `CMD_END(stream_id)` - half-close.
//!
//! [`StreamDispatcher`] is the trait the bridge daemon
//! implements; [`TcpStreamDispatcher`] is a reference impl that
//! opens real TCP sockets. The trait shape mirrors
//! [`crate::NextHopExecutor`] for symmetry - both are async,
//! both surface failures as `String` (the daemon logs + reaps
//! the offending circuit; failures here MUST NOT tear down the
//! whole session).
//!
//! # Wire format
//!
//! The current Mirage spec uses top-level CMD_BEGIN / CMD_DATA /
//! CMD_END cell commands. Inside an onion-wrapped RELAY at the
//! exit, the client encodes the same logical sub-commands as a
//! [`RelaySubCell`] with command byte = CMD_BEGIN / CMD_DATA /
//! CMD_END and body:
//!
//! ```text
//! BEGIN body:
//!   stream_id  u16 BE
//!   host_len   u8
//!   host       [host_len]
//!   port       u16 BE
//!
//! DATA body:
//!   stream_id  u16 BE
//!   bytes      [variable]
//!
//! END body:
//!   stream_id  u16 BE
//! ```
//!
//! Phase 2I+ may move these to a dedicated `mirage-circuit::stream`
//! module; for now the codec lives in this dispatcher.

use async_trait::async_trait;
pub use mirage_circuit::{BeginBody, DataBody, EndBody, StreamId};
use mirage_circuit::{RelaySubCell, StreamBodyError, CMD_BEGIN, CMD_DATA, CMD_END};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

/// Errors from the stream dispatcher.
#[derive(Debug, Error)]
pub enum StreamError {
    /// The peeled bytes didn't parse as a `RelaySubCell`.
    #[error("not a stream sub-cell: {0}")]
    NotASubCell(String),
    /// The sub-cell body didn't parse for its command.
    #[error("body parse: {0}")]
    Body(&'static str),
    /// Upstream TCP I/O failure.
    #[error("upstream io: {0}")]
    Io(#[from] std::io::Error),
    /// Sub-command refers to an unknown `stream_id`.
    #[error("unknown stream {0}")]
    UnknownStream(StreamId),
    /// Sub-command's command byte isn't BEGIN/DATA/END.
    #[error("unsupported sub-command {0:#04x}")]
    UnsupportedCommand(u8),
    /// Reverse-direction channel was dropped (caller stopped
    /// listening for upstream bytes).
    #[error("reverse channel closed")]
    ReverseChannelClosed,
    /// BEGIN target is a loopback / private / link-local /
    /// multicast / unspecified destination, and the dispatcher
    /// config disallows them. Closes RT-SD-5 (SSRF).
    #[error("forbidden destination: {0}")]
    ForbiddenDestination(String),
    /// Per-dispatcher stream limit reached. Closes RT-SD-1
    /// (unbounded task spawning DoS).
    #[error("dispatcher at stream capacity ({0})")]
    StreamCapacity(usize),
    /// DNS resolution returned no addresses or only filtered ones.
    #[error("resolution: {0}")]
    Resolution(&'static str),
    /// BEGIN reused an already-live `stream_id`. Closes RT-SD-7
    /// (orphaned read-pump on stream_id reuse): silently overwriting
    /// the map entry leaks the prior upstream read-pump task, which
    /// keeps reading the old socket and mis-routes its StreamEvents to
    /// whichever circuit now owns the id. Reuse is a protocol violation.
    #[error("duplicate stream {0}")]
    DuplicateStream(StreamId),
    /// Upstream TCP connect exceeded `connect_timeout`. A blackholed
    /// or filtered destination must not pin the inline `dispatch()`
    /// (and thus the whole session loop) for the OS default.
    #[error("upstream connect timed out")]
    ConnectTimeout,
}

impl From<StreamBodyError> for StreamError {
    fn from(e: StreamBodyError) -> Self {
        match e {
            StreamBodyError::Body(s) => StreamError::Body(s),
        }
    }
}

/// One outbound stream-event the dispatcher emits when bytes
/// arrive from upstream. The caller routes these back to the
/// circuit (onion-wraps + sends as CMD_RELAY back to prev hop).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEvent {
    /// Bytes from upstream destined for the client. The caller
    /// should encode this as `RelaySubCell { CMD_DATA, body }`
    /// where body = `stream_id || bytes`, onion-seal, and send
    /// back over the prev-hop link.
    Data {
        /// Stream this data belongs to.
        stream_id: StreamId,
        /// Bytes received from upstream.
        bytes: Vec<u8>,
    },
    /// Upstream half-closed (EOF on the read side). Caller
    /// should emit `RelaySubCell { CMD_END, stream_id }` to
    /// notify the client.
    End {
        /// Stream that ended.
        stream_id: StreamId,
    },
}

/// Async trait the daemon implements (or uses the
/// [`TcpStreamDispatcher`] reference impl). One instance per
/// exit-hop circuit.
#[async_trait]
pub trait StreamDispatcher: Send + Sync {
    /// Process one peeled-at-exit payload. The dispatcher parses
    /// the [`RelaySubCell`] and routes by command. Returns
    /// `Ok(())` on successful dispatch; `Err(_)` if the input
    /// was malformed (the caller logs + reaps the circuit).
    ///
    /// **Side effects**: BEGIN opens a TCP socket and starts a
    /// task pumping bytes from upstream; DATA writes to the
    /// existing socket; END half-closes the write side.
    async fn dispatch(&self, payload: &[u8]) -> Result<(), StreamError>;
}

// TcpStreamDispatcher - reference impl using tokio TCP

/// Per-dispatcher configuration. Production exits MUST keep
/// `allow_private_destinations = false` (RT-SD-5). The stream cap
/// + write timeout close RT-SD-1 + RT-SD-3 respectively.
#[derive(Debug, Clone)]
pub struct TcpStreamDispatcherConfig {
    /// If `false` (default), reject BEGIN whose destination resolves to an
    /// RFC1918 / CGNAT / IPv6-ULA private-network address. Set `true` ONLY for
    /// an exit that must legitimately reach an internal service behind NAT;
    /// leaving it on by default is the SSRF vector RT-SD-5 calls out. Note this
    /// no longer implies loopback (see `allow_loopback_destinations`) and never
    /// admits link-local / metadata / multicast - those are rejected always.
    pub allow_private_destinations: bool,
    /// If `false` (default), reject BEGIN whose destination resolves to
    /// loopback (127.0.0.0/8, ::1). Gated *independently* of
    /// `allow_private_destinations` so a test/demo that needs to dial localhost
    /// cannot silently also re-admit the whole RFC1918 lateral-movement surface,
    /// and vice-versa. Set `true` ONLY for tests/demos.
    pub allow_loopback_destinations: bool,
    /// Maximum simultaneous streams per dispatcher. A client (or
    /// compromised peeler) sending an unbounded BEGIN stream
    /// would otherwise force the daemon to spawn unbounded tasks.
    /// Closes RT-SD-1.
    pub max_streams: usize,
    /// Upstream write timeout. A slow / non-responsive upstream
    /// could otherwise pin a write_all forever, holding the
    /// channel-end + memory + a tokio task. Closes RT-SD-3.
    pub upstream_write_timeout: Duration,
    /// Upstream TCP connect timeout for a `CMD_BEGIN`. Without it a
    /// client BEGIN to a blackholed host:port stalls the inline
    /// `dispatch()` for the OS default (~127s on Linux), freezing
    /// the whole multiplexed session loop and starving the tick
    /// reaper. The destination is attacker-chosen, so this is a
    /// remote stall vector.
    pub connect_timeout: Duration,
    /// Optional explicit DNS allowlist. If `Some`, only the
    /// listed hostnames + their resolved IPs are accepted.
    /// `None` means "any non-private IP / hostname". This is a
    /// hardening knob for operators running constrained exits.
    pub host_allowlist: Option<Vec<String>>,
}

impl Default for TcpStreamDispatcherConfig {
    fn default() -> Self {
        Self {
            allow_private_destinations: false,
            allow_loopback_destinations: false,
            max_streams: 256,
            upstream_write_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            host_allowlist: None,
        }
    }
}

impl TcpStreamDispatcherConfig {
    /// Convenience for tests/demos that need to dial localhost.
    /// Do NOT call this in production exit configs.
    pub fn permissive_for_tests() -> Self {
        Self {
            allow_private_destinations: true,
            allow_loopback_destinations: true,
            ..Self::default()
        }
    }
}

/// Reference [`StreamDispatcher`] backed by `tokio::net::TcpStream`.
///
/// One instance per exit-hop circuit. Maintains a `HashMap<
/// StreamId, mpsc::Sender<Vec<u8>>>` so DATA sub-cells reach the
/// right socket. Per-stream upstream-read tasks pump bytes back to
/// a single `mpsc::Sender<StreamEvent>` the caller drains to
/// onion-wrap + send back to prev hop.
pub struct TcpStreamDispatcher {
    /// Per-stream write-channel: DATA sub-cells push to here.
    /// BOUNDED so a client that floods DATA at a stream whose
    /// upstream is slow/stalled cannot make the bridge buffer the
    /// forward stream without limit (OOM DoS). `dispatch()` runs
    /// inline in the per-client session loop, so a full channel
    /// backpressures THAT client's link - correct end-to-end flow
    /// control, since every stream on a session belongs to one
    /// authenticated client.
    streams: Arc<Mutex<HashMap<StreamId, tokio::sync::mpsc::Sender<Vec<u8>>>>>,
    /// Reverse-channel: upstream bytes pushed here. Caller
    /// drains via `events_rx`. BOUNDED so a client that requests a
    /// high-bandwidth exit target and then stops draining cannot make
    /// the bridge buffer the return stream without limit (OOM DoS): the
    /// read-pump `send().await` blocks when this is full, backpressuring
    /// the upstream socket read.
    events_tx: tokio::sync::mpsc::Sender<StreamEvent>,
    /// Per-dispatcher config (capacity, timeout, host policy).
    config: TcpStreamDispatcherConfig,
}

/// Capacity of the per-circuit reverse-channel (`StreamEvent`s). With a
/// 4 KiB read buffer this bounds in-flight return bytes to ~1 MiB per exit
/// circuit before backpressure engages.
const EXIT_EVENTS_CHANNEL_CAP: usize = 256;

/// Capacity of each per-stream FORWARD (client->upstream) write channel.
/// Bounds buffered forward bytes to ~`FORWARD_CHANNEL_CAP` DATA chunks per
/// stream before `dispatch()` blocks and backpressures the client link.
const FORWARD_CHANNEL_CAP: usize = 64;

impl TcpStreamDispatcher {
    /// Construct with default (production-safe) config. Returns
    /// the dispatcher + the receiver the caller drains for
    /// upstream-events.
    pub fn new() -> (Self, tokio::sync::mpsc::Receiver<StreamEvent>) {
        Self::with_config(TcpStreamDispatcherConfig::default())
    }

    /// Construct with explicit config.
    pub fn with_config(
        config: TcpStreamDispatcherConfig,
    ) -> (Self, tokio::sync::mpsc::Receiver<StreamEvent>) {
        let (events_tx, events_rx) = tokio::sync::mpsc::channel(EXIT_EVENTS_CHANNEL_CAP);
        (
            Self {
                streams: Arc::new(Mutex::new(HashMap::new())),
                events_tx,
                config,
            },
            events_rx,
        )
    }
}

/// Returns true if `ip` is a destination an exit MUST NOT
/// connect to: loopback / private / link-local / multicast /
/// unspecified / broadcast. Conservative; reject if unsure.
// The reserved-range predicate is written as explicit per-octet checks (one
// disjunct per documented CIDR block) for auditability; clippy's "simplified"
// form (range `.contains`) is harder to map back to the block list.
/// Loopback destinations (127.0.0.0/8, ::1). Separated from the rest so an
/// operator who deliberately fronts a service on localhost can opt *only*
/// loopback back in, without also re-admitting RFC1918 lateral movement.
fn ip_is_loopback_dest(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// Private-network / shared-address-space destinations: RFC1918, CGNAT
/// 100.64/10, and IPv6 ULA fc00::/7. Reachable-but-internal ranges that an
/// operator running behind NAT may legitimately need to reach, but which must
/// stay off by default so the exit can't be turned into an intranet pivot.
fn ip_is_private_network_dest(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private() || {
                // 100.64.0.0/10 CGNAT.
                let o = v4.octets();
                o[0] == 100 && (o[1] & 0xC0) == 0x40
            }
        }
        IpAddr::V6(v6) => {
            // fc00::/7 unique-local.
            (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

/// Destinations that are *never* safe to reach through the exit regardless of
/// operator policy: link-local (incl. the 169.254.169.254 cloud metadata
/// endpoint), multicast, broadcast, unspecified, documentation/benchmark
/// reserved ranges, and IPv4-mapped-IPv6 wrappers of the same. No flag re-admits
/// these - they are pure SSRF / metadata-exfil surface.
#[allow(clippy::nonminimal_bool)]
fn ip_is_always_forbidden_dest(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_documentation()
                || {
                    // 192.0.0.0/24, 192.0.2.0/24, 198.18.0.0/15,
                    // 198.51.100.0/24, 203.0.113.0/24 reserved.
                    let o = v4.octets();
                    (o[0] == 192 && o[1] == 0 && (o[2] == 0 || o[2] == 2))
                        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
                }
        }
        IpAddr::V6(v6) => {
            v6.is_multicast() || v6.is_unspecified() || {
                let s = v6.segments();
                // fe80::/10 link-local.
                (s[0] & 0xffc0) == 0xfe80
                        // ::ffff:0:0/96 IPv4-mapped - the embedded v4 is
                        // validated separately by the caller.
                        || (s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0
                            && s[4] == 0 && s[5] == 0xffff)
                        // IPv4-transition embeddings that carry a v4 destination
                        // inside a v6 address (red-team #13): a proxy exit must
                        // not let one reach an internal v4 (e.g. 2002:0a00::/24
                        // -> 10.0.0.0/8) by dressing it as v6. These legacy
                        // mechanisms are refused outright:
                        //   2002::/16       6to4
                        //   2001::/32       Teredo
                        //   64:ff9b::/96    NAT64 well-known prefix
                        //   64:ff9b:1::/48  NAT64 local-use prefix
                        //   ::/96           IPv4-compatible (deprecated; :: and
                        //                   ::1 already handled above/loopback)
                        || s[0] == 0x2002
                        || (s[0] == 0x2001 && s[1] == 0x0000)
                        || (s[0] == 0x0064 && s[1] == 0xff9b)
                        || (s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0
                            && s[4] == 0 && s[5] == 0
                            && !(s[6] == 0 && (s[7] == 0 || s[7] == 1)))
            }
        }
    }
}

/// Policy gate parameterised by the two independent opt-ins. Loopback and
/// RFC1918 are gated *separately* so enabling one never silently enables the
/// other, and always-forbidden ranges are rejected unconditionally.
pub(crate) fn ip_forbidden_as_destination(
    ip: IpAddr,
    allow_private: bool,
    allow_loopback: bool,
) -> bool {
    if ip_is_always_forbidden_dest(ip) {
        return true;
    }
    if ip_is_loopback_dest(ip) && !allow_loopback {
        return true;
    }
    if ip_is_private_network_dest(ip) && !allow_private {
        return true;
    }
    false
}

#[async_trait]
impl StreamDispatcher for TcpStreamDispatcher {
    async fn dispatch(&self, payload: &[u8]) -> Result<(), StreamError> {
        let sub =
            RelaySubCell::decode(payload).map_err(|e| StreamError::NotASubCell(format!("{e}")))?;
        match sub.command {
            CMD_BEGIN => {
                let begin = BeginBody::decode(&sub.body)?;

                // RT-SD-1: cap simultaneous streams. RT-SD-7: reject reuse
                // of a live stream_id before doing any work (see
                // StreamError::DuplicateStream). Both checks under one lock.
                {
                    let g = self.streams.lock().await;
                    if g.contains_key(&begin.stream_id) {
                        return Err(StreamError::DuplicateStream(begin.stream_id));
                    }
                    if g.len() >= self.config.max_streams {
                        return Err(StreamError::StreamCapacity(self.config.max_streams));
                    }
                }

                // RT-SD-5: host policy. Resolve, then reject if
                // any candidate IP is private/loopback/link-local/
                // etc, unless config opts in.
                if let Some(allowlist) = &self.config.host_allowlist {
                    if !allowlist.iter().any(|h| h == &begin.host) {
                        return Err(StreamError::ForbiddenDestination(begin.host.clone()));
                    }
                }
                // RT-SD-5 + DNS-rebind/TOCTOU fix: resolve ONCE, reject any
                // candidate forbidden under the (loopback, private) policy, then
                // connect to the VALIDATED SocketAddrs directly. Passing the
                // hostname back into TcpStream::connect would trigger a SECOND,
                // independent DNS resolution at dial time, letting a short-TTL
                // rebinding nameserver swap in a forbidden IP after the check -
                // so this validate-then-dial path runs UNCONDITIONALLY, even
                // when private/loopback are allowed (the two opt-ins only widen
                // *which* IPs pass the filter, never whether it runs).
                let addr = format!("{}:{}", begin.host, begin.port);
                let connect_timeout = self.config.connect_timeout;
                let allow_private = self.config.allow_private_destinations;
                let allow_loopback = self.config.allow_loopback_destinations;
                let stream = {
                    let resolved: Vec<std::net::SocketAddr> = tokio::net::lookup_host(&addr)
                        .await
                        .map_err(|_| StreamError::Resolution("could not resolve"))?
                        .collect();
                    if resolved.is_empty() {
                        return Err(StreamError::Resolution("no addresses"));
                    }
                    for sa in &resolved {
                        if ip_forbidden_as_destination(sa.ip(), allow_private, allow_loopback) {
                            return Err(StreamError::ForbiddenDestination(format!(
                                "{} -> {}",
                                begin.host, sa
                            )));
                        }
                    }
                    // Every candidate passed policy - dial them directly, in
                    // order, never re-resolving the name.
                    let mut connected = None;
                    let mut last_err: Option<std::io::Error> = None;
                    for sa in &resolved {
                        match tokio::time::timeout(connect_timeout, TcpStream::connect(sa)).await {
                            Ok(Ok(s)) => {
                                connected = Some(s);
                                break;
                            }
                            Ok(Err(e)) => last_err = Some(e),
                            Err(_) => {
                                last_err = Some(std::io::Error::new(
                                    std::io::ErrorKind::TimedOut,
                                    "connect timed out",
                                ))
                            }
                        }
                    }
                    connected.ok_or_else(|| {
                        StreamError::Io(last_err.unwrap_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::AddrNotAvailable,
                                "all resolved addresses failed to connect",
                            )
                        }))
                    })?
                };
                stream.set_nodelay(true).ok();
                let (mut up_r, mut up_w) = stream.into_split();

                let (tx_to_socket, mut rx_for_socket) =
                    tokio::sync::mpsc::channel::<Vec<u8>>(FORWARD_CHANNEL_CAP);
                self.streams
                    .lock()
                    .await
                    .insert(begin.stream_id, tx_to_socket);

                // Pump bytes coming FROM the client -> upstream.
                // RT-SD-3: cap any single write_all by the
                // configured timeout so a slow upstream can't
                // pin this task forever.
                let write_timeout = self.config.upstream_write_timeout;
                tokio::spawn(async move {
                    while let Some(bytes) = rx_for_socket.recv().await {
                        match tokio::time::timeout(write_timeout, up_w.write_all(&bytes)).await {
                            Ok(Ok(())) => {}
                            Ok(Err(_)) | Err(_) => {
                                tracing::debug!(
                                    "TcpStreamDispatcher: upstream write failed or timed out"
                                );
                                break;
                            }
                        }
                    }
                    let _ = up_w.shutdown().await;
                });

                // Pump bytes coming FROM upstream -> client.
                let events_tx = self.events_tx.clone();
                let stream_id = begin.stream_id;
                let streams = self.streams.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    loop {
                        match up_r.read(&mut buf).await {
                            Ok(0) => {
                                let _ = events_tx.send(StreamEvent::End { stream_id }).await;
                                streams.lock().await.remove(&stream_id);
                                break;
                            }
                            Ok(n) => {
                                // `.await` here is the backpressure: when the
                                // session loop falls behind draining the
                                // reverse channel, this blocks instead of
                                // buffering unbounded return bytes.
                                if events_tx
                                    .send(StreamEvent::Data {
                                        stream_id,
                                        bytes: buf[..n].to_vec(),
                                    })
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            Err(_) => {
                                let _ = events_tx.send(StreamEvent::End { stream_id }).await;
                                streams.lock().await.remove(&stream_id);
                                break;
                            }
                        }
                    }
                });
                Ok(())
            }
            CMD_DATA => {
                let data = DataBody::decode(&sub.body)?;
                // Clone the Sender OUT of the lock so the (now bounded,
                // backpressuring) `send().await` never holds the streams
                // mutex across an await - that would serialize every other
                // stream's dispatch behind one slow upstream.
                let tx = {
                    let streams = self.streams.lock().await;
                    streams
                        .get(&data.stream_id)
                        .ok_or(StreamError::UnknownStream(data.stream_id))?
                        .clone()
                };
                tx.send(data.bytes)
                    .await
                    .map_err(|_| StreamError::ReverseChannelClosed)?;
                Ok(())
            }
            CMD_END => {
                let end = EndBody::decode(&sub.body)?;
                // Drop the write-channel to signal shutdown to the
                // upstream-pump task. The read-pump task will
                // surface its own END once upstream EOFs.
                let mut streams = self.streams.lock().await;
                streams.remove(&end.stream_id);
                Ok(())
            }
            other => Err(StreamError::UnsupportedCommand(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    #[test]
    fn ssrf_gate_separates_loopback_from_private_and_pins_always_forbidden() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        let lo4 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let lo6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let rfc1918 = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
        let ula = IpAddr::V6("fd00::1".parse().unwrap());
        let metadata = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)); // link-local / cloud metadata
        let public = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)); // example.com

        // Default posture: everything non-public is forbidden.
        for ip in [lo4, lo6, rfc1918, ula, metadata] {
            assert!(
                ip_forbidden_as_destination(ip, false, false),
                "{ip} must be forbidden by default"
            );
        }
        assert!(!ip_forbidden_as_destination(public, false, false));

        // Red-team #13: IPv4-transition v6 embeddings must be always-forbidden
        // (they can carry an internal v4 destination), even with BOTH opt-ins.
        for s in [
            "2002:0a00:0001::",   // 6to4 wrapping 10.0.0.1
            "2001:0000:4136::",   // Teredo
            "64:ff9b::0a00:0001", // NAT64 well-known -> 10.0.0.1
            "64:ff9b:1::c0a8:1",  // NAT64 local-use
            "::0a00:0001",        // IPv4-compatible -> 10.0.0.1
        ] {
            let ip = IpAddr::V6(s.parse().unwrap());
            assert!(
                ip_is_always_forbidden_dest(ip) && ip_forbidden_as_destination(ip, true, true),
                "{s} (v4-in-v6 embedding) must be always forbidden"
            );
        }
        // ...but a normal global-unicast v6 (2000::/3) is fine.
        assert!(!ip_forbidden_as_destination(
            IpAddr::V6("2606:4700:4700::1111".parse().unwrap()),
            false,
            false
        ));

        // Enabling PRIVATE must NOT re-admit loopback, and must NEVER
        // re-admit the always-forbidden metadata endpoint (#32 collapse).
        assert!(!ip_forbidden_as_destination(rfc1918, true, false));
        assert!(!ip_forbidden_as_destination(ula, true, false));
        assert!(
            ip_forbidden_as_destination(lo4, true, false),
            "allow_private must not open loopback"
        );
        assert!(
            ip_forbidden_as_destination(lo6, true, false),
            "allow_private must not open loopback"
        );
        assert!(
            ip_forbidden_as_destination(metadata, true, false),
            "cloud metadata is always forbidden"
        );

        // Enabling LOOPBACK must NOT re-admit RFC1918/ULA, nor metadata.
        assert!(!ip_forbidden_as_destination(lo4, false, true));
        assert!(!ip_forbidden_as_destination(lo6, false, true));
        assert!(
            ip_forbidden_as_destination(rfc1918, false, true),
            "allow_loopback must not open RFC1918"
        );
        assert!(
            ip_forbidden_as_destination(metadata, false, true),
            "cloud metadata is always forbidden even with loopback on"
        );

        // Even both opt-ins together cannot re-admit an always-forbidden range.
        assert!(ip_forbidden_as_destination(metadata, true, true));
        // The strict composed predicate still flags every non-public range.
        for ip in [lo4, lo6, rfc1918, ula, metadata] {
            assert!(
                ip_forbidden_as_destination(ip, false, false),
                "{ip} must stay in strict set"
            );
        }
        assert!(!ip_forbidden_as_destination(public, false, false));
    }

    #[test]
    fn begin_body_roundtrip() {
        let body = BeginBody {
            stream_id: 7,
            host: "example.com".to_string(),
            port: 443,
        };
        let bytes = body.encode().unwrap();
        let decoded = BeginBody::decode(&bytes).unwrap();
        assert_eq!(decoded, body);
    }

    #[test]
    fn begin_body_rejects_zero_port() {
        let body = BeginBody {
            stream_id: 1,
            host: "a".into(),
            port: 0,
        };
        // encode allows it (codec is permissive on encode), decode
        // rejects (defensive on parse).
        let bytes = body.encode().unwrap();
        assert!(BeginBody::decode(&bytes).is_err());
    }

    #[test]
    fn data_body_roundtrip_carries_bytes() {
        let body = DataBody {
            stream_id: 42,
            bytes: b"GET / HTTP/1.1\r\n".to_vec(),
        };
        let bytes = body.encode();
        let decoded = DataBody::decode(&bytes).unwrap();
        assert_eq!(decoded, body);
    }

    #[test]
    fn end_body_roundtrip() {
        let body = EndBody { stream_id: 999 };
        let bytes = body.encode();
        let decoded = EndBody::decode(&bytes).unwrap();
        assert_eq!(decoded, body);
    }

    #[tokio::test]
    async fn dispatcher_unknown_command_errors() {
        let (d, _rx) = TcpStreamDispatcher::new();
        let sub = RelaySubCell {
            command: 0x77,
            body: vec![],
        }
        .encode()
        .unwrap();
        let err = d.dispatch(&sub).await.unwrap_err();
        assert!(matches!(err, StreamError::UnsupportedCommand(0x77)));
    }

    #[tokio::test]
    async fn dispatcher_unknown_stream_data_errors() {
        let (d, _rx) = TcpStreamDispatcher::new();
        let sub = RelaySubCell {
            command: CMD_DATA,
            body: DataBody {
                stream_id: 99,
                bytes: b"hi".to_vec(),
            }
            .encode(),
        }
        .encode()
        .unwrap();
        let err = d.dispatch(&sub).await.unwrap_err();
        assert!(matches!(err, StreamError::UnknownStream(99)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dispatcher_rejects_duplicate_stream_id() {
        // RT-SD-7: a second BEGIN reusing a live stream_id must be rejected,
        // not silently overwrite the map entry (which orphans the prior
        // upstream read-pump task and mis-routes its StreamEvents).
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = echo.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = sock.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        let (d, _events) =
            TcpStreamDispatcher::with_config(TcpStreamDispatcherConfig::permissive_for_tests());
        let begin = |id: u16| {
            RelaySubCell {
                command: CMD_BEGIN,
                body: BeginBody {
                    stream_id: id,
                    host: addr.ip().to_string(),
                    port: addr.port(),
                }
                .encode()
                .unwrap(),
            }
            .encode()
            .unwrap()
        };
        // First BEGIN for stream 1 succeeds and registers the stream.
        d.dispatch(&begin(1)).await.unwrap();
        // Reusing stream_id 1 is rejected as a protocol violation.
        let err = d.dispatch(&begin(1)).await.unwrap_err();
        assert!(
            matches!(err, StreamError::DuplicateStream(1)),
            "got {err:?}"
        );
        // A fresh stream_id still works.
        d.dispatch(&begin(2)).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dispatcher_begin_data_end_round_trip() {
        // Boot an echo server.
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = echo.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = sock.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                    let _ = w.shutdown().await;
                });
            }
        });

        // Drive the dispatcher: BEGIN -> echo's address. Tests
        // need to dial localhost, so use permissive config.
        let (d, mut events) =
            TcpStreamDispatcher::with_config(TcpStreamDispatcherConfig::permissive_for_tests());
        let begin_sub = RelaySubCell {
            command: CMD_BEGIN,
            body: BeginBody {
                stream_id: 1,
                host: addr.ip().to_string(),
                port: addr.port(),
            }
            .encode()
            .unwrap(),
        }
        .encode()
        .unwrap();
        d.dispatch(&begin_sub).await.unwrap();

        // DATA -> write payload.
        let payload = b"Mirage stream dispatch works.";
        let data_sub = RelaySubCell {
            command: CMD_DATA,
            body: DataBody {
                stream_id: 1,
                bytes: payload.to_vec(),
            }
            .encode(),
        }
        .encode()
        .unwrap();
        d.dispatch(&data_sub).await.unwrap();

        // Drain reverse channel - should see the echo bytes
        // arrive as a StreamEvent::Data.
        let mut got = Vec::new();
        while got.len() < payload.len() {
            match tokio::time::timeout(std::time::Duration::from_secs(2), events.recv()).await {
                Ok(Some(StreamEvent::Data { bytes, .. })) => got.extend_from_slice(&bytes),
                Ok(Some(StreamEvent::End { .. })) => break,
                Ok(None) => break,
                Err(_) => panic!("timeout waiting for echo"),
            }
        }
        assert_eq!(got, payload);

        // END.
        let end_sub = RelaySubCell {
            command: CMD_END,
            body: EndBody { stream_id: 1 }.encode().to_vec(),
        }
        .encode()
        .unwrap();
        d.dispatch(&end_sub).await.unwrap();
    }

    #[tokio::test]
    async fn dispatcher_rejects_loopback_by_default() {
        // RT-SD-5: production default rejects 127.0.0.1.
        let (d, _rx) = TcpStreamDispatcher::new();
        let sub = RelaySubCell {
            command: CMD_BEGIN,
            body: BeginBody {
                stream_id: 1,
                host: "127.0.0.1".to_string(),
                port: 1234,
            }
            .encode()
            .unwrap(),
        }
        .encode()
        .unwrap();
        let err = d.dispatch(&sub).await.unwrap_err();
        assert!(
            matches!(err, StreamError::ForbiddenDestination(_)),
            "expected ForbiddenDestination, got {err:?}"
        );
    }

    #[tokio::test]
    async fn dispatcher_rejects_private_ip_by_default() {
        let (d, _rx) = TcpStreamDispatcher::new();
        for host in ["10.0.0.5", "192.168.1.1", "172.16.0.1", "169.254.169.254"] {
            let sub = RelaySubCell {
                command: CMD_BEGIN,
                body: BeginBody {
                    stream_id: 1,
                    host: host.to_string(),
                    port: 80,
                }
                .encode()
                .unwrap(),
            }
            .encode()
            .unwrap();
            let err = d.dispatch(&sub).await.unwrap_err();
            assert!(
                matches!(err, StreamError::ForbiddenDestination(_)),
                "host={host} expected ForbiddenDestination, got {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn dispatcher_rejects_ipv6_link_local_and_loopback() {
        let (d, _rx) = TcpStreamDispatcher::new();
        for host in ["::1", "fe80::1", "fc00::1"] {
            let sub = RelaySubCell {
                command: CMD_BEGIN,
                body: BeginBody {
                    stream_id: 1,
                    host: host.to_string(),
                    port: 80,
                }
                .encode()
                .unwrap(),
            }
            .encode()
            .unwrap();
            let err = d.dispatch(&sub).await.unwrap_err();
            assert!(
                matches!(err, StreamError::ForbiddenDestination(_)),
                "host={host} expected ForbiddenDestination, got {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn dispatcher_rejects_host_outside_allowlist() {
        let cfg = TcpStreamDispatcherConfig {
            host_allowlist: Some(vec!["example.com".to_string()]),
            ..TcpStreamDispatcherConfig::permissive_for_tests()
        };
        let (d, _rx) = TcpStreamDispatcher::with_config(cfg);
        let sub = RelaySubCell {
            command: CMD_BEGIN,
            body: BeginBody {
                stream_id: 1,
                host: "not-on-list.example".to_string(),
                port: 443,
            }
            .encode()
            .unwrap(),
        }
        .encode()
        .unwrap();
        let err = d.dispatch(&sub).await.unwrap_err();
        assert!(matches!(err, StreamError::ForbiddenDestination(_)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dispatcher_enforces_stream_capacity() {
        // RT-SD-1: cap at 3, open 3, the 4th BEGIN fails.
        // Use a keep-alive listener that holds the connection
        // open so the upstream-read task doesn't EOF + remove
        // the stream from the map mid-test.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (_keep_tx, mut keep_rx) = tokio::sync::mpsc::channel::<()>(1);
        tokio::spawn(async move {
            let mut accepted = Vec::new();
            loop {
                tokio::select! {
                    Ok((sock, _)) = listener.accept() => accepted.push(sock),
                    _ = keep_rx.recv() => break,
                }
            }
        });
        let cfg = TcpStreamDispatcherConfig {
            max_streams: 3,
            ..TcpStreamDispatcherConfig::permissive_for_tests()
        };
        let (d, _rx) = TcpStreamDispatcher::with_config(cfg);
        for sid in 1u16..=3 {
            let sub = RelaySubCell {
                command: CMD_BEGIN,
                body: BeginBody {
                    stream_id: sid,
                    host: addr.ip().to_string(),
                    port: addr.port(),
                }
                .encode()
                .unwrap(),
            }
            .encode()
            .unwrap();
            d.dispatch(&sub).await.unwrap();
        }
        // 4th hits the cap.
        let sub = RelaySubCell {
            command: CMD_BEGIN,
            body: BeginBody {
                stream_id: 4,
                host: addr.ip().to_string(),
                port: addr.port(),
            }
            .encode()
            .unwrap(),
        }
        .encode()
        .unwrap();
        let err = d.dispatch(&sub).await.unwrap_err();
        assert!(
            matches!(err, StreamError::StreamCapacity(3)),
            "expected StreamCapacity, got {err:?}"
        );
    }
}
