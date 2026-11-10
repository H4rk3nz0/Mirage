//! The userspace IP gateway: terminate every TCP flow off the TUN and hand
//! each one out as a [`TcpFlow`] (target + byte stream).
//!
//! # How it works
//!
//! smoltcp normally acts as a host bound to specific addresses. To act as a
//! *transparent gateway* - accepting connections the app makes to ANY
//! destination - we run smoltcp with [`Interface::set_any_ip`] and, whenever we
//! see a TCP SYN to a not-yet-seen `(dst_ip, dst_port)`, we spin up a listening
//! socket bound to exactly that endpoint. smoltcp then completes the handshake
//! as if it were the destination; once established we surface the flow.
//!
//! The single [`NetStack::run`] task owns everything (device, interface,
//! sockets) - no shared locking. It bridges smoltcp's synchronous poll model to
//! async [`TcpFlow`] handles via per-flow read channels + one shared write
//! command channel (with `PollSender` backpressure).

// Every slice index here is computed as `x.min(len)` or guarded by a preceding
// length/`can_send`/`front()` check, so it cannot panic; the `unwrap`s on
// `front_mut()` are proven `Some` by the immediately-preceding `front()` match
// in the same loop iteration.
#![allow(clippy::indexing_slicing, clippy::unwrap_used)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpCidr, IpEndpoint};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

use crate::device::TunDevice;
use crate::flow::{parse_packet, FlowKey, Protocol};

/// Netstack tuning knobs.
#[derive(Debug, Clone, Copy)]
pub struct NetStackConfig {
    /// Device MTU (max IP packet size).
    pub mtu: usize,
    /// Per-socket smoltcp send/recv buffer size (bytes).
    pub socket_buffer: usize,
    /// Depth of each flow's app->caller read channel (in packets).
    pub read_channel_depth: usize,
    /// Depth of the shared caller->stack write-command channel.
    pub write_channel_depth: usize,
    /// Max concurrently-tracked flows (backstop against SYN-flood memory use).
    pub max_flows: usize,
    /// Cap on TOTAL caller->app bytes buffered across all flows. When exceeded,
    /// the loop stops draining the write-command channel so `TcpFlow::poll_write`
    /// blocks and TCP backpressure reaches the remote (prevents a stalled local
    /// app + fast remote from exhausting client memory).
    pub pending_write_cap: usize,
    /// Per-socket inactivity timeout: an idle / half-open (never-ACKed) socket is
    /// aborted after this, so a SYN flood or abandoned handshake can't pin
    /// buffers and wedge `max_flows` forever.
    pub flow_timeout: std::time::Duration,
    /// Keep-alive probe interval on established flows (reaps silently-dead peers).
    pub keepalive: std::time::Duration,
}

impl Default for NetStackConfig {
    fn default() -> Self {
        Self {
            mtu: crate::device::DEFAULT_TUN_MTU,
            socket_buffer: 64 * 1024,
            read_channel_depth: 16,
            write_channel_depth: 64,
            max_flows: 2048,
            pending_write_cap: 4 * 1024 * 1024,
            flow_timeout: std::time::Duration::from_secs(30),
            keepalive: std::time::Duration::from_secs(15),
        }
    }
}

/// A write command from a [`TcpFlow`] / [`UdpFlow`] to the netstack loop.
enum StackCmd {
    /// Application-bound bytes to inject into the TCP flow's send buffer.
    Data(SocketHandle, Vec<u8>),
    /// Half-close the TCP flow (the caller finished writing) -> smoltcp FIN.
    Shutdown(SocketHandle),
    /// A UDP datagram to deliver to the app. Keyed by `dst` (the flow's target,
    /// NOT a raw `SocketHandle`) so a reply arriving after the dst socket was
    /// reaped is safely dropped instead of panicking smoltcp with a stale handle.
    UdpData {
        /// The flow's target (dst); the reply socket is looked up live from this.
        dst: SocketAddr,
        /// The app's endpoint (the datagram's destination on the local side).
        src: SocketAddr,
        /// Datagram payload.
        data: Vec<u8>,
    },
}

/// A terminated flow surfaced by the netstack: either a TCP byte-stream or a
/// UDP datagram flow. Both carry the `target` the app was trying to reach.
#[derive(Debug)]
pub enum Flow {
    /// A TCP connection as an async byte stream.
    Tcp(TcpFlow),
    /// A UDP association as a datagram stream.
    Udp(UdpFlow),
}

/// A terminated UDP flow: datagrams to/from a local app for one `(src -> target)`
/// association. The caller tunnels these through Mirage's UDP relay - reading
/// yields datagrams the app SENT, sending delivers datagrams back TO the app.
pub struct UdpFlow {
    /// Where the app addressed its datagrams (the Mirage relay target).
    pub target: SocketAddr,
    /// The app endpoint to deliver replies to.
    src: SocketAddr,
    rx: mpsc::Receiver<Vec<u8>>,
    cmd: mpsc::Sender<StackCmd>,
}

impl std::fmt::Debug for UdpFlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpFlow")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl UdpFlow {
    /// Next datagram the app sent to `target`. `None` when the flow is reaped.
    pub async fn recv_datagram(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }

    /// Deliver a datagram from `target` back to the app. Returns `false` if the
    /// netstack is gone. (UDP is lossy; a full send buffer drops the datagram.)
    pub async fn send_datagram(&self, data: Vec<u8>) -> bool {
        self.cmd
            .send(StackCmd::UdpData {
                dst: self.target,
                src: self.src,
                data,
            })
            .await
            .is_ok()
    }

    /// Split into a datagram receiver (app->target) + sender (target->app) so both
    /// directions can be pumped concurrently in a `select!` without a
    /// borrow conflict (mirrors how the SOCKS UDP-ASSOCIATE path uses two halves).
    #[must_use]
    pub fn split(self) -> (UdpFlowRx, UdpFlowTx) {
        (
            UdpFlowRx { rx: self.rx },
            UdpFlowTx {
                dst: self.target,
                src: self.src,
                cmd: self.cmd,
            },
        )
    }
}

/// Receive half of a split [`UdpFlow`]: datagrams the app sent to the target.
pub struct UdpFlowRx {
    rx: mpsc::Receiver<Vec<u8>>,
}

impl UdpFlowRx {
    /// Next datagram the app sent. `None` once the flow is reaped.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }
}

/// Send half of a split [`UdpFlow`]: datagrams to deliver back to the app.
pub struct UdpFlowTx {
    dst: SocketAddr,
    src: SocketAddr,
    cmd: mpsc::Sender<StackCmd>,
}

impl UdpFlowTx {
    /// Deliver a datagram from `target` back to the app. `false` if gone.
    pub async fn send(&self, data: Vec<u8>) -> bool {
        self.cmd
            .send(StackCmd::UdpData {
                dst: self.dst,
                src: self.src,
                data,
            })
            .await
            .is_ok()
    }
}

/// A terminated TCP flow: an async byte stream to/from a local app, plus the
/// `target` (`dst ip:port`) the app was trying to reach. The caller tunnels
/// this through Mirage - reading yields what the app SENT, writing delivers
/// bytes back TO the app.
pub struct TcpFlow {
    /// Where the app wanted to connect (the Mirage dial target).
    pub target: SocketAddr,
    handle: SocketHandle,
    reader: mpsc::Receiver<Vec<u8>>,
    leftover: Vec<u8>,
    pos: usize,
    writer: PollSender<StackCmd>,
    read_closed: bool,
}

impl std::fmt::Debug for TcpFlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpFlow")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl AsyncRead for TcpFlow {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Serve any leftover from a previous partial read first.
        if self.pos < self.leftover.len() {
            let n = (self.leftover.len() - self.pos).min(buf.remaining());
            let start = self.pos;
            buf.put_slice(&self.leftover[start..start + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        if self.read_closed {
            return Poll::Ready(Ok(())); // EOF
        }
        match self.reader.poll_recv(cx) {
            Poll::Ready(Some(chunk)) => {
                // An empty chunk is the EOF sentinel the netstack pushes on the
                // app's FIN (receive half closed). Latch EOF and return 0 bytes.
                if chunk.is_empty() {
                    self.read_closed = true;
                    return Poll::Ready(Ok(()));
                }
                let n = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..n]);
                if n < chunk.len() {
                    self.leftover = chunk;
                    self.pos = n;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                self.read_closed = true;
                Poll::Ready(Ok(())) // EOF: the socket closed
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for TcpFlow {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.writer.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let handle = self.handle;
                self.writer
                    .send_item(StackCmd::Data(handle, buf.to_vec()))
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(_)) => {
                Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.writer.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let handle = self.handle;
                let _ = self.writer.send_item(StackCmd::Shutdown(handle));
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Per-flow bookkeeping the loop holds.
struct FlowSlot {
    /// The full (src,dst) flow key (frees `active_flows` on reap).
    key: FlowKey,
    /// Push app-received bytes to the flow's reader.
    read_tx: mpsc::Sender<Vec<u8>>,
    /// The flow handle, held until the connection is established then emitted.
    pending_flow: Option<TcpFlow>,
    /// Caller->app bytes awaiting room in the socket send buffer.
    pending_write: std::collections::VecDeque<Vec<u8>>,
    /// Bytes currently held in `pending_write` (for O(1) global-cap accounting).
    pending_write_bytes: usize,
    /// True once the flow has been emitted to the caller.
    emitted: bool,
    /// True once the caller asked to half-close (FIN pending).
    shutdown_requested: bool,
    /// True once an EOF sentinel has been pushed to the reader (the app sent FIN).
    read_eof_sent: bool,
}

/// Per-`(src,dst)` UDP flow bookkeeping. (The dst socket is `udp_sockets[key.dst]`
/// and the app endpoint is `key.src`, so neither is duplicated here.)
struct UdpFlowSlot {
    /// Push app-sent datagrams to the flow's reader.
    read_tx: mpsc::Sender<Vec<u8>>,
    /// Last time a datagram moved either way (for idle reap; UDP has no FIN).
    last_activity: SmolInstant,
}

/// The userspace IP gateway. Drive it with [`NetStack::run`].
pub struct NetStack<D: TunDevice> {
    device: D,
    qdev: crate::queue_device::QueueDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    cfg: NetStackConfig,
    flows: HashMap<SocketHandle, FlowSlot>,
    /// (src,dst) 4-tuples with a live socket - dedups SYN retransmits into one
    /// flow while letting distinct parallel connections to the same dst coexist.
    active_flows: std::collections::HashSet<FlowKey>,
    /// One shared UDP socket per dst endpoint (smoltcp demuxes senders on recv).
    udp_sockets: HashMap<SocketAddr, SocketHandle>,
    /// Per-`(src,dst)` UDP flow state, keyed by the 4-tuple.
    udp_flows: HashMap<FlowKey, UdpFlowSlot>,
    /// Total caller->app bytes buffered across all flows (global write cap).
    pending_write_bytes: usize,
    flow_tx: mpsc::Sender<Flow>,
    cmd_tx: mpsc::Sender<StackCmd>,
    cmd_rx: mpsc::Receiver<StackCmd>,
    /// Separate UDP-reply channel, drained UNCONDITIONALLY so TCP's write-cap
    /// backpressure (which gates `cmd_rx`) can never starve UDP replies.
    udp_cmd_tx: mpsc::Sender<StackCmd>,
    udp_cmd_rx: mpsc::Receiver<StackCmd>,
    /// Monotonic base for smoltcp timestamps (elapsed since construction).
    start: tokio::time::Instant,
    /// Last time idle UDP flows were swept (throttles the O(n) reap).
    last_udp_reap: SmolInstant,
}

/// smoltcp `IpEndpoint` from a std `SocketAddr` (bind + reply addressing).
fn to_ip_endpoint(a: SocketAddr) -> IpEndpoint {
    IpEndpoint::new(a.ip().into(), a.port())
}

/// std `SocketAddr` from a smoltcp `IpEndpoint` (recv sender identity).
fn from_ip_endpoint(e: IpEndpoint) -> SocketAddr {
    SocketAddr::new(e.addr.into(), e.port)
}

impl<D: TunDevice> NetStack<D> {
    /// Build a netstack over `device`. Returns the stack (to `run`) and the
    /// receiver that yields each terminated [`TcpFlow`].
    #[must_use]
    pub fn new(device: D, cfg: NetStackConfig) -> (Self, mpsc::Receiver<Flow>) {
        let mut qdev = crate::queue_device::QueueDevice::new(cfg.mtu);
        let mut iface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut qdev,
            SmolInstant::from_millis(0),
        );
        // Give the interface a placeholder address + a default route, and turn
        // on any-ip so it accepts SYNs to arbitrary destinations (the gateway
        // trick). The listening socket bound to (dst_ip, dst_port) makes smoltcp
        // reply AS the destination.
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(smoltcp::wire::IpAddress::v4(10, 0, 0, 1), 24));
        });
        iface.set_any_ip(true);
        let _ = iface
            .routes_mut()
            .add_default_ipv4_route(smoltcp::wire::Ipv4Address::new(10, 0, 0, 1));

        let (flow_tx, flow_rx) = mpsc::channel(cfg.write_channel_depth.max(8));
        let (cmd_tx, cmd_rx) = mpsc::channel(cfg.write_channel_depth);
        let (udp_cmd_tx, udp_cmd_rx) = mpsc::channel(cfg.write_channel_depth);
        (
            Self {
                device,
                qdev,
                iface,
                sockets: SocketSet::new(vec![]),
                cfg,
                flows: HashMap::new(),
                active_flows: std::collections::HashSet::new(),
                udp_sockets: HashMap::new(),
                udp_flows: HashMap::new(),
                pending_write_bytes: 0,
                flow_tx,
                cmd_tx,
                cmd_rx,
                udp_cmd_tx,
                udp_cmd_rx,
                start: tokio::time::Instant::now(),
                last_udp_reap: SmolInstant::from_millis(0),
            },
            flow_rx,
        )
    }

    fn now(&self) -> SmolInstant {
        SmolInstant::from_micros(self.start.elapsed().as_micros() as i64)
    }

    /// Run the gateway loop until the device closes or all flow receivers drop.
    pub async fn run(mut self) -> Result<(), crate::TunError> {
        let mut rxbuf = vec![0u8; self.cfg.mtu.max(1600)];
        loop {
            // Decide how long smoltcp is happy to sleep (timers/retransmits).
            let now = self.now();
            let delay = self
                .iface
                .poll_delay(now, &self.sockets)
                .map_or(tokio::time::Duration::from_millis(100), |d| {
                    tokio::time::Duration::from_micros(d.total_micros())
                });

            tokio::select! {
                biased;
                // A caller wrote to / closed a flow. Gated on the global write
                // cap: while too much is already buffered we STOP draining the
                // command channel, so poll_write blocks and TCP backpressures the
                // remote (the recv/sleep branches keep the loop alive + draining
                // pending_write, which re-opens this branch when it drops below cap).
                cmd = self.cmd_rx.recv(), if self.pending_write_bytes < self.cfg.pending_write_cap => {
                    match cmd {
                        Some(c) => self.apply_cmd(c),
                        None => {} // all flows dropped their senders; keep serving inbound
                    }
                }
                // UDP replies: drained UNCONDITIONALLY (never gated by the TCP
                // write cap, so a backpressured TCP flow can't starve UDP).
                udp = self.udp_cmd_rx.recv() => {
                    if let Some(c) = udp {
                        self.apply_cmd(c);
                    }
                }
                // A packet arrived from the TUN.
                r = self.device.recv(&mut rxbuf) => {
                    let n = r?;
                    if n > 0 {
                        self.ingest_packet(rxbuf[..n].to_vec());
                    }
                }
                // smoltcp timer tick (retransmits, delayed ACKs, ...).
                () = tokio::time::sleep(delay) => {}
            }

            self.poll_and_pump().await?;
        }
    }

    /// Feed one inbound packet: create a listening socket for a fresh TCP SYN,
    /// then queue the packet for smoltcp.
    fn ingest_packet(&mut self, pkt: Vec<u8>) {
        if let Some(p) = parse_packet(&pkt) {
            match p.key.protocol {
                Protocol::Tcp => {
                    if p.tcp_syn
                        && !self.active_flows.contains(&p.key)
                        && self.flows.len() < self.cfg.max_flows
                    {
                        self.open_listener(p.key);
                    }
                }
                Protocol::Udp => {
                    // Every datagram carries (src,dst) - establish the flow (and
                    // the shared dst socket) on first sight, bounded by max_flows.
                    if !self.udp_flows.contains_key(&p.key)
                        && self.udp_flows.len() < self.cfg.max_flows
                    {
                        self.open_udp_flow(p.key);
                    }
                }
            }
        }
        self.qdev.push_rx(pkt);
    }

    /// Create a smoltcp TCP socket listening on `key.dst` (the app's dst) and a
    /// [`TcpFlow`] to surface once it establishes.
    fn open_listener(&mut self, key: FlowKey) {
        let target = key.dst;
        let rx_buf = tcp::SocketBuffer::new(vec![0u8; self.cfg.socket_buffer]);
        let tx_buf = tcp::SocketBuffer::new(vec![0u8; self.cfg.socket_buffer]);
        let mut socket = tcp::Socket::new(rx_buf, tx_buf);
        // Bound half-open / idle sockets so a SYN flood or an abandoned handshake
        // can't pin buffers and wedge max_flows forever: on timeout smoltcp drives
        // the socket to Closed, which the reap in `service_socket` frees. Keep-
        // alive additionally reaps silently-dead ESTABLISHED peers (a live local
        // app keeps ACKing probes, so a busy flow is never killed).
        socket.set_timeout(Some(smoltcp::time::Duration::from_micros(
            self.cfg.flow_timeout.as_micros() as u64,
        )));
        socket.set_keep_alive(Some(smoltcp::time::Duration::from_micros(
            self.cfg.keepalive.as_micros() as u64,
        )));
        // Listen on the exact destination the app is dialing.
        if socket.listen(target).is_err() {
            return;
        }
        let handle = self.sockets.add(socket);
        let (read_tx, read_rx) = mpsc::channel(self.cfg.read_channel_depth);
        let flow = TcpFlow {
            target,
            handle,
            reader: read_rx,
            leftover: Vec::new(),
            pos: 0,
            writer: PollSender::new(self.cmd_tx.clone()),
            read_closed: false,
        };
        self.flows.insert(
            handle,
            FlowSlot {
                key,
                read_tx,
                pending_flow: Some(flow),
                pending_write: std::collections::VecDeque::new(),
                pending_write_bytes: 0,
                emitted: false,
                shutdown_requested: false,
                read_eof_sent: false,
            },
        );
        self.active_flows.insert(key);
    }

    /// Establish a UDP flow for `key`, creating the shared dst-keyed socket on
    /// first use, and emit a [`UdpFlow`] to the caller.
    fn open_udp_flow(&mut self, key: FlowKey) {
        let dst = key.dst;
        // `created` tracks whether THIS call allocated the shared dst socket, so
        // we can roll it back if the flow can't be emitted (else a full flow_tx
        // would leave an orphan socket uncapped by max_flows).
        let (dst_handle, created) = if let Some(h) = self.udp_sockets.get(&dst) {
            (*h, false)
        } else {
            let buf = self.cfg.socket_buffer;
            let mut socket = udp::Socket::new(
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 32], vec![0u8; buf]),
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 32], vec![0u8; buf]),
            );
            if socket.bind(to_ip_endpoint(dst)).is_err() {
                return;
            }
            let h = self.sockets.add(socket);
            self.udp_sockets.insert(dst, h);
            (h, true)
        };
        let (read_tx, read_rx) = mpsc::channel(self.cfg.read_channel_depth);
        let flow = UdpFlow {
            target: dst,
            src: key.src,
            rx: read_rx,
            cmd: self.udp_cmd_tx.clone(),
        };
        // Only register the flow if the caller actually receives it (a full/closed
        // flow channel just drops this datagram; a retransmit retries).
        if self.flow_tx.try_send(Flow::Udp(flow)).is_ok() {
            let now = self.now();
            self.udp_flows.insert(
                key,
                UdpFlowSlot {
                    read_tx,
                    last_activity: now,
                },
            );
        } else if created {
            // Roll back the just-created orphan socket (no flow will back it).
            self.sockets.remove(dst_handle);
            self.udp_sockets.remove(&dst);
        }
    }

    fn apply_cmd(&mut self, cmd: StackCmd) {
        match cmd {
            StackCmd::Data(handle, data) => {
                if let Some(slot) = self.flows.get_mut(&handle) {
                    // Buffer onto the socket; the pump drains any remainder. Track
                    // bytes on the per-slot + global counters for the write cap.
                    self.pending_write_bytes += data.len();
                    slot.pending_write_bytes += data.len();
                    slot.pending_write.push_back(data);
                }
            }
            StackCmd::Shutdown(handle) => {
                if let Some(slot) = self.flows.get_mut(&handle) {
                    slot.shutdown_requested = true;
                }
            }
            StackCmd::UdpData { dst, src, data } => {
                // Look up the reply socket LIVE by dst - never a caller-held raw
                // handle. After a reap the dst key is gone, so a late reply is
                // dropped (UDP is lossy) instead of panicking smoltcp with a
                // stale/recycled handle (the CRITICAL bug). UDP is also lossy on
                // a full tx buffer.
                if let Some(&handle) = self.udp_sockets.get(&dst) {
                    let now = self.now();
                    let socket = self.sockets.get_mut::<udp::Socket>(handle);
                    let _ = socket.send_slice(&data, to_ip_endpoint(src));
                    // A reply is activity too: refresh the idle clock so a
                    // downlink-only association isn't reaped mid-stream.
                    if let Some(slot) = self.udp_flows.get_mut(&FlowKey {
                        src,
                        dst,
                        protocol: Protocol::Udp,
                    }) {
                        slot.last_activity = now;
                    }
                }
            }
        }
    }

    /// Poll smoltcp until quiescent, shuttle socket data to/from flows, and
    /// flush produced packets to the TUN.
    async fn poll_and_pump(&mut self) -> Result<(), crate::TunError> {
        // Poll until no more progress + no queued rx.
        loop {
            let now = self.now();
            let _ = self.iface.poll(now, &mut self.qdev, &mut self.sockets);
            if !self.qdev.has_rx() {
                break;
            }
        }

        // Move data between each TCP socket and its flow.
        let handles: Vec<SocketHandle> = self.flows.keys().copied().collect();
        for handle in handles {
            self.service_socket(handle);
        }
        // Route inbound UDP datagrams to their flows; sweep idle UDP flows.
        self.service_udp();
        self.reap_idle_udp();

        // Flush everything smoltcp produced out to the TUN. A single failed write
        // (transient ENOBUFS/EIO under load, or an undeliverable oversize packet)
        // must NOT tear down the whole gateway and every live flow: drop the
        // offending packet and keep serving. A genuinely dead device still
        // terminates the loop cleanly via `recv` in `run`.
        while let Some(pkt) = self.qdev.pop_tx() {
            if let Err(e) = self.device.send(&pkt).await {
                tracing::warn!(error = %e, len = pkt.len(), "tun: dropping packet, device send failed");
            }
        }
        Ok(())
    }

    fn service_socket(&mut self, handle: SocketHandle) {
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        let established = socket.may_send() || socket.may_recv();

        // Emit the flow once the handshake completes. Distinguish transient
        // channel-full (retry next round, socket stays ESTABLISHED so the TCP
        // window backpressures the app) from a closed receiver (caller gone -> abort).
        if established {
            if let Some(slot) = self.flows.get_mut(&handle) {
                if !slot.emitted {
                    if let Some(flow) = slot.pending_flow.take() {
                        match self.flow_tx.try_send(Flow::Tcp(flow)) {
                            Ok(()) => slot.emitted = true,
                            Err(mpsc::error::TrySendError::Full(Flow::Tcp(flow))) => {
                                slot.pending_flow = Some(flow); // retry later
                            }
                            Err(_) => {
                                // Closed (caller gone) - or an unexpected Full of a
                                // non-Tcp variant, which can't happen here. Abort.
                                slot.emitted = true;
                                self.sockets.get_mut::<tcp::Socket>(handle).abort();
                            }
                        }
                    }
                }
            }
        }

        // app -> caller: drain socket recv into the flow's read channel, but
        // only while the channel has room (else leave it buffered so the TCP
        // window backpressures the app).
        loop {
            let socket = self.sockets.get_mut::<tcp::Socket>(handle);
            if !socket.can_recv() {
                break;
            }
            let Some(slot) = self.flows.get(&handle) else {
                break;
            };
            let Ok(permit) = slot.read_tx.try_reserve() else {
                break; // reader full - apply backpressure
            };
            let mut tmp = vec![0u8; 8 * 1024];
            match socket.recv_slice(&mut tmp) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    tmp.truncate(n);
                    permit.send(tmp);
                }
            }
        }

        // App half-close (FIN): once the receive half is closed (may_recv false)
        // while we can still send (CloseWait) and the rx buffer is fully drained,
        // push ONE empty-Vec EOF sentinel so a read-to-EOF caller stops reading
        // and half-closes the bridge-bound direction. Keep read_tx alive so the
        // caller-dropped-flow guard below still works while the write half is open.
        {
            let socket = self.sockets.get::<tcp::Socket>(handle);
            let half_closed = !socket.may_recv() && socket.may_send() && !socket.can_recv();
            if half_closed {
                if let Some(slot) = self.flows.get_mut(&handle) {
                    if slot.emitted
                        && !slot.read_eof_sent
                        && slot.read_tx.try_send(Vec::new()).is_ok()
                    {
                        slot.read_eof_sent = true;
                    }
                }
            }
        }

        // caller -> app: push buffered writes into the socket send buffer,
        // decrementing the per-slot + global byte counters as they drain.
        let mut drained_total = 0usize;
        if let Some(slot) = self.flows.get_mut(&handle) {
            loop {
                let socket = self.sockets.get_mut::<tcp::Socket>(handle);
                if !socket.can_send() {
                    break;
                }
                let front_len = match slot.pending_write.front() {
                    Some(f) => f.len(),
                    None => break,
                };
                let sent = socket.send_slice(slot.pending_write.front().unwrap());
                match sent {
                    Ok(0) | Err(_) => break,
                    Ok(n) if n >= front_len => {
                        slot.pending_write.pop_front();
                        slot.pending_write_bytes =
                            slot.pending_write_bytes.saturating_sub(front_len);
                        drained_total += front_len;
                    }
                    Ok(n) => {
                        // Partial: drop the sent prefix, keep the remainder.
                        slot.pending_write.front_mut().unwrap().drain(..n);
                        slot.pending_write_bytes = slot.pending_write_bytes.saturating_sub(n);
                        drained_total += n;
                    }
                }
            }
            // Half-close once all buffered writes are flushed.
            if slot.shutdown_requested && slot.pending_write.is_empty() {
                self.sockets.get_mut::<tcp::Socket>(handle).close();
            }
        }
        self.pending_write_bytes = self.pending_write_bytes.saturating_sub(drained_total);

        // Caller-dropped-flow teardown. The caller is the sole owner of the read
        // `Receiver`, so once the flow has been emitted a closed `read_tx` means
        // the caller dropped its `TcpFlow` (e.g. `tunnel_flow` gave up after all
        // bridges were unhealthy - no `shutdown`, no `close`). Without this the
        // socket sits ESTABLISHED/CLOSE_WAIT forever, leaking the FlowSlot
        // (~2xsocket_buffer) and pinning `active_targets[dst]` - and once
        // `flows.len()` hits `max_flows` the whole gateway wedges. Abort so the
        // reap below frees the socket, FlowSlot, and target.
        if let Some(slot) = self.flows.get(&handle) {
            if slot.emitted && slot.read_tx.is_closed() {
                let socket = self.sockets.get_mut::<tcp::Socket>(handle);
                if !matches!(socket.state(), tcp::State::Closed) {
                    socket.abort();
                }
            }
        }

        // Reap a fully-closed socket - but hold off while received bytes are
        // still buffered AND a reader still exists to take them: removing the
        // socket now would drop its rx_buffer and hand the reader a premature EOF
        // (silent truncation). Later rounds drain the remainder as the reader
        // frees channel space. If the reader is gone there is nobody to truncate,
        // so reap regardless to avoid leaking the FlowSlot. Dropping the removed
        // slot drops `read_tx` -> EOF to any (still-live) flow reader.
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        if matches!(socket.state(), tcp::State::Closed) {
            let can_recv = socket.can_recv();
            let reader_gone = self
                .flows
                .get(&handle)
                .is_none_or(|s| s.read_tx.is_closed());
            if !can_recv || reader_gone {
                self.sockets.remove(handle);
                if let Some(slot) = self.flows.remove(&handle) {
                    self.active_flows.remove(&slot.key);
                    self.pending_write_bytes = self
                        .pending_write_bytes
                        .saturating_sub(slot.pending_write_bytes);
                }
            }
        }
    }

    /// Drain each UDP socket's received datagrams and route them (by sender =
    /// the app's endpoint) to the matching `(src,dst)` flow's reader.
    fn service_udp(&mut self) {
        let now = self.now();
        let sockets: Vec<(SocketAddr, SocketHandle)> =
            self.udp_sockets.iter().map(|(d, h)| (*d, *h)).collect();
        for (dst, handle) in sockets {
            loop {
                // Copy the datagram + sender out, releasing the socket borrow
                // before touching `udp_flows` (a disjoint field).
                let recvd = {
                    let socket = self.sockets.get_mut::<udp::Socket>(handle);
                    if socket.can_recv() {
                        match socket.recv() {
                            Ok((payload, meta)) => {
                                Some((from_ip_endpoint(meta.endpoint), payload.to_vec()))
                            }
                            Err(_) => None,
                        }
                    } else {
                        None
                    }
                };
                let Some((src, payload)) = recvd else {
                    break;
                };
                let key = FlowKey {
                    src,
                    dst,
                    protocol: Protocol::Udp,
                };
                if let Some(slot) = self.udp_flows.get_mut(&key) {
                    // A datagram arrived - refresh the idle clock even if the
                    // reader is full (drop-on-full, UDP lossy), so a busy-but-
                    // backpressured flow isn't reaped mid-stream.
                    slot.last_activity = now;
                    let _ = slot.read_tx.try_send(payload);
                }
            }
        }
    }

    /// Sweep UDP flows idle past `flow_timeout` (UDP has no FIN), then free any
    /// dst socket with no remaining flows. Throttled to ~1s.
    fn reap_idle_udp(&mut self) {
        let now = self.now();
        if (now - self.last_udp_reap) < smoltcp::time::Duration::from_secs(1) {
            return;
        }
        self.last_udp_reap = now;
        let timeout =
            smoltcp::time::Duration::from_micros(self.cfg.flow_timeout.as_micros() as u64);
        let stale: Vec<FlowKey> = self
            .udp_flows
            .iter()
            // Reap idle flows AND flows whose caller dropped the receiver (the
            // UDP analogue of the TCP caller-drop teardown) so a destination
            // isn't blackholed for up to flow_timeout after the caller gives up.
            .filter(|(_, s)| s.read_tx.is_closed() || (now - s.last_activity) > timeout)
            .map(|(k, _)| *k)
            .collect();
        for key in stale {
            // Dropping the slot drops `read_tx` -> the flow's recv_datagram ends.
            self.udp_flows.remove(&key);
        }
        // Free dst sockets that no longer back any flow.
        let live_dsts: std::collections::HashSet<SocketAddr> =
            self.udp_flows.keys().map(|k| k.dst).collect();
        let dead: Vec<SocketAddr> = self
            .udp_sockets
            .keys()
            .filter(|d| !live_dsts.contains(*d))
            .copied()
            .collect();
        for dst in dead {
            if let Some(h) = self.udp_sockets.remove(&dst) {
                self.sockets.remove(h);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::MemoryTun;
    use crate::queue_device::QueueDevice;
    use smoltcp::iface::{Config, Interface, SocketSet};
    use smoltcp::wire::{IpAddress, Ipv4Address};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A manually-driven smoltcp TCP client, bridged to the async `NetStack` via
    /// a `MemoryTun` handle. Models "an app on the host connecting through the
    /// TUN".
    struct Client {
        dev: QueueDevice,
        iface: Interface,
        sockets: SocketSet<'static>,
        handle: SocketHandle,
    }

    impl Client {
        fn connect(src: (u8, u8, u8, u8), local_port: u16, dst: SocketAddr) -> Self {
            let mut dev = QueueDevice::new(1500);
            let mut iface = Interface::new(
                Config::new(HardwareAddress::Ip),
                &mut dev,
                SmolInstant::from_millis(0),
            );
            iface.update_ip_addrs(|a| {
                let _ = a.push(IpCidr::new(IpAddress::v4(src.0, src.1, src.2, src.3), 24));
            });
            let _ = iface
                .routes_mut()
                .add_default_ipv4_route(Ipv4Address::new(src.0, src.1, src.2, 1));
            let mut sockets = SocketSet::new(vec![]);
            let sock = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; 65536]),
                tcp::SocketBuffer::new(vec![0u8; 65536]),
            );
            let handle = sockets.add(sock);
            let remote = match dst.ip() {
                std::net::IpAddr::V4(v4) => {
                    let o = v4.octets();
                    (IpAddress::v4(o[0], o[1], o[2], o[3]), dst.port())
                }
                _ => panic!("ipv4 only in test"),
            };
            let local = (IpAddress::v4(src.0, src.1, src.2, src.3), local_port);
            {
                let s = sockets.get_mut::<tcp::Socket>(handle);
                s.connect(iface.context(), remote, local).unwrap();
            }
            Client {
                dev,
                iface,
                sockets,
                handle,
            }
        }

        fn poll(&mut self) {
            let _ = self.iface.poll(
                SmolInstant::from_millis(0),
                &mut self.dev,
                &mut self.sockets,
            );
        }

        fn socket(&mut self) -> &mut tcp::Socket<'static> {
            self.sockets.get_mut::<tcp::Socket>(self.handle)
        }
    }

    /// Bridge one round of packets between the client and the running netstack,
    /// giving the netstack task time to process.
    async fn pump(client: &mut Client, handle: &mut crate::device::MemoryTunHandle) {
        client.poll();
        while let Some(pkt) = client.dev.pop_tx() {
            let _ = handle.inject(pkt).await;
        }
        // Let the netstack task run and emit replies.
        tokio::time::sleep(tokio::time::Duration::from_millis(3)).await;
        while let Some(pkt) = handle.try_captured() {
            client.dev.push_rx(pkt);
        }
        client.poll();
    }

    /// Pump two clients sharing one netstack, routing each captured reply to the
    /// client whose local port it's addressed to (so the two flows don't cross).
    async fn pump_two(
        a: &mut Client,
        ap: u16,
        b: &mut Client,
        bp: u16,
        handle: &mut crate::device::MemoryTunHandle,
    ) {
        a.poll();
        b.poll();
        while let Some(pkt) = a.dev.pop_tx() {
            let _ = handle.inject(pkt).await;
        }
        while let Some(pkt) = b.dev.pop_tx() {
            let _ = handle.inject(pkt).await;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(3)).await;
        while let Some(pkt) = handle.try_captured() {
            if let Some(p) = crate::flow::parse_packet(&pkt) {
                if p.key.dst.port() == ap {
                    a.dev.push_rx(pkt);
                } else if p.key.dst.port() == bp {
                    b.dev.push_rx(pkt);
                }
            }
        }
        a.poll();
        b.poll();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn parallel_flows_to_same_dst_each_get_a_flow() {
        // The 4-tuple-keying fix: two connections to the SAME dst from distinct
        // source ports must BOTH be terminated (dst-only dedup would RST/collapse
        // the second).
        let (dev, mut handle) = MemoryTun::new(1500, 512);
        let (stack, mut flows) = NetStack::new(dev, NetStackConfig::default());
        tokio::spawn(stack.run());

        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let mut c1 = Client::connect((10, 0, 0, 2), 40000, target);
        let mut c2 = Client::connect((10, 0, 0, 2), 40001, target);

        let mut targets = Vec::new();
        for _ in 0..250 {
            pump_two(&mut c1, 40000, &mut c2, 40001, &mut handle).await;
            while let Ok(Flow::Tcp(f)) = flows.try_recv() {
                targets.push(f.target);
            }
            if targets.len() >= 2 {
                break;
            }
        }
        assert_eq!(
            targets.len(),
            2,
            "both parallel connections to the same dst must each yield a flow"
        );
        assert!(targets.iter().all(|t| *t == target));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn netstack_terminates_tcp_and_pumps_both_directions() {
        let (dev, mut handle) = MemoryTun::new(1500, 256);
        let (stack, mut flows) = NetStack::new(dev, NetStackConfig::default());
        tokio::spawn(stack.run());

        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let mut client = Client::connect((10, 0, 0, 2), 40000, target);

        // Pump until the netstack emits the terminated flow.
        let mut flow = None;
        for _ in 0..200 {
            pump(&mut client, &mut handle).await;
            if let Ok(Flow::Tcp(f)) = flows.try_recv() {
                flow = Some(f);
                break;
            }
        }
        let mut flow = flow.expect("netstack must emit a TcpFlow for the SYN target");
        assert_eq!(flow.target, target, "flow target = the app's dst");

        // client -> app data: the client sends, the flow (caller side) reads it.
        assert!(client.socket().can_send());
        client.socket().send_slice(b"GET / HTTP/1.1\r\n").unwrap();
        let mut got = Vec::new();
        for _ in 0..200 {
            pump(&mut client, &mut handle).await;
            let mut buf = [0u8; 64];
            if let Ok(n) =
                tokio::time::timeout(tokio::time::Duration::from_millis(5), flow.read(&mut buf))
                    .await
            {
                let n = n.unwrap();
                if n > 0 {
                    got.extend_from_slice(&buf[..n]);
                }
            }
            if got == b"GET / HTTP/1.1\r\n" {
                break;
            }
        }
        assert_eq!(
            got, b"GET / HTTP/1.1\r\n",
            "app bytes reached the flow reader"
        );

        // app -> client data: the flow (caller side) writes, the client reads it.
        flow.write_all(b"HTTP/1.1 200 OK\r\n").await.unwrap();
        flow.flush().await.unwrap();
        let mut cgot = Vec::new();
        for _ in 0..200 {
            pump(&mut client, &mut handle).await;
            if client.socket().can_recv() {
                let mut buf = [0u8; 64];
                if let Ok(n) = client.socket().recv_slice(&mut buf) {
                    cgot.extend_from_slice(&buf[..n]);
                }
            }
            if cgot == b"HTTP/1.1 200 OK\r\n" {
                break;
            }
        }
        assert_eq!(cgot, b"HTTP/1.1 200 OK\r\n", "flow writes reached the app");
    }

    /// Drive a smoltcp UDP client through the netstack: send a datagram to a
    /// target, assert a `UdpFlow` surfaces with the app's datagram, then send a
    /// reply back and assert the client receives it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn netstack_terminates_udp_and_pumps_datagrams() {
        let (dev, mut handle) = MemoryTun::new(1500, 256);
        let (stack, mut flows) = NetStack::new(dev, NetStackConfig::default());
        tokio::spawn(stack.run());

        let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let mut cdev = QueueDevice::new(1500);
        let mut ciface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut cdev,
            SmolInstant::from_millis(0),
        );
        ciface.update_ip_addrs(|a| {
            let _ = a.push(IpCidr::new(IpAddress::v4(10, 0, 0, 2), 24));
        });
        let _ = ciface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(10, 0, 0, 1));
        let mut csockets = SocketSet::new(vec![]);
        let csock = udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 8192]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 8192]),
        );
        let ch = csockets.add(csock);
        csockets
            .get_mut::<udp::Socket>(ch)
            .bind(to_ip_endpoint("10.0.0.2:40000".parse().unwrap()))
            .unwrap();

        // Client sends a datagram to the target.
        let _ = ciface.poll(SmolInstant::from_millis(0), &mut cdev, &mut csockets);
        csockets
            .get_mut::<udp::Socket>(ch)
            .send_slice(b"dns-query", to_ip_endpoint(target))
            .unwrap();

        // Pump client -> netstack until the UdpFlow surfaces.
        let mut uflow = None;
        for _ in 0..200 {
            let _ = ciface.poll(SmolInstant::from_millis(0), &mut cdev, &mut csockets);
            while let Some(pkt) = cdev.pop_tx() {
                let _ = handle.inject(pkt).await;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(3)).await;
            while let Some(pkt) = handle.try_captured() {
                cdev.push_rx(pkt);
            }
            let _ = ciface.poll(SmolInstant::from_millis(0), &mut cdev, &mut csockets);
            if let Ok(Flow::Udp(u)) = flows.try_recv() {
                uflow = Some(u);
                break;
            }
        }
        let mut uflow = uflow.expect("netstack must emit a UdpFlow for the datagram target");
        assert_eq!(uflow.target, target);

        // The app's datagram is delivered to the flow.
        let dgram =
            tokio::time::timeout(tokio::time::Duration::from_secs(2), uflow.recv_datagram())
                .await
                .expect("recv within timeout")
                .expect("a datagram");
        assert_eq!(dgram, b"dns-query");

        // Reply: send_datagram -> the client receives it.
        assert!(uflow.send_datagram(b"dns-response".to_vec()).await);
        let mut got = None;
        for _ in 0..200 {
            let _ = ciface.poll(SmolInstant::from_millis(0), &mut cdev, &mut csockets);
            while let Some(pkt) = cdev.pop_tx() {
                let _ = handle.inject(pkt).await;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(3)).await;
            while let Some(pkt) = handle.try_captured() {
                cdev.push_rx(pkt);
            }
            let _ = ciface.poll(SmolInstant::from_millis(0), &mut cdev, &mut csockets);
            let s = csockets.get_mut::<udp::Socket>(ch);
            if s.can_recv() {
                if let Ok((p, _)) = s.recv() {
                    got = Some(p.to_vec());
                    break;
                }
            }
        }
        assert_eq!(got.expect("reply datagram"), b"dns-response");
    }
}
