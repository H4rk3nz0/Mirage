//! The [`TunDevice`] abstraction + an in-memory [`MemoryTun`] for tests.
//!
//! A TUN device carries **raw IP packets** (layer 3, no Ethernet header) - each
//! `recv` yields one IP datagram from the kernel and each `send` writes one back.

use async_trait::async_trait;

/// Errors from a TUN device.
#[derive(Debug, thiserror::Error)]
pub enum TunError {
    /// Underlying device I/O failed.
    #[error("tun io: {0}")]
    Io(#[from] std::io::Error),
    /// The device (or its peer channel) is closed.
    #[error("tun device closed")]
    Closed,
    /// A packet exceeded the device MTU.
    #[error("packet too large: {len} > mtu {mtu}")]
    TooLarge {
        /// Offered packet length.
        len: usize,
        /// Device MTU.
        mtu: usize,
    },
}

/// An OS (or in-memory) TUN device carrying raw IP packets.
///
/// Implementations are single-owner (`&mut self`): the netstack owns the device
/// and drives both directions from one task, so no interior locking is needed.
#[async_trait]
pub trait TunDevice: Send {
    /// Read one IP packet from the device into `buf`; returns its byte length.
    /// Cancel-safe at the task level (the netstack `select!`s on it).
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, TunError>;

    /// Write one IP packet to the device.
    async fn send(&mut self, pkt: &[u8]) -> Result<(), TunError>;

    /// Maximum IP packet size the device accepts (its MTU).
    fn mtu(&self) -> usize;
}

/// Default TUN MTU. 1500 minus a conservative headroom for the Mirage/transport
/// framing overhead so tunneled segments don't fragment on a typical 1500-MTU
/// underlay. (A production deployment may probe and lower this further.)
pub const DEFAULT_TUN_MTU: usize = 1400;

/// In-memory [`TunDevice`] for tests: the netstack reads packets the test
/// **injects** and the test **captures** packets the netstack sends. Backed by
/// bounded tokio channels so backpressure behaves like a real device queue.
pub struct MemoryTun {
    /// Packets flowing INTO the netstack (as if from the kernel / apps).
    inbound: tokio::sync::mpsc::Receiver<Vec<u8>>,
    /// Packets the netstack writes OUT (as if to the kernel / apps).
    outbound: tokio::sync::mpsc::Sender<Vec<u8>>,
    mtu: usize,
}

/// The test-side handle to a [`MemoryTun`]: inject packets in, read packets out.
pub struct MemoryTunHandle {
    /// Push a packet the netstack will `recv` next.
    inject: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// Receive packets the netstack `send`s.
    captured: tokio::sync::mpsc::Receiver<Vec<u8>>,
}

impl MemoryTun {
    /// Create a paired `(device, handle)` with the given MTU and queue depth.
    #[must_use]
    pub fn new(mtu: usize, queue_depth: usize) -> (Self, MemoryTunHandle) {
        let (inject_tx, inbound_rx) = tokio::sync::mpsc::channel(queue_depth);
        let (outbound_tx, captured_rx) = tokio::sync::mpsc::channel(queue_depth);
        (
            MemoryTun {
                inbound: inbound_rx,
                outbound: outbound_tx,
                mtu,
            },
            MemoryTunHandle {
                inject: inject_tx,
                captured: captured_rx,
            },
        )
    }
}

#[async_trait]
impl TunDevice for MemoryTun {
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, TunError> {
        let pkt = self.inbound.recv().await.ok_or(TunError::Closed)?;
        let n = pkt.len().min(buf.len());
        // `n <= min(pkt.len(), buf.len())`, so both slices are in bounds.
        if let (Some(dst), Some(src)) = (buf.get_mut(..n), pkt.get(..n)) {
            dst.copy_from_slice(src);
        }
        Ok(n)
    }

    async fn send(&mut self, pkt: &[u8]) -> Result<(), TunError> {
        if pkt.len() > self.mtu {
            return Err(TunError::TooLarge {
                len: pkt.len(),
                mtu: self.mtu,
            });
        }
        self.outbound
            .send(pkt.to_vec())
            .await
            .map_err(|_| TunError::Closed)
    }

    fn mtu(&self) -> usize {
        self.mtu
    }
}

impl MemoryTunHandle {
    /// Inject a packet the netstack will read via [`TunDevice::recv`].
    pub async fn inject(&self, pkt: Vec<u8>) -> Result<(), TunError> {
        self.inject.send(pkt).await.map_err(|_| TunError::Closed)
    }

    /// Await the next packet the netstack emitted via [`TunDevice::send`].
    pub async fn next_captured(&mut self) -> Option<Vec<u8>> {
        self.captured.recv().await
    }

    /// Non-blocking capture drain (for assertions without awaiting).
    pub fn try_captured(&mut self) -> Option<Vec<u8>> {
        self.captured.try_recv().ok()
    }
}

/// A production [`TunDevice`] driven by in-memory packet channels instead of an
/// OS interface - the integration point for platforms whose VPN API delivers
/// packets by **callback** rather than a file descriptor. Chiefly **iOS**: a
/// `NEPacketTunnelProvider` reads app packets via `packetFlow.readPackets` and
/// writes replies via `packetFlow.writePackets`, and the FFI layer bridges those
/// to this device's channels.
///
/// Direction convention (same as a real TUN):
/// - **inbound** = packets an app wants to send OUT (the host pushes them in;
///   the netstack reads them via [`TunDevice::recv`]).
/// - **outbound** = packets the tunnel produced to deliver back to apps (the
///   netstack writes them via [`TunDevice::send`]; the host drains them).
///
/// Backed by bounded channels so backpressure mimics a real device queue. It
/// contains no `unsafe`; the platform-specific glue (and any `unsafe` FFI) lives
/// in the bindings crate, keeping this crate `#![forbid(unsafe_code)]`.
pub struct ChannelTun {
    inbound: tokio::sync::mpsc::Receiver<Vec<u8>>,
    outbound: tokio::sync::mpsc::Sender<Vec<u8>>,
    mtu: usize,
}

/// Host-side handle to a [`ChannelTun`]: push app packets in, drain tunnel
/// packets out. The `try_*` variants are non-blocking so a synchronous FFI
/// callback (e.g. iOS `packetFlow.readPackets`) can feed the device without an
/// async context.
pub struct ChannelTunHandle {
    inbound: tokio::sync::mpsc::Sender<Vec<u8>>,
    outbound: tokio::sync::mpsc::Receiver<Vec<u8>>,
}

impl ChannelTun {
    /// Create a paired `(device, handle)` with the given MTU and per-direction
    /// queue depth. Hand the `ChannelTun` to the netstack and keep the
    /// `ChannelTunHandle` on the platform bridge.
    #[must_use]
    pub fn new(mtu: usize, queue_depth: usize) -> (Self, ChannelTunHandle) {
        let (in_tx, in_rx) = tokio::sync::mpsc::channel(queue_depth);
        let (out_tx, out_rx) = tokio::sync::mpsc::channel(queue_depth);
        (
            ChannelTun {
                inbound: in_rx,
                outbound: out_tx,
                mtu,
            },
            ChannelTunHandle {
                inbound: in_tx,
                outbound: out_rx,
            },
        )
    }
}

#[async_trait]
impl TunDevice for ChannelTun {
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, TunError> {
        let pkt = self.inbound.recv().await.ok_or(TunError::Closed)?;
        let n = pkt.len().min(buf.len());
        if let (Some(dst), Some(src)) = (buf.get_mut(..n), pkt.get(..n)) {
            dst.copy_from_slice(src);
        }
        Ok(n)
    }

    async fn send(&mut self, pkt: &[u8]) -> Result<(), TunError> {
        if pkt.len() > self.mtu {
            return Err(TunError::TooLarge {
                len: pkt.len(),
                mtu: self.mtu,
            });
        }
        self.outbound
            .send(pkt.to_vec())
            .await
            .map_err(|_| TunError::Closed)
    }

    fn mtu(&self) -> usize {
        self.mtu
    }
}

/// A cloneable sink for pushing inbound (app -> tunnel) packets into a
/// [`ChannelTun`], decoupled from the outbound-drain side of the
/// [`ChannelTunHandle`]. The iOS FFI keeps one of these to feed packets from
/// `packetFlow.readPackets` while a separate task drains outbound packets.
#[derive(Clone)]
pub struct ChannelTunSink(tokio::sync::mpsc::Sender<Vec<u8>>);

impl ChannelTunSink {
    /// Non-blocking push (for a synchronous FFI callback). Returns `true` if
    /// enqueued, `false` if the queue is full (dropped) or the device is gone.
    #[must_use]
    pub fn try_push(&self, pkt: Vec<u8>) -> bool {
        self.0.try_send(pkt).is_ok()
    }

    /// Awaiting push (applies backpressure).
    ///
    /// # Errors
    /// [`TunError::Closed`] if the paired [`ChannelTun`] has been dropped.
    pub async fn push(&self, pkt: Vec<u8>) -> Result<(), TunError> {
        self.0.send(pkt).await.map_err(|_| TunError::Closed)
    }
}

impl ChannelTunHandle {
    /// A cloneable inbound sink, so the push path (FFI callback) and the
    /// outbound-drain path (a task calling [`Self::next_outbound`]) can live in
    /// different tasks or threads.
    #[must_use]
    pub fn inbound_sink(&self) -> ChannelTunSink {
        ChannelTunSink(self.inbound.clone())
    }

    /// Push a packet an app is sending OUT (awaits queue space; the netstack
    /// reads it via [`TunDevice::recv`]). Errors only if the device was dropped.
    ///
    /// # Errors
    /// Returns [`TunError::Closed`] if the paired [`ChannelTun`] has been dropped.
    pub async fn push_inbound(&self, pkt: Vec<u8>) -> Result<(), TunError> {
        self.inbound.send(pkt).await.map_err(|_| TunError::Closed)
    }

    /// Non-blocking [`Self::push_inbound`] for synchronous FFI callbacks.
    /// Returns `true` if the packet was enqueued, `false` if the queue was full
    /// (packet dropped - TCP will retransmit) or the device is gone. A real TUN
    /// device drops on a full queue too, so this is faithful, not lossy-by-bug.
    #[must_use]
    pub fn try_push_inbound(&self, pkt: Vec<u8>) -> bool {
        self.inbound.try_send(pkt).is_ok()
    }

    /// Await the next packet the tunnel produced for delivery to apps (the
    /// netstack wrote it via [`TunDevice::send`]). `None` once the device is gone.
    pub async fn next_outbound(&mut self) -> Option<Vec<u8>> {
        self.outbound.recv().await
    }

    /// Non-blocking drain of the next outbound packet, for a polling FFI bridge.
    #[must_use]
    pub fn try_next_outbound(&mut self) -> Option<Vec<u8>> {
        self.outbound.try_recv().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_tun_roundtrips_inject_and_capture() {
        let (mut dev, mut handle) = MemoryTun::new(DEFAULT_TUN_MTU, 8);

        handle.inject(vec![1, 2, 3, 4]).await.unwrap();
        let mut buf = [0u8; 64];
        let n = dev.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &[1, 2, 3, 4]);

        dev.send(&[9, 8, 7]).await.unwrap();
        assert_eq!(handle.next_captured().await.unwrap(), vec![9, 8, 7]);
    }

    #[tokio::test]
    async fn memory_tun_rejects_oversize() {
        let (mut dev, _h) = MemoryTun::new(4, 8);
        let err = dev.send(&[0u8; 5]).await.unwrap_err();
        assert!(matches!(err, TunError::TooLarge { len: 5, mtu: 4 }));
    }

    #[tokio::test]
    async fn memory_tun_closed_when_handle_dropped() {
        let (mut dev, handle) = MemoryTun::new(64, 8);
        drop(handle);
        assert!(matches!(
            dev.recv(&mut [0u8; 8]).await,
            Err(TunError::Closed)
        ));
    }

    // ChannelTun (the iOS packet-flow device) mirrors the direction semantics of
    // a real TUN: host pushes app-outbound packets IN (netstack recv), netstack
    // sends tunnel-response packets OUT (host drains).
    #[tokio::test]
    async fn channel_tun_roundtrips_both_directions() {
        let (mut dev, mut handle) = ChannelTun::new(DEFAULT_TUN_MTU, 8);

        // App -> tunnel (async push, then netstack recv).
        handle.push_inbound(vec![10, 20, 30]).await.unwrap();
        let mut buf = [0u8; 64];
        let n = dev.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &[10, 20, 30]);

        // Tunnel -> app (netstack send, then host drain).
        dev.send(&[4, 5]).await.unwrap();
        assert_eq!(handle.next_outbound().await.unwrap(), vec![4, 5]);
    }

    #[tokio::test]
    async fn channel_tun_sync_ffi_paths_work() {
        let (mut dev, mut handle) = ChannelTun::new(64, 2);

        // Non-blocking push (the sync FFI callback path) succeeds until full.
        assert!(handle.try_push_inbound(vec![1]));
        assert!(handle.try_push_inbound(vec![2]));
        // Queue depth is 2; the third try is dropped (returns false), faithful
        // to a real device dropping on a full queue.
        assert!(!handle.try_push_inbound(vec![3]));

        let mut buf = [0u8; 8];
        assert_eq!(dev.recv(&mut buf).await.unwrap(), 1);

        dev.send(&[7, 7, 7]).await.unwrap();
        assert_eq!(handle.try_next_outbound(), Some(vec![7, 7, 7]));
        assert_eq!(handle.try_next_outbound(), None);
    }

    #[tokio::test]
    async fn channel_tun_rejects_oversize_and_closes() {
        let (mut dev, handle) = ChannelTun::new(4, 8);
        assert!(matches!(
            dev.send(&[0u8; 5]).await,
            Err(TunError::TooLarge { len: 5, mtu: 4 })
        ));
        drop(handle);
        assert!(matches!(
            dev.recv(&mut [0u8; 8]).await,
            Err(TunError::Closed)
        ));
    }
}
