//! A queue-backed [`smoltcp::phy::Device`] bridging smoltcp's synchronous
//! poll model to the async [`crate::TunDevice`].
//!
//! smoltcp drives I/O by calling `receive`/`transmit` during `Interface::poll`.
//! We can't block on async device I/O inside `poll`, so the netstack task
//! shuttles packets through two in-memory queues:
//!
//! - `rx`: packets read from the TUN, waiting to be consumed by `poll`.
//! - `tx`: packets `poll` produced, waiting to be written to the TUN.
//!
//! The async loop fills `rx` (from `TunDevice::recv`) and drains `tx` (to
//! `TunDevice::send`) around each `poll` call.

use std::collections::VecDeque;

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

/// In-memory packet-queue device handed to `Interface::poll`.
pub(crate) struct QueueDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl QueueDevice {
    pub(crate) fn new(mtu: usize) -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu,
        }
    }

    /// Enqueue a packet read from the TUN for smoltcp to consume next `poll`.
    pub(crate) fn push_rx(&mut self, pkt: Vec<u8>) {
        self.rx.push_back(pkt);
    }

    /// Pop the next packet smoltcp produced (to be written to the TUN).
    pub(crate) fn pop_tx(&mut self) -> Option<Vec<u8>> {
        self.tx.pop_front()
    }

    /// Whether smoltcp has RX packets still queued (drives extra poll passes).
    pub(crate) fn has_rx(&self) -> bool {
        !self.rx.is_empty()
    }
}

/// `RxToken` handing smoltcp one dequeued packet.
pub(crate) struct QueueRxToken(Vec<u8>);

impl RxToken for QueueRxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

/// `TxToken` pushing an emitted packet onto the tx queue.
pub(crate) struct QueueTxToken<'a> {
    tx: &'a mut VecDeque<Vec<u8>>,
}

impl TxToken for QueueTxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.tx.push_back(buf);
        r
    }
}

impl Device for QueueDevice {
    type RxToken<'a> = QueueRxToken;
    type TxToken<'a> = QueueTxToken<'a>;

    fn receive(&mut self, _ts: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((QueueRxToken(pkt), QueueTxToken { tx: &mut self.tx }))
    }

    fn transmit(&mut self, _ts: Instant) -> Option<Self::TxToken<'_>> {
        Some(QueueTxToken { tx: &mut self.tx })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        // TUN = raw IP, no Ethernet header.
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}
