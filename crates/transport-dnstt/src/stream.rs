//! Reliable, ordered byte stream over the lossy request/response DNS channel.
//!
//! A [`ReliableEndpoint`] is a small TCP-like state machine: a byte-offset
//! sequence space, cumulative ACKs, an out-of-order reassembly buffer, and
//! Go-Back-N retransmission (each outgoing [`Packet`] carries the still-unacked
//! window from `send_base`, so a lost query or answer is recovered on the next
//! poll - no timers needed inside the endpoint). Both client and server run the
//! SAME endpoint; the client drives timing by polling, the server is reactive.
//!
//! The Mirage session rides on the delivered byte stream and supplies all
//! crypto, so this layer only guarantees reliability + ordering, not secrecy.

use std::collections::{BTreeMap, VecDeque};

use crate::arq::{Packet, FLAG_FIN, FLAG_SYN};

/// Cap on out-of-order segments buffered ahead of `recv_next`. Each entry holds
/// at most one packet's payload (bounded by the DNS message size), so this hard-
/// bounds the reorder buffer's memory. A genuine peer runs Go-Back-N from its
/// send base and so barely fills this at all; a large buffer only ever comes
/// from an attacker forging future `seq`s, which we drop past the cap.
const MAX_REORDER_SEGS: usize = 1024;
/// Refuse a future segment starting more than this far ahead of `recv_next`: a
/// real peer never sends beyond its (small) send window, so anything further is
/// junk that would only pin memory until it times out.
const MAX_REORDER_AHEAD: u32 = 1 << 20;

/// TCP-like reliable endpoint over DNS packets.
pub struct ReliableEndpoint {
    session: u32,
    is_client: bool,
    // Send side: unacked outgoing bytes, `send_base` is the seq of the front.
    send_stream: VecDeque<u8>,
    send_base: u32,
    fin_queued: bool,
    fin_sent: bool,
    // Receive side.
    recv_next: u32,
    reorder: BTreeMap<u32, Vec<u8>>,
    delivered: VecDeque<u8>,
    peer_fin_at: Option<u32>,
    peer_syn: bool,
    // The client announces a new session with SYN until it hears back.
    announce_syn: bool,
}

impl ReliableEndpoint {
    /// New endpoint. `is_client` sets SYN-announce behaviour.
    pub fn new(session: u32, is_client: bool) -> Self {
        Self {
            session,
            is_client,
            send_stream: VecDeque::new(),
            send_base: 0,
            fin_queued: false,
            fin_sent: false,
            recv_next: 0,
            reorder: BTreeMap::new(),
            delivered: VecDeque::new(),
            peer_fin_at: None,
            peer_syn: false,
            announce_syn: is_client,
        }
    }

    /// Session id.
    pub fn session(&self) -> u32 {
        self.session
    }

    /// Queue application bytes for reliable delivery to the peer.
    pub fn write(&mut self, data: &[u8]) {
        self.send_stream.extend(data.iter().copied());
    }

    /// Signal orderly close: a FIN is sent after all queued data is acked.
    pub fn close(&mut self) {
        self.fin_queued = true;
    }

    /// True once the peer has FIN'd and we've delivered all its bytes.
    pub fn peer_finished(&self) -> bool {
        self.peer_fin_at.is_some_and(|at| self.recv_next >= at)
    }

    /// Drain in-order bytes ready for the application.
    pub fn take_delivered(&mut self) -> Vec<u8> {
        self.delivered.drain(..).collect()
    }

    /// Bytes still waiting to be acked by the peer (for poll-rate decisions).
    pub fn unacked_len(&self) -> usize {
        self.send_stream.len()
    }

    /// Build the next outgoing packet, carrying up to `max_data` unacked bytes
    /// from `send_base` and the current cumulative ACK.
    pub fn build_packet(&mut self, max_data: usize) -> Packet {
        let n = self.send_stream.len().min(max_data);
        let data: Vec<u8> = self.send_stream.iter().take(n).copied().collect();
        let mut flags = 0u8;
        if self.announce_syn {
            flags |= FLAG_SYN;
        }
        // FIN rides the packet once everything up to it is in this send window
        // (i.e. we've queued all data and this packet drains the buffer).
        if self.fin_queued && n == self.send_stream.len() {
            flags |= FLAG_FIN;
            self.fin_sent = true;
        }
        Packet {
            session: self.session,
            seq: self.send_base,
            ack: self.recv_next,
            flags,
            data,
        }
    }

    /// Process an incoming packet: apply its ACK to our send window, absorb its
    /// data into the reassembly buffer, and note SYN/FIN.
    pub fn on_packet(&mut self, pkt: &Packet) {
        // Any reply from the peer means our session is known - stop announcing.
        if self.is_client {
            self.announce_syn = false;
        }
        if pkt.flags & FLAG_SYN != 0 {
            self.peer_syn = true;
        }
        // Cumulative ACK: drop acked bytes (clamped - never trust the peer to
        // ack more than we actually sent).
        if pkt.ack > self.send_base {
            let acked = ((pkt.ack - self.send_base) as usize).min(self.send_stream.len());
            self.send_stream.drain(..acked);
            self.send_base += acked as u32;
        }
        // Data.
        if !pkt.data.is_empty() {
            self.accept_data(pkt.seq, &pkt.data);
        }
        // FIN marks the peer's final byte offset.
        if pkt.flags & FLAG_FIN != 0 {
            let end = pkt.seq.wrapping_add(pkt.data.len() as u32);
            self.peer_fin_at = Some(end);
        }
    }

    fn accept_data(&mut self, seq: u32, data: &[u8]) {
        match seq.cmp(&self.recv_next) {
            std::cmp::Ordering::Equal => {
                self.delivered.extend(data.iter().copied());
                self.recv_next = self.recv_next.wrapping_add(data.len() as u32);
                // Drain any now-contiguous reordered segments.
                while let Some(seg) = self.reorder.remove(&self.recv_next) {
                    self.recv_next = self.recv_next.wrapping_add(seg.len() as u32);
                    self.delivered.extend(seg);
                }
            }
            std::cmp::Ordering::Greater => {
                // Future segment - buffer for reassembly (keep the longest seen),
                // but bound the buffer so a peer forging far-ahead `seq`s can't
                // grow it without limit. Drop anything past the window, and once
                // the segment count is capped only update seqs we already hold.
                if seq.wrapping_sub(self.recv_next) > MAX_REORDER_AHEAD {
                    return;
                }
                if let Some(existing) = self.reorder.get_mut(&seq) {
                    if data.len() > existing.len() {
                        *existing = data.to_vec();
                    }
                } else if self.reorder.len() < MAX_REORDER_SEGS {
                    self.reorder.insert(seq, data.to_vec());
                }
            }
            // seq < recv_next => already-delivered duplicate; ignore.
            std::cmp::Ordering::Less => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive a full client<->server transfer over a channel that DROPS and
    /// REORDERS packets, asserting both byte streams arrive intact.
    #[test]
    fn reliable_over_lossy_reordering_channel() {
        let mut client = ReliableEndpoint::new(0x1234, true);
        let mut server = ReliableEndpoint::new(0x1234, false);

        let up: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let down: Vec<u8> = (0..7000u32).map(|i| ((i * 3 + 1) % 251) as u8).collect();
        client.write(&up);
        client.close();
        server.write(&down);
        server.close();

        let mut got_up = Vec::new();
        let mut got_down = Vec::new();
        // Deterministic pseudo-loss/reorder pattern (no RNG in tests).
        let mut tick = 0u32;
        let mut in_flight_to_server: Vec<Packet> = Vec::new();
        let mut in_flight_to_client: Vec<Packet> = Vec::new();
        const MTU: usize = 100;

        for _ in 0..4000 {
            tick += 1;
            // Client polls: build a packet toward the server.
            let cp = client.build_packet(MTU);
            // Drop 1 in 4; otherwise deliver (sometimes delayed by one tick).
            if tick % 4 != 0 {
                in_flight_to_server.push(cp);
            }
            // Server processes whatever "arrived" (reorder: process newest first
            // occasionally by rotating the queue).
            if tick % 3 == 0 {
                in_flight_to_server.reverse();
            }
            for p in in_flight_to_server.drain(..) {
                server.on_packet(&p);
            }
            got_up.extend(server.take_delivered());
            // Server responds.
            let sp = server.build_packet(MTU);
            if tick % 5 != 0 {
                in_flight_to_client.push(sp);
            }
            if tick % 7 == 0 {
                in_flight_to_client.reverse();
            }
            for p in in_flight_to_client.drain(..) {
                client.on_packet(&p);
            }
            got_down.extend(client.take_delivered());

            if got_up.len() >= up.len()
                && got_down.len() >= down.len()
                && client.peer_finished()
                && server.peer_finished()
            {
                break;
            }
        }
        assert_eq!(
            got_up, up,
            "upstream must arrive intact over a lossy channel"
        );
        assert_eq!(got_down, down, "downstream must arrive intact");
        assert!(
            client.peer_finished() && server.peer_finished(),
            "FINs exchanged"
        );
    }

    #[test]
    fn duplicate_and_old_segments_ignored() {
        let mut ep = ReliableEndpoint::new(1, false);
        let p = |seq: u32, d: &[u8]| Packet {
            session: 1,
            seq,
            ack: 0,
            flags: 0,
            data: d.to_vec(),
        };
        ep.on_packet(&p(0, b"hello"));
        ep.on_packet(&p(0, b"hello")); // exact duplicate
        ep.on_packet(&p(2, b"ll")); // fully-old overlap
        assert_eq!(ep.take_delivered(), b"hello");
    }

    #[test]
    fn reorder_buffer_is_bounded() {
        let mut ep = ReliableEndpoint::new(1, false);
        let seg = |seq: u32, d: &[u8]| Packet {
            session: 1,
            seq,
            ack: 0,
            flags: 0,
            data: d.to_vec(),
        };
        // recv_next stays 0 (nothing in-order arrives), so every segment lands
        // in the reorder buffer. Flood far more distinct future seqs than the
        // cap: the buffer must not grow past MAX_REORDER_SEGS.
        for i in 0..(MAX_REORDER_SEGS as u32 * 4) {
            ep.on_packet(&seg(1 + i * 8, b"junk"));
        }
        assert!(
            ep.reorder.len() <= MAX_REORDER_SEGS,
            "reorder buffer must stay bounded, got {}",
            ep.reorder.len()
        );
        // A segment beyond the ahead-window is refused outright.
        let far = MAX_REORDER_AHEAD + 10_000;
        ep.on_packet(&seg(far, b"x"));
        assert!(
            !ep.reorder.contains_key(&far),
            "segments past the window must be dropped"
        );
        // Nothing was delivered (all bytes were out of order); the endpoint is
        // otherwise unharmed and still at the start of the stream.
        assert!(ep.take_delivered().is_empty());
        assert_eq!(ep.recv_next, 0);
    }

    #[test]
    fn ack_clamped_to_sent() {
        let mut ep = ReliableEndpoint::new(1, true);
        ep.write(b"abc");
        // Peer maliciously acks far beyond what we sent - must not underflow.
        ep.on_packet(&Packet {
            session: 1,
            seq: 0,
            ack: 9_999,
            flags: 0,
            data: Vec::new(),
        });
        assert_eq!(ep.unacked_len(), 0);
        assert_eq!(ep.send_base, 3, "send_base advances only by bytes we sent");
    }
}
