//! ARQ packet format for the DNS tunnel + name packing.
//!
//! The DNS channel is request/response, lossy, and reordering, with tiny MTUs.
//! On top of it we run a sequence-numbered, cumulatively-ACK'd reliable stream
//! (see [`stream`](crate::stream)). This module defines the on-wire **packet**
//! that both directions exchange, plus the base32 packing that turns an
//! upstream packet into a DNS query name under the tunnel domain.
//!
//! Packet header (big-endian): `session(4) seq(4) ack(4) flags(1)` then data.
//! - `session` - per-client id so the stateless server can demultiplex.
//! - `seq`     - sender's next byte-stream offset for `data`.
//! - `ack`     - highest contiguous byte offset the sender has received.
//! - `flags`   - SYN (open) / FIN (close).

use crate::dns::{base32_decode, base32_encode};

/// Connection-open flag.
pub const FLAG_SYN: u8 = 0x01;
/// Connection-close flag.
pub const FLAG_FIN: u8 = 0x02;

/// Fixed packet header length.
pub const HEADER_LEN: usize = 13;

/// Per-packet random nonce prepended to every wire packet. The 13-byte plaintext
/// header (session/seq/ack/flags) is otherwise low-entropy - at SYN/keepalive
/// `seq == ack == 0` gives a long run of zero bytes, which base32-encodes to a
/// run of `a`s: a zero-false-positive passive signature no real DNS query has.
/// We whiten the header with `BLAKE3(nonce)` so the on-wire bytes are uniformly
/// random. The nonce is public, so this defeats the STATISTICAL classifier (the
/// realistic DPI threat for a last-resort DNS carrier); a Mirage-aware censor
/// with the scheme could still de-whiten - a per-tunnel PSK would be needed to
/// stop that, which dnstt does not currently carry.
pub const HEADER_NONCE_LEN: usize = 3;

/// Derive the 13-byte header keystream from the packet nonce.
fn header_keystream(nonce: &[u8; HEADER_NONCE_LEN]) -> [u8; HEADER_LEN] {
    let mut h = mirage_crypto::blake3::Hasher::new();
    h.update(b"mirage-dnstt-hdr-v1");
    h.update(nonce);
    let mut out = [0u8; HEADER_LEN];
    let digest = h.finalize();
    out.copy_from_slice(&digest.as_bytes()[..HEADER_LEN]);
    out
}

/// A reliable-stream packet exchanged in one DNS query or response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// Per-client session id (server demux key).
    pub session: u32,
    /// Sender's byte-stream offset of the first `data` byte.
    pub seq: u32,
    /// Highest contiguous byte offset the sender has received from the peer.
    pub ack: u32,
    /// SYN / FIN flags.
    pub flags: u8,
    /// Payload bytes (may be empty - an empty upstream packet is a poll).
    pub data: Vec<u8>,
}

impl Packet {
    /// Serialize to raw bytes (used verbatim for downstream TXT payloads).
    pub fn encode(&self) -> Vec<u8> {
        // Random per-packet nonce (breaks the fixed base32 run at handshake time).
        let mut nonce = [0u8; HEADER_NONCE_LEN];
        // A failed CSPRNG must not send a predictable-nonce packet: fall back to a
        // best-effort seed from the mutable header so at least seq/ack vary it.
        if getrandom::fill(&mut nonce).is_err() {
            let s = self.seq ^ self.ack ^ self.session;
            nonce.copy_from_slice(&s.to_be_bytes()[..HEADER_NONCE_LEN]);
        }
        let ks = header_keystream(&nonce);

        // Plaintext 13-byte header, then XOR with the keystream.
        let mut hdr = [0u8; HEADER_LEN];
        hdr[0..4].copy_from_slice(&self.session.to_be_bytes());
        hdr[4..8].copy_from_slice(&self.seq.to_be_bytes());
        hdr[8..12].copy_from_slice(&self.ack.to_be_bytes());
        hdr[12] = self.flags;
        for (b, k) in hdr.iter_mut().zip(ks.iter()) {
            *b ^= *k;
        }

        let mut out = Vec::with_capacity(HEADER_NONCE_LEN + HEADER_LEN + self.data.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&hdr);
        // `data` carries the already-encrypted Mirage session bytes (high entropy).
        out.extend_from_slice(&self.data);
        out
    }

    /// Parse from raw bytes. Returns `None` if shorter than the header.
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < HEADER_NONCE_LEN + HEADER_LEN {
            return None;
        }
        let mut nonce = [0u8; HEADER_NONCE_LEN];
        nonce.copy_from_slice(&buf[..HEADER_NONCE_LEN]);
        let ks = header_keystream(&nonce);
        // De-whiten the 13-byte header.
        let mut hdr = [0u8; HEADER_LEN];
        for i in 0..HEADER_LEN {
            hdr[i] = buf[HEADER_NONCE_LEN + i] ^ ks[i];
        }
        let g4 = |i: usize| u32::from_be_bytes([hdr[i], hdr[i + 1], hdr[i + 2], hdr[i + 3]]);
        Some(Self {
            session: g4(0),
            seq: g4(4),
            ack: g4(8),
            flags: hdr[12],
            data: buf[HEADER_NONCE_LEN + HEADER_LEN..].to_vec(),
        })
    }

    /// Pack an upstream packet into a DNS query name under `tunnel_domain`:
    /// `base32(packet)` split into <=63-char labels, then the domain. Returns
    /// `None` if the resulting name would exceed the 255-byte DNS limit (caller
    /// must send less `data`).
    pub fn to_query_name(&self, tunnel_domain: &str) -> Option<String> {
        let b32 = base32_encode(&self.encode());
        let mut name = String::with_capacity(b32.len() + 1 + tunnel_domain.len() + 4);
        // Split the base32 blob into <=63-char labels.
        let bytes = b32.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let end = (i + 63).min(bytes.len());
            // SAFETY: base32 output is ASCII.
            name.push_str(std::str::from_utf8(&bytes[i..end]).ok()?);
            name.push('.');
            i = end;
        }
        name.push_str(tunnel_domain.trim_start_matches('.'));
        // Wire length ~ each label +1 length octet, +1 root. Approximate check.
        if name.len() + 2 > 253 {
            return None;
        }
        Some(name)
    }

    /// Recover an upstream packet from a query name (server side): strip the
    /// tunnel domain suffix, concat the data labels, base32-decode, then
    /// [`Packet::decode`].
    pub fn from_query_name(qname: &str, tunnel_domain: &str) -> Option<Self> {
        let q = qname.to_ascii_lowercase();
        let dom = tunnel_domain.trim_start_matches('.').to_ascii_lowercase();
        let prefix = q.strip_suffix(&dom)?.trim_end_matches('.');
        let b32: String = prefix.split('.').filter(|l| !l.is_empty()).collect();
        let raw = base32_decode(&b32)?;
        Packet::decode(&raw)
    }
}

/// Largest `data` payload that fits in an upstream query packet for
/// `tunnel_domain` (leaving room for the 13-byte header + base32 expansion +
/// labels + domain within the 253-byte name limit). Conservative.
pub fn max_upstream_data(tunnel_domain: &str) -> usize {
    let dom = tunnel_domain.trim_start_matches('.').len();
    // Available name chars for base32 (minus domain, dots, root headroom).
    let avail = 253usize.saturating_sub(dom + 8);
    // Each label of 63 chars costs one extra length octet; approximate by *63/64.
    let b32_chars = avail * 63 / 64;
    // base32: 8 chars per 5 bytes => raw = chars * 5 / 8.
    let raw = b32_chars * 5 / 8;
    raw.saturating_sub(HEADER_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_encode_decode() {
        let p = Packet {
            session: 0xDEAD_BEEF,
            seq: 1000,
            ack: 42,
            flags: FLAG_SYN,
            data: b"hello dns tunnel".to_vec(),
        };
        assert_eq!(Packet::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn empty_poll_packet() {
        let p = Packet {
            session: 7,
            seq: 5,
            ack: 5,
            flags: 0,
            data: Vec::new(),
        };
        let d = Packet::decode(&p.encode()).unwrap();
        assert_eq!(d, p);
        assert!(d.data.is_empty());
    }

    #[test]
    fn query_name_roundtrip() {
        let dom = "t.example.com";
        let n = max_upstream_data(dom);
        assert!(n >= 60, "expected a usable upstream MTU, got {n}");
        let p = Packet {
            session: 0x1122_3344,
            seq: 99,
            ack: 7,
            flags: 0,
            data: (0..n as u32).map(|i| (i % 251) as u8).collect(),
        };
        let name = p.to_query_name(dom).unwrap();
        assert!(name.ends_with(dom), "name must be under the tunnel domain");
        assert!(name.split('.').all(|l| l.len() <= 63), "labels <=63");
        let recovered = Packet::from_query_name(&name, dom).unwrap();
        assert_eq!(recovered, p);
    }

    #[test]
    fn query_name_rejects_wrong_domain() {
        let p = Packet {
            session: 1,
            seq: 0,
            ack: 0,
            flags: 0,
            data: b"x".to_vec(),
        };
        let name = p.to_query_name("t.example.com").unwrap();
        assert!(Packet::from_query_name(&name, "other.domain").is_none());
    }

    #[test]
    fn oversized_upstream_data_rejected() {
        let p = Packet {
            session: 1,
            seq: 0,
            ack: 0,
            flags: 0,
            data: vec![0u8; 4096],
        };
        assert!(
            p.to_query_name("t.example.com").is_none(),
            "a 4 KiB payload cannot fit in a DNS name"
        );
    }
}
