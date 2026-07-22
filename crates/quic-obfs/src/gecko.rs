//! Gecko fragmentation layer.
//!
//! Salamander (XOR) hides the QUIC header structure but leaves the datagram
//! *sizes* intact - QUIC handshake (long-header) datagrams cluster near ~1200 B,
//! which statistical DPI can still flag. Gecko splits each long-header datagram
//! into 2-8 random-sized, randomly-padded fragments (each sent as its own
//! Salamander-wrapped datagram), randomising the packet-size distribution.
//! Short-header (data-phase) datagrams are sent whole.
//!
//! Every plaintext frame (before Salamander XOR) starts with a 1-byte tag:
//! [`TAG_WHOLE`] = an unfragmented datagram follows; [`TAG_FRAGMENT`] = a
//! fragment of a larger datagram follows. The [`Reassembler`] turns received
//! frames back into datagrams.

use std::collections::HashMap;

/// Plaintext frame tag: the remaining bytes are one whole QUIC datagram.
pub const TAG_WHOLE: u8 = 0x00;
/// Plaintext frame tag: the remaining bytes are one fragment of a datagram.
pub const TAG_FRAGMENT: u8 = 0x01;

const MIN_FRAGS: usize = 2;
const MAX_FRAGS: usize = 8;
const MAX_PAD: usize = 256;
/// tag(1) + group(4) + idx(1) + count(1) + chunk_len(2)
const FRAG_HEADER: usize = 9;
/// Datagrams at least this large are eligible for fragmentation.
const FRAGMENT_THRESHOLD: usize = 128;
/// Cap on in-flight partial reassembly groups (evict oldest beyond this).
const MAX_GROUPS: usize = 256;

fn rand_bytes(out: &mut [u8]) {
    getrandom::fill(out).expect("OS CSPRNG");
}

fn rand_u32() -> u32 {
    let mut b = [0u8; 4];
    rand_bytes(&mut b);
    u32::from_be_bytes(b)
}

/// Uniform-ish integer in `[lo, hi]` (inclusive). `hi >= lo` required.
fn rand_range(lo: usize, hi: usize) -> usize {
    if hi <= lo {
        return lo;
    }
    let span = (hi - lo + 1) as u32;
    lo + (rand_u32() % span) as usize
}

/// Is this QUIC datagram a long-header packet (Initial / Handshake / 0-RTT)?
/// QUIC long-header packets set the high bit (0x80) of the first byte; short
/// header (1-RTT data) packets clear it (0x40 fixed bit, 0x80 clear).
pub fn is_long_header(datagram: &[u8]) -> bool {
    datagram.first().is_some_and(|b| b & 0x80 != 0)
}

/// Whether `datagram` should be fragmented (long-header AND large enough).
pub fn should_fragment(datagram: &[u8]) -> bool {
    datagram.len() >= FRAGMENT_THRESHOLD && is_long_header(datagram)
}

/// Wrap a datagram as a single WHOLE plaintext frame (tag + datagram).
pub fn whole(datagram: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(1 + datagram.len());
    f.push(TAG_WHOLE);
    f.extend_from_slice(datagram);
    f
}

/// Split `datagram` into N (2-8) fragment frames with random chunk sizes and
/// random trailing padding. Each returned Vec is a plaintext frame ready to be
/// Salamander-wrapped and sent as its own UDP datagram.
pub fn fragment(datagram: &[u8]) -> Vec<Vec<u8>> {
    let n = rand_range(MIN_FRAGS, MAX_FRAGS.min(datagram.len().max(MIN_FRAGS)));
    let chunks = random_split(datagram, n);
    let group = rand_u32();
    let count = chunks.len() as u8;
    let mut out = Vec::with_capacity(chunks.len());
    for (i, chunk) in chunks.iter().enumerate() {
        let pad = rand_range(0, MAX_PAD);
        let mut f = Vec::with_capacity(FRAG_HEADER + chunk.len() + pad);
        f.push(TAG_FRAGMENT);
        f.extend_from_slice(&group.to_be_bytes());
        f.push(i as u8);
        f.push(count);
        f.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        f.extend_from_slice(chunk);
        if pad > 0 {
            let base = f.len();
            f.resize(base + pad, 0);
            rand_bytes(&mut f[base..]);
        }
        out.push(f);
    }
    out
}

/// Split `data` into `n` contiguous chunks of random (>=1) sizes. Falls back to
/// one chunk if `data` is too small to split.
fn random_split(data: &[u8], n: usize) -> Vec<Vec<u8>> {
    let len = data.len();
    if n <= 1 || len < n {
        return vec![data.to_vec()];
    }
    // Choose n-1 distinct cut points in 1..len.
    let mut cuts: Vec<usize> = Vec::with_capacity(n - 1);
    let mut guard = 0;
    while cuts.len() < n - 1 && guard < n * 8 {
        let c = rand_range(1, len - 1);
        if !cuts.contains(&c) {
            cuts.push(c);
        }
        guard += 1;
    }
    cuts.sort_unstable();
    let mut chunks = Vec::with_capacity(n);
    let mut prev = 0;
    for &c in &cuts {
        chunks.push(data[prev..c].to_vec());
        prev = c;
    }
    chunks.push(data[prev..].to_vec());
    chunks
}

struct Partial {
    count: u8,
    frags: Vec<Option<Vec<u8>>>,
    filled: usize,
    seq: u64,
}

/// Reassembles Gecko fragment frames back into whole datagrams. Evicts the
/// oldest partial groups beyond [`MAX_GROUPS`] so a flood of never-completed
/// groups can't grow memory unboundedly.
#[derive(Default)]
pub struct Reassembler {
    groups: HashMap<u32, Partial>,
    seq: u64,
}

impl Reassembler {
    /// New empty reassembler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one de-salamandered plaintext frame. Returns `Some(datagram)` when a
    /// whole datagram is available (immediately for [`TAG_WHOLE`], or when a
    /// fragment completes its group). Returns `None` for a partial group or a
    /// malformed frame.
    pub fn accept(&mut self, frame: &[u8]) -> Option<Vec<u8>> {
        match frame.first().copied()? {
            TAG_WHOLE => Some(frame.get(1..)?.to_vec()),
            TAG_FRAGMENT => self.accept_fragment(frame),
            _ => None,
        }
    }

    fn accept_fragment(&mut self, frame: &[u8]) -> Option<Vec<u8>> {
        if frame.len() < FRAG_HEADER {
            return None;
        }
        let group = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]);
        let idx = frame[5] as usize;
        let count = frame[6];
        let chunk_len = u16::from_be_bytes([frame[7], frame[8]]) as usize;
        if count == 0 || idx >= count as usize {
            return None;
        }
        let chunk = frame.get(FRAG_HEADER..FRAG_HEADER + chunk_len)?;

        self.seq += 1;
        let seq = self.seq;
        let entry = self.groups.entry(group).or_insert_with(|| Partial {
            count,
            frags: vec![None; count as usize],
            filled: 0,
            seq,
        });
        // A group_id collision with a different count => treat as fresh.
        if entry.count != count {
            *entry = Partial {
                count,
                frags: vec![None; count as usize],
                filled: 0,
                seq,
            };
        }
        if entry.frags[idx].is_none() {
            entry.frags[idx] = Some(chunk.to_vec());
            entry.filled += 1;
        }
        if entry.filled == count as usize {
            let done = self.groups.remove(&group)?;
            let mut datagram = Vec::new();
            for part in done.frags {
                datagram.extend_from_slice(&part?);
            }
            return Some(datagram);
        }
        self.evict_if_needed();
        None
    }

    fn evict_if_needed(&mut self) {
        if self.groups.len() <= MAX_GROUPS {
            return;
        }
        if let Some((&oldest, _)) = self.groups.iter().min_by_key(|(_, p)| p.seq) {
            self.groups.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_header_detection() {
        assert!(is_long_header(&[0xC0, 0x00])); // long header (Initial)
        assert!(is_long_header(&[0xE0])); // long header
        assert!(!is_long_header(&[0x40, 0x00])); // short header (1-RTT)
        assert!(!is_long_header(&[]));
    }

    #[test]
    fn whole_roundtrips() {
        let mut r = Reassembler::new();
        let dg = b"a short-header data packet".to_vec();
        let frame = whole(&dg);
        assert_eq!(r.accept(&frame), Some(dg));
    }

    #[test]
    fn fragment_reassembles_in_order() {
        let dg: Vec<u8> = (0..1200u32).map(|i| (i % 256) as u8).collect();
        let frags = fragment(&dg);
        assert!(frags.len() >= MIN_FRAGS && frags.len() <= MAX_FRAGS);
        // Fragment sizes vary (padding + random splits) - the whole point.
        let mut r = Reassembler::new();
        let mut recovered = None;
        for f in &frags {
            if let Some(d) = r.accept(f) {
                recovered = Some(d);
            }
        }
        assert_eq!(recovered, Some(dg));
    }

    #[test]
    fn fragment_reassembles_out_of_order() {
        let dg: Vec<u8> = (0..900u32).map(|i| (i * 7 % 256) as u8).collect();
        let mut frags = fragment(&dg);
        frags.reverse(); // deliver in reverse order
        let mut r = Reassembler::new();
        let mut recovered = None;
        for f in &frags {
            if let Some(d) = r.accept(f) {
                recovered = Some(d);
            }
        }
        assert_eq!(recovered, Some(dg));
    }

    #[test]
    fn incomplete_group_yields_nothing() {
        let dg: Vec<u8> = vec![0x33; 800];
        let frags = fragment(&dg);
        let mut r = Reassembler::new();
        // Drop the last fragment - never completes.
        for f in &frags[..frags.len() - 1] {
            assert_eq!(r.accept(f), None);
        }
    }

    #[test]
    fn two_interleaved_datagrams_reassemble() {
        let d1: Vec<u8> = (0..600u32).map(|i| i as u8).collect();
        let d2: Vec<u8> = (0..700u32).map(|i| (i + 1) as u8).collect();
        let f1 = fragment(&d1);
        let f2 = fragment(&d2);
        let mut r = Reassembler::new();
        let (mut r1, mut r2) = (None, None);
        // Interleave the two fragment streams.
        let maxn = f1.len().max(f2.len());
        for i in 0..maxn {
            if let Some(f) = f1.get(i) {
                if let Some(d) = r.accept(f) {
                    r1 = Some(d);
                }
            }
            if let Some(f) = f2.get(i) {
                if let Some(d) = r.accept(f) {
                    r2 = Some(d);
                }
            }
        }
        assert_eq!(r1, Some(d1));
        assert_eq!(r2, Some(d2));
    }
}
