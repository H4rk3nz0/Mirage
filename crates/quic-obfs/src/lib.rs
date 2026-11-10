//! QUIC packet obfuscation for Mirage's QUIC carriers (hysteria2 + h3).
//!
//! # Why
//!
//! Mirage's QUIC carriers use `quinn` + `rustls` defaults, so their QUIC Initial
//! ClientHello, transport parameters, version, and connection IDs form a
//! **non-browser QUIC fingerprint** a state DPI can match - and the raw QUIC
//! long-header structure is visible on the wire. This crate hides it.
//!
//! # Salamander (implemented here)
//!
//! Each outgoing UDP datagram is prefixed with a random `SALT_LEN`-byte salt and
//! XORed with a keyed-BLAKE3 keystream derived from `(key, salt)`. On the wire
//! every datagram is indistinguishable from random bytes - no QUIC header, no
//! version, no fingerprint. Both peers derive the same `key` from a shared obfs
//! password, so the receiver de-obfuscates before handing the datagram to quinn.
//! This is the same idea as Hysteria2's "Salamander" obfuscation.
//!
//! # Gecko (fragmentation - [`gecko`] layer)
//!
//! Salamander alone leaves the QUIC handshake datagrams clustered near ~1200 B,
//! which statistical DPI can still flag. The [`gecko`] layer fragments large
//! (long-header) datagrams into 2-8 random-sized, randomly-padded pieces - each
//! its own Salamander-wrapped datagram - randomising the packet-size
//! distribution. Short-header (data-phase) packets pass through unfragmented.
//!
//! # Usage
//!
//! [`client_endpoint`] / [`server_endpoint`] build a `quinn::Endpoint` whose UDP
//! socket is wrapped in the obfuscator. The transports call these instead of
//! `quinn::Endpoint::client` / `::server` when an obfs password is configured.

#![forbid(unsafe_code)]
// Byte-level packet framing with explicit length checks throughout; indexing is
// intentional and guarded. Docs reference many protocol terms (QUIC, GSO/GRO,
// ClientHello, Salamander) that would otherwise trip doc_markdown.
#![allow(clippy::indexing_slicing, clippy::doc_markdown)]

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use quinn::udp::RecvMeta;
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::io::ReadBuf;

pub mod gecko;
pub mod h3_probe;
pub mod wu;

/// Random salt prepended to every obfuscated datagram.
pub const SALT_LEN: usize = 8;

/// Largest UDP datagram we will receive + de-obfuscate. QUIC keeps datagrams
/// well under this; the extra headroom covers the salt + any Gecko framing.
const RECV_BUF: usize = 2048;

/// How many undersized cover tokens may be spent looking for one large enough to
/// hold a datagram. Bounded so a pathological cover (every token tiny) degrades to
/// sending unpadded rather than burning bandwidth without end.
const MAX_COVER_SKIP: usize = 8;

/// Smallest cover record able to hold a HANDSHAKE datagram.
///
/// QUIC's 1200-byte floor (`MIN_INITIAL_SIZE`) applies ONLY to datagrams carrying
/// an Initial packet - quinn enforces it when parsing one, not on every datagram.
/// After the handshake there is no floor at all: an ACK-only datagram runs about
/// fifty bytes. So a cover full of small records is NOT useless for shaping, as an
/// earlier version of this assumed - it shapes the small datagrams that dominate a
/// client's upstream perfectly well, and only oversized ones cannot be padded into
/// it. Filtering records against this constant would discard the useful majority
/// to guard against the minority; the per-datagram fit check does the right thing
/// instead.
pub const QUIC_MIN_HANDSHAKE_RECORD: u16 = 1200 + 3 + SALT_LEN as u16;

/// Datagram-layer shaping for a QUIC carrier.
///
/// # Why this shape and not a full pacer
///
/// On a TCP carrier the kernel owns the packet layer, so record-level shaping
/// cannot reach acknowledgements or segmentation - measured as the residual that
/// survives every record-level fix. QUIC hands that layer back: every datagram,
/// acknowledgements included, passes through this socket.
///
/// The obvious move - queue real datagrams and release them on a schedule - feeds
/// straight back into quinn's loss detection and congestion control, where a
/// delayed acknowledgement becomes a spurious retransmission and ADDS traffic,
/// i.e. a new leak. So this deliberately shapes only the two things that cost
/// nothing to control:
///
/// - **Size**: every datagram is padded up to the next size the cover calls for,
///   so the on-wire size distribution is the cover's rather than the payload's.
///   Padding only ever grows a datagram, never delays or splits one.
/// - **Idle**: when the connection has nothing to send, cover datagrams keep the
///   flow alive at the cover's cadence, so an idle tunnel does not go silent.
///
/// Real datagrams are never held back, so quinn's timing, RTT estimate and
/// congestion window are untouched. That leaves the timing of genuinely busy
/// periods unshaped - an honest limitation, and the reason this is a first
/// increment rather than the finished article.
#[derive(Clone, Debug)]
pub struct QuicShape {
    /// The cover's record sequence: `(wire size, gap before this record)`.
    ///
    /// Both fields come from one real capture and are replayed together, because
    /// they are one measurement. Real traffic is BURSTY - on a browse capture 43%
    /// of gaps are under a millisecond, with bursts up to 22 records, punctuated
    /// by pauses out to 286 ms - so a single scalar cadence reproduces neither the
    /// arrangement nor the average rate. (Using the MEDIAN gap as a tick is
    /// especially wrong: it is small precisely BECAUSE most gaps sit inside
    /// bursts, so it turns a 60 record/s capture into a 1000 datagram/s
    /// metronome.) Replaying the sequence gets the grouping for free, and it stays
    /// replay rather than synthesis - injected structure would be its own
    /// fingerprint.
    pub tokens: Vec<(u16, std::time::Duration)>,
}

impl QuicShape {
    /// Largest datagram this shape will pad up to, so a caller can reserve the
    /// matching path-MTU headroom.
    #[must_use]
    pub fn max_size(&self) -> u16 {
        self.tokens.iter().map(|&(sz, _)| sz).max().unwrap_or(0)
    }

    /// Mean inter-record gap: the cover's actual average rate, and what an idle
    /// tunnel will cost per record.
    #[must_use]
    pub fn mean_gap(&self) -> std::time::Duration {
        if self.tokens.is_empty() {
            return std::time::Duration::from_millis(20);
        }
        let total: std::time::Duration = self.tokens.iter().map(|&(_, g)| g).sum();
        total / self.tokens.len() as u32
    }
}

/// Worst-case bytes this crate adds to a quinn datagram on the wire:
/// [`SALT_LEN`] + the 1-byte Gecko frame tag + the largest Wu-2023 preamble
/// (`1 + MAX_PRE`).
///
/// quinn cannot see this inflation - it sizes datagrams (and its MTU-discovery
/// probes) against the path MTU as if the socket were transparent. A CONSTANT
/// overhead is self-correcting, because probes are inflated by the same amount
/// as data. A VARIABLE one is not: a probe that happens to draw a short
/// preamble succeeds and raises the MTU, then a data packet that draws a long
/// one exceeds the path MTU and is dropped - loss that quinn misattributes to
/// congestion. Callers that enable the preamble MUST reserve this much headroom
/// (see [`mtu_upper_bound_with_overhead`]).
pub const WU_MAX_WIRE_OVERHEAD: u16 =
    SALT_LEN as u16 + 1 + 1 + mirage_common::wu_preamble::MAX_PRE as u16;

/// quinn's default MTU-discovery ceiling (`MtuDiscoveryConfig::upper_bound`),
/// which already embeds its own tunnel safety margin below the 1500 B Ethernet
/// MTU.
pub const QUINN_DEFAULT_MTU_UPPER_BOUND: u16 = 1452;

/// The MTU-discovery ceiling to give quinn so that even a worst-case obfuscated
/// datagram still fits the path MTU quinn's own default targets.
///
/// Without this, a full-size datagram under the preamble reaches
/// `1452 + WU_MAX_WIRE_OVERHEAD` bytes on the wire, over the Ethernet MTU.
#[must_use]
pub fn mtu_upper_bound_with_overhead() -> u16 {
    QUINN_DEFAULT_MTU_UPPER_BOUND.saturating_sub(WU_MAX_WIRE_OVERHEAD)
}

/// Derive the 32-byte obfuscation key from a shared password. Both peers must
/// use the same password (out-of-band / from the invite), exactly like
/// Hysteria2's `obfs.password`.
pub fn key_from_password(password: &[u8]) -> [u8; 32] {
    *blake3::hash(password).as_bytes()
}

/// Derive a per-bridge DEFAULT obfuscation key from the bridge's X25519 static
/// public key. Used when no explicit `quic_obfs_password` is configured so that
/// hysteria2 / h3 obfuscate BY DEFAULT and never put a parseable QUIC handshake
/// on the wire. Client and bridge derive the same key from public material both
/// already hold (the invite carries the bridge pubkey), exactly like the
/// per-bridge cover-SNI derivation (F9-L).
///
/// This defeats generic QUIC-classifying / protocol-fingerprinting DPI. It is
/// NOT a secret against an adversary who already knows the bridge's public key
/// (e.g. holds the invite); set `quic_obfs_password` for a secrecy-grade shared
/// key. Domain-separated (BLAKE3 derive-key mode) from [`key_from_password`] and
/// from the hysteria2 knock token so the three never collide.
pub fn default_obfs_key(bridge_static_pk: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(
        "mirage quic-obfs default per-bridge key v1",
        bridge_static_pk,
    )
}

/// Fill `out` with keyed-BLAKE3 keystream for `(key, salt)`.
fn keystream(key: &[u8; 32], salt: &[u8], out: &mut [u8]) {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(salt);
    h.finalize_xof().fill(out);
}

/// Obfuscate `payload` -> `out` = `salt || (payload XOR keystream(key,salt))`.
pub fn salamander_wrap(key: &[u8; 32], payload: &[u8], out: &mut Vec<u8>) {
    out.clear();
    out.resize(SALT_LEN + payload.len(), 0);
    getrandom::fill(&mut out[..SALT_LEN]).expect("OS CSPRNG");
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&out[..SALT_LEN]);
    // Generate the keystream directly into the output region, then XOR the
    // payload in place - no separate per-datagram keystream allocation.
    keystream(key, &salt, &mut out[SALT_LEN..]);
    for i in 0..payload.len() {
        out[SALT_LEN + i] ^= payload[i];
    }
}

/// De-obfuscate a received datagram IN PLACE. `buf` starts as `salt || xored`;
/// on success `buf[..returned_len]` holds the recovered payload. Returns `None`
/// if the datagram is shorter than the salt (malformed / not ours).
pub fn salamander_unwrap(key: &[u8; 32], buf: &mut [u8]) -> Option<usize> {
    if buf.len() < SALT_LEN {
        return None;
    }
    let plen = buf.len() - SALT_LEN;
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&buf[..SALT_LEN]);
    // XOR the keystream in fixed stack-sized chunks, moving plaintext down to
    // buf[0..] - no per-datagram heap keystream allocation. Writing buf[off+i]
    // while reading buf[SALT_LEN+off+i] is safe: every absolute index is read
    // (SALT_LEN iterations) before it is later overwritten.
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(&salt);
    let mut reader = h.finalize_xof();
    let mut chunk = [0u8; 1024];
    let mut off = 0;
    while off < plen {
        let n = (plen - off).min(chunk.len());
        reader.fill(&mut chunk[..n]);
        for i in 0..n {
            buf[off + i] = buf[SALT_LEN + off + i] ^ chunk[i];
        }
        off += n;
    }
    Some(plen)
}

/// A `quinn::AsyncUdpSocket` that Salamander-obfuscates every datagram.
///
/// GSO/GRO batching is disabled (`max_*_segments = 1`) so obfuscation is a
/// clean per-datagram transform. quinn stays at a conservative MTU
/// (`may_fragment` defaults true) which absorbs the salt overhead.
pub struct ObfsSocket {
    io: tokio::net::UdpSocket,
    key: [u8; 32],
    /// When true, every on-wire datagram carries a Wu-2023 printable preamble
    /// (see [`wu`]) so the flow clears the GFW's fully-encrypted-traffic
    /// classifier. Both peers must agree; a mismatch de-frames to garbage that
    /// quinn's AEAD then drops. Off by default (see [`wu`] for the tradeoff).
    wu: bool,
    /// Gecko reassembly state (interior-mutable: `poll_recv` takes `&self`).
    reasm: std::sync::Mutex<gecko::Reassembler>,
    /// Datagram-layer shaping, when configured. See [`QuicShape`].
    shape: Option<QuicShape>,
    /// Cursor into `shape.tokens`, advanced once per emitted datagram.
    shape_cursor: std::sync::atomic::AtomicUsize,
    /// Where to send idle cover. Learned from the first real transmit, because a
    /// client socket has no peer until quinn dials one.
    last_dest: std::sync::Mutex<Option<SocketAddr>>,
    /// Microseconds since the socket was created at the last real transmit, so
    /// the cover injector can tell an idle connection from a busy one without
    /// contending on a lock.
    ///
    /// Microseconds, not milliseconds: cover tokens can be spaced well under a
    /// millisecond apart - a single TLS record becomes a burst of back-to-back
    /// MTU packets - and at millisecond resolution every such gap truncates to
    /// zero, which turns the idle check into "always inject" and floods the link.
    last_send_us: std::sync::atomic::AtomicU64,
    /// Socket creation instant, the origin for `last_send_us`.
    born: std::time::Instant,
    /// Datagrams emitted while shaping was on.
    shaped_total: std::sync::atomic::AtomicU64,
    /// Of those, how many were LARGER than the cover size drawn for them and so
    /// went out at their true length. Every one of those is a datagram whose size
    /// is the payload's rather than the cover's - the size channel leaking - so it
    /// has to be counted rather than assumed rare.
    shaped_oversize: std::sync::atomic::AtomicU64,
    /// Datagrams that went out UNPADDED because no cover token was large enough
    /// within [`MAX_COVER_SKIP`] tries. This is the real residual size leak, kept
    /// apart from `shaped_oversize` (which merely counts tokens spent on cover),
    /// so "the size channel is closed" is a measurement and not a belief.
    shaped_unpadded: std::sync::atomic::AtomicU64,
}

impl fmt::Debug for ObfsSocket {
    // The obfuscation `key` is deliberately omitted so it never lands in logs.
    #[allow(clippy::missing_fields_in_debug)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObfsSocket")
            .field("local", &self.io.local_addr().ok())
            .finish_non_exhaustive()
    }
}

impl ObfsSocket {
    /// Wrap a bound std UDP socket in the Gecko obfuscator (Salamander XOR +
    /// handshake-packet fragmentation). `wu` enables the Wu-2023 printable
    /// preamble on every datagram (see [`wu`]); both peers must set it alike.
    pub fn wrap(std_sock: std::net::UdpSocket, key: [u8; 32], wu: bool) -> io::Result<Arc<Self>> {
        Self::wrap_shaped(std_sock, key, wu, None, false)
    }

    /// [`Self::wrap`] plus optional datagram-layer shaping ([`QuicShape`]).
    /// Spawns the idle-cover injector when a shape is given.
    /// `inject_cover` spawns the idle-cover task. It is correct ONLY for a
    /// single-peer (client) socket. A server endpoint's socket is shared by every
    /// client and outlives all of them, so an injector there would aim cover at
    /// `last_dest` - whichever client transmitted most recently - and keep sending
    /// to that address indefinitely after it disconnects, which is unsolicited
    /// traffic to a host that may since have been reassigned, and a beacon
    /// announcing the bridge. Server-side idle cover comes from the per-session
    /// pacer above the transport instead, which is where per-connection state
    /// actually exists.
    pub fn wrap_shaped(
        std_sock: std::net::UdpSocket,
        key: [u8; 32],
        wu: bool,
        shape: Option<QuicShape>,
        inject_cover: bool,
    ) -> io::Result<Arc<Self>> {
        std_sock.set_nonblocking(true)?;
        let io = tokio::net::UdpSocket::from_std(std_sock)?;
        let sock = Arc::new(Self {
            io,
            key,
            wu,
            reasm: std::sync::Mutex::new(gecko::Reassembler::new()),
            shape: shape.clone(),
            shape_cursor: std::sync::atomic::AtomicUsize::new(0),
            last_dest: std::sync::Mutex::new(None),
            last_send_us: std::sync::atomic::AtomicU64::new(0),
            born: std::time::Instant::now(),
            shaped_total: std::sync::atomic::AtomicU64::new(0),
            shaped_oversize: std::sync::atomic::AtomicU64::new(0),
            shaped_unpadded: std::sync::atomic::AtomicU64::new(0),
        });
        if let (true, Some(sh)) = (inject_cover, shape) {
            spawn_cover_injector(Arc::clone(&sock), sh);
        }
        Ok(sock)
    }

    /// Next wire size the cover calls for, or `None` when unshaped.
    fn next_shape_size(&self) -> Option<usize> {
        let sh = self.shape.as_ref()?;
        if sh.tokens.is_empty() {
            return None;
        }
        let i = self
            .shape_cursor
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Some(sh.tokens[i % sh.tokens.len()].0 as usize)
    }

    fn note_send(&self, dest: SocketAddr) {
        *self.last_dest.lock().expect("last_dest mutex") = Some(dest);
        self.last_send_us.store(
            self.born.elapsed().as_micros() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// Salamander-wrap `frame` and send it as one UDP datagram. Returns the
    /// raw `try_send_to` result so the caller can react to `WouldBlock`.
    fn send_frame(&self, frame: &[u8], dest: SocketAddr) -> io::Result<usize> {
        self.send_frame_with_prefix(frame, &self.wu_prefix(), dest)
    }

    /// A fresh Wu-2023 preamble when the evasion is on, else empty.
    ///
    /// Generated SEPARATELY from sending so a caller that is sizing a datagram can
    /// subtract this length before padding. Adding it afterwards - which is what
    /// the previous shape of this code did - inflates every shaped datagram by a
    /// random 22 to 85 bytes, so the wire sizes stop being the cover's and pick up
    /// a uniform jitter of their own. Two features that each close a channel were
    /// quietly cancelling each other.
    fn wu_prefix(&self) -> Vec<u8> {
        if self.wu {
            mirage_common::wu_preamble::make_preamble()
        } else {
            Vec::new()
        }
    }

    /// Salamander-wrap `frame` behind an already-chosen `prefix` and send it.
    fn send_frame_with_prefix(
        &self,
        frame: &[u8],
        prefix: &[u8],
        dest: SocketAddr,
    ) -> io::Result<usize> {
        let mut obf = Vec::with_capacity(SALT_LEN + frame.len());
        salamander_wrap(&self.key, frame, &mut obf);
        if prefix.is_empty() {
            self.io.try_send_to(&obf, dest)
        } else {
            let mut out = Vec::with_capacity(prefix.len() + obf.len());
            out.extend_from_slice(prefix);
            out.extend_from_slice(&obf);
            self.io.try_send_to(&out, dest)
        }
    }
}

#[derive(Debug)]
struct ObfsPoller(Arc<ObfsSocket>);

impl UdpPoller for ObfsPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.get_mut().0.io.poll_send_ready(cx)
    }
}

impl AsyncUdpSocket for ObfsSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(ObfsPoller(self))
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        // GSO is disabled, so `transmit` is a single QUIC datagram.
        let dest = transmit.destination;
        if gecko::should_fragment(transmit.contents) {
            // Long-header (handshake) packet: fragment into 2-8 padded pieces,
            // each Salamander-wrapped as its own datagram - randomises sizes.
            self.note_send(dest);
            let frames = gecko::fragment(transmit.contents);
            for (i, frame) in frames.iter().enumerate() {
                if let Err(e) = self.send_frame(frame, dest) {
                    if i == 0 {
                        // Nothing sent yet - clean retry of the whole transmit.
                        return Err(e);
                    }
                    // Some fragments already went out; dropping the rest just
                    // costs a QUIC retransmit of this (loss-tolerant) handshake
                    // packet. Report success so quinn doesn't re-fragment+dupe.
                    break;
                }
            }
            Ok(())
        } else {
            // Short-header (data) packet: send whole, single datagram, padded up
            // to the size the cover calls for. Padding only GROWS a datagram - a
            // real one is never delayed, split or held back, so quinn's timing and
            // congestion control are untouched.
            let (frame, prefix) = match self.shape.as_ref() {
                None => (gecko::whole(transmit.contents), self.wu_prefix()),
                Some(_) => {
                    // Choose the preamble up front: it is part of the wire size,
                    // so the padding target has to be net of it.
                    let prefix = self.wu_prefix();
                    let overhead = SALT_LEN + prefix.len();
                    // Emit the cover's size sequence EXACTLY, whatever the payload
                    // is doing. A datagram cannot be shrunk, so when the next cover
                    // token is too small to hold it we do not send the datagram at
                    // its true length (that is the payload's size on the wire, i.e.
                    // the leak measured at 11-57% of datagrams). We spend that token
                    // on a genuine COVER datagram instead and take the next one,
                    // until a token fits.
                    //
                    // The size sequence is therefore a function of the cover alone -
                    // never of the payload - while real data simply fills whichever
                    // tokens are large enough. Nothing is delayed to a schedule, so
                    // quinn's timing and congestion control stay untouched; the cost
                    // is the bandwidth of the skipped tokens, which is bounded by
                    // the cover's own rate.
                    //
                    // QUIC's 1200-byte Initial floor means small cover records can
                    // never carry QUIC data, so this is also the only way to
                    // reproduce them at all: as cover.
                    // If no record in the whole cover can hold this datagram, the
                    // search is guaranteed to fail - skip it rather than spend
                    // MAX_COVER_SKIP cover datagrams discovering that.
                    let biggest = self
                        .shape
                        .as_ref()
                        .map_or(0, |sh| usize::from(sh.max_size()));
                    let hopeless = biggest <= 3 + overhead + transmit.contents.len();
                    let mut frame = None;
                    for _ in 0..(if hopeless { 0 } else { MAX_COVER_SKIP }) {
                        let Some(target) = self.next_shape_size() else {
                            break;
                        };
                        let want = target.saturating_sub(overhead);
                        let total = self
                            .shaped_total
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                            + 1;
                        if want > 3 + transmit.contents.len() {
                            frame = Some(gecko::whole_padded(transmit.contents, want));
                            break;
                        }
                        // Token too small for this datagram: spend it as cover,
                        // sized net of its own preamble so it lands on the wire at
                        // the cover's size too.
                        let cover_prefix = self.wu_prefix();
                        let cover_want = target.saturating_sub(SALT_LEN + cover_prefix.len());
                        let cover = gecko::cover(cover_want.max(1));
                        let _ = self.send_frame_with_prefix(&cover, &cover_prefix, dest);
                        let over = self
                            .shaped_oversize
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                            + 1;
                        if over.is_power_of_two() {
                            tracing::debug!(
                                skipped = over,
                                total,
                                "quic-obfs: cover token too small for the datagram - \
                                 spent on cover, taking the next"
                            );
                        }
                    }
                    // Exhausted the search (a cover with no token large enough):
                    // send unpadded rather than stall the connection. THIS is the
                    // residual size leak - a datagram going out at its own length -
                    // so it is counted separately from tokens merely spent on cover,
                    // and it should be zero for any sane cover.
                    let chosen = frame.unwrap_or_else(|| {
                        let leaked = self
                            .shaped_unpadded
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                            + 1;
                        tracing::warn!(
                            unpadded = leaked,
                            "quic-obfs: no cover token large enough after {MAX_COVER_SKIP} tries - \
                             datagram sent at its TRUE size (size channel leaking). The cover \
                             profile has no records big enough to carry a QUIC datagram."
                        );
                        gecko::whole(transmit.contents)
                    });
                    (chosen, prefix)
                }
            };
            let r = self
                .send_frame_with_prefix(&frame, &prefix, dest)
                .map(|_| ());
            if r.is_ok() {
                self.note_send(dest);
            }
            r
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut tmp = [0u8; RECV_BUF];
        loop {
            let mut rb = ReadBuf::new(&mut tmp);
            match self.io.poll_recv_from(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(addr)) => {
                    let n = rb.filled().len();
                    // Strip the Wu-2023 preamble first (when enabled) so the
                    // remaining bytes are the Salamander datagram. A bad preamble
                    // (corrupt / injected) is skipped like any malformed input.
                    let obf_start = if self.wu {
                        match wu::strip_preamble(&tmp[..n]) {
                            Some(s) => s,
                            None => continue,
                        }
                    } else {
                        0
                    };
                    let Some(plen) = salamander_unwrap(&self.key, &mut tmp[obf_start..n]) else {
                        // Malformed / not-ours datagram - skip, keep polling.
                        continue;
                    };
                    // De-salamandered plaintext is a Gecko frame (WHOLE or a
                    // FRAGMENT). Reassemble; only deliver a completed datagram.
                    let datagram = {
                        let mut r = self.reasm.lock().expect("reassembler mutex");
                        r.accept(&tmp[obf_start..obf_start + plen])
                    };
                    let Some(dg) = datagram else {
                        // Partial fragment group - wait for the rest.
                        continue;
                    };
                    let out = &mut bufs[0];
                    let take = dg.len().min(out.len());
                    out[..take].copy_from_slice(&dg[..take]);
                    meta[0] = RecvMeta {
                        addr,
                        len: take,
                        stride: take,
                        ecn: None,
                        dst_ip: None,
                    };
                    return Poll::Ready(Ok(1));
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }
}

/// Keep an idle QUIC flow alive at the cover's cadence.
///
/// Fires only when the socket has been quiet for a full `idle_gap`, so a busy
/// connection is never given extra traffic to compete with - the cover fills
/// SILENCE rather than adding to work. The datagrams carry [`gecko::TAG_COVER`]
/// and are dropped below the peer's quinn, so neither endpoint's congestion
/// control or loss detection ever sees them.
///
/// The task exits once the socket is dropped, which is what ends a session.
fn spawn_cover_injector(sock: Arc<ObfsSocket>, shape: QuicShape) {
    let weak = Arc::downgrade(&sock);
    drop(sock);
    tokio::spawn(async move {
        if shape.tokens.is_empty() {
            return;
        }
        // Walk the cover's own record sequence, sleeping its real gaps. That
        // reproduces the capture's BURST structure - clusters of near-simultaneous
        // records separated by genuine pauses - instead of a uniform tick, which
        // no real traffic looks like and which (at a browse capture's 1.5 ms
        // median) would be a thousand datagrams a second.
        let mut i = 0usize;
        loop {
            let (size, gap) = shape.tokens[i % shape.tokens.len()];
            i = i.wrapping_add(1);
            tokio::time::sleep(gap.max(std::time::Duration::from_micros(200))).await;
            let Some(s) = weak.upgrade() else {
                return; // socket gone: session over
            };
            let Some(dest) = *s.last_dest.lock().expect("last_dest mutex") else {
                continue; // no peer yet - quinn has not dialled
            };
            // Only fill SILENCE. A busy connection is already putting datagrams on
            // the wire; adding to them would raise the rate above the cover's
            // rather than hold it there.
            let quiet_for = s.born.elapsed().as_micros().saturating_sub(u128::from(
                s.last_send_us.load(std::sync::atomic::Ordering::Relaxed),
            ));
            if quiet_for < gap.as_micros() {
                continue;
            }
            let frame = gecko::cover(usize::from(size).saturating_sub(SALT_LEN).max(1));
            // Best-effort: a would-block here just means the next token tries again.
            let _ = s.send_frame(&frame, dest);
            s.note_send(dest);
        }
    });
}

/// Build a QUIC **client** endpoint whose socket Salamander-obfuscates traffic.
/// `wu` enables the Wu-2023 printable preamble (see [`wu`]); both peers must
/// agree on it.
pub fn client_endpoint(bind: SocketAddr, key: [u8; 32], wu: bool) -> io::Result<quinn::Endpoint> {
    client_endpoint_shaped(bind, key, wu, None)
}

/// [`client_endpoint`] with optional datagram-layer shaping ([`QuicShape`]).
pub fn client_endpoint_shaped(
    bind: SocketAddr,
    key: [u8; 32],
    wu: bool,
    shape: Option<QuicShape>,
) -> io::Result<quinn::Endpoint> {
    let std_sock = std::net::UdpSocket::bind(bind)?;
    let socket = ObfsSocket::wrap_shaped(std_sock, key, wu, shape, true)?;
    quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
}

/// Build a QUIC **server** endpoint whose socket Salamander-obfuscates traffic.
/// `wu` enables the Wu-2023 printable preamble (see [`wu`]); both peers must
/// agree on it.
pub fn server_endpoint(
    bind: SocketAddr,
    server_config: quinn::ServerConfig,
    key: [u8; 32],
    wu: bool,
) -> io::Result<quinn::Endpoint> {
    server_endpoint_shaped(bind, server_config, key, wu, None)
}

/// [`server_endpoint`] with optional datagram-layer shaping ([`QuicShape`]).
pub fn server_endpoint_shaped(
    bind: SocketAddr,
    server_config: quinn::ServerConfig,
    key: [u8; 32],
    wu: bool,
    shape: Option<QuicShape>,
) -> io::Result<quinn::Endpoint> {
    let std_sock = std::net::UdpSocket::bind(bind)?;
    let socket = ObfsSocket::wrap_shaped(std_sock, key, wu, shape, false)?;
    quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Wu preamble is part of the WIRE size, so a shaped datagram has to be
    /// padded net of it. Adding the preamble after choosing the size inflates
    /// every datagram by a random 22-85 bytes, which puts a uniform jitter on the
    /// wire where the cover's own sizes should be - two features that each close a
    /// channel silently cancelling each other. This pins the arithmetic.
    #[test]
    fn wu_preamble_is_inside_the_shaped_size_budget() {
        use mirage_common::wu_preamble::{MAX_PRE, MIN_PRE};
        // A preamble is 1 length char + [MIN_PRE, MAX_PRE] body.
        let (lo, hi) = (1 + MIN_PRE, 1 + MAX_PRE);
        for target in [400usize, 900, 1358] {
            for pre_len in [lo, (lo + hi) / 2, hi] {
                let overhead = SALT_LEN + pre_len;
                let want = target.saturating_sub(overhead);
                let dg = vec![7u8; want.saturating_sub(64)];
                let frame = gecko::whole_padded(&dg, want);
                // salt + preamble + frame is what actually leaves the socket.
                let wire = SALT_LEN + pre_len + frame.len();
                assert_eq!(
                    wire, target,
                    "wire size must equal the cover's target with the preamble counted \
                     (target={target}, preamble={pre_len})"
                );
            }
        }
    }

    #[test]
    fn mtu_headroom_keeps_the_worst_case_datagram_inside_the_path_mtu() {
        // A full-size quinn datagram at the clamped ceiling, plus the worst-case
        // obfuscation overhead, must still fit the budget quinn's own default
        // ceiling targets - otherwise a long preamble draw silently exceeds the
        // path MTU and quinn reads the drop as congestion.
        let clamped = mtu_upper_bound_with_overhead();
        assert!(
            clamped + WU_MAX_WIRE_OVERHEAD <= QUINN_DEFAULT_MTU_UPPER_BOUND,
            "clamped datagram {clamped} + overhead {WU_MAX_WIRE_OVERHEAD} must fit {QUINN_DEFAULT_MTU_UPPER_BOUND}"
        );
        // And the clamp must stay above quinn's 1200 B floor, or MTU discovery
        // would be configured below the minimum it will ever use.
        assert!(
            clamped > 1200,
            "clamped ceiling {clamped} must exceed the QUIC minimum"
        );
        // Sanity: the UNCLAMPED default really is too big, which is why the
        // clamp exists. A const assertion, since both operands are constants and
        // a runtime assert! over them is compiled away.
        const _: () = assert!(
            QUINN_DEFAULT_MTU_UPPER_BOUND + WU_MAX_WIRE_OVERHEAD > 1500 - 28,
            "the unclamped ceiling should overflow the Ethernet MTU budget"
        );
    }

    #[test]
    fn salamander_roundtrips() {
        let key = key_from_password(b"correct horse battery staple");
        for payload in [
            &b""[..],
            &b"a"[..],
            &b"the quick brown fox jumps over the lazy dog"[..],
            &vec![0x42u8; 1200][..],
        ] {
            let mut wire = Vec::new();
            salamander_wrap(&key, payload, &mut wire);
            assert_eq!(wire.len(), SALT_LEN + payload.len());
            // The obfuscated body must not equal the plaintext. Only assert this
            // for payloads long enough that a keystream-equals-zero coincidence
            // is negligible (1/256 per byte): a 1-byte payload would flake ~0.4%
            // of runs otherwise. At >= 8 bytes the collision probability is 2^-64.
            if payload.len() >= 8 {
                assert_ne!(&wire[SALT_LEN..], payload, "payload left in cleartext");
            }
            let mut buf = wire.clone();
            let plen = salamander_unwrap(&key, &mut buf).unwrap();
            assert_eq!(&buf[..plen], payload, "roundtrip mismatch");
        }
    }

    #[test]
    fn distinct_salts_across_wraps() {
        let key = key_from_password(b"pw");
        let mut a = Vec::new();
        let mut b = Vec::new();
        salamander_wrap(&key, b"same payload", &mut a);
        salamander_wrap(&key, b"same payload", &mut b);
        // Random salt => two wraps of the same payload differ on the wire.
        assert_ne!(a, b, "salt not randomised - replayable/linkable");
    }

    #[test]
    fn wrong_key_does_not_recover() {
        let k1 = key_from_password(b"one");
        let k2 = key_from_password(b"two");
        let mut wire = Vec::new();
        salamander_wrap(&k1, b"secret quic packet", &mut wire);
        let mut buf = wire.clone();
        let plen = salamander_unwrap(&k2, &mut buf).unwrap();
        assert_ne!(&buf[..plen], b"secret quic packet");
    }

    #[test]
    fn default_obfs_key_is_deterministic_and_domain_separated() {
        let pk = [0x42u8; 32];
        // Client and bridge derive the SAME key from the (public) bridge pubkey.
        assert_eq!(default_obfs_key(&pk), default_obfs_key(&pk));
        // Different bridges -> different default keys.
        let mut pk2 = pk;
        pk2[0] ^= 0x01;
        assert_ne!(default_obfs_key(&pk), default_obfs_key(&pk2));
        // Domain-separated from a password that happens to equal the pubkey bytes
        // (derive-key mode vs plain hash), so the two derivations never collide.
        assert_ne!(default_obfs_key(&pk), key_from_password(&pk));
    }

    // ---- end-to-end QUIC over the obfuscated socket ----

    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::time::Duration;

    #[derive(Debug)]
    struct SkipVerify(Arc<rustls::crypto::CryptoProvider>);
    impl rustls::client::danger::ServerCertVerifier for SkipVerify {
        fn verify_server_cert(
            &self,
            _e: &CertificateDer<'_>,
            _i: &[CertificateDer<'_>],
            _s: &rustls::pki_types::ServerName<'_>,
            _o: &[u8],
            _n: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _m: &[u8],
            _c: &CertificateDer<'_>,
            _d: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _m: &[u8],
            _c: &CertificateDer<'_>,
            _d: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    /// Full QUIC connection over TWO obfuscated endpoints, transferring 50 KiB.
    /// Exercises: handshake-packet fragmentation (long-header), the Salamander
    /// XOR, reassembly, and (when `wu`) the Wu-2023 preamble - end to end
    /// through real quinn.
    async fn quic_roundtrip_over_gecko_socket_inner(wu: bool) {
        quic_roundtrip_inner(wu, None).await;
    }

    async fn quic_roundtrip_inner(wu: bool, shape: Option<QuicShape>) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let key = key_from_password(b"shared-obfs-password");

        // Server config: self-signed cert + ALPN h3.
        let ck = rcgen::generate_simple_self_signed(vec!["obfs.test".into()]).unwrap();
        let cert = CertificateDer::from(ck.cert);
        let sk: PrivateKeyDer = PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()).into();
        let mut stls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], sk)
            .unwrap();
        stls.alpn_protocols = vec![b"h3".to_vec()];
        let scfg = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(stls).unwrap(),
        ));
        let server =
            server_endpoint_shaped("127.0.0.1:0".parse().unwrap(), scfg, key, wu, shape.clone())
                .unwrap();
        let addr = server.local_addr().unwrap();

        // Client config: skip-verify + ALPN h3.
        let mut ctls = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipVerify(provider)))
            .with_no_client_auth();
        ctls.alpn_protocols = vec![b"h3".to_vec()];
        let mut client =
            client_endpoint_shaped("127.0.0.1:0".parse().unwrap(), key, wu, shape).unwrap();
        client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(ctls).unwrap(),
        )));

        let payload: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
        let payload_c = payload.clone();

        let server_task = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let got = recv.read_to_end(200_000).await.unwrap();
            send.write_all(&got).await.unwrap();
            send.finish().unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;
        });

        let conn = client.connect(addr, "obfs.test").unwrap().await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(&payload_c).await.unwrap();
        send.finish().unwrap();
        let echoed = recv.read_to_end(200_000).await.unwrap();
        assert_eq!(
            echoed, payload,
            "payload did not survive the obfuscated QUIC path"
        );
        server_task.await.unwrap();
    }

    /// The shaped path must carry a real QUIC connection intact. Size shaping
    /// pads datagrams, and padding that is not framed with an explicit length is
    /// handed to quinn as part of the QUIC packet, where it fails AEAD and
    /// presents as a connection that simply does not work. 50 KiB through a real
    /// handshake is what catches that.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn quic_roundtrip_over_shaped_socket() {
        quic_roundtrip_inner(
            false,
            Some(QuicShape {
                tokens: vec![
                    (1200, std::time::Duration::from_millis(50)),
                    (700, std::time::Duration::from_micros(200)),
                    (1200, std::time::Duration::from_millis(12)),
                    (350, std::time::Duration::from_micros(300)),
                ],
            }),
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn quic_roundtrip_over_gecko_socket() {
        quic_roundtrip_over_gecko_socket_inner(false).await;
    }

    /// Same end-to-end path with the Wu-2023 preamble on: the printable prefix
    /// must strip cleanly on receive so a real QUIC handshake + 50 KiB survive.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn quic_roundtrip_over_gecko_socket_with_wu_preamble() {
        quic_roundtrip_over_gecko_socket_inner(true).await;
    }
}
