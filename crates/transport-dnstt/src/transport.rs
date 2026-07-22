//! DNS-tunnel transport driver: turns the [`ReliableEndpoint`] state machine
//! into a live carrier over UDP DNS, presenting a `tokio::io::DuplexStream`
//! the Mirage session rides on.
//!
//! Client = 3 tasks sharing the endpoint: a write-pump (Mirage writes -> send
//! buffer), a reader (DNS responses -> endpoint -> Mirage reads), and an adaptive
//! poller (emits queries fast under load, backs off when idle). Server =
//! reactive: one UDP socket demultiplexes queries to per-session drivers by the
//! `Packet.session` id; each query draws one response carrying whatever
//! downstream is ready, sized to fit the 512-byte UDP budget after the echoed
//! question name.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{split, AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};

use crate::arq::{max_upstream_data, Packet};
use crate::dns::{encode_query, encode_response, parse_query, parse_response};
use crate::stream::ReliableEndpoint;

/// Carrier duplex buffer (bytes each direction).
const DUPLEX_BUF: usize = 64 * 1024;
/// Scratch buffer for one DNS datagram.
const DGRAM: usize = 1500;
/// Fastest client poll interval under active load.
const POLL_FAST: Duration = Duration::from_millis(15);
/// Slowest client poll interval when idle (keeps the tunnel + downstream alive).
const POLL_SLOW_MS: u64 = 800;
/// Cap on concurrent server-side sessions. These are keyed on the pre-auth
/// `session` id from an incoming query, so this bounds how many `session_driver`
/// tasks + duplex buffers an attacker enumerating ids can force us to hold; the
/// least-recently-active entry is evicted to admit a new one past the cap.
const MAX_SESSIONS: usize = 512;
/// Reclaim a session whose last query is older than this. A live client polls
/// at least every [`POLL_SLOW_MS`], so any genuine multi-packet session refreshes
/// well inside this window; anything quieter is dead (or a half-open flood).
const SESSION_IDLE: Duration = Duration::from_secs(30);
/// How often the serve loop sweeps idle sessions. Running the full O(n) reap on
/// EVERY datagram let a spoofed-session-id flood pay a MAX_SESSIONS-entry scan per
/// cheap packet (resource-DoS #8); amortizing it to once per interval keeps that
/// scan off the per-datagram hot path. An idle session now lingers at most
/// SESSION_IDLE + REAP_INTERVAL, and MAX_SESSIONS still bounds memory between
/// sweeps, so semantics are preserved.
const REAP_INTERVAL: Duration = Duration::from_secs(1);
/// Sample size for the approximate-LRU eviction at [`MAX_SESSIONS`]. Bounds the
/// evict scan to O(SAMPLE) instead of O(MAX_SESSIONS) per new id under a
/// distinct-id flood, mirroring `bridge::rate_limit`'s bounded eviction.
const EVICT_SAMPLE: usize = 32;
/// Sustained cap on NEW server-side sessions admitted per second (token-bucket
/// refill rate). Even when the bridge drains `new_sessions`, a spoofed-id flood
/// must not force unbounded `session_driver` spawns + 128 KiB duplex allocs. A
/// legit client opens ONE session for its whole connection, so this throttles
/// only the rate of *distinct new ids*; a throttled client's SYN retries and is
/// admitted as tokens refill. Sized generously so real new-client bursts pass.
const NEW_SESSION_RATE_PER_SEC: u32 = 128;
/// Burst capacity for the new-session admission token bucket (see
/// [`NEW_SESSION_RATE_PER_SEC`]).
const NEW_SESSION_BURST: u32 = 256;

fn rand_u32() -> u32 {
    let mut b = [0u8; 4];
    getrandom::fill(&mut b).expect("OS CSPRNG");
    u32::from_be_bytes(b)
}

/// Downstream data budget for a response echoing `qname`, staying under the
/// 512-byte plain-DNS/UDP message limit. Accounts for header, the echoed
/// question, the compressed answer header, and TXT chunk overhead.
fn downstream_mtu(qname: &str) -> usize {
    let name_wire: usize = qname
        .split('.')
        .filter(|l| !l.is_empty())
        .map(|l| l.len() + 1)
        .sum::<usize>()
        + 1; // + root
             // 12 header + (name_wire + 4) question + (2 ptr + 10) answer hdr
             // + 11 mirrored EDNS0 OPT (finding #11) + margin.
    let overhead = 12 + name_wire + 4 + 12 + 11 + 6;
    512usize
        .saturating_sub(overhead)
        .saturating_sub(crate::arq::HEADER_LEN)
}

// Client

/// Dial a DNS tunnel: `target` is the resolver (or the bridge's `:53`) that
/// forwards queries under `tunnel_domain` to the bridge. Returns a carrier the
/// Mirage session drives immediately (the tunnel establishes lazily on traffic).
pub async fn dnstt_client_connect(
    target: SocketAddr,
    tunnel_domain: &str,
    _deadline: Duration,
) -> io::Result<DuplexStream> {
    let bind: SocketAddr = if target.is_ipv6() {
        "[::]:0".parse().expect("bind")
    } else {
        "0.0.0.0:0".parse().expect("bind")
    };
    let socket = Arc::new(UdpSocket::bind(bind).await?);
    socket.connect(target).await?;

    let ep = Arc::new(Mutex::new(ReliableEndpoint::new(rand_u32(), true)));
    let (carrier, driver_io) = tokio::io::duplex(DUPLEX_BUF);
    let (mut dr_read, mut dr_write) = split(driver_io);
    let notify = Arc::new(Notify::new());
    let domain = tunnel_domain.to_string();
    let mtu = max_upstream_data(&domain);

    // Write-pump: Mirage -> endpoint send buffer.
    {
        let ep = Arc::clone(&ep);
        let notify = Arc::clone(&notify);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match dr_read.read(&mut buf).await {
                    Ok(0) | Err(_) => {
                        if let Ok(mut g) = ep.lock() {
                            g.close();
                        }
                        notify.notify_one();
                        break;
                    }
                    Ok(n) => {
                        if let Ok(mut g) = ep.lock() {
                            g.write(&buf[..n]);
                        }
                        notify.notify_one();
                    }
                }
            }
        });
    }
    // Reader: DNS responses -> endpoint -> Mirage.
    {
        let ep = Arc::clone(&ep);
        let socket = Arc::clone(&socket);
        let notify = Arc::clone(&notify);
        tokio::spawn(async move {
            let mut buf = vec![0u8; DGRAM];
            loop {
                let Ok(n) = socket.recv(&mut buf).await else {
                    break;
                };
                let delivered = {
                    let Some((_, payload)) = parse_response(&buf[..n]) else {
                        continue;
                    };
                    let Some(pkt) = Packet::decode(&payload) else {
                        continue;
                    };
                    let Ok(mut g) = ep.lock() else { break };
                    g.on_packet(&pkt);
                    g.take_delivered()
                };
                if !delivered.is_empty() && dr_write.write_all(&delivered).await.is_err() {
                    break;
                }
                notify.notify_one();
            }
        });
    }
    // Poller: emit queries at an adaptive rate.
    {
        let ep = Arc::clone(&ep);
        let socket = Arc::clone(&socket);
        let notify = Arc::clone(&notify);
        tokio::spawn(async move {
            let mut idle = 0u32;
            loop {
                let (pkt, unacked) = {
                    let Ok(mut g) = ep.lock() else { break };
                    (g.build_packet(mtu), g.unacked_len())
                };
                if let Some(qname) = pkt.to_query_name(&domain) {
                    // Draw the DNS transaction id from the CSPRNG per query. A
                    // real resolver picks these unpredictably, so a monotonic
                    // counter (1, 2, 3, ...) would trivially fingerprint the
                    // tunnel versus genuine DNS traffic.
                    let dns_id = rand_u32() as u16;
                    if let Some(q) = encode_query(dns_id, &qname) {
                        let _ = socket.send(&q).await;
                    }
                }
                let delay = if unacked > 0 || idle < 4 {
                    // Jitter the active-poll gap (base ~15 ms -> 5..=25 ms) so the
                    // query cadence isn't a fixed ~67 queries/s metronome, which
                    // no real DNS client emits (red-team HIGH #5). Mean is
                    // unchanged so throughput/latency are preserved.
                    let base = POLL_FAST.as_millis() as u64;
                    Duration::from_millis(base.saturating_sub(10) + u64::from(rand_u32() % 21))
                } else {
                    Duration::from_millis((50u64 << idle.min(4)).min(POLL_SLOW_MS))
                };
                tokio::select! {
                    () = notify.notified() => idle = 0,
                    () = tokio::time::sleep(delay) => idle = idle.saturating_add(1),
                }
            }
        });
    }
    Ok(carrier)
}

// Server

/// Run the bridge-side DNS-tunnel handler on `socket` (a bound UDP:53). Each new
/// session id yields a carrier on `new_sessions` - the bridge runs a Mirage
/// session over each. Loops until the socket errors.
pub async fn dnstt_serve(
    socket: Arc<UdpSocket>,
    tunnel_domain: &str,
    new_sessions: mpsc::Sender<DuplexStream>,
) -> io::Result<()> {
    let domain = tunnel_domain.to_string();
    let mut sessions: HashMap<u32, Session> = HashMap::new();
    let mut buf = vec![0u8; DGRAM];
    // Amortized idle reaper: swept at most once per REAP_INTERVAL, not per packet.
    let mut last_reap = Instant::now();
    // Global new-session admission rate cap (integer token bucket).
    let mut new_tokens: u32 = NEW_SESSION_BURST;
    let mut last_refill = Instant::now();
    loop {
        let (n, from) = socket.recv_from(&mut buf).await?;
        let Some(q) = parse_query(&buf[..n]) else {
            continue;
        };
        let Some(pkt) = Packet::from_query_name(&q.name, &domain) else {
            continue;
        };
        let sess = pkt.session;
        let now = Instant::now();

        // Amortized idle reclamation. Dropping a session's sender closes the
        // driver's receiver, freeing its `session_driver` + duplex buffer.
        // Running the full O(n) retain on EVERY datagram let a spoofed-id flood
        // pay a MAX_SESSIONS-entry scan per cheap packet, so sweep at most once
        // per REAP_INTERVAL (memory stays bounded by MAX_SESSIONS between sweeps).
        if now.duration_since(last_reap) >= REAP_INTERVAL {
            reap_idle(&mut sessions, now);
            last_reap = now;
        }

        if let Some(s) = sessions.get_mut(&sess) {
            s.last_seen = now;
        } else {
            // A new, still-unauthenticated session id. Admit BEFORE allocating.
            // 1) Global new-session rate cap so a flood can't saturate this task
            //    with `session_driver` spawns even when the bridge is draining.
            //    Refill in whole tokens; leave `last_refill` untouched until at
            //    least one token accrues so sub-millisecond time isn't lost.
            let elapsed_ms = now.duration_since(last_refill).as_millis() as u64;
            let refill = (elapsed_ms * u64::from(NEW_SESSION_RATE_PER_SEC) / 1000)
                .min(u64::from(NEW_SESSION_BURST)) as u32;
            if refill > 0 {
                new_tokens = new_tokens.saturating_add(refill).min(NEW_SESSION_BURST);
                last_refill = now;
            }
            if new_tokens == 0 {
                continue; // over the new-session rate cap; client retries its SYN
            }
            // 2) Reserve a slot in the new-session channel FIRST. Reserving before
            //    the 128 KiB `duplex` alloc means a spoofed id we can't hand off
            //    costs nothing - no alloc, no task spawn (resource-DoS #8).
            let Ok(permit) = new_sessions.try_reserve() else {
                continue; // bridge not accepting new sessions; client retries its SYN
            };
            new_tokens -= 1;
            // 3) At cap, evict with a bounded sample (not an O(MAX_SESSIONS) scan).
            if sessions.len() >= MAX_SESSIONS {
                evict_approx_lru(&mut sessions);
            }
            let (carrier, driver_io) = tokio::io::duplex(DUPLEX_BUF);
            permit.send(carrier);
            let (tx, rx) = mpsc::channel(128);
            tokio::spawn(session_driver(rx, Arc::clone(&socket), driver_io));
            sessions.insert(sess, Session { tx, last_seen: now });
        }

        if let Some(s) = sessions.get(&sess) {
            let msg = Inbound {
                from,
                dns_id: q.id,
                qname: q.name,
                pkt,
                recursion_desired: q.recursion_desired,
                had_opt: q.had_opt,
            };
            if s.tx.try_send(msg).is_err() {
                // Session backlogged or gone - drop the query (client will retry).
            }
        }
    }
}

/// Reclaim sessions idle longer than [`SESSION_IDLE`]. Dropping a `Session`'s
/// sender closes its driver's receiver, freeing the `session_driver` task + its
/// duplex buffer. Called by the serve loop at most once per [`REAP_INTERVAL`].
fn reap_idle(sessions: &mut HashMap<u32, Session>, now: Instant) {
    sessions.retain(|_, s| now.duration_since(s.last_seen) < SESSION_IDLE);
}

/// Approximate-LRU eviction: sample the first [`EVICT_SAMPLE`] entries and drop
/// the least-recently-active among them. O(SAMPLE) instead of O(MAX_SESSIONS)
/// per new id under a distinct-id flood (resource-DoS #8), mirroring
/// `bridge::rate_limit`'s bounded eviction.
fn evict_approx_lru(sessions: &mut HashMap<u32, Session>) {
    if let Some(victim) = sessions
        .iter()
        .take(EVICT_SAMPLE)
        .min_by_key(|(_, s)| s.last_seen)
        .map(|(k, _)| *k)
    {
        sessions.remove(&victim);
    }
}

/// A tracked server-side session: the channel feeding its [`session_driver`] and
/// the last time a query for it arrived (for idle reclamation + LRU eviction).
struct Session {
    tx: mpsc::Sender<Inbound>,
    last_seen: Instant,
}

/// One demultiplexed inbound query handed to a [`session_driver`]. Carries the
/// query's RD/EDNS state so the response can mirror it authoritatively (#11).
struct Inbound {
    from: SocketAddr,
    dns_id: u16,
    qname: String,
    pkt: Packet,
    recursion_desired: bool,
    had_opt: bool,
}

/// Per-session server driver: a write-pump (Mirage -> endpoint) plus the query
/// loop (each incoming query -> on_packet -> one response with pending downstream).
async fn session_driver(
    mut rx: mpsc::Receiver<Inbound>,
    socket: Arc<UdpSocket>,
    driver_io: DuplexStream,
) {
    let ep = Arc::new(Mutex::new(ReliableEndpoint::new(0, false)));
    let (mut dr_read, mut dr_write) = split(driver_io);
    let pump = {
        let ep = Arc::clone(&ep);
        tokio::spawn(async move {
            let mut b = vec![0u8; 16 * 1024];
            loop {
                match dr_read.read(&mut b).await {
                    Ok(0) | Err(_) => {
                        if let Ok(mut g) = ep.lock() {
                            g.close();
                        }
                        break;
                    }
                    Ok(n) => {
                        if let Ok(mut g) = ep.lock() {
                            g.write(&b[..n]);
                        }
                    }
                }
            }
        })
    };
    while let Some(inb) = rx.recv().await {
        let (delivered, resp) = {
            let Ok(mut g) = ep.lock() else { break };
            g.on_packet(&inb.pkt);
            let d = g.take_delivered();
            let r = g.build_packet(downstream_mtu(&inb.qname));
            (d, r)
        };
        if !delivered.is_empty() && dr_write.write_all(&delivered).await.is_err() {
            break;
        }
        if let Some(msg) = encode_response(
            inb.dns_id,
            &inb.qname,
            &resp.encode(),
            inb.recursion_desired,
            inb.had_opt,
        ) {
            let _ = socket.send_to(&msg, inb.from).await;
        }
    }
    // The session was reclaimed (its sender dropped) or the peer FIN'd: stop the
    // write-pump so this session frees its task + duplex buffer instead of
    // lingering after the entry leaves the `sessions` map.
    pump.abort();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Full carrier round-trip over real loopback UDP: client dials, both sides
    /// exchange bytes through the DNS tunnel, everything arrives intact.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn carrier_roundtrip_over_udp() {
        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = server_sock.local_addr().unwrap();
        let (tx, mut rx) = mpsc::channel(4);
        tokio::spawn(dnstt_serve(server_sock, "t.example.com", tx));

        let mut client = dnstt_client_connect(addr, "t.example.com", Duration::from_secs(5))
            .await
            .unwrap();

        // Client -> server (a few KiB, exercising many DNS exchanges + reassembly).
        let up: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
        client.write_all(&up).await.unwrap();

        let mut server_carrier = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("server session")
            .expect("carrier");
        let mut got = vec![0u8; up.len()];
        tokio::time::timeout(Duration::from_secs(10), server_carrier.read_exact(&mut got))
            .await
            .expect("server read timed out")
            .unwrap();
        assert_eq!(got, up, "upstream corrupted");

        // Server -> client (larger, download-heavy like real browsing).
        let down: Vec<u8> = (0..8000u32).map(|i| ((i * 7 + 1) % 251) as u8).collect();
        server_carrier.write_all(&down).await.unwrap();
        let mut got2 = vec![0u8; down.len()];
        tokio::time::timeout(Duration::from_secs(15), client.read_exact(&mut got2))
            .await
            .expect("client read timed out")
            .unwrap();
        assert_eq!(got2, down, "downstream corrupted");
    }

    /// A pre-auth flood of distinct session ids must not wedge the server: the
    /// bounded/idle-evicted session map keeps it healthy, and a legitimate
    /// multi-packet session dialed afterwards still completes end to end.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn half_open_flood_does_not_break_legit_session() {
        use crate::arq::{Packet, FLAG_SYN};
        use crate::dns::encode_query;

        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = server_sock.local_addr().unwrap();
        let (tx, mut rx) = mpsc::channel(64);
        tokio::spawn(dnstt_serve(server_sock, "t.example.com", tx));
        // Stand in for the bridge: echo each carrier's bytes back so a legit
        // session can be observed round-tripping. Draining also stops the
        // new-session channel from filling under the flood.
        tokio::spawn(async move {
            while let Some(carrier) = rx.recv().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = split(carrier);
                    let mut b = vec![0u8; 4096];
                    loop {
                        match r.read(&mut b).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) if w.write_all(&b[..n]).await.is_ok() => {}
                            Ok(_) => break,
                        }
                    }
                });
            }
        });

        // Flood many distinct, never-completed session ids past MAX_SESSIONS to
        // exercise the cap + LRU eviction (each would otherwise pin a task+buffer).
        let flood = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        flood.connect(addr).await.unwrap();
        for sess in 0..(MAX_SESSIONS as u32 + 256) {
            let pkt = Packet {
                session: sess.wrapping_add(0x8000_0000),
                seq: 0,
                ack: 0,
                flags: FLAG_SYN,
                data: Vec::new(),
            };
            let qname = pkt.to_query_name("t.example.com").expect("qname");
            let q = encode_query(rand_u32() as u16, &qname).expect("encode");
            let _ = flood.send(&q).await;
        }

        // A genuine client must still connect and round-trip through the tunnel.
        let mut client = dnstt_client_connect(addr, "t.example.com", Duration::from_secs(5))
            .await
            .unwrap();
        let up: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        client.write_all(&up).await.unwrap();
        let mut echoed = vec![0u8; up.len()];
        tokio::time::timeout(Duration::from_secs(20), client.read_exact(&mut echoed))
            .await
            .expect("legit session made no progress after a half-open flood - server wedged")
            .unwrap();
        assert_eq!(echoed, up, "legit round-trip corrupted under flood");
    }

    /// Reserve-before-allocate (#8): once the new-session channel is full, further
    /// distinct spoofed ids are dropped at the admission check *before* any 128 KiB
    /// duplex is allocated. Observable as: an undrained capacity-N channel yields at
    /// most N carriers no matter how many distinct ids flood in.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn undrained_channel_bounds_admissions_before_alloc() {
        use crate::arq::{Packet, FLAG_SYN};
        use crate::dns::encode_query;

        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = server_sock.local_addr().unwrap();
        // Small channel we deliberately do NOT drain.
        let (tx, mut rx) = mpsc::channel(4);
        tokio::spawn(dnstt_serve(server_sock, "t.example.com", tx));

        let flood = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        flood.connect(addr).await.unwrap();
        for sess in 0..500u32 {
            let pkt = Packet {
                session: sess.wrapping_add(0x4000_0000),
                seq: 0,
                ack: 0,
                flags: FLAG_SYN,
                data: Vec::new(),
            };
            let qname = pkt.to_query_name("t.example.com").expect("qname");
            let q = encode_query(rand_u32() as u16, &qname).expect("encode");
            let _ = flood.send(&q).await;
        }
        // Let the server process the flood.
        tokio::time::sleep(Duration::from_millis(300)).await;

        let mut count = 0;
        while rx.try_recv().is_ok() {
            count += 1;
        }
        assert!(count >= 1, "server admitted no session at all");
        assert!(
            count <= 4,
            "admission not gated before alloc: {count} carriers escaped a cap-4 channel"
        );
    }

    /// The amortized reaper still expires idle sessions and keeps fresh ones.
    #[test]
    fn reaper_expires_only_idle_sessions() {
        let base = Instant::now();
        let mut sessions: HashMap<u32, Session> = HashMap::new();
        let (tx1, _rx1) = mpsc::channel::<Inbound>(1);
        let (tx2, _rx2) = mpsc::channel::<Inbound>(1);
        // #1 seen at base + SESSION_IDLE; #2 seen at base.
        sessions.insert(
            1,
            Session {
                tx: tx1,
                last_seen: base + SESSION_IDLE,
            },
        );
        sessions.insert(
            2,
            Session {
                tx: tx2,
                last_seen: base,
            },
        );
        // Sweep at a moment where #2 is idle (> SESSION_IDLE past base) but #1 isn't.
        reap_idle(
            &mut sessions,
            base + SESSION_IDLE + Duration::from_millis(500),
        );
        assert!(sessions.contains_key(&1), "recently-seen session survives");
        assert!(!sessions.contains_key(&2), "idle session reaped");
    }

    /// The bounded-sample eviction removes exactly one entry at cap.
    #[test]
    fn eviction_is_bounded_and_removes_one() {
        let now = Instant::now();
        let mut sessions: HashMap<u32, Session> = HashMap::new();
        for i in 0..MAX_SESSIONS as u32 {
            let (tx, _rx) = mpsc::channel::<Inbound>(1);
            // Make one entry strictly oldest so the sample has a clear minimum.
            let last_seen = if i == 0 {
                now
            } else {
                now + Duration::from_secs(1)
            };
            sessions.insert(i, Session { tx, last_seen });
        }
        let before = sessions.len();
        evict_approx_lru(&mut sessions);
        assert_eq!(sessions.len(), before - 1, "exactly one entry evicted");
    }
}
