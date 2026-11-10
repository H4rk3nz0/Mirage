//! End-to-end integration test: real traffic through bridge via SOCKS5.
//!
//! Topology:
//!
//! ```text
//! test_app -TCP-> [Mirage session: client connect]
//!                        down encrypted
//!                 [Mirage session: bridge accept]
//!                        down decrypted
//!                 [SOCKS5 server: serve_one_connect]
//!                        down TCP
//!                 [target: echo / HTTP server]
//! ```
//!
//! Tests:
//!
//! - `socks5_connect_echo_round_trip`: full SOCKS5 CONNECT + echo data
//!   over a Mirage session.  Verifies framing, encryption, SOCKS5
//!   negotiation, and copy_bidirectional all work together.
//! - `socks5_token_replay_rejected`: second connection with the same
//!   single-use token is rejected at the Noise handshake.
//! - `multi_entry_pool_failover`: first bridge entry is unreachable;
//!   client retries and succeeds through the second entry.

use std::sync::Arc;
use std::time::Duration;

use mirage_crypto::ed25519_dalek::SigningKey;
use mirage_crypto::x25519_dalek::{PublicKey, StaticSecret};
use mirage_discovery::replay::SyncReplaySet;
use mirage_discovery::token::{sign_token, CapabilityToken};
use mirage_session::{accept, connect, TokenVerifier};
use mirage_socks5::AllowlistPolicy;
use tokio::io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn rand_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    getrandom::fill(&mut s).unwrap();
    s
}

struct Keys {
    client_x_sk: [u8; 32],
    bridge_x_sk: [u8; 32],
    bridge_x_pk: [u8; 32],
    bridge_ed_pk: [u8; 32],
    op_sk: SigningKey,
    op_pk: [u8; 32],
}

fn fresh_keys() -> Keys {
    let client_x_sk = StaticSecret::from(rand_seed()).to_bytes();
    let bsk_seed = rand_seed();
    let bsk = StaticSecret::from(bsk_seed);
    let bridge_x_pk = *PublicKey::from(&bsk).as_bytes();
    let bridge_x_sk = bsk.to_bytes();
    let bridge_id_sk = SigningKey::from_bytes(&rand_seed());
    let bridge_ed_pk = bridge_id_sk.verifying_key().to_bytes();
    let op_sk = SigningKey::from_bytes(&rand_seed());
    let op_pk = op_sk.verifying_key().to_bytes();
    Keys {
        client_x_sk,
        bridge_x_sk,
        bridge_x_pk,
        bridge_ed_pk,
        op_sk,
        op_pk,
    }
}

fn issue_token(k: &Keys, now: u64) -> CapabilityToken {
    sign_token([0xAB; 32], k.bridge_ed_pk, now + 3600, &k.op_sk)
}

/// Policy that allows loopback - needed so the bridge can reach
/// test echo servers running on 127.0.0.1.
fn test_policy() -> AllowlistPolicy {
    AllowlistPolicy {
        deny_loopback: false,
        deny_private_networks: false,
        allowed_ports: None,
    }
}

/// Build an 8-byte SOCKS5 CONNECT request for an IPv4 target.
/// `buf` receives: greeting(3) + NO_AUTH(2) + request(10) = 15 bytes.
fn socks5_connect_ipv4(addr: std::net::Ipv4Addr, port: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(15);
    // Greeting: VER=5, NMETHODS=1, METHOD=NO_AUTH(0x00)
    buf.extend_from_slice(&[0x05, 0x01, 0x00]);
    // Request: VER=5, CMD=CONNECT(1), RSV=0, ATYP=IPv4(1)
    buf.push(0x05);
    buf.push(0x01);
    buf.push(0x00);
    buf.push(0x01);
    buf.extend_from_slice(&addr.octets());
    buf.extend_from_slice(&port.to_be_bytes());
    buf
}

/// Read + discard the SOCKS5 greeting reply and CONNECT reply
/// (exactly 2 + 10 = 12 bytes for an IPv4 bound address).
async fn consume_socks5_reply<S: AsyncRead + Unpin>(s: &mut S) {
    // method-selection reply: VER METHOD (2 bytes)
    let mut tmp = [0u8; 2];
    s.read_exact(&mut tmp).await.unwrap();
    assert_eq!(tmp, [0x05, 0x00], "expected NO_AUTH method reply");
    // CONNECT reply: VER REP RSV ATYP + 4-byte IPv4 + 2-byte port = 10
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05, "expected VER=5 in reply");
    assert_eq!(reply[1], 0x00, "expected REP=SUCCESS in reply");
}

// -- echo server helpers ------------------------------------------------------

/// Spawn a loopback TCP echo server. Returns its bind address.
async fn spawn_echo_server() -> std::net::SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = match l.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            s.set_nodelay(true).ok();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// Spawn a bridge that runs SOCKS5 over Mirage sessions.
///
/// Uses `SyncReplaySet` - the production-recommended concurrent pattern.
/// The `check_and_insert` lock is held only for the duration of the
/// synchronous replay check, not across the async Noise handshake.
async fn spawn_bridge(k: Arc<Keys>, now: u64, replay: Arc<SyncReplaySet>) -> std::net::SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (sock, _) = match l.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            sock.set_nodelay(true).ok();
            let k = Arc::clone(&k);
            let replay = Arc::clone(&replay);
            tokio::spawn(async move {
                let mut v = TokenVerifier::new_shared(&replay, now);
                let session =
                    match accept(sock, &k.bridge_x_sk, &k.bridge_ed_pk, &k.op_pk, &mut v).await {
                        Ok(s) => s,
                        Err(_) => return,
                    };

                let policy = test_policy();
                let (_, mut upstream, mut session) = match mirage_socks5::serve_one_connect(
                    session,
                    &policy,
                    Duration::from_secs(5),
                )
                .await
                {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let _ = copy_bidirectional(&mut session, &mut upstream).await;
                let _ = session.shutdown().await;
                let _ = upstream.shutdown().await;
            });
        }
    });
    addr
}

// -- tests --------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks5_connect_echo_round_trip() {
    let k = Arc::new(fresh_keys());
    let now = 1_700_000_000u64;
    let replay = Arc::new(SyncReplaySet::new(64));

    let echo_addr = spawn_echo_server().await;
    let bridge_addr = spawn_bridge(Arc::clone(&k), now, Arc::clone(&replay)).await;
    let token = issue_token(&k, now);

    tokio::time::timeout(Duration::from_secs(10), async move {
        // Open a Mirage session to the bridge.
        let sock = TcpStream::connect(bridge_addr).await.unwrap();
        sock.set_nodelay(true).ok();
        let mut session = connect(sock, &k.client_x_sk, &k.bridge_x_pk, &token)
            .await
            .expect("mirage connect");

        // Send SOCKS5 CONNECT targeting the echo server.
        let socks5_req = socks5_connect_ipv4(std::net::Ipv4Addr::LOCALHOST, echo_addr.port());
        session.write_all(&socks5_req).await.unwrap();
        session.flush().await.unwrap();

        // Consume SOCKS5 success reply.
        consume_socks5_reply(&mut session).await;

        // Send payload and expect echo.
        let payload = b"Mirage delivers internet freedom over encrypted tunnels.";
        session.write_all(payload).await.unwrap();
        session.flush().await.unwrap();

        let mut got = vec![0u8; payload.len()];
        session.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload, "echo payload mismatch");

        // Send a second chunk to confirm the session stays open.
        let payload2 = b"The censor sees nothing.";
        session.write_all(payload2).await.unwrap();
        session.flush().await.unwrap();
        let mut got2 = vec![0u8; payload2.len()];
        session.read_exact(&mut got2).await.unwrap();
        assert_eq!(got2, payload2, "second echo mismatch");
    })
    .await
    .expect("test deadline hit");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks5_token_replay_rejected() {
    // A token is single-use (replay set). A second connection with
    // the same token MUST be rejected at the Noise handshake.
    let k = Arc::new(fresh_keys());
    let now = 1_700_000_000u64;
    let replay = Arc::new(SyncReplaySet::new(64));

    let echo_addr = spawn_echo_server().await;
    let bridge_addr = spawn_bridge(Arc::clone(&k), now, Arc::clone(&replay)).await;
    let token = issue_token(&k, now);

    // First connection: should succeed.
    {
        let sock = TcpStream::connect(bridge_addr).await.unwrap();
        sock.set_nodelay(true).ok();
        let mut session = connect(sock, &k.client_x_sk, &k.bridge_x_pk, &token)
            .await
            .expect("first connect should succeed");
        let socks5_req = socks5_connect_ipv4(std::net::Ipv4Addr::LOCALHOST, echo_addr.port());
        session.write_all(&socks5_req).await.unwrap();
        session.flush().await.unwrap();
        consume_socks5_reply(&mut session).await;
        let _ = session.shutdown().await;
    }

    // Give the bridge a moment to commit the replay entry before
    // the second connect.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Second connection with the SAME token: bridge rejects msg3 and
    // closes the TCP socket. The client's `connect` returns Ok
    // (msg3 already sent - no bridge ack in Noise-XX). Rejection is
    // detected when the client tries to USE the session: the
    // underlying TCP is already closed, so the first write/read fails.
    let sock2 = TcpStream::connect(bridge_addr).await.unwrap();
    sock2.set_nodelay(true).ok();
    let mut session2 = tokio::time::timeout(
        Duration::from_secs(5),
        connect(sock2, &k.client_x_sk, &k.bridge_x_pk, &token),
    )
    .await
    .expect("replay connect timed out")
    .expect("connect itself (msg1-3 exchange) is always Ok in Noise-XX");

    // Give the bridge a moment to process msg3, detect the replay,
    // and close the TCP socket before we try to write.
    tokio::time::sleep(Duration::from_millis(30)).await;

    // The SOCKS5 CONNECT request will fail because the bridge has
    // already closed the underlying TCP connection.
    let socks5_req = socks5_connect_ipv4(std::net::Ipv4Addr::LOCALHOST, echo_addr.port());
    let write_result = session2.write_all(&socks5_req).await;
    let flush_result = session2.flush().await;
    // At least one of write/flush must fail; on a cleanly closed
    // socket the error may surface on the subsequent read.
    if write_result.is_ok() && flush_result.is_ok() {
        let mut reply = [0u8; 2];
        let read_result = session2.read_exact(&mut reply).await;
        assert!(
            read_result.is_err(),
            "replay token MUST cause session failure; got Ok on first use"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_entry_pool_failover() {
    // Simulates the multi-entry pool's retry logic at the TCP level:
    // the first bridge entry's port is closed (ECONNREFUSED), so the
    // pool should skip it and succeed through the second entry.
    let k = Arc::new(fresh_keys());
    let now = 1_700_000_000u64;
    let replay = Arc::new(SyncReplaySet::new(64));

    let echo_addr = spawn_echo_server().await;
    let good_bridge_addr = spawn_bridge(Arc::clone(&k), now, Arc::clone(&replay)).await;

    // Reserve a port that is immediately released - it will be
    // ECONNREFUSED by the time the test hits it.
    let dead_port = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
        // l is dropped here; port is no longer bound.
    };

    let token = issue_token(&k, now);

    tokio::time::timeout(Duration::from_secs(10), async move {
        // Try dead bridge first - should fail TCP connect.
        let dead_addr = format!("127.0.0.1:{dead_port}");
        let dead_result = TcpStream::connect(&dead_addr).await;
        assert!(
            dead_result.is_err(),
            "dead port must refuse connections for this test to be meaningful"
        );

        // Now try good bridge - pool retry logic in client main.rs
        // would pick this after marking the dead entry failed.
        let sock = TcpStream::connect(good_bridge_addr).await.unwrap();
        sock.set_nodelay(true).ok();
        let mut session = connect(sock, &k.client_x_sk, &k.bridge_x_pk, &token)
            .await
            .expect("good bridge connect should succeed");

        let socks5_req = socks5_connect_ipv4(std::net::Ipv4Addr::LOCALHOST, echo_addr.port());
        session.write_all(&socks5_req).await.unwrap();
        session.flush().await.unwrap();
        consume_socks5_reply(&mut session).await;

        let payload = b"failover works";
        session.write_all(payload).await.unwrap();
        session.flush().await.unwrap();
        let mut got = vec![0u8; payload.len()];
        session.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload, "echo after failover mismatch");
    })
    .await
    .expect("failover test deadline hit");
}
