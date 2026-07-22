//! Three-hop end-to-end demo: app -> client -> bridge -> upstream.
//!
//! Exercises the same code path a real `mirage-bridge` + `mirage-client`
//! pair uses, but wires them in-process so a single `cargo test` run
//! verifies the full stack without any config files or binaries.
//!
//! Topology:
//!
//! ```text
//!                       TCP loopback          Mirage session         TCP loopback
//!     app_client  ---------------->  client_side  ==============>  bridge_side  ---------------->  upstream (echo)
//!                 <----------------              <==============              <----------------
//! ```
//!
//! Everything except the session-layer encryption is plain TCP on
//! localhost, which is exactly how a user running `mirage-client` on
//! their laptop and `mirage-bridge` on a VPS will look at the wire
//! level.

use mirage_crypto::ed25519_dalek::SigningKey;
use mirage_crypto::x25519_dalek::{PublicKey, StaticSecret};
use mirage_discovery::replay::ReplaySet;
use mirage_discovery::token::{sign_token, CapabilityToken};
use mirage_session::{accept, connect, TokenVerifier};
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn rand_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    getrandom::fill(&mut s).unwrap();
    s
}

/// Tiny echo server. Reads forever, echoes each chunk back. Treats
/// EOF as a clean shutdown.
async fn run_echo_upstream(listener: TcpListener) {
    while let Ok((mut sock, _)) = listener.accept().await {
        sock.set_nodelay(true).ok();
        tokio::spawn(async move {
            let (mut r, mut w) = sock.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
            let _ = w.shutdown().await;
        });
    }
}

/// Bridge side: accept Mirage session from the client, open TCP to
/// the upstream, bidirectionally copy bytes in both directions.
async fn run_bridge(
    listener: TcpListener,
    upstream: String,
    bridge_x_sk: [u8; 32],
    bridge_ed_pk: [u8; 32],
    op_pk: [u8; 32],
    now_unix: u64,
) {
    while let Ok((sock, _)) = listener.accept().await {
        sock.set_nodelay(true).ok();
        let upstream = upstream.clone();
        tokio::spawn(async move {
            let mut rs = ReplaySet::new(64);
            let mut v = TokenVerifier::new(&mut rs, now_unix);
            let mut session = match accept(sock, &bridge_x_sk, &bridge_ed_pk, &op_pk, &mut v).await
            {
                Ok(s) => s,
                Err(_) => return,
            };
            let mut up = match TcpStream::connect(&upstream).await {
                Ok(s) => s,
                Err(_) => return,
            };
            up.set_nodelay(true).ok();
            let _ = copy_bidirectional(&mut session, &mut up).await;
            let _ = session.shutdown().await;
            let _ = up.shutdown().await;
        });
    }
}

/// Client side: accept local app TCP, open Mirage session to bridge,
/// bidirectionally copy bytes.
async fn run_client(
    listener: TcpListener,
    bridge_addr: String,
    client_x_sk: [u8; 32],
    bridge_x_pk: [u8; 32],
    token: CapabilityToken,
) {
    while let Ok((mut local, _)) = listener.accept().await {
        local.set_nodelay(true).ok();
        let bridge_addr = bridge_addr.clone();
        let token = token.clone();
        tokio::spawn(async move {
            let sock = match TcpStream::connect(&bridge_addr).await {
                Ok(s) => s,
                Err(_) => return,
            };
            sock.set_nodelay(true).ok();
            let mut session = match connect(sock, &client_x_sk, &bridge_x_pk, &token).await {
                Ok(s) => s,
                Err(_) => return,
            };
            let _ = copy_bidirectional(&mut local, &mut session).await;
            let _ = session.shutdown().await;
            let _ = local.shutdown().await;
        });
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_hop_echo_localhost() {
    // ---- 1. Boot the upstream echo server ----
    let upstream_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_l.local_addr().unwrap();
    tokio::spawn(run_echo_upstream(upstream_l));

    // ---- 2. Boot the bridge ----
    let bsk_bytes = rand_seed();
    let bridge_x_sk = StaticSecret::from(bsk_bytes).to_bytes();
    let bridge_x_pk = *PublicKey::from(&StaticSecret::from(bsk_bytes)).as_bytes();
    let bridge_id_sk = SigningKey::from_bytes(&rand_seed());
    let bridge_ed_pk = bridge_id_sk.verifying_key().to_bytes();
    let op_sk = SigningKey::from_bytes(&rand_seed());
    let op_pk = op_sk.verifying_key().to_bytes();

    let bridge_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_addr = bridge_l.local_addr().unwrap().to_string();
    let now_unix = 1_700_000_000u64;
    tokio::spawn(run_bridge(
        bridge_l,
        upstream_addr.to_string(),
        bridge_x_sk,
        bridge_ed_pk,
        op_pk,
        now_unix,
    ));

    // ---- 3. Mint a capability token ----
    let token = sign_token([0xCC; 32], bridge_ed_pk, now_unix + 3600, &op_sk);

    // ---- 4. Boot the client ----
    let client_x_sk = StaticSecret::from(rand_seed()).to_bytes();
    let client_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_local_addr = client_l.local_addr().unwrap();
    tokio::spawn(run_client(
        client_l,
        bridge_addr.clone(),
        client_x_sk,
        bridge_x_pk,
        token,
    ));

    // ---- 5. App dials the client's local port, talks to echo ----
    let mut app = TcpStream::connect(client_local_addr).await.unwrap();
    app.set_nodelay(true).ok();

    // Send a mix of small and large messages.
    for payload in [
        vec![b'a'; 1],
        vec![b'b'; 50],
        vec![b'c'; 4096],
        (0..20_000u32).map(|i| (i % 251) as u8).collect(),
    ] {
        let len = (payload.len() as u32).to_be_bytes();
        app.write_all(&len).await.unwrap();
        app.write_all(&payload).await.unwrap();
        app.flush().await.unwrap();

        let mut got_len = [0u8; 4];
        app.read_exact(&mut got_len).await.unwrap();
        assert_eq!(got_len, len);
        let mut got_payload = vec![0u8; payload.len()];
        app.read_exact(&mut got_payload).await.unwrap();
        assert_eq!(
            got_payload,
            payload,
            "echo mismatch at payload size {}",
            payload.len()
        );
    }

    app.shutdown().await.unwrap();
}
