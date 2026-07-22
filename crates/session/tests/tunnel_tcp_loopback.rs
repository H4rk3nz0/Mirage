//! End-to-end integration test over real TCP on loopback.
//!
//! Exercises the full stack the way a real bridge and client will:
//!
//! - `tokio::net::TcpListener` binds an OS port.
//! - Bridge task: accepts TCP -> runs [`mirage_session::accept`] ->
//!   echoes decrypted bytes back over the session.
//! - Client task: `tokio::net::TcpStream::connect` -> runs
//!   [`mirage_session::connect`] -> writes and expects echo.
//!
//! This is the first test that validates the byte path all the way
//! down to the kernel socket buffers. Any framing or flushing bug
//! not caught by the in-memory duplex tests surfaces here.

use mirage_crypto::ed25519_dalek::SigningKey;
use mirage_crypto::x25519_dalek::{PublicKey, StaticSecret};
use mirage_discovery::replay::ReplaySet;
use mirage_discovery::token::{sign_token, CapabilityToken};
use mirage_session::{accept, connect, TokenVerifier};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    let bsk = StaticSecret::from(rand_seed());
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
    sign_token([0xCC; 32], k.bridge_ed_pk, now + 3600, &k.op_sk)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn echo_over_real_tcp_localhost() {
    let k = fresh_keys();
    let now = 1_700_000_000u64;
    let token = issue_token(&k, now);

    // Bridge: bind, accept one connection, echo 1024 bytes.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bind_addr = listener.local_addr().unwrap();

    let bridge_task = {
        let bridge_x_sk = k.bridge_x_sk;
        let bridge_ed_pk = k.bridge_ed_pk;
        let op_pk = k.op_pk;
        tokio::spawn(async move {
            let (sock, _peer) = listener.accept().await.unwrap();
            sock.set_nodelay(true).unwrap();
            let mut rs = ReplaySet::new(16);
            let mut v = TokenVerifier::new(&mut rs, now);
            let mut session = accept(sock, &bridge_x_sk, &bridge_ed_pk, &op_pk, &mut v)
                .await
                .expect("bridge accept");

            // Echo 3 packets of varied sizes, then EOF on peer close.
            for _ in 0..3 {
                let mut len_buf = [0u8; 4];
                session.read_exact(&mut len_buf).await.unwrap();
                let n = u32::from_be_bytes(len_buf) as usize;
                let mut payload = vec![0u8; n];
                session.read_exact(&mut payload).await.unwrap();
                session.write_all(&len_buf).await.unwrap();
                session.write_all(&payload).await.unwrap();
                session.flush().await.unwrap();
            }
        })
    };

    // Client: connect, handshake, send 3 packets, verify echo.
    let client_task = {
        let client_x_sk = k.client_x_sk;
        let bridge_x_pk = k.bridge_x_pk;
        let token = token.clone();
        tokio::spawn(async move {
            let sock = TcpStream::connect(bind_addr).await.unwrap();
            sock.set_nodelay(true).unwrap();
            let mut session = connect(sock, &client_x_sk, &bridge_x_pk, &token)
                .await
                .expect("client connect");

            for size in [1usize, 100, 50_000] {
                let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
                let len_buf = (payload.len() as u32).to_be_bytes();
                session.write_all(&len_buf).await.unwrap();
                session.write_all(&payload).await.unwrap();
                session.flush().await.unwrap();

                let mut got_len = [0u8; 4];
                session.read_exact(&mut got_len).await.unwrap();
                assert_eq!(got_len, len_buf);
                let mut got_payload = vec![0u8; size];
                session.read_exact(&mut got_payload).await.unwrap();
                assert_eq!(got_payload, payload, "echo mismatch at size {size}");
            }
        })
    };

    // Tight overall deadline guards against the handshake silently
    // hanging in a future refactor.
    let joined = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        client_task.await.unwrap();
        bridge_task.await.unwrap();
    })
    .await;
    joined.expect("test deadline hit - handshake or echo hung");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hostile_client_without_token_is_rejected() {
    // A random peer on the wire who doesn't have a valid capability
    // token can probe the bridge. Spec §02 §11.3: bridge MUST reject
    // the 67-byte no-token msg 3 form. We don't bother running the
    // full Noise handshake with a malicious client; instead, we
    // verify that a bridge's `accept` times out if the peer sends
    // garbage bytes on the wire.
    let k = fresh_keys();
    let now = 1_700_000_000u64;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bind_addr = listener.local_addr().unwrap();

    let bridge_task = {
        let bridge_x_sk = k.bridge_x_sk;
        let bridge_ed_pk = k.bridge_ed_pk;
        let op_pk = k.op_pk;
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut rs = ReplaySet::new(16);
            let mut v = TokenVerifier::new(&mut rs, now);
            let res = accept(sock, &bridge_x_sk, &bridge_ed_pk, &op_pk, &mut v).await;
            assert!(res.is_err(), "bridge must reject garbage handshake");
        })
    };

    let hostile_task = tokio::spawn(async move {
        let mut sock = TcpStream::connect(bind_addr).await.unwrap();
        // Send 2 KiB of /dev/urandom-style noise - will not parse as a
        // valid MSG_1.
        let mut junk = vec![0u8; 2048];
        getrandom::fill(&mut junk).unwrap();
        sock.write_all(&junk).await.ok();
        let _ = sock.shutdown().await;
    });

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        hostile_task.await.unwrap();
        bridge_task.await.unwrap();
    })
    .await
    .expect("hostile-client test deadline hit");
}
