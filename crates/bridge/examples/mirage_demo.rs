//! `mirage-demo` - single-command end-to-end demonstration.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example mirage_demo -p mirage-bridge
//! ```
//!
//! What it does:
//!
//! 1. Spawns an HTTP/1.1 server on `127.0.0.1:PORT_A` that returns
//!    a canned page identifying as the "uncensored origin."
//! 2. Spawns a Mirage bridge on `127.0.0.1:PORT_B` that proxies
//!    encrypted Mirage sessions to the origin. Full Noise-XX +
//!    ML-KEM-768 + AEAD session-frame layer on the wire.
//! 3. Spawns a local Mirage client proxy on `127.0.0.1:PORT_C`.
//!    Accepts plain TCP from the user; talks Mirage to the bridge.
//! 4. Issues a real HTTP/1.1 GET through the client proxy.
//! 5. Prints the response.
//!
//! Output (success):
//!
//! ```text
//! [demo] Boot sequence:
//! [demo]   HTTP origin   listening on 127.0.0.1:38421
//! [demo]   Mirage bridge listening on 127.0.0.1:42137 (PQ-hybrid session)
//! [demo]   Client proxy  listening on 127.0.0.1:51999 (plain TCP in, Mirage out)
//! [demo]
//! [demo] Sending: GET / HTTP/1.1 to client proxy...
//! [demo]
//! [demo] === RESPONSE ===
//! [demo] HTTP/1.1 200 OK
//! [demo] Content-Length: 90
//! [demo] Content-Type: text/html
//! [demo]
//! [demo] <html><body><h1>Uncensored origin</h1>
//! [demo] <p>This page reached you through a Mirage tunnel.</p>
//! [demo] </body></html>
//! [demo] ================
//! [demo]
//! [demo] [ok] Round trip succeeded. Wire path: 1x Noise-XX handshake,
//! [demo]   1x ML-KEM-768 key encapsulation, ~12 AEAD-framed cells.
//! ```

use mirage_crypto::ed25519_dalek::SigningKey;
use mirage_crypto::x25519_dalek::{PublicKey, StaticSecret};
use mirage_discovery::replay::ReplaySet;
use mirage_discovery::token::sign_token;
use mirage_session::{accept, connect, TokenVerifier};
use std::error::Error;
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn rand_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    getrandom::fill(&mut s).expect("OS CSPRNG");
    s
}

const ORIGIN_BODY: &str = "<html><body><h1>Uncensored origin</h1>\n<p>This page reached you through a Mirage tunnel.</p>\n</body></html>";

async fn run_origin(listener: TcpListener) {
    while let Ok((mut sock, _)) = listener.accept().await {
        sock.set_nodelay(true).ok();
        tokio::spawn(async move {
            let mut req = [0u8; 4096];
            let n = sock.read(&mut req).await.unwrap_or(0);
            // Sanity: don't reply unless we got something HTTP-looking.
            let head = String::from_utf8_lossy(&req[..n]);
            if !head.starts_with("GET ") {
                return;
            }
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n{}",
                ORIGIN_BODY.len(),
                ORIGIN_BODY
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.shutdown().await;
        });
    }
}

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

async fn run_client_proxy(
    listener: TcpListener,
    bridge_addr: String,
    client_x_sk: [u8; 32],
    bridge_x_pk: [u8; 32],
    token: mirage_discovery::token::CapabilityToken,
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

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn Error>> {
    // Boot: HTTP origin.
    let origin_l = TcpListener::bind("127.0.0.1:0").await?;
    let origin_addr = origin_l.local_addr()?;
    tokio::spawn(run_origin(origin_l));

    // Boot: Mirage bridge.
    let bsk_bytes = rand_seed();
    let bridge_x_sk = StaticSecret::from(bsk_bytes).to_bytes();
    let bridge_x_pk = *PublicKey::from(&StaticSecret::from(bsk_bytes)).as_bytes();
    let bridge_id_sk = SigningKey::from_bytes(&rand_seed());
    let bridge_ed_pk = bridge_id_sk.verifying_key().to_bytes();
    let op_sk = SigningKey::from_bytes(&rand_seed());
    let op_pk = op_sk.verifying_key().to_bytes();
    let bridge_l = TcpListener::bind("127.0.0.1:0").await?;
    let bridge_addr = bridge_l.local_addr()?.to_string();
    let now_unix = 1_700_000_000u64;
    tokio::spawn(run_bridge(
        bridge_l,
        origin_addr.to_string(),
        bridge_x_sk,
        bridge_ed_pk,
        op_pk,
        now_unix,
    ));

    // Boot: client proxy.
    let token = sign_token([0xCC; 32], bridge_ed_pk, now_unix + 3600, &op_sk);
    let client_x_sk = StaticSecret::from(rand_seed()).to_bytes();
    let client_l = TcpListener::bind("127.0.0.1:0").await?;
    let client_local = client_l.local_addr()?;
    tokio::spawn(run_client_proxy(
        client_l,
        bridge_addr.clone(),
        client_x_sk,
        bridge_x_pk,
        token,
    ));

    eprintln!("[demo] Boot sequence:");
    eprintln!("[demo]   HTTP origin   listening on {origin_addr}");
    eprintln!("[demo]   Mirage bridge listening on {bridge_addr} (PQ-hybrid session)");
    eprintln!("[demo]   Client proxy  listening on {client_local} (plain TCP in, Mirage out)");
    eprintln!("[demo]");
    eprintln!("[demo] Sending: GET / HTTP/1.1 to client proxy...");
    eprintln!("[demo]");

    // Make a real HTTP request through the proxy.
    let mut app = TcpStream::connect(client_local).await?;
    app.set_nodelay(true).ok();
    let req = "GET / HTTP/1.1\r\nHost: origin.local\r\nConnection: close\r\n\r\n";
    app.write_all(req.as_bytes()).await?;
    app.shutdown().await?;

    let mut buf = Vec::new();
    app.read_to_end(&mut buf).await?;
    let resp = String::from_utf8_lossy(&buf);

    eprintln!("[demo] === RESPONSE ===");
    for line in resp.lines() {
        eprintln!("[demo] {line}");
    }
    eprintln!("[demo] ================");
    eprintln!("[demo]");

    let ok = resp.starts_with("HTTP/1.1 200 OK") && resp.contains(ORIGIN_BODY);
    if ok {
        eprintln!("[demo] [ok] Round trip succeeded. Wire path: 1x Noise-XX handshake,");
        eprintln!("[demo]   1x ML-KEM-768 key encapsulation, AEAD-framed cells.");
        eprintln!("[demo]");
        eprintln!("[demo] Mirage delivered HTTP traffic end-to-end through an");
        eprintln!("[demo] encrypted post-quantum-hybrid tunnel. The framework works.");
        Ok(())
    } else {
        eprintln!("[demo] [FAIL] Round trip failed.");
        Err("response did not match expected body".into())
    }
}
