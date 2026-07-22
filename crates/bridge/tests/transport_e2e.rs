//! End-to-end integration tests for transport carrier layers.
//!
//! # Topology (all three tests)
//!
//! ```text
//! test_app -TCP-> [transport carrier handshake]
//!                        down carrier stream
//!                 [Mirage session: bridge accept]
//!                        down decrypted
//!                 [SOCKS5 server: serve_one_connect]
//!                        down TCP
//!                 [target: echo server]
//! ```
//!
//! Tests:
//! - `ss2022_round_trip`   - SS-2022 AEAD framing as carrier
//! - `ws_round_trip`       - HTTP/WebSocket upgrade as carrier
//! - `vless_round_trip`    - VLESS 26-byte header auth as carrier

use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use mirage_crypto::ed25519_dalek::SigningKey;
use mirage_crypto::x25519_dalek::{PublicKey, StaticSecret};
use mirage_discovery::replay::SyncReplaySet;
use mirage_discovery::token::{sign_token, CapabilityToken};
use mirage_session::{accept, connect, TokenVerifier};
use mirage_socks5::AllowlistPolicy;
use tokio::io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// Shared test helpers  (re-declared; integration test binaries don't share
// helpers across files)

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

fn test_policy() -> AllowlistPolicy {
    AllowlistPolicy {
        deny_loopback: false,
        deny_private_networks: false,
        allowed_ports: None,
    }
}

fn socks5_connect_ipv4(addr: std::net::Ipv4Addr, port: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(15);
    buf.extend_from_slice(&[0x05, 0x01, 0x00]);
    buf.push(0x05);
    buf.push(0x01);
    buf.push(0x00);
    buf.push(0x01);
    buf.extend_from_slice(&addr.octets());
    buf.extend_from_slice(&port.to_be_bytes());
    buf
}

async fn consume_socks5_reply<S: AsyncRead + Unpin>(s: &mut S) {
    let mut tmp = [0u8; 2];
    s.read_exact(&mut tmp).await.unwrap();
    assert_eq!(tmp, [0x05, 0x00], "expected NO_AUTH method reply");
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05, "expected VER=5 in reply");
    assert_eq!(reply[1], 0x00, "expected REP=SUCCESS in reply");
}

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

/// Run the bridge-side SOCKS5 + copy loop on a stream that has already
/// passed transport-layer auth.  Generic over the accepted stream type.
async fn run_socks5_bridge<S>(session_stream: mirage_session::stream::SessionStream<S>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let policy = test_policy();
    let (_, mut upstream, mut session) =
        match mirage_socks5::serve_one_connect(session_stream, &policy, Duration::from_secs(5))
            .await
        {
            Ok(v) => v,
            Err(_) => return,
        };
    let _ = copy_bidirectional(&mut session, &mut upstream).await;
    let _ = session.shutdown().await;
    let _ = upstream.shutdown().await;
}

// Test 1: ss2022_round_trip

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ss2022_round_trip() {
    let k = Arc::new(fresh_keys());
    let now = 1_700_000_000u64;
    let replay = Arc::new(SyncReplaySet::new(64));

    // Generate a random 32-byte PSK for this test run.
    let psk: [u8; 32] = rand_seed();
    let psk = Arc::new(psk);

    let echo_addr = spawn_echo_server().await;

    // -- Bridge listener --
    let bridge_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_addr = bridge_listener.local_addr().unwrap();

    {
        let k = Arc::clone(&k);
        let replay = Arc::clone(&replay);
        let psk = Arc::clone(&psk);
        tokio::spawn(async move {
            loop {
                let (sock, _) = match bridge_listener.accept().await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                sock.set_nodelay(true).ok();
                let k = Arc::clone(&k);
                let replay = Arc::clone(&replay);
                let psk = Arc::clone(&psk);
                tokio::spawn(async move {
                    // Step 1: SS-2022 carrier handshake.
                    let ss_stream = match mirage_transport_shadowsocks::ss2022_server_auth(
                        sock,
                        &psk,
                        Duration::from_secs(5),
                    )
                    .await
                    {
                        Ok(s) => s,
                        Err(_) => return,
                    };

                    // Step 2: Mirage session handshake over the SS-2022 stream.
                    let mut v = TokenVerifier::new_shared(&replay, now);
                    let session =
                        match accept(ss_stream, &k.bridge_x_sk, &k.bridge_ed_pk, &k.op_pk, &mut v)
                            .await
                        {
                            Ok(s) => s,
                            Err(_) => return,
                        };

                    run_socks5_bridge(session).await;
                });
            }
        });
    }

    let token = issue_token(&k, now);

    tokio::time::timeout(Duration::from_secs(30), async move {
        // Client side: TCP -> SS-2022 handshake -> Mirage session -> SOCKS5.
        let sock = TcpStream::connect(bridge_addr).await.unwrap();
        sock.set_nodelay(true).ok();

        let ss_stream =
            mirage_transport_shadowsocks::ss2022_client_dial(sock, &psk, Duration::from_secs(5))
                .await
                .expect("ss2022 client dial");

        let mut session = connect(ss_stream, &k.client_x_sk, &k.bridge_x_pk, &token)
            .await
            .expect("mirage connect over ss2022");

        // SOCKS5 CONNECT to echo server.
        let socks5_req = socks5_connect_ipv4(std::net::Ipv4Addr::LOCALHOST, echo_addr.port());
        session.write_all(&socks5_req).await.unwrap();
        session.flush().await.unwrap();
        consume_socks5_reply(&mut session).await;

        // Echo round-trip.
        let payload = b"Mirage over Shadowsocks-2022 AEAD framing.";
        session.write_all(payload).await.unwrap();
        session.flush().await.unwrap();
        let mut got = vec![0u8; payload.len()];
        session.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload, "ss2022 echo payload mismatch");

        // Second chunk.
        let payload2 = b"BLAKE3-derived subkeys, counter nonces.";
        session.write_all(payload2).await.unwrap();
        session.flush().await.unwrap();
        let mut got2 = vec![0u8; payload2.len()];
        session.read_exact(&mut got2).await.unwrap();
        assert_eq!(got2, payload2, "ss2022 second echo mismatch");
    })
    .await
    .expect("ss2022_round_trip deadline hit");
}

// Test 2: ws_round_trip

/// Client-side WS upgrade + Mirage auth frame, used only in this test.
///
/// Mirrors what `WsClientTransport::dial` does, but operates on an already-
/// connected TCP stream so we can inspect the bound port.
async fn ws_client_connect(
    mut stream: TcpStream,
    bridge_static_pk: &[u8; 32],
) -> Result<mirage_transport_ws::WsStream<TcpStream>, mirage_transport::TransportError> {
    // Phase 1: Send HTTP/1.1 WebSocket upgrade request. RT #15: the Mirage
    // auth frame rides Sec-WebSocket-Protocol (base64url) so the bridge
    // validates BEFORE replying 101; there is no post-101 auth frame.
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    let auth_frame = mirage_transport_ws::build_auth_frame(bridge_static_pk, None)
        .map_err(mirage_transport::TransportError::Other)?;
    let auth_token = B64URL.encode(auth_frame);
    let raw_key: [u8; 16] = rand_seed()[..16].try_into().unwrap();
    let ws_key = B64.encode(raw_key);
    // Audit #13: the auth token rides in a realistic session Cookie (a long
    // base64url value is ordinary there), and Sec-WebSocket-Protocol offers only
    // a real cover subprotocol - no `v1.bearer.` tell. The bridge scans cookies
    // for the one whose value decodes to a valid auth frame.
    let req = format!(
        "GET /ws HTTP/1.1\r\nHost: test.local\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nCookie: sessionid={auth_token}\r\nSec-WebSocket-Key: {ws_key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(mirage_transport::TransportError::Io)?;
    stream
        .flush()
        .await
        .map_err(mirage_transport::TransportError::Io)?;

    // Phase 2: Read the HTTP 101 Switching Protocols response.
    let mut resp_buf = Vec::with_capacity(256);
    let mut tmp = [0u8; 1];
    loop {
        stream
            .read_exact(&mut tmp)
            .await
            .map_err(mirage_transport::TransportError::Io)?;
        resp_buf.push(tmp[0]);
        if resp_buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if resp_buf.len() > 4096 {
            return Err(mirage_transport::TransportError::Wire(
                "ws: server HTTP response too large",
            ));
        }
    }
    let resp = std::str::from_utf8(&resp_buf)
        .map_err(|_| mirage_transport::TransportError::Wire("ws: non-utf8 in server response"))?;
    if !resp.starts_with("HTTP/1.1 101") {
        return Err(mirage_transport::TransportError::Wire(
            "ws: expected 101 Switching Protocols",
        ));
    }

    // Phase 3: Wrap in WebSocket client role (auth already done pre-101).
    let ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
        stream,
        tokio_tungstenite::tungstenite::protocol::Role::Client,
        None,
    )
    .await;

    Ok(mirage_transport_ws::WsStream::new(ws))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_round_trip() {
    let k = Arc::new(fresh_keys());
    let now = 1_700_000_000u64;
    let replay = Arc::new(SyncReplaySet::new(64));

    let echo_addr = spawn_echo_server().await;

    // -- Bridge listener --
    let bridge_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_addr = bridge_listener.local_addr().unwrap();

    {
        let k = Arc::clone(&k);
        let replay = Arc::clone(&replay);
        tokio::spawn(async move {
            loop {
                let (sock, _) = match bridge_listener.accept().await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                sock.set_nodelay(true).ok();
                let k = Arc::clone(&k);
                let replay = Arc::clone(&replay);
                tokio::spawn(async move {
                    // Step 1: HTTP/WS upgrade + Mirage auth frame.
                    let seen = mirage_transport::SeenNonceSet::new(Duration::from_secs(60));
                    let ws_stream = match mirage_transport_ws::ws_server_auth(
                        sock,
                        &k.bridge_x_pk,
                        None,
                        Duration::from_secs(5),
                        &seen,
                    )
                    .await
                    {
                        Ok(s) => s,
                        Err(_) => return,
                    };

                    // Step 2: Mirage session handshake over the WS stream.
                    let mut v = TokenVerifier::new_shared(&replay, now);
                    let session =
                        match accept(ws_stream, &k.bridge_x_sk, &k.bridge_ed_pk, &k.op_pk, &mut v)
                            .await
                        {
                            Ok(s) => s,
                            Err(_) => return,
                        };

                    run_socks5_bridge(session).await;
                });
            }
        });
    }

    let token = issue_token(&k, now);

    tokio::time::timeout(Duration::from_secs(30), async move {
        // Client: TCP -> HTTP WS upgrade -> Mirage auth frame -> session.
        let sock = TcpStream::connect(bridge_addr).await.unwrap();
        sock.set_nodelay(true).ok();

        let ws_stream = ws_client_connect(sock, &k.bridge_x_pk)
            .await
            .expect("ws client connect");

        let mut session = connect(ws_stream, &k.client_x_sk, &k.bridge_x_pk, &token)
            .await
            .expect("mirage connect over ws");

        // SOCKS5 CONNECT to echo server.
        let socks5_req = socks5_connect_ipv4(std::net::Ipv4Addr::LOCALHOST, echo_addr.port());
        session.write_all(&socks5_req).await.unwrap();
        session.flush().await.unwrap();
        consume_socks5_reply(&mut session).await;

        // Echo round-trip.
        let payload = b"Mirage over WebSocket tunnel.";
        session.write_all(payload).await.unwrap();
        session.flush().await.unwrap();
        let mut got = vec![0u8; payload.len()];
        session.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload, "ws echo payload mismatch");

        // Second chunk.
        let payload2 = b"CDN-fronted, censor-resistant.";
        session.write_all(payload2).await.unwrap();
        session.flush().await.unwrap();
        let mut got2 = vec![0u8; payload2.len()];
        session.read_exact(&mut got2).await.unwrap();
        assert_eq!(got2, payload2, "ws second echo mismatch");
    })
    .await
    .expect("ws_round_trip deadline hit");
}

// Test 4: vless_round_trip

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vless_round_trip() {
    let k = Arc::new(fresh_keys());
    let now = 1_700_000_000u64;
    let replay = Arc::new(SyncReplaySet::new(64));

    // A random UUID for this test client.
    let client_uuid: [u8; 16] = rand_seed()[..16].try_into().unwrap();

    let echo_addr = spawn_echo_server().await;

    // -- Bridge listener --
    let bridge_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_addr = bridge_listener.local_addr().unwrap();

    {
        let k = Arc::clone(&k);
        let replay = Arc::clone(&replay);
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match bridge_listener.accept().await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                sock.set_nodelay(true).ok();
                let k = Arc::clone(&k);
                let replay = Arc::clone(&replay);
                tokio::spawn(async move {
                    // Step 1: Read and validate the 26-byte VLESS auth frame.
                    let config = mirage_transport_vless::VlessConfig {
                        authorized_uuids: vec![client_uuid],
                    };
                    if mirage_transport_vless::vless_server_auth(
                        &mut sock,
                        &config,
                        Duration::from_secs(5),
                    )
                    .await
                    .is_err()
                    {
                        return;
                    }

                    // Step 2: Send the 2-byte VLESS response header.
                    if mirage_transport_vless::vless_server_send_response(&mut sock)
                        .await
                        .is_err()
                    {
                        return;
                    }
                    if sock.flush().await.is_err() {
                        return;
                    }

                    // Step 3: Mirage session handshake over the raw TCP socket
                    // (VLESS adds no additional framing past the header bytes).
                    let mut v = TokenVerifier::new_shared(&replay, now);
                    let session =
                        match accept(sock, &k.bridge_x_sk, &k.bridge_ed_pk, &k.op_pk, &mut v).await
                        {
                            Ok(s) => s,
                            Err(_) => return,
                        };

                    run_socks5_bridge(session).await;
                });
            }
        });
    }

    let token = issue_token(&k, now);

    tokio::time::timeout(Duration::from_secs(30), async move {
        // Client: TCP -> VLESS header -> read server response -> Mirage session.
        let mut sock = TcpStream::connect(bridge_addr).await.unwrap();
        sock.set_nodelay(true).ok();

        // Send the 26-byte VLESS client auth frame.
        mirage_transport_vless::vless_client_send_header(&mut sock, &client_uuid)
            .await
            .expect("vless client send header");
        sock.flush().await.unwrap();

        // Read the 2-byte VLESS server response.
        mirage_transport_vless::vless_client_read_response(&mut sock, Duration::from_secs(5))
            .await
            .expect("vless client read response");

        // Now run the Mirage session handshake on the same TCP socket.
        let mut session = connect(sock, &k.client_x_sk, &k.bridge_x_pk, &token)
            .await
            .expect("mirage connect over vless");

        // SOCKS5 CONNECT to echo server.
        let socks5_req = socks5_connect_ipv4(std::net::Ipv4Addr::LOCALHOST, echo_addr.port());
        session.write_all(&socks5_req).await.unwrap();
        session.flush().await.unwrap();
        consume_socks5_reply(&mut session).await;

        // Echo round-trip.
        let payload = b"Mirage over VLESS UUID auth framing.";
        session.write_all(payload).await.unwrap();
        session.flush().await.unwrap();
        let mut got = vec![0u8; payload.len()];
        session.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload, "vless echo payload mismatch");

        // Second chunk.
        let payload2 = b"No crypto - outer transport handles confidentiality.";
        session.write_all(payload2).await.unwrap();
        session.flush().await.unwrap();
        let mut got2 = vec![0u8; payload2.len()];
        session.read_exact(&mut got2).await.unwrap();
        assert_eq!(got2, payload2, "vless second echo mismatch");
    })
    .await
    .expect("vless_round_trip deadline hit");
}
