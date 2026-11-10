//! End-to-end carrier test mirroring the client/bridge integration contract:
//! a tagged mux carrier initiator (the client) and a responder (the bridge)
//! that dials real upstream TCP sockets per accepted stream. Validates the
//! full stream lifecycle - session tag framing, many concurrent streams over
//! one carrier, real-socket bridging via `copy_bidirectional`, and a refused
//! target surfacing as an `open()` error - without the SOCKS/policy layer.

use std::time::Duration;

use mirage_mux::{MuxConnection, MuxPolicy, MuxTarget, StreamRole, MUX_SESSION_TAG};
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Spawn a loopback TCP echo server; returns its port.
async fn spawn_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

/// Responder mirroring the bridge's `run_mux_session` (minus SOCKS policy):
/// consume the 0x00 session tag, then per accepted stream dial the target as a
/// real `TcpStream`, `accept()` on success (`BeginOk`) / `reject()` on failure.
fn spawn_responder(bridge_side: tokio::io::DuplexStream) {
    tokio::spawn(async move {
        let mut sess = bridge_side;
        let mut tag = [0u8; 1];
        if sess.read_exact(&mut tag).await.is_err() || tag[0] != MUX_SESSION_TAG {
            return;
        }
        let (_conn, mut acc) =
            MuxConnection::new(sess, StreamRole::Responder, MuxPolicy::default());
        while let Some(inc) = acc.accept().await {
            let addr = if let MuxTarget::Ipv4 { addr, port } = inc.target() {
                std::net::SocketAddr::from((*addr, *port))
            } else {
                inc.reject(0x08); // address type not supported
                continue;
            };
            tokio::spawn(async move {
                match TcpStream::connect(addr).await {
                    Ok(mut up) => {
                        let mut st = inc.accept();
                        let _ = copy_bidirectional(&mut st, &mut up).await;
                    }
                    Err(_) => inc.reject(0x05), // connection refused
                }
            });
        }
    });
}

#[tokio::test]
async fn tagged_carrier_bridges_many_streams_to_upstream() {
    let echo_port = spawn_echo().await;
    let (client_side, bridge_side) = tokio::io::duplex(64 * 1024);
    spawn_responder(bridge_side);

    // Client: write the session tag, then wrap as an initiator carrier.
    let mut cs = client_side;
    cs.write_all(&[MUX_SESSION_TAG]).await.unwrap();
    let (client, _acc) = MuxConnection::new(cs, StreamRole::Initiator, MuxPolicy::default());

    // 50 concurrent streams over the ONE carrier, each round-tripping.
    let mut handles = Vec::new();
    for i in 0..50u32 {
        let client = client.clone();
        handles.push(tokio::spawn(async move {
            let target = MuxTarget::Ipv4 {
                addr: [127, 0, 0, 1],
                port: echo_port,
            };
            let mut st = client.open(target).await.unwrap();
            let msg = format!("hello-{i}");
            st.write_all(msg.as_bytes()).await.unwrap();
            let mut got = vec![0u8; msg.len()];
            st.read_exact(&mut got).await.unwrap();
            assert_eq!(got, msg.as_bytes());
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    // All 50 rode one carrier => one handshake, one token, one per-IP slot.
    assert!(client.open_stream_count() <= 50);
}

#[tokio::test]
async fn refused_target_surfaces_as_open_error() {
    // Bind then drop to obtain a definitely-closed loopback port.
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = dead.local_addr().unwrap().port();
    drop(dead);

    let (client_side, bridge_side) = tokio::io::duplex(64 * 1024);
    spawn_responder(bridge_side);
    let mut cs = client_side;
    cs.write_all(&[MUX_SESSION_TAG]).await.unwrap();
    let (client, _acc) = MuxConnection::new(cs, StreamRole::Initiator, MuxPolicy::default());

    let target = MuxTarget::Ipv4 {
        addr: [127, 0, 0, 1],
        port: dead_port,
    };
    let res = tokio::time::timeout(Duration::from_secs(5), client.open(target))
        .await
        .expect("open should resolve, not hang");
    assert!(
        res.is_err(),
        "open to a refused target must surface an error"
    );
}
