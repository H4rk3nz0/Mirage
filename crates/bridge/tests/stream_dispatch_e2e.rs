//! End-to-end: a Mirage session carries a stream BEGIN/DATA/END
//! flow, and the bridge's `TcpStreamDispatcher` opens a real TCP
//! socket to the destination and pumps bytes both ways.
//!
//! Topology:
//!
//! ```text
//!  client                           bridge                     destination
//!  ------                           ------                     -----------
//!   open mirage session  ----->
//!                               (accept)
//!   send CMD_RELAY (BEGIN echo)->
//!                               peel; StreamDispatcher.BEGIN
//!                                    --TcpStream::connect-->
//!                                                            (echo server)
//!   send CMD_RELAY (DATA)------>
//!                               peel; StreamDispatcher.DATA-->
//!                                                            (echoes)
//!                                                           <---
//!                               StreamEvent::Data           <---
//!   read CMD_RELAY (DATA)<------  wrap; send back
//! ```
//!
//! Proves: the stream dispatcher integrates correctly with a
//! real `SessionStream` end-to-end. The bridge is a real
//! `mirage_session::accept`'d session; the destination is a
//! real `TcpListener` echo; the bytes traverse Noise-XX +
//! ML-KEM-768 + AEAD frames + RelaySubCell + TCP.

use mirage_bridge::stream_dispatcher::{
    BeginBody, DataBody, StreamDispatcher, StreamEvent, TcpStreamDispatcher,
    TcpStreamDispatcherConfig,
};
use mirage_circuit::{RelaySubCell, CMD_BEGIN, CMD_DATA, CMD_END};
use mirage_crypto::ed25519_dalek::SigningKey;
use mirage_crypto::x25519_dalek::{PublicKey, StaticSecret};
use mirage_discovery::replay::ReplaySet;
use mirage_discovery::token::sign_token;
use mirage_session::{accept, connect, TokenVerifier};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn rand_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    getrandom::fill(&mut s).unwrap();
    s
}

/// A toy TCP echo server.
async fn echo_server(listener: TcpListener) {
    while let Ok((mut sock, _)) = listener.accept().await {
        sock.set_nodelay(true).ok();
        tokio::spawn(async move {
            let (mut r, mut w) = sock.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
            let _ = w.shutdown().await;
        });
    }
}

/// Length-prefixed framing helpers so a single Mirage session
/// can carry multiple stream sub-cells with deterministic
/// boundaries. The wire shape: `[u16 BE len][bytes]`. The
/// dispatcher uses `RelaySubCell::decode` on the inner bytes.
async fn write_framed<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    sub: &RelaySubCell,
) -> std::io::Result<()> {
    let encoded = sub
        .encode()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e}")))?;
    let len = (encoded.len() as u16).to_be_bytes();
    w.write_all(&len).await?;
    w.write_all(&encoded).await?;
    w.flush().await
}

async fn read_framed<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<RelaySubCell> {
    let mut len = [0u8; 2];
    r.read_exact(&mut len).await?;
    let n = u16::from_be_bytes(len) as usize;
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await?;
    RelaySubCell::decode(&buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e}")))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bridge_dispatches_stream_to_real_tcp() {
    // 1. Boot echo server.
    let echo_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_l.local_addr().unwrap();
    tokio::spawn(echo_server(echo_l));

    // 2. Boot bridge: accept Mirage session, run StreamDispatcher
    //    on inbound sub-cells, pump StreamEvents back out.
    let bsk_bytes = rand_seed();
    let bridge_x_sk = StaticSecret::from(bsk_bytes).to_bytes();
    let bridge_x_pk = *PublicKey::from(&StaticSecret::from(bsk_bytes)).as_bytes();
    let bridge_id_sk = SigningKey::from_bytes(&rand_seed());
    let bridge_ed_pk = bridge_id_sk.verifying_key().to_bytes();
    let op_sk = SigningKey::from_bytes(&rand_seed());
    let op_pk = op_sk.verifying_key().to_bytes();
    let bridge_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_addr = bridge_l.local_addr().unwrap();
    let now_unix = 1_700_000_000u64;

    tokio::spawn(async move {
        let (sock, _) = bridge_l.accept().await.unwrap();
        sock.set_nodelay(true).ok();
        let mut rs = ReplaySet::new(64);
        let mut v = TokenVerifier::new(&mut rs, now_unix);
        let session = accept(sock, &bridge_x_sk, &bridge_ed_pk, &op_pk, &mut v)
            .await
            .unwrap();
        let (mut session_r, mut session_w) = tokio::io::split(session);

        let (dispatcher, mut events_rx) =
            TcpStreamDispatcher::with_config(TcpStreamDispatcherConfig::permissive_for_tests());

        // Pump A: read inbound sub-cells from the client's
        // session, dispatch into the StreamDispatcher.
        let dispatcher_for_reader = std::sync::Arc::new(dispatcher);
        let dispatcher_clone = dispatcher_for_reader.clone();
        let reader_task = tokio::spawn(async move {
            loop {
                let sub = match read_framed(&mut session_r).await {
                    Ok(s) => s,
                    Err(_) => break,
                };
                if let Err(e) = dispatcher_clone.dispatch(&sub.encode().unwrap()).await {
                    eprintln!("dispatcher error: {e}");
                    break;
                }
            }
        });

        // Pump B: drain StreamEvents from the dispatcher, encode
        // as RelaySubCells, send back over the session.
        let writer_task = tokio::spawn(async move {
            while let Some(event) = events_rx.recv().await {
                let sub = match event {
                    StreamEvent::Data { stream_id, bytes } => RelaySubCell {
                        command: CMD_DATA,
                        body: DataBody { stream_id, bytes }.encode(),
                    },
                    StreamEvent::End { stream_id } => RelaySubCell {
                        command: CMD_END,
                        body: mirage_bridge::stream_dispatcher::EndBody { stream_id }
                            .encode()
                            .to_vec(),
                    },
                };
                if write_framed(&mut session_w, &sub).await.is_err() {
                    break;
                }
            }
        });

        let _ = reader_task.await;
        let _ = writer_task.await;
    });

    // 3. Mint client capability token.
    let token = sign_token([0xCC; 32], bridge_ed_pk, now_unix + 3600, &op_sk);

    // 4. Client connects to bridge, runs Mirage handshake.
    let client_x_sk = StaticSecret::from(rand_seed()).to_bytes();
    let sock = TcpStream::connect(bridge_addr).await.unwrap();
    sock.set_nodelay(true).ok();
    let session = connect(sock, &client_x_sk, &bridge_x_pk, &token)
        .await
        .unwrap();
    let (mut session_r, mut session_w) = tokio::io::split(session);

    // 5. Client sends BEGIN to echo server.
    let begin = RelaySubCell {
        command: CMD_BEGIN,
        body: BeginBody {
            stream_id: 7,
            host: echo_addr.ip().to_string(),
            port: echo_addr.port(),
        }
        .encode()
        .unwrap(),
    };
    write_framed(&mut session_w, &begin).await.unwrap();

    // 6. Client sends DATA.
    let payload = b"Mirage end-to-end: BEGIN/DATA/END dispatched through a real session.";
    let data = RelaySubCell {
        command: CMD_DATA,
        body: DataBody {
            stream_id: 7,
            bytes: payload.to_vec(),
        }
        .encode(),
    };
    write_framed(&mut session_w, &data).await.unwrap();

    // 7. Client reads echoed DATA back.
    let mut got = Vec::new();
    while got.len() < payload.len() {
        let sub = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            read_framed(&mut session_r),
        )
        .await
        .expect("timeout reading echoed DATA")
        .expect("framing error");
        if sub.command == CMD_DATA {
            let body = DataBody::decode(&sub.body).unwrap();
            got.extend_from_slice(&body.bytes);
        }
    }
    assert_eq!(got, payload, "echoed payload mismatch");

    // 8. Client sends END.
    let end = RelaySubCell {
        command: CMD_END,
        body: mirage_bridge::stream_dispatcher::EndBody { stream_id: 7 }
            .encode()
            .to_vec(),
    };
    write_framed(&mut session_w, &end).await.unwrap();

    eprintln!("[ok] Stream dispatch end-to-end: real BEGIN/DATA/END flowed through a Mirage session to a real TCP destination");
}
