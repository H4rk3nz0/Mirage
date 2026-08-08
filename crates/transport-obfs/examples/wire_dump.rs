//! Dump what obfs-tcp actually puts on the wire, byte for byte.
//!
//! Reads the socket rather than the source: the question "is there a fixed
//! signature at a fixed offset" is answered by what a DPI box would see, not by
//! what the code looks like it does.
use mirage_discovery::wire::Endpoint;
use mirage_transport::{ClientTransport, DialInputs};
use mirage_transport_obfs::ObfsClientTransport;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let mut buf = vec![0u8; 256];
        let mut got = 0;
        // Read until we have the auth plus a session-message prefix.
        while got < 96 {
            match sock.read(&mut buf[got..]).await {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(_) => break,
            }
        }
        buf.truncate(got);
        buf
    });

    let t = ObfsClientTransport;
    let std::net::SocketAddr::V4(v4) = addr else {
        panic!("expected v4")
    };
    let ep = Endpoint::Ipv4 {
        addr: v4.ip().octets(),
        port: v4.port(),
    };
    let inputs = DialInputs {
        endpoint: &ep,
        bridge_static_pk: &[7u8; 32],
        obfs_secret: None,
        deadline: std::time::Duration::from_secs(5),
    };
    let mut stream = t.dial(&inputs).await.expect("dial");

    // Exactly what the session layer sends first: a real message 1.
    let msg1 = mirage_session::wire::Message1 {
        wire_version: 1,
        noise_msg_1: [0u8; mirage_session::wire::NOISE_MSG_1_LEN],
    }
    .encode();
    stream.write_all(&msg1).await.expect("write msg1");
    stream.flush().await.expect("flush");

    let seen = server.await.expect("join");
    println!("captured {} bytes", seen.len());
    println!(
        "bytes[0..8]   {:02X?}   (auth nonce - should look random)",
        &seen[0..8]
    );
    if seen.len() >= 72 {
        println!("bytes[64..72] {:02X?}", &seen[64..72]);
        let magic = &seen[64..66];
        println!(
            "bytes[64..66] as ascii: {:?}",
            String::from_utf8_lossy(magic)
        );
        if magic == b"MI" {
            println!("RESULT: FIXED SIGNATURE PRESENT at offset 64 -> DPI can memcmp this");
            std::process::exit(1);
        }
        println!("RESULT: no fixed magic at offset 64");
    }
}
