// MIRAGE: minimal DTLS client probe for on-the-wire fingerprint capture and
// interop validation. Emits the Chrome-profile ClientHello (default config =>
// offer_chrome_fingerprint), completes the handshake against any DTLS 1.2 peer
// (e.g. `openssl s_server -dtls1_2`), sends one line, prints the echo, exits.
//
//   cargo run --example mirage_dtls_probe -- 127.0.0.1:4444 [srtp]
//
// Pass a second arg "srtp" to also offer use_srtp (the full 6-extension WebRTC
// shape). Without it, the WebRTC-specific use_srtp is omitted (5 extensions) —
// the cipher/sig/groups/record-version fingerprint is identical either way.

use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use util::Conn;
use webrtc_dtls::config::*;
use webrtc_dtls::conn::DTLSConn;
use webrtc_dtls::crypto::Certificate;
use webrtc_dtls::extension::extension_use_srtp::SrtpProtectionProfile;
use webrtc_dtls::Error;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: Vec<String> = std::env::args().collect();
    let server = args.get(1).cloned().unwrap_or_else(|| "127.0.0.1:4444".to_owned());
    let with_srtp = args.get(2).map(|s| s == "srtp").unwrap_or(false);

    let conn = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    conn.connect(&server).await?;
    eprintln!("[probe] connecting to {server} (srtp={with_srtp})..");

    let certificate = Certificate::generate_self_signed(vec!["localhost".to_owned()])?;

    let config = Config {
        certificates: vec![certificate],
        insecure_skip_verify: true,
        extended_master_secret: ExtendedMasterSecretType::Request,
        // Offering SRTP makes this the full 6-extension WebRTC ClientHello.
        srtp_protection_profiles: if with_srtp {
            vec![SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80]
        } else {
            vec![]
        },
        // cipher_suites left empty => offer_chrome_fingerprint kicks in.
        ..Default::default()
    };

    // The ClientHello is emitted inside DTLSConn::new, so even if the handshake
    // does not complete the fingerprint is already on the wire (and captured).
    let dtls = tokio::time::timeout(
        Duration::from_secs(8),
        DTLSConn::new(conn, config, true, None),
    )
    .await;

    match dtls {
        Ok(Ok(dtls_conn)) => {
            // If the server was pinned to a single cipher (e.g. openssl
            // -cipher ECDHE-ECDSA-CHACHA20-POLY1305), a completed handshake
            // proves that suite interoperated with a non-Mirage stack.
            eprintln!("[probe] handshake OK");
            let dc: Arc<dyn Conn + Send + Sync> = Arc::new(dtls_conn);
            let _ = dc.send(b"MIRAGE_DTLS_PROBE\n").await;
            let mut buf = vec![0u8; 2048];
            match tokio::time::timeout(Duration::from_secs(3), dc.recv(&mut buf)).await {
                Ok(Ok(n)) => eprintln!(
                    "[probe] echo {} bytes: {:?}",
                    n,
                    String::from_utf8_lossy(&buf[..n])
                ),
                _ => eprintln!("[probe] no echo (peer may not echo) — handshake still proves interop"),
            }
            eprintln!("[probe] RESULT: HANDSHAKE_OK");
        }
        Ok(Err(e)) => eprintln!("[probe] handshake failed: {e} (ClientHello was still sent — capture is valid)"),
        Err(_) => eprintln!("[probe] handshake timed out (ClientHello was still sent — capture is valid)"),
    }

    Ok(())
}
