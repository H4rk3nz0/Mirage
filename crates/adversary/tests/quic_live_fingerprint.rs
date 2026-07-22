//! Live validation of the `quic_initial` oracle against REAL quinn output.
//!
//! The unit tests pin the decrypter to RFC 9001 Appendix A's vectors. This test
//! closes the loop: it captures an *actual* quinn client Initial off a socket,
//! runs the oracle on it, and asserts (a) it decrypts + parses as genuine QUIC
//! (which is WHY a real quinn flow evades the fully-encrypted-traffic entropy
//! detector), and (b) it exhibits exactly the three quinn-vs-Chrome tells the
//! mimicry fork must close. This is the measured target for that work.

use std::sync::Arc;
use std::time::Duration;

use mirage_adversary::quic_initial::{fingerprint_from_initial, QUIC_V1};

/// rustls verifier that accepts any cert (this is a client-fingerprint test; we
/// never complete the handshake).
#[derive(Debug)]
struct SkipVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &rustls::pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &rustls::pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quinn_initial_decrypts_and_shows_the_quinn_fingerprint() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    // A plain UDP socket standing in for the server: quinn will send its client
    // Initial here, and we capture that datagram raw off the wire.
    let capture = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let capture_addr = capture.local_addr().unwrap();

    // A real, stock quinn client (ALPN h3, skip-verify).
    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify(provider)))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(qcc)));

    // Kick off the connect; quinn's endpoint driver emits the Initial to the
    // capture address. It never gets a response, so it will retransmit - we only
    // need the first datagram.
    let ep = endpoint.clone();
    tokio::spawn(async move {
        if let Ok(connecting) = ep.connect(capture_addr, "example.com") {
            let _ = connecting.await; // fails (no server); irrelevant
        }
    });

    let mut buf = vec![0u8; 2048];
    let (n, _from) = tokio::time::timeout(Duration::from_secs(5), capture.recv_from(&mut buf))
        .await
        .expect("no QUIC Initial captured within 5s")
        .expect("recv_from failed");
    let initial = &buf[..n];

    // The oracle decrypts + fingerprints the REAL quinn Initial from its on-wire
    // DCID + the public Initial salt.
    let fp = fingerprint_from_initial(initial)
        .expect("oracle must decrypt + parse a genuine quinn Initial");

    // (a) It is genuine, parseable QUIC - byte0/version/CID parse, ClientHello
    //     decrypts. This is precisely why a real quinn flow is classified as QUIC
    //     and NOT dropped as a fully-encrypted random blob.
    assert_eq!(fp.version, QUIC_V1);
    assert!(
        !fp.cipher_suites.is_empty(),
        "ClientHello cipher suites parsed"
    );
    assert!(
        fp.alpn.iter().any(|a| a == "h3"),
        "ALPN h3 must be present, got {:?}",
        fp.alpn
    );

    // (b) It shows EXACTLY the quinn-vs-Chrome tells the mimicry fork must fix:
    assert_eq!(
        fp.dcid_len, 20,
        "quinn default initial DCID is 20 bytes; Chrome uses 8"
    );
    assert!(
        !fp.has_grease,
        "rustls emits NO GREASE; Chrome QUIC is GREASE-saturated - the #1 fix"
    );
    assert!(
        fp.has_min_ack_delay,
        "quinn always sends the min_ack_delay draft param; Chrome QUIC v1 does not"
    );

    endpoint.close(0u32.into(), b"done");
}

/// Capture the first Initial from a quinn client built with the Chrome config
/// wins Mirage's h3/hysteria2 transports now apply (8-byte `initial_dst_cid_provider`).
/// Proves the config change actually shrinks the on-wire DCID to Chrome's 8 bytes.
async fn capture_client_initial(config: quinn::ClientConfig) -> Vec<u8> {
    let capture = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let capture_addr = capture.local_addr().unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(config);
    let ep = endpoint.clone();
    tokio::spawn(async move {
        if let Ok(c) = ep.connect(capture_addr, "example.com") {
            let _ = c.await;
        }
    });
    let mut buf = vec![0u8; 2048];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), capture.recv_from(&mut buf))
        .await
        .expect("no Initial captured")
        .expect("recv");
    endpoint.close(0u32.into(), b"done");
    buf[..n].to_vec()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chrome_config_win_produces_8_byte_dcid_on_the_wire() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify(provider)))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let mut config = quinn::ClientConfig::new(Arc::new(qcc));

    // The exact Chrome-alignment win the transports apply.
    config.initial_dst_cid_provider(Arc::new(|| {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).expect("csprng");
        quinn::ConnectionId::new(&b)
    }));

    let initial = capture_client_initial(config).await;
    let fp = fingerprint_from_initial(&initial).expect("parse config'd Initial");
    assert_eq!(
        fp.dcid_len, 8,
        "the initial_dst_cid_provider config win must put an 8-byte DCID on the wire (Chrome), \
         vs stock quinn's 20 asserted above"
    );
    // GREASE + min_ack_delay tells remain (need the fork) - documents the gap.
    assert!(!fp.has_grease);
    assert!(fp.has_min_ack_delay);
}
