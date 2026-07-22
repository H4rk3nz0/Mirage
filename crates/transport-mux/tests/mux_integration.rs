//! Integration tests for [`mirage_transport_mux`].
//!
//! These tests cover the seven scenarios specified in the crate design:
//!
//! 1. `detect_tls_record_header`
//! 2. `detect_http_get`
//! 3. `detect_http_post`
//! 4. `detect_opaque_unknown`
//! 5. `obfs_auth_routed_correctly`
//! 6. `obfs_garbage_falls_through`
//! 7. `tls_bytes_not_consumed`

use mirage_transport_mux::{detect_kind, MuxConfig, MuxResult, ProtocolKind, ProtocolMux};
use mirage_transport_obfs::{obfs_auth_tag, OBFS_AUTH_LEN};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// Helper: build a loopback TCP pair where one end has data pre-written.

/// Bind a loopback listener, connect a client, write `data` from the
/// client side, and return (`server_stream`, `client_stream`).
async fn loopback_pair_with_data(data: &[u8]) -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let data_owned = data.to_vec();
    let client_task = tokio::spawn(async move {
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&data_owned).await.unwrap();
        client.flush().await.unwrap();
        client
    });

    let (server, _) = listener.accept().await.unwrap();
    let client = client_task.await.unwrap();
    (server, client)
}

/// Returns a [`ProtocolMux`] with obfs enabled and no SS-2022 PSK.
fn mux_obfs_only(pk: [u8; 32]) -> ProtocolMux {
    ProtocolMux::new(MuxConfig {
        bridge_static_pk: pk,
        obfs_secret: None,
        bridge_static_sk: [0u8; 32],
        relay_ss_psk: None,
        ss_psk: None,
        obfs_enabled: true,
        vless_uuid: None,
    })
}

/// Anti-probe: a replayed SS-2022 handshake salt must fall through to cover
/// (Unknown) rather than draw the confirming server response. Craft a valid
/// SS-2022 peek (salt + AEAD length chunk), pre-seed its salt as "already
/// seen", and assert the mux does NOT authenticate it.
#[tokio::test]
async fn ss2022_salt_replay_falls_through_to_cover() {
    use mirage_crypto::chacha20poly1305::aead::Aead;
    use mirage_crypto::chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};

    let psk = [0x42u8; 32];
    let salt = [0x07u8; 16];
    let subkey = mirage_transport_shadowsocks::derive_session_key(&psk, &salt);
    let cipher = ChaCha20Poly1305::new_from_slice(&subkey).unwrap();
    // 2-byte length plaintext at nonce 0 -> 18-byte encrypted length chunk.
    let enc_len = cipher
        .encrypt(&Nonce::from([0u8; 12]), [0u8, 34].as_ref())
        .unwrap();
    let mut peek = Vec::with_capacity(34);
    peek.extend_from_slice(&salt);
    peek.extend_from_slice(&enc_len); // 16 + 18 = 34 = SS2022_MIN_PEEK

    let mux = ProtocolMux::new(MuxConfig {
        bridge_static_pk: [0u8; 32],
        obfs_secret: None,
        bridge_static_sk: [0u8; 32],
        relay_ss_psk: None,
        ss_psk: Some(psk),
        obfs_enabled: false,
        vless_uuid: None,
    });

    let seen = mirage_transport::SeenNonceSet::new(Duration::from_secs(300));
    let mut salt_key = [0u8; 32];
    salt_key[..16].copy_from_slice(&salt);
    assert!(
        seen.check_and_insert(salt_key, std::time::Instant::now()),
        "prime the salt as already-seen"
    );

    let (server, _client) = loopback_pair_with_data(&peek).await;
    let res = mux
        .accept(server, Duration::from_secs(2), &seen)
        .await
        .unwrap();
    assert!(
        matches!(res, MuxResult::Unknown(_)),
        "a replayed SS-2022 salt must fall through to cover, got {res:?}"
    );
}

/// Returns a [`ProtocolMux`] with all transports disabled.
fn mux_disabled() -> ProtocolMux {
    ProtocolMux::new(MuxConfig {
        bridge_static_pk: [0u8; 32],
        obfs_secret: None,
        bridge_static_sk: [0u8; 32],
        relay_ss_psk: None,
        ss_psk: None,
        obfs_enabled: false,
        vless_uuid: None,
    })
}

/// Regression (M6): the mux single-port VLESS pre-filter must read the version
/// byte at offset 0 (spec-faithful order), NOT offset 16. A prior layout put the
/// UUID at bytes 0..16 and version at 16; when the frame was reordered to
/// `[version@0, uuid@1..17]` the pre-filter kept checking offset 16 - a random
/// UUID byte - so ~255/256 of real client frames failed the pre-filter and were
/// cover-forwarded instead of authenticated. This drives the REAL client writer
/// (`vless_client_send_header`) against the mux and asserts authentication, with
/// a UUID whose byte 15 is non-zero (the exact case the offset-16 bug dropped).
#[tokio::test]
async fn vless_prefilter_accepts_real_client_frame() {
    let uuid = [0x11u8; 16]; // byte 15 = 0x11 != 0x00 -> would fail an offset-16 version check
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let uuid_c = uuid;
    let client_task = tokio::spawn(async move {
        let mut c = TcpStream::connect(addr).await.unwrap();
        mirage_transport_vless::vless_client_send_header(&mut c, &uuid_c)
            .await
            .unwrap();
        c.flush().await.unwrap();
        c // keep the connection alive for the duration of the accept
    });
    let (server, _) = listener.accept().await.unwrap();
    let _client = client_task.await.unwrap();

    let mux = ProtocolMux::new(MuxConfig {
        bridge_static_pk: [0u8; 32],
        obfs_secret: None,
        bridge_static_sk: [0u8; 32],
        relay_ss_psk: None,
        ss_psk: None,
        obfs_enabled: false,
        vless_uuid: Some(uuid),
    });
    let seen = mirage_transport::SeenNonceSet::new(Duration::from_secs(300));
    let res = mux
        .accept(server, Duration::from_secs(2), &seen)
        .await
        .unwrap();
    assert!(
        matches!(res, MuxResult::AuthenticatedVless(_)),
        "a spec-order VLESS frame from the real client writer must authenticate via the mux, got {res:?}"
    );
}

/// Regression (C1): a bridge<->bridge relay leg wrapped in SS-2022 (keyed by the
/// relay PSK) must be accepted via `MuxConfig::relay_ss_psk`, so the Mirage
/// session's cleartext `MI` handshake magic never rides the inter-bridge wire.
#[tokio::test]
async fn relay_ss2022_wrap_authenticates_via_mux() {
    // Stand-in for the bridge-crate `derive_relay_ss_psk` (tested there); the mux
    // only needs the dialer's PSK and its `relay_ss_psk` to match.
    let relay_psk = [0x99u8; 32];
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client_task = tokio::spawn(async move {
        let c = TcpStream::connect(addr).await.unwrap();
        // Dial SS-2022 (writes salt + encrypted request header, 0-RTT deferred
        // response). Hold the stream open so the mux can complete server auth.
        let _ss =
            mirage_transport_shadowsocks::ss2022_client_dial(c, &relay_psk, Duration::from_secs(3))
                .await
                .expect("relay ss2022 client dial");
        tokio::time::sleep(Duration::from_millis(300)).await;
    });
    let (server, _) = listener.accept().await.unwrap();

    let mux = ProtocolMux::new(MuxConfig {
        bridge_static_pk: [0u8; 32],
        obfs_secret: None,
        bridge_static_sk: [0u8; 32],
        relay_ss_psk: Some(relay_psk), // accept the relay leg keyed by the relay PSK
        ss_psk: None,
        obfs_enabled: false,
        vless_uuid: None,
    });
    let seen = mirage_transport::SeenNonceSet::new(Duration::from_secs(300));
    let res = mux
        .accept(server, Duration::from_secs(3), &seen)
        .await
        .unwrap();
    assert!(
        matches!(res, MuxResult::AuthenticatedShadowsocks(_, _)),
        "relay leg wrapped in SS-2022 under relay_ss_psk must be accepted, got {res:?}"
    );
    client_task.await.unwrap();
}

// Test 1 - detect_tls_record_header

#[test]
fn detect_tls_record_header() {
    // TLS 1.2 ClientHello outer record header
    let bytes = [0x16u8, 0x03, 0x03, 0x00, 0xf1, 0x01, 0x00, 0x00];
    assert_eq!(detect_kind(&bytes), ProtocolKind::Tls);
}

// Test 2 - detect_http_get

#[test]
fn detect_http_get() {
    let bytes = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    assert_eq!(detect_kind(bytes), ProtocolKind::Http);
}

// Test 3 - detect_http_post

#[test]
fn detect_http_post() {
    let bytes = b"POST /meek HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
    assert_eq!(detect_kind(bytes), ProtocolKind::Http);
}

// Test 4 - detect_opaque_unknown

#[test]
fn detect_opaque_unknown() {
    // High-entropy random-looking bytes - none match TLS or HTTP.
    let bytes = [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe];
    assert_eq!(detect_kind(&bytes), ProtocolKind::OpaqueUnknown);
}

// Test 5 - obfs_auth_routed_correctly

#[tokio::test]
async fn obfs_auth_routed_correctly() {
    let bridge_pk = [0xAAu8; 32];
    let mut nonce = [0u8; 32];
    // Fill with a non-trivial pattern so it doesn't accidentally look like
    // an HTTP verb or TLS header.
    for (i, b) in nonce.iter_mut().enumerate() {
        *b = (i as u8).wrapping_add(0x80);
    }
    let tag = obfs_auth_tag(&bridge_pk, &nonce);

    let mut auth_bytes = [0u8; OBFS_AUTH_LEN];
    auth_bytes[..32].copy_from_slice(&nonce);
    auth_bytes[32..64].copy_from_slice(&tag);

    let (server, _client) = loopback_pair_with_data(&auth_bytes).await;

    let mux = mux_obfs_only(bridge_pk);
    let result = mux
        .accept(
            server,
            Duration::from_secs(5),
            &mirage_transport::SeenNonceSet::new(std::time::Duration::from_secs(60)),
        )
        .await
        .unwrap();

    assert!(
        matches!(result, MuxResult::AuthenticatedObfsTcp(_)),
        "expected AuthenticatedObfsTcp, got {result:?}"
    );
}

// Test 6 - obfs_garbage_falls_through

#[tokio::test]
async fn obfs_garbage_falls_through() {
    // 64 bytes of zeros - will not pass BLAKE3 auth verify.
    let garbage = [0u8; 64];
    let (server, _client) = loopback_pair_with_data(&garbage).await;

    let mux = mux_obfs_only([0x11u8; 32]);
    let result = mux
        .accept(
            server,
            Duration::from_secs(5),
            &mirage_transport::SeenNonceSet::new(std::time::Duration::from_secs(60)),
        )
        .await
        .unwrap();

    assert!(
        matches!(result, MuxResult::Unknown(_)),
        "expected Unknown, got {result:?}"
    );
}

// Test 7 - tls_bytes_not_consumed

#[tokio::test]
async fn tls_bytes_not_consumed() {
    // Construct a minimal TLS-looking byte sequence.
    // Content-type = 0x16, version = 0x03 0x01 (TLS 1.0 compat), length = 0x005a.
    let tls_bytes = [0x16u8, 0x03, 0x01, 0x00, 0x5a, 0x01, 0x00, 0x00];

    let (server, _client) = loopback_pair_with_data(&tls_bytes).await;

    let mux = mux_disabled(); // detection still works regardless of auth config
    let result = mux
        .accept(
            server,
            Duration::from_secs(5),
            &mirage_transport::SeenNonceSet::new(std::time::Duration::from_secs(60)),
        )
        .await
        .unwrap();

    // Verify we got Tls(stream) back.
    let mut stream = match result {
        MuxResult::Tls(s) => s,
        other => panic!("expected Tls, got {other:?}"),
    };

    // The bytes must still be readable from the stream (peek was non-consuming).
    let mut buf = [0u8; 8];
    let n = stream.read(&mut buf).await.unwrap();
    assert!(n >= 2, "should have read at least the TLS header bytes");
    assert_eq!(
        buf[0], 0x16,
        "first byte must still be 0x16 (TLS handshake)"
    );
    assert_eq!(buf[1], 0x03, "second byte must still be 0x03 (TLS version)");
}

// Additional edge-case tests

#[test]
fn detect_http_options() {
    let bytes = b"OPTIONS * HTTP/1.1";
    assert_eq!(detect_kind(bytes), ProtocolKind::Http);
}

#[test]
fn detect_http_connect() {
    let bytes = b"CONNECT host:443 HTTP/1.1";
    assert_eq!(detect_kind(bytes), ProtocolKind::Http);
}

#[test]
fn detect_tls_13_outer_version() {
    // TLS 1.3 still uses 0x0303 in the outer record for compatibility.
    let bytes = [0x16u8, 0x03, 0x03, 0x02, 0x00, 0x01, 0x00, 0x00];
    assert_eq!(detect_kind(&bytes), ProtocolKind::Tls);
}

#[tokio::test(start_paused = true)]
async fn unknown_on_timeout() {
    // A server side that receives no data should time out and return Unknown.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Connect but never send data.
    let _client = TcpStream::connect(addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();

    let mux = mux_disabled();
    let result = mux
        .accept(
            server,
            Duration::from_millis(10),
            &mirage_transport::SeenNonceSet::new(std::time::Duration::from_secs(60)),
        )
        .await
        .unwrap();
    assert!(
        matches!(result, MuxResult::Unknown(_)),
        "expected Unknown on timeout, got {result:?}"
    );
}

#[tokio::test]
async fn http_stream_bytes_not_consumed() {
    let http_bytes = b"GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let (server, _client) = loopback_pair_with_data(http_bytes).await;

    let mux = mux_disabled();
    let result = mux
        .accept(
            server,
            Duration::from_secs(5),
            &mirage_transport::SeenNonceSet::new(std::time::Duration::from_secs(60)),
        )
        .await
        .unwrap();

    let mut stream = match result {
        MuxResult::Http(s) => s,
        other => panic!("expected Http, got {other:?}"),
    };

    // Bytes must still be present after peek.
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"GET ");
}
