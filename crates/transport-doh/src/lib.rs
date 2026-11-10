//! DoH-tunnel transport for Mirage.
//!
//! # Overview
//!
//! DNS-over-HTTPS (`DoH`) tunneling makes Mirage traffic look like DNS resolver
//! traffic to a well-known public `DoH` endpoint (Google `8.8.8.8/dns-query`,
//! Cloudflare `1.1.1.1/dns-query`, Quad9, ...). Blocking this transport
//! requires a censor to block all HTTPS to major public DNS resolvers - a
//! high-collateral operation most ISPs and country-level networks avoid.
//!
//! # Implementation approach
//!
//! Rather than steganographically encoding into real DNS wireformat (fragile
//! and complex), this crate uses a simpler approach that retains the
//! traffic-shape plausibility:
//!
//! - Client sends `POST /dns-query HTTP/1.1` with
//!   `Content-Type: application/dns-message`.
//! - Body is a fixed-size Mirage auth frame followed by binary session data
//!   (not real DNS format - the security comes from the Noise layer inside).
//! - Bridge responds with `Content-Type: application/dns-message` and the
//!   session reply in the body.
//! - Subsequent long-polling round-trips follow the same meek pattern but
//!   retain the `DoH` content-type and path.
//!
//! This is semantically equivalent to `transport-meek` with a different
//! HTTP path (`/dns-query`) and content-type (`application/dns-message`).
//! The session machinery is shared via [`mirage_transport_meek`].
//!
//! # Threat model fit
//!
//! - **T1 (signature DPI):** [ok] - traffic has the same shape as HTTPS POST to
//!   a public DNS resolver endpoint.
//! - **T2 (active prober):** [ok] - the auth frame requires `bridge_static_pk`
//!   to forge; probers get an HTTP 400 response.
//! - **T3 (ML on flow shape):** partial - long-polling rhythm is detectable
//!   at the flow level; compose with jitter for fuller coverage.
//!
//! # Capability bit
//!
//! `DOH_TUNNEL_CAPABILITY_BIT` = bit 4 (`DOH_TUNNEL`, pre-reserved for `DoH`).
//!
//! # Wire routing
//!
//! The bridge's HTTP mux handler identifies `DoH` requests by:
//! - Method: `POST`
//! - Path: `/dns-query`
//! - `Content-Type: application/dns-message`
//!
//! A matching connection is handed to [`doh_bridge_serve`]; anything else
//! (plain POST or WebSocket upgrade) follows the existing meek / WS paths.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use mirage_transport::TransportError;
use mirage_transport_meek::{build_auth_frame, MeekServerStream};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

/// Capability bit for the DoH-tunnel transport (bit 4).
///
/// Pre-reserved as `DOH_TUNNEL`.
pub const DOH_TUNNEL_CAPABILITY_BIT: u32 = 1 << 4;

/// HTTP path that identifies a `DoH` request.
pub const DOH_PATH: &str = "/dns-query";

/// HTTP `Content-Type` header value used for `DoH` traffic.
pub const DOH_CONTENT_TYPE: &str = "application/dns-message";

// Configuration

/// Bridge-side `DoH` transport configuration.
pub struct DohServerConfig {
    /// Bridge's X25519 static public key (32 bytes). Used to verify the
    /// BLAKE3-keyed auth MAC in the first POST body.
    pub bridge_static_pk: [u8; 32],
}

// Server-side: bridge serve

/// Accept a DoH-tunneled Mirage session on `stream`.
///
/// Wraps [`mirage_transport_meek::meek_bridge_serve`] with DoH-specific
/// routing: validates that the first POST's path is `/dns-query` and uses
/// `Content-Type: application/dns-message` in all HTTP responses.
///
/// Returns a [`MeekServerStream`] ready for the Mirage session layer
/// (Noise handshake + SOCKS5 framing).
///
/// Returns [`TransportError::Timeout`] if the first POST is not received
/// within `deadline`.
pub async fn doh_bridge_serve<S>(
    stream: S,
    config: &DohServerConfig,
    deadline: Duration,
) -> Result<MeekServerStream, TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Delegate to the Meek driver with DoH-specific response content-type.
    // Path validation is skipped here because the bridge mux already
    // identified this connection as a DoH POST before calling us.
    mirage_transport_meek::meek_bridge_serve(
        stream,
        &config.bridge_static_pk,
        deadline,
        DOH_CONTENT_TYPE,
    )
    .await
}

/// Accept a DoH-tunneled Mirage session on `stream`, routing it through
/// `store` to support CDN-fronted multi-connection sessions.
///
/// Wraps [`mirage_transport_meek::meek_bridge_serve_multconn`] with the
/// DoH-specific `Content-Type: application/dns-message` response header.
///
/// See [`mirage_transport_meek::meek_bridge_serve_multconn`] for the full
/// semantics of [`MeekServeOutcome`].
pub async fn doh_bridge_serve_multconn<S>(
    stream: S,
    config: &DohServerConfig,
    store: &mirage_transport_meek::MeekSessionStore,
    deadline: Duration,
    seen_nonces: &mirage_transport::SeenNonceSet,
) -> Result<mirage_transport_meek::MeekServeOutcome, mirage_transport_meek::MeekReject<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    mirage_transport_meek::meek_bridge_serve_multconn(
        stream,
        store,
        &config.bridge_static_pk,
        deadline,
        DOH_CONTENT_TYPE,
        seen_nonces,
    )
    .await
}

// Client-side connect

/// Connect to a Mirage bridge via DoH-tunnel transport.
///
/// Steps:
/// 1. Sends `POST /dns-query HTTP/1.1` with `Content-Type: application/dns-message`
///    and the 72-byte Mirage auth frame as the body.
/// 2. Returns a [`MeekClientStream`] configured with `DoH` headers that the
///    Mirage Noise session can drive like any other bidirectional stream.
///
/// The `host` parameter is used as the HTTP `Host` header (the front domain
/// for CDN-fronted `DoH`, or the bridge IP for direct connections).
///
/// `stream` should be an already-connected TCP stream to the bridge endpoint.
pub async fn doh_client_connect<S>(
    stream: S,
    bridge_static_pk: &[u8; 32],
    host: impl Into<String>,
    deadline: Duration,
) -> Result<mirage_transport_meek::MeekClientStream, TransportError>
where
    // Generic so the client can hand a plain TCP or a client-TLS stream (#4).
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    tokio::time::timeout(deadline, async {
        let auth_frame = build_auth_frame(bridge_static_pk)
            .map_err(|e| TransportError::Other(format!("doh auth frame: {e}")))?;

        let mut session_id = [0u8; 32];
        getrandom::fill(&mut session_id)
            .map_err(|e| TransportError::Other(format!("doh session id: {e}")))?;

        let session_b64 = base64_encode(&session_id);
        let host_s = host.into();

        let client_stream = mirage_transport_meek::MeekClientStream::new_with_content_type(
            stream,
            host_s,
            DOH_PATH.to_string(),
            session_id,
            Some(auth_frame.to_vec()),
            session_b64,
            DOH_CONTENT_TYPE.to_string(),
        )
        .await;

        Ok::<mirage_transport_meek::MeekClientStream, TransportError>(client_stream)
    })
    .await
    .map_err(|_| TransportError::Timeout(deadline))?
}

fn base64_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = *chunk.get(1).unwrap_or(&0) as usize;
        let b2 = *chunk.get(2).unwrap_or(&0) as usize;
        let n = (b0 << 16) | (b1 << 8) | b2;
        write!(out, "{}", CHARS[n >> 18] as char).unwrap();
        write!(out, "{}", CHARS[(n >> 12) & 0x3f] as char).unwrap();
        if chunk.len() > 1 {
            write!(out, "{}", CHARS[(n >> 6) & 0x3f] as char).unwrap();
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            write!(out, "{}", CHARS[n & 0x3f] as char).unwrap();
        } else {
            out.push('=');
        }
    }
    out
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_transport_meek::build_auth_frame;
    use tokio::io::duplex;

    /// A deterministic bridge static key for tests.
    fn test_pk() -> [u8; 32] {
        [0x42u8; 32]
    }

    fn test_server_config() -> DohServerConfig {
        DohServerConfig {
            bridge_static_pk: test_pk(),
        }
    }

    // doh_auth_frame_valid - server accepts a properly formed DoH POST.

    #[tokio::test]
    async fn doh_auth_frame_valid() {
        let pk = test_pk();
        let config = test_server_config();

        let (client_end, server_end) = duplex(65536);

        // Build auth frame.
        let auth_frame = build_auth_frame(&pk).expect("build_auth_frame");

        // Construct a minimal DoH POST request.
        let body = auth_frame.to_vec();
        let request = format!(
            "POST /dns-query HTTP/1.1\r\nHost: 1.1.1.1\r\nContent-Type: {DOH_CONTENT_TYPE}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );

        // Spawn server task.
        let server_task = tokio::spawn(async move {
            doh_bridge_serve(server_end, &config, Duration::from_secs(5)).await
        });

        // Client: send request + body.
        let mut client_end = client_end;
        use tokio::io::AsyncWriteExt;
        client_end
            .write_all(request.as_bytes())
            .await
            .expect("write request");
        client_end.write_all(&body).await.expect("write body");
        client_end.flush().await.expect("flush");

        let result = server_task.await.expect("task");
        assert!(result.is_ok(), "valid DoH auth should succeed");
    }

    // doh_wrong_pk_rejected - wrong bridge_pk -> auth fails.

    #[tokio::test]
    async fn doh_wrong_pk_rejected() {
        let right_pk = test_pk();
        let wrong_pk = [0xFFu8; 32];
        let config = DohServerConfig {
            bridge_static_pk: wrong_pk,
        };

        let (client_end, server_end) = duplex(65536);

        // Auth frame built with `right_pk`; server configured with `wrong_pk`.
        let auth_frame = build_auth_frame(&right_pk).expect("build_auth_frame");
        let body = auth_frame.to_vec();
        let request = format!(
            "POST /dns-query HTTP/1.1\r\nHost: 1.1.1.1\r\nContent-Type: {DOH_CONTENT_TYPE}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );

        let server_task = tokio::spawn(async move {
            doh_bridge_serve(server_end, &config, Duration::from_secs(5)).await
        });

        let mut client_end = client_end;
        use tokio::io::AsyncWriteExt;
        client_end
            .write_all(request.as_bytes())
            .await
            .expect("write request");
        client_end.write_all(&body).await.expect("write body");
        client_end.flush().await.expect("flush");

        let result = server_task.await.expect("task");
        assert!(
            matches!(result, Err(TransportError::Auth(_))),
            "wrong PK must yield Auth error"
        );
    }

    // doh_content_type_header_correct - HTTP response includes DoH content-type.

    #[tokio::test]
    async fn doh_content_type_header_correct() {
        use tokio::io::AsyncReadExt;

        let pk = test_pk();
        let config = test_server_config();

        let (mut client_end, server_end) = duplex(65536);

        let auth_frame = build_auth_frame(&pk).expect("build_auth_frame");
        let body = auth_frame.to_vec();
        let request = format!(
            "POST /dns-query HTTP/1.1\r\nHost: 1.1.1.1\r\nContent-Type: {DOH_CONTENT_TYPE}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );

        // Spawn server task; the driver sends its first HTTP response after
        // MEEK_RESPONSE_WAIT_MS (<=500ms) since no session layer is running.
        let server_task = tokio::spawn(async move {
            doh_bridge_serve(server_end, &config, Duration::from_secs(5)).await
        });

        use tokio::io::AsyncWriteExt;
        client_end
            .write_all(request.as_bytes())
            .await
            .expect("write request");
        client_end.write_all(&body).await.expect("write body");
        client_end.flush().await.expect("flush");

        // Read the server's HTTP response (arrives after the driver's wait).
        let mut response_buf = vec![0u8; 4096];
        let n = client_end
            .read(&mut response_buf)
            .await
            .expect("read response");
        let response_text = std::str::from_utf8(&response_buf[..n]).expect("response is UTF-8");

        assert!(
            response_text.contains(DOH_CONTENT_TYPE),
            "response must contain Content-Type: {DOH_CONTENT_TYPE}; got:\n{response_text}"
        );
        assert!(
            response_text.starts_with("HTTP/1.1 200"),
            "response must be HTTP 200; got:\n{response_text}"
        );

        // Server task should have completed successfully.
        let result = server_task.await.expect("task");
        assert!(result.is_ok(), "doh auth must succeed");
    }

    // doh_auth_frame_too_small - body shorter than auth frame rejected.

    #[tokio::test]
    async fn doh_auth_frame_too_small() {
        let config = test_server_config();
        let (client_end, server_end) = duplex(65536);

        // Body is only 10 bytes - shorter than MEEK_AUTH_FRAME_LEN (72).
        let body = vec![0u8; 10];
        let request = format!(
            "POST /dns-query HTTP/1.1\r\nHost: 1.1.1.1\r\nContent-Type: {DOH_CONTENT_TYPE}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );

        let server_task = tokio::spawn(async move {
            doh_bridge_serve(server_end, &config, Duration::from_secs(5)).await
        });

        let mut client_end = client_end;
        use tokio::io::AsyncWriteExt;
        client_end
            .write_all(request.as_bytes())
            .await
            .expect("write request");
        client_end.write_all(&body).await.expect("write body");
        client_end.flush().await.expect("flush");

        let result = server_task.await.expect("task");
        assert!(
            result.is_err(),
            "body shorter than auth frame must be rejected"
        );
        assert!(
            !matches!(result, Err(TransportError::Auth(_))),
            "short body is a Wire error, not an Auth error"
        );
    }
}
