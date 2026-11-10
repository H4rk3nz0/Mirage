//! VLESS framing transport for Mirage.
//!
//! # Overview
//!
//! VLESS is a lightweight framing layer that provides UUID-based client
//! authentication with **no crypto of its own**.  All confidentiality and
//! integrity protection comes from the outer transport that carries the
//! VLESS stream - typically Reality TLS or WebSocket-over-TLS.
//!
//! Because the auth is just a UUID lookup, this crate is **fully
//! implemented** at the framing level.  Only the outer transport (not this
//! crate) needs the heavy crypto.
//!
//! # Wire format
//!
//! The VLESS inner stream is carried over an already-established outer
//! transport stream (Reality TLS, WebSocket, ...).  The first bytes in each
//! direction are:
//!
//! ```text
//! Client -> Bridge  (auth frame, 26 bytes fixed, spec-faithful field order):
//!   version[1]     = 0x00
//!   uuid[16]       Client UUID credential (128-bit)
//!   addon_len[1]   = 0x00  (no extensions for Mirage use)
//!   command[1]     = 0x01  (TCP)
//!   port[2]        BE u16 = magic dest port  (derived from the uuid)
//!   atyp[1]        = 0x01  (IPv4)
//!   addr[4]        = magic dest addr (derived from the uuid, 198.18.0.0/15)
//!
//!   [Mirage session bytes follow immediately]
//!
//! Bridge -> Client  (response header, 2 bytes fixed):
//!   version[1]     = 0x00
//!   addon_len[1]   = 0x00
//!
//!   [Mirage session bytes follow immediately]
//! ```
//!
//! The magic destination (`addr:port`) is where a real VLESS request carries
//! the client's varying target host:port; a Mirage carrier has no real target,
//! so it embeds a sentinel. Rather than a fixed cross-bridge constant (the
//! former `127.0.0.2:8192`, an exact-match Mirage tell after any outer-layer
//! compromise - audit #27) the sentinel is *derived per credential* from the
//! UUID via [`derive_vless_magic`]: both ends already share the UUID, so they
//! agree without any extra exchange, and different UUIDs (hence different
//! bridges/clients) carry different values. Bridges MUST reject frames whose
//! magic does not match the value derived from the presented (authorized) UUID.
//!
//! # Validation rules (server-side)
//!
//! [`vless_server_auth`] validates:
//! 1. `uuid` is in the bridge's `authorized_uuids` set.
//! 2. `version == 0x00`.
//! 3. `addon_len == 0x00`.
//! 4. `command == 0x01` (TCP).
//! 5. `atyp == 0x01` (IPv4).
//! 6. `port` and `addr` equal `derive_vless_magic(uuid)` for that UUID.
//!
//! Any failure returns [`TransportError::Auth`] without signalling the
//! remote peer - the outer transport falls through to cover-service behavior.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use mirage_transport::TransportError;
use std::time::Duration;
use subtle::ConstantTimeEq as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Capability bit for VLESS (bit 9).
/// Operators stamp this into `transport_caps` in their announcement to
/// signal they accept VLESS-framed connections.
pub const VLESS_CAPABILITY_BIT: u32 = 1 << 9;

/// VLESS protocol version byte (always 0x00 in Mirage use).
pub const VLESS_VERSION: u8 = 0x00;

/// VLESS command byte: TCP forward.
pub const VLESS_COMMAND_TCP: u8 = 0x01;

/// VLESS address type byte: IPv4.
pub const VLESS_ATYP_IPV4: u8 = 0x01;

/// BLAKE3 domain-separation label for the per-credential magic destination KDF.
const VLESS_MAGIC_LABEL: &str = "mirage vless magic dest v1";

/// Derive the per-credential "magic" destination (IPv4 address + port) that the
/// VLESS auth frame carries where a real VLESS request carries the client's
/// varying target host:port (audit #27).
///
/// A hard-coded constant (the former `127.0.0.2:8192`) was an exact-match value
/// *identical across every bridge*: after any outer-layer compromise it is a
/// cross-bridge Mirage fingerprint. Deriving it from the UUID - the credential
/// both client and bridge already share at this layer - gives each credential a
/// distinct value while both ends still agree without any extra wire exchange.
/// (The VLESS layer does not hold the bridge static pubkey, so the UUID is the
/// shared secret to key off; the derivation is one-way, so exposing the magic
/// after an outer-layer compromise does not reveal the UUID.) The value never
/// appears in cleartext (the outer transport encrypts the frame) and the bridge
/// never dials it - it is only a sentinel - so it is mapped into the
/// non-routable RFC 2544 benchmarking range `198.18.0.0/15`.
#[must_use]
pub fn derive_vless_magic(uuid: &[u8; 16]) -> ([u8; 4], u16) {
    // Array-destructure (no indexing) the first bytes of the KDF output.
    let [b0, b1, b2, b3, b4, b5, b6, ..] =
        mirage_crypto::blake3::derive_key(VLESS_MAGIC_LABEL, uuid);
    // 198.18.0.0/15 (RFC 2544, non-routable): 2 * 256 * 256 distinct addresses.
    let addr = [198, 18 | (b0 & 0x01), b1, b2];
    // Port in 1024..=65535: non-zero and unprivileged (a plausible dest port).
    // Reduce modulo bias by drawing a 32-bit dividend: 2^32 % 64512 leaves a
    // ~1.5e-5 non-uniformity vs the ~1.5% that a 16-bit dividend produced
    // (65536 % 64512 = 1024, doubling ports 1024..2047).
    let port = 1024 + (u32::from_be_bytes([b3, b4, b5, b6]) % (65535 - 1024 + 1)) as u16;
    (addr, port)
}

/// Total byte length of the client auth frame:
/// `uuid(16) + version(1) + addon_len(1) + command(1) + port(2) + atyp(1) + addr(4) = 26`.
pub const VLESS_CLIENT_FRAME_LEN: usize = 26;

/// Total byte length of the server response header:
/// `version(1) + addon_len(1) = 2`.
pub const VLESS_SERVER_RESPONSE_LEN: usize = 2;

// Configuration

/// Bridge-side VLESS configuration.
///
/// Lists the set of UUID credentials the bridge will accept.  A client whose
/// UUID is not in this set receives [`TransportError::Auth`].
pub struct VlessConfig {
    /// Authorized client UUIDs.  Each entry is a 16-byte raw UUID (the
    /// binary representation - no hyphens, no `{}`).
    pub authorized_uuids: Vec<[u8; 16]>,
}

// Client-side framing helpers

/// Send the VLESS client auth frame on an already-established outer transport
/// stream.
///
/// Writes the fixed 26-byte frame (spec-faithful field order, version first):
/// `0x00 || uuid[16] || 0x00 || 0x01 || magic_port_be[2] || 0x01 || magic_addr[4]`
/// where the magic destination is [`derive_vless_magic`]`(client_uuid)`.
///
/// Does NOT flush - callers may pipeline session bytes immediately after and
/// flush once.
pub async fn vless_client_send_header<S>(
    stream: &mut S,
    client_uuid: &[u8; 16],
) -> Result<(), TransportError>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let (magic_addr, magic_port) = derive_vless_magic(client_uuid);
    let mut frame = [0u8; VLESS_CLIENT_FRAME_LEN];
    // Spec-faithful VLESS request order: version[0] || uuid[1..17] || addon_len[17].
    // Putting the version first makes byte 0 deterministically 0x00 (matching real
    // Xray VLESS) instead of a random UUID byte - closing a post-compromise
    // distinguisher (audit #27) without adding any new tell.
    frame[0] = VLESS_VERSION; // version
    frame[1..17].copy_from_slice(client_uuid);
    frame[17] = 0x00; // addon_len
    frame[18] = VLESS_COMMAND_TCP;
    let port_bytes = magic_port.to_be_bytes();
    frame[19] = port_bytes[0];
    frame[20] = port_bytes[1];
    frame[21] = VLESS_ATYP_IPV4;
    frame[22..26].copy_from_slice(&magic_addr);
    stream.write_all(&frame).await.map_err(TransportError::Io)
}

/// Read and validate the VLESS client auth frame from `stream`.
///
/// On success the stream is positioned at byte 27 (just past the auth frame),
/// ready for Mirage session bytes.
///
/// Validates all fields against their expected constants and checks the UUID
/// against `config.authorized_uuids`.  Any mismatch returns
/// [`TransportError::Auth`] without leaking which field failed.
///
/// The `deadline` is applied to the read operation.  Returns
/// [`TransportError::Timeout`] if the peer does not send the full frame
/// within the deadline.
pub async fn vless_server_auth<S>(
    stream: &mut S,
    config: &VlessConfig,
    deadline: Duration,
) -> Result<(), TransportError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut frame = [0u8; VLESS_CLIENT_FRAME_LEN];
    tokio::time::timeout(deadline, stream.read_exact(&mut frame))
        .await
        .map_err(|_| TransportError::Timeout(deadline))?
        .map_err(TransportError::Io)?;

    if vless_frame_authorized(config, &frame) {
        Ok(())
    } else {
        Err(TransportError::Auth("vless auth failed"))
    }
}

/// Validate a complete VLESS client frame (UUID + all structural fields).
/// Shared by the consuming [`vless_server_auth`] and the non-consuming
/// [`vless_server_peek_auth`]. `frame` MUST be at least
/// [`VLESS_CLIENT_FRAME_LEN`] bytes; only the first that many are read.
///
/// All field checks are combined before returning so timing does not reveal
/// which specific field failed.
fn vless_frame_authorized(config: &VlessConfig, frame: &[u8]) -> bool {
    if frame.len() < VLESS_CLIENT_FRAME_LEN {
        return false;
    }
    // Spec-faithful order: version[0] || uuid[1..17] || addon_len[17].
    let version = frame[0];
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&frame[1..17]);
    let addon_len = frame[17];
    let command = frame[18];
    let port = u16::from_be_bytes([frame[19], frame[20]]);
    let atyp = frame[21];
    let mut addr = [0u8; 4];
    addr.copy_from_slice(&frame[22..26]);

    // Constant-time credential check: the UUID is the auth secret, so a
    // data-dependent early-exit (`==` / `.any(...)`) would leak, via response
    // timing, how many leading bytes of a guessed UUID matched an authorized
    // one. Compare every authorized UUID over its fixed 16 bytes and OR the
    // results together without short-circuiting.
    //
    // The magic destination is now derived per-credential (audit #27), so it is
    // folded INTO this loop: a frame is credentialed iff, for some authorized
    // UUID, the frame's UUID matches AND its magic addr/port equal the value
    // derived from that same UUID. Each iteration does identical work (one
    // derive + three constant-time compares) regardless of the outcome, so the
    // per-credential magic check adds no data-dependent branch.
    let mut cred_match = subtle::Choice::from(0u8);
    for authorized in &config.authorized_uuids {
        let (exp_addr, exp_port) = derive_vless_magic(authorized);
        let uuid_eq = authorized.ct_eq(&uuid);
        let addr_eq = exp_addr.ct_eq(&addr);
        let port_eq = exp_port.ct_eq(&port);
        cred_match |= uuid_eq & addr_eq & port_eq;
    }
    let cred_ok = bool::from(cred_match);
    let structural_ok = version == VLESS_VERSION
        && addon_len == 0x00
        && command == VLESS_COMMAND_TCP
        && atyp == VLESS_ATYP_IPV4;

    cred_ok && structural_ok
}

/// Non-consuming pre-classifier: is `peeked` an authorized VLESS client
/// frame? The entire VLESS auth lives in the fixed
/// [`VLESS_CLIENT_FRAME_LEN`]-byte frame, so a single-port mux can validate
/// it from **peeked** bytes and only consume the frame on success. A probe
/// with a wrong UUID (or any non-VLESS opaque bytes that happened to match
/// the structural pre-filter) then falls through with its bytes intact and
/// is cover-forwarded like every other rejected probe - instead of having
/// its first 26 bytes consumed and the truncated remainder spliced to the
/// decoy (RT #2). The UUID is the credential, so only a holder of it passes.
#[must_use = "dropping the auth result silently accepts an unauthorized VLESS client"]
pub fn vless_server_peek_auth(config: &VlessConfig, peeked: &[u8]) -> bool {
    vless_frame_authorized(config, peeked)
}

/// Send the VLESS server response header on `stream`.
///
/// Writes the fixed 2-byte response: `version(0x00) || addon_len(0x00)`.
/// The caller sends Mirage session bytes immediately after.
///
/// **Not used on the live Mirage path (F21 0-RTT):** the bridge no longer emits
/// a standalone response - even enveloped in the outer transport it read as a
/// tiny server-first record + an extra RTT. Retained for strict VLESS-interop
/// and unit tests. A faithful VLESS server prepends these 2 bytes to the FIRST
/// downstream data frame, never as a lone record.
pub async fn vless_server_send_response<S>(stream: &mut S) -> Result<(), TransportError>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let response = [VLESS_VERSION, 0x00];
    stream
        .write_all(&response)
        .await
        .map_err(TransportError::Io)
}

/// Read the VLESS server response header from `stream`.
///
/// Validates `version == 0x00` and `addon_len == 0x00`.
/// Returns [`TransportError::Wire`] if either field is unexpected.
///
/// **Not used on the live Mirage path (F21 0-RTT):** the client no longer
/// blocks on a response - it pipelines Noise msg1 directly after the header.
/// Retained for strict VLESS-interop and unit tests.
pub async fn vless_client_read_response<S>(
    stream: &mut S,
    deadline: Duration,
) -> Result<(), TransportError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut response = [0u8; VLESS_SERVER_RESPONSE_LEN];
    tokio::time::timeout(deadline, stream.read_exact(&mut response))
        .await
        .map_err(|_| TransportError::Timeout(deadline))?
        .map_err(TransportError::Io)?;
    if response[0] != VLESS_VERSION {
        return Err(TransportError::Wire(
            "vless: unexpected server version byte",
        ));
    }
    if response[1] != 0x00 {
        return Err(TransportError::Wire("vless: unexpected server addon_len"));
    }
    Ok(())
}

// VLESS is composed at the session layer AFTER an outer transport (Reality
// TLS / WebSocket) has dialed and established a `DuplexStream`: callers invoke
// `vless_client_send_header` / `vless_server_auth` on that stream directly.
// There is deliberately no standalone `ClientTransport` impl - it would either
// duplicate the outer transport's dial logic or couple VLESS to one specific
// carrier, both of which the free-function composition avoids.

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn test_uuid() -> [u8; 16] {
        [
            0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4,
            0x30, 0xc8,
        ]
    }

    fn test_config(uuids: &[[u8; 16]]) -> VlessConfig {
        VlessConfig {
            authorized_uuids: uuids.to_vec(),
        }
    }

    // vless_header_round_trip

    #[tokio::test]
    async fn vless_header_round_trip() {
        let uuid = test_uuid();
        let config = test_config(&[uuid]);

        let (mut client_end, mut server_end) = duplex(256);

        // Client sends header.
        vless_client_send_header(&mut client_end, &uuid)
            .await
            .expect("client header write must succeed");
        client_end.flush().await.expect("flush");

        // Server reads and validates.
        vless_server_auth(&mut server_end, &config, Duration::from_secs(1))
            .await
            .expect("server auth must accept valid UUID");
    }

    /// RT #2: the non-consuming peek classifier accepts a valid frame
    /// (even with trailing bytes), and rejects a wrong UUID / short buffer
    /// WITHOUT consuming - so a failed probe can fall through to cover.
    #[test]
    fn peek_auth_accepts_valid_rejects_others() {
        let uuid = test_uuid();
        let config = test_config(&[uuid]);
        let (magic_addr, magic_port) = derive_vless_magic(&uuid);
        let mut frame = [0u8; VLESS_CLIENT_FRAME_LEN];
        frame[0] = VLESS_VERSION;
        frame[1..17].copy_from_slice(&uuid);
        frame[17] = 0x00;
        frame[18] = VLESS_COMMAND_TCP;
        frame[19..21].copy_from_slice(&magic_port.to_be_bytes());
        frame[21] = VLESS_ATYP_IPV4;
        frame[22..26].copy_from_slice(&magic_addr);

        assert!(vless_server_peek_auth(&config, &frame));
        // Trailing bytes (a real peek sees more than the frame) still validate.
        let mut padded = frame.to_vec();
        padded.extend_from_slice(&[0xABu8; 12]);
        assert!(vless_server_peek_auth(&config, &padded));
        // Wrong UUID -> reject (the probe falls through to cover).
        let mut bad = frame;
        bad[0] ^= 0x01;
        assert!(!vless_server_peek_auth(&config, &bad));
        // Too few bytes -> reject, no panic.
        assert!(!vless_server_peek_auth(&config, &frame[..10]));
    }

    // vless_rejects_wrong_uuid

    #[tokio::test]
    async fn vless_rejects_wrong_uuid() {
        let good_uuid = test_uuid();
        let bad_uuid = [0xFFu8; 16];
        let config = test_config(&[good_uuid]);

        let (mut client_end, mut server_end) = duplex(256);

        vless_client_send_header(&mut client_end, &bad_uuid)
            .await
            .expect("client write must succeed");
        client_end.flush().await.expect("flush");

        let result = vless_server_auth(&mut server_end, &config, Duration::from_secs(1)).await;
        assert!(
            matches!(result, Err(TransportError::Auth(_))),
            "wrong UUID must yield Auth error; got {result:?}"
        );
    }

    // vless_rejects_wrong_command

    #[tokio::test]
    async fn vless_rejects_wrong_command() {
        let uuid = test_uuid();
        let config = test_config(&[uuid]);

        let (mut client_end, mut server_end) = duplex(256);

        // Build frame with command = 0x02 (UDP) instead of 0x01 (TCP).
        let (magic_addr, magic_port) = derive_vless_magic(&uuid);
        let mut frame = [0u8; VLESS_CLIENT_FRAME_LEN];
        frame[0] = VLESS_VERSION;
        frame[1..17].copy_from_slice(&uuid);
        frame[17] = 0x00; // addon_len
        frame[18] = 0x02; // <-- wrong command (UDP)
        let port_bytes = magic_port.to_be_bytes();
        frame[19] = port_bytes[0];
        frame[20] = port_bytes[1];
        frame[21] = VLESS_ATYP_IPV4;
        frame[22..26].copy_from_slice(&magic_addr);

        client_end.write_all(&frame).await.expect("write");
        client_end.flush().await.expect("flush");

        let result = vless_server_auth(&mut server_end, &config, Duration::from_secs(1)).await;
        assert!(
            matches!(result, Err(TransportError::Auth(_))),
            "wrong command must yield Auth error; got {result:?}"
        );
    }

    // vless_rejects_wrong_addr

    #[tokio::test]
    async fn vless_rejects_wrong_addr() {
        let uuid = test_uuid();
        let config = test_config(&[uuid]);

        let (mut client_end, mut server_end) = duplex(256);

        let (_magic_addr, magic_port) = derive_vless_magic(&uuid);
        let mut frame = [0u8; VLESS_CLIENT_FRAME_LEN];
        frame[0] = VLESS_VERSION;
        frame[1..17].copy_from_slice(&uuid);
        frame[17] = 0x00;
        frame[18] = VLESS_COMMAND_TCP;
        let port_bytes = magic_port.to_be_bytes();
        frame[19] = port_bytes[0];
        frame[20] = port_bytes[1];
        frame[21] = VLESS_ATYP_IPV4;
        frame[22..26].copy_from_slice(&[10, 0, 0, 1]); // <-- wrong addr

        client_end.write_all(&frame).await.expect("write");
        client_end.flush().await.expect("flush");

        let result = vless_server_auth(&mut server_end, &config, Duration::from_secs(1)).await;
        assert!(
            matches!(result, Err(TransportError::Auth(_))),
            "wrong addr must yield Auth error; got {result:?}"
        );
    }

    // vless_rejects_wrong_port

    #[tokio::test]
    async fn vless_rejects_wrong_port() {
        let uuid = test_uuid();
        let config = test_config(&[uuid]);

        let (mut client_end, mut server_end) = duplex(256);

        let (magic_addr, _magic_port) = derive_vless_magic(&uuid);
        let mut frame = [0u8; VLESS_CLIENT_FRAME_LEN];
        frame[0] = VLESS_VERSION;
        frame[1..17].copy_from_slice(&uuid);
        frame[17] = 0x00;
        frame[18] = VLESS_COMMAND_TCP;
        // Port 443 (0x01BB): < 1024, so never equal to a derived magic port.
        frame[19] = 0x01;
        frame[20] = 0xBB;
        frame[21] = VLESS_ATYP_IPV4;
        frame[22..26].copy_from_slice(&magic_addr);

        client_end.write_all(&frame).await.expect("write");
        client_end.flush().await.expect("flush");

        let result = vless_server_auth(&mut server_end, &config, Duration::from_secs(1)).await;
        assert!(
            matches!(result, Err(TransportError::Auth(_))),
            "wrong port must yield Auth error; got {result:?}"
        );
    }

    // vless_server_response_header

    #[tokio::test]
    async fn vless_server_response_header() {
        let (mut server_end, mut client_end) = duplex(256);

        vless_server_send_response(&mut server_end)
            .await
            .expect("server response write must succeed");
        server_end.flush().await.expect("flush");

        let mut buf = [0u8; VLESS_SERVER_RESPONSE_LEN];
        client_end
            .read_exact(&mut buf)
            .await
            .expect("client read response");
        assert_eq!(buf[0], VLESS_VERSION, "response version byte must be 0x00");
        assert_eq!(buf[1], 0x00, "response addon_len must be 0x00");
    }

    // Correctness checks

    #[test]
    fn constants_have_expected_values() {
        assert_eq!(VLESS_VERSION, 0x00);
        assert_eq!(VLESS_COMMAND_TCP, 0x01);
        // VLESS capability bit is bit 9 = 512.
        assert_eq!(VLESS_CAPABILITY_BIT, 512);
        assert_eq!(VLESS_ATYP_IPV4, 0x01);
        assert_eq!(VLESS_CLIENT_FRAME_LEN, 26);
        assert_eq!(VLESS_SERVER_RESPONSE_LEN, 2);
    }

    // Audit #27: per-credential derived magic destination

    /// The magic destination is derived per-credential (per-UUID), not a fixed
    /// cross-bridge constant: it differs across UUIDs, is deterministic for one
    /// UUID, and lands in the non-routable 198.18.0.0/15 range.
    #[test]
    fn magic_dest_is_per_credential_derived_and_nonroutable() {
        let a = derive_vless_magic(&[0x01u8; 16]);
        let a2 = derive_vless_magic(&[0x01u8; 16]);
        let b = derive_vless_magic(&[0x02u8; 16]);
        assert_eq!(a, a2, "deterministic for one uuid");
        assert_ne!(a, b, "different uuids -> different magic");
        for (addr, port) in [a, b] {
            assert_eq!(addr[0], 198);
            assert!(addr[1] == 18 || addr[1] == 19, "within 198.18.0.0/15");
            assert!(port >= 1024, "port unprivileged/non-zero");
        }
        assert_ne!(a.0, [127, 0, 0, 2], "not the old loopback constant");
    }

    /// The bridge actually enforces the per-credential magic: a frame with a
    /// valid, authorized UUID but a *mismatched* magic (another UUID's derived
    /// value) is rejected; the correctly-derived magic is accepted. This proves
    /// client-embed and server-verify agree via [`derive_vless_magic`].
    #[test]
    fn frame_with_mismatched_magic_is_rejected() {
        let uuid = test_uuid();
        let config = test_config(&[uuid]);
        let mut frame = [0u8; VLESS_CLIENT_FRAME_LEN];
        frame[0] = VLESS_VERSION;
        frame[1..17].copy_from_slice(&uuid);
        frame[17] = 0x00;
        frame[18] = VLESS_COMMAND_TCP;
        frame[21] = VLESS_ATYP_IPV4;

        // Correct UUID but a DIFFERENT uuid's magic -> rejected.
        let (other_addr, other_port) = derive_vless_magic(&[0xAAu8; 16]);
        frame[19..21].copy_from_slice(&other_port.to_be_bytes());
        frame[22..26].copy_from_slice(&other_addr);
        assert!(
            !vless_server_peek_auth(&config, &frame),
            "mismatched magic must be rejected"
        );

        // The correctly-derived magic for this UUID is accepted.
        let (addr, port) = derive_vless_magic(&uuid);
        frame[19..21].copy_from_slice(&port.to_be_bytes());
        frame[22..26].copy_from_slice(&addr);
        assert!(
            vless_server_peek_auth(&config, &frame),
            "correctly-derived magic must be accepted"
        );
    }

    #[tokio::test]
    async fn vless_empty_authorized_set_rejects_any_uuid() {
        let config = test_config(&[]);
        let uuid = test_uuid();

        let (mut client_end, mut server_end) = duplex(256);
        vless_client_send_header(&mut client_end, &uuid)
            .await
            .expect("write");
        client_end.flush().await.expect("flush");

        let result = vless_server_auth(&mut server_end, &config, Duration::from_secs(1)).await;
        assert!(
            matches!(result, Err(TransportError::Auth(_))),
            "empty authorized set must reject all UUIDs; got {result:?}"
        );
    }

    #[tokio::test]
    async fn vless_multiple_authorized_uuids() {
        let uuid_a = [0x01u8; 16];
        let uuid_b = [0x02u8; 16];
        let uuid_c = [0x03u8; 16];
        let config = test_config(&[uuid_a, uuid_b, uuid_c]);

        for uuid in [uuid_a, uuid_b, uuid_c] {
            let (mut client_end, mut server_end) = duplex(256);
            vless_client_send_header(&mut client_end, &uuid)
                .await
                .expect("write");
            client_end.flush().await.expect("flush");
            vless_server_auth(&mut server_end, &config, Duration::from_secs(1))
                .await
                .unwrap_or_else(|_| panic!("UUID {uuid:?} should be accepted"));
        }
    }

    #[tokio::test]
    async fn vless_client_response_read_validates_version() {
        let (mut writer, mut reader) = duplex(16);

        // Write a bad version byte.
        writer.write_all(&[0x01, 0x00]).await.expect("write");
        writer.flush().await.expect("flush");

        let result = vless_client_read_response(&mut reader, Duration::from_secs(1)).await;
        assert!(
            matches!(result, Err(TransportError::Wire(_))),
            "bad version byte must yield Wire error; got {result:?}"
        );
    }
}
