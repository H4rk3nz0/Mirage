//! Hysteria2 transport for Mirage.
//!
//! Hysteria2 is a censorship-circumvention proxy that uses QUIC. The upstream
//! project pairs it with a custom "BRUTAL" congestion-control algorithm that
//! holds a fixed configured send rate regardless of packet loss or RTT. This
//! transport ships a REAL BRUTAL controller ([`brutal::Brutal`], an out-of-crate
//! `quinn_proto::congestion::Controller` - the trait is public in quinn-proto
//! 0.11, so the old "private types" blocker is obsolete). It is OPT-IN
//! (`Hysteria2ServerConfig::brutal_cc`): the default remains quinn's stock BBR,
//! because BRUTAL's fixed-rate non-backoff pacing is a behavioural tell and
//! antisocial on shared paths. Enable it on a hostile link that throttles via
//! induced loss, where holding the rate through loss is the point.
//!
//! # Design
//!
//! - Outer layer: QUIC TLS 1.3 with a runtime-generated self-signed certificate.
//!   The client skips TLS verification because the real authentication is
//!   provided by the Mirage Noise-XX handshake that runs inside the stream.
//! - Knock (pre-auth filter, NOT authentication): before handing the stream to
//!   the Noise layer, the client sends a 32-byte knock token (see
//!   [`derive_knock_token`]). Enumeration resistance (finding #9) holds ONLY
//!   when the knock is bound to a genuinely-secret `obfs_key` - a per-bridge
//!   secret delivered in the authenticated invite (`INVITE_EXT_QUIC_OBFS_SECRET`,
//!   absent from the public announcement) or a config `quic_obfs_password`. The
//!   standard deploy tools (`mirage-setup`, `mirage-keygen`) generate this secret
//!   and embed it in every invite by default, so a normal deployment IS
//!   enumeration-resistant: a censor who scraped only the announcement holds the
//!   pubkey but not the secret and CANNOT reproduce a passing knock. If, however,
//!   the `obfs_key` resolves to the pubkey-derived DEFAULT (a hand-built invite
//!   lacking the secret AND no config password), the knock is derivable from the
//!   announcement alone and provides NO enumeration resistance - the client logs
//!   a one-time warning in that case. In plain-QUIC mode (`obfs_key` = `None`)
//!   the token is likewise pubkey-only. In every mode the knock is only a cheap
//!   scanner filter; the real authentication is always the inner Noise-XX
//!   handshake.
//! - Congestion: quinn's built-in BBR with an initial window sized to the
//!   operator's target rate (see [`compute_brutal_window`]). Not fixed-rate,
//!   not loss-immune.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod brutal;

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use mirage_crypto::subtle::ConstantTimeEq;
use mirage_transport::TransportError;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Capability bit for Hysteria2 (bit 8).
pub const HYSTERIA2_CAPABILITY_BIT: u32 = 1 << 8;

/// QUIC ALPN value used by Hysteria2 (HTTP/3 identifier).
///
/// # Wire-fidelity honesty (finding #12)
///
/// This transport advertises the `"h3"` ALPN but does NOT speak HTTP/3: after
/// the QUIC+TLS handshake it opens a bidi stream and writes a raw 32-byte knock
/// (see [`hysteria2_client_connect`]) - no HTTP/3 SETTINGS, no HEADERS, no
/// genuine auth request. A real `h3` endpoint sends SETTINGS immediately, so an
/// active QUIC prober that completes the handshake and speaks HTTP/3 can tell
/// this apart (an "h3 impostor"). We keep `"h3"` because on 443/UDP it is still
/// the best passive BLEND - real HTTP/3 is what lives there - and a rarer ALPN
/// would stand out more; a full HTTP/3 exchange is a large change not done here.
///
/// This matters ONLY in plain-QUIC mode (`obfs_key == None`), where the quinn
/// Initial fingerprint (quinn != Chrome; the param set/order + GREASE need the
/// quinn-proto fork, see [`apply_chrome_transport_params`]) and this h3-impostor
/// shape are exposed on the wire. Obfs is ON BY DEFAULT (the client and bridge
/// set `obfs_key` by the precedence `quic_obfs_password`, then the invite secret
/// `INVITE_EXT_QUIC_OBFS_SECRET`, then a pubkey default); with obfs on, the
/// Salamander layer XORs the entire QUIC datagram, so both the quinn Initial
/// fingerprint AND the ALPN (which lives in the encrypted QUIC CRYPTO stream) are
/// hidden from a passive observer. Operators SHOULD keep obfs on; plain-QUIC mode
/// is fingerprintable and is a deliberate, documented trade-off, not disguised
/// HTTP/3 mimicry.
pub const HYSTERIA2_ALPN: &[u8] = b"h3";

/// Domain-separation label for knock-token derivation. The literal is fixed
/// wire-format material (changing it changes the derived token) so it still
/// reads "auth" for compatibility - but the token is a pre-auth knock filter,
/// not authentication (see [`derive_knock_token`]).
const HYSTERIA2_KNOCK_LABEL: &str = "mirage hysteria2 v1 auth";

/// Length of the knock token in bytes.
const KNOCK_TOKEN_LEN: usize = 32;

/// Minimum BRUTAL congestion window (64 KiB).
const MIN_BRUTAL_WINDOW: u64 = 64 * 1024;

// Server configuration

/// Default cover hostname for the QUIC SNI + self-signed cert SAN.
///
/// Operators SHOULD override this (bridge `hysteria2_hostname`, client
/// `hysteria2_hostname`) to match a plausible front for their deployment.
/// A fixed value is a weak fingerprint; the previous hardcoded `"mirage"`
/// was an EXACT-MATCH smoking gun - the cert SAN and the client SNI were
/// both literally `"mirage"`, flaggable with zero ML and zero false
/// positives. The client and bridge values MUST match: a passive observer
/// compares the client's SNI against the cert SAN, so a mismatch is itself
/// a distinguisher.
pub const DEFAULT_HYSTERIA2_HOSTNAME: &str = "cdn.example.com";

/// Derive a plausible, per-bridge cover hostname (the QUIC SNI a passive
/// observer sees, and the self-signed cert's SAN) deterministically from the
/// bridge's static X25519 public key.
///
/// A *fixed* default (the former [`DEFAULT_HYSTERIA2_HOSTNAME`],
/// `cdn.example.com`) has two tells: it is an RFC 2606 *reserved* documentation
/// domain a censor can prove is never a real service (F9-L), and being
/// identical across every bridge it is itself a cross-bridge Mirage
/// fingerprint. Deriving from the key gives each bridge a distinct,
/// non-reserved hostname while keeping the client's SNI and the bridge's cert
/// SAN identical (both ends compute it from the shared public key, so the
/// passive SNI-vs-SAN match a censor checks still holds).
///
/// This is only the *unconfigured* fallback: when the operator leaves the
/// hostname empty. Operators SHOULD still set an explicit front
/// (`hysteria2_hostname` / `h3_hostname`) resolving to a domain they actually
/// serve, which additionally defeats active SNI-cert probing.
#[must_use]
pub fn derive_cover_hostname(pk: &[u8; 32]) -> String {
    // Two independent FNV-1a passes over the key -> two base-36 labels + a
    // common TLD chosen by the key. Dependency-free and deterministic; not
    // security-sensitive (need only look like a real edge hostname).
    let h1 = fnv1a(pk, 0xcbf2_9ce4_8422_2325);
    let h2 = fnv1a(pk, 0x8422_2325_cbf2_9ce4);
    const TLDS: [&str; 3] = ["net", "com", "io"];
    let tld = TLDS[(h1 % 3) as usize];
    format!("{}.{}.{}", base36_label(h1), base36_label(h2), tld)
}

/// Resolve the effective cover hostname: the operator's value if set, else the
/// per-bridge derived fallback. Empty string means "auto-derive".
#[must_use]
pub fn effective_cover_hostname(configured: &str, pk: &[u8; 32]) -> String {
    if configured.is_empty() {
        derive_cover_hostname(pk)
    } else {
        configured.to_string()
    }
}

fn fnv1a(bytes: &[u8], seed: u64) -> u64 {
    let mut h = seed;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// A 7-char DNS label: an alphabetic lead (never an all-numeric label) followed
/// by lowercase base-36 characters - always a valid RFC 1123 hostname label.
fn base36_label(v: u64) -> String {
    const D: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    const A: &[u8; 26] = b"abcdefghijklmnopqrstuvwxyz";
    let mut out = [b'a'; 7];
    out[0] = A[(v % 26) as usize];
    let mut rem = v / 26;
    for slot in out.iter_mut().skip(1) {
        *slot = D[(rem % 36) as usize];
        rem /= 36;
    }
    String::from_utf8(out.to_vec()).expect("ascii label")
}

/// Server-side Hysteria2 configuration.
#[derive(Clone)]
pub struct Hysteria2ServerConfig {
    /// Bridge's X25519 static public key (32 bytes). Used to derive the
    /// expected knock token from the client (a pre-auth filter, not auth).
    pub bridge_static_pk: [u8; 32],
    /// BRUTAL send rate in bytes per second. `0` means unlimited (window
    /// clamped only at `MIN_BRUTAL_WINDOW`).
    pub send_rate_bps: u64,
    /// Cover hostname for the self-signed cert SAN. See
    /// [`DEFAULT_HYSTERIA2_HOSTNAME`].
    pub hostname: String,
    /// Gecko/Salamander QUIC-obfuscation key. When `Some`, the UDP socket
    /// de-obfuscates incoming datagrams + obfuscates outgoing. MUST match the
    /// client's key. `None` = plain QUIC.
    pub obfs_key: Option<[u8; 32]>,
    /// Optional path to a DER-encoded X.509 leaf cert to present on the QUIC
    /// handshake instead of a runtime self-signed cert. Pair with `key_der_path`.
    /// A real CA chain (reverse proxy / CDN / certbot) closes the RT #25
    /// active-prober cert tell. `None` = self-signed (warned).
    pub cert_der_path: Option<std::path::PathBuf>,
    /// Optional path to the matching PKCS#8 DER private key for `cert_der_path`.
    pub key_der_path: Option<std::path::PathBuf>,
    /// Opt-in to the real BRUTAL congestion controller (M3): fixed-rate,
    /// loss-immune server sending. `false` (default) keeps quinn's BBR. Enable
    /// only on a hostile link that throttles via induced loss - BRUTAL's
    /// non-backoff pacing is a behavioural tell and antisocial on shared paths.
    pub brutal_cc: bool,
}

// Client configuration

/// Client-side Hysteria2 configuration.
pub struct Hysteria2ClientConfig {
    /// Bridge's X25519 static public key (32 bytes). Used to derive the
    /// knock token sent to the server (a pre-auth filter, not auth).
    pub bridge_static_pk: [u8; 32],
    /// BRUTAL send rate in bytes per second. `0` means unlimited.
    pub send_rate_bps: u64,
    /// Cover hostname presented as the QUIC SNI. MUST match the bridge's
    /// cert SAN. See [`DEFAULT_HYSTERIA2_HOSTNAME`].
    pub hostname: String,
    /// Gecko/Salamander QUIC-obfuscation key. When `Some`, the UDP socket
    /// XOR-scrambles every datagram + fragments handshake packets so the wire
    /// shows no QUIC fingerprint. MUST match the bridge's key. `None` = plain.
    pub obfs_key: Option<[u8; 32]>,
}

// Stream wrapper

/// A bidirectional byte stream over a QUIC connection, returned
/// after a successful Hysteria2 handshake.
///
/// Wraps a `quinn::SendStream` + `quinn::RecvStream` pair and
/// implements `AsyncRead` + `AsyncWrite` so the Noise session can
/// drive it without knowing about QUIC.
pub struct Hysteria2Stream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    remote_addr: SocketAddr,
    /// L2: the server's h3 CONTROL stream (plain-QUIC mode only). Held - never
    /// finished or dropped - for the connection lifetime so it stays a valid h3
    /// control stream to an active prober. `None` in obfs mode / on the client.
    _h3_control: Option<quinn::SendStream>,
}

impl Hysteria2Stream {
    fn new(send: quinn::SendStream, recv: quinn::RecvStream, remote_addr: SocketAddr) -> Self {
        Self {
            send,
            recv,
            remote_addr,
            _h3_control: None,
        }
    }

    /// Attach the held server h3 control stream (L2).
    fn with_h3_control(mut self, control: Option<quinn::SendStream>) -> Self {
        self._h3_control = control;
        self
    }

    /// The QUIC peer's socket address. The bridge MUST use this (not a
    /// placeholder) to feed the per-IP rate limiter and probe-defense
    /// soft-block, so the Hysteria2 accept path is not a bypass (RT #17).
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}

impl AsyncRead for Hysteria2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for Hysteria2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Route through the tokio AsyncWrite impl which maps quinn::WriteError -> io::Error.
        <quinn::SendStream as tokio::io::AsyncWrite>::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        <quinn::SendStream as tokio::io::AsyncWrite>::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        <quinn::SendStream as tokio::io::AsyncWrite>::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

// BRUTAL congestion window math
// quinn 0.11's Controller trait uses private types (Instant, RttEstimator)
// that are not accessible from outside the crate. We therefore cannot plug
// in a custom Controller. Instead we configure BBR (quinn's built-in) with
// an initial window sized to the operator's target rate - "BBR with a
// rate-sized initial congestion window", NOT strict BRUTAL. BBR still backs
// off on sustained loss; this is NOT the loss-immune fixed-rate pacing BRUTAL
// provides, and callers must not assume that defence exists here.
//
// The window formula below matches the Hysteria2 BRUTAL rate formula and is
// used only to size BBR's initial window (and for accuracy in tests / rate
// calculations); it does not by itself make the controller loss-immune.

/// Compute the target congestion window for a given rate (bits/s) and RTT.
///
/// `rate_bps * rtt / 8` bytes, clamped to `MIN_BRUTAL_WINDOW` (64 KiB).
pub fn compute_brutal_window(rate_bps: u64, rtt: Duration) -> u64 {
    if rate_bps == 0 {
        return u64::MAX / 2;
    }
    let rtt_secs = rtt.as_secs_f64();
    #[allow(clippy::float_arithmetic)]
    let window = (rate_bps as f64 * rtt_secs / 8.0) as u64;
    window.max(MIN_BRUTAL_WINDOW)
}

/// Derive the initial BBR send window for a given target rate and a
/// conservative assumed RTT of 100 ms (used at connection open).
pub fn initial_window_for_rate(rate_bps: u64) -> u64 {
    compute_brutal_window(rate_bps, Duration::from_millis(100))
}

// Knock token derivation (cheap pre-auth filter, NOT authentication)

/// Derive the 32-byte knock token for a bridge, optionally bound to the
/// per-bridge invite secret.
///
/// # Enumeration-oracle fix (finding #9, Option A)
///
/// When `invite_secret` is `Some`, the token is derived from the bridge static
/// public key AND the per-bridge invite secret (`obfs_key`, delivered only in
/// the authenticated invite via `INVITE_EXT_QUIC_OBFS_SECRET`, NOT in the public
/// announcement). A censor who scraped only the announcement holds the pubkey
/// but not the secret, so it CANNOT reproduce a passing knock: the observable
/// pass/fail branch collapses to "always fail" for such a scraper, closing the
/// pubkey-only enumeration oracle. Both ends already share `obfs_key` (the
/// Salamander key that also encrypts the QUIC datagrams), and the client and
/// bridge derive this token from the same `(pk, obfs_key)` pair, so they still
/// agree.
///
/// This closes the oracle ONLY when `obfs_key` is genuinely secret - i.e. it
/// came from the invite's per-bridge secret or a config password. The standard
/// deploy tools embed that secret in every invite, so a normal deployment is
/// enumeration-resistant. Callers MUST NOT pass the pubkey-DERIVED default key
/// (`mirage_quic_obfs::default_obfs_key`) here expecting resistance: it is a
/// function of the announced pubkey, so a scraper reproduces it - binding the
/// knock to it is no better than the pubkey-only branch. The caller
/// (`resolve_obfs_key`) is responsible for detecting that fallback and warning.
///
/// When `invite_secret` is `None` (plain-QUIC mode, discouraged - see
/// [`HYSTERIA2_ALPN`]), the token falls back to the pubkey-only derivation. It
/// is then a cheap, public-key-gated pre-auth filter - NOT authentication and
/// forgeable from the announcement - whose only job is to drop unrelated
/// internet scanners before the Noise layer. The token stays byte-identical to
/// the pre-fix derivation in this mode, so a plain-QUIC deployment interoperates
/// unchanged.
///
/// In BOTH modes the real authentication is the inner Mirage Noise-XX handshake
/// that runs on the returned stream; the knock is never authentication.
///
/// Uses BLAKE3's `derive_key` with the domain-separation label
/// `"mirage hysteria2 v1 auth"`; the context material is the bridge static pk
/// alone (unbound) or `pk || obfs_key` (invite-bound).
fn derive_knock_token(
    bridge_static_pk: &[u8; 32],
    invite_secret: Option<&[u8; 32]>,
) -> [u8; KNOCK_TOKEN_LEN] {
    match invite_secret {
        None => blake3::derive_key(HYSTERIA2_KNOCK_LABEL, bridge_static_pk.as_slice()),
        Some(secret) => {
            // Context material = pk || secret. The 64-byte length is unreachable
            // by the pubkey-only (32-byte) branch, so the two modes cannot
            // collide, and forging the Some-branch token requires the secret.
            let mut material = [0u8; 64];
            material[..32].copy_from_slice(bridge_static_pk);
            material[32..].copy_from_slice(secret);
            blake3::derive_key(HYSTERIA2_KNOCK_LABEL, &material)
        }
    }
}

// TLS helpers

/// Build a quinn `ServerConfig` with:
/// - A runtime-generated self-signed certificate whose SAN is `hostname`.
/// - ALPN `"h3"`.
/// - BBR congestion controller with an initial window sized for `send_rate_bps`.
///
/// # Active-probe limitation (RT #25)
///
/// The leaf cert is **self-signed**, so an active QUIC prober that validates
/// the chain sees an untrusted cert - distinguishable from a real CDN/HTTP3
/// origin, which presents a publicly-trusted chain. The Mirage session inside
/// is unaffected (the bridge is authenticated by the inner PQ-Noise handshake,
/// not this cert), but the chain itself is a fingerprint. There is no way to
/// fix this purely in-process without a CA-issued cert; operators running
/// Hysteria2 on a contested network SHOULD either front the endpoint with a
/// real reverse proxy / CDN that terminates QUIC with a trusted cert, or only
/// expose it behind a hostname whose self-signed posture is plausible. A
/// startup `warn!` surfaces this so it is not a silent tell.
/// Install the congestion controller on `transport`: opt-in BRUTAL (fixed-rate,
/// loss-immune, M3) when `brutal` is set and a rate is configured, else quinn's
/// stock BBR. BBR stays the default - BRUTAL's non-backoff pacing is a
/// behavioural tell and antisocial on shared paths, so it is opt-in for hostile
/// links that throttle via induced loss.
fn install_congestion(transport: &mut quinn::TransportConfig, send_rate_bps: u64, brutal: bool) {
    if brutal && send_rate_bps != 0 {
        transport.congestion_controller_factory(Arc::new(brutal::BrutalConfig {
            rate_bps: send_rate_bps,
        }));
    } else {
        transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    }
}

fn build_server_quinn_config(
    send_rate_bps: u64,
    hostname: &str,
    cert_key_der: Option<(&std::path::Path, &std::path::Path)>,
    brutal: bool,
) -> Result<quinn::ServerConfig, TransportError> {
    // Cert source: an operator-provided DER cert+key (a real CA chain from a
    // reverse proxy / CDN / certbot, `openssl x509 -outform der` + a PKCS#8 DER
    // key) closes the RT #25 active-prober tell; otherwise a runtime self-signed
    // cert (warned about, since an active prober validating the chain can then
    // distinguish it from a real CDN).
    let (cert_der, priv_key): (CertificateDer<'static>, PrivatePkcs8KeyDer<'static>) =
        match cert_key_der {
            Some((cert_path, key_path)) => {
                let cert_bytes = std::fs::read(cert_path).map_err(|e| {
                    TransportError::Other(format!("hysteria2 cert {}: {e}", cert_path.display()))
                })?;
                let key_bytes = std::fs::read(key_path).map_err(|e| {
                    TransportError::Other(format!("hysteria2 key {}: {e}", key_path.display()))
                })?;
                (
                    CertificateDer::from(cert_bytes),
                    PrivatePkcs8KeyDer::from(key_bytes),
                )
            }
            None => {
                tracing::warn!(
                    %hostname,
                    "hysteria2: presenting a SELF-SIGNED QUIC cert - an active prober that \
                     validates the chain can distinguish this from a real CDN (RT #25). \
                     Set hysteria2_cert_der_path/hysteria2_key_der_path (or front with a \
                     CA-issued cert) on a contested network."
                );
                let rcgen::CertifiedKey { cert, key_pair } =
                    rcgen::generate_simple_self_signed(vec![hostname.to_string()])
                        .map_err(|e| TransportError::Other(format!("rcgen: {e}")))?;
                (
                    CertificateDer::from(cert),
                    PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
                )
            }
        };

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], priv_key.into())
        .map_err(|e| TransportError::Other(format!("rustls server config: {e}")))?;
    tls_config.alpn_protocols = vec![HYSTERIA2_ALPN.to_vec()];

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .map_err(|e| TransportError::Other(format!("quinn server crypto: {e}")))?,
    ));

    // Congestion control: opt-in BRUTAL (fixed-rate, loss-immune) or the default
    // BBR. `send_window` remains a flow-control/memory CAP sized for the rate.
    let mut transport = quinn::TransportConfig::default();
    install_congestion(&mut transport, send_rate_bps, brutal);
    let initial_window = initial_window_for_rate(send_rate_bps);
    transport.send_window(initial_window);
    // L3: apply the same Chrome-QUIC transport-parameter magnitudes the client
    // uses, so the plain-QUIC (obfs-off) posture is not client/server-asymmetric.
    apply_chrome_transport_params(&mut transport);
    server_config.transport_config(Arc::new(transport));

    Ok(server_config)
}

/// Build a quinn client config with:
/// - `DangerousClientConfig` that skips TLS certificate verification.
/// - ALPN `"h3"`.
/// - BBR congestion controller with an initial window sized for `send_rate_bps`.
fn build_client_quinn_config(
    send_rate_bps: u64,
    brutal: bool,
) -> Result<quinn::ClientConfig, TransportError> {
    let crypto_provider = Arc::new(rustls::crypto::ring::default_provider());

    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipCertVerifier::new(Arc::clone(&crypto_provider)))
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![HYSTERIA2_ALPN.to_vec()];

    let quic_client_config = QuicClientConfig::try_from(tls_config)
        .map_err(|e| TransportError::Other(format!("quinn client crypto: {e}")))?;

    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));

    // Chrome-QUIC alignment for real-QUIC (mimicry) flows. Harmless under the
    // Salamander obfs (which XORs the whole handshake). Chrome uses an 8-byte
    // initial Destination CID; quinn defaults to 20.
    client_config.initial_dst_cid_provider(Arc::new(|| {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).expect("OS CSPRNG for QUIC DCID");
        quinn::ConnectionId::new(&b)
    }));

    let mut transport = quinn::TransportConfig::default();
    install_congestion(&mut transport, send_rate_bps, brutal);
    let initial_window = initial_window_for_rate(send_rate_bps);
    transport.send_window(initial_window);
    apply_chrome_transport_params(&mut transport);
    client_config.transport_config(Arc::new(transport));

    Ok(client_config)
}

/// Move the numeric transport parameters toward Chrome-QUIC magnitudes (the
/// values reachable via quinn's public API; the parameter *set/order* + GREASE
/// need the quinn-proto fork). Applies to real-QUIC/mimicry flows; harmless when
/// the Salamander obfs XORs the handshake.
pub(crate) fn apply_chrome_transport_params(t: &mut quinn::TransportConfig) {
    use std::time::Duration;
    if let Ok(idle) = quinn::IdleTimeout::try_from(Duration::from_secs(30)) {
        t.max_idle_timeout(Some(idle));
    }
    t.receive_window(quinn::VarInt::from_u32(15_728_640)); // ~15 MB (Chrome initial_max_data)
    t.stream_receive_window(quinn::VarInt::from_u32(6_291_456)); // ~6 MB
    t.max_concurrent_bidi_streams(quinn::VarInt::from_u32(100));
    t.max_concurrent_uni_streams(quinn::VarInt::from_u32(103));
}

/// A TLS certificate verifier that accepts any certificate.
///
/// This is safe in Mirage's security model because the Noise-XX
/// handshake running inside the QUIC stream provides the actual
/// authentication. TLS is used only to satisfy QUIC's transport
/// requirement and to produce HTTPS-looking traffic on the wire.
#[derive(Debug)]
struct SkipCertVerifier(Arc<rustls::crypto::CryptoProvider>);

impl SkipCertVerifier {
    fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Arc<Self> {
        Arc::new(Self(provider))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

// Server accept

/// A persistent QUIC server endpoint for accepting Hysteria2 connections.
///
/// Unlike `hysteria2_server_accept` (which binds on every call), `Hysteria2Server`
/// binds once and exposes `accept_one` so the caller can loop without rebinding.
pub struct Hysteria2Server {
    endpoint: quinn::Endpoint,
    expected_knock: [u8; KNOCK_TOKEN_LEN],
    /// True in plain-QUIC mode (`obfs_key == None`). Only then can an active h3
    /// prober complete the handshake and inspect streams, so only then do we open
    /// a server h3 control stream + SETTINGS (L2) to present a real-origin shape.
    /// With obfs on, the whole QUIC is XORed, so the control stream would be pure
    /// overhead - skip it.
    obfs_off: bool,
}

impl Hysteria2Server {
    /// Bind a QUIC UDP listener at `addr` and return a server handle.
    pub fn bind(config: &Hysteria2ServerConfig, addr: SocketAddr) -> Result<Self, TransportError> {
        // Empty hostname -> derive a per-bridge cover SAN from the static key
        // (F9-L: never the RFC 2606 `cdn.example.com`, never a shared constant).
        let hostname = effective_cover_hostname(&config.hostname, &config.bridge_static_pk);
        let cert_key_der = match (&config.cert_der_path, &config.key_der_path) {
            (Some(c), Some(k)) => Some((c.as_path(), k.as_path())),
            // Only one of the pair set: a likely misconfiguration. Fall back to
            // self-signed but say so, rather than silently ignoring the one path.
            (Some(_), None) | (None, Some(_)) => {
                tracing::warn!(
                    "hysteria2: only one of hysteria2_cert_der_path / \
                     hysteria2_key_der_path is set - BOTH are required to present \
                     an operator cert; falling back to a self-signed cert."
                );
                None
            }
            (None, None) => None,
        };
        let server_cfg = build_server_quinn_config(
            config.send_rate_bps,
            &hostname,
            cert_key_der,
            config.brutal_cc,
        )?;
        let endpoint = match config.obfs_key {
            // Gecko/Salamander QUIC obfuscation on the UDP socket.
            Some(key) => mirage_quic_obfs::server_endpoint(addr, server_cfg, key)
                .map_err(|e| TransportError::Other(format!("obfs server bind {addr}: {e}")))?,
            None => quinn::Endpoint::server(server_cfg, addr)
                .map_err(|e| TransportError::Other(format!("server bind {addr}: {e}")))?,
        };
        Ok(Self {
            endpoint,
            // Bind the knock to the invite-only obfs secret when present, so a
            // pubkey-only scraper cannot forge a passing knock (finding #9).
            expected_knock: derive_knock_token(&config.bridge_static_pk, config.obfs_key.as_ref()),
            obfs_off: config.obfs_key.is_none(),
        })
    }

    /// Accept one Hysteria2 connection that passes the knock pre-auth filter.
    ///
    /// The knock is NOT authentication (the inner Noise-XX handshake is); it
    /// only drops unrelated scanners early.
    ///
    /// Returns `None` when the endpoint is closed (server shutting down).
    /// Returns `Some(Err(...))` for knock/timeout failures on a single
    /// connection; the endpoint stays open and the caller should loop.
    pub async fn accept_one(
        &self,
        deadline: Duration,
    ) -> Option<Result<Hysteria2Stream, TransportError>> {
        let incoming = self.endpoint.accept().await?;
        let expected = self.expected_knock;
        let obfs_off = self.obfs_off;
        Some(
            tokio::time::timeout(deadline, async move {
                let connection = incoming
                    .await
                    .map_err(|e| TransportError::Other(format!("QUIC accept: {e}")))?;
                let remote_addr = connection.remote_address();

                // L2: in plain-QUIC mode, open a real h3 server control stream +
                // SETTINGS (best-effort) BEFORE the knock, exactly as a real h3
                // origin does immediately on connection - so an active h3 prober
                // sees a working origin, not an impostor that sends no SETTINGS.
                // Held for the connection lifetime on the returned stream.
                let h3_control = if obfs_off {
                    mirage_quic_obfs::h3_probe::open_h3_server_control(&connection)
                        .await
                        .ok()
                } else {
                    None
                };

                let (mut send, mut recv) = connection
                    .accept_bi()
                    .await
                    .map_err(|e| TransportError::Other(format!("accept_bi: {e}")))?;

                let mut token_buf = [0u8; KNOCK_TOKEN_LEN];
                recv.read_exact(&mut token_buf)
                    .await
                    .map_err(|e| TransportError::Other(format!("knock token read: {e}")))?;

                // Constant-time compare - match the rest of the codebase
                // (ws/meek/token). This is only a cheap pre-auth knock, not
                // authentication (the inner Noise-XX handshake authenticates);
                // the constant-time compare merely avoids leaking match-length
                // timing to a scanner probing the filter.
                if token_buf.as_slice().ct_eq(expected.as_slice()).unwrap_u8() != 1 {
                    // RT circumvention #7: this endpoint advertises ALPN `h3`, so
                    // a real HTTP/3 origin would ANSWER a bad request, not drop it.
                    // In plain-QUIC mode (obfs off) an active prober completes the
                    // QUIC+TLS handshake and reaches here; answer with a benign
                    // nginx 404 (the same probe defense the MASQUE carrier has)
                    // instead of a silent drop that would fingerprint the bridge.
                    // Best-effort; the connection is still rejected below.
                    let _ = mirage_quic_obfs::h3_probe::send_benign_h3_404(&mut send).await;
                    return Err(TransportError::Auth("hysteria2: knock token mismatch"));
                }

                Ok::<Hysteria2Stream, TransportError>(
                    Hysteria2Stream::new(send, recv, remote_addr).with_h3_control(h3_control),
                )
            })
            .await
            .map_err(|_| TransportError::Timeout(deadline))
            .and_then(|r| r),
        )
    }
}

/// Bind a QUIC listener and accept one Hysteria2 connection that passes the
/// knock pre-auth filter (the inner Noise-XX handshake does the real auth).
///
/// Steps:
/// 1. Binds a UDP socket at `addr`.
/// 2. Waits up to `deadline` for an incoming QUIC connection.
/// 3. Accepts one bidirectional stream.
/// 4. Reads the 32-byte knock token from the client.
/// 5. Verifies the knock token against `bridge_static_pk` (a pre-auth filter,
///    not authentication); closes on mismatch.
/// 6. Returns the stream and the `quinn::Endpoint` (caller drops it when done).
pub async fn hysteria2_server_accept(
    config: &Hysteria2ServerConfig,
    addr: SocketAddr,
    deadline: Duration,
) -> Result<(Hysteria2Stream, quinn::Endpoint), TransportError> {
    let server = Hysteria2Server::bind(config, addr)?;
    let stream = server
        .accept_one(deadline)
        .await
        .ok_or_else(|| TransportError::Other("endpoint closed".into()))??;
    Ok((stream, server.endpoint))
}

// Client connect

/// Connect to a Hysteria2 bridge endpoint.
///
/// Steps:
/// 1. Creates a QUIC client endpoint bound on `0.0.0.0:0` (ephemeral port).
/// 2. Connects to `addr` using TLS SNI `config.hostname` (matching the server's cert SAN).
/// 3. Opens a bidirectional stream.
/// 4. Sends the 32-byte knock token derived from `bridge_static_pk` (a cheap
///    pre-auth filter, not authentication).
/// 5. Returns the stream ready for the Mirage Noise session.
pub async fn hysteria2_client_connect(
    config: &Hysteria2ClientConfig,
    addr: SocketAddr,
    deadline: Duration,
) -> Result<Hysteria2Stream, TransportError> {
    // BRUTAL is a server-downlink feature (the censored direction is usually the
    // bridge->client download); the client keeps BBR to stay a good network
    // citizen on its uplink.
    let client_cfg = build_client_quinn_config(config.send_rate_bps, false)?;

    // Bind the client on the appropriate wildcard address.
    let bind_addr: SocketAddr = if addr.is_ipv6() {
        "[::]:0".parse().expect("static addr")
    } else {
        "0.0.0.0:0".parse().expect("static addr")
    };
    let mut endpoint = match config.obfs_key {
        // Gecko/Salamander QUIC obfuscation on the UDP socket.
        Some(key) => mirage_quic_obfs::client_endpoint(bind_addr, key)
            .map_err(|e| TransportError::Other(format!("obfs client endpoint: {e}")))?,
        None => quinn::Endpoint::client(bind_addr)
            .map_err(|e| TransportError::Other(format!("client endpoint: {e}")))?,
    };
    endpoint.set_default_client_config(client_cfg);

    // Bind the knock to the invite-only obfs secret when present (finding #9);
    // the bridge derives the identical token from the same (pk, obfs_key) pair.
    let knock_token = derive_knock_token(&config.bridge_static_pk, config.obfs_key.as_ref());
    // Match the server's SAN derivation so a passive SNI-vs-SAN check still ties
    // out (F9-L). Empty hostname -> per-bridge value from the shared static key.
    let hostname = effective_cover_hostname(&config.hostname, &config.bridge_static_pk);

    tokio::time::timeout(deadline, async {
        let connection = endpoint
            .connect(addr, &hostname)
            .map_err(|e| TransportError::Other(format!("connect: {e}")))?
            .await
            .map_err(|e| TransportError::Other(format!("QUIC handshake: {e}")))?;

        let (mut send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| TransportError::Other(format!("open_bi: {e}")))?;

        // Send the 32-byte knock token (pre-auth filter, not authentication).
        // NOTE (finding #12): this is a RAW knock, not an HTTP/3 request - no
        // SETTINGS/HEADERS - so despite the "h3" ALPN this is not HTTP/3 mimicry
        // and is distinguishable by an active h3-speaking prober in plain-QUIC
        // mode. Keep obfs on (default) so the whole handshake is XOR-hidden. See
        // [`HYSTERIA2_ALPN`].
        send.write_all(&knock_token)
            .await
            .map_err(|e| TransportError::Other(format!("knock token write: {e}")))?;
        send.flush()
            .await
            .map_err(|e| TransportError::Other(format!("knock token flush: {e}")))?;

        let remote_addr = connection.remote_address();
        Ok::<Hysteria2Stream, TransportError>(Hysteria2Stream::new(send, recv, remote_addr))
    })
    .await
    .map_err(|_| TransportError::Timeout(deadline))?
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn loopback_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn cover_hostname_is_deterministic_valid_and_unreserved() {
        let pk = [7u8; 32];
        // Deterministic: client SNI must equal bridge SAN (same key -> same host).
        assert_eq!(derive_cover_hostname(&pk), derive_cover_hostname(&pk));
        // Distinct keys -> distinct hostnames (no shared-constant fingerprint).
        assert_ne!(
            derive_cover_hostname(&[1u8; 32]),
            derive_cover_hostname(&[2u8; 32])
        );
        let host = derive_cover_hostname(&pk);
        // Never an RFC 2606 reserved / documentation form.
        for bad in ["example", ".test", ".invalid", ".localhost"] {
            assert!(!host.contains(bad), "{host} must not look reserved ({bad})");
        }
        // Valid hostname: three dot-separated labels, each 1..=63 chars of
        // [a-z0-9-], leading label starting alphabetic.
        let labels: Vec<&str> = host.split('.').collect();
        assert_eq!(labels.len(), 3, "expected host.host.tld, got {host}");
        for l in &labels {
            assert!(!l.is_empty() && l.len() <= 63, "bad label {l:?}");
            assert!(
                l.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'),
                "label {l:?} has invalid chars"
            );
        }
        assert!(
            labels[0].as_bytes()[0].is_ascii_lowercase(),
            "leading label must start alphabetic: {host}"
        );
        // effective_cover_hostname: honour an explicit override, else derive.
        assert_eq!(
            effective_cover_hostname("front.example.org", &pk),
            "front.example.org"
        );
        assert_eq!(effective_cover_hostname("", &pk), host);
    }

    /// Find a free UDP port by binding temporarily.
    fn free_udp_port() -> u16 {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind probe socket");
        sock.local_addr().expect("local addr").port()
    }

    /// Round-trip test: server and client connect, exchange data.
    #[tokio::test]
    async fn hysteria2_client_server_roundtrip() {
        let port = free_udp_port();
        let addr = loopback_addr(port);
        let pk = [0x42u8; 32];
        let deadline = Duration::from_secs(5);

        // Exercise the Gecko/Salamander obfuscation path end-to-end (both sides
        // share the same key). The echo roundtrip must survive obfuscation.
        let obfs = Some(mirage_quic_obfs::key_from_password(b"hy2-test-obfs"));
        let server_config = Hysteria2ServerConfig {
            bridge_static_pk: pk,
            send_rate_bps: 10_000_000,
            hostname: DEFAULT_HYSTERIA2_HOSTNAME.into(),
            obfs_key: obfs,
            cert_der_path: None,
            key_der_path: None,
            brutal_cc: false,
        };
        let client_config = Hysteria2ClientConfig {
            bridge_static_pk: pk,
            send_rate_bps: 10_000_000,
            hostname: DEFAULT_HYSTERIA2_HOSTNAME.into(),
            obfs_key: obfs,
        };

        // Channel to signal when the server has written the echo.
        let (server_ready_tx, server_ready_rx) = tokio::sync::oneshot::channel::<()>();

        let server_task = tokio::spawn(async move {
            let (mut stream, ep) = hysteria2_server_accept(&server_config, addr, deadline)
                .await
                .expect("server accept");
            // Echo: read 5 bytes, write them back.
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).await.expect("server read");
            stream.write_all(&buf).await.expect("server write");
            stream.flush().await.expect("server flush");
            // Signal client it can read, then keep the endpoint alive while
            // the client reads the response (dropping ep kills the connection).
            let _ = server_ready_tx.send(());
            // Wait for the QUIC connection to drain naturally.
            ep.wait_idle().await;
        });

        // Give the server a moment to bind.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut client_stream = hysteria2_client_connect(&client_config, addr, deadline)
            .await
            .expect("client connect");
        client_stream
            .write_all(b"hello")
            .await
            .expect("client write");
        client_stream.flush().await.expect("client flush");

        // Wait for the server to write before reading.
        let _ = server_ready_rx.await;

        let mut response = [0u8; 5];
        client_stream
            .read_exact(&mut response)
            .await
            .expect("client read");
        assert_eq!(&response, b"hello");

        server_task.await.expect("server task");
    }

    /// Wrong knock token -> server rejects the connection at the pre-auth filter.
    #[tokio::test]
    async fn hysteria2_wrong_knock_rejected() {
        let port = free_udp_port();
        let addr = loopback_addr(port);
        let server_pk = [0xAAu8; 32];
        let client_pk = [0xBBu8; 32]; // different key -> wrong token
        let deadline = Duration::from_secs(5);

        let server_config = Hysteria2ServerConfig {
            bridge_static_pk: server_pk,
            send_rate_bps: 0,
            hostname: DEFAULT_HYSTERIA2_HOSTNAME.into(),
            obfs_key: None,
            cert_der_path: None,
            key_der_path: None,
            brutal_cc: false,
        };
        let client_config = Hysteria2ClientConfig {
            bridge_static_pk: client_pk,
            send_rate_bps: 0,
            hostname: DEFAULT_HYSTERIA2_HOSTNAME.into(),
            obfs_key: None,
        };

        let server_task = tokio::spawn(async move {
            // Server should reject at the knock filter (TransportError::Auth is
            // the generic transport error variant used for the knock mismatch).
            let result = hysteria2_server_accept(&server_config, addr, deadline).await;
            match result {
                Err(TransportError::Auth(_)) => {} // expected
                Ok(_) => panic!("server should have rejected mismatched knock token"),
                Err(e) => panic!("expected Auth error, got different error: {e}"),
            }
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        // The client connects and opens a bi-stream, sending the wrong knock token.
        // We must keep the returned stream alive long enough for the server to
        // read the token and return its auth error - dropping the stream/connection
        // immediately would close the QUIC connection before the server processes it.
        let client_result = hysteria2_client_connect(&client_config, addr, deadline).await;

        // Wait for the server to finish processing before asserting.
        server_task
            .await
            .expect("server task panicked unexpectedly");

        // The client may succeed (stream was opened) or fail depending on timing;
        // either way is fine since the meaningful assertion is on the server side.
        let _ = client_result;
    }

    /// The window formula is deterministic for a given (rate, rtt) pair and does
    /// not decrease on loss. NOTE: this tests only the window-sizing math. The
    /// transport runs quinn's stock BBR (which DOES back off on sustained loss),
    /// NOT a loss-immune fixed-rate BRUTAL controller - quinn 0.11 does not admit
    /// an out-of-crate `congestion::Controller`. The name reflects the BRUTAL
    /// rate formula used to size BBR's initial window, not any loss immunity.
    #[test]
    fn brutal_window_formula_is_deterministic() {
        let rate_bps: u64 = 100_000_000;
        let rtt = Duration::from_millis(50);
        // Compute twice with the same inputs - result must be identical.
        let w1 = compute_brutal_window(rate_bps, rtt);
        let w2 = compute_brutal_window(rate_bps, rtt);
        assert_eq!(w1, w2, "BRUTAL window must not change between calls");

        // The window must be at least the minimum floor.
        assert!(
            w1 >= MIN_BRUTAL_WINDOW,
            "window must be >= MIN_BRUTAL_WINDOW"
        );
    }

    /// Window scales with RTT.
    #[test]
    fn brutal_window_scales_with_rtt() {
        let rate_bps: u64 = 100_000_000; // 100 Mbps = 12.5 MB/s

        // At 100ms RTT: window = 12_500_000 * 0.1 = 1_250_000 bytes
        let window_100ms = compute_brutal_window(rate_bps, Duration::from_millis(100));
        // At 200ms RTT: window = 12_500_000 * 0.2 = 2_500_000 bytes
        let window_200ms = compute_brutal_window(rate_bps, Duration::from_millis(200));

        assert!(
            window_200ms > window_100ms,
            "window must grow with RTT: {window_200ms} > {window_100ms}"
        );
    }

    /// Knock-token derivation is deterministic and key-bound. In the pubkey-only
    /// (plain-QUIC) mode being derivable from the public key alone is exactly why
    /// the knock is only a pre-auth filter, not authentication.
    #[test]
    fn knock_token_deterministic_and_key_bound() {
        let pk_a = [0x11u8; 32];
        let pk_b = [0x22u8; 32];

        let t1 = derive_knock_token(&pk_a, None);
        let t2 = derive_knock_token(&pk_a, None);
        let t3 = derive_knock_token(&pk_b, None);

        assert_eq!(t1, t2, "derivation must be deterministic");
        assert_ne!(t1, t3, "different keys must produce different tokens");
    }

    /// Finding #9 (Option A): binding the knock to the invite-only obfs secret
    /// makes it UNFORGEABLE from the public announcement. A censor holding only
    /// the pubkey (the `None` derivation) cannot reproduce the invite-bound
    /// token, so the pass/fail enumeration branch collapses to "always fail".
    #[test]
    fn knock_token_invite_bound_is_unforgeable_from_pubkey() {
        let pk = [0x11u8; 32];
        let secret = [0xABu8; 32];
        let other_secret = [0xCDu8; 32];

        let pubkey_only = derive_knock_token(&pk, None); // what a scraper can build
        let bound = derive_knock_token(&pk, Some(&secret));
        let bound_again = derive_knock_token(&pk, Some(&secret));
        let bound_other = derive_knock_token(&pk, Some(&other_secret));

        // Client and bridge sharing (pk, obfs_key) agree - interop preserved.
        assert_eq!(bound, bound_again, "same (pk, secret) must agree");
        // A pubkey-only scraper's token does NOT pass an invite-bound bridge.
        assert_ne!(
            bound, pubkey_only,
            "invite-bound token must differ from the pubkey-forgeable one"
        );
        // Different invite secrets yield different tokens (per-bridge isolation).
        assert_ne!(
            bound, bound_other,
            "different invite secrets must produce different tokens"
        );
    }

    /// Plain-QUIC (no invite secret) stays byte-identical to the pre-fix,
    /// pubkey-only derivation, so a plain-QUIC deployment interoperates unchanged.
    #[test]
    fn knock_token_plain_quic_is_backward_compatible() {
        let pk = [0x33u8; 32];
        assert_eq!(
            derive_knock_token(&pk, None),
            blake3::derive_key(HYSTERIA2_KNOCK_LABEL, pk.as_slice()),
            "None branch must equal the legacy pubkey-only token"
        );
    }

    /// Capability bit is 256 (bit 8).
    #[test]
    fn capability_bit_is_256() {
        assert_eq!(HYSTERIA2_CAPABILITY_BIT, 256);
    }
}
