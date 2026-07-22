//! Embeddable Mirage client library.
//!
//! # Why a library, not just a daemon
//!
//! The existing `mirage-client` is a standalone daemon that
//! exposes a SOCKS5 endpoint. Useful, but constrains every
//! integration to "use SOCKS5." A browser extension wants to
//! handle individual requests; a mobile VPN wants to handle IP
//! packets; a Rust app wants `tunnel.connect("example.com:443")`
//! returning a duplex stream. All of those need the same primitive -
//! "open a Mirage tunnel to a configured bridge, hand back a
//! duplex stream" - without going through a separate process.
//!
//! `mirage-core` is that primitive. It exposes:
//!
//! - [`MirageCore`] - held by the embedding application.
//! - [`MirageCore::open_tunnel`] - open one Mirage session, return
//!   the duplex byte stream the application can drive.
//! - [`MirageConfig`] / [`Transport`] - configure the bootstrap
//!   invite and which carrier transport to ride.
//!
//! # What `open_tunnel` does
//!
//! 1. Resolves the bootstrap bridge endpoint + its X25519 static
//!    key from the invite's bootstrap announcement.
//! 2. Pops a single-use bootstrap capability token (round-robin).
//! 3. Generates a fresh X25519 ephemeral and dials the bridge over
//!    the configured [`Transport`] (plain TCP, REALITY-v2 TLS
//!    mimicry, or obfs-tcp).
//! 4. Runs the post-quantum Noise-XX + ML-KEM-768 handshake
//!    ([`mirage_session::connect`]) with the token bound into
//!    message 3.
//! 5. Returns a [`MirageTunnel`] (`AsyncRead` + `AsyncWrite`) that
//!    is the live, encrypted Mirage session - the embedding app
//!    speaks SOCKS5-over-Mirage (or whatever the bridge serves)
//!    across it.
//!
//! # Usage
//!
//! ```ignore
//! use mirage_core::{MirageCore, MirageConfig};
//!
//! let config = MirageConfig::from_invite_text("mirage://...")?;
//! let core = MirageCore::new(config);
//! let tunnel = core.open_tunnel().await?;
//! // tunnel: AsyncRead + AsyncWrite - drive it from any tokio task.
//! ```
//!
//! # Not yet wired in THIS facade (tracked for later iterations)
//!
//! This `mirage-core` facade is a thin standalone entry point; the full client
//! daemon (`crates/client`) already wires the adaptive router + success-rate
//! persistence live. What this facade does not yet expose:
//! - Adaptive multi-transport SELECTION + per-network success-rate persistence
//!   (both live in the client daemon today; naive parallel `race_transports`
//!   was removed as an anti-enumeration footgun - see `mirage_transport`).
//! - Multi-hop circuit construction and `.mirage` onion resolution.
//! - Cover-traffic scheduling (record-level `PaddedStream` exists but is not
//!   driven from this facade).
//!
//! These are additive: the [`MirageCore::open_tunnel`] signature is
//! stable, so consumers building against it today keep working when
//! selection / circuits land.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use mirage_crypto::x25519_dalek::StaticSecret;
use mirage_discovery::invite::MasterInvite;
use mirage_discovery::token::CapabilityToken;
use mirage_discovery::wire::Endpoint;
use mirage_session::{connect, SessionStream};
use mirage_transport::{ClientTransport, DialInputs, DuplexStream};
use mirage_transport_obfs::ObfsClientTransport;
use mirage_transport_reality::{reality_connect, ClientCarrierInputs};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// Errors produced by [`MirageCore`].
#[derive(Debug, Error)]
pub enum CoreError {
    /// Could not parse the invite text or load it from disk.
    #[error("invite: {0}")]
    Invite(String),
    /// No bootstrap endpoint available - the invite has no
    /// `bootstrap_announcement` AND no discovery channels are
    /// wired up. This build requires the invite to carry one.
    #[error("invite has no bootstrap endpoint and no discovery wired")]
    NoBootstrap,
    /// All bootstrap tokens have been consumed; the application
    /// must obtain a fresh invite or a refresh-token batch.
    #[error("bootstrap token pool exhausted")]
    TokensExhausted,
    /// The bootstrap endpoint cannot be dialed by this client (e.g.
    /// an onion endpoint with no Tor route wired up).
    #[error("unsupported endpoint: {0}")]
    UnsupportedEndpoint(&'static str),
    /// Underlying transport / session error (dial, carrier handshake,
    /// or the Mirage session handshake).
    #[error("transport: {0}")]
    Transport(String),
    /// I/O failure during connect.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Which carrier transport the Mirage session rides over.
///
/// The session-layer crypto is identical across all of them; the
/// transport only changes what the *outer* bytes look like to a
/// network observer.
#[derive(Debug, Clone, Default)]
pub enum Transport {
    /// Plain TCP - the Mirage session frames ride directly over TCP.
    /// A mux-enabled bridge auto-detects the session on its listen
    /// port. Simplest; offers no traffic-analysis resistance of its
    /// own (the Noise layer still encrypts contents).
    #[default]
    PlainTcp,
    /// REALITY-v2: TLS 1.3 mimicry with the auth-probe carried in the
    /// `ClientHello` `session_id`. To a DPI box the connection looks
    /// like a normal TLS handshake to `server_name`.
    Reality {
        /// SNI presented in the `ClientHello` (a plausible cover host).
        server_name: String,
        /// Optional pinned compressed-SEC1 ECDSA P-256 key for
        /// `CertificateVerify` validation (cover-mimicry mode). `None`
        /// uses the cert's own SPKI (ephemeral mode).
        cert_verify_override_pk: Option<[u8; 33]>,
        /// Optional Reality anti-probe root from the invite
        /// (`INVITE_EXT_REALITY_PROBE_ROOT`). When `Some`, a per-epoch secret
        /// derived from it is folded into the auth probe so a censor with only
        /// the public announcement cannot forge it. `None` = legacy probe.
        ///
        /// NOTE: `mirage-core` is a standalone embeddable facade that no in-repo
        /// binary currently depends on; the live client path
        /// (`crates/client`) carries its own equivalent plumbing. This field is
        /// kept for API completeness/parity, but the live-exercised path is the
        /// client's, not this one.
        #[allow(clippy::doc_markdown)]
        probe_root: Option<[u8; 32]>,
    },
    /// obfs-tcp: a 64-byte BLAKE3-keyed handshake over raw TCP with
    /// no TLS layer; the wire looks like uniform-random bytes. Auth
    /// derives from the bridge's X25519 static key.
    Obfs,
}

/// Configuration for [`MirageCore`].
///
/// Fields are public so applications can construct a config
/// programmatically (e.g., a browser extension reading an invite
/// from extension storage).
pub struct MirageConfig {
    /// Decoded master invite.
    pub invite: MasterInvite,
    /// Hard deadline for the dial + Mirage handshake. Default 10 s.
    pub handshake_timeout: Duration,
    /// Carrier transport to ride. Default [`Transport::PlainTcp`].
    pub transport: Transport,
}

impl MirageConfig {
    /// Parse a `mirage://<base64-url>` or bare base64-url invite
    /// text into a config. Defaults to [`Transport::PlainTcp`]; set
    /// [`MirageConfig::transport`] afterward to ride a carrier.
    pub fn from_invite_text(text: &str) -> Result<Self, CoreError> {
        let body = text.strip_prefix("mirage://").unwrap_or(text);
        let invite = MasterInvite::decode_text(body)
            .map_err(|e| CoreError::Invite(format!("decode: {e}")))?;
        // SECURITY: `MasterInvite::decode` deliberately does NOT verify the
        // embedded bootstrap announcement - it pushes that obligation onto
        // the caller (invite.rs §8.6). The standalone client remembers
        // (client/src/main.rs); this embeddable library MUST too, or an
        // attacker who flips bytes of an invite in transit (QR re-encode,
        // messenger relay) can swap ONLY the announcement's bridge_x25519_pk
        // + endpoint - leaving the operator pin intact - and redirect the
        // client to a hostile bridge that captures its bootstrap tokens.
        // Verify the announcement against the invite's operator pin HERE, at
        // the single parse entry point, so no consumer can forget it.
        match invite.bootstrap_announcement.as_ref() {
            None => return Err(CoreError::NoBootstrap),
            Some(ann) => ann
                .verify(&invite.operator_ed25519_pk)
                .map_err(|e| CoreError::Invite(format!("announcement signature: {e}")))?,
        }
        if invite.bootstrap_tokens.is_empty() {
            return Err(CoreError::TokensExhausted);
        }
        Ok(Self {
            invite,
            handshake_timeout: Duration::from_secs(10),
            transport: Transport::default(),
        })
    }
}

impl core::fmt::Debug for MirageConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MirageConfig")
            .field("invite", &"<MasterInvite>")
            .field("handshake_timeout", &self.handshake_timeout)
            .field("transport", &self.transport)
            .finish()
    }
}

/// Live duplex tunnel returned by [`MirageCore::open_tunnel`].
///
/// Implements [`AsyncRead`] + [`AsyncWrite`]; reading and writing
/// move plaintext across the encrypted Mirage session (the framing,
/// double-AEAD, and time-ratchet all happen inside). Any tokio-based
/// consumer can drive it: a SOCKS5 client, an HTTP CONNECT proxy, a
/// TUN packet pump, etc.
pub struct MirageTunnel {
    inner: SessionStream<DuplexStream>,
}

impl core::fmt::Debug for MirageTunnel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // No session state is disclosed (no keys, seq counters, or peer
        // address) - a live tunnel is opaque by design.
        f.debug_struct("MirageTunnel").finish_non_exhaustive()
    }
}

impl AsyncRead for MirageTunnel {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // SessionStream<DuplexStream> is Unpin (DuplexStream is a
        // Pin<Box<..>>), so a plain Pin::new reborrow is sound.
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for MirageTunnel {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// The embeddable Mirage client.
///
/// Hold one `MirageCore` per application instance; share via `Arc`
/// across tokio tasks. Bootstrap-token consumption is an atomic
/// round-robin so concurrent `open_tunnel` calls don't deterministically
/// reuse one token.
pub struct MirageCore {
    config: MirageConfig,
    /// Round-robin cursor over bootstrap tokens. Each `open_tunnel`
    /// advances the cursor.
    token_cursor: Arc<AtomicUsize>,
}

impl MirageCore {
    /// Construct from a config. Cheap (no network I/O).
    pub fn new(config: MirageConfig) -> Self {
        Self {
            config,
            token_cursor: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Endpoint of the bootstrap bridge from the invite. Useful for
    /// applications that want to display "currently connected to
    /// `<host>:<port>`" without parsing the invite themselves.
    pub fn bootstrap_endpoint(&self) -> Result<&Endpoint, CoreError> {
        self.config
            .invite
            .bootstrap_announcement
            .as_ref()
            .map(|a| &a.endpoint)
            .ok_or(CoreError::NoBootstrap)
    }

    /// How many bootstrap tokens are available. The application
    /// SHOULD prompt the user to refresh their invite as this
    /// count approaches zero.
    pub fn token_pool_size(&self) -> usize {
        self.config.invite.bootstrap_tokens.len()
    }

    /// Pop the next bootstrap token (single-use round-robin
    /// rotation). Returns `None` when the pool is empty.
    fn next_token(&self) -> Option<&CapabilityToken> {
        let n = self.config.invite.bootstrap_tokens.len();
        if n == 0 {
            return None;
        }
        let idx = self.token_cursor.fetch_add(1, Ordering::Relaxed) % n;
        self.config.invite.bootstrap_tokens.get(idx)
    }

    /// Dial the configured transport to `endpoint`, returning a
    /// type-erased duplex stream ready for the Mirage handshake.
    async fn dial_transport(
        &self,
        endpoint: &Endpoint,
        bridge_x25519_pk: &[u8; 32],
        deadline: Duration,
    ) -> Result<DuplexStream, CoreError> {
        match &self.config.transport {
            Transport::PlainTcp => {
                let tcp = self.tcp_connect(endpoint, deadline).await?;
                Ok(Box::pin(tcp))
            }
            Transport::Obfs => {
                // The obfs transport opens its own TCP connection and
                // performs the 64-byte BLAKE3-keyed handshake.
                let stream = ObfsClientTransport::new()
                    .dial(&DialInputs {
                        endpoint,
                        bridge_static_pk: bridge_x25519_pk,
                        // #9: key the knock on the invite obfs secret when present.
                        obfs_secret: self.config.invite.obfs_secret.as_ref(),
                        deadline,
                    })
                    .await
                    .map_err(|e| CoreError::Transport(format!("obfs dial: {e}")))?;
                Ok(stream)
            }
            Transport::Reality {
                server_name,
                cert_verify_override_pk,
                probe_root,
            } => {
                let tcp = self.tcp_connect(endpoint, deadline).await?;
                let reality = reality_connect(
                    tcp,
                    &ClientCarrierInputs {
                        bridge_static_pk: bridge_x25519_pk,
                        probe_root: probe_root
                            .as_ref()
                            .unwrap_or(&mirage_transport_reality::PROBE_ROOT_DISABLED),
                        server_name,
                        now_unix: now_unix_u32(),
                        cert_verify_override_pk: cert_verify_override_pk.as_ref(),
                        tls_fingerprint: None,
                    },
                )
                .await
                .map_err(|e| CoreError::Transport(format!("reality handshake: {e}")))?;
                // Shaper-v2: opt-in envelope pacing (MIRAGE_REALITY_PACE). Off by
                // default - returns the carrier stream unchanged. The client writes
                // upstream, so it paces the `Up` direction.
                Ok(Box::pin(mirage_transport_reality::maybe_pace(
                    reality,
                    mirage_transport_reality::pacer::Dir::Up,
                )))
            }
        }
    }

    /// TCP-connect to `endpoint` under `deadline`, with `TCP_NODELAY`.
    async fn tcp_connect(
        &self,
        endpoint: &Endpoint,
        deadline: Duration,
    ) -> Result<TcpStream, CoreError> {
        let addr = endpoint_to_dial_str(endpoint)?;
        let tcp = tokio::time::timeout(deadline, TcpStream::connect(&addr))
            .await
            .map_err(|_| CoreError::Transport(format!("tcp connect to {addr} timed out")))?
            .map_err(CoreError::Io)?;
        tcp.set_nodelay(true).ok();
        Ok(tcp)
    }

    /// Open one Mirage tunnel to the bootstrap bridge.
    ///
    /// Returns a [`MirageTunnel`] - the live, encrypted Mirage session
    /// as an `AsyncRead` + `AsyncWrite` duplex. Consumes one bootstrap
    /// token (round-robin). The entire dial + handshake is bounded by
    /// [`MirageConfig::handshake_timeout`].
    pub async fn open_tunnel(&self) -> Result<MirageTunnel, CoreError> {
        let ann = self
            .config
            .invite
            .bootstrap_announcement
            .as_ref()
            .ok_or(CoreError::NoBootstrap)?;
        let bridge_x25519_pk = ann.bridge_x25519_pk;
        let endpoint = ann.endpoint.clone();
        let token = self.next_token().ok_or(CoreError::TokensExhausted)?.clone();
        let deadline = self.config.handshake_timeout;

        // Fresh X25519 ephemeral per connection (forward secrecy + no
        // cross-tunnel linkability).
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| CoreError::Transport(format!("csprng: {e}")))?;
        let client_x25519_sk = StaticSecret::from(seed).to_bytes();

        let stream = self
            .dial_transport(&endpoint, &bridge_x25519_pk, deadline)
            .await?;

        let session = tokio::time::timeout(
            deadline,
            connect(stream, &client_x25519_sk, &bridge_x25519_pk, &token),
        )
        .await
        .map_err(|_| CoreError::Transport("mirage handshake timed out".into()))?
        .map_err(|e| CoreError::Transport(format!("mirage handshake: {e}")))?;

        tracing::debug!(
            transport = ?self.config.transport,
            "mirage-core: tunnel established"
        );
        Ok(MirageTunnel { inner: session })
    }
}

/// Render an [`Endpoint`] as a `host:port` string for
/// [`TcpStream::connect`].
fn endpoint_to_dial_str(e: &Endpoint) -> Result<String, CoreError> {
    match e {
        Endpoint::Ipv4 { addr, port } => Ok(format!(
            "{}.{}.{}.{}:{port}",
            addr[0], addr[1], addr[2], addr[3]
        )),
        Endpoint::Ipv6 { addr, port } => {
            let ip = std::net::Ipv6Addr::from(*addr);
            Ok(format!("[{ip}]:{port}"))
        }
        Endpoint::Domain { domain, port } => Ok(format!("{domain}:{port}")),
        Endpoint::OnionV3 { .. } => Err(CoreError::UnsupportedEndpoint(
            "onion endpoint requires Tor routing, not wired in mirage-core",
        )),
    }
}

/// Current Unix time as a `u32` (seconds), saturating. Used for the
/// REALITY auth-probe timestamp.
fn now_unix_u32() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX))
        .unwrap_or(0)
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_crypto::ed25519_dalek::{Signer, SigningKey};
    use mirage_crypto::x25519_dalek::PublicKey;
    use mirage_discovery::replay::ReplaySet;
    use mirage_discovery::token::sign_token;
    use mirage_discovery::wire::{Announcement, Endpoint, SIG_LEN};
    use mirage_session::{accept, TokenVerifier};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn rand_seed() -> [u8; 32] {
        let mut s = [0u8; 32];
        getrandom::fill(&mut s).unwrap();
        s
    }

    /// Build a self-consistent invite whose bootstrap announcement is
    /// signed by `op`, names `bridge_ed_pk` / `bridge_x_pk`, points at
    /// `endpoint`, and carries a single token valid at `now`.
    fn make_invite(
        op: &SigningKey,
        bridge_ed_pk: [u8; 32],
        bridge_x_pk: [u8; 32],
        endpoint: Endpoint,
        now: u64,
    ) -> MasterInvite {
        let op_pk = op.verifying_key().to_bytes();
        let mut ann = Announcement {
            issued_at: now.saturating_sub(10),
            expires_at: now + 9_000_000,
            bridge_ed25519_pk: bridge_ed_pk,
            bridge_x25519_pk: bridge_x_pk,
            transport_caps: 1,
            endpoint,
            extra_endpoints: Vec::new(),
            signature: [0u8; SIG_LEN],
        };
        let mut prefix = Vec::new();
        ann.encode_signed_prefix(&mut prefix);
        ann.signature = op.sign(&prefix).to_bytes();

        let token = sign_token([0xCDu8; 32], bridge_ed_pk, now + 9_000_000, op);

        MasterInvite::new(
            op_pk,
            [0x01u8; 32],
            now.saturating_sub(10),
            now + 9_000_000,
            Vec::new(),
            vec![token],
            Some(ann),
        )
        .unwrap()
    }

    /// Convenience invite with a placeholder endpoint for the
    /// non-network accessor tests.
    fn dummy_invite() -> MasterInvite {
        let op = SigningKey::from_bytes(&rand_seed());
        make_invite(
            &op,
            [0x11u8; 32],
            [0x22u8; 32],
            Endpoint::Ipv4 {
                addr: [127, 0, 0, 1],
                port: 4433,
            },
            1_000_000,
        )
    }

    fn dummy_config() -> MirageConfig {
        MirageConfig {
            invite: dummy_invite(),
            handshake_timeout: Duration::from_secs(10),
            transport: Transport::PlainTcp,
        }
    }

    #[test]
    fn config_from_invite_text_roundtrip() {
        let invite = dummy_invite();
        let text = invite.encode_text();
        let cfg = MirageConfig::from_invite_text(&format!("mirage://{text}")).unwrap();
        assert_eq!(cfg.invite.bootstrap_tokens.len(), 1);
        assert!(matches!(cfg.transport, Transport::PlainTcp));
        let cfg2 = MirageConfig::from_invite_text(&text).unwrap();
        assert_eq!(cfg2.invite.bootstrap_tokens.len(), 1);
    }

    /// Regression for #4: an invite whose bootstrap announcement was
    /// tampered after signing (here: a flipped `bridge_x25519_pk`, the
    /// MITM-redirect vector) MUST be rejected at parse time - mirage-core
    /// must not blindly trust the embedded announcement.
    #[test]
    fn config_from_invite_text_rejects_tampered_announcement() {
        let mut invite = dummy_invite();
        // Flip a byte of the announcement's bridge X25519 key, leaving the
        // operator pin (and thus the now-stale signature) intact.
        let ann = invite.bootstrap_announcement.as_mut().unwrap();
        ann.bridge_x25519_pk[0] ^= 0x01;
        let text = invite.encode_text();
        let err = MirageConfig::from_invite_text(&format!("mirage://{text}"))
            .expect_err("tampered announcement must be rejected");
        assert!(
            matches!(err, CoreError::Invite(ref s) if s.contains("signature")),
            "expected a signature error, got {err:?}"
        );
    }

    #[test]
    fn bootstrap_endpoint_accessible() {
        let core = MirageCore::new(dummy_config());
        let ep = core.bootstrap_endpoint().unwrap();
        match ep {
            Endpoint::Ipv4 { port, .. } => assert_eq!(*port, 4433),
            _ => panic!("expected ipv4"),
        }
    }

    #[test]
    fn token_pool_size_matches_invite() {
        let core = MirageCore::new(dummy_config());
        assert_eq!(core.token_pool_size(), 1);
    }

    #[test]
    fn next_token_round_robin() {
        let core = MirageCore::new(dummy_config());
        // With 1 token, rotating gives the same token each call.
        let t1 = core.next_token().unwrap().token_id;
        let t2 = core.next_token().unwrap().token_id;
        assert_eq!(t1, t2);
    }

    #[test]
    fn endpoint_dial_str_formats() {
        assert_eq!(
            endpoint_to_dial_str(&Endpoint::Ipv4 {
                addr: [10, 0, 0, 1],
                port: 443
            })
            .unwrap(),
            "10.0.0.1:443"
        );
        assert_eq!(
            endpoint_to_dial_str(&Endpoint::Domain {
                domain: "bridge.example".into(),
                port: 8443
            })
            .unwrap(),
            "bridge.example:8443"
        );
        assert!(endpoint_to_dial_str(&Endpoint::OnionV3 {
            ascii: [b'a'; 56],
            port: 443
        })
        .is_err());
    }

    /// Bridge keyset for the end-to-end tunnel tests.
    struct BridgeKeys {
        op: SigningKey,
        op_pk: [u8; 32],
        bx_sk: [u8; 32],
        bx_pk: [u8; 32],
        bed_pk: [u8; 32],
    }

    fn bridge_keys() -> BridgeKeys {
        let op = SigningKey::from_bytes(&rand_seed());
        let op_pk = op.verifying_key().to_bytes();
        let bx = StaticSecret::from(rand_seed());
        let bx_pk = *PublicKey::from(&bx).as_bytes();
        let bed = SigningKey::from_bytes(&rand_seed());
        BridgeKeys {
            op,
            op_pk,
            bx_sk: bx.to_bytes(),
            bx_pk,
            bed_pk: bed.verifying_key().to_bytes(),
        }
    }

    fn ipv4_endpoint(addr: std::net::SocketAddr) -> Endpoint {
        match addr.ip() {
            std::net::IpAddr::V4(v4) => Endpoint::Ipv4 {
                addr: v4.octets(),
                port: addr.port(),
            },
            std::net::IpAddr::V6(_) => unreachable!("bound to 127.0.0.1"),
        }
    }

    /// Spawn a one-shot bridge: optionally verify the obfs handshake,
    /// run `mirage_session::accept`, then echo one 5-byte message.
    fn spawn_echo_bridge(
        listener: TcpListener,
        k: &BridgeKeys,
        now: u64,
        obfs: bool,
    ) -> tokio::task::JoinHandle<()> {
        let (bx_sk, bx_pk, bed_pk, op_pk) = (k.bx_sk, k.bx_pk, k.bed_pk, k.op_pk);
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            if obfs {
                mirage_transport_obfs::obfs_server_authenticate(
                    &mut sock,
                    &bx_pk,
                    None,
                    Duration::from_secs(5),
                )
                .await
                .expect("obfs server auth");
            }
            let mut rs = ReplaySet::new(16);
            let mut v = TokenVerifier::new(&mut rs, now);
            let mut s = accept(sock, &bx_sk, &bed_pk, &op_pk, &mut v)
                .await
                .expect("bridge accept");
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
            s.flush().await.unwrap();
        })
    }

    /// Drive `open_tunnel` over `transport` against a live bridge and
    /// assert the echo round-trips through the encrypted session.
    async fn assert_tunnel_echo(transport: Transport, obfs: bool) {
        let now = 1_700_000_000u64;
        let k = bridge_keys();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let bridge = spawn_echo_bridge(listener, &k, now, obfs);

        let invite = make_invite(&k.op, k.bed_pk, k.bx_pk, ipv4_endpoint(addr), now);
        let core = MirageCore::new(MirageConfig {
            invite,
            handshake_timeout: Duration::from_secs(5),
            transport,
        });

        let mut tunnel = core.open_tunnel().await.expect("open_tunnel");
        tunnel.write_all(b"hello").await.unwrap();
        tunnel.flush().await.unwrap();
        let mut got = [0u8; 5];
        tunnel.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello");
        bridge.await.unwrap();
    }

    /// Full end-to-end over plain TCP: real Noise-XX + ML-KEM-768
    /// handshake, returned tunnel echoes bytes through the session.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn open_tunnel_plain_tcp_roundtrip_through_real_bridge() {
        assert_tunnel_echo(Transport::PlainTcp, false).await;
    }

    /// Full end-to-end over the obfs-tcp carrier: the bridge verifies
    /// the 64-byte BLAKE3 handshake, then the Mirage session rides the
    /// same socket. Proves the obfs `DuplexStream` feeds the session
    /// handshake correctly through the public `open_tunnel` API.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn open_tunnel_obfs_roundtrip_through_real_bridge() {
        assert_tunnel_echo(Transport::Obfs, true).await;
    }

    #[tokio::test]
    async fn open_tunnel_exhausted_pool_errors() {
        // Build a core whose token pool is then drained past capacity.
        // With one token and a cursor that has wrapped, next_token still
        // yields it; to exercise TokensExhausted we construct an invite
        // with tokens then clear via a zero-token path.
        let op = SigningKey::from_bytes(&rand_seed());
        let invite = make_invite(
            &op,
            [0x11u8; 32],
            [0x22u8; 32],
            Endpoint::Ipv4 {
                addr: [127, 0, 0, 1],
                port: 1,
            },
            1_000_000,
        );
        let mut cfg = MirageConfig {
            invite,
            handshake_timeout: Duration::from_millis(200),
            transport: Transport::PlainTcp,
        };
        cfg.invite.bootstrap_tokens.clear();
        let core = MirageCore::new(cfg);
        let err = core.open_tunnel().await.unwrap_err();
        assert!(matches!(err, CoreError::TokensExhausted), "got {err:?}");
    }
}
