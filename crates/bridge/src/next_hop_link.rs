//! Outbound bridge->next-hop circuit link + dialer abstractions
//! (multi-hop relay, the Phase 2I I/O layer).
//!
//! # Separation of concerns
//!
//! The cell-relay ENGINE - [`crate::circuit_executor::BridgeCircuitExecutor`] -
//! is transport- and authentication-agnostic: it speaks circuit [`Cell`]s
//! over a [`NextHopLink`]. *How* a link to the next bridge is established
//! (which transport, and the bridge-to-bridge authentication / credential
//! model) is the one piece that needs a network design decision, and it lives
//! entirely behind [`NextHopDialer`]. This keeps the security-critical relay
//! logic - onion peeling, per-circuit isolation, return-path mapping, all in
//! [`mirage_circuit::bridge_circuit`] - independent of and unit-testable
//! without a live two-bridge network.
//!
//! - [`SessionStreamLink`] is the production link: it frames cells over an
//!   already-authenticated, full-duplex stream to the next hop (e.g. a
//!   `mirage_session::SessionStream`). Once a `NextHopDialer` exists that
//!   establishes that stream, multi-hop relay is live end-to-end.
//! - Tests inject an in-memory link (a `tokio::io::duplex` pair driven by a
//!   mock next-hop bridge), exercising the full relay engine offline.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use mirage_circuit::cell::Cell;
use mirage_circuit::HopEndpoint;
use mirage_discovery::token::CapabilityToken;
use mirage_runtime::cell_io::{read_cell, write_cell};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

/// BLAKE3 domain-separation label for the relay-leg SS-2022 PSK (C1).
const RELAY_SS_PSK_LABEL: &str = "mirage relay ss2022 psk v1";

/// Derive the SS-2022 PSK used to obfuscate a bridge<->bridge relay leg (C1).
///
/// Deterministic from the ACCEPTING bridge's X25519 public key: the dialer keys
/// off the next-hop pubkey it is dialing, and the target keys off its OWN public
/// key, so both compute the same PSK with no extra provisioning. The key is
/// public-derivable, so it authenticates nothing - it only hides the session's
/// cleartext `MI` handshake magic from an observer on the inter-bridge path;
/// authentication remains the inner Noise-XX session + per-hop capability token.
#[must_use]
pub fn derive_relay_ss_psk(bridge_pk: &[u8; 32]) -> [u8; 32] {
    mirage_crypto::blake3::derive_key(RELAY_SS_PSK_LABEL, bridge_pk)
}

/// A framed, full-duplex circuit-cell link to a next-hop bridge.
///
/// All methods take `&self` (interior mutability) so the link can be held in
/// an `Arc` and shared between the relay engine's send path and its inbound
/// read-pump concurrently.
#[async_trait]
pub trait NextHopLink: Send + Sync {
    /// Send one cell to the next hop. Errors are link-fatal for the
    /// circuits multiplexed on this link.
    async fn send(&self, cell: Cell) -> Result<(), String>;

    /// Read the next cell from the next hop. Returns `None` when the link
    /// is closed or a read error occurs (the pump then exits and the
    /// circuit is reaped).
    async fn recv(&self) -> Option<Cell>;

    /// Best-effort close of the underlying transport.
    async fn close(&self);
}

/// Establishes a fresh [`NextHopLink`] to a next-hop bridge.
///
/// The implementation owns the transport choice and the bridge-to-bridge
/// authentication model. A relay holds one `Arc<dyn NextHopDialer>` and calls
/// [`dial`](Self::dial) on each circuit extension that misses the link pool.
#[async_trait]
pub trait NextHopDialer: Send + Sync {
    /// Connect to `next_hop_pk` at `endpoint`, perform whatever transport +
    /// session handshake the deployment requires, and return a framed link
    /// ready to carry `CMD_CREATE`.
    async fn dial(
        &self,
        next_hop_pk: [u8; 32],
        endpoint: HopEndpoint,
    ) -> Result<Arc<dyn NextHopLink>, String>;
}

/// Production [`NextHopLink`]: circuit cells framed over an authenticated,
/// already-established full-duplex stream to the next bridge.
///
/// The stream is split so the relay engine's send path and the inbound
/// read-pump never contend on a single lock - sends take `writer`, the pump
/// takes `reader`.
pub struct SessionStreamLink<S: AsyncRead + AsyncWrite + Unpin + Send> {
    reader: Mutex<ReadHalf<S>>,
    writer: Mutex<WriteHalf<S>>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> SessionStreamLink<S> {
    /// Wrap an established, authenticated stream to the next hop.
    pub fn new(stream: S) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
        }
    }
}

#[async_trait]
impl<S: AsyncRead + AsyncWrite + Unpin + Send> NextHopLink for SessionStreamLink<S> {
    async fn send(&self, cell: Cell) -> Result<(), String> {
        let mut w = self.writer.lock().await;
        write_cell(&mut *w, &cell)
            .await
            .map_err(|e| format!("next-hop link write: {e}"))
    }

    async fn recv(&self) -> Option<Cell> {
        let mut r = self.reader.lock().await;
        read_cell(&mut *r).await.ok()
    }

    async fn close(&self) {
        let mut w = self.writer.lock().await;
        let _ = w.shutdown().await;
    }
}

/// Production [`NextHopDialer`]: dials the next-hop bridge over TCP, runs a
/// full authenticated Mirage transport session against it (the bridge-to-bridge
/// relay leg), and frames circuit cells over that session via
/// [`SessionStreamLink`].
///
/// # Bridge-to-bridge authentication model
///
/// The relay authenticates to the next hop like any other Mirage client - it
/// presents an **operator-issued capability token** minted for that peer
/// bridge. The relay's config provisions one token per peer it may extend to
/// (`peer_tokens`). Crucially, the relay uses its **stable bridge X25519
/// identity** (`relay_static_sk`) as the session's initiator key rather than an
/// ephemeral key: Noise-XX encrypts that static in message 3, so a passive
/// observer never sees it, but the NEXT HOP learns it and can match it against
/// its relay-peer allowlist to (a) accept the leg and (b) mark the session as a
/// RELAY session - which is what makes it require per-hop client-token
/// verification (see `BridgeCircuitState::new_relay`).
pub struct SessionNextHopDialer {
    /// Relay's stable X25519 static secret - the session initiator key. The
    /// next hop learns the matching public key (Noise-XX msg 3) and can
    /// allowlist it as a known relay peer.
    relay_static_sk: [u8; 32],
    /// Per-peer relay capability token, keyed by the peer bridge's X25519
    /// static public key. `dial(next_hop_pk, ..)` looks the token up here.
    peer_tokens: HashMap<[u8; 32], CapabilityToken>,
    /// Bound on the TCP connect + session handshake to the next hop.
    dial_timeout: Duration,
    /// Whether the relay may dial private / loopback / link-local / reserved IP
    /// destinations. Default `false`: the next-hop `endpoint` is client-chosen
    /// (it rides the client's EXTEND cell), so an unfiltered dial is an SSRF /
    /// internal-port-scan primitive (127.0.0.1, 10/8, 169.254.169.254 cloud
    /// metadata, ...). Mirrors the exit dispatcher's `allow_private_destinations`.
    allow_private: bool,
}

impl SessionNextHopDialer {
    /// Construct a relay dialer that refuses private/unsafe next-hop
    /// destinations (the safe default). `relay_static_sk` is the relay bridge's
    /// X25519 static secret; `peer_tokens` maps each reachable peer bridge's
    /// X25519 public key to the operator-issued relay token for it.
    #[must_use]
    pub fn new(
        relay_static_sk: [u8; 32],
        peer_tokens: HashMap<[u8; 32], CapabilityToken>,
        dial_timeout: Duration,
    ) -> Self {
        Self {
            relay_static_sk,
            peer_tokens,
            dial_timeout,
            allow_private: false,
        }
    }

    /// Permit private / loopback destinations (test / trusted-LAN deployments
    /// only). DANGEROUS in production: the next-hop endpoint is client-chosen,
    /// so enabling this turns the relay into an SSRF probe.
    #[must_use]
    pub fn allow_private_destinations(mut self) -> Self {
        self.allow_private = true;
        self
    }
}

/// Resolve a routable [`HopEndpoint`] to a [`SocketAddr`] for a direct TCP dial.
/// `OnionV3` (and the deprecated `Domain`) endpoints are refused - the direct
/// TCP relay leg only reaches IP endpoints.
fn endpoint_to_socketaddr(endpoint: &HopEndpoint) -> Result<SocketAddr, String> {
    match endpoint {
        HopEndpoint::Ipv4 { addr, port } => {
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(*addr)), *port))
        }
        HopEndpoint::Ipv6 { addr, port } => {
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(*addr)), *port))
        }
        other => Err(format!(
            "relay dial: non-IP next-hop endpoint not supported ({other:?})"
        )),
    }
}

#[async_trait]
impl NextHopDialer for SessionNextHopDialer {
    async fn dial(
        &self,
        next_hop_pk: [u8; 32],
        endpoint: HopEndpoint,
    ) -> Result<Arc<dyn NextHopLink>, String> {
        let addr = endpoint_to_socketaddr(&endpoint)?;
        let token = self.peer_tokens.get(&next_hop_pk).ok_or_else(|| {
            "relay dial: no relay token provisioned for next-hop bridge".to_string()
        })?;
        // SSRF guard: the next-hop endpoint is CLIENT-chosen (it rides the
        // client's EXTEND cell). Refuse private/loopback/link-local/reserved
        // targets (e.g. 127.0.0.1, 10/8, 169.254.169.254 cloud metadata) unless
        // explicitly allowed - the endpoint is not bound to `next_hop_pk`, so a
        // client naming a real peer could otherwise scan/hit internal services.
        // Use the SAME parametrised gate as the exit path (red-team #10): even
        // when `allow_private` is set, always-forbidden ranges (cloud metadata,
        // link-local, multicast, IPv4-in-IPv6 embeddings) stay refused - the old
        // single-flag `!allow_private && ...` bypassed the whole check and
        // re-admitted metadata whenever private targets were allowed.
        if crate::stream_dispatcher::ip_forbidden_as_destination(
            addr.ip(),
            self.allow_private,
            self.allow_private,
        ) {
            return Err(format!(
                "relay dial: refusing private/unsafe next-hop address {addr} (SSRF guard)"
            ));
        }

        let connect_and_handshake = async {
            let tcp = TcpStream::connect(addr)
                .await
                .map_err(|e| format!("relay dial: TCP connect {addr}: {e}"))?;
            tcp.set_nodelay(true).ok();
            // C1: wrap the relay leg in SS-2022 so the Mirage session's cleartext
            // `MI` handshake magic (+ fixed message-type bytes) never appear on the
            // wire between bridges. The PSK is derived from the TARGET bridge's
            // public key (the target derives the identical key from its own key and
            // accepts it via `MuxConfig::relay_ss_psk`), so no extra provisioning is
            // needed. This obfuscates only; authentication remains the inner Noise
            // session. The peer MUST run the protocol mux (the default) to unwrap it.
            let relay_psk = derive_relay_ss_psk(&next_hop_pk);
            let ss = mirage_transport_shadowsocks::ss2022_client_dial(
                tcp,
                &relay_psk,
                self.dial_timeout,
            )
            .await
            .map_err(|e| format!("relay dial: ss2022 wrap: {e}"))?;
            // Full authenticated Mirage session to the next hop, keyed by the
            // relay's stable identity so the peer can allowlist us as a relay.
            let session = mirage_session::connect(ss, &self.relay_static_sk, &next_hop_pk, token)
                .await
                .map_err(|e| format!("relay dial: session handshake: {e}"))?;
            Ok::<_, String>(session)
        };

        let session = tokio::time::timeout(self.dial_timeout, connect_and_handshake)
            .await
            .map_err(|_| format!("relay dial: timed out after {:?}", self.dial_timeout))??;

        Ok(Arc::new(SessionStreamLink::new(session)) as Arc<dyn NextHopLink>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_circuit::CMD_CREATE;

    #[tokio::test]
    async fn session_stream_link_round_trips_cells_both_ways() {
        let (near, far) = tokio::io::duplex(8192);
        let link = SessionStreamLink::new(near);

        // link.send -> the far (raw) end reads the framed cell.
        let out = Cell::new(42, CMD_CREATE, vec![1, 2, 3]).unwrap();
        link.send(out).await.unwrap();
        let mut far = far;
        let got = read_cell(&mut far).await.unwrap();
        assert_eq!(got.circ_id, 42);
        assert_eq!(got.command, CMD_CREATE);

        // far writes a framed cell -> link.recv reads it.
        let reply = Cell::new(43, CMD_CREATE, vec![9, 9]).unwrap();
        write_cell(&mut far, &reply).await.unwrap();
        let recvd = link.recv().await.expect("link recv");
        assert_eq!(recvd.circ_id, 43);

        // EOF on the far end surfaces as None (pump-exit signal).
        drop(far);
        assert!(link.recv().await.is_none(), "closed link -> recv None");
    }

    #[tokio::test]
    async fn dialer_establishes_authenticated_relay_link_and_frames_cells() {
        use mirage_crypto::ed25519_dalek::SigningKey;
        use mirage_crypto::x25519_dalek::{PublicKey, StaticSecret};
        use mirage_discovery::replay::ReplaySet;
        use mirage_discovery::token::sign_token;
        use mirage_session::TokenVerifier;
        use tokio::net::TcpListener;

        let now = 1_700_000_000u64;
        let op_sk = SigningKey::from_bytes(&[0x11; 32]);
        let op_pk = op_sk.verifying_key().to_bytes();
        // Next hop (bridge-1) transport + identity keys.
        let b1_x = StaticSecret::from([0x22; 32]);
        let b1_pk = *PublicKey::from(&b1_x).as_bytes();
        let b1_sk = b1_x.to_bytes();
        let b1_id = SigningKey::from_bytes(&[0x33; 32]);
        let b1_ed_pk = b1_id.verifying_key().to_bytes();
        // Relay (bridge-0) stable identity used as the session initiator key.
        let relay_sk = StaticSecret::from([0x44; 32]).to_bytes();
        // Operator-issued relay token naming bridge-1.
        let token = sign_token([0x55; 32], b1_ed_pk, now + 3600, &op_sk);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // bridge-1: accept the relay leg (verifies the token) + read one cell.
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            // C1: the dialer SS-2022-wraps the relay leg; unwrap it with the relay
            // PSK derived from bridge-1's own pubkey (the identical key the dialer
            // derived from the next-hop pubkey it dialed).
            let relay_psk = derive_relay_ss_psk(&b1_pk);
            let ss = mirage_transport_shadowsocks::ss2022_server_auth(
                tcp,
                &relay_psk,
                Duration::from_secs(5),
            )
            .await
            .expect("bridge-1 ss2022 unwrap relay leg");
            let mut replay = ReplaySet::new(64);
            let mut verifier = TokenVerifier::new(&mut replay, now);
            let mut session = mirage_session::accept(ss, &b1_sk, &b1_ed_pk, &op_pk, &mut verifier)
                .await
                .expect("bridge-1 accept relay leg");
            read_cell(&mut session).await.expect("read framed cell")
        });

        // Relay dials bridge-1 and frames a CREATE cell over the link.
        let mut peers = HashMap::new();
        peers.insert(b1_pk, token);
        // Loopback listener -> allow private for this test.
        let dialer = SessionNextHopDialer::new(relay_sk, peers, Duration::from_secs(5))
            .allow_private_destinations();
        let ep = match addr {
            SocketAddr::V4(v4) => HopEndpoint::Ipv4 {
                addr: v4.ip().octets(),
                port: v4.port(),
            },
            SocketAddr::V6(v6) => HopEndpoint::Ipv6 {
                addr: v6.ip().octets(),
                port: v6.port(),
            },
        };
        let link = dialer.dial(b1_pk, ep).await.expect("relay dial");
        link.send(Cell::new(7, CMD_CREATE, vec![0xAB; 100]).unwrap())
            .await
            .expect("send over link");

        let got = server.await.unwrap();
        assert_eq!(got.circ_id, 7);
        assert_eq!(got.command, CMD_CREATE);
        assert_eq!(got.body, vec![0xAB; 100]);
    }

    #[tokio::test]
    async fn dialer_without_token_for_peer_errors() {
        let dialer = SessionNextHopDialer::new([0x44; 32], HashMap::new(), Duration::from_secs(1));
        let ep = HopEndpoint::Ipv4 {
            addr: [127, 0, 0, 1],
            port: 9,
        };
        let err = dialer
            .dial([0x99; 32], ep)
            .await
            .err()
            .expect("dial without a peer token must fail");
        assert!(err.contains("no relay token"), "got: {err}");
    }

    #[tokio::test]
    async fn dialer_refuses_private_next_hop_ssrf() {
        use mirage_crypto::ed25519_dalek::SigningKey;
        use mirage_discovery::token::sign_token;
        // A valid token for the peer, but the client-chosen endpoint points at
        // a private / cloud-metadata address -> refused (SSRF guard), never dialed.
        let op = SigningKey::from_bytes(&[0x11; 32]);
        let peer_pk = [0x22; 32];
        let token = sign_token([0x55; 32], [0x33; 32], 4_000_000_000, &op);
        let mut peers = HashMap::new();
        peers.insert(peer_pk, token);
        let dialer = SessionNextHopDialer::new([0x44; 32], peers, Duration::from_secs(1));

        for octets in [
            [127, 0, 0, 1],
            [10, 0, 0, 5],
            [169, 254, 169, 254],
            [192, 168, 1, 1],
        ] {
            let ep = HopEndpoint::Ipv4 {
                addr: octets,
                port: 443,
            };
            let err = dialer
                .dial(peer_pk, ep)
                .await
                .err()
                .unwrap_or_else(|| panic!("private target {octets:?} must be refused"));
            assert!(err.contains("SSRF guard"), "got: {err} for {octets:?}");
        }
    }
}
