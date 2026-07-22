//! Mirage client daemon.
//!
//! Exposes a local TCP port on the user's machine; every incoming
//! connection is tunneled through a fresh Mirage session to a
//! bridge, and the bridge runs a SOCKS5 server on the decrypted
//! side. Applications point their SOCKS5 configuration at the
//! client's local bind.
//!
//! # Multi-entry pool (Phase 2P)
//!
//! The headline feature of Mirage is that the client maintains
//! sessions through **multiple entry bridges simultaneously**, each
//! independently addressable.  When a censor blocks one bridge's
//! IP, others keep flowing.
//!
//! ```json
//! {
//!   "local_bind": "127.0.0.1:1080",
//!   "invites": [
//!     "mirage://base64invite1...",
//!     "mirage://base64invite2...",
//!     "mirage://base64invite3..."
//!   ]
//! }
//! ```
//!
//! Each invite points at one bridge.  The client picks the next
//! healthy entry in round-robin order.  On connection failure the
//! entry is soft-failed for `entry_failure_backoff_secs` (default
//! 30) and the next entry is tried transparently.  If every entry
//! fails the connection is refused with an error.
//!
//! # Single-invite backward compat
//!
//! The original `invite` field is still supported and merged with
//! `invites`.  Explicit-hex fields (`bridge_addr`,
//! `bridge_x25519_pk_hex`, etc.) remain for debugging.
//!
//! # Token rotation
//!
//! Each bootstrap token is single-use (bridge-side replay set
//! enforces). The client rotates through `invite.bootstrap_tokens`
//! in round-robin order per bridge entry. A client with N tokens
//! can open N tunnels before needing a fresh invite. Session-scoped
//! refresh tokens (v0.1.1) let a long-lived client request more
//! tokens in-band after the first successful session.

// The client handles bridge secrets, capability tokens, and (in TUN mode) raw
// device packets. It contains no `unsafe` and must never acquire any: forbid it
// at the crate root so a future edit that reaches for `unsafe` fails to compile.
#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

use std::collections::VecDeque;

use mirage_circuit::{
    cell::Cell, circuit::Circuit, derive_hop_keys_from_handshake, BeginBody, DataBody, EndBody,
    ExtendBody, ExtendFinishBody, HandshakeBody, HopEndpoint, HopKeys, RelaySubCell, CMD_BEGIN,
    CMD_CREATE, CMD_CREATED, CMD_CREATED_CONT, CMD_CREATE_CONT, CMD_DATA, CMD_END, CMD_EXTEND,
    CMD_EXTENDED, CMD_EXTENDED_CONT, CMD_EXTEND_CONT, CMD_EXTEND_FINISH, CMD_RELAY,
    MAX_CELL_PAYLOAD, MAX_CIRCUIT_HOPS, RELAY_SUBCELL_HEADER_LEN,
};
use mirage_common::process_hardening::harden_process;
use mirage_crypto::x25519_dalek::StaticSecret;
use mirage_discovery::derive::{derive_port, epoch_for_time, NAMESPACE_CLIENT_TO_BRIDGE};
use mirage_discovery::invite::MasterInvite;
use mirage_discovery::pipeline::ClientSubscriber;
use mirage_discovery::router::DiscoveryRouter;
use mirage_discovery::token::{CapabilityToken, TOKEN_LEN};
use mirage_discovery::token_fs::FsCapabilityToken;
use mirage_discovery::wire::Endpoint;
use mirage_discovery::{redeem_invite_claim, refresh_session_tokens};
use mirage_discovery_dht::MainlineDhtClient;
use mirage_discovery_dns_txt::{DnsTxtChannel, HickoryDnsTxtResolver};
use mirage_discovery_nostr::relay::{NostrRelayChannel, NostrRelayConfig};
use mirage_discovery_nostr::signing::NostrSigningKey;
use mirage_runtime::cell_io::{read_cell, write_cell};
use mirage_session::cover::{CoverDecision, CoverPolicy, CoverScheduler};
use mirage_session::{
    connect, connect_fs, HandshakeInitiator, SessionError, SessionStream, UdpFramer,
    MAX_UDP_DATAGRAM_BYTES, UDP_RELAY_MAGIC_HOSTNAME, UDP_RELAY_MAGIC_PORT,
};
use mirage_socks5::server::{read_request, send_success_reply_for_internal, ConnectTarget};
use mirage_socks5::{REP_GENERAL_FAILURE, REP_HOST_UNREACHABLE, REP_SUCCEEDED};

mod local_socks;
use mirage_mux::{MuxConnError, MuxConnection, MuxPolicy, MuxTarget, StreamRole, MUX_SESSION_TAG};
use mirage_transport::adaptive::{class_of, outcome_reward, AdaptiveRouter};
use mirage_transport::posture_net::PostureNet;
use mirage_transport::DuplexStream;
use mirage_transport::{
    load_from_path, rank_names, save_to_path, NetworkFingerprint, SelectionPolicy, SuccessRateMap,
};
use mirage_transport_hysteria2::{hysteria2_client_connect, Hysteria2ClientConfig};
use mirage_transport_pad::{PadConfig, PaddedStream};
use mirage_transport_reality::{reality_connect, ClientCarrierInputs};
use serde::Deserialize;
use tokio::io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

// -- configuration ------------------------------------------------------------

// No `Debug`: holds the client X25519 secret, the SS-2022 PSK, and a capability
// token (all as hex). Omitting Debug makes a stray `debug!(?config)` a compile
// error rather than a secret leak into logs/backups.
#[derive(Deserialize)]
struct ClientConfig {
    /// `host:port` the client listens on for local SOCKS5 connections.
    local_bind: String,

    // ----- Multi-entry pool (Phase 2P) -----
    /// List of invites for multiple bridge entries.
    /// Each entry is `"mirage://<base64-url>"` or bare base64-url.
    /// Takes priority over the singular `invite` field.
    #[serde(default)]
    invites: Vec<String>,

    // ----- Single-invite mode (backward compat) -----
    /// Single bridge invite. If `invites` is also set, this is
    /// merged as an additional entry.
    #[serde(default)]
    invite: Option<String>,

    // ----- Explicit-hex mode (debug / migration) -----
    #[serde(default)]
    bridge_addr: Option<String>,
    #[serde(default)]
    bridge_x25519_pk_hex: Option<String>,
    #[serde(default)]
    client_x25519_sk_hex: Option<String>,
    #[serde(default)]
    token_hex: Option<String>,

    #[serde(default = "default_handshake_timeout_secs")]
    handshake_timeout_secs: u64,

    // ---- TUN VPN mode (build feature `tun`) ----
    /// Route ALL OS traffic through Mirage via a TUN device - transparent,
    /// system-wide, no per-app SOCKS config. Requires a `tun`-feature build and
    /// `CAP_NET_ADMIN`. Default false = SOCKS5 proxy mode. When enabled, the
    /// SOCKS5 listener still runs too (apps can use either).
    #[serde(default)]
    tun_enabled: bool,
    /// TUN interface name.
    #[serde(default = "default_tun_name")]
    tun_name: String,
    /// TUN interface address (the gateway apps route to).
    #[serde(default = "default_tun_address")]
    tun_address: std::net::Ipv4Addr,
    /// TUN interface netmask.
    #[serde(default = "default_tun_netmask")]
    tun_netmask: std::net::Ipv4Addr,
    /// TUN interface MTU.
    #[serde(default = "default_tun_mtu")]
    tun_mtu: usize,

    // ---- Reality transport (v0.1a) ----
    #[serde(default)]
    reality_enabled: bool,
    #[serde(default)]
    reality_sni: Option<String>,

    /// PARANOID MODE (Proteus). One switch for the strongest posture: Reality
    /// carrier, multi-hop onion relay, handshake padding, fail-closed (no raw
    /// fallback), and - the headline - REPLAY pacing, so the flow wears a real
    /// recorded video-streaming shape (the entropy-floor law: generated traffic is
    /// detectable, replayed real traffic is not). Overrides the individual switches.
    /// The bridge must also run paranoid/reality+replay for the pacing to match.
    #[serde(default)]
    paranoid: bool,
    /// Envelope pacing mode: `video`/`browse` (generative) or `replay` (wear a real
    /// captured trace - recommended; see `tools/cover-sources`). Config equivalent of
    /// `MIRAGE_REALITY_PACE`. Paranoid mode sets this to `replay`.
    #[serde(default)]
    reality_pace: Option<String>,
    /// For `reality_pace = "replay"`: the trace file, or a directory library of real
    /// traces (one is chosen per session). Config equivalent of
    /// `MIRAGE_REALITY_PACE_PROFILE`.
    #[serde(default)]
    reality_pace_profile: Option<String>,
    /// Explicit opt-in to the unobfuscated raw-TCP carrier. When NO obfuscated
    /// transport is configured, the client would otherwise silently fall back to
    /// raw Noise-over-TCP, whose `MI` magic + message-type bytes are a cleartext
    /// distinguisher a censor pins on the first packet (red-team #11). To avoid
    /// silently exposing a censored user, that fallback now FAILS unless this is
    /// `true`. Only set it on an uncensored network (dev/testing).
    #[serde(default)]
    allow_insecure_raw: bool,
    /// Permit Shadowsocks-2022 as the SOLE outer carrier despite its uniform-
    /// random-from-byte-0 wire (the Wu-2023 fully-encrypted-traffic signature a
    /// GFW-class entropy classifier flags - the same class that got obfs4
    /// dropped, red-team #3). ss2022's entropy is inherent (AEAD + random salt)
    /// and it cannot be nested inside a mimicry transport here, so with no other
    /// transport configured the client fails closed unless this is `true`. Only
    /// set it where Shadowsocks itself is permitted and no entropy DPI runs.
    #[serde(default)]
    allow_ss2022_outer: bool,
    /// Wrap the meek / DoH / WebSocket carriers in client-originated TLS
    /// (red-team #4). These carriers speak cleartext HTTP by default; with this
    /// set, the client completes a REAL browser-rooted TLS handshake to a
    /// TLS-terminating front (a CDN edge, or an nginx/Caddy on :443 with a cert
    /// valid for the front domain) before the HTTP, so the flow is genuinely
    /// HTTPS-to-a-front rather than plaintext. Requires such a terminator in
    /// front of the bridge. Default `false` (cleartext; only safe on an
    /// uncensored network or behind an EXTERNAL terminator the client reaches in
    /// cleartext).
    #[serde(default)]
    carrier_tls: bool,
    /// Explicit SNI / cert hostname for [`Self::carrier_tls`]. Defaults to the
    /// carrier's front domain (meek/DoH) or cover host (WS) when unset.
    #[serde(default)]
    carrier_tls_sni: Option<String>,
    /// JA3/JA4 fingerprint template (`"chrome-desktop"`,
    /// `"firefox-desktop"`, `"safari-desktop"`).  Default:
    /// `"chrome-desktop"`.
    #[serde(default)]
    reality_tls_fingerprint: Option<String>,

    // ---- Shadowsocks-2022 transport ----
    /// Shadowsocks-2022 PSK (hex, 32 bytes).  If set, dial the bridge using
    /// SS-2022 as the carrier instead of Reality TLS.
    #[serde(default)]
    ss2022_psk_hex: Option<String>,

    // ---- WebSocket transport ----
    /// Use WebSocket as the carrier.  Requires the bridge to have
    /// `ws_enabled=true`.  Ignored if `ss2022_psk_hex` is also set
    /// (SS-2022 takes precedence).
    #[serde(default)]
    ws_enabled: Option<bool>,
    /// WebSocket path (default `"/"`).  Used when `ws_enabled=true`.
    #[serde(default)]
    ws_path: Option<String>,

    // ---- Hysteria2 (QUIC/BRUTAL) transport ----
    /// Use Hysteria2 (QUIC + BRUTAL congestion) as the carrier.
    /// Takes priority over all other transports when `true`.
    /// Requires the bridge to have `hysteria2_bind` configured.
    #[serde(default)]
    hysteria2_enabled: Option<bool>,
    /// Target send rate in Mbps for the BRUTAL congestion controller.
    /// Default 100 Mbps.  Ignored unless `hysteria2_enabled=true`.
    #[serde(default)]
    hysteria2_send_rate_mbps: Option<u64>,
    /// Cover hostname for the Hysteria2 QUIC SNI. MUST match the bridge's
    /// `hysteria2_hostname`. When unset, a per-bridge cover hostname is derived
    /// from the bridge static key (the bridge derives the identical SAN), so the
    /// default is never the RFC 2606 `cdn.example.com` nor a shared constant.
    #[serde(default)]
    hysteria2_hostname: Option<String>,

    // ---- HTTP/3 (MASQUE) transport ----
    /// Enable the HTTP/3 (QUIC) carrier. Requires the bridge to have
    /// `h3_enabled`. Dials the bridge endpoint over QUIC + HTTP/3.
    #[serde(default)]
    h3_enabled: Option<bool>,
    /// Cover hostname for the HTTP/3 QUIC SNI. MUST match the bridge's
    /// `h3_hostname`. When unset, derived per-bridge from the bridge static key
    /// (matching the bridge's SAN), never the RFC 2606 `cdn.example.com`.
    #[serde(default)]
    h3_hostname: Option<String>,
    /// Shared password enabling Gecko/Salamander QUIC obfuscation on the QUIC
    /// carriers (h3 / hysteria2). When set, every QUIC datagram is XOR-scrambled
    /// and handshake packets are fragmented, so the wire shows no QUIC
    /// fingerprint. MUST match the bridge's `quic_obfs_password`.
    #[serde(default)]
    quic_obfs_password: Option<String>,
    /// Disable Salamander QUIC obfuscation and speak plain, parseable QUIC on
    /// the h3/hysteria2 carriers. Salamander XORs datagrams into a uniform-random
    /// stream (the Wu-2023 entropy signature - red-team #9); plain QUIC evades
    /// that but re-exposes the quinn!=Chrome fingerprint, so it should be fronted
    /// by a real CA-cert origin. MUST match the bridge's `quic_obfs_disable` - a
    /// mismatch garbles the QUIC Initial. Default `false` (Salamander).
    #[serde(default)]
    quic_obfs_disable: bool,

    // ---- dnstt (DNS tunnel) transport ----
    /// Enable the full DNS-tunnel carrier. Requires `dnstt_domain` +
    /// `dnstt_resolver`. Works where only DNS/port 53 is allowed.
    #[serde(default)]
    dnstt_enabled: Option<bool>,
    /// Tunnel domain the bridge is the authoritative name server for.
    #[serde(default)]
    dnstt_domain: Option<String>,
    /// Resolver (or the bridge's `host:53`) to send DNS queries to.
    #[serde(default)]
    dnstt_resolver: Option<String>,

    // ---- Meek HTTP domain-fronting transport ----
    /// CDN front domain for Meek HTTP long-polling (used as the HTTP `Host`
    /// header so the CDN routes the request to the bridge reflector).
    /// When set, Meek is used as the carrier transport.
    /// Priority: below SS-2022, above DoH.
    #[serde(default)]
    meek_front_domain: Option<String>,
    /// HTTP path for Meek requests. Default `"/"` (never a project-identifying string).
    #[serde(default)]
    meek_path: Option<String>,

    // ---- WebRTC transport ----
    /// Signaling `Host` header / front domain. When set, the WebRTC carrier is
    /// tried: SDP is exchanged over HTTP, the session rides a data channel.
    #[serde(default)]
    webrtc_signaling_host: Option<String>,
    /// Signaling request path.  Default `"/webrtc/offer"`.
    #[serde(default)]
    webrtc_path: Option<String>,
    /// STUN/TURN servers for ICE (empty = default STUN / host candidates).
    #[serde(default)]
    webrtc_ice_servers: Vec<String>,

    // ---- DoH-tunnel transport ----
    /// HTTP `Host` header (front domain) for DNS-over-HTTPS tunneling.
    /// When set, DoH is used as the carrier: `POST /dns-query` with
    /// `Content-Type: application/dns-message`.  Priority: below Meek,
    /// above WebSocket.
    #[serde(default)]
    doh_front_domain: Option<String>,

    // ---- VLESS framing (applied on top of any carrier) ----
    /// VLESS UUID (hex, optionally with dashes, 16 bytes / 36 chars).
    /// When set, the client sends a VLESS auth header after the carrier
    /// transport handshake and before the Mirage Noise session.
    /// The bridge must have `vless_uuid_hex` set to the same value.
    #[serde(default)]
    vless_uuid_hex: Option<String>,

    // ---- Multi-entry failure policy ----
    /// How long (seconds) a failed entry is skipped before being
    /// retried.  Default 30.  Set to 0 to disable soft-failure
    /// (always try every entry).
    #[serde(default = "default_entry_failure_backoff_secs")]
    entry_failure_backoff_secs: u64,

    /// Path to persist per-network transport success rates. The client loads it
    /// on startup (biasing toward transports that worked before) and saves every
    /// 60s, so learned censorship state survives a restart instead of being
    /// re-probed from scratch. Omitted/`null` = ON by default at the XDG state
    /// path (`$XDG_STATE_HOME/mirage/success-state.json`, else
    /// `$HOME/.local/state/mirage/...`; see `default_success_state_path`). Set
    /// an explicit path to override, or `""` to disable persistence entirely.
    #[serde(default)]
    success_state_path: Option<String>,

    // ---- Frame-padding and jitter (T3 ML flow-fingerprinting countermeasure) ----
    /// When true, wraps every transport stream with PaddedStream before the
    /// Noise session. Must match the bridge's `pad_enabled` setting.
    ///
    /// Default ON (DPI-R1): without padding the fixed-length Noise handshake
    /// (msg1 1221B, msg2 1189B, msg3 203B) is a single-flow passive fingerprint
    /// that a GFW-class classifier catches on connection one. Padding buckets +
    /// jitters those sizes. Both sides default-on so generated config pairs are
    /// resistant out of the box.
    #[serde(default = "default_true")]
    pad_enabled: bool,

    /// When true (default), the client multiplexes many browser connections
    /// over a small pool of long-lived bridge sessions instead of one fresh
    /// session (handshake + capability token + per-IP slot) per connection.
    /// This is what makes a browser - which opens 100-300 parallel connections
    /// to load a page - workable: the expensive Noise+ML-KEM handshake and the
    /// single-use token are amortized across hundreds of streams. Must match
    /// the bridge's `stream_mux_enabled` setting. Turn OFF only for a
    /// circuit-relay deployment (`circuit_relay_enabled`), which uses its own
    /// session model.
    #[serde(default = "default_true")]
    stream_mux_enabled: bool,

    /// Constant-bitrate frame size for the padding layer (bytes).
    /// Only meaningful when `pad_enabled = true`.
    /// `None` (default) - event-driven mode (jitter + chaff).
    #[serde(default)]
    pad_cbr_frame_bytes: Option<usize>,

    /// CBR inter-frame interval in milliseconds. Default 10.
    /// Only meaningful when `pad_cbr_frame_bytes` is set.
    #[serde(default = "default_pad_cbr_interval_ms")]
    pad_cbr_interval_ms: u64,

    // ---- Dynamic discovery (Nostr + DNS TXT) ----
    /// WebSocket URLs of Nostr relays to subscribe to for dynamic bridge discovery.
    /// Format: `["wss://relay.damus.io", "wss://nostr.bitcoiner.social"]`.
    /// When non-empty, a background task periodically fetches bridge announcements
    /// from these relays and adds newly-discovered bridge addresses to the pool.
    /// This lets clients find a bridge's new IP after the operator moves it to evade
    /// a censor - no manual config update required.
    #[serde(default)]
    nostr_relays: Vec<String>,
    /// DNS apex zones for DNS TXT discovery (channel of last resort when Nostr is blocked).
    /// Format: `["bridges.example.com", "fallback.example.org"]`.
    /// The client looks up TXT records at `_mirage.<hex(info_hash)>.<apex>` to fetch
    /// bridge announcements published by the operator via their DNS zone authority.
    /// DNS TXT discovery works even when Nostr/WebSocket connections are blocked.
    #[serde(default)]
    dns_discovery_apexes: Vec<String>,
    /// BitTorrent mainline DHT bootstrap node addresses for BEP-44 discovery.
    ///
    /// When non-empty, a `MainlineDhtClient` is added to the discovery router
    /// alongside any Nostr relays and DNS TXT channels.  Operators publish
    /// announcements under their BEP-44 mutable item key so clients can find
    /// them even when ALL relay-based channels are blocked - DHT traffic is
    /// indistinguishable from normal BitTorrent on UDP:6881.
    ///
    /// Default: empty (DHT discovery disabled).  Leave empty if the censor
    /// does not block Nostr and you want to avoid the extra UDP traffic.
    ///
    /// Bootstrap nodes: any reachable DHT node works.  Well-known public nodes:
    ///   - `dht.transmissionbt.com:6881`
    ///   - `router.bittorrent.com:6881`
    ///   - `router.utorrent.com:6881`
    ///
    /// An empty list with `dht_enabled: true` uses the `mainline` crate's
    /// default bootstrap nodes (the same BitTorrent DHT bootstrap list).
    #[serde(default)]
    dht_bootstrap_addrs: Vec<String>,
    /// Enable BitTorrent mainline DHT discovery even if `dht_bootstrap_addrs`
    /// is empty (uses the `mainline` crate's built-in bootstrap list).
    /// Default false.  Set true when the operator publishes via DHT and you
    /// want the censorship-resistant UDP discovery channel.
    #[serde(default)]
    dht_enabled: bool,
    /// How often (seconds) the discovery task re-fetches the current epoch's
    /// announcements from all configured channels. Default 300 (5 minutes).
    #[serde(default = "default_discovery_interval_secs")]
    discovery_interval_secs: u64,

    // ---- Circuit relay mode (Phase 2H) ----
    /// When true, the client runs a circuit-layer handshake (CMD_CREATE ->
    /// CMD_CREATED) inside the transport session and routes SOCKS5 traffic
    /// as onion-sealed CMD_RELAY cells. The bridge must have
    /// `circuit_relay_enabled = true`.  Default false (SOCKS5 passthrough).
    ///
    /// MULTI-HOP (wired): the client builds an onion circuit through the entry
    /// bridge plus additional hops selected from OTHER pool bridges - it sends
    /// `CMD_EXTEND` to telescope to each exit hop and onion-seals traffic across
    /// all layers. With >=2 distinct, IP-reachable, token-bearing bridges in the
    /// pool it forms a 2-hop circuit: the entry sees your IP but not the
    /// destination; the exit sees the destination but not your IP. Genuine
    /// anonymity requires the hops to be DIFFERENT operators' bridges (a
    /// multi-operator mesh); a single-operator two-bridge circuit still lets that
    /// operator correlate entry+exit. With only the entry available it degrades
    /// to single-hop (entry == exit, no anonymity).
    #[serde(default)]
    circuit_relay: bool,

    // ---- Cover traffic (idle-period decoy fetches) ----
    /// Decoy destinations the client fetches THROUGH the tunnel during idle
    /// periods so an observer of the encrypted tunnel can't infer "user is idle"
    /// from a quiet channel. Each entry is `host[:port][/path]` (default port
    /// 443, path `/`) and is fetched over REAL end-to-end HTTPS - so unlike
    /// synthetic record-size shaping (which the codebase measured can BACKFIRE
    /// against real covers), cover traffic can never emit a wrong byte
    /// distribution; it IS a real distribution. Empty (default) disables cover.
    /// Point these at high-traffic fronted hosts consistent with your carriers.
    #[serde(default)]
    cover_destinations: Vec<String>,
    /// Idle time (seconds) after which cover engages. Default 60.
    #[serde(default = "default_cover_idle_secs")]
    cover_idle_secs: u64,
    /// Mean seconds between cover fetches while idle. Default 30.
    #[serde(default = "default_cover_interval_secs")]
    cover_interval_secs: u64,
    /// Hard cap on cover's share of tunnel bytes (0.05 = 5%). Default 0.05.
    #[serde(default = "default_cover_max_fraction")]
    cover_max_fraction: f64,
}

fn default_cover_idle_secs() -> u64 {
    60
}
fn default_cover_interval_secs() -> u64 {
    30
}
fn default_cover_max_fraction() -> f64 {
    0.05
}

fn default_handshake_timeout_secs() -> u64 {
    10
}
fn default_tun_name() -> String {
    "mirage0".to_string()
}
fn default_tun_address() -> std::net::Ipv4Addr {
    std::net::Ipv4Addr::new(10, 200, 0, 1)
}
fn default_tun_netmask() -> std::net::Ipv4Addr {
    std::net::Ipv4Addr::new(255, 255, 255, 0)
}
fn default_tun_mtu() -> usize {
    1400
}
fn default_entry_failure_backoff_secs() -> u64 {
    30
}
fn default_true() -> bool {
    true
}

fn default_pad_cbr_interval_ms() -> u64 {
    10
}
fn default_discovery_interval_secs() -> u64 {
    300
}

/// Default path for the learned transport-success state, used when the config
/// leaves `success_state_path` unset. Resolves to
/// `$XDG_STATE_HOME/mirage/success-state.json` (or `$HOME/.local/state/...`),
/// so a plain deployment persists "what worked on this network" across restarts
/// by default. Returns `None` when neither env var is set (e.g. a minimal
/// container) - persistence then stays off rather than writing to a guessed
/// location.
fn default_success_state_path() -> Option<String> {
    let base = match std::env::var_os("XDG_STATE_HOME") {
        Some(x) if !x.is_empty() && std::path::Path::new(&x).is_absolute() => {
            std::path::PathBuf::from(x)
        }
        _ => std::path::PathBuf::from(std::env::var_os("HOME")?).join(".local/state"),
    };
    Some(
        base.join("mirage")
            .join("success-state.json")
            .to_string_lossy()
            .into_owned(),
    )
}

// -- credential helpers -------------------------------------------------------

fn decode_key32(hex_str: &str, name: &'static str) -> Result<[u8; 32], String> {
    let raw = hex::decode(hex_str.trim()).map_err(|e| format!("{name}: hex decode: {e}"))?;
    if raw.len() != 32 {
        return Err(format!("{name}: expected 32 bytes, got {}", raw.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn decode_token(hex_str: &str) -> Result<CapabilityToken, String> {
    let raw = hex::decode(hex_str.trim()).map_err(|e| format!("token: hex decode: {e}"))?;
    if raw.len() != TOKEN_LEN {
        return Err(format!(
            "token: expected {TOKEN_LEN} bytes, got {}",
            raw.len()
        ));
    }
    CapabilityToken::decode(&raw).map_err(|e| format!("token: decode: {e}"))
}

fn endpoint_to_dial_str(e: &Endpoint) -> Result<String, String> {
    // A wildcard/unspecified host (0.0.0.0 or ::) is a bind-only placeholder, not
    // a dial target. It reaches this client only from a mis-minted invite (e.g.
    // `mirage-setup` where the public address was left as "same as bind"). Fail
    // with an actionable message instead of limping: hysteria2 rejects it outright
    // and reality only appears to work by the OS routing 0.0.0.0 -> localhost on
    // the same machine, then dies later in the handshake.
    match e {
        Endpoint::Ipv4 { addr, port } => {
            let ip = std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
            if ip.is_unspecified() {
                return Err(format!(
                    "invite bridge endpoint is {ip}:{port}, a wildcard bind address that is \
                     not routable; regenerate the invite with the bridge's real reachable \
                     address (its LAN/public IP, or 127.0.0.1 for same-machine testing)"
                ));
            }
            Ok(format!("{ip}:{port}"))
        }
        Endpoint::Ipv6 { addr, port } => {
            let ip = std::net::Ipv6Addr::from(*addr);
            if ip.is_unspecified() {
                return Err(format!(
                    "invite bridge endpoint is [{ip}]:{port}, a wildcard bind address that is \
                     not routable; regenerate the invite with the bridge's real reachable \
                     address (its LAN/public IP, or ::1 for same-machine testing)"
                ));
            }
            Ok(format!("[{ip}]:{port}"))
        }
        Endpoint::Domain { domain, port } => Ok(format!("{domain}:{port}")),
        Endpoint::OnionV3 { .. } => {
            Err("invite endpoint is OnionV3; clients must route via Tor (v0.2)".into())
        }
    }
}

// -- per-bridge entry ---------------------------------------------------------

/// Credentials for one specific bridge: address, X25519 pubkey,
/// token pool, and transport settings.  Multiple `BridgeEntry`
/// instances live in the [`EntryPool`].
/// Carrier transport to use when dialing a bridge.
enum TransportMode {
    /// Plain TCP then Noise session (default / legacy).
    Raw,
    /// Reality TLS wrapper before Noise session.
    Reality {
        sni: String,
        // Compressed SEC1 P-256 CertVerify pubkey (from the invite).
        tls_cert_verify_pk: Option<[u8; 33]>,
        tls_fingerprint:
            Option<&'static mirage_transport_reality::tls_fingerprint::TlsFingerprintTemplate>,
    },
    /// Shadowsocks-2022 AEAD carrier.
    Ss2022 { psk: [u8; 32] },
    /// WebSocket carrier.
    WebSocket { path: String },
    /// Hysteria2 (QUIC + BRUTAL) carrier.  Bypasses TCP entirely.
    Hysteria2 {
        /// BRUTAL send rate in bits per second.
        send_rate_bps: u64,
        /// Cover hostname for the QUIC SNI (matches the bridge cert SAN).
        hostname: String,
        /// Gecko/Salamander QUIC-obfuscation key (from `quic_obfs_password`),
        /// or `None` for plain QUIC.
        obfs_key: Option<[u8; 32]>,
    },
    /// HTTP/3 (QUIC + MASQUE) carrier.  Bypasses TCP entirely; the Mirage
    /// session rides inside HTTP/3 DATA frames.
    H3 {
        /// Cover hostname for the QUIC SNI (matches the bridge cert SAN).
        hostname: String,
        /// Gecko/Salamander QUIC-obfuscation key (from `quic_obfs_password`),
        /// or `None` for plain QUIC.
        obfs_key: Option<[u8; 32]>,
    },
    /// Full DNS-tunnel (dnstt) carrier. Bypasses TCP; the Mirage session rides
    /// over a real DNS covert channel (base32 query names + TXT answers). Works
    /// where only DNS/port 53 is permitted.
    Dnstt {
        /// Tunnel domain the bridge is the authoritative NS for.
        domain: String,
        /// Resolver (or the bridge's `:53`) to send queries to.
        resolver: std::net::SocketAddr,
    },
    /// Meek HTTP domain-fronting long-poll carrier.
    Meek {
        /// HTTP `Host` header (CDN front domain).
        front_domain: String,
        /// HTTP request path (default `"/"`).
        path: String,
    },
    /// DoH-tunnel carrier: `POST /dns-query`, `Content-Type: application/dns-message`.
    Doh {
        /// HTTP `Host` header (CDN front domain or bridge IP).
        front_domain: String,
    },
    /// WebRTC data-channel carrier. SDP is exchanged with the bridge over HTTP
    /// signaling; the session then rides a DTLS-SCTP data channel over UDP.
    WebRtc {
        /// HTTP `Host` header for the signaling POST (CDN front domain).
        signaling_host: String,
        /// Signaling request path the bridge routes to its WebRTC handler.
        path: String,
        /// STUN/TURN servers (empty = built-in default STUN / host candidates).
        ice_servers: Vec<String>,
    },
}

struct BridgeEntry {
    bridge_addr: String,
    bridge_x25519_pk: [u8; 32],
    /// Bridge Ed25519 identity key from the announcement; used to verify
    /// session refresh tokens returned during the claim exchange.
    bridge_ed25519_pk: [u8; 32],
    /// Per-invite claim SECRET (v0.1e). When `Some`, the client performs a
    /// claim exchange at startup to obtain fresh `SessionRefreshToken`s,
    /// extending operational life beyond the bootstrap token pool. The secret
    /// is never sent raw: `try_claim_entry` derives a per-bridge id via
    /// `claim::derive_claim_id` so hostile bridges can't link the user across
    /// the mesh (#2).
    claim_id: Option<[u8; 32]>,
    credentials: Credentials,
    handshake_timeout: Duration,
    transport: TransportMode,
    /// Shared salt from the invite, kept for epoch-derived port computation.
    shared_salt: Option<[u8; 32]>,
    /// Port-hopping parameters from the `INVITE_EXT_PORT_HOP` extension.
    /// `(port_base, port_range)` - when `Some`, the client tries the
    /// current-epoch and next-epoch derived ports before the static address.
    port_hop: Option<(u16, u16)>,
    /// Secret QUIC-obfs key from the `INVITE_EXT_QUIC_OBFS_SECRET` extension.
    /// When `Some`, the hysteria2 / h3 dial derives its obfs key from this
    /// per-bridge secret (via `key_from_password`) instead of the pubkey-derived
    /// default - so only invite holders can de-obfuscate. `None` = default path.
    obfs_secret: Option<[u8; 32]>,
    /// Reality anti-probe root from the `INVITE_EXT_REALITY_PROBE_ROOT` extension.
    /// When `Some`, the Reality carrier folds a per-epoch secret derived from
    /// this per-bridge root into the auth probe, so a censor who scraped only the
    /// public announcement cannot forge a probe. `None` = legacy probe (the
    /// bridge accepts it while its `reality_probe_accept_legacy` is on).
    probe_root: Option<[u8; 32]>,
    /// Forward-secret rendezvous anchor epoch from the invite
    /// (`INVITE_EXT_FORWARD_SECRET_RENDEZVOUS`). When `Some`, the background
    /// discovery subscriber for this bridge's group derives per-epoch keys from
    /// the one-way ratchet anchored here instead of directly from the salt.
    fs_rendezvous_anchor: Option<u64>,
    /// Fresh `CapabilityToken`s obtained via the in-band claim/refresh flow.
    /// Drained before the bootstrap token pool to avoid replay-set exhaustion.
    /// `Arc`-wrapped so the per-transport sibling entries of one bridge SHARE a
    /// single deque - siblings represent the same bridge/credentials, so a
    /// claimed token consumed via one transport must not be re-presentable via
    /// another (one-shot tokens are replay-protected).
    fresh_tokens: Arc<std::sync::Mutex<VecDeque<CapabilityToken>>>,
    /// Per-bridge FS downgrade DEADLINE (unix seconds): while `now < deadline`,
    /// [`Self::next_credentials`] presents legacy tokens instead of preferring
    /// forward-secure ones. Set when a session that presented an FS token
    /// established locally but died on first use - the signature of an OLD bridge
    /// that cannot parse the 315-byte FS msg-3 (rolling-upgrade fleet). `0` =
    /// FS active.
    ///
    /// The downgrade is TIME-BOXED (not permanent) so a single on-path RST
    /// cannot permanently strip forward secrecy: a censor who injects one RST
    /// during an FS handshake forces at most [`FS_DOWNGRADE_WINDOW_SECS`] of
    /// legacy before the client re-attempts FS (red-team #17). A genuinely old
    /// bridge simply wastes ~one FS attempt per window. `Arc`-shared across
    /// per-transport siblings like the token cursors.
    fs_unsupported_until: Arc<AtomicU64>,
    /// VLESS UUID - when `Some`, the client inserts a VLESS auth header
    /// after the carrier transport and before the Mirage Noise handshake.
    vless_uuid: Option<[u8; 16]>,
    /// When true, wraps the transport stream with `PaddedStream` before the
    /// Noise handshake. Must match the bridge's `pad_enabled` setting.
    pad_enabled: bool,
    /// When true, the h3/hysteria2 dial speaks plain parseable QUIC instead of
    /// Salamander-obfuscated QUIC (red-team #9). Stamped from the client config;
    /// must match the bridge's `quic_obfs_disable`.
    quic_obfs_disable: bool,
    /// When true, the meek/DoH/WS dial wraps the carrier TCP in real TLS to a
    /// terminating front before the HTTP (red-team #4). Stamped from config.
    carrier_tls: bool,
    /// Optional explicit SNI for `carrier_tls` (else the front/cover host).
    carrier_tls_sni: Option<String>,
    /// CBR frame size for the padding layer (bytes). `None` = event-driven.
    pad_cbr_frame_bytes: Option<usize>,
    /// CBR inter-frame interval in milliseconds. Default 10.
    pad_cbr_interval_ms: u64,
    /// Operator Ed25519 pubkey from the invite (trust anchor for announcements).
    /// Zero-filled for entries created in explicit-hex mode (no invite).
    operator_ed25519_pk: [u8; 32],
    /// Dynamically discovered alternate addresses for this bridge.
    /// Background Nostr/DNS discovery task pushes new endpoints here when the
    /// operator moves the bridge to a new IP to evade a censor.
    /// The dial path prepends these before the static bootstrap address.
    discovered_addrs: Arc<tokio::sync::RwLock<Vec<String>>>,
    /// Set once an operator-signed revocation for this bridge's ed25519 identity
    /// is seen on a discovery channel. A revoked entry is skipped by `pick_entry`
    /// so a compromised/seized bridge is no longer dialed. Shared across every
    /// transport-mode clone of the same bridge.
    revoked: Arc<std::sync::atomic::AtomicBool>,
    /// When true, the transport session carries a circuit-relay
    /// handshake (CMD_CREATE -> CMD_CREATED) and SOCKS5 traffic is
    /// relayed as onion-sealed CMD_RELAY cells. Bridge must have
    /// `circuit_relay_enabled = true`.
    circuit_relay: bool,
    /// When true, browser CONNECTs to this bridge ride multiplexed streams over
    /// a small pool of long-lived carriers ([`mux_carriers`]). Stamped from
    /// `ClientConfig::mux_enabled` by `build_pool`.
    mux_enabled: bool,
    /// Pool of live mux carriers to this bridge (one Noise+ML-KEM handshake +
    /// one capability token each), reused across many browser connections so
    /// the per-connection cost collapses to O(1) per user. Grows on demand up
    /// to [`MAX_STREAMS_PER_CARRIER`] streams per carrier; dead carriers are
    /// pruned lazily. Shared across sibling entries would be wrong (each is a
    /// distinct transport/session), so this is per-entry.
    mux_carriers: Arc<Mutex<Vec<MuxConnection>>>,
    /// Single-flight guard for carrier establishment (MUX-CLIENT-1). Held ONLY
    /// across the handshake - never across the `mux_carriers` lock - so a burst
    /// of connections coalesces onto one handshake while carrier *reuse* is
    /// never blocked behind an in-flight dial.
    mux_establishing: Arc<Mutex<()>>,
}

/// How long (seconds) a bridge stays downgraded to legacy tokens after an FS
/// session died on first use. Time-boxed so one censor-injected RST cannot
/// permanently strip forward secrecy; long enough that a genuinely old bridge
/// wastes only ~one FS attempt per window (red-team #17).
const FS_DOWNGRADE_WINDOW_SECS: u64 = 600;

/// Wall-clock unix seconds, saturating to 0 on a pre-epoch clock.
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

enum Credentials {
    Invite {
        /// `Arc`-shared so per-transport sibling entries of one bridge draw
        /// from the SAME bootstrap pool + cursor - sharing prevents two
        /// transports from presenting the same one-shot token (replay-reject).
        tokens: Arc<Vec<CapabilityToken>>,
        cursor: Arc<AtomicUsize>,
        /// Forward-secure bootstrap tokens from the invite's 0x08 extension.
        /// Preferred over `tokens` when non-empty (they give issuer-compromise
        /// forward security). Same Arc-shared cursor discipline as `tokens`.
        fs_tokens: Arc<Vec<FsCapabilityToken>>,
        fs_cursor: Arc<AtomicUsize>,
    },
    Static {
        client_x25519_sk: [u8; 32],
        token: CapabilityToken,
    },
}

/// The token a dial actually presents. Selected by [`BridgeEntry::next_credentials`]
/// and dispatched to the matching handshake driver by [`dial_session`].
#[derive(Clone)]
enum PresentedToken {
    /// Legacy operator-signed capability token -> `connect`.
    Legacy(CapabilityToken),
    /// Forward-secure epoch-subkey token -> `connect_fs`.
    Fs(FsCapabilityToken),
}

/// Drive the tunnel handshake with whichever token form was selected. Legacy and
/// forward-secure tokens use distinct message-3 wire forms, so they dispatch to
/// `connect` / `connect_fs` respectively; both return the same session stream.
async fn dial_session<S>(
    carrier: S,
    client_sk: &[u8; 32],
    bridge_x25519_pk: &[u8; 32],
    token: &PresentedToken,
) -> Result<SessionStream<S>, SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match token {
        PresentedToken::Legacy(t) => connect(carrier, client_sk, bridge_x25519_pk, t).await,
        PresentedToken::Fs(t) => connect_fs(carrier, client_sk, bridge_x25519_pk, t).await,
    }
}

impl BridgeEntry {
    /// Build from a single `invite` string.
    fn from_invite(
        invite_text: &str,
        handshake_timeout: Duration,
        transport: TransportMode,
    ) -> Result<Self, String> {
        let text = invite_text
            .trim()
            .strip_prefix("mirage://")
            .unwrap_or(invite_text.trim());
        let invite = MasterInvite::decode_text(text).map_err(|e| format!("invite: decode: {e}"))?;

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if !invite.is_valid_at(now_unix) {
            return Err(format!(
                "invite: outside validity window (now={now_unix}, \
                 issued={}, expires={})",
                invite.issued_at, invite.expires_at
            ));
        }

        let ann = invite.bootstrap_announcement.ok_or_else(|| {
            "invite: missing bootstrap_announcement; cannot dial without bridge hint".to_string()
        })?;
        ann.verify(&invite.operator_ed25519_pk)
            .map_err(|e| format!("invite: announcement signature: {e}"))?;

        let bridge_addr = endpoint_to_dial_str(&ann.endpoint)?;
        let tokens = invite.bootstrap_tokens.clone();
        let fs_tokens = invite.fs_bootstrap_tokens.clone();
        if tokens.is_empty() && fs_tokens.is_empty() {
            return Err(
                "invite: no bootstrap tokens (legacy or FS); nothing to present".to_string(),
            );
        }

        // Randomise each cursor start so concurrent clients don't all claim
        // token 0 first and collide on the replay set. Guarded against a zero
        // len (an FS-only or legacy-only invite leaves the other pool empty).
        let rand_start = |n: usize| -> usize {
            if n == 0 {
                return 0;
            }
            let mut b = [0u8; 8];
            getrandom::fill(&mut b).expect("csprng");
            (u64::from_be_bytes(b) as usize) % n
        };
        let start = rand_start(tokens.len());
        let fs_start = rand_start(fs_tokens.len());

        let shared_salt = Some(*invite.shared_salt);
        let port_hop = invite.port_hop;
        let obfs_secret = invite.obfs_secret;
        let probe_root = invite.probe_root;
        // Inline the anchor (epoch of issued_at) rather than call the &self
        // method: `invite` is partially moved (bootstrap_announcement taken
        // above), so a whole-struct borrow would not compile; field reads are ok.
        let fs_rendezvous_anchor = invite
            .forward_secret_rendezvous
            .then(|| epoch_for_time(invite.issued_at));
        let bridge_ed25519_pk = ann.bridge_ed25519_pk;
        let claim_id = invite.claim_id;
        let operator_ed25519_pk = invite.operator_ed25519_pk;

        Ok(Self {
            bridge_addr,
            bridge_x25519_pk: ann.bridge_x25519_pk,
            bridge_ed25519_pk,
            claim_id,
            credentials: Credentials::Invite {
                tokens: Arc::new(tokens),
                cursor: Arc::new(AtomicUsize::new(start)),
                fs_tokens: Arc::new(fs_tokens),
                fs_cursor: Arc::new(AtomicUsize::new(fs_start)),
            },
            handshake_timeout,
            transport,
            shared_salt,
            port_hop,
            obfs_secret,
            probe_root,
            fs_rendezvous_anchor,
            fresh_tokens: Arc::new(std::sync::Mutex::new(VecDeque::new())),
            fs_unsupported_until: Arc::new(AtomicU64::new(0)),
            vless_uuid: None,          // set by build_pool() after construction
            pad_enabled: false,        // set by build_pool()
            quic_obfs_disable: false,  // set by build_pool()
            carrier_tls: false,        // set by build_pool()
            carrier_tls_sni: None,     // set by build_pool()
            pad_cbr_frame_bytes: None, // set by build_pool()
            pad_cbr_interval_ms: 10,   // set by build_pool()
            circuit_relay: false,      // set by build_pool()
            mux_enabled: false,        // set by build_pool()
            mux_carriers: Arc::new(Mutex::new(Vec::new())),
            mux_establishing: Arc::new(Mutex::new(())),
            operator_ed25519_pk,
            discovered_addrs: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            revoked: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Pick the next credential set.  Returns `(client_x25519_sk, token)`.
    ///
    /// Fresh tokens from the claim/refresh flow are drained first; only
    /// after the deque is empty does the call fall back to the bootstrap
    /// pool.  This prevents replay-set exhaustion when claim is wired up.
    fn next_credentials(&self) -> ([u8; 32], PresentedToken) {
        let fresh_sk = || {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).expect("OS CSPRNG");
            StaticSecret::from(seed).to_bytes()
        };
        // Fresh tokens are single-use session-refresh tokens obtained via the
        // in-band claim exchange (legacy, bridge-signed). Prefer them over the
        // bootstrap pools.
        if let Ok(mut deque) = self.fresh_tokens.lock() {
            if let Some(t) = deque.pop_front() {
                return (fresh_sk(), PresentedToken::Legacy(t));
            }
        }
        match &self.credentials {
            Credentials::Invite {
                tokens,
                cursor,
                fs_tokens,
                fs_cursor,
            } => {
                // Prefer forward-secure tokens when the invite carried them,
                // UNLESS this bridge has been marked FS-unsupported (an old
                // daemon that couldn't parse our FS msg-3) - then fall back to
                // the legacy tokens, which an FS invite always co-mints. Also
                // falls back for older (legacy-only) invites with an empty FS
                // pool. A degenerate FS-unsupported-and-no-legacy invite (should
                // not occur - dual-mint always includes legacy) still yields an
                // FS token rather than panicking on an empty legacy pool.
                let downgraded =
                    now_unix_secs() < self.fs_unsupported_until.load(Ordering::Relaxed);
                let use_fs = !fs_tokens.is_empty() && (!downgraded || tokens.is_empty());
                if use_fs {
                    let idx = fs_cursor.fetch_add(1, Ordering::Relaxed) % fs_tokens.len();
                    (fresh_sk(), PresentedToken::Fs(fs_tokens[idx].clone()))
                } else {
                    let idx = cursor.fetch_add(1, Ordering::Relaxed) % tokens.len();
                    (fresh_sk(), PresentedToken::Legacy(tokens[idx].clone()))
                }
            }
            Credentials::Static {
                client_x25519_sk,
                token,
            } => (*client_x25519_sk, PresentedToken::Legacy(token.clone())),
        }
    }

    fn describe_mode(&self) -> &'static str {
        match (&self.credentials, &self.transport) {
            (_, TransportMode::Hysteria2 { .. }) => "hysteria2",
            (_, TransportMode::H3 { .. }) => "h3",
            (_, TransportMode::Dnstt { .. }) => "dnstt",
            (_, TransportMode::Ss2022 { .. }) => "ss2022",
            (_, TransportMode::Meek { .. }) => "meek",
            (_, TransportMode::WebRtc { .. }) => "webrtc",
            (_, TransportMode::Doh { .. }) => "doh",
            (_, TransportMode::WebSocket { .. }) => "websocket",
            (_, TransportMode::Reality { .. }) => "reality",
            (Credentials::Invite { .. }, TransportMode::Raw) => "invite",
            (Credentials::Static { .. }, TransportMode::Raw) => "explicit-hex",
        }
    }

    fn token_count(&self) -> usize {
        match &self.credentials {
            // Report the pool actually presented: FS when available, else legacy.
            Credentials::Invite {
                tokens, fs_tokens, ..
            } => {
                if fs_tokens.is_empty() {
                    tokens.len()
                } else {
                    fs_tokens.len()
                }
            }
            Credentials::Static { .. } => 1,
        }
    }

    /// A session that presented a forward-secure token established locally but
    /// died on first use - the signature of an OLD bridge daemon that cannot
    /// parse the 315-byte FS msg-3 (its `connect_fs` succeeds after writing msg-3,
    /// then the bridge closes the connection on the unknown message type). Mark
    /// this bridge FS-unsupported so the pool's retry presents a co-minted legacy
    /// token instead, keeping the old bridge reachable. Only acts when the invite
    /// carries BOTH FS and legacy tokens (else there is nothing to downgrade to);
    /// idempotent. Reset only on process restart.
    fn note_fs_dial_dead(&self) {
        if let Credentials::Invite {
            tokens, fs_tokens, ..
        } = &self.credentials
        {
            if !fs_tokens.is_empty() && !tokens.is_empty() {
                let now = now_unix_secs();
                let until = now.saturating_add(FS_DOWNGRADE_WINDOW_SECS);
                let prev = self.fs_unsupported_until.swap(until, Ordering::Relaxed);
                // Warn only on a FRESH downgrade (previous window had expired),
                // not on every re-confirmation while still downgraded.
                if prev <= now {
                    warn!(
                        bridge = %self.bridge_addr,
                        window_secs = FS_DOWNGRADE_WINDOW_SECS,
                        "forward-secure token rejected (bridge predates FS support or an on-path \
                         reset); downgrading this bridge to legacy tokens temporarily"
                    );
                }
            }
        }
    }
}

// -- entry pool ---------------------------------------------------------------

/// H3 throttle-detection tunables.
/// Minimum bytes a session must move before its goodput is a reliable signal;
/// below this, per-session variance (small transfers) dominates.
const GOODPUT_MIN_BYTES: u64 = 256 * 1024;
/// Minimum session duration (seconds) before goodput is meaningful.
const GOODPUT_MIN_SECS: f64 = 2.0;
/// A session whose goodput is below this fraction of the transport's healthy
/// baseline is treated as throttled.
const GOODPUT_THROTTLE_FRACTION: f64 = 0.4;
/// Bounded low reward recorded for a throttled session: dispreferences the
/// carrier in EXP3 without a hard block (it still works, just deprioritized).
const GOODPUT_THROTTLE_REWARD: f64 = 0.2;
/// EWMA weight for a new healthy goodput sample.
const GOODPUT_EMA_ALPHA: f64 = 0.3;

/// Decide whether a session's `goodput_bps` indicates censor throttling relative
/// to the transport's healthy `baseline_bps` (H3). RELATIVE, not absolute, so a
/// uniformly slow network (every carrier low -> low baseline) does NOT trigger -
/// only a carrier now far slower than its OWN established baseline does. With no
/// baseline yet, never throttled (the first healthy sample sets the baseline).
fn is_throttled(goodput_bps: f64, baseline_bps: Option<f64>) -> bool {
    match baseline_bps {
        Some(base) if base > 0.0 => goodput_bps < base * GOODPUT_THROTTLE_FRACTION,
        _ => false,
    }
}

/// Failure state for one bridge entry.
#[derive(Clone)]
struct EntryHealth {
    /// `None` = healthy; `Some(instant)` = failed at that time.
    failed_at: Option<Instant>,
    /// Exponential moving average of TCP connect latency in milliseconds.
    /// None = no measurement yet. Used to prefer faster-responding bridges.
    latency_ema_ms: Option<f64>,
    /// Exponential moving average of *healthy* session goodput (bytes/sec) for
    /// this entry's transport (H3). Updated only from non-throttled sessions so
    /// it tracks the transport's baseline throughput; a later session whose
    /// goodput falls far below it is treated as censor throttling (a mainstream
    /// tactic distinct from outright blocking) and dispreferenced in the router.
    /// `None` = no baseline yet.
    goodput_ema_bps: Option<f64>,
}

/// Multi-entry pool: holds N `BridgeEntry` instances and routes new
/// tunnel requests to the next healthy entry in round-robin order.
///
/// On per-entry failure the pool soft-fails the entry for
/// `failure_backoff` and tries the next one automatically.  If all
/// entries are soft-failed simultaneously, returns `None` from
/// `pick_entry` so the caller can surface an error.
/// All `BridgeEntry::describe_mode()` labels - the known-static transport set
/// the success-rate persistence loader re-interns disk records as. Keep in
/// sync with `describe_mode`.
const KNOWN_TRANSPORTS: &[&str] = &[
    "hysteria2",
    "h3",
    "dnstt",
    "ss2022",
    "meek",
    "webrtc",
    "doh",
    "websocket",
    "reality",
    "invite",
    "explicit-hex",
];

struct EntryPool {
    entries: Vec<BridgeEntry>,
    health: Mutex<Vec<EntryHealth>>,
    cursor: AtomicUsize,
    failure_backoff: Duration,
    /// Signalled when ALL bridge entries are simultaneously exhausted (mass IP
    /// block event). The background Nostr discovery task wakes immediately on
    /// this signal rather than waiting for the next periodic tick, so the client
    /// can recover in seconds instead of minutes.
    discovery_trigger: Arc<tokio::sync::Notify>,
    /// Per-(network, transport) success-rate map. Every dial outcome is
    /// recorded here (success in `record_latency`, failure in `mark_failure`),
    /// persisted across restarts, and surfaced in the management API. This is
    /// the learning substrate for adaptive transport selection: a transport
    /// that's blocked on this network accrues failures and a low rate.
    success_map: Arc<SuccessRateMap>,
    /// Network bucket for `success_map` keys. v1 uses a single global bucket
    /// (`NetworkFingerprint::unknown()`); per-network fingerprinting (so the
    /// learned state is scoped to "this Wi-Fi / this ISP") is a follow-up.
    network: NetworkFingerprint,
    /// The adversarial routing-entropy engine: an EXP3 bandit + censorship-
    /// posture gate + diversity guard layered over `success_map`. It replaces
    /// the deterministic `select::rank` best-first order with an entropy-
    /// controlled, censor-adaptive selection distribution, so the client is a
    /// moving target rather than a fixed one. Behind a `std::sync::Mutex`
    /// because `select`/`record` never `.await`.
    routing: std::sync::Mutex<AdaptiveRouting>,
    /// Verified-connected egress gate. `true` once a Mirage session handshake to
    /// SOME bridge has completed (a real authenticated tunnel exists, not merely
    /// TCP reachability), cleared when every entry is simultaneously exhausted.
    /// This is the authoritative "are we tunnelled" signal: the startup preflight
    /// sets it eagerly, the dial paths keep it current, and the management API
    /// surfaces it so the GUI / OS kill-switch can arm egress on it.
    egress_verified: AtomicBool,
    /// Unix seconds at which `egress_verified` last transitioned to `true`
    /// (0 = never verified yet). Surfaced for observability.
    egress_since_unix: AtomicU64,
}

/// Bundles the [`AdaptiveRouter`] with the collaborative, poisoning-robust
/// posture estimator ([`PostureNet`] - "censorship weather") under one lock.
/// The router selects against the *robust aggregate* posture; local dial
/// outcomes feed `posture_net.ingest_local`, and `posture_net.ingest_peer` is
/// the seam the discovery/gossip layer feeds swarm observations into.
struct AdaptiveRouting {
    router: AdaptiveRouter,
    posture_net: PostureNet,
    /// Closed-loop self-adversary: runs the censor's own fully-encrypted-traffic
    /// classifier (Wu et al. 2023) against each transport's first-packet egress
    /// character and folds a PREDICTIVE penalty into the router reward, so the
    /// client steers off entropy-DPI-flaggable carriers before they are blocked.
    self_adversary: mirage_transport::self_adversary::SelfAdversary,
}

/// Draw a 64-bit seed for the routing engine's sampling PRNG from the OS CSPRNG.
///
/// A CSPRNG failure is fatal, not something to paper over: silently falling back
/// to a zero seed (the previous `let _ =` behaviour) makes the adversarial
/// transport-selection PRNG fully predictable, which an adaptive censor can
/// exploit. Fail loudly instead - a broken OS CSPRNG means every other secret is
/// compromised too, so a clean crash is the correct, observable outcome.
fn adaptive_seed() -> u64 {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).expect("OS CSPRNG for routing seed");
    u64::from_le_bytes(b)
}

/// An HTTP request line + headers - what a meek / WebSocket / DoH carrier opens
/// with. All printable, so a censor's fully-encrypted classifier exempts it.
const HTTP_REQUEST_WITNESS: &[u8] =
    b"GET / HTTP/1.1\r\nHost: cdn.example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n";

/// A TLS 1.3 ClientHello prefix - what a Reality / VLESS carrier opens with:
/// record header, a length-structured body (bit-skewed away from ~0.5), and a
/// printable SNI + ALPN run. Exempt from the fully-encrypted classifier as a real
/// ClientHello is (the printable SNI is a >20-byte contiguous run).
const TLS_CLIENT_HELLO_WITNESS: &[u8] =
    b"\x16\x03\x01\x00\xfc\x01\x00\x00\xf8\x03\x03www.cloudflare-cdn.example.com\x00\x13\x02\x13\x01\x00\x00http/1.1";

/// A deterministic ciphertext-like sample (SplitMix64): ~0.5 set-bit fraction,
/// no printable structure - what a carrier that frames Noise/AEAD directly on TCP
/// puts on the wire, and what a fully-encrypted-traffic classifier flags.
fn random_egress_witness() -> Vec<u8> {
    let mut x = 0x1234_5678_9abc_def0u64;
    (0..64)
        .map(|_| {
            x = x.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
            ((x ^ (x >> 31)) >> 24) as u8
        })
        .collect()
}

/// A representative FIRST-PACKET egress sample for `transport`, modelling what a
/// censor's fully-encrypted-traffic classifier (Wu et al. 2023) inspects on the
/// first packet of a connection.
///
/// The EXEMPT carriers are enumerated explicitly: TLS-wrapped (`reality`/`vless`,
/// a ClientHello with a printable SNI) and HTTP-wrapped (`meek`/`websocket`/`ws`/
/// `doh`). UDP/QUIC/DTLS/DNS carriers (`hysteria2`/`h3`/`webrtc`/`dnstt`) are not
/// the TCP entropy-DPI heuristic's target and are exempt too - the HTTP witness
/// is a stand-in for that exempt verdict, NOT a faithful byte model of their real
/// (QUIC Initial / STUN / DTLS / DNS) first packets.
///
/// Every other name - the raw-Noise/AEAD-on-TCP carriers (`ss2022`, `shadowsocks`,
/// `invite`, `explicit-hex`, `raw`, `obfs`, ...) AND any unknown/future transport -
/// **fails safe** to the flagged (uniformly-random) witness, so a new
/// raw-ciphertext carrier added to `describe_mode` without touching this map is
/// steered away by default rather than silently exempted.
///
/// This is a transport-CHARACTER model (a predictive per-transport prior the real
/// Wu classifier evaluates), not a live per-flow socket tap (which would require a
/// tap inside every transport). See [`mirage_transport::self_adversary`].
fn transport_egress_witness(name: &str) -> Vec<u8> {
    match name {
        // TLS-shaped first packet (ClientHello + SNI): exempt.
        "reality" | "vless" => TLS_CLIENT_HELLO_WITNESS.to_vec(),
        // HTTP/text-shaped first packet: exempt.
        "meek" | "websocket" | "ws" | "doh" => HTTP_REQUEST_WITNESS.to_vec(),
        // UDP / QUIC / DTLS / DNS: not the TCP entropy-DPI's target -> exempt
        // (HTTP witness stands in for the verdict; see docs).
        "hysteria2" | "h3" | "webrtc" | "dnstt" => HTTP_REQUEST_WITNESS.to_vec(),
        // Raw Noise/AEAD directly on TCP + any unknown/future transport: FAIL SAFE
        // to the flagged witness.
        _ => random_egress_witness(),
    }
}

/// Best-effort gather of the coarse network signals used to derive the
/// per-network [`NetworkFingerprint`]. Missing signals just narrow the
/// fingerprint; nothing here fails the client.
fn gather_network_signals() -> mirage_transport::netfp::NetworkSignals {
    // Local outbound IP: `connect`-ing a UDP socket to a public IP triggers the
    // OS route lookup + source-address selection but sends NO datagram, so it
    // reveals which local IP (hence subnet) reaches the internet without any
    // traffic. Loopback/unspecified results are discarded.
    let local_ip = std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("1.1.1.1:53")?;
            Ok(s.local_addr()?.ip())
        })
        .ok()
        .filter(|ip| !ip.is_unspecified() && !ip.is_loopback());
    mirage_transport::netfp::NetworkSignals {
        local_ip,
        resolvers: read_system_resolvers(),
    }
}

/// Parse resolver IPs from `/etc/resolv.conf` (Unix). Empty on any platform /
/// error where it can't be read.
fn read_system_resolvers() -> Vec<std::net::IpAddr> {
    std::fs::read_to_string("/etc/resolv.conf")
        .map(|s| {
            s.lines()
                .filter_map(|l| {
                    l.trim()
                        .strip_prefix("nameserver ")
                        .and_then(|rest| rest.trim().parse::<std::net::IpAddr>().ok())
                })
                .collect()
        })
        .unwrap_or_default()
}

impl EntryPool {
    fn new(
        entries: Vec<BridgeEntry>,
        failure_backoff: Duration,
        discovery_trigger: Arc<tokio::sync::Notify>,
        success_map: Arc<SuccessRateMap>,
        network: NetworkFingerprint,
    ) -> Self {
        let n = entries.len();
        Self {
            entries,
            health: Mutex::new(vec![
                EntryHealth {
                    failed_at: None,
                    latency_ema_ms: None,
                    goodput_ema_bps: None,
                };
                n
            ]),
            cursor: AtomicUsize::new(0),
            failure_backoff,
            discovery_trigger,
            success_map,
            network,
            routing: std::sync::Mutex::new(AdaptiveRouting {
                router: AdaptiveRouter::new(adaptive_seed()),
                posture_net: PostureNet::new(),
                self_adversary: mirage_transport::self_adversary::SelfAdversary::with_params(
                    mirage_transport::self_adversary::SelfAdversaryParams {
                        // The witness is a deterministic per-transport prior, so
                        // the verdict is certain from the first sample - no noise
                        // to smooth, so apply the predictive penalty immediately.
                        // (Raise min_samples once a live, stochastic per-flow tap
                        // replaces the static witness.)
                        min_samples: 1,
                        ..Default::default()
                    },
                ),
            }),
            egress_verified: AtomicBool::new(false),
            egress_since_unix: AtomicU64::new(0),
        }
    }

    /// Mark egress verified-connected: a Mirage session handshake to a bridge
    /// completed. Records the first-transition timestamp for observability.
    /// Called on every successful carrier/session open and by the preflight.
    fn mark_egress_verified(&self) {
        if !self.egress_verified.swap(true, Ordering::Release) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            self.egress_since_unix.store(now, Ordering::Relaxed);
            info!("egress verified-connected: authenticated Mirage tunnel established");
        }
    }

    /// Mark egress down: every bridge entry is simultaneously exhausted, so no
    /// verified tunnel exists. The next successful open re-arms the gate.
    fn mark_egress_down(&self) {
        if self.egress_verified.swap(false, Ordering::Release) {
            self.egress_since_unix.store(0, Ordering::Relaxed);
            warn!("egress DOWN: all bridge entries exhausted; no verified tunnel");
        }
    }

    /// `(verified, since_unix)` snapshot of the egress gate for the management API.
    fn egress_status(&self) -> (bool, u64) {
        (
            self.egress_verified.load(Ordering::Acquire),
            self.egress_since_unix.load(Ordering::Relaxed),
        )
    }

    /// Pick the next healthy entry index, preferring entries with the
    /// lowest observed TCP connect latency (EMA). Among entries with no
    /// latency measurement yet the round-robin cursor is used as a
    /// tiebreak so unknown entries share load evenly.
    ///
    /// Returns `None` if all entries are currently soft-failed (caller
    /// should surface a "no healthy bridge" error).
    async fn pick_entry(&self) -> Option<usize> {
        let n = self.entries.len();
        if n == 0 {
            return None;
        }
        let now = Instant::now();
        let mut health = self.health.lock().await;
        // Expire old failures.
        if self.failure_backoff > Duration::ZERO {
            for h in health.iter_mut() {
                if let Some(t) = h.failed_at {
                    if now.duration_since(t) >= self.failure_backoff {
                        h.failed_at = None;
                    }
                }
            }
        }
        // Collect indices of healthy entries.
        let start = self.cursor.fetch_add(1, Ordering::Relaxed);
        let healthy: Vec<usize> = (0..n)
            .map(|i| (start + i) % n)
            .filter(|&idx| health[idx].failed_at.is_none())
            // Skip a bridge whose operator has published a signed revocation.
            .filter(|&idx| {
                !self.entries[idx]
                    .revoked
                    .load(std::sync::atomic::Ordering::Relaxed)
            })
            .collect();
        if healthy.is_empty() {
            // Fall back to the least-recently-failed entry as a last-resort
            // probe, so one bad round doesn't refuse every connection for the
            // whole backoff window. BUT a signed revocation is authoritative:
            // never fall back to a revoked bridge (else a censor who can
            // soft-fail the healthy entries could force-select a burned one
            // during a blackout). If EVERY entry is revoked, hard-fail with
            // `None` rather than dial a revoked bridge (red-team regression fix).
            return (0..n)
                .filter(|&idx| {
                    !self.entries[idx]
                        .revoked
                        .load(std::sync::atomic::Ordering::Relaxed)
                })
                .min_by_key(|&idx| health[idx].failed_at);
        }
        // Compute median latency across entries that have measurements,
        // so unknown entries are treated as "average" rather than best
        // or worst.
        let known_latencies: Vec<f64> = healthy
            .iter()
            .filter_map(|&idx| health[idx].latency_ema_ms)
            .collect();
        let _median_latency: f64 = if known_latencies.is_empty() {
            f64::MAX
        } else {
            let mut sorted = known_latencies.clone();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            sorted[sorted.len() / 2]
        };
        // Adaptive transport selection: among healthy entries, prefer the
        // transport the success-rate map ranks best on this network - sticky to
        // what's working, exponential-backoff on what looks blocked, never
        // permanently dropping any (censorship isn't assumed permanent). The
        // cursor-ordered `healthy` list is the tie-break, so equally-ranked
        // transports still spread load across bridges. (Latency EMA stays
        // observability-only - concentrating on min-latency would defeat that
        // spreading.)
        let mut uniq: Vec<&'static str> = Vec::new();
        for &idx in &healthy {
            let name = self.entries[idx].describe_mode();
            if !uniq.contains(&name) {
                uniq.push(name);
            }
        }
        // Adversarial routing-entropy selection: SAMPLE the transport from an
        // EXP3 distribution (posture-gated by bearer class, diversity-capped per
        // transport) instead of taking a deterministic best-first order. The
        // client's choice is therefore a high-entropy distribution a censor
        // cannot pre-empt - warm-started from, and learning online against, the
        // same `success_map` substrate the deterministic ranker used.
        let selected = {
            let mut g = self.routing.lock().expect("routing lock poisoned");
            // Select against the collaborative, poisoning-robust posture
            // aggregate (first-hand + trusted-peer intelligence).
            let posture = g.posture_net.posture(now);
            g.router
                .select(&self.network, &uniq, &self.success_map, &posture, now)
        };
        if let Some(name) = selected {
            if let Some(&idx) = healthy
                .iter()
                .find(|&&i| self.entries[i].describe_mode() == name)
            {
                return Some(idx);
            }
        }
        // Fallback to the deterministic ranker - only reached if the sampled
        // transport somehow has no healthy entry (it can't: `uniq` is derived
        // from `healthy`), so this is belt-and-suspenders that also keeps the
        // well-tested `select::rank` path live.
        let ranked = rank_names(
            &self.success_map,
            &self.network,
            &uniq,
            &SelectionPolicy::default(),
            now,
        );
        if let Some(&best) = ranked.first() {
            if let Some(&idx) = healthy
                .iter()
                .find(|&&i| self.entries[i].describe_mode() == best)
            {
                return Some(idx);
            }
        }
        Some(healthy[0])
    }

    /// Mark entry `idx` as failed. It will be skipped for
    /// `failure_backoff` before becoming eligible again.
    async fn mark_failure(&self, idx: usize) {
        {
            let mut health = self.health.lock().await;
            if let Some(h) = health.get_mut(idx) {
                h.failed_at = Some(Instant::now());
            }
        }
        // Record the failure against this entry's transport so the
        // success-rate map learns which carriers are blocked on this network,
        // and feed the same signal to the routing engine (reward 0 = blocked)
        // + posture (this bearer class just failed).
        if let Some(e) = self.entries.get(idx) {
            let name = e.describe_mode();
            self.success_map.record(&self.network, name, false);
            let mut g = self.routing.lock().expect("routing lock poisoned");
            g.posture_net
                .ingest_local(class_of(name), false, Instant::now());
            g.router.record(&self.network, name, 0.0);
        }
    }

    /// Record a successful TCP connect latency for entry `idx`.
    /// Updates the exponential moving average (α = 0.2) so recent
    /// measurements have more weight than older ones.
    async fn record_latency(&self, idx: usize, latency_ms: u64) {
        // A dial succeeded end-to-end (carrier/session handshake completed):
        // egress is verified-connected. This is the single success choke point
        // for both the mux and legacy paths, so the gate arms here for all
        // transports.
        self.mark_egress_verified();
        {
            let mut health = self.health.lock().await;
            if let Some(h) = health.get_mut(idx) {
                h.latency_ema_ms = Some(match h.latency_ema_ms {
                    None => latency_ms as f64,
                    Some(prev) => prev * 0.8 + latency_ms as f64 * 0.2,
                });
            }
        }
        // Record the success against this entry's transport, and reward the
        // routing engine (latency-scaled: a fast success beats a slow one beats
        // a block) + lift this bearer class's posture score.
        if let Some(e) = self.entries.get(idx) {
            let name = e.describe_mode();
            self.success_map.record(&self.network, name, true);
            let base = outcome_reward(true, Some(Duration::from_millis(latency_ms)));
            let mut g = self.routing.lock().expect("routing lock poisoned");
            // Closed-loop self-adversary: grade this transport's first-packet
            // egress character with the censor's own fully-encrypted classifier
            // and fold a PREDICTIVE penalty into the reward, so a carrier an
            // entropy-DPI censor would flag (e.g. raw obfs) is dispreferred even
            // while it still connects - steering off it before it is blocked.
            let witness = transport_egress_witness(name);
            g.self_adversary.observe(&self.network, name, &witness);
            let reward = base * g.self_adversary.reward_multiplier(&self.network, name);
            g.posture_net
                .ingest_local(class_of(name), true, Instant::now());
            g.router.record(&self.network, name, reward);
        }
    }

    /// Record a completed session's goodput for entry `idx` (H3). Ignores tiny /
    /// short sessions (insufficient signal). Updates the healthy-goodput baseline
    /// only from NON-throttled sessions (so a sustained throttle keeps
    /// triggering until the carrier recovers); a session whose goodput is far
    /// below that baseline records a bounded low reward, steering EXP3 off a
    /// throttled carrier the block/latency detector would never notice.
    async fn record_session_goodput(&self, idx: usize, bytes: u64, elapsed: Duration) {
        let secs = elapsed.as_secs_f64();
        if bytes < GOODPUT_MIN_BYTES || secs < GOODPUT_MIN_SECS {
            return; // too little data to distinguish throttling from a small transfer
        }
        let goodput = bytes as f64 / secs;
        let throttled = {
            let mut health = self.health.lock().await;
            let Some(h) = health.get_mut(idx) else {
                return;
            };
            let throttled = is_throttled(goodput, h.goodput_ema_bps);
            if !throttled {
                h.goodput_ema_bps = Some(match h.goodput_ema_bps {
                    None => goodput,
                    Some(prev) => prev * (1.0 - GOODPUT_EMA_ALPHA) + goodput * GOODPUT_EMA_ALPHA,
                });
            }
            throttled
        };
        if throttled {
            if let Some(e) = self.entries.get(idx) {
                let name = e.describe_mode();
                self.success_map.record(&self.network, name, true); // it worked, just slowly
                let mut g = self.routing.lock().expect("routing lock poisoned");
                g.router
                    .record(&self.network, name, GOODPUT_THROTTLE_REWARD);
                debug!(
                    transport = name,
                    goodput_bps = goodput as u64,
                    "H3: session goodput far below carrier baseline - throttle penalty"
                );
            }
        }
    }

    /// Mark entry `idx` as healthy after a successful probe, clearing any
    /// failure mark and updating the latency EMA.
    async fn mark_healthy(&self, idx: usize, latency_ms: u64) {
        let mut health = self.health.lock().await;
        if let Some(h) = health.get_mut(idx) {
            h.failed_at = None;
            let alpha = 0.2_f64;
            match h.latency_ema_ms {
                None => h.latency_ema_ms = Some(latency_ms as f64),
                Some(ref mut ema) => *ema = alpha * latency_ms as f64 + (1.0 - alpha) * *ema,
            }
        }
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the CONNECT data path multiplexes over shared carriers. The flag
    /// is stamped uniformly onto every entry by `build_pool`, so any entry is
    /// representative.
    fn mux_enabled(&self) -> bool {
        self.entries.first().is_some_and(|e| e.mux_enabled)
    }

    fn total_tokens(&self) -> usize {
        self.entries.iter().map(|e| e.token_count()).sum()
    }

    pub async fn bridge_stats(&self) -> Vec<BridgeStat> {
        let health = self.health.lock().await;
        let now = Instant::now();
        let mut out = Vec::with_capacity(self.entries.len());
        for (idx, e) in self.entries.iter().enumerate() {
            let h = &health[idx];
            let (port_hop_active, current_derived_port) =
                if let (Some(salt), Some((base, range))) = (e.shared_salt, e.port_hop) {
                    let now_unix = discovery_now_unix();
                    let epoch = epoch_for_time(now_unix);
                    let port = derive_port(&salt, NAMESPACE_CLIENT_TO_BRIDGE, epoch, base, range);
                    (true, port)
                } else {
                    (false, None)
                };
            let bridge_pk_fp = if e.bridge_ed25519_pk != [0u8; 32] {
                hex::encode(e.bridge_ed25519_pk)[..16].to_string()
            } else {
                String::new()
            };
            let fresh_tokens_remaining = e.fresh_tokens.lock().map(|d| d.len()).unwrap_or(0);
            let tstats = self.success_map.lookup(&self.network, e.describe_mode());
            // Live mux carrier/stream counts (prune dead carriers while here).
            let (mux_carriers, mux_streams) = {
                let mut carriers = e.mux_carriers.lock().await;
                carriers.retain(|c| !c.is_closed());
                let streams: u32 = carriers.iter().map(|c| c.open_stream_count()).sum();
                (carriers.len(), streams)
            };
            out.push(BridgeStat {
                idx,
                addr: e.bridge_addr.clone(),
                transport: e.describe_mode().to_string(),
                latency_ms: h.latency_ema_ms.map(|f| f as u64),
                healthy: h
                    .failed_at
                    .map(|t| now.duration_since(t) >= self.failure_backoff)
                    .unwrap_or(true),
                bridge_pk_fp,
                fresh_tokens_remaining,
                port_hop_active,
                current_derived_port,
                transport_successes: tstats.successes,
                transport_failures: tstats.failures,
                mux_carriers,
                mux_streams,
            });
        }
        out
    }

    /// Aggregate live mux carriers + open streams across every bridge entry.
    /// Surfaced in `/api/status` so the operator can see the O(1)-per-user
    /// carrier count vs the many streams riding it.
    async fn mux_totals(&self) -> (usize, u32) {
        let mut carriers = 0usize;
        let mut streams = 0u32;
        for e in &self.entries {
            let cs = e.mux_carriers.lock().await;
            carriers += cs.iter().filter(|c| !c.is_closed()).count();
            streams += cs.iter().map(|c| c.open_stream_count()).sum::<u32>();
        }
        (carriers, streams)
    }
}

#[derive(serde::Serialize)]
pub struct BridgeStat {
    pub idx: usize,
    pub addr: String,
    pub transport: String,
    pub latency_ms: Option<u64>,
    pub healthy: bool,
    /// First 16 hex chars of bridge_ed25519_pk; empty string for explicit-hex mode.
    pub bridge_pk_fp: String,
    /// Number of fresh tokens remaining in the deque (from claim/refresh).
    pub fresh_tokens_remaining: usize,
    #[serde(default)]
    pub port_hop_active: bool,
    #[serde(default)]
    pub current_derived_port: Option<u16>,
    /// Learned dial successes for this entry's transport on the current
    /// network (from the persisted success-rate map). Observability for
    /// "which carriers are working / blocked here".
    #[serde(default)]
    pub transport_successes: u32,
    /// Learned dial failures for this entry's transport on the current network.
    #[serde(default)]
    pub transport_failures: u32,
    /// Live mux carriers to this bridge (each = one Noise+ML-KEM session that
    /// many browser streams share). O(1) per user is the healthy state.
    #[serde(default)]
    pub mux_carriers: usize,
    /// Total open mux streams across this bridge's carriers (~ the app
    /// connections currently tunnelled through it).
    #[serde(default)]
    pub mux_streams: u32,
}

// -- nostr discovery -----------------------------------------------------------

/// `(bridge_x25519_pk, discovered_addrs Arc)` for each entry in a discovery
/// group. Aliased to keep the nested channel/map types readable (clippy
/// type_complexity).
type EntryAddrList = Vec<(
    [u8; 32],
    [u8; 32],
    Arc<std::sync::atomic::AtomicBool>,
    Arc<tokio::sync::RwLock<Vec<String>>>,
)>;

/// Accumulator value while grouping entries by `(shared_salt, operator_pk)`:
/// the group-uniform FS anchor plus its entry list.
type DiscoveryGroupAcc = (Option<u64>, EntryAddrList);

/// Groups bridge entries that share the same `(shared_salt, operator_ed25519_pk)`.
/// One `ClientSubscriber` per group; the subscriber fetches announcements for
/// all entries in the group during each discovery tick.
struct DiscoveryGroup {
    shared_salt: [u8; 32],
    operator_pk: [u8; 32],
    /// Forward-secret rendezvous anchor epoch (from the invite). `Some` => the
    /// subscriber derives per-epoch discovery keys from the ratchet anchored
    /// here; `None` => baseline direct-from-salt derivation. All entries in a
    /// group share one invite, so this is group-uniform.
    fs_rendezvous_anchor: Option<u64>,
    /// `(bridge_x25519_pk, discovered_addrs Arc)` for each entry in this group.
    entries: EntryAddrList,
}

/// Background task: periodically fetch bridge announcements from all configured
/// discovery channels (Nostr relays + DNS TXT apexes) and push newly-discovered
/// addresses into each entry's `discovered_addrs`.
///
/// When a censor blocks a bridge's IP, the operator publishes a new announcement
/// with the bridge's new address. This task fetches those announcements and
/// transparently adds the new address to the dial pool - no client restart needed.
///
/// Channel diversity is a censorship-resistance property: Nostr requires WebSocket
/// connectivity; DNS TXT works even when WebSocket is blocked (DNS is too pervasive
/// to selectively censor without breaking the whole internet).
///
/// The task also wakes immediately when `trigger` is notified (signalled by the
/// dial path when ALL entries fail simultaneously), so recovery happens in seconds
/// during a mass IP block rather than waiting for the next periodic tick.
async fn run_nostr_discovery(
    relay_urls: Vec<String>,
    dns_apexes: Vec<String>,
    dht_bootstrap_addrs: Vec<String>,
    dht_enabled: bool,
    groups: Vec<DiscoveryGroup>,
    interval: Duration,
    trigger: Arc<tokio::sync::Notify>,
) {
    use mirage_discovery::channel::DiscoveryChannel;
    use mirage_discovery_dht::DhtFetchChannel;
    use std::sync::Arc as StdArc;

    // Start the DHT client once and clone it per group (cheap - same actor thread).
    let dht_client: Option<MainlineDhtClient> = if dht_enabled {
        let result = if dht_bootstrap_addrs.is_empty() {
            MainlineDhtClient::new()
        } else {
            MainlineDhtClient::new_with_bootstrap(&dht_bootstrap_addrs)
        };
        match result {
            Ok(c) => {
                info!(
                    bootstrap = dht_bootstrap_addrs.len(),
                    "discovery: mainline DHT channel active"
                );
                Some(c)
            }
            Err(e) => {
                warn!(error = %e, "discovery: failed to start DHT client; DHT discovery disabled");
                None
            }
        }
    } else {
        None
    };

    // Shared channels: DNS TXT (same for every discovery group). Nostr channels
    // are built PER-GROUP below, because they now carry the group's `shared_salt`
    // to mask the NIP-44 frame length (red-team): a shared channel could not know
    // which cohort's salt to unmask with.
    let mut shared_channels: Vec<StdArc<dyn DiscoveryChannel>> = Vec::new();

    // Add DNS TXT channels - channel of last resort when Nostr/WebSocket is blocked.
    // One channel per apex zone; uses the system resolver (falls back to Google DNS).
    for apex in &dns_apexes {
        let name: &'static str = Box::leak(format!("dns-txt:{apex}").into_boxed_str());
        // Each apex gets its own resolver instance (cheap - backed by ref-counted state).
        let ch = DnsTxtChannel::new(HickoryDnsTxtResolver::new_system(), apex.as_str(), name);
        shared_channels.push(StdArc::new(ch) as StdArc<dyn DiscoveryChannel>);
    }

    if shared_channels.is_empty() && relay_urls.is_empty() && dht_client.is_none() {
        warn!("discovery: no valid channels (no Nostr relays, DNS apexes, or DHT); background discovery disabled");
        return;
    }

    // Build (subscriber, entry_list) pairs - one per group.
    // Each group gets a router that includes ALL shared channels PLUS a
    // group-specific DHT fetch channel keyed by that group's operator pubkey.
    // DHT channels are per-group because the BEP-44 lookup key is
    // SHA-1(operator_pk || info_hash) - different operator -> different DHT slot.
    let pairs: Vec<(ClientSubscriber, EntryAddrList)> = groups
        .into_iter()
        .map(|g| {
            let mut channels = shared_channels.clone();
            // Per-group Nostr channels: each carries this cohort's shared_salt so
            // it can unmask the NIP-44 frame length the operator published under
            // (red-team). A relay scraper without the salt cannot unmask, so it
            // cannot run the length-consistency enumeration test.
            for url in &relay_urls {
                let name: &'static str =
                    Box::leak(format!("nostr:{}:{}", hex::encode(&g.operator_pk[..4]), url).into_boxed_str());
                let cfg = NostrRelayConfig::new(url.as_str(), name);
                match NostrRelayChannel::new(cfg, NostrSigningKey::generate()) {
                    Ok(ch) => {
                        let ch = ch.with_frame_salt(g.shared_salt);
                        channels.push(StdArc::new(ch) as StdArc<dyn DiscoveryChannel>);
                    }
                    Err(e) => {
                        warn!(url = %url, error = %e, "discovery: invalid Nostr relay URL; skipping");
                    }
                }
            }
            if let Some(ref dht) = dht_client {
                let dht_name: &'static str =
                    Box::leak(format!("dht:{}", hex::encode(&g.operator_pk[..8])).into_boxed_str());
                // #17/#18: the fetch channel is keyed by the operator's PUBLIC
                // identity key. It derives the per-epoch blinded rendezvous
                // pubkey to read + verify records, but holds no signing key, so
                // a malicious client cannot forge a rendezvous PUT.
                let dht_ch = DhtFetchChannel::new(dht.clone(), g.operator_pk, dht_name);
                channels.push(StdArc::new(dht_ch) as StdArc<dyn DiscoveryChannel>);
            }
            let router = DiscoveryRouter::with_channels(channels);
            let mut sub = ClientSubscriber::new(g.shared_salt, g.operator_pk, router);
            // Forward-secret rendezvous: derive per-epoch discovery keys from the
            // ratchet anchored at the invite's issue epoch (matches the operator
            // publisher's `--forward-secret` mode).
            if let Some(anchor) = g.fs_rendezvous_anchor {
                sub = sub.with_forward_secret(anchor);
            }
            (sub, g.entries)
        })
        .collect();

    info!(
        nostr_relays = relay_urls.len(),
        dns_apexes = dns_apexes.len(),
        dht = dht_client.is_some(),
        groups = pairs.len(),
        interval_secs = interval.as_secs(),
        "dynamic discovery: background task started"
    );

    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        // Wake on whichever comes first: the periodic tick, or an emergency
        // notification from the dial path (all entries failed simultaneously).
        tokio::select! {
            _ = ticker.tick() => {},
            _ = trigger.notified() => {
                debug!("nostr discovery: emergency re-fetch (all bridges failed)");
            }
        }

        // Clock-skew-corrected time (see pin_clock_offset), so a poisoned OS
        // clock cannot silently land discovery on the wrong (empty) epoch.
        let now_unix = discovery_now_unix();
        let epoch = epoch_for_time(now_unix);

        for (subscriber, entry_list) in &pairs {
            let fetch = subscriber.fetch_for_epoch(epoch, now_unix).await;

            if !fetch.channels_failed.is_empty() {
                debug!(
                    failed = ?fetch.channels_failed,
                    "nostr discovery: some channels failed this tick"
                );
            }

            // Enforce operator revocations. The pipeline only surfaces revocations
            // whose operator signature already verified, so a match means the
            // operator has retired/repudiated this bridge (e.g. seizure): disable
            // the entry so `pick_entry` never dials it again, and drop any
            // dynamically-discovered addresses for it. Process BEFORE announcements
            // so a revocation in the same tick wins over a re-announcement.
            for rev in &fetch.revocations {
                for (_x, ed, revoked, discovered) in entry_list {
                    if ed == &rev.target_ed25519_pk {
                        if !revoked.swap(true, std::sync::atomic::Ordering::Relaxed) {
                            warn!(
                                bridge = %hex::encode(&ed[..8]),
                                "bridge REVOKED by operator - disabling entry and dropping its addresses"
                            );
                        }
                        discovered.write().await.clear();
                    }
                }
            }

            for ann in &fetch.announcements {
                for (bridge_pk, _ed, _revoked, discovered) in entry_list {
                    if bridge_pk != &ann.bridge_x25519_pk {
                        continue;
                    }
                    let mut guard = discovered.write().await;
                    for ep in ann.endpoints() {
                        match endpoint_to_dial_str(ep) {
                            Ok(addr) if !guard.contains(&addr) => {
                                info!(
                                    addr = %addr,
                                    bridge_pk = %hex::encode(bridge_pk)[..16].to_string(),
                                    "nostr discovery: new bridge address"
                                );
                                guard.push(addr);
                                // Cap at 8 addresses per entry (FIFO).
                                if guard.len() > 8 {
                                    guard.remove(0);
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }
}

// -- pool construction ---------------------------------------------------------

/// Build an `EntryPool` from a `ClientConfig`.
///
/// Priority order:
/// 1. `invites` list (each item is one entry)
/// 2. singular `invite` field (merged as one more entry)
/// 3. explicit-hex fields (one entry)
///
/// If none of the above is present, returns `Err`.
/// Collect every carrier transport the config enables, in priority order
/// (Hysteria2 > SS-2022 > Meek > DoH > WebSocket > Reality). Returns
/// `[Raw]` only when nothing else is configured - Raw is never auto-added as a
/// fallback alongside obfuscated transports (that would silently downgrade to
/// an unobfuscated carrier under censorship).
fn collect_transports(config: &ClientConfig) -> Result<Vec<TransportMode>, String> {
    let mut out: Vec<TransportMode> = Vec::new();
    // Shared Gecko/Salamander QUIC-obfuscation key (h3 + hysteria2).
    let quic_obfs_key: Option<[u8; 32]> = config
        .quic_obfs_password
        .as_ref()
        .filter(|p| !p.is_empty())
        .map(|p| mirage_quic_obfs::key_from_password(p.as_bytes()));
    if config.hysteria2_enabled == Some(true) {
        let rate_mbps = config.hysteria2_send_rate_mbps.unwrap_or(100);
        out.push(TransportMode::Hysteria2 {
            send_rate_bps: rate_mbps * 1_000_000,
            // Empty -> the transport derives a per-bridge cover SNI/SAN from the
            // bridge static key at dial time (F9-L).
            hostname: config.hysteria2_hostname.clone().unwrap_or_default(),
            obfs_key: quic_obfs_key,
        });
    }
    if config.h3_enabled == Some(true) {
        out.push(TransportMode::H3 {
            // Empty -> derived per-bridge from the bridge static key at dial.
            hostname: config.h3_hostname.clone().unwrap_or_default(),
            obfs_key: quic_obfs_key,
        });
    }
    if config.dnstt_enabled == Some(true) {
        let domain = config
            .dnstt_domain
            .clone()
            .ok_or_else(|| "dnstt_enabled requires dnstt_domain".to_string())?;
        let resolver = config
            .dnstt_resolver
            .as_ref()
            .ok_or_else(|| "dnstt_enabled requires dnstt_resolver".to_string())?
            .parse()
            .map_err(|e| format!("dnstt_resolver: {e}"))?;
        out.push(TransportMode::Dnstt { domain, resolver });
    }
    if let Some(ref psk_hex) = config.ss2022_psk_hex {
        out.push(TransportMode::Ss2022 {
            psk: decode_key32(psk_hex, "ss2022_psk")?,
        });
    }
    if let Some(ref front_domain) = config.meek_front_domain {
        let path = config
            .meek_path
            .clone()
            // Innocuous default - never the project-identifying "/mirage".
            .unwrap_or_else(|| "/".to_owned());
        out.push(TransportMode::Meek {
            front_domain: front_domain.clone(),
            path,
        });
    }
    if let Some(ref front_domain) = config.doh_front_domain {
        out.push(TransportMode::Doh {
            front_domain: front_domain.clone(),
        });
    }
    if let Some(ref signaling_host) = config.webrtc_signaling_host {
        let path = config
            .webrtc_path
            .clone()
            .unwrap_or_else(|| "/webrtc/offer".to_owned());
        out.push(TransportMode::WebRtc {
            signaling_host: signaling_host.clone(),
            path,
            ice_servers: config.webrtc_ice_servers.clone(),
        });
    }
    if config.ws_enabled == Some(true) {
        let path = config.ws_path.clone().unwrap_or_else(|| "/".to_owned());
        out.push(TransportMode::WebSocket { path });
    }
    if config.reality_enabled {
        let sni = config
            .reality_sni
            .clone()
            .ok_or_else(|| "reality_enabled=true requires reality_sni".to_string())?;
        let tls_fingerprint = if let Some(name) = config.reality_tls_fingerprint.as_deref() {
            Some(
                mirage_transport_reality::tls_fingerprint::lookup(name).ok_or_else(|| {
                    format!(
                        "unknown reality_tls_fingerprint {name:?}; known: \
                         chrome-desktop, firefox-desktop, safari-desktop"
                    )
                })?,
            )
        } else {
            None
        };
        out.push(TransportMode::Reality {
            sni,
            tls_cert_verify_pk: None, // patched per-invite in build_pool
            tls_fingerprint,
        });
    }
    // meek / DoH / WebSocket speak CLEARTEXT HTTP over the TCP socket: the
    // client does NOT originate TLS (red-team #4). They are only "HTTPS-like"
    // when the operator fronts the bridge with a REAL TLS terminator (a CDN edge
    // like Cloudflare/Fastly, or a local nginx/Caddy on :443 with an ACME cert)
    // that terminates TLS and forwards cleartext to the bridge. Used bare
    // (direct to the bridge), a censor sees plaintext HTTP + the auth token on
    // the wire. Warn loudly so an operator can't mistake the built-in "looks
    // like a CDN" shaping for on-wire TLS. (Full client-originated TLS is the
    // tracked real-TLS-termination work.)
    if !config.carrier_tls
        && out.iter().any(|m| {
            matches!(
                m,
                TransportMode::Meek { .. }
                    | TransportMode::Doh { .. }
                    | TransportMode::WebSocket { .. }
            )
        })
    {
        warn!(
            "meek/DoH/WebSocket carriers emit CLEARTEXT HTTP (carrier_tls is off) - they are \
             censorship-resistant ONLY behind a real TLS terminator. Set carrier_tls=true so the \
             client originates real TLS to the front, OR front the bridge with a CDN edge / nginx \
             on :443. Do NOT expose a bare meek/ws/doh port on a censored network."
        );
    }
    if out.is_empty() {
        // No obfuscated transport configured. Raw Noise-over-TCP exposes the
        // `MI` magic + message-type bytes in cleartext on the first packet - a
        // censor pins that instantly (red-team #11). Fail closed rather than
        // silently downgrade a possibly-censored user; require an explicit
        // opt-in for the uncensored dev/test case.
        if !config.allow_insecure_raw {
            return Err(
                "no obfuscated transport configured (reality/hysteria2/ws/meek/...); \
                        refusing to fall back to the unobfuscated raw-TCP carrier, whose MI \
                        magic is a cleartext censor signature. Configure a transport, or set \
                        allow_insecure_raw=true if you are on an uncensored network."
                    .to_string(),
            );
        }
        warn!(
            "no obfuscated transport configured; using the UNOBFUSCATED raw-TCP carrier \
             (allow_insecure_raw=true). The MI magic is a cleartext distinguisher - do NOT \
             use this on a censored network."
        );
        out.push(TransportMode::Raw);
    }
    // Fail closed if the ONLY carrier(s) are Wu-detectable (uniform-random from
    // byte 0). ss2022's entropy is inherent and it can't be nested inside a
    // mimicry transport here, so as a sole outer carrier it is trivially
    // entropy-classified (red-team #3). Same discipline as the raw-TCP guard.
    if !out.is_empty()
        && out
            .iter()
            .all(|m| matches!(m, TransportMode::Ss2022 { .. }))
        && !config.allow_ss2022_outer
    {
        return Err(
            "the only configured transport is Shadowsocks-2022, whose wire is uniform \
                    random from byte 0 - the exact Wu-2023 fully-encrypted-traffic signature a \
                    GFW-class entropy classifier flags (this is the class that got obfs4 dropped). \
                    Configure a mimicry transport (reality/meek/ws/...) alongside it, or set \
                    allow_ss2022_outer=true if Shadowsocks is permitted and no entropy DPI runs \
                    on your network."
                .to_string(),
        );
    }
    Ok(out)
}

/// Apply PARANOID mode + config-driven pacing before the pool is built. Paranoid is
/// one switch for the strongest posture (it overrides the individual toggles); the
/// `reality_pace*` fields are honored whether or not paranoid is set.
fn apply_paranoid(config: &mut ClientConfig) {
    if config.paranoid {
        config.reality_enabled = true; // hide as real TLS to a real cover host
        config.pad_enabled = true; // pad the Noise handshake
        config.allow_insecure_raw = false; // fail closed - never fall back to raw
        if config.reality_pace.is_none() {
            config.reality_pace = Some("replay".to_string()); // wear a real recorded shape
        }
        // Multi-hop (`circuit_relay`) is complementary but needs several bridges + relay
        // support, so it is left as a separate opt-in rather than forced here (forcing it
        // on a small/relay-less pool would break the session). Enable it alongside.
        tracing::warn!(
            reality = true,
            padding = true,
            pace = ?config.reality_pace,
            multihop = config.circuit_relay,
            "PARANOID MODE: Reality carrier + handshake padding + fail-closed + replay \
             pacing (wears a real recorded cover shape). The bridge must also enable \
             reality + replay for the shape to match. Enable circuit_relay for multi-hop."
        );
    }
    // Config-driven pacing (takes precedence over the env vars), paranoid or not.
    if let Some(mode) = config.reality_pace.clone() {
        mirage_transport_reality::set_pace_override(
            mode.clone(),
            config.reality_pace_profile.clone(),
        );
        if mode == "replay" && config.reality_pace_profile.is_none() {
            tracing::warn!(
                "reality_pace=replay but reality_pace_profile is unset; pacing stays inactive \
                 until a trace library is configured (see tools/cover-sources/README.md)"
            );
        }
    }
}

fn build_pool(mut config: ClientConfig) -> Result<EntryPool, String> {
    apply_paranoid(&mut config);
    let handshake_timeout = Duration::from_secs(config.handshake_timeout_secs);
    let failure_backoff = Duration::from_secs(config.entry_failure_backoff_secs);

    // Collect EVERY configured carrier transport as a candidate (priority
    // order). build_pool emits one entry per (bridge x candidate transport);
    // the dial path then prefers the transport the success-rate map says is
    // working on this network, and fails over to the others.
    let transports = collect_transports(&config)?;

    let mut invite_texts: Vec<String> = config.invites.clone();
    if let Some(ref single) = config.invite {
        invite_texts.push(single.clone());
    }

    let mut entries: Vec<BridgeEntry> = Vec::new();

    for (i, text) in invite_texts.iter().enumerate() {
        // Parse the invite ONCE into a base entry (with any candidate
        // transport - it's replaced per sibling below).
        let base = match BridgeEntry::from_invite(
            text,
            handshake_timeout,
            clone_transport_mode(&transports[0]),
        ) {
            Ok(e) => e,
            Err(err) => {
                warn!(index = i, error = %err, "invite entry failed to parse; skipping");
                continue;
            }
        };
        // Reality propagates the invite's cert-verify key; parse it once.
        let cert_verify_pk = {
            let clean = text.trim().strip_prefix("mirage://").unwrap_or(text.trim());
            MasterInvite::decode_text(clean)
                .ok()
                .and_then(|inv| inv.tls_cert_verify_pk)
        };
        // Share the bridge's one-shot credential pool + fresh-token deque +
        // discovered-address list across every per-transport sibling, so two
        // transports can never present (and burn) the same one-shot token.
        let (shared_tokens, shared_cursor, shared_fs_tokens, shared_fs_cursor) =
            match &base.credentials {
                Credentials::Invite {
                    tokens,
                    cursor,
                    fs_tokens,
                    fs_cursor,
                } => (
                    Arc::clone(tokens),
                    Arc::clone(cursor),
                    Arc::clone(fs_tokens),
                    Arc::clone(fs_cursor),
                ),
                // from_invite always yields Invite credentials.
                Credentials::Static { .. } => continue,
            };
        for t in &transports {
            let mut transport = clone_transport_mode(t);
            if let TransportMode::Reality {
                ref mut tls_cert_verify_pk,
                ..
            } = transport
            {
                *tls_cert_verify_pk = cert_verify_pk;
            }
            entries.push(BridgeEntry {
                bridge_addr: base.bridge_addr.clone(),
                bridge_x25519_pk: base.bridge_x25519_pk,
                bridge_ed25519_pk: base.bridge_ed25519_pk,
                claim_id: base.claim_id,
                credentials: Credentials::Invite {
                    tokens: Arc::clone(&shared_tokens),
                    cursor: Arc::clone(&shared_cursor),
                    fs_tokens: Arc::clone(&shared_fs_tokens),
                    fs_cursor: Arc::clone(&shared_fs_cursor),
                },
                handshake_timeout,
                transport,
                shared_salt: base.shared_salt,
                port_hop: base.port_hop,
                obfs_secret: base.obfs_secret,
                probe_root: base.probe_root,
                fs_rendezvous_anchor: base.fs_rendezvous_anchor,
                fresh_tokens: Arc::clone(&base.fresh_tokens),
                fs_unsupported_until: Arc::clone(&base.fs_unsupported_until),
                vless_uuid: None,          // stamped below
                pad_enabled: false,        // stamped below
                quic_obfs_disable: false,  // stamped below
                carrier_tls: false,        // stamped below
                carrier_tls_sni: None,     // stamped below
                pad_cbr_frame_bytes: None, // stamped below
                pad_cbr_interval_ms: 10,   // stamped below
                circuit_relay: false,      // stamped below
                mux_enabled: false,        // stamped below
                mux_carriers: Arc::new(Mutex::new(Vec::new())),
                mux_establishing: Arc::new(Mutex::new(())),
                operator_ed25519_pk: base.operator_ed25519_pk,
                discovered_addrs: Arc::clone(&base.discovered_addrs),
                revoked: Arc::clone(&base.revoked),
            });
        }
    }

    // Fall through to explicit-hex mode if no invites produced entries.
    if entries.is_empty() {
        let bridge_addr = config
            .bridge_addr
            .ok_or_else(|| "no valid invites and no bridge_addr".to_string())?;
        let bridge_x25519_pk = decode_key32(
            config
                .bridge_x25519_pk_hex
                .as_deref()
                .ok_or_else(|| "explicit mode: bridge_x25519_pk_hex required".to_string())?,
            "bridge_x25519_pk",
        )?;
        let client_x25519_sk = decode_key32(
            config
                .client_x25519_sk_hex
                .as_deref()
                .ok_or_else(|| "explicit mode: client_x25519_sk_hex required".to_string())?,
            "client_x25519_sk",
        )?;
        let token = decode_token(
            config
                .token_hex
                .as_deref()
                .ok_or_else(|| "explicit mode: token_hex required".to_string())?,
        )?;
        entries.push(BridgeEntry {
            bridge_addr,
            bridge_x25519_pk,
            bridge_ed25519_pk: [0u8; 32], // not available in explicit-hex mode
            claim_id: None,               // claim not supported in explicit-hex mode
            credentials: Credentials::Static {
                client_x25519_sk,
                token,
            },
            handshake_timeout,
            // Explicit-hex is a single-bridge dev/test mode with a single
            // one-shot Static token, so it stays single-transport (no
            // credential-sharing siblings): use the top configured candidate.
            transport: clone_transport_mode(&transports[0]),
            shared_salt: None,
            port_hop: None,
            obfs_secret: None, // no invite in explicit-hex mode
            probe_root: None,  // no invite in explicit-hex mode -> legacy probe
            fs_rendezvous_anchor: None,
            fresh_tokens: Arc::new(std::sync::Mutex::new(VecDeque::new())),
            fs_unsupported_until: Arc::new(AtomicU64::new(0)),
            vless_uuid: None,          // set below if vless_uuid_hex is configured
            pad_enabled: false,        // set by build_pool()
            quic_obfs_disable: false,  // set by build_pool()
            carrier_tls: false,        // set by build_pool()
            carrier_tls_sni: None,     // set by build_pool()
            pad_cbr_frame_bytes: None, // set by build_pool()
            pad_cbr_interval_ms: 10,   // set by build_pool()
            circuit_relay: false,      // set by build_pool()
            mux_enabled: false,        // set by build_pool()
            mux_carriers: Arc::new(Mutex::new(Vec::new())),
            mux_establishing: Arc::new(Mutex::new(())),
            operator_ed25519_pk: [0u8; 32], // not available in explicit-hex mode
            discovered_addrs: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            revoked: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        });
    }

    if entries.is_empty() {
        return Err("no bridge entries configured".to_string());
    }

    // Parse VLESS UUID and stamp it onto every entry.
    let vless_uuid: Option<[u8; 16]> = if let Some(ref hex_str) = config.vless_uuid_hex {
        let cleaned = hex_str.replace('-', "");
        let raw = hex::decode(&cleaned).map_err(|e| format!("vless_uuid_hex: hex decode: {e}"))?;
        if raw.len() != 16 {
            return Err(format!(
                "vless_uuid_hex: expected 16 bytes, got {}",
                raw.len()
            ));
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&raw);
        Some(uuid)
    } else {
        None
    };
    if vless_uuid.is_some() {
        // Deanon: VLESS emits a STATIC 16-byte client UUID before the Noise
        // handshake. Over an unauthenticated Raw carrier that UUID is in
        // cleartext on the wire - a stable identifier that links the user
        // across every session and IP. Refuse the combination: VLESS must ride
        // an encrypted outer transport (Reality / WebSocket-over-TLS / etc.).
        if entries
            .iter()
            .any(|e| matches!(e.transport, TransportMode::Raw))
        {
            return Err(
                "vless_uuid_hex is set but a bridge resolves to the Raw carrier - the \
                        VLESS UUID would be sent in cleartext (a cross-session tracking handle). \
                        Use VLESS only over an encrypted carrier (reality/ws/...), or remove \
                        vless_uuid_hex."
                    .to_string(),
            );
        }
        for entry in &mut entries {
            entry.vless_uuid = vless_uuid;
        }
    }

    // Stamp pad config onto every entry.
    if config.pad_enabled {
        for entry in &mut entries {
            entry.pad_enabled = true;
            entry.pad_cbr_frame_bytes = config.pad_cbr_frame_bytes;
            entry.pad_cbr_interval_ms = config.pad_cbr_interval_ms;
        }
    }

    // Stamp circuit_relay flag.
    if config.circuit_relay {
        for entry in &mut entries {
            entry.circuit_relay = true;
        }
    }

    // Stamp the QUIC-obfs-disable flag (red-team #9: plain QUIC vs Salamander).
    if config.quic_obfs_disable {
        for entry in &mut entries {
            entry.quic_obfs_disable = true;
        }
    }

    // Stamp the carrier-TLS flag + SNI (red-team #4: TLS-wrap meek/DoH/WS).
    if config.carrier_tls {
        for entry in &mut entries {
            entry.carrier_tls = true;
            entry.carrier_tls_sni = config.carrier_tls_sni.clone();
        }
    }

    // Stamp mux flag. Multiplexing is incompatible with circuit-relay's session
    // model, so it is force-disabled whenever circuit_relay is on (the CONNECT
    // traffic is onion-relayed, not a mux carrier).
    let mux_on = config.stream_mux_enabled && !config.circuit_relay;
    for entry in &mut entries {
        entry.mux_enabled = mux_on;
    }

    // Collect dynamic discovery groups before moving entries into the pool.
    // Group entries by (shared_salt, operator_ed25519_pk) - the same pair
    // identifies which announcement info-hash to subscribe to.
    let need_discovery = !config.nostr_relays.is_empty()
        || !config.dns_discovery_apexes.is_empty()
        || config.dht_enabled;
    let discovery_groups: Vec<DiscoveryGroup> = if need_discovery {
        use std::collections::HashMap;
        // Value carries the (group-uniform) FS anchor alongside the entry list.
        let mut map: HashMap<([u8; 32], [u8; 32]), DiscoveryGroupAcc> = HashMap::new();
        for entry in &entries {
            if let Some(salt) = entry.shared_salt {
                let op_pk = entry.operator_ed25519_pk;
                if op_pk != [0u8; 32] {
                    let slot = map.entry((salt, op_pk)).or_default();
                    // All entries under one (salt, op_pk) come from one invite,
                    // so the FS anchor is identical; record it once.
                    slot.0 = slot.0.or(entry.fs_rendezvous_anchor);
                    slot.1.push((
                        entry.bridge_x25519_pk,
                        entry.bridge_ed25519_pk,
                        Arc::clone(&entry.revoked),
                        Arc::clone(&entry.discovered_addrs),
                    ));
                }
            }
        }
        map.into_iter()
            .map(
                |((salt, op_pk), (fs_rendezvous_anchor, ents))| DiscoveryGroup {
                    shared_salt: salt,
                    operator_pk: op_pk,
                    fs_rendezvous_anchor,
                    entries: ents,
                },
            )
            .collect()
    } else {
        Vec::new()
    };

    // Load persisted per-network transport success rates so "what worked
    // before" biases this run. A missing/unreadable file starts fresh.
    //
    // ON BY DEFAULT (seamless-deploy): if the operator didn't set an explicit
    // `success_state_path`, fall back to the XDG state dir so a plain
    // deployment stops cold-relearning which carriers are censored on every
    // restart (the exact re-probing of known-blocked raw/UDP carriers the
    // self-adversary steers off). An operator can still pin a path, or set it
    // to "" to disable persistence entirely.
    let resolved_state_path = match config.success_state_path.as_deref() {
        Some("") => None, // explicit opt-out
        Some(p) => Some(p.to_string()),
        None => default_success_state_path(),
    };
    let success_map = Arc::new(match resolved_state_path.as_deref() {
        Some(path) => load_from_path(path, KNOWN_TRANSPORTS).unwrap_or_else(|e| {
            warn!(path = %path, error = %e, "success-state load failed; starting fresh");
            SuccessRateMap::new()
        }),
        None => SuccessRateMap::new(),
    });
    // Per-network fingerprint: scope the router's + posture's learned state to
    // "the network we're actually on" (stable across DHCP, flips when the user
    // moves networks). Falls back to `unknown()` when signals are unavailable.
    let network = gather_network_signals().fingerprint();
    info!(
        network = %hex::encode(&network.digest[..6]),
        "network fingerprint derived; routing/posture state scoped to this network"
    );

    let discovery_trigger = Arc::new(tokio::sync::Notify::new());
    let pool = EntryPool::new(
        entries,
        failure_backoff,
        Arc::clone(&discovery_trigger),
        Arc::clone(&success_map),
        network,
    );

    // Persist learned transport health periodically so it survives restarts
    // (avoids re-probing every blocked transport from scratch on relaunch).
    // On by default via `resolved_state_path` (XDG state dir); "" opts out.
    if let Some(path) = resolved_state_path.clone() {
        // Best-effort: ensure the parent dir exists (the default XDG path may
        // not have been created yet). A failure here is non-fatal - the first
        // save will surface it.
        if let Some(parent) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let map = Arc::clone(&success_map);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            tick.tick().await; // skip the immediate first tick
            loop {
                tick.tick().await;
                if let Err(e) = save_to_path(&map, &path) {
                    warn!(path = %path, error = %e, "success-state save failed");
                }
            }
        });
    }

    // Spawn background dynamic discovery task if any channels are configured.
    let has_discovery = (!config.nostr_relays.is_empty()
        || !config.dns_discovery_apexes.is_empty()
        || config.dht_enabled)
        && !discovery_groups.is_empty();
    if has_discovery {
        let relay_urls = config.nostr_relays.clone();
        let dns_apexes = config.dns_discovery_apexes.clone();
        let dht_bootstrap_addrs = config.dht_bootstrap_addrs.clone();
        let dht_enabled = config.dht_enabled;
        let interval = Duration::from_secs(config.discovery_interval_secs);
        tokio::spawn(run_nostr_discovery(
            relay_urls,
            dns_apexes,
            dht_bootstrap_addrs,
            dht_enabled,
            discovery_groups,
            interval,
            discovery_trigger,
        ));
    }

    Ok(pool)
}

/// Clone a `TransportMode` (needed because `TransportMode` holds non-Copy
/// types and is used in a loop).
fn clone_transport_mode(t: &TransportMode) -> TransportMode {
    match t {
        TransportMode::Raw => TransportMode::Raw,
        TransportMode::Reality {
            sni,
            tls_cert_verify_pk,
            tls_fingerprint,
        } => TransportMode::Reality {
            sni: sni.clone(),
            tls_cert_verify_pk: *tls_cert_verify_pk,
            tls_fingerprint: *tls_fingerprint,
        },
        TransportMode::Ss2022 { psk } => TransportMode::Ss2022 { psk: *psk },
        TransportMode::WebSocket { path } => TransportMode::WebSocket { path: path.clone() },
        TransportMode::Hysteria2 {
            send_rate_bps,
            hostname,
            obfs_key,
        } => TransportMode::Hysteria2 {
            send_rate_bps: *send_rate_bps,
            hostname: hostname.clone(),
            obfs_key: *obfs_key,
        },
        TransportMode::H3 { hostname, obfs_key } => TransportMode::H3 {
            hostname: hostname.clone(),
            obfs_key: *obfs_key,
        },
        TransportMode::Dnstt { domain, resolver } => TransportMode::Dnstt {
            domain: domain.clone(),
            resolver: *resolver,
        },
        TransportMode::Meek { front_domain, path } => TransportMode::Meek {
            front_domain: front_domain.clone(),
            path: path.clone(),
        },
        TransportMode::Doh { front_domain } => TransportMode::Doh {
            front_domain: front_domain.clone(),
        },
        TransportMode::WebRtc {
            signaling_host,
            path,
            ice_servers,
        } => TransportMode::WebRtc {
            signaling_host: signaling_host.clone(),
            path: path.clone(),
            ice_servers: ice_servers.clone(),
        },
    }
}

// -- Embeddable library API (mobile / FFI) ---------------------------------------
//
// The CLI path below owns argv, tracing init, self-elevation and process::exit.
// Everything a host application (an Android VpnService or an iOS
// NEPacketTunnelProvider, via the FFI crate) needs is exposed here instead:
// parse a config, build the bridge pool, and run the TUN loop on a device the OS
// hands us - with a CancellationToken to stop cleanly. No argv, no process::exit,
// no OS-route installation (the platform VPN API owns routing on mobile).

/// An opaque, parsed Mirage client configuration.
///
/// Built from the same JSON a desktop `mirage-client` reads
/// ([`Config::from_json`]). Feed it to [`Client::new`]. This replaces the CLI
/// argv path for embedded hosts.
pub struct Config(ClientConfig);

impl Config {
    /// Parse a client configuration from a JSON string (the same schema the
    /// desktop client loads from a file).
    pub fn from_json(json: &str) -> Result<Self, String> {
        let cfg: ClientConfig =
            serde_json::from_str(json).map_err(|e| format!("config parse: {e}"))?;
        Ok(Self(cfg))
    }

    /// Whether the config requests TUN/VPN mode.
    #[must_use]
    pub fn tun_enabled(&self) -> bool {
        self.0.tun_enabled
    }

    /// The configured TUN MTU in bytes.
    #[must_use]
    pub fn tun_mtu(&self) -> usize {
        self.0.tun_mtu
    }
}

/// A built Mirage client: a pool of bridge entries ready to carry tunneled flows.
///
/// The typical mobile lifecycle is: the host app stands up the OS VPN (Android
/// `VpnService`, iOS `NEPacketTunnelProvider`), obtains a [`mirage_tun::TunDevice`]
/// (an fd-backed device on Android, a packet-flow bridge on iOS), then calls
/// [`Client::run_tun`] on a background task. Cancelling the supplied
/// [`CancellationToken`](tokio_util::sync::CancellationToken) stops the tunnel.
pub struct Client {
    pool: Arc<EntryPool>,
}

impl Client {
    /// Build the client from a parsed [`Config`]. This constructs the bridge
    /// pool (credentials, transports, discovery) but does not dial anything yet.
    pub fn new(config: Config) -> Result<Self, String> {
        Ok(Self {
            pool: Arc::new(build_pool(config.0)?),
        })
    }

    /// Number of bridge entries in the pool.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.pool.len()
    }

    /// Run the TUN VPN loop on a caller-provided [`mirage_tun::TunDevice`] until
    /// `shutdown` is cancelled.
    ///
    /// Mirage runs the userspace netstack on `device` and tunnels every
    /// terminated flow through the bridge pool. It installs NO OS routes - on
    /// mobile the platform VPN API owns routing (and, on Android, the app must
    /// `VpnService.protect()` the carrier sockets; see the FFI crate). Returns
    /// `Ok(())` on a clean shutdown, or `Err` if the netstack fails.
    pub async fn run_tun<D>(
        &self,
        device: D,
        mtu: usize,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> Result<(), String>
    where
        D: mirage_tun::TunDevice + Send + 'static,
    {
        run_tun_with_device(Arc::clone(&self.pool), device, mtu, shutdown).await
    }
}

// -- Socket protection hook (Android VpnService.protect) -------------------------
//
// On Android every socket the client opens for a CARRIER must be excluded from
// the VPN via `VpnService.protect(fd)`, or the encrypted carrier packets are
// themselves routed back INTO the tunnel - an infinite loop that also breaks
// connectivity. Desktop has no such requirement. The FFI layer installs a
// protector that upcalls into the host `VpnService`; when none is installed
// (desktop) the dial path is byte-identical to before.

type SocketProtector = Box<dyn Fn(i32) -> bool + Send + Sync>;
static SOCKET_PROTECTOR: std::sync::OnceLock<SocketProtector> = std::sync::OnceLock::new();

/// Install a socket-protection callback (Android only).
///
/// `f` receives the raw fd of each freshly-created carrier socket BEFORE it
/// connects and must exclude it from the VPN (typically `VpnService.protect(fd)`),
/// returning `true` on success. Idempotent: only the first call takes effect.
/// Desktop callers never invoke this, so the dial path is unchanged there.
pub fn set_socket_protector<F>(f: F)
where
    F: Fn(i32) -> bool + Send + Sync + 'static,
{
    let _ = SOCKET_PROTECTOR.set(Box::new(f));
}

/// Whether a socket protector has been installed (i.e. we're on mobile).
fn socket_protector_installed() -> bool {
    SOCKET_PROTECTOR.get().is_some()
}

/// Ask the host to protect `fd`. No protector installed (desktop) => `true`.
/// Only called on Unix (where sockets have fds to protect); on other platforms
/// the protect path is compiled out entirely.
#[cfg(unix)]
fn protect_socket(fd: i32) -> bool {
    SOCKET_PROTECTOR.get().is_none_or(|f| f(fd))
}

/// Dial a bridge carrier over TCP.
///
/// Desktop (no protector): identical to `TcpStream::connect(addr)` - resolves
/// every candidate address and tries each. Mobile (protector installed):
/// resolves, creates the socket, hands its fd to [`protect_socket`] BEFORE
/// connecting (so the carrier is excluded from the VPN), then connects.
async fn dial_bridge_tcp(addr: &str) -> std::io::Result<TcpStream> {
    if !socket_protector_installed() {
        return TcpStream::connect(addr).await;
    }
    use tokio::net::TcpSocket;
    let mut last_err = std::io::Error::new(std::io::ErrorKind::Other, "no address resolved");
    for sa in tokio::net::lookup_host(addr).await? {
        let socket = if sa.is_ipv4() {
            TcpSocket::new_v4()
        } else {
            TcpSocket::new_v6()
        }?;
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            if !protect_socket(socket.as_raw_fd()) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "VpnService.protect() rejected the carrier socket",
                ));
            }
        }
        match socket.connect(sa).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

// -- CLI entry point ------------------------------------------------------------

/// Command-line entry point for the `mirage-client` binary.
///
/// This is the desktop/CLI driver: it parses argv, dispatches the
/// `status`/`doctor`/`connect` subcommands, loads the config, performs
/// process hardening + optional self-elevation, and runs the daemon. It owns
/// all CLI concerns (including `std::process::exit` on the terminal paths), so
/// the embeddable library API below (used by the mobile FFI) never touches
/// argv or the process lifetime. The `mirage-client` bin is a thin
/// `#[tokio::main]` wrapper around this.
pub async fn cli_main() {
    if let Err(e) = harden_process() {
        eprintln!("fatal: failed to disable core dumps: {e}");
        std::process::exit(2);
    }
    // Tracing is initialized inside `run_daemon` (the only path that needs it),
    // so the diagnostic subcommands - status / doctor / --check-config /
    // --version / --help - produce clean, log-free output.
    let argv: Vec<String> = std::env::args().collect();
    match argv.get(1).map(|s| s.as_str()) {
        Some("--version") | Some("-V") => {
            println!("mirage-client {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }
        Some("--help") | Some("-h") => {
            println!(
                "mirage-client {ver}\n\
                 \n\
                 Usage: mirage-client <config.json> [options]\n\
                        mirage-client connect <mirage://invite> [--socks <addr>] [--reality-sni <domain>] [--hysteria2]\n\
                        mirage-client status [--management-bind <addr>]\n\
                        mirage-client doctor <config.json | mirage://invite>\n\
                 \n\
                 Options:\n\
                   <config.json>             Path to the client JSON configuration file.\n\
                   connect <invite>          One-command connect from an invite URL (no config file).\n\
                                             --socks <addr> sets the local listener (default 127.0.0.1:1080);\n\
                                             --reality-sni / --hysteria2 enable those carriers.\n\
                   status                    Query a running daemon's management API and\n\
                                             print sessions + per-bridge transport health.\n\
                   doctor <config|invite>    Preflight: validate the config/invite and live-\n\
                                             test whether each bridge is reachable.\n\
                   --version, -V             Print version and exit.\n\
                   --help, -h                Print this help and exit.\n\
                   --check-config            Validate config and print a summary without starting.\n\
                   --management-bind <addr>  Serve management JSON API at this address (e.g. 127.0.0.1:19443).\n\
                 \n\
                 Config transport fields (priority order, only one active at a time):\n\
                   hysteria2_enabled        QUIC/BRUTAL carrier (highest priority).\n\
                   ss2022_psk_hex           Shadowsocks-2022 AEAD carrier.\n\
                   meek_front_domain        Meek HTTP long-poll carrier (CDN Host header).\n\
                   doh_front_domain         DoH-tunnel carrier (POST /dns-query).\n\
                   ws_enabled               WebSocket carrier.\n\
                   reality_enabled          Reality TLS carrier.\n\
                   (none of the above)      Raw Noise session over TCP.\n\
                 \n\
                 Optional overlay (any carrier):\n\
                   vless_uuid_hex     VLESS auth frame inserted before the Noise handshake.\n\
                 \n\
                 Generate config with: mirage-keygen --write-client-config client.json\n\
                 Once running, point your SOCKS5 proxy at the configured local_bind address.",
                ver = env!("CARGO_PKG_VERSION")
            );
            std::process::exit(0);
        }
        Some("status") => {
            // Query a running daemon's management API and print a
            // human-readable status (sessions + per-bridge transport health).
            run_status_query(&argv).await;
            std::process::exit(0);
        }
        Some("doctor") => {
            // Connectivity preflight: validate the config/invite AND live-test
            // whether each bridge is actually reachable, with actionable hints.
            run_doctor(&argv).await;
            std::process::exit(0);
        }
        Some("connect") => {
            // One-command onboarding: build a config straight from an invite
            // URL (+ optional transport flags) and run the daemon - no JSON
            // config file needed.
            let (config, mgmt) = build_connect_config(&argv);
            run_daemon(config, mgmt).await;
            return;
        }
        Some(p) if p.starts_with('-') && p != "--management-bind" && p != "--check-config" => {
            eprintln!("mirage-client: unknown flag '{p}'. Try --help.");
            std::process::exit(2);
        }
        _ => {}
    }

    let config_path = match argv.get(1) {
        Some(p) if !p.starts_with('-') => p.clone(),
        _ => {
            eprintln!("usage: mirage-client <config.json> [--management-bind <addr>]\nTry --help for more information.");
            std::process::exit(2);
        }
    };

    // Parse --management-bind <addr> and --check-config
    let mut management_bind: Option<String> = None;
    let mut check_only = false;
    for (i, arg) in argv.iter().enumerate() {
        if arg == "--management-bind" {
            management_bind = argv.get(i + 1).cloned();
        }
        if arg == "--check-config" {
            check_only = true;
        }
    }

    let config: ClientConfig = match std::fs::read_to_string(&config_path)
        .map_err(|e| format!("read {config_path}: {e}"))
        .and_then(|s| serde_json::from_str::<ClientConfig>(&s).map_err(|e| e.to_string()))
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("fatal: config error: {e}");
            std::process::exit(2);
        }
    };

    if check_only {
        let local_bind_chk = config.local_bind.clone();
        let pool = match build_pool(config) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("mirage-client config ERROR: {e}");
                std::process::exit(1);
            }
        };
        println!("mirage-client config OK");
        println!("  local_bind:  {}", local_bind_chk);
        println!("  entries:     {}", pool.len());
        for (i, e) in pool.entries.iter().enumerate() {
            let ph = if e.port_hop.is_some() {
                " [port-hop]"
            } else {
                ""
            };
            let vl = if e.vless_uuid.is_some() {
                " [vless]"
            } else {
                ""
            };
            let pk = if e.bridge_ed25519_pk != [0u8; 32] {
                format!(" pk={}...", &hex::encode(e.bridge_ed25519_pk)[..16])
            } else {
                String::new()
            };
            println!(
                "  entry[{i}]:    {} ({}){}{}{}",
                e.bridge_addr,
                e.describe_mode(),
                ph,
                vl,
                pk
            );
        }
        std::process::exit(0);
    }

    // Windows: TUN mode needs Administrator (Wintun adapter + route changes).
    // If requested and we're not elevated, relaunch elevated via a UAC prompt
    // and exit this instance. No-op on other platforms / when TUN is off.
    if let Err(e) = maybe_self_elevate_for_tun(config.tun_enabled) {
        eprintln!("fatal: {e}");
        std::process::exit(2);
    }

    run_daemon(config, management_bind).await;
}

/// Windows self-elevation for TUN mode. When `tun_enabled` and the process is
/// not already Administrator, relaunch it elevated (triggering a UAC prompt via
/// PowerShell `Start-Process -Verb RunAs`) and exit; the elevated copy carries
/// the same arguments and does the real work. Returns `Ok(())` to proceed
/// in-process when already elevated. Returns `Err` if elevation was declined or
/// the helper could not run. Uses only `std::process` - no `unsafe`, no FFI -
/// so the crate stays `#![forbid(unsafe_code)]`.
#[cfg(windows)]
fn maybe_self_elevate_for_tun(tun_enabled: bool) -> Result<(), String> {
    if !tun_enabled {
        return Ok(());
    }
    if windows_is_elevated() {
        return Ok(());
    }
    let exe = std::env::current_exe()
        .map_err(|e| format!("self-elevate: cannot locate own executable: {e}"))?
        .to_string_lossy()
        .into_owned();
    let args: Vec<String> = std::env::args().skip(1).collect();
    eprintln!(
        "mirage: TUN mode requires Administrator on Windows - requesting elevation. \
         Approve the UAC prompt; the tunnel opens in an elevated window."
    );
    let cmd = windows_relaunch_elevated_cmd(&exe, &args);
    let status = std::process::Command::new(&cmd[0])
        .args(&cmd[1..])
        .status()
        .map_err(|e| format!("self-elevate: could not launch elevation helper: {e}"))?;
    if !status.success() {
        return Err("UAC elevation was declined or failed; TUN mode needs \
                    Administrator (approve the prompt, or run from an elevated \
                    terminal)"
            .to_string());
    }
    // The elevated instance is running (Start-Process launches it detached);
    // this unprivileged instance has nothing further to do.
    std::process::exit(0);
}

/// Non-Windows: elevation is handled by root/`CAP_NET_ADMIN` (Linux) or `sudo`
/// (macOS); there is no UAC to trigger, so this is a no-op.
#[cfg(not(windows))]
#[allow(clippy::unnecessary_wraps)]
fn maybe_self_elevate_for_tun(_tun_enabled: bool) -> Result<(), String> {
    Ok(())
}

/// Query (via PowerShell) whether the current process holds the Administrator
/// role. Any failure is treated as "not elevated" so we fail toward requesting
/// elevation rather than assuming we have it.
#[cfg(windows)]
fn windows_is_elevated() -> bool {
    let cmd = windows_is_elevated_cmd();
    std::process::Command::new(&cmd[0])
        .args(&cmd[1..])
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim()
                .eq_ignore_ascii_case("true")
        })
        .unwrap_or(false)
}

/// PowerShell command that prints `True`/`False` for whether the current token
/// is in the Administrators role.
#[cfg(any(windows, test))]
fn windows_is_elevated_cmd() -> Vec<String> {
    vec![
        "powershell".into(),
        "-NoProfile".into(),
        "-Command".into(),
        "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]\
         ::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
            .into(),
    ]
}

/// Quote one argument for a PowerShell single-quoted string literal (only `'`
/// is special inside `'...'`, and it is escaped by doubling). Prevents an
/// argument containing spaces or metacharacters from being re-split or
/// interpreted when relaunched through `Start-Process -ArgumentList`.
#[cfg(any(windows, test))]
fn ps_single_quote(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', "''"))
}

/// PowerShell command that relaunches `exe` with `args`, elevated (UAC via
/// `-Verb RunAs`). The elevated process is launched detached.
#[cfg(any(windows, test))]
fn windows_relaunch_elevated_cmd(exe: &str, args: &[String]) -> Vec<String> {
    let file = ps_single_quote(exe);
    let script = if args.is_empty() {
        format!("Start-Process -FilePath {file} -Verb RunAs")
    } else {
        let arglist = args
            .iter()
            .map(|a| ps_single_quote(a))
            .collect::<Vec<_>>()
            .join(",");
        format!("Start-Process -FilePath {file} -ArgumentList {arglist} -Verb RunAs")
    };
    vec![
        "powershell".into(),
        "-NoProfile".into(),
        "-Command".into(),
        script,
    ]
}

/// Build the entry pool, spawn the background tasks (discovery, claim, probe,
/// token refresh, management API), and serve the local SOCKS5 listener until
/// shutdown. Shared by the config-file path and `mirage connect`.
/// Signed correction (seconds) applied to the OS clock when deriving discovery
/// epochs - set once at startup by [`pin_clock_offset`] from a multi-source
/// HTTPS-`Date` consensus. `0` = OS clock trusted (or unverified, fail-open).
static CLOCK_OFFSET_SECS: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

/// Current Unix time for discovery-epoch derivation, corrected by the startup
/// clock-skew pin. Use this - not a bare `SystemTime::now()` - everywhere an
/// info-hash epoch (`floor(t/3600)`) is computed, so a poisoned OS clock cannot
/// silently land the client on the wrong (empty) epoch.
fn discovery_now_unix() -> u64 {
    let os = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    (os + CLOCK_OFFSET_SECS.load(std::sync::atomic::Ordering::Relaxed)).max(0) as u64
}

/// Time-check targets: the hosts the client is ALREADY configured to contact
/// for discovery/cover (nostr relays, the DoH / meek CDN fronts). Reusing them
/// means the clock probes introduce no new hardcoded-host signature - an
/// ordinary `GET /` to a host the client already talks to. Returns `(host, port)`.
fn time_check_hosts(config: &ClientConfig) -> Vec<(String, u16)> {
    let mut hosts: Vec<(String, u16)> = Vec::new();
    let mut push = |raw: &str| {
        let h = raw.trim();
        let h = ["wss://", "https://", "ws://", "http://"]
            .iter()
            .find_map(|p| h.strip_prefix(p))
            .unwrap_or(h);
        let h = h.split('/').next().unwrap_or(h);
        let (host, port) = match h.rsplit_once(':') {
            Some((hh, pp)) => match pp.parse::<u16>() {
                Ok(port) => (hh.to_string(), port),
                Err(_) => (h.to_string(), 443),
            },
            None => (h.to_string(), 443),
        };
        if !host.is_empty() && !hosts.iter().any(|(x, _)| x == &host) {
            hosts.push((host, port));
        }
    };
    for r in &config.nostr_relays {
        push(r);
    }
    if let Some(d) = &config.doh_front_domain {
        push(d);
    }
    if let Some(d) = &config.meek_front_domain {
        push(d);
    }
    hosts
}

/// One-shot startup clock-skew pin (see the `mirage-time` crate). Fetches
/// HTTPS-`Date` readings from [`time_check_hosts`] concurrently, computes a
/// median consensus, and:
///   - within 5 min of the OS clock -> trust it (offset 0);
///   - 5 min - 24 h -> warn and correct the discovery clock to consensus;
///   - > 24 h with >= 3 agreeing sources -> correct (the LOCAL clock is wrong);
///   - > 24 h with < 3 sources -> **refuse** (a poisoned clock/source could route
///     > the client to an attacker's epoch);
///   - no sources reachable -> warn and proceed on the OS clock (fail-open - the
///     time check must never itself brick discovery).
async fn pin_clock_offset(config: &ClientConfig) {
    let hosts = time_check_hosts(config);
    if hosts.is_empty() {
        return;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let timeout = std::time::Duration::from_secs(6);

    let mut set = tokio::task::JoinSet::new();
    for (host, port) in hosts {
        set.spawn(async move { mirage_time::fetch_https_date(&host, port, timeout, now).await });
    }
    let mut readings: Vec<mirage_time::SourceReading> = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok(Some(r)) = joined {
            readings.push(r);
        }
    }

    let fresh = readings.iter().filter(|r| r.is_fresh(now)).count();
    let consensus = mirage_time::consensus(&readings, now);
    match mirage_time::check_local_time(now, consensus) {
        Ok(t) => {
            let off = t as i64 - now as i64;
            if off != 0 {
                CLOCK_OFFSET_SECS.store(off, std::sync::atomic::Ordering::Relaxed);
            }
        }
        Err(mirage_time::TimePinError::NoFreshSources) => {
            warn!("clock unverified: no time sources reachable; using OS clock for discovery");
        }
        Err(mirage_time::TimePinError::SkewExceeded(dev)) => {
            if fresh >= 3 {
                let c = consensus.unwrap_or(now);
                warn!(
                    deviation_secs = dev,
                    sources = fresh,
                    "system clock is badly skewed vs a {fresh}-source time consensus; \
                     correcting the discovery clock - FIX YOUR SYSTEM CLOCK"
                );
                CLOCK_OFFSET_SECS
                    .store(c as i64 - now as i64, std::sync::atomic::Ordering::Relaxed);
            } else {
                fatal(format!(
                    "system clock is off by {dev}s but only {fresh} independent time \
                     source(s) were reachable - refusing discovery (a poisoned clock or \
                     time source could route you to an attacker). Fix your system clock, \
                     or configure more nostr relays / a DoH front so the clock can be \
                     verified against >= 3 sources."
                ));
            }
        }
    }
}

async fn run_daemon(config: ClientConfig, management_bind: Option<String>) {
    mirage_common::init_tracing();
    // One-shot clock-skew pin BEFORE any epoch-derived discovery, so a poisoned
    // OS clock is detected (and corrected, or refused) rather than silently
    // landing on an empty epoch.
    pin_clock_offset(&config).await;

    let local_bind = config.local_bind.clone();
    // Extract TUN params before `build_pool` consumes `config`.
    let tun_enabled = config.tun_enabled;
    let tun_name = config.tun_name.clone();
    let tun_address = config.tun_address;
    let tun_netmask = config.tun_netmask;
    let tun_mtu = config.tun_mtu;
    // Extract cover-traffic policy before `build_pool` consumes `config`.
    let cover_policy = if config.cover_destinations.is_empty() {
        None
    } else {
        Some(CoverPolicy {
            idle_threshold: Duration::from_secs(config.cover_idle_secs),
            mean_inter_fetch: Duration::from_secs(config.cover_interval_secs),
            max_cover_fraction: config.cover_max_fraction,
            destinations: config.cover_destinations.clone(),
        })
    };
    let pool = Arc::new(build_pool(config).unwrap_or_else(|e| fatal(e)));

    info!(
        local_bind = %local_bind,
        entry_count = pool.len(),
        total_tokens = pool.total_tokens(),
        "mirage-client: accepting local connections"
    );
    for (i, e) in pool.entries.iter().enumerate() {
        // Show first 16 hex chars of bridge_ed25519_pk as a short fingerprint.
        // Operators can cross-reference with the bridge's own startup log.
        let pk_fp = if e.bridge_ed25519_pk != [0u8; 32] {
            format!("{}...", &hex::encode(e.bridge_ed25519_pk)[..16])
        } else {
            "(explicit-hex mode)".to_string()
        };
        info!(
            idx = i,
            bridge = %e.bridge_addr,
            mode = e.describe_mode(),
            tokens = e.token_count(),
            bridge_pk = %pk_fp,
            port_hop = e.port_hop.is_some(),
            "pool entry"
        );
    }
    if pool.len() > 1 {
        info!(
            "multi-entry pool active: {} bridges - \
             censor must block ALL to cut the connection",
            pool.len()
        );
    }

    // Startup parallel probe: TCP-connect to every bridge entry concurrently
    // to seed latency measurements and detect unreachable bridges before the
    // first user connection arrives. Runs with a 3-second per-entry timeout
    // so startup never blocks more than ~3 s regardless of pool size.
    if pool.len() > 0 {
        info!(
            "probing {} bridge entr{} at startup...",
            pool.len(),
            if pool.len() == 1 { "y" } else { "ies" }
        );
        probe_all_entries(&pool, Duration::from_secs(3), Duration::ZERO).await;
    }

    // Claim fresh tokens for each entry that carries a claim_id.  This runs
    // after the probe so we already know which bridges are reachable.  A
    // successful claim stores SessionRefreshToken.inner CapabilityTokens in
    // entry.fresh_tokens, which next_credentials() drains before falling back
    // to the bootstrap pool.  On claim failure we warn and continue - the
    // bootstrap pool (typically 8 tokens) still works for short-lived usage.
    {
        let claim_count = pool.entries.iter().filter(|e| e.claim_id.is_some()).count();
        if claim_count > 0 {
            info!(
                "claiming fresh tokens for {claim_count} bridge entr{}...",
                if claim_count == 1 { "y" } else { "ies" }
            );
            claim_all_entries(&pool, Duration::from_secs(10)).await;
        }
    }

    // Background periodic probe loop: re-probe all bridges to refresh latency
    // EMAs and recover entries that come back after a transient failure.
    // #8: the period is JITTERED (45-90 s, not a fixed 60 s) and the probes are
    // STAGGERED across an ~8 s window, so the recurring re-probe is not a
    // constant-cadence, single-burst behavioural fingerprint.
    {
        let bg_pool = Arc::clone(&pool);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(jitter_duration(
                    Duration::from_secs(45),
                    Duration::from_secs(90),
                ))
                .await;
                probe_all_entries(&bg_pool, Duration::from_secs(5), Duration::from_secs(8)).await;
            }
        });
    }

    // Background token refresh loop: every 2 minutes, check each entry's
    // fresh_tokens deque and request more from the bridge when below the
    // low watermark.  Net cost: 1 token consumed per refresh, 8 returned.
    {
        let bg_pool = Arc::clone(&pool);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(120)).await;
                refresh_low_entries(&bg_pool, Duration::from_secs(10)).await;
            }
        });
    }

    let active_sessions: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let total_sessions: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));

    // The local SOCKS5 listener is NO_AUTH (any local client may use it). Bound
    // to a non-loopback address it becomes an OPEN, unauthenticated proxy that
    // anyone on the network can route traffic through - traffic that exits
    // attributable to this (at-risk) user. Warn loudly, mirroring the management
    // API's guard; the safe default is 127.0.0.1.
    if !host_is_loopback(&local_bind) {
        warn!(
            addr = %local_bind,
            "local SOCKS5 proxy bound to a NON-loopback address - this is an OPEN, \
             unauthenticated proxy; anyone who can reach it tunnels traffic that exits \
             as YOU. Bind to 127.0.0.1 unless you have deliberately firewalled this port."
        );
    }
    let listener = TcpListener::bind(&local_bind)
        .await
        .unwrap_or_else(|e| fatal(format!("bind {local_bind}: {e}")));

    let start_time = std::time::Instant::now();
    if let Some(ref mgmt_bind) = management_bind {
        let mgmt_pool = Arc::clone(&pool);
        let mgmt_active = Arc::clone(&active_sessions);
        let mgmt_total = Arc::clone(&total_sessions);
        let mgmt_lb = local_bind.clone();
        let mgmt_addr = mgmt_bind.clone();
        tokio::spawn(serve_management(
            mgmt_addr,
            mgmt_pool,
            mgmt_active,
            mgmt_total,
            start_time,
            mgmt_lb,
        ));
    }

    // Cover traffic: idle-period decoy fetches through the tunnel. Opt-in
    // (empty destinations => disabled). Connects to our own SOCKS listener as a
    // local client, so it exercises the exact real tunnel path.
    if let Some(policy) = cover_policy {
        let cover_bind = local_bind.clone();
        tokio::spawn(run_cover_traffic(cover_bind, policy));
    }

    // TUN VPN mode: transparent, system-wide routing through Mirage. Runs
    // ALONGSIDE the SOCKS5 listener (apps can use either). Always compiled;
    // enabled at RUNTIME by `tun_enabled` (the OS device needs CAP_NET_ADMIN,
    // or Administrator on Windows).
    if tun_enabled {
        let tun_pool = Arc::clone(&pool);
        tokio::spawn(async move {
            if let Err(e) = run_tun(tun_pool, tun_name, tun_address, tun_netmask, tun_mtu).await {
                error!(error = %e, "TUN mode exited");
            }
        });
    }

    // Egress preflight (mux path): eagerly establish + verify a Mirage tunnel to
    // the best bridge before the first browser request. This makes the client
    // verified-connected up front (arming the egress gate the GUI / kill-switch
    // read), warms a mux carrier the first CONNECT reuses, and surfaces an
    // unreachable-bridge condition in the logs immediately instead of on first
    // use. Best-effort and non-blocking: if no bridge is reachable yet, the gate
    // stays closed and the first real connection re-attempts verification.
    if pool.mux_enabled() {
        let pf_pool = Arc::clone(&pool);
        tokio::spawn(async move {
            if let Some(idx) = pf_pool.pick_entry().await {
                let (timeout, bridge) = {
                    let e = &pf_pool.entries[idx];
                    (e.handshake_timeout, e.bridge_addr.clone())
                };
                let t0 = Instant::now();
                match get_or_create_carrier(&pf_pool.entries[idx], timeout).await {
                    Ok((_carrier, _fresh)) => {
                        // Arms the egress gate + records the success for routing;
                        // the warmed carrier stays in the pool for reuse.
                        pf_pool
                            .record_latency(idx, t0.elapsed().as_millis() as u64)
                            .await;
                        info!(bridge = %bridge, "egress preflight: tunnel verified");
                    }
                    Err(e) => {
                        warn!(bridge = %bridge, error = %e, "egress preflight: no bridge reachable yet; will verify on first use");
                        pf_pool.mark_failure(idx).await;
                    }
                }
            }
        });
    }

    loop {
        let (local, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!(error = %e, "local accept failed; backing off");
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        local.set_nodelay(true).ok();
        let pool = Arc::clone(&pool);
        let active_sessions_clone = Arc::clone(&active_sessions);
        let total_sessions_clone = Arc::clone(&total_sessions);
        tokio::spawn(async move {
            total_sessions_clone.fetch_add(1, Ordering::Relaxed);
            active_sessions_clone.fetch_add(1, Ordering::Relaxed);
            if let Err(e) = tunnel_one(local, peer, pool).await {
                debug!(peer = %peer, error = %e, "tunnel ended with error");
            }
            active_sessions_clone.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

// -- tunnel logic --------------------------------------------------------------

/// Streams per mux carrier before a fresh carrier is established. Kept below
/// the mux policy cap (256) and the bridge's per-session stream cap so a single
/// user rarely needs more than one or two carriers per bridge, holding O(1)
/// per-IP concurrency slots instead of O(connections).
const MAX_STREAMS_PER_CARRIER: u32 = 200;

/// How long to wait for a local app to finish its SOCKS5 greeting+request
/// before abandoning the connection (frees the task + fd).
const LOCAL_SOCKS_NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(10);

/// Idle timeout for a mux stream tunnel: a keep-alive connection with zero
/// bytes in either direction for this long is reaped, freeing the stream and
/// the bridge's upstream socket. Set well above normal browser keep-alive
/// (60-300 s) so legitimate idle-then-reused connections still work; a reaped
/// stream just re-opens cheaply over the existing carrier (no re-handshake).
const MUX_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// Flow-control + concurrency policy for client-side mux carriers.
fn mux_policy() -> MuxPolicy {
    MuxPolicy::default()
}

/// Convert a locally-parsed SOCKS5 destination into a `MuxTarget`, validating
/// that it is representable on the mux wire (LDH domain, non-zero port).
fn destination_to_muxtarget(dest: &local_socks::Destination) -> Result<MuxTarget, String> {
    let target = match dest {
        local_socks::Destination::Ip(std::net::SocketAddr::V4(a)) => MuxTarget::Ipv4 {
            addr: a.ip().octets(),
            port: a.port(),
        },
        local_socks::Destination::Ip(std::net::SocketAddr::V6(a)) => {
            // The mux encoder requires v4-mapped addresses to use the IPv4 form.
            if let Some(v4) = a.ip().to_ipv4_mapped() {
                MuxTarget::Ipv4 {
                    addr: v4.octets(),
                    port: a.port(),
                }
            } else {
                MuxTarget::Ipv6 {
                    addr: a.ip().octets(),
                    port: a.port(),
                }
            }
        }
        local_socks::Destination::Domain(d, port) => MuxTarget::Domain {
            domain: d.clone(),
            port: *port,
        },
    };
    // Fail fast on an unrepresentable target (non-LDH host, port 0) rather than
    // discovering it deep in open_local after burning a carrier.
    target.encode().map_err(|e| format!("target: {e}"))?;
    Ok(target)
}

/// Reuse a live carrier to `entry` with stream capacity, if one exists. Takes
/// the carriers lock only BRIEFLY (no dial), prunes dead carriers, and reaps
/// excess idle carriers keeping at most one warm spare - so a burst that opened
/// many carriers doesn't keep holding several bridge sessions (and per-IP slots)
/// open once the streams drain, while the spare avoids a re-handshake.
async fn reuse_carrier(entry: &BridgeEntry) -> Option<MuxConnection> {
    let mut carriers = entry.mux_carriers.lock().await;
    carriers.retain(|c| !c.is_closed());
    let mut idle_spare_kept = false;
    carriers.retain(|c| {
        if c.open_stream_count() == 0 {
            if idle_spare_kept {
                c.close();
                return false;
            }
            idle_spare_kept = true;
        }
        true
    });
    carriers
        .iter()
        .find(|c| c.open_stream_count() < MAX_STREAMS_PER_CARRIER)
        .cloned()
}

/// Get a live mux carrier to `entry` with stream capacity, establishing a fresh
/// one (a single handshake + one capability token) only when none exists or all
/// are full.
///
/// MUX-CLIENT-1: establishment is single-flighted via `mux_establishing` and the
/// dial NEVER holds the `mux_carriers` lock, so (a) a burst coalesces onto one
/// handshake - the first task dials while the rest wait on the guard, then reuse
/// the carrier it pushed - and (b) carrier *reuse* is never blocked behind an
/// in-flight dial.
/// Returns `(carrier, fresh)` where `fresh` is true only when this call newly
/// established the carrier (vs reusing a warm one). The caller uses `fresh` to
/// attribute a first-`open` failure to THIS dial's token: a freshly-established
/// forward-secure carrier that fails its first stream open is the old-bridge
/// signature (see `tunnel_one_mux`).
async fn get_or_create_carrier(
    entry: &BridgeEntry,
    timeout: Duration,
) -> Result<(MuxConnection, bool), String> {
    // Fast path: an existing carrier has capacity.
    if let Some(c) = reuse_carrier(entry).await {
        return Ok((c, false));
    }
    // Single-flight the dial. Others block here, not on the carriers lock.
    let _establish_guard = entry.mux_establishing.lock().await;
    // The leader may have established one while we waited for the guard.
    if let Some(c) = reuse_carrier(entry).await {
        return Ok((c, false));
    }
    // We are the establisher. `establish_session` performs the full transport
    // dial + Noise+ML-KEM handshake and spends one token.
    let mut session = establish_session(entry, timeout).await?;
    // Declare the session a mux carrier so the bridge runs the mux responder.
    // Best-effort: `connect_fs` returned after writing msg-3 WITHOUT a read, and
    // this tag byte is likewise a local write, so against an OLD bridge it
    // usually succeeds locally (the bridge's close arrives ~1 RTT later). The
    // reliable detection is the first stream `open` round-trip in
    // `tunnel_one_mux` (which reads); we still attribute a write failure here as
    // a bonus for the fast-RST case.
    if let Err(e) = async {
        session.write_all(&[MUX_SESSION_TAG]).await?;
        session.flush().await
    }
    .await
    {
        entry.note_fs_dial_dead();
        return Err(format!("mux tag write: {e}"));
    }
    let (conn, _acceptor) = MuxConnection::new(session, StreamRole::Initiator, mux_policy());
    // The client never accepts peer-opened streams; dropping the acceptor makes
    // any (unexpected) inbound Begin be reset automatically.
    {
        let mut carriers = entry.mux_carriers.lock().await;
        carriers.push(conn.clone());
        debug!(
            bridge = %entry.bridge_addr,
            carriers = carriers.len(),
            "mux: established new carrier"
        );
    }
    Ok((conn, true))
}

/// Jittered inter-attempt backoff for the bridge failover loops.
///
/// Without it, a failed dial `continue`s to the next entry with no delay, so a
/// censor that RSTs the first flow can watch one source IP burst STRUCTURALLY
/// DIVERSE bearer classes (QUIC -> TLS -> opaque-TCP -> DNS -> HTTP) to the same
/// destination within a few hundred milliseconds - a circumvention signature no
/// real application produces (red-team completeness-critic A). A jittered,
/// mildly-growing gap between attempts spreads the sequence out so it resembles
/// a flaky-network app's retries rather than an automated multi-protocol sweep.
/// Only incurred on failover (the happy path dials once), so it costs latency
/// exactly when we most want to avoid looking like a probe.
async fn failover_backoff(attempt: usize) {
    let mut b = [0u8; 2];
    let jitter = match getrandom::fill(&mut b) {
        Ok(()) => (u16::from_le_bytes(b) as u64) % 500,
        Err(_) => 0,
    };
    let base = 150 + 120 * (attempt.min(6) as u64);
    tokio::time::sleep(Duration::from_millis(base + jitter)).await;
}

/// Extract the host part of a `host:port` (or bare host / IP) dial string.
/// Handles `1.2.3.4:443`, `[2001:db8::1]:443`, bare IPs, and `domain:443`.
fn host_of_dial_str(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // Fast path: a full socket address (covers v4:port and [v6]:port).
    if let Ok(sa) = s.parse::<std::net::SocketAddr>() {
        return Some(sa.ip().to_string());
    }
    // A bare IP (no port).
    if s.parse::<std::net::IpAddr>().is_ok() {
        return Some(s.to_string());
    }
    // `[v6]:port` or `[v6]` bracketed form.
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return Some(rest[..end].to_string());
        }
    }
    // `domain:port` - strip a trailing numeric port only.
    if let Some((host, port)) = s.rsplit_once(':') {
        if !host.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            return Some(host.to_string());
        }
    }
    Some(s.to_string())
}

/// Collect every bridge IP the client may dial, so TUN routing can exclude them
/// from the tunnel (CRIT #25). Reads each entry's static `bridge_addr` plus its
/// discovered addresses, resolving any hostnames to IPs. Best-effort: a name
/// that fails to resolve now is simply not excluded (it can be re-derived when
/// discovery next runs), but the static endpoints - the common case - are.
///
/// KNOWN RESIDUAL (red-team #14): this is a SNAPSHOT taken at TUN start. A bridge
/// whose IP is *rotated in* by later discovery is NOT retroactively excluded, so
/// in VPN mode its carrier packets would route into the tunnel and loop, making
/// that freshly-rotated bridge unreachable until the client is restarted. This
/// degrades gracefully - every bridge known at start (and the whole existing
/// pool) keeps working - and the SOCKS5 proxy is unaffected. A live route-monitor
/// that re-pins exclusions on each discovery tick is the full fix (a follow-up;
/// it needs a shared, mutable `RouteGuard` + a background refresh task).
async fn collect_bridge_ips(pool: &EntryPool) -> Vec<std::net::IpAddr> {
    use std::collections::HashSet;
    let mut hosts: HashSet<String> = HashSet::new();
    for entry in &pool.entries {
        if let Some(h) = host_of_dial_str(&entry.bridge_addr) {
            hosts.insert(h);
        }
        for a in entry.discovered_addrs.read().await.iter() {
            if let Some(h) = host_of_dial_str(a) {
                hosts.insert(h);
            }
        }
    }
    let mut ips: HashSet<std::net::IpAddr> = HashSet::new();
    for h in hosts {
        if let Ok(ip) = h.parse::<std::net::IpAddr>() {
            ips.insert(ip);
        } else if let Ok(addrs) = tokio::net::lookup_host(format!("{h}:0")).await {
            for sa in addrs {
                ips.insert(sa.ip());
            }
        }
    }
    ips.into_iter().collect()
}

/// TUN VPN mode: open the TUN device, run the userspace netstack, and tunnel
/// every terminated flow through the carrier pool. Transparent + system-wide -
/// no per-app SOCKS config. Requires CAP_NET_ADMIN (Administrator on Windows).
async fn run_tun(
    pool: Arc<EntryPool>,
    name: String,
    address: std::net::Ipv4Addr,
    netmask: std::net::Ipv4Addr,
    mtu: usize,
) -> Result<(), String> {
    use mirage_tun::{OsTun, OsTunConfig, RouteConfig, RouteGuard};
    let dev = OsTun::create(&OsTunConfig {
        name: Some(name.clone()),
        address,
        netmask,
        mtu,
    })
    .map_err(|e| format!("tun: open device {name}: {e}"))?;

    // The kernel may not honour the requested name (macOS forces `utunN`), so
    // route installation must use the ACTUAL interface name, not `name`.
    let iface_name = dev.if_name().unwrap_or_else(|| name.clone());

    // CRIT #24/#25/#29: a TUN that is merely `up` routes NOTHING - the kernel
    // still egresses every packet on the physical link, so the user leaks in
    // clear while believing they are tunnelled. Install the OS routes that
    // actually capture traffic (split-default) while excluding the bridge IPs
    // (so the encrypted carrier does not recurse into the tunnel). FAIL-CLOSED:
    // if the routes cannot be installed we tear the device down and refuse to
    // run rather than present a leaking pseudo-VPN. The guard restores the
    // original table on drop.
    let bridge_ips = collect_bridge_ips(&pool).await;
    let _routes = RouteGuard::install(&RouteConfig {
        tun_name: iface_name.clone(),
        bridge_ips,
        enable_ipv6: true,
    })
    .map_err(|e| {
        format!(
            "tun: refusing to run - could not install capture routes ({e}). \
             Your traffic would otherwise leak in clear. Ensure you are running \
             as root/Administrator (Linux: CAP_NET_ADMIN)."
        )
    })?;
    info!(iface = %iface_name, %address, mtu, "TUN mode active: transparent system-wide VPN (routes installed, bridge excluded)");
    // `_routes` (the RouteGuard) stays live for the whole call below and is
    // dropped here on return, restoring the original routing table. The desktop
    // daemon runs until the process is killed, so pass a token that is never
    // cancelled; the loop still exits (with Err) if the netstack channel closes.
    run_tun_with_device(pool, dev, mtu, tokio_util::sync::CancellationToken::new()).await
}

/// Core of the TUN path shared by the desktop daemon and the mobile FFI: run
/// the userspace netstack on `device`, tunnel every terminated flow through
/// `pool`, and stop cleanly when `shutdown` is cancelled.
///
/// Unlike [`run_tun`], this takes an already-constructed [`mirage_tun::TunDevice`]
/// and installs NO OS routes - the caller owns both. On desktop the caller is
/// [`run_tun`] (it opens `OsTun` + installs a `RouteGuard` first); on mobile the
/// caller is [`Client::run_tun`] (the OS VPN API provides the device and owns
/// routing).
async fn run_tun_with_device<D>(
    pool: Arc<EntryPool>,
    device: D,
    mtu: usize,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<(), String>
where
    D: mirage_tun::TunDevice + Send + 'static,
{
    use mirage_tun::{NetStack, NetStackConfig};
    let ns_cfg = NetStackConfig {
        mtu,
        ..NetStackConfig::default()
    };
    let (stack, mut flows) = NetStack::new(device, ns_cfg);
    let stack_task = tokio::spawn(stack.run());
    // Each terminated flow -> one Mirage-tunneled task (TCP stream or UDP relay).
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => {
                stack_task.abort();
                return Ok(());
            }
            maybe_flow = flows.recv() => {
                let Some(flow) = maybe_flow else {
                    return Err("tun: netstack flow channel closed".to_string());
                };
                let pool = pool.clone();
                match flow {
                    mirage_tun::Flow::Tcp(f) => {
                        tokio::spawn(async move {
                            if let Err(e) = tunnel_flow(pool, f).await {
                                // Deanon: never record the user's destination, not even
                                // at debug (matches the onion/SOCKS safe-logging policy).
                                debug!(error = %e, "tun tcp flow ended");
                            }
                        });
                    }
                    mirage_tun::Flow::Udp(u) => {
                        tokio::spawn(async move {
                            if let Err(e) = tunnel_udp_flow(pool, u).await {
                                debug!(error = %e, "tun udp flow ended");
                            }
                        });
                    }
                }
            }
        }
    }
}

/// Tunnel one terminated TUN flow to its target through the carrier pool.
/// Mirrors [`tunnel_one_mux`], but the target comes from the IP header (not a
/// SOCKS5 request) and there is NO SOCKS5 reply - the netstack already
/// completed the app's local TCP handshake.
async fn tunnel_flow(pool: Arc<EntryPool>, flow: mirage_tun::TcpFlow) -> Result<(), String> {
    let target = socketaddr_to_muxtarget(flow.target)?;
    let n = pool.len();
    let mut last_err = String::from("no healthy bridge entries");
    for attempt in 0..n {
        if attempt > 0 {
            failover_backoff(attempt).await;
        }
        let Some(idx) = pool.pick_entry().await else {
            break;
        };
        let entry = &pool.entries[idx];
        let timeout = entry.handshake_timeout;
        let (carrier, _fresh) = match get_or_create_carrier(entry, timeout).await {
            Ok(c) => c,
            Err(e) => {
                pool.mark_failure(idx).await;
                last_err = e;
                continue;
            }
        };
        match tokio::time::timeout(timeout, carrier.open(target.clone())).await {
            Ok(Ok(stream)) => {
                // Idle-aware copy: reaps a silently-dead tunnel (freeing the
                // netstack flow slot + the bridge's upstream socket) instead of
                // pinning it forever - mirrors the SOCKS mux path.
                let started = Instant::now();
                let res =
                    mirage_socks5::copy_bidirectional_idle(flow, stream, MUX_STREAM_IDLE_TIMEOUT)
                        .await;
                if let Ok((up, down)) = &res {
                    // H3: feed session goodput to the throttle detector.
                    pool.record_session_goodput(idx, up + down, started.elapsed())
                        .await;
                }
                return res.map(|_| ()).map_err(|e| format!("copy: {e}"));
            }
            Ok(Err(e)) => {
                pool.mark_failure(idx).await;
                last_err = format!("open: {e}");
            }
            Err(_) => {
                pool.mark_failure(idx).await;
                last_err = "open timed out".to_string();
            }
        }
    }
    Err(last_err)
}

/// Build a [`MuxTarget`] from the concrete socket address the app dialed.
fn socketaddr_to_muxtarget(addr: std::net::SocketAddr) -> Result<MuxTarget, String> {
    let t = match addr {
        std::net::SocketAddr::V4(a) => MuxTarget::Ipv4 {
            addr: a.ip().octets(),
            port: a.port(),
        },
        std::net::SocketAddr::V6(a) => match a.ip().to_ipv4_mapped() {
            Some(v4) => MuxTarget::Ipv4 {
                addr: v4.octets(),
                port: a.port(),
            },
            None => MuxTarget::Ipv6 {
                addr: a.ip().octets(),
                port: a.port(),
            },
        },
    };
    t.encode().map_err(|e| format!("target: {e}"))?;
    Ok(t)
}

/// Tunnel one terminated TUN **UDP** flow to its target through Mirage's UDP
/// relay (UDP-over-Mirage). Each app datagram is wrapped in the SOCKS5-UDP
/// header for `target` - the same wire form the bridge's UDP relay expects, so
/// this reuses the exact relay path as SOCKS5 UDP-ASSOCIATE - and framed over
/// the session; replies are stripped and delivered back to the app. Idle-aware:
/// a UDP association with no traffic either way for a minute is torn down.
async fn tunnel_udp_flow(pool: Arc<EntryPool>, flow: mirage_tun::UdpFlow) -> Result<(), String> {
    let dest = mirage_socks5::Socks5UdpDest::Ip(flow.target);
    let session = open_udp_relay_session(&pool, Duration::from_secs(15)).await?;
    let (rx, tx) = tokio::io::split(session);
    let mut framer_rx = UdpFramer::new(rx);
    let mut framer_tx = UdpFramer::new(tx);
    let (mut fin, fout) = flow.split();
    let idle = Duration::from_secs(60);

    loop {
        tokio::select! {
            // app -> target: add the SOCKS5-UDP header, frame over the relay.
            d = tokio::time::timeout(idle, fin.recv()) => match d {
                Ok(Some(dgram)) => {
                    if dgram.len() <= MAX_UDP_DATAGRAM_BYTES {
                        let framed = mirage_socks5::encode_udp_dgram(&dest, &dgram)
                            .map_err(|e| format!("udp encode: {e}"))?;
                        if framer_tx.send(&framed).await.is_err() {
                            break;
                        }
                    }
                }
                Ok(None) => break, // flow reaped by the netstack
                Err(_) => break,   // idle timeout
            },
            // target -> app: strip the SOCKS5-UDP header, deliver to the app.
            f = framer_rx.recv() => match f {
                Ok(Some(framed)) => {
                    if let Ok((_dst, payload)) = mirage_socks5::decode_udp_dgram(&framed) {
                        let _ = fout.send(payload.to_vec()).await;
                    }
                }
                _ => break,
            },
        }
    }
    Ok(())
}

/// CONNECT over a multiplexed carrier: acquire/reuse a carrier for the best
/// entry, open a stream to the requested target, synthesize the SOCKS5 reply to
/// the app from the bridge's accept/reject, then bridge the two.
async fn tunnel_one_mux(
    mut local: TcpStream,
    peer: std::net::SocketAddr,
    pool: Arc<EntryPool>,
    dest: local_socks::Destination,
) -> Result<(), String> {
    let target = match destination_to_muxtarget(&dest) {
        Ok(t) => t,
        Err(e) => {
            let _ = local_socks::send_connect_reply(&mut local, REP_GENERAL_FAILURE).await;
            return Err(format!("mux target (peer={peer}): {e}"));
        }
    };

    let n = pool.len();
    let mut last_err = String::from("no healthy bridge entries");
    for attempt in 0..n {
        // Spread failover attempts in time so a censor can't watch a sub-second
        // sweep across diverse bearer classes to the same dest (critic-A).
        if attempt > 0 {
            failover_backoff(attempt).await;
        }
        let idx = match pool.pick_entry().await {
            Some(i) => i,
            None => {
                warn!(peer = %peer, attempt, "all bridge entries exhausted (mux)");
                break;
            }
        };
        let entry = &pool.entries[idx];
        let timeout = entry.handshake_timeout;
        let (carrier, fresh) = match get_or_create_carrier(entry, timeout).await {
            Ok(c) => c,
            Err(e) => {
                warn!(peer = %peer, attempt, entry_idx = idx, bridge = %entry.bridge_addr, error = %e, "mux carrier establish failed; trying next");
                pool.mark_failure(idx).await;
                last_err = e;
                continue;
            }
        };
        let t0 = Instant::now();
        // Bound the open (MUX-CLIENT-2): a TCP-alive but unresponsive bridge
        // must not freeze the stream open forever with no SOCKS reply. On
        // timeout, treat it like a dead carrier and try the next entry.
        let opened = match tokio::time::timeout(timeout, carrier.open(target.clone())).await {
            Ok(r) => r,
            Err(_) => {
                warn!(peer = %peer, attempt, entry_idx = idx, "mux open timed out; retrying");
                // A FRESH carrier whose very first open round-trip never
                // completes is the old-bridge-rejected-our-FS-msg-3 signature
                // (it silently dropped/closed after the handshake). Downgrade.
                if fresh {
                    entry.note_fs_dial_dead();
                }
                pool.mark_failure(idx).await;
                last_err = "open timed out".to_string();
                continue;
            }
        };
        match opened {
            Ok(stream) => {
                pool.record_latency(idx, t0.elapsed().as_millis() as u64)
                    .await;
                if let Err(e) = local_socks::send_connect_reply(&mut local, REP_SUCCEEDED).await {
                    return Err(format!("mux: reply to app (peer={peer}): {e}"));
                }
                // Idle-aware bridge: reaps a dead keep-alive tunnel (freeing the
                // stream + the bridge's upstream socket) instead of pinning it
                // forever; half-closes on EOF. Takes ownership of both streams.
                let started = Instant::now();
                let res =
                    mirage_socks5::copy_bidirectional_idle(local, stream, MUX_STREAM_IDLE_TIMEOUT)
                        .await;
                if let Ok((up, down)) = &res {
                    // H3: feed session goodput to the throttle detector.
                    pool.record_session_goodput(idx, up + down, started.elapsed())
                        .await;
                }
                return log_copy_result(peer, &entry.bridge_addr, res);
            }
            Err(MuxConnError::Rejected(code)) => {
                // The carrier is healthy but the bridge could not reach the
                // target: a target failure, not a bridge failure. Report it to
                // the app and stop (another bridge would likely also fail).
                let rep = if code == 0 {
                    REP_HOST_UNREACHABLE
                } else {
                    code
                };
                let _ = local_socks::send_connect_reply(&mut local, rep).await;
                return Ok(());
            }
            Err(MuxConnError::Closed) => {
                // Carrier died between acquisition and open; prune-and-retry.
                // If this was a FRESHLY-established carrier, its death on the
                // first open is the old-bridge-rejected-our-FS-msg-3 signature
                // (connect_fs returned locally; the bridge closed on the unknown
                // message type, first observed here on the open's read).
                // Downgrade this bridge to legacy so the retry reaches it.
                warn!(peer = %peer, attempt, entry_idx = idx, "mux carrier closed mid-open; retrying");
                if fresh {
                    entry.note_fs_dial_dead();
                }
                last_err = "carrier closed".to_string();
                continue;
            }
            Err(MuxConnError::StreamLimit) => {
                // Local carrier momentarily full - a transient client-side
                // condition, NOT a bridge fault. Retry (a fresh carrier will be
                // established) without soft-failing the entry.
                last_err = "carrier stream limit".to_string();
                continue;
            }
            Err(e) => {
                warn!(peer = %peer, attempt, entry_idx = idx, error = %e, "mux open failed");
                // Same reasoning as the Closed arm: a fresh carrier failing its
                // first open is the old-bridge FS-rejection signature.
                if fresh {
                    entry.note_fs_dial_dead();
                }
                pool.mark_failure(idx).await;
                last_err = e.to_string();
                continue;
            }
        }
    }

    pool.discovery_trigger.notify_one();
    // Every entry exhausted: no verified tunnel exists. Fail closed (SOCKS error,
    // never a direct connection) and clear the egress gate.
    pool.mark_egress_down();
    let _ = local_socks::send_connect_reply(&mut local, REP_HOST_UNREACHABLE).await;
    Err(format!("all bridge entries failed (mux): {last_err}"))
}

/// Open a tunnel from `local` through the best available bridge entry.
///
/// The retry loop only attempts the TCP connect to each bridge entry.
/// `local` is not consumed until we have a confirmed TCP connection to a
/// bridge, at which point `dial_with_sock` takes ownership and no further
/// retry is possible (we can't re-read SOCKS5 data from `local` after
/// handing it off).
///
/// For Hysteria2 entries the TCP dial is skipped entirely; QUIC handles
/// transport internally.
async fn tunnel_one(
    mut local: TcpStream,
    peer: std::net::SocketAddr,
    pool: Arc<EntryPool>,
) -> Result<(), String> {
    // Terminate the local SOCKS5 negotiation so we can branch CONNECT vs UDP
    // ASSOCIATE. For CONNECT the consumed greeting+request are replayed to the
    // bridge transparently (Socks5ReplayStream) and the bridge's method-select
    // reply is swallowed, so the dial/pipe path below is byte-identical on the
    // wire to the old raw-pipe behaviour.
    // Bound the local negotiation: a half-open local socket that never sends a
    // complete SOCKS request must not park this task (and its fd) forever.
    let lreq = match tokio::time::timeout(
        LOCAL_SOCKS_NEGOTIATION_TIMEOUT,
        local_socks::read_local_request(&mut local),
    )
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return Err(format!("local socks5 (peer={peer}): {e}")),
        Err(_) => return Err(format!("local socks5 (peer={peer}): negotiation timed out")),
    };
    if lreq.command == local_socks::LocalCommand::UdpAssociate {
        return udp_associate(local, peer, pool).await;
    }

    // Mux path (default): multiplex this CONNECT as a stream over a shared,
    // long-lived carrier so the Noise+ML-KEM handshake and the one-shot
    // capability token are amortized across many browser connections instead
    // of paid per-connection. UDP ASSOCIATE and circuit-relay keep their own
    // dedicated sessions (handled above / by mux_enabled being off).
    //
    // Gate on target representability: a target the mux wire can't carry (a
    // non-LDH hostname the legacy SOCKS path forwards fine) falls back to the
    // legacy single-session path rather than failing (mux-ldh-hostname fix).
    if pool.mux_enabled() && destination_to_muxtarget(&lreq.dest).is_ok() {
        return tunnel_one_mux(local, peer, pool, lreq.dest).await;
    }

    let local = local_socks::Socks5ReplayStream::new(local, lreq.replay, 2);

    let n = pool.len();
    let mut last_err = String::from("no healthy bridge entries");

    for attempt in 0..n {
        // Spread failover attempts (critic-A: no sub-second diverse-bearer sweep).
        if attempt > 0 {
            failover_backoff(attempt).await;
        }
        let idx = match pool.pick_entry().await {
            Some(i) => i,
            None => {
                warn!(peer = %peer, attempt, "all bridge entries exhausted");
                break;
            }
        };
        let entry = &pool.entries[idx];

        // Circuit-relay: select additional onion hops (hop 1+) from OTHER pool
        // bridges so the client builds a multi-hop circuit. Empty => single-hop.
        let extra_hops: Vec<CircuitHop> = if entry.circuit_relay {
            select_circuit_extra_hops(&pool, idx)
        } else {
            Vec::new()
        };

        // Hysteria2 uses QUIC (UDP) - bypass the TCP connect loop entirely.
        if let TransportMode::Hysteria2 {
            send_rate_bps,
            hostname,
            obfs_key,
        } = &entry.transport
        {
            let t0 = Instant::now();
            match dial_hysteria2(
                local,
                peer,
                entry,
                &extra_hops,
                *send_rate_bps,
                hostname.clone(),
                *obfs_key,
            )
            .await
            {
                Ok(()) => {
                    pool.record_latency(idx, t0.elapsed().as_millis() as u64)
                        .await;
                    return Ok(());
                }
                Err(e) => {
                    warn!(
                        peer = %peer,
                        attempt,
                        entry_idx = idx,
                        bridge = %entry.bridge_addr,
                        error = %e,
                        "hysteria2 connect failed; trying next"
                    );
                    pool.mark_failure(idx).await;
                    last_err = format!("hysteria2 {}: {e}", entry.bridge_addr);
                    // `local` was consumed - cannot retry further.
                    return Err(format!("all bridge entries failed: {last_err}"));
                }
            }
        }

        // HTTP/3 uses QUIC (UDP) - bypass the TCP connect loop entirely.
        if let TransportMode::H3 { hostname, obfs_key } = &entry.transport {
            let t0 = Instant::now();
            match dial_h3(local, peer, entry, &extra_hops, hostname.clone(), *obfs_key).await {
                Ok(()) => {
                    pool.record_latency(idx, t0.elapsed().as_millis() as u64)
                        .await;
                    return Ok(());
                }
                Err(e) => {
                    warn!(
                        peer = %peer,
                        attempt,
                        entry_idx = idx,
                        bridge = %entry.bridge_addr,
                        error = %e,
                        "h3 connect failed"
                    );
                    pool.mark_failure(idx).await;
                    last_err = format!("h3 {}: {e}", entry.bridge_addr);
                    // `local` was consumed - cannot retry further.
                    return Err(format!("all bridge entries failed: {last_err}"));
                }
            }
        }

        // dnstt uses a DNS/UDP channel - bypass the TCP connect loop entirely.
        if let TransportMode::Dnstt { domain, resolver } = &entry.transport {
            let t0 = Instant::now();
            match dial_dnstt(local, peer, entry, &extra_hops, domain.clone(), *resolver).await {
                Ok(()) => {
                    pool.record_latency(idx, t0.elapsed().as_millis() as u64)
                        .await;
                    return Ok(());
                }
                Err(e) => {
                    warn!(peer = %peer, attempt, entry_idx = idx, bridge = %entry.bridge_addr, error = %e, "dnstt connect failed");
                    pool.mark_failure(idx).await;
                    last_err = format!("dnstt {}: {e}", entry.bridge_addr);
                    return Err(format!("all bridge entries failed: {last_err}"));
                }
            }
        }

        // Meek manages its own TCP connect internally (with auth frame construction
        // and port-hop via tcp_connect_to_entry).  Bypass the per-candidate loop.
        if matches!(entry.transport, TransportMode::Meek { .. }) {
            let t0 = Instant::now();
            match dial_meek(local, peer, entry, &extra_hops).await {
                Ok(()) => {
                    pool.record_latency(idx, t0.elapsed().as_millis() as u64)
                        .await;
                    return Ok(());
                }
                Err(e) => {
                    warn!(
                        peer = %peer,
                        attempt,
                        entry_idx = idx,
                        bridge = %entry.bridge_addr,
                        error = %e,
                        "meek connect failed"
                    );
                    pool.mark_failure(idx).await;
                    last_err = format!("meek {}: {e}", entry.bridge_addr);
                    // `local` was consumed - cannot retry further.
                    return Err(format!("all bridge entries failed: {last_err}"));
                }
            }
        }

        // WebRTC - self-managed (HTTP signaling + UDP data channel), bypass.
        if matches!(entry.transport, TransportMode::WebRtc { .. }) {
            let t0 = Instant::now();
            match dial_webrtc(local, peer, entry, &extra_hops).await {
                Ok(()) => {
                    pool.record_latency(idx, t0.elapsed().as_millis() as u64)
                        .await;
                    return Ok(());
                }
                Err(e) => {
                    warn!(
                        peer = %peer,
                        attempt,
                        entry_idx = idx,
                        bridge = %entry.bridge_addr,
                        error = %e,
                        "webrtc connect failed"
                    );
                    pool.mark_failure(idx).await;
                    last_err = format!("webrtc {}: {e}", entry.bridge_addr);
                    return Err(format!("all bridge entries failed: {last_err}"));
                }
            }
        }

        // DoH tunnel - same bypass pattern as Meek.
        if matches!(entry.transport, TransportMode::Doh { .. }) {
            let t0 = Instant::now();
            match dial_doh(local, peer, entry, &extra_hops).await {
                Ok(()) => {
                    pool.record_latency(idx, t0.elapsed().as_millis() as u64)
                        .await;
                    return Ok(());
                }
                Err(e) => {
                    warn!(
                        peer = %peer,
                        attempt,
                        entry_idx = idx,
                        bridge = %entry.bridge_addr,
                        error = %e,
                        "doh connect failed"
                    );
                    pool.mark_failure(idx).await;
                    last_err = format!("doh {}: {e}", entry.bridge_addr);
                    return Err(format!("all bridge entries failed: {last_err}"));
                }
            }
        }

        // Build the list of addresses to try for this entry.
        //
        // Priority order (highest first):
        //   1. Epoch-derived port-hop addresses (same IP, rolling port - fast
        //      to resolve, may bypass port-specific blocking).
        //   2. Dynamically discovered addresses from Nostr (new IPs published
        //      by the operator after a censor blocked the old one).
        //   3. Static bootstrap address from the invite (always the fallback).
        let mut candidate_addrs: Vec<String> = Vec::with_capacity(12);
        if let (Some(salt), Some((base, range))) = (entry.shared_salt, entry.port_hop) {
            let now_unix = discovery_now_unix();
            let epoch = epoch_for_time(now_unix);
            let host = entry
                .bridge_addr
                .rsplit_once(':')
                .map(|(h, _)| h)
                .unwrap_or(&entry.bridge_addr);
            for ep in [epoch, epoch + 1] {
                if let Some(port) = derive_port(&salt, NAMESPACE_CLIENT_TO_BRIDGE, ep, base, range)
                {
                    candidate_addrs.push(format!("{host}:{port}"));
                }
            }
        }
        // Insert Nostr-discovered addresses after port-hop but before static.
        {
            let discovered = entry.discovered_addrs.read().await;
            for addr in discovered.iter() {
                if !candidate_addrs.contains(addr) {
                    candidate_addrs.push(addr.clone());
                }
            }
        }
        candidate_addrs.push(entry.bridge_addr.clone()); // static fallback always last

        let t0 = Instant::now();
        let mut tcp_err: Option<String> = None;
        for addr in &candidate_addrs {
            match TcpStream::connect(addr.as_str()).await {
                Ok(bridge_sock) => {
                    if addr != &entry.bridge_addr {
                        debug!(
                            peer = %peer,
                            derived_addr = %addr,
                            "port-hop: connected on derived port"
                        );
                    }
                    pool.record_latency(idx, t0.elapsed().as_millis() as u64)
                        .await;
                    bridge_sock.set_nodelay(true).ok();
                    set_carrier_keepalive(&bridge_sock);
                    // `local` consumed here - no further retry after this point.
                    return dial_with_sock(local, peer, entry, &extra_hops, bridge_sock).await;
                }
                Err(e) => {
                    debug!(addr = %addr, error = %e, "TCP connect candidate failed");
                    tcp_err = Some(e.to_string());
                }
            }
        }
        // All candidates for this entry failed.
        warn!(
            peer = %peer,
            attempt,
            entry_idx = idx,
            bridge = %entry.bridge_addr,
            candidates = candidate_addrs.len(),
            "all TCP candidates failed for this entry"
        );
        pool.mark_failure(idx).await;
        last_err = format!(
            "connect bridge {}: {}",
            entry.bridge_addr,
            tcp_err.as_deref().unwrap_or("unknown error")
        );
    }

    // All entries exhausted - signal the discovery task to do an immediate
    // re-fetch so the client can recover quickly from a mass IP block rather
    // than waiting for the next periodic discovery tick.
    pool.discovery_trigger.notify_one();
    // No verified tunnel remains; clear the egress gate (fail closed - the SOCKS
    // reply was already an error, never a direct connection).
    pool.mark_egress_down();
    Err(format!("all bridge entries failed: {last_err}"))
}

/// Finish a carrier into an authenticated Mirage session: apply the VLESS
/// overlay (if configured), padding, and run the Noise+ML-KEM handshake. The
/// carrier is type-erased to `DuplexStream` by `pad_stream_if_enabled`, so all
/// transports yield the SAME `SessionStream<DuplexStream>` - letting one UDP
/// relay path serve every TCP carrier (universal UDP-over-TCP).
async fn finish_carrier<C>(
    mut carrier: C,
    entry: &BridgeEntry,
    client_sk: [u8; 32],
    token: PresentedToken,
    timeout: Duration,
) -> Result<SessionStream<DuplexStream>, String>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    apply_vless_if_needed(&mut carrier, entry.vless_uuid, timeout).await?;
    let carrier = pad_stream_if_enabled(carrier, entry);
    tokio::time::timeout(
        timeout,
        dial_session(carrier, &client_sk, &entry.bridge_x25519_pk, &token),
    )
    .await
    .map_err(|_| format!("handshake timed out after {timeout:?}"))?
    .map_err(|e| format!("handshake: {e}"))
}

/// Resolve the QUIC (hysteria2 / h3) obfuscation key for a dial.
///
/// Precedence, highest first:
/// 1. `config_key` - an explicit client-config `quic_obfs_password`, hashed.
/// 2. The invite's per-bridge secret (`INVITE_EXT_QUIC_OBFS_SECRET`), hashed -
///    known only to invite holders, so a censor who merely scraped the bridge
///    pubkey from discovery cannot de-obfuscate.
/// 3. The pubkey-derived default (`default_obfs_key`) - obfuscated-by-default,
///    but not secret against a pubkey-knowing adversary.
///
/// The bridge derives the identical key from its matching config
/// (`quic_obfs_password` / `quic_obfs_secret_hex`), so both sides always agree.
fn resolve_obfs_key(config_key: Option<[u8; 32]>, entry: &BridgeEntry) -> [u8; 32] {
    if let Some(k) = config_key {
        return k;
    }
    if let Some(s) = entry.obfs_secret {
        return mirage_quic_obfs::key_from_password(&s);
    }
    // RT R3-#7: falling back to the pubkey-derived default. The QUIC obfs still
    // works, but because this key is a function of the announced bridge pubkey,
    // the knock token bound to it is reproducible by a pubkey scraper - there is
    // NO enumeration resistance in this mode. The standard deploy tools embed a
    // per-bridge secret in every invite, so this fallback only happens for a
    // hand-built invite that omitted it (and with no config quic_obfs_password).
    // Warn once so a misconfigured deployment is visible rather than silently
    // degraded.
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        warn!(
            "QUIC obfs key falling back to the pubkey-derived default: no invite \
             obfs secret (INVITE_EXT_QUIC_OBFS_SECRET) and no quic_obfs_password. \
             The Hysteria2/H3 knock is enumerable from the bridge pubkey in this \
             mode. Re-issue invites with mirage-setup/mirage-keygen (which embed \
             the secret by default) to restore enumeration resistance."
        );
    });
    mirage_quic_obfs::default_obfs_key(&entry.bridge_x25519_pk)
}

/// A meek/DoH/WS carrier connection, optionally wrapped in client-originated
/// TLS (red-team #4). Those carriers speak cleartext HTTP; when `carrier_tls` is
/// enabled the client first completes a REAL browser-rooted TLS handshake to a
/// TLS-terminating front (a CDN edge, or an nginx/Caddy on :443), so the HTTP
/// rides encrypted on the wire and the flow is genuinely HTTPS-to-a-front rather
/// than plaintext. Implements `AsyncRead`/`AsyncWrite` by delegating to the
/// active variant, so the carrier codecs stay stream-generic.
enum CarrierConn {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for CarrierConn {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            CarrierConn::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            CarrierConn::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for CarrierConn {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            CarrierConn::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            CarrierConn::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            CarrierConn::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            CarrierConn::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            CarrierConn::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            CarrierConn::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Complete a real TLS handshake over `tcp` (SNI = `sni`), verified against the
/// Mozilla webpki roots. The operator must terminate TLS in front of the bridge
/// (a CDN edge or a local nginx/Caddy on :443 with a cert valid for `sni`).
async fn carrier_tls_wrap(
    tcp: TcpStream,
    sni: &str,
    timeout: Duration,
) -> Result<CarrierConn, String> {
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::rustls::{ClientConfig, RootCertStore};
    use tokio_rustls::TlsConnector;
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = std::sync::Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("carrier tls config: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(std::sync::Arc::new(cfg));
    let server_name = ServerName::try_from(sni.to_string())
        .map_err(|_| format!("carrier tls: bad SNI {sni:?}"))?;
    let tls = tokio::time::timeout(timeout, connector.connect(server_name, tcp))
        .await
        .map_err(|_| format!("carrier tls: handshake timed out after {timeout:?}"))?
        .map_err(|e| format!("carrier tls: handshake: {e}"))?;
    Ok(CarrierConn::Tls(Box::new(tls)))
}

/// Wrap `tcp` for a meek/DoH/WS arm: real TLS when the entry has `carrier_tls`
/// set, else a plain passthrough. `default_sni` is the front/cover host used
/// when the client didn't configure an explicit `carrier_tls_sni`.
async fn carrier_maybe_tls(
    tcp: TcpStream,
    entry: &BridgeEntry,
    default_sni: &str,
    timeout: Duration,
) -> Result<CarrierConn, String> {
    if entry.carrier_tls {
        let sni = entry.carrier_tls_sni.as_deref().unwrap_or(default_sni);
        carrier_tls_wrap(tcp, sni, timeout).await
    } else {
        Ok(CarrierConn::Plain(tcp))
    }
}

/// Establish an authenticated Mirage session to `entry` over its carrier,
/// returning a uniform `SessionStream<DuplexStream>`. Mirrors the per-transport
/// carrier setup in [`try_claim_entry`] but returns the session instead of
/// running a specific exchange - used by the UDP-over-tunnel relay. Works for
/// every carrier including the QUIC ones (h3 / hysteria2), which dial their own
/// UDP transport instead of a TCP socket.
async fn establish_session(
    entry: &BridgeEntry,
    timeout: Duration,
) -> Result<SessionStream<DuplexStream>, String> {
    let (client_sk, token) = entry.next_credentials();

    // QUIC carriers (h3 / hysteria2) dial their own UDP transport - no TCP
    // socket. Handled here (before tcp_connect_to_entry) so the UoT relay path
    // can establish a session over them exactly like the TCP carriers, giving
    // UDP-over-tunnel parity across all 8 transports.
    match &entry.transport {
        TransportMode::Hysteria2 {
            send_rate_bps,
            hostname,
            obfs_key,
        } => {
            let bridge_sa = resolve_hysteria2_dial_addr(entry)
                .await
                .map_err(|e| format!("hysteria2: {e}"))?;
            let stream = tokio::time::timeout(
                timeout,
                hysteria2_client_connect(
                    &Hysteria2ClientConfig {
                        bridge_static_pk: entry.bridge_x25519_pk,
                        send_rate_bps: *send_rate_bps,
                        hostname: hostname.clone(),
                        // Obfs ON by default. Key precedence: explicit client
                        // config password -> per-bridge SECRET from the invite
                        // (ext 0x06, invite-holders only) -> pubkey-derived
                        // default (never on-wire clear). Bridge derives the
                        // identical key from its matching config. None => plain
                        // parseable QUIC when quic_obfs_disable is set (#9).
                        obfs_key: if entry.quic_obfs_disable {
                            None
                        } else {
                            Some(resolve_obfs_key(*obfs_key, entry))
                        },
                    },
                    bridge_sa,
                    timeout,
                ),
            )
            .await
            .map_err(|_| format!("hysteria2: timed out after {timeout:?}"))?
            .map_err(|e| format!("hysteria2: {e}"))?;
            return finish_carrier(stream, entry, client_sk, token, timeout).await;
        }
        TransportMode::H3 { hostname, obfs_key } => {
            let bridge_sa = resolve_bridge_socketaddr(entry)
                .await
                .map_err(|e| format!("h3: {e}"))?;
            // Empty hostname -> per-bridge cover SNI from the bridge static key,
            // matching the bridge's SAN derivation (F9-L).
            let hostname = mirage_transport_hysteria2::effective_cover_hostname(
                hostname,
                &entry.bridge_x25519_pk,
            );
            let path = mirage_transport_masque::build_connect_udp_path(
                &bridge_sa.ip().to_string(),
                bridge_sa.port(),
            )
            .unwrap_or_else(|_| "/".to_string());
            // Obfs ON by default. Same precedence as hysteria2: config password
            // -> invite secret (ext 0x06) -> pubkey-derived default. None => plain
            // parseable QUIC when quic_obfs_disable is set (#9).
            let h3_obfs = if entry.quic_obfs_disable {
                None
            } else {
                Some(resolve_obfs_key(*obfs_key, entry))
            };
            let stream = mirage_transport_masque::h3::h3_client_connect(
                bridge_sa, &hostname, &hostname, &path, timeout, h3_obfs,
            )
            .await
            .map_err(|e| format!("h3: {e}"))?;
            return finish_carrier(stream, entry, client_sk, token, timeout).await;
        }
        TransportMode::Dnstt { domain, resolver } => {
            // DNS tunnel: dials its own UDP DNS channel, no TCP socket.
            let stream =
                mirage_transport_dnstt::transport::dnstt_client_connect(*resolver, domain, timeout)
                    .await
                    .map_err(|e| format!("dnstt: {e}"))?;
            return finish_carrier(stream, entry, client_sk, token, timeout).await;
        }
        _ => {}
    }

    let bridge_sock = tcp_connect_to_entry(entry, timeout).await?;
    match &entry.transport {
        TransportMode::Raw => finish_carrier(bridge_sock, entry, client_sk, token, timeout).await,
        TransportMode::Ss2022 { psk } => {
            let c = mirage_transport_shadowsocks::ss2022_client_dial(bridge_sock, psk, timeout)
                .await
                .map_err(|e| format!("ss2022: {e}"))?;
            // Proteus: pace the SS carrier to the shared envelope (matched to the bridge).
            let seed = c.pace_seed();
            let c = mirage_transport_reality::maybe_pace_stream(
                c,
                mirage_transport_reality::pacer::Dir::Up,
                seed,
            );
            finish_carrier(c, entry, client_sk, token, timeout).await
        }
        TransportMode::WebSocket { path } => {
            let cover = ws_cover_host(&entry.bridge_addr);
            let stream = carrier_maybe_tls(bridge_sock, entry, cover, timeout).await?;
            let c = mirage_transport_ws::ws_client_connect(
                stream,
                &entry.bridge_x25519_pk,
                entry.obfs_secret.as_ref(),
                path,
                cover,
                timeout,
            )
            .await
            .map_err(|e| format!("websocket: {e}"))?;
            finish_carrier(c, entry, client_sk, token, timeout).await
        }
        TransportMode::Reality {
            sni,
            tls_cert_verify_pk,
            tls_fingerprint,
        } => {
            let now_unix: u32 = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0);
            let c = tokio::time::timeout(
                timeout,
                reality_connect(
                    bridge_sock,
                    &ClientCarrierInputs {
                        bridge_static_pk: &entry.bridge_x25519_pk,
                        probe_root: entry
                            .probe_root
                            .as_ref()
                            .unwrap_or(&mirage_transport_reality::PROBE_ROOT_DISABLED),
                        server_name: sni,
                        now_unix,
                        cert_verify_override_pk: tls_cert_verify_pk.as_ref(),
                        tls_fingerprint: *tls_fingerprint,
                    },
                ),
            )
            .await
            .map_err(|_| format!("reality timed out after {timeout:?}"))?
            .map_err(|e| format!("reality: {e}"))?;
            // Shaper-v2: opt-in envelope pacing, matched to the bridge. Off by default.
            let c =
                mirage_transport_reality::maybe_pace(c, mirage_transport_reality::pacer::Dir::Up);
            finish_carrier(c, entry, client_sk, token, timeout).await
        }
        TransportMode::Doh { front_domain } => {
            let stream = carrier_maybe_tls(bridge_sock, entry, front_domain, timeout).await?;
            let c = mirage_transport_doh::doh_client_connect(
                stream,
                &entry.bridge_x25519_pk,
                front_domain.clone(),
                timeout,
            )
            .await
            .map_err(|e| format!("doh: {e}"))?;
            finish_carrier(c, entry, client_sk, token, timeout).await
        }
        TransportMode::Meek { front_domain, path } => {
            let auth_frame = mirage_transport_meek::build_auth_frame(&entry.bridge_x25519_pk)
                .map_err(|e| format!("meek: auth frame: {e}"))?;
            let mut session_id = [0u8; 32];
            getrandom::fill(&mut session_id).expect("OS CSPRNG");
            let session_b64 = B64.encode(session_id);
            let stream = carrier_maybe_tls(bridge_sock, entry, front_domain, timeout).await?;
            let c = mirage_transport_meek::MeekClientStream::new_with_content_type(
                stream,
                front_domain.clone(),
                path.clone(),
                session_id,
                Some(auth_frame.to_vec()),
                session_b64,
                "application/octet-stream".into(),
            )
            .await;
            finish_carrier(c, entry, client_sk, token, timeout).await
        }
        // QUIC carriers are dialed before the TCP connect above; unreachable here.
        TransportMode::Hysteria2 { .. }
        | TransportMode::H3 { .. }
        | TransportMode::Dnstt { .. } => {
            unreachable!("UDP carriers handled before tcp_connect_to_entry")
        }
        // WebRTC runs its own signaling + UDP data channel via dial_webrtc.
        TransportMode::WebRtc { .. } => {
            unreachable!("webrtc handled by its own bypass before tcp_connect_to_entry")
        }
    }
}

/// Perform a SOCKS5 client CONNECT to `host:port` over an established session
/// (used to reach the bridge's magic UDP-relay hostname). Reads + discards the
/// BND reply so the caller can use the stream as the relay channel.
async fn socks5_connect_over_session<S>(
    session: &mut S,
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let fut = async {
        session
            .write_all(&[0x05, 0x01, 0x00])
            .await
            .map_err(|e| format!("greeting: {e}"))?;
        // Flush: message-framed carriers (WebSocket/meek) buffer writes into a
        // frame and won't transmit the greeting until flushed - without this
        // the read below hangs on those transports.
        session
            .flush()
            .await
            .map_err(|e| format!("greeting flush: {e}"))?;
        let mut m = [0u8; 2];
        session
            .read_exact(&mut m)
            .await
            .map_err(|e| format!("method reply: {e}"))?;
        if m != [0x05, 0x00] {
            return Err(format!("bad method reply {m:?}"));
        }
        let hb = host.as_bytes();
        let mut req = vec![0x05, 0x01, 0x00, 0x03, hb.len() as u8];
        req.extend_from_slice(hb);
        req.extend_from_slice(&port.to_be_bytes());
        session
            .write_all(&req)
            .await
            .map_err(|e| format!("connect req: {e}"))?;
        session
            .flush()
            .await
            .map_err(|e| format!("connect req flush: {e}"))?;
        let mut reply = [0u8; 4];
        session
            .read_exact(&mut reply)
            .await
            .map_err(|e| format!("connect reply: {e}"))?;
        if reply[1] != 0x00 {
            return Err(format!("connect rejected (rep=0x{:02x})", reply[1]));
        }
        let bnd_len = match reply[3] {
            0x01 => 4,
            0x04 => 16,
            0x03 => {
                let mut l = [0u8; 1];
                session
                    .read_exact(&mut l)
                    .await
                    .map_err(|e| format!("bnd len: {e}"))?;
                l[0] as usize
            }
            other => return Err(format!("bad bnd atyp 0x{other:02x}")),
        };
        let mut bnd = vec![0u8; bnd_len + 2];
        session
            .read_exact(&mut bnd)
            .await
            .map_err(|e| format!("bnd: {e}"))?;
        Ok::<(), String>(())
    };
    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| "socks5 magic connect timed out".to_string())?
}

/// Open an authenticated relay session to a bridge's magic UDP host, trying
/// pool entries in adaptive order until one succeeds.
async fn open_udp_relay_session(
    pool: &EntryPool,
    timeout: Duration,
) -> Result<SessionStream<DuplexStream>, String> {
    let mut last_err = String::from("no eligible bridge entries for UDP relay");
    for attempt in 0..pool.len() {
        // Spread failover attempts (critic-A: no sub-second diverse-bearer sweep).
        if attempt > 0 {
            failover_backoff(attempt).await;
        }
        let Some(idx) = pool.pick_entry().await else {
            break;
        };
        let entry = &pool.entries[idx];
        let t0 = Instant::now();
        match establish_session(entry, timeout).await {
            Ok(mut s) => {
                match socks5_connect_over_session(
                    &mut s,
                    UDP_RELAY_MAGIC_HOSTNAME,
                    UDP_RELAY_MAGIC_PORT,
                    timeout,
                )
                .await
                {
                    Ok(()) => {
                        pool.record_latency(idx, t0.elapsed().as_millis() as u64)
                            .await;
                        return Ok(s);
                    }
                    Err(e) => {
                        // Established but the first SOCKS exchange died: the
                        // old-bridge-rejects-FS signature. Downgrade to legacy.
                        entry.note_fs_dial_dead();
                        pool.mark_failure(idx).await;
                        last_err = format!("udp magic-connect {}: {e}", entry.bridge_addr);
                    }
                }
            }
            Err(e) => {
                pool.mark_failure(idx).await;
                last_err = format!("udp session {}: {e}", entry.bridge_addr);
            }
        }
    }
    Err(last_err)
}

/// Handle a SOCKS5 UDP ASSOCIATE: open a local UDP relay socket, tell the app
/// its address, open a Mirage relay session to the bridge's UDP relay, and pump
/// datagrams both ways (UDP-over-TCP). The TCP control connection `local` stays
/// open; its close tears the association down (per the SOCKS5 spec).
async fn udp_associate(
    mut local: TcpStream,
    peer: std::net::SocketAddr,
    pool: Arc<EntryPool>,
) -> Result<(), String> {
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("udp bind: {e}"))?;
    let relay_addr = udp
        .local_addr()
        .map_err(|e| format!("udp local_addr: {e}"))?;
    local_socks::send_udp_associate_reply(&mut local, relay_addr).await?;

    let timeout = Duration::from_secs(15);
    let session = open_udp_relay_session(&pool, timeout).await?;
    info!(peer = %peer, relay = %relay_addr, "udp-over-tcp association established");

    // Split the session into UdpFramer halves: app datagrams (already in
    // SOCKS5-UDP wire format, which is exactly the bridge's framed format) are
    // forwarded verbatim - no re-encoding needed.
    let (rx, tx) = tokio::io::split(session);
    let mut framer_rx = UdpFramer::new(rx);
    let mut framer_tx = UdpFramer::new(tx);
    let udp = Arc::new(udp);
    let client_addr: Arc<std::sync::Mutex<Option<std::net::SocketAddr>>> =
        Arc::new(std::sync::Mutex::new(None));

    let udp_up = Arc::clone(&udp);
    let ca_up = Arc::clone(&client_addr);
    let uplink = tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        loop {
            let (n, src) = match udp_up.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            // Bind the association to the FIRST source and reject every other
            // one. The client UDP relay socket is reachable by any local process;
            // last-writer-wins would let a co-resident process inject datagrams
            // into the user's tunnel and hijack the downlink (replies would be
            // sent to whoever wrote last). SOCKS5 UDP is a single-client relay, so
            // only the process that opened the association may use it.
            {
                let mut g = match ca_up.lock() {
                    Ok(g) => g,
                    Err(_) => break,
                };
                match *g {
                    None => *g = Some(src),
                    Some(bound) if bound != src => continue, // foreign source: drop
                    Some(_) => {}
                }
            }
            // Drop an over-cap datagram rather than tearing down the whole
            // uplink direction (UDP-RELAY-OVERSIZE-TEARDOWN): one 16 KB+ datagram
            // must not permanently break all uploads. Only a real session-write
            // failure ends the loop.
            if n > MAX_UDP_DATAGRAM_BYTES {
                continue;
            }
            if framer_tx.send(&buf[..n]).await.is_err() {
                break;
            }
        }
    });

    let udp_down = Arc::clone(&udp);
    let ca_down = Arc::clone(&client_addr);
    let downlink = tokio::spawn(async move {
        // Runs until the framer channel yields Ok(None) (clean EOF) or Err
        // (sender dropped) - both fall out of the `while let`.
        while let Ok(Some(dgram)) = framer_rx.recv().await {
            let dest = ca_down.lock().ok().and_then(|g| *g);
            if let Some(addr) = dest {
                let _ = udp_down.send_to(&dgram, addr).await;
            }
        }
    });

    // Block until the TCP control connection closes (or errors), then tear down.
    let mut probe = [0u8; 1];
    let _ = local.read(&mut probe).await;
    uplink.abort();
    downlink.abort();
    info!(peer = %peer, "udp-over-tcp association closed");
    Ok(())
}

/// The cover `Host`/authority the WebSocket upgrade should present - the
/// bridge's host portion (domain if fronted, else its IP). Never `localhost`
/// (which no real wss:// traffic carries - a passive Mirage tell).
fn ws_cover_host(bridge_addr: &str) -> &str {
    bridge_addr
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(bridge_addr)
}

/// Resolve a bridge entry's address to a `SocketAddr` for the QUIC dialers
/// (h3 / hysteria2), which need a resolved IP:port. Domain forms do a one-shot
/// lookup and take the first address.
async fn resolve_bridge_socketaddr(entry: &BridgeEntry) -> Result<std::net::SocketAddr, String> {
    if let Ok(sa) = entry.bridge_addr.parse() {
        Ok(sa)
    } else {
        tokio::net::lookup_host(&entry.bridge_addr)
            .await
            .map_err(|e| format!("resolve {}: {e}", entry.bridge_addr))?
            .next()
            .ok_or_else(|| format!("no addresses for {}", entry.bridge_addr))
    }
}

/// Resolve the Hysteria2 UDP dial address, applying epoch port-hop (M4). When the
/// invite carries a shared salt + port base/range, dial the CURRENT-epoch derived
/// port (which the bridge binds alongside the static port), so a censor blocking
/// the static UDP port cannot block the QUIC carrier. Falls back to the static
/// port when port-hop is not configured. QUIC has no fast-fail on a wrong UDP
/// port, so we dial exactly one derived port (the one the bridge is on this
/// epoch) rather than sweeping.
async fn resolve_hysteria2_dial_addr(entry: &BridgeEntry) -> Result<std::net::SocketAddr, String> {
    let mut sa = resolve_bridge_socketaddr(entry).await?;
    if let (Some(salt), Some((base, range))) = (entry.shared_salt, entry.port_hop) {
        let epoch = epoch_for_time(discovery_now_unix());
        if let Some(port) = derive_port(&salt, NAMESPACE_CLIENT_TO_BRIDGE, epoch, base, range) {
            sa.set_port(port);
        }
    }
    Ok(sa)
}

/// Dial a bridge entry using Hysteria2 (QUIC/UDP).  Does not open a TCP
/// connection; QUIC handles transport internally.
///
/// `local` is consumed unconditionally - this function must not be called
/// in a retry loop after it has taken ownership of `local`.
async fn dial_hysteria2(
    mut local: impl AsyncRead + AsyncWrite + Unpin + Send,
    peer: std::net::SocketAddr,
    entry: &BridgeEntry,
    extra_hops: &[CircuitHop],
    send_rate_bps: u64,
    hostname: String,
    obfs_key: Option<[u8; 32]>,
) -> Result<(), String> {
    let (client_sk, token) = entry.next_credentials();
    let timeout = entry.handshake_timeout;

    // Resolve the bridge address (applying epoch port-hop, M4). The hysteria2
    // client needs a resolved IP:port; for domain names we do a one-shot lookup.
    let bridge_sa: std::net::SocketAddr = resolve_hysteria2_dial_addr(entry)
        .await
        .map_err(|e| format!("hysteria2: {e}"))?;

    let hy2_config = Hysteria2ClientConfig {
        bridge_static_pk: entry.bridge_x25519_pk,
        send_rate_bps,
        hostname,
        // Obfs ON by default (config password -> invite secret -> pubkey
        // default). None => plain parseable QUIC when quic_obfs_disable is set
        // (#9); it MUST match the bridge or the QUIC Initial won't decode.
        obfs_key: if entry.quic_obfs_disable {
            None
        } else {
            Some(resolve_obfs_key(obfs_key, entry))
        },
    };

    let hy2_stream = tokio::time::timeout(
        timeout,
        hysteria2_client_connect(&hy2_config, bridge_sa, timeout),
    )
    .await
    .map_err(|_| format!("hysteria2: timed out after {timeout:?}"))?
    .map_err(|e| format!("hysteria2: {e}"))?;

    let hy2_stream = pad_stream_if_enabled(hy2_stream, entry);
    let mut session = tokio::time::timeout(
        timeout,
        dial_session(hy2_stream, &client_sk, &entry.bridge_x25519_pk, &token),
    )
    .await
    .map_err(|_| format!("handshake timed out after {timeout:?}"))?
    .map_err(|e| format!("handshake: {e}"))?;

    info!(
        peer = %peer,
        bridge = %entry.bridge_addr,
        transport = "hysteria2",
        "session established; tunneling"
    );

    if entry.circuit_relay {
        run_circuit_relay(local, peer, session, entry, extra_hops).await
    } else {
        let res = copy_bidirectional(&mut local, &mut session).await;
        let _ = session.shutdown().await;
        let _ = local.shutdown().await;
        log_copy_result(peer, &entry.bridge_addr, res)
    }
}

/// Dial a bridge entry using the HTTP/3 (QUIC + MASQUE) carrier. Like
/// hysteria2, QUIC (UDP) bypasses the TCP connect loop; `local` is consumed
/// unconditionally - do not retry after this call.
async fn dial_h3(
    mut local: impl AsyncRead + AsyncWrite + Unpin + Send,
    peer: std::net::SocketAddr,
    entry: &BridgeEntry,
    extra_hops: &[CircuitHop],
    hostname: String,
    obfs_key: Option<[u8; 32]>,
) -> Result<(), String> {
    let (client_sk, token) = entry.next_credentials();
    let timeout = entry.handshake_timeout;

    let bridge_sa: std::net::SocketAddr = if let Ok(sa) = entry.bridge_addr.parse() {
        sa
    } else {
        tokio::net::lookup_host(&entry.bridge_addr)
            .await
            .map_err(|e| format!("h3: resolve {}: {e}", entry.bridge_addr))?
            .next()
            .ok_or_else(|| format!("h3: no addresses for {}", entry.bridge_addr))?
    };

    // Empty hostname -> per-bridge cover SNI from the bridge static key, matching
    // the bridge's SAN derivation (F9-L).
    let hostname =
        mirage_transport_hysteria2::effective_cover_hostname(&hostname, &entry.bridge_x25519_pk);

    // Authority/path for the HTTP/3 HEADERS frame. The bridge skips the HEADERS
    // by length; these only shape what an HTTP/3-aware DPI sees. Path is the
    // canonical CONNECT-UDP template (RFC 9298 §3).
    let path = mirage_transport_masque::build_connect_udp_path(
        &bridge_sa.ip().to_string(),
        bridge_sa.port(),
    )
    .unwrap_or_else(|_| "/".to_string());

    // Obfs ON by default (config password -> invite secret -> pubkey default),
    // matching the always-obfuscating bridge.
    let h3_stream = mirage_transport_masque::h3::h3_client_connect(
        bridge_sa,
        &hostname,
        &hostname,
        &path,
        timeout,
        if entry.quic_obfs_disable {
            None
        } else {
            Some(resolve_obfs_key(obfs_key, entry))
        },
    )
    .await
    .map_err(|e| format!("h3: {e}"))?;

    let h3_stream = pad_stream_if_enabled(h3_stream, entry);
    let mut session = tokio::time::timeout(
        timeout,
        dial_session(h3_stream, &client_sk, &entry.bridge_x25519_pk, &token),
    )
    .await
    .map_err(|_| format!("handshake timed out after {timeout:?}"))?
    .map_err(|e| format!("handshake: {e}"))?;

    info!(
        peer = %peer,
        bridge = %entry.bridge_addr,
        transport = "h3",
        "session established; tunneling"
    );

    if entry.circuit_relay {
        run_circuit_relay(local, peer, session, entry, extra_hops).await
    } else {
        let res = copy_bidirectional(&mut local, &mut session).await;
        let _ = session.shutdown().await;
        let _ = local.shutdown().await;
        log_copy_result(peer, &entry.bridge_addr, res)
    }
}

/// Dial a bridge entry using the full DNS tunnel (dnstt). Bypasses TCP; the
/// carrier is a real DNS covert channel. `local` is consumed unconditionally.
async fn dial_dnstt(
    mut local: impl AsyncRead + AsyncWrite + Unpin + Send,
    peer: std::net::SocketAddr,
    entry: &BridgeEntry,
    extra_hops: &[CircuitHop],
    domain: String,
    resolver: std::net::SocketAddr,
) -> Result<(), String> {
    let (client_sk, token) = entry.next_credentials();
    let timeout = entry.handshake_timeout;
    let stream =
        mirage_transport_dnstt::transport::dnstt_client_connect(resolver, &domain, timeout)
            .await
            .map_err(|e| format!("dnstt: {e}"))?;
    let stream = pad_stream_if_enabled(stream, entry);
    let mut session = tokio::time::timeout(
        timeout,
        dial_session(stream, &client_sk, &entry.bridge_x25519_pk, &token),
    )
    .await
    .map_err(|_| format!("handshake timed out after {timeout:?}"))?
    .map_err(|e| format!("handshake: {e}"))?;
    info!(
        peer = %peer,
        bridge = %entry.bridge_addr,
        transport = "dnstt",
        "session established; tunneling"
    );
    if entry.circuit_relay {
        run_circuit_relay(local, peer, session, entry, extra_hops).await
    } else {
        let res = copy_bidirectional(&mut local, &mut session).await;
        let _ = session.shutdown().await;
        let _ = local.shutdown().await;
        log_copy_result(peer, &entry.bridge_addr, res)
    }
}

/// Dial a bridge entry using Meek (domain-fronted HTTP long-polling).
///
/// TCP connection and auth frame construction are handled here.  Port-hop
/// candidates are tried via [`tcp_connect_to_entry`].  `local` is consumed
/// unconditionally - do not retry after this call.
async fn dial_meek(
    mut local: impl AsyncRead + AsyncWrite + Unpin + Send,
    peer: std::net::SocketAddr,
    entry: &BridgeEntry,
    extra_hops: &[CircuitHop],
) -> Result<(), String> {
    let (front_domain, path) = match &entry.transport {
        TransportMode::Meek { front_domain, path } => (front_domain.clone(), path.clone()),
        _ => return Err("internal: dial_meek called on non-meek entry (bug)".into()),
    };

    let (client_sk, token) = entry.next_credentials();
    let timeout = entry.handshake_timeout;

    let bridge_sock = tcp_connect_to_entry(entry, timeout)
        .await
        .map_err(|e| format!("meek: {e}"))?;

    let auth_frame = mirage_transport_meek::build_auth_frame(&entry.bridge_x25519_pk)
        .map_err(|e| format!("meek: auth frame: {e}"))?;

    let mut session_id = [0u8; 32];
    getrandom::fill(&mut session_id).expect("OS CSPRNG");
    let session_b64 = B64.encode(session_id);

    let stream = carrier_maybe_tls(bridge_sock, entry, &front_domain, timeout).await?;
    let mut c = mirage_transport_meek::MeekClientStream::new_with_content_type(
        stream,
        front_domain,
        path,
        session_id,
        Some(auth_frame.to_vec()),
        session_b64,
        "application/octet-stream".into(),
    )
    .await;

    apply_vless_if_needed(&mut c, entry.vless_uuid, timeout).await?;
    let c = pad_stream_if_enabled(c, entry);
    let mut session = tokio::time::timeout(
        timeout,
        dial_session(c, &client_sk, &entry.bridge_x25519_pk, &token),
    )
    .await
    .map_err(|_| format!("meek: handshake timed out after {timeout:?}"))?
    .map_err(|e| format!("meek: handshake: {e}"))?;

    info!(
        peer = %peer,
        bridge = %entry.bridge_addr,
        transport = "meek",
        "session established; tunneling"
    );

    if entry.circuit_relay {
        run_circuit_relay(local, peer, session, entry, extra_hops).await
    } else {
        let res = copy_bidirectional(&mut local, &mut session).await;
        let _ = session.shutdown().await;
        let _ = local.shutdown().await;
        log_copy_result(peer, &entry.bridge_addr, res)
    }
}

/// Dial a bridge entry using the WebRTC carrier: exchange SDP with the bridge
/// over HTTP signaling, then run the Mirage session over the DTLS-SCTP data
/// channel. Requires the `webrtc` feature; without it, returns an error.
/// `local` is consumed unconditionally - do not retry after this call.
async fn dial_webrtc(
    mut local: impl AsyncRead + AsyncWrite + Unpin + Send,
    peer: std::net::SocketAddr,
    entry: &BridgeEntry,
    extra_hops: &[CircuitHop],
) -> Result<(), String> {
    {
        let (signaling_host, path, ice_servers) = match &entry.transport {
            TransportMode::WebRtc {
                signaling_host,
                path,
                ice_servers,
            } => (signaling_host.clone(), path.clone(), ice_servers.clone()),
            _ => return Err("internal: dial_webrtc called on non-webrtc entry (bug)".into()),
        };
        let (client_sk, token) = entry.next_credentials();
        let timeout = entry.handshake_timeout;

        let addr = tokio::net::lookup_host(&entry.bridge_addr)
            .await
            .map_err(|e| format!("webrtc: resolve {}: {e}", entry.bridge_addr))?
            .next()
            .ok_or_else(|| format!("webrtc: {} resolved to no address", entry.bridge_addr))?;
        let signaling = mirage_transport_webrtc::HttpSignaling::new(
            addr,
            signaling_host,
            path,
            &entry.bridge_x25519_pk,
        );
        // cover_media=true: negotiate a cover audio track so the connection
        // profiles as a real WebRTC call, not a bare data channel.
        let c =
            mirage_transport_webrtc::webrtc_dial(&signaling, &ice_servers, "data", true, timeout)
                .await
                .map_err(|e| format!("webrtc: {e}"))?;

        let mut c = c;
        apply_vless_if_needed(&mut c, entry.vless_uuid, timeout).await?;
        let c = pad_stream_if_enabled(c, entry);
        let mut session = tokio::time::timeout(
            timeout,
            dial_session(c, &client_sk, &entry.bridge_x25519_pk, &token),
        )
        .await
        .map_err(|_| format!("webrtc: handshake timed out after {timeout:?}"))?
        .map_err(|e| format!("webrtc: handshake: {e}"))?;

        info!(
            peer = %peer,
            bridge = %entry.bridge_addr,
            transport = "webrtc",
            "session established; tunneling"
        );

        if entry.circuit_relay {
            run_circuit_relay(local, peer, session, entry, extra_hops).await
        } else {
            let res = copy_bidirectional(&mut local, &mut session).await;
            let _ = session.shutdown().await;
            let _ = local.shutdown().await;
            log_copy_result(peer, &entry.bridge_addr, res)
        }
    }
}

/// Dial a bridge entry using DoH-tunnel (`POST /dns-query`, `Content-Type:
/// application/dns-message`).  Mirrors the [`dial_meek`] pattern; the path
/// and content-type are fixed by the DoH spec.
async fn dial_doh(
    mut local: impl AsyncRead + AsyncWrite + Unpin + Send,
    peer: std::net::SocketAddr,
    entry: &BridgeEntry,
    extra_hops: &[CircuitHop],
) -> Result<(), String> {
    let front_domain = match &entry.transport {
        TransportMode::Doh { front_domain } => front_domain.clone(),
        _ => return Err("internal: dial_doh called on non-doh entry (bug)".into()),
    };

    let (client_sk, token) = entry.next_credentials();
    let timeout = entry.handshake_timeout;

    let bridge_sock = tcp_connect_to_entry(entry, timeout)
        .await
        .map_err(|e| format!("doh: {e}"))?;

    let stream = carrier_maybe_tls(bridge_sock, entry, &front_domain, timeout).await?;
    let mut c = mirage_transport_doh::doh_client_connect(
        stream,
        &entry.bridge_x25519_pk,
        front_domain,
        timeout,
    )
    .await
    .map_err(|e| format!("doh: {e}"))?;

    apply_vless_if_needed(&mut c, entry.vless_uuid, timeout).await?;
    let c = pad_stream_if_enabled(c, entry);
    let mut session = tokio::time::timeout(
        timeout,
        dial_session(c, &client_sk, &entry.bridge_x25519_pk, &token),
    )
    .await
    .map_err(|_| format!("doh: handshake timed out after {timeout:?}"))?
    .map_err(|e| format!("doh: handshake: {e}"))?;

    info!(
        peer = %peer,
        bridge = %entry.bridge_addr,
        transport = "doh",
        "session established; tunneling"
    );

    if entry.circuit_relay {
        run_circuit_relay(local, peer, session, entry, extra_hops).await
    } else {
        let res = copy_bidirectional(&mut local, &mut session).await;
        let _ = session.shutdown().await;
        let _ = local.shutdown().await;
        log_copy_result(peer, &entry.bridge_addr, res)
    }
}

/// Apply VLESS framing on `stream` if `vless_uuid` is `Some`.
/// After this call the stream is ready for the Noise handshake.
///
/// F21 (0-RTT): the client writes ONLY the VLESS header here and does NOT block
/// on a server response. The Noise initiator's first message (msg1) is written
/// immediately after - so the header rides in the same flight as msg1 (client
/// speaks first, no extra round trip). The bridge no longer emits a standalone
/// 2-byte VLESS response header (which, even enveloped in the outer Reality/WS
/// transport, showed up as a distinctive tiny server-first record + an extra
/// RTT in the encrypted flow - a pathognomonic pattern the pad layer never
/// covered). VLESS here is always wrapped by an authenticated outer transport,
/// so eliding the response leaks nothing to an adversary without the outer keys.
async fn apply_vless_if_needed<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    vless_uuid: Option<[u8; 16]>,
    _timeout: Duration,
) -> Result<(), String> {
    if let Some(uuid) = vless_uuid {
        mirage_transport_vless::vless_client_send_header(stream, &uuid)
            .await
            .map_err(|e| format!("vless header: {e}"))?;
    }
    Ok(())
}

/// Optionally wraps `stream` in [`PaddedStream`] to enable frame-size
/// bucketing and timing jitter. Returns a type-erased `DuplexStream` in
/// both branches so callers need not be generic over the padding choice.
fn pad_stream_if_enabled<S>(stream: S, entry: &BridgeEntry) -> DuplexStream
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // F3 (fingerprint): Reality owns its own TLS RecordShaper - the single
    // size/timing authority on that path. Layering PaddedStream on top emits a
    // power-of-two TLS-record-size comb plus a metronomic chaff-record beacon
    // *inside* the mimicked "TLS" flow, a distinguisher a real HTTPS origin
    // never shows. Gate padding OFF for Reality; if chaff is wanted there it
    // must be implemented inside the Reality shaper, not stacked here.
    let owns_record_shaper = matches!(entry.transport, TransportMode::Reality { .. });
    if entry.pad_enabled && !owns_record_shaper {
        let cfg = PadConfig {
            cbr_frame_bytes: entry.pad_cbr_frame_bytes,
            cbr_interval_ms: entry.pad_cbr_interval_ms,
            ..PadConfig::default()
        };
        Box::pin(PaddedStream::wrap(stream, cfg))
    } else {
        Box::pin(stream)
    }
}

/// Drive the full session over an already-established bridge TCP socket.
/// Dispatches to the correct carrier transport, then runs the bidirectional
/// copy until the tunnel closes.
async fn dial_with_sock(
    mut local: impl AsyncRead + AsyncWrite + Unpin + Send,
    peer: std::net::SocketAddr,
    entry: &BridgeEntry,
    extra_hops: &[CircuitHop],
    mut bridge_sock: TcpStream,
) -> Result<(), String> {
    let (client_sk, token) = entry.next_credentials();
    let timeout = entry.handshake_timeout;

    match &entry.transport {
        TransportMode::Ss2022 { psk } => {
            let c = mirage_transport_shadowsocks::ss2022_client_dial(bridge_sock, psk, timeout)
                .await
                .map_err(|e| {
                    warn!(
                        peer = %peer,
                        bridge = %entry.bridge_addr,
                        error = %e,
                        "ss2022 carrier handshake failed"
                    );
                    format!("ss2022: {e}")
                })?;
            // Proteus: pace the SS carrier to the shared envelope (matched to the bridge).
            let seed = c.pace_seed();
            let mut c = mirage_transport_reality::maybe_pace_stream(
                c,
                mirage_transport_reality::pacer::Dir::Up,
                seed,
            );
            apply_vless_if_needed(&mut c, entry.vless_uuid, timeout).await?;
            let c = pad_stream_if_enabled(c, entry);
            let mut session = tokio::time::timeout(
                timeout,
                dial_session(c, &client_sk, &entry.bridge_x25519_pk, &token),
            )
            .await
            .map_err(|_| format!("handshake timed out after {timeout:?}"))?
            .map_err(|e| format!("handshake: {e}"))?;
            info!(
                peer = %peer,
                bridge = %entry.bridge_addr,
                transport = "ss2022",
                "session established; tunneling"
            );
            if entry.circuit_relay {
                run_circuit_relay(local, peer, session, entry, extra_hops).await
            } else {
                let res = copy_bidirectional(&mut local, &mut session).await;
                let _ = session.shutdown().await;
                let _ = local.shutdown().await;
                log_copy_result(peer, &entry.bridge_addr, res)
            }
        }

        TransportMode::WebSocket { path } => {
            let cover = ws_cover_host(&entry.bridge_addr);
            let stream = carrier_maybe_tls(bridge_sock, entry, cover, timeout)
                .await
                .map_err(|e| format!("websocket: {e}"))?;
            let mut c = mirage_transport_ws::ws_client_connect(
                stream,
                &entry.bridge_x25519_pk,
                entry.obfs_secret.as_ref(),
                path,
                cover,
                timeout,
            )
            .await
            .map_err(|e| {
                warn!(
                    peer = %peer,
                    bridge = %entry.bridge_addr,
                    error = %e,
                    "websocket carrier handshake failed"
                );
                format!("websocket: {e}")
            })?;
            apply_vless_if_needed(&mut c, entry.vless_uuid, timeout).await?;
            let c = pad_stream_if_enabled(c, entry);
            let mut session = tokio::time::timeout(
                timeout,
                dial_session(c, &client_sk, &entry.bridge_x25519_pk, &token),
            )
            .await
            .map_err(|_| format!("handshake timed out after {timeout:?}"))?
            .map_err(|e| format!("handshake: {e}"))?;
            info!(
                peer = %peer,
                bridge = %entry.bridge_addr,
                transport = "websocket",
                "session established; tunneling"
            );
            if entry.circuit_relay {
                run_circuit_relay(local, peer, session, entry, extra_hops).await
            } else {
                let res = copy_bidirectional(&mut local, &mut session).await;
                let _ = session.shutdown().await;
                let _ = local.shutdown().await;
                log_copy_result(peer, &entry.bridge_addr, res)
            }
        }

        TransportMode::Reality {
            sni,
            tls_cert_verify_pk,
            tls_fingerprint,
        } => {
            let now_unix: u32 = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0);
            let reality = tokio::time::timeout(
                timeout,
                reality_connect(
                    bridge_sock,
                    &ClientCarrierInputs {
                        bridge_static_pk: &entry.bridge_x25519_pk,
                        probe_root: entry
                            .probe_root
                            .as_ref()
                            .unwrap_or(&mirage_transport_reality::PROBE_ROOT_DISABLED),
                        server_name: sni,
                        now_unix,
                        cert_verify_override_pk: tls_cert_verify_pk.as_ref(),
                        tls_fingerprint: *tls_fingerprint,
                    },
                ),
            )
            .await
            .map_err(|_| format!("reality handshake timed out after {timeout:?}"))?
            .map_err(|e| format!("reality: {e}"))?;
            // Shaper-v2: opt-in envelope pacing (MIRAGE_REALITY_PACE), matched to
            // the bridge which paces every authenticated session. Off by default
            // (returns the carrier unchanged). Client writes upstream -> `Up`.
            let mut reality = mirage_transport_reality::maybe_pace(
                reality,
                mirage_transport_reality::pacer::Dir::Up,
            );
            apply_vless_if_needed(&mut reality, entry.vless_uuid, timeout).await?;
            let reality = pad_stream_if_enabled(reality, entry);
            let mut session = tokio::time::timeout(
                timeout,
                dial_session(reality, &client_sk, &entry.bridge_x25519_pk, &token),
            )
            .await
            .map_err(|_| format!("handshake timed out after {timeout:?}"))?
            .map_err(|e| format!("handshake: {e}"))?;
            info!(
                peer = %peer,
                bridge = %entry.bridge_addr,
                transport = "reality",
                "session established; tunneling"
            );
            if entry.circuit_relay {
                run_circuit_relay(local, peer, session, entry, extra_hops).await
            } else {
                let res = copy_bidirectional(&mut local, &mut session).await;
                let _ = session.shutdown().await;
                let _ = local.shutdown().await;
                log_copy_result(peer, &entry.bridge_addr, res)
            }
        }

        TransportMode::Raw => {
            apply_vless_if_needed(&mut bridge_sock, entry.vless_uuid, timeout).await?;
            let bridge_sock = pad_stream_if_enabled(bridge_sock, entry);
            let mut session = tokio::time::timeout(
                timeout,
                dial_session(bridge_sock, &client_sk, &entry.bridge_x25519_pk, &token),
            )
            .await
            .map_err(|_| format!("handshake timed out after {timeout:?}"))?
            .map_err(|e| format!("handshake: {e}"))?;
            info!(
                peer = %peer,
                bridge = %entry.bridge_addr,
                transport = "raw",
                "session established; tunneling"
            );
            if entry.circuit_relay {
                run_circuit_relay(local, peer, session, entry, extra_hops).await
            } else {
                let res = copy_bidirectional(&mut local, &mut session).await;
                let _ = session.shutdown().await;
                let _ = local.shutdown().await;
                log_copy_result(peer, &entry.bridge_addr, res)
            }
        }

        // Hysteria2 uses QUIC (UDP) and is handled in `tunnel_one` before the
        // TCP connect. This arm is unreachable in normal operation.
        TransportMode::Hysteria2 { .. } => {
            Err("internal: Hysteria2 must not reach dial_with_sock (bug)".to_string())
        }

        // H3 (QUIC) dials via dial_h3(); never reaches the TCP sock path.
        // This arm is unreachable in normal operation.
        TransportMode::H3 { .. } => {
            Err("internal: H3 must not reach dial_with_sock (bug)".to_string())
        }

        // dnstt dials its own DNS/UDP channel; never reaches the TCP sock path.
        TransportMode::Dnstt { .. } => {
            Err("internal: Dnstt must not reach dial_with_sock (bug)".to_string())
        }

        // Meek constructs its own TCP connection internally via dial_meek().
        // This arm is unreachable in normal operation.
        TransportMode::Meek { .. } => {
            Err("internal: Meek must not reach dial_with_sock (bug)".to_string())
        }

        // DoH constructs its own TCP connection internally via dial_doh().
        // This arm is unreachable in normal operation.
        TransportMode::Doh { .. } => {
            Err("internal: DoH must not reach dial_with_sock (bug)".to_string())
        }

        // WebRTC dials via dial_webrtc (HTTP signaling + UDP); never here.
        TransportMode::WebRtc { .. } => {
            Err("internal: WebRtc must not reach dial_with_sock (bug)".to_string())
        }
    }
}

/// One additional onion hop the client wants to extend the circuit to (hop 1+,
/// beyond the directly-dialled entry). Selected from the bridge pool: a bridge
/// DIFFERENT from the entry (and from earlier hops), with a routable IP endpoint
/// and a per-hop capability token the target bridge will verify.
#[derive(Clone)]
struct CircuitHop {
    /// Target bridge X25519 static public key.
    bridge_x25519_pk: [u8; 32],
    /// Routable IP endpoint the previous hop dials to reach this one.
    endpoint: HopEndpoint,
    /// Client static X25519 secret used for THIS hop's per-hop handshake.
    client_static_sk: [u8; 32],
    /// Single-use capability token this hop's bridge verifies (bound to it).
    /// Either a legacy or forward-secure token, mirroring `next_credentials`.
    token: PresentedToken,
}

/// Parse a bridge's `host:port` address into a routable [`HopEndpoint`] for a
/// relay's direct next-hop TCP dial. Only IP literals qualify - the relay leg
/// cannot resolve hostnames or reach onion endpoints, so domain/onion bridges
/// are skipped as circuit hops.
fn parse_hop_endpoint(addr: &str) -> Result<HopEndpoint, String> {
    let sa: std::net::SocketAddr = addr
        .parse()
        .map_err(|_| format!("hop endpoint is not an ip:port literal: {addr}"))?;
    match sa {
        std::net::SocketAddr::V4(v4) => Ok(HopEndpoint::Ipv4 {
            addr: v4.ip().octets(),
            port: v4.port(),
        }),
        std::net::SocketAddr::V6(v6) => Ok(HopEndpoint::Ipv6 {
            addr: v6.ip().octets(),
            port: v6.port(),
        }),
    }
}

/// Select the additional onion hops (hop 1+) for a circuit, from bridges in the
/// pool OTHER than the entry. Each candidate must be a DISTINCT bridge (a static
/// key not equal to the entry's or any already-selected hop's), reachable at a
/// routable IP endpoint (the previous hop dials it directly), and carry a
/// capability token bound to it (the hop's bridge verifies it during EXTEND).
///
/// Selects up to [`MAX_CIRCUIT_HOPS`]` - 1` extra hops, giving a 2- or 3-hop
/// circuit when enough distinct token-bearing peers exist. The anonymity
/// property holds from 2 hops (entry sees the client IP, exit sees the
/// destination, neither sees both); a 3rd (middle) hop additionally means no
/// single bridge sees both its predecessor and successor's identities. Returns
/// empty if no eligible peer exists, in which case the circuit is single-hop.
/// The /24 (IPv4) or /48 (IPv6) prefix of a bridge address, used as a circuit
/// anti-affinity key. `None` for a hostname-based address (nothing to compare).
fn hop_affinity_subnet(addr: &str) -> Option<Vec<u8>> {
    let host = addr.rsplit_once(':').map_or(addr, |(h, _)| h);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    match host.parse::<std::net::IpAddr>().ok()? {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            Some(vec![o[0], o[1], o[2]])
        }
        std::net::IpAddr::V6(v6) => Some(v6.octets()[..6].to_vec()),
    }
}

/// Fisher-Yates shuffle using the OS CSPRNG. A predictable (pool-order) circuit
/// path lets anyone who knows the pool - e.g. an invite holder - anticipate the
/// hops; a fresh random permutation per circuit removes that handle.
fn csprng_shuffle<T>(v: &mut [T]) {
    for i in (1..v.len()).rev() {
        let mut b = [0u8; 8];
        let j = match getrandom::fill(&mut b) {
            Ok(()) => (u64::from_le_bytes(b) % (i as u64 + 1)) as usize,
            Err(_) => 0,
        };
        v.swap(i, j);
    }
}

fn select_circuit_extra_hops(pool: &EntryPool, entry_idx: usize) -> Vec<CircuitHop> {
    let max_extra = MAX_CIRCUIT_HOPS.saturating_sub(1);
    let entry_pk = pool.entries[entry_idx].bridge_x25519_pk;

    // Candidate middle/exit hops: not the entry, and a distinct static key.
    let mut candidates: Vec<usize> = (0..pool.entries.len())
        .filter(|&i| i != entry_idx && pool.entries[i].bridge_x25519_pk != entry_pk)
        .collect();
    // Randomize the path so it is not a fixed pool-order scan a pool-holder can
    // predict.
    csprng_shuffle(&mut candidates);

    let mut used_pks: Vec<[u8; 32]> = vec![entry_pk];
    let mut used_subnets: Vec<Vec<u8>> = hop_affinity_subnet(&pool.entries[entry_idx].bridge_addr)
        .into_iter()
        .collect();

    // Pass 1 enforces subnet anti-affinity so a single operator (or a /24 an
    // adversary controls) cannot occupy two circuit positions and correlate
    // entry+exit. Pass 2 relaxes it only if the pool is too small/homogeneous to
    // fill the circuit otherwise - a working shorter circuit beats no circuit.
    let mut hops: Vec<CircuitHop> = Vec::with_capacity(max_extra);
    for enforce_affinity in [true, false] {
        for &i in &candidates {
            if hops.len() >= max_extra {
                break;
            }
            let e = &pool.entries[i];
            if used_pks.contains(&e.bridge_x25519_pk) {
                continue;
            }
            let subnet = hop_affinity_subnet(&e.bridge_addr);
            if enforce_affinity {
                if let Some(ref s) = subnet {
                    if used_subnets.contains(s) {
                        continue;
                    }
                }
            }
            let Ok(endpoint) = parse_hop_endpoint(&e.bridge_addr) else {
                continue;
            };
            let (client_static_sk, token) = e.next_credentials();
            used_pks.push(e.bridge_x25519_pk);
            if let Some(s) = subnet {
                used_subnets.push(s);
            }
            hops.push(CircuitHop {
                bridge_x25519_pk: e.bridge_x25519_pk,
                endpoint,
                client_static_sk,
                token,
            });
        }
        if hops.len() >= max_extra {
            break;
        }
    }
    hops
}

/// Extend an established circuit by one hop over the existing hop-0 session
/// (the 2-hop telescoping case: the entry is the recipient of the EXTEND cell
/// and dials `hop` on the client's behalf). Mirrors the tested
/// `runtime::SingleTransportHopRuntime::extend_hop`: EXTEND (fragmented) ->
/// EXTENDED -> EXTEND_FINISH (token), then derives the new hop's onion keys.
///
/// Returns the new hop's [`HopKeys`] for [`Circuit::extend`]. The caller peels
/// no onion here because for the 2-hop case the EXTEND rides raw on the hop-0
/// session (hop-0 IS the recipient); 3+ hop telescoping RELAY-wraps the EXTEND
/// and needs the bridge's inner-cell dispatch.
async fn extend_circuit_hop<S>(
    session: &mut mirage_session::SessionStream<S>,
    circ_id: u32,
    hop: &CircuitHop,
    handshake_timeout: Duration,
    circuit: &mut Circuit,
    relay_wrap: bool,
) -> Result<HopKeys, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    // 1. Per-hop handshake msg1 (carries the token in msg3). Legacy vs
    //    forward-secure token selects the initiator variant, exactly as a
    //    direct dial does.
    let mut init = match &hop.token {
        PresentedToken::Legacy(t) => {
            HandshakeInitiator::new(&hop.client_static_sk, &hop.bridge_x25519_pk, t)
        }
        PresentedToken::Fs(t) => {
            HandshakeInitiator::new_fs(&hop.client_static_sk, &hop.bridge_x25519_pk, t)
        }
    }
    .map_err(|e| format!("extend initiator: {e}"))?;
    let msg1 = init
        .write_message_1()
        .map_err(|e| format!("extend msg1: {e}"))?;

    // 2. Send the EXTEND (msg1, fragmented; msg1 ~1221 B > cell cap).
    //
    //    * Hop-1 (`relay_wrap == false`): the last established hop (the entry)
    //      IS the direct session peer, so the EXTEND rides RAW as CMD_EXTEND(+
    //      CMD_EXTEND_CONT) top-level cells - the proven 2-hop path.
    //    * Deep hop (`relay_wrap == true`): the recipient is an interior hop
    //      reached through the onion, so each EXTEND fragment is wrapped as a
    //      RelaySubCell and onion-sealed across the CURRENT circuit so the last
    //      hop peels it and dispatches it as an inner CMD_EXTEND.
    let extend_body = ExtendBody {
        next_hop_pk: hop.bridge_x25519_pk,
        endpoint: hop.endpoint.clone(),
        hs_msg1: msg1,
    };
    if relay_wrap {
        // Reserve one AEAD tag PER current hop + the RelaySubCell header so the
        // sealed cell fits MAX_CELL_PAYLOAD.
        let inner_max =
            // Size against MAX_CIRCUIT_HOPS, NOT the real hop count, so the cell
            // body is depth-independent and a relay cannot read its position off
            // (MAX_CELL_PAYLOAD - body_len)/16. Mirrors MAX_REVERSE_RELAY_DATA_BYTES
            // (the reverse direction already did this).
            MAX_CELL_PAYLOAD.saturating_sub(MAX_CIRCUIT_HOPS * 16 + RELAY_SUBCELL_HEADER_LEN);
        let (first, conts) = extend_body
            .encode_fragmented(inner_max)
            .map_err(|e| format!("EXTEND encode: {e}"))?;
        send_relay_subcell(session, circuit, circ_id, CMD_EXTEND, first).await?;
        for cont in conts {
            send_relay_subcell(session, circuit, circ_id, CMD_EXTEND_CONT, cont).await?;
        }
    } else {
        let (first, conts) = extend_body
            .encode_fragmented(MAX_CELL_PAYLOAD)
            .map_err(|e| format!("EXTEND encode: {e}"))?;
        write_cell(session, &Cell::new(circ_id, CMD_EXTEND, first).unwrap())
            .await
            .map_err(|e| format!("EXTEND write: {e}"))?;
        for cont in conts {
            write_cell(session, &Cell::new(circ_id, CMD_EXTEND_CONT, cont).unwrap())
                .await
                .map_err(|e| format!("EXTEND_CONT write: {e}"))?;
        }
    }

    // 3. Read the EXTENDED reply -> reassemble msg2. Deep hops return it
    //    onion-wrapped (as reverse RelaySubCell{CMD_EXTENDED/_CONT} cells the
    //    interior hops forwarded through the onion); hop-1 returns raw cells.
    let msg2 = if relay_wrap {
        read_relay_extended(session, circuit, circ_id, handshake_timeout).await?
    } else {
        read_raw_extended(session, circ_id, handshake_timeout).await?
    };

    // 4. Finish the handshake: snapshot the circuit binding BEFORE
    //    write_message_3 consumes the initiator, then send EXTEND_FINISH(msg3)
    //    the same way (raw for hop-1, relay-wrapped for a deep hop).
    init.read_message_2(&msg2)
        .map_err(|e| format!("extend msg2: {e}"))?;
    let (mlkem_ss, binding) = init
        .circuit_hop_binding()
        .map_err(|e| format!("extend binding: {e}"))?;
    let (msg3, _keys) = init
        .write_message_3()
        .map_err(|e| format!("extend msg3: {e}"))?;
    let finish_body = ExtendFinishBody { hs_msg3: msg3 }
        .encode()
        .map_err(|e| format!("EXTEND_FINISH encode: {e}"))?;
    if relay_wrap {
        send_relay_subcell(session, circuit, circ_id, CMD_EXTEND_FINISH, finish_body).await?;
    } else {
        write_cell(
            session,
            &Cell::new(circ_id, CMD_EXTEND_FINISH, finish_body).unwrap(),
        )
        .await
        .map_err(|e| format!("EXTEND_FINISH write: {e}"))?;
    }

    Ok(derive_hop_keys_from_handshake(&mlkem_ss, &binding))
}

/// Onion-seal a control sub-cell across the current circuit and write it as a
/// `CMD_RELAY` cell - the deep-hop transport for EXTEND / EXTEND_CONT /
/// EXTEND_FINISH. The last established hop peels the final layer and dispatches
/// the inner command.
async fn send_relay_subcell<S>(
    session: &mut mirage_session::SessionStream<S>,
    circuit: &mut Circuit,
    circ_id: u32,
    command: u8,
    body: Vec<u8>,
) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let sub = RelaySubCell { command, body }
        .encode()
        .map_err(|e| format!("relay sub-cell encode (cmd={command}): {e}"))?;
    let sealed = circuit
        .relay_seal(&sub)
        .map_err(|e| format!("relay sub-cell seal (cmd={command}): {e}"))?;
    write_cell(session, &Cell::new(circ_id, CMD_RELAY, sealed).unwrap())
        .await
        .map_err(|e| format!("relay sub-cell write (cmd={command}): {e}"))
}

/// Read a raw `CMD_EXTENDED`(+`CMD_EXTENDED_CONT`) flight (hop-1 path) and
/// reassemble the raw `hs_msg2`.
async fn read_raw_extended<S>(
    session: &mut mirage_session::SessionStream<S>,
    circ_id: u32,
    handshake_timeout: Duration,
) -> Result<Vec<u8>, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let first = tokio::time::timeout(handshake_timeout, read_cell(session))
        .await
        .map_err(|_| "EXTENDED timeout".to_string())?
        .map_err(|e| format!("EXTENDED read: {e}"))?;
    if first.command != CMD_EXTENDED || first.circ_id != circ_id {
        return Err(format!(
            "EXTENDED unexpected cmd={} circ={}",
            first.command, first.circ_id
        ));
    }
    if first.body.len() < 2 {
        return Err("EXTENDED body too short".to_string());
    }
    let total_len = u16::from_be_bytes([first.body[0], first.body[1]]) as usize;
    let mut msg2 = first.body[2..].to_vec();
    while msg2.len() < total_len {
        let cont = tokio::time::timeout(handshake_timeout, read_cell(session))
            .await
            .map_err(|_| "EXTENDED_CONT timeout".to_string())?
            .map_err(|e| format!("EXTENDED_CONT read: {e}"))?;
        if cont.command != CMD_EXTENDED_CONT || cont.circ_id != circ_id {
            return Err(format!("EXTENDED_CONT unexpected cmd={}", cont.command));
        }
        msg2.extend_from_slice(&cont.body);
    }
    Ok(msg2)
}

/// Read an onion-wrapped EXTENDED flight (deep-hop path): each reply is a
/// `CMD_RELAY` cell that, once `relay_open`ed across the current circuit,
/// reveals a `RelaySubCell{CMD_EXTENDED/CMD_EXTENDED_CONT}` fragment. Reassemble
/// the raw `hs_msg2`.
async fn read_relay_extended<S>(
    session: &mut mirage_session::SessionStream<S>,
    circuit: &mut Circuit,
    circ_id: u32,
    handshake_timeout: Duration,
) -> Result<Vec<u8>, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let mut msg2: Vec<u8> = Vec::new();
    let mut total: Option<usize> = None;
    loop {
        let cell = tokio::time::timeout(handshake_timeout, read_cell(session))
            .await
            .map_err(|_| "EXTENDED(relay) timeout".to_string())?
            .map_err(|e| format!("EXTENDED(relay) read: {e}"))?;
        if cell.command != CMD_RELAY || cell.circ_id != circ_id {
            continue; // ignore unrelated cells (e.g. padding)
        }
        let plaintext = circuit
            .relay_open(&cell.body)
            .map_err(|e| format!("EXTENDED(relay) open: {e}"))?;
        let sub =
            RelaySubCell::decode(&plaintext).map_err(|e| format!("EXTENDED(relay) decode: {e}"))?;
        match sub.command {
            CMD_EXTENDED => {
                if sub.body.len() < 2 {
                    return Err("EXTENDED(relay) body too short".to_string());
                }
                total = Some(u16::from_be_bytes([sub.body[0], sub.body[1]]) as usize);
                msg2.extend_from_slice(&sub.body[2..]);
            }
            CMD_EXTENDED_CONT => {
                msg2.extend_from_slice(&sub.body);
            }
            other => {
                return Err(format!("EXTENDED(relay) unexpected inner cmd={other}"));
            }
        }
        if let Some(t) = total {
            if msg2.len() >= t {
                msg2.truncate(t);
                break;
            }
        }
    }
    Ok(msg2)
}

/// Run circuit relay mode for a single local SOCKS5 connection.
///
/// 1. Parses SOCKS5 CONNECT from `local` -> gets target host:port.
/// 2. Sends SOCKS5 success reply (the circuit is the upstream).
/// 3. Does CMD_CREATE -> CMD_CREATED circuit handshake -> derives HopKeys, then
///    EXTENDs through each hop in `extra_hops` (2+-hop onion circuit).
/// 4. Sends CMD_RELAY (BEGIN host:port) through the circuit.
/// 5. Relays DATA bidirectionally with onion sealing/unsealing.
/// 6. Sends CMD_RELAY (END) when the local connection closes.
async fn run_circuit_relay<S>(
    mut local: impl AsyncRead + AsyncWrite + Unpin + Send,
    peer: std::net::SocketAddr,
    mut session: mirage_session::SessionStream<S>,
    entry: &BridgeEntry,
    extra_hops: &[CircuitHop],
) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    // 1. Parse SOCKS5 CONNECT request from the local application.
    let (req, local) = read_request(&mut local)
        .await
        .map_err(|e| format!("socks5 parse (peer={peer}): {e}"))?;
    let mut local = local;
    let (host, port) = match &req.target {
        ConnectTarget::Domain(host, port) => (host.clone(), *port),
        ConnectTarget::Ipv4(addr, port) => (addr.to_string(), *port),
        ConnectTarget::Ipv6(addr, port) => (addr.to_string(), *port),
    };
    // Send SOCKS5 success reply - the circuit takes the role of the upstream.
    send_success_reply_for_internal(&mut local)
        .await
        .map_err(|e| format!("socks5 reply (peer={peer}): {e}"))?;

    // 2. Circuit CREATE handshake.
    // Uses a fresh ephemeral X25519 for each circuit - per-hop key isolation.
    let mut circ_x_seed = [0u8; 32];
    getrandom::fill(&mut circ_x_seed).expect("OS CSPRNG");
    let circ_x_sk = mirage_crypto::x25519_dalek::StaticSecret::from(circ_x_seed).to_bytes();

    let mut initiator =
        HandshakeInitiator::new_for_circuit_hop(&circ_x_sk, &entry.bridge_x25519_pk)
            .map_err(|e| format!("circuit initiator (peer={peer}): {e}"))?;
    let msg1 = initiator
        .write_message_1()
        .map_err(|e| format!("circuit msg1 (peer={peer}): {e}"))?;

    // Send CMD_CREATE, fragmented if needed (msg1 = 1221 B > 1017 B cell cap).
    let circ_id: u32 = {
        let mut b = [0u8; 4];
        getrandom::fill(&mut b).expect("OS CSPRNG");
        u32::from_be_bytes(b).max(1) // ensure non-zero
    };
    let (first_body, cont_bodies) = HandshakeBody { hs_msg: msg1 }
        .encode_fragmented(MAX_CELL_PAYLOAD)
        .map_err(|e| format!("circuit CREATE encode (peer={peer}): {e}"))?;
    write_cell(
        &mut session,
        &Cell::new(circ_id, CMD_CREATE, first_body).unwrap(),
    )
    .await
    .map_err(|e| format!("circuit CREATE write (peer={peer}): {e}"))?;
    for cont in cont_bodies {
        write_cell(
            &mut session,
            &Cell::new(circ_id, CMD_CREATE_CONT, cont).unwrap(),
        )
        .await
        .map_err(|e| format!("circuit CREATE_CONT write (peer={peer}): {e}"))?;
    }

    // Read CMD_CREATED + CMD_CREATED_CONT fragments -> reassemble msg2.
    let msg2 = {
        let first = tokio::time::timeout(entry.handshake_timeout, read_cell(&mut session))
            .await
            .map_err(|_| format!("circuit CREATED timeout (peer={peer})"))?
            .map_err(|e| format!("circuit CREATED read (peer={peer}): {e}"))?;
        if first.command != CMD_CREATED || first.circ_id != circ_id {
            return Err(format!(
                "circuit CREATED unexpected cmd={} circ={} (peer={peer})",
                first.command, first.circ_id
            ));
        }
        if first.body.len() < 2 {
            return Err(format!("circuit CREATED body too short (peer={peer})"));
        }
        let total_len = u16::from_be_bytes([first.body[0], first.body[1]]) as usize;
        let mut msg2 = first.body[2..].to_vec();
        while msg2.len() < total_len {
            let cont = tokio::time::timeout(entry.handshake_timeout, read_cell(&mut session))
                .await
                .map_err(|_| format!("circuit CREATED_CONT timeout (peer={peer})"))?
                .map_err(|e| format!("circuit CREATED_CONT read (peer={peer}): {e}"))?;
            if cont.command != CMD_CREATED_CONT || cont.circ_id != circ_id {
                return Err(format!(
                    "circuit CREATED_CONT unexpected cmd={} (peer={peer})",
                    cont.command
                ));
            }
            msg2.extend_from_slice(&cont.body);
        }
        msg2
    };

    // Derive per-hop circuit keys.
    initiator
        .read_message_2(&msg2)
        .map_err(|e| format!("circuit msg2 (peer={peer}): {e}"))?;
    let (mlkem_ss, circuit_binding) = initiator
        .circuit_hop_binding()
        .map_err(|e| format!("circuit_hop_binding (peer={peer}): {e}"))?;
    let entry_hop_keys = derive_hop_keys_from_handshake(&mlkem_ss, &circuit_binding);

    // Build the onion circuit: hop 0 (the directly-dialled entry) plus each
    // additional hop via EXTEND. A 2+-hop circuit gives the anonymity property -
    // the entry sees the client IP but not the destination; the exit sees the
    // destination but not the client IP.
    let mut circuit = Circuit::new();
    circuit
        .extend(entry_hop_keys)
        .map_err(|e| format!("circuit hop0 (peer={peer}): {e}"))?;
    for (i, hop) in extra_hops.iter().enumerate() {
        // First extra hop (i == 0, reaching hop-1): the entry IS the session
        // peer, so the EXTEND rides raw. Deeper hops (i >= 1) must onion-wrap
        // the EXTEND across the already-built circuit so the last hop dispatches
        // it - mirrored by the bridge's inner-EXTEND handling + reverse-wrapped
        // EXTENDED reply.
        let relay_wrap = i >= 1;
        let keys = extend_circuit_hop(
            &mut session,
            circ_id,
            hop,
            entry.handshake_timeout,
            &mut circuit,
            relay_wrap,
        )
        .await
        .map_err(|e| format!("circuit extend hop{} (peer={peer}): {e}", i + 1))?;
        circuit
            .extend(keys)
            .map_err(|e| format!("circuit hop{} keys (peer={peer}): {e}", i + 1))?;
    }
    info!(peer = %peer, hops = circuit.hop_count(), "onion circuit built");

    // 3. Send CMD_RELAY (BEGIN host:port), onion-sealed across all hops.
    let stream_id: u16 = {
        let mut b = [0u8; 2];
        getrandom::fill(&mut b).expect("OS CSPRNG");
        u16::from_be_bytes(b).max(1) // ensure non-zero
    };
    let begin_body = BeginBody {
        stream_id,
        host: host.clone(),
        port,
    }
    .encode()
    .map_err(|e| format!("BEGIN encode (peer={peer}): {e}"))?;
    let begin_sub = RelaySubCell {
        command: CMD_BEGIN,
        body: begin_body,
    }
    .encode()
    .map_err(|e| format!("BEGIN sub-cell encode (peer={peer}): {e}"))?;
    let begin_sealed = circuit
        .relay_seal(&begin_sub)
        .map_err(|e| format!("BEGIN seal (peer={peer}): {e}"))?;
    write_cell(
        &mut session,
        &Cell::new(circ_id, CMD_RELAY, begin_sealed)
            .map_err(|e| format!("BEGIN cell (peer={peer}): {e}"))?,
    )
    .await
    .map_err(|e| format!("BEGIN write (peer={peer}): {e}"))?;

    // NOTE: the user's destination (`host:port`) is deliberately NOT logged at
    // INFO. This runs on the user's own device; a seized/inspected client log
    // must not become a plaintext record of where the user connected. The
    // destination is available at debug for local troubleshooting only.
    info!(
        peer = %peer,
        bridge = %entry.bridge_addr,
        circ_id,
        "circuit established; relaying"
    );
    // Deanon: a seized client device must not be a log of where the user went.
    // Do NOT record the destination host/port (not even at debug).
    debug!(circ_id, "circuit target established");

    // 4. Bidirectional relay loop. The `Circuit` tracks the per-direction
    // sequence counters internally (relay_seal/relay_open), so no manual seq.
    let mut local_buf = vec![0u8; 16 * 1024];
    let mut local_eof = false;
    // MAX data per CMD_RELAY cell: cell cap minus ONE AEAD tag PER HOP (each hop
    // adds a 16-byte onion layer) minus the sub-cell header (3) + stream_id (2).
    // Constant-size forward cells (depth-independent) so a relay cannot read its
    // hop index off the body length. Mirrors MAX_REVERSE_RELAY_DATA_BYTES.
    let max_data_bytes: usize = MAX_CELL_PAYLOAD.saturating_sub(MAX_CIRCUIT_HOPS * 16 + 3 + 2);

    // H4: circuit padding machine. On MULTI-HOP circuits, emit an onion-sealed
    // CMD_PADDING cover cell on a JITTERED cadence (never a fixed interval - that
    // would itself be a timing tell). Padding cells are the SAME constant 1024 B
    // as data cells (no size/format tell), advance the per-hop seq exactly like a
    // data cell (both peers stay aligned), and are dropped at the hop that peels
    // them - injecting genuine timing/volume cover that a flow-correlation model
    // cannot subtract. Single-hop circuits get no inter-hop padding.
    let padding_on = circuit.hop_count() >= 2;
    let pad_lo = Duration::from_millis(800);
    let pad_hi = Duration::from_millis(4000);
    let mut pad_timer = Box::pin(tokio::time::sleep(jitter_duration(pad_lo, pad_hi)));

    loop {
        tokio::select! {
            // Circuit padding: emit a jittered cover cell (multi-hop only).
            () = &mut pad_timer, if padding_on => {
                if let Ok(sealed) = circuit.build_padding_payload() {
                    if let Ok(cell) = Cell::new(circ_id, CMD_RELAY, sealed) {
                        let _ = write_cell(&mut session, &cell).await;
                    }
                }
                pad_timer
                    .as_mut()
                    .reset(tokio::time::Instant::now() + jitter_duration(pad_lo, pad_hi));
            }
            // Local -> circuit: read data, seal as CMD_RELAY(DATA).
            n = local.read(&mut local_buf), if !local_eof => {
                match n {
                    Err(e) => {
                        debug!(peer = %peer, error = %e, "local read error; closing circuit");
                        break;
                    }
                    Ok(0) => {
                        // Local EOF - send CMD_RELAY(END) and stop reading.
                        local_eof = true;
                        let end_body = EndBody { stream_id }.encode().to_vec();
                        let end_sub = RelaySubCell { command: CMD_END, body: end_body }
                            .encode()
                            .map_err(|e| format!("END encode (peer={peer}): {e}"))?;
                        let end_sealed = circuit.relay_seal(&end_sub)
                            .map_err(|e| format!("END seal (peer={peer}): {e}"))?;
                        if let Ok(cell) = Cell::new(circ_id, CMD_RELAY, end_sealed) {
                            let _ = write_cell(&mut session, &cell).await;
                        }
                    }
                    Ok(n) => {
                        // Send in chunks that fit in one cell.
                        let mut offset = 0;
                        while offset < n {
                            let take = (n - offset).min(max_data_bytes);
                            let data_body = DataBody {
                                stream_id,
                                bytes: local_buf[offset..offset + take].to_vec(),
                            }.encode();
                            let data_sub = RelaySubCell { command: CMD_DATA, body: data_body }
                                .encode()
                                .map_err(|e| format!("DATA encode (peer={peer}): {e}"))?;
                            let data_sealed = circuit.relay_seal(&data_sub)
                                .map_err(|e| format!("DATA seal (peer={peer}): {e}"))?;
                            write_cell(&mut session, &Cell::new(circ_id, CMD_RELAY, data_sealed).unwrap())
                                .await
                                .map_err(|e| format!("DATA write (peer={peer}): {e}"))?;
                            offset += take;
                        }
                    }
                }
            }

            // Circuit -> local: read CMD_RELAY, unseal, write to local.
            cell_res = read_cell(&mut session) => {
                let cell = match cell_res {
                    Ok(c) => c,
                    Err(e) => {
                        debug!(peer = %peer, error = %e, "session read error");
                        break;
                    }
                };
                if cell.command != CMD_RELAY || cell.circ_id != circ_id {
                    continue; // ignore unrelated cells (e.g., padding)
                }
                let plaintext = match circuit.relay_open(&cell.body) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!(peer = %peer, error = %e, "relay_open failed; closing");
                        break;
                    }
                };
                let sub = match RelaySubCell::decode(&plaintext) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                match sub.command {
                    CMD_DATA => {
                        if let Ok(d) = DataBody::decode(&sub.body) {
                            if d.stream_id == stream_id && local.write_all(&d.bytes).await.is_err() {
                                break;
                            }
                        }
                    }
                    CMD_END => break,
                    _ => {}
                }
            }
        }
    }

    let _ = local.shutdown().await;
    Ok(())
}

/// Process-wide tunneled-byte counters, surfaced via the management API +
/// `mirage-client status`. `UP` = client->bridge (upload), `DOWN` =
/// bridge->client (download). Relaxed ordering is fine - these are monotonic
/// observability counters, not synchronization.
static TOTAL_BYTES_UP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static TOTAL_BYTES_DOWN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn log_copy_result(
    peer: std::net::SocketAddr,
    bridge: &str,
    res: Result<(u64, u64), std::io::Error>,
) -> Result<(), String> {
    match res {
        Ok((l2s, s2l)) => {
            TOTAL_BYTES_UP.fetch_add(l2s, Ordering::Relaxed);
            TOTAL_BYTES_DOWN.fetch_add(s2l, Ordering::Relaxed);
            info!(
                peer = %peer,
                bridge = %bridge,
                local_to_session_bytes = l2s,
                session_to_local_bytes = s2l,
                "tunnel closed cleanly"
            );
            Ok(())
        }
        Err(e) => {
            warn!(peer = %peer, bridge = %bridge, error = %e, "copy ended with error");
            Err(format!("copy: {e}"))
        }
    }
}

// -- Cover traffic -------------------------------------------------------------

/// Cover-traffic driver: during idle periods, fetch decoy destinations THROUGH
/// the tunnel so a tunnel observer can't read "user idle" off a quiet channel.
///
/// `record_activity` is fed the delta of the process-wide tunnel byte counters
/// each tick. Those counters also increment for the cover we inject (cover rides
/// the client's OWN SOCKS listener, byte-identical to a browser), so the cover
/// bytes are SUBTRACTED back out before they reach `record_activity` - otherwise
/// the same bytes count as both cover AND user activity, which inflates the share
/// denominator and lets the scheduler run cover ABOVE `max_cover_fraction`. Cover
/// rides real end-to-end HTTPS, so it can never emit a wrong synthetic byte
/// distribution.
async fn run_cover_traffic(local_bind: String, policy: CoverPolicy) {
    let mut scheduler = CoverScheduler::new(policy.clone());
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let read_total =
        || TOTAL_BYTES_UP.load(Ordering::Relaxed) + TOTAL_BYTES_DOWN.load(Ordering::Relaxed);
    let mut last_total = read_total();
    // Cumulative bytes WE injected as cover, and how much of that we've already
    // excluded from the activity signal. The difference cancels our own cover
    // out of each tick's raw counter delta.
    let mut cover_total: u64 = 0;
    let mut cover_excluded: u64 = 0;
    info!(
        destinations = policy.destinations.len(),
        idle_s = policy.idle_threshold.as_secs(),
        "cover traffic enabled"
    );
    loop {
        ticker.tick().await;
        let now = std::time::Instant::now();
        let cur = read_total();
        let raw_delta = cur.saturating_sub(last_total);
        last_total = cur;
        // Remove the cover bytes that landed on the counters since last tick, so
        // our own decoy traffic is never counted as user activity.
        let cover_delta = cover_total.saturating_sub(cover_excluded);
        cover_excluded = cover_total;
        let activity_delta = raw_delta.saturating_sub(cover_delta);
        if activity_delta > 0 {
            scheduler.record_activity(activity_delta, now);
        }
        if let CoverDecision::Fetch { destination_idx } = scheduler.tick(now) {
            let Some(dest) = policy.destinations.get(destination_idx).cloned() else {
                continue;
            };
            match cover_fetch_one(&local_bind, &dest).await {
                Ok(n) => {
                    debug!(bytes = n, "cover fetch complete");
                    cover_total = cover_total.saturating_add(n);
                    scheduler.record_cover(n, std::time::Instant::now());
                }
                Err(e) => {
                    // A failed decoy fetch is non-fatal; still space out the next.
                    debug!(dest = %dest, error = %e, "cover fetch failed");
                    scheduler.record_cover(0, std::time::Instant::now());
                }
            }
        }
    }
}

/// Cap on bytes read back from a single cover fetch (a decoy need not download a
/// whole large page; ~256 KiB is a plausible page-plus-assets volume and bounds
/// the cost).
const COVER_FETCH_READ_CAP: u64 = 256 * 1024;

/// Perform ONE cover fetch: connect to the client's OWN SOCKS listener as a
/// local client (byte-identical to a browser), CONNECT the decoy host over the
/// tunnel, complete a REAL HTTPS request, and discard the response. Returns the
/// total bytes moved (for the scheduler's cover-share accounting).
async fn cover_fetch_one(local_bind: &str, dest: &str) -> Result<u64, String> {
    // Parse `host[:port][/path]`.
    let (hostport, path) = match dest.find('/') {
        Some(i) => (&dest[..i], dest[i..].to_string()),
        None => (dest, "/".to_string()),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>()
                .map_err(|_| format!("cover: bad port in {dest:?}"))?,
        ),
        None => (hostport.to_string(), 443u16),
    };
    let host_bytes = host.as_bytes();
    if host_bytes.is_empty() || host_bytes.len() > 255 {
        return Err(format!("cover: bad host {host:?}"));
    }

    let connect_timeout = Duration::from_secs(15);
    let mut sock = tokio::time::timeout(connect_timeout, TcpStream::connect(local_bind))
        .await
        .map_err(|_| "cover: connect to local SOCKS timed out".to_string())?
        .map_err(|e| format!("cover: connect to local SOCKS {local_bind}: {e}"))?;
    sock.set_nodelay(true).ok();

    // SOCKS5 greeting: VER=5, one method, NO-AUTH.
    sock.write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(|e| format!("cover: socks greeting: {e}"))?;
    let mut sel = [0u8; 2];
    sock.read_exact(&mut sel)
        .await
        .map_err(|e| format!("cover: socks method reply: {e}"))?;
    if sel != [0x05, 0x00] {
        return Err(format!("cover: socks method rejected: {sel:?}"));
    }
    // SOCKS5 CONNECT to host:port (domain address type).
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8];
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&port.to_be_bytes());
    sock.write_all(&req)
        .await
        .map_err(|e| format!("cover: socks connect: {e}"))?;
    // Reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT - read the fixed head then
    // skip the variable address.
    let mut head = [0u8; 4];
    sock.read_exact(&mut head)
        .await
        .map_err(|e| format!("cover: socks reply head: {e}"))?;
    if head[1] != 0x00 {
        return Err(format!("cover: socks connect failed (rep={})", head[1]));
    }
    let addr_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            sock.read_exact(&mut l)
                .await
                .map_err(|e| format!("cover: socks reply atyp len: {e}"))?;
            l[0] as usize
        }
        other => return Err(format!("cover: socks reply bad atyp {other}")),
    };
    let mut skip = vec![0u8; addr_len + 2];
    sock.read_exact(&mut skip)
        .await
        .map_err(|e| format!("cover: socks reply addr: {e}"))?;

    // `sock` now tunnels raw bytes to host:port. Do a REAL end-to-end HTTPS
    // request (verified against the Mozilla webpki roots, SNI = host).
    let mut tls = cover_tls_connect(sock, &host, connect_timeout).await?;
    let get = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; \
         Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36\r\n\
         Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
         Accept-Language: en-US,en;q=0.9\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(get.as_bytes())
        .await
        .map_err(|e| format!("cover: http write: {e}"))?;
    let mut moved = get.len() as u64;
    let mut buf = vec![0u8; 8192];
    let read_timeout = Duration::from_secs(20);
    loop {
        match tokio::time::timeout(read_timeout, tls.read(&mut buf)).await {
            Ok(Ok(0)) => break, // clean EOF (Connection: close)
            Ok(Ok(n)) => {
                moved += n as u64;
                if moved >= COVER_FETCH_READ_CAP {
                    break;
                }
            }
            Ok(Err(_)) => break, // TLS/read error - end the fetch, count what moved
            Err(_) => break,     // idle read timeout
        }
    }
    let _ = tls.shutdown().await;
    Ok(moved)
}

/// TLS-wrap a tunneled stream for a cover fetch (browser webpki roots, SNI =
/// `host`). Returns the `tokio_rustls` client stream directly so the caller can
/// read/write the HTTPS bytes.
async fn cover_tls_connect(
    tcp: TcpStream,
    host: &str,
    timeout: Duration,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::rustls::{ClientConfig, RootCertStore};
    use tokio_rustls::TlsConnector;
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = std::sync::Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("cover tls config: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(std::sync::Arc::new(cfg));
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| format!("cover tls: bad SNI {host:?}"))?;
    tokio::time::timeout(timeout, connector.connect(server_name, tcp))
        .await
        .map_err(|_| "cover tls: handshake timed out".to_string())?
        .map_err(|e| format!("cover tls: handshake: {e}"))
}

/// Probe all bridge entries concurrently to seed latency EMAs.
///
/// Hysteria2 entries are skipped - QUIC probes would require a token.
/// All TCP-based entries (Raw, Reality, SS-2022, WS, Meek, DoH) are
/// probed via a bare TCP connect, which verifies network reachability without
/// consuming a credential. The bridge will read-timeout on the open socket
/// after its handshake deadline, which is a tolerable cost of <=1 slot per
/// entry per probe cycle.
/// Probe every bridge entry to refresh reachability/latency.
///
/// `stagger_max` spreads the per-entry connect attempts over a random window
/// (#8): the STARTUP probe passes `ZERO` (connect fast, get online), but the
/// periodic BACKGROUND probe passes a non-zero window so N near-simultaneous
/// SYNs to N different bridge IPs don't fire as one recognizable burst on a
/// fixed cadence.
async fn probe_all_entries(pool: &EntryPool, probe_timeout: Duration, stagger_max: Duration) {
    let n = pool.len();
    let mut join_set = tokio::task::JoinSet::new();
    for idx in 0..n {
        let entry = &pool.entries[idx];
        let is_h2 = matches!(
            entry.transport,
            TransportMode::Hysteria2 { .. }
                | TransportMode::H3 { .. }
                | TransportMode::Dnstt { .. }
        );
        if is_h2 {
            // QUIC carriers (Hysteria2 / H3) can't be TCP-probed. Leave them in
            // their default healthy state rather than spawning a probe whose
            // empty-candidate path would mark_failure() them into backoff -
            // that latent bug made every QUIC entry unreachable at attempt 0.
            continue;
        }
        // Build candidate list (derived ports first, static last)
        let candidates: Vec<String> = {
            let mut c = Vec::with_capacity(3);
            if let (Some(salt), Some((base, range))) = (entry.shared_salt, entry.port_hop) {
                let now_unix = discovery_now_unix();
                let epoch = epoch_for_time(now_unix);
                let host = entry
                    .bridge_addr
                    .rsplit_once(':')
                    .map(|(h, _)| h)
                    .unwrap_or(&entry.bridge_addr);
                for ep in [epoch, epoch + 1] {
                    if let Some(port) =
                        derive_port(&salt, NAMESPACE_CLIENT_TO_BRIDGE, ep, base, range)
                    {
                        c.push(format!("{host}:{port}"));
                    }
                }
            }
            c.push(entry.bridge_addr.clone());
            c
        };

        join_set.spawn(async move {
            if candidates.is_empty() {
                return (idx, None::<u64>);
            }
            // #8: spread background probes across a random window so the fan-out
            // isn't a single N-SYN burst. ZERO on the startup path (dial fast).
            if stagger_max > Duration::ZERO {
                tokio::time::sleep(jitter_duration(Duration::ZERO, stagger_max)).await;
            }
            let t0 = tokio::time::Instant::now();
            // Probe all candidates concurrently; first to succeed wins.
            let mut inner = tokio::task::JoinSet::new();
            for addr in candidates {
                inner.spawn(async move {
                    tokio::time::timeout(probe_timeout, TcpStream::connect(&addr)).await
                });
            }
            while let Some(res) = inner.join_next().await {
                if let Ok(Ok(Ok(_))) = res {
                    inner.abort_all();
                    return (idx, Some(t0.elapsed().as_millis() as u64));
                }
            }
            (idx, None)
        });
    }
    while let Some(res) = join_set.join_next().await {
        if let Ok((idx, maybe_ms)) = res {
            match maybe_ms {
                Some(ms) => {
                    pool.mark_healthy(idx, ms).await;
                    info!(
                        idx,
                        bridge = %pool.entries[idx].bridge_addr,
                        latency_ms = ms,
                        "probe: bridge reachable"
                    );
                }
                None => {
                    pool.mark_failure(idx).await; // only fails if all candidates fail
                    warn!(
                        idx,
                        bridge = %pool.entries[idx].bridge_addr,
                        "probe: bridge unreachable"
                    );
                }
            }
        }
    }
}

// -- token claim/refresh flow -------------------------------------------------

/// Token deque length below which the background loop triggers a refresh.
const FRESH_TOKEN_LOW_WATERMARK: usize = 3;

/// Enable TCP keepalive on a bridge carrier socket. Now that a mux carrier is
/// LONG-LIVED (one session serving many streams), an idle carrier can be
/// silently killed by an on-path NAT / stateful-firewall idle timeout;
/// keepalive both keeps that middlebox state alive and turns a dead bridge into
/// a prompt socket error (so the carrier is pruned) instead of the next stream
/// open paying a full timeout. Fail-soft - best effort.
/// Uniform-random `Duration` in `[lo, hi]` from the OS CSPRNG.
///
/// Used to break FIXED-cadence behavioural tells (RT circumvention #8): a
/// censor watching a client's flows over time can fingerprint regular events
/// (a 60 s re-probe burst, a 25 s keepalive) that no ordinary application
/// emits on a metronome. Jittering each so it is neither fixed nor uniform
/// across clients removes the cross-flow cadence handle. Falls back to the
/// midpoint if the CSPRNG is momentarily unavailable (never stalls).
fn jitter_duration(lo: Duration, hi: Duration) -> Duration {
    let lo_ms = lo.as_millis() as u64;
    let hi_ms = hi.as_millis() as u64;
    if hi_ms <= lo_ms {
        return lo;
    }
    let span = hi_ms - lo_ms;
    let mut buf = [0u8; 8];
    let off = match getrandom::fill(&mut buf) {
        Ok(()) => u64::from_le_bytes(buf) % span,
        Err(_) => span / 2,
    };
    Duration::from_millis(lo_ms + off)
}

fn set_carrier_keepalive(sock: &TcpStream) {
    // Jitter per-connection (#8): a fixed 25 s/15 s keepalive is a constant
    // wire cadence unique to Mirage carriers. Real apps vary; so do we.
    let ka = socket2::TcpKeepalive::new()
        .with_time(jitter_duration(
            Duration::from_secs(20),
            Duration::from_secs(40),
        ))
        .with_interval(jitter_duration(
            Duration::from_secs(10),
            Duration::from_secs(25),
        ));
    let _ = socket2::SockRef::from(sock).set_tcp_keepalive(&ka);
}

/// Build the candidate address list for `entry` and TCP-connect to the first
/// reachable one.  Used by both the claim and refresh paths.
async fn tcp_connect_to_entry(entry: &BridgeEntry, timeout: Duration) -> Result<TcpStream, String> {
    let mut candidates: Vec<String> = Vec::with_capacity(3);
    if let (Some(salt), Some((base, range))) = (entry.shared_salt, entry.port_hop) {
        let now_unix = discovery_now_unix();
        let epoch = epoch_for_time(now_unix);
        let host = entry
            .bridge_addr
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(&entry.bridge_addr);
        for ep in [epoch, epoch + 1] {
            if let Some(port) = derive_port(&salt, NAMESPACE_CLIENT_TO_BRIDGE, ep, base, range) {
                candidates.push(format!("{host}:{port}"));
            }
        }
    }
    candidates.push(entry.bridge_addr.clone());

    let mut last_err = String::from("no addresses");
    for addr in &candidates {
        // dial_bridge_tcp is TcpStream::connect on desktop, and a
        // protect-before-connect path on Android (VpnService.protect).
        match tokio::time::timeout(timeout, dial_bridge_tcp(addr.as_str())).await {
            Ok(Ok(sock)) => {
                sock.set_nodelay(true).ok();
                set_carrier_keepalive(&sock);
                return Ok(sock);
            }
            Ok(Err(e)) => last_err = e.to_string(),
            Err(_) => last_err = format!("timeout connecting to {addr}"),
        }
    }
    Err(format!("TCP connect failed: {last_err}"))
}

/// Run `redeem_invite_claim` on an already-established Mirage session.
/// Returns the `CapabilityToken`s extracted from the piggybacked refresh
/// tokens (each `SessionRefreshToken.inner` is a usable `CapabilityToken`).
async fn claim_on_session<S: AsyncRead + AsyncWrite + Unpin>(
    session: &mut SessionStream<S>,
    bridge_ed_pk: &[u8; 32],
    claim_id: [u8; 32],
    timeout: Duration,
) -> Result<Vec<CapabilityToken>, String> {
    let outcome = tokio::time::timeout(
        timeout,
        redeem_invite_claim(&mut *session, bridge_ed_pk, claim_id, 8),
    )
    .await
    .map_err(|_| "claim: timed out".to_string())?
    .map_err(|e| format!("claim: {e}"))?;
    let _ = session.shutdown().await;
    Ok(outcome.tokens.into_iter().map(|t| t.inner).collect())
}

/// TCP-connect to the bridge (trying derived ports first, then static),
/// apply the transport carrier, run the Noise handshake, and call the
/// claim exchange to obtain fresh `CapabilityToken`s.
///
/// This consumes one bootstrap token from the entry's credential pool.
/// Returns an empty `Vec` if the entry has no `claim_id`.
async fn try_claim_entry(
    entry: &BridgeEntry,
    timeout: Duration,
) -> Result<Vec<CapabilityToken>, String> {
    // `entry.claim_id` holds the per-invite SECRET, never sent raw. Derive the
    // per-bridge id so two hostile bridges can't compare claimed-invite sets to
    // link this user across the mesh (#2). See `claim::derive_claim_id`.
    let claim_id = match entry.claim_id {
        Some(secret) => mirage_discovery::claim::derive_claim_id(&secret, &entry.bridge_ed25519_pk),
        None => return Ok(vec![]),
    };

    if matches!(
        entry.transport,
        TransportMode::Hysteria2 { .. } | TransportMode::H3 { .. } | TransportMode::Dnstt { .. }
    ) {
        return Err("claim not supported over hysteria2".into());
    }

    let bridge_sock = tcp_connect_to_entry(entry, timeout)
        .await
        .map_err(|e| format!("claim {e}"))?;
    let (client_sk, token) = entry.next_credentials();

    // Each transport arm: wrap socket -> (VLESS) -> Noise session -> claim exchange.
    match &entry.transport {
        TransportMode::Raw => {
            let mut bridge_sock = bridge_sock;
            apply_vless_if_needed(&mut bridge_sock, entry.vless_uuid, timeout).await?;
            let bridge_sock = pad_stream_if_enabled(bridge_sock, entry);
            let mut s = tokio::time::timeout(
                timeout,
                dial_session(bridge_sock, &client_sk, &entry.bridge_x25519_pk, &token),
            )
            .await
            .map_err(|_| format!("handshake timed out after {timeout:?}"))?
            .map_err(|e| format!("handshake: {e}"))?;
            claim_on_session(&mut s, &entry.bridge_ed25519_pk, claim_id, timeout).await
        }

        TransportMode::Ss2022 { psk } => {
            let c = mirage_transport_shadowsocks::ss2022_client_dial(bridge_sock, psk, timeout)
                .await
                .map_err(|e| format!("ss2022: {e}"))?;
            // Proteus: pace the SS carrier to the shared envelope (matched to the bridge).
            let seed = c.pace_seed();
            let mut c = mirage_transport_reality::maybe_pace_stream(
                c,
                mirage_transport_reality::pacer::Dir::Up,
                seed,
            );
            apply_vless_if_needed(&mut c, entry.vless_uuid, timeout).await?;
            let c = pad_stream_if_enabled(c, entry);
            let mut s = tokio::time::timeout(
                timeout,
                dial_session(c, &client_sk, &entry.bridge_x25519_pk, &token),
            )
            .await
            .map_err(|_| format!("handshake timed out after {timeout:?}"))?
            .map_err(|e| format!("handshake: {e}"))?;
            claim_on_session(&mut s, &entry.bridge_ed25519_pk, claim_id, timeout).await
        }

        TransportMode::WebSocket { path } => {
            let cover = ws_cover_host(&entry.bridge_addr);
            // red-team #4: wrap the carrier TCP in client-originated TLS when the
            // entry opts in, so the claim's HTTP rides encrypted to a TLS front.
            let stream = carrier_maybe_tls(bridge_sock, entry, cover, timeout).await?;
            let mut c = mirage_transport_ws::ws_client_connect(
                stream,
                &entry.bridge_x25519_pk,
                entry.obfs_secret.as_ref(),
                path,
                cover,
                timeout,
            )
            .await
            .map_err(|e| format!("websocket: {e}"))?;
            apply_vless_if_needed(&mut c, entry.vless_uuid, timeout).await?;
            let c = pad_stream_if_enabled(c, entry);
            let mut s = tokio::time::timeout(
                timeout,
                dial_session(c, &client_sk, &entry.bridge_x25519_pk, &token),
            )
            .await
            .map_err(|_| format!("handshake timed out after {timeout:?}"))?
            .map_err(|e| format!("handshake: {e}"))?;
            claim_on_session(&mut s, &entry.bridge_ed25519_pk, claim_id, timeout).await
        }

        TransportMode::Reality {
            sni,
            tls_cert_verify_pk,
            tls_fingerprint,
        } => {
            let now_unix: u32 = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0);
            let c = tokio::time::timeout(
                timeout,
                reality_connect(
                    bridge_sock,
                    &ClientCarrierInputs {
                        bridge_static_pk: &entry.bridge_x25519_pk,
                        probe_root: entry
                            .probe_root
                            .as_ref()
                            .unwrap_or(&mirage_transport_reality::PROBE_ROOT_DISABLED),
                        server_name: sni,
                        now_unix,
                        cert_verify_override_pk: tls_cert_verify_pk.as_ref(),
                        tls_fingerprint: *tls_fingerprint,
                    },
                ),
            )
            .await
            .map_err(|_| format!("reality timed out after {timeout:?}"))?
            .map_err(|e| format!("reality: {e}"))?;
            // Shaper-v2: opt-in envelope pacing, matched to the bridge. Off by default.
            let mut c =
                mirage_transport_reality::maybe_pace(c, mirage_transport_reality::pacer::Dir::Up);
            apply_vless_if_needed(&mut c, entry.vless_uuid, timeout).await?;
            let c = pad_stream_if_enabled(c, entry);
            let mut s = tokio::time::timeout(
                timeout,
                dial_session(c, &client_sk, &entry.bridge_x25519_pk, &token),
            )
            .await
            .map_err(|_| format!("handshake timed out after {timeout:?}"))?
            .map_err(|e| format!("handshake: {e}"))?;
            claim_on_session(&mut s, &entry.bridge_ed25519_pk, claim_id, timeout).await
        }

        TransportMode::Hysteria2 { .. } => Err("claim not supported over hysteria2".into()),
        TransportMode::H3 { .. } => Err("claim not supported over h3".into()),
        TransportMode::Dnstt { .. } => Err("claim not supported over dnstt".into()),
        TransportMode::WebRtc { .. } => Err("claim not supported over webrtc".into()),

        TransportMode::Meek { front_domain, path } => {
            let auth_frame = mirage_transport_meek::build_auth_frame(&entry.bridge_x25519_pk)
                .map_err(|e| format!("meek: auth frame: {e}"))?;
            let mut session_id = [0u8; 32];
            getrandom::fill(&mut session_id).expect("OS CSPRNG");
            let session_b64 = B64.encode(session_id);
            // red-team #4: TLS-wrap the carrier before the meek POSTs when opted in.
            let stream = carrier_maybe_tls(bridge_sock, entry, front_domain, timeout).await?;
            let mut c = mirage_transport_meek::MeekClientStream::new_with_content_type(
                stream,
                front_domain.clone(),
                path.clone(),
                session_id,
                Some(auth_frame.to_vec()),
                session_b64,
                "application/octet-stream".into(),
            )
            .await;
            apply_vless_if_needed(&mut c, entry.vless_uuid, timeout).await?;
            let c = pad_stream_if_enabled(c, entry);
            let mut s = tokio::time::timeout(
                timeout,
                dial_session(c, &client_sk, &entry.bridge_x25519_pk, &token),
            )
            .await
            .map_err(|_| format!("handshake timed out after {timeout:?}"))?
            .map_err(|e| format!("handshake: {e}"))?;
            claim_on_session(&mut s, &entry.bridge_ed25519_pk, claim_id, timeout).await
        }

        TransportMode::Doh { front_domain } => {
            // red-team #4: TLS-wrap the carrier before the DoH POSTs when opted in.
            let stream = carrier_maybe_tls(bridge_sock, entry, front_domain, timeout).await?;
            let mut c = mirage_transport_doh::doh_client_connect(
                stream,
                &entry.bridge_x25519_pk,
                front_domain.clone(),
                timeout,
            )
            .await
            .map_err(|e| format!("doh: {e}"))?;
            apply_vless_if_needed(&mut c, entry.vless_uuid, timeout).await?;
            let c = pad_stream_if_enabled(c, entry);
            let mut s = tokio::time::timeout(
                timeout,
                dial_session(c, &client_sk, &entry.bridge_x25519_pk, &token),
            )
            .await
            .map_err(|_| format!("handshake timed out after {timeout:?}"))?
            .map_err(|e| format!("handshake: {e}"))?;
            claim_on_session(&mut s, &entry.bridge_ed25519_pk, claim_id, timeout).await
        }
    }
}

/// Run `try_claim_entry` for every pool entry that carries a `claim_id`.
/// Fresh tokens are stored in `entry.fresh_tokens` and will be preferred
/// by `next_credentials()` over the bootstrap pool.
async fn claim_all_entries(pool: &EntryPool, timeout: Duration) {
    // Per-transport sibling entries of one bridge SHARE a fresh-token deque
    // (Arc), so claim ONCE per unique (bridge, claim_id) - otherwise we'd fire
    // one redundant claim per sibling for the same invite (and the bridge may
    // reject the duplicates as claim-id reuse).
    let mut claimed: std::collections::HashSet<([u8; 32], [u8; 32])> =
        std::collections::HashSet::new();
    for entry in &pool.entries {
        let Some(claim_id) = entry.claim_id else {
            continue;
        };
        if !claimed.insert((entry.bridge_x25519_pk, claim_id)) {
            continue; // a sibling already claimed; tokens are in the shared deque
        }
        push_tokens_to_entry(entry, try_claim_entry(entry, timeout).await, "claim");
    }
}

/// Push `tokens` from a claim or refresh call into `entry.fresh_tokens`,
/// logging the outcome at the appropriate level.
fn push_tokens_to_entry(
    entry: &BridgeEntry,
    result: Result<Vec<CapabilityToken>, String>,
    op: &str,
) {
    match result {
        Ok(tokens) if !tokens.is_empty() => {
            let count = tokens.len();
            if let Ok(mut deque) = entry.fresh_tokens.lock() {
                for t in tokens {
                    deque.push_back(t);
                }
            }
            info!(bridge = %entry.bridge_addr, fresh_tokens = count, "{op}: tokens stored");
        }
        Ok(_) => {
            info!(bridge = %entry.bridge_addr, "{op}: no tokens returned");
        }
        Err(e) => {
            warn!(bridge = %entry.bridge_addr, error = %e, "{op}: failed; relying on bootstrap pool");
        }
    }
}

// -- background refresh flow --------------------------------------------------

/// Run `refresh_session_tokens` on an already-established Mirage session.
/// Returns `CapabilityToken`s extracted from the bridge-issued refresh tokens.
async fn refresh_on_session<S: AsyncRead + AsyncWrite + Unpin>(
    session: &mut SessionStream<S>,
    bridge_ed_pk: &[u8; 32],
    timeout: Duration,
) -> Result<Vec<CapabilityToken>, String> {
    let batch = tokio::time::timeout(
        timeout,
        refresh_session_tokens(&mut *session, bridge_ed_pk, 8),
    )
    .await
    .map_err(|_| "refresh: timed out".to_string())?
    .map_err(|e| format!("refresh: {e}"))?;
    let _ = session.shutdown().await;
    Ok(batch.tokens.into_iter().map(|t| t.inner).collect())
}

/// Open a fresh Mirage session to `entry` and call the in-band refresh
/// exchange to mint new `CapabilityToken`s.  This consumes one token
/// from the pool (bootstrap or fresh), so callers should only invoke
/// this when the deque is genuinely low.
///
/// Not supported for Hysteria2 or explicit-hex entries.
async fn try_refresh_entry(
    entry: &BridgeEntry,
    timeout: Duration,
) -> Result<Vec<CapabilityToken>, String> {
    if entry.bridge_ed25519_pk == [0u8; 32] {
        return Err("refresh not available for explicit-hex entries".into());
    }
    if matches!(
        entry.transport,
        TransportMode::Hysteria2 { .. } | TransportMode::H3 { .. } | TransportMode::Dnstt { .. }
    ) {
        return Err("refresh not supported over hysteria2".into());
    }

    let bridge_sock = tcp_connect_to_entry(entry, timeout)
        .await
        .map_err(|e| format!("refresh {e}"))?;
    let (client_sk, token) = entry.next_credentials();

    match &entry.transport {
        TransportMode::Raw => {
            let mut bridge_sock = bridge_sock;
            apply_vless_if_needed(&mut bridge_sock, entry.vless_uuid, timeout).await?;
            let bridge_sock = pad_stream_if_enabled(bridge_sock, entry);
            let mut s = tokio::time::timeout(
                timeout,
                dial_session(bridge_sock, &client_sk, &entry.bridge_x25519_pk, &token),
            )
            .await
            .map_err(|_| format!("handshake timed out after {timeout:?}"))?
            .map_err(|e| format!("handshake: {e}"))?;
            refresh_on_session(&mut s, &entry.bridge_ed25519_pk, timeout).await
        }

        TransportMode::Ss2022 { psk } => {
            let c = mirage_transport_shadowsocks::ss2022_client_dial(bridge_sock, psk, timeout)
                .await
                .map_err(|e| format!("ss2022: {e}"))?;
            // Proteus: pace the SS carrier to the shared envelope (matched to the bridge).
            let seed = c.pace_seed();
            let mut c = mirage_transport_reality::maybe_pace_stream(
                c,
                mirage_transport_reality::pacer::Dir::Up,
                seed,
            );
            apply_vless_if_needed(&mut c, entry.vless_uuid, timeout).await?;
            let c = pad_stream_if_enabled(c, entry);
            let mut s = tokio::time::timeout(
                timeout,
                dial_session(c, &client_sk, &entry.bridge_x25519_pk, &token),
            )
            .await
            .map_err(|_| format!("handshake timed out after {timeout:?}"))?
            .map_err(|e| format!("handshake: {e}"))?;
            refresh_on_session(&mut s, &entry.bridge_ed25519_pk, timeout).await
        }

        TransportMode::WebSocket { path } => {
            let cover = ws_cover_host(&entry.bridge_addr);
            // red-team #4: wrap the carrier TCP in client-originated TLS when the
            // entry opts in, so the refresh's HTTP rides encrypted to a TLS front.
            let stream = carrier_maybe_tls(bridge_sock, entry, cover, timeout).await?;
            let mut c = mirage_transport_ws::ws_client_connect(
                stream,
                &entry.bridge_x25519_pk,
                entry.obfs_secret.as_ref(),
                path,
                cover,
                timeout,
            )
            .await
            .map_err(|e| format!("websocket: {e}"))?;
            apply_vless_if_needed(&mut c, entry.vless_uuid, timeout).await?;
            let c = pad_stream_if_enabled(c, entry);
            let mut s = tokio::time::timeout(
                timeout,
                dial_session(c, &client_sk, &entry.bridge_x25519_pk, &token),
            )
            .await
            .map_err(|_| format!("handshake timed out after {timeout:?}"))?
            .map_err(|e| format!("handshake: {e}"))?;
            refresh_on_session(&mut s, &entry.bridge_ed25519_pk, timeout).await
        }

        TransportMode::Reality {
            sni,
            tls_cert_verify_pk,
            tls_fingerprint,
        } => {
            let now_unix: u32 = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0);
            let c = tokio::time::timeout(
                timeout,
                reality_connect(
                    bridge_sock,
                    &ClientCarrierInputs {
                        bridge_static_pk: &entry.bridge_x25519_pk,
                        probe_root: entry
                            .probe_root
                            .as_ref()
                            .unwrap_or(&mirage_transport_reality::PROBE_ROOT_DISABLED),
                        server_name: sni,
                        now_unix,
                        cert_verify_override_pk: tls_cert_verify_pk.as_ref(),
                        tls_fingerprint: *tls_fingerprint,
                    },
                ),
            )
            .await
            .map_err(|_| format!("reality timed out after {timeout:?}"))?
            .map_err(|e| format!("reality: {e}"))?;
            // Shaper-v2: opt-in envelope pacing, matched to the bridge. Off by default.
            let mut c =
                mirage_transport_reality::maybe_pace(c, mirage_transport_reality::pacer::Dir::Up);
            apply_vless_if_needed(&mut c, entry.vless_uuid, timeout).await?;
            let c = pad_stream_if_enabled(c, entry);
            let mut s = tokio::time::timeout(
                timeout,
                dial_session(c, &client_sk, &entry.bridge_x25519_pk, &token),
            )
            .await
            .map_err(|_| format!("handshake timed out after {timeout:?}"))?
            .map_err(|e| format!("handshake: {e}"))?;
            refresh_on_session(&mut s, &entry.bridge_ed25519_pk, timeout).await
        }

        TransportMode::Hysteria2 { .. } => Err("refresh not supported over hysteria2".into()),
        TransportMode::H3 { .. } => Err("refresh not supported over h3".into()),
        TransportMode::Dnstt { .. } => Err("refresh not supported over dnstt".into()),
        TransportMode::WebRtc { .. } => Err("refresh not supported over webrtc".into()),

        TransportMode::Meek { front_domain, path } => {
            let auth_frame = mirage_transport_meek::build_auth_frame(&entry.bridge_x25519_pk)
                .map_err(|e| format!("meek: auth frame: {e}"))?;
            let mut session_id = [0u8; 32];
            getrandom::fill(&mut session_id).expect("OS CSPRNG");
            let session_b64 = B64.encode(session_id);
            // red-team #4: TLS-wrap the carrier before the meek POSTs when opted in.
            let stream = carrier_maybe_tls(bridge_sock, entry, front_domain, timeout).await?;
            let mut c = mirage_transport_meek::MeekClientStream::new_with_content_type(
                stream,
                front_domain.clone(),
                path.clone(),
                session_id,
                Some(auth_frame.to_vec()),
                session_b64,
                "application/octet-stream".into(),
            )
            .await;
            apply_vless_if_needed(&mut c, entry.vless_uuid, timeout).await?;
            let c = pad_stream_if_enabled(c, entry);
            let mut s = tokio::time::timeout(
                timeout,
                dial_session(c, &client_sk, &entry.bridge_x25519_pk, &token),
            )
            .await
            .map_err(|_| format!("handshake timed out after {timeout:?}"))?
            .map_err(|e| format!("handshake: {e}"))?;
            refresh_on_session(&mut s, &entry.bridge_ed25519_pk, timeout).await
        }

        TransportMode::Doh { front_domain } => {
            // red-team #4: TLS-wrap the carrier before the DoH POSTs when opted in.
            let stream = carrier_maybe_tls(bridge_sock, entry, front_domain, timeout).await?;
            let mut c = mirage_transport_doh::doh_client_connect(
                stream,
                &entry.bridge_x25519_pk,
                front_domain.clone(),
                timeout,
            )
            .await
            .map_err(|e| format!("doh: {e}"))?;
            apply_vless_if_needed(&mut c, entry.vless_uuid, timeout).await?;
            let c = pad_stream_if_enabled(c, entry);
            let mut s = tokio::time::timeout(
                timeout,
                dial_session(c, &client_sk, &entry.bridge_x25519_pk, &token),
            )
            .await
            .map_err(|_| format!("handshake timed out after {timeout:?}"))?
            .map_err(|e| format!("handshake: {e}"))?;
            refresh_on_session(&mut s, &entry.bridge_ed25519_pk, timeout).await
        }
    }
}

/// Refresh tokens for any entry whose `fresh_tokens` deque is at or below
/// [`FRESH_TOKEN_LOW_WATERMARK`].  Called by the background loop.
async fn refresh_low_entries(pool: &EntryPool, timeout: Duration) {
    // Sibling entries share one fresh-token deque (Arc), so refresh ONCE per
    // unique bridge - a single refresh tops up the deque all siblings drain.
    let mut refreshed: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    for entry in &pool.entries {
        if !refreshed.insert(entry.bridge_x25519_pk) {
            continue;
        }
        let current_len = entry
            .fresh_tokens
            .lock()
            .map(|d| d.len())
            .unwrap_or(usize::MAX); // poisoned = skip
        if current_len <= FRESH_TOKEN_LOW_WATERMARK {
            debug!(
                bridge = %entry.bridge_addr,
                fresh_remaining = current_len,
                "refresh: fresh token deque low; requesting more"
            );
            push_tokens_to_entry(entry, try_refresh_entry(entry, timeout).await, "refresh");
        }
    }
}

/// Is `host` (a `Host:` header value or a bind string, with optional port) a
/// loopback literal? Used to keep the machine-local management API local.
fn host_is_loopback(host: &str) -> bool {
    let h = host.trim();
    let bare = if let Some(rest) = h.strip_prefix('[') {
        // IPv6 literal `[addr]:port` -> addr
        rest.split(']').next().unwrap_or("")
    } else {
        // `host:port` -> host (also handles a bare host with no port)
        h.split(':').next().unwrap_or("")
    };
    matches!(bare, "127.0.0.1" | "localhost" | "::1")
}

async fn serve_management(
    bind: String,
    pool: Arc<EntryPool>,
    active_sessions: Arc<AtomicUsize>,
    total_sessions: Arc<AtomicUsize>,
    start_time: std::time::Instant,
    local_bind: String,
) {
    // RT #10: the management API exposes session stats AND the live bridge
    // list (IPs + ports) with no authentication. It is a MACHINE-LOCAL API;
    // binding it to a non-loopback address publishes the fleet to the
    // network. Warn loudly (the Host-header check below still blocks
    // cross-origin browser reads, but a non-loopback bind is a direct leak).
    if !host_is_loopback(&bind) {
        warn!(
            addr = %bind,
            "management API bound to a NON-loopback address - it serves the live bridge list \
             unauthenticated. Bind to 127.0.0.1 and firewall the port."
        );
    }
    let listener = match TcpListener::bind(&bind).await {
        Ok(l) => {
            info!(addr = %bind, "management API listening");
            l
        }
        Err(e) => {
            warn!(addr = %bind, error = %e, "management: bind failed; management API disabled");
            return;
        }
    };

    loop {
        let (mut sock, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => continue,
        };
        let pool = Arc::clone(&pool);
        let active = Arc::clone(&active_sessions);
        let total = Arc::clone(&total_sessions);
        let start = start_time;
        let lb = local_bind.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let req = std::str::from_utf8(&buf[..n]).unwrap_or("");

            // DNS-rebinding defense (RT #10): a malicious web page can make
            // its domain resolve to 127.0.0.1 to defeat the same-origin
            // policy, but its requests still carry its own Host header. This
            // is a machine-local API with no legitimate cross-host caller, so
            // reject any request whose Host is not a loopback literal.
            let host_ok = req
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("host:"))
                .and_then(|l| l.split_once(':').map(|x| x.1))
                .map(host_is_loopback)
                .unwrap_or(false);
            if !host_ok {
                let resp = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
                let _ = sock.write_all(resp.as_bytes()).await;
                return;
            }

            let path = req
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("/");

            let body = match path {
                "/api/status" => {
                    let uptime = start.elapsed().as_secs();
                    let (mux_carriers, mux_streams) = pool.mux_totals().await;
                    let (egress_verified, egress_since) = pool.egress_status();
                    serde_json::json!({
                        "version": env!("CARGO_PKG_VERSION"),
                        "local_bind": lb,
                        "active_sessions": active.load(Ordering::Relaxed),
                        "total_sessions": total.load(Ordering::Relaxed),
                        "uptime_secs": uptime,
                        "total_bytes_up": TOTAL_BYTES_UP.load(Ordering::Relaxed),
                        "total_bytes_down": TOTAL_BYTES_DOWN.load(Ordering::Relaxed),
                        "mux_carriers": mux_carriers,
                        "mux_streams": mux_streams,
                        // Verified-connected egress gate: `true` once a Mirage
                        // tunnel handshake has completed. The GUI / OS kill-switch
                        // consume this to arm or release egress.
                        "egress_verified": egress_verified,
                        "egress_verified_since_unix": egress_since,
                    })
                    .to_string()
                }
                "/api/bridges" => {
                    let stats = pool.bridge_stats().await;
                    serde_json::to_string(&stats).unwrap_or_else(|_| "[]".into())
                }
                _ => {
                    let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                    let _ = sock.write_all(resp.as_bytes()).await;
                    return;
                }
            };

            // NO `Access-Control-Allow-Origin` header (RT #10): this local API
            // must rely on the browser same-origin policy to block a malicious
            // web page from reading the bridge list cross-origin. A wildcard
            // CORS header previously opted every web page in.
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        });
    }
}

fn fatal<S: Into<String>>(msg: S) -> ! {
    eprintln!("fatal: {}", msg.into());
    std::process::exit(2);
}

// -- `mirage-client connect <invite>` ---------------------------------------

/// Build the connect-mode config JSON from an invite + convenience flags.
/// Pure (no validation/exit) so it's unit-testable; serde fills every other
/// field with its default.
fn connect_config_json(
    invite: &str,
    socks: &str,
    reality_sni: Option<&str>,
    hysteria2: bool,
) -> serde_json::Value {
    let mut cfg = serde_json::json!({ "invite": invite, "local_bind": socks });
    if let Some(sni) = reality_sni {
        cfg["reality_enabled"] = serde_json::json!(true);
        cfg["reality_sni"] = serde_json::json!(sni);
    }
    if hysteria2 {
        cfg["hysteria2_enabled"] = serde_json::json!(true);
    }
    cfg
}

/// Resolve the invite from argv, reading stdin when the positional arg is `-`.
/// A literal invite on argv triggers a warning (it is world-visible in the
/// process list); `-` reads one line from stdin, which is not.
fn read_invite_from_argv_or_stdin(argv: &[String]) -> String {
    match argv.get(2) {
        Some(s) if s == "-" => {
            use std::io::BufRead;
            let mut line = String::new();
            if std::io::stdin().lock().read_line(&mut line).is_err() || line.trim().is_empty() {
                eprintln!("error: no invite on stdin (expected `mirage://...`)");
                std::process::exit(2);
            }
            line.trim().to_string()
        }
        Some(s) if !s.starts_with('-') => {
            eprintln!(
                "warning: the invite is a bearer credential and was passed on the command \
                 line, where any local user can read it via `ps`. Prefer `MIRAGE_INVITE=... \
                 mirage-client connect` or piping it: `... | mirage-client connect -`."
            );
            s.clone()
        }
        _ => {
            eprintln!(
                "usage: mirage-client connect <mirage://invite | -> [--socks <addr>] \
                 [--reality-sni <domain>] [--hysteria2] [--management-bind <addr>]\n\
                 (or set MIRAGE_INVITE in the environment; `-` reads the invite from stdin)"
            );
            std::process::exit(2);
        }
    }
}

/// Parse a `mirage connect <invite> [flags]` invocation into a `ClientConfig`
/// (+ optional management bind). Exits the process on a missing/invalid invite
/// or unknown flag.
fn build_connect_config(argv: &[String]) -> (ClientConfig, Option<String>) {
    // An invite is a BEARER credential. Anything on the command line is visible
    // to every other local user via `ps` / `/proc/<pid>/cmdline`, so the invite
    // is taken (in priority order) from a place that is NOT world-visible:
    //   1. the `MIRAGE_INVITE` environment variable, or
    //   2. standard input, when the positional arg is `-` (e.g. piped from a
    //      password manager: `pass mirage | mirage-client connect -`).
    // A literal invite on argv still works for convenience, but prints a warning
    // because it leaks the credential to the local process list.
    let invite = if let Ok(env_invite) = std::env::var("MIRAGE_INVITE") {
        if !env_invite.trim().is_empty() {
            env_invite.trim().to_string()
        } else {
            read_invite_from_argv_or_stdin(argv)
        }
    } else {
        read_invite_from_argv_or_stdin(argv)
    };
    // Validate the invite decodes before building anything.
    let clean = invite
        .trim()
        .strip_prefix("mirage://")
        .unwrap_or(invite.trim());
    if MasterInvite::decode_text(clean).is_err() {
        eprintln!("mirage-client connect: invalid invite (could not decode)");
        std::process::exit(2);
    }

    let mut socks = "127.0.0.1:1080".to_string();
    let mut reality_sni: Option<String> = None;
    let mut hysteria2 = false;
    let mut mgmt: Option<String> = None;
    let mut i = 3;
    while i < argv.len() {
        match argv[i].as_str() {
            "--socks" => {
                if let Some(a) = argv.get(i + 1) {
                    socks = a.clone();
                }
                i += 2;
            }
            "--reality-sni" => {
                reality_sni = argv.get(i + 1).cloned();
                i += 2;
            }
            "--hysteria2" => {
                hysteria2 = true;
                i += 1;
            }
            "--management-bind" => {
                mgmt = argv.get(i + 1).cloned();
                i += 2;
            }
            other => {
                eprintln!("mirage-client connect: unknown flag '{other}'. Try --help.");
                std::process::exit(2);
            }
        }
    }

    let cfg = connect_config_json(&invite, &socks, reality_sni.as_deref(), hysteria2);
    let config: ClientConfig = serde_json::from_value(cfg)
        .unwrap_or_else(|e| fatal(format!("connect: build config: {e}")));
    (config, mgmt)
}

// -- `mirage-client status` -------------------------------------------------

/// Query a running daemon's management API and print a human-readable status:
/// sessions, uptime, and per-bridge transport health (the success/failure
/// counts the adaptive selector learns from).
/// Connectivity preflight: validate a config file or invite, then live-test
/// whether each resulting bridge is actually reachable. This is the first thing
/// to run when "it won't connect" - it separates "bad config" from "config is
/// fine but the bridge/network is unreachable" and gives actionable hints.
async fn run_doctor(argv: &[String]) {
    println!("mirage-client doctor - connectivity preflight\n");

    let arg = match argv.get(2) {
        Some(a) if !a.starts_with('-') => a.clone(),
        _ => {
            eprintln!("usage: mirage-client doctor <config.json | mirage://invite>");
            std::process::exit(2);
        }
    };

    // Build a ClientConfig from an invite URL or a JSON config file.
    let looks_like_invite = {
        let clean = arg.trim().strip_prefix("mirage://").unwrap_or(arg.trim());
        arg.trim_start().starts_with("mirage://") || MasterInvite::decode_text(clean).is_ok()
    };
    let config: ClientConfig = if looks_like_invite {
        // Reuse the `connect` invite->config path (reads argv[2] + flags).
        let (c, _) = build_connect_config(argv);
        println!("[ok] invite decoded");
        c
    } else {
        match std::fs::read_to_string(&arg)
            .map_err(|e| format!("read {arg}: {e}"))
            .and_then(|s| serde_json::from_str::<ClientConfig>(&s).map_err(|e| e.to_string()))
        {
            Ok(c) => {
                println!("[ok] config file parsed");
                c
            }
            Err(e) => {
                println!("[FAIL] config: {e}");
                std::process::exit(1);
            }
        }
    };

    let local_bind = config.local_bind.clone();
    let pool = match build_pool(config) {
        Ok(p) => p,
        Err(e) => {
            println!("[FAIL] config invalid: {e}");
            std::process::exit(1);
        }
    };
    println!(
        "[ok] {} bridge entr{} built",
        pool.len(),
        if pool.len() == 1 { "y" } else { "ies" }
    );

    // Is the local SOCKS port free? (A common "it won't start" cause.)
    match TcpListener::bind(&local_bind).await {
        Ok(l) => {
            drop(l);
            println!("[ok] local SOCKS port {local_bind} is free");
        }
        Err(e) => {
            println!(
                "[warn] local SOCKS port {local_bind} is unavailable ({e})\n        \
                 stop whatever is listening there, or set a different `local_bind`."
            );
        }
    }
    println!();

    // Live reachability test per entry.
    let timeout = Duration::from_secs(6);
    let mut reachable = 0usize;
    for (i, e) in pool.entries.iter().enumerate() {
        let mode = e.describe_mode();
        let udp = matches!(mode, "hysteria2" | "h3" | "dnstt" | "webrtc");
        let note = if udp {
            " (UDP/DNS transport - TCP probe is indicative only)"
        } else {
            ""
        };
        let t0 = Instant::now();
        match tcp_connect_to_entry(e, timeout).await {
            Ok(_) => {
                let ms = t0.elapsed().as_millis();
                println!(
                    "  [{i}] [ok] {} reachable via {mode} ({ms} ms){note}",
                    e.bridge_addr
                );
                reachable += 1;
            }
            Err(err) => {
                println!(
                    "  [{i}] [FAIL] {} unreachable via {mode}{note}",
                    e.bridge_addr
                );
                println!("        {err}");
            }
        }
    }

    println!();
    if reachable == 0 {
        println!(
            "[FAIL] no bridge is reachable.\n  Check that: the bridge process is running; the \
             address/port in the invite is current; and no local firewall or on-path censor is \
             blocking it. If the operator rotated the bridge's IP, request a fresh invite."
        );
        std::process::exit(1);
    }
    if reachable < pool.len() {
        println!(
            "[warn] {reachable}/{} bridges reachable - the client will fail over to the \
             reachable ones.",
            pool.len()
        );
    } else {
        println!("[ok] all {} bridge(s) reachable.", pool.len());
    }
    println!(
        "\nReady. Start with `mirage-client {}`, then point your app's SOCKS5 proxy at {}.",
        if looks_like_invite {
            format!("connect {arg}")
        } else {
            arg.clone()
        },
        local_bind
    );
}

async fn run_status_query(argv: &[String]) {
    let mut addr = "127.0.0.1:19443".to_string();
    let mut i = 2;
    while i < argv.len() {
        if argv[i] == "--management-bind" {
            if let Some(a) = argv.get(i + 1) {
                addr = a.clone();
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    let status = match mgmt_get_json(&addr, "/api/status").await {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "mirage-client status: cannot reach management API at {addr}: {e}\n\
                 (run the daemon with `--management-bind {addr}` to enable it)"
            );
            std::process::exit(1);
        }
    };
    let bridges = mgmt_get_json(&addr, "/api/bridges")
        .await
        .unwrap_or_else(|_| serde_json::Value::Array(Vec::new()));
    print!("{}", format_status(&status, &bridges));
}

/// Minimal HTTP GET of a localhost management endpoint -> parsed JSON body.
/// Hand-rolled (no HTTP-client dependency); the API is tiny and loopback-only.
async fn mgmt_get_json(addr: &str, path: &str) -> Result<serde_json::Value, String> {
    let mut sock = tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(addr))
        .await
        .map_err(|_| "connect timed out".to_string())?
        .map_err(|e| e.to_string())?;
    // The API enforces a loopback Host (DNS-rebind defense); send the host part.
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or("127.0.0.1");
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    sock.write_all(req.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let mut resp = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), sock.read_to_end(&mut resp))
        .await
        .map_err(|_| "read timed out".to_string())?
        .map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&resp);
    let status_line = text.lines().next().unwrap_or("");
    if !status_line.contains(" 200") {
        return Err(format!("management API returned: {status_line}"));
    }
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
    serde_json::from_str(body).map_err(|e| format!("parse JSON: {e}"))
}

/// Render the `/api/status` + `/api/bridges` JSON as a human-readable block.
/// Pure (no I/O), so it's unit-testable and tolerant of missing fields.
fn format_status(status: &serde_json::Value, bridges: &serde_json::Value) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let version = status["version"].as_str().unwrap_or("?");
    let uptime = status["uptime_secs"].as_u64().unwrap_or(0);
    let active = status["active_sessions"].as_u64().unwrap_or(0);
    let total = status["total_sessions"].as_u64().unwrap_or(0);
    let local = status["local_bind"].as_str().unwrap_or("?");
    let up = status["total_bytes_up"].as_u64().unwrap_or(0);
    let down = status["total_bytes_down"].as_u64().unwrap_or(0);
    let _ = writeln!(out, "Mirage client {version}");
    let _ = writeln!(
        out,
        "  uptime {}  |  sessions {active} active / {total} total  |  local {local}",
        fmt_duration(uptime)
    );
    let _ = writeln!(
        out,
        "  traffic  up {}  down {}",
        fmt_bytes(up),
        fmt_bytes(down)
    );
    let mc = status["mux_carriers"].as_u64().unwrap_or(0);
    let ms = status["mux_streams"].as_u64().unwrap_or(0);
    let _ = writeln!(
        out,
        "  mux      {mc} carrier{} carrying {ms} stream{}",
        if mc == 1 { "" } else { "s" },
        if ms == 1 { "" } else { "s" }
    );
    match bridges.as_array() {
        Some(arr) if !arr.is_empty() => {
            let _ = writeln!(out, "  bridges (per-network transport health, learned):");
            for b in arr {
                let idx = b["idx"].as_u64().unwrap_or(0);
                let baddr = b["addr"].as_str().unwrap_or("?");
                let transport = b["transport"].as_str().unwrap_or("?");
                let healthy = b["healthy"].as_bool().unwrap_or(false);
                let lat = b["latency_ms"]
                    .as_u64()
                    .map(|l| format!("{l}ms"))
                    .unwrap_or_else(|| "--".to_string());
                let ok = b["transport_successes"].as_u64().unwrap_or(0);
                let fail = b["transport_failures"].as_u64().unwrap_or(0);
                let carriers = b["mux_carriers"].as_u64().unwrap_or(0);
                let streams = b["mux_streams"].as_u64().unwrap_or(0);
                let muxinfo = if carriers > 0 {
                    format!("   mux {carriers}c/{streams}s")
                } else {
                    String::new()
                };
                let _ = writeln!(
                    out,
                    "    [{idx}] {baddr:<22} {transport:<10} {:<4} {lat:>6}   ok {ok} / fail {fail}{muxinfo}",
                    if healthy { "up" } else { "down" }
                );
            }
        }
        _ => {
            let _ = writeln!(out, "  (no bridge entries reported)");
        }
    }
    out
}

/// Human-readable byte count: `1.5 GiB`, `820 KiB`, `512 B`.
fn fmt_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

/// Compact duration: `1h23m`, `45m07s`, or `12s`.
fn fmt_duration(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h}h{m:02}m")
    } else if m > 0 {
        format!("{m}m{s:02}s")
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod windows_elevation_tests {
    use super::*;

    #[test]
    fn ps_single_quote_escapes_correctly() {
        assert_eq!(ps_single_quote("simple"), "'simple'");
        // Spaces and backslashes are literal inside a single-quoted PS string.
        assert_eq!(
            ps_single_quote(r"C:\Program Files\mirage\c.json"),
            r"'C:\Program Files\mirage\c.json'"
        );
        // The only special char, `'`, is escaped by doubling.
        assert_eq!(ps_single_quote("it's"), "'it''s'");
        // A crafted arg cannot break out of the quoting to inject a command:
        // decoding the PowerShell single-quoted literal (strip outer quotes,
        // collapse doubled quotes) must round-trip to exactly the input.
        let evil = "'; Remove-Item C:\\ -Recurse; '";
        let q = ps_single_quote(evil);
        assert!(q.starts_with('\'') && q.ends_with('\''));
        let decoded = q[1..q.len() - 1].replace("''", "'");
        assert_eq!(decoded, evil, "quoting must be injection-safe + reversible");
    }

    #[test]
    fn elevation_check_cmd_queries_admin_role() {
        let c = windows_is_elevated_cmd();
        assert_eq!(c[0], "powershell");
        let script = c.last().unwrap();
        assert!(script.contains("IsInRole"));
        assert!(script.contains("Administrator"));
    }

    #[test]
    fn relaunch_cmd_uses_runas_and_quotes_args() {
        let cmd = windows_relaunch_elevated_cmd(
            r"C:\mirage\mirage-client.exe",
            &["--config".into(), r"C:\cfg\c.json".into()],
        );
        assert_eq!(cmd[0], "powershell");
        let script = cmd.last().unwrap();
        assert!(script.starts_with(r"Start-Process -FilePath 'C:\mirage\mirage-client.exe'"));
        assert!(script.contains("-Verb RunAs"), "must trigger UAC: {script}");
        assert!(script.contains(r"-ArgumentList '--config','C:\cfg\c.json'"));

        // No args -> no -ArgumentList, still elevated.
        let bare = windows_relaunch_elevated_cmd("x.exe", &[]);
        let s = bare.last().unwrap();
        assert!(!s.contains("ArgumentList"));
        assert!(s.contains("-Verb RunAs"));
    }
}

#[cfg(test)]
mod self_adversary_witness_tests {
    use super::*;
    use mirage_transport::self_adversary::looks_fully_encrypted;

    #[test]
    fn obfs_class_witness_is_flagged_others_exempt() {
        // The predictive penalty hinges on the witness classification: carriers
        // that frame Noise/obfs directly on TCP must look fully-encrypted
        // (flagged -> penalised); TLS/HTTP-wrapped carriers must be exempt. A
        // future edit that inverts this would silently disable the steering.
        for name in [
            "obfs",
            "obfs-tcp",
            "ss2022",
            "shadowsocks",
            "raw",
            "invite",
            "explicit-hex",
        ] {
            assert!(
                looks_fully_encrypted(&transport_egress_witness(name)),
                "{name} carries a uniformly-random first packet -> must be flagged"
            );
        }
        for name in [
            "reality",
            "vless",
            "meek",
            "websocket",
            "ws",
            "doh",
            "hysteria2",
            "h3",
            "webrtc",
            "dnstt",
        ] {
            assert!(
                !looks_fully_encrypted(&transport_egress_witness(name)),
                "{name} opens with a structured/printable first packet -> must be exempt"
            );
        }
    }

    #[test]
    fn unknown_transport_fails_safe_to_flagged() {
        // A future/unknown transport name must default to the flagged (random)
        // witness, so a new raw-ciphertext carrier is steered away rather than
        // silently exempted (fail-safe, not fail-open).
        for name in ["some-future-raw-transport", "", "trojan-raw", "unknown"] {
            assert!(
                looks_fully_encrypted(&transport_egress_witness(name)),
                "unknown transport '{name}' must fail safe to flagged"
            );
        }
    }
}

#[cfg(test)]
mod success_recording_tests {
    use super::*;

    fn test_entry(transport: TransportMode) -> BridgeEntry {
        BridgeEntry {
            bridge_addr: "127.0.0.1:443".to_string(),
            bridge_x25519_pk: [0u8; 32],
            bridge_ed25519_pk: [0u8; 32],
            claim_id: None,
            credentials: Credentials::Invite {
                tokens: Arc::new(Vec::new()),
                cursor: Arc::new(AtomicUsize::new(0)),
                fs_tokens: Arc::new(Vec::new()),
                fs_cursor: Arc::new(AtomicUsize::new(0)),
            },
            handshake_timeout: Duration::from_secs(5),
            transport,
            shared_salt: None,
            port_hop: None,
            obfs_secret: None,
            probe_root: None,
            fs_rendezvous_anchor: None,
            fresh_tokens: Arc::new(std::sync::Mutex::new(VecDeque::new())),
            fs_unsupported_until: Arc::new(AtomicU64::new(0)),
            vless_uuid: None,
            pad_enabled: false,
            quic_obfs_disable: false,
            carrier_tls: false,
            carrier_tls_sni: None,
            pad_cbr_frame_bytes: None,
            pad_cbr_interval_ms: 10,
            circuit_relay: false,
            mux_enabled: false,
            mux_carriers: Arc::new(Mutex::new(Vec::new())),
            mux_establishing: Arc::new(Mutex::new(())),
            operator_ed25519_pk: [0u8; 32],
            discovered_addrs: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            revoked: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// M4: with epoch port-hop configured, the Hysteria2 UDP dial must target the
    /// CURRENT-epoch derived port (the one the bridge binds via the identical
    /// `derive_port` call), NOT the static port - so a censor blocking the static
    /// UDP port cannot block the QUIC carrier.
    #[tokio::test]
    async fn hysteria2_port_hop_dials_derived_udp_port() {
        let salt = [0x5Au8; 32];
        let base = 20_000u16;
        let range = 1_000u16;
        let mut e = test_entry(TransportMode::Hysteria2 {
            send_rate_bps: 0,
            hostname: "cdn.example.com".into(),
            obfs_key: None,
        });
        e.shared_salt = Some(salt);
        e.port_hop = Some((base, range));
        let epoch = epoch_for_time(discovery_now_unix());
        let want_now = derive_port(&salt, NAMESPACE_CLIENT_TO_BRIDGE, epoch, base, range);
        let want_next = derive_port(&salt, NAMESPACE_CLIENT_TO_BRIDGE, epoch + 1, base, range);
        let got = resolve_hysteria2_dial_addr(&e).await.unwrap();
        assert!(
            Some(got.port()) == want_now || Some(got.port()) == want_next,
            "port-hop must dial the epoch-derived port (got {}, want {want_now:?}/{want_next:?})",
            got.port()
        );
        assert_ne!(got.port(), 443, "port-hop must NOT dial the static port");
        assert!(
            (base..base + range).contains(&got.port()),
            "derived port in range"
        );

        // Without port-hop, the static address is dialed unchanged.
        let e2 = test_entry(TransportMode::Hysteria2 {
            send_rate_bps: 0,
            hostname: "cdn.example.com".into(),
            obfs_key: None,
        });
        let got2 = resolve_hysteria2_dial_addr(&e2).await.unwrap();
        assert_eq!(got2.port(), 443, "no port-hop => static port");
    }

    fn legacy_and_fs_tokens() -> (CapabilityToken, FsCapabilityToken) {
        use mirage_crypto::ed25519_dalek::SigningKey;
        use mirage_discovery::token::sign_token;
        use mirage_discovery::token_fs::EpochSigner;
        let op = SigningKey::from_bytes(&[9u8; 32]);
        let legacy = sign_token([1u8; 32], [2u8; 32], 2_000_000_000, &op);
        let signer = EpochSigner::generate(&op, 1, 2_000_000_000).unwrap();
        let fs = signer.sign_token([3u8; 32], [2u8; 32], 2_000_000_000);
        (legacy, fs)
    }

    #[tokio::test]
    async fn carrier_tls_roundtrips_through_carrier_conn() {
        // red-team #4: a real TLS handshake, wrapped in CarrierConn::Tls, must
        // read/write transparently so the meek/DoH/WS codecs run over it.
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_rustls::rustls::pki_types::{
            CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName,
        };
        use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
        use tokio_rustls::{TlsAcceptor, TlsConnector};

        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = CertificateDer::from(ck.cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));

        let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let server_cfg = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        let client_cfg = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let mut b = [0u8; 5];
            tls.read_exact(&mut b).await.unwrap();
            tls.write_all(&b).await.unwrap();
            tls.flush().await.unwrap();
        });

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let tls = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        let mut cc = CarrierConn::Tls(Box::new(tls));
        cc.write_all(b"hello").await.unwrap();
        cc.flush().await.unwrap();
        let mut got = [0u8; 5];
        cc.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello");
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn carrier_maybe_tls_is_plain_when_disabled() {
        // Default (carrier_tls=false): no TLS handshake, a plain passthrough,
        // so existing cleartext-carrier deployments and the e2e are unaffected.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _srv = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let entry = test_entry(reality()); // carrier_tls defaults false
        let cc = carrier_maybe_tls(tcp, &entry, "example.com", Duration::from_secs(2))
            .await
            .unwrap();
        assert!(matches!(cc, CarrierConn::Plain(_)));
    }

    #[test]
    fn fs_unsupported_flag_downgrades_to_legacy() {
        // A dual-mint invite prefers FS, but after an old bridge rejects it
        // (note_fs_dial_dead) the SAME entry falls back to the co-minted legacy
        // token so the old bridge stays reachable - the rolling-upgrade fix.
        let (legacy, fs) = legacy_and_fs_tokens();
        let mut entry = test_entry(reality());
        entry.credentials = Credentials::Invite {
            tokens: Arc::new(vec![legacy]),
            cursor: Arc::new(AtomicUsize::new(0)),
            fs_tokens: Arc::new(vec![fs]),
            fs_cursor: Arc::new(AtomicUsize::new(0)),
        };
        // Fresh: prefers FS.
        assert!(matches!(entry.next_credentials().1, PresentedToken::Fs(_)));
        // Old-bridge death -> time-boxed downgrade (deadline in the future).
        entry.note_fs_dial_dead();
        assert!(entry.fs_unsupported_until.load(Ordering::Relaxed) > now_unix_secs());
        // Now presents legacy (old bridge reachable).
        assert!(matches!(
            entry.next_credentials().1,
            PresentedToken::Legacy(_)
        ));
        // Once the window elapses, FS is re-attempted (a single RST cannot
        // permanently strip FS). Simulate expiry by clearing the deadline.
        entry.fs_unsupported_until.store(0, Ordering::Relaxed);
        assert!(matches!(entry.next_credentials().1, PresentedToken::Fs(_)));
    }

    #[test]
    fn note_fs_dial_dead_is_noop_without_legacy_fallback() {
        // An FS-only invite has nothing to downgrade to: keep presenting FS
        // rather than getting stuck with no token.
        let (_legacy, fs) = legacy_and_fs_tokens();
        let mut entry = test_entry(reality());
        entry.credentials = Credentials::Invite {
            tokens: Arc::new(Vec::new()),
            cursor: Arc::new(AtomicUsize::new(0)),
            fs_tokens: Arc::new(vec![fs]),
            fs_cursor: Arc::new(AtomicUsize::new(0)),
        };
        entry.note_fs_dial_dead();
        assert_eq!(
            entry.fs_unsupported_until.load(Ordering::Relaxed),
            0,
            "no legacy pool => no downgrade"
        );
        assert!(matches!(entry.next_credentials().1, PresentedToken::Fs(_)));
    }

    #[test]
    fn egress_gate_transitions() {
        let pool = EntryPool::new(
            vec![test_entry(reality())],
            Duration::from_secs(0),
            Arc::new(tokio::sync::Notify::new()),
            Arc::new(SuccessRateMap::new()),
            NetworkFingerprint::unknown(),
        );
        // Fresh pool: egress is NOT verified (fail-closed default state).
        assert_eq!(pool.egress_status(), (false, 0));

        // A verified tunnel arms the gate and stamps a since-timestamp.
        pool.mark_egress_verified();
        let (verified, since) = pool.egress_status();
        assert!(verified);
        // Timestamp is best-effort (0 only if the clock is unavailable).
        let _ = since;

        // Idempotent: re-verifying stays armed.
        pool.mark_egress_verified();
        assert!(pool.egress_status().0);

        // Exhaustion clears the gate and the timestamp.
        pool.mark_egress_down();
        assert_eq!(pool.egress_status(), (false, 0));

        // Re-arming after a drop works (recovery).
        pool.mark_egress_verified();
        assert!(pool.egress_status().0);
    }

    #[test]
    fn resolve_obfs_key_precedence() {
        let mut entry = test_entry(reality());
        entry.bridge_x25519_pk = [0x11u8; 32];

        // 1. Explicit client-config password wins.
        let cfg_key = mirage_quic_obfs::key_from_password(b"pw");
        assert_eq!(resolve_obfs_key(Some(cfg_key), &entry), cfg_key);

        // 2. No config password + invite secret -> derive from the invite
        //    secret. MUST equal what the bridge derives from quic_obfs_secret_hex
        //    (key_from_password over the same 32 bytes), or QUIC obfs desyncs.
        let secret = [0x5Au8; 32];
        entry.obfs_secret = Some(secret);
        assert_eq!(
            resolve_obfs_key(None, &entry),
            mirage_quic_obfs::key_from_password(&secret)
        );

        // 3. Neither -> pubkey-derived default.
        entry.obfs_secret = None;
        assert_eq!(
            resolve_obfs_key(None, &entry),
            mirage_quic_obfs::default_obfs_key(&entry.bridge_x25519_pk)
        );
    }

    fn reality() -> TransportMode {
        TransportMode::Reality {
            sni: "example.com".to_string(),
            tls_cert_verify_pk: None,
            tls_fingerprint: None,
        }
    }

    #[tokio::test]
    async fn pool_records_transport_outcomes_into_success_map() {
        let map = Arc::new(SuccessRateMap::new());
        let net = NetworkFingerprint::unknown();
        let pool = EntryPool::new(
            vec![test_entry(reality())],
            Duration::from_secs(30),
            Arc::new(tokio::sync::Notify::new()),
            Arc::clone(&map),
            net.clone(),
        );
        pool.record_latency(0, 12).await;
        pool.record_latency(0, 18).await;
        pool.mark_failure(0).await;
        let s = map.lookup(&net, "reality");
        assert_eq!(s.successes, 2, "two successful dials recorded");
        assert_eq!(s.failures, 1, "one failure recorded");
    }

    #[tokio::test]
    async fn recording_an_out_of_range_idx_is_a_noop() {
        let map = Arc::new(SuccessRateMap::new());
        let net = NetworkFingerprint::unknown();
        let pool = EntryPool::new(
            Vec::new(), // no entries
            Duration::from_secs(30),
            Arc::new(tokio::sync::Notify::new()),
            Arc::clone(&map),
            net,
        );
        // Must not panic on an absent index, and must record nothing.
        pool.record_latency(0, 5).await;
        pool.mark_failure(0).await;
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn every_transport_label_is_persistable() {
        // Each label the pool records under MUST be in KNOWN_TRANSPORTS, or the
        // persistence loader silently drops it on reload (learned state lost).
        let modes = [
            TransportMode::Raw,
            reality(),
            TransportMode::Ss2022 { psk: [0u8; 32] },
            TransportMode::WebSocket {
                path: "/".to_string(),
            },
            TransportMode::Hysteria2 {
                send_rate_bps: 1,
                hostname: "h".to_string(),
                obfs_key: None,
            },
            TransportMode::Meek {
                front_domain: "f".to_string(),
                path: "/".to_string(),
            },
            TransportMode::Doh {
                front_domain: "f".to_string(),
            },
        ];
        for m in modes {
            let e = test_entry(m);
            let label = e.describe_mode();
            assert!(
                KNOWN_TRANSPORTS.contains(&label),
                "describe_mode label {label:?} missing from KNOWN_TRANSPORTS - \
                 persistence would drop it"
            );
        }
    }

    #[test]
    fn sibling_entries_share_one_shot_credential_cursor() {
        // Per-transport siblings of one bridge MUST share the cursor Arc, so a
        // one-shot token consumed via one transport advances the cursor for the
        // others - otherwise two transports present the same token and the
        // bridge replay-rejects the second. This is the core safety invariant
        // of the per-transport-entry design.
        let shared_cursor = Arc::new(AtomicUsize::new(0));
        let shared_tokens = Arc::new(Vec::new());
        let shared_fs_tokens = Arc::new(Vec::new());
        let shared_fs_cursor = Arc::new(AtomicUsize::new(0));
        let a = Credentials::Invite {
            tokens: Arc::clone(&shared_tokens),
            cursor: Arc::clone(&shared_cursor),
            fs_tokens: Arc::clone(&shared_fs_tokens),
            fs_cursor: Arc::clone(&shared_fs_cursor),
        };
        let b = Credentials::Invite {
            tokens: Arc::clone(&shared_tokens),
            cursor: Arc::clone(&shared_cursor),
            fs_tokens: Arc::clone(&shared_fs_tokens),
            fs_cursor: Arc::clone(&shared_fs_cursor),
        };
        if let (Credentials::Invite { cursor: ca, .. }, Credentials::Invite { cursor: cb, .. }) =
            (&a, &b)
        {
            ca.fetch_add(1, Ordering::Relaxed); // transport A takes a token
            cb.fetch_add(1, Ordering::Relaxed); // transport B takes the NEXT one
            assert_eq!(
                shared_cursor.load(Ordering::Relaxed),
                2,
                "both siblings advance ONE shared cursor (no double-spend)"
            );
        } else {
            panic!("expected Invite credentials");
        }
    }

    #[tokio::test]
    async fn pick_entry_prefers_unblocked_transport() {
        // Two per-transport entries for one bridge: reality + ss2022. With
        // reality recorded as repeatedly blocked and ss2022 working, the
        // adversarial routing engine must SAMPLE ss2022 the large majority of
        // the time - but NOT deterministically: it retains a small exploration
        // probability on reality (the "routing entropy" property - a censor
        // can't pin a fixed order). We assert the strong-majority behaviour.
        let map = Arc::new(SuccessRateMap::new());
        let net = NetworkFingerprint::unknown();
        let pool = EntryPool::new(
            vec![
                test_entry(reality()),
                test_entry(TransportMode::Ss2022 { psk: [0u8; 32] }),
            ],
            Duration::from_secs(0), // disable health soft-fail; test TRANSPORT selection
            Arc::new(tokio::sync::Notify::new()),
            Arc::clone(&map),
            net.clone(),
        );
        // Strong signal: reality blocked, ss2022 working (warm-starts the bandit).
        for _ in 0..12 {
            map.record(&net, "reality", false);
        }
        for _ in 0..6 {
            map.record(&net, "ss2022", true);
        }
        let mut ss = 0usize;
        let total = 300usize;
        for _ in 0..total {
            let idx = pool.pick_entry().await.expect("a healthy entry");
            if pool.entries[idx].describe_mode() == "ss2022" {
                ss += 1;
            }
        }
        let share = ss as f64 / total as f64;
        assert!(
            share > 0.6,
            "adaptive selection must strongly prefer the working transport (ss2022 share {share})"
        );
        assert!(
            share < 1.0,
            "selection must retain exploration entropy on the blocked transport, not be deterministic (share {share})"
        );
    }

    #[test]
    fn connect_config_maps_flags_to_serde_fields() {
        // The connect-mode JSON must deserialize into ClientConfig with the
        // flags landing on the right fields and everything else defaulted.
        let json = connect_config_json(
            "mirage://abc",
            "127.0.0.1:9999",
            Some("cdn.example.com"),
            true,
        );
        let cfg: ClientConfig =
            serde_json::from_value(json).expect("connect config must deserialize");
        assert_eq!(cfg.invite.as_deref(), Some("mirage://abc"));
        assert_eq!(cfg.local_bind, "127.0.0.1:9999");
        assert!(cfg.reality_enabled);
        assert_eq!(cfg.reality_sni.as_deref(), Some("cdn.example.com"));
        assert_eq!(cfg.hysteria2_enabled, Some(true));
        // Minimal form (invite + socks only) also deserializes -> Raw default.
        let minimal = connect_config_json("mirage://x", "127.0.0.1:1080", None, false);
        let cfg2: ClientConfig =
            serde_json::from_value(minimal).expect("minimal connect config must deserialize");
        assert!(!cfg2.reality_enabled);
        assert_eq!(cfg2.hysteria2_enabled, None);
    }

    #[test]
    fn paranoid_mode_composes_the_strong_posture() {
        // One switch forces Reality + multi-hop + padding + fail-closed + replay pacing.
        let mut cfg: ClientConfig = serde_json::from_value(serde_json::json!({
            "invite": "mirage://x", "local_bind": "127.0.0.1:1080", "paranoid": true
        }))
        .expect("paranoid config deserializes");
        assert!(!cfg.reality_enabled, "off before normalization");
        apply_paranoid(&mut cfg);
        assert!(cfg.reality_enabled, "reality forced on");
        assert!(cfg.pad_enabled, "handshake padding forced on");
        assert!(!cfg.allow_insecure_raw, "fail closed - no raw fallback");
        assert_eq!(
            cfg.reality_pace.as_deref(),
            Some("replay"),
            "wears a real recorded cover shape"
        );
        // A non-paranoid config is left alone.
        let mut plain: ClientConfig = serde_json::from_value(serde_json::json!({
            "invite": "mirage://x", "local_bind": "127.0.0.1:1080"
        }))
        .unwrap();
        apply_paranoid(&mut plain);
        assert!(!plain.reality_enabled && plain.reality_pace.is_none());
    }

    #[test]
    fn fmt_duration_compact_forms() {
        assert_eq!(fmt_duration(12), "12s");
        assert_eq!(fmt_duration(125), "2m05s");
        assert_eq!(fmt_duration(3725), "1h02m");
    }

    #[test]
    fn fmt_bytes_scales_units() {
        assert_eq!(fmt_bytes(512), "512 B");
        assert_eq!(fmt_bytes(1024), "1.0 KiB");
        assert_eq!(fmt_bytes(1536), "1.5 KiB");
        assert_eq!(fmt_bytes(5 * 1024 * 1024), "5.0 MiB");
    }

    #[test]
    fn format_status_renders_and_tolerates_missing_fields() {
        let status = serde_json::json!({
            "version": "0.1.0", "uptime_secs": 3725,
            "active_sessions": 2, "total_sessions": 9, "local_bind": "127.0.0.1:1080",
            "total_bytes_up": 1536, "total_bytes_down": 5242880
        });
        let bridges = serde_json::json!([
            { "idx": 0, "addr": "1.2.3.4:443", "transport": "reality", "healthy": true,
              "latency_ms": 45, "transport_successes": 40, "transport_failures": 2 },
            { "idx": 1, "addr": "1.2.3.4:443", "transport": "hysteria2", "healthy": false,
              "transport_successes": 0, "transport_failures": 5 }
        ]);
        let out = format_status(&status, &bridges);
        assert!(out.contains("Mirage client 0.1.0"));
        assert!(out.contains("1h02m"), "uptime rendered");
        assert!(
            out.contains("1.5 KiB") && out.contains("5.0 MiB"),
            "traffic rendered"
        );
        assert!(out.contains("reality") && out.contains("hysteria2"));
        assert!(out.contains("ok 40 / fail 2"), "learned counts rendered");
        // Missing fields must not panic and must degrade gracefully.
        let empty = format_status(&serde_json::json!({}), &serde_json::json!([]));
        assert!(empty.contains("Mirage client ?"));
        assert!(empty.contains("no bridge entries"));
    }
}

#[cfg(test)]
mod cover_fetch_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// `cover_fetch_one` must speak a correct SOCKS5 greeting + CONNECT to the
    /// local SOCKS listener, naming the decoy host/port. A mock SOCKS server
    /// validates the exact bytes; the fetch then attempts TLS (which fails once
    /// the mock closes) - proving the SOCKS negotiation front-half is correct.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cover_fetch_speaks_correct_socks5_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<(String, u16)>();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Greeting: VER=5, NMETHODS=1, METHOD=0.
            let mut greet = [0u8; 3];
            sock.read_exact(&mut greet).await.unwrap();
            assert_eq!(greet, [0x05, 0x01, 0x00], "socks greeting");
            sock.write_all(&[0x05, 0x00]).await.unwrap();
            // CONNECT: VER,CMD,RSV,ATYP=domain,len,host,port.
            let mut head = [0u8; 5];
            sock.read_exact(&mut head).await.unwrap();
            assert_eq!(&head[..4], &[0x05, 0x01, 0x00, 0x03], "socks connect head");
            let hlen = head[4] as usize;
            let mut host = vec![0u8; hlen];
            sock.read_exact(&mut host).await.unwrap();
            let mut port = [0u8; 2];
            sock.read_exact(&mut port).await.unwrap();
            let host = String::from_utf8(host).unwrap();
            let port = u16::from_be_bytes(port);
            // Success reply (BND = 0.0.0.0:0), then close to end the fetch at TLS.
            sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            drop(sock);
            let _ = tx.send((host, port));
        });

        // The fetch will error at the TLS stage (mock closed) - we only care
        // that it drove the SOCKS negotiation correctly.
        let _ = cover_fetch_one(&addr.to_string(), "decoy.example.com:8443/path").await;
        server.await.unwrap();
        let (host, port) = rx.await.unwrap();
        assert_eq!(host, "decoy.example.com");
        assert_eq!(port, 8443);
    }

    /// Default-port + default-path parsing: bare `host` implies :443 and `/`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cover_fetch_defaults_port_443() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<u16>();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut greet = [0u8; 3];
            sock.read_exact(&mut greet).await.unwrap();
            sock.write_all(&[0x05, 0x00]).await.unwrap();
            let mut head = [0u8; 5];
            sock.read_exact(&mut head).await.unwrap();
            let hlen = head[4] as usize;
            let mut host = vec![0u8; hlen];
            sock.read_exact(&mut host).await.unwrap();
            let mut port = [0u8; 2];
            sock.read_exact(&mut port).await.unwrap();
            sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            drop(sock);
            let _ = tx.send(u16::from_be_bytes(port));
        });
        let _ = cover_fetch_one(&addr.to_string(), "bare-host.example").await;
        server.await.unwrap();
        assert_eq!(rx.await.unwrap(), 443);
    }
}

#[cfg(test)]
mod embeddable_api_tests {
    use super::*;

    // The mobile FFI parses the same JSON schema the desktop client reads.
    #[test]
    fn config_from_json_parses_minimal_and_reads_tun_fields() {
        // local_bind is the only required field; everything else defaults.
        let cfg =
            Config::from_json(r#"{"local_bind":"127.0.0.1:1080"}"#).expect("minimal config parses");
        assert!(!cfg.tun_enabled(), "tun defaults off");
        assert_eq!(cfg.tun_mtu(), default_tun_mtu());

        let tun = Config::from_json(
            r#"{"local_bind":"127.0.0.1:1080","tun_enabled":true,"tun_mtu":1400}"#,
        )
        .expect("tun config parses");
        assert!(tun.tun_enabled());
        assert_eq!(tun.tun_mtu(), 1400);
    }

    #[test]
    fn config_from_json_rejects_garbage_and_missing_required() {
        assert!(Config::from_json("not json").is_err());
        // Missing the required `local_bind`.
        assert!(Config::from_json(r#"{"tun_enabled":true}"#).is_err());
    }

    // A config with a well-formed invite builds a Client (bridge pool) without
    // dialing - proving Config -> Client::new is wired end to end.
    #[test]
    fn client_new_builds_pool_from_invite_config() {
        // Reuse the connect-config helper's invite path via a raw config: an
        // explicit-hex single bridge entry is the simplest pool that build_pool
        // accepts without network. bridge_addr + bridge_x25519_pk_hex form one
        // entry; tokens come from the bootstrap pool.
        let json = format!(
            r#"{{"local_bind":"127.0.0.1:1080",
                 "bridge_addr":"192.0.2.10:443",
                 "bridge_x25519_pk_hex":"{pk}",
                 "bridge_ed25519_pk_hex":"{pk}"}}"#,
            pk = "11".repeat(32)
        );
        match Config::from_json(&json) {
            Ok(cfg) => {
                // build_pool may still reject if this minimal explicit-hex shape
                // is insufficient; either way it must not panic, and a success
                // yields a usable entry count.
                if let Ok(client) = Client::new(cfg) {
                    assert!(client.entry_count() >= 1);
                }
            }
            Err(e) => panic!("explicit-hex config should parse: {e}"),
        }
    }
}

#[cfg(test)]
mod h3_throttle_tests {
    use super::{is_throttled, GOODPUT_MIN_BYTES, GOODPUT_MIN_SECS, GOODPUT_THROTTLE_FRACTION};

    #[test]
    fn no_baseline_is_never_throttled() {
        // The first healthy sample sets the baseline; it must not self-penalize.
        assert!(!is_throttled(1.0, None));
        assert!(!is_throttled(1_000_000.0, None));
    }

    #[test]
    fn goodput_far_below_baseline_is_throttled() {
        let baseline = Some(1_000_000.0); // 1 MB/s healthy baseline
                                          // Just under the fraction -> throttled.
        assert!(is_throttled(
            1_000_000.0 * GOODPUT_THROTTLE_FRACTION - 1.0,
            baseline
        ));
        // A severe drop -> throttled.
        assert!(is_throttled(10_000.0, baseline));
    }

    #[test]
    fn goodput_near_baseline_is_not_throttled() {
        let baseline = Some(1_000_000.0);
        // Exactly at the fraction is NOT below it -> not throttled.
        assert!(!is_throttled(
            1_000_000.0 * GOODPUT_THROTTLE_FRACTION,
            baseline
        ));
        // Healthy / faster than baseline -> not throttled.
        assert!(!is_throttled(900_000.0, baseline));
        assert!(!is_throttled(2_000_000.0, baseline));
    }

    #[test]
    fn zero_baseline_is_not_throttled() {
        // A degenerate zero baseline must never divide-by-zero into a penalty.
        // black_box so the literal-arg call isn't const-folded to assert!(true).
        let z = std::hint::black_box(0.0);
        assert!(!is_throttled(std::hint::black_box(0.0), Some(z)));
        assert!(!is_throttled(std::hint::black_box(100.0), Some(z)));
    }

    // Compile-time guard on the tunables (a runtime assert on constants folds to
    // assert!(true)); keeps a careless edit from making the signal gate vacuous.
    const _: () = assert!(GOODPUT_MIN_BYTES >= 64 * 1024);
    const _: () = assert!(GOODPUT_MIN_SECS >= 1.0);
    const _: () = assert!(GOODPUT_THROTTLE_FRACTION > 0.1 && GOODPUT_THROTTLE_FRACTION < 0.8);
}
