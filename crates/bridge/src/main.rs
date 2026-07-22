//! Mirage bridge daemon.
//!
//! Listens on a configured TCP port; every accepted Mirage session
//! runs a **SOCKS5 server** on the decrypted byte stream. The client
//! app (any SOCKS5-compatible tool - curl, a browser, an MTA) sees
//! a CONNECT-capable SOCKS5 proxy at `mirage-client`'s local bind;
//! the bridge is where the SOCKS5 server actually runs, so the
//! client is an encrypted transparent forwarder.
//!
//! # MVP scope (v0.1)
//!
//! - **No Reality-v2 TLS carrier yet**. The bridge speaks raw Mirage
//!   session frames directly over TCP. Reality-v2's ClientHello-
//!   masquerade wraps this in a follow-up iteration. Until then the
//!   wire is trivially fingerprintable - use on hostile networks
//!   only for protocol-functional testing.
//! - **No dynamic announcement publishing**. Operators publish
//!   announcements with the `mirage-discovery::OperatorPublisher`
//!   separately; the bridge itself does not push its own location.
//! - **In-memory replay set**. A restart loses replay state, within
//!   which a previously-used token could be replayed. Acceptable for
//!   v0.1; persistent set lands with the operator-tooling iteration.
//! - **Process hardening** via `mirage_common::process_hardening::
//!   harden_process` at the very first line of main so a panic
//!   before we finish setup cannot core-dump keys.
//! - **Default-deny SOCKS5 policy**. Out of the box the bridge
//!   refuses to CONNECT to loopback, link-local, RFC 1918, and ULA
//!   targets so a fresh operator deployment cannot be weaponized
//!   as an internal-network scanner. Operators can loosen this
//!   via config.
//!
//! # Configuration
//!
//! JSON file (path passed as the sole CLI arg):
//!
//! ```json
//! {
//!   "bind": "0.0.0.0:8443",
//!   "bridge_x25519_sk_hex": "...64 hex...",
//!   "bridge_ed25519_pk_hex": "...64 hex...",
//!   "operator_ed25519_pk_hex": "...64 hex...",
//!   "replay_capacity": 65536,
//!   "handshake_timeout_secs": 10,
//!   "max_concurrent_sessions": 4096,
//!   "socks5_connect_timeout_secs": 10,
//!   "allow_private_network_targets": false,
//!   "allow_loopback_targets": false
//! }
//! ```

mod admin;
mod claim_log;
mod metrics;
mod rate_limit;

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use std::collections::{HashMap, HashSet};

use crate::metrics::{
    serve_metrics, Metrics, TRANSPORT_MEEK, TRANSPORT_OBFS_TCP, TRANSPORT_RAW, TRANSPORT_REALITY,
    TRANSPORT_SS2022, TRANSPORT_VLESS, TRANSPORT_WS,
};
use crate::rate_limit::PerPeerLimiter;

// Cohort cooperation stack (Phase 2N / alpha wiring).
use mirage_bridge::{
    BridgeCircuitExecutor, BridgeCircuitKeys, CohortDistressMonitor, CohortHeartbeat,
    CohortReplayCoordinator, ConnectionGatekeeper, DistressMonitorConfig, DistressSensor,
    GatekeeperConfig, HeartbeatConfig, LivePeerTracker, PeerDistressMap, SessionNextHopDialer,
    SessionTask, SessionTaskConfig,
};
use mirage_common::process_hardening::harden_process;
use mirage_crypto::x25519_dalek::{PublicKey, StaticSecret};
use mirage_discovery::claim::{
    ClaimRequest, ClaimResponse, CLAIM_MAGIC_HOSTNAME, CLAIM_MAGIC_PORT,
    CLAIM_STATUS_ALREADY_CLAIMED, CLAIM_STATUS_CAPACITY, CLAIM_STATUS_INTERNAL, CLAIM_STATUS_OK,
    CLAIM_STATUS_POLICY,
};
use mirage_discovery::cohort::{
    CohortRequest, CohortResponse, COHORT_MAGIC_HOSTNAME, COHORT_MAGIC_PORT,
    COHORT_MAX_N_PER_REQUEST, COHORT_STATUS_EMPTY, COHORT_STATUS_EXHAUSTED,
    DEFAULT_PER_TOKEN_REVEAL_CAP,
};
use mirage_discovery::refresh::{
    sign_refresh_token, RefreshRequest, RefreshResponse, REFRESH_MAGIC_HOSTNAME,
    REFRESH_MAGIC_PORT, REFRESH_MAX_PER_REQUEST, REFRESH_STATUS_EXHAUSTED, REFRESH_STATUS_POLICY,
};
use mirage_discovery::replay::SyncReplaySet;
use mirage_discovery::wire::Announcement;
use mirage_mux::{MuxConnection, MuxPolicy, StreamRole, MUX_SESSION_TAG};
use mirage_session::{
    accept_with_peer_static, TokenVerifier, UdpFramer, MAX_UDP_DATAGRAM_BYTES,
    UDP_RELAY_MAGIC_HOSTNAME, UDP_RELAY_MAGIC_PORT,
};
use mirage_socks5::{
    connect_and_reply, connect_target, decode_udp_dgram, encode_udp_dgram, read_request,
    send_success_reply_for_internal, AllowlistPolicy, ConnectTarget, Socks5UdpDest,
};
use mirage_transport::DuplexStream;
use mirage_transport_hysteria2::{Hysteria2Server, Hysteria2ServerConfig};
use mirage_transport_mux::{MuxConfig, MuxResult, PrefixedStream, ProtocolMux};
use mirage_transport_pad::{PadConfig, PaddedStream};
use mirage_transport_reality::{
    reality_accept, AcceptOutcome, BridgeCarrierInputs, ReplayProbeSet,
};
use serde::Deserialize;
use tokio::io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

/// On-disk configuration file for a bridge daemon.
// No `Debug`: this struct holds the bridge's long-term X25519 + Ed25519 secret
// keys (as hex). Deriving Debug would let a stray `debug!(?config)` or a
// panic-formatted value dump the master secrets into journald/backups. Omitting
// it makes any such attempt a compile error.
#[derive(Deserialize)]
struct BridgeConfig {
    /// `host:port` the bridge listens on for client tunnels.
    bind: String,
    /// Bridge's X25519 static secret (hex, 32 bytes).
    bridge_x25519_sk_hex: String,
    /// Bridge's Ed25519 identity pubkey (hex, 32 bytes). MUST match
    /// the pubkey the operator signs capability tokens against.
    bridge_ed25519_pk_hex: String,
    /// Bridge's Ed25519 identity SECRET (hex, 32 bytes). Required to
    /// mint session refresh tokens ([`mirage_discovery::refresh`])
    /// and for future operator-delegated signing roles. Optional
    /// only when `refresh_enabled = false` AND no other feature
    /// needs the bridge to produce Ed25519 signatures.
    #[serde(default)]
    bridge_ed25519_sk_hex: Option<String>,
    /// Operator's Ed25519 verifying key (hex, 32 bytes). Trust anchor
    /// for capability-token signatures.
    operator_ed25519_pk_hex: String,
    /// PREVIOUS operator Ed25519 verifying key (hex, 32 bytes),
    /// accepted during a mother-key rotation overlap window
    /// (v0.1i). When set, capability tokens signed by this key
    /// also verify - covers invites minted before the rotation.
    /// Remove from config after the overlap ends.
    #[serde(default)]
    operator_ed25519_pk_prev_hex: Option<String>,
    /// Maximum replay-set entries. Default 65536.
    #[serde(default = "default_replay_capacity")]
    replay_capacity: usize,
    /// Per-connection handshake deadline (seconds). Default 10.
    #[serde(default = "default_handshake_timeout_secs")]
    handshake_timeout_secs: u64,
    /// Maximum concurrent sessions. A bridge that blows past this
    /// cap applies TCP-level backpressure - new `accept()`s happen
    /// only as existing sessions close. Default 4096.
    #[serde(default = "default_max_concurrent_sessions")]
    max_concurrent_sessions: usize,
    /// Per-SOCKS5-CONNECT deadline (seconds). Default 10.
    #[serde(default = "default_socks5_connect_timeout_secs")]
    socks5_connect_timeout_secs: u64,
    /// If true, the bridge will proxy to targets in RFC 1918 / ULA
    /// / link-local / CGNAT. Default false - loud opt-in for
    /// operators who intentionally expose an internal network.
    #[serde(default)]
    allow_private_network_targets: bool,
    /// If true, the bridge will proxy to loopback targets on its
    /// own host. Default false. Enables using the bridge itself as
    /// a local exit for services on the bridge host; also a
    /// footgun for operators who didn't mean to.
    #[serde(default)]
    allow_loopback_targets: bool,
    /// If true, per-session INFO logs replace the SOCKS5 target with
    /// `<anonymized>`. The operator sees session lifecycle events
    /// but not "which client asked for which site." Default TRUE -
    /// privacy is the default posture for a Mirage bridge. Operators
    /// running an audit-focused deployment can set this false.
    ///
    /// NOTE: this covers the *destination* only. Client identity is governed
    /// separately by [`anonymize_client_logs`].
    #[serde(default = "default_anonymize_target_logs")]
    anonymize_target_logs: bool,
    /// If true (the DEFAULT), client IP addresses are never written to logs: a
    /// per-run-salted, irreversible opaque `client-xxxxxxxx` label is logged
    /// instead. This keeps session-lifecycle logs useful (a given client's lines
    /// share one label within a run) while ensuring a **seized bridge with
    /// retained logs cannot reveal which clients connected** - which is itself
    /// incriminating for a user in a censored region, even with the destination
    /// redacted. Set false to log raw client IPs (opt-in; only with a lawful
    /// need AND explicit disclosure to users).
    #[serde(default = "default_true")]
    anonymize_client_logs: bool,

    // ---- Reality transport (v0.1a) ----
    /// If true, the bridge requires an incoming Reality auth probe
    /// before running the Mirage session handshake. Clients without
    /// a valid probe are transparently forwarded to `cover_addr`.
    /// Default false: the bridge speaks raw Mirage frames directly
    /// on TCP (the MVP mode).
    #[serde(default)]
    reality_enabled: bool,

    /// PARANOID MODE (Proteus), bridge side. One switch: forces Reality on, strict
    /// anti-probe (rejects legacy probes), and REPLAY pacing so authenticated sessions
    /// wear a real recorded video-streaming shape. Overrides the individual switches.
    /// Clients must also run paranoid/replay for the pacing to match.
    #[serde(default)]
    paranoid: bool,
    /// Envelope pacing mode for authenticated Reality sessions: `video`/`browse` or
    /// `replay` (wear a real captured trace - recommended). Config equivalent of
    /// `MIRAGE_REALITY_PACE`. Paranoid mode sets this to `replay`.
    #[serde(default)]
    reality_pace: Option<String>,
    /// For `reality_pace = "replay"`: a trace file, or a directory library of real
    /// traces (one is chosen per session; keep it fresh with tools/cover-sources).
    /// Config equivalent of `MIRAGE_REALITY_PACE_PROFILE`.
    #[serde(default)]
    reality_pace_profile: Option<String>,
    /// `host:port` of the cover destination for unauthenticated
    /// peers. Required if `reality_enabled = true` AND
    /// [`Self::reality_cover_addrs`] is empty. Operators typically
    /// pick a real HTTPS endpoint that serves real traffic (a
    /// popular CDN tenant, `www.example.com:443`, etc.) so active
    /// probes see indistinguishable behavior.
    ///
    /// **Single-cover deployments are operationally fragile** - the
    /// IP-fanout signature (every accept on this bridge IP triggers
    /// exactly one outbound TLS to the same cover IP) is a passive
    /// flow-correlation distinguisher. Prefer `reality_cover_addrs`
    /// for production.
    #[serde(default)]
    reality_cover_addr: Option<String>,
    /// Pool of cover destinations. When non-empty, supersedes
    /// `reality_cover_addr` (it is concatenated for backward
    /// compatibility) and the bridge picks uniformly at random per
    /// incoming ClientHello. >= 4 entries recommended; >= 2 minimum
    /// for any meaningful decorrelation.
    ///
    /// Each entry is `host:port`. Resolved at bridge startup; if a
    /// resolution fails the bridge logs and skips that entry. If
    /// the resolved pool is empty after merging this list with
    /// `reality_cover_addr`, the bridge fails to start.
    ///
    /// Audit fix (analyst finding #1): IP-fanout flow correlation.
    #[serde(default)]
    reality_cover_addrs: Vec<String>,

    // ---- obfs-tcp transport (v0.1t) ----
    /// If true, the bridge accepts obfs-tcp connections on
    /// [`Self::obfs_bind`]. obfs-tcp is the T1-grade signature-DPI
    /// bypass transport. Complementary to Reality (which
    /// fits T2 active-prober). Operators advertise the
    /// `transport_caps::OBFS_TCP` bit in their announcement when
    /// this is set.
    #[serde(default)]
    obfs_enabled: bool,
    /// `host:port` for the obfs-tcp listener. Defaults to
    /// `0.0.0.0:8443` if unset and `obfs_enabled = true`.
    #[serde(default)]
    obfs_bind: Option<String>,

    // ---- Protocol multiplexer (v0.2 transport integration) ----
    /// Enable Shadowsocks-2022 carrier. If set, bridges accept SS-2022
    /// connections classified by the protocol mux.
    #[serde(default)]
    pub ss2022_psk_hex: Option<String>,

    /// Enable VLESS transport. If set, the protocol mux will attempt
    /// VLESS auth for opaque connections. Value is a hex-encoded 16-byte
    /// UUID (32 hex chars, no hyphens).
    #[serde(default)]
    pub vless_uuid_hex: Option<String>,

    /// Enable WebSocket transport. When true the mux routes
    /// HTTP-upgrade connections to the WS/meek handler.
    #[serde(default)]
    pub ws_enabled: bool,

    /// Enable the WebRTC carrier signaling endpoint. When true the mux routes
    /// `application/sdp` POSTs to the WebRTC offer/answer handler; the session
    /// then rides a DTLS-SCTP data channel over UDP.
    #[serde(default)]
    pub webrtc_enabled: bool,

    /// STUN/TURN servers the bridge advertises for ICE (empty = default STUN /
    /// host candidates). Used when `webrtc_enabled` is set.
    #[serde(default)]
    pub webrtc_ice_servers: Vec<String>,

    /// Enable the traffic-padding and timing-jitter layer (T3 defence).
    ///
    /// When `true` every accepted session stream is wrapped with
    /// [`mirage_transport_pad::PaddedStream`] before the Mirage Noise
    /// handshake runs. Clients **must** have `pad_enabled: true` in their
    /// config as well - the padding protocol is symmetric.
    ///
    /// Default mode (when `pad_cbr_frame_bytes` is unset): up to 5 ms
    /// jitter + 200 ms chaff interval.
    /// CBR mode (when `pad_cbr_frame_bytes` is set): see that field.
    #[serde(default = "default_true")]
    pub pad_enabled: bool,

    /// When `true` (default), a session whose first plaintext byte is the mux
    /// tag (`0x00`) is treated as a multiplexed carrier: many client streams
    /// ride the one authenticated session, each opening a target via a mux
    /// `Begin` frame. This is what lets one browser (100-300 parallel
    /// connections) hold O(1) per-IP concurrency slots + O(1) handshakes/tokens
    /// instead of O(connections). Clients **must** have `mux_enabled: true`
    /// too. Legacy single-request SOCKS sessions (`0x05` first byte) are
    /// unaffected and still accepted, so this is backward compatible. (Named
    /// `stream_mux_enabled` to avoid collision with `mux_enabled`, which gates
    /// the unrelated single-port multi-transport ProtocolMux.)
    ///
    /// Amplification note: with mux, one carrier (= one per-IP concurrency slot)
    /// drives up to 256 streams, so the effective per-IP upstream-connect
    /// ceiling is `max_concurrent_per_ip x 256`. That is the intended trade-off -
    /// a real browser needs hundreds of concurrent streams - but an operator
    /// worried about a single-IP flood should size `max_concurrent_per_ip` and
    /// the process fd `ulimit` accordingly.
    #[serde(default = "default_true")]
    pub stream_mux_enabled: bool,

    /// Constant-bitrate frame size for the padding layer (bytes).
    ///
    /// When set, `pad_enabled` uses CBR mode: one frame of exactly this
    /// size is sent every `pad_cbr_interval_ms` milliseconds, filling idle
    /// bandwidth with CSPRNG noise.  Wire bitrate (bps) =
    /// `pad_cbr_frame_bytes x 8000 / pad_cbr_interval_ms`.
    ///
    /// `None` (default) - event-driven mode (jitter + chaff).
    #[serde(default)]
    pub pad_cbr_frame_bytes: Option<usize>,

    /// CBR inter-frame interval in milliseconds. Default 10.
    /// Only meaningful when `pad_cbr_frame_bytes` is set.
    #[serde(default = "default_pad_cbr_interval_ms")]
    pub pad_cbr_interval_ms: u64,

    /// Enable protocol mux (single-port multi-transport dispatch).
    /// Default true - the mux runs on every primary/derived listener
    /// TCP connection and dispatches by first-bytes classification.
    #[serde(default = "default_true")]
    pub mux_enabled: bool,
    /// Deadline for reading the ClientHello. Default 10 s.
    #[serde(default = "default_reality_ch_timeout_secs")]
    reality_client_hello_timeout_secs: u64,
    /// Hard cap on how long the bridge will shuttle cover-service
    /// bytes after an auth failure. Default 30 s - enough that a
    /// real HTTPS session completes, short enough that a flood of
    /// junk connections doesn't tie up the bridge indefinitely.
    #[serde(default = "default_reality_cover_cap_secs")]
    reality_cover_duration_cap_secs: u64,
    /// Reality anti-probe epoch binding: when `true` (default), the bridge also
    /// accepts legacy (pre-epoch-binding) auth probes so clients holding
    /// pre-extension invites keep working during a rollover. Set `false` once
    /// the client population has fresh invites to CLOSE pubkey-only bridge
    /// enumeration - a censor who scraped the public announcement can build a
    /// legacy probe but not the invite-only epoch-bound one. Ignored on bridges
    /// whose static key predates the extension (they have no root anyway).
    #[serde(default = "default_reality_probe_accept_legacy")]
    reality_probe_accept_legacy: bool,
    /// TLS identity mode (Reality v0.1c+):
    ///
    /// - `ephemeral` (default): bridge mints a fresh Ed25519
    ///   keypair + self-signed cert each session. Client verifies
    ///   CertVerify against the cert's SPKI. Handshake completes
    ///   for Mirage clients; fails chain-validation for strict CA
    ///   probers.
    /// - `pinned`: operator provides raw DER cert bytes + an
    ///   Ed25519 signing key. The cert is served verbatim each
    ///   session; CertVerify signs with the provided key. Client
    ///   verifies against the invite-published
    ///   `tls_cert_verify_pk`. Use this for cover-cert mimicry
    ///   (point the cert at a real site's cert bytes) OR for
    ///   custom CA-signed cert+key pairs (chain validates).
    /// - `borrow` (H1): like `pinned`, but the DER cert is fetched
    ///   AUTOMATICALLY from `reality_cover_addr` at startup (no
    ///   `reality_tls_cert_der_path` needed) so the served cert
    ///   MATCHES the cover a censor sees when fetching it directly
    ///   (passive cert-comparison parity). Still requires
    ///   `reality_tls_signing_sk_hex` (the stable key the invite's
    ///   `tls_cert_verify_pk` pins); CertVerify is signed with it, so
    ///   an ACTIVE CertVerify probe still diverges (documented residual).
    #[serde(default)]
    reality_tls_mode: Option<String>,
    /// Path to DER-encoded X.509 cert bytes. Required if
    /// `reality_tls_mode = "pinned"`. Use `mirage-cover-fetch`
    /// to grab a real host's cert, or convert your own via
    /// `openssl x509 -outform der -in cert.pem -out cert.der`.
    #[serde(default)]
    reality_tls_cert_der_path: Option<String>,
    /// Hex-encoded Ed25519 signing private key. Required if
    /// `reality_tls_mode = "pinned"`. This key must correspond
    /// to the pubkey the operator published in the invite's
    /// `tls_cert_verify_pk` field.
    #[serde(default)]
    reality_tls_signing_sk_hex: Option<String>,

    // ---- Cohort service ----
    /// Path to a JSON file holding a list of signed bridge
    /// announcements this bridge is willing to share with
    /// authenticated clients (see `mirage-discovery::cohort`).
    /// Default: no cohort - an unconfigured bridge responds
    /// EMPTY to every cohort request.
    #[serde(default)]
    cohort_announcements_path: Option<String>,
    /// Per-invite-token lifetime cap on unique bridges revealed
    /// through the cohort service. Counting is in-memory; a bridge
    /// restart resets per-token counters. Default 8.
    #[serde(default = "default_cohort_reveal_cap")]
    cohort_reveal_cap_per_token: u8,
    /// Maximum size of the random subtraction applied to each
    /// cohort response's count. Without this, a bridge that
    /// always returns exactly N would itself be a traffic-shape
    /// fingerprint ("the bridge-at-1.2.3.4 always returns 4 on
    /// request of 4"). With jitter J, each response returns
    /// `U[1, max_n] - U[0, J]`, clamped to `[1, max_n]` and the
    /// remaining reveal budget. Default 3. Set to 0 to disable
    /// jitter (NOT recommended).
    #[serde(default = "default_cohort_reveal_jitter")]
    cohort_reveal_jitter: u8,

    // ---- Session refresh tokens (v0.1d) ----
    /// Enable the in-band refresh-token issuer
    /// ([`mirage_discovery::refresh`]). When true the bridge
    /// accepts refresh tokens at session handshake AND intercepts
    /// SOCKS5 CONNECTs to [`REFRESH_MAGIC_HOSTNAME`] to mint fresh
    /// ones. Default true - there is no downside to running it,
    /// and operators often want long-lived clients not to run out
    /// of handshake credentials.
    #[serde(default = "default_refresh_enabled")]
    refresh_enabled: bool,
    /// Max refresh tokens a single root (bootstrap or prior
    /// refresh) token can ever mint through this bridge. In-memory;
    /// resets on bridge restart. Default 16.
    #[serde(default = "default_refresh_per_root_cap")]
    refresh_per_root_cap: u8,
    /// TTL applied to newly-minted refresh tokens (seconds).
    /// Shorter is safer. Default 6 h.
    #[serde(default = "default_refresh_ttl_seconds")]
    refresh_ttl_seconds: u64,

    // ---- Per-invite claim (v0.1e) ----
    /// Enable the per-invite redemption service
    /// ([`mirage_discovery::claim`]). When true the bridge
    /// intercepts SOCKS5 CONNECTs to
    /// `_mirage_claim._internal` and enforces a local set of
    /// already-claimed invite ids. Default true.
    #[serde(default = "default_claim_enabled")]
    claim_enabled: bool,
    /// Maximum number of distinct claim ids the bridge will remember
    /// before rejecting new claims with `CAPACITY`. Default
    /// 1_000_000 - generous for most operators.
    #[serde(default = "default_claim_capacity")]
    claim_capacity: usize,
    /// Path to the on-disk claim log. When set, every accepted
    /// claim_id is mirrored to this file; a bridge restart reloads
    /// the file so the one-claim-per-invite invariant survives
    /// reboots. `None` (default) = in-memory only (pre-v0.1t
    /// behavior). B1-invariant honesty - without this set,
    /// "stateless seizure-resilience" is partly aspirational and
    /// claim re-redemption is a known reset-on-restart vector.
    #[serde(default)]
    claim_log_path: Option<String>,
    /// If true, `fsync` after every claim-log append. Same trade-
    /// off as `replay_log_fsync`: ~1ms/claim cost, durability
    /// under kernel crash. Default false (rare claims; cron-
    /// scheduled fsync is enough).
    #[serde(default)]
    claim_log_fsync: bool,

    // ---- Persistent replay set (v0.1g, A14b) ----
    /// Path to the on-disk replay log. When set, capability-token
    /// acceptance is mirrored to this file; a bridge restart
    /// reloads it and the single-use invariant survives reboots.
    /// `None` (default) = in-memory only (pre-v0.1g behavior).
    #[serde(default)]
    replay_log_path: Option<String>,
    /// If true, `fsync` after every replay-log append. Trades
    /// ~1 ms per handshake for kernel-crash / power-loss
    /// durability. Default false - flush-to-OS-page-cache only,
    /// which survives userspace crashes but not hardware events.
    #[serde(default)]
    replay_log_fsync: bool,

    // ---- Info-hash-derived port hopping (v0.1o, A35) ----
    /// Shared salt for port derivation, hex-encoded 32 bytes.
    /// MUST match the `master_invite`'s `shared_salt` so client +
    /// bridge derive the same port. Typically copied from the
    /// keygen JSON; operators who rotate the salt mid-deployment
    /// must restart bridges with the new value.
    #[serde(default)]
    derived_port_shared_salt_hex: Option<String>,
    /// Lower bound of the derived-port range (>= 1024). When set
    /// alongside `derived_port_range`, the bridge ALSO listens on
    /// the current epoch's derived port + the next epoch's, in
    /// addition to `bind`. Default: feature off (bridge listens
    /// only on `bind`).
    #[serde(default)]
    derived_port_base: Option<u16>,
    /// Width of the derived-port range. Larger = more rotation
    /// entropy (and more collateral cost for a censor blocking
    /// the whole range). Typical values: 100-8192.
    #[serde(default)]
    derived_port_range: Option<u16>,
    /// Bind host for the derived ports. Defaults to the host part
    /// of `bind`. Operators rarely need to override.
    #[serde(default)]
    derived_port_bind_host: Option<String>,

    // ---- Metrics / observability (v0.1j, I8) ----
    /// `host:port` to bind the Prometheus text-exposition endpoint
    /// on. `None` disables the endpoint. Operators SHOULD bind to
    /// a loopback or management-network address - the endpoint
    /// exposes bridge internals (counters, status distributions)
    /// and is not intended for public consumption.
    #[serde(default)]
    metrics_bind: Option<String>,

    /// `host:port` for the in-process operator admin UI (a small local web app
    /// to view live counters, edit this config, and restart the service). `None`
    /// disables it. MUST be loopback (e.g. `127.0.0.1:3825`) - it can READ and
    /// WRITE the config. The `--admin-ui [addr]` CLI flag enables it too (bare
    /// flag defaults to `127.0.0.1:3825`) and overrides this field.
    #[serde(default)]
    admin_bind: Option<String>,

    /// systemd unit name the admin UI's "Restart" action targets. Defaults to
    /// `mirage-bridge` (the unit `mirage-setup` installs).
    #[serde(default = "default_admin_service")]
    admin_service: String,

    // ---- Per-source-IP rate limit (v0.1f, A21) ----
    /// Max new TCP connections accepted per source IP per minute.
    /// The bucket burst-size equals the per-minute budget (a client
    /// that's been idle can reconnect up to this many times in a
    /// burst, then must wait for refill). 0 disables rate-limiting.
    /// Default 60 - one per second, plenty for legitimate usage,
    /// cuts flood-based probing.
    #[serde(default = "default_rate_limit_per_minute")]
    rate_limit_per_ip_per_minute: u32,
    /// Max concurrent sessions per source IP. A connection beyond
    /// this cap is dropped at TCP-accept. 0 disables. Default 32.
    #[serde(default = "default_max_concurrent_per_ip")]
    max_concurrent_per_ip: usize,
    /// Soft cap on the total number of source IPs tracked by the
    /// rate limiter. When exceeded, the oldest-seen idle entry is
    /// evicted. Default 65536.
    #[serde(default = "default_rate_limit_max_entries")]
    rate_limit_max_entries: usize,

    // ---- Cohort P2P gossip (alpha) ----
    //
    // When `gossip_bind` is set the bridge listens for inbound gossip
    // connections from other cohort members. When `gossip_peers` is
    // non-empty the bridge also dials each listed peer at startup and
    // maintains a persistent outbound connection.
    //
    // Gossip uses the bridge's existing Ed25519 signing key
    // (`bridge_ed25519_sk_hex`) - no separate key required. If
    // `bridge_ed25519_sk_hex` is absent and `gossip_bind` is set the
    // bridge logs a warning and disables gossip.
    //
    // All four cooperation paths are wired when gossip is enabled:
    //   - `ConnectionGatekeeper` propagates `ProbeScanDetected` and
    //     soft-blocks IPs flagged by any peer.
    //   - `CohortReplayCoordinator` publishes `TokenBurned` after
    //     each successful session handshake so peers pre-empt replay.
    //   - `CohortDistressMonitor` tracks session-semaphore fill and
    //     publishes `EntryDistressed` when load crosses 80 %.
    //   - `CohortHeartbeat` sends periodic `CohortMembership` events
    //     so each bridge knows its peers are alive.
    /// TCP `host:port` the bridge listens for inbound gossip from
    /// cohort peers. `None` (default) - gossip disabled entirely.
    #[serde(default)]
    gossip_bind: Option<String>,
    /// Addresses of cohort peers to dial at startup.
    /// Format: `["1.2.3.4:9443", "[::1]:9443"]`.
    /// The bridge reconnects automatically on disconnect.
    #[serde(default)]
    gossip_peers: Vec<String>,
    /// Auth-failure threshold before a source IP is flagged as a
    /// probe scanner and published via gossip. Default 5.
    #[serde(default = "default_gossip_probe_threshold")]
    gossip_probe_threshold: u32,
    /// Ed25519 pubkeys of authorized cohort peers, hex-encoded
    /// (32 bytes each). Events from any other publisher are
    /// dropped before processing. Must include every bridge in
    /// the cohort, including this bridge's own pubkey.
    /// Example: `["a1b2c3...64hex...", "d4e5f6...64hex..."]`
    #[serde(default)]
    gossip_authorized_peer_pks: Vec<String>,
    /// Suppress the public-bind safety warning for gossip. Default
    /// false: the bridge emits a `tracing::warn!` whenever
    /// `gossip_bind` resolves to a non-loopback, non-RFC-1918
    /// address. Set to `true` if you have firewall rules in place
    /// and want to silence the noise.
    #[serde(default)]
    gossip_bind_public_ok: bool,
    /// Cohort-wide secret (32 bytes, hex-encoded) for the cross-bridge
    /// **leaked-invite detector**. Every bridge in the cohort MUST be
    /// configured with the SAME key. When present (and gossip is
    /// active), the bridge publishes a privacy-preserving keyed tag of
    /// each accepted claim id, and correlates peers' tags to flag an
    /// invite claimed at more than one bridge (a leaked/shared invite).
    /// Absent -> the leak detector is disabled; no claim tags are
    /// published or correlated. Generate with
    /// `openssl rand -hex 32`. Independent of `bridge_ed25519_sk_hex`.
    #[serde(default)]
    cohort_claim_tag_key_hex: Option<String>,
    /// Equivocation window (seconds) for the leaked-invite detector: a
    /// claim tag must be observed from two or more distinct bridges
    /// within this span to raise an alert. Wider catches slow-spreading
    /// leaks but raises the roaming false-positive rate; narrower flags
    /// only near-concurrent misuse. Unset -> the library default
    /// (`mirage_bridge::DEFAULT_LEAK_WINDOW`, 24 h). Only meaningful
    /// when `cohort_claim_tag_key_hex` is set.
    #[serde(default)]
    cohort_leak_window_secs: Option<u64>,

    // ---- Active-probe resistance: shadow target ----
    /// `host:port` to forward unrecognised TCP connections to.
    ///
    /// When the protocol mux cannot classify an incoming connection
    /// (no recognised transport signature in the first bytes), the bridge
    /// normally silently drops it - an obvious fingerprint for active probers.
    /// With `shadow_target` set the bridge instead opens a TCP connection to
    /// the target and splices bytes bidirectionally, making it
    /// indistinguishable from a real HTTP/HTTPS server to external scanners.
    ///
    /// Pick a real, always-reachable host: `1.1.1.1:443`, a CDN IP, a
    /// popular site's TCP endpoint.  The shadow target receives the raw
    /// bytes from the prober and its responses are relayed back - so the
    /// prober sees a real TLS negotiation, real HTTP responses, or whatever
    /// the target speaks.
    ///
    /// Duration cap: shadow connections are limited to
    /// `reality_cover_duration_cap_secs` (default 30 s) so a flood of
    /// junk connections cannot hold bridge threads indefinitely.
    #[serde(default)]
    shadow_target: Option<String>,

    /// Plaintext-HTTP shadow/decoy for FAILED probes on the HTTP-bearing
    /// transports (WebSocket / meek / DoH). Distinct from `shadow_target`
    /// (which raw-splices and may point at a TLS endpoint): when a prober
    /// fails auth over an HTTP transport, the bridge replays the prober's
    /// EXACT request to this backend so it returns a genuine 200/403/404 -
    /// byte-identical to probing the decoy directly. MUST speak plaintext
    /// HTTP/1.1 (e.g. a local nginx, or a reverse-proxy to a real site).
    ///
    /// Unset => failed HTTP probes are dropped (and the IP is probe-scored).
    /// A connection that IS shadow-forwarded is NEVER probe-scored - once the
    /// bridge commits to mimicking the decoy it must behave exactly like the
    /// decoy, which never soft-blocks; soft-blocking would let the prober's
    /// next connection get a bare pre-read drop, re-introducing the very
    /// bridge-vs-decoy fingerprint shadow-forwarding exists to remove.
    #[serde(default)]
    http_shadow_target: Option<String>,

    // ---- Hysteria2 transport (v0.2) ----
    /// UDP `host:port` for the Hysteria2 QUIC listener. Hysteria2 runs
    /// on UDP, separate from the TCP primary listener. Example:
    /// `"0.0.0.0:8443"` - sharing port 8443 with the TCP listener is
    /// fine because TCP and UDP are distinct L4 protocols.
    /// `None` (default) - Hysteria2 disabled.
    #[serde(default)]
    hysteria2_bind: Option<String>,
    /// Enable Hysteria2 on the same UDP port as the primary TCP listener.
    /// When true and `hysteria2_bind` is not explicitly set, the bridge
    /// binds a QUIC/UDP socket on the same host:port as `bind`.
    /// TCP:N + UDP:N looks like HTTP/3 to any network scanner.
    /// Default false.
    #[serde(default)]
    hysteria2_enabled: bool,
    /// BRUTAL target send rate in Mbit/s for the Hysteria2 transport.
    /// Default 100 Mbit/s. Set to 0 for unlimited (limited only by QUIC
    /// flow control).
    #[serde(default = "default_hysteria2_send_rate_mbps")]
    hysteria2_send_rate_mbps: u64,

    /// Cover hostname for the Hysteria2 self-signed cert SAN - the QUIC
    /// SNI a passive observer sees. Operators SHOULD set this to a
    /// plausible front; clients MUST use the same value. When empty
    /// (the default), a per-bridge cover hostname is derived from the
    /// bridge static key - never the RFC 2606 `cdn.example.com` and never
    /// a shared constant (F9-L). The previous hardcoded `"mirage"` SAN+SNI
    /// was an exact-match smoking gun.
    #[serde(default = "default_hysteria2_hostname")]
    hysteria2_hostname: String,
    /// Optional path to a DER-encoded X.509 leaf cert for the Hysteria2 QUIC
    /// listener (a real CA chain from a reverse proxy / CDN / certbot; convert
    /// PEM via `openssl x509 -outform der`). Pair with `hysteria2_key_der_path`.
    /// When both are set the bridge presents this cert instead of a runtime
    /// self-signed one, closing the RT #25 active-prober cert tell. Default:
    /// unset (self-signed, warned).
    #[serde(default)]
    hysteria2_cert_der_path: Option<String>,
    /// Path to the matching PKCS#8 DER private key for `hysteria2_cert_der_path`.
    #[serde(default)]
    hysteria2_key_der_path: Option<String>,
    /// Opt-in to the real BRUTAL congestion controller for the Hysteria2 QUIC
    /// listener (M3): fixed-rate, loss-immune sending that holds throughput
    /// through censor-induced loss. Default false (quinn's BBR). Enable only on
    /// a hostile link - BRUTAL's non-backoff pacing is a behavioural tell and
    /// antisocial on shared/congested paths.
    #[serde(default)]
    hysteria2_brutal: bool,

    // ---- HTTP/3 (MASQUE) carrier ----
    /// Enable the HTTP/3 carrier on a QUIC/UDP socket on the same host:port
    /// as the primary TCP `bind` (TCP:N + UDP:N with ALPN `h3` looks like an
    /// HTTP/3 web origin). Mutually exclusive with `hysteria2_enabled` on the
    /// same port. Default false.
    #[serde(default)]
    h3_enabled: bool,
    /// Cover hostname for the HTTP/3 self-signed cert SAN / QUIC SNI. Clients
    /// MUST use the same value. When empty (the default), derived per-bridge
    /// from the bridge static key (F9-L) - never the RFC 2606 `cdn.example.com`.
    #[serde(default = "default_h3_hostname")]
    h3_hostname: String,
    /// Shared password enabling Gecko/Salamander QUIC obfuscation on the QUIC
    /// carriers (h3 + hysteria2). When set, every QUIC datagram is XOR-scrambled
    /// and handshake packets are fragmented, hiding the QUIC fingerprint. MUST
    /// match the client's `quic_obfs_password`. Highest-precedence obfs source.
    #[serde(default)]
    quic_obfs_password: Option<String>,
    /// Hex-encoded 32-byte secret QUIC-obfuscation key, distributed to clients
    /// inside the invite (`INVITE_EXT_QUIC_OBFS_SECRET`). `mirage-keygen` /
    /// `mirage-setup` generate this and embed the matching secret in the invite,
    /// so QUIC obfuscation is secret-grade by default (an adversary needs an
    /// actual invite, not merely the scraped bridge pubkey). Lower precedence
    /// than `quic_obfs_password`; when neither is set the key derives from the
    /// bridge pubkey (obfuscated but not secret).
    #[serde(default)]
    quic_obfs_secret_hex: Option<String>,
    /// Disable Salamander QUIC obfuscation and speak plain, parseable QUIC.
    ///
    /// Salamander XORs each datagram into a uniform-random stream (the Wu-2023
    /// fully-encrypted-traffic entropy signature - red-team #9). Plain QUIC
    /// parses as genuine QUIC (evades the entropy classifier) but re-exposes the
    /// quinn!=Chrome QUIC fingerprint + an active-probe oracle behind the
    /// self-signed cert, so it should be fronted by a real CA-cert origin. This
    /// flag MUST match the client's `quic_obfs_disable` - a mismatch garbles the
    /// QUIC Initial and breaks the transport silently. Default `false`
    /// (Salamander), so existing deployments are unchanged.
    #[serde(default)]
    quic_obfs_disable: bool,

    // ---- dnstt (DNS tunnel) carrier ----
    /// Enable the full DNS-tunnel handler. The bridge is the authoritative name
    /// server for `dnstt_domain` and answers tunnel queries on `dnstt_bind`
    /// (UDP). Requires `dnstt_domain`. Default false.
    #[serde(default)]
    dnstt_enabled: bool,
    /// Tunnel domain this bridge is authoritative for (e.g. `t.example.com`).
    #[serde(default)]
    dnstt_domain: Option<String>,
    /// UDP address to answer DNS-tunnel queries on. Default `0.0.0.0:5353`.
    #[serde(default = "default_dnstt_bind")]
    dnstt_bind: String,

    // ---- Circuit relay (Phase 2H) ----
    /// When true, the bridge runs the circuit-relay [`SessionTask`] / state
    /// machine after the Mirage session handshake instead of a SOCKS5 proxy.
    /// Clients request it via the `CIRCUIT_RELAY` transport-capability bit.
    /// Default false - a plain SOCKS5 proxy unless set.
    ///
    /// MULTI-HOP is fully wired, both directions, decided per accepted session.
    ///
    /// OUTBOUND (extend): with a `relay_peers` dial token configured, the daemon
    /// builds a relay-capable executor (`BridgeCircuitExecutor::with_relay` plus a
    /// `SessionNextHopDialer`) and dials the next hop on a client's `CMD_EXTEND`,
    /// so this node acts as an intermediate relay.
    ///
    /// INBOUND (be an extended hop): when an accepted session's authenticated peer
    /// key is in the `relay_peers` allowlist (i.e. an upstream bridge opened a
    /// relay leg), the session runs in relay mode with per-hop capability-token
    /// verification, so this node acts as a middle/exit hop and verifies the
    /// client's per-hop token (`CMD_EXTEND_FINISH`) before serving.
    ///
    /// With `relay_peers` empty the node is a direct-client circuit EXIT only.
    /// Enable `circuit_relay_enabled` to accept circuit sessions at all; add
    /// `relay_peers` to place the node in a mesh.
    #[serde(default)]
    circuit_relay_enabled: bool,

    /// Peer bridges in the multi-hop relay mesh. Each entry gives a peer bridge's
    /// X25519 static public key (hex) and - for peers this node DIALS - an
    /// operator-issued relay capability token (hex wire bytes) the peer verifies.
    ///
    /// Listing a peer serves two roles: (a) OUTBOUND - with a token, this node
    /// can extend a circuit to that peer on a client's `CMD_EXTEND`; (b) INBOUND -
    /// the peer's key is added to the allowlist that recognizes a relay leg it
    /// opens to this node, flipping that session into per-hop-token-verifying
    /// relay mode. A terminal exit that only RECEIVES relayed circuits lists its
    /// upstream entry with an EMPTY token (inbound authorization needs no dial
    /// token). Empty `relay_peers` (default) => direct-client exit only. For
    /// genuine anonymity the peers should be DIFFERENT operators' bridges.
    #[serde(default)]
    relay_peers: Vec<RelayPeerConfig>,
}

/// One peer bridge in the relay mesh. See [`Config::relay_peers`].
#[derive(Clone, serde::Deserialize)]
struct RelayPeerConfig {
    /// Peer bridge X25519 static public key, hex (64 chars).
    bridge_x25519_pk: String,
    /// Operator-issued relay capability token for that peer, hex-encoded
    /// `CapabilityToken` wire bytes. This node presents it when dialing the peer
    /// (OUTBOUND relay). Optional (default empty): a peer this node only ever
    /// receives relayed circuits FROM (a terminal exit's upstream entry) needs
    /// no dial token - listing its pubkey alone authorizes it as an INBOUND
    /// relay leg (flips the accepted session into per-hop-token-verifying relay
    /// mode). Omit the token for inbound-only neighbours.
    #[serde(default)]
    relay_token: String,
}

/// Parsed relay-mesh membership: the OUTBOUND dial map plus the INBOUND
/// authorized-peer key set.
struct RelayMesh {
    /// `peer_pk -> relay_token` for peers this node can DIAL (extend to). Only
    /// peers that supplied a well-formed token appear here.
    dial_tokens: std::collections::HashMap<[u8; 32], mirage_discovery::token::CapabilityToken>,
    /// Every configured peer's static key - the allowlist for recognizing an
    /// INBOUND relay leg (a peer authenticating with its stable identity). A
    /// terminal exit populates this without any dial token.
    authorized_keys: std::collections::HashSet<[u8; 32]>,
}

/// Parse `relay_peers` config into a [`RelayMesh`]. Skips (with a warning) any
/// entry whose pubkey is malformed, so one bad mesh entry doesn't take down the
/// whole relay capability. A valid pubkey with an absent/malformed token still
/// authorizes the peer for INBOUND relay (it just can't be dialed outbound).
fn parse_relay_peers(peers: &[RelayPeerConfig]) -> RelayMesh {
    let mut dial_tokens = std::collections::HashMap::new();
    let mut authorized_keys = std::collections::HashSet::new();
    for p in peers {
        let Ok(pk_bytes) = hex::decode(&p.bridge_x25519_pk) else {
            warn!(pk = %p.bridge_x25519_pk, "relay_peer: bad hex pubkey; skipping");
            continue;
        };
        let Ok(pk): Result<[u8; 32], _> = pk_bytes.try_into() else {
            warn!("relay_peer: pubkey not 32 bytes; skipping");
            continue;
        };
        // A valid pubkey authorizes the peer as an inbound relay leg regardless
        // of whether it also carries an outbound dial token.
        authorized_keys.insert(pk);
        // Inbound-only peers legitimately omit the token.
        if p.relay_token.is_empty() {
            continue;
        }
        let Ok(tok_bytes) = hex::decode(&p.relay_token) else {
            warn!("relay_peer: bad hex token; skipping outbound dial (inbound still authorized)");
            continue;
        };
        match mirage_discovery::token::CapabilityToken::decode(&tok_bytes) {
            Ok(tok) => {
                dial_tokens.insert(pk, tok);
            }
            Err(e) => {
                warn!(error = %e, "relay_peer: token decode failed; skipping outbound dial (inbound still authorized)");
            }
        }
    }
    RelayMesh {
        dial_tokens,
        authorized_keys,
    }
}

fn default_true() -> bool {
    true
}
fn default_replay_capacity() -> usize {
    65_536
}

/// Default bridge state path `$XDG_STATE_HOME/mirage/<name>` (or
/// `$HOME/.local/state/mirage/<name>`), used to give a plain deployment
/// sensible on-disk defaults without an extra config step. Returns `None` when
/// neither env var is set (e.g. a bare system service), so the caller falls back
/// to its explicit-config-or-warn path rather than writing to a guessed
/// location.
fn default_bridge_state_path(name: &str) -> Option<String> {
    let base = match std::env::var_os("XDG_STATE_HOME") {
        Some(x) if !x.is_empty() && std::path::Path::new(&x).is_absolute() => {
            std::path::PathBuf::from(x)
        }
        _ => std::path::PathBuf::from(std::env::var_os("HOME")?).join(".local/state"),
    };
    Some(
        base.join("mirage")
            .join(name)
            .to_string_lossy()
            .into_owned(),
    )
}
fn default_handshake_timeout_secs() -> u64 {
    10
}
fn default_max_concurrent_sessions() -> usize {
    4_096
}
fn default_socks5_connect_timeout_secs() -> u64 {
    10
}
fn default_anonymize_target_logs() -> bool {
    true
}

// Client-IP log anonymization

/// Process-wide switch for client-IP log anonymization. Set once at startup from
/// `BridgeConfig::anonymize_client_logs`; a single global value means the ~60
/// `client = %plog(&peer)` log sites need no per-call flag threading.
static ANONYMIZE_CLIENT_LOGS: AtomicBool = AtomicBool::new(true);

/// Per-run random salt so anonymized client labels are irreversible to the IP
/// and unlinkable across process restarts. Set once at startup.
static CLIENT_LOG_SALT: AtomicU64 = AtomicU64::new(0);

/// Process-wide switch for stream multiplexing. Set once at startup from
/// `BridgeConfig::mux_enabled`; read at the post-handshake dispatch so an
/// operator can force legacy single-request sessions without threading a flag
/// through the ~8 `run_authenticated_session` call sites.
static MUX_ENABLED: AtomicBool = AtomicBool::new(true);

/// Relay mesh - OUTBOUND dial map: `peer_pk -> relay_token` for the bridges this
/// node can relay circuits TO (extend to on a client's `CMD_EXTEND`). Set once
/// at startup from `config.relay_peers`. Non-empty => the circuit-relay path
/// builds a relay-capable executor with a next-hop dialer (see the accept path).
/// A `OnceLock` static avoids threading the map through the ~8
/// `run_authenticated_session` call sites (mirrors `MUX_ENABLED`).
static RELAY_PEER_TOKENS: std::sync::OnceLock<
    Arc<std::collections::HashMap<[u8; 32], mirage_discovery::token::CapabilityToken>>,
> = std::sync::OnceLock::new();

/// Relay mesh - INBOUND authorized-peer allowlist: the static keys of bridges
/// permitted to open a RELAY leg to this node (they authenticate with their
/// stable X25519 identity, learned via `accept_with_peer_static`). When an
/// accepted session's peer key is in this set, the circuit session is driven in
/// RELAY MODE with per-hop capability-token verification - the exit/middle half
/// of multi-hop. A terminal exit populates this (from `relay_peers`) even though
/// it holds no outbound dial token for the upstream entry.
static RELAY_PEER_KEYS: std::sync::OnceLock<Arc<std::collections::HashSet<[u8; 32]>>> =
    std::sync::OnceLock::new();

/// Initialise the client-log anonymization state from config (once, at startup).
fn init_client_log_anonymization(anonymize: bool) {
    ANONYMIZE_CLIENT_LOGS.store(anonymize, Ordering::Relaxed);
    let mut s = [0u8; 8];
    let _ = getrandom::fill(&mut s);
    CLIENT_LOG_SALT.store(u64::from_le_bytes(s), Ordering::Relaxed);
}

/// Render a client peer address for logging. When anonymization is on (default),
/// returns a per-run-stable, irreversible opaque `client-xxxxxxxx` label (salted
/// FNV-1a over the IP only - the ephemeral port is dropped), so one client's log
/// lines correlate within a run but a seized log never reveals the IP. When off,
/// returns the raw `IP:port`.
fn plog(peer: &std::net::SocketAddr) -> String {
    if !ANONYMIZE_CLIENT_LOGS.load(Ordering::Relaxed) {
        return peer.to_string();
    }
    let mut h = CLIENT_LOG_SALT.load(Ordering::Relaxed) ^ 0xcbf2_9ce4_8422_2325;
    for b in peer.ip().to_string().as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("client-{:08x}", (h & 0xffff_ffff) as u32)
}
fn default_reality_ch_timeout_secs() -> u64 {
    10
}
fn default_reality_cover_cap_secs() -> u64 {
    30
}

/// Default for [`BridgeConfig::reality_probe_accept_legacy`]: `false` - secure by
/// default. Legacy (pubkey-only) anti-probe knocks that predate the epoch/invite
/// binding are REJECTED unless an operator explicitly opts back in. Accepting
/// them makes the epoch-MAC binding vacuous and re-opens pubkey-only bridge
/// enumeration, so it must be a conscious choice, only during a key rollover when
/// some clients still hold pre-epoch tokens. A fresh deployment (hand-written
/// config, `mirage-keygen`, or `mirage-setup`) is closed from the first packet.
fn default_reality_probe_accept_legacy() -> bool {
    false
}
fn default_cohort_reveal_cap() -> u8 {
    DEFAULT_PER_TOKEN_REVEAL_CAP
}
fn default_cohort_reveal_jitter() -> u8 {
    3
}
fn default_refresh_enabled() -> bool {
    true
}
fn default_refresh_per_root_cap() -> u8 {
    mirage_discovery::DEFAULT_REFRESH_PER_ROOT_CAP
}
fn default_refresh_ttl_seconds() -> u64 {
    mirage_discovery::DEFAULT_REFRESH_TTL_SECONDS
}
fn default_claim_enabled() -> bool {
    true
}
fn default_claim_capacity() -> usize {
    1_000_000
}
fn default_rate_limit_per_minute() -> u32 {
    60
}
fn default_max_concurrent_per_ip() -> usize {
    32
}
fn default_rate_limit_max_entries() -> usize {
    65_536
}

fn default_gossip_probe_threshold() -> u32 {
    5
}
fn default_admin_service() -> String {
    "mirage-bridge".to_string()
}

impl BridgeConfig {
    /// Validate an arbitrary JSON value as a `BridgeConfig` WITHOUT applying it.
    /// The admin UI calls this to reject a malformed edit before persisting, so a
    /// bad config never fatals the daemon on the next restart.
    pub fn validate_value(v: &serde_json::Value) -> Result<(), String> {
        serde_json::from_value::<BridgeConfig>(v.clone())
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

fn default_hysteria2_send_rate_mbps() -> u64 {
    100
}
fn default_hysteria2_hostname() -> String {
    // Empty -> the transport derives a per-bridge cover SAN from the static key
    // (F9-L). Operators SHOULD still set an explicit front they actually serve.
    String::new()
}

fn default_h3_hostname() -> String {
    // Empty -> derived per-bridge from the static key at listener start (F9-L).
    String::new()
}

fn default_dnstt_bind() -> String {
    // Unprivileged default; operators front this behind :53 (NAT / resolver).
    "0.0.0.0:5353".to_string()
}

/// Spawn a best-effort splice of `client` to a shadow/decoy `target`,
/// replaying `replay` (request bytes already consumed during auth) first so
/// the backend emits a genuine response. Never blocks the accept loop.
///
/// **Probe-scoring is intentionally NOT done here.** A connection we
/// shadow-forward must behave EXACTLY like the decoy, and a real decoy never
/// soft-blocks a client; calling the gatekeeper on this path would let the
/// prober's *next* connection get a bare pre-read drop, re-introducing the
/// bridge-vs-decoy fingerprint this path removes. Scoring stays on the
/// drop-only path in [`handle_http_reject`].
fn forward_to_shadow(
    mut client: TcpStream,
    replay: Vec<u8>,
    target: String,
    cap: Duration,
    metrics: Arc<Metrics>,
) {
    metrics.shadow_forwarded();
    tokio::spawn(async move {
        let Ok(Ok(mut upstream)) =
            tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&target)).await
        else {
            return;
        };
        // The whole post-connect exchange (replay write + bidirectional splice)
        // is bounded by `cap` so a wedged/slow decoy cannot pin this task -
        // the earlier replay write_all had no deadline of its own.
        let _ = tokio::time::timeout(cap, async move {
            if !replay.is_empty() {
                upstream.write_all(&replay).await?;
            }
            copy_bidirectional(&mut client, &mut upstream).await?;
            Ok::<(), std::io::Error>(())
        })
        .await;
    });
}

/// Handle a failed-probe reject on an HTTP-bearing transport (and the Unknown
/// mux path). `ctx` is `Some((stream, replay))` when the stream is intact and
/// the consumed bytes can be replayed byte-identically to a shadow, or `None`
/// when the stream is unforwardable (post-101 WS / partial read). Enforces the
/// forward-XOR-score invariant: a forwarded connection is never scored; a
/// dropped one is.
async fn handle_http_reject(
    ctx: Option<(TcpStream, Vec<u8>)>,
    shadow: &Option<String>,
    shadow_cap: Duration,
    metrics: &Arc<Metrics>,
    gatekeeper: &Option<Arc<ConnectionGatekeeper>>,
    peer_ip: std::net::IpAddr,
) {
    match (ctx, shadow) {
        // Forwardable + a shadow is configured: mimic the decoy.
        (Some((stream, replay)), Some(target)) => {
            forward_to_shadow(
                stream,
                replay,
                target.clone(),
                shadow_cap,
                Arc::clone(metrics),
            );
        }
        // A shadow IS configured but this particular failure is unforwardable
        // (post-101 WebSocket / partial read): drop SILENTLY. Crucially, do
        // NOT probe-score. Once the operator opts into decoy mimicry, NO probe
        // may ever soft-block this IP - otherwise the prober's NEXT (possibly
        // forwardable) connection gets a bare pre-read drop, re-introducing the
        // exact bridge-vs-decoy fingerprint shadow-forwarding exists to remove.
        // Probe-scoring and shadow-forwarding are mutually-exclusive strategies.
        (_, Some(_)) => {
            // `ctx`'s stream (if any) drops here. No scoring.
        }
        // No shadow configured: genuine drop-only mode - probe-score so
        // scanning IPs accumulate toward the soft-block threshold.
        (_, None) => {
            if let Some(gk) = gatekeeper {
                gk.observe_auth_failure(peer_ip).await;
            }
        }
    }
}
fn default_pad_cbr_interval_ms() -> u64 {
    10
}

/// Hard cap on how long a magic-hostname handler (`cohort`,
/// `refresh`, `claim`) will wait for the client to send its fixed-
/// size request body after SOCKS5 CONNECT succeeds. Without this,
/// a client that opens a session, issues CONNECT, then stalls can
/// hold a session slot indefinitely (RT-rl-2).
const MAGIC_HOST_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Reports bridge load as 0-255 based on how full the session
/// semaphore is. Used by [`CohortDistressMonitor`] to decide
/// when to publish `EntryDistressed` gossip events to peers.
struct SemaphoreLoadSensor {
    max_permits: usize,
    /// AtomicUsize tracking active session count. Updated by
    /// the accept loop via `active_sessions` counter rather than
    /// polling the semaphore (which has no `used()` API).
    active: Arc<AtomicUsize>,
}

impl DistressSensor for SemaphoreLoadSensor {
    fn current_severity(&self) -> u8 {
        let active = self.active.load(Ordering::Relaxed);
        // Scale 0-255 proportional to semaphore fill.
        ((active.min(self.max_permits) * 255) / self.max_permits.max(1)) as u8
    }
}

/// RAII guard: decrements the active-session counter on drop.
/// Held inside each session task so the counter stays accurate
/// even on early task exit (panic, cancellation, error return).
struct ActiveGuard(Arc<AtomicUsize>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

struct BridgeKeys {
    bridge_x25519_sk: [u8; 32],
    bridge_ed25519_pk: [u8; 32],
    operator_ed25519_pk: [u8; 32],
    /// Operator's PREVIOUS Ed25519 verifying key, accepted during
    /// a mother-key rotation overlap window (v0.1i).
    operator_ed25519_pk_prev: Option<[u8; 32]>,
    /// Bridge's Ed25519 signing key. Held only when the operator
    /// provided `bridge_ed25519_sk_hex`; required to mint refresh
    /// tokens. `None` disables any feature that needs bridge-side
    /// Ed25519 signatures.
    bridge_ed25519_sk: Option<mirage_crypto::ed25519_dalek::SigningKey>,
}

fn decode_key32(hex_str: &str, name: &'static str) -> Result<[u8; 32], String> {
    let raw = hex::decode(hex_str.trim()).map_err(|e| format!("{name}: hex decode: {e}"))?;
    if raw.len() != 32 {
        return Err(format!("{name}: expected 32 bytes, got {}", raw.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// Resolve the QUIC-obfs key (hysteria2 / h3) and a mode label, mirroring the
/// client's [`resolve_obfs_key`] precedence so both sides always agree:
///
/// 1. `quic_obfs_password` - an explicit out-of-band shared string, hashed.
/// 2. `quic_obfs_secret_hex` - the per-bridge secret also embedded in the invite
///    (`INVITE_EXT_QUIC_OBFS_SECRET`); secret-grade against pubkey-scraping DPI.
/// 3. Pubkey-derived default - obfuscated but not secret.
///
/// A malformed `quic_obfs_secret_hex` is logged and skipped (falls through to
/// the default) rather than aborting the bridge.
fn resolve_bridge_obfs_key(
    password: Option<&str>,
    secret_hex: Option<&str>,
    bridge_pk: &[u8; 32],
) -> ([u8; 32], &'static str) {
    if let Some(p) = password.filter(|p| !p.is_empty()) {
        return (
            mirage_quic_obfs::key_from_password(p.as_bytes()),
            "shared-password",
        );
    }
    if let Some(hex) = secret_hex.filter(|s| !s.is_empty()) {
        match decode_key32(hex, "quic_obfs_secret_hex") {
            Ok(secret) => {
                return (
                    mirage_quic_obfs::key_from_password(&secret),
                    "invite-secret",
                )
            }
            Err(e) => warn!(error = %e, "quic_obfs_secret_hex invalid; using pubkey default"),
        }
    }
    (
        mirage_quic_obfs::default_obfs_key(bridge_pk),
        "per-bridge-default",
    )
}

/// Returns `true` if `addr` is NOT a loopback or private-network address
/// and therefore constitutes a "public" bind worth warning about.
///
/// Private ranges checked:
///   - 127.x.x.x / ::1  (loopback)
///   - 10.x.x.x          (RFC 1918 class-A)
///   - 172.16-31.x.x     (RFC 1918 class-B)
///   - 192.168.x.x       (RFC 1918 class-C)
fn is_public_bind_addr(addr: &std::net::SocketAddr) -> bool {
    match addr.ip() {
        std::net::IpAddr::V4(ip) => {
            let o = ip.octets();
            let loopback = o[0] == 127;
            let rfc1918_a = o[0] == 10;
            let rfc1918_b = o[0] == 172 && (16..=31).contains(&o[1]);
            let rfc1918_c = o[0] == 192 && o[1] == 168;
            !(loopback || rfc1918_a || rfc1918_b || rfc1918_c)
        }
        std::net::IpAddr::V6(ip) => !ip.is_loopback(),
    }
}

fn policy_from(config: &BridgeConfig) -> AllowlistPolicy {
    let mut p = AllowlistPolicy::safe_defaults();
    if config.allow_loopback_targets {
        p.deny_loopback = false;
    }
    if config.allow_private_network_targets {
        p.deny_private_networks = false;
    }
    p
}

/// `--doctor` active self-tests: verify the bridge can reach the internet (else
/// it cannot proxy) and that any Reality cover hosts are real + reachable (a
/// fake or unreachable cover is both a fingerprint and breaks the auth-probe
/// fallback). Prints a report; does not start the bridge.
async fn bridge_doctor_probes(config: &BridgeConfig) {
    use tokio::net::TcpStream;
    let timeout = Duration::from_secs(6);
    println!();
    // 1. Upstream internet reachability - the bridge proxies to the internet;
    //    if it cannot reach it, it cannot serve clients.
    let upstreams = ["1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443"];
    let mut reachable = false;
    for u in upstreams {
        if let Ok(Ok(_)) = tokio::time::timeout(timeout, TcpStream::connect(u)).await {
            reachable = true;
            break;
        }
    }
    if reachable {
        println!("  upstream:       [ok] internet reachable");
    } else {
        println!(
            "  upstream:       [FAIL] cannot reach the internet (tried {}) - the bridge \
             cannot proxy; check egress firewall / routing",
            upstreams.join(", ")
        );
    }
    // 2. Reality cover-host reachability (only if Reality is configured).
    if config.reality_enabled {
        let mut covers: Vec<String> = config.reality_cover_addrs.clone();
        if let Some(a) = &config.reality_cover_addr {
            covers.push(a.clone());
        }
        if covers.is_empty() {
            println!("  reality cover:  (none configured - auth-probe failures are dropped)");
        } else {
            for c in &covers {
                let target = if c.contains(':') {
                    c.clone()
                } else {
                    format!("{c}:443")
                };
                match tokio::time::timeout(timeout, TcpStream::connect(&target)).await {
                    Ok(Ok(_)) => println!("  reality cover:  [ok] {c} reachable"),
                    Ok(Err(e)) => println!(
                        "  reality cover:  [FAIL] {c} unreachable ({e}) - a real, reachable \
                         cover site is required for plausible fallback"
                    ),
                    Err(_) => println!(
                        "  reality cover:  [FAIL] {c} timed out - use a real, fast cover site"
                    ),
                }
            }
        }
    }
}

/// Apply PARANOID mode + config-driven pacing on the bridge before startup. Paranoid
/// forces Reality on, strict anti-probe, and replay pacing; the `reality_pace*` fields
/// are honored whether or not paranoid is set.
fn apply_paranoid_bridge(config: &mut BridgeConfig) {
    if config.paranoid {
        config.reality_enabled = true;
        config.reality_probe_accept_legacy = false; // strict: reject pubkey-only probes
        if config.reality_pace.is_none() {
            config.reality_pace = Some("replay".to_string());
        }
        tracing::warn!(
            reality = true,
            strict_probe = true,
            pace = ?config.reality_pace,
            "PARANOID MODE: Reality carrier + strict anti-probe + replay pacing (sessions \
             wear a real recorded cover shape). Clients must also run paranoid/replay."
        );
    }
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

#[tokio::main]
async fn main() {
    match harden_process() {
        Ok(report) => {
            if !report.core_dumps_disabled {
                eprintln!(
                    "warning: core-dump disable is best-effort on this platform; \
                     ensure OS-level controls are configured"
                );
            }
        }
        Err(e) => {
            eprintln!("fatal: failed to disable core dumps: {e}");
            std::process::exit(2);
        }
    }

    // Install the tracing subscriber so the daemon actually emits its
    // operator-facing logs - probe-scan warnings, "duplicate claim attempt -
    // possible invite leak", cohort/gossip events, rate-limit drops. Honors
    // RUST_LOG (the operator runbook relies on `RUST_LOG=debug`); defaults to
    // "info". Without this the bridge ran SILENTLY: every info!/warn!/error!
    // was discarded, defeating the documented alerting story. `try_init` is
    // idempotent (matches the client, which already calls this).
    mirage_common::init_tracing();

    // Handle flags that must work before a config file exists.
    let argv: Vec<String> = std::env::args().collect();
    match argv.get(1).map(|s| s.as_str()) {
        Some("--version") | Some("-V") => {
            println!("mirage-bridge {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }
        Some("--help") | Some("-h") => {
            println!(
                "mirage-bridge {ver}\n\
                 \n\
                 Usage: mirage-bridge <config.json> [--check-config | --doctor] [--admin-ui [host:port]]\n\
                 \n\
                 Options:\n\
                   <config.json>     Path to the bridge JSON configuration file.\n\
                   --check-config    Validate the config file and print a summary without starting the bridge.\n\
                   --doctor          --check-config PLUS active self-tests: upstream internet\n\
                                     reachability and reality cover-host reachability.\n\
                   --admin-ui [addr] Serve the local operator admin UI. Address is optional and\n\
                                     defaults to 127.0.0.1:3825 (loopback). Pass a value to override,\n\
                                     e.g. --admin-ui 127.0.0.1:9000. Overrides the config's admin_bind.\n\
                   --version, -V     Print version and exit.\n\
                   --help, -h        Print this help and exit.\n\
                 \n\
                 Generate config with: mirage-keygen --write-bridge-config bridge.json\n\
                 See QUICKSTART.md for full setup instructions.",
                ver = env!("CARGO_PKG_VERSION")
            );
            std::process::exit(0);
        }
        Some(p) if p.starts_with('-') && p != "--check-config" && p != "--doctor" => {
            eprintln!("mirage-bridge: unknown flag '{p}'. Try --help.");
            std::process::exit(2);
        }
        _ => {}
    }

    mirage_common::init_tracing();

    let config_path = match argv.get(1) {
        Some(p) => p.clone(),
        None => {
            eprintln!("usage: mirage-bridge <config.json>\nTry --help for more information.");
            std::process::exit(2);
        }
    };
    let check_only = argv
        .iter()
        .any(|a| a == "--check-config" || a == "--doctor");

    // `--admin-ui [host:port]` enables the operator admin UI. The address is
    // OPTIONAL: a bare `--admin-ui` defaults to 127.0.0.1:3825. A value overrides
    // both the default and the config's `admin_bind`.
    let admin_ui_cli = argv.iter().position(|a| a == "--admin-ui").map(|i| {
        argv.get(i + 1)
            .filter(|v| !v.starts_with('-'))
            .cloned()
            .unwrap_or_else(|| "127.0.0.1:3825".to_string())
    });

    let mut config: BridgeConfig = match std::fs::read_to_string(&config_path)
        .map_err(|e| format!("read {config_path}: {e}"))
        .and_then(|s| serde_json::from_str::<BridgeConfig>(&s).map_err(|e| e.to_string()))
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("fatal: config error: {e}");
            std::process::exit(2);
        }
    };
    apply_paranoid_bridge(&mut config);

    // Active-probe shadow config sanity (mimicry footguns). `http_shadow_target`
    // MUST speak PLAINTEXT HTTP - the bridge replays a plaintext HTTP request to
    // it on a failed HTTP probe - whereas `shadow_target` raw-splices and may be
    // a TLS endpoint. A misconfig silently degrades unobservability rather than
    // breaking function, so surface it loudly at startup.
    match (&config.http_shadow_target, &config.shadow_target) {
        (Some(http_sh), _) if http_sh.ends_with(":443") || http_sh.ends_with(":8443") => {
            warn!(
                target = %http_sh,
                "http_shadow_target looks like a TLS endpoint; it MUST speak plaintext \
                 HTTP (the bridge replays a plaintext HTTP request to it). Failed HTTP \
                 probes would receive TLS garbage instead of a genuine response."
            );
        }
        (Some(http_sh), Some(raw_sh)) if http_sh == raw_sh => {
            warn!(
                "http_shadow_target == shadow_target; the latter raw-splices and is often \
                 a TLS endpoint. Use a dedicated plaintext-HTTP decoy for http_shadow_target \
                 so failed WebSocket/meek/DoH probes receive a real HTTP response."
            );
        }
        (None, Some(_)) => {
            warn!(
                "shadow_target is set but http_shadow_target is not: opaque (Unknown) probes \
                 are shadow-forwarded while failed WebSocket/meek/DoH probes are dropped + \
                 probe-scored - an inconsistency an active prober can exploit. Set \
                 http_shadow_target to a plaintext-HTTP decoy for consistent active-probe \
                 resistance across all transports."
            );
        }
        _ => {}
    }

    let bridge_ed25519_sk = match config.bridge_ed25519_sk_hex.as_deref() {
        None => None,
        Some(h) => {
            let raw = mirage_crypto::zeroize::Zeroizing::new(
                decode_key32(h, "bridge_ed25519_sk").unwrap_or_else(|e| fatal(&e)),
            );
            let sk = mirage_crypto::ed25519_dalek::SigningKey::from_bytes(&raw);
            // Defense-in-depth: the derived pubkey MUST match the
            // separately-configured identity pubkey. A mismatch here
            // means the operator has desynced their config and would
            // be minting refresh tokens signed by a key clients don't
            // know.
            let derived_pk = sk.verifying_key().to_bytes();
            let configured_pk = decode_key32(&config.bridge_ed25519_pk_hex, "bridge_ed25519_pk")
                .unwrap_or_else(|e| fatal(&e));
            if derived_pk != configured_pk {
                fatal("bridge_ed25519_sk does not match bridge_ed25519_pk");
            }
            Some(sk)
        }
    };
    if config.refresh_enabled && bridge_ed25519_sk.is_none() {
        fatal(
            "refresh_enabled=true requires bridge_ed25519_sk_hex in config. \
             Either provide the key or set refresh_enabled=false.",
        );
    }
    let operator_ed25519_pk_prev = config
        .operator_ed25519_pk_prev_hex
        .as_deref()
        .map(|h| decode_key32(h, "operator_ed25519_pk_prev").unwrap_or_else(|e| fatal(&e)));
    let keys = BridgeKeys {
        bridge_x25519_sk: decode_key32(&config.bridge_x25519_sk_hex, "bridge_x25519_sk")
            .unwrap_or_else(|e| fatal(&e)),
        bridge_ed25519_pk: decode_key32(&config.bridge_ed25519_pk_hex, "bridge_ed25519_pk")
            .unwrap_or_else(|e| fatal(&e)),
        operator_ed25519_pk: decode_key32(&config.operator_ed25519_pk_hex, "operator_ed25519_pk")
            .unwrap_or_else(|e| fatal(&e)),
        operator_ed25519_pk_prev,
        bridge_ed25519_sk,
    };
    if keys.operator_ed25519_pk_prev.is_some() {
        info!("operator key rotation overlap: accepting tokens signed by the previous key");
    }

    // --check-config: validate without binding anything.
    if check_only {
        let bridge_pk_hex = hex::encode(keys.bridge_ed25519_pk);
        let fingerprint = &bridge_pk_hex[..16];
        let transports: Vec<&str> = {
            let mut t = vec!["raw"];
            if config.reality_enabled {
                t.push("reality");
            }
            if config.obfs_enabled {
                t.push("obfs-tcp");
            }
            if config.ss2022_psk_hex.is_some() {
                t.push("ss2022");
            }
            if config.ws_enabled {
                t.push("websocket");
            }
            if config.webrtc_enabled {
                t.push("webrtc");
            }
            if config.vless_uuid_hex.is_some() {
                t.push("vless");
            }
            if config.hysteria2_bind.is_some() || config.hysteria2_enabled {
                t.push("hysteria2");
            }
            t
        };
        println!("mirage-bridge config OK");
        println!("  bind:           {}", config.bind);
        println!("  bridge pk:      {}...  (first 16 hex chars)", fingerprint);
        println!("  transports:     {}", transports.join(", "));
        println!("  max sessions:   {}", config.max_concurrent_sessions);
        println!(
            "  replay log:     {}",
            config
                .replay_log_path
                .as_deref()
                .unwrap_or("(in-memory only)")
        );
        if config.gossip_bind.is_some() {
            println!(
                "  gossip bind:    {}",
                config.gossip_bind.as_deref().unwrap_or("")
            );
            println!("  gossip peers:   {}", config.gossip_peers.len());
        }
        if let Some(ref m) = config.metrics_bind {
            println!("  metrics:        http://{m}/metrics");
        }
        // These two toggles MUST match the client's settings (symmetric
        // protocols); surface them so a mismatched pair is easy to spot.
        println!(
            "  padding:        {} (client must match)",
            if config.pad_enabled { "on" } else { "off" }
        );
        println!(
            "  stream mux:     {} (client must match)",
            if config.stream_mux_enabled {
                "on"
            } else {
                "off"
            }
        );
        // Is the primary bind address actually bindable right now?
        match tokio::net::TcpListener::bind(&config.bind).await {
            Ok(l) => {
                drop(l);
                println!("  bind port:      available");
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                println!(
                    "  bind port:      needs privileges (expected for ports < 1024; run as \
                     root or grant CAP_NET_BIND_SERVICE)"
                );
            }
            Err(e) => {
                println!(
                    "  bind port:      [warn] UNAVAILABLE ({e}) - stop the conflicting \
                     listener or change `bind`"
                );
            }
        }
        // `--doctor`: active network self-tests beyond static validation.
        if argv.iter().any(|a| a == "--doctor") {
            bridge_doctor_probes(&config).await;
        }
        std::process::exit(0);
    }

    // Deprecation warning: obfs_bind is now ignored. obfs-tcp is
    // handled by the primary port mux (MuxResult::AuthenticatedObfsTcp).
    if config.obfs_bind.is_some() {
        warn!(
            "obfs_bind is deprecated and ignored; obfs-tcp is now handled by \
             the primary port mux. Remove obfs_bind from your config."
        );
    }

    // Replay set: in-memory by default; disk-backed when
    // `replay_log_path` is set (v0.1g, A14b). Persistent form
    // survives bridge restart so accepted tokens stay replay-
    // blocked for the token's full TTL, not just the bridge's uptime.
    // SyncReplaySet wraps the inner ReplaySet in a std::sync::Mutex
    // and exposes &self methods. The brief critical section (a
    // HashMap insert + an optional log append) is held only at the
    // exact check-and-insert point in the handshake; concurrent
    // handshakes do NOT serialize behind one async-mutex guard for
    // the full Noise exchange. Audit fix: CRITICAL-Trust-1.
    // Default the replay-log to the XDG state dir when the operator didn't set
    // one, so a plain deployment gets disk-backed, restart-surviving token
    // replay protection WITHOUT an extra config step (seamless-deploy). A system
    // service with no $HOME/$XDG_STATE_HOME falls through to the in-memory
    // warning below, where the operator should still pin an explicit path. Set
    // `replay_log_path` to `""` to force in-memory.
    let resolved_replay_log: Option<String> = match config.replay_log_path.as_deref() {
        Some("") => None,
        Some(p) => Some(p.to_string()),
        None => default_bridge_state_path("replay-log"),
    };
    if config.replay_log_path.is_none() {
        if let Some(p) = resolved_replay_log.as_deref() {
            if let Some(parent) = std::path::Path::new(p).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
    }
    let replay_set: Arc<SyncReplaySet> = if let Some(path) = resolved_replay_log.as_deref() {
        // Refuse to start with a clock before UNIX_EPOCH: now_unix=0 would
        // poison the replay log's TTL baseline (and downstream token expiry).
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_else(|_| fatal("bridge clock is before UNIX_EPOCH; refusing to start"));
        let log = mirage_discovery::PersistentReplayLog::open(path, config.replay_log_fsync)
            .unwrap_or_else(|e| fatal(&format!("replay log open {path}: {e}")));
        let rs = SyncReplaySet::with_log(config.replay_capacity, log, now_unix)
            .unwrap_or_else(|e| fatal(&format!("replay log restore: {e}")));
        info!(
            path = %path,
            fsync = config.replay_log_fsync,
            restored = rs.len(),
            "replay log: disk-backed mode engaged"
        );
        Arc::new(rs)
    } else {
        tracing::warn!(
            "replay_log_path not configured - token replay protection resets on restart; \
             set replay_log_path in production"
        );
        Arc::new(SyncReplaySet::new(config.replay_capacity))
    };
    let handshake_timeout = Duration::from_secs(config.handshake_timeout_secs);
    let socks5_timeout = Duration::from_secs(config.socks5_connect_timeout_secs);
    let session_semaphore = Arc::new(tokio::sync::Semaphore::new(config.max_concurrent_sessions));
    let policy = Arc::new(policy_from(&config));

    // Cohort setup: load announcements the operator has pre-signed
    // and registered as this bridge's peers. An empty/missing file
    // produces a bridge that replies EMPTY to every cohort request.
    let cohort = Arc::new(CohortState::load(&config));

    // Refresh setup: if enabled, hold the bridge's signing key and
    // per-root-token issue counters so a single bootstrap token
    // can't be parlayed into an unlimited chain of refresh tokens.
    let refresh = Arc::new(RefreshState::new(
        config.refresh_enabled,
        keys.bridge_ed25519_sk.clone(),
        config.refresh_per_root_cap,
        Duration::from_secs(config.refresh_ttl_seconds),
    ));

    // Claim setup: one-time invite redemption. Narrows a leaked
    // invite's usable window at this bridge - once redeemed, a
    // duplicate-claim attempt signals compromise.
    let claim = Arc::new(ClaimState::new_with_optional_log(
        config.claim_enabled,
        config.claim_capacity,
        config.claim_log_path.as_deref(),
        config.claim_log_fsync,
    ));

    // Per-source-IP rate limiter. Dropped connections bypass ALL
    // protocol work, so a flood costs the bridge only a TCP socket
    // + hashmap lookup per attempt.
    let peer_limiter = Arc::new(PerPeerLimiter::new(
        config.rate_limit_per_ip_per_minute,
        config.max_concurrent_per_ip,
        config.rate_limit_max_entries,
    ));

    // Active-session counter for the distress sensor. Incremented by
    // the accept loop on permit acquisition; decremented on task drop.
    let active_sessions = Arc::new(AtomicUsize::new(0));

    // Cohort gossip cooperation stack (alpha). Wired only when the
    // operator configures `gossip_bind`. Requires `bridge_ed25519_sk_hex`
    // - the same key used for refresh tokens. All four cooperation
    // primitives share a single `TcpCohortGossip` transport.
    let cohort_gatekeeper: Option<Arc<ConnectionGatekeeper>>;
    let cohort_replay_coord: Option<Arc<CohortReplayCoordinator>>;
    // Hold these alive for the process lifetime (their tasks keep running).
    let _cohort_distress_monitor: Option<CohortDistressMonitor>;
    let _cohort_heartbeat: Option<CohortHeartbeat>;
    let _cohort_peer_distress_map: Option<Arc<PeerDistressMap>>;
    let _cohort_live_tracker: Option<Arc<LivePeerTracker>>;
    let _cohort_leak_detector: Option<Arc<mirage_bridge::LeakDetector>>;
    // Retained so we can subscribe a gossip-event metrics counter after
    // the metrics object is constructed (metrics is built after gossip setup).
    let gossip_handle: Option<Arc<dyn mirage_discovery::cohort_gossip::CohortGossip>>;
    if let Some(ref gossip_bind_str) = config.gossip_bind.clone() {
        if let Some(ref bridge_ed_sk) = keys.bridge_ed25519_sk {
            use mirage_bridge::{spawn_gossip_to_distress_map, spawn_gossip_to_live_tracker};
            use mirage_discovery::cohort_gossip::CohortGossip;
            use mirage_discovery::{TcpCohortGossip, TcpCohortGossipConfig};
            use std::net::ToSocketAddrs;

            // Parse the bind address.
            let gossip_bind_addr: std::net::SocketAddr = match gossip_bind_str.parse() {
                Ok(a) => a,
                Err(e) => {
                    fatal(&format!("gossip_bind {gossip_bind_str:?}: {e}"));
                }
            };

            // Build the authorized-pk set. Includes this bridge's
            // own key AND all listed peer keys so inbound gossip
            // from any cohort member is accepted.
            let mut authorized: HashSet<[u8; 32]> = HashSet::new();
            authorized.insert(bridge_ed_sk.verifying_key().to_bytes());
            for pk_hex in &config.gossip_authorized_peer_pks {
                match decode_key32(pk_hex.trim(), "gossip_authorized_peer_pk") {
                    Ok(pk) => {
                        authorized.insert(pk);
                    }
                    Err(e) => {
                        warn!(pk_hex = %pk_hex, error = %e, "gossip: bad peer pk; skipping");
                    }
                }
            }

            // Resolve initial peer addresses.
            let mut peer_addrs: Vec<std::net::SocketAddr> = Vec::new();
            for addr_str in &config.gossip_peers {
                match addr_str.to_socket_addrs().map(|mut it| it.next()) {
                    Ok(Some(a)) => peer_addrs.push(a),
                    _ => warn!(addr = %addr_str, "gossip: peer address failed to resolve"),
                }
            }

            match TcpCohortGossip::bind(TcpCohortGossipConfig {
                bind: gossip_bind_addr,
                authorized,
                peers: peer_addrs.clone(),
                reconnect_backoff: Duration::from_secs(5),
                broadcast_capacity: 512,
                max_inbound_connections: 64,
                outbound_queue_depth: 128,
                max_skew_secs: 300,
                first_frame_timeout: Duration::from_secs(30),
                inbound_idle_timeout: Duration::from_secs(120),
            })
            .await
            {
                Ok((gossip_tcp, gossip_addr)) => {
                    info!(
                        bind = %gossip_addr,
                        authorized_pks = config.gossip_authorized_peer_pks.len() + 1,
                        "cohort gossip: P2P transport bound"
                    );

                    // Public-bind safety warning: gossip has no
                    // authentication layer at the TCP level. Binding
                    // to a public address exposes the port to
                    // connection-flood attacks. Warn unless the
                    // operator explicitly acknowledged the risk.
                    if !config.gossip_bind_public_ok && is_public_bind_addr(&gossip_bind_addr) {
                        tracing::warn!(
                            gossip_bind = %gossip_bind_addr,
                            "gossip port is bound to a public address; firewall to cohort peer IPs only. \
                             The gossip TCP listener has no authentication layer - exposure risks connection flooding. \
                             See QUICKSTART.md \"Security notes for alpha operators\" for details."
                        );
                    }

                    let gossip: Arc<dyn CohortGossip> = Arc::new(gossip_tcp);

                    // ConnectionGatekeeper - probe detection + soft-block
                    // propagation.
                    let gatekeeper = Arc::new(ConnectionGatekeeper::new(
                        gossip.clone(),
                        bridge_ed_sk.clone(),
                        GatekeeperConfig {
                            detector: mirage_bridge::ProbeDetectorConfig {
                                threshold: config.gossip_probe_threshold,
                                ..Default::default()
                            },
                            // RT #9: when the bridge presents a shadow/decoy
                            // posture, disable accept-time soft-block bare
                            // drops (they'd be a distinguisher vs. the decoy).
                            // The Reality transport IS such a decoy posture when
                            // a cover is configured: a soft-blocked/probed IP must
                            // fall through to reality_accept's TLS cover path, not
                            // get a bare accept-time RST (which re-opens the RT #9
                            // distinguisher on the flagship transport - red-team
                            // HIGH #6).
                            shadow_active: config.shadow_target.is_some()
                                || config.http_shadow_target.is_some()
                                || (config.reality_enabled
                                    && (config.reality_cover_addr.is_some()
                                        || !config.reality_cover_addrs.is_empty())),
                            ..Default::default()
                        },
                    ));
                    cohort_gatekeeper = Some(Arc::clone(&gatekeeper));

                    // CohortReplayCoordinator - wraps the SAME SyncReplaySet
                    // so gossip-ingested TokenBurned events land in the
                    // bridge's authoritative replay set.
                    let coord = Arc::new(CohortReplayCoordinator::new(
                        gossip.clone(),
                        bridge_ed_sk.clone(),
                        Arc::clone(&replay_set),
                        3600,
                    ));
                    cohort_replay_coord = Some(Arc::clone(&coord));

                    // PeerDistressMap - absorbs EntryDistressed gossip.
                    let distress_map = Arc::new(PeerDistressMap::new(Duration::from_secs(120)));
                    let _sub =
                        spawn_gossip_to_distress_map(gossip.clone(), Arc::clone(&distress_map));
                    _cohort_peer_distress_map = Some(distress_map);

                    // CohortDistressMonitor - publishes EntryDistressed
                    // when session load exceeds 80 %.
                    let sensor = Arc::new(SemaphoreLoadSensor {
                        max_permits: config.max_concurrent_sessions,
                        active: Arc::clone(&active_sessions),
                    });
                    let distress_monitor = CohortDistressMonitor::new(
                        gossip.clone(),
                        bridge_ed_sk.clone(),
                        sensor,
                        DistressMonitorConfig {
                            sample_interval: Duration::from_secs(5),
                            publish_threshold: 204, // 80 % of 255
                            republish_interval: Duration::from_secs(60),
                            peer_entry_ttl: Duration::from_secs(120),
                            min_publish_interval: Duration::from_secs(10),
                        },
                    );
                    _cohort_distress_monitor = Some(distress_monitor);

                    // LivePeerTracker + CohortHeartbeat.
                    let live_tracker = Arc::new(LivePeerTracker::new());
                    let _live_sub =
                        spawn_gossip_to_live_tracker(gossip.clone(), Arc::clone(&live_tracker));
                    let heartbeat = CohortHeartbeat::new(
                        gossip.clone(),
                        bridge_ed_sk.clone(),
                        Arc::clone(&live_tracker),
                        HeartbeatConfig {
                            heartbeat_interval: Duration::from_secs(30),
                            alive_window: Duration::from_secs(90),
                            reap_after: Duration::from_secs(3600),
                        },
                    );
                    _cohort_heartbeat = Some(heartbeat);
                    _cohort_live_tracker = Some(live_tracker);

                    // Cross-bridge leaked-invite detector (optional):
                    // requires a cohort-wide claim-tag key shared by
                    // every bridge. When present, install the claim-
                    // observation publisher on `claim` and subscribe a
                    // detector that correlates peers' claim tags.
                    _cohort_leak_detector = match config.cohort_claim_tag_key_hex.as_deref() {
                        Some(hex_str) => match decode_key32(hex_str, "cohort_claim_tag_key_hex") {
                            Ok(cohort_tag_key) => {
                                let window = config
                                    .cohort_leak_window_secs
                                    .map(Duration::from_secs)
                                    .unwrap_or(mirage_bridge::DEFAULT_LEAK_WINDOW);
                                let detector = Arc::new(mirage_bridge::LeakDetector::new(window));
                                let _leak_sub = mirage_bridge::spawn_gossip_to_leak_detector(
                                    gossip.clone(),
                                    Arc::clone(&detector),
                                );
                                claim.set_observer(ClaimGossipPublisher {
                                    gossip: gossip.clone(),
                                    signing_key: bridge_ed_sk.clone(),
                                    cohort_tag_key,
                                });
                                info!(
                                    window_secs = window.as_secs(),
                                    "cohort leak detector: active (claim-observation tags \
                                     published + correlated for cross-bridge equivocation)"
                                );
                                Some(detector)
                            }
                            Err(e) => {
                                warn!(
                                    error = %e,
                                    "cohort_claim_tag_key_hex invalid; cross-bridge leak \
                                     detector disabled"
                                );
                                None
                            }
                        },
                        None => {
                            debug!(
                                "cohort_claim_tag_key_hex not set; cross-bridge leak detector \
                                 disabled (single-bridge claim dedup still active)"
                            );
                            None
                        }
                    };

                    gossip_handle = Some(gossip);

                    info!(
                        peers = config.gossip_peers.len(),
                        "cohort gossip: full cooperation stack active \
                         (probe-defense, replay-coord, distress, heartbeat)"
                    );
                }
                Err(e) => {
                    warn!(
                        bind = %gossip_bind_str,
                        error = %e,
                        "cohort gossip: bind failed; running without cooperation stack"
                    );
                    cohort_gatekeeper = None;
                    cohort_replay_coord = None;
                    _cohort_distress_monitor = None;
                    _cohort_heartbeat = None;
                    _cohort_peer_distress_map = None;
                    _cohort_live_tracker = None;
                    _cohort_leak_detector = None;
                    gossip_handle = None;
                }
            }
        } else {
            warn!(
                "gossip_bind is set but bridge_ed25519_sk_hex is absent; \
                 gossip requires the bridge signing key. Cooperation disabled."
            );
            cohort_gatekeeper = None;
            cohort_replay_coord = None;
            _cohort_distress_monitor = None;
            _cohort_heartbeat = None;
            _cohort_peer_distress_map = None;
            _cohort_live_tracker = None;
            _cohort_leak_detector = None;
            gossip_handle = None;
        }
    } else {
        cohort_gatekeeper = None;
        cohort_replay_coord = None;
        _cohort_distress_monitor = None;
        _cohort_heartbeat = None;
        _cohort_peer_distress_map = None;
        _cohort_live_tracker = None;
        _cohort_leak_detector = None;
        gossip_handle = None;
    }

    // Reality carrier setup (optional).
    let reality_cfg = if config.reality_enabled {
        // Build the cover-pool: concatenate the legacy single
        // `reality_cover_addr` with the new `reality_cover_addrs`
        // pool. Per-entry resolution failures are logged and skipped
        // (so a partially-broken DNS doesn't take down the bridge).
        let mut raw_entries: Vec<String> = Vec::new();
        if let Some(s) = config.reality_cover_addr.as_deref() {
            raw_entries.push(s.to_string());
        }
        raw_entries.extend(config.reality_cover_addrs.iter().cloned());
        if raw_entries.is_empty() {
            fatal("reality_enabled=true requires reality_cover_addr or reality_cover_addrs");
        }
        // Fail-closed on the generated-sample placeholder. A bridge fronting a
        // reserved/example/placeholder host presents an obviously-fake cover
        // (and `.invalid` never resolves), so refuse to start until the operator
        // sets a real, high-traffic host they actually front. This turns the
        // keygen sample's `REPLACE-WITH-REAL-CDN-HOST.invalid` sentinel into a
        // clear error instead of a silent empty cover pool.
        for entry in &raw_entries {
            let host = entry.rsplit_once(':').map_or(entry.as_str(), |(h, _)| h);
            if host.contains("REPLACE-WITH")
                || host.eq_ignore_ascii_case("www.example.com")
                || host.eq_ignore_ascii_case("example.com")
                || host
                    .rsplit_once('.')
                    .is_some_and(|(_, tld)| tld.eq_ignore_ascii_case("invalid"))
            {
                fatal(&format!(
                    "reality_cover_addr {entry:?} is a placeholder - set a real, \
                     high-traffic CDN/host you actually front before starting the bridge"
                ));
            }
        }
        let mut cover_pool: Vec<std::net::SocketAddr> = Vec::with_capacity(raw_entries.len());
        // (addr, SNI host) pairs retained so startup flight-profiling probes the
        // cover with its real hostname - SNI-based vhosting means the wrong SNI
        // would fetch a different cert and mis-size the padding target.
        let mut cover_hosts: Vec<(std::net::SocketAddr, String)> =
            Vec::with_capacity(raw_entries.len());
        for entry in &raw_entries {
            match entry.to_socket_addrs_first() {
                Ok(addr) => {
                    cover_pool.push(addr);
                    let host = entry
                        .rsplit_once(':')
                        .map_or(entry.as_str(), |(h, _)| h)
                        .to_string();
                    cover_hosts.push((addr, host));
                }
                Err(e) => {
                    warn!(entry = %entry, error = %e, "reality_cover_addrs: skipping entry that failed to resolve");
                }
            }
        }
        if cover_pool.is_empty() {
            fatal("reality cover pool resolved empty; refusing to start");
        }
        let cover_pool_size = cover_pool.len();
        if cover_pool_size < 2 {
            warn!(
                count = cover_pool_size,
                "reality cover pool has only one destination; IP-fanout flow correlation is\
                 detectable; >= 4 destinations recommended."
            );
        }
        let tls_identity = load_tls_identity(&config)
            .await
            .unwrap_or_else(|e| fatal(&e));
        let tls_mode_name = match tls_identity {
            Some(_) => "pinned",
            None => "ephemeral",
        };
        info!(
            mode = tls_mode_name,
            cover_pool_size, "reality TLS identity loaded"
        );
        // Anti-enumeration posture (epoch-ratcheted probe). Epoch binding is
        // always active on a real bridge (the derived root is non-zero); whether
        // it actually CLOSES pubkey-only enumeration depends on rejecting legacy
        // probes. The default is now secure (reject); this warns only the operator
        // who has DELIBERATELY re-opened the hole for a rollover.
        if config.reality_probe_accept_legacy {
            warn!(
                "reality anti-probe: accepting LEGACY probes \
                 (reality_probe_accept_legacy=true, EXPLICITLY set) - a censor who \
                 scraped the public announcement can still confirm this bridge. This is \
                 only safe during a key rollover; set reality_probe_accept_legacy=false \
                 (the default) as soon as your clients hold fresh probe_root-bearing invites."
            );
        } else {
            info!("reality anti-probe: epoch-bound probes enforced (legacy probes rejected)");
        }
        // Profile each cover's real TLS 1.3 server-flight size once, so the
        // authenticated path can pad its synthesized Certificate flight up to
        // match (closes the self-signed-flight-too-small distinguisher). Runs
        // concurrently, best-effort, time-bounded; an un-probeable cover falls
        // back to a generic ~3.5 KB target (still far better than un-padded).
        let cover_flight_targets = probe_cover_flight_targets(&cover_hosts).await;
        Some(Arc::new(RealityDispatchConfig {
            bridge_static_sk: StaticSecret::from(keys.bridge_x25519_sk),
            probe_root: mirage_transport_reality::derive_probe_root(&keys.bridge_x25519_sk),
            probe_accept_legacy: config.reality_probe_accept_legacy,
            cover_pool,
            ch_timeout: Duration::from_secs(config.reality_client_hello_timeout_secs),
            cover_cap: Duration::from_secs(config.reality_cover_duration_cap_secs),
            replay_probe_set: Arc::new(Mutex::new(ReplayProbeSet::new(65_536))),
            tls_identity: tls_identity.map(Arc::new),
            cover_flight_targets,
        }))
    } else {
        None
    };

    // Protocol multiplexer config (v0.2 transport integration).
    // When mux_enabled, every primary/derived listener TCP accept
    // passes through ProtocolMux.accept() before dispatching to
    // transport-specific handlers. The mux classifies by first-bytes
    // sniff: TLS->Reality, HTTP->WS/meek, obfs-tagged->obfs-tcp,
    // SS-2022 tag->Shadowsocks. Unknown bytes fall through to cover.
    let mux_cfg_opt: Option<Arc<MuxConfig>> = if config.mux_enabled {
        let bridge_x_pk_for_mux = {
            let sk = StaticSecret::from(keys.bridge_x25519_sk);
            *PublicKey::from(&sk).as_bytes()
        };
        let ss_psk = config.ss2022_psk_hex.as_deref().map(|hex_str| {
            let mut bytes = [0u8; 32];
            hex::decode_to_slice(hex_str.trim(), &mut bytes)
                .expect("valid ss2022_psk_hex (32-byte hex)");
            bytes
        });
        let vless_uuid = config.vless_uuid_hex.as_deref().map(|hex_str| {
            // Accept both plain 32-char hex and standard UUID format
            // (with dashes: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).
            // Strip hyphens first so both forms parse identically.
            let normalized: String = hex_str.trim().chars().filter(|&c| c != '-').collect();
            let raw = hex::decode(&normalized)
                .expect("valid vless_uuid_hex (hex with or without dashes)");
            raw.try_into()
                .expect("vless_uuid_hex must be exactly 16 bytes after dash-stripping")
        });
        // #9: the raw per-bridge obfs secret (same value embedded in invites as
        // INVITE_EXT_QUIC_OBFS_SECRET). When present, obfs-tcp knocks are
        // verified against the secret-keyed tag, so a pubkey-only prober cannot
        // forge one. A malformed value falls through to pubkey verification.
        let obfs_secret: Option<[u8; 32]> = config
            .quic_obfs_secret_hex
            .as_deref()
            .filter(|s| !s.is_empty())
            .and_then(|hex| decode_key32(hex, "quic_obfs_secret_hex").ok());
        Some(Arc::new(MuxConfig {
            bridge_static_pk: bridge_x_pk_for_mux,
            obfs_secret,
            // Static secret for WebRTC SDP-seal ECDH (#10).
            bridge_static_sk: keys.bridge_x25519_sk,
            ss_psk,
            // C1: accept the relay-leg SS-2022 wrap when this node can be an
            // inbound relay target. Derived from our OWN pubkey; a dialing peer
            // derives the identical PSK from this pubkey (the next-hop it dials).
            relay_ss_psk: if config.circuit_relay_enabled {
                Some(mirage_bridge::next_hop_link::derive_relay_ss_psk(
                    &bridge_x_pk_for_mux,
                ))
            } else {
                None
            },
            obfs_enabled: config.obfs_enabled,
            vless_uuid,
        }))
    } else {
        None
    };

    // Metrics: in-process counters + optional Prometheus endpoint.
    // Constructed with deployment labels so the `info` gauge tags
    // scraped metrics with the bridge's transport + TLS mode.
    let tls_mode_label = match &reality_cfg {
        Some(rc) => {
            if rc.tls_identity.is_some() {
                "pinned"
            } else {
                "ephemeral"
            }
        }
        None => "n/a",
    };
    let transport_label = if reality_cfg.is_some() {
        "reality-v0.1c"
    } else {
        "raw"
    };
    let metrics = Arc::new(Metrics::new(
        env!("CARGO_PKG_VERSION"),
        transport_label,
        tls_mode_label,
    ));

    if let Some(bind) = config.metrics_bind.clone() {
        let listener = TcpListener::bind(&bind)
            .await
            .unwrap_or_else(|e| fatal(&format!("metrics bind {bind}: {e}")));
        let addr = listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| bind.clone());
        info!(bind = %addr, "metrics endpoint: /metrics");
        let m = Arc::clone(&metrics);
        let rs_for_metrics = Arc::clone(&replay_set);
        let replay_size_fn: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(move || {
            // Snapshot via SyncReplaySet's len(). The internal
            // std::sync::Mutex critical section is sub-microsecond
            // and never blocks on .await, so we can take it
            // synchronously here. On poison: returns 0 (metrics-
            // only; not a security predicate).
            rs_for_metrics.len() as u64
        });
        tokio::spawn(async move { serve_metrics(listener, m, replay_size_fn).await });
    }

    // In-process operator admin UI (opt-in). Reads live counters, edits this
    // config file (secret-preserving, atomic 0600), and can restart the systemd
    // unit. Token-gated + loopback-only; see `admin` module docs.
    if let Some(bind) = admin_ui_cli.clone().or_else(|| config.admin_bind.clone()) {
        admin::warn_if_public(&bind);
        match TcpListener::bind(&bind).await {
            Ok(listener) => {
                let addr = listener
                    .local_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| bind.clone());
                let token = admin::gen_token();
                admin::log_access_url(&addr, &token);
                let rs_for_admin = Arc::clone(&replay_set);
                let replay_size_fn: Arc<dyn Fn() -> u64 + Send + Sync> =
                    Arc::new(move || rs_for_admin.len() as u64);
                let state = Arc::new(admin::AdminState {
                    config_path: config_path.clone(),
                    metrics: Arc::clone(&metrics),
                    replay_size_fn,
                    start_time: std::time::Instant::now(),
                    token,
                    service_name: config.admin_service.clone(),
                });
                tokio::spawn(async move { admin::serve_admin(listener, state).await });
            }
            Err(e) => warn!(addr = %bind, error = %e, "admin UI bind failed; admin UI disabled"),
        }
    }

    // Gossip-event metrics subscriber: counts inbound gossip events by kind
    // for the mirage_cohort_events_received_total counter family.
    if let Some(ref gh) = gossip_handle {
        use mirage_discovery::cohort_gossip::GossipEvent;
        let mut rx = gh.subscribe().await;
        let m = Arc::clone(&metrics);
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(signed) => match signed.event {
                        GossipEvent::ProbeScanDetected { .. } => m.gossip_event_probe_block(),
                        GossipEvent::TokenBurned { .. } => m.gossip_event_burn(),
                        GossipEvent::EntryDistressed { .. } => m.gossip_event_distress(),
                        GossipEvent::CohortMembership { .. } => m.gossip_event_heartbeat(),
                        GossipEvent::ClaimObserved { .. } => m.gossip_event_claim_observed(),
                    },
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                }
            }
        });
    }

    let primary_listener = TcpListener::bind(&config.bind)
        .await
        .unwrap_or_else(|e| fatal(&format!("bind {}: {e}", config.bind)));

    // Info-hash-derived port multi-bind (v0.1o, A35).
    // When the operator configures both `derived_port_base` and
    // `derived_port_range` plus a `derived_port_shared_salt_hex`,
    // the bridge ALSO binds on the current epoch's derived port
    // and the next epoch's, so connections landing on either
    // (across an epoch tick) are accepted. The primary `bind`
    // continues to listen for legacy clients that don't compute
    // the derived port.
    let derived_listeners = setup_derived_listeners(&config).await;

    let anonymize_target_logs = config.anonymize_target_logs;
    // Initialise client-IP log anonymization (default on) before any session
    // logging happens.
    init_client_log_anonymization(config.anonymize_client_logs);
    MUX_ENABLED.store(config.stream_mux_enabled, Ordering::Relaxed);
    // Relay mesh: parse the configured peer bridges into (a) the OUTBOUND dial
    // token map (extend-to capability) and (b) the INBOUND authorized-peer key
    // set (recognize a relay leg -> per-hop-token-verifying relay mode). Both
    // feed the circuit-relay accept path.
    {
        let mesh = parse_relay_peers(&config.relay_peers);
        if !mesh.dial_tokens.is_empty() {
            info!(
                peers = mesh.dial_tokens.len(),
                "relay mesh: outbound extend-capable (can dial next hops)"
            );
        }
        if !mesh.authorized_keys.is_empty() {
            info!(
                peers = mesh.authorized_keys.len(),
                "relay mesh: inbound relay legs authorized (acts as exit/middle hop)"
            );
        }
        let _ = RELAY_PEER_TOKENS.set(Arc::new(mesh.dial_tokens));
        let _ = RELAY_PEER_KEYS.set(Arc::new(mesh.authorized_keys));
    }
    if !config.anonymize_client_logs {
        warn!(
            "anonymize_client_logs is FALSE: per-session logs will record raw client \
             IP addresses. A seized bridge log will reveal which clients connected."
        );
    }
    let transport_mode = if reality_cfg.is_some() {
        "reality-v0.1c"
    } else {
        "raw"
    };
    let hysteria2_active = config.hysteria2_bind.is_some() || config.hysteria2_enabled;
    let bridge_pk_fingerprint = &hex::encode(keys.bridge_ed25519_pk)[..16];
    info!(
        bind = %config.bind,
        replay_capacity = config.replay_capacity,
        max_concurrent_sessions = config.max_concurrent_sessions,
        allow_loopback = config.allow_loopback_targets,
        allow_private = config.allow_private_network_targets,
        anonymize_target_logs,
        transport = transport_mode,
        hysteria2 = hysteria2_active,
        circuit_relay = config.circuit_relay_enabled,
        bridge_pk = %bridge_pk_fingerprint,
        "mirage-bridge: accepting SOCKS5-over-Mirage sessions"
    );
    if !anonymize_target_logs {
        warn!(
            "anonymize_target_logs is FALSE: per-session logs will record client-requested \
             hostnames and ports. Do NOT ship these logs to any shared infrastructure."
        );
    }

    info!(
        rate_limit_per_minute = config.rate_limit_per_ip_per_minute,
        max_concurrent_per_ip = config.max_concurrent_per_ip,
        "per-peer rate-limit engaged"
    );

    // C1: relay-leg SS-2022 obfuscation is unwrapped by the protocol mux. A
    // relay TARGET with the mux disabled cannot unwrap an obfuscated relay leg
    // (its raw dispatch expects a bare session), so relay legs to it would fail.
    if config.circuit_relay_enabled && !config.mux_enabled {
        warn!(
            "circuit_relay_enabled with mux_enabled=false: inbound relay legs are \
             SS-2022-obfuscated (C1) and are unwrapped only by the protocol mux. \
             Enable mux_enabled (the default) on relay-target bridges, or peers \
             dialing this node as a relay hop will fail to connect."
        );
    }

    // Merge accepts from the primary listener + every derived
    // listener into a single channel. The accept loop below pulls
    // from that channel.
    let (accept_tx, mut accept_rx) =
        tokio::sync::mpsc::channel::<(TcpStream, std::net::SocketAddr)>(1024);
    for (label, l) in std::iter::once(("primary", primary_listener)).chain(
        derived_listeners.into_iter().map(|(p, l)| {
            let leaked: &'static str = Box::leak(format!("derived:{p}").into_boxed_str());
            (leaked, l)
        }),
    ) {
        let tx = accept_tx.clone();
        tokio::spawn(async move {
            loop {
                match l.accept().await {
                    Ok((sock, peer)) => {
                        if tx.send((sock, peer)).await.is_err() {
                            return; // accept loop closed
                        }
                    }
                    Err(e) => {
                        error!(listener = %label, error = %e, "accept failed; backing off");
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                }
            }
        });
    }
    drop(accept_tx); // the spawned tasks each hold their own clone

    // Hysteria2 QUIC accept loop. When hysteria2_enabled=true (and no
    // explicit hysteria2_bind override), binds UDP on the same host:port
    // as the primary TCP listener. TCP:N + UDP:N is indistinguishable
    // from an HTTP/3 server - zero extra external ports.
    let h2_bind_opt: Option<std::net::SocketAddr> = if let Some(ref explicit) =
        config.hysteria2_bind
    {
        match explicit.parse::<std::net::SocketAddr>() {
            Ok(a) => {
                let primary_port = config
                    .bind
                    .rsplit_once(':')
                    .and_then(|(_, p)| p.parse::<u16>().ok())
                    .unwrap_or(0);
                if a.port() != primary_port {
                    warn!(
                        primary_port,
                        hysteria2_port = a.port(),
                        "hysteria2_bind uses a DIFFERENT port number than `bind` - \
                         this adds a second external socket. Prefer removing \
                         hysteria2_bind and setting hysteria2_enabled=true instead."
                    );
                }
                Some(a)
            }
            Err(e) => {
                error!(addr = %explicit, error = %e, "hysteria2_bind: invalid address; Hysteria2 disabled");
                None
            }
        }
    } else if config.hysteria2_enabled {
        match config.bind.parse::<std::net::SocketAddr>() {
            Ok(a) => {
                info!(
                    addr = %a,
                    "hysteria2: sharing port with primary TCP listener (UDP - looks like HTTP/3)"
                );
                Some(a)
            }
            Err(e) => {
                error!(error = %e, "hysteria2_enabled: cannot parse primary bind address for UDP; Hysteria2 disabled");
                None
            }
        }
    } else {
        None
    };

    // Traffic-padding config (None when pad_enabled = false).
    let pad_config: Option<PadConfig> = if config.pad_enabled {
        Some(PadConfig {
            cbr_frame_bytes: config.pad_cbr_frame_bytes,
            cbr_interval_ms: config.pad_cbr_interval_ms,
            ..PadConfig::default()
        })
    } else {
        None
    };

    if let Some(h2_bind_addr) = h2_bind_opt {
        let bridge_x_pk_h2 = {
            let sk = StaticSecret::from(keys.bridge_x25519_sk);
            *PublicKey::from(&sk).as_bytes()
        };
        let h2_send_rate_bps = config
            .hysteria2_send_rate_mbps
            .saturating_mul(1_000_000)
            .saturating_div(8);
        let circuit_relay_h2 = config.circuit_relay_enabled;
        let h2_hostname = config.hysteria2_hostname.clone();
        // Obfs is ON by default. Key precedence (matches the client's
        // resolve_obfs_key): quic_obfs_password > quic_obfs_secret_hex (also in
        // the invite) > pubkey-derived default, so the QUIC handshake is never a
        // parseable fingerprint on the wire and is secret-grade when an invite
        // secret is configured.
        let (h2_obfs_key, h2_obfs_mode) = resolve_bridge_obfs_key(
            config.quic_obfs_password.as_deref(),
            config.quic_obfs_secret_hex.as_deref(),
            &bridge_x_pk_h2,
        );
        // red-team #9: Salamander XOR => uniform-random datagrams (Wu FET tell).
        // Plain QUIC evades that but re-exposes the quinn!=Chrome fingerprint +
        // self-signed-cert active-probe oracle; must match the client's flag.
        let h2_obfs_key_opt = if config.quic_obfs_disable {
            warn!(addr = %h2_bind_addr, "hysteria2: Salamander obfs DISABLED (quic_obfs_disable) - \
                   plain parseable QUIC. Evades the Wu entropy classifier but re-exposes the \
                   quinn!=Chrome QUIC fingerprint + a self-signed-cert probe oracle: front this \
                   bridge with a real CA-cert origin. The CLIENT must also set quic_obfs_disable.");
            None
        } else {
            Some(h2_obfs_key)
        };
        // Build the QUIC server config ONCE; each listener clones it.
        let h2_cfg = Hysteria2ServerConfig {
            bridge_static_pk: bridge_x_pk_h2,
            send_rate_bps: h2_send_rate_bps,
            hostname: h2_hostname,
            obfs_key: h2_obfs_key_opt,
            cert_der_path: config
                .hysteria2_cert_der_path
                .as_ref()
                .map(std::path::PathBuf::from),
            key_der_path: config
                .hysteria2_key_der_path
                .as_ref()
                .map(std::path::PathBuf::from),
            brutal_cc: config.hysteria2_brutal,
        };
        // M4: bind the primary UDP port PLUS the current+next epoch derived UDP
        // ports (the SAME epoch derivation as the TCP port-hop listeners), so a
        // censor blocking the static UDP port cannot kill the QUIC carrier. Each
        // port runs an identical, independent accept loop with the SAME per-IP
        // rate limit + cohort soft-block + session semaphore (no bypass).
        let mut h2_bind_addrs = vec![h2_bind_addr];
        let h2_derived = derived_udp_bind_addrs(&config, h2_bind_addr);
        if !h2_derived.is_empty() {
            info!(
                count = h2_derived.len(),
                "hysteria2: adding derived-port UDP listeners (port-hop)"
            );
        }
        h2_bind_addrs.extend(h2_derived);
        for h2_bind_addr in h2_bind_addrs {
            let h2_cfg = h2_cfg.clone();
            let keys_h2 = Arc::new(keys_to_copy(&keys));
            let replay_h2 = Arc::clone(&replay_set);
            let policy_h2 = Arc::clone(&policy);
            let cohort_h2 = Arc::clone(&cohort);
            let refresh_h2 = Arc::clone(&refresh);
            let claim_h2 = Arc::clone(&claim);
            let gk_h2 = cohort_gatekeeper.clone();
            let rc_h2 = cohort_replay_coord.clone();
            let metrics_h2 = Arc::clone(&metrics);
            let session_sem_h2 = Arc::clone(&session_semaphore);
            let peer_limiter_h2 = Arc::clone(&peer_limiter);
            let pad_cfg_h2 = pad_config.clone();
            info!(addr = %h2_bind_addr, obfs = h2_obfs_mode, "hysteria2: QUIC listener starting");
            tokio::spawn(async move {
                let server = match Hysteria2Server::bind(&h2_cfg, h2_bind_addr) {
                    Ok(s) => s,
                    Err(e) => {
                        error!(addr = %h2_bind_addr, error = %e, "hysteria2: bind failed");
                        return;
                    }
                };
                info!(addr = %h2_bind_addr, "hysteria2: QUIC endpoint bound");
                loop {
                    match server.accept_one(handshake_timeout).await {
                        None => {
                            info!("hysteria2: endpoint closed; exiting accept loop");
                            break;
                        }
                        Some(Err(e)) => {
                            debug!(error = %e, "hysteria2: connection rejected");
                            continue;
                        }
                        Some(Ok(stream)) => {
                            // RT #17: the Hysteria2 path MUST apply the SAME per-IP
                            // rate limit + cohort soft-block as the TCP accept loop,
                            // keyed on the REAL QUIC peer (previously hardcoded to
                            // 0.0.0.0:0, so H2 was a total bypass - single-IP
                            // exhaustion of the global session semaphore + probe
                            // detector poisoned with 0.0.0.0).
                            let peer: std::net::SocketAddr = stream.remote_addr();
                            let peer_guard = match peer_limiter_h2.try_acquire(peer.ip()) {
                                Some(g) => g,
                                None => {
                                    debug!(client = %plog(&peer), "hysteria2: rate-limited; dropping");
                                    metrics_h2.rate_limit_drop();
                                    continue;
                                }
                            };
                            if let Some(ref gk) = gk_h2 {
                                if !gk.should_accept(peer.ip()).await {
                                    debug!(client = %plog(&peer), "hysteria2: cohort soft-blocked; dropping");
                                    metrics_h2.rate_limit_drop();
                                    continue;
                                }
                            }
                            let permit = match Arc::clone(&session_sem_h2).acquire_owned().await {
                                Ok(p) => p,
                                Err(_) => break,
                            };
                            let keys_task = Arc::clone(&keys_h2);
                            let replay_task = Arc::clone(&replay_h2);
                            let policy_task = Arc::clone(&policy_h2);
                            let cohort_task = Arc::clone(&cohort_h2);
                            let refresh_task = Arc::clone(&refresh_h2);
                            let claim_task = Arc::clone(&claim_h2);
                            let gk_task = gk_h2.clone();
                            let rc_task = rc_h2.clone();
                            let metrics_task = Arc::clone(&metrics_h2);
                            let pad_cfg = pad_cfg_h2.clone();
                            tokio::spawn(async move {
                                let _permit = permit;
                                // Hold the per-IP slot for the session's lifetime.
                                let _peer_guard = peer_guard;
                                metrics_task.session_accepted();
                                metrics_task
                                    .session_by_transport(crate::metrics::TRANSPORT_HYSTERIA2);
                                let res = run_authenticated_session(
                                    into_session_stream(stream, pad_cfg.as_ref()),
                                    peer,
                                    keys_task,
                                    replay_task,
                                    handshake_timeout,
                                    policy_task,
                                    socks5_timeout,
                                    anonymize_target_logs,
                                    circuit_relay_h2,
                                    cohort_task,
                                    refresh_task,
                                    claim_task,
                                    gk_task,
                                    rc_task,
                                    Arc::clone(&metrics_task),
                                )
                                .await;
                                match &res {
                                    Ok(()) => metrics_task.session_closed_ok(),
                                    Err(_) => metrics_task.session_closed_err(),
                                }
                                if let Err(e) = res {
                                    debug!(error = %e, "hysteria2 session ended with error");
                                }
                            });
                        }
                    }
                }
            });
        }
    }

    // HTTP/3 (MASQUE) QUIC listener. Binds UDP on the same host:port as the
    // primary TCP `bind`; QUIC + ALPN `h3` + HTTP/3 framing looks like an
    // HTTP/3 web origin. Mutually exclusive with hysteria2 on the same port.
    if config.h3_enabled {
        match config.bind.parse::<std::net::SocketAddr>() {
            Ok(h3_addr) => {
                let keys_h3 = Arc::new(keys_to_copy(&keys));
                let replay_h3 = Arc::clone(&replay_set);
                let policy_h3 = Arc::clone(&policy);
                let cohort_h3 = Arc::clone(&cohort);
                let refresh_h3 = Arc::clone(&refresh);
                let claim_h3 = Arc::clone(&claim);
                let gk_h3 = cohort_gatekeeper.clone();
                let rc_h3 = cohort_replay_coord.clone();
                let metrics_h3 = Arc::clone(&metrics);
                let session_sem_h3 = Arc::clone(&session_semaphore);
                let peer_limiter_h3 = Arc::clone(&peer_limiter);
                let pad_cfg_h3 = pad_config.clone();
                let circuit_relay_h3 = config.circuit_relay_enabled;
                // Empty hostname -> derive a per-bridge cover SAN from the static
                // key (F9-L: not the RFC 2606 default, not a shared constant).
                let bridge_x_pk_h3 = {
                    let sk = StaticSecret::from(keys.bridge_x25519_sk);
                    *PublicKey::from(&sk).as_bytes()
                };
                let h3_hostname = mirage_transport_hysteria2::effective_cover_hostname(
                    &config.h3_hostname,
                    &bridge_x_pk_h3,
                );
                // Obfs ON by default (see the hysteria2 branch): password ->
                // invite secret -> per-bridge pubkey default.
                let (h3_obfs_key, h3_obfs_mode) = resolve_bridge_obfs_key(
                    config.quic_obfs_password.as_deref(),
                    config.quic_obfs_secret_hex.as_deref(),
                    &bridge_x_pk_h3,
                );
                info!(addr = %h3_addr, hostname = %h3_hostname, obfs = h3_obfs_mode, "h3: QUIC/HTTP3 listener starting");
                // red-team #9: same Salamander-vs-plain-QUIC toggle as hysteria2.
                let h3_obfs_key_opt = if config.quic_obfs_disable {
                    warn!(addr = %h3_addr, "h3: Salamander obfs DISABLED (quic_obfs_disable) - plain \
                           parseable QUIC; re-exposes the quinn!=Chrome fingerprint + probe oracle, \
                           front with a real CA-cert origin. The CLIENT must also set the flag.");
                    None
                } else {
                    Some(h3_obfs_key)
                };
                tokio::spawn(async move {
                    let endpoint = match mirage_transport_masque::h3::h3_server_endpoint(
                        h3_addr,
                        &h3_hostname,
                        h3_obfs_key_opt,
                    ) {
                        Ok(e) => e,
                        Err(e) => {
                            error!(addr = %h3_addr, error = %e, "h3: bind failed");
                            return;
                        }
                    };
                    info!(addr = %h3_addr, "h3: QUIC endpoint bound");
                    loop {
                        let incoming = match endpoint.accept().await {
                            Some(i) => i,
                            None => {
                                info!("h3: endpoint closed; exiting accept loop");
                                break;
                            }
                        };
                        let keys_t = Arc::clone(&keys_h3);
                        let replay_t = Arc::clone(&replay_h3);
                        let policy_t = Arc::clone(&policy_h3);
                        let cohort_t = Arc::clone(&cohort_h3);
                        let refresh_t = Arc::clone(&refresh_h3);
                        let claim_t = Arc::clone(&claim_h3);
                        let gk_t = gk_h3.clone();
                        let rc_t = rc_h3.clone();
                        let metrics_t = Arc::clone(&metrics_h3);
                        let session_sem_t = Arc::clone(&session_sem_h3);
                        let peer_limiter_t = Arc::clone(&peer_limiter_h3);
                        let pad_cfg_t = pad_cfg_h3.clone();
                        tokio::spawn(async move {
                            let conn = match incoming.await {
                                Ok(c) => c,
                                Err(e) => {
                                    debug!(error = %e, "h3: connection handshake failed");
                                    return;
                                }
                            };
                            let peer = conn.remote_address();
                            // Same per-IP rate limit + cohort soft-block as the
                            // TCP path, keyed on the real QUIC peer.
                            let _peer_guard = match peer_limiter_t.try_acquire(peer.ip()) {
                                Some(g) => g,
                                None => {
                                    debug!(client = %plog(&peer), "h3: rate-limited; dropping");
                                    metrics_t.rate_limit_drop();
                                    return;
                                }
                            };
                            if let Some(ref gk) = gk_t {
                                if !gk.should_accept(peer.ip()).await {
                                    debug!(client = %plog(&peer), "h3: cohort soft-blocked; dropping");
                                    metrics_t.rate_limit_drop();
                                    return;
                                }
                            }
                            let _permit = match Arc::clone(&session_sem_t).acquire_owned().await {
                                Ok(p) => p,
                                Err(_) => return,
                            };
                            let h3_stream =
                                match mirage_transport_masque::h3::h3_server_accept_conn(conn).await
                                {
                                    Ok(s) => s,
                                    Err(e) => {
                                        debug!(client = %plog(&peer), error = %e, "h3: accept failed");
                                        return;
                                    }
                                };
                            metrics_t.session_accepted();
                            let res = run_authenticated_session(
                                into_session_stream(h3_stream, pad_cfg_t.as_ref()),
                                peer,
                                keys_t,
                                replay_t,
                                handshake_timeout,
                                policy_t,
                                socks5_timeout,
                                anonymize_target_logs,
                                circuit_relay_h3,
                                cohort_t,
                                refresh_t,
                                claim_t,
                                gk_t,
                                rc_t,
                                Arc::clone(&metrics_t),
                            )
                            .await;
                            match &res {
                                Ok(()) => metrics_t.session_closed_ok(),
                                Err(_) => metrics_t.session_closed_err(),
                            }
                            if let Err(e) = res {
                                debug!(client = %plog(&peer), error = %e, "h3 session ended with error");
                            }
                        });
                    }
                });
            }
            Err(e) => {
                error!(error = %e, "h3_enabled: cannot parse bind address; H3 disabled");
            }
        }
    }

    // dnstt (full DNS tunnel) listener: a UDP socket answering tunnel queries
    // under `dnstt_domain`; each new session id yields a carrier we run a Mirage
    // session over. dnstt has no stable per-client IP (resolver-fronted), so it
    // relies on the global session semaphore rather than per-IP rate limiting.
    if config.dnstt_enabled {
        match (
            config.dnstt_domain.clone(),
            config.dnstt_bind.parse::<std::net::SocketAddr>(),
        ) {
            (Some(dnstt_domain), Ok(dnstt_addr)) => {
                let keys_d = Arc::new(keys_to_copy(&keys));
                let replay_d = Arc::clone(&replay_set);
                let policy_d = Arc::clone(&policy);
                let cohort_d = Arc::clone(&cohort);
                let refresh_d = Arc::clone(&refresh);
                let claim_d = Arc::clone(&claim);
                let gk_d = cohort_gatekeeper.clone();
                let rc_d = cohort_replay_coord.clone();
                let metrics_d = Arc::clone(&metrics);
                let session_sem_d = Arc::clone(&session_semaphore);
                let pad_cfg_d = pad_config.clone();
                let circuit_relay_d = config.circuit_relay_enabled;
                info!(addr = %dnstt_addr, domain = %dnstt_domain, "dnstt: DNS-tunnel listener starting");
                tokio::spawn(async move {
                    let socket = match tokio::net::UdpSocket::bind(dnstt_addr).await {
                        Ok(s) => Arc::new(s),
                        Err(e) => {
                            error!(addr = %dnstt_addr, error = %e, "dnstt: bind failed");
                            return;
                        }
                    };
                    info!(addr = %dnstt_addr, "dnstt: UDP listener bound");
                    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
                    let serve_sock = Arc::clone(&socket);
                    let dom = dnstt_domain.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            mirage_transport_dnstt::transport::dnstt_serve(serve_sock, &dom, tx)
                                .await
                        {
                            error!(error = %e, "dnstt: serve loop ended");
                        }
                    });
                    while let Some(carrier) = rx.recv().await {
                        let permit = match Arc::clone(&session_sem_d).acquire_owned().await {
                            Ok(p) => p,
                            Err(_) => break,
                        };
                        let keys_t = Arc::clone(&keys_d);
                        let replay_t = Arc::clone(&replay_d);
                        let policy_t = Arc::clone(&policy_d);
                        let cohort_t = Arc::clone(&cohort_d);
                        let refresh_t = Arc::clone(&refresh_d);
                        let claim_t = Arc::clone(&claim_d);
                        let gk_t = gk_d.clone();
                        let rc_t = rc_d.clone();
                        let metrics_t = Arc::clone(&metrics_d);
                        let pad_cfg_t = pad_cfg_d.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            metrics_t.session_accepted();
                            let res = run_authenticated_session(
                                into_session_stream(carrier, pad_cfg_t.as_ref()),
                                dnstt_addr,
                                keys_t,
                                replay_t,
                                handshake_timeout,
                                policy_t,
                                socks5_timeout,
                                anonymize_target_logs,
                                circuit_relay_d,
                                cohort_t,
                                refresh_t,
                                claim_t,
                                gk_t,
                                rc_t,
                                Arc::clone(&metrics_t),
                            )
                            .await;
                            match &res {
                                Ok(()) => metrics_t.session_closed_ok(),
                                Err(_) => metrics_t.session_closed_err(),
                            }
                            if let Err(e) = res {
                                debug!(error = %e, "dnstt session ended with error");
                            }
                        });
                    }
                });
            }
            (None, _) => error!("dnstt_enabled requires dnstt_domain; dnstt disabled"),
            (_, Err(e)) => error!(error = %e, "dnstt_bind: invalid address; dnstt disabled"),
        }
    }

    // Session stores for HTTP-based transports.
    // One store per transport variant so Meek and DoH sessions cannot
    // collide even if a client somehow reuses a session ID across variants.
    let meek_session_store = Arc::new(mirage_transport_meek::MeekSessionStore::new());
    let doh_session_store = Arc::new(mirage_transport_meek::MeekSessionStore::new());
    // RT #8: process-wide replay-nonce set shared across ALL HTTP-ish
    // transport auth attempts (WebSocket / meek / DoH). The auth frames carry
    // a random nonce + a +/-30 s timestamp window; without a seen-set a captured
    // frame replays within the window to confirm a bridge. TTL (300 s) is well
    // above any transport's skew window; capacity-bounded against flooding.
    let http_auth_replay = Arc::new(mirage_transport::SeenNonceSet::new(Duration::from_secs(
        300,
    )));
    // Anti-probe: SS-2022 has no peek-stage timestamp check, so a captured
    // (salt||header) handshake replays and would draw the confirming server
    // response. This set records each 16-byte request salt at the mux peek so a
    // replay falls through to cover instead of confirming the bridge - the
    // active-probe resistance the removed obfs4 carrier used to provide.
    let ss2022_replay = Arc::new(mirage_transport::SeenNonceSet::new(Duration::from_secs(
        300,
    )));
    loop {
        let (sock, peer) = match accept_rx.recv().await {
            Some(v) => v,
            None => {
                info!("all listeners closed; exiting accept loop");
                break;
            }
        };
        sock.set_nodelay(true).ok();

        // Per-peer rate limit: check BEFORE session-semaphore
        // acquire, so a flood of rejects doesn't tie up the global
        // concurrency budget. Dropped connections cost only a TCP
        // socket + hashmap lookup.
        let peer_guard = match peer_limiter.try_acquire(peer.ip()) {
            Some(g) => g,
            None => {
                debug!(client = %plog(&peer), "rate-limited; dropping");
                metrics.rate_limit_drop();
                drop(sock);
                continue;
            }
        };

        // Cohort soft-block: shed flagged IPs before the semaphore
        // acquire. `should_accept` takes a tokio RwLock read-guard
        // that is sub-microsecond on uncontested fast path and does
        // not hold the loop under any real load. Placed BEFORE
        // semaphore acquisition so a flood from a blocked IP never
        // consumes concurrency budget.
        if let Some(ref gk) = cohort_gatekeeper {
            if !gk.should_accept(peer.ip()).await {
                debug!(client = %plog(&peer), "cohort soft-blocked; dropping");
                metrics.rate_limit_drop();
                drop(sock);
                continue;
            }
        }

        let permit = match Arc::clone(&session_semaphore).acquire_owned().await {
            Ok(p) => p,
            Err(_) => {
                info!("session semaphore closed; shutting down accept loop");
                break;
            }
        };

        let replay = Arc::clone(&replay_set);
        let keys_copy = Arc::new(keys_to_copy(&keys));
        let policy = Arc::clone(&policy);
        let reality = reality_cfg.clone();
        let mux_cfg = mux_cfg_opt.clone();
        let cohort = Arc::clone(&cohort);
        let refresh = Arc::clone(&refresh);
        let claim = Arc::clone(&claim);
        let metrics_clone = Arc::clone(&metrics);
        let gatekeeper = cohort_gatekeeper.clone();
        let replay_coord = cohort_replay_coord.clone();
        let active = Arc::clone(&active_sessions);
        let ws_transport_enabled = config.ws_enabled;
        let webrtc_transport_enabled = config.webrtc_enabled;
        let webrtc_ice_servers = config.webrtc_ice_servers.clone();
        let circuit_relay_enabled = config.circuit_relay_enabled;
        let meek_store = Arc::clone(&meek_session_store);
        let doh_store = Arc::clone(&doh_session_store);
        let http_auth_replay = Arc::clone(&http_auth_replay);
        let ss2022_replay = Arc::clone(&ss2022_replay);
        let pad_cfg = pad_config.clone();
        let shadow_tgt = config.shadow_target.clone();
        let http_shadow_tgt = config.http_shadow_target.clone();
        let shadow_cap = Duration::from_secs(config.reality_cover_duration_cap_secs);
        tokio::spawn(async move {
            let _permit = permit;
            let _peer_guard = peer_guard;
            // Increment the active counter HERE (inside the task)
            // so spawn-failure cannot produce a phantom increment.
            // ActiveGuard::Drop decrements on task exit regardless
            // of how the task ends (error, panic, normal return).
            active.fetch_add(1, Ordering::Relaxed);
            let _active_guard = ActiveGuard(active);
            metrics_clone.session_accepted();

            // Protocol mux: when enabled, classify the incoming
            // connection by its first bytes before handing off to a
            // transport-specific handler. Mux runs with the same
            // handshake_timeout so a stalled client cannot hold the
            // slot open past the configured deadline.
            //
            // Dispatch table:
            //   MuxResult::Tls                  -> Reality accept path
            //   MuxResult::Http                 -> WS / meek (Phase 3 stub)
            //   MuxResult::AuthenticatedObfsTcp -> obfs-tcp authenticated stream
            //   MuxResult::AuthenticatedShadowsocks -> SS-2022 AEAD stream
            //   MuxResult::Unknown              -> cover-forward (unauthenticated)
            let (sock, res) = if let Some(ref mc) = mux_cfg {
                let mux = ProtocolMux::new((**mc).clone());
                match mux.accept(sock, handshake_timeout, &ss2022_replay).await {
                    Ok(MuxResult::Tls(s)) => {
                        metrics_clone.session_by_transport(TRANSPORT_REALITY);
                        // Dispatch to Reality handler (or raw if Reality not configured).
                        let res = match &reality {
                            Some(rc) => {
                                handle_session_reality(
                                    s,
                                    peer,
                                    keys_copy,
                                    replay,
                                    handshake_timeout,
                                    policy,
                                    socks5_timeout,
                                    anonymize_target_logs,
                                    Arc::clone(rc),
                                    circuit_relay_enabled,
                                    cohort,
                                    refresh,
                                    claim,
                                    gatekeeper,
                                    replay_coord,
                                    pad_cfg.clone(),
                                    Arc::clone(&metrics_clone),
                                )
                                .await
                            }
                            None => {
                                handle_session_raw(
                                    s,
                                    peer,
                                    keys_copy,
                                    replay,
                                    handshake_timeout,
                                    policy,
                                    socks5_timeout,
                                    anonymize_target_logs,
                                    circuit_relay_enabled,
                                    cohort,
                                    refresh,
                                    claim,
                                    gatekeeper,
                                    replay_coord,
                                    pad_cfg.clone(),
                                    Arc::clone(&metrics_clone),
                                )
                                .await
                            }
                        };
                        match &res {
                            Ok(()) => metrics_clone.session_closed_ok(),
                            Err(_) => metrics_clone.session_closed_err(),
                        }
                        if let Err(e) = res {
                            debug!(client = %plog(&peer), error = %e, "session ended with error");
                        }
                        return;
                    }
                    Ok(MuxResult::Http(s)) => {
                        // WebSocket / DoH / meek dispatch.
                        //
                        // The mux used peek() so the full HTTP request is
                        // still in the socket buffer. We peek up to 1 KiB
                        // to distinguish the three HTTP sub-transports:
                        //   DoH:  POST /dns-query + Content-Type: application/dns-message
                        //   WS:   GET  + Upgrade: websocket
                        //   Meek: POST (any other path / content-type)
                        let bridge_pk = mc.bridge_static_pk;
                        let mut peek_buf = [0u8; 1024];
                        let n = s.peek(&mut peek_buf).await.unwrap_or(0);
                        let peeked = &peek_buf[..n];
                        let is_ws = ws_transport_enabled
                            && peeked
                                .windows(b"upgrade:".len())
                                .any(|w| w.eq_ignore_ascii_case(b"upgrade:"))
                            && peeked
                                .windows(b"websocket".len())
                                .any(|w| w.eq_ignore_ascii_case(b"websocket"));
                        let is_doh = !is_ws
                            && peeked
                                .windows(b"/dns-query".len())
                                .any(|w| w == b"/dns-query")
                            && peeked
                                .windows(b"application/dns-message".len())
                                .any(|w| w.eq_ignore_ascii_case(b"application/dns-message"));
                        // WebRTC signaling: an application/sdp POST. Consumes `s`
                        // only on the matched (diverging) path, so the chain
                        // below is unaffected when it doesn't match / is disabled.
                        if webrtc_transport_enabled
                            && peeked
                                .windows(b"application/sdp".len())
                                .any(|w| w.eq_ignore_ascii_case(b"application/sdp"))
                        {
                            metrics_clone.session_by_transport(crate::metrics::TRANSPORT_WEBRTC);
                            tracing::debug!(
                                client = %plog(&peer),
                                "protocol mux: HTTP -> WebRTC signaling"
                            );
                            let webrtc_deadline = handshake_timeout.max(Duration::from_secs(30));
                            let mut sig = s;
                            // SDP seal (#10): recover the per-exchange seal key via
                            // ephemeral-static ECDH. The client DHs a fresh
                            // ephemeral secret against `bridge_pk`; we DH our static
                            // secret against the transmitted ephemeral pk. The seal
                            // key is secret from a discovery-watcher who only knows
                            // the (public) bridge key.
                            let webrtc_static_sk = StaticSecret::from(mc.bridge_static_sk);
                            let established = async {
                                let (_p, offer, webrtc_seal_key) =
                                    mirage_transport_webrtc::read_offer_request(
                                        &mut sig,
                                        &webrtc_static_sk,
                                    )
                                    .await
                                    .map_err(|e| e.to_string())?;
                                // Reciprocate cover media iff the client offered
                                // an audio m-line (never add an m-line the offer
                                // lacks).
                                let cover = offer.contains("m=audio");
                                let (answer, accept) = mirage_transport_webrtc::webrtc_answer(
                                    offer,
                                    &webrtc_ice_servers,
                                    cover,
                                    webrtc_deadline,
                                )
                                .await
                                .map_err(|e| e.to_string())?;
                                mirage_transport_webrtc::write_answer_response(
                                    &mut sig,
                                    &webrtc_seal_key,
                                    &answer,
                                )
                                .await
                                .map_err(|e| e.to_string())?;
                                accept
                                    .established(webrtc_deadline)
                                    .await
                                    .map_err(|e| e.to_string())
                            }
                            .await;
                            match established {
                                Ok(ws) => {
                                    let res = run_authenticated_session(
                                        into_session_stream(ws, pad_cfg.as_ref()),
                                        peer,
                                        keys_copy,
                                        replay,
                                        handshake_timeout,
                                        policy,
                                        socks5_timeout,
                                        anonymize_target_logs,
                                        circuit_relay_enabled,
                                        cohort,
                                        refresh,
                                        claim,
                                        gatekeeper,
                                        replay_coord,
                                        Arc::clone(&metrics_clone),
                                    )
                                    .await;
                                    match &res {
                                        Ok(()) => metrics_clone.session_closed_ok(),
                                        Err(_) => metrics_clone.session_closed_err(),
                                    }
                                    if let Err(e) = res {
                                        debug!(
                                            client = %plog(&peer),
                                            error = %e,
                                            "webrtc session ended with error"
                                        );
                                    }
                                }
                                Err(e) => {
                                    tracing::debug!(
                                        client = %plog(&peer),
                                        error = %e,
                                        "webrtc signaling failed"
                                    );
                                    metrics_clone.session_closed_err();
                                }
                            }
                            return;
                        }

                        if is_ws {
                            metrics_clone.session_by_transport(TRANSPORT_WS);
                            tracing::debug!(
                                client = %plog(&peer),
                                "protocol mux: HTTP -> WebSocket tunnel"
                            );
                            match mirage_transport_ws::ws_server_auth(
                                s,
                                &bridge_pk,
                                // #9: secret-keyed WS knock when configured.
                                mc.obfs_secret.as_ref(),
                                handshake_timeout,
                                &http_auth_replay,
                            )
                            .await
                            {
                                Ok(ws_stream) => {
                                    let res = run_authenticated_session(
                                        into_session_stream(ws_stream, pad_cfg.as_ref()),
                                        peer,
                                        keys_copy,
                                        replay,
                                        handshake_timeout,
                                        policy,
                                        socks5_timeout,
                                        anonymize_target_logs,
                                        circuit_relay_enabled,
                                        cohort,
                                        refresh,
                                        claim,
                                        gatekeeper,
                                        replay_coord,
                                        Arc::clone(&metrics_clone),
                                    )
                                    .await;
                                    match &res {
                                        Ok(()) => metrics_clone.session_closed_ok(),
                                        Err(_) => metrics_clone.session_closed_err(),
                                    }
                                    if let Err(e) = res {
                                        debug!(
                                            client = %plog(&peer),
                                            error = %e,
                                            "ws session ended with error"
                                        );
                                    }
                                }
                                Err((e, ctx)) => {
                                    tracing::debug!(
                                        client = %plog(&peer),
                                        error = %e,
                                        "ws auth failed"
                                    );
                                    // Pre-101 probes (e.g. a plain GET) are
                                    // byte-identically forwarded to the HTTP
                                    // shadow; post-101 failures drop + score.
                                    handle_http_reject(
                                        ctx,
                                        &http_shadow_tgt,
                                        shadow_cap,
                                        &metrics_clone,
                                        &gatekeeper,
                                        peer.ip(),
                                    )
                                    .await;
                                    metrics_clone.session_closed_err();
                                }
                            }
                        } else if is_doh {
                            // DoH tunnel: POST /dns-query with
                            // Content-Type: application/dns-message.
                            tracing::debug!(
                                client = %plog(&peer),
                                "protocol mux: HTTP -> DoH tunnel"
                            );
                            let doh_cfg = mirage_transport_doh::DohServerConfig {
                                bridge_static_pk: bridge_pk,
                            };
                            match mirage_transport_doh::doh_bridge_serve_multconn(
                                s,
                                &doh_cfg,
                                &doh_store,
                                handshake_timeout,
                                &http_auth_replay,
                            )
                            .await
                            {
                                Ok(mirage_transport_meek::MeekServeOutcome::NewSession(
                                    doh_stream,
                                )) => {
                                    metrics_clone
                                        .session_by_transport(crate::metrics::TRANSPORT_MEEK);
                                    let res = run_authenticated_session(
                                        into_session_stream(doh_stream, pad_cfg.as_ref()),
                                        peer,
                                        keys_copy,
                                        replay,
                                        handshake_timeout,
                                        policy,
                                        socks5_timeout,
                                        anonymize_target_logs,
                                        circuit_relay_enabled,
                                        cohort,
                                        refresh,
                                        claim,
                                        gatekeeper,
                                        replay_coord,
                                        Arc::clone(&metrics_clone),
                                    )
                                    .await;
                                    match &res {
                                        Ok(()) => metrics_clone.session_closed_ok(),
                                        Err(_) => metrics_clone.session_closed_err(),
                                    }
                                    if let Err(e) = res {
                                        debug!(
                                            client = %plog(&peer),
                                            error = %e,
                                            "doh session ended with error"
                                        );
                                    }
                                }
                                Ok(mirage_transport_meek::MeekServeOutcome::Existing) => {
                                    // TCP connection routed to existing session; nothing to do.
                                }
                                Err((e, ctx)) => {
                                    tracing::debug!(
                                        client = %plog(&peer),
                                        error = %e,
                                        "doh serve failed"
                                    );
                                    handle_http_reject(
                                        ctx,
                                        &http_shadow_tgt,
                                        shadow_cap,
                                        &metrics_clone,
                                        &gatekeeper,
                                        peer.ip(),
                                    )
                                    .await;
                                    metrics_clone.session_closed_err();
                                }
                            }
                        } else {
                            metrics_clone.session_by_transport(TRANSPORT_MEEK);
                            tracing::debug!(
                                client = %plog(&peer),
                                "protocol mux: HTTP -> meek"
                            );
                            match mirage_transport_meek::meek_bridge_serve_multconn(
                                s,
                                &meek_store,
                                &bridge_pk,
                                handshake_timeout,
                                "application/octet-stream",
                                &http_auth_replay,
                            )
                            .await
                            {
                                Ok(mirage_transport_meek::MeekServeOutcome::NewSession(
                                    meek_stream,
                                )) => {
                                    let res = run_authenticated_session(
                                        into_session_stream(meek_stream, pad_cfg.as_ref()),
                                        peer,
                                        keys_copy,
                                        replay,
                                        handshake_timeout,
                                        policy,
                                        socks5_timeout,
                                        anonymize_target_logs,
                                        circuit_relay_enabled,
                                        cohort,
                                        refresh,
                                        claim,
                                        gatekeeper,
                                        replay_coord,
                                        Arc::clone(&metrics_clone),
                                    )
                                    .await;
                                    match &res {
                                        Ok(()) => metrics_clone.session_closed_ok(),
                                        Err(_) => metrics_clone.session_closed_err(),
                                    }
                                    if let Err(e) = res {
                                        debug!(
                                            client = %plog(&peer),
                                            error = %e,
                                            "meek session ended with error"
                                        );
                                    }
                                }
                                Ok(mirage_transport_meek::MeekServeOutcome::Existing) => {
                                    // TCP connection routed to existing session; nothing to do.
                                }
                                Err((e, ctx)) => {
                                    tracing::debug!(
                                        client = %plog(&peer),
                                        error = %e,
                                        "meek serve failed"
                                    );
                                    handle_http_reject(
                                        ctx,
                                        &http_shadow_tgt,
                                        shadow_cap,
                                        &metrics_clone,
                                        &gatekeeper,
                                        peer.ip(),
                                    )
                                    .await;
                                    metrics_clone.session_closed_err();
                                }
                            }
                        }
                        return;
                    }
                    Ok(MuxResult::AuthenticatedObfsTcp(s)) => {
                        metrics_clone.session_by_transport(TRANSPORT_OBFS_TCP);
                        // obfs-tcp already authenticated by the mux;
                        // skip the separate obfs_server_authenticate
                        // and run the Mirage session directly.
                        let res = run_authenticated_session(
                            into_session_stream(s, pad_cfg.as_ref()),
                            peer,
                            keys_copy,
                            replay,
                            handshake_timeout,
                            policy,
                            socks5_timeout,
                            anonymize_target_logs,
                            circuit_relay_enabled,
                            cohort,
                            refresh,
                            claim,
                            gatekeeper,
                            replay_coord,
                            Arc::clone(&metrics_clone),
                        )
                        .await;
                        match &res {
                            Ok(()) => metrics_clone.session_closed_ok(),
                            Err(_) => metrics_clone.session_closed_err(),
                        }
                        if let Err(e) = res {
                            debug!(client = %plog(&peer), error = %e, "obfs-mux session ended with error");
                        }
                        return;
                    }
                    Ok(MuxResult::AuthenticatedShadowsocks(stream, seed)) => {
                        metrics_clone.session_by_transport(TRANSPORT_SS2022);
                        // SS-2022 authenticated - stream is AEAD-framed. Proteus: pace the
                        // SS carrier (Dir::Down) to the shared envelope, then run the session.
                        let stream = mirage_transport_reality::maybe_pace_stream(
                            stream,
                            mirage_transport_reality::pacer::Dir::Down,
                            seed,
                        );
                        let res = run_authenticated_session(
                            into_session_stream(stream, pad_cfg.as_ref()),
                            peer,
                            keys_copy,
                            replay,
                            handshake_timeout,
                            policy,
                            socks5_timeout,
                            anonymize_target_logs,
                            circuit_relay_enabled,
                            cohort,
                            refresh,
                            claim,
                            gatekeeper,
                            replay_coord,
                            Arc::clone(&metrics_clone),
                        )
                        .await;
                        match &res {
                            Ok(()) => metrics_clone.session_closed_ok(),
                            Err(_) => metrics_clone.session_closed_err(),
                        }
                        if let Err(e) = res {
                            debug!(client = %plog(&peer), error = %e, "ss2022-mux session ended with error");
                        }
                        return;
                    }
                    Ok(MuxResult::AuthenticatedVless(s)) => {
                        metrics_clone.session_by_transport(TRANSPORT_VLESS);
                        // VLESS header consumed by mux; no standalone server
                        // response (F21 0-RTT). Raw TcpStream ready for session.
                        debug!(client = %plog(&peer), "protocol mux: VLESS authenticated");
                        let res = run_authenticated_session(
                            into_session_stream(s, pad_cfg.as_ref()),
                            peer,
                            keys_copy,
                            replay,
                            handshake_timeout,
                            policy,
                            socks5_timeout,
                            anonymize_target_logs,
                            circuit_relay_enabled,
                            cohort,
                            refresh,
                            claim,
                            gatekeeper,
                            replay_coord,
                            Arc::clone(&metrics_clone),
                        )
                        .await;
                        match &res {
                            Ok(()) => metrics_clone.session_closed_ok(),
                            Err(_) => metrics_clone.session_closed_err(),
                        }
                        if let Err(e) = res {
                            debug!(client = %plog(&peer), error = %e, "vless-mux session ended with error");
                        }
                        return;
                    }
                    Ok(MuxResult::Unknown(s)) => {
                        // No transport matched - active-probe resistance path.
                        // Raw-splice to the (possibly-TLS) shadow_target with an
                        // empty replay: the mux only peek()ed, so the prober's
                        // bytes are still in the kernel buffer for
                        // copy_bidirectional. Unset shadow_target => drop +
                        // probe-score (unchanged from before this refactor).
                        tracing::debug!(
                            client = %plog(&peer),
                            "protocol mux: unknown transport; active-probe path"
                        );
                        handle_http_reject(
                            Some((s, Vec::new())),
                            &shadow_tgt,
                            shadow_cap,
                            &metrics_clone,
                            &gatekeeper,
                            peer.ip(),
                        )
                        .await;
                        metrics_clone.session_closed_err();
                        return;
                    }
                    Err(e) => {
                        tracing::debug!(client = %plog(&peer), error = %e, "protocol mux error");
                        metrics_clone.session_closed_err();
                        return;
                    }
                }
            } else {
                // Mux disabled: return the socket for the existing dispatch below.
                (sock, Ok(()))
            };
            // Mux disabled path: dispatch directly to Reality or raw.
            let _: Result<(), std::io::Error> = res;
            let res = match &reality {
                Some(rc) => {
                    metrics_clone.session_by_transport(TRANSPORT_REALITY);
                    handle_session_reality(
                        sock,
                        peer,
                        keys_copy,
                        replay,
                        handshake_timeout,
                        policy,
                        socks5_timeout,
                        anonymize_target_logs,
                        Arc::clone(rc),
                        circuit_relay_enabled,
                        cohort,
                        refresh,
                        claim,
                        gatekeeper,
                        replay_coord,
                        pad_cfg.clone(),
                        Arc::clone(&metrics_clone),
                    )
                    .await
                }
                None => {
                    metrics_clone.session_by_transport(TRANSPORT_RAW);
                    handle_session_raw(
                        sock,
                        peer,
                        keys_copy,
                        replay,
                        handshake_timeout,
                        policy,
                        socks5_timeout,
                        anonymize_target_logs,
                        circuit_relay_enabled,
                        cohort,
                        refresh,
                        claim,
                        gatekeeper,
                        replay_coord,
                        pad_cfg.clone(),
                        Arc::clone(&metrics_clone),
                    )
                    .await
                }
            };
            match &res {
                Ok(()) => metrics_clone.session_closed_ok(),
                Err(_) => metrics_clone.session_closed_err(),
            }
            if let Err(e) = res {
                debug!(client = %plog(&peer), error = %e, "session ended with error");
            }
        });
    }
}

/// Shared state for Reality dispatch: one instance per bridge,
/// cloned into each accept task.
/// Probe every cover's real TLS 1.3 server-flight wire size, concurrently and
/// best-effort, returning a per-cover padding target. Called once at bridge
/// startup. Each probe is time-bounded by [`mirage_transport_reality::probe_cover_flight`]
/// (a slow/unreachable cover yields the generic default rather than blocking).
async fn probe_cover_flight_targets(
    covers: &[(std::net::SocketAddr, String)],
) -> std::collections::HashMap<std::net::SocketAddr, (usize, Vec<usize>)> {
    // Bound each probe generously; the whole set runs in parallel so total
    // startup cost is ~one timeout, not the sum.
    let per_probe = Duration::from_secs(6);
    let mut set = tokio::task::JoinSet::new();
    for (addr, host) in covers {
        let addr = *addr;
        let host = host.clone();
        set.spawn(async move {
            let profile =
                mirage_transport_reality::probe_cover_flight(addr, &host, per_probe).await;
            (
                addr,
                host,
                profile.flight_wire_len,
                profile.record_wire_lens,
            )
        });
    }
    let mut map = std::collections::HashMap::new();
    while let Some(res) = set.join_next().await {
        if let Ok((addr, host, len, records)) = res {
            // Multiple hostnames may resolve to the same IP; keep the first probe.
            let n_records = records.len();
            if map.insert(addr, (len, records)).is_none() {
                info!(
                    cover = %host,
                    flight_wire_len = len,
                    records = n_records,
                    "reality: cover flight profiled"
                );
            }
        }
    }
    map
}

struct RealityDispatchConfig {
    bridge_static_sk: StaticSecret,
    /// Per-bridge Reality anti-probe root, re-derived at startup from the
    /// bridge's X25519 static secret (the SAME value the invite-mint embedded in
    /// invites via `INVITE_EXT_REALITY_PROBE_ROOT`). The bridge derives the
    /// per-epoch probe secret from it and the probe's timestamp to close
    /// pubkey-only enumeration. See `mirage_transport_reality::derive_probe_root`.
    probe_root: [u8; 32],
    /// When `true` (default), also accept legacy (pre-epoch-binding) probes so
    /// clients holding pre-extension invites keep working during rollover.
    /// Operators set `reality_probe_accept_legacy = false` post-rollout to close
    /// the enumeration hole.
    probe_accept_legacy: bool,
    /// Cover-destination pool. The bridge picks uniformly at random
    /// from this set per incoming ClientHello to decorrelate the
    /// IP-fanout signature (analyst finding #1).
    cover_pool: Vec<std::net::SocketAddr>,
    ch_timeout: Duration,
    cover_cap: Duration,
    replay_probe_set: Arc<Mutex<ReplayProbeSet>>,
    /// Pinned TLS identity (cert bytes + signing key). `None` =
    /// ephemeral mode (v0.1c behavior).
    tls_identity: Option<Arc<mirage_transport_reality::TlsIdentity>>,
    /// Per-cover authenticated-flight wire-size target, measured once at
    /// startup by probing each cover's real TLS 1.3 server flight. The bridge
    /// pads its synthesized `Certificate` flight up to the picked cover's value
    /// so a passive censor comparing the two encrypted flights sees a matching
    /// size (closes the self-signed-flight-too-small tell). Empty if cover-flight
    /// mimicry is disabled.
    ///
    /// The `Vec<usize>` is the cover's measured per-record wire framing (M1): the
    /// bridge splits its synthesized flight into records of these sizes so the
    /// *record boundaries*, not just the total, match the real server. Empty vec =
    /// coalesce into one record (legacy).
    cover_flight_targets: std::collections::HashMap<std::net::SocketAddr, (usize, Vec<usize>)>,
}

impl RealityDispatchConfig {
    /// Pick a cover destination DETERMINISTICALLY from the client's source IP.
    ///
    /// A real HTTPS endpoint presents the SAME certificate every time a given
    /// client connects. Choosing a fresh cover per accept (the previous behavior)
    /// meant an active prober reconnecting from one address saw a DIFFERENT server
    /// certificate each time - a 1-of-N tell no real server produces, and a
    /// reliable bridge detector. Keying the choice on the source IP (mixed with
    /// the bridge's secret `probe_root` so the mapping is bridge-specific and not
    /// trivially precomputable) makes each prober see a stable cover/cert, while
    /// DIFFERENT provers still spread across the pool - preserving egress
    /// diversity across the client base.
    fn pick_cover(&self, client_ip: std::net::IpAddr) -> std::net::SocketAddr {
        debug_assert!(!self.cover_pool.is_empty(), "cover_pool non-empty by ctor");
        if self.cover_pool.len() == 1 {
            return self.cover_pool[0];
        }
        // FNV-1a over (probe_root || source-IP octets): stable per source, well
        // distributed, no crypto dependency needed (this is a routing choice, not
        // a security boundary).
        let mut acc: u64 = 0xcbf29ce484222325;
        let mut mix = |b: u8| {
            acc ^= u64::from(b);
            acc = acc.wrapping_mul(0x0000_0100_0000_01b3);
        };
        for b in self.probe_root.iter() {
            mix(*b);
        }
        match client_ip {
            std::net::IpAddr::V4(v4) => v4.octets().iter().for_each(|b| mix(*b)),
            std::net::IpAddr::V6(v6) => v6.octets().iter().for_each(|b| mix(*b)),
        }
        let idx = (acc % self.cover_pool.len() as u64) as usize;
        self.cover_pool[idx]
    }

    /// The authenticated-flight padding target for `cover`, if one was measured
    /// at startup. `None` disables padding for that connection (ephemeral/test
    /// path or mimicry off).
    fn cover_flight_target(&self, cover: std::net::SocketAddr) -> Option<usize> {
        self.cover_flight_targets.get(&cover).map(|(len, _)| *len)
    }

    /// The cover's measured per-record framing for M1 record-boundary mimicry.
    /// Empty slice = no per-record data (coalesce into one record).
    fn cover_flight_records(&self, cover: std::net::SocketAddr) -> &[usize] {
        self.cover_flight_targets
            .get(&cover)
            .map(|(_, records)| records.as_slice())
            .unwrap_or(&[])
    }
}

/// Set up the info-hash-derived multi-bind listeners (A35).
///
/// Returns a vec of `(port, listener)` for the current epoch + the
/// NEXT epoch. Empty when the feature is disabled. Logs an
/// operator-readable line per listener.
///
/// Skipped silently (with a warning) if the operator misconfigures -
/// derivation rejects (e.g., port_base < 1024) come through as
/// `None`.
/// Derive the current + next epoch UDP bind addresses for the Hysteria2 QUIC
/// port-hop (M4). Reuses the SAME epoch derivation as the TCP derived listeners
/// (`setup_derived_listeners`), so a client that derives the epoch port dials the
/// matching UDP port. Binds on the same IP as `base_addr`. Returns empty unless
/// derived-port hopping is configured (base + range + salt).
fn derived_udp_bind_addrs(
    config: &BridgeConfig,
    base_addr: std::net::SocketAddr,
) -> Vec<std::net::SocketAddr> {
    use mirage_discovery::derive::{derive_port, epoch_for_time, NAMESPACE_CLIENT_TO_BRIDGE};
    let (port_base, port_range) = match (config.derived_port_base, config.derived_port_range) {
        (Some(b), Some(r)) => (b, r),
        _ => return Vec::new(),
    };
    let salt = match config
        .derived_port_shared_salt_hex
        .as_deref()
        .and_then(|h| decode_key32(h, "derived_port_shared_salt").ok())
    {
        Some(s) => s,
        None => return Vec::new(),
    };
    let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => return Vec::new(),
    };
    let epoch_now = epoch_for_time(now);
    let ip = base_addr.ip();
    [epoch_now, epoch_now + 1]
        .into_iter()
        .filter_map(|e| {
            derive_port(&salt, NAMESPACE_CLIENT_TO_BRIDGE, e, port_base, port_range)
                .map(|port| std::net::SocketAddr::new(ip, port))
        })
        .collect()
}

async fn setup_derived_listeners(config: &BridgeConfig) -> Vec<(u16, TcpListener)> {
    use mirage_discovery::derive::NAMESPACE_CLIENT_TO_BRIDGE;
    use mirage_discovery::derive::{derive_port, epoch_for_time};

    let (port_base, port_range) = match (config.derived_port_base, config.derived_port_range) {
        (Some(b), Some(r)) => (b, r),
        _ => return Vec::new(),
    };
    let salt_hex = match config.derived_port_shared_salt_hex.as_deref() {
        Some(h) => h,
        None => {
            warn!("derived_port_base+range set but derived_port_shared_salt_hex missing; feature disabled");
            return Vec::new();
        }
    };
    let salt = match decode_key32(salt_hex, "derived_port_shared_salt") {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "derived_port_shared_salt_hex bad; feature disabled");
            return Vec::new();
        }
    };

    let now_unix = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        // A broken clock would derive the wrong epoch's ports; emit none
        // rather than advertise mismatched ports.
        Err(_) => {
            warn!("clock before UNIX_EPOCH; derived-port feature disabled this cycle");
            return Vec::new();
        }
    };
    let epoch_now = epoch_for_time(now_unix);
    let epoch_next = epoch_now + 1;

    // Bind host: explicit override OR the host part of `bind`. If
    // the bind is `0.0.0.0:8443` then we strip `:8443` and use
    // `0.0.0.0` as the host for derived ports.
    let bind_host = config.derived_port_bind_host.clone().unwrap_or_else(|| {
        config
            .bind
            .rsplit_once(':')
            .map(|(h, _)| h.to_string())
            .unwrap_or_else(|| "0.0.0.0".to_string())
    });

    let mut out = Vec::new();
    let mut seen_ports = std::collections::HashSet::new();
    for epoch in [epoch_now, epoch_next] {
        let port = match derive_port(
            &salt,
            NAMESPACE_CLIENT_TO_BRIDGE,
            epoch,
            port_base,
            port_range,
        ) {
            Some(p) => p,
            None => {
                warn!(
                    port_base,
                    port_range, "derived port out of valid range; check config"
                );
                return Vec::new();
            }
        };
        // Same port across two epochs (1-in-port_range chance) ->
        // bind once.
        if !seen_ports.insert(port) {
            continue;
        }
        let bind = format!("{bind_host}:{port}");
        match TcpListener::bind(&bind).await {
            Ok(l) => {
                info!(epoch, port, bind = %bind, "derived-port listener engaged");
                out.push((port, l));
            }
            Err(e) => {
                // Operator-visible warning; we don't fatal because
                // the primary listener still serves clients that
                // know the explicit endpoint.
                warn!(
                    epoch,
                    port,
                    bind = %bind,
                    error = %e,
                    "derived-port bind failed (port collision?); skipping"
                );
            }
        }
    }
    out
}

/// Hard cap on the DER-encoded certificate we'll load into memory.
/// Real TLS certs live well under 8 KiB; 64 KiB is generous and
/// protects an operator who misconfigures `reality_tls_cert_der_path`
/// against an OOM on startup from a multi-GB file.
const MAX_REALITY_CERT_DER_BYTES: u64 = 64 * 1024;

/// Load the Reality TLS identity from disk + config, or return
/// `Ok(None)` for ephemeral mode.
///
/// # Zeroize hygiene
///
/// The raw hex-decoded signing-key bytes are wrapped in
/// `Zeroizing` before the `SigningKey` is built, so the intermediate
/// 32-byte material is wiped from heap + stack the moment the
/// function returns. `SigningKey` itself implements `ZeroizeOnDrop`
/// via the upstream `zeroize` feature, so the returned identity
/// zeroes on drop as well.
/// A rustls verifier that accepts ANY server cert (H1). Used ONLY to CAPTURE a
/// cover's leaf cert for mimicry - never a trust decision. Mirrors the standalone
/// `mirage-cover-fetch` tool so the auto-borrow path and the manual tool agree.
#[derive(Debug)]
struct AcceptAnyVerifier;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme as S;
        vec![
            S::ED25519,
            S::RSA_PKCS1_SHA256,
            S::RSA_PKCS1_SHA384,
            S::RSA_PKCS1_SHA512,
            S::RSA_PSS_SHA256,
            S::RSA_PSS_SHA384,
            S::RSA_PSS_SHA512,
            S::ECDSA_NISTP256_SHA256,
            S::ECDSA_NISTP384_SHA384,
            S::ECDSA_NISTP521_SHA512,
        ]
    }
}

/// Connect to `target` (host:port) over TLS and capture the leaf cert DER (H1).
/// Verification is INTENTIONALLY off - this is a mimicry-target capture, not a
/// trust check. Bounded by connect + handshake timeouts so a stuck cover cannot
/// hang bridge startup.
async fn fetch_cover_leaf_cert_der(target: &str) -> Result<Vec<u8>, String> {
    use tokio::io::AsyncWriteExt as _;
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    let (host, _port) = target
        .rsplit_once(':')
        .ok_or_else(|| format!("reality_cover_addr {target:?} must be host:port"))?;
    if host.is_empty() {
        return Err("reality_cover_addr has an empty host".to_string());
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyVerifier))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(cfg));
    let server_name: rustls::pki_types::ServerName<'static> =
        rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| format!("invalid cover SNI {host:?}: {e}"))?;
    let dur = Duration::from_secs(10);
    let tcp = tokio::time::timeout(dur, TcpStream::connect(target))
        .await
        .map_err(|_| format!("cover cert fetch: connect {target} timed out"))?
        .map_err(|e| format!("cover cert fetch: connect {target}: {e}"))?;
    tcp.set_nodelay(true).ok();
    let mut tls = tokio::time::timeout(dur, connector.connect(server_name, tcp))
        .await
        .map_err(|_| "cover cert fetch: TLS handshake timed out".to_string())?
        .map_err(|e| format!("cover cert fetch: TLS handshake: {e}"))?;
    let leaf_der: Vec<u8> = {
        let (_io, conn) = tls.get_ref();
        let certs = conn
            .peer_certificates()
            .ok_or_else(|| "cover presented no certificates".to_string())?;
        certs
            .first()
            .ok_or_else(|| "cover cert chain empty".to_string())?
            .as_ref()
            .to_vec()
    };
    let _ = tls.shutdown().await;
    if leaf_der.len() as u64 > MAX_REALITY_CERT_DER_BYTES {
        return Err(format!(
            "cover cert exceeds {MAX_REALITY_CERT_DER_BYTES}-byte cap ({} bytes)",
            leaf_der.len()
        ));
    }
    Ok(leaf_der)
}

async fn load_tls_identity(
    config: &BridgeConfig,
) -> Result<Option<mirage_transport_reality::TlsIdentity>, String> {
    use mirage_crypto::zeroize::Zeroizing;

    match config.reality_tls_mode.as_deref() {
        None | Some("") | Some("ephemeral") => Ok(None),
        Some("borrow") => {
            // H1: present the cover's REAL leaf cert (captured at startup) so a
            // censor comparing the served cert against the cover's own cert sees
            // a match (passive cert-comparison parity - the biggest structural
            // divergence from cert synthesis), with ZERO operator cert file to
            // manage. CertVerify is still signed by the operator's STABLE key
            // (published in the invite as tls_cert_verify_pk), so this does NOT
            // close an ACTIVE CertVerify probe - documented residual - but it
            // removes the passive served-cert mismatch by default.
            let cover = config
                .reality_cover_addr
                .as_deref()
                .filter(|s| !s.is_empty())
                .or_else(|| config.reality_cover_addrs.first().map(String::as_str))
                .ok_or_else(|| {
                    "reality_tls_mode=borrow requires reality_cover_addr(s)".to_string()
                })?;
            let sk_hex = config
                .reality_tls_signing_sk_hex
                .as_deref()
                .ok_or_else(|| {
                    "reality_tls_mode=borrow requires reality_tls_signing_sk_hex".to_string()
                })?;
            let cert_der = fetch_cover_leaf_cert_der(cover)
                .await
                .map_err(|e| format!("reality_tls_mode=borrow: {e}"))?;
            info!(
                cover,
                der_len = cert_der.len(),
                "reality: borrowed cover leaf cert (passive cert-comparison parity)"
            );
            let raw = Zeroizing::new(
                hex::decode(sk_hex.trim()).map_err(|e| format!("signing sk hex: {e}"))?,
            );
            if raw.len() != 32 {
                return Err(format!("signing sk: expected 32 bytes, got {}", raw.len()));
            }
            let signing_key = p256::ecdsa::SigningKey::from_slice(&raw)
                .map_err(|e| format!("reality_tls_signing_sk_hex: invalid P-256 scalar: {e}"))?;
            Ok(Some(mirage_transport_reality::TlsIdentity {
                cert_der,
                signing_key,
            }))
        }
        Some("pinned") => {
            let cert_path = config.reality_tls_cert_der_path.as_deref().ok_or_else(|| {
                "reality_tls_mode=pinned requires reality_tls_cert_der_path".to_string()
            })?;
            let sk_hex = config
                .reality_tls_signing_sk_hex
                .as_deref()
                .ok_or_else(|| {
                    "reality_tls_mode=pinned requires reality_tls_signing_sk_hex".to_string()
                })?;
            // Cap the cert file size before reading so a misconfigured
            // path cannot OOM the bridge at startup.
            let meta =
                std::fs::metadata(cert_path).map_err(|e| format!("stat {cert_path}: {e}"))?;
            if meta.len() > MAX_REALITY_CERT_DER_BYTES {
                return Err(format!(
                    "{cert_path}: cert DER exceeds {MAX_REALITY_CERT_DER_BYTES}-byte cap ({} bytes)",
                    meta.len()
                ));
            }
            let cert_der =
                std::fs::read(cert_path).map_err(|e| format!("read {cert_path}: {e}"))?;
            let raw = Zeroizing::new(
                hex::decode(sk_hex.trim()).map_err(|e| format!("signing sk hex: {e}"))?,
            );
            if raw.len() != 32 {
                return Err(format!("signing sk: expected 32 bytes, got {}", raw.len()));
            }
            // ECDSA P-256 scalar (browser-realistic CertVerify scheme 0x0403).
            let signing_key = p256::ecdsa::SigningKey::from_slice(&raw)
                .map_err(|e| format!("reality_tls_signing_sk_hex: invalid P-256 scalar: {e}"))?;
            Ok(Some(mirage_transport_reality::TlsIdentity {
                cert_der,
                signing_key,
            }))
        }
        Some(other) => Err(format!("unknown reality_tls_mode: {other}")),
    }
}

/// Tiny extension trait so the config parser can grab the first
/// resolved socket addr without pulling in another helper crate.
trait ToSocketAddrsFirst {
    fn to_socket_addrs_first(&self) -> Result<std::net::SocketAddr, String>;
}
impl ToSocketAddrsFirst for str {
    fn to_socket_addrs_first(&self) -> Result<std::net::SocketAddr, String> {
        use std::net::ToSocketAddrs;
        self.to_socket_addrs()
            .map_err(|e| e.to_string())
            .and_then(|mut it| it.next().ok_or_else(|| "no addresses resolved".to_string()))
    }
}

struct KeysCopy {
    bridge_x25519_sk: [u8; 32],
    bridge_ed25519_pk: [u8; 32],
    operator_ed25519_pk: [u8; 32],
    operator_ed25519_pk_prev: Option<[u8; 32]>,
}

fn keys_to_copy(k: &BridgeKeys) -> KeysCopy {
    KeysCopy {
        bridge_x25519_sk: k.bridge_x25519_sk,
        bridge_ed25519_pk: k.bridge_ed25519_pk,
        operator_ed25519_pk_prev: k.operator_ed25519_pk_prev,
        operator_ed25519_pk: k.operator_ed25519_pk,
    }
}

/// Raw-TCP dispatch: no Reality carrier. The MVP mode.
#[allow(clippy::too_many_arguments)]
async fn handle_session_raw(
    client_sock: TcpStream,
    peer: std::net::SocketAddr,
    keys: Arc<KeysCopy>,
    replay: Arc<SyncReplaySet>,
    handshake_timeout: Duration,
    policy: Arc<AllowlistPolicy>,
    socks5_timeout: Duration,
    anonymize_target_logs: bool,
    circuit_relay_enabled: bool,
    cohort: Arc<CohortState>,
    refresh: Arc<RefreshState>,
    claim: Arc<ClaimState>,
    gatekeeper: Option<Arc<ConnectionGatekeeper>>,
    replay_coord: Option<Arc<CohortReplayCoordinator>>,
    pad_config: Option<PadConfig>,
    metrics: Arc<Metrics>,
) -> Result<(), String> {
    run_authenticated_session(
        into_session_stream(client_sock, pad_config.as_ref()),
        peer,
        keys,
        replay,
        handshake_timeout,
        policy,
        socks5_timeout,
        anonymize_target_logs,
        circuit_relay_enabled,
        cohort,
        refresh,
        claim,
        gatekeeper,
        replay_coord,
        metrics,
    )
    .await
}

/// Reality dispatch: verify the auth probe, fall through to cover on
/// failure, run the Mirage session handshake inside TLS records on
/// success.
#[allow(clippy::too_many_arguments)]
async fn handle_session_reality(
    client_sock: TcpStream,
    peer: std::net::SocketAddr,
    keys: Arc<KeysCopy>,
    replay: Arc<SyncReplaySet>,
    handshake_timeout: Duration,
    policy: Arc<AllowlistPolicy>,
    socks5_timeout: Duration,
    anonymize_target_logs: bool,
    reality: Arc<RealityDispatchConfig>,
    circuit_relay_enabled: bool,
    cohort: Arc<CohortState>,
    refresh: Arc<RefreshState>,
    claim: Arc<ClaimState>,
    gatekeeper: Option<Arc<ConnectionGatekeeper>>,
    replay_coord: Option<Arc<CohortReplayCoordinator>>,
    // Padding is intentionally NOT applied on the Reality path (F3): its TLS
    // RecordShaper is the sole size/timing owner. Kept in the signature for
    // dispatch symmetry with the other transports.
    _pad_config: Option<PadConfig>,
    metrics: Arc<Metrics>,
) -> Result<(), String> {
    let now_unix: u32 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);

    // Phase 0: Reality handshake. We pass the replay-probe `Mutex` by reference;
    // `reality_accept` locks it only around the synchronous probe verification
    // and releases before the ClientHello read and the cover-serve. Do NOT lock
    // here and pass a guard in: this is a single bridge-wide lock, and holding
    // it across the (up to `cover_cap`) cover-serve lets one attacker holding an
    // unauthenticated socket open serialize every other Reality accept.
    let outcome = {
        // Deterministic per source IP: a given prober always gets the same cover
        // (stable cert on reconnect, like a real server), while different clients
        // still spread across the pool.
        let cover_addr = reality.pick_cover(peer.ip());
        let cover_flight_target = reality.cover_flight_target(cover_addr);
        let cover_flight_records = reality.cover_flight_records(cover_addr);
        let mut inputs = BridgeCarrierInputs {
            bridge_static_sk: &reality.bridge_static_sk,
            now_unix,
            cover_addr,
            replay_set: &reality.replay_probe_set,
            probe_root: &reality.probe_root,
            accept_legacy: reality.probe_accept_legacy,
            client_hello_read_timeout: reality.ch_timeout,
            cover_duration_cap: reality.cover_cap,
            tls_identity: reality.tls_identity.as_deref(),
            cover_flight_target,
            cover_flight_records,
        };
        reality_accept(client_sock, &mut inputs)
            .await
            .map_err(|e| format!("reality_accept: {e}"))?
    };

    match outcome {
        AcceptOutcome::Authenticated(stream) => {
            info!(client = %plog(&peer), "reality: authenticated; running Mirage session");
            metrics.reality_authenticated();
            // F3 (fingerprint): Reality's TLS RecordShaper is the sole size/timing
            // owner on this path. Do NOT also wrap the inner stream in PaddedStream
            // - that would push a power-of-two record-size comb + chaff beacon out
            // through the TLS records. MUST match the client, which gates padding
            // off for Reality in `pad_stream_if_enabled`.
            //
            // Shaper-v2: opt-in envelope pacing (MIRAGE_REALITY_PACE), off by
            // default. The bridge writes downstream, so it paces `Down`. Both ends
            // must set the same class; the schedule seed is derived from the shared
            // keys, so no extra negotiation is needed.
            let stream = mirage_transport_reality::maybe_pace(
                stream,
                mirage_transport_reality::pacer::Dir::Down,
            );
            run_authenticated_session(
                into_session_stream(stream, None),
                peer,
                keys,
                replay,
                handshake_timeout,
                policy,
                socks5_timeout,
                anonymize_target_logs,
                circuit_relay_enabled,
                cohort,
                refresh,
                claim,
                gatekeeper,
                replay_coord,
                metrics,
            )
            .await
        }
        AcceptOutcome::CoverServed { c2s, s2c } => {
            info!(
                client = %plog(&peer),
                c2s,
                s2c,
                "reality: probe failed; cover served"
            );
            metrics.reality_cover_served(c2s, s2c);
            Ok(())
        }
    }
}

/// Box a transport stream into a [`DuplexStream`], optionally wrapping it
/// with the traffic-padding layer when `pad` is `Some`.
///
/// All call sites that feed into [`run_authenticated_session`] go through
/// this helper so padding is applied uniformly regardless of transport.
fn into_session_stream<S>(stream: S, pad: Option<&PadConfig>) -> DuplexStream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match pad {
        Some(cfg) => Box::pin(PaddedStream::wrap(stream, cfg.clone())),
        None => Box::pin(stream),
    }
}

/// Idle timeout for a bridged mux stream: a keep-alive stream with zero bytes
/// in either direction for this long is reaped, releasing its upstream socket
/// (mux-idle-timeout). Matches the client's `MUX_STREAM_IDLE_TIMEOUT`.
const MUX_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// Convert a mux `Begin` target into the SOCKS5 connect target the bridge's
/// resolver / policy / dialer understands.
fn muxtarget_to_connecttarget(t: &mirage_mux::MuxTarget) -> ConnectTarget {
    match t {
        mirage_mux::MuxTarget::Ipv4 { addr, port } => {
            ConnectTarget::Ipv4(std::net::Ipv4Addr::from(*addr), *port)
        }
        mirage_mux::MuxTarget::Ipv6 { addr, port } => {
            ConnectTarget::Ipv6(std::net::Ipv6Addr::from(*addr), *port)
        }
        mirage_mux::MuxTarget::Domain { domain, port } => {
            ConnectTarget::Domain(domain.clone(), *port)
        }
    }
}

/// Run a multiplexed carrier session: accept client-opened streams, connect
/// each to its requested target under policy, and bridge them. One
/// authenticated session serves many streams, so a browser's parallel
/// connections cost O(1) handshakes / tokens / per-IP concurrency slots.
///
/// Per-stream, `BeginOk` is deferred until the upstream actually connects, so
/// the client learns success/failure (and synthesizes the app's SOCKS reply)
/// only once the target is reachable - a refusal becomes a `Reset` carrying the
/// SOCKS reply code.
async fn run_mux_session<S>(
    session: S,
    peer: std::net::SocketAddr,
    policy: Arc<AllowlistPolicy>,
    connect_timeout: Duration,
    anonymize_target_logs: bool,
    metrics: Arc<Metrics>,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    info!(client = %plog(&peer), "mux carrier session established");
    let (_conn, mut acceptor) =
        MuxConnection::new(session, StreamRole::Responder, MuxPolicy::default());
    while let Some(incoming) = acceptor.accept().await {
        let target = incoming.target().clone();
        let policy = Arc::clone(&policy);
        let metrics = Arc::clone(&metrics);
        tokio::spawn(async move {
            let ct = muxtarget_to_connecttarget(&target);
            match connect_target(&ct, &policy, connect_timeout).await {
                Ok(up) => {
                    // Accept AFTER the upstream is up so the client's BeginOk
                    // (-> app SOCKS success reply) is only sent on real success.
                    let stream = incoming.accept();
                    if anonymize_target_logs {
                        info!(client = %plog(&peer), "mux stream CONNECT established; bridging");
                    } else {
                        info!(
                            client = %plog(&peer),
                            target = %ct.host_str(),
                            port = ct.port(),
                            "mux stream CONNECT established; bridging"
                        );
                    }
                    // Idle-aware: reaps a dead keep-alive stream and releases the
                    // upstream socket instead of pinning it forever; half-closes
                    // on EOF. Takes ownership of both streams.
                    let res =
                        mirage_socks5::copy_bidirectional_idle(stream, up, MUX_STREAM_IDLE_TIMEOUT)
                            .await;
                    if let Err(e) = res {
                        debug!(client = %plog(&peer), error = %e, "mux stream copy ended with error");
                    }
                }
                Err(rep) => {
                    metrics.socks5_failed();
                    debug!(client = %plog(&peer), rep, "mux stream connect refused");
                    // Reset(rep) -> the client maps rep to a SOCKS5 failure reply.
                    incoming.reject(rep);
                }
            }
        });
    }
    info!(client = %plog(&peer), "mux carrier session closed");
    Ok(())
}

/// Mirage session handshake -> SOCKS5 CONNECT -> bidirectional byte pump.
///
/// When `gatekeeper` is `Some`, auth failures are fed to the cohort
/// probe detector which may publish `ProbeScanDetected` to peers.
/// When `replay_coord` is `Some`, each successful token burn is
/// gossiped to cohort peers via `notify_burn()`.
/// When `circuit_relay_enabled` is `true`, the post-handshake flow is
/// a [`SessionTask`] circuit state machine instead of SOCKS5.
#[allow(clippy::too_many_arguments)]
async fn run_authenticated_session(
    client_sock: mirage_transport::DuplexStream,
    peer: std::net::SocketAddr,
    keys: Arc<KeysCopy>,
    replay: Arc<SyncReplaySet>,
    handshake_timeout: Duration,
    policy: Arc<AllowlistPolicy>,
    socks5_timeout: Duration,
    anonymize_target_logs: bool,
    circuit_relay_enabled: bool,
    cohort: Arc<CohortState>,
    refresh: Arc<RefreshState>,
    claim: Arc<ClaimState>,
    gatekeeper: Option<Arc<ConnectionGatekeeper>>,
    replay_coord: Option<Arc<CohortReplayCoordinator>>,
    metrics: Arc<Metrics>,
) -> Result<(), String> {
    // Fail CLOSED on a broken clock. The previous `.unwrap_or(0)` made
    // now_unix=0 when the host clock is before UNIX_EPOCH, and 0 < every
    // capability token's `expires_at`, so EVERY expired token would verify
    // (and TTL eviction in the replay set would misbehave). Token expiry is
    // the sole freshness control on the handshake - refuse rather than
    // accept-everything.
    let now_unix = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => {
            return Err(
                "bridge clock is before UNIX_EPOCH; refusing handshake (would disable \
                 capability-token expiry)"
                    .to_string(),
            )
        }
    };

    // Phase 1: Mirage handshake under a deadline.
    //
    // The replay set is held as Arc<SyncReplaySet>; the internal
    // std::sync::Mutex is acquired briefly during the final
    // check-and-insert step inside read_message_3, and never across
    // .await points. Concurrent handshakes do NOT serialize behind
    // one async-mutex held for the full Noise exchange. Audit fix:
    // CRITICAL-Trust-1.
    let (session, peer_static, token_id, token_kind) = {
        let mut verifier = TokenVerifier::new_shared(replay.as_ref(), now_unix);
        // Enable refresh-token acceptance when the bridge holds its
        // signing key. Verification falls through to the
        // `mirage-refresh-v1`-domain-separated path if the
        // operator-signature path rejects.
        if refresh.enabled {
            verifier = verifier.with_refresh_issuer(&keys.bridge_ed25519_pk);
        }
        // Rotation-overlap acceptance (v0.1i): if the operator
        // configured a previous pubkey, tokens signed by it verify
        // too. Checked BEFORE the refresh fallback so an old-
        // invite token is classified Bootstrap, not Refresh.
        if let Some(prev) = &keys.operator_ed25519_pk_prev {
            verifier = verifier.with_prev_operator(prev);
        }
        // `accept_with_peer_static` also returns the authenticated initiator's
        // X25519 static key (revealed under encryption in Noise msg 3). We match
        // it against the relay-peer allowlist below to recognize an INBOUND
        // relay leg vs a direct client - the exit/middle half of multi-hop.
        let s = match tokio::time::timeout(
            handshake_timeout,
            accept_with_peer_static(
                client_sock,
                &keys.bridge_x25519_sk,
                &keys.bridge_ed25519_pk,
                &keys.operator_ed25519_pk,
                &mut verifier,
            ),
        )
        .await
        {
            Err(_) => {
                metrics.handshake_timeout();
                // Auth failure: feed to cohort probe detector.
                if let Some(ref gk) = gatekeeper {
                    gk.observe_auth_failure(peer.ip()).await;
                }
                return Err(format!("handshake timed out after {handshake_timeout:?}"));
            }
            Ok(Err(e)) => {
                metrics.handshake_failed();
                // Auth failure: feed to cohort probe detector.
                if let Some(ref gk) = gatekeeper {
                    gk.observe_auth_failure(peer.ip()).await;
                }
                return Err(format!("handshake: {e}"));
            }
            Ok(Ok((s, peer_static))) => (s, peer_static),
        };
        (
            s.0,
            s.1,
            verifier.last_accepted_token_id,
            verifier.last_accepted_kind,
        )
    };
    if let Some(kind) = token_kind {
        debug!(client = %plog(&peer), ?kind, "token accepted");
        match kind {
            mirage_session::AcceptedTokenKind::Bootstrap => metrics.token_bootstrap(),
            mirage_session::AcceptedTokenKind::Refresh => metrics.token_refresh(),
        }
    }

    // Gossip the token burn to cohort peers. The local replay-set
    // insert already happened inside `accept()` via `TokenVerifier`.
    // `notify_burn()` skips the re-insert and just publishes so
    // peers can pre-empt a cross-bridge replay attempt within <100ms.
    if let (Some(tid), Some(coord)) = (token_id, replay_coord.as_ref()) {
        coord.notify_burn(tid).await;
    }

    // Circuit relay mode: hand the authenticated session to the
    // circuit state machine (SessionTask) instead of SOCKS5.
    if circuit_relay_enabled {
        // #32: honour the two SEPARATE operator knobs on the circuit-exit path
        // too. Previously only `deny_private_networks` was read here, and it was
        // fed to a single dispatcher flag that (via `permissive_for_tests`) also
        // silently re-opened loopback - so an operator enabling private-network
        // targets unintentionally turned the circuit exit into a localhost/SSRF
        // reachable surface. Loopback now tracks `deny_loopback` independently.
        let allow_private = !policy.deny_private_networks;
        let allow_loopback = !policy.deny_loopback;
        let ckeys = BridgeCircuitKeys {
            bridge_x25519_sk: keys.bridge_x25519_sk,
            bridge_ed25519_pk: keys.bridge_ed25519_pk,
            operator_ed25519_pk: keys.operator_ed25519_pk,
        };

        // Two orthogonal roles, decided per accepted session:
        //
        // * OUTBOUND (`relay_capable`): a relay-peer DIAL map is configured, so
        //   this node can extend a circuit onward when a client sends CMD_EXTEND
        //   - built with a next-hop dialer (`with_relay`). The next-hop endpoint
        //   rides the client's EXTEND cell.
        //
        // * INBOUND (`inbound_is_relay`): the authenticated peer's static key is
        //   in the relay-peer allowlist, i.e. THIS session is a relay leg opened
        //   by an upstream bridge, so circuits on it are EXTENDED hops. They must
        //   run in relay mode (`with_relay_mode`) with per-hop capability-token
        //   verification (`with_token_verification`) - the client's per-hop token
        //   arrives in CMD_EXTEND_FINISH and gates exit/extend. The state machine
        //   fails closed if relay mode and token-verification disagree.
        //
        // The two are independent: an entry (inbound direct client, outbound
        // capable), a terminal exit (inbound relay leg, no outbound), and a
        // middle relay (both) are all expressible.
        let relay_tokens = RELAY_PEER_TOKENS.get().cloned();
        let relay_capable = relay_tokens.as_ref().is_some_and(|m| !m.is_empty());
        let inbound_is_relay = RELAY_PEER_KEYS
            .get()
            .is_some_and(|keyset| keyset.contains(&peer_static));

        // Build the (possibly token-verifying) executor for whichever role.
        let make_verifying = |exec: BridgeCircuitExecutor| {
            // Fail CLOSED. Per-hop capability-token verification gates exit/extend
            // for a circuit leg that was NOT session-authenticated as a direct
            // client. The relay allowlist (`inbound_is_relay`) is a positive
            // signal, but an upstream bridge that is NOT in the allowlist is
            // misclassified as a direct entry - and if this bridge is
            // relay-capable, that misclassified leg could extend/exit with NO
            // per-hop token check. So verify whenever this bridge can relay, not
            // only when we positively recognise the upstream. (A genuine direct
            // client is already gated at the session layer; single-hop legs carry
            // no EXTEND cell, so verification is a no-op for them.)
            if inbound_is_relay || relay_capable {
                exec.with_token_verification(replay.clone(), keys.operator_ed25519_pk_prev)
            } else {
                exec
            }
        };

        let task = if relay_capable {
            let dialer = SessionNextHopDialer::new(
                keys.bridge_x25519_sk,
                (*relay_tokens.unwrap()).clone(),
                Duration::from_secs(10),
            );
            let dialer = if allow_private {
                dialer.allow_private_destinations()
            } else {
                dialer
            };
            let (executor, exit_events_rx, next_hop_rx) = BridgeCircuitExecutor::with_relay(
                ckeys,
                allow_private,
                allow_loopback,
                Arc::new(dialer),
            );
            let executor = make_verifying(executor);
            info!(
                client = %plog(&peer),
                inbound_relay = inbound_is_relay,
                "circuit-relay session; SessionTask (extend-capable{})",
                if inbound_is_relay { " + relay-leg" } else { "" }
            );
            let t = SessionTask::new(session, Arc::new(executor), SessionTaskConfig::default())
                .with_exit_events(exit_events_rx)
                .with_next_hop_events(next_hop_rx);
            if inbound_is_relay {
                t.with_relay_mode()
            } else {
                t
            }
        } else {
            let (executor, exit_events_rx) =
                BridgeCircuitExecutor::new(ckeys, allow_private, allow_loopback);
            let executor = make_verifying(executor);
            info!(
                client = %plog(&peer),
                inbound_relay = inbound_is_relay,
                "circuit-relay session; SessionTask ({})",
                if inbound_is_relay { "exit hop (relay leg)" } else { "exit-only" }
            );
            let t = SessionTask::new(session, Arc::new(executor), SessionTaskConfig::default())
                .with_exit_events(exit_events_rx);
            if inbound_is_relay {
                t.with_relay_mode()
            } else {
                t
            }
        };
        return task
            .run()
            .await
            .map_err(|e| format!("circuit-relay (peer={peer}): {e}"));
    }

    info!(client = %plog(&peer), "session established; reading client request");

    // Peek the first byte to dispatch SOCKS5 (0x05) vs. an HTTP CONNECT proxy
    // request. Control channels (cohort/refresh/claim/udp magic targets) are
    // SOCKS5-only, so HTTP CONNECT only ever carries real proxy traffic and
    // bypasses the magic-target logic entirely. Both run AFTER the
    // token-authenticated Mirage handshake, so this is same-trust as SOCKS5.
    let mut session = session;
    let mut first = [0u8; 1];
    match tokio::time::timeout(socks5_timeout, session.read_exact(&mut first)).await {
        Ok(Ok(_)) => {}
        _ => {
            metrics.socks5_failed();
            return Err("client sent no request before timeout".to_string());
        }
    }
    // Mux carrier (first byte = 0x00): many client streams ride this one
    // authenticated session. The tag byte is consumed; the mux frames follow.
    // Gated on the bridge's own `mux_enabled` so an operator can force legacy.
    if first[0] == MUX_SESSION_TAG && MUX_ENABLED.load(Ordering::Relaxed) {
        return run_mux_session(
            session,
            peer,
            policy.clone(),
            socks5_timeout,
            anonymize_target_logs,
            metrics,
        )
        .await;
    }
    // Replay the consumed byte for whichever parser runs.
    let session = PrefixedStream::new(first.to_vec(), session);
    if first[0] != 0x05 {
        return handle_http_connect(
            session,
            peer,
            &policy,
            socks5_timeout,
            anonymize_target_logs,
        )
        .await;
    }

    // Phase 2: SOCKS5 method-selection + request parse. Then
    // dispatch: magic hostname -> cohort service; everything else
    // -> normal CONNECT.
    let (req, session) = match read_request(session).await {
        Ok(v) => v,
        Err(e) => {
            debug!(client = %plog(&peer), error = %e, "SOCKS5 parse failed");
            metrics.socks5_failed();
            return Err(format!("socks5: {e}"));
        }
    };

    if is_cohort_target(&req.target) {
        info!(client = %plog(&peer), "cohort request received");
        return handle_cohort_request(session, peer, token_id, token_kind, cohort, metrics).await;
    }
    if is_refresh_target(&req.target) {
        info!(client = %plog(&peer), "refresh request received");
        return handle_refresh_request(session, peer, token_id, token_kind, refresh, metrics).await;
    }
    if is_claim_target(&req.target) {
        info!(client = %plog(&peer), "claim request received");
        return handle_claim_request(session, peer, token_id, token_kind, claim, refresh, metrics)
            .await;
    }
    if is_udp_relay_target(&req.target) {
        info!(client = %plog(&peer), "udp-relay session opened");
        return handle_udp_relay_request(session, peer, policy.clone(), metrics).await;
    }

    // Standard CONNECT path.
    let (up, session) = match connect_and_reply(session, &req, &policy, socks5_timeout).await {
        Ok(v) => v,
        Err(e) => {
            debug!(client = %plog(&peer), error = %e, "SOCKS5 connect failed");
            metrics.socks5_failed();
            return Err(format!("socks5 connect: {e}"));
        }
    };

    // Per-session log. If anonymize_target_logs is on (default),
    // redact the target; operators still see that SOMETHING was
    // tunneled, which is enough for capacity metrics, but not who
    // asked for what.
    if anonymize_target_logs {
        info!(client = %plog(&peer), "SOCKS5 CONNECT established; bridging");
    } else {
        info!(
            client = %plog(&peer),
            target = %req.target.host_str(),
            port = req.target.port(),
            "SOCKS5 CONNECT established; bridging"
        );
    }

    // Phase 3: bidirectional byte pump between SOCKS5 client (encrypted Mirage
    // session) and upstream TCP. Idle-aware (BRIDGE-LEGACY-COPY-NO-IDLE): reaps
    // a dead/idle legacy tunnel and releases its permit + upstream fd instead of
    // pinning a concurrency slot forever, mirroring the mux path.
    match mirage_socks5::copy_bidirectional_idle(session, up, MUX_STREAM_IDLE_TIMEOUT).await {
        Ok((c2u, u2c)) => {
            if anonymize_target_logs {
                info!(
                    client = %plog(&peer),
                    client_to_upstream_bytes = c2u,
                    upstream_to_client_bytes = u2c,
                    "session closed cleanly"
                );
            } else {
                info!(
                    client = %plog(&peer),
                    target = %req.target.host_str(),
                    client_to_upstream_bytes = c2u,
                    upstream_to_client_bytes = u2c,
                    "session closed cleanly"
                );
            }
            Ok(())
        }
        Err(e) => {
            warn!(client = %plog(&peer), error = %e, "bidirectional copy ended with error");
            Err(format!("copy: {e}"))
        }
    }
}

fn fatal(msg: &str) -> ! {
    eprintln!("fatal: {msg}");
    std::process::exit(2);
}

// Cohort service

/// Per-bridge cohort state: the signed announcements this bridge
/// knows about, plus in-memory per-token bookkeeping for rationing.
struct CohortState {
    /// Pre-signed announcements for other bridges in the operator's
    /// mesh. Empty means "this bridge reveals nothing."
    known: Vec<Announcement>,
    /// Per-token reveal bookkeeping. Keys are capability-token ids
    /// that have ever made at least one successful cohort request;
    /// values are the set of bridge pubkeys we've already told them
    /// about, and a running count. Resets on bridge restart.
    per_token: Mutex<HashMap<[u8; 32], PerTokenReveal>>,
    /// Max unique bridges any single token can learn about over
    /// the bridge's lifetime.
    reveal_cap: u8,
    /// Random-subtraction window on response count to defeat
    /// "count is always N" traffic-shape fingerprints.
    reveal_jitter: u8,
    /// Round-robin cursor over `known` so sequential requests from
    /// different tokens don't all receive the same first-N.
    rotation: std::sync::atomic::AtomicUsize,
}

struct PerTokenReveal {
    seen: std::collections::HashSet<[u8; 32]>,
    /// Last access timestamp; used to evict the oldest entry when
    /// the per-token table reaches its hard cap (audit fix:
    /// HIGH-Trust-3, unbounded HashMap growth).
    last_seen: std::time::Instant,
}

/// Hard cap on the per-token cohort-state and per-root refresh-state
/// HashMaps. Without this, a single attacker minting refresh
/// descendants and using each one for a cohort/refresh request
/// could push memory usage unbounded over the bridge's uptime.
/// 65536 entries x ~64 B/entry ~ 4 MiB, easy on any host.
const COHORT_PER_TOKEN_TABLE_CAP: usize = 65536;
/// Hard cap on the per-root refresh-state table. Same rationale.
const REFRESH_PER_ROOT_TABLE_CAP: usize = 65536;

impl CohortState {
    fn load(config: &BridgeConfig) -> Self {
        let known = match &config.cohort_announcements_path {
            None => Vec::new(),
            Some(path) => match Self::load_from_path(path) {
                Ok(v) => {
                    info!(count = v.len(), path = %path, "loaded cohort announcements");
                    v
                }
                Err(e) => {
                    warn!(error = %e, path = %path, "cohort load failed; bridge will reply EMPTY");
                    Vec::new()
                }
            },
        };
        Self {
            known,
            per_token: Mutex::new(HashMap::new()),
            reveal_cap: config.cohort_reveal_cap_per_token,
            reveal_jitter: config.cohort_reveal_jitter,
            rotation: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn load_from_path(path: &str) -> Result<Vec<Announcement>, String> {
        use serde::Deserialize;
        #[derive(Deserialize)]
        struct Entry {
            #[serde(rename = "hex")]
            hex: String,
        }
        #[derive(Deserialize)]
        struct File {
            announcements: Vec<Entry>,
        }
        let s = std::fs::read_to_string(path).map_err(|e| format!("read: {e}"))?;
        let f: File = serde_json::from_str(&s).map_err(|e| format!("json: {e}"))?;
        let mut out = Vec::with_capacity(f.announcements.len());
        for (i, e) in f.announcements.iter().enumerate() {
            let bytes =
                hex::decode(e.hex.trim()).map_err(|err| format!("entry {i}: hex decode: {err}"))?;
            let ann = Announcement::decode(&bytes)
                .map_err(|err| format!("entry {i}: announcement decode: {err}"))?;
            out.push(ann);
        }
        Ok(out)
    }

    /// Select up to `max_n` announcements that the caller (with
    /// this `token_id`) has not already been told about, respecting
    /// the per-token lifetime reveal cap.
    async fn pick_for_token(
        &self,
        token_id: Option<[u8; 32]>,
        max_n: u8,
    ) -> (Vec<Announcement>, u8 /* status */) {
        if self.known.is_empty() {
            return (Vec::new(), COHORT_STATUS_EMPTY);
        }
        let token_id = match token_id {
            Some(t) => t,
            None => {
                // No token context (test-only no-token handshake
                // or a future non-token flow). Reject the cohort
                // request rather than leaking without rationing.
                return (Vec::new(), COHORT_STATUS_EXHAUSTED);
            }
        };
        let mut per = self.per_token.lock().await;
        // Cap-and-evict: if the table is full and this is a new
        // token_id, evict the oldest-touched entry first. Without
        // this, a chain of refresh-derived tokens lets one attacker
        // grow the table unbounded.
        if per.len() >= COHORT_PER_TOKEN_TABLE_CAP && !per.contains_key(&token_id) {
            if let Some(oldest_key) = per.iter().min_by_key(|(_, v)| v.last_seen).map(|(k, _)| *k) {
                per.remove(&oldest_key);
            }
        }
        let entry = per.entry(token_id).or_insert_with(|| PerTokenReveal {
            seen: std::collections::HashSet::new(),
            last_seen: std::time::Instant::now(),
        });
        entry.last_seen = std::time::Instant::now();
        if entry.seen.len() >= self.reveal_cap as usize {
            return (Vec::new(), COHORT_STATUS_EXHAUSTED);
        }

        // Traffic-shape jitter. A bridge that always returns exactly
        // `max_n` is itself fingerprintable by a probe sending a
        // known `max_n` and observing the count. We subtract a
        // random value drawn uniformly from `[0, reveal_jitter]`,
        // clamped so the floor of at least 1 still holds. Draws
        // from the OS CSPRNG; the picker state is otherwise
        // deterministic.
        let jitter = if self.reveal_jitter == 0 {
            0u8
        } else {
            let mut b = [0u8; 1];
            // OS CSPRNG failure would be catastrophic; under panic
            // we fall back to "no jitter this request" so the
            // bridge stays up. The jitter is defense-in-depth, not
            // a cryptographic control.
            let j = getrandom::fill(&mut b).map(|_| b[0]).unwrap_or(0);
            j % (self.reveal_jitter + 1)
        };
        let requested = max_n.saturating_sub(jitter).max(1);
        let remaining_cap = (self.reveal_cap as usize).saturating_sub(entry.seen.len());
        let effective_max = (requested as usize).min(remaining_cap);

        let mut out = Vec::with_capacity(effective_max);
        let cursor_start = self
            .rotation
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        for i in 0..self.known.len() {
            if out.len() >= effective_max {
                break;
            }
            let idx = (cursor_start + i) % self.known.len();
            let a = &self.known[idx];
            if entry.seen.contains(&a.bridge_ed25519_pk) {
                continue;
            }
            entry.seen.insert(a.bridge_ed25519_pk);
            out.push(a.clone());
        }
        let status = if out.is_empty() {
            COHORT_STATUS_EXHAUSTED
        } else {
            mirage_discovery::cohort::COHORT_STATUS_OK
        };
        (out, status)
    }
}

/// Parse an HTTP CONNECT request line (`CONNECT host:port HTTP/1.1`) into
/// `(host, port)`. Pure + unit-testable.
fn parse_connect_target(first_line: &str) -> Result<(String, u16), String> {
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    if !method.eq_ignore_ascii_case("CONNECT") {
        return Err(format!("unsupported method {method:?}"));
    }
    let target = parts.next().ok_or("missing target")?;
    let (host, port) = target.rsplit_once(':').ok_or("target missing port")?;
    if host.is_empty() {
        return Err("empty host".to_string());
    }
    let port: u16 = port.parse().map_err(|_| "bad port".to_string())?;
    Ok((host.to_string(), port))
}

/// Serve an HTTP CONNECT proxy request over the authenticated session: parse
/// the CONNECT head, apply the SAME SSRF allowlist policy as the SOCKS5 exit
/// (resolve once, reject private/unsafe targets, dial only the validated
/// addrs - DNS-rebind safe), reply `200 Connection Established`, then bridge
/// bytes. Carries real proxy traffic only; control channels are SOCKS5.
async fn handle_http_connect<S>(
    mut session: S,
    peer: std::net::SocketAddr,
    policy: &AllowlistPolicy,
    timeout: Duration,
    anonymize_target_logs: bool,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Read the request head up to CRLFCRLF, bounded so a client can't make us
    // buffer without limit.
    const MAX_HEAD: usize = 8192;
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        match tokio::time::timeout(timeout, session.read_exact(&mut byte)).await {
            Ok(Ok(_)) => {
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
                if head.len() > MAX_HEAD {
                    let _ = session
                        .write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n")
                        .await;
                    return Err("http connect: request head too large".to_string());
                }
            }
            _ => return Err("http connect: read head failed/timed out".to_string()),
        }
    }
    let head_str =
        std::str::from_utf8(&head).map_err(|_| "http connect: non-utf8 head".to_string())?;
    let first_line = head_str.lines().next().unwrap_or("");
    let (host, port) = match parse_connect_target(first_line) {
        Ok(v) => v,
        Err(e) => {
            let _ = session
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                .await;
            return Err(format!("http connect: {e}"));
        }
    };

    // Resolve once + SSRF policy check, then dial the VALIDATED addrs.
    let addr = format!("{host}:{port}");
    let resolved: Vec<std::net::SocketAddr> =
        match tokio::time::timeout(timeout, tokio::net::lookup_host(&addr)).await {
            Ok(Ok(it)) => it.collect(),
            _ => {
                let _ = session
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    .await;
                return Err("http connect: resolve failed".to_string());
            }
        };
    if let Err(e) = policy.check_all(resolved.iter()) {
        let _ = session
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await;
        return Err(format!("http connect: forbidden destination: {e}"));
    }
    let mut up = None;
    for sa in &resolved {
        if let Ok(Ok(s)) = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(sa)).await {
            up = Some(s);
            break;
        }
    }
    let up = match up {
        Some(s) => s,
        None => {
            let _ = session
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await;
            return Err("http connect: all resolved addresses failed".to_string());
        }
    };
    up.set_nodelay(true).ok();

    session
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .map_err(|e| format!("http connect: write 200: {e}"))?;

    if anonymize_target_logs {
        info!(client = %plog(&peer), "HTTP CONNECT established; bridging");
    } else {
        info!(client = %plog(&peer), target = %host, port, "HTTP CONNECT established; bridging");
    }

    // Idle-aware (BRIDGE-LEGACY-COPY-NO-IDLE): reap a dead/idle HTTP-CONNECT
    // tunnel instead of pinning its concurrency slot + upstream fd forever.
    match mirage_socks5::copy_bidirectional_idle(session, up, MUX_STREAM_IDLE_TIMEOUT).await {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("http connect copy: {e}")),
    }
}

fn is_cohort_target(t: &ConnectTarget) -> bool {
    // Why eq_ignore_ascii_case: DNS is case-insensitive (RFC 1035 §2.3.3).
    // A SOCKS5 client that sends `_Mirage_Cohort._INTERNAL` would
    // otherwise miss the magic-host dispatch and fall through to a
    // real DNS resolution against the bridge's resolver, leaking
    // the magic hostname to whatever upstream DNS the bridge uses.
    matches!(
        t,
        ConnectTarget::Domain(name, COHORT_MAGIC_PORT)
            if name.eq_ignore_ascii_case(COHORT_MAGIC_HOSTNAME)
    )
}

async fn handle_cohort_request<S>(
    mut session: S,
    peer: std::net::SocketAddr,
    token_id: Option<[u8; 32]>,
    token_kind: Option<mirage_session::AcceptedTokenKind>,
    cohort: Arc<CohortState>,
    metrics: Arc<Metrics>,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // SOCKS5 reply: success with all-zero BND so the client can
    // begin the application-layer exchange.
    send_success_reply_for_internal(&mut session)
        .await
        .map_err(|e| format!("cohort reply: {e}"))?;

    // Read a fixed 3-byte request under a hard deadline (RT-rl-2).
    let mut buf = [0u8; 3];
    tokio::time::timeout(MAGIC_HOST_REQUEST_TIMEOUT, session.read_exact(&mut buf))
        .await
        .map_err(|_| "cohort read: timeout".to_string())?
        .map_err(|e| format!("cohort read: {e}"))?;
    let req = match CohortRequest::decode(&buf) {
        Ok(r) => r,
        Err(e) => {
            // Reply with a BAD_REQUEST and close.
            let resp = CohortResponse::empty(mirage_discovery::cohort::COHORT_STATUS_BAD_REQUEST);
            let _ = session.write_all(&resp.encode()).await;
            let _ = session.flush().await;
            return Err(format!("cohort decode: {e}"));
        }
    };
    // RT #16: refresh-authenticated sessions get NO cohort reveals. The
    // anti-enumeration reveal cap is charged per session `token_id`, but
    // `refresh` mints a FRESH token_id per bootstrap - so a client refreshing
    // its session could reset the cap and multiply fleet disclosure (5x per
    // bootstrap by default). Cohort reveals are a bootstrap-lineage budget;
    // a refresh session already holds a working entry and does not need more.
    // Reply EXHAUSTED so the client stops asking.
    if matches!(token_kind, Some(mirage_session::AcceptedTokenKind::Refresh)) {
        let resp = CohortResponse::empty(mirage_discovery::cohort::COHORT_STATUS_EXHAUSTED);
        session
            .write_all(&resp.encode())
            .await
            .map_err(|e| format!("cohort write: {e}"))?;
        session
            .flush()
            .await
            .map_err(|e| format!("cohort flush: {e}"))?;
        info!(client = %plog(&peer), "cohort reveal denied to refresh session (RT #16)");
        return Ok(());
    }
    let max_n = req.max_n.min(COHORT_MAX_N_PER_REQUEST);
    let (anns, status) = cohort.pick_for_token(token_id, max_n).await;
    let resp = CohortResponse {
        status,
        announcements: anns,
    };
    let wire = resp.encode();
    session
        .write_all(&wire)
        .await
        .map_err(|e| format!("cohort write: {e}"))?;
    session
        .flush()
        .await
        .map_err(|e| format!("cohort flush: {e}"))?;
    info!(
        client = %plog(&peer),
        status,
        count = resp.announcements.len(),
        "cohort request served"
    );
    metrics.cohort_outcome(status);
    let _ = session.shutdown().await;
    Ok(())
}

// Session-refresh service

/// Per-bridge refresh state. Holds the signing key + per-root-token
/// issue counters so a single accepted token can mint at most
/// `per_root_cap` descendants across its lifetime at this bridge.
struct RefreshState {
    enabled: bool,
    signing_sk: Option<mirage_crypto::ed25519_dalek::SigningKey>,
    per_root_cap: u8,
    ttl: Duration,
    per_root: Mutex<HashMap<[u8; 32], (u32, std::time::Instant)>>,
}

impl RefreshState {
    fn new(
        enabled: bool,
        signing_sk: Option<mirage_crypto::ed25519_dalek::SigningKey>,
        per_root_cap: u8,
        ttl: Duration,
    ) -> Self {
        Self {
            enabled: enabled && signing_sk.is_some(),
            signing_sk,
            per_root_cap,
            ttl,
            per_root: Mutex::new(HashMap::new()),
        }
    }

    /// Mint up to `count` fresh refresh tokens for the given root
    /// token, respecting the per-root lifetime cap. Returns `(tokens,
    /// status)`; status is one of `REFRESH_STATUS_OK`,
    /// `REFRESH_STATUS_EXHAUSTED`, `REFRESH_STATUS_POLICY`.
    async fn mint_for_root(
        &self,
        root_token_id: Option<[u8; 32]>,
        count: u8,
        now_unix: u64,
    ) -> (Vec<mirage_discovery::refresh::SessionRefreshToken>, u8) {
        if !self.enabled {
            return (Vec::new(), REFRESH_STATUS_POLICY);
        }
        let Some(sk) = self.signing_sk.as_ref() else {
            return (Vec::new(), REFRESH_STATUS_POLICY);
        };
        // Refresh requires an authenticated session's root-token id.
        // Without it (test-only no-token handshake) refuse to mint -
        // otherwise the per-root cap can't be enforced.
        let Some(root) = root_token_id else {
            return (Vec::new(), REFRESH_STATUS_EXHAUSTED);
        };

        let mut per = self.per_root.lock().await;
        // Cap-and-evict: bound the per_root table to defeat the
        // unbounded-chain attack where a single attacker mints
        // arbitrarily many descendants and forces an entry per
        // descendant. Audit fix: HIGH-Trust-3.
        if per.len() >= REFRESH_PER_ROOT_TABLE_CAP && !per.contains_key(&root) {
            if let Some(oldest_key) = per
                .iter()
                .min_by_key(|(_, (_, last_seen))| *last_seen)
                .map(|(k, _)| *k)
            {
                per.remove(&oldest_key);
            }
        }
        let now = std::time::Instant::now();
        let entry = per.entry(root).or_insert((0u32, now));
        entry.1 = now;
        let counter = &mut entry.0;
        let remaining = (self.per_root_cap as u32).saturating_sub(*counter);
        if remaining == 0 {
            return (Vec::new(), REFRESH_STATUS_EXHAUSTED);
        }
        let requested = (count as u32).min(REFRESH_MAX_PER_REQUEST as u32);
        let to_mint = requested.min(remaining) as usize;
        if to_mint == 0 {
            return (Vec::new(), REFRESH_STATUS_EXHAUSTED);
        }

        let expires_at = now_unix.saturating_add(self.ttl.as_secs());
        let mut out = Vec::with_capacity(to_mint);
        let mut csprng_failed = false;
        for _ in 0..to_mint {
            let mut tid = [0u8; 32];
            if getrandom::fill(&mut tid).is_err() {
                // CSPRNG failure: abort to avoid issuing predictable
                // token ids. Surface this as an explicit status
                // (not a silent empty-OK) so the client can log +
                // retry rather than thinking the bridge chose to
                // issue zero tokens. RT-refresh-3.
                csprng_failed = true;
                break;
            }
            out.push(sign_refresh_token(tid, sk, expires_at));
        }
        *counter = counter.saturating_add(out.len() as u32);
        let status = if csprng_failed && out.is_empty() {
            error!("CSPRNG failure during refresh token mint; returning INTERNAL");
            mirage_discovery::refresh::REFRESH_STATUS_INTERNAL
        } else {
            mirage_discovery::refresh::REFRESH_STATUS_OK
        };
        (out, status)
    }
}

fn is_refresh_target(t: &ConnectTarget) -> bool {
    matches!(
        t,
        ConnectTarget::Domain(name, REFRESH_MAGIC_PORT)
            if name.eq_ignore_ascii_case(REFRESH_MAGIC_HOSTNAME)
    )
}

async fn handle_refresh_request<S>(
    mut session: S,
    peer: std::net::SocketAddr,
    token_id: Option<[u8; 32]>,
    token_kind: Option<mirage_session::AcceptedTokenKind>,
    refresh: Arc<RefreshState>,
    metrics: Arc<Metrics>,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // Audit fix HIGH-Trust-1: refresh tokens cannot themselves mint
    // refresh tokens. Without this rule, a single leaked bootstrap
    // mints N refresh tokens; each opens a session and (under the
    // prior rule) mints another N; chain grows as N^d for depth d
    // and the per-bridge `per_root` map grows accordingly.
    //
    // Lineage tracking via wire-format change is the v0.2 fix; for
    // v0.1, refuse the request with REFRESH_STATUS_POLICY when the
    // session's authenticating token is itself a refresh token. The
    // user can still re-authenticate via their original bootstrap
    // (or any descendant the bridge still accepts) and refresh from
    // there - the chain depth is now capped at 1.
    if matches!(token_kind, Some(mirage_session::AcceptedTokenKind::Refresh)) {
        let resp = RefreshResponse::empty(mirage_discovery::refresh::REFRESH_STATUS_POLICY);
        let wire = resp.encode();
        // SOCKS5 success reply so we can write the protocol response.
        send_success_reply_for_internal(&mut session)
            .await
            .map_err(|e| format!("refresh reply: {e}"))?;
        let _ = session.write_all(&wire).await;
        let _ = session.flush().await;
        let _ = session.shutdown().await;
        info!(
            client = %plog(&peer),
            status = mirage_discovery::refresh::REFRESH_STATUS_POLICY,
            "refresh refused: requesting session is itself refresh-authenticated"
        );
        metrics.refresh_outcome(mirage_discovery::refresh::REFRESH_STATUS_POLICY);
        return Ok(());
    }
    // SOCKS5 success reply so the client can proceed.
    send_success_reply_for_internal(&mut session)
        .await
        .map_err(|e| format!("refresh reply: {e}"))?;

    // Read the fixed 3-byte refresh request under a hard deadline
    // (RT-rl-2).
    let mut buf = [0u8; 3];
    tokio::time::timeout(MAGIC_HOST_REQUEST_TIMEOUT, session.read_exact(&mut buf))
        .await
        .map_err(|_| "refresh read: timeout".to_string())?
        .map_err(|e| format!("refresh read: {e}"))?;
    let req = match RefreshRequest::decode(&buf) {
        Ok(r) => r,
        Err(e) => {
            let resp =
                RefreshResponse::empty(mirage_discovery::refresh::REFRESH_STATUS_BAD_REQUEST);
            let _ = session.write_all(&resp.encode()).await;
            let _ = session.flush().await;
            return Err(format!("refresh decode: {e}"));
        }
    };

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (tokens, status) = refresh.mint_for_root(token_id, req.count, now_unix).await;
    let resp = RefreshResponse { status, tokens };
    let wire = resp.encode();
    session
        .write_all(&wire)
        .await
        .map_err(|e| format!("refresh write: {e}"))?;
    session
        .flush()
        .await
        .map_err(|e| format!("refresh flush: {e}"))?;
    info!(
        client = %plog(&peer),
        status,
        count = resp.tokens.len(),
        "refresh request served"
    );
    metrics.refresh_outcome(status);
    let _ = session.shutdown().await;
    Ok(())
}

// Per-invite claim service (v0.1e)

/// Publishes a privacy-preserving `ClaimObserved` gossip event when
/// this bridge accepts a first-use claim, feeding the cohort's
/// cross-bridge leaked-invite detector ([`mirage_bridge::LeakDetector`]).
/// Installed on [`ClaimState`] at startup only when gossip is active
/// AND a cohort claim-tag key is configured; otherwise claims are not
/// gossiped at all.
struct ClaimGossipPublisher {
    gossip: Arc<dyn mirage_discovery::cohort_gossip::CohortGossip>,
    signing_key: mirage_crypto::ed25519_dalek::SigningKey,
    cohort_tag_key: [u8; 32],
}

impl ClaimGossipPublisher {
    /// Derive the cohort tag for `claim_id` and publish a signed
    /// `ClaimObserved`. The raw claim id never leaves this process -
    /// only its cohort-keyed tag. Best-effort: the gossip layer never
    /// blocks on slow peers and silently drops when the channel is
    /// down, so this can't stall the claim response.
    async fn publish(&self, claim_id: &[u8; 32]) {
        use mirage_discovery::cohort_gossip::{GossipEvent, SignedGossipEvent};
        let claim_tag =
            mirage_discovery::claim::claim_observation_tag(&self.cohort_tag_key, claim_id);
        let observed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let event = GossipEvent::ClaimObserved {
            claim_tag,
            observed_at,
        };
        let signed = SignedGossipEvent::sign(event, &self.signing_key);
        self.gossip.publish(signed).await;
    }
}

/// Per-bridge claim state. Tracks claim ids this bridge has
/// accepted so a second REDEEM for the same id fails with
/// `ALREADY_CLAIMED`. Optionally backed by a persistent log
/// (v0.1t) so a bridge restart preserves the one-claim-per-invite
/// invariant (B1 honesty).
struct ClaimState {
    enabled: bool,
    capacity: usize,
    /// Set of claim ids already accepted at this bridge. Backed
    /// by `log` when present; restored on bridge startup.
    claimed: Mutex<std::collections::HashSet<[u8; 32]>>,
    /// Root tokens (handshake-consumed bootstrap/refresh tokens)
    /// that have already used their single claim budget. Per-session
    /// cap = 1: an authenticated session may insert AT MOST one
    /// claim_id regardless of how many `REDEEM` requests it sends.
    /// Without this, a client with one bootstrap token could spam
    /// random claim_ids into the bridge's claimed set to exhaust
    /// capacity (RT-claim-1).
    used_roots: Mutex<std::collections::HashSet<[u8; 32]>>,
    /// Optional disk-backed claim log. When `Some`, every
    /// successful claim is written before returning to the client.
    log: Option<tokio::sync::Mutex<crate::claim_log::PersistentClaimLog>>,
    /// Cohort claim-observation publisher. Set once at startup when
    /// gossip + a cohort claim-tag key are configured; `None`/unset
    /// disables cross-bridge leak attribution. `OnceLock` because the
    /// gossip stack is built after `ClaimState` (the `Arc` is already
    /// shared by then) but before any session is served.
    claim_observer: std::sync::OnceLock<ClaimGossipPublisher>,
}

impl ClaimState {
    /// In-memory-only constructor (used by tests; production uses
    /// `new_with_optional_log`).
    #[cfg(test)]
    fn new(enabled: bool, capacity: usize) -> Self {
        Self {
            enabled,
            capacity,
            claimed: Mutex::new(std::collections::HashSet::new()),
            used_roots: Mutex::new(std::collections::HashSet::new()),
            log: None,
            claim_observer: std::sync::OnceLock::new(),
        }
    }

    /// Construct with optional persistence. On startup, loads any
    /// existing log entries into the in-memory sets so the one-
    /// claim-per-invite invariant survives a bridge restart.
    fn new_with_optional_log(
        enabled: bool,
        capacity: usize,
        path: Option<&str>,
        fsync_every_write: bool,
    ) -> Self {
        let mut claimed = std::collections::HashSet::new();
        let mut used_roots = std::collections::HashSet::new();
        let log = match path {
            Some(p) => {
                match crate::claim_log::PersistentClaimLog::load(p) {
                    Ok(records) => {
                        for (cid, rid) in records {
                            claimed.insert(cid);
                            used_roots.insert(rid);
                        }
                    }
                    Err(e) => {
                        warn!(path = %p, error = %e, "claim log: load failed; starting empty");
                    }
                }
                match crate::claim_log::PersistentClaimLog::open(p, fsync_every_write) {
                    Ok(log) => {
                        info!(
                            path = %p,
                            fsync = fsync_every_write,
                            restored = claimed.len(),
                            "claim log: disk-backed mode engaged"
                        );
                        Some(tokio::sync::Mutex::new(log))
                    }
                    Err(e) => {
                        warn!(path = %p, error = %e, "claim log: open failed; in-memory only");
                        None
                    }
                }
            }
            None => None,
        };
        Self {
            enabled,
            capacity,
            claimed: Mutex::new(claimed),
            used_roots: Mutex::new(used_roots),
            log,
            claim_observer: std::sync::OnceLock::new(),
        }
    }

    /// Install the cohort claim-observation publisher. Startup-only;
    /// a second call is a no-op (`OnceLock`).
    fn set_observer(&self, publisher: ClaimGossipPublisher) {
        let _ = self.claim_observer.set(publisher);
    }

    /// Publish a `ClaimObserved` gossip event for an accepted claim, if
    /// the cohort observer is installed. No-op otherwise. Called only
    /// after [`Self::try_claim`] returns [`CLAIM_STATUS_OK`] - i.e. on a
    /// genuine first-use at this bridge, which is exactly the signal the
    /// detector correlates across bridges.
    async fn notify_claim_observed(&self, claim_id: &[u8; 32]) {
        if let Some(publisher) = self.claim_observer.get() {
            publisher.publish(claim_id).await;
        }
    }

    /// Attempt to claim `claim_id`, charging the attempt against
    /// `root_token_id` (the token the session handshake accepted).
    /// Per-root cap = 1: a single session-root can only register one
    /// claim_id. Returns the status byte that should go on the wire:
    /// - `OK` - first time for both the claim_id AND the root.
    /// - `ALREADY_CLAIMED` - the claim_id is already in the set,
    ///   OR this root has already claimed once.
    /// - `CAPACITY` - set is full.
    /// - `POLICY` - claim is disabled, or the request arrived on a
    ///   test-only no-token session (no root id to charge).
    async fn try_claim(&self, claim_id: [u8; 32], root_token_id: Option<[u8; 32]>) -> u8 {
        if !self.enabled {
            return CLAIM_STATUS_POLICY;
        }
        // A session with no root-token identity cannot claim - we'd
        // have no way to enforce the per-session budget.
        let Some(root) = root_token_id else {
            return CLAIM_STATUS_POLICY;
        };
        let mut roots = self.used_roots.lock().await;
        if roots.contains(&root) {
            return CLAIM_STATUS_ALREADY_CLAIMED;
        }
        // Bound the roots set against cumulative memory growth -
        // uses the same capacity as claimed ids (they grow in
        // lockstep in the common case).
        if roots.len() >= self.capacity {
            return CLAIM_STATUS_CAPACITY;
        }
        let mut set = self.claimed.lock().await;
        if set.contains(&claim_id) {
            // Don't record the root as "used" - the client can
            // retry with a different claim_id (they may have sent
            // the wrong one). But still return ALREADY_CLAIMED so
            // the duplicate-claim warning fires.
            return CLAIM_STATUS_ALREADY_CLAIMED;
        }
        if set.len() >= self.capacity {
            return CLAIM_STATUS_CAPACITY;
        }
        // Persist BEFORE returning success: a crash between insert
        // and disk-write would otherwise admit a re-redemption.
        // B1 honesty: the on-disk log is the durable
        // truth.
        if let Some(log_mtx) = &self.log {
            let mut log = log_mtx.lock().await;
            if let Err(e) = log.append(&claim_id, &root) {
                warn!(error = %e, "claim log append failed; refusing claim");
                return CLAIM_STATUS_INTERNAL;
            }
        }
        set.insert(claim_id);
        roots.insert(root);
        CLAIM_STATUS_OK
    }
}

fn is_claim_target(t: &ConnectTarget) -> bool {
    matches!(
        t,
        ConnectTarget::Domain(name, CLAIM_MAGIC_PORT)
            if name.eq_ignore_ascii_case(CLAIM_MAGIC_HOSTNAME)
    )
}

async fn handle_claim_request<S>(
    mut session: S,
    peer: std::net::SocketAddr,
    token_id: Option<[u8; 32]>,
    token_kind: Option<mirage_session::AcceptedTokenKind>,
    claim: Arc<ClaimState>,
    refresh: Arc<RefreshState>,
    metrics: Arc<Metrics>,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    send_success_reply_for_internal(&mut session)
        .await
        .map_err(|e| format!("claim reply: {e}"))?;

    // Read fixed-size request under a hard deadline (RT-rl-2).
    let mut buf = [0u8; mirage_discovery::CLAIM_REQUEST_LEN];
    tokio::time::timeout(MAGIC_HOST_REQUEST_TIMEOUT, session.read_exact(&mut buf))
        .await
        .map_err(|_| "claim read: timeout".to_string())?
        .map_err(|e| format!("claim read: {e}"))?;
    let req = match ClaimRequest::decode(&buf) {
        Ok(r) => r,
        Err(e) => {
            let resp = ClaimResponse::empty(mirage_discovery::claim::CLAIM_STATUS_BAD_REQUEST);
            let _ = session.write_all(&resp.encode()).await;
            let _ = session.flush().await;
            return Err(format!("claim decode: {e}"));
        }
    };

    let status = claim.try_claim(req.claim_id, token_id).await;

    // Audit fix HIGH-Trust-1 (claim path): the refresh piggyback mints
    // refresh tokens, so it MUST inherit the same depth-1 chain cap as
    // handle_refresh_request - otherwise a refresh-authenticated session
    // could `claim(fresh_id, refresh_count=N)` and recharge the chain via
    // the piggyback, bypassing the guard at the dedicated refresh handler.
    // The claim itself still succeeds (claim_id is recorded); only the
    // refresh piggyback is suppressed for refresh-authenticated sessions.
    let refresh_authenticated =
        matches!(token_kind, Some(mirage_session::AcceptedTokenKind::Refresh));
    if refresh_authenticated && status == CLAIM_STATUS_OK && req.refresh_count > 0 {
        info!(
            client = %plog(&peer),
            "claim ok but refresh piggyback suppressed: session is refresh-authenticated (depth-1 cap)"
        );
    }

    // On successful claim, piggyback the requested refresh tokens.
    // On non-OK status, return the status with no tokens.
    let tokens = if !refresh_authenticated && status == CLAIM_STATUS_OK && req.refresh_count > 0 {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let (t, _rstatus) = refresh
            .mint_for_root(token_id, req.refresh_count, now_unix)
            .await;
        t
    } else {
        Vec::new()
    };

    let resp = ClaimResponse { status, tokens };
    let wire = resp.encode();
    session
        .write_all(&wire)
        .await
        .map_err(|e| format!("claim write: {e}"))?;
    session
        .flush()
        .await
        .map_err(|e| format!("claim flush: {e}"))?;
    info!(
        client = %plog(&peer),
        status,
        refresh_count = resp.tokens.len(),
        claim_id_prefix = %format_args!("{:02x}{:02x}{:02x}{:02x}",
            req.claim_id[0], req.claim_id[1], req.claim_id[2], req.claim_id[3]),
        "claim request served"
    );
    metrics.claim_outcome(status);
    if status == CLAIM_STATUS_ALREADY_CLAIMED {
        // Operator-visible alert: a duplicate claim attempt is a
        // leak signal. Worth surfacing loudly.
        warn!(
            client = %plog(&peer),
            claim_id_prefix = %format_args!("{:02x}{:02x}{:02x}{:02x}",
                req.claim_id[0], req.claim_id[1], req.claim_id[2], req.claim_id[3]),
            "duplicate claim attempt - possible invite leak"
        );
    }
    // Cohort cross-bridge leak attribution: on a genuine first-use at
    // this bridge, gossip a privacy-preserving tag of the claim id so
    // peers can detect the SAME invite being claimed elsewhere (a
    // leaked/shared invite). Done AFTER the client response is flushed
    // so the best-effort gossip publish never delays the reply. No-op
    // unless an observer was installed at startup.
    if status == CLAIM_STATUS_OK {
        claim.notify_claim_observed(&req.claim_id).await;
    }
    let _ = session.shutdown().await;
    Ok(())
}

// UDP-relay service (v0.1r): bridge-side end of UDP-over-Mirage

fn is_udp_relay_target(t: &ConnectTarget) -> bool {
    matches!(
        t,
        ConnectTarget::Domain(name, UDP_RELAY_MAGIC_PORT)
            if name.eq_ignore_ascii_case(UDP_RELAY_MAGIC_HOSTNAME)
    )
}

/// Hard cap on how long an idle UDP-relay session sits without
/// either side sending. Without this, a misbehaving client that
/// holds the session open forever consumes a session slot. Five
/// minutes covers the longest typical "bursty UDP request" idle
/// gap (DNS resolver retries, QUIC connection migration,
/// WireGuard keepalives).
const UDP_RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Recv buffer for upstream UDP responses. Sized to the maximum UDP payload
/// (65535) so a large datagram is not TRUNCATED before we decide whether it
/// fits the tunnel's per-datagram cap; datagrams that don't fit after
/// re-wrapping are dropped, not truncated or relayed short.
const UDP_RECV_BUFFER_SIZE: usize = 65535;

/// Bridge-side UDP-relay handler. Reads SOCKS5-UDP-formatted
/// datagrams off the Mirage session via `UdpFramer`, sends them to
/// the named upstream over UDP, and returns response datagrams.
///
/// One UDP socket per session - bound ephemerally on the bridge
/// host so per-session NAT mapping at the bridge's egress is
/// fresh. The socket is dropped when the session ends.
///
/// AllowlistPolicy applies: a session that asks the bridge to send
/// UDP to loopback / private networks is rejected per-datagram
/// rather than per-session, so a misbehaving client can't open a
/// relay and then probe internal hosts at will.
async fn handle_udp_relay_request<S>(
    mut session: S,
    peer: std::net::SocketAddr,
    policy: Arc<AllowlistPolicy>,
    metrics: Arc<Metrics>,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use tokio::net::UdpSocket;

    metrics.udp_relay_session_opened();
    // SOCKS5 success reply so the client moves on to the framer.
    send_success_reply_for_internal(&mut session)
        .await
        .map_err(|e| format!("udp-relay reply: {e}"))?;

    // Ephemeral UDP socket on whichever interface the bridge host
    // routes through. Bind to 0.0.0.0:0 so the kernel picks the
    // local source - matches normal egress behavior.
    let upstream_sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("udp-relay bind: {e}"))?;
    let upstream_sock = Arc::new(upstream_sock);
    debug!(client = %plog(&peer), local = ?upstream_sock.local_addr(), "udp-relay socket bound");

    let (rx_session, tx_session) = tokio::io::split(session);
    let mut framer_rx = UdpFramer::new(rx_session);
    let framer_tx = UdpFramer::new(tx_session);
    let framer_tx = Arc::new(tokio::sync::Mutex::new(framer_tx));

    // Track the LAST destination the client sent to. Return
    // datagrams from that peer flow back; datagrams from any other
    // peer are dropped (client didn't ask for them, and they could
    // be from an attacker spraying the bridge's source port).
    //
    // For multi-destination sessions (rare) the client sends a
    // datagram to each in turn; the last-seen-peer policy means
    // only the most recent peer's responses come back. A future
    // iteration can demux per-destination via a HashMap if real
    // workloads need it.
    let last_dest: Arc<tokio::sync::Mutex<Option<std::net::SocketAddr>>> =
        Arc::new(tokio::sync::Mutex::new(None));

    let session_label = format!("{peer}");

    // Spawn the upstream->client direction.
    //
    // RT-udp-relay-6: NO timeout on `recv_from` here. The client-
    // side direction below drives session lifetime via its own
    // idle timeout; when it ends, it aborts this task. Earlier
    // versions had independent timeouts on both sides which left
    // a half-open relay (client still forwarding upstream while
    // the response task had already exited). Now every session
    // ends in exactly one place.
    let up_to_cli = {
        let upstream_sock = Arc::clone(&upstream_sock);
        let last_dest = Arc::clone(&last_dest);
        let framer_tx = Arc::clone(&framer_tx);
        let session_label = session_label.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; UDP_RECV_BUFFER_SIZE];
            loop {
                let (n, src) = match upstream_sock.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(e) => {
                        debug!(peer = %session_label, error = %e, "udp-relay recv_from");
                        return;
                    }
                };
                let allowed = {
                    let last = last_dest.lock().await;
                    matches!(*last, Some(addr) if addr == src)
                };
                if !allowed {
                    // Drop datagrams from peers the client didn't
                    // ask for. RT-udp-relay-1: last-dest-only.
                    continue;
                }
                let dgram = match encode_udp_dgram(&Socks5UdpDest::Ip(src), &buf[..n]) {
                    Ok(d) => d,
                    Err(_) => continue, // shouldn't happen for IP dests
                };
                // Drop an over-cap re-wrapped datagram rather than tearing down
                // the whole downlink direction (UDP-RELAY-OVERSIZE-TEARDOWN):
                // one oversized upstream response must not permanently break all
                // replies. Only a real session-write failure ends the loop.
                if dgram.len() > MAX_UDP_DATAGRAM_BYTES {
                    continue;
                }
                let mut fx = framer_tx.lock().await;
                if fx.send(&dgram).await.is_err() {
                    return;
                }
            }
        })
    };

    // Client->upstream direction (this task; stays in-handler so
    // the function returns when the client side ends).
    loop {
        let dgram = match tokio::time::timeout(UDP_RELAY_IDLE_TIMEOUT, framer_rx.recv()).await {
            Ok(Ok(Some(d))) => d,
            Ok(Ok(None)) => break, // clean EOF
            Ok(Err(e)) => {
                debug!(client = %plog(&peer), error = %e, "udp-relay frame recv");
                break;
            }
            Err(_) => {
                debug!(client = %plog(&peer), "udp-relay client idle");
                break;
            }
        };
        let (dest, payload) = match decode_udp_dgram(&dgram) {
            Ok(v) => v,
            Err(e) => {
                debug!(client = %plog(&peer), error = %e, "udp-relay malformed datagram");
                continue;
            }
        };
        let socket_dest: std::net::SocketAddr = match dest {
            Socks5UdpDest::Ip(a) => {
                // Single-IP datagram: policy-check, then send.
                if let Err(reason) = policy.check(&a) {
                    // Deanon: never log the client's UDP destination (matches the
                    // TCP path's anonymize_target_logs default).
                    debug!(client = %plog(&peer), reason, "udp-relay policy denied");
                    metrics.udp_relay_policy_denial();
                    continue;
                }
                a
            }
            Socks5UdpDest::Domain { name, port } => {
                // Resolve to ALL records. Then `check_all`: refuse
                // the whole datagram if ANY record is in a denied
                // range. This closes the DNS-rebinding window
                // where a malicious authoritative server returns
                // `[public, 127.0.0.1]` and the bridge picks one
                // record per datagram - over a session, some
                // datagrams could land on the private IP. The
                // stricter "fail if any denied" closes that
                // entirely.
                let target = format!("{name}:{port}");
                let resolved: Vec<std::net::SocketAddr> =
                    match tokio::net::lookup_host(target).await {
                        Ok(iter) => iter.collect(),
                        Err(e) => {
                            // Deanon: omit the resolved name (it is the client's dest).
                            debug!(client = %plog(&peer), error = %e, "udp-relay resolve failed");
                            continue;
                        }
                    };
                if let Err(reason) = policy.check_all(&resolved) {
                    debug!(
                        client = %plog(&peer),
                        candidates = resolved.len(),
                        reason,
                        "udp-relay policy denied (check_all)"
                    );
                    metrics.udp_relay_policy_denial();
                    continue;
                }
                match resolved.into_iter().next() {
                    Some(a) => a,
                    None => continue,
                }
            }
        };
        if upstream_sock.send_to(payload, socket_dest).await.is_err() {
            continue;
        }
        metrics.udp_relay_dgram_relayed();
        let mut last = last_dest.lock().await;
        *last = Some(socket_dest);
    }

    up_to_cli.abort();
    info!(client = %plog(&peer), "udp-relay session closed");
    Ok(())
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    /// M4: the bridge binds the SAME epoch-derived UDP port the client dials
    /// (both call `derive_port` with `NAMESPACE_CLIENT_TO_BRIDGE`), so hysteria2
    /// port-hopping actually connects. Proves client<->bridge derivation agreement.
    #[test]
    fn derived_udp_bind_addrs_matches_client_derivation() {
        use mirage_discovery::derive::{derive_port, epoch_for_time, NAMESPACE_CLIENT_TO_BRIDGE};
        let salt = [0x5Au8; 32];
        let (base, range) = (20_000u16, 1_000u16);
        let k = "11".repeat(32);
        let json = format!(
            r#"{{"bind":"0.0.0.0:443","bridge_x25519_sk_hex":"{k}","bridge_ed25519_pk_hex":"{k}","operator_ed25519_pk_hex":"{k}","derived_port_base":{base},"derived_port_range":{range},"derived_port_shared_salt_hex":"{}"}}"#,
            hex::encode(salt)
        );
        let config: BridgeConfig = serde_json::from_str(&json).expect("minimal config");
        let base_addr: std::net::SocketAddr = "127.0.0.1:443".parse().unwrap();
        let addrs = derived_udp_bind_addrs(&config, base_addr);
        assert_eq!(addrs.len(), 2, "current + next epoch");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let want = derive_port(
            &salt,
            NAMESPACE_CLIENT_TO_BRIDGE,
            epoch_for_time(now),
            base,
            range,
        )
        .unwrap();
        assert!(
            addrs.iter().any(|a| a.port() == want),
            "bridge must bind the current-epoch derived port {want} the client dials"
        );
        assert!(
            addrs
                .iter()
                .all(|a| a.ip() == base_addr.ip() && (base..base + range).contains(&a.port())),
            "same IP, port in [base, base+range)"
        );
    }

    /// H1: a malformed cover target must return a clean `Err` (never panic), so
    /// a misconfigured `reality_tls_mode=borrow` fails startup with a clear
    /// message rather than crashing. (The happy-path fetch is byte-identical to
    /// the shipped `mirage-cover-fetch` tool's capture path.)
    #[tokio::test]
    async fn fetch_cover_leaf_cert_der_rejects_malformed_target() {
        // No port separator.
        assert!(fetch_cover_leaf_cert_der("no-port-here").await.is_err());
        // Empty host.
        assert!(fetch_cover_leaf_cert_der(":443").await.is_err());
    }

    #[test]
    fn bridge_obfs_key_precedence_and_client_agreement() {
        let pk = [0x11u8; 32];
        let secret = [0x5Au8; 32];
        let secret_hex = hex::encode(secret);

        // 1. Explicit password wins over everything.
        let (k_pw, mode) = resolve_bridge_obfs_key(Some("hunter2"), Some(&secret_hex), &pk);
        assert_eq!(mode, "shared-password");
        assert_eq!(k_pw, mirage_quic_obfs::key_from_password(b"hunter2"));

        // 2. With no password, the invite secret (hex) is used - and it MUST
        //    equal the key the client derives from the invite's raw 32-byte
        //    secret (`key_from_password(&secret)`), or QUIC obfs desyncs.
        let (k_secret, mode) = resolve_bridge_obfs_key(None, Some(&secret_hex), &pk);
        assert_eq!(mode, "invite-secret");
        assert_eq!(k_secret, mirage_quic_obfs::key_from_password(&secret));

        // 3. Neither set -> pubkey-derived default (obfuscated, not secret).
        let (k_def, mode) = resolve_bridge_obfs_key(None, None, &pk);
        assert_eq!(mode, "per-bridge-default");
        assert_eq!(k_def, mirage_quic_obfs::default_obfs_key(&pk));

        // 4. Empty strings are treated as unset; malformed hex falls through.
        assert_eq!(
            resolve_bridge_obfs_key(Some(""), Some(""), &pk).1,
            "per-bridge-default"
        );
        assert_eq!(
            resolve_bridge_obfs_key(None, Some("zzzz"), &pk).1,
            "per-bridge-default"
        );
    }

    #[test]
    fn parse_connect_target_accepts_valid_and_rejects_bad() {
        assert_eq!(
            parse_connect_target("CONNECT example.com:443 HTTP/1.1").unwrap(),
            ("example.com".to_string(), 443)
        );
        // Case-insensitive method, IPv4 literal.
        assert_eq!(
            parse_connect_target("connect 1.2.3.4:8080 HTTP/1.0").unwrap(),
            ("1.2.3.4".to_string(), 8080)
        );
        // Rejections.
        assert!(
            parse_connect_target("GET / HTTP/1.1").is_err(),
            "non-CONNECT method"
        );
        assert!(
            parse_connect_target("CONNECT example.com HTTP/1.1").is_err(),
            "no port"
        );
        assert!(
            parse_connect_target("CONNECT :443 HTTP/1.1").is_err(),
            "empty host"
        );
        assert!(
            parse_connect_target("CONNECT host:notaport HTTP/1.1").is_err(),
            "bad port"
        );
        assert!(parse_connect_target("").is_err(), "empty line");
    }

    /// Core acceptance for the HTTP active-probe-resistance path:
    /// `forward_to_shadow` must
    /// (a) deliver the replayed request to the shadow backend BYTE-IDENTICALLY
    /// so the decoy emits its genuine response, and (b) splice that response
    /// back to the prober. The shadow then becomes indistinguishable from the
    /// real backend probed directly.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn forward_to_shadow_replays_request_then_splices_response() {
        use tokio::net::TcpListener;

        const PROBE: &[u8] = b"GET / HTTP/1.1\r\nHost: cdn.example.com\r\n\r\n";
        const DECOY_RESPONSE: &[u8] = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";

        // Stand-in decoy: read exactly the replayed request, then answer like
        // a real backend and close.
        let shadow = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let shadow_addr = shadow.local_addr().unwrap();
        let shadow_task = tokio::spawn(async move {
            let (mut sock, _) = shadow.accept().await.unwrap();
            let mut got = vec![0u8; PROBE.len()];
            sock.read_exact(&mut got).await.unwrap();
            sock.write_all(DECOY_RESPONSE).await.unwrap();
            sock.flush().await.unwrap();
            got
        });

        // A "prober" connects to a loopback listener; the accepted socket is
        // the client stream handed to forward_to_shadow.
        let bridge = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bridge_addr = bridge.local_addr().unwrap();
        let prober = tokio::spawn(async move {
            let mut p = TcpStream::connect(bridge_addr).await.unwrap();
            let mut resp = Vec::new();
            p.read_to_end(&mut resp).await.unwrap();
            resp
        });
        let (client_sock, _) = bridge.accept().await.unwrap();

        let metrics = Arc::new(Metrics::new("0.1.0", "raw", "ephemeral"));
        forward_to_shadow(
            client_sock,
            PROBE.to_vec(),
            shadow_addr.to_string(),
            Duration::from_secs(5),
            Arc::clone(&metrics),
        );

        let shadow_got = shadow_task.await.unwrap();
        assert_eq!(
            shadow_got, PROBE,
            "shadow must receive the byte-identical replayed request"
        );
        let prober_resp = prober.await.unwrap();
        assert_eq!(
            prober_resp, DECOY_RESPONSE,
            "prober must receive the decoy's genuine response, spliced back"
        );
    }

    /// Regression for RT-claim-1: a single authenticated session
    /// (represented here by one `root_token_id`) must be allowed
    /// AT MOST one successful claim. Without this cap, a client
    /// with one bootstrap token could spam random claim_ids and
    /// fill the bridge's claimed set to capacity.
    #[tokio::test]
    async fn claim_state_rejects_second_claim_from_same_root() {
        let cs = ClaimState::new(true, 1024);
        let root = Some([0x11u8; 32]);
        // First claim with this root: OK.
        assert_eq!(cs.try_claim([0x01u8; 32], root).await, CLAIM_STATUS_OK);
        // Second claim from the same root with a different id:
        // must be rejected as ALREADY_CLAIMED, regardless of the
        // fact that the new claim_id has never been seen before.
        assert_eq!(
            cs.try_claim([0x02u8; 32], root).await,
            CLAIM_STATUS_ALREADY_CLAIMED
        );
        // Different roots remain independent - they get their own
        // single-claim budget.
        let root2 = Some([0x22u8; 32]);
        assert_eq!(cs.try_claim([0x03u8; 32], root2).await, CLAIM_STATUS_OK);
    }

    #[tokio::test]
    async fn claim_state_rejects_anonymous_root() {
        // Regression for RT-claim-1: a session with no root-token
        // identity (test-only no-token handshake) cannot claim -
        // we'd have no way to enforce the per-session cap.
        let cs = ClaimState::new(true, 1024);
        assert_eq!(cs.try_claim([0x01u8; 32], None).await, CLAIM_STATUS_POLICY);
    }

    #[tokio::test]
    async fn claim_state_duplicate_claim_id_does_not_burn_root() {
        // A client that sends a duplicate claim_id (e.g., attacker
        // echoing a known-leaked id) must get ALREADY_CLAIMED, but
        // the root-token's one-shot budget should NOT be marked
        // spent - the user's own client may want to retry with the
        // correct id. This is also what lets the victim, on a
        // fresh session, still claim their REAL claim_id at other
        // bridges.
        let cs = ClaimState::new(true, 1024);
        let root_a = Some([0xAAu8; 32]);
        let root_b = Some([0xBBu8; 32]);
        // Root A claims id X.
        assert_eq!(cs.try_claim([0xCCu8; 32], root_a).await, CLAIM_STATUS_OK);
        // Root B tries to claim the same id -> ALREADY_CLAIMED.
        assert_eq!(
            cs.try_claim([0xCCu8; 32], root_b).await,
            CLAIM_STATUS_ALREADY_CLAIMED
        );
        // Root B's budget not consumed -> can now claim a different id.
        assert_eq!(cs.try_claim([0xDDu8; 32], root_b).await, CLAIM_STATUS_OK);
    }

    /// End-to-end of the cross-bridge leak-attribution path through the
    /// real `ClaimGossipPublisher`: two bridges that share one cohort
    /// claim-tag key (but have distinct gossip identities) each redeem
    /// the SAME leaked invite. Their published `ClaimObserved` tags must
    /// match (proving cohort keying is deterministic) so the detector
    /// correlates them into a single two-publisher equivocation.
    #[tokio::test]
    async fn claim_observation_publisher_feeds_cross_bridge_leak_detector() {
        use mirage_crypto::ed25519_dalek::SigningKey;
        use mirage_discovery::cohort_gossip::{CohortGossip, MemoryGossip};

        let cohort_key = [0x7Eu8; 32];
        let sk_a = SigningKey::from_bytes(&[0xA1; 32]);
        let sk_b = SigningKey::from_bytes(&[0xB2; 32]);

        let gossip = MemoryGossip::new();
        gossip.authorize(sk_a.verifying_key().to_bytes()).await;
        gossip.authorize(sk_b.verifying_key().to_bytes()).await;
        let gossip: Arc<dyn CohortGossip> = Arc::new(gossip);

        let detector = Arc::new(mirage_bridge::LeakDetector::new(
            mirage_bridge::DEFAULT_LEAK_WINDOW,
        ));
        let _sub =
            mirage_bridge::spawn_gossip_to_leak_detector(gossip.clone(), Arc::clone(&detector));

        let pub_a = ClaimGossipPublisher {
            gossip: gossip.clone(),
            signing_key: sk_a,
            cohort_tag_key: cohort_key,
        };
        let pub_b = ClaimGossipPublisher {
            gossip: gossip.clone(),
            signing_key: sk_b,
            cohort_tag_key: cohort_key,
        };

        // The SAME leaked invite is redeemed at both bridges.
        let leaked_claim_id = [0x5Au8; 32];
        let tag = mirage_discovery::claim::claim_observation_tag(&cohort_key, &leaked_claim_id);
        // Re-publish until the async subscriber catches a pair (a
        // broadcast channel only delivers post-subscribe; the detector
        // dedupes by publisher, so the count caps at 2).
        for _ in 0..100 {
            pub_a.publish(&leaked_claim_id).await;
            pub_b.publish(&leaked_claim_id).await;
            if detector.observer_count(&tag) >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            detector.observer_count(&tag),
            2,
            "same invite claimed at two bridges must yield one tag from two publishers"
        );

        // A different invite claimed at only bridge A must NOT correlate.
        let other_id = [0x99u8; 32];
        let other_tag = mirage_discovery::claim::claim_observation_tag(&cohort_key, &other_id);
        for _ in 0..10 {
            pub_a.publish(&other_id).await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            detector.observer_count(&other_tag) <= 1,
            "a single-bridge claim must never reach the equivocation threshold"
        );
    }
}
