//! Operator-facing bridge metrics in Prometheus text-exposition form.
//!
//! # Why an in-process counter set, not the `prometheus` crate?
//!
//! The `prometheus` crate pulls in `protobuf`, `reqwest`, and a
//! family of transitive deps that nearly double the bridge binary
//! and broaden the audit surface. The operational requirement is
//! modest: a handful of counters and gauges scraped over HTTP/1.1.
//! A plain `AtomicU64` per counter plus a ~30-line HTTP responder
//! (using the already-present tokio runtime) covers it with zero
//! new crate deps.
//!
//! # What's exposed
//!
//! All metric names are `mirage_bridge_*`.
//!
//! - `sessions_total{outcome}` - cumulative session outcomes.
//! - `sessions_active` - current in-flight sessions.
//! - `reality_probes_total{outcome}` - authenticated / cover_served.
//! - `cover_bytes_total{direction}` - c2s / s2c on probe failure.
//! - `rate_limit_drops_total` - TCP-level rejections before any
//!   handshake work.
//! - `cohort_requests_total{status}` - cohort service outcomes.
//! - `refresh_requests_total{status}` - refresh service outcomes.
//! - `claim_requests_total{status}` - claim service outcomes.
//! - `tokens_accepted_total{kind}` - bootstrap / refresh token
//!   verification successes.
//! - `replay_set_size` - current entries (best-effort snapshot).
//! - `info{version,transport,tls_mode}` - build + deployment tag;
//!   always value 1.
//!
//! # Security + privacy
//!
//! - Metrics DO NOT carry per-session identifiers, peer IPs,
//!   client hostnames, or any content. Under the `lives at stake`
//!   threat model, anonymity-leaking metrics are worse than no
//!   metrics. A bridge operator can audit this module for the
//!   whole data surface in under 5 minutes.
//! - The endpoint binds to whatever the operator configures. For
//!   a public-facing bridge, bind to a loopback or
//!   management-network address, not the public IP.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

// -- per-transport session index constants ------------------------------------
pub const TRANSPORT_REALITY: usize = 0;
pub const TRANSPORT_OBFS_TCP: usize = 1;
pub const TRANSPORT_SS2022: usize = 2;
pub const TRANSPORT_WS: usize = 3;
pub const TRANSPORT_MEEK: usize = 4;
pub const TRANSPORT_VLESS: usize = 5;
/// RESERVED (obfs4 transport was removed - kept so the per-transport
/// counter indices below do not shift). Never emitted.
#[allow(dead_code)]
pub const TRANSPORT_OBFS4: usize = 6;
pub const TRANSPORT_HYSTERIA2: usize = 7;
pub const TRANSPORT_RAW: usize = 8;
/// RESERVED (HLS transport was removed - kept so the per-transport counter
/// indices below do not shift). Never emitted.
#[allow(dead_code)]
pub const TRANSPORT_HLS: usize = 9;
/// Only emitted when the bridge is built with the `webrtc` feature.
#[allow(dead_code)]
pub const TRANSPORT_WEBRTC: usize = 10;

/// Number of transport buckets in [`Metrics::sessions_by_transport`].
const TRANSPORT_COUNT: usize = 11;
/// Label names for each transport index (used in Prometheus output).
const TRANSPORT_LABELS: [&str; TRANSPORT_COUNT] = [
    "reality",
    "obfs_tcp",
    "ss2022",
    "websocket",
    "meek",
    "vless",
    "obfs4",
    "hysteria2",
    "raw",
    "hls",
    "webrtc",
];

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, warn};

/// Atomic-backed counter set for one bridge instance.
///
/// Cloning the `Arc` is cheap; all increment methods take `&self`
/// so callers hold `Arc<Metrics>` and never block each other.
pub struct Metrics {
    // ---- sessions ----
    pub(crate) sessions_accepted: AtomicU64,
    pub(crate) sessions_closed_ok: AtomicU64,
    pub(crate) sessions_closed_err: AtomicU64,
    pub(crate) sessions_handshake_failed: AtomicU64,
    pub(crate) sessions_handshake_timeout: AtomicU64,
    pub(crate) sessions_socks5_failed: AtomicU64,
    pub(crate) sessions_active: AtomicU64,

    // ---- Reality probes ----
    pub(crate) reality_authenticated: AtomicU64,
    pub(crate) reality_cover_served: AtomicU64,
    pub(crate) cover_bytes_c2s: AtomicU64,
    pub(crate) cover_bytes_s2c: AtomicU64,

    // ---- rate limiter ----
    pub(crate) rate_limit_drops: AtomicU64,

    // ---- magic-hostname services ----
    pub(crate) cohort_ok: AtomicU64,
    pub(crate) cohort_empty: AtomicU64,
    pub(crate) cohort_exhausted: AtomicU64,
    pub(crate) cohort_bad_request: AtomicU64,

    pub(crate) refresh_ok: AtomicU64,
    pub(crate) refresh_exhausted: AtomicU64,
    pub(crate) refresh_policy: AtomicU64,
    pub(crate) refresh_internal: AtomicU64,
    pub(crate) refresh_bad_request: AtomicU64,

    pub(crate) claim_ok: AtomicU64,
    pub(crate) claim_already: AtomicU64,
    pub(crate) claim_capacity: AtomicU64,
    pub(crate) claim_policy: AtomicU64,
    pub(crate) claim_bad_request: AtomicU64,

    // ---- tokens ----
    pub(crate) tokens_bootstrap: AtomicU64,
    pub(crate) tokens_refresh: AtomicU64,

    // ---- UDP relay (v0.1r) ----
    pub(crate) udp_relay_sessions_opened: AtomicU64,
    pub(crate) udp_relay_dgrams_relayed: AtomicU64,
    pub(crate) udp_relay_policy_denials: AtomicU64,

    // ---- per-transport session counters ----
    /// Sessions by transport: reality, obfs_tcp, ss2022, websocket, meek, vless, obfs4, hysteria2, raw
    pub sessions_by_transport: [AtomicU64; TRANSPORT_COUNT],

    // ---- shadow-target cover forwarding ----
    pub(crate) shadow_forwarded: AtomicU64,

    // ---- cohort gossip event counters ----
    pub(crate) gossip_events_probe_block: AtomicU64,
    pub(crate) gossip_events_burn: AtomicU64,
    pub(crate) gossip_events_distress: AtomicU64,
    pub(crate) gossip_events_heartbeat: AtomicU64,
    pub(crate) gossip_events_claim_observed: AtomicU64,

    // ---- build/deployment info labels (static) ----
    version: String,
    transport: String,
    tls_mode: String,
}

impl Metrics {
    /// Construct with static deployment labels for the `info` gauge.
    pub fn new(version: &str, transport: &str, tls_mode: &str) -> Self {
        Self {
            sessions_accepted: AtomicU64::new(0),
            sessions_closed_ok: AtomicU64::new(0),
            sessions_closed_err: AtomicU64::new(0),
            sessions_handshake_failed: AtomicU64::new(0),
            sessions_handshake_timeout: AtomicU64::new(0),
            sessions_socks5_failed: AtomicU64::new(0),
            sessions_active: AtomicU64::new(0),
            reality_authenticated: AtomicU64::new(0),
            reality_cover_served: AtomicU64::new(0),
            cover_bytes_c2s: AtomicU64::new(0),
            cover_bytes_s2c: AtomicU64::new(0),
            rate_limit_drops: AtomicU64::new(0),
            cohort_ok: AtomicU64::new(0),
            cohort_empty: AtomicU64::new(0),
            cohort_exhausted: AtomicU64::new(0),
            cohort_bad_request: AtomicU64::new(0),
            refresh_ok: AtomicU64::new(0),
            refresh_exhausted: AtomicU64::new(0),
            refresh_policy: AtomicU64::new(0),
            refresh_internal: AtomicU64::new(0),
            refresh_bad_request: AtomicU64::new(0),
            claim_ok: AtomicU64::new(0),
            claim_already: AtomicU64::new(0),
            claim_capacity: AtomicU64::new(0),
            claim_policy: AtomicU64::new(0),
            claim_bad_request: AtomicU64::new(0),
            tokens_bootstrap: AtomicU64::new(0),
            tokens_refresh: AtomicU64::new(0),
            udp_relay_sessions_opened: AtomicU64::new(0),
            udp_relay_dgrams_relayed: AtomicU64::new(0),
            udp_relay_policy_denials: AtomicU64::new(0),
            sessions_by_transport: std::array::from_fn(|_| AtomicU64::new(0)),
            shadow_forwarded: AtomicU64::new(0),
            gossip_events_probe_block: AtomicU64::new(0),
            gossip_events_burn: AtomicU64::new(0),
            gossip_events_distress: AtomicU64::new(0),
            gossip_events_heartbeat: AtomicU64::new(0),
            gossip_events_claim_observed: AtomicU64::new(0),
            version: version.to_string(),
            transport: transport.to_string(),
            tls_mode: tls_mode.to_string(),
        }
    }

    /// Snapshot the counter set as JSON for the in-process admin dashboard
    /// (`--admin-bind`). Same privacy posture as the Prometheus surface: no
    /// per-session identifiers, peer IPs, or content - only aggregate counters.
    pub fn snapshot_json(&self, replay_size: u64, uptime_secs: u64) -> serde_json::Value {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let by_transport: serde_json::Map<String, serde_json::Value> = TRANSPORT_LABELS
            .iter()
            .zip(self.sessions_by_transport.iter())
            .filter(|(_, c)| c.load(Ordering::Relaxed) > 0)
            .map(|(label, c)| ((*label).to_string(), g(c).into()))
            .collect();
        serde_json::json!({
            "version": self.version,
            "transport": self.transport,
            "tls_mode": self.tls_mode,
            "uptime_secs": uptime_secs,
            "replay_set_size": replay_size,
            "sessions": {
                "active": g(&self.sessions_active),
                "accepted": g(&self.sessions_accepted),
                "closed_ok": g(&self.sessions_closed_ok),
                "closed_err": g(&self.sessions_closed_err),
                "handshake_failed": g(&self.sessions_handshake_failed),
                "handshake_timeout": g(&self.sessions_handshake_timeout),
                "socks5_failed": g(&self.sessions_socks5_failed),
            },
            "sessions_by_transport": by_transport,
            "reality": {
                "authenticated": g(&self.reality_authenticated),
                "cover_served": g(&self.reality_cover_served),
                "cover_bytes_c2s": g(&self.cover_bytes_c2s),
                "cover_bytes_s2c": g(&self.cover_bytes_s2c),
            },
            "rate_limit_drops": g(&self.rate_limit_drops),
            "shadow_forwarded": g(&self.shadow_forwarded),
            "tokens": {
                "bootstrap": g(&self.tokens_bootstrap),
                "refresh": g(&self.tokens_refresh),
            },
            "udp_relay": {
                "sessions_opened": g(&self.udp_relay_sessions_opened),
                "dgrams_relayed": g(&self.udp_relay_dgrams_relayed),
                "policy_denials": g(&self.udp_relay_policy_denials),
            },
        })
    }

    // ---- increments ----

    pub fn session_accepted(&self) {
        self.sessions_accepted.fetch_add(1, Ordering::Relaxed);
        self.sessions_active.fetch_add(1, Ordering::Relaxed);
    }
    pub fn session_closed_ok(&self) {
        self.sessions_closed_ok.fetch_add(1, Ordering::Relaxed);
        self.sessions_active.fetch_sub(1, Ordering::Relaxed);
    }
    pub fn session_closed_err(&self) {
        self.sessions_closed_err.fetch_add(1, Ordering::Relaxed);
        self.sessions_active.fetch_sub(1, Ordering::Relaxed);
    }
    pub fn handshake_failed(&self) {
        self.sessions_handshake_failed
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn handshake_timeout(&self) {
        self.sessions_handshake_timeout
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn socks5_failed(&self) {
        self.sessions_socks5_failed.fetch_add(1, Ordering::Relaxed);
    }
    pub fn reality_authenticated(&self) {
        self.reality_authenticated.fetch_add(1, Ordering::Relaxed);
    }
    pub fn reality_cover_served(&self, c2s: u64, s2c: u64) {
        self.reality_cover_served.fetch_add(1, Ordering::Relaxed);
        self.cover_bytes_c2s.fetch_add(c2s, Ordering::Relaxed);
        self.cover_bytes_s2c.fetch_add(s2c, Ordering::Relaxed);
    }
    pub fn rate_limit_drop(&self) {
        self.rate_limit_drops.fetch_add(1, Ordering::Relaxed);
    }
    pub fn cohort_outcome(&self, status: u8) {
        use mirage_discovery::cohort::{
            COHORT_STATUS_BAD_REQUEST, COHORT_STATUS_EMPTY, COHORT_STATUS_EXHAUSTED,
            COHORT_STATUS_OK,
        };
        let c = match status {
            s if s == COHORT_STATUS_OK => &self.cohort_ok,
            s if s == COHORT_STATUS_EMPTY => &self.cohort_empty,
            s if s == COHORT_STATUS_EXHAUSTED => &self.cohort_exhausted,
            s if s == COHORT_STATUS_BAD_REQUEST => &self.cohort_bad_request,
            _ => &self.cohort_bad_request,
        };
        c.fetch_add(1, Ordering::Relaxed);
    }
    pub fn refresh_outcome(&self, status: u8) {
        use mirage_discovery::refresh::{
            REFRESH_STATUS_BAD_REQUEST, REFRESH_STATUS_EXHAUSTED, REFRESH_STATUS_INTERNAL,
            REFRESH_STATUS_OK, REFRESH_STATUS_POLICY,
        };
        let c = match status {
            s if s == REFRESH_STATUS_OK => &self.refresh_ok,
            s if s == REFRESH_STATUS_EXHAUSTED => &self.refresh_exhausted,
            s if s == REFRESH_STATUS_POLICY => &self.refresh_policy,
            s if s == REFRESH_STATUS_INTERNAL => &self.refresh_internal,
            s if s == REFRESH_STATUS_BAD_REQUEST => &self.refresh_bad_request,
            _ => &self.refresh_bad_request,
        };
        c.fetch_add(1, Ordering::Relaxed);
    }
    pub fn claim_outcome(&self, status: u8) {
        use mirage_discovery::claim::{
            CLAIM_STATUS_ALREADY_CLAIMED, CLAIM_STATUS_BAD_REQUEST, CLAIM_STATUS_CAPACITY,
            CLAIM_STATUS_OK, CLAIM_STATUS_POLICY,
        };
        let c = match status {
            s if s == CLAIM_STATUS_OK => &self.claim_ok,
            s if s == CLAIM_STATUS_ALREADY_CLAIMED => &self.claim_already,
            s if s == CLAIM_STATUS_CAPACITY => &self.claim_capacity,
            s if s == CLAIM_STATUS_POLICY => &self.claim_policy,
            s if s == CLAIM_STATUS_BAD_REQUEST => &self.claim_bad_request,
            _ => &self.claim_bad_request,
        };
        c.fetch_add(1, Ordering::Relaxed);
    }
    pub fn token_bootstrap(&self) {
        self.tokens_bootstrap.fetch_add(1, Ordering::Relaxed);
    }
    pub fn token_refresh(&self) {
        self.tokens_refresh.fetch_add(1, Ordering::Relaxed);
    }
    pub fn udp_relay_session_opened(&self) {
        self.udp_relay_sessions_opened
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn udp_relay_dgram_relayed(&self) {
        self.udp_relay_dgrams_relayed
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn udp_relay_policy_denial(&self) {
        self.udp_relay_policy_denials
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the per-transport session counter for index `idx`.
    /// Out-of-range indices are silently ignored.
    pub fn session_by_transport(&self, idx: usize) {
        if idx < TRANSPORT_COUNT {
            self.sessions_by_transport[idx].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Increment the gossip event counter for a probe-block (ProbeScanDetected) event.
    pub fn gossip_event_probe_block(&self) {
        self.gossip_events_probe_block
            .fetch_add(1, Ordering::Relaxed);
    }
    /// Increment the gossip event counter for a token-burn (TokenBurned) event.
    pub fn gossip_event_burn(&self) {
        self.gossip_events_burn.fetch_add(1, Ordering::Relaxed);
    }
    /// Increment the gossip event counter for a distress (EntryDistressed) event.
    pub fn gossip_event_distress(&self) {
        self.gossip_events_distress.fetch_add(1, Ordering::Relaxed);
    }
    /// Increment the gossip event counter for a heartbeat (CohortMembership) event.
    pub fn gossip_event_heartbeat(&self) {
        self.gossip_events_heartbeat.fetch_add(1, Ordering::Relaxed);
    }
    /// Increment the gossip event counter for a claim-observation
    /// (ClaimObserved) event - the cross-bridge leak-detector signal.
    pub fn gossip_event_claim_observed(&self) {
        self.gossip_events_claim_observed
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the shadow-forwarded counter (connection forwarded to decoy target).
    pub fn shadow_forwarded(&self) {
        self.shadow_forwarded.fetch_add(1, Ordering::Relaxed);
    }

    // ---- render ----

    /// Render a Prometheus text-exposition snapshot.
    ///
    /// Format reference:
    /// <https://prometheus.io/docs/instrumenting/exposition_formats/#text-based-format>.
    pub fn render_prometheus(&self, replay_set_size: u64) -> String {
        let mut out = String::with_capacity(2048);

        // info
        out.push_str("# HELP mirage_bridge_info Bridge build + deployment metadata.\n");
        out.push_str("# TYPE mirage_bridge_info gauge\n");
        out.push_str(&format!(
            "mirage_bridge_info{{version=\"{}\",transport=\"{}\",tls_mode=\"{}\"}} 1\n",
            escape(&self.version),
            escape(&self.transport),
            escape(&self.tls_mode)
        ));

        // sessions
        out.push_str("# HELP mirage_bridge_sessions_total Cumulative session lifecycle events.\n");
        out.push_str("# TYPE mirage_bridge_sessions_total counter\n");
        let sessions: BTreeMap<&str, &AtomicU64> = [
            ("accepted", &self.sessions_accepted),
            ("closed_ok", &self.sessions_closed_ok),
            ("closed_err", &self.sessions_closed_err),
            ("handshake_failed", &self.sessions_handshake_failed),
            ("handshake_timeout", &self.sessions_handshake_timeout),
            ("socks5_failed", &self.sessions_socks5_failed),
        ]
        .into_iter()
        .collect();
        for (label, counter) in sessions {
            out.push_str(&format!(
                "mirage_bridge_sessions_total{{outcome=\"{}\"}} {}\n",
                label,
                counter.load(Ordering::Relaxed)
            ));
        }
        out.push_str("# HELP mirage_bridge_sessions_active Currently in-flight sessions.\n");
        out.push_str("# TYPE mirage_bridge_sessions_active gauge\n");
        out.push_str(&format!(
            "mirage_bridge_sessions_active {}\n",
            self.sessions_active.load(Ordering::Relaxed)
        ));

        // reality probes
        out.push_str("# HELP mirage_bridge_reality_probes_total Reality auth-probe outcomes.\n");
        out.push_str("# TYPE mirage_bridge_reality_probes_total counter\n");
        out.push_str(&format!(
            "mirage_bridge_reality_probes_total{{outcome=\"authenticated\"}} {}\n",
            self.reality_authenticated.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "mirage_bridge_reality_probes_total{{outcome=\"cover_served\"}} {}\n",
            self.reality_cover_served.load(Ordering::Relaxed)
        ));

        // cover bytes
        out.push_str(
            "# HELP mirage_bridge_cover_bytes_total Bytes shuttled through Reality cover fallback.\n",
        );
        out.push_str("# TYPE mirage_bridge_cover_bytes_total counter\n");
        out.push_str(&format!(
            "mirage_bridge_cover_bytes_total{{direction=\"c2s\"}} {}\n",
            self.cover_bytes_c2s.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "mirage_bridge_cover_bytes_total{{direction=\"s2c\"}} {}\n",
            self.cover_bytes_s2c.load(Ordering::Relaxed)
        ));

        // rate limit
        out.push_str("# HELP mirage_bridge_rate_limit_drops_total Connections rejected at TCP accept by the per-source-IP rate limiter.\n");
        out.push_str("# TYPE mirage_bridge_rate_limit_drops_total counter\n");
        out.push_str(&format!(
            "mirage_bridge_rate_limit_drops_total {}\n",
            self.rate_limit_drops.load(Ordering::Relaxed)
        ));

        // cohort
        out.push_str(
            "# HELP mirage_bridge_cohort_requests_total Cohort-service outcomes by status.\n",
        );
        out.push_str("# TYPE mirage_bridge_cohort_requests_total counter\n");
        for (label, c) in [
            ("ok", &self.cohort_ok),
            ("empty", &self.cohort_empty),
            ("exhausted", &self.cohort_exhausted),
            ("bad_request", &self.cohort_bad_request),
        ] {
            out.push_str(&format!(
                "mirage_bridge_cohort_requests_total{{status=\"{}\"}} {}\n",
                label,
                c.load(Ordering::Relaxed)
            ));
        }

        // refresh
        out.push_str(
            "# HELP mirage_bridge_refresh_requests_total Refresh-token outcomes by status.\n",
        );
        out.push_str("# TYPE mirage_bridge_refresh_requests_total counter\n");
        for (label, c) in [
            ("ok", &self.refresh_ok),
            ("exhausted", &self.refresh_exhausted),
            ("policy", &self.refresh_policy),
            ("internal", &self.refresh_internal),
            ("bad_request", &self.refresh_bad_request),
        ] {
            out.push_str(&format!(
                "mirage_bridge_refresh_requests_total{{status=\"{}\"}} {}\n",
                label,
                c.load(Ordering::Relaxed)
            ));
        }

        // claim
        out.push_str(
            "# HELP mirage_bridge_claim_requests_total Invite-claim outcomes by status.\n",
        );
        out.push_str("# TYPE mirage_bridge_claim_requests_total counter\n");
        for (label, c) in [
            ("ok", &self.claim_ok),
            ("already_claimed", &self.claim_already),
            ("capacity", &self.claim_capacity),
            ("policy", &self.claim_policy),
            ("bad_request", &self.claim_bad_request),
        ] {
            out.push_str(&format!(
                "mirage_bridge_claim_requests_total{{status=\"{}\"}} {}\n",
                label,
                c.load(Ordering::Relaxed)
            ));
        }

        // tokens
        out.push_str(
            "# HELP mirage_bridge_tokens_accepted_total Tokens that passed session-handshake verification.\n",
        );
        out.push_str("# TYPE mirage_bridge_tokens_accepted_total counter\n");
        out.push_str(&format!(
            "mirage_bridge_tokens_accepted_total{{kind=\"bootstrap\"}} {}\n",
            self.tokens_bootstrap.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "mirage_bridge_tokens_accepted_total{{kind=\"refresh\"}} {}\n",
            self.tokens_refresh.load(Ordering::Relaxed)
        ));

        // replay set
        out.push_str(
            "# HELP mirage_bridge_replay_set_size Live entries in the capability-token replay set.\n",
        );
        out.push_str("# TYPE mirage_bridge_replay_set_size gauge\n");
        out.push_str(&format!(
            "mirage_bridge_replay_set_size {replay_set_size}\n"
        ));

        // UDP relay
        out.push_str(
            "# HELP mirage_bridge_udp_relay_sessions_total Cumulative UDP-relay session opens.\n",
        );
        out.push_str("# TYPE mirage_bridge_udp_relay_sessions_total counter\n");
        out.push_str(&format!(
            "mirage_bridge_udp_relay_sessions_total {}\n",
            self.udp_relay_sessions_opened.load(Ordering::Relaxed)
        ));
        out.push_str(
            "# HELP mirage_bridge_udp_relay_datagrams_total Cumulative UDP datagrams relayed (client->upstream).\n",
        );
        out.push_str("# TYPE mirage_bridge_udp_relay_datagrams_total counter\n");
        out.push_str(&format!(
            "mirage_bridge_udp_relay_datagrams_total {}\n",
            self.udp_relay_dgrams_relayed.load(Ordering::Relaxed)
        ));
        out.push_str(
            "# HELP mirage_bridge_udp_relay_policy_denials_total Datagrams refused by AllowlistPolicy.\n",
        );
        out.push_str("# TYPE mirage_bridge_udp_relay_policy_denials_total counter\n");
        out.push_str(&format!(
            "mirage_bridge_udp_relay_policy_denials_total {}\n",
            self.udp_relay_policy_denials.load(Ordering::Relaxed)
        ));

        // per-transport session counters
        out.push_str(
            "# HELP mirage_sessions_by_transport_total Cumulative sessions accepted per transport.\n",
        );
        out.push_str("# TYPE mirage_sessions_by_transport_total counter\n");
        for (idx, label) in TRANSPORT_LABELS.iter().enumerate() {
            out.push_str(&format!(
                "mirage_sessions_by_transport_total{{transport=\"{}\"}} {}\n",
                label,
                self.sessions_by_transport[idx].load(Ordering::Relaxed)
            ));
        }

        // shadow-target cover forwarding
        out.push_str(
            "# HELP mirage_bridge_shadow_forwarded_total Connections forwarded to the shadow/decoy target (active-probe resistance).\n",
        );
        out.push_str("# TYPE mirage_bridge_shadow_forwarded_total counter\n");
        out.push_str(&format!(
            "mirage_bridge_shadow_forwarded_total {}\n",
            self.shadow_forwarded.load(Ordering::Relaxed)
        ));

        // cohort gossip event counters
        out.push_str(
            "# HELP mirage_cohort_events_received_total Gossip events received by kind.\n",
        );
        out.push_str("# TYPE mirage_cohort_events_received_total counter\n");
        for (kind, counter) in [
            ("probe_block", &self.gossip_events_probe_block),
            ("burn", &self.gossip_events_burn),
            ("distress", &self.gossip_events_distress),
            ("heartbeat", &self.gossip_events_heartbeat),
            ("claim_observed", &self.gossip_events_claim_observed),
        ] {
            out.push_str(&format!(
                "mirage_cohort_events_received_total{{kind=\"{}\"}} {}\n",
                kind,
                counter.load(Ordering::Relaxed)
            ));
        }

        out
    }
}

/// Escape a Prometheus label value per the exposition format.
/// Requires escaping `\`, `"`, and newlines.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

/// Hard cap on how long a `/metrics` request may hold a connection
/// open. Long enough for a big render + slow link, short enough to
/// shed a stuck scraper.
const METRICS_REQ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Max bytes read while parsing the request line + headers. A
/// well-behaved Prometheus scraper sends well under 1 KiB.
const METRICS_MAX_REQ_BYTES: usize = 8 * 1024;

/// Run a minimal HTTP/1.1 responder serving `GET /metrics`. Any
/// other request yields `404`. Binds on the provided listener.
///
/// The responder is intentionally tiny - no routing framework, no
/// keep-alive, one request per connection. A Prometheus scraper
/// typically hits the endpoint every 15-60 s, so throughput
/// concerns are nil.
pub async fn serve_metrics(
    listener: TcpListener,
    metrics: Arc<Metrics>,
    replay_size_fn: Arc<dyn Fn() -> u64 + Send + Sync>,
) {
    // Hard cap on concurrent scrape connections. A misconfigured
    // operator who binds metrics to a non-loopback address would
    // otherwise be vulnerable to a flood of half-open scrape
    // connections each spawning a per-task TCP slot. With 32 slots
    // and a 10s per-request timeout, the worst case is 32 stale
    // connections, well within any host's TCP table.
    const METRICS_MAX_CONCURRENT: usize = 32;
    let semaphore = Arc::new(tokio::sync::Semaphore::new(METRICS_MAX_CONCURRENT));
    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "metrics accept failed");
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                continue;
            }
        };
        // Try to acquire a permit; drop the connection fast if at cap.
        // try_acquire avoids holding the accept loop while a flood
        // burns concurrent slots.
        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                debug!(peer = %peer, "metrics scrape rejected: concurrent cap");
                drop(sock);
                continue;
            }
        };
        let m = Arc::clone(&metrics);
        let rs = Arc::clone(&replay_size_fn);
        tokio::spawn(async move {
            let _permit = permit; // released on task drop
            if let Err(e) = tokio::time::timeout(METRICS_REQ_TIMEOUT, handle_one(sock, m, rs)).await
            {
                debug!(peer = %peer, error = %e, "metrics request timed out");
            }
        });
    }
}

async fn handle_one(
    mut sock: TcpStream,
    metrics: Arc<Metrics>,
    replay_size_fn: Arc<dyn Fn() -> u64 + Send + Sync>,
) -> std::io::Result<()> {
    // Read request line + headers until blank line or cap.
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 512];
    loop {
        if buf.len() >= METRICS_MAX_REQ_BYTES {
            return write_response(&mut sock, 413, "Payload Too Large", "").await;
        }
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    // Parse the request line.
    let first = match std::str::from_utf8(&buf) {
        Ok(s) => s.lines().next().unwrap_or(""),
        Err(_) => "",
    };
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    if method != "GET" {
        return write_response(&mut sock, 405, "Method Not Allowed", "method not allowed\n").await;
    }
    // Tolerate query strings on /metrics (some scrapers attach
    // ?collect[]=foo or similar). RT-metrics-1: strict equality
    // would 404 on those. Only the path component of the URI is
    // routed; everything after `?` is ignored.
    let path_only = path.split_once('?').map(|(p, _)| p).unwrap_or(path);
    if path_only != "/metrics" {
        return write_response(&mut sock, 404, "Not Found", "not found\n").await;
    }
    let body = metrics.render_prometheus((replay_size_fn)());
    write_response(&mut sock, 200, "OK", &body).await
}

async fn write_response(
    sock: &mut TcpStream,
    code: u16,
    reason: &str,
    body: &str,
) -> std::io::Result<()> {
    let headers = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n",
        len = body.len(),
    );
    sock.write_all(headers.as_bytes()).await?;
    sock.write_all(body.as_bytes()).await?;
    sock.flush().await?;
    let _ = sock.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_has_all_sections() {
        let m = Metrics::new("0.1.0", "reality-v0.1c", "pinned");
        m.session_accepted();
        m.reality_authenticated();
        m.rate_limit_drop();
        m.token_bootstrap();
        let out = m.render_prometheus(42);
        for needle in [
            "mirage_bridge_info{",
            "mirage_bridge_sessions_total{outcome=\"accepted\"} 1",
            "mirage_bridge_sessions_active 1",
            "mirage_bridge_reality_probes_total{outcome=\"authenticated\"} 1",
            "mirage_bridge_rate_limit_drops_total 1",
            "mirage_bridge_tokens_accepted_total{kind=\"bootstrap\"} 1",
            "mirage_bridge_replay_set_size 42",
        ] {
            assert!(out.contains(needle), "missing {needle:?} in:\n{out}");
        }
    }

    #[test]
    fn sessions_active_follows_open_close() {
        let m = Metrics::new("0.1.0", "raw", "ephemeral");
        m.session_accepted();
        m.session_accepted();
        assert!(m.render_prometheus(0).contains("sessions_active 2"));
        m.session_closed_ok();
        assert!(m.render_prometheus(0).contains("sessions_active 1"));
        m.session_closed_err();
        assert!(m.render_prometheus(0).contains("sessions_active 0"));
    }

    #[test]
    fn unknown_status_buckets_into_bad_request() {
        let m = Metrics::new("0.1.0", "raw", "ephemeral");
        // 0xFF is not a defined cohort / refresh / claim status.
        m.cohort_outcome(0xFF);
        m.refresh_outcome(0xFF);
        m.claim_outcome(0xFF);
        let out = m.render_prometheus(0);
        assert!(out.contains("cohort_requests_total{status=\"bad_request\"} 1"));
        assert!(out.contains("refresh_requests_total{status=\"bad_request\"} 1"));
        assert!(out.contains("claim_requests_total{status=\"bad_request\"} 1"));
    }

    #[test]
    fn escape_handles_prometheus_special_chars() {
        assert_eq!(escape("normal"), "normal");
        assert_eq!(escape("a\"b"), "a\\\"b");
        assert_eq!(escape("a\\b"), "a\\\\b");
        assert_eq!(escape("a\nb"), "a\\nb");
    }

    #[tokio::test]
    async fn http_responder_serves_metrics() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let m = Arc::new(Metrics::new("0.1.0", "raw", "ephemeral"));
        m.session_accepted();
        let rs: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| 7);
        let m2 = Arc::clone(&m);
        tokio::spawn(async move { serve_metrics(listener, m2, rs).await });
        // Simple HTTP/1.1 client: GET /metrics.
        let mut sock = TcpStream::connect(addr).await.unwrap();
        sock.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        let _ = sock.read_to_end(&mut buf).await;
        let s = String::from_utf8_lossy(&buf);
        assert!(s.starts_with("HTTP/1.1 200 OK"));
        assert!(s.contains("mirage_bridge_sessions_active 1"));
        assert!(s.contains("mirage_bridge_replay_set_size 7"));
    }

    #[tokio::test]
    async fn http_responder_404s_unknown_path() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let m = Arc::new(Metrics::new("0.1.0", "raw", "ephemeral"));
        let rs: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| 0);
        tokio::spawn(async move { serve_metrics(listener, m, rs).await });
        let mut sock = TcpStream::connect(addr).await.unwrap();
        sock.write_all(b"GET /other HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        let _ = sock.read_to_end(&mut buf).await;
        let s = String::from_utf8_lossy(&buf);
        assert!(s.starts_with("HTTP/1.1 404 Not Found"));
    }

    #[tokio::test]
    async fn http_responder_tolerates_query_string_on_metrics() {
        // RT-metrics-1: scrapers that send `?collect[]=foo` etc.
        // must not get 404s. Only the path component routes.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let m = Arc::new(Metrics::new("0.1.0", "raw", "ephemeral"));
        let rs: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| 0);
        tokio::spawn(async move { serve_metrics(listener, m, rs).await });
        let mut sock = TcpStream::connect(addr).await.unwrap();
        sock.write_all(b"GET /metrics?collect[]=foo HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        let _ = sock.read_to_end(&mut buf).await;
        let s = String::from_utf8_lossy(&buf);
        assert!(
            s.starts_with("HTTP/1.1 200 OK"),
            "expected 200 with query string, got:\n{s}"
        );
    }

    #[tokio::test]
    async fn http_responder_405s_non_get() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let m = Arc::new(Metrics::new("0.1.0", "raw", "ephemeral"));
        let rs: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| 0);
        tokio::spawn(async move { serve_metrics(listener, m, rs).await });
        let mut sock = TcpStream::connect(addr).await.unwrap();
        sock.write_all(b"POST /metrics HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        let _ = sock.read_to_end(&mut buf).await;
        let s = String::from_utf8_lossy(&buf);
        assert!(s.starts_with("HTTP/1.1 405"));
    }
}
