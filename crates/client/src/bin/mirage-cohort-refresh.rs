//! `mirage-cohort-refresh` - diagnostic: ask a bridge for a cohort update.
//!
//! Usage: `mirage-cohort-refresh <client-config.json> [max_n]`
//!
//! Opens a Mirage session using the same config format as
//! `mirage-client`, sends a cohort LIST request, prints the
//! signature-verified announcements the bridge returns. Useful for
//! operators to confirm the cohort service is healthy and for
//! researchers to enumerate what a single invite can reach.
//!
//! Exits non-zero on any error. The returned announcements are
//! verified against the invite's operator pubkey before printing -
//! a hostile bridge that returns forged announcements produces a
//! BadSignature error rather than silent acceptance.
//!
//! All transport modes supported by `mirage-client` are supported here:
//! Raw, Reality, SS-2022, WebSocket, Meek, and DoH.

use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use mirage_common::process_hardening::harden_process;
use mirage_crypto::x25519_dalek::{PublicKey, StaticSecret};
use mirage_discovery::cohort::COHORT_MAX_N_PER_REQUEST;
use mirage_discovery::cohort_client::refresh_cohort;
use mirage_discovery::invite::MasterInvite;
use mirage_discovery::wire::Endpoint;
use mirage_session::connect;
use mirage_transport::AsyncReadWrite;
use mirage_transport_hysteria2::{hysteria2_client_connect, Hysteria2ClientConfig};
use mirage_transport_reality::{reality_connect, ClientCarrierInputs};
use serde::Deserialize;
use tokio::net::TcpStream;

type DuplexStream = std::pin::Pin<Box<dyn AsyncReadWrite + Send>>;

// No `Debug`: holds the client secret key, PSK, and token - omitting Debug
// prevents an accidental secret leak into logs.
#[derive(Deserialize)]
struct ClientConfig {
    #[serde(default)]
    invite: Option<String>,
    // Explicit-hex fields: parsed to accept the same config JSON as mirage-client,
    // but cohort-refresh requires invite mode for the trust anchor.
    #[allow(dead_code)]
    #[serde(default)]
    bridge_addr: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    bridge_x25519_pk_hex: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    client_x25519_sk_hex: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    token_hex: Option<String>,
    #[serde(default = "default_handshake_timeout_secs")]
    handshake_timeout_secs: u64,
    // ---- Reality ----
    #[serde(default)]
    reality_enabled: bool,
    #[serde(default)]
    reality_sni: Option<String>,
    #[serde(default)]
    reality_tls_fingerprint: Option<String>,
    // ---- SS-2022 ----
    #[serde(default)]
    ss2022_psk_hex: Option<String>,
    // ---- WebSocket ----
    #[serde(default)]
    ws_enabled: Option<bool>,
    #[serde(default)]
    ws_path: Option<String>,
    // ---- Hysteria2 ----
    #[serde(default)]
    hysteria2_enabled: Option<bool>,
    #[serde(default)]
    hysteria2_send_rate_mbps: Option<u64>,
    // ---- Meek ----
    #[serde(default)]
    meek_front_domain: Option<String>,
    #[serde(default)]
    meek_path: Option<String>,
    // ---- DoH ----
    #[serde(default)]
    doh_front_domain: Option<String>,
    // ---- VLESS ----
    #[serde(default)]
    vless_uuid_hex: Option<String>,
}

fn default_handshake_timeout_secs() -> u64 {
    10
}

fn fatal<S: AsRef<str>>(msg: S) -> ! {
    eprintln!("fatal: {}", msg.as_ref());
    std::process::exit(2);
}

#[tokio::main]
async fn main() {
    if let Err(e) = harden_process() {
        fatal(format!("harden_process: {e}"));
    }

    let mut args = std::env::args().skip(1);
    let cfg_path = match args.next() {
        Some(p) => p,
        None => {
            eprintln!("usage: mirage-cohort-refresh <config.json> [max_n]");
            std::process::exit(2);
        }
    };
    let max_n: u8 = args
        .next()
        .as_deref()
        .map(|s| s.parse().unwrap_or(COHORT_MAX_N_PER_REQUEST))
        .unwrap_or(COHORT_MAX_N_PER_REQUEST);

    let cfg: ClientConfig = std::fs::read_to_string(&cfg_path)
        .map_err(|e| format!("read: {e}"))
        .and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
        .unwrap_or_else(|e| fatal(format!("config: {e}")));

    // Derive dialing parameters from the first invite (same logic as mirage-client).
    let (bridge_addr, bridge_x25519_pk, client_sk, token, operator_pk, tls_override_pk, probe_root) =
        if let Some(invite_text) = cfg.invite.as_deref() {
            let text = invite_text
                .trim()
                .strip_prefix("mirage://")
                .unwrap_or(invite_text.trim());
            let invite = MasterInvite::decode_text(text)
                .unwrap_or_else(|e| fatal(format!("invite decode: {e}")));
            let ann = invite
                .bootstrap_announcement
                .clone()
                .unwrap_or_else(|| fatal("invite has no bootstrap_announcement"));
            ann.verify(&invite.operator_ed25519_pk)
                .unwrap_or_else(|e| fatal(format!("invite ann verify: {e}")));
            let addr = endpoint_to_dial(&ann.endpoint)
                .unwrap_or_else(|e| fatal(format!("invite endpoint: {e}")));
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).expect("csprng");
            let csk = StaticSecret::from(seed).to_bytes();
            let _pk = PublicKey::from(&StaticSecret::from(csk)); // sanity
            if invite.bootstrap_tokens.is_empty() {
                fatal("invite has no bootstrap tokens");
            }
            let mut idx_bytes = [0u8; 8];
            getrandom::fill(&mut idx_bytes).expect("csprng");
            let idx = (u64::from_be_bytes(idx_bytes) as usize) % invite.bootstrap_tokens.len();
            let tok = invite.bootstrap_tokens[idx].clone();
            (
                addr,
                ann.bridge_x25519_pk,
                csk,
                tok,
                invite.operator_ed25519_pk,
                invite.tls_cert_verify_pk,
                invite.probe_root,
            )
        } else {
            // Explicit-hex mode has no trust anchor for announcement verification.
            fatal(
                "cohort-refresh requires invite mode; the bridge must be reached via an invite \
                 so we know which operator to verify returned announcements against",
            )
        };

    let timeout = Duration::from_secs(cfg.handshake_timeout_secs);

    // Parse optional VLESS UUID.
    let vless_uuid: Option<[u8; 16]> = if let Some(ref hex_str) = cfg.vless_uuid_hex {
        let cleaned = hex_str.replace('-', "");
        let raw = hex::decode(&cleaned).unwrap_or_else(|e| fatal(format!("vless_uuid_hex: {e}")));
        if raw.len() != 16 {
            fatal(format!(
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

    let anns = if cfg.hysteria2_enabled == Some(true) {
        // Hysteria2: QUIC dial, no TCP socket needed.
        let send_rate_bps = cfg.hysteria2_send_rate_mbps.unwrap_or(100) * 1_000_000;
        let bridge_sa: std::net::SocketAddr = bridge_addr.parse().unwrap_or_else(|_| {
            tokio::runtime::Handle::current().block_on(async {
                tokio::net::lookup_host(&bridge_addr)
                    .await
                    .unwrap_or_else(|e| fatal(format!("hy2 resolve {bridge_addr}: {e}")))
                    .next()
                    .unwrap_or_else(|| fatal(format!("hy2: no addresses for {bridge_addr}")))
            })
        });
        let hy2_cfg = Hysteria2ClientConfig {
            bridge_static_pk: bridge_x25519_pk,
            send_rate_bps,
            // Cohort-refresh is an operator tool; the self-signed cert is not
            // verified (SkipCertVerifier). Empty hostname -> the transport derives
            // the same per-bridge cover SNI the bridge uses for its SAN (F9-L),
            // so even this maintenance path presents a matching, non-reserved SNI.
            hostname: String::new(),
            // Maintenance tool: plain QUIC (no obfs) - operators run it from a
            // trusted network. Add obfs_key here to exercise obfuscated refresh.
            obfs_key: None,
        };
        let hy2_stream = tokio::time::timeout(
            timeout,
            hysteria2_client_connect(&hy2_cfg, bridge_sa, timeout),
        )
        .await
        .unwrap_or_else(|_| fatal("hysteria2 timeout"))
        .unwrap_or_else(|e| fatal(format!("hysteria2: {e}")));
        let session = tokio::time::timeout(
            timeout,
            connect(hy2_stream, &client_sk, &bridge_x25519_pk, &token),
        )
        .await
        .unwrap_or_else(|_| fatal("session handshake timeout"))
        .unwrap_or_else(|e| fatal(format!("session: {e}")));
        // RT #26: bound the WHOLE cohort exchange so a hostile bridge that
        // dribbles bytes (slow-loris) cannot hang the tool indefinitely.
        tokio::time::timeout(timeout, refresh_cohort(session, &operator_pk, max_n))
            .await
            .unwrap_or_else(|_| fatal("cohort exchange timeout"))
            .unwrap_or_else(|e| fatal(format!("cohort: {e}")))
    } else {
        // All TCP-based transports: connect, wrap carrier, optional VLESS, Noise session.
        let sock = TcpStream::connect(&bridge_addr)
            .await
            .unwrap_or_else(|e| fatal(format!("connect {bridge_addr}: {e}")));
        sock.set_nodelay(true).ok();

        let carrier: DuplexStream = wrap_carrier(
            sock,
            &cfg,
            &bridge_x25519_pk,
            tls_override_pk,
            probe_root,
            timeout,
        )
        .await;

        // Apply VLESS framing if configured.
        let mut carrier = carrier;
        if let Some(uuid) = vless_uuid {
            mirage_transport_vless::vless_client_send_header(&mut carrier, &uuid)
                .await
                .unwrap_or_else(|e| fatal(format!("vless header: {e}")));
            mirage_transport_vless::vless_client_read_response(&mut carrier, timeout)
                .await
                .unwrap_or_else(|e| fatal(format!("vless response: {e}")));
        }

        let session = tokio::time::timeout(
            timeout,
            connect(carrier, &client_sk, &bridge_x25519_pk, &token),
        )
        .await
        .unwrap_or_else(|_| fatal("session handshake timeout"))
        .unwrap_or_else(|e| fatal(format!("session: {e}")));
        // RT #26: bound the WHOLE cohort exchange so a hostile bridge that
        // dribbles bytes (slow-loris) cannot hang the tool indefinitely.
        tokio::time::timeout(timeout, refresh_cohort(session, &operator_pk, max_n))
            .await
            .unwrap_or_else(|_| fatal("cohort exchange timeout"))
            .unwrap_or_else(|e| fatal(format!("cohort: {e}")))
    };

    // Print results as JSON on stdout.
    let json = serde_json::json!({
        "status": anns.status,
        "count": anns.announcements.len(),
        "announcements": anns.announcements.iter().enumerate().map(|(i, a)| {
            serde_json::json!({
                "index": i,
                "bridge_ed25519_pk_hex": hex::encode(a.bridge_ed25519_pk),
                "bridge_x25519_pk_hex": hex::encode(a.bridge_x25519_pk),
                "endpoint": endpoint_to_string(&a.endpoint),
                "expires_at": a.expires_at,
            })
        }).collect::<Vec<_>>(),
    });
    println!("{}", serde_json::to_string_pretty(&json).unwrap());
}

/// Wrap `sock` in the appropriate carrier transport, returning a boxed
/// `AsyncRead + AsyncWrite + Unpin + Send` stream.
async fn wrap_carrier(
    sock: TcpStream,
    cfg: &ClientConfig,
    bridge_x25519_pk: &[u8; 32],
    // Compressed SEC1 P-256 CertVerify pubkey (from the invite).
    tls_override_pk: Option<[u8; 33]>,
    // Reality anti-probe root (from the invite); `None` -> legacy probe.
    probe_root: Option<[u8; 32]>,
    timeout: Duration,
) -> DuplexStream {
    if let Some(ref psk_hex) = cfg.ss2022_psk_hex {
        let raw =
            hex::decode(psk_hex.trim()).unwrap_or_else(|e| fatal(format!("ss2022_psk_hex: {e}")));
        let psk: [u8; 32] = raw
            .try_into()
            .unwrap_or_else(|_| fatal("ss2022_psk_hex: expected 32 bytes"));
        let c = mirage_transport_shadowsocks::ss2022_client_dial(sock, &psk, timeout)
            .await
            .unwrap_or_else(|e| fatal(format!("ss2022: {e}")));
        return Box::pin(c);
    }

    if let Some(ref front_domain) = cfg.meek_front_domain {
        let path = cfg
            .meek_path
            .clone()
            .unwrap_or_else(|| "/mirage".to_owned());
        let auth_frame = mirage_transport_meek::build_auth_frame(bridge_x25519_pk)
            .unwrap_or_else(|e| fatal(format!("meek auth frame: {e}")));
        let mut session_id = [0u8; 32];
        getrandom::fill(&mut session_id).expect("csprng");
        let session_b64 = B64.encode(session_id);
        let c = mirage_transport_meek::MeekClientStream::new_with_content_type(
            sock,
            front_domain.clone(),
            path,
            session_id,
            Some(auth_frame.to_vec()),
            session_b64,
            "application/octet-stream".into(),
        )
        .await;
        return Box::pin(c);
    }

    if let Some(ref front_domain) = cfg.doh_front_domain {
        let c = mirage_transport_doh::doh_client_connect(
            sock,
            bridge_x25519_pk,
            front_domain.clone(),
            timeout,
        )
        .await
        .unwrap_or_else(|e| fatal(format!("doh: {e}")));
        return Box::pin(c);
    }

    if cfg.ws_enabled == Some(true) {
        let path = cfg.ws_path.clone().unwrap_or_else(|| "/".to_owned());
        // Maintenance tool: a neutral cover Host (never "localhost").
        let c = mirage_transport_ws::ws_client_connect(
            sock,
            bridge_x25519_pk,
            // Maintenance tool: no invite obfs secret in scope, so the knock is
            // pubkey-keyed (audit #9 fallback). Bridges that require a secret-keyed
            // WS knock should refresh cohorts via a secret-carrying client config.
            None,
            &path,
            "cdn.example.com",
            timeout,
        )
        .await
        .unwrap_or_else(|e| fatal(format!("websocket: {e}")));
        return Box::pin(c);
    }

    if cfg.reality_enabled {
        let sni = cfg
            .reality_sni
            .as_deref()
            .unwrap_or_else(|| fatal("reality_enabled=true requires reality_sni"));
        let tls_fingerprint = if let Some(ref name) = cfg.reality_tls_fingerprint {
            mirage_transport_reality::tls_fingerprint::lookup(name)
                .unwrap_or_else(|| fatal(format!("unknown reality_tls_fingerprint: {name}")))
        } else {
            mirage_transport_reality::tls_fingerprint::lookup("chrome-desktop")
                .expect("chrome-desktop fingerprint always present")
        };
        let now_unix: u32 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        let c = tokio::time::timeout(
            timeout,
            reality_connect(
                sock,
                &ClientCarrierInputs {
                    bridge_static_pk: bridge_x25519_pk,
                    probe_root: probe_root
                        .as_ref()
                        .unwrap_or(&mirage_transport_reality::PROBE_ROOT_DISABLED),
                    server_name: sni,
                    now_unix,
                    cert_verify_override_pk: tls_override_pk.as_ref(),
                    tls_fingerprint: Some(tls_fingerprint),
                },
            ),
        )
        .await
        .unwrap_or_else(|_| fatal("reality timeout"))
        .unwrap_or_else(|e| fatal(format!("reality: {e}")));
        // Shaper-v2: opt-in envelope pacing, matched to the bridge (which paces
        // every authenticated session). Off by default. Client writes upstream.
        let c = mirage_transport_reality::maybe_pace(c, mirage_transport_reality::pacer::Dir::Up);
        return Box::pin(c);
    }

    // Raw: no carrier wrapping.
    Box::pin(sock)
}

fn endpoint_to_string(e: &Endpoint) -> String {
    match e {
        Endpoint::Ipv4 { addr, port } => {
            format!("{}.{}.{}.{}:{port}", addr[0], addr[1], addr[2], addr[3])
        }
        Endpoint::Ipv6 { addr, port } => {
            let ip = std::net::Ipv6Addr::from(*addr);
            format!("[{ip}]:{port}")
        }
        Endpoint::Domain { domain, port } => format!("{domain}:{port}"),
        Endpoint::OnionV3 { .. } => "onion-v3".to_string(),
    }
}

fn endpoint_to_dial(e: &Endpoint) -> Result<String, String> {
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
        Endpoint::OnionV3 { .. } => Err("onion addresses require Tor routing".into()),
    }
}
