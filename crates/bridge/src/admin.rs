//! In-process operator admin UI, opt-in via `--admin-ui` (defaults to
//! `127.0.0.1:3825`; pass `--admin-ui <host:port>` to override).
//!
//! A small HTTP/1.1 server for metrics, config editing, and service restart.
//!
//! # Security posture (this is a privileged, config-writing surface)
//!
//! - The listener defaults to loopback. An explicit public bind is allowed with
//!   a warning; requests still require a loopback `Host` header.
//! - **Bearer token.** Every `/api/*` call requires `Authorization: Bearer
//!   <token>`, compared in constant time. The token is random per start and
//!   written to a secret access-URL file in `STATE_DIRECTORY` when systemd
//!   provides one, or beside the bridge config otherwise. On Unix it has mode
//!   `0600`; on Windows it inherits the directory ACL. The operator opens that
//!   URL; its fragment passes the token to the browser.
//! - **No CORS, strict CSP, no framing.** The page is self-hosted; responses set a
//!   strict `Content-Security-Policy` (incl. `frame-ancestors 'none'`), `X-Frame-Options:
//!   DENY` (anti-clickjacking), and `nosniff`, and never emit `Access-Control-Allow-Origin`.
//! - The access token is omitted from structured tracing logs.
//! - Known secret config fields are masked before sending the config to the
//!   browser and restored from disk when an unchanged value is saved.
//! - **Atomic 0600 writes.** Config is written via the same secure-file path the
//!   provisioning tools use.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

use crate::metrics::Metrics;

/// The embedded single-page admin app (HTML + inlined CSS/JS, no external refs).
const ADMIN_HTML: &str = include_str!("admin_ui/index.html");

/// Config keys holding long-term secret material. Masked outbound, restored from
/// disk on write. `operator_ed25519_pk_hex` is a PUBLIC key and is NOT here.
const SECRET_KEYS: &[&str] = &[
    "bridge_x25519_sk_hex",
    "bridge_ed25519_sk_hex",
    "ss2022_psk_hex",
    "reality_tls_signing_sk_hex",
    "derived_port_shared_salt_hex",
    "cohort_claim_tag_key_hex",
    "quic_obfs_secret_hex",
    "quic_obfs_password",
    "relay_token",
];
/// Sentinel the UI echoes back for an unchanged secret field.
const SECRET_MASK: &str = "__MIRAGE_SECRET_UNCHANGED__";

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 512 * 1024;
const REQ_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_CONCURRENT: usize = 16;

/// Everything the admin handlers need. Cloned as an `Arc` per connection.
pub struct AdminState {
    pub config_path: String,
    pub metrics: Arc<Metrics>,
    pub replay_size_fn: Arc<dyn Fn() -> u64 + Send + Sync>,
    pub start_time: Instant,
    pub token: String,
    /// systemd unit name used for the "Restart" action.
    pub service_name: String,
}

/// Generate a fresh 128-bit hex token for this run. Never enable the admin API
/// with a predictable credential if the operating system RNG fails.
pub fn gen_token() -> Result<String, getrandom::Error> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b)?;
    Ok(hex::encode(b))
}

/// Serve the admin UI until the listener errors fatally. Mirrors
/// [`crate::metrics::serve_metrics`]'s accept-loop shape.
pub async fn serve_admin(listener: TcpListener, state: Arc<AdminState>) {
    let sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT));
    loop {
        let (sock, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "admin: accept failed");
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let permit = match sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                drop(sock);
                continue;
            }
        };
        let st = Arc::clone(&state);
        tokio::spawn(async move {
            let _permit = permit;
            let _ = tokio::time::timeout(REQ_TIMEOUT, handle_conn(sock, st)).await;
        });
    }
}

struct Request {
    method: String,
    path: String,
    host_ok: bool,
    bearer: Option<String>,
    body: Vec<u8>,
}

async fn read_request(sock: &mut TcpStream) -> Option<Request> {
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 4096];
    // Read until we have the full header block.
    let hdr_end = loop {
        if let Some(pos) = find_sub(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return None;
        }
        let n = sock.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    };

    let head = String::from_utf8_lossy(&buf[..hdr_end]).to_string();
    let mut lines = head.lines();
    let first = lines.next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let raw_path = parts.next().unwrap_or("/");
    let path = raw_path.split('?').next().unwrap_or(raw_path).to_string();

    let mut host_ok = false;
    let mut host_count = 0usize;
    let mut bearer = None;
    let mut content_len = 0usize;
    for line in lines {
        if let Some((name, val)) = line.split_once(':') {
            let val = val.trim();
            match name.trim().to_ascii_lowercase().as_str() {
                "host" => {
                    host_ok = host_count == 0 && host_is_loopback(val);
                    host_count += 1;
                }
                "authorization" => {
                    bearer = val.strip_prefix("Bearer ").map(|s| s.trim().to_string())
                }
                "content-length" => content_len = val.parse().unwrap_or(0),
                _ => {}
            }
        }
    }
    if content_len > MAX_BODY_BYTES {
        return None;
    }

    // Body = whatever came after the header block, plus the rest up to content_len.
    let mut body: Vec<u8> = buf[hdr_end..].to_vec();
    while body.len() < content_len {
        let n = sock.read(&mut tmp).await.ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_len);

    Some(Request {
        method,
        path,
        host_ok,
        bearer,
        body,
    })
}

async fn handle_conn(mut sock: TcpStream, state: Arc<AdminState>) {
    let req = match read_request(&mut sock).await {
        Some(r) => r,
        None => return,
    };

    // DNS-rebinding defense: reject any request whose Host is not loopback.
    if !req.host_ok {
        let _ = write_resp(
            &mut sock,
            403,
            "Forbidden",
            "text/plain",
            b"loopback host required\n",
        )
        .await;
        return;
    }

    // The page itself loads without a token (the browser must fetch it to read
    // the token from the URL fragment); everything else requires the Bearer.
    if req.path == "/" || req.path == "/index.html" {
        let _ = write_html(&mut sock, ADMIN_HTML.as_bytes()).await;
        return;
    }

    if !authorized(&req, &state.token) {
        let _ = write_resp(
            &mut sock,
            401,
            "Unauthorized",
            "application/json",
            b"{\"error\":\"bad or missing token\"}",
        )
        .await;
        return;
    }

    let (code, reason, body) = route_api(&req, &state).await;
    let _ = write_resp(&mut sock, code, reason, "application/json", body.as_bytes()).await;
}

fn authorized(req: &Request, token: &str) -> bool {
    match &req.bearer {
        Some(t) => ct_eq(t.as_bytes(), token.as_bytes()),
        None => false,
    }
}

async fn route_api(req: &Request, state: &Arc<AdminState>) -> (u16, &'static str, String) {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/api/status") => {
            let uptime = state.start_time.elapsed().as_secs();
            let replay = (state.replay_size_fn)();
            (
                200,
                "OK",
                state.metrics.snapshot_json(replay, uptime).to_string(),
            )
        }
        ("GET", "/api/config") => match read_masked_config(&state.config_path) {
            Ok(v) => (200, "OK", v.to_string()),
            Err(e) => (500, "Internal Server Error", err_json(&e)),
        },
        ("POST", "/api/config") => match write_config(&state.config_path, &req.body) {
            Ok(()) => (200, "OK", "{\"ok\":true}".to_string()),
            Err(e) => (400, "Bad Request", err_json(&e)),
        },
        ("POST", "/api/restart") => {
            let (ok, msg) = restart_service(&state.service_name);
            (
                200,
                "OK",
                serde_json::json!({ "ok": ok, "message": msg }).to_string(),
            )
        }
        ("GET", "/api/meta") => (
            200,
            "OK",
            serde_json::json!({
                "service": state.service_name,
                "config_path": state.config_path,
                "version": env!("CARGO_PKG_VERSION"),
            })
            .to_string(),
        ),
        _ => (404, "Not Found", "{\"error\":\"not found\"}".to_string()),
    }
}

// Config read (masked) / write (secret-preserving + validated)

fn read_masked_config(path: &str) -> Result<serde_json::Value, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let mut cfg: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("parse {path}: {e}"))?;
    let mut secrets = serde_json::Map::new();
    if let Some(obj) = cfg.as_object_mut() {
        for k in SECRET_KEYS {
            if let Some(v) = obj.get(*k) {
                let present = !v.is_null() && v.as_str().map(|s| !s.is_empty()).unwrap_or(true);
                secrets.insert((*k).to_string(), present.into());
                if present {
                    obj.insert(
                        (*k).to_string(),
                        serde_json::Value::String(SECRET_MASK.into()),
                    );
                }
            }
        }
    }
    // Relay credentials live inside an array, unlike the top-level secrets.
    // The raw JSON editor sends this array back, so it must never receive the
    // outbound capability tokens in cleartext.
    if let Some(peers) = cfg
        .get_mut("relay_peers")
        .and_then(serde_json::Value::as_array_mut)
    {
        for peer in peers {
            if let Some(token) = peer.get_mut("relay_token") {
                if token.as_str().is_some_and(|s| !s.is_empty()) {
                    *token = serde_json::Value::String(SECRET_MASK.into());
                }
            }
        }
    }
    Ok(serde_json::json!({ "config": cfg, "secrets": secrets, "path": path }))
}

fn write_config(path: &str, body: &[u8]) -> Result<(), String> {
    let mut edited: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("request body is not JSON: {e}"))?;
    if !edited.is_object() {
        return Err("config must be a JSON object".into());
    }

    // Restore any masked/omitted secret from the CURRENT on-disk config so the UI
    // can neither read nor accidentally erase key material.
    let original_text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read current config for secret restoration: {e}"))?;
    let original: serde_json::Value = serde_json::from_str(&original_text)
        .map_err(|e| format!("cannot parse current config for secret restoration: {e}"))?;
    if let (Some(e), Some(o)) = (edited.as_object_mut(), original.as_object()) {
        for k in SECRET_KEYS {
            let is_mask = e.get(*k).and_then(|v| v.as_str()) == Some(SECRET_MASK);
            let missing = !e.contains_key(*k);
            if is_mask || missing {
                match o.get(*k) {
                    Some(ov) => {
                        e.insert((*k).to_string(), ov.clone());
                    }
                    None => {
                        e.remove(*k);
                    }
                }
            }
        }
    }

    // Match relay peers by public key, not array position: the operator may
    // reorder peers in the JSON editor. A mask on an unknown peer is invalid;
    // accepting it would persist the sentinel as a purported token.
    if let Some(edited_peers) = edited
        .get_mut("relay_peers")
        .and_then(serde_json::Value::as_array_mut)
    {
        let original_peers = original
            .get("relay_peers")
            .and_then(serde_json::Value::as_array);
        for peer in edited_peers {
            let Some(peer_obj) = peer.as_object_mut() else {
                continue; // Real config validation below reports the malformed peer.
            };
            let Some(pk) = peer_obj
                .get("bridge_x25519_pk")
                .and_then(serde_json::Value::as_str)
            else {
                continue;
            };
            let masked = peer_obj
                .get("relay_token")
                .and_then(serde_json::Value::as_str)
                == Some(SECRET_MASK);
            if !masked && peer_obj.contains_key("relay_token") {
                continue;
            }
            let prior = original_peers.and_then(|peers| {
                peers.iter().find(|old| {
                    old.get("bridge_x25519_pk")
                        .and_then(serde_json::Value::as_str)
                        == Some(pk)
                })
            });
            match prior.and_then(|p| p.get("relay_token")) {
                Some(token) => {
                    peer_obj.insert("relay_token".into(), token.clone());
                }
                None if masked => {
                    return Err("masked relay token has no matching on-disk peer".into());
                }
                None => {} // New inbound-only peer; serde supplies an empty token.
            }
        }
    }

    // Validate by deserializing into the real config type BEFORE persisting; a
    // malformed edit is rejected here instead of fataling the daemon on restart.
    crate::BridgeConfig::validate_value(&edited).map_err(|e| format!("invalid config: {e}"))?;

    mirage_common::secure_file::write_secret_json(path, &edited)
        .map_err(|e| format!("write {path}: {e}"))
}

// Restart (deferred so the HTTP response flushes before the process dies)

fn restart_service(service: &str) -> (bool, String) {
    // Only offer to restart when this really is a running systemd unit; otherwise
    // hand the operator the command to run themselves.
    let active = std::process::Command::new("systemctl")
        .arg("is-active")
        .arg(service)
        .output();
    let is_active = matches!(active, Ok(ref o) if o.status.success()
        && String::from_utf8_lossy(&o.stdout).trim() == "active");
    if !is_active {
        return (
            false,
            format!("not a running systemd unit - restart manually: systemctl restart {service}"),
        );
    }
    // Defer: this process IS the service, so the restart will kill us. Sleep long
    // enough for the HTTP response to flush, then hand off to systemd.
    let svc = service.to_string();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(700));
        let _ = std::process::Command::new("systemctl")
            .arg("restart")
            .arg(&svc)
            .status();
    });
    (
        true,
        format!("restarting {service} via systemd - reconnecting..."),
    )
}

// HTTP + small helpers

async fn write_html(sock: &mut TcpStream, body: &[u8]) -> std::io::Result<()> {
    // Strict CSP: everything is inlined and self-hosted, so no external origins.
    let headers = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {len}\r\n\
         Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; \
script-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; \
form-action 'none'; frame-ancestors 'none'\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\
         Referrer-Policy: no-referrer\r\n\
         Connection: close\r\n\r\n",
        len = body.len()
    );
    sock.write_all(headers.as_bytes()).await?;
    sock.write_all(body).await?;
    sock.flush().await?;
    let _ = sock.shutdown().await;
    Ok(())
}

async fn write_resp(
    sock: &mut TcpStream,
    code: u16,
    reason: &str,
    ctype: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let headers = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: {ctype}\r\n\
         Content-Length: {len}\r\n\
         Cache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Content-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\n\
         Connection: close\r\n\r\n",
        len = body.len()
    );
    sock.write_all(headers.as_bytes()).await?;
    sock.write_all(body).await?;
    sock.flush().await?;
    let _ = sock.shutdown().await;
    Ok(())
}

fn err_json(msg: &str) -> String {
    serde_json::json!({ "error": msg }).to_string()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    d == 0
}

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// True if a `Host:` value is a loopback name or address with an optional port.
fn host_is_loopback(host: &str) -> bool {
    let h = host.trim();
    let bare = if let Some(rest) = h.strip_prefix('[') {
        let Some((addr, suffix)) = rest.split_once(']') else {
            return false;
        };
        if !suffix.is_empty() {
            let Some(port) = suffix.strip_prefix(':') else {
                return false;
            };
            if port.parse::<u16>().is_err() {
                return false;
            }
        }
        addr
    } else if h.parse::<std::net::IpAddr>().is_ok() {
        h
    } else if let Some((addr, port)) = h.rsplit_once(':') {
        if addr.contains(':') || port.parse::<u16>().is_err() {
            return false;
        }
        addr
    } else {
        h
    };
    if bare.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match bare.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => v4.is_loopback(),
        Ok(std::net::IpAddr::V6(v6)) => v6.is_loopback(),
        Err(_) => false,
    }
}

/// Warn (as [`crate::metrics`] does) if the admin bind is not loopback.
pub fn warn_if_public(bind: &str) {
    let host = bind.rsplit_once(':').map(|(a, _)| a).unwrap_or(bind);
    if !host_is_loopback(host) {
        warn!(
            addr = %bind,
            "admin UI bound to a NON-loopback address - it can READ AND WRITE the \
             bridge config (incl. restart). Bind to 127.0.0.1 and firewall the port."
        );
    }
}

/// Save the access URL without putting its bearer token in service logs.
/// systemd's `STATE_DIRECTORY` is writable even with `ProtectSystem=strict`.
pub fn write_access_url(config_path: &str, bind: &str, token: &str) -> std::io::Result<PathBuf> {
    let state_dir = std::env::var_os("STATE_DIRECTORY").filter(|p| !p.is_empty());
    write_access_url_in(
        config_path,
        bind,
        token,
        state_dir.as_deref().map(Path::new),
    )
}

fn write_access_url_in(
    config_path: &str,
    bind: &str,
    token: &str,
    state_dir: Option<&Path>,
) -> std::io::Result<PathBuf> {
    let config_path = std::fs::canonicalize(config_path)?;
    let path = if let Some(state_dir) = state_dir {
        if !state_dir.is_absolute() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "STATE_DIRECTORY must be absolute",
            ));
        }
        let file_name = config_path.file_name().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "config has no file name")
        })?;
        let mut name = file_name.to_os_string();
        name.push(".admin-url");
        state_dir.join(name)
    } else {
        let mut name = config_path.as_os_str().to_os_string();
        name.push(".admin-url");
        PathBuf::from(name)
    };
    mirage_common::secure_file::write_secret(&path, format!("http://{bind}/#t={token}\n"))?;
    Ok(path)
}

/// Log only the location of the access file, never its contents.
pub fn log_access_file(bind: &str, path: &Path) {
    info!(bind = %bind, access_file = %path.display(), "admin UI listening; read access URL from file");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_cfg(body: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let mut b = [0u8; 8];
        let _ = getrandom::fill(&mut b);
        p.push(format!("mirage-admin-test-{}.json", hex::encode(b)));
        std::fs::write(&p, body).unwrap();
        p
    }

    // A minimal config that deserializes as a valid BridgeConfig, carrying one
    // secret (reality_tls_signing_sk_hex) and one editable non-secret.
    fn valid_config(rate: u64, secret: &str) -> String {
        format!(
            r#"{{
              "bind": "127.0.0.1:9000",
              "bridge_x25519_sk_hex": "{k}",
              "bridge_ed25519_pk_hex": "{k}",
              "operator_ed25519_pk_hex": "{k}",
              "reality_tls_signing_sk_hex": "{secret}",
              "hysteria2_send_rate_mbps": {rate}
            }}"#,
            k = "11".repeat(32),
        )
    }

    #[test]
    fn host_loopback_accepts_local_rejects_remote() {
        assert!(host_is_loopback("127.0.0.1"));
        assert!(host_is_loopback("127.0.0.1:3825"));
        assert!(host_is_loopback("localhost:3825"));
        assert!(host_is_loopback("[::1]:3825"));
        assert!(host_is_loopback("::1"));
        assert!(!host_is_loopback("[::1]evil.example"));
        assert!(!host_is_loopback("[::1]:invalid"));
        assert!(!host_is_loopback("127.0.0.1:invalid"));
        assert!(!host_is_loopback("evil.example.com"));
        assert!(!host_is_loopback("10.0.0.5:3825"));
        assert!(!host_is_loopback("0.0.0.0"));
    }

    #[test]
    fn ct_eq_matches_only_identical() {
        assert!(ct_eq(b"abc123", b"abc123"));
        assert!(!ct_eq(b"abc123", b"abc124"));
        assert!(!ct_eq(b"abc", b"abcd"));
    }

    #[test]
    fn access_url_is_saved_beside_config() {
        let config = tmp_cfg("{}");
        let config_path = config.to_str().unwrap();
        let access =
            write_access_url_in(config_path, "127.0.0.1:3825", "first-token", None).unwrap();
        assert!(access.is_absolute());
        assert_eq!(
            std::fs::read_to_string(&access).unwrap(),
            "http://127.0.0.1:3825/#t=first-token\n"
        );

        write_access_url_in(config_path, "127.0.0.1:3825", "next-token", None).unwrap();
        assert_eq!(
            std::fs::read_to_string(&access).unwrap(),
            "http://127.0.0.1:3825/#t=next-token\n"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&access).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        std::fs::remove_file(access).unwrap();
        std::fs::remove_file(config).unwrap();
    }

    #[test]
    fn access_url_requires_existing_config() {
        let config = tmp_cfg("{}");
        std::fs::remove_file(&config).unwrap();
        assert!(
            write_access_url_in(config.to_str().unwrap(), "127.0.0.1:3825", "token", None).is_err()
        );
    }

    #[test]
    fn access_url_uses_state_directory_when_provided() {
        let config = tmp_cfg("{}");
        let state_dir = config.with_extension("state");
        std::fs::create_dir(&state_dir).unwrap();
        let access = write_access_url_in(
            config.to_str().unwrap(),
            "127.0.0.1:3825",
            "state-token",
            Some(&state_dir),
        )
        .unwrap();
        assert_eq!(
            access,
            state_dir.join(format!(
                "{}.admin-url",
                config.file_name().unwrap().to_string_lossy()
            ))
        );
        assert_eq!(
            std::fs::read_to_string(&access).unwrap(),
            "http://127.0.0.1:3825/#t=state-token\n"
        );
        std::fs::remove_file(access).unwrap();
        std::fs::remove_dir(state_dir).unwrap();
        std::fs::remove_file(config).unwrap();
    }

    #[test]
    fn masked_config_hides_secret_and_marks_present() {
        let p = tmp_cfg(&valid_config(50, "deadbeef"));
        let v = read_masked_config(p.to_str().unwrap()).unwrap();
        assert_eq!(v["config"]["reality_tls_signing_sk_hex"], SECRET_MASK);
        assert_eq!(v["config"]["hysteria2_send_rate_mbps"], 50);
        assert_eq!(v["secrets"]["reality_tls_signing_sk_hex"], true);
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn write_preserves_masked_secret_and_applies_edit() {
        let p = tmp_cfg(&valid_config(50, "SECRETKEY_ORIGINAL"));
        let path = p.to_str().unwrap();

        // Simulate the UI: it received the masked secret and a changed non-secret,
        // and POSTs the whole config back with the secret still masked.
        let edited = serde_json::json!({
            "bind": "127.0.0.1:9000",
            "bridge_x25519_sk_hex": "11".repeat(32),
            "bridge_ed25519_pk_hex": "11".repeat(32),
            "operator_ed25519_pk_hex": "11".repeat(32),
            "reality_tls_signing_sk_hex": SECRET_MASK,
            "hysteria2_send_rate_mbps": 200
        });
        write_config(path, edited.to_string().as_bytes()).unwrap();

        let on_disk: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        // Secret restored from disk (NEVER the mask), edit applied.
        assert_eq!(on_disk["reality_tls_signing_sk_hex"], "SECRETKEY_ORIGINAL");
        assert_eq!(on_disk["hysteria2_send_rate_mbps"], 200);
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn relay_tokens_and_quic_password_stay_masked_when_peers_reorder() {
        let mut cfg: serde_json::Value = serde_json::from_str(&valid_config(50, "x")).unwrap();
        cfg["quic_obfs_password"] = "shared QUIC secret".into();
        cfg["relay_peers"] = serde_json::json!([
            { "bridge_x25519_pk": "aa".repeat(32), "relay_token": "token-for-a" },
            { "bridge_x25519_pk": "bb".repeat(32), "relay_token": "token-for-b" }
        ]);
        let p = tmp_cfg(&cfg.to_string());
        let path = p.to_str().unwrap();

        let mut masked = read_masked_config(path).unwrap()["config"].clone();
        let wire = masked.to_string();
        assert!(!wire.contains("shared QUIC secret"));
        assert!(!wire.contains("token-for-a"));
        assert!(!wire.contains("token-for-b"));
        assert_eq!(masked["quic_obfs_password"], SECRET_MASK);
        assert_eq!(masked["relay_peers"][0]["relay_token"], SECRET_MASK);
        assert_eq!(masked["relay_peers"][1]["relay_token"], SECRET_MASK);

        masked["relay_peers"].as_array_mut().unwrap().reverse();
        write_config(path, masked.to_string().as_bytes()).unwrap();
        let saved: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(saved["quic_obfs_password"], "shared QUIC secret");
        assert_eq!(saved["relay_peers"][0]["relay_token"], "token-for-b");
        assert_eq!(saved["relay_peers"][1]["relay_token"], "token-for-a");

        let mut unknown = masked;
        unknown["relay_peers"][0]["bridge_x25519_pk"] = "cc".repeat(32).into();
        assert!(write_config(path, unknown.to_string().as_bytes()).is_err());
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn write_rejects_invalid_config() {
        let p = tmp_cfg(&valid_config(50, "x"));
        // Missing required `bind` -> validation must reject, file unchanged.
        let bad = serde_json::json!({ "hysteria2_send_rate_mbps": 10 });
        let before = std::fs::read_to_string(&p).unwrap();
        assert!(write_config(p.to_str().unwrap(), bad.to_string().as_bytes()).is_err());
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            before,
            "rejected write leaves file intact"
        );
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn write_refuses_when_current_config_cannot_be_read() {
        let p = tmp_cfg(&valid_config(50, "secret"));
        std::fs::remove_file(&p).unwrap();
        let edited =
            serde_json::from_str::<serde_json::Value>(&valid_config(60, SECRET_MASK)).unwrap();
        assert!(write_config(p.to_str().unwrap(), edited.to_string().as_bytes()).is_err());
        assert!(
            !p.exists(),
            "must not replace the missing config with masked fields"
        );
    }

    async fn raw_http(addr: &str, req: &str) -> String {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(req.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        String::from_utf8_lossy(&out).to_string()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn server_enforces_auth_and_host_and_serves_status() {
        let p = tmp_cfg(&valid_config(77, "sekret"));
        let state = Arc::new(AdminState {
            config_path: p.to_string_lossy().to_string(),
            metrics: Arc::new(Metrics::new("0.0.0-test", "reality", "ephemeral")),
            replay_size_fn: Arc::new(|| 0),
            start_time: Instant::now(),
            token: "testtoken123".to_string(),
            service_name: "mirage-bridge-nonexistent-test".to_string(),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(serve_admin(listener, state));
        tokio::time::sleep(Duration::from_millis(50)).await;

        // GET / with loopback host -> HTML page, no token needed.
        let page = raw_http(
            &addr,
            &format!("GET / HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert!(page.contains("200 OK"), "page: {page}");
        assert!(page.contains("Mirage Bridge"), "serves the SPA");
        // Anti-clickjacking + no-sniff hardening must be present on the page response.
        assert!(
            page.contains("X-Frame-Options: DENY"),
            "anti-clickjacking header: {page}"
        );
        assert!(
            page.contains("frame-ancestors 'none'"),
            "CSP forbids framing: {page}"
        );
        assert!(
            page.contains("X-Content-Type-Options: nosniff"),
            "nosniff: {page}"
        );

        // /api/status without a token -> 401.
        let noauth = raw_http(
            &addr,
            &format!("GET /api/status HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert!(noauth.contains("401"), "no-token must 401: {noauth}");

        // /api/status with the token -> 200 + live JSON.
        let ok = raw_http(&addr, &format!("GET /api/status HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer testtoken123\r\nConnection: close\r\n\r\n")).await;
        assert!(
            ok.contains("200 OK") && ok.contains("\"sessions\""),
            "authed status: {ok}"
        );

        // Non-loopback Host -> 403 (DNS-rebinding defense).
        let rebind = raw_http(&addr, "GET /api/status HTTP/1.1\r\nHost: evil.example.com\r\nAuthorization: Bearer testtoken123\r\nConnection: close\r\n\r\n").await;
        assert!(rebind.contains("403"), "rebinding host must 403: {rebind}");

        let duplicate = raw_http(&addr, &format!("GET /api/status HTTP/1.1\r\nHost: evil.example.com\r\nHost: {addr}\r\nAuthorization: Bearer testtoken123\r\nConnection: close\r\n\r\n")).await;
        assert!(
            duplicate.contains("403"),
            "duplicate Host must 403: {duplicate}"
        );

        // /api/config with token -> secret masked on the wire.
        let cfg = raw_http(&addr, &format!("GET /api/config HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer testtoken123\r\nConnection: close\r\n\r\n")).await;
        assert!(
            cfg.contains(SECRET_MASK) && !cfg.contains("sekret"),
            "secret must be masked on the wire: {cfg}"
        );

        std::fs::remove_file(p).ok();
    }
}
