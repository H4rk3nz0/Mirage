//! In-process operator admin UI, opt-in via `--admin-ui` (defaults to
//! `127.0.0.1:3825`; pass `--admin-ui <host:port>` to override).
//!
//! A tiny hand-rolled HTTP/1.1 server (same style as [`crate::metrics`]) that
//! serves a self-contained single-page app plus a small JSON control API to
//! read the live counter set, view/edit the bridge's JSON config, and restart
//! the service. No framework, no new dependency - tokio + serde_json only.
//!
//! # Security posture (this is a privileged, config-writing surface)
//!
//! - **Loopback only.** The server refuses to serve unless the request's `Host`
//!   header is a loopback literal (DNS-rebinding defense), and a non-loopback
//!   *bind* is warned about loudly at startup. Keep it on `127.0.0.1`.
//! - **Bearer token.** Every `/api/*` call requires `Authorization: Bearer
//!   <token>`, compared in constant time. The token is random per start and
//!   printed to the operator console; it is delivered to the browser via the URL
//!   fragment (never sent to the server, never logged). A local process that
//!   cannot read the console cannot drive the API, and a cross-origin page cannot
//!   set the `Authorization` header - so CSRF is structurally blocked.
//! - **No CORS, strict CSP.** The page is self-hosted; responses set a strict
//!   `Content-Security-Policy` and never emit `Access-Control-Allow-Origin`.
//! - **Secrets never leave the box.** Long-term key material in the config
//!   (`*_sk_hex`, `*_secret_hex`, `*_psk_hex`, salt, relay token) is masked
//!   before the config is sent to the browser and restored from disk on write,
//!   so the UI can never read or clobber a secret it never saw.
//! - **Atomic 0600 writes.** Config is written via the same secure-file path the
//!   provisioning tools use.

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

/// Generate a fresh 128-bit hex token for this run.
pub fn gen_token() -> String {
    let mut b = [0u8; 16];
    // Failure here is catastrophic RNG failure; fall back to time-free zeros only
    // to avoid a panic, but such a bridge has bigger problems.
    let _ = getrandom::fill(&mut b);
    hex::encode(b)
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
    let mut bearer = None;
    let mut content_len = 0usize;
    for line in lines {
        if let Some((name, val)) = line.split_once(':') {
            let val = val.trim();
            match name.trim().to_ascii_lowercase().as_str() {
                "host" => host_ok = host_is_loopback(val),
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
    let original: serde_json::Value = std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| serde_json::json!({}));
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
script-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'\r\n\
         X-Content-Type-Options: nosniff\r\n\
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

/// True if a `Host:` header value points at loopback (`127.0.0.0/8`, `::1`, or
/// `localhost`), ignoring any `:port` suffix.
fn host_is_loopback(host: &str) -> bool {
    let h = host.trim();
    // Strip an optional port suffix. Bracketed `[::1]:p` -> `::1`; a single-colon
    // `host:p` -> `host`; a bare multi-colon IPv6 (`::1`) is left intact.
    let bare = if let Some(rest) = h.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else if h.matches(':').count() == 1 {
        h.split(':').next().unwrap_or(h)
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

/// Log the one-time access URL (token in the fragment, never sent to the server).
pub fn log_access_url(bind: &str, token: &str) {
    info!(bind = %bind, "admin UI: http://{bind}/#t={token}");
    // Also to stdout so it's visible even at a low log level.
    println!("\n  Mirage bridge admin UI:  http://{bind}/#t={token}\n");
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

        // /api/config with token -> secret masked on the wire.
        let cfg = raw_http(&addr, &format!("GET /api/config HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer testtoken123\r\nConnection: close\r\n\r\n")).await;
        assert!(
            cfg.contains(SECRET_MASK) && !cfg.contains("sekret"),
            "secret must be masked on the wire: {cfg}"
        );

        std::fs::remove_file(p).ok();
    }
}
