#![allow(missing_docs)]
// Deny `unsafe` everywhere in the GUI shell, with exactly ONE audited exception
// (the pre_exec PR_SET_PDEATHSIG below, annotated inline). `deny` rather than
// `forbid` so that single, reviewed exception can exist; every other `unsafe`
// fails to compile.
#![deny(unsafe_code)]
#![windows_subsystem = "windows"]

//! Mirage client GUI - a thin native supervisor over the `mirage-client` daemon.
//!
//! The GUI never links the client library: it spawns the `mirage-client` binary
//! with `--management-bind 127.0.0.1:19443` and polls that daemon's loopback
//! HTTP JSON API (`/api/status`, `/api/bridges`) to render live status, streaming
//! the child's logs into a panel and killing it on quit. Rendering is Slint's
//! software renderer (no OpenGL, no GTK, no system font library) so the binary
//! builds with plain `cargo build` and ships in the release archives.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use slint::ComponentHandle;

slint::include_modules!();

/// Loopback management API the daemon is told to expose and the GUI polls.
const MGMT_ADDR: &str = "127.0.0.1:19443";
/// Default SOCKS bind baked into the invite-only temp config.
const DEFAULT_SOCKS_BIND: &str = "127.0.0.1:1080";
/// Ring-buffer cap for the log panel.
const LOG_CAP: usize = 500;
/// How often the poll thread refreshes status.
const POLL_INTERVAL: Duration = Duration::from_millis(1500);

#[derive(Clone, PartialEq)]
enum DaemonState {
    Stopped,
    Starting,
    Running,
    Error(String),
}

/// State shared between the UI-thread callbacks, the log-reader threads, and the
/// background poll thread.
struct Shared {
    child: Mutex<Option<std::process::Child>>,
    logs: Mutex<VecDeque<String>>,
    state: Mutex<DaemonState>,
    /// Whether to launch the daemon with `--paranoid` (the GUI's Paranoid
    /// switch). The daemon echoes its actual posture back in /api/status.
    paranoid: Mutex<bool>,
    /// Name of the saved profile currently connected (empty = ad-hoc invite).
    active_profile: Mutex<String>,
}

impl Shared {
    fn new() -> Self {
        Self {
            child: Mutex::new(None),
            logs: Mutex::new(VecDeque::new()),
            state: Mutex::new(DaemonState::Stopped),
            paranoid: Mutex::new(false),
            active_profile: Mutex::new(String::new()),
        }
    }

    fn set_state(&self, s: DaemonState) {
        *self.state.lock().expect("state lock") = s;
    }

    fn paranoid(&self) -> bool {
        *self.paranoid.lock().expect("paranoid lock")
    }

    fn active_profile(&self) -> String {
        self.active_profile.lock().expect("profile lock").clone()
    }

    fn push_log(&self, line: String) {
        let mut l = self.logs.lock().expect("logs lock");
        l.push_back(line);
        while l.len() > LOG_CAP {
            l.pop_front();
        }
    }
}

/// One row rendered by /api/bridges, deserialized straight from the daemon JSON.
#[derive(Clone, Default, serde::Deserialize)]
struct BridgeStat {
    #[allow(dead_code)]
    idx: usize,
    addr: String,
    transport: String,
    #[serde(default)]
    latency_ms: Option<u64>,
    healthy: bool,
    #[serde(default)]
    #[allow(dead_code)]
    bridge_pk_fp: String,
    #[serde(default)]
    fresh_tokens_remaining: usize,
    #[serde(default)]
    port_hop_active: bool,
    #[serde(default)]
    current_derived_port: Option<u16>,
    #[serde(default)]
    mux_carriers: usize,
    #[serde(default)]
    mux_streams: u32,
}

// Raw HTTP helper (no reqwest/ureq needed)

fn http_get(addr: &str, path: &str) -> Option<String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let mut stream = TcpStream::connect(addr).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(2))).ok();
    let req = format!("GET {path} HTTP/1.0\r\nHost: {addr}\r\n\r\n");
    stream.write_all(req.as_bytes()).ok()?;
    let mut resp = String::new();
    stream.read_to_string(&mut resp).ok();
    resp.split("\r\n\r\n").nth(1).map(|s| s.to_string())
}

/// POST to a state-changing management endpoint. Sends the `X-Mirage-Control`
/// header the daemon requires (a non-simple header a cross-origin browser page
/// cannot forge), so only this native client can trigger it. Best-effort.
fn http_post_control(addr: &str, path: &str) {
    use std::io::Write;
    use std::net::TcpStream;

    if let Ok(mut stream) = TcpStream::connect(addr) {
        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
        let req = format!(
            "POST {path} HTTP/1.0\r\nHost: {addr}\r\nX-Mirage-Control: 1\r\nContent-Length: 0\r\n\r\n"
        );
        let _ = stream.write_all(req.as_bytes());
    }
}

// Binary / launch helpers

fn find_client_binary() -> Option<std::path::PathBuf> {
    let exe_suffix = std::env::consts::EXE_SUFFIX;
    let bin_name = format!("mirage-client{exe_suffix}");
    let candidates: Vec<std::path::PathBuf> = vec![
        std::env::current_exe()
            .ok()
            .map(|p| p.with_file_name(&bin_name))
            .unwrap_or_default(),
        std::path::PathBuf::from(format!("./{bin_name}")),
        std::path::PathBuf::from(format!("./target/debug/{bin_name}")),
        std::path::PathBuf::from(format!("./target/release/{bin_name}")),
        std::path::PathBuf::from("/usr/local/bin/mirage-client"),
        std::path::PathBuf::from("/usr/bin/mirage-client"),
    ];
    candidates.into_iter().find(|p| p.exists())
}

/// Write the invite-only temp config owner-only (0600), refusing to follow a
/// symlink so another local user can't pre-plant one to read/redirect the write.
fn write_temp_config(invite: &str) -> std::io::Result<std::path::PathBuf> {
    let tmp = std::env::temp_dir().join("mirage-gui-client.json");
    let cfg = serde_json::json!({
        "local_bind": DEFAULT_SOCKS_BIND,
        "invite": invite,
        "handshake_timeout_secs": 10
    });
    let cfg_str = serde_json::to_string_pretty(&cfg).expect("json serialization cannot fail");
    let _ = std::fs::remove_file(&tmp); // drop any stale file/symlink
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true).mode(0o600);
        #[cfg(target_os = "linux")]
        opts.custom_flags(libc::O_NOFOLLOW);
        opts.open(&tmp)
            .and_then(|mut f| f.write_all(cfg_str.as_bytes()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&tmp, cfg_str.as_bytes())?;
    }
    Ok(tmp)
}

fn launch_client(shared: &Arc<Shared>, invite: String, config_path: String) {
    let binary = match find_client_binary() {
        Some(p) => p,
        None => {
            shared.set_state(DaemonState::Error(
                "mirage-client binary not found. Put it next to this GUI, or on PATH.".into(),
            ));
            return;
        }
    };

    let config = if !config_path.trim().is_empty() {
        config_path.trim().to_string()
    } else {
        match write_temp_config(invite.trim()) {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(e) => {
                shared.set_state(DaemonState::Error(format!(
                    "failed to write temp config: {e}"
                )));
                return;
            }
        }
    };

    let mut command = std::process::Command::new(&binary);
    command
        .arg(&config)
        .arg("--management-bind")
        .arg(MGMT_ADDR)
        // Logs are captured into the panel, not a terminal - no ANSI colour.
        .env("NO_COLOR", "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    // The Paranoid switch forces the strong posture regardless of the config.
    if shared.paranoid() {
        command.arg("--paranoid");
    }

    // Linux: SIGKILL this child if the GUI dies (covers hard-kills that skip Drop).
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: runs in the forked child between fork and exec.
        // prctl(PR_SET_PDEATHSIG) is async-signal-safe and allocates nothing.
        // The one audited `unsafe` in this crate; denied everywhere else.
        #[allow(unsafe_code)]
        unsafe {
            command.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                Ok(())
            });
        }
    }

    match command.spawn() {
        Ok(mut child) => {
            let out = child.stdout.take();
            let err = child.stderr.take();
            *shared.child.lock().expect("child lock") = Some(child);
            shared.set_state(DaemonState::Starting);
            if let Some(o) = out {
                spawn_log_reader(o, Arc::clone(shared));
            }
            if let Some(e) = err {
                spawn_log_reader(e, Arc::clone(shared));
            }
        }
        Err(e) => shared.set_state(DaemonState::Error(format!(
            "failed to launch mirage-client: {e}"
        ))),
    }
}

fn spawn_log_reader(reader: impl std::io::Read + Send + 'static, shared: Arc<Shared>) {
    std::thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::BufReader::new(reader)
            .lines()
            .map_while(Result::ok)
        {
            let line = clean_log_line(&line);
            if !line.is_empty() {
                shared.push_log(line);
            }
        }
    });
}

// Built-in file browser (no external file-dialog tool required)

/// Sensible directory to open the browser at: $HOME (or %USERPROFILE%), else the
/// current dir, else the filesystem root.
fn start_dir() -> std::path::PathBuf {
    #[cfg(windows)]
    let home = std::env::var_os("USERPROFILE");
    #[cfg(not(windows))]
    let home = std::env::var_os("HOME");
    home.map(std::path::PathBuf::from)
        .filter(|p| p.is_dir())
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| std::path::PathBuf::from("/"))
}

/// List `dir`'s sub-directories and `.json` files (dot-files hidden), directories
/// first then alphabetical, with a leading `..` entry. Returns the resolved path
/// string and the entries `(name, is_dir)`.
fn list_dir(dir: &std::path::Path) -> (String, Vec<(String, bool)>) {
    let mut items: Vec<(String, bool)> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue;
            }
            let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if is_dir || name.to_ascii_lowercase().ends_with(".json") {
                items.push((name, is_dir));
            }
        }
    }
    items.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then_with(|| a.0.to_ascii_lowercase().cmp(&b.0.to_ascii_lowercase()))
    });
    let mut entries = vec![("..".to_string(), true)];
    entries.extend(items);
    (dir.display().to_string(), entries)
}

/// Build the Slint model for the browser list.
fn entries_model(entries: Vec<(String, bool)>) -> slint::ModelRc<BrowserEntry> {
    let rows: Vec<BrowserEntry> = entries
        .into_iter()
        .map(|(name, is_dir)| BrowserEntry {
            name: name.into(),
            is_dir,
        })
        .collect();
    slint::ModelRc::new(slint::VecModel::from(rows))
}

/// Populate the browser UI for `dir` and show it.
fn open_browser_at(ui: &AppWindow, dir: &std::path::Path) {
    let (path, entries) = list_dir(dir);
    ui.set_browser_path(path.into());
    ui.set_browser_entries(entries_model(entries));
    ui.set_show_browser(true);
}

fn stop_client(shared: &Arc<Shared>) {
    if let Some(ref mut child) = *shared.child.lock().expect("child lock") {
        let _ = child.kill();
        let _ = child.wait();
    }
    *shared.child.lock().expect("child lock") = None;
    shared.set_state(DaemonState::Stopped);
}

// Saved connection profiles

/// A named connection profile: an invite string and/or a client.json path. Stored
/// as a small JSON array in the user's config dir so the GUI can offer one-click
/// reconnects across launches. Contents are the same secrets the user already
/// pasted; no new sensitive material is introduced.
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
struct Profile {
    name: String,
    #[serde(default)]
    invite: String,
    #[serde(default)]
    config_path: String,
}

/// Where profiles live: `$XDG_CONFIG_HOME/mirage/gui-profiles.json` (Linux),
/// `~/Library/Application Support/mirage/...` (macOS), `%APPDATA%\mirage\...`
/// (Windows), falling back to the current directory if none resolve.
fn profiles_path() -> std::path::PathBuf {
    #[cfg(windows)]
    let base = std::env::var_os("APPDATA").map(std::path::PathBuf::from);
    #[cfg(target_os = "macos")]
    let base = std::env::var_os("HOME")
        .map(|h| std::path::PathBuf::from(h).join("Library/Application Support"));
    #[cfg(all(not(windows), not(target_os = "macos")))]
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config")));
    base.unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("mirage")
        .join("gui-profiles.json")
}

fn load_profiles() -> Vec<Profile> {
    std::fs::read_to_string(profiles_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_profiles(list: &[Profile]) {
    let path = profiles_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(s) = serde_json::to_string_pretty(list) {
        let _ = std::fs::write(&path, s);
    }
}

/// A short human subtitle for a profile row: the config filename if present,
/// else a truncated preview of the invite.
fn profile_subtitle(p: &Profile) -> String {
    if !p.config_path.is_empty() {
        std::path::Path::new(&p.config_path)
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| p.config_path.clone())
    } else if !p.invite.is_empty() {
        let preview: String = p.invite.trim().chars().take(30).collect();
        if p.invite.trim().chars().count() > 30 {
            format!("{preview}...")
        } else {
            preview
        }
    } else {
        String::new()
    }
}

fn profiles_model(list: &[Profile], active: &str) -> slint::ModelRc<ProfileRow> {
    let rows: Vec<ProfileRow> = list
        .iter()
        .map(|p| ProfileRow {
            name: p.name.clone().into(),
            subtitle: profile_subtitle(p).into(),
            active: !active.is_empty() && p.name == active,
        })
        .collect();
    slint::ModelRc::new(slint::VecModel::from(rows))
}

// Log line cleanup

/// Remove ANSI SGR escape sequences so terminal colour codes don't render as
/// literal garbage in the log panel.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for n in chars.by_ref() {
                if n.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// `2026-07-13T14:56:33.5Z  WARN mirage_client: copy ended` -> `14:56:33 WARN copy ended`.
fn clean_log_line(raw: &str) -> String {
    let s = strip_ansi(raw);
    let s = s.trim();
    if s.is_empty() {
        return String::new();
    }
    let (ts, rest) = match s.find('Z') {
        Some(z) if z >= 19 && s[..z].contains('T') => {
            (s.get(11..19).unwrap_or(""), s[z + 1..].trim_start())
        }
        _ => ("", s),
    };
    let (level, msg) = match rest.find(": ") {
        Some(i) => (
            rest[..i].split_whitespace().next().unwrap_or(""),
            &rest[i + 2..],
        ),
        None => ("", rest),
    };
    let body = if msg.is_empty() { rest } else { msg };
    match (ts.is_empty(), level.is_empty()) {
        (false, false) => format!("{ts} {level} {body}"),
        (true, false) => format!("{level} {body}"),
        (false, true) => format!("{ts} {body}"),
        (true, true) => body.to_string(),
    }
}

fn format_uptime(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

fn transport_color(t: &str) -> slint::Color {
    let (r, g, b) = if t.contains("reality") {
        (50, 100, 200)
    } else if t.contains("hysteria") {
        (30, 160, 70)
    } else if t.contains("ss2022") || t.contains("shadow") {
        (120, 80, 190)
    } else if t.contains("doh") || t.contains("dnstt") {
        (20, 150, 180)
    } else if t.contains("ws") || t.contains("websocket") {
        (30, 160, 150)
    } else {
        (90, 100, 115)
    };
    slint::Color::from_rgb_u8(r, g, b)
}

fn latency_color(ms: u64) -> slint::Color {
    let (r, g, b) = if ms < 100 {
        (80, 200, 120)
    } else if ms < 300 {
        (220, 180, 60)
    } else {
        (220, 90, 70)
    };
    slint::Color::from_rgb_u8(r, g, b)
}

// Background poll thread -> UI

fn spawn_poll_thread(ui: slint::Weak<AppWindow>, shared: Arc<Shared>) {
    std::thread::spawn(move || loop {
        std::thread::sleep(POLL_INTERVAL);

        // Detect unexpected child death.
        let child_alive = {
            let mut c = shared.child.lock().expect("child lock");
            match c.as_mut() {
                None => false,
                Some(ch) => match ch.try_wait() {
                    Ok(Some(_)) => {
                        *c = None;
                        false
                    }
                    Ok(None) => true,
                    Err(_) => false,
                },
            }
        };
        if !child_alive {
            let mut st = shared.state.lock().expect("state lock");
            if *st == DaemonState::Running || *st == DaemonState::Starting {
                *st = DaemonState::Error("mirage-client exited unexpectedly".into());
            }
        }

        // Poll status + bridges (only meaningful while a child is up).
        let mut status: Option<serde_json::Value> = None;
        let mut bridges: Vec<BridgeStat> = Vec::new();
        if child_alive {
            if let Some(body) = http_get(MGMT_ADDR, "/api/status") {
                status = serde_json::from_str(&body).ok();
                if status.is_some() {
                    let mut st = shared.state.lock().expect("state lock");
                    if *st == DaemonState::Starting {
                        *st = DaemonState::Running;
                    }
                }
            }
            if let Some(body) = http_get(MGMT_ADDR, "/api/bridges") {
                bridges = serde_json::from_str(&body).unwrap_or_default();
            }
        }

        let state = shared.state.lock().expect("state lock").clone();
        let active_profile = shared.active_profile();
        let logs: Vec<String> = shared
            .logs
            .lock()
            .expect("logs lock")
            .iter()
            .cloned()
            .collect();

        // Marshal into UI-thread update.
        let _ = ui.upgrade_in_event_loop(move |ui| {
            apply_snapshot(&ui, &state, status, bridges, logs, &active_profile);
        });
    });
}

/// Prettify a wire transport name for display ("reality" -> "Reality").
fn prettify_carrier(t: &str) -> String {
    match t.to_ascii_lowercase().as_str() {
        "reality" => "Reality".into(),
        "hysteria2" => "Hysteria2".into(),
        "ss2022" | "shadowsocks" => "Shadowsocks".into(),
        "meek" => "meek".into(),
        "websocket" | "ws" => "WebSocket".into(),
        "vless" => "VLESS".into(),
        "doh" => "DoH".into(),
        "dnstt" | "dns" => "dnstt".into(),
        "webrtc" => "WebRTC".into(),
        "h3" | "masque" => "MASQUE".into(),
        "obfs" => "obfs".into(),
        "raw" => "Raw".into(),
        other if !other.is_empty() => {
            let mut c = other.chars();
            c.next()
                .map(|f| f.to_uppercase().collect::<String>() + c.as_str())
                .unwrap_or_default()
        }
        _ => "-".into(),
    }
}

/// Prettify a discovery channel name ("dht" -> "DHT").
fn prettify_channel(c: &str) -> String {
    match c.to_ascii_lowercase().as_str() {
        "dht" => "DHT".into(),
        "nostr" => "Nostr".into(),
        "dns" => "DNS TXT".into(),
        other => other.to_uppercase(),
    }
}

fn apply_snapshot(
    ui: &AppWindow,
    state: &DaemonState,
    status: Option<serde_json::Value>,
    bridges: Vec<BridgeStat>,
    logs: Vec<String>,
    active_profile: &str,
) {
    let (state_str, err) = match state {
        DaemonState::Stopped => ("stopped", String::new()),
        DaemonState::Starting => ("starting", String::new()),
        DaemonState::Running => ("running", String::new()),
        DaemonState::Error(e) => ("error", e.clone()),
    };
    ui.set_daemon_state(state_str.into());
    ui.set_error_text(err.into());
    ui.set_active_profile(active_profile.into());
    // Keep the profile list (and its active highlight) in sync with disk + state.
    ui.set_profiles(profiles_model(&load_profiles(), active_profile));

    if let Some(v) = status {
        ui.set_bind_addr(v["local_bind"].as_str().unwrap_or("").into());
        ui.set_version(v["version"].as_str().unwrap_or("").into());
        let active = v["active_sessions"].as_u64().unwrap_or(0);
        let total = v["total_sessions"].as_u64().unwrap_or(0);
        ui.set_sessions(format!("{active} / {total}").into());
        ui.set_uptime(format_uptime(v["uptime_secs"].as_u64().unwrap_or(0)).into());
        let carriers = v["mux_carriers"].as_u64().unwrap_or(0);
        let streams = v["mux_streams"].as_u64().unwrap_or(0);
        ui.set_mux(format!("{carriers} x {streams}").into());
        ui.set_session_streams(streams.to_string().into());

        // Discovery status + strong-posture flag.
        ui.set_paranoid(v["paranoid"].as_bool().unwrap_or(false));
        ui.set_discovery_active(v["discovery_active"].as_bool().unwrap_or(false));
        ui.set_discovered_count(v["discovered_count"].as_i64().unwrap_or(0) as i32);
        let chans: Vec<ChannelRow> = v["discovery_channels"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|c| c.as_str())
                    .map(|c| ChannelRow {
                        name: prettify_channel(c).into(),
                        // Configured channels are shown as in-play; the daemon
                        // does not expose per-channel liveness yet.
                        healthy: true,
                    })
                    .collect()
            })
            .unwrap_or_default();
        ui.set_channels(slint::ModelRc::new(slint::VecModel::from(chans)));
    }

    // Derive the "via <carrier> - bridge <fp>" line from the primary bridge:
    // prefer one actively carrying traffic, else the first healthy, else first.
    if let Some(primary) = bridges
        .iter()
        .find(|b| b.healthy && b.mux_carriers > 0)
        .or_else(|| bridges.iter().find(|b| b.healthy))
        .or_else(|| bridges.first())
    {
        ui.set_via_carrier(prettify_carrier(&primary.transport).into());
        ui.set_via_bridge(primary.bridge_pk_fp.clone().into());
    } else {
        ui.set_via_carrier("".into());
        ui.set_via_bridge("".into());
    }

    let rows: Vec<BridgeRow> = bridges
        .iter()
        .map(|b| {
            let lat = b
                .latency_ms
                .map(|m| format!("{m}ms"))
                .unwrap_or_else(|| "-".into());
            let lat_col = latency_color(b.latency_ms.unwrap_or(9999));
            let port = if b.port_hop_active {
                b.current_derived_port
                    .map(|p| p.to_string())
                    .unwrap_or_default()
            } else {
                String::new()
            };
            let mux = if b.mux_carriers > 0 {
                format!("{}x{}", b.mux_carriers, b.mux_streams)
            } else {
                String::new()
            };
            BridgeRow {
                addr: b.addr.clone().into(),
                transport: b.transport.clone().into(),
                transport_color: transport_color(&b.transport),
                latency: lat.into(),
                latency_color: lat_col,
                tokens: b.fresh_tokens_remaining.to_string().into(),
                mux: mux.into(),
                healthy: b.healthy,
                port: port.into(),
                // Stable identity colour derived from the bridge's pubkey fp (or
                // address) - same bridge always gets the same swatch.
                id_color: identity_color(if b.bridge_pk_fp.is_empty() {
                    &b.addr
                } else {
                    &b.bridge_pk_fp
                }),
            }
        })
        .collect();
    ui.set_bridges(slint::ModelRc::new(slint::VecModel::from(rows)));

    // Join into one string so the log is selectable/copyable in the TextEdit.
    ui.set_log_text(logs.join("\n").into());
}

/// Deterministic, readable colour from an arbitrary id string (bridge pubkey/
/// address). Uses a stable FNV-1a hash -> HSV with fixed saturation/value so every
/// swatch is distinct but legible on the dark panel.
fn identity_color(id: &str) -> slint::Color {
    let mut h: u64 = 0xcbf29ce484222325;
    for byte in id.bytes() {
        h ^= u64::from(byte);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    let hue = (h % 360) as f64;
    // HSV(hue, 0.55, 0.85) -> RGB.
    let (s, v) = (0.55_f64, 0.85_f64);
    let c = v * s;
    let x = c * (1.0 - ((hue / 60.0) % 2.0 - 1.0).abs());
    let m = v - c;
    let (r, g, b) = match (hue / 60.0) as u32 {
        0 => (c, x, 0.0),
        1 => (x, c, 0.0),
        2 => (0.0, c, x),
        3 => (0.0, x, c),
        4 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };
    slint::Color::from_rgb_u8(
        ((r + m) * 255.0) as u8,
        ((g + m) * 255.0) as u8,
        ((b + m) * 255.0) as u8,
    )
}

// Clipboard (best-effort; GTK-free backend)

fn copy_to_clipboard(text: &str) -> bool {
    match arboard::Clipboard::new() {
        Ok(mut cb) => cb.set_text(text.to_string()).is_ok(),
        Err(_) => false,
    }
}

// main

fn main() -> Result<(), slint::PlatformError> {
    // Answer --version / --help WITHOUT opening a window (so the binary is usable
    // and smoke-testable on a headless machine, and behaves like the CLIs).
    if let Some(flag) = std::env::args().nth(1) {
        match flag.as_str() {
            "--version" | "-V" => {
                println!("mirage-client-gui {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "--help" | "-h" => {
                println!(
                    "mirage-client-gui {}\n\n\
                     A desktop UI that supervises the mirage-client daemon.\n\
                     Run with no arguments to open the window. The mirage-client binary must be\n\
                     alongside this one or on PATH.\n\n\
                     Options:\n  \
                       --version, -V   Print version and exit.\n  \
                       --help, -h      Print this help and exit.",
                    env!("CARGO_PKG_VERSION")
                );
                return Ok(());
            }
            _ => {}
        }
    }

    let ui = AppWindow::new()?;
    let shared = Arc::new(Shared::new());

    // Load saved profiles from disk into the picker.
    ui.set_profiles(profiles_model(&load_profiles(), ""));

    {
        let ui_weak = ui.as_weak();
        let shared = Arc::clone(&shared);
        ui.on_start(move || {
            if let Some(ui) = ui_weak.upgrade() {
                let invite = ui.get_invite().to_string();
                let path = ui.get_config_path().to_string();
                // An ad-hoc invite is not a saved profile.
                shared.active_profile.lock().expect("profile lock").clear();
                launch_client(&shared, invite, path);
            }
        });
    }
    {
        let ui_weak = ui.as_weak();
        let shared = Arc::clone(&shared);
        ui.on_stop(move || {
            stop_client(&shared);
            shared.active_profile.lock().expect("profile lock").clear();
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_active_profile("".into());
                ui.set_profiles(profiles_model(&load_profiles(), ""));
            }
        });
    }
    // Reconnect = restart the daemon with the same invite/config. This re-walks
    // discovery and renegotiates carriers; the active profile is preserved.
    {
        let ui_weak = ui.as_weak();
        let shared = Arc::clone(&shared);
        ui.on_reconnect(move || {
            if let Some(ui) = ui_weak.upgrade() {
                let invite = ui.get_invite().to_string();
                let path = ui.get_config_path().to_string();
                stop_client(&shared);
                launch_client(&shared, invite, path);
            }
        });
    }
    // Re-discover: ask the running daemon to walk the rendezvous channels now
    // (POST /api/rediscover). Non-blocking; the poll loop reflects the result.
    {
        ui.on_rediscover(move || {
            std::thread::spawn(|| http_post_control(MGMT_ADDR, "/api/rediscover"));
        });
    }
    // Paranoid toggle: flip the launch flag and, if connected, restart into the
    // new posture. The daemon echoes its actual posture back in /api/status.
    {
        let ui_weak = ui.as_weak();
        let shared = Arc::clone(&shared);
        ui.on_toggle_paranoid(move || {
            {
                let mut p = shared.paranoid.lock().expect("paranoid lock");
                *p = !*p;
            }
            if let Some(ui) = ui_weak.upgrade() {
                let running = shared.state.lock().expect("state lock").clone();
                if matches!(running, DaemonState::Running | DaemonState::Starting) {
                    let invite = ui.get_invite().to_string();
                    let path = ui.get_config_path().to_string();
                    stop_client(&shared);
                    launch_client(&shared, invite, path);
                }
            }
        });
    }
    // Save the current form as a named profile (replacing any of the same name).
    {
        let ui_weak = ui.as_weak();
        let shared = Arc::clone(&shared);
        ui.on_save_profile(move || {
            if let Some(ui) = ui_weak.upgrade() {
                let name = ui.get_profile_name().to_string().trim().to_string();
                let invite = ui.get_invite().to_string();
                let config_path = ui.get_config_path().to_string();
                if name.is_empty() || (invite.is_empty() && config_path.is_empty()) {
                    return;
                }
                let mut list = load_profiles();
                list.retain(|p| p.name != name);
                list.push(Profile {
                    name,
                    invite,
                    config_path,
                });
                list.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
                save_profiles(&list);
                ui.set_profiles(profiles_model(&list, &shared.active_profile()));
                ui.set_profile_name("".into());
            }
        });
    }
    // Connect using a saved profile: load its fields, mark it active, (re)launch.
    {
        let ui_weak = ui.as_weak();
        let shared = Arc::clone(&shared);
        ui.on_load_profile(move |name| {
            if let Some(ui) = ui_weak.upgrade() {
                if let Some(p) = load_profiles()
                    .into_iter()
                    .find(|p| p.name == name.as_str())
                {
                    let nm = p.name.clone();
                    *shared.active_profile.lock().expect("profile lock") = nm.clone();
                    ui.set_invite(p.invite.clone().into());
                    ui.set_config_path(p.config_path.clone().into());
                    ui.set_active_profile(nm.clone().into());
                    ui.set_show_connect(false);
                    ui.set_profiles(profiles_model(&load_profiles(), &nm));
                    stop_client(&shared);
                    launch_client(&shared, p.invite, p.config_path);
                }
            }
        });
    }
    // Forget a saved profile.
    {
        let ui_weak = ui.as_weak();
        let shared = Arc::clone(&shared);
        ui.on_delete_profile(move |name| {
            if let Some(ui) = ui_weak.upgrade() {
                let mut list = load_profiles();
                list.retain(|p| p.name != name.as_str());
                save_profiles(&list);
                ui.set_profiles(profiles_model(&list, &shared.active_profile()));
            }
        });
    }
    // Built-in file browser - open, navigate, pick, cancel. All handlers run on
    // the UI thread; directory listing is a fast synchronous fs read.
    {
        let ui_weak = ui.as_weak();
        ui.on_browse(move || {
            if let Some(ui) = ui_weak.upgrade() {
                open_browser_at(&ui, &start_dir());
            }
        });
    }
    {
        let ui_weak = ui.as_weak();
        ui.on_browser_enter(move |name| {
            if let Some(ui) = ui_weak.upgrade() {
                let cur = std::path::PathBuf::from(ui.get_browser_path().to_string());
                let target = if name == ".." {
                    cur.parent().map(|p| p.to_path_buf()).unwrap_or(cur)
                } else {
                    cur.join(name.as_str())
                };
                open_browser_at(&ui, &target);
            }
        });
    }
    {
        let ui_weak = ui.as_weak();
        ui.on_browser_pick(move |name| {
            if let Some(ui) = ui_weak.upgrade() {
                let full =
                    std::path::PathBuf::from(ui.get_browser_path().to_string()).join(name.as_str());
                ui.set_config_path(full.to_string_lossy().to_string().into());
                ui.set_show_browser(false);
            }
        });
    }
    {
        let ui_weak = ui.as_weak();
        ui.on_browser_cancel(move || {
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_show_browser(false);
            }
        });
    }
    {
        let ui_weak = ui.as_weak();
        ui.on_copy_bind(move || {
            if let Some(ui) = ui_weak.upgrade() {
                let addr = ui.get_bind_addr().to_string();
                if !addr.is_empty() && copy_to_clipboard(&addr) {
                    ui.set_copied(true);
                    let w = ui.as_weak();
                    // Clear the "copied!" flash after a moment.
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_millis(1200));
                        let _ = w.upgrade_in_event_loop(|ui| ui.set_copied(false));
                    });
                }
            }
        });
    }
    {
        let ui_weak = ui.as_weak();
        let shared = Arc::clone(&shared);
        ui.on_clear_log(move || {
            shared.logs.lock().expect("logs lock").clear();
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_log_text("".into());
            }
        });
    }

    // Kill the daemon when the window closes.
    {
        let shared = Arc::clone(&shared);
        ui.window().on_close_requested(move || {
            stop_client(&shared);
            slint::CloseRequestResponse::HideWindow
        });
    }

    spawn_poll_thread(ui.as_weak(), Arc::clone(&shared));

    let run = ui.run();
    // Belt-and-suspenders: ensure the child is reaped even on a clean loop exit.
    stop_client(&shared);
    run
}

#[cfg(test)]
mod tests {
    use super::list_dir;

    #[test]
    fn list_dir_shows_dirs_and_json_only_dirs_first() {
        let mut base = std::env::temp_dir();
        let mut b = [0u8; 8];
        let _ = getrandom_fill(&mut b);
        base.push(format!("mirage-gui-listdir-{}", hex8(&b)));
        std::fs::create_dir_all(base.join("sub")).unwrap();
        std::fs::write(base.join("client.json"), "{}").unwrap();
        std::fs::write(base.join("notes.txt"), "x").unwrap();
        std::fs::write(base.join(".hidden.json"), "{}").unwrap();

        let (path, entries) = list_dir(&base);
        assert_eq!(path, base.display().to_string());
        assert_eq!(entries[0], ("..".to_string(), true), "'..' is always first");
        // 'sub' (dir) before 'client.json' (file); dot-file and .txt excluded.
        let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            vec!["..", "sub", "client.json"],
            "dirs first, json only, dotfiles hidden"
        );
        assert!(entries[1].1, "'sub' is a directory");
        assert!(!entries[2].1, "'client.json' is a file");

        std::fs::remove_dir_all(base).ok();
    }

    // Tiny local helpers so the test doesn't pull new deps.
    fn getrandom_fill(b: &mut [u8]) -> std::io::Result<()> {
        use std::io::Read;
        std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(b))
    }
    fn hex8(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
