//! `mirage-setup` - interactive CLI wizard that generates ready-to-use
//! `bridge.json` and `client.json` config files for a Mirage deployment.
//!
//! Replaces the manual "run keygen, read big JSON, extract fields" workflow
//! with a guided Q&A session. Supports three setup modes:
//!   1. New deployment  - generates bridge.json + client.json
//!   2. Bridge only     - generates bridge.json (existing client already configured)
//!   3. Client only     - generates client.json from an invite URL

use mirage_common::process_hardening::harden_process;
use mirage_crypto::ed25519_dalek::{Signer, SigningKey};
use mirage_crypto::x25519_dalek::{PublicKey, StaticSecret};
use mirage_discovery::invite::{MasterInvite, MAX_BOOTSTRAP_TOKENS};
use mirage_discovery::token::sign_token_jittered;
use mirage_discovery::wire::{transport_caps, Announcement, Endpoint, SIG_LEN};
use serde_json::json;
use std::io::{self, BufRead, Write};

// -- CSPRNG helpers ------------------------------------------------------------

fn rand_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    getrandom::fill(&mut s).expect("OS CSPRNG failed");
    s
}

fn hex_of(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as FmtWrite;
        write!(&mut s, "{b:02x}").unwrap();
    }
    s
}

// -- Terminal prompt helpers ---------------------------------------------------

fn flush() {
    std::io::stdout().flush().expect("stdout flush");
}

// -- Presentation: colour + banner ---------------------------------------------

/// ANSI colour is used only to give the wizard a little identity (banner, step
/// headers, ok/warn markers). It is suppressed when stdout is not a TTY (piped
/// to a file, captured by another tool) or when NO_COLOR is set, so scripted
/// runs and non-ANSI terminals stay clean.
fn colour_on() -> bool {
    use std::io::IsTerminal;
    std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
}

/// Wrap `s` in an ANSI SGR sequence when colour is enabled, else return it bare.
fn paint(s: &str, code: &str) -> String {
    if colour_on() {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

// The Mirage palette, as 256-colour ANSI codes: azure (primary), violet (echo),
// teal (ok), amber (caution), slate (muted).
const C_AZURE: &str = "38;5;75";
const C_VIOLET: &str = "38;5;141";
const C_CREST: &str = "38;5;111";
const C_TEAL: &str = "38;5;43";
const C_AMBER: &str = "38;5;179";
const C_SLATE: &str = "38;5;103";
const C_TITLE: &str = "1;38;5;189";

/// The Mirage identity banner: a peak on the horizon and its refracted mirage
/// echo, matching the logo. ASCII-only so it renders on every terminal.
fn banner() {
    println!();
    println!("      {}", paint("/\\", C_CREST));
    println!("     {}", paint("/  \\", C_CREST));
    println!(
        "    {}      {}",
        paint("/____\\", C_VIOLET),
        paint("M I R A G E", C_TITLE)
    );
    println!(
        "   {}    {}",
        paint("~~~~~~~~", C_AZURE),
        paint("censorship-resistance framework", C_SLATE)
    );
    println!("    {}", paint("\\    /", "38;5;60"));
    println!(
        "     {}     {}",
        paint("\\  /", "38;5;60"),
        paint("Don't be invisible. Be uninteresting.", C_SLATE)
    );
    println!("      {}", paint("\\/", "38;5;60"));
}

/// Print `question [default]: `, read a line.  Returns default if blank.
/// On EOF prints "\nAborted." and exits 1.
fn prompt_str(question: &str, default: &str) -> String {
    let stdin = io::stdin();
    let mut line = String::new();
    // Any input is valid (empty => default), so there is no re-prompt path:
    // the body runs exactly once. (Contrast prompt_yn / prompt_u64, which
    // genuinely loop on invalid input.)
    if default.is_empty() {
        print!("{question}: ");
    } else {
        print!("{question} [{default}]: ");
    }
    flush();
    line.clear();
    match stdin.lock().read_line(&mut line) {
        Ok(0) => {
            println!("\nAborted.");
            std::process::exit(1);
        }
        Ok(_) => {
            let trimmed = line.trim().to_string();
            if trimmed.is_empty() {
                return default.to_string();
            }
            trimmed
        }
        Err(e) => {
            eprintln!("stdin error: {e}");
            std::process::exit(1);
        }
    }
}

/// Print `question [Y/n]:` or `[y/N]:`, parse y/n.  Re-prompts on junk.
fn prompt_yn(question: &str, default_yes: bool) -> bool {
    let hint = if default_yes { "Y/n" } else { "y/N" };
    let stdin = io::stdin();
    loop {
        print!("{question} [{hint}]: ");
        flush();
        let mut line = String::new();
        match stdin.lock().read_line(&mut line) {
            Ok(0) => {
                println!("\nAborted.");
                std::process::exit(1);
            }
            Ok(_) => {
                let t = line.trim().to_lowercase();
                if t.is_empty() {
                    return default_yes;
                }
                if t == "y" || t == "yes" {
                    return true;
                }
                if t == "n" || t == "no" {
                    return false;
                }
                println!("  Invalid - try again.");
            }
            Err(e) => {
                eprintln!("stdin error: {e}");
                std::process::exit(1);
            }
        }
    }
}

/// Print `question [default]: `, parse u64.  Re-prompts on invalid.
fn prompt_u64(question: &str, default: u64) -> u64 {
    let default_str = default.to_string();
    loop {
        let raw = prompt_str(question, &default_str);
        match raw.parse::<u64>() {
            Ok(v) => return v,
            Err(_) => println!("  Invalid - try again."),
        }
    }
}

/// Present a numbered menu and return the 1-based index the operator chose.
/// `items` are `(label, blurb)` - the blurb explains *why* you'd pick it, which
/// is the difference between a wizard people tolerate and one they trust.
fn prompt_choice(title: &str, items: &[(&str, &str)], default_ix: usize) -> usize {
    println!();
    println!("{title}");
    for (i, (label, blurb)) in items.iter().enumerate() {
        println!("  {}. {:<16} {}", i + 1, label, blurb);
    }
    loop {
        let raw = prompt_str("Choice", &(default_ix + 1).to_string());
        match raw.trim().parse::<usize>() {
            Ok(v) if v >= 1 && v <= items.len() => return v - 1,
            _ => println!("  Pick 1-{}.", items.len()),
        }
    }
}

// -- Presentation -------------------------------------------------------------

const RULE: &str = "------------------------------------------------------------";

/// A numbered step header, so the operator always knows where they are.
fn section(step: u8, total: u8, title: &str) {
    println!();
    println!("{}", paint(RULE, C_SLATE));
    println!(
        "  {}  {}",
        paint(&format!("Step {step}/{total}"), C_AZURE),
        paint(title, C_TITLE)
    );
    println!("{}", paint(RULE, C_SLATE));
}

/// An indented explanatory line. Used to say WHY a question is being asked.
fn note(msg: &str) {
    println!("  {} {msg}", paint("*", C_SLATE));
}

fn warn_line(msg: &str) {
    println!("  {} {msg}", paint("!", C_AMBER));
}

/// Front-parity vetting (H2): actively probe the chosen Reality cover so a
/// typo'd / offline / non-TLS-1.3 host is caught at provisioning instead of
/// silently failing EVERY handshake at runtime. Advisory only - it runs on the
/// operator's workstation (whose path to the cover may differ from the bridge
/// host's), so a failure warns rather than aborts.
fn vet_reality_cover(cover: &str) {
    use std::net::ToSocketAddrs;
    if cover.is_empty() {
        return;
    }
    let Some(addr) = (cover, 443u16)
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
    else {
        warn_line(&format!(
            "could not resolve {cover}:443 - double-check the cover domain."
        ));
        return;
    };
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return; // no runtime available; skip the (optional) probe
    };
    let profile = rt.block_on(mirage_transport_reality::probe_cover_flight(
        addr,
        cover,
        std::time::Duration::from_secs(8),
    ));
    if profile.flight_wire_len == mirage_transport_reality::DEFAULT_COVER_FLIGHT_WIRE_LEN {
        warn_line(&format!(
            "'{cover}' did not complete a TLS 1.3 handshake from this machine."
        ));
        warn_line("If the BRIDGE host can't reach it either, ALL Reality handshakes will fail -");
        warn_line("verify the domain serves modern HTTPS and is reachable from the bridge.");
    } else {
        note(&format!(
            "cover '{cover}' verified: live TLS 1.3 (~{} B server flight).",
            profile.flight_wire_len
        ));
    }
}

fn ok_line(msg: &str) {
    println!("  {} {msg}", paint("(ok)", C_TEAL));
}

// -- Deployment profiles ------------------------------------------------------

/// A tuned starting point. Most operators should never have to answer thirty
/// questions - they pick a profile that matches their situation and adjust.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Profile {
    Balanced,
    MaxReach,
    Stealth,
    BehindCdn,
    Custom,
}

fn ask_profile() -> Profile {
    let ix = prompt_choice(
        "How should this bridge be tuned?",
        &[
            (
                "Balanced",
                "Reality + Hysteria2. The right answer for most operators.",
            ),
            (
                "Max reach",
                "Every carrier, incl. DNS + CDN fallbacks. Best odds on hostile networks.",
            ),
            (
                "Stealth",
                "Reality only, padding on, strict probe resistance. Lowest profile.",
            ),
            (
                "Behind a CDN",
                "WebSocket + meek, for nginx / Cloudflare fronting.",
            ),
            ("Custom", "Ask me about every carrier individually."),
        ],
        0,
    );
    match ix {
        0 => Profile::Balanced,
        1 => Profile::MaxReach,
        2 => Profile::Stealth,
        3 => Profile::BehindCdn,
        _ => Profile::Custom,
    }
}

// -- Preflight ----------------------------------------------------------------

/// Check the things that otherwise fail *after* the operator has answered every
/// question and copied files to a server. Cheap here, expensive later.
fn preflight(bind: &str) {
    println!();
    println!("Preflight:");

    // Port actually bindable on this host?
    match std::net::TcpListener::bind(bind) {
        Ok(l) => {
            drop(l);
            ok_line(&format!("{bind} is free and bindable"));
        }
        Err(e) => {
            let k = e.kind();
            if k == std::io::ErrorKind::AddrInUse {
                warn_line(&format!(
                    "{bind} is ALREADY IN USE - the bridge will fail to start until you free it"
                ));
            } else if k == std::io::ErrorKind::PermissionDenied {
                warn_line(&format!(
                    "{bind}: permission denied. Ports below 1024 need root or \
                     `setcap cap_net_bind_service+ep` on the binary."
                ));
            } else {
                warn_line(&format!(
                    "{bind} is not bindable on THIS machine ({e}). That is fine if you are \
                     generating a config for a different server."
                ));
            }
        }
    }

    // Privileged port reminder even when the bind succeeded (e.g. running as root).
    if let Some(port) = bind.rsplit(':').next().and_then(|p| p.parse::<u16>().ok()) {
        if port < 1024 {
            note(
                "Privileged port: run the bridge as root, or grant \
                 `setcap cap_net_bind_service+ep /usr/local/bin/mirage-bridge`.",
            );
        }
        if port == 443 {
            note("Port 443 is the best choice for blending in with ordinary HTTPS.");
        }
    }
}

// -- Endpoint parsing (copied from mirage-keygen) -----------------------------

fn parse_endpoint(s: &str) -> Endpoint {
    let (host, port) = match s.rfind(':') {
        Some(idx) => (&s[..idx], &s[idx + 1..]),
        None => {
            eprintln!("fatal: address must be host:port");
            std::process::exit(1);
        }
    };
    let port: u16 = match port.parse() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("fatal: invalid port");
            std::process::exit(1);
        }
    };
    if host.starts_with('[') && host.ends_with(']') {
        let inner = &host[1..host.len() - 1];
        let ip: std::net::Ipv6Addr = inner.parse().unwrap_or_else(|_| {
            eprintln!("fatal: invalid IPv6");
            std::process::exit(1);
        });
        return Endpoint::Ipv6 {
            addr: ip.octets(),
            port,
        };
    }
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return Endpoint::Ipv4 {
            addr: ip.octets(),
            port,
        };
    }
    Endpoint::Domain {
        domain: host.to_string(),
        port,
    }
}

/// Validate that `s` looks like `host:port` with a valid u16 port.
fn validate_bind(s: &str) -> bool {
    match s.rfind(':') {
        None => false,
        Some(idx) => s[idx + 1..].parse::<u16>().is_ok(),
    }
}

/// True if `host:port`'s host is the unspecified/wildcard address (0.0.0.0 or
/// ::). Valid as a *bind* address, never as a *dial* target in an invite.
fn is_wildcard_host(addr: &str) -> bool {
    let host = match addr.rfind(':') {
        Some(i) => &addr[..i],
        None => addr,
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.is_unspecified(),
        Err(_) => false, // a domain name is a fine dial target
    }
}

// -- Bridge key generation -----------------------------------------------------

struct BridgeKeys {
    op_sk: SigningKey,
    op_pk: [u8; 32],
    bridge_id_sk: SigningKey,
    bridge_ed_pk: [u8; 32],
    bridge_x_sk: [u8; 32],
    bridge_x_pk: [u8; 32],
    ss2022_psk_hex: Option<String>,
    /// Per-bridge secret QUIC-obfs key: embedded in the invite (ext 0x06) and
    /// written to the bridge config (`quic_obfs_secret_hex`), so QUIC
    /// obfuscation is secret-grade by default (invite holders only).
    obfs_secret: [u8; 32],
}

fn generate_bridge_keys(enable_ss2022: bool) -> BridgeKeys {
    let op_sk = SigningKey::from_bytes(&rand_seed());
    let op_pk = op_sk.verifying_key().to_bytes();

    let bridge_id_sk = SigningKey::from_bytes(&rand_seed());
    let bridge_ed_pk = bridge_id_sk.verifying_key().to_bytes();

    let bridge_x_sk_raw = StaticSecret::from(rand_seed());
    let bridge_x_pk = *PublicKey::from(&bridge_x_sk_raw).as_bytes();
    let bridge_x_sk = bridge_x_sk_raw.to_bytes();

    // NOTE: no Reality CertVerify signing key here. The bridge config this tool
    // writes runs Reality in the DEFAULT ephemeral mode: the bridge mints a
    // fresh per-boot cert and signs CertVerify with THAT cert's key, and the
    // client verifies against the cert SPKI on the wire. Baking a fixed pubkey
    // into the invite would orphan it (the ephemeral bridge never signs with
    // it), so every reality handshake would fail `CertVerify signature invalid`.
    // (mirage-keygen already learned this - see its invite comment.) A pinned
    // deployment is a separate opt-in that also writes reality_tls_mode=pinned +
    // reality_tls_signing_sk_hex to the bridge config.
    let ss2022_psk_hex = if enable_ss2022 {
        let mut psk = [0u8; 32];
        getrandom::fill(&mut psk).expect("OS CSPRNG failed");
        Some(hex_of(&psk))
    } else {
        None
    };

    BridgeKeys {
        op_sk,
        op_pk,
        bridge_id_sk,
        bridge_ed_pk,
        bridge_x_sk,
        bridge_x_pk,
        ss2022_psk_hex,
        obfs_secret: rand_seed(),
    }
}

// -- Bridge transport questions ------------------------------------------------

struct TransportChoices {
    reality: bool,
    reality_cover: String,
    hysteria2: bool,
    hysteria2_mbps: u64,
    ss2022: bool,
    ws: bool,
    /// CDN front domain for the meek carrier (client fronts through it). `Some`
    /// advertises the MEEK cap in the invite; the bridge serves meek on any
    /// authenticated HTTP POST, so no bridge flag is needed.
    meek_front_domain: Option<String>,
    /// WebRTC data-channel carrier (needs an HTTPS signaling broker).
    webrtc: bool,
    webrtc_signaling_host: String,
    webrtc_ice_servers: Vec<String>,
    /// MASQUE / HTTP-3 carrier - the session rides inside HTTP/3 DATA frames.
    masque: bool,
    masque_hostname: String,
    /// DNS-over-HTTPS carrier (client fronts through a public DoH provider).
    doh_front_domain: Option<String>,
    /// Full DNS tunnel. Last-resort carrier for networks where only DNS escapes.
    /// Needs a delegated domain whose NS record points at this bridge.
    dnstt_domain: Option<String>,
    /// VLESS framing (UUID auth) for interop with existing infrastructure.
    vless: bool,
    /// Multiplex many streams over one carrier connection.
    stream_mux: bool,
    shadow_target: Option<String>,
    pad_enabled: bool,
    pad_cbr: bool,
    pad_cbr_frame_bytes: usize,
    pad_cbr_interval_ms: u64,
}

/// Ask only what the chosen profile cannot infer.
///
/// A profile fixes the carrier *set*; anything that is deployment-specific and
/// genuinely unguessable (a cover domain, a CDN front, a delegated DNS zone) is
/// still asked, because a wrong default there is worse than a question.
fn ask_bridge_transports(profile: Profile) -> TransportChoices {
    let custom = profile == Profile::Custom;

    // Carrier set implied by the profile.
    let (mut reality, mut hysteria2, mut ss2022, mut ws, mut webrtc, mut masque, mut vless) =
        match profile {
            Profile::Balanced => (true, true, false, false, false, false, false),
            Profile::MaxReach => (true, true, true, true, true, true, false),
            Profile::Stealth => (true, false, false, false, false, false, false),
            Profile::BehindCdn => (false, false, false, true, false, false, false),
            Profile::Custom => (true, true, false, false, false, false, false),
        };
    let mut want_meek = matches!(profile, Profile::MaxReach | Profile::BehindCdn);
    let mut want_doh = profile == Profile::MaxReach;
    let mut want_dnstt = profile == Profile::MaxReach;
    let mut pad_enabled = profile == Profile::Stealth;
    let mut stream_mux = profile != Profile::Stealth;

    if custom {
        println!();
        println!("Carriers - each one is a different wire shape. More carriers = more");
        println!("ways through a hostile network, at the cost of a larger attack surface.");
        reality = prompt_yn("Reality TLS (looks like real HTTPS - recommended)", true);
        hysteria2 = prompt_yn(
            "Hysteria2 QUIC (same UDP port as TCP; looks like HTTP/3)",
            true,
        );
        masque = prompt_yn("MASQUE / HTTP-3 (session inside HTTP/3 DATA frames)", false);
        ss2022 = prompt_yn("Shadowsocks-2022 (opaque, fast)", false);
        ws = prompt_yn("WebSocket (HTTP upgrade - CDN/nginx friendly)", false);
        vless = prompt_yn(
            "VLESS framing (UUID auth; interop with existing setups)",
            false,
        );
        webrtc = prompt_yn("WebRTC data channel (looks like a video call)", false);
        want_meek = prompt_yn("meek (domain-fronted HTTP long-poll via a CDN)", false);
        want_doh = prompt_yn("DoH (carrier hidden in DNS-over-HTTPS)", false);
        want_dnstt = prompt_yn("dnstt (full DNS tunnel - last resort, slow)", false);
        stream_mux = prompt_yn("Stream multiplexing (many streams per connection)", true);
    } else {
        println!();
        note("Carrier set chosen by profile; you can edit bridge.json afterwards.");
    }

    // Deployment-specific values the profile cannot guess.
    let reality_cover = if reality {
        println!();
        note("Unauthenticated probes get a real TLS session with this host, so a");
        note("scanner sees an ordinary site instead of a bridge. Use a real HTTPS site.");
        let cover = prompt_str("  Reality cover domain", "www.microsoft.com");
        vet_reality_cover(&cover);
        cover
    } else {
        String::new()
    };

    let hysteria2_mbps = if hysteria2 && custom {
        prompt_u64("  Hysteria2 send rate (Mbps)", 100)
    } else {
        100
    };

    let masque_hostname = if masque {
        prompt_str("  HTTP/3 hostname to present", "www.cloudflare.com")
    } else {
        String::new()
    };

    let meek_front_domain = if want_meek {
        println!();
        note("meek fronts through a CDN: clients connect to the CDN's domain, which");
        note("forwards to your bridge. Blocking it means blocking the whole CDN.");
        let d = prompt_str("  CDN front domain", "ajax.aspnetcdn.com");
        if d.is_empty() {
            None
        } else {
            Some(d)
        }
    } else {
        None
    };

    let doh_front_domain = if want_doh {
        let d = prompt_str("  DoH front domain", "cloudflare-dns.com");
        if d.is_empty() {
            None
        } else {
            Some(d)
        }
    } else {
        None
    };

    let dnstt_domain = if want_dnstt {
        println!();
        note("dnstt needs a domain you control, with an NS record delegating a");
        note("subdomain to this bridge's IP. Leave blank to skip.");
        let d = prompt_str("  Delegated DNS zone (e.g. t.example.com)", "");
        if d.is_empty() {
            None
        } else {
            Some(d)
        }
    } else {
        None
    };

    let (webrtc_signaling_host, webrtc_ice_servers) = if webrtc {
        let host = prompt_str(
            "  WebRTC signaling host (HTTPS broker clients reach)",
            "signal.example.com",
        );
        let ice = prompt_str(
            "  STUN/TURN servers (blank = built-in; comma-separated)",
            "",
        );
        let ice_servers: Vec<String> = ice
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        (host, ice_servers)
    } else {
        (String::new(), Vec::new())
    };

    // Active-probe resistance.
    println!();
    note("Unrecognised connections can be forwarded to a decoy host, so a scanner");
    note("that probes this port sees a normal server rather than a silent one.");
    let shadow_target = if prompt_yn("Forward unrecognised connections to a decoy", true) {
        Some(prompt_str(
            "  Decoy host:port (a real HTTPS server)",
            "1.1.1.1:443",
        ))
    } else {
        warn_line("Without a decoy, a scanner can tell this port is 'something unusual'.");
        None
    };

    // Traffic-shape concealment.
    if custom {
        println!();
        note("Padding + jitter hide packet-size and timing patterns from ML flow");
        note("classifiers. Costs bandwidth. The client MUST use the same setting.");
        pad_enabled = prompt_yn("Enable frame padding + timing jitter", pad_enabled);
    } else if pad_enabled {
        note("Padding enabled by profile (clients must set pad_enabled too).");
    }
    let (pad_cbr, pad_cbr_frame_bytes, pad_cbr_interval_ms) = if pad_enabled && custom {
        if prompt_yn(
            "  Constant-bitrate mode? (perfect concealment, high cost)",
            false,
        ) {
            let frame = prompt_u64("  CBR frame size (bytes)", 1024) as usize;
            let interval = prompt_u64("  CBR interval (ms)", 10);
            (true, frame, interval)
        } else {
            (false, 0, 0)
        }
    } else {
        (false, 0, 0)
    };

    TransportChoices {
        reality,
        reality_cover,
        hysteria2,
        hysteria2_mbps,
        ss2022,
        ws,
        meek_front_domain,
        webrtc,
        webrtc_signaling_host,
        webrtc_ice_servers,
        masque,
        masque_hostname,
        doh_front_domain,
        dnstt_domain,
        vless,
        stream_mux,
        shadow_target,
        pad_enabled,
        pad_cbr,
        pad_cbr_frame_bytes,
        pad_cbr_interval_ms,
    }
}

/// Human-readable list of the carriers this deployment actually turned on.
/// Single source of truth for both the pre-write review and the final summary.
fn active_transport_names(t: &TransportChoices) -> Vec<&'static str> {
    let mut active: Vec<&str> = Vec::new();
    if t.reality {
        active.push("reality");
    }
    if t.hysteria2 {
        active.push("hysteria2");
    }
    if t.masque {
        active.push("masque/h3");
    }
    if t.ss2022 {
        active.push("shadowsocks-2022");
    }
    if t.ws {
        active.push("websocket");
    }
    if t.vless {
        active.push("vless");
    }
    if t.meek_front_domain.is_some() {
        active.push("meek");
    }
    if t.doh_front_domain.is_some() {
        active.push("doh");
    }
    if t.dnstt_domain.is_some() {
        active.push("dnstt");
    }
    if t.webrtc {
        active.push("webrtc");
    }
    if active.is_empty() {
        active.push("raw");
    }
    active
}

// -- Bridge config JSON builder ------------------------------------------------

fn build_bridge_config(
    bind: &str,
    keys: &BridgeKeys,
    transports: &TransportChoices,
    max_sessions: u64,
) -> serde_json::Value {
    let mut cfg = json!({
        "bind": bind,
        "bridge_x25519_sk_hex": hex_of(&keys.bridge_x_sk),
        "bridge_ed25519_pk_hex": hex_of(&keys.bridge_ed_pk),
        "bridge_ed25519_sk_hex": hex_of(&keys.bridge_id_sk.to_bytes()),
        "operator_ed25519_pk_hex": hex_of(&keys.op_pk),
        // Matches the obfs_secret embedded in the invite (ext 0x06): QUIC
        // obfuscation is secret-grade by default, synced across both outputs.
        "quic_obfs_secret_hex": hex_of(&keys.obfs_secret),
        "replay_capacity": 65536,
        "handshake_timeout_secs": 10,
        "max_concurrent_sessions": max_sessions,
        "socks5_connect_timeout_secs": 10,
        "allow_private_network_targets": false,
        "allow_loopback_targets": false,
    });

    let m = cfg.as_object_mut().unwrap();

    if transports.reality {
        m.insert("reality_enabled".to_string(), json!(true));
        m.insert(
            "reality_cover_addr".to_string(),
            json!(format!("{}:443", transports.reality_cover)),
        );
        m.insert(
            "reality_client_hello_timeout_secs".to_string(),
            json!(10u64),
        );
        m.insert("reality_cover_duration_cap_secs".to_string(), json!(30u64));
        // Fresh deployment: every invite this tool mints carries a probe_root, so
        // NO legacy-probe clients can exist for this brand-new bridge key. Reject
        // legacy probes from the start to close pubkey-only enumeration (the
        // daemon's rollover-safe default is the permissive `true`).
        m.insert("reality_probe_accept_legacy".to_string(), json!(false));
    }

    if transports.hysteria2 {
        m.insert("hysteria2_enabled".to_string(), json!(true));
        m.insert(
            "hysteria2_send_rate_mbps".to_string(),
            json!(transports.hysteria2_mbps),
        );
    }

    if let Some(ref psk) = keys.ss2022_psk_hex {
        m.insert("ss2022_psk_hex".to_string(), json!(psk));
    }

    if transports.ws {
        m.insert("ws_enabled".to_string(), json!(true));
    }

    // meek needs no bridge flag: the bridge serves it on any authenticated HTTP
    // POST that isn't WebSocket/DoH. The client's meek_front_domain + the invite
    // MEEK cap are what enable it end to end.

    if transports.webrtc {
        m.insert("webrtc_enabled".to_string(), json!(true));
        if !transports.webrtc_ice_servers.is_empty() {
            m.insert(
                "webrtc_ice_servers".to_string(),
                json!(transports.webrtc_ice_servers),
            );
        }
    }

    if transports.masque {
        m.insert("h3_enabled".to_string(), json!(true));
        if !transports.masque_hostname.is_empty() {
            m.insert("h3_hostname".to_string(), json!(transports.masque_hostname));
        }
    }

    if let Some(ref zone) = transports.dnstt_domain {
        m.insert("dnstt_enabled".to_string(), json!(true));
        m.insert("dnstt_domain".to_string(), json!(zone));
    }

    if transports.vless {
        // UUID-shaped auth token for the VLESS framing layer.
        m.insert(
            "vless_uuid_hex".to_string(),
            json!(hex_of(&rand_seed()[..16])),
        );
    }

    if transports.stream_mux {
        m.insert("stream_mux_enabled".to_string(), json!(true));
    }

    if let Some(ref tgt) = transports.shadow_target {
        m.insert("shadow_target".to_string(), json!(tgt));
    }

    if transports.pad_enabled {
        m.insert("pad_enabled".to_string(), json!(true));
        if transports.pad_cbr {
            m.insert(
                "pad_cbr_frame_bytes".to_string(),
                json!(transports.pad_cbr_frame_bytes),
            );
            m.insert(
                "pad_cbr_interval_ms".to_string(),
                json!(transports.pad_cbr_interval_ms),
            );
        }
    }

    cfg
}

// -- Invite / token minting ----------------------------------------------------

struct InviteParams {
    bootstrap_tokens: usize,
    token_ttl_hours: u64,
    invite_ttl_hours: u64,
}

fn mint_invite(
    keys: &BridgeKeys,
    endpoint_str: &str,
    transports: &TransportChoices,
    params: &InviteParams,
) -> String {
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let token_expires_at = now_unix + params.token_ttl_hours * 3600;
    let invite_expires_at = now_unix + params.invite_ttl_hours * 3600;

    let endpoint = parse_endpoint(endpoint_str);

    let mut t_caps = 0u32;
    if transports.reality {
        t_caps |= transport_caps::REALITY_V2;
    }
    if transports.hysteria2 {
        t_caps |= transport_caps::HYSTERIA2;
    }
    if transports.ss2022 {
        t_caps |= transport_caps::SHADOWSOCKS_2022;
    }
    if transports.ws {
        t_caps |= transport_caps::WS_TUNNEL;
    }
    if transports.meek_front_domain.is_some() {
        t_caps |= transport_caps::MEEK;
    }
    if transports.webrtc {
        t_caps |= transport_caps::WEBRTC;
    }
    // Fallback: at least one cap bit should be set
    if t_caps == 0 {
        t_caps = transport_caps::REALITY_V2;
    }

    let mut announcement = Announcement {
        issued_at: now_unix,
        expires_at: invite_expires_at,
        bridge_ed25519_pk: keys.bridge_ed_pk,
        bridge_x25519_pk: keys.bridge_x_pk,
        transport_caps: t_caps,
        endpoint,
        extra_endpoints: Vec::new(),
        signature: [0u8; SIG_LEN],
    };
    let mut ann_prefix = Vec::new();
    announcement.encode_signed_prefix(&mut ann_prefix);
    announcement.signature = keys.op_sk.sign(&ann_prefix).to_bytes();

    let n_tokens = params.bootstrap_tokens.min(MAX_BOOTSTRAP_TOKENS);
    let token_jitter = (params.token_ttl_hours * 3600) / 2;
    let tokens: Vec<_> = (0..n_tokens)
        .map(|_| {
            let tid = rand_seed();
            sign_token_jittered(
                tid,
                keys.bridge_ed_pk,
                token_expires_at,
                token_jitter,
                &keys.op_sk,
            )
        })
        .collect();

    // Forward-secure bootstrap tokens, minted automatically alongside the legacy
    // ones (dual-mint): a capable client presents an FS token, an older client
    // ignores the extension and uses the legacy tokens. cert_valid_until =
    // invite expiry so the epoch subkey lives exactly as long as the invite.
    let fs_tokens = mirage_discovery::token_fs::mint_fs_tokens(
        &keys.op_sk,
        keys.bridge_ed_pk,
        now_unix,
        invite_expires_at,
        token_expires_at,
        token_jitter,
        n_tokens,
    )
    .unwrap_or_else(|e| {
        eprintln!("fatal: fs token mint: {e}");
        std::process::exit(1);
    });

    let shared_salt = rand_seed();
    let claim_id = rand_seed();

    let invite = MasterInvite::new_with_extensions(
        keys.op_pk,
        shared_salt,
        now_unix,
        invite_expires_at,
        Vec::new(),
        tokens,
        Some(announcement),
        // tls_cert_verify_pk = None: ephemeral reality mode (see generate_bridge_keys).
        // The client verifies CertVerify against the bridge's per-boot cert SPKI.
        None,
        Some(claim_id),
        None,
        None,
        None, // port_hop - use mirage-keygen --port-base/--port-range to enable
    )
    .unwrap_or_else(|e| {
        eprintln!("fatal: invite build: {e}");
        std::process::exit(1);
    })
    .with_obfs_secret(keys.obfs_secret)
    // Reality anti-probe root, derived from the bridge's X25519 static secret so
    // the bridge re-derives the SAME value at runtime with no extra config.
    .with_probe_root(mirage_transport_reality::derive_probe_root(
        &keys.bridge_x_sk,
    ))
    .with_fs_bootstrap_tokens(fs_tokens);

    format!("mirage://{}", invite.encode_text())
}

// -- Client config JSON builder ------------------------------------------------

// Internal single-call helper: each parameter is a distinct CLI flag mapped 1:1
// into the client-config JSON. A params struct would add indirection without
// reducing the essential arity.
#[allow(clippy::too_many_arguments)]
fn build_client_config(
    local_bind: &str,
    invite_url: &str,
    reality: bool,
    reality_sni: &str,
    hysteria2: bool,
    hysteria2_mbps: u64,
    ss2022_psk_hex: Option<&str>,
    ws: bool,
    ws_path: &str,
    meek_front_domain: Option<&str>,
    webrtc_signaling_host: Option<&str>,
    webrtc_ice_servers: &[String],
    pad_enabled: bool,
    pad_cbr: bool,
    pad_cbr_frame_bytes: usize,
    pad_cbr_interval_ms: u64,
    nostr_relays: &[String],
    dns_discovery_apexes: &[String],
    dht_enabled: bool,
) -> serde_json::Value {
    let mut cfg = json!({
        "local_bind": local_bind,
        "invite": invite_url,
        "handshake_timeout_secs": 10,
    });

    let m = cfg.as_object_mut().unwrap();

    if reality {
        m.insert("reality_enabled".to_string(), json!(true));
        m.insert("reality_sni".to_string(), json!(reality_sni));
    }

    if hysteria2 {
        m.insert("hysteria2_enabled".to_string(), json!(true));
        m.insert(
            "hysteria2_send_rate_mbps".to_string(),
            json!(hysteria2_mbps),
        );
    }

    if let Some(psk) = ss2022_psk_hex {
        m.insert("ss2022_psk_hex".to_string(), json!(psk));
    }

    if ws {
        m.insert("ws_enabled".to_string(), json!(true));
        m.insert("ws_path".to_string(), json!(ws_path));
    }

    if let Some(front) = meek_front_domain {
        m.insert("meek_front_domain".to_string(), json!(front));
        m.insert("meek_path".to_string(), json!("/"));
    }

    if let Some(host) = webrtc_signaling_host {
        m.insert("webrtc_signaling_host".to_string(), json!(host));
        m.insert("webrtc_path".to_string(), json!("/webrtc/offer"));
        if !webrtc_ice_servers.is_empty() {
            m.insert("webrtc_ice_servers".to_string(), json!(webrtc_ice_servers));
        }
    }

    if pad_enabled {
        m.insert("pad_enabled".to_string(), json!(true));
        if pad_cbr {
            m.insert(
                "pad_cbr_frame_bytes".to_string(),
                json!(pad_cbr_frame_bytes),
            );
            m.insert(
                "pad_cbr_interval_ms".to_string(),
                json!(pad_cbr_interval_ms),
            );
        }
    }

    if !nostr_relays.is_empty() {
        m.insert("nostr_relays".to_string(), json!(nostr_relays));
    }
    if !dns_discovery_apexes.is_empty() {
        m.insert(
            "dns_discovery_apexes".to_string(),
            json!(dns_discovery_apexes),
        );
    }
    if dht_enabled {
        // Fetch bridge announcements from the BitTorrent mainline DHT (BEP-44).
        // Empty bootstrap list = the mainline crate's built-in bootstrap nodes.
        m.insert("dht_enabled".to_string(), json!(true));
    }
    if !nostr_relays.is_empty() || !dns_discovery_apexes.is_empty() || dht_enabled {
        m.insert("discovery_interval_secs".to_string(), json!(300u64));
    }

    cfg
}

// -- Post-write summary printer ------------------------------------------------

// Internal single-call helper: parameters mirror the CLI flags / computed paths
// printed in the setup summary; a params struct would not reduce the arity.
#[allow(clippy::too_many_arguments)]
fn print_summary(
    bind: &str,
    public_addr: &str,
    transports: &[&str],
    bridge_pk_hex: &str,
    bridge_path: Option<&str>,
    client_path: Option<&str>,
    invite_url: &str,
    n_tokens: usize,
    token_ttl_hours: u64,
    invite_ttl_hours: u64,
    publish_relay_urls: &[String],
    dht_enabled: bool,
) {
    let sep = "-".repeat(57);
    println!();
    println!("{}", paint(&sep, C_SLATE));
    println!("  {}", paint("Mirage deployment configured.", "1;38;5;43"));
    println!();
    println!("  Bridge:     {bind}  (public: {public_addr})");
    let t_list = transports.join(", ");
    println!("  Transports: {t_list}");
    let pk_short = &bridge_pk_hex[..16.min(bridge_pk_hex.len())];
    println!("  Bridge PK:  {pk_short}...   (first 16 hex chars - audit at startup)");
    println!();
    println!("  Files written:");
    if let Some(bp) = bridge_path {
        println!("    {bp:<14}->  copy to server, run: mirage-bridge {bp}");
    }
    if let Some(cp) = client_path {
        println!("    {cp:<14}->  distribute to users, run: mirage-client {cp}");
    }
    println!();
    println!("  Invite URL (share with clients instead of client.json):");
    println!("  {invite_url}");
    println!();
    println!(
        "  Tokens: {n_tokens} x {token_ttl_hours} h validity (invite valid {invite_ttl_hours} h from now)"
    );
    if !publish_relay_urls.is_empty() || dht_enabled {
        println!();
        println!("  Auto-announcement (run on your operator workstation, not the bridge):");
        let relay_flags: String = publish_relay_urls
            .iter()
            .map(|u| format!(" \\\n      --relay {u}"))
            .collect();
        let dht_flag = if dht_enabled { " \\\n      --dht" } else { "" };
        println!("    mirage-publish --daemon --from keygen.json{relay_flags}{dht_flag}");
        if dht_enabled && publish_relay_urls.is_empty() {
            println!(
                "    (--dht announces on the mainline DHT; add --relay wss://<url> for Nostr too.)"
            );
        }
    } else {
        println!();
        println!("  Announcement publishing (pick at least one channel):");
        println!(
            "    mirage-publish --from keygen.json --dht            # BitTorrent mainline DHT"
        );
        println!(
            "    mirage-publish --from keygen.json --relay wss://<relay> [--relay ...]  # Nostr"
        );
        println!("    Add --daemon to keep republishing on every epoch boundary (~1 h).");
    }

    // A crisp, ordered checklist so the operator knows exactly what to do next.
    println!();
    println!("  {}", paint("Next steps:", C_TITLE));
    let mut step = 1u8;
    if let Some(bp) = bridge_path {
        println!(
            "  {}. Copy {bp} to your server and start it:  {}",
            step,
            paint(&format!("mirage-bridge {bp}"), C_AZURE)
        );
        step += 1;
    }
    if !publish_relay_urls.is_empty() || dht_enabled {
        println!(
            "  {step}. Run the {} command above on your workstation to announce the bridge.",
            paint("mirage-publish", C_AZURE)
        );
    } else {
        println!(
            "  {step}. Publish an announcement ({} above) so clients can find the bridge.",
            paint("mirage-publish", C_AZURE)
        );
    }
    step += 1;
    println!(
        "  {step}. Share the invite with users: run {}, or paste it into the GUI.",
        paint("mirage-client <invite>", C_AZURE)
    );

    println!("{}", paint(&sep, C_SLATE));
}

// -- Write helper --------------------------------------------------------------

/// Write a config file.
///
/// These files carry PRIVATE KEY MATERIAL (`bridge_ed25519_sk_hex`,
/// `bridge_x25519_sk_hex`, PSKs) or a bearer invite, so:
///   * an existing file is never silently clobbered - losing a bridge's identity
///     key silently would invalidate every invite already handed out;
///   * the file is created 0600 on Unix, so it is not world-readable on a shared
///     host the moment it lands.
fn write_json(path: &str, value: &serde_json::Value) {
    if std::path::Path::new(path).exists() {
        println!();
        warn_line(&format!("{path} already exists."));
        note("Overwriting a bridge config REPLACES its identity key, which");
        note("invalidates every invite you have already distributed.");
        if !prompt_yn(&format!("  Overwrite {path}?"), false) {
            println!("  Left {path} untouched. Aborting so nothing is half-written.");
            std::process::exit(1);
        }
    }

    // Config files embed private keys / a bearer invite - write 0600 atomically
    // (no world-readable window, no symlink redirect). See secure_file.
    if let Err(e) = mirage_common::secure_file::write_secret_json(path, value) {
        eprintln!("error: could not write {path}: {e}");
        std::process::exit(1);
    }
}

/// Emit a ready-to-install systemd unit, so "deploy" is a copy and two commands
/// rather than a research project. Hardening directives are included because a
/// bridge is an internet-facing daemon holding long-term keys.
fn write_systemd_unit(path: &str, bridge_cfg_path: &str, bind: &str) {
    let privileged = bind
        .rsplit(':')
        .next()
        .and_then(|p| p.parse::<u16>().ok())
        .is_some_and(|p| p < 1024);
    let caps = if privileged {
        "AmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE"
    } else {
        "CapabilityBoundingSet="
    };
    let unit = format!(
        "[Unit]\n\
         Description=Mirage bridge\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart=/usr/local/bin/mirage-bridge /etc/mirage/{cfg}\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         DynamicUser=yes\n\
         StateDirectory=mirage\n\
         {caps}\n\
         NoNewPrivileges=yes\n\
         PrivateTmp=yes\n\
         PrivateDevices=yes\n\
         ProtectSystem=strict\n\
         ProtectHome=yes\n\
         ProtectKernelTunables=yes\n\
         ProtectKernelModules=yes\n\
         ProtectControlGroups=yes\n\
         RestrictAddressFamilies=AF_INET AF_INET6\n\
         RestrictNamespaces=yes\n\
         LockPersonality=yes\n\
         MemoryDenyWriteExecute=yes\n\
         SystemCallArchitectures=native\n\
         SystemCallFilter=@system-service\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        cfg = bridge_cfg_path,
        caps = caps,
    );
    if let Err(e) = std::fs::write(path, unit) {
        warn_line(&format!("could not write {path}: {e}"));
    }
}

fn setup_bridge_and_client(generate_client: bool) {
    let total_steps: u8 = if generate_client { 6 } else { 5 };

    section(1, total_steps, "Where the bridge listens");
    note("The bind address is what the bridge opens locally. 0.0.0.0 means");
    note("'every interface', which is usually what you want on a server.");
    let bind = loop {
        let v = prompt_str("Bridge bind address (all interfaces)", "0.0.0.0:443");
        if validate_bind(&v) {
            break v;
        }
        println!("  Invalid - try again.");
    };
    preflight(&bind);

    // 2. Public address clients dial. Baked verbatim into the invite, so it MUST
    // be a routable destination - never the wildcard bind address (0.0.0.0 / ::).
    // The wildcard is a bind-only placeholder no client can connect to: hysteria2
    // refuses it ("invalid remote address"), and reality only limps through by the
    // OS routing 0.0.0.0 -> localhost on the same machine. Re-prompt until valid.
    let public_addr = loop {
        let public_raw = prompt_str("Public address clients will connect to", "same as bind");
        let candidate = if public_raw == "same as bind" || public_raw.is_empty() {
            bind.clone()
        } else {
            public_raw
        };
        if is_wildcard_host(&candidate) {
            println!(
                "  '{candidate}' is a wildcard/unspecified address - clients cannot dial it.\n  \
                 Enter the bridge's real reachable address: its LAN/public IP, or\n  \
                 127.0.0.1 for same-machine testing."
            );
            continue;
        }
        break candidate;
    };

    section(2, total_steps, "How it blends in");
    let profile = ask_profile();
    let transports = ask_bridge_transports(profile);

    section(3, total_steps, "Capacity and invite lifetime");
    let max_sessions = prompt_u64("Max concurrent sessions", 4096);
    let n_tokens_raw = prompt_u64(
        "Bootstrap tokens (client uses one per session until invite expires)",
        16,
    );
    let n_tokens = (n_tokens_raw as usize).min(MAX_BOOTSTRAP_TOKENS);
    let token_ttl_hours = prompt_u64("Token validity in hours", 24);
    let invite_ttl_hours = prompt_u64("Invite validity in hours", 168);

    // 4b. Announcement relay URLs - used only in the setup summary to
    //     generate the `mirage-publish --daemon` command for operators.
    //     The bridge itself never connects to Nostr; publishing stays on
    //     the operator's workstation where the signing key lives.
    println!();
    let publish_nostr = prompt_yn(
        "Configure Nostr relay URLs for auto-announcement publishing?",
        false,
    );
    let publish_relay_urls: Vec<String> = if publish_nostr {
        let raw = prompt_str(
            "  Nostr relay WebSocket URLs (comma-separated)",
            "wss://relay.damus.io,wss://nos.lol",
        );
        raw.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        Vec::new()
    };

    // Mainline DHT (BEP-44): censorship-resistant discovery with no relay list to
    // block. Announcements are stored across the global BitTorrent DHT under the
    // per-epoch info-hash and fetched by clients with the operator pubkey. When
    // enabled, the client fetches from the DHT and the printed mirage-publish
    // command gets `--dht`. Recommended default.
    let dht_enabled = prompt_yn(
        "Announce on + discover via the mainline DHT (BEP-44, no relay list to block)",
        true,
    );

    // 5. Output paths
    println!();
    let bridge_path = prompt_str("Write bridge config to", "bridge.json");
    let client_path = if generate_client {
        Some(prompt_str("Write client config to", "client.json"))
    } else {
        None
    };

    // Multi-hop: does this bridge also relay circuits for other bridges? A relay
    // forwards an onion-wrapped cell to the next hop without being able to read
    // it, so no single bridge sees both who the user is and where they are going.
    println!();
    note("A relay-enabled bridge can act as a middle hop in a 3-hop circuit,");
    note("so no single bridge sees both the user and their destination.");
    let relay_enabled = prompt_yn("Allow this bridge to relay circuits for others", false);

    // Generate key material
    let keys = generate_bridge_keys(transports.ss2022);

    // Mint invite
    let invite_params = InviteParams {
        bootstrap_tokens: n_tokens,
        token_ttl_hours,
        invite_ttl_hours,
    };
    let invite_url = mint_invite(&keys, &public_addr, &transports, &invite_params);

    // Build bridge config
    let mut bridge_cfg = build_bridge_config(&bind, &keys, &transports, max_sessions);
    if relay_enabled {
        bridge_cfg
            .as_object_mut()
            .expect("bridge config is an object")
            .insert("circuit_relay_enabled".to_string(), json!(true));
    }

    // Review before anything touches the disk.
    println!();
    println!("{RULE}");
    println!("  Review");
    println!("{RULE}");
    println!("  Listening on   {bind}");
    println!("  Clients dial   {public_addr}");
    println!(
        "  Carriers       {}",
        active_transport_names(&transports).join(", ")
    );
    println!(
        "  Probe decoy    {}",
        transports
            .shadow_target
            .as_deref()
            .unwrap_or("none (scanner can tell this port is unusual)")
    );
    println!(
        "  Padding        {}",
        if transports.pad_enabled { "on" } else { "off" }
    );
    println!(
        "  Relays circuits {}",
        if relay_enabled { "yes" } else { "no" }
    );
    println!(
        "  Writing        {bridge_path}{}",
        match client_path {
            Some(ref c) => format!(", {c}"),
            None => String::new(),
        }
    );
    println!();
    if !prompt_yn("Write these files?", true) {
        println!("Nothing written. Re-run mirage-setup to start over.");
        std::process::exit(0);
    }

    write_json(&bridge_path, &bridge_cfg);

    // Build and write client config (setup type 1 only)
    let client_path_written = if let Some(ref cp) = client_path {
        let client_cfg = build_client_config(
            "127.0.0.1:1080",
            &invite_url,
            transports.reality,
            &transports.reality_cover,
            transports.hysteria2,
            transports.hysteria2_mbps,
            keys.ss2022_psk_hex.as_deref(),
            transports.ws,
            "/",
            transports.meek_front_domain.as_deref(),
            if transports.webrtc_signaling_host.is_empty() {
                None
            } else {
                Some(transports.webrtc_signaling_host.as_str())
            },
            &transports.webrtc_ice_servers,
            transports.pad_enabled,
            transports.pad_cbr,
            transports.pad_cbr_frame_bytes,
            transports.pad_cbr_interval_ms,
            &[], // nostr_relays: operator fills in after deployment
            &[], // dns_discovery_apexes: operator fills in after deployment
            dht_enabled,
        );
        let mut client_cfg = client_cfg;
        {
            let m = client_cfg
                .as_object_mut()
                .expect("client config is an object");
            if let Some(ref doh) = transports.doh_front_domain {
                m.insert("doh_front_domain".to_string(), json!(doh));
            }
            if let Some(ref zone) = transports.dnstt_domain {
                m.insert("dnstt_enabled".to_string(), json!(true));
                m.insert("dnstt_domain".to_string(), json!(zone));
            }
            // Whole-device VPN. Always compiled into the client; this only flips
            // the runtime switch (it additionally needs CAP_NET_ADMIN, or
            // Administrator on Windows).
            println!();
            note("TUN mode routes the WHOLE device through Mirage - no per-app proxy");
            note("setup. It needs CAP_NET_ADMIN (Linux/macOS) or Administrator (Windows).");
            if prompt_yn("Enable whole-device VPN (TUN) in the client config", false) {
                m.insert("tun_enabled".to_string(), json!(true));
            }
        }
        write_json(cp, &client_cfg);
        Some(cp.as_str())
    } else {
        None
    };

    // Deployment artifact: a hardened systemd unit, so shipping this to a server
    // is a copy plus two commands instead of a research project.
    println!();
    if prompt_yn("Also write a hardened systemd unit for this bridge", true) {
        let unit_path = prompt_str("  Write unit to", "mirage-bridge.service");
        write_systemd_unit(&unit_path, &bridge_path, &bind);
        ok_line(&format!("{unit_path} written"));
        note("Install with:");
        note(&format!(
            "  sudo install -Dm600 {bridge_path} /etc/mirage/{bridge_path}"
        ));
        note(&format!(
            "  sudo install -Dm644 {unit_path} /etc/systemd/system/{unit_path}"
        ));
        note("  sudo systemctl daemon-reload && sudo systemctl enable --now mirage-bridge");
    }

    // Collect active transport names for summary
    let active = active_transport_names(&transports);

    let bridge_pk_hex = hex_of(&keys.bridge_ed_pk);

    println!(
        "\nDone. Written: {bridge_path}{}",
        client_path_written
            .map(|p| format!(", {p}"))
            .unwrap_or_default()
    );

    print_summary(
        &bind,
        &public_addr,
        &active,
        &bridge_pk_hex,
        Some(bridge_path.as_str()),
        client_path_written,
        &invite_url,
        n_tokens,
        token_ttl_hours,
        invite_ttl_hours,
        &publish_relay_urls,
        dht_enabled,
    );
}

fn setup_client_from_invite() {
    // 1. Invite URL
    let invite_url = loop {
        let v = prompt_str("Paste invite URL (mirage://...)", "");
        if v.is_empty() {
            eprintln!("error: invite URL is required");
            std::process::exit(1);
        }
        if v.starts_with("mirage://") {
            break v;
        }
        println!("  Invalid - try again. (URL must start with mirage://)");
    };

    // 2. Local bind
    let local_bind = loop {
        let v = prompt_str("Local SOCKS5 bind address", "127.0.0.1:1080");
        if validate_bind(&v) {
            break v;
        }
        println!("  Invalid - try again.");
    };

    // 3. Transport questions
    println!();
    let reality = prompt_yn("Enable Reality TLS", true);
    let reality_sni = if reality {
        prompt_str("  Reality SNI (cover domain)", "www.example.com")
    } else {
        String::new()
    };

    let hysteria2 = prompt_yn("Enable Hysteria2 QUIC", false);
    let hysteria2_mbps = if hysteria2 {
        prompt_u64("  Send rate in Mbps", 100)
    } else {
        100
    };

    let ss2022 = prompt_yn("Enable Shadowsocks-2022", false);
    let ss2022_psk_hex: Option<String> = if ss2022 {
        let psk = prompt_str("  SS-2022 PSK hex (from bridge operator)", "");
        if psk.is_empty() {
            eprintln!("error: SS-2022 PSK is required when SS-2022 is enabled");
            std::process::exit(1);
        }
        Some(psk)
    } else {
        None
    };

    let ws = prompt_yn("Enable WebSocket", false);
    let ws_path = if ws {
        prompt_str("  WebSocket path", "/")
    } else {
        "/".to_string()
    };

    let meek_front_domain = if prompt_yn("Enable meek (CDN-fronted HTTP long-poll)", false) {
        let d = prompt_str("  CDN front domain (Host header, from bridge operator)", "");
        if d.is_empty() {
            None
        } else {
            Some(d)
        }
    } else {
        None
    };

    let webrtc_signaling_host = if prompt_yn("Enable WebRTC (DTLS-SCTP data channel)", false) {
        let h = prompt_str("  Signaling broker host (from bridge operator)", "");
        if h.is_empty() {
            None
        } else {
            Some(h)
        }
    } else {
        None
    };
    let webrtc_ice_servers: Vec<String> = if webrtc_signaling_host.is_some() {
        prompt_str(
            "  STUN/TURN servers (blank = built-in; comma-separated)",
            "",
        )
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
    } else {
        Vec::new()
    };

    let pad_enabled = prompt_yn(
        "Enable frame-padding (must match bridge's pad_enabled setting)",
        false,
    );
    let (pad_cbr, pad_cbr_frame_bytes, pad_cbr_interval_ms) = if pad_enabled {
        let cbr = prompt_yn(
            "  Use CBR mode? (constant bitrate - must match bridge)",
            false,
        );
        if cbr {
            let frame = prompt_u64("  CBR frame size in bytes", 1024) as usize;
            let interval = prompt_u64("  CBR interval in ms", 10);
            (true, frame, interval)
        } else {
            (false, 0, 0)
        }
    } else {
        (false, 0, 0)
    };

    // Dynamic discovery: lets the client find new bridge IPs without manual config.
    // Nostr is the primary channel; DNS TXT is the channel of last resort (works
    // even when WebSocket/Nostr connections are blocked by the censor).
    let nostr_enabled = prompt_yn(
        "Enable Nostr discovery? (auto-fetches new bridge addresses from Nostr relays)",
        false,
    );
    let nostr_relays: Vec<String> = if nostr_enabled {
        let raw = prompt_str(
            "  Nostr relay WebSocket URLs (comma-separated)",
            "wss://relay.damus.io,wss://nos.lol",
        );
        raw.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        Vec::new()
    };
    let dns_enabled = prompt_yn(
        "Enable DNS TXT discovery? (channel of last resort - works even when Nostr is blocked)",
        false,
    );
    let dns_discovery_apexes: Vec<String> = if dns_enabled {
        let raw = prompt_str(
            "  DNS apex zones (comma-separated, e.g. bridges.example.com)",
            "",
        );
        raw.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        Vec::new()
    };
    let dht_enabled = prompt_yn(
        "Enable mainline DHT discovery? (BEP-44, no relay list to block - recommended)",
        true,
    );

    // 4. Output path
    println!();
    let client_path = prompt_str("Write client config to", "client.json");

    // Build and write
    let client_cfg = build_client_config(
        &local_bind,
        &invite_url,
        reality,
        &reality_sni,
        hysteria2,
        hysteria2_mbps,
        ss2022_psk_hex.as_deref(),
        ws,
        &ws_path,
        meek_front_domain.as_deref(),
        webrtc_signaling_host.as_deref(),
        &webrtc_ice_servers,
        pad_enabled,
        pad_cbr,
        pad_cbr_frame_bytes,
        pad_cbr_interval_ms,
        &nostr_relays,
        &dns_discovery_apexes,
        dht_enabled,
    );
    write_json(&client_path, &client_cfg);

    println!("\nDone. Written: {client_path}");
    println!();
    println!("  To connect: mirage-client {client_path}");
    println!("  SOCKS5 proxy will be available at {local_bind}");
}

// -- Entry point ---------------------------------------------------------------

fn main() {
    if let Err(e) = harden_process() {
        eprintln!("fatal: harden_process: {e}");
        std::process::exit(2);
    }

    banner();
    println!();
    println!("  This wizard writes ready-to-run config and prints the exact commands to");
    println!(
        "  deploy. It never phones home. {}",
        paint("Press Ctrl+C at any time to abort.", C_SLATE)
    );
    println!();
    println!("  {}", paint("What are you setting up?", C_TITLE));
    println!("  1. New deployment  - generate bridge.json + client.json");
    println!("  2. Bridge only     - generate bridge.json (you already have a client)");
    println!("  3. Client only     - generate client.json (you have an invite URL)");

    let choice = loop {
        let v = prompt_str("Choice", "1");
        match v.trim() {
            "1" => break 1u8,
            "2" => break 2u8,
            "3" => break 3u8,
            _ => println!("  Invalid - try again."),
        }
    };

    match choice {
        1 => setup_bridge_and_client(true),
        2 => setup_bridge_and_client(false),
        3 => setup_client_from_invite(),
        _ => unreachable!(),
    }
}
