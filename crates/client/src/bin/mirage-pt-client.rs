//! Tor pluggable-transport (PT 2.1) adapter for Mirage.
//!
//! # What this binary does
//!
//! Tor's pluggable-transport infrastructure spawns external binaries
//! to wrap traffic in censorship-resistant transports (obfs4,
//! Snowflake, meek, webtunnel, etc.). This binary makes Mirage
//! one of those options: a user adds it to their `torrc` and Tor
//! routes traffic through Mirage to reach a Tor bridge.
//!
//! ```text
//! Tor (browser / daemon)
//!   down SOCKS5 to 127.0.0.1:<auto>
//! mirage-pt-client       <- this binary, advertises SOCKS5 endpoint via PT proto
//!   down delegates SOCKS5 forward
//! mirage-client          <- already running; tunnels SOCKS5-out via Mirage session
//!   down Mirage session over Reality / obfs / future transports
//! Mirage bridge
//!   down regular SOCKS5 egress
//! Tor bridge -> Tor network
//! ```
//!
//! # Scope (v0.1t)
//!
//! This is a PT-protocol **shim**: it advertises the existing
//! `mirage-client` daemon's SOCKS5 bind as a PT method to Tor. The
//! shim itself does not run any tunnel; it parses Tor's
//! `TOR_PT_*` environment variables, prints the conformant PT 2.1
//! response on stdout, and keeps stdin/stdout alive so Tor knows
//! the transport is up.
//!
//! Future expansion (v0.2): the shim could embed `mirage-client`'s
//! library form so the user only runs one binary, and per-bridge
//! arguments come from Tor's `TOR_PT_CLIENT_TRANSPORTS_V1` rather
//! than a separate Mirage config.
//!
//! # Configuration
//!
//! Set these environment variables before invoking. Tor sets the
//! `TOR_PT_*` ones automatically; the user (via torrc) sets the
//! `MIRAGE_PT_*` ones.
//!
//! - `TOR_PT_MANAGED_TRANSPORT_VER` - set by Tor; must include `1`.
//! - `TOR_PT_CLIENT_TRANSPORTS` - set by Tor; must include `mirage`.
//! - `TOR_PT_STATE_LOCATION` - set by Tor; we don't use it (no state).
//! - `MIRAGE_PT_SOCKS5` - set by the user; the existing
//!   `mirage-client`'s `local_bind` (e.g., `127.0.0.1:1080`).
//!
//! # Example torrc
//!
//! ```text
//! ClientTransportPlugin mirage exec /usr/local/bin/mirage-pt-client
//! Bridge mirage 0.0.0.0:0
//! ```
//!
//! And export `MIRAGE_PT_SOCKS5=127.0.0.1:1080` before starting Tor.
//! The user is responsible for running `mirage-client config.json`
//! separately.
//!
//! # PT 2.1 protocol references
//!
//! - <https://spec.torproject.org/pt-spec/index.html>
//! - <https://gitweb.torproject.org/torspec.git/plain/proposals/106-less-tls-constraint.txt>

use std::io::Write;
use std::process::ExitCode;

const PT_VERSION_REPLY: &str = "VERSION 1";
const TRANSPORT_NAME: &str = "mirage";

fn pt_log(msg: &str) {
    // PT logs go to stderr (PT spec §3.3.4: LOG SEVERITY=info MESSAGE=...).
    // We use the structured form so Tor's PT parser categorises by severity.
    eprintln!("LOG SEVERITY=info MESSAGE={msg}");
}

fn pt_error(msg: &str) {
    eprintln!("LOG SEVERITY=error MESSAGE={msg}");
}

/// PT 2.1 protocol exit codes.
fn die_env_err(reason: &str) -> ExitCode {
    pt_error(&format!("ENV-ERROR {reason}"));
    println!("ENV-ERROR {reason}");
    ExitCode::from(1)
}

fn die_proxy_unsupported() -> ExitCode {
    println!("PROXY-ERROR upstream proxies not supported");
    ExitCode::from(1)
}

fn main() -> ExitCode {
    // 1. Validate Tor's protocol-version negotiation.
    let ver = std::env::var("TOR_PT_MANAGED_TRANSPORT_VER").unwrap_or_default();
    if !ver.split(',').any(|v| v.trim() == "1") {
        return die_env_err("TOR_PT_MANAGED_TRANSPORT_VER must include 1");
    }
    println!("{PT_VERSION_REPLY}");
    let _ = std::io::stdout().flush();

    // 2. Detect upstream-proxy request and refuse (we don't tunnel
    //    through another proxy; Mirage IS the tunnel). Tor sets
    //    TOR_PT_PROXY when the user requested a proxy upstream of
    //    the PT.
    if std::env::var("TOR_PT_PROXY").is_ok() {
        return die_proxy_unsupported();
    }

    // 3. Confirm Tor wants `mirage` as a transport.
    let transports = std::env::var("TOR_PT_CLIENT_TRANSPORTS").unwrap_or_default();
    if !transports.split(',').any(|t| t.trim() == TRANSPORT_NAME) {
        return die_env_err(&format!(
            "TOR_PT_CLIENT_TRANSPORTS must include '{TRANSPORT_NAME}'"
        ));
    }

    // 4. Get the existing mirage-client SOCKS5 bind from env.
    let socks5 = match std::env::var("MIRAGE_PT_SOCKS5") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            return die_env_err(
                "MIRAGE_PT_SOCKS5 must be set to mirage-client's local_bind (e.g., 127.0.0.1:1080)",
            );
        }
    };

    // Sanity-check the value is host:port.
    if socks5.parse::<std::net::SocketAddr>().is_err() {
        return die_env_err("MIRAGE_PT_SOCKS5 must be host:port");
    }

    // 5. Output PT 2.1 CMETHOD line:
    //    CMETHOD <name> <socks-version> <127.0.0.1:port>
    //    Tor connects to <addr>, speaks SOCKS5, and Mirage forwards.
    println!("CMETHOD {TRANSPORT_NAME} socks5 {socks5}");
    println!("CMETHODS DONE");
    let _ = std::io::stdout().flush();
    pt_log(&format!("mirage PT advertised SOCKS5 endpoint {socks5}"));

    // 6. Stay alive until Tor sends EOF on stdin (PT spec §3.3.5).
    //    Tor closes our stdin to signal shutdown; we exit cleanly.
    use std::io::Read;
    let mut buf = [0u8; 256];
    loop {
        match std::io::stdin().read(&mut buf) {
            Ok(0) => break,    // Tor closed stdin; shutting down
            Ok(_) => continue, // ignore; Tor may write things we don't care about
            Err(_) => break,
        }
    }
    pt_log("mirage PT shutting down (stdin EOF)");
    ExitCode::SUCCESS
}
