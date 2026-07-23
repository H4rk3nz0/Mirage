//! `mirage-keygen` - one-shot key material generator.
//!
//! Prints a fresh operator + bridge keypair and, under them, a
//! bundled `MasterInvite` carrying `bootstrap_tokens` and a signed
//! `bootstrap_announcement` pointing at the bridge. The output is
//! structured so an operator running `mirage-keygen > bootstrap.json`
//! gets everything needed to populate both `mirage-bridge` config
//! and a `mirage-client` invite in a single invocation.
//!
//! **Operator private key is redacted by default** (prints
//! `<REDACTED>` instead of the hex). This is the highest-trust key
//! in the Mirage trust root; pass `--reveal-operator-sk` to include
//! it when setting up a fresh operator identity on an air-gapped
//! machine. Never ship that flag to a production shell where shell
//! history, backups, or terminal scroll-back could retain the bytes.
//!
//! # Flags
//!
//! - `--reveal-operator-sk`: include operator private key hex.
//! - `--bridge-endpoint <host:port>`: bake this address into the
//!   bootstrap announcement embedded in the invite (default
//!   `127.0.0.1:8443` for local demos).
//! - `--tokens <N>`: number of bootstrap tokens to mint (default 8,
//!   max 16 per spec §6.1).
//! - `--invite-ttl-hours <N>`: invite validity window (default 168,
//!   = 7 days).
//! - `--token-ttl-hours <N>`: per-token expiry (default 24).

use mirage_common::process_hardening::harden_process;
use mirage_crypto::ed25519_dalek::{Signer, SigningKey};
use mirage_crypto::x25519_dalek::{PublicKey, StaticSecret};
use mirage_discovery::invite::{MasterInvite, MAX_BOOTSTRAP_TOKENS};
use mirage_discovery::token::sign_token_jittered;
use mirage_discovery::wire::{transport_caps, Announcement, Endpoint, SIG_LEN};
use serde_json::json;

fn rand_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    getrandom::fill(&mut s).expect("OS CSPRNG failed");
    s
}

struct Args {
    reveal_operator_sk: bool,
    bridge_endpoint: String,
    tokens: usize,
    invite_ttl_hours: u64,
    token_ttl_hours: u64,
    /// Additional bridge endpoints to include in the primary
    /// bridge's cohort list. Each gets its own freshly-minted
    /// keypair (written in the output under `cohort`) and a
    /// signed announcement ready to be loaded by the primary
    /// bridge's `cohort_announcements_path`.
    cohort_endpoints: Vec<String>,
    /// Generate a random 32-byte SS-2022 PSK and include it in
    /// the output.
    ss2022: bool,
    /// Include WebSocket transport config in the output.
    ws: bool,
    /// Generate a random VLESS UUID and include it in the output.
    vless: bool,
    /// Enable Hysteria2 (QUIC/BRUTAL) transport. UDP shares the same
    /// port number as the primary TCP bind.
    hysteria2: bool,
    /// Enable forward-secret rendezvous (invite ext 0x07): the operator's
    /// `mirage-publish` drives a one-way discovery-key ratchet and discards the
    /// salt (producer forward secrecy). Opt-in: BOTH the publisher and clients
    /// must run a release that honours the flag, or discovery desyncs.
    forward_secret_rendezvous: bool,
    /// Base64 ECHConfigList for the carrier front (CDN's DNS HTTPS value). Embedded in
    /// the invite so clients use ECH on the carrier_tls handshake (encrypts the inner SNI).
    ech_config: Option<String>,
    /// CDN front domain for Meek HTTP long-polling.  When set, the
    /// generated invite's `transport_caps` will include the MEEK bit
    /// and `--write-client-config` will include `meek_front_domain`.
    meek_front_domain: Option<String>,
    /// CDN front domain for DoH-tunnel transport (`POST /dns-query`).
    /// When set, the MEEK bit is also set (DoH reuses the Meek path)
    /// and `--write-client-config` will include `doh_front_domain`.
    doh_front_domain: Option<String>,
    /// If set, write the bridge config JSON to this path instead of
    /// (or in addition to) stdout. The file contains a ready-to-use
    /// `mirage-bridge` JSON config with all active transport fields.
    write_bridge_config: Option<String>,
    /// If set, write the client config JSON to this path. The file
    /// contains a `mirage-client` JSON config with the invite URL baked in.
    write_client_config: Option<String>,
    /// Port-hopping base port (A35). Requires `--port-range`.
    port_base: Option<u16>,
    /// Port-hopping range. The epoch-derived port lands in
    /// `[port_base, port_base + port_range)`. Requires `--port-base`.
    port_range: Option<u16>,
}

fn parse_args() -> Args {
    let mut args = Args {
        reveal_operator_sk: false,
        bridge_endpoint: "127.0.0.1:8443".to_string(),
        tokens: 8,
        invite_ttl_hours: 168,
        token_ttl_hours: 24,
        cohort_endpoints: Vec::new(),
        ss2022: false,
        ws: false,
        vless: false,
        hysteria2: false,
        forward_secret_rendezvous: false,
        ech_config: None,
        meek_front_domain: None,
        doh_front_domain: None,
        write_bridge_config: None,
        write_client_config: None,
        port_base: None,
        port_range: None,
    };
    let argv: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--reveal-operator-sk" => args.reveal_operator_sk = true,
            "--bridge-endpoint" => {
                i += 1;
                args.bridge_endpoint = argv
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| fatal("--bridge-endpoint needs a value"));
            }
            "--tokens" => {
                i += 1;
                args.tokens = argv
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| fatal("--tokens needs an integer"));
            }
            "--invite-ttl-hours" => {
                i += 1;
                args.invite_ttl_hours = argv
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| fatal("--invite-ttl-hours needs an integer"));
            }
            "--token-ttl-hours" => {
                i += 1;
                args.token_ttl_hours = argv
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| fatal("--token-ttl-hours needs an integer"));
            }
            "--cohort-endpoint" => {
                i += 1;
                let v = argv
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| fatal("--cohort-endpoint needs a value"));
                args.cohort_endpoints.push(v);
            }
            "--ss2022" => args.ss2022 = true,
            "--forward-secret-rendezvous" => args.forward_secret_rendezvous = true,
            "--ech-config" => {
                i += 1;
                args.ech_config = Some(
                    argv.get(i)
                        .cloned()
                        .unwrap_or_else(|| fatal("--ech-config needs a base64 ECHConfigList")),
                );
            }
            "--ws" => args.ws = true,
            "--vless" => args.vless = true,
            "--hysteria2" => args.hysteria2 = true,
            "--meek" => {
                i += 1;
                args.meek_front_domain = Some(argv.get(i).cloned().unwrap_or_else(|| {
                    fatal("--meek needs a front domain (e.g. meek.cdn.example.com)")
                }));
            }
            "--doh" => {
                i += 1;
                args.doh_front_domain = Some(
                    argv.get(i)
                        .cloned()
                        .unwrap_or_else(|| fatal("--doh needs a front domain (e.g. dns.google)")),
                );
            }
            "--write-bridge-config" => {
                i += 1;
                args.write_bridge_config = Some(
                    argv.get(i)
                        .cloned()
                        .unwrap_or_else(|| fatal("--write-bridge-config needs a path")),
                );
            }
            "--write-client-config" => {
                i += 1;
                args.write_client_config = Some(
                    argv.get(i)
                        .cloned()
                        .unwrap_or_else(|| fatal("--write-client-config needs a path")),
                );
            }
            "--port-base" => {
                i += 1;
                args.port_base = Some(
                    argv.get(i)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or_else(|| fatal("--port-base needs a u16")),
                );
            }
            "--port-range" => {
                i += 1;
                args.port_range = Some(
                    argv.get(i)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or_else(|| fatal("--port-range needs a u16")),
                );
            }
            "-V" | "--version" => {
                println!("mirage-keygen {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "-h" | "--help" => {
                println!(
                    "mirage-keygen {ver}\n\
                     \n\
                     Usage: mirage-keygen [OPTIONS] > keys.json\n\
                     \n\
                     Options:\n\
                       --reveal-operator-sk               Include operator private key in output.\n\
                       --bridge-endpoint <host:port>      Bake this address into the invite (default: 127.0.0.1:8443).\n\
                       --tokens <N>                       Bootstrap tokens to mint (default: 8, max 16).\n\
                       --invite-ttl-hours <N>             Invite validity window in hours (default: 168).\n\
                       --token-ttl-hours <N>              Per-token expiry in hours (default: 24).\n\
                       --cohort-endpoint <host:port>      Add a cohort bridge (repeatable).\n\
                       --ss2022                           Generate SS-2022 PSK.\n\
                       --ws                               Include WebSocket transport config.\n\
                       --vless                            Generate VLESS UUID.\n\
                       --hysteria2                        Enable Hysteria2 (QUIC/BRUTAL) transport (UDP on same port as TCP).\n\
                       --forward-secret-rendezvous        Forward-secret discovery (invite ext 0x07); publisher discards salt. Opt-in: upgrade publisher+clients together.\n\
                       --meek <front_domain>              Enable Meek HTTP long-poll carrier (e.g. meek.cdn.example.com).\n\
                       --doh <front_domain>               Enable DoH-tunnel carrier (e.g. dns.google).\n\
                       --write-bridge-config <path>       Write bridge config JSON to file.\n\
                       --write-client-config <path>       Write client config JSON to file.\n\
                       --port-base <N>                    Enable port hopping: base port (must be >= 1024).\n\
                       --port-range <N>                   Port hopping range (must be > 0; use with --port-base).\n\
                       --version, -V                      Print version and exit.\n\
                       --help, -h                         Print this help and exit.",
                    ver = env!("CARGO_PKG_VERSION")
                );
                std::process::exit(0);
            }
            other => fatal(&format!("unknown arg: {other}")),
        }
        i += 1;
    }
    if args.tokens == 0 || args.tokens > MAX_BOOTSTRAP_TOKENS {
        fatal(&format!("--tokens must be 1..={MAX_BOOTSTRAP_TOKENS}",));
    }
    match (args.port_base, args.port_range) {
        (Some(_), None) | (None, Some(_)) => {
            fatal("--port-base and --port-range must be used together");
        }
        (Some(b), Some(r)) => {
            if b < 1024 {
                fatal("--port-base must be >= 1024 (privileged ports cannot be derived)");
            }
            if r == 0 {
                fatal("--port-range must be > 0");
            }
            if (b as u32) + (r as u32) > 65536 {
                fatal("--port-base + --port-range exceeds 65535");
            }
        }
        _ => {}
    }
    args
}

fn parse_endpoint(s: &str) -> Endpoint {
    // Accept: "host:port" where host is either an IPv4 dotted-quad,
    // an [IPv6] in brackets, or a domain name.
    let (host, port) = match s.rfind(':') {
        Some(idx) => (&s[..idx], &s[idx + 1..]),
        None => fatal("--bridge-endpoint must be host:port"),
    };
    let port: u16 = port
        .parse()
        .unwrap_or_else(|_| fatal("invalid port in --bridge-endpoint"));

    // IPv6 literal: [::1]
    if host.starts_with('[') && host.ends_with(']') {
        let inner = &host[1..host.len() - 1];
        let ip: std::net::Ipv6Addr = inner
            .parse()
            .unwrap_or_else(|_| fatal("invalid IPv6 in --bridge-endpoint"));
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
    // Domain.
    Endpoint::Domain {
        domain: host.to_string(),
        port,
    }
}

fn main() {
    if let Err(e) = harden_process() {
        eprintln!("fatal: harden_process: {e}");
        std::process::exit(2);
    }

    let args = parse_args();
    let endpoint = parse_endpoint(&args.bridge_endpoint);

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let token_expires_at = now_unix + args.token_ttl_hours * 3600;
    let invite_expires_at = now_unix + args.invite_ttl_hours * 3600;

    // Operator identity.
    let op_sk = SigningKey::from_bytes(&rand_seed());
    let op_pk = op_sk.verifying_key().to_bytes();

    // Bridge identity + static X25519.
    let bridge_id_sk = SigningKey::from_bytes(&rand_seed());
    let bridge_ed_pk = bridge_id_sk.verifying_key().to_bytes();
    let bridge_x_sk_raw = StaticSecret::from(rand_seed());
    let bridge_x_pk = *PublicKey::from(&bridge_x_sk_raw).as_bytes();
    let bridge_x_sk = bridge_x_sk_raw.to_bytes();

    // TLS identity for Reality pinned/cover-mimicry modes. The
    // signing key lives in the bridge's config; the matching pubkey
    // goes into the invite so Mirage clients know what to verify
    // CertVerify against. If the operator isn't running pinned mode
    // (ephemeral default), these are still useful scaffolding they
    // can ignore.
    // Reality CertVerify signing identity: ECDSA P-256 (scheme 0x0403, matching
    // real browsers). A raw 32-byte value exceeds the curve order with prob
    // ~2^-32, so rejection-sample a valid scalar. The pubkey published in the
    // invite is the compressed SEC1 point (33 bytes).
    let tls_signing_sk = loop {
        if let Ok(k) = p256::ecdsa::SigningKey::from_slice(&rand_seed()) {
            break k;
        }
    };
    let tls_signing_pk: [u8; 33] = tls_signing_sk
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("compressed P-256 point is 33 bytes");
    let tls_signing_sk_bytes: [u8; 32] = tls_signing_sk.to_bytes().into();

    // Optional transport material, generated only when the respective
    // CLI flag is set.

    // SS-2022: 32-byte random PSK.
    let ss2022_psk_hex: Option<String> = if args.ss2022 {
        let mut psk = [0u8; 32];
        getrandom::fill(&mut psk).expect("OS CSPRNG failed");
        Some(hex_of(&psk))
    } else {
        None
    };

    // VLESS UUID: 16 random bytes formatted as standard UUID.
    let vless_uuid: Option<String> = if args.vless {
        let mut raw = [0u8; 16];
        getrandom::fill(&mut raw).expect("OS CSPRNG failed");
        // Format as xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.
        Some(format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            raw[0], raw[1], raw[2], raw[3],
            raw[4], raw[5],
            raw[6], raw[7],
            raw[8], raw[9],
            raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
        ))
    } else {
        None
    };

    // Build transport_caps for the announcement.
    let mut t_caps = transport_caps::REALITY_V2;
    if args.ss2022 {
        t_caps |= transport_caps::SHADOWSOCKS_2022;
    }
    if args.ws {
        t_caps |= transport_caps::WS_TUNNEL;
    }
    if args.vless {
        t_caps |= transport_caps::VLESS;
    }
    if args.meek_front_domain.is_some() {
        t_caps |= transport_caps::MEEK;
    }
    if args.doh_front_domain.is_some() {
        t_caps |= transport_caps::DOH_TUNNEL;
    }

    // Bootstrap announcement signed by operator.
    let mut announcement = Announcement {
        issued_at: now_unix,
        expires_at: invite_expires_at,
        bridge_ed25519_pk: bridge_ed_pk,
        bridge_x25519_pk: bridge_x_pk,
        transport_caps: t_caps,
        endpoint: endpoint.clone(),
        extra_endpoints: Vec::new(),
        signature: [0u8; SIG_LEN],
    };
    let mut ann_prefix = Vec::new();
    announcement.encode_signed_prefix(&mut ann_prefix);
    announcement.signature = op_sk.sign(&ann_prefix).to_bytes();

    // Bootstrap tokens - each pinned to the bridge identity.
    // RT-CN-11: jitter expiries across half the nominal TTL so a
    // leaked subset can't reveal the mint timestamp.
    let token_jitter_seconds = (args.token_ttl_hours * 3600) / 2;
    let tokens: Vec<_> = (0..args.tokens)
        .map(|_| {
            let tid = rand_seed();
            sign_token_jittered(
                tid,
                bridge_ed_pk,
                token_expires_at,
                token_jitter_seconds,
                &op_sk,
            )
        })
        .collect();

    // Forward-secure bootstrap tokens (dual-minted alongside the legacy ones).
    // cert_valid_until = invite expiry, so the epoch subkey is valid for exactly
    // the invite lifetime. Capable clients present these; older clients skip the
    // extension and use the legacy tokens above.
    let fs_tokens = mirage_discovery::token_fs::mint_fs_tokens(
        &op_sk,
        bridge_ed_pk,
        now_unix,
        invite_expires_at,
        token_expires_at,
        token_jitter_seconds,
        args.tokens,
    )
    .unwrap_or_else(|e| fatal(&format!("fs token mint: {e}")));

    let shared_salt = rand_seed();
    // Per-invite claim id (v0.1e): lets the first-use client redeem
    // the invite at a bridge, narrowing a leaked invite's window.
    let claim_id = rand_seed();
    // Per-bridge secret QUIC-obfs key. Embedded in the invite (ext 0x06) AND in
    // every bridge config this tool emits (`quic_obfs_secret_hex`), so QUIC
    // obfuscation is secret-grade by default: an adversary needs an actual
    // invite (not merely the scraped bridge pubkey) to de-obfuscate.
    let obfs_secret = rand_seed();
    let port_hop = match (args.port_base, args.port_range) {
        (Some(b), Some(r)) => Some((b, r)),
        _ => None,
    };
    let invite = MasterInvite::new_with_extensions(
        op_pk,
        shared_salt,
        now_unix,
        invite_expires_at,
        Vec::new(),
        tokens.clone(),
        Some(announcement.clone()),
        // tls_cert_verify_pk: None for the DEFAULT (ephemeral) reality mode.
        // The ephemeral bridge mints a per-session cert and signs CertVerify
        // with THAT cert's key, so the client must verify against the cert
        // SPKI - not a fixed key. Setting Some(tls_signing_pk) here orphaned it
        // (the ephemeral bridge never signs with that key), so every reality
        // handshake failed `CertVerify signature invalid`. A pinned-reality
        // setup (reality_tls_mode=pinned + reality_tls_signing_sk_hex on the
        // bridge) must instead carry the matching pubkey - a separate opt-in.
        None,
        Some(claim_id),
        // No mother key in v0.1 keygen MVP - operators add via
        // mirage-rotate when they generate one.
        None,
        None,
        port_hop,
    )
    .unwrap_or_else(|e| fatal(&format!("invite build: {e}")))
    .with_obfs_secret(obfs_secret)
    // Reality anti-probe root, derived from the bridge's X25519 static secret so
    // the bridge re-derives the SAME value at runtime with no extra config.
    .with_probe_root(mirage_transport_reality::derive_probe_root(&bridge_x_sk))
    .with_fs_bootstrap_tokens(fs_tokens);
    let invite = match &args.ech_config {
        Some(b64) => {
            use base64::Engine as _;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .unwrap_or_else(|e| fatal(&format!("--ech-config: invalid base64: {e}")));
            invite.with_ech_config(bytes)
        }
        None => invite,
    };
    let invite = if args.forward_secret_rendezvous {
        invite.with_forward_secret_rendezvous()
    } else {
        invite
    };
    let invite_url = format!("mirage://{}", invite.encode_text());

    // ---- Cohort bridges ----
    //
    // For each extra endpoint the operator named, mint a fresh
    // bridge keypair and an operator-signed announcement. The
    // primary bridge loads these as its cohort list; each extra
    // bridge is given its own sample config (so operators can
    // deploy them independently).
    let cohort_bridges: Vec<_> = args
        .cohort_endpoints
        .iter()
        .map(|ep| mint_cohort_bridge(ep, &op_sk, now_unix, invite_expires_at))
        .collect();

    let mut out = json!({
        "_comment": "mirage-keygen output; pipe this to a private file. Operator SK is the root of trust.",
        "now_unix": now_unix,
        "operator": {
            "ed25519_sk_hex": if args.reveal_operator_sk {
                hex_of(&op_sk.to_bytes())
            } else {
                "<REDACTED - pass --reveal-operator-sk to include>".to_string()
            },
            "ed25519_pk_hex": hex_of(&op_pk),
        },
        "bridge": {
            "x25519_sk_hex": hex_of(&bridge_x_sk),
            "x25519_pk_hex": hex_of(&bridge_x_pk),
            "ed25519_sk_hex": hex_of(&bridge_id_sk.to_bytes()),
            "ed25519_pk_hex": hex_of(&bridge_ed_pk),
            "endpoint": args.bridge_endpoint,
            // Carried here so `mirage-rotate` can re-embed the SAME secret in the
            // rotated invite, keeping it in sync with the unchanged bridge config.
            "obfs_secret_hex": hex_of(&obfs_secret),
        },
        "invite": {
            "url": invite_url,
            "expires_at": invite_expires_at,
            "token_count": tokens.len(),
            "token_ttl_seconds": args.token_ttl_hours * 3600,
        },
        "sample_bridge_config": {
            "bind": args.bridge_endpoint,
            "bridge_x25519_sk_hex": hex_of(&bridge_x_sk),
            "bridge_ed25519_pk_hex": hex_of(&bridge_ed_pk),
            "bridge_ed25519_sk_hex": hex_of(&bridge_id_sk.to_bytes()),
            "operator_ed25519_pk_hex": hex_of(&op_pk),
            "quic_obfs_secret_hex": hex_of(&obfs_secret),
            "replay_capacity": 65536,
            "handshake_timeout_secs": 10,
            "max_concurrent_sessions": 4096,
            "socks5_connect_timeout_secs": 10,
            "_comment_policy": "Both allow_* default to false; set true ONLY for deliberate internal-network exposure.",
            "allow_private_network_targets": false,
            "allow_loopback_targets": false
        },
        "sample_bridge_config_reality": {
            "_comment": "Reality transport v0.1c: full TLS 1.3 handshake mimicry. In ephemeral mode (default) the bridge mints a fresh cert per session. For cover-cert mimicry or pinned CA certs, set reality_tls_mode=pinned and point reality_tls_cert_der_path at a DER file.",
            "bind": args.bridge_endpoint,
            "bridge_x25519_sk_hex": hex_of(&bridge_x_sk),
            "bridge_ed25519_pk_hex": hex_of(&bridge_ed_pk),
            "bridge_ed25519_sk_hex": hex_of(&bridge_id_sk.to_bytes()),
            "operator_ed25519_pk_hex": hex_of(&op_pk),
            "quic_obfs_secret_hex": hex_of(&obfs_secret),
            "replay_capacity": 65536,
            "handshake_timeout_secs": 10,
            "max_concurrent_sessions": 4096,
            "socks5_connect_timeout_secs": 10,
            "allow_private_network_targets": false,
            "allow_loopback_targets": false,
            "reality_enabled": true,
            "reality_cover_addr": "REPLACE-WITH-REAL-CDN-HOST.invalid:443",
            "reality_client_hello_timeout_secs": 10,
            "reality_cover_duration_cap_secs": 30,
            "_comment_probe": "Anti-probe epoch binding is always active. Set reality_probe_accept_legacy=false to close pubkey-only enumeration - but ONLY if every client reaches this bridge via an invite (which carries its probe_root). A bridge reached via the cohort service (clients hold no per-bridge invite for it) MUST keep this true, else it rejects legitimate cohort clients. Left true here for safety; flip to false for an invite-only bridge.",
            "reality_probe_accept_legacy": true
        },
        "sample_bridge_config_reality_pinned": {
            "_comment": "Pinned-TLS reality: bridge serves reality_tls_cert_der_path verbatim and signs CertVerify with reality_tls_signing_sk_hex. The invite carries the matching pubkey (tls_cert_verify_pk) so Mirage clients verify against this key, not the cert's SPKI. Use with `mirage-cover-fetch REPLACE-WITH-REAL-CDN-HOST.invalid:443 > cover.der` for cover-cert mimicry, or with a real CA-signed cert+key pair for chain-valid TLS.",
            "bind": args.bridge_endpoint,
            "bridge_x25519_sk_hex": hex_of(&bridge_x_sk),
            "bridge_ed25519_pk_hex": hex_of(&bridge_ed_pk),
            "bridge_ed25519_sk_hex": hex_of(&bridge_id_sk.to_bytes()),
            "operator_ed25519_pk_hex": hex_of(&op_pk),
            "quic_obfs_secret_hex": hex_of(&obfs_secret),
            "replay_capacity": 65536,
            "handshake_timeout_secs": 10,
            "max_concurrent_sessions": 4096,
            "socks5_connect_timeout_secs": 10,
            "allow_private_network_targets": false,
            "allow_loopback_targets": false,
            "reality_enabled": true,
            "reality_cover_addr": "REPLACE-WITH-REAL-CDN-HOST.invalid:443",
            "reality_client_hello_timeout_secs": 10,
            "reality_cover_duration_cap_secs": 30,
            "_comment_probe": "See sample_bridge_config_reality: set reality_probe_accept_legacy=false to close pubkey-only enumeration ONLY for an invite-reached bridge, never a cohort-reached one. Left true for safety.",
            "reality_probe_accept_legacy": true,
            "reality_tls_mode": "pinned",
            "reality_tls_cert_der_path": "/etc/mirage/cover.der",
            "reality_tls_signing_sk_hex": hex_of(&tls_signing_sk_bytes)
        },
        "reality_tls": {
            "_comment": "Supplied in the invite as tls_cert_verify_pk. Keep signing_sk_hex on the bridge only; it MUST NOT travel with the invite.",
            "signing_pk_hex": hex_of(&tls_signing_pk),
            "signing_sk_hex": hex_of(&tls_signing_sk_bytes)
        },
        "sample_client_config_invite_mode": {
            "local_bind": "127.0.0.1:1080",
            "invite": invite_url.clone(),
            "handshake_timeout_secs": 10
        },
        "sample_client_config_invite_mode_reality": {
            "_comment": "Client pairs with sample_bridge_config_reality. reality_sni MUST match the cover's hostname for the traffic inspection shape to align.",
            "local_bind": "127.0.0.1:1080",
            "invite": invite_url,
            "handshake_timeout_secs": 10,
            "reality_enabled": true,
            "reality_sni": "REPLACE-WITH-REAL-CDN-HOST.invalid"
        },
        "cohort": {
            "_comment": "Pre-signed announcements for other bridges this operator runs. Drop `cohort_announcements_file` into a file and point `cohort_announcements_path` at it in the primary bridge config. The primary bridge will hand these out, one subset per client, respecting `cohort_reveal_cap_per_token`.",
            "bridges": cohort_bridges.iter().map(|b| serde_json::json!({
                "endpoint": b.endpoint,
                "x25519_sk_hex": b.x25519_sk_hex,
                "x25519_pk_hex": b.x25519_pk_hex,
                "ed25519_sk_hex": b.ed25519_sk_hex,
                "ed25519_pk_hex": b.ed25519_pk_hex,
                "announcement_hex": b.announcement_hex,
            })).collect::<Vec<_>>(),
            "cohort_announcements_file": {
                "announcements": cohort_bridges.iter().map(|b| serde_json::json!({
                    "hex": b.announcement_hex,
                })).collect::<Vec<_>>(),
            },
        },
    });

    // Attach optional transport sections to the root object.
    let out_map = out.as_object_mut().expect("json root is object");

    if let Some(ref psk_hex) = ss2022_psk_hex {
        out_map.insert("ss2022".to_string(), serde_json::json!({
            "bridge_config": { "ss2022_psk_hex": psk_hex },
            "client_config": { "ss2022_psk_hex": psk_hex },
            "_comment": "Pre-shared key for Shadowsocks-2022 carrier. Keep secret. Both bridge and client must use the same PSK."
        }));
    }

    if args.ws {
        out_map.insert("websocket".to_string(), serde_json::json!({
            "bridge_config": { "ws_enabled": true },
            "client_config": { "ws_enabled": true, "ws_path": "/" },
            "_comment": "WebSocket carrier. For CDN fronting, point the CDN origin at the bridge IP."
        }));
    }

    if let Some(ref uuid_str) = vless_uuid {
        // Bridge config uses the UUID with dashes; strip dashes for the
        // 32-char hex form also shown (both are now accepted at parse time).
        let uuid_hex_nodash: String = uuid_str.chars().filter(|&c| c != '-').collect();
        out_map.insert("vless".to_string(), serde_json::json!({
            "bridge_config": { "vless_uuid_hex": uuid_str },
            "client_config_note": "VLESS UUID auth is bridge-side only; clients use standard VLESS headers.",
            "_comment": "VLESS framing layer UUID. Format: 32-char hex (no dashes) for bridge config.",
            "_uuid_nodash": uuid_hex_nodash,
        }));
    }

    if args.hysteria2 {
        out_map.insert("hysteria2".to_string(), serde_json::json!({
            "bridge_config": { "hysteria2_enabled": true },
            "client_config": { "hysteria2_enabled": true, "hysteria2_send_rate_mbps": 50 },
            "_comment": "Hysteria2 QUIC/BRUTAL transport. UDP shares same port number as primary TCP bind - indistinguishable from HTTP/3."
        }));
        // Also annotate sample_bridge_config so operators see the field inline.
        if let Some(sbc) = out_map
            .get_mut("sample_bridge_config")
            .and_then(|v| v.as_object_mut())
        {
            sbc.insert("hysteria2_enabled".to_string(), serde_json::json!(true));
        }
    }

    if let Some(ref front_domain) = args.meek_front_domain {
        out_map.insert("meek".to_string(), serde_json::json!({
            "_comment": "Meek HTTP domain-fronting long-poll carrier. The bridge requires no extra config - the protocol mux handles HTTP automatically. The client uses meek_front_domain as the HTTP Host header for CDN-fronting.",
            "client_config": { "meek_front_domain": front_domain, "meek_path": "/mirage" },
        }));
    }

    if let Some(ref front_domain) = args.doh_front_domain {
        out_map.insert("doh".to_string(), serde_json::json!({
            "_comment": "DoH-tunnel carrier (POST /dns-query, Content-Type: application/dns-message). No extra bridge config needed. The client uses doh_front_domain as the HTTP Host header.",
            "client_config": { "doh_front_domain": front_domain },
        }));
    }

    if let Some((base, range)) = port_hop {
        out_map.insert("port_hop".to_string(), serde_json::json!({
            "_comment": "Port-hopping (A35): bridge binds derived_port_base/range/salt; invite already carries the extension. Set these fields in your bridge config alongside the static `bind` address.",
            "bridge_config_fields": {
                "derived_port_base": base,
                "derived_port_range": range,
                "derived_port_shared_salt_hex": hex_of(&shared_salt),
            },
            "port_base": base,
            "port_range": range,
            "shared_salt_hex": hex_of(&shared_salt),
        }));
        // Add shared_salt explicitly into the invite section for operator convenience.
        if let Some(inv) = out_map.get_mut("invite").and_then(|v| v.as_object_mut()) {
            inv.insert(
                "derived_port_shared_salt_hex".to_string(),
                serde_json::json!(hex_of(&shared_salt)),
            );
        }
    }

    // --write-bridge-config: write a ready-to-use bridge config JSON.
    if let Some(ref path) = args.write_bridge_config {
        let mut bridge_cfg = serde_json::json!({
            "bind": args.bridge_endpoint,
            "bridge_x25519_sk_hex": hex_of(&bridge_x_sk),
            "bridge_ed25519_pk_hex": hex_of(&bridge_ed_pk),
            "bridge_ed25519_sk_hex": hex_of(&bridge_id_sk.to_bytes()),
            "operator_ed25519_pk_hex": hex_of(&op_pk),
            "quic_obfs_secret_hex": hex_of(&obfs_secret),
            "replay_capacity": 65536,
            "handshake_timeout_secs": 10,
            "max_concurrent_sessions": 4096,
            "socks5_connect_timeout_secs": 10,
            "allow_private_network_targets": false,
            "allow_loopback_targets": false,
        });
        let m = bridge_cfg.as_object_mut().unwrap();
        if let Some(ref psk) = ss2022_psk_hex {
            m.insert("ss2022_psk_hex".to_string(), serde_json::json!(psk));
        }
        if args.ws {
            m.insert("ws_enabled".to_string(), serde_json::json!(true));
        }
        if let Some(ref uuid) = vless_uuid {
            m.insert("vless_uuid_hex".to_string(), serde_json::json!(uuid));
        }
        if args.hysteria2 {
            m.insert("hysteria2_enabled".to_string(), serde_json::json!(true));
        }
        if let Some((base, range)) = port_hop {
            m.insert("derived_port_base".to_string(), serde_json::json!(base));
            m.insert("derived_port_range".to_string(), serde_json::json!(range));
            m.insert(
                "derived_port_shared_salt_hex".to_string(),
                serde_json::json!(hex_of(&shared_salt)),
            );
        }
        // Bridge config embeds long-term PRIVATE KEYS - write it 0600 atomically
        // (never world-readable, no symlink redirect). See mirage_common::secure_file.
        mirage_common::secure_file::write_secret_json(path, &bridge_cfg)
            .unwrap_or_else(|e| fatal(&format!("--write-bridge-config: {e}")));
        eprintln!("wrote bridge config (0600) -> {path}");
    }

    // --write-client-config: write a ready-to-use client config JSON.
    if let Some(ref path) = args.write_client_config {
        let mut client_cfg = serde_json::json!({
            "local_bind": "127.0.0.1:1080",
            "invite": invite_url,
            "handshake_timeout_secs": 10,
        });
        if let Some(ref uuid_str) = vless_uuid {
            // Include the VLESS UUID in the client config when --vless is used.
            let uuid_nodash: String = uuid_str.chars().filter(|&c| c != '-').collect();
            client_cfg["vless_uuid_hex"] = serde_json::json!(uuid_nodash);
        }
        if let Some(ref front_domain) = args.meek_front_domain {
            client_cfg["meek_front_domain"] = serde_json::json!(front_domain);
        }
        if let Some(ref front_domain) = args.doh_front_domain {
            client_cfg["doh_front_domain"] = serde_json::json!(front_domain);
        }
        // Mirror the bridge's carrier transports into the client config so the
        // generated pair is actually USABLE. Previously only vless/meek/doh
        // were emitted, so `--ss2022`/`--ws`/`--hysteria2` produced a
        // client that fell back to Raw - which the bridge mux does not
        // classify, so the handshake was reset. (Found via the Podman e2e.)
        if let Some(ref psk) = ss2022_psk_hex {
            client_cfg["ss2022_psk_hex"] = serde_json::json!(psk);
        }
        if args.ws {
            client_cfg["ws_enabled"] = serde_json::json!(true);
            client_cfg["ws_path"] = serde_json::json!("/");
        }
        if args.hysteria2 {
            client_cfg["hysteria2_enabled"] = serde_json::json!(true);
            client_cfg["hysteria2_send_rate_mbps"] = serde_json::json!(50);
        }
        // Client config embeds a BEARER INVITE (bootstrap tokens + secrets) -
        // write it 0600 atomically, same rationale as the bridge config.
        mirage_common::secure_file::write_secret_json(path, &client_cfg)
            .unwrap_or_else(|e| fatal(&format!("--write-client-config: {e}")));
        eprintln!("wrote client config (0600) -> {path}");
    }

    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}

fn hex_of(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        write!(&mut s, "{b:02x}").unwrap();
    }
    s
}

struct CohortBridge {
    endpoint: String,
    x25519_sk_hex: String,
    x25519_pk_hex: String,
    ed25519_sk_hex: String,
    ed25519_pk_hex: String,
    announcement_hex: String,
}

fn mint_cohort_bridge(
    endpoint_s: &str,
    op_sk: &SigningKey,
    issued_at: u64,
    expires_at: u64,
) -> CohortBridge {
    let endpoint = parse_endpoint(endpoint_s);
    let id_sk = SigningKey::from_bytes(&rand_seed());
    let ed_pk = id_sk.verifying_key().to_bytes();
    let x_sk_raw = StaticSecret::from(rand_seed());
    let x_pk = *PublicKey::from(&x_sk_raw).as_bytes();
    let x_sk = x_sk_raw.to_bytes();
    let mut ann = Announcement {
        issued_at,
        expires_at,
        bridge_ed25519_pk: ed_pk,
        bridge_x25519_pk: x_pk,
        transport_caps: transport_caps::REALITY_V2,
        endpoint,
        extra_endpoints: Vec::new(),
        signature: [0u8; SIG_LEN],
    };
    let mut prefix = Vec::new();
    ann.encode_signed_prefix(&mut prefix);
    ann.signature = op_sk.sign(&prefix).to_bytes();
    let ann_bytes = ann.encode();
    CohortBridge {
        endpoint: endpoint_s.to_string(),
        x25519_sk_hex: hex_of(&x_sk),
        x25519_pk_hex: hex_of(&x_pk),
        ed25519_sk_hex: hex_of(&id_sk.to_bytes()),
        ed25519_pk_hex: hex_of(&ed_pk),
        announcement_hex: hex_of(&ann_bytes),
    }
}

fn fatal(msg: &str) -> ! {
    eprintln!("fatal: {msg}");
    std::process::exit(2);
}
