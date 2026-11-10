//! `mirage-rotate` - operator mother-key / invite rotation tooling.
//!
//! Closes the A1 gap: turns the currently-manual "mint a new invite,
//! overlap for 7 days, rotate bridge config" ceremony into a
//! scriptable flow.
//!
//! # Modes
//!
//! - `--mode routine`: reuse the operator's existing Ed25519
//!   signing key; mint a fresh invite (new `shared_salt`, fresh
//!   `claim_id`, fresh bootstrap tokens). Bridges accept both the
//!   old and new invites without any config change because tokens
//!   in both are signed by the same operator key.
//!
//! - `--mode compromise-rotate-operator`: generate a NEW operator
//!   Ed25519 keypair; mint a fresh invite signed by it. Bridges
//!   must be reconfigured with
//!   `operator_ed25519_pk_hex = <new>` and
//!   `operator_ed25519_pk_prev_hex = <old>` for the overlap
//!   window, then the `prev` field is dropped once users have
//!   migrated. Old invites continue to work at bridges during the
//!   overlap; they stop working at cutover.
//!
//! # Inputs
//!
//! `--from <path.json>`: an earlier `mirage-keygen` output. The
//! operator's SK is read from it (requires the original run to have
//! included `--reveal-operator-sk`). Bridge key material is also
//! read from here, so the new invite's bootstrap announcement
//! points at the same bridge.
//!
//! `--bridge-endpoint <host:port>`: override the endpoint in the
//! bootstrap announcement (useful if the bridge moves). Defaults to
//! the endpoint in `--from`.
//!
//! `--tokens N`: number of bootstrap tokens in the new invite
//! (default 8, same as `mirage-keygen`).
//!
//! `--invite-ttl-hours N`: new invite validity (default 168 = 7 d).
//! `--token-ttl-hours N`: per-token TTL (default 24).
//!
//! # Output
//!
//! JSON on stdout with:
//! - `mode`: echoes the selected mode.
//! - `operator`: pubkey (always) + SK hex (only with
//!   `--reveal-operator-sk`).
//! - `invite.url`: the new `mirage://...` URL for user distribution.
//! - `sample_bridge_config_overlay`: JSON patch to apply to the
//!   running bridge config.
//! - `rotation_notes`: human-readable reminder of the overlap
//!   window and cutover steps.
//!
//! # Security notes
//!
//! - Any machine that runs `mirage-rotate` must already hold the
//!   operator SK. Treat it the same as `mirage-keygen` with
//!   `--reveal-operator-sk` - ideally air-gapped.
//! - The new invite distribution channel is still out-of-band
//!   (A1 residual gap). This tool just mints the bytes; delivery
//!   is the operator's responsibility.

use mirage_common::process_hardening::harden_process;
use mirage_crypto::ed25519_dalek::{Signer, SigningKey};
use mirage_crypto::x25519_dalek::{PublicKey, StaticSecret};
use mirage_discovery::invite::{MasterInvite, MAX_BOOTSTRAP_TOKENS};
use mirage_discovery::token::sign_token_jittered;
use mirage_discovery::wire::{transport_caps, Announcement, Endpoint, SIG_LEN};
use serde_json::{json, Value};

fn rand_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    getrandom::fill(&mut s).expect("OS CSPRNG failed");
    s
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Routine,
    CompromiseRotateOperator,
}

struct Args {
    mode: Mode,
    from_path: String,
    bridge_endpoint: Option<String>,
    tokens: usize,
    invite_ttl_hours: u64,
    token_ttl_hours: u64,
    reveal_operator_sk: bool,
}

fn parse_args() -> Args {
    let mut args = Args {
        mode: Mode::Routine,
        from_path: String::new(),
        bridge_endpoint: None,
        tokens: 8,
        invite_ttl_hours: 168,
        token_ttl_hours: 24,
        reveal_operator_sk: false,
    };
    let argv: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--mode" => {
                i += 1;
                let v = argv
                    .get(i)
                    .map(|s| s.as_str())
                    .unwrap_or_else(|| fatal("--mode needs a value"));
                args.mode = match v {
                    "routine" => Mode::Routine,
                    "compromise-rotate-operator" => Mode::CompromiseRotateOperator,
                    other => fatal(&format!(
                        "unknown --mode: {other} (expected routine|compromise-rotate-operator)"
                    )),
                };
            }
            "--from" => {
                i += 1;
                args.from_path = argv
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| fatal("--from needs a path"));
            }
            "--bridge-endpoint" => {
                i += 1;
                args.bridge_endpoint = Some(
                    argv.get(i)
                        .cloned()
                        .unwrap_or_else(|| fatal("--bridge-endpoint needs a value")),
                );
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
            "--reveal-operator-sk" => args.reveal_operator_sk = true,
            "-h" | "--help" => {
                eprintln!(
                    "usage: mirage-rotate --from <keygen.json> \
                     [--mode routine|compromise-rotate-operator] \
                     [--bridge-endpoint host:port] [--tokens N] \
                     [--invite-ttl-hours N] [--token-ttl-hours N] \
                     [--reveal-operator-sk]"
                );
                std::process::exit(0);
            }
            other => fatal(&format!("unknown arg: {other}")),
        }
        i += 1;
    }
    if args.from_path.is_empty() {
        fatal("--from <keygen.json> is required");
    }
    if args.tokens == 0 || args.tokens > MAX_BOOTSTRAP_TOKENS {
        fatal(&format!("--tokens must be 1..={MAX_BOOTSTRAP_TOKENS}"));
    }
    args
}

fn fatal(msg: &str) -> ! {
    eprintln!("fatal: {msg}");
    std::process::exit(2);
}

fn hex_of(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_to_key32(s: &str, name: &str) -> [u8; 32] {
    let raw = hex::decode(s.trim()).unwrap_or_else(|e| fatal(&format!("{name}: hex decode: {e}")));
    if raw.len() != 32 {
        fatal(&format!("{name}: expected 32 bytes, got {}", raw.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    out
}

/// Parse a 33-byte compressed-SEC1 ECDSA P-256 pubkey hex (the Reality
/// `tls_cert_verify_pk` published in the invite).
fn hex_to_key33(s: &str, name: &str) -> [u8; 33] {
    let raw = hex::decode(s.trim()).unwrap_or_else(|e| fatal(&format!("{name}: hex decode: {e}")));
    if raw.len() != 33 {
        fatal(&format!("{name}: expected 33 bytes, got {}", raw.len()));
    }
    let mut out = [0u8; 33];
    out.copy_from_slice(&raw);
    out
}

fn read_from(path: &str) -> Value {
    let s = std::fs::read_to_string(path).unwrap_or_else(|e| fatal(&format!("read {path}: {e}")));
    serde_json::from_str(&s).unwrap_or_else(|e| fatal(&format!("parse {path}: {e}")))
}

fn parse_endpoint(s: &str) -> Endpoint {
    let (host, port) = match s.rfind(':') {
        Some(idx) => (&s[..idx], &s[idx + 1..]),
        None => fatal("--bridge-endpoint must be host:port"),
    };
    let port: u16 = port
        .parse()
        .unwrap_or_else(|_| fatal("invalid port in --bridge-endpoint"));
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
    Endpoint::Domain {
        domain: host.to_string(),
        port,
    }
}

fn main() {
    if let Err(e) = harden_process() {
        fatal(&format!("harden_process: {e}"));
    }
    let args = parse_args();
    let prev = read_from(&args.from_path);

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Previous operator SK must be embedded in the source JSON.
    let prev_op_sk_hex = prev
        .pointer("/operator/ed25519_sk_hex")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| fatal("source JSON has no operator.ed25519_sk_hex (was --reveal-operator-sk passed to mirage-keygen?)"));
    if prev_op_sk_hex.starts_with('<') {
        fatal(
            "source JSON has a redacted operator.ed25519_sk_hex placeholder. Re-run mirage-keygen \
             with --reveal-operator-sk on the air-gapped machine holding the key and feed that \
             JSON here, or inject the SK into the JSON manually before calling mirage-rotate.",
        );
    }
    let prev_op_sk_bytes = hex_to_key32(prev_op_sk_hex, "operator.ed25519_sk_hex");
    let prev_op_sk = SigningKey::from_bytes(&prev_op_sk_bytes);
    let prev_op_pk = prev_op_sk.verifying_key().to_bytes();

    // Bridge key material.
    let bridge_x_sk_hex = prev
        .pointer("/bridge/x25519_sk_hex")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| fatal("source JSON has no bridge.x25519_sk_hex"));
    let bridge_x_sk_raw = hex_to_key32(bridge_x_sk_hex, "bridge.x25519_sk_hex");
    let bridge_x_sk_static = StaticSecret::from(bridge_x_sk_raw);
    let bridge_x_pk = *PublicKey::from(&bridge_x_sk_static).as_bytes();
    let bridge_ed_pk = hex_to_key32(
        prev.pointer("/bridge/ed25519_pk_hex")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| fatal("source JSON has no bridge.ed25519_pk_hex")),
        "bridge.ed25519_pk_hex",
    );
    let bridge_x_sk_bytes = bridge_x_sk_static.to_bytes();

    // Endpoint: CLI override or source JSON.
    let endpoint_str = args.bridge_endpoint.clone().unwrap_or_else(|| {
        prev.pointer("/bridge/endpoint")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| fatal("no --bridge-endpoint and source JSON has no bridge.endpoint"))
    });
    let endpoint = parse_endpoint(&endpoint_str);

    // Decide the new operator key.
    let (new_op_sk, new_op_pk, rotated) = match args.mode {
        Mode::Routine => (prev_op_sk, prev_op_pk, false),
        Mode::CompromiseRotateOperator => {
            let fresh = SigningKey::from_bytes(&rand_seed());
            let pk = fresh.verifying_key().to_bytes();
            (fresh, pk, true)
        }
    };

    // Mint the new bootstrap announcement, signed by the NEW
    // operator key. Tokens in the new invite MUST be signed by the
    // same key that signs this announcement, otherwise clients
    // that use the new invite will decode an announcement they
    // can't verify.
    let invite_expires_at = now_unix + args.invite_ttl_hours * 3600;
    let token_expires_at = now_unix + args.token_ttl_hours * 3600;

    let mut announcement = Announcement {
        issued_at: now_unix,
        expires_at: invite_expires_at,
        bridge_ed25519_pk: bridge_ed_pk,
        bridge_x25519_pk: bridge_x_pk,
        transport_caps: transport_caps::REALITY_V2,
        endpoint,
        extra_endpoints: Vec::new(),
        signature: [0u8; SIG_LEN],
    };
    let mut ann_prefix = Vec::new();
    announcement.encode_signed_prefix(&mut ann_prefix);
    announcement.signature = new_op_sk.sign(&ann_prefix).to_bytes();

    // RT-CN-11: jitter each token's expiry across half the
    // nominal TTL. Without jitter, all tokens in this batch
    // expire at the same second; a leaked subset reveals the
    // mint timestamp. With jitter, individual expiries land
    // in `[token_expires_at, token_expires_at + ttl/2)`.
    let token_jitter_seconds = (args.token_ttl_hours * 3600) / 2;
    let tokens: Vec<_> = (0..args.tokens)
        .map(|_| {
            sign_token_jittered(
                rand_seed(),
                bridge_ed_pk,
                token_expires_at,
                token_jitter_seconds,
                &new_op_sk,
            )
        })
        .collect();

    // Forward-secure bootstrap tokens rooted at the NEW operator key. A bridge
    // in a compromise-rotation overlap accepts both new- and prev-root FS tokens
    // (the FS verify path tries accept_prev_operator_pk), matching the legacy
    // Path A' behaviour, so in-flight FS invites keep working across rotation.
    let fs_tokens = mirage_discovery::token_fs::mint_fs_tokens(
        &new_op_sk,
        bridge_ed_pk,
        now_unix,
        invite_expires_at,
        token_expires_at,
        token_jitter_seconds,
        args.tokens,
    )
    .unwrap_or_else(|e| fatal(&format!("fs token mint: {e}")));

    // Fresh salt + claim id for the new invite.
    let shared_salt = rand_seed();
    let claim_id = rand_seed();

    // TLS signing key stays the same across routine rotation so the
    // invite's `tls_cert_verify_pk` and the bridge's
    // `reality_tls_signing_sk_hex` don't need touching. Compromise
    // rotation of the operator key does NOT imply compromise of
    // the bridge-side TLS signing key - but operators who want to
    // roll everything can run `mirage-keygen` fresh instead.
    let tls_signing_pk = prev
        .pointer("/reality_tls/signing_pk_hex")
        .and_then(|v| v.as_str())
        .map(|h| hex_to_key33(h, "reality_tls.signing_pk_hex"));

    // Carry the bridge's existing QUIC-obfs secret into the rotated invite so it
    // stays in sync with the (unchanged) bridge config. Absent on invites minted
    // by pre-obfs-secret keygen -> new invite falls back to the pubkey default,
    // matching a bridge without `quic_obfs_secret_hex`.
    let obfs_secret = prev
        .pointer("/bridge/obfs_secret_hex")
        .and_then(|v| v.as_str())
        .map(|h| hex_to_key32(h, "bridge.obfs_secret_hex"));

    let mut invite = MasterInvite::new_with_extensions(
        new_op_pk,
        shared_salt,
        now_unix,
        invite_expires_at,
        Vec::new(),
        tokens,
        Some(announcement.clone()),
        tls_signing_pk,
        Some(claim_id),
        // mirage-rotate doesn't currently have a `--mother-pk`
        // argument; operators stamping mother-key extension into
        // their invites should pass it via a future flag. Tracked
        // for the v0.1.x rotation tool refresh.
        None,
        None,
        None, // port_hop preserved from the original invite if present - not modified by rotate
    )
    .unwrap_or_else(|e| fatal(&format!("invite build: {e}")));
    if let Some(secret) = obfs_secret {
        invite = invite.with_obfs_secret(secret);
    }
    // Reality anti-probe root, derived from the bridge's X25519 static secret so
    // the bridge re-derives the SAME value at runtime with no extra config
    // (mirrors the obfs-secret escalation). Closes pubkey-only bridge
    // enumeration once operators run the bridge with accept_legacy off.
    invite = invite.with_probe_root(mirage_transport_reality::derive_probe_root(
        &bridge_x_sk_bytes,
    ));
    invite = invite.with_fs_bootstrap_tokens(fs_tokens);
    let invite_url = format!("mirage://{}", invite.encode_text());

    // Build the bridge config overlay.
    let overlay = match args.mode {
        Mode::Routine => json!({
            "_comment": "Routine rotation: operator key unchanged. No bridge config change is strictly required - tokens from both the old and new invite are signed by the same operator key and work at the bridge simultaneously. Included for completeness.",
            "operator_ed25519_pk_hex": hex_of(&new_op_pk)
        }),
        Mode::CompromiseRotateOperator => json!({
            "_comment": "Compromise-rotate: operator key changed. Apply these fields to bridge.json and restart. After the overlap window (default 7 days), remove operator_ed25519_pk_prev_hex to cut off the old invite.",
            "operator_ed25519_pk_hex": hex_of(&new_op_pk),
            "operator_ed25519_pk_prev_hex": hex_of(&prev_op_pk)
        }),
    };

    let notes = match args.mode {
        Mode::Routine => vec![
            "Distribute invite.url to users over the same OOB channel you used before.",
            "Bridges continue to accept the OLD invite automatically - no config change needed.",
            "Stop publishing announcements under the OLD invite's shared_salt once all users have migrated.",
        ],
        Mode::CompromiseRotateOperator => vec![
            "Apply sample_bridge_config_overlay to EVERY bridge's config and restart.",
            "During the overlap window, both old and new invites work at bridges.",
            "Distribute invite.url to users.",
            "After the overlap (default 7 days or once users confirm migration), REMOVE operator_ed25519_pk_prev_hex from all bridge configs and restart - at that point old invites stop working.",
            "If the compromise also suspects bridge key material, re-run mirage-keygen from scratch rather than only rotating the operator key.",
        ],
    };

    let out = json!({
        "mode": match args.mode {
            Mode::Routine => "routine",
            Mode::CompromiseRotateOperator => "compromise-rotate-operator",
        },
        "now_unix": now_unix,
        "rotated_operator_key": rotated,
        "operator": {
            "ed25519_pk_hex": hex_of(&new_op_pk),
            "ed25519_pk_prev_hex": hex_of(&prev_op_pk),
            "ed25519_sk_hex": if args.reveal_operator_sk {
                hex_of(&new_op_sk.to_bytes())
            } else {
                "<REDACTED - pass --reveal-operator-sk to include>".to_string()
            }
        },
        "bridge": {
            "x25519_sk_hex": hex_of(&bridge_x_sk_bytes),
            "x25519_pk_hex": hex_of(&bridge_x_pk),
            "ed25519_pk_hex": hex_of(&bridge_ed_pk),
            "endpoint": endpoint_str
        },
        "invite": {
            "url": invite_url,
            "expires_at": invite_expires_at,
            "token_count": args.tokens,
            "token_ttl_seconds": args.token_ttl_hours * 3600,
            "claim_id_hex": hex_of(&claim_id)
        },
        "sample_bridge_config_overlay": overlay,
        "rotation_notes": notes
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
