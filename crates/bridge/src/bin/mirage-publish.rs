//! `mirage-publish` - operator-automation CLI for periodic
//! announcement publishing (v0.1n; closes the I8 / "operator-
//! published announcements" automation gap noted on the active
//! roadmap).
//!
//! # Why a separate binary
//!
//! The bridge daemon does NOT hold the operator's Ed25519
//! signing key - that's the whole point of the operator/bridge
//! separation. So the bridge can't sign announcements on its own
//! schedule. The pre-v0.1n flow had operators driving
//! `mirage_discovery::OperatorPublisher` from their own Rust
//! glue or shell scripts; this CLI replaces that with a
//! cron-runnable one-shot.
//!
//! # Threat-model placement
//!
//! - This binary HOLDS the operator SK during its short run.
//!   Operators MUST keep the SK on the same host that runs this
//!   tool - typically NOT the bridge host. A pattern that works
//!   well: keep the SK on a dedicated "operator workstation"
//!   that has outbound access to Nostr relays but no inbound
//!   exposure. A systemd-timer fires this CLI hourly.
//! - The published bytes are operator-signed announcements;
//!   compromise of the signing key allows forging future
//!   announcements (covered by the rotation tooling, v0.1i).
//!
//! # Usage
//!
//! ```sh
//! mirage-publish --from /etc/mirage/keygen.json \
//!     --relay wss://relay.damus.io \
//!     --relay wss://nos.lol \
//!     --epochs 0,1   # current + next epoch (default)
//! ```
//!
//! Exit codes:
//! - 0: at least one relay accepted the publish for every
//!   configured epoch.
//! - 2: configuration / argument error.
//! - 3: every relay failed - operator should check connectivity
//!   and the relay list.

use std::sync::Arc;
use std::time::Duration;

use mirage_common::process_hardening::harden_process;
use mirage_crypto::ed25519_dalek::SigningKey;
use mirage_crypto::zeroize::Zeroizing;
use mirage_discovery::channel::DiscoveryChannel;
use mirage_discovery::derive::epoch_for_time;
use mirage_discovery::invite::MasterInvite;
use mirage_discovery::pipeline::OperatorPublisher;
use mirage_discovery::router::{DiscoveryRouter, RouterConfig};
use mirage_discovery::wire::{transport_caps, Announcement, Endpoint, SIG_LEN};
use mirage_discovery_dht::{DhtChannel, MainlineDhtClient};
use mirage_discovery_nostr::relay::{NostrRelayChannel, NostrRelayConfig};
use mirage_discovery_nostr::signing::NostrSigningKey;
use mirage_spec::DISCOVERY_EPOCH_SECONDS;

fn fatal(msg: &str) -> ! {
    eprintln!("fatal: {msg}");
    std::process::exit(2);
}

struct Args {
    from_path: String,
    relays: Vec<String>,
    /// Announce on the BitTorrent mainline DHT (BEP-44) in addition to / instead
    /// of Nostr relays. Censorship-resistant: no relay list to block.
    dht: bool,
    /// Optional custom DHT bootstrap nodes (`host:port`, repeatable). Empty =
    /// the mainline crate's built-in bootstrap set.
    dht_bootstrap: Vec<String>,
    epochs: Vec<i64>,
    bridge_endpoint: Option<String>,
    /// Additional bridge endpoints (multi-endpoint announcement).
    /// May be repeated. Up to
    /// `ANNOUNCEMENT_MAX_EXTRA_ENDPOINTS` entries.
    extra_endpoints: Vec<String>,
    ann_ttl_seconds: u64,
    /// Run as a long-lived daemon: re-publish on every epoch
    /// boundary instead of exiting after one round.
    daemon: bool,
    /// Override the daemon re-publish interval (seconds).
    /// Default: sleep until 60 s after the next epoch boundary.
    daemon_interval_secs: Option<u64>,
}

fn parse_args() -> Args {
    let mut args = Args {
        from_path: String::new(),
        relays: Vec::new(),
        dht: false,
        dht_bootstrap: Vec::new(),
        epochs: vec![0, 1],
        bridge_endpoint: None,
        extra_endpoints: Vec::new(),
        ann_ttl_seconds: 7200, // 2h: covers ~ 2 epochs at the
        // 3600s default; clients pulling
        // late still see a fresh blob.
        daemon: false,
        daemon_interval_secs: None,
    };
    let argv: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--from" => {
                i += 1;
                args.from_path = argv
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| fatal("--from needs a path"));
            }
            "--relay" => {
                i += 1;
                args.relays.push(
                    argv.get(i)
                        .cloned()
                        .unwrap_or_else(|| fatal("--relay needs a URL")),
                );
            }
            "--dht" => {
                args.dht = true;
            }
            "--dht-bootstrap" => {
                i += 1;
                args.dht_bootstrap.push(
                    argv.get(i)
                        .cloned()
                        .unwrap_or_else(|| fatal("--dht-bootstrap needs a host:port")),
                );
            }
            "--epochs" => {
                i += 1;
                let raw = argv
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| fatal("--epochs needs a CSV list"));
                args.epochs = raw
                    .split(',')
                    .map(|s| {
                        s.trim()
                            .parse::<i64>()
                            .unwrap_or_else(|_| fatal(&format!("bad epoch offset: {s:?}")))
                    })
                    .collect();
                if args.epochs.is_empty() {
                    fatal("--epochs cannot be empty");
                }
            }
            "--bridge-endpoint" => {
                i += 1;
                args.bridge_endpoint = Some(
                    argv.get(i)
                        .cloned()
                        .unwrap_or_else(|| fatal("--bridge-endpoint needs a value")),
                );
            }
            "--extra-endpoint" => {
                i += 1;
                let v = argv
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| fatal("--extra-endpoint needs a host:port"));
                args.extra_endpoints.push(v);
            }
            "--ann-ttl-seconds" => {
                i += 1;
                args.ann_ttl_seconds = argv
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| fatal("--ann-ttl-seconds needs an integer"));
            }
            "--daemon" => {
                args.daemon = true;
            }
            "--daemon-interval-secs" => {
                i += 1;
                args.daemon_interval_secs = Some(
                    argv.get(i)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or_else(|| fatal("--daemon-interval-secs needs an integer")),
                );
            }
            "-h" | "--help" => {
                eprintln!(
                    "usage: mirage-publish --from <keygen.json> \
                     [--relay <wss://...> ...] [--dht] \
                     [--dht-bootstrap host:port ...] \
                     [--epochs offset1,offset2,...] \
                     [--bridge-endpoint host:port] \
                     [--extra-endpoint host:port] [--extra-endpoint ...] \
                     [--ann-ttl-seconds N] \
                     [--daemon [--daemon-interval-secs N]]\n\
                     \n\
                     At least one channel is required: --relay (Nostr) and/or\n\
                     --dht (BitTorrent mainline DHT, BEP-44 - no relay list to\n\
                     block). --dht-bootstrap adds custom DHT bootstrap nodes.\n\
                     \n\
                     Default --epochs is `0,1` (current + next). Negative\n\
                     offsets are accepted but rarely useful - clients fetching\n\
                     historical epochs already moved on.\n\
                     \n\
                     --extra-endpoint repeats up to {} times to advertise\n\
                     additional bridge IPs in a v0.1t multi-endpoint\n\
                     announcement. Operators with bridge-IP\n\
                     rotation SHOULD list every reachable endpoint here.\n\
                     \n\
                     --daemon: stay running and re-publish each epoch boundary\n\
                     (default: exit after one round; use systemd timer or cron\n\
                     for scheduled one-shot). With --daemon the process never\n\
                     exits 3 - relay failures are logged and retried next cycle.\n\
                     --daemon-interval-secs N: override the sleep between\n\
                     publish runs (default: sleep to 60 s after each epoch\n\
                     boundary, i.e. ~1 h minus clock offset).",
                    mirage_discovery::wire::ANNOUNCEMENT_MAX_EXTRA_ENDPOINTS,
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
    if args.relays.is_empty() && !args.dht {
        fatal("at least one announcement channel is required: --relay <wss://...> and/or --dht");
    }
    args
}

/// Parse the optional `--extra-endpoint` list into Endpoint values.
/// Caps at `ANNOUNCEMENT_MAX_EXTRA_ENDPOINTS`; refuses to start with
/// more (operator can re-run with fewer or split into separate
/// announcements).
fn extra_endpoints_from_args(args: &Args) -> Vec<Endpoint> {
    if args.extra_endpoints.len()
        > mirage_discovery::wire::ANNOUNCEMENT_MAX_EXTRA_ENDPOINTS as usize
    {
        fatal(&format!(
            "too many --extra-endpoint entries (max {})",
            mirage_discovery::wire::ANNOUNCEMENT_MAX_EXTRA_ENDPOINTS
        ));
    }
    args.extra_endpoints
        .iter()
        .map(|s| parse_endpoint(s))
        .collect()
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

/// Decode a 32-byte hex string into a `Zeroizing` array. The
/// input `s` came from the keygen JSON (operator-controlled) and
/// is treated as sensitive - operator SKs flow through this
/// path. Raw and decoded forms zero on drop.
fn hex_to_key32_zeroizing(s: &str, name: &str) -> Zeroizing<[u8; 32]> {
    let raw = Zeroizing::new(
        hex::decode(s.trim()).unwrap_or_else(|e| fatal(&format!("{name}: hex decode: {e}"))),
    );
    if raw.len() != 32 {
        fatal(&format!("{name}: expected 32 bytes, got {}", raw.len()));
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&raw);
    out
}

/// Decode a 32-byte hex into a plain `[u8; 32]` - for non-secret
/// public keys / endpoint material that doesn't need zeroize.
fn hex_to_key32(s: &str, name: &str) -> [u8; 32] {
    let raw = hex::decode(s.trim()).unwrap_or_else(|e| fatal(&format!("{name}: hex decode: {e}")));
    if raw.len() != 32 {
        fatal(&format!("{name}: expected 32 bytes, got {}", raw.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    out
}

#[tokio::main]
async fn main() {
    if let Err(e) = harden_process() {
        fatal(&format!("harden_process: {e}"));
    }
    let args = parse_args();

    // Load operator + bridge keys + endpoint from the keygen JSON.
    // The file may contain the operator SK (sensitive). Hold the
    // raw JSON string in `Zeroizing` so its heap-backing is wiped
    // on drop - RT-publish-4.
    let raw = Zeroizing::new(
        std::fs::read_to_string(&args.from_path)
            .unwrap_or_else(|e| fatal(&format!("read {}: {e}", args.from_path))),
    );
    let json: serde_json::Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| fatal(&format!("parse json: {e}")));

    let op_sk_hex = json
        .pointer("/operator/ed25519_sk_hex")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| fatal("source JSON has no operator.ed25519_sk_hex"));
    if op_sk_hex.starts_with('<') {
        fatal(
            "source JSON has a redacted operator SK placeholder. Re-run mirage-keygen with \
             --reveal-operator-sk on the air-gapped machine and feed THAT JSON to mirage-publish.",
        );
    }
    let op_sk_bytes = hex_to_key32_zeroizing(op_sk_hex, "operator.ed25519_sk_hex");
    let op_sk = SigningKey::from_bytes(&op_sk_bytes);

    // Resolve the shared salt by going through the invite's
    // canonical decode path - RT-publish-5: avoids ad-hoc byte
    // slicing that silently extracts garbage on a malformed URL.
    let invite_url = json
        .pointer("/invite/url")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| fatal("source JSON has no invite.url"));
    let invite =
        MasterInvite::decode_text(invite_url.strip_prefix("mirage://").unwrap_or(invite_url))
            .unwrap_or_else(|e| fatal(&format!("invite.url: {e}")));
    let shared_salt = *invite.shared_salt;
    // Sanity: invite's operator pubkey must match our SK's pubkey.
    let derived_op_pk = op_sk.verifying_key().to_bytes();
    if derived_op_pk != invite.operator_ed25519_pk {
        fatal(
            "operator.ed25519_sk_hex does not derive to invite.operator_ed25519_pk; \
             the two fields are out of sync - verify the keygen JSON has not been edited.",
        );
    }

    let bridge_x_pk = hex_to_key32(
        json.pointer("/bridge/x25519_pk_hex")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| fatal("source JSON has no bridge.x25519_pk_hex")),
        "bridge.x25519_pk_hex",
    );
    let bridge_ed_pk = hex_to_key32(
        json.pointer("/bridge/ed25519_pk_hex")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| fatal("source JSON has no bridge.ed25519_pk_hex")),
        "bridge.ed25519_pk_hex",
    );
    let endpoint_str = args.bridge_endpoint.clone().unwrap_or_else(|| {
        json.pointer("/bridge/endpoint")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| {
                fatal("source JSON has no bridge.endpoint and --bridge-endpoint not given")
            })
    });
    let endpoint = parse_endpoint(&endpoint_str);

    // Effective TTL - static across daemon runs because the epoch-offset
    // list and operator-requested TTL don't change between iterations.
    // RT-publish-2: `expires_at` MUST cover the latest epoch we intend to
    // publish for so an announcement for epoch+N is not born already-expired.
    let max_offset = args.epochs.iter().copied().max().unwrap_or(0).max(0) as u64;
    let needed_for_top_offset = max_offset
        .saturating_mul(DISCOVERY_EPOCH_SECONDS)
        .saturating_add(DISCOVERY_EPOCH_SECONDS); // grace into the next epoch
    let effective_ttl = args.ann_ttl_seconds.max(needed_for_top_offset);
    if effective_ttl > args.ann_ttl_seconds {
        eprintln!(
            "note: extending announcement TTL from {}s to {}s to cover --epochs offset +{}",
            args.ann_ttl_seconds, effective_ttl, max_offset
        );
    }

    // Static announcement fields (timestamps filled in per-run so they
    // stay fresh across daemon iterations instead of ageing from startup).
    let ann_static = Announcement {
        issued_at: 0,
        expires_at: 0,
        bridge_ed25519_pk: bridge_ed_pk,
        bridge_x25519_pk: bridge_x_pk,
        transport_caps: transport_caps::REALITY_V2,
        endpoint,
        extra_endpoints: extra_endpoints_from_args(&args),
        signature: [0u8; SIG_LEN],
    };

    // Build the router with one channel per --relay URL.
    let mut channels: Vec<Arc<dyn DiscoveryChannel>> = Vec::with_capacity(args.relays.len());
    for url in &args.relays {
        let cfg_name: &'static str = Box::leak(format!("nostr:{url}").into_boxed_str());
        let cfg = NostrRelayConfig {
            url: url.clone(),
            name: cfg_name,
            io_timeout: Duration::from_secs(15),
            fetch_event_cap: 64,
            fetch_byte_cap: 256 * 1024,
            created_at_since: None,
            default_event_ttl_secs: Some(args.ann_ttl_seconds),
        };
        // Per-EPOCH Nostr identity: the fixed disposable key is only a fallback;
        // `.with_epoch_secret` makes each publish sign with a key derived from
        // (operator_secret, info_hash), so the author pubkey rotates every epoch
        // and a Nostr `authors` filter cannot enumerate the operator's
        // rendezvous history across epochs (red-team HIGH #8). The base is
        // derived from the operator SK, NOT the invite salt, so invite-holders
        // cannot forge publishes (audit CRIT #17/#18). Matches the DHT channel's
        // blinded keys.
        let nostr_epoch_secret: [u8; 32] =
            *mirage_crypto::blake3::Hasher::new_derive_key("mirage nostr epoch base v2")
                .update(&op_sk_bytes[..])
                .finalize()
                .as_bytes();
        let nostr_key = NostrSigningKey::generate();
        let ch = NostrRelayChannel::new(cfg, nostr_key)
            .unwrap_or_else(|e| fatal(&format!("relay {url}: {e}")))
            .with_epoch_secret(nostr_epoch_secret)
            // Mask the NIP-44 frame length with the cohort shared_salt so a relay
            // scraper cannot enumerate announcements (red-team).
            .with_frame_salt(shared_salt);
        channels.push(Arc::new(ch));
    }

    // BitTorrent mainline DHT (BEP-44) publish channel. No relay list to block:
    // announcements are stored under the per-epoch info-hash across the global
    // DHT and fetched by clients with the operator pubkey. Signs with the same
    // operator key as the announcement; seq is wall-clock seconds (monotonic, so
    // a re-publish is never rejected as stale).
    if args.dht {
        let dht_client = if args.dht_bootstrap.is_empty() {
            MainlineDhtClient::new()
        } else {
            MainlineDhtClient::new_with_bootstrap(&args.dht_bootstrap)
        }
        .unwrap_or_else(|e| fatal(&format!("dht: failed to start mainline client: {e}")));
        let seq_supplier = || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
                .unwrap_or(0)
        };
        // The DHT put is signed by a per-epoch BLINDING of the operator
        // identity key (audit CRIT #17/#18): the on-wire pubkey `k` is
        // `t*A_id`, so it still doesn't leak the operator identity or link
        // across epochs - but only a holder of the operator SECRET (this
        // binary) can sign it. Invite-holders derive the same blinded pubkey
        // from the operator's PUBLIC key to read, yet cannot forge a PUT.
        let ch = DhtChannel::new(dht_client, *op_sk_bytes, seq_supplier);
        channels.push(Arc::new(ch));
        eprintln!(
            "note: publishing to the mainline DHT ({} custom bootstrap node(s))",
            args.dht_bootstrap.len()
        );
    }

    let router = DiscoveryRouter::new(channels, RouterConfig::default());
    let mut publisher = OperatorPublisher::new(&op_sk, shared_salt, router);
    // Forward-secret rendezvous: when the invite carries the flag, drive a
    // one-way ratchet anchored at the invite's issue epoch and DISCARD the salt,
    // so a seizure of this publisher host cannot decrypt archived past-epoch
    // announcements (producer forward secrecy). The client keeps the salt and
    // opens blobs normally.
    if invite.forward_secret_rendezvous {
        let anchor = invite.fs_anchor_epoch();
        let now_epoch = epoch_for_time(unix_now());
        publisher = publisher.with_forward_secret_ratchet(anchor, now_epoch);
        eprintln!(
            "forward-secret rendezvous ON: ratchet anchored at epoch {anchor}, salt discarded"
        );
    }

    // Initial publish run.
    let ok = do_publish_run(&publisher, &args.epochs, &ann_static, effective_ttl).await;

    if !args.daemon {
        std::process::exit(if ok { 0 } else { 3 });
    }

    // Daemon loop: re-publish each epoch boundary.
    // Relay failures are logged but do not abort - the next cycle retries.
    eprintln!("daemon: running continuously (Ctrl+C to stop)");
    loop {
        let now = unix_now();
        let sleep_secs = match args.daemon_interval_secs {
            Some(n) => n,
            None => {
                // Sleep to 60 s after the start of the next epoch so we
                // publish a fresh announcement for the new epoch shortly
                // after it opens - before any client's poll fires.
                let secs_into_epoch = now % DISCOVERY_EPOCH_SECONDS;
                let secs_to_boundary = DISCOVERY_EPOCH_SECONDS - secs_into_epoch;
                secs_to_boundary + 60
            }
        };
        eprintln!("daemon: next publish in {sleep_secs}s");
        tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
        let _ok = do_publish_run(&publisher, &args.epochs, &ann_static, effective_ttl).await;
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One publish round: sign + seal + fan-out for every requested epoch offset.
///
/// Fills fresh `issued_at`/`expires_at` into each announcement clone so
/// daemon iterations don't hand out timestamps that age from startup.
/// Returns `true` when every epoch succeeded on at least one relay.
async fn do_publish_run(
    publisher: &OperatorPublisher<'_>,
    epochs: &[i64],
    ann_static: &Announcement,
    effective_ttl: u64,
) -> bool {
    let now = unix_now();
    let now_epoch = epoch_for_time(now);
    // Forward-secret mode: advance the ratchet floor to the current epoch,
    // deleting every earlier key (no-op in baseline mode). The publisher then
    // seals only current + future epochs; a negative `--epochs` offset (a past
    // epoch) is unrepresentable in FS mode and its publish will fail cleanly.
    publisher.advance_fs_floor(now_epoch);
    let mut overall_ok = true;
    for offset in epochs {
        let target_epoch = (now_epoch as i64 + offset).max(0) as u64;
        // Clone static fields and stamp fresh timestamps + zero signature.
        // The publisher re-signs each clone before sealing, so the zero
        // signature here is intentional (publish_announcement requires it).
        let mut ann = ann_static.clone();
        ann.issued_at = now;
        ann.expires_at = now.saturating_add(effective_ttl);
        ann.signature = [0u8; SIG_LEN];
        match publisher.publish_announcement(ann, target_epoch).await {
            Ok(summary) => {
                let any_ok = summary.any_success();
                println!(
                    "epoch={target_epoch} (offset {offset:+}): {}",
                    if any_ok { "OK" } else { "ALL_FAIL" }
                );
                for r in &summary.reports {
                    let outcome = match &r.outcome {
                        Ok(()) => "ok".to_string(),
                        Err(e) => format!("err: {e}"),
                    };
                    println!("  {} -> {outcome}", r.channel);
                }
                if !any_ok {
                    overall_ok = false;
                }
            }
            Err(e) => {
                eprintln!("epoch={target_epoch}: pipeline error: {e}");
                overall_ok = false;
            }
        }
    }
    overall_ok
}
