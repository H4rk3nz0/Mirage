# Configuration

Mirage is configured with a single JSON file per role - one for the **client**,
one for the **bridge**. Every carrier, discovery channel, and feature is
compiled into the binary; the config selects what runs. There are no build-time
feature flags to get wrong.

Point a daemon at its file with `--config <path>` (or the role's default path).
`mirage-setup` generates working files for both roles - start there and tune
below.

Unlisted keys take their default. Booleans default to `false`, optional strings
to unset, and lists to empty unless noted.

---

## Client

### Connection

| Key | Default | Meaning |
|---|---|---|
| `local_bind` | `127.0.0.1:1080` | SOCKS5 listen address. Use `socks5h://` in apps so DNS resolves at the bridge. |
| `invite` | - | A single `mirage://...` invite. |
| `invites` | `[]` | Multiple invites (a cohort). The client pools all their bridges. |
| `handshake_timeout_secs` | `10` | Per-bridge handshake deadline. |
| `entry_failure_backoff_secs` | `30` | How long a bridge that just failed is skipped. |
| `success_state_path` | - | Absolute path to persist learned per-network carrier success across restarts. |
| `circuit_relay` | `false` | Request multi-hop onion routing (bridge must allow it). |

### Carrier selection

Carriers are tried adaptively; enabling more gives the client more ways around a
block. Each is selected at runtime - nothing to recompile.

| Key | Default | Meaning |
|---|---|---|
| `reality_enabled` | `false` | Reality TLS-mimicry carrier. |
| `reality_sni` | - | Cover SNI the Reality handshake presents. |
| `reality_tls_fingerprint` | - | ClientHello fingerprint profile to imitate. |
| `carrier_tls`, `carrier_tls_sni` | - | Generic TLS carrier + its SNI. |
| `ws_enabled`, `ws_path` | `false`, `/` | WebSocket carrier and its request path. |
| `quic_obfs_password` | - | Shared password for QUIC (Hysteria2/H3) obfuscation. |
| `quic_obfs_disable` | `false` | Turn QUIC obfuscation off (must match the bridge). |
| `dnstt_enabled`, `dnstt_domain`, `dnstt_resolver` | `false` | DNS-tunnel carrier, its zone, and the resolver to use. |
| `meek_front_domain`, `meek_path` | - | Domain-fronting (meek) front host and path. |
| `doh_front_domain` | - | DNS-over-HTTPS front domain. |
| `webrtc_signaling_host`, `webrtc_path`, `webrtc_ice_servers` | - | WebRTC carrier signaling host, path, and ICE servers. |
| `vless_uuid_hex` | - | VLESS credential (must match the bridge). |
| `allow_insecure_raw` | `false` | Permit the unauthenticated plain-TCP carrier (testing only). |

### Whole-device VPN (TUN)

See [getting-started §4](getting-started.md#4-whole-device-vpn-optional). Linux
only today; fails closed elsewhere.

| Key | Default | Meaning |
|---|---|---|
| `tun_enabled` | `false` | Capture the whole device, not just SOCKS-configured apps. |
| `tun_name` | `mirage0` | Interface name. |
| `tun_address` | `10.200.0.1` | Interface address. |
| `tun_netmask` | `255.255.255.0` | Interface netmask. |
| `tun_mtu` | `1400` | Interface MTU. |

### Discovery

| Key | Default | Meaning |
|---|---|---|
| `nostr_relays` | `[]` | Nostr relay URLs to fetch bridge announcements from. |
| `dns_discovery_apexes` | `[]` | DNS apexes carrying TXT-record announcements. |
| `dht_enabled` | `false` | Discover bridges over the BitTorrent mainline DHT. |
| `dht_bootstrap_addrs` | `[]` | Custom DHT bootstrap nodes. |
| `discovery_interval_secs` | `300` | How often to re-fetch announcements. |

### Privacy & cover traffic

| Key | Default | Meaning |
|---|---|---|
| `pad_enabled` | `false` | Constant-bitrate padding on carrier streams. |
| `pad_cbr_frame_bytes`, `pad_cbr_interval_ms` | -, `10` | Padding frame size and cadence. |
| `stream_mux_enabled` | `false` | Multiplex multiple flows over one carrier connection. |
| `cover_destinations` | `[]` | Real hosts to fetch as decoy traffic when idle. |
| `cover_idle_secs`, `cover_interval_secs` | `60`, `30` | Idle threshold before cover starts and its cadence. |
| `cover_max_fraction` | `0.05` | Cap cover at this fraction of real traffic. |

---

## Bridge

### Listener & limits

| Key | Default | Meaning |
|---|---|---|
| `bind` | - | Address the bridge listens on. |
| `max_concurrent_sessions` | - | Cap on simultaneous sessions. |
| `handshake_timeout_secs` | `10` | Per-connection handshake deadline. |
| `replay_capacity` | - | Size of the token/handshake replay set. |
| `rate_limit_per_ip_per_minute`, `max_concurrent_per_ip`, `rate_limit_max_entries` | - | Per-IP rate limiting. |

### Exit policy (SSRF containment)

| Key | Default | Meaning |
|---|---|---|
| `allow_private_network_targets` | `false` | Permit proxying to RFC1918/CGNAT/ULA. Loud opt-in. |
| `allow_loopback_targets` | `false` | Permit proxying to loopback - **independent** of the above. |
| `anonymize_target_logs` | `true` | Replace the destination with `<anonymized>` in logs. |
| `anonymize_client_logs` | `true` | Anonymize client IPs in logs. |

> Link-local, the cloud-metadata endpoint, and multicast are refused regardless
> of these flags.

### Carriers (bridge side)

| Key | Default | Meaning |
|---|---|---|
| `reality_enabled`, `reality_cover_addr(s)` | `false` | Reality carrier and the real cover site(s) it fronts. |
| `reality_tls_mode` | `ephemeral` | Reality TLS identity: `ephemeral` (a fresh self-signed cert per connection), `pinned` (serve `reality_tls_cert_der_path`, signed by `reality_tls_signing_sk_hex`), or `borrow` (auto-fetch the cover site's real leaf cert at startup for passive cert-comparison parity - still needs `reality_tls_signing_sk_hex`, and requires `reality_cover_addr(s)`). |
| `reality_tls_cert_der_path`, `reality_tls_signing_sk_hex` | - | Pinned-cert DER path and its Ed25519 signing key (required for `pinned`; `borrow` needs only the signing key). |
| `reality_probe_accept_legacy` | `false` | Accept pre-epoch-MAC probes (keep off unless mid-migration). |
| `hysteria2_enabled`, `hysteria2_bind` | `false` | Hysteria2 QUIC carrier and its UDP listener (defaults to the `bind` host:port). |
| `hysteria2_send_rate_mbps` | `100` | Advertised send rate (Mbps) the Hysteria2 congestion control paces to. |
| `hysteria2_hostname` | - | TLS front (SNI) the Hysteria2 listener presents. Set a real HTTP/3 origin you actually serve; empty derives a per-bridge SAN from the static key. |
| `hysteria2_brutal` | `false` | Opt-in BRUTAL loss-immune congestion control. Leave OFF except on genuinely lossy/hostile links - a constant send rate is itself a behavioural tell. |
| `hysteria2_cert_der_path`, `hysteria2_key_der_path` | - | Serve a real leaf cert (DER) + PKCS#8 key (DER) instead of a self-signed one; set **both or neither**. Closes the self-signed-cert active-prober tell. |
| `obfs_enabled`, `obfs_bind` | `false` | obfs-tcp carrier and its listener. |
| `ws_enabled` | `false` | Accept the WebSocket carrier. |
| `quic_obfs_password`, `quic_obfs_secret_hex`, `quic_obfs_disable` | - | QUIC obfuscation credentials. `quic_obfs_secret_hex` also keys the anti-probe knock - set it, and it's embedded in invites automatically. |
| `dnstt_enabled`, `dnstt_domain`, `dnstt_bind` | `false` | DNS-tunnel carrier. |
| `vless_uuid_hex` | - | VLESS credential. |
| `shadow_target`, `http_shadow_target` | - | Where unauthenticated/probe traffic is transparently forwarded (the cover). |

### Multi-hop

| Key | Default | Meaning |
|---|---|---|
| `circuit_relay_enabled` | `false` | Act as a relay hop in onion circuits. |
| `relay_peers` | `[]` | Next-hop bridges this relay may extend to. |

### Discovery publishing & cohorts

Announcements are published by `mirage-publish` (which holds the operator key
only during its run). Related keys: `cohort_announcements_path`,
`cohort_reveal_cap_per_token`, `cohort_reveal_jitter`, `refresh_enabled`,
`refresh_per_root_cap`, `refresh_ttl_seconds`, `claim_enabled`, `claim_capacity`.

### Port-hopping

Port-hopping rotates the listen port every epoch from a shared salt, so a censor
who blocks one port loses it within an epoch. When enabled, the bridge listens on
the **current and next epoch's derived ports in addition to `bind`**, and clients
must hold a matching `port_hop` invite (mint one with `mirage-keygen
--port-base <N> --port-range <N>`).

| Key | Default | Meaning |
|---|---|---|
| `derived_port_base` | - (off) | Lower bound (>= 1024) of the derived-port range. Set with `derived_port_range` to enable. |
| `derived_port_range` | - | Width of the range. Typical `100`-`8192`; larger = more rotation entropy and more collateral cost to a censor blocking the whole range. |
| `derived_port_shared_salt_hex` | - | 32-byte hex salt shared with clients (carried by the `port_hop` invite / keygen JSON). **Required** - without it the feature stays disabled (the bridge warns and falls back to `bind` only). |
| `derived_port_bind_host` | host of `bind` | Bind host for the derived ports. Rarely overridden. |

### Metrics, gossip, durability

`metrics_bind` exposes Prometheus metrics (keep it on loopback). `gossip_*` lets a
fleet of bridges share probe intelligence. Replay/claim durability is controlled
by `replay_log_path` / `claim_log_path` and their `_fsync` toggles.

### Admin web UI

An optional local web UI to view live counters, edit this config, and restart the
service - see [operators.md §8](operators.md#8-admin-web-ui-optional). Enable it
with the `--admin-ui` flag or these keys:

| Key | Default | Meaning |
|---|---|---|
| `admin_bind` | - (off) | `host:port` for the admin UI. **Loopback only** (it reads and writes this config, including secrets). The `--admin-ui [addr]` flag enables it too and overrides this. |
| `admin_service` | `mirage-bridge` | systemd unit the UI's **Restart** button targets. |

---

Secrets (`*_sk_hex`, `*_secret_hex`, `ss2022_psk_hex`, the `invite`) are
sensitive. Keep bridge/client config files `0600`; `mirage-setup` and
`mirage-keygen` write them that way. Never commit them.
