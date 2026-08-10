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
| `wu_evasion` | `false` | Wear the Wu-2023 printable preamble on the high-entropy carriers (obfuscated QUIC + Shadowsocks-2022) so their uniform-random wire clears the GFW's fully-encrypted-traffic classifier. A per-network posture; must match the bridge. Also lets Shadowsocks stand alone under entropy DPI (see `allow_ss2022_outer`). |
| `dnstt_enabled`, `dnstt_domain`, `dnstt_resolver` | `false` | DNS-tunnel carrier, its zone, and the resolver to use. |
| `meek_front_domain`, `meek_path` | - | Domain-fronting (meek) front host and path. |
| `doh_front_domain` | - | DNS-over-HTTPS front domain. |
| `webrtc_signaling_host`, `webrtc_path`, `webrtc_ice_servers` | - | WebRTC carrier signaling host, path, and ICE servers. |
| `vless_uuid_hex` | - | VLESS credential (must match the bridge). |
| `allow_insecure_raw` | `false` | Permit the unauthenticated plain-TCP carrier (testing only). |

### Whole-device VPN (TUN)

See [getting-started section 4](getting-started.md#4-whole-device-vpn-optional). Linux
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

### Proteus (traffic shaping)

Makes the tunnel's wire shape a real recorded flow's instead of its own. Applies to every
paced carrier, not just Reality. **Both ends must agree**: Proteus adds framing, so one
side shaping and the other not hangs the session rather than merely looking different.

| Key | Default | Meaning |
|---|---|---|
| `proteus` | - | `true` turns it on and is normally all you need - the daemon sources and refreshes its own cover library in the background. Also accepts a cost tier: `lean` (default, 2.5 GB/day = ~0.23 Mbit/s sustained) or `balanced` (6 GB/day = ~0.56 Mbit/s). A tier is a THROUGHPUT and LATENCY choice, not a concealment one - both measured indistinguishable from each other (which is not the same as undetectable; a small residual activity signal remains on every budget tested, see docs/proteus.md). Measured medians on the dwelled cover these tiers were taken against: lean 9-13 KB/s, balanced 13-21 KB/s. At the default tiers Proteus is a low-bandwidth channel, but that is the BUDGET, not the design - see `proteus_max_gb_day` and docs/proteus.md. Also accepts an explicit mode: `"replay"` (what `true` means) or the weaker generative classes `"video"`/`"browse"`. |
| `proteus_max_gb_day` | the tier's ceiling | Your own cover budget instead of a tier's, as a number in GB/day (`40`) or the string `"unlimited"`. **This is the throughput dial**: cover rate and tunnel rate are the same quantity, 1:1, so doubling the budget doubles the ceiling. It also sets worst-case LATENCY, because cheap cover cannot also be smooth - see [Proteus](proteus.md). `"unlimited"` means no capture is ever rejected for cost, and admits the high-bitrate video class - the only cover fast enough to carry a tunnel at line speed, though that path is not yet validated end to end (see [Proteus](proteus.md)). Billed only while a session is open. |
| `proteus_sources` | `global` | Where cover is recorded FROM: `global`, a region (`cn`, `ir`, `ru`, `tr`), or a comma-separated list of your own URLs. **The default is Wikipedia + PeerTube, which is blocked in several of the places this tool is for** - set a region or your own list on a censored client. |
| `proteus_profile` | - | Pin a specific trace file or library directory instead. **Setting this turns auto-sourcing off**, and also turns off the bridge-library sync. |
| `proteus_profile_up` | - | Separate library for the UPSTREAM direction. Self-sourcing sets this to the dense `upstream` class automatically; if you pin `proteus_profile` by hand you should set this too, or the tunnel inherits a 20x-slower download. Note that pointing `proteus_profile` at a library ROOT pools the class subdirs for downstream but deliberately EXCLUDES `upstream/`, which is recorded dense to carry flow control and is the wrong shape to wear as downstream browsing. See [Proteus](proteus.md). |

Cost ceilings cap what an envelope costs to replay, by **rejecting a capture and recording a
different one** - every trace stays a real capture, so a budget changes which real flow gets
worn and never synthesises a cheaper-looking one. The same accept-or-re-record machinery
enforces the latency ceiling, the opening-silence check and the upstream-gap check; a
capture that fails any of them is replaced rather than repaired.

The auto-sourced library lands in `$MIRAGE_STATE_DIR/cover`, else `$XDG_STATE_HOME/mirage/cover`,
else `~/.local/state/mirage/cover`. Env equivalents: `MIRAGE_PROTEUS`,
`MIRAGE_PROTEUS_PROFILE`, `MIRAGE_PROTEUS_PROFILE_UP`.

`paranoid: true` turns Proteus on as part of the strong posture. Details, including
per-site target-conditioned replay and what a given envelope costs to replay
continuously: [cover sources](../tools/cover-sources/README.md).

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
| `wu_evasion` | `false` | Wear the Wu-2023 printable preamble on the high-entropy carriers (obfuscated QUIC + Shadowsocks-2022). For QUIC it must match the client; Shadowsocks is auto-detected per connection. Enable on networks running GFW-class entropy DPI. |
| `dnstt_enabled`, `dnstt_domain`, `dnstt_bind` | `false` | DNS-tunnel carrier. |
| `vless_uuid_hex` | - | VLESS credential. |
| `shadow_target`, `http_shadow_target` | `reality_cover_addr` | Where unauthenticated/probe traffic is transparently forwarded. Both default to `reality_cover_addr` verbatim. **Leave them alone unless you know why.** See below. |

#### Why the probe decoys default to the cover host

Both fields forward probe traffic somewhere; the question is where. The answer is
not "anywhere plausible", and it is not even "the right host on a sensible port" -
it is **`reality_cover_addr` exactly**. That is a measured result rather than a
preference, and both of the plausible-looking alternatives were tried and leak.

The test scores a single endpoint's probe classes *against each other*: send 17
TLS/HTTP-shaped probes, take each class's median latency, and ask whether they
form one cluster or two. A real web host forwards nothing, so every class costs
one round trip and the medians are unimodal. A bridge that answers some classes
locally and forwards the rest splits into a fast group and a slow group. The
split needs no reference capture of the genuine host, which is what makes it
worth defending against.

Against a live bridge:

| `http_shadow_target` | `http11` bytes | `http11` timing | gap stat G | p |
|---|---|---|---|---|
| unset | 0 vs 0 | 21.3 / 33.4 ms | 10.74 | 0.0002 |
| `example.com:80` | 406 vs 0 | 13.5 / 32.4 ms | 10.90 | 0.0002 |
| cover host `:80` | **173 vs 0** | 32.0 / 31.9 ms | 0.23 | 1.0 |
| **`reality_cover_addr`** (`:443`) | **0 vs 0** | **32.0 / 31.9 ms** | **0.47** | **0.9993** |

Row 2 is why "point it at a plaintext-HTTP server" - all the old startup warning
asked for - is not the fix. It moves the outlier from 21.3 ms to 13.5 ms and leaves
the endpoint exactly as separable. The observable was never "does this answer HTTP
plausibly"; it is **"does this cost what the cover host costs,"** and only a decoy
at the cover's own distance pays the right price.

Row 3 is why the **port** matters, and it is a tell this project introduced while
fixing the timing one. The cover's `:443` is a TLS port: it answers a plaintext GET
with silence and a FIN. Its `:80` answers with a real 301. So forwarding to `:80`
closed the timing partition and opened a **173-vs-0 byte channel** - the worse of the
two, because bytes are categorical and cost a prober a single probe rather than a
hundred.

Row 4 is the answer, and it is the same principle as the rest of the design:
**forward, do not emulate.** Send failed HTTP probes to the cover's own TLS port and
the genuine host produces both the silence and the round trip, because it is the
genuine host doing it.

The bridge now warns on a different host *and* on the right host at a different
port. Reproduce with `scripts/probe-suite/`; predictions and outcomes are recorded
before each run in `scripts/probe-suite/PREREGISTERED.md`.

#### Cover-host choice is a latency decision

A related measurement, from the same suite: a splice does not add cost, it
**relocates** cost out of the connect phase into the response phase, because its own
setup to the cover happens after the prober's connect has already returned.

    cover host : connect 17.84 + post-connect 14.11 = 31.95 ms
    bridge     : connect  0.09 + post-connect 31.89 = 31.98 ms

The bridge's post-connect cost equals the cover's *entire* cost to within 0.06 ms.
The size of that relocation is the **bridge-to-cover RTT**, so a bridge network-close
to its cover host is far harder to separate on timing than one far from it.

Prefer a `reality_cover_addr` that is close to the bridge. This is not yet checked at
startup, and the figures above come from a bridge on loopback - they are a lower
bound on a real deployment's gap, not a measurement of one.

**What this does not fix.** The cross-arm comparator (`compare.py`, which does need
a synchronised capture of the real host) still separates 9 of 17 classes on byte-level
and connection-lifecycle differences. Closing the partition removes the tell available
to a prober who knows only the bridge's address; it does not make the bridge
indistinguishable from the host it fronts.

The bridge takes the same `proteus` / `proteus_profile` / `proteus_profile_up` keys as the
client, with the same meanings - see [Proteus](#proteus-traffic-shaping). Both ends must
have it on.

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
service - see [operators.md section 8](operators.md#8-admin-web-ui-optional). Enable it
with the `--admin-ui` flag or these keys:

| Key | Default | Meaning |
|---|---|---|
| `admin_bind` | - (off) | `host:port` for the admin UI. **Loopback only** (it reads and writes this config, including secrets). The `--admin-ui [addr]` flag enables it too and overrides this. |
| `admin_service` | `mirage-bridge` | systemd unit the UI's **Restart** button targets. |

---

Secrets (`*_sk_hex`, `*_secret_hex`, `ss2022_psk_hex`, the `invite`) are
sensitive. Keep bridge/client config files `0600`; `mirage-setup` and
`mirage-keygen` write them that way. Never commit them.
