# Feature reference

Everything Mirage ships. **All of it is in the standard build** - there are no optional
features, no `--features` flags, and nothing here needs a special compile. Each item is
turned on at runtime in your config.

- [Carriers](#carriers)
- [Layers](#layers)
- [Discovery](#discovery)
- [How you use the tunnel](#how-you-use-the-tunnel)
- [Multi-hop](#multi-hop)
- [Defenses](#defenses)
- [Binaries](#binaries)

---

## Carriers

A **carrier** is the wire shape your session takes. The session crypto is identical in every
case - only the disguise changes. A client can hold several and switch when one stops
working.

| Carrier | Imitates | Transport | Enable with |
|---|---|---|---|
| **Reality** | A real TLS session with a real site | TCP | `reality_enabled` |
| **Hysteria2** | QUIC with aggressive congestion control | UDP | `hysteria2_enabled` |
| **MASQUE / HTTP-3** | HTTP/3 web traffic (session in DATA frames) | UDP | `h3_enabled` |
| **WebRTC** | A video call (DTLS-SCTP data channel) | UDP | `webrtc_enabled` |
| **meek** | HTTPS to a CDN (domain-fronted long-poll) | TCP | `meek_front_domain` (client) |
| **WebSocket** | An HTTP upgrade to a web app | TCP | `ws_enabled` |
| **Shadowsocks-2022** | Nothing - opaque random bytes | TCP | `ss2022_psk_hex` |
| **VLESS** | TLS/WS-framed proxy traffic | TCP | `vless_uuid_hex` |
| **DoH** | DNS-over-HTTPS queries | TCP | `doh_front_domain` (client) |
| **dnstt** | Ordinary DNS queries/responses | UDP | `dnstt_enabled` + `dnstt_domain` |
| **obfs** | Random bytes over bare TCP | TCP | `obfs_enabled` |

**Choosing.** Start with **Reality** - it survives active probing because a prober gets a
genuine TLS session with a real site. Add **Hysteria2** for lossy links. Reach for **meek**
or **dnstt** only when a network is hostile enough to need them; they cost latency or
bandwidth. **Single-port dispatch** lets one bridge port serve every TCP carrier at once.

---

## Layers

Ride on top of any carrier.

| Layer | What it does | Enable with |
|---|---|---|
| **Padding + jitter** | Buckets frame sizes and randomises inter-packet timing, to defeat ML flow fingerprinting. | `pad_enabled` (**both** ends) |
| **CBR mode** | Constant bitrate - near-total shape concealment, high bandwidth cost. | `pad_cbr_frame_bytes` |
| **Stream multiplexing** | Many logical streams over one carrier connection, with per-stream flow control. | `stream_mux_enabled` |
| **Cover traffic** | Fetches real decoy pages while idle, so "idle" doesn't stand out. | `cover_destinations` |

---

## Discovery

How a client finds bridges when it has no invite. Rendezvous locations are derived per
**epoch**, so they rotate on their own.

| Channel | Strength | Weakness | Enable with |
|---|---|---|---|
| **Nostr** | Fast, reliable, many relays | Relays are blockable and can log | `nostr_relays` |
| **DHT** (BEP-44) | No list to seize; global | Slower; the DHT is public | `dht_enabled` |
| **DNS TXT** | Works wherever DNS works | Needs a domain you control | `dns_discovery_apexes` |

You can run several at once. **Invites** remain the direct path and need no channel at all.

---

## How you use the tunnel

**SOCKS5 proxy** - default `127.0.0.1:1080`. No privileges needed. Per-app configuration.
Always use `socks5h://` so DNS resolves at the bridge, not on your machine.

**TUN VPN** - `"tun_enabled": true`. Captures **every TCP and UDP flow** from the whole
device through a userspace IP stack - no per-app setup. On start the client installs the OS
routes that actually redirect traffic into the tunnel (a split-default capture) and adds a
bypass route for each bridge IP so the encrypted carrier itself is not tunnelled; on exit it
restores your routing table. Needs `CAP_NET_ADMIN` or root.

Whole-device routing is wired on **Linux** (`iproute2`), **macOS** (`utun` + `/sbin/route`), and
**Windows** (Wintun + `netsh`). All three need elevation - root/`CAP_NET_ADMIN` on Linux, `sudo`
on macOS, an elevated Administrator terminal on Windows. If routes can't be installed the client
fails closed. The SOCKS5 listener runs alongside TUN everywhere, so apps can use either.

---

## Multi-hop

Chain up to **3 bridges** into an onion circuit. Each hop is authenticated with its own
capability token and can unwrap only its own layer, so no single bridge sees both the client
and the destination. Operators opt in with `circuit_relay_enabled`; clients request it with
`circuit_relay`.

Costs latency and bandwidth. Worth it when the threat is a bridge operator, not just the
network.

---

## Defenses

| Defense | Against |
|---|---|
| **Active-probe resistance** | A censor connecting to your port to test what it is. Unauthenticated probes get a real TLS session with the cover host. |
| **Probe decoy** (`shadow_target`) | Scanners. Unrecognised connections are forwarded to a real server, so the port looks ordinary. |
| **Replay protection** | Recorded handshakes being replayed. Bounded replay window, optionally persisted. |
| **Epoch-rotated rendezvous** | Bulk bridge enumeration via discovery. |
| **Capability tokens** | Unauthorised use. Every session presents a signed, expiring token. |
| **Post-quantum session keys** | "Harvest now, decrypt later." ML-KEM-768 is mixed into the Noise handshake. |
| **Padding + jitter** | ML/DPI flow classifiers. |
| **Replay pacing** (`paranoid` mode) | Traffic-analysis. The flow's packet sizes/timing replay a real recorded video-streaming envelope instead of a generated one; build the library with `tools/cover-sources`. |
| **Log anonymization** | Your own logs being used against your users after a seizure. On by default. |
| **Egress restrictions** | Your bridge being used as an open proxy or for SSRF. Private/loopback targets refused by default. |
| **Rate limiting** | Resource exhaustion and abuse. Per-IP connection and rate caps. |

Limits and non-goals: **[security model](security-model.md)**.

---

## Binaries

Every one is in the standard build.

| Binary | What it's for |
|---|---|
| **`mirage-client`** | The client daemon. SOCKS5 proxy and/or TUN VPN. |
| **`mirage-client-gui`** | Graphical client - paste an invite or browse to a config, click Connect. Slint software renderer (no GTK); ships in the `...-gui` release archives. |
| **`mirage-bridge`** | The bridge daemon operators run. |
| **`mirage-setup`** | Interactive wizard: profiles, preflight checks, writes both configs + a hardened systemd unit. |
| **`mirage-keygen`** | One-shot key/invite generator for scripted deployments. |
| **`mirage-publish`** | Publishes bridge announcements to Nostr / DNS / DHT. Run on your workstation. |
| **`mirage-rotate`** | Key and invite rotation. |
| **`mirage-cover-fetch`** | Downloads a real TLS transcript to use as cover material. |
| **`mirage-cover-record`** | Records a real video stream's wire envelope into the Proteus replay library (paranoid mode). Self-contained - no external tools. |
| **`mirage-cohort-refresh`** | Diagnostic: asks a bridge for a cohort update. |
| **`mirage-pt-client`** | Tor pluggable-transport (PT 2.1) adapter - run Mirage as a Tor PT. |

---

Next: **[Configuration](configuration.md)** * **[Internals](internals.md)** *
**[Security model](security-model.md)**
