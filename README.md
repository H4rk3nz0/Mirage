# Mirage

**A censorship-resistance framework stack.** Pluggable carriers, epoch-rotated bridge
discovery, authenticated session crypto, and optional onion routing - behind one local
SOCKS5 proxy or a full-device VPN.

> **Status:** `0.1.3-alpha.1`. Deployable today. Wire formats and config may still change
> before `0.1.0`.

Mirage is not a single protocol. It is a **stack of interchangeable layers** - you pick
what your network lets through, and the same session crypto rides on top of any of them.

---

## Why it works

| Principle | What it means |
|---|---|
| **Don't be invisible, be uninteresting** | Ride protocols the censor doesn't want to block - HTTP/3, WebRTC, DNS-over-HTTPS, TLS. |
| **The adversary pays per block** | Blocking Mirage should mean blocking Cloudflare, or video calls, or DNS. That's a bill they have to justify. |
| **Small blast radius** | Losing a bridge, a discovery channel, a key, or the upstream CDN degrades gracefully. Nothing takes down the fleet. |

**One build, every capability.** There are no `--features` flags to remember and no
"optional" builds. Every carrier, every discovery channel, the GUI, and the TUN VPN are
compiled into the standard build. What you actually use is chosen at **runtime, in config**.

---

## Get started

**-> [Full documentation](docs/)**

| I want to... | Start here |
|---|---|
| Connect to a bridge someone gave me | **[Getting started](docs/getting-started.md)** |
| Run a bridge for others | **[Operator guide](docs/operators.md)** |
| Know what's in the box | **[Feature reference](docs/features.md)** |
| Understand how it works | **[Internals](docs/internals.md)** |
| Tune every knob | **[Configuration](docs/configuration.md)** |
| Know what it does and doesn't protect | **[Security model](docs/security-model.md)** |

### 60-second version

**Connect** - you need an invite (a `mirage://...` string) from someone running a bridge:

```sh
mirage-client client.json      # then point your browser at socks5://127.0.0.1:1080
```

Or run `mirage-client-gui`, paste the invite, click **Connect**.

**Run a bridge** - the wizard writes both configs and the invite for you:

```sh
mirage-setup                   # answer the questions
mirage-bridge bridge.json      # then hand out the invite it printed
```

---

## What you get

**Carriers** - the wire shape your traffic takes. Pick per-network; the client can hold
several and switch when one gets blocked.

| Carrier | Looks like | Good for |
|---|---|---|
| **Reality** | Real TLS to a real site | The default. Survives active probing. |
| **Hysteria2** | QUIC | Lossy / high-latency links. |
| **MASQUE** | HTTP/3 | Networks that allow QUIC to CDNs. |
| **WebRTC** | A video call | Blocking it breaks conferencing. |
| **meek** | CDN-fronted HTTPS | Hostile networks with a reachable CDN. |
| **WebSocket** | Ordinary web traffic | Deploying behind nginx / a CDN. |
| **Shadowsocks-2022** | Nothing (opaque) | Simple, fast, known-good. |
| **VLESS** | TLS/WS-framed | Interop with existing infrastructure. |
| **DoH** | DNS-over-HTTPS | Only DNS gets out. |
| **dnstt** | Plain DNS | Captive portals; the last resort. |
| **obfs** | Random bytes | Test-bed / bare TCP. |

**Layers that ride on top of any carrier:** frame padding + timing jitter (defeats ML flow
fingerprinting), stream multiplexing, and single-port dispatch across every carrier at once.

**Finding bridges** - epoch-rotated rendezvous over **Nostr**, **DNS TXT**, and the
**BitTorrent DHT**, so there's no single list to seize.

**Two ways to use it** - a local **SOCKS5 proxy**, or a **TUN VPN** that captures every TCP
*and* UDP flow from the whole device with no per-app setup.

**Multi-hop** - chain up to **3 bridges** into an onion circuit, each hop authenticated
separately, so no single bridge sees both who you are and where you're going.

**Paranoid mode** - one config switch (`paranoid: true`) puts on the strongest posture:
Reality carrier, handshake padding, fail-closed, and **replay pacing** - the flow wears a
real recorded video-streaming shape (see [`tools/cover-sources`](tools/cover-sources)), so
traffic-analysis sees genuine traffic, not a generated imitation.

Runs on **Linux, macOS, and Windows**. Full detail in the
**[feature reference](docs/features.md)**.

---

## Install

Prebuilt binaries for Linux (x86_64/aarch64/armv7, static musl), macOS (Intel + Apple
Silicon), and Windows are attached to every [release](../../releases).

**Verify what you downloaded.** A censor's cheapest attack is getting you to run *their*
build:

```sh
sha256sum -c SHA256SUMS.txt                                   # integrity
gh attestation verify <archive> --owner <ORG>                 # provenance (Sigstore)
```

### Build from source

```sh
cargo build --release --workspace     # needs the pinned toolchain (rust-toolchain.toml)
nix build .#mirage-bridge             # or reproducibly, via Nix
```

No feature flags, no system libraries. The desktop GUI (`mirage-client-gui`)
renders with Slint's software renderer - it builds with plain `cargo` and links
only the standard C runtime. On Linux it's a glibc build that uses your existing
desktop (X11/Wayland) at run time; it ships in the `...-gui` release archives.

---

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
