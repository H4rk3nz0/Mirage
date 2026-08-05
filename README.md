<p align="center">
  <img src="assets/mirage-banner.svg" alt="Mirage" width="640">
</p>

<p align="center">
  Pluggable carriers &middot; epoch-rotated discovery &middot; authenticated session crypto &middot; replay-based traffic shaping &middot; onion routing<br>
  <sub>All behind one local SOCKS5 proxy or a full-device VPN</sub>
</p>

<p align="center">
  <a href="docs/getting-started.md"><b>Get started</b></a> &nbsp;&middot;&nbsp;
  <a href="docs/operators.md">Run a bridge</a> &nbsp;&middot;&nbsp;
  <a href="docs/features.md">Features</a> &nbsp;&middot;&nbsp;
  <a href="docs/security-model.md">Security model</a>
</p>

> **Status:** `0.1.6-alpha.1`. Deployable today. Wire formats and config may still change
> before a stable release.

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

## Proteus: wear real traffic, not a fake shape

Our flagship layer, and a genuine upgrade to Reality. **Reality** makes the *connection*
look real - a real TLS session to a real host, resistant to active probing. **Proteus**
makes the *flow* look real too.

Even a perfect TLS disguise leaks its purpose through traffic *shape* - packet sizes and
timing. A proxy shuttling data doesn't breathe like someone streaming a video, and
traffic-analysis classifiers key on exactly that. Proteus closes it: it records a
**genuine** video stream or web page load and replays its exact wire envelope - sizes,
direction, timing - with your data hidden inside the encrypted record bodies.

The point is *replay, not fake*. A generated "video-like" pattern is always subtly wrong,
and subtly-wrong is detectable; a real recorded envelope carries no invented structure to
be wrong about. The size axis is closed on the wire: the paced tunnel's records match the
recorded profile exactly, per carrier.

**Timing is not closed yet, and the docs say so.** Replicated censor-vantage measurement
still separates an active tunnel from an idle one at about AUC 0.57 against a 0.53 control
- far from the 1.0 an unshaped tunnel gives, and not the indistinguishability the design
aims at. Two causes were found and fixed this cycle; the remainder is unattributed. See
[proteus.md](docs/proteus.md), which carries the numbers and the failed hypotheses rather
than only the successes.

Turning it on is one line, on the bridge and on the client:

```json
{ "proteus": true }
```

That is the whole procedure. With nothing else configured, each end records and refreshes
its own cover library in the background - measured at 2 seconds from a cold start to
wearing a real envelope. There is no recorder to run, no timer to install and no capture
files to copy anywhere.

| | |
|---|---|
| **Both directions** | Client shapes what it sends up, bridge shapes what it sends down - a censor watching either sees real traffic. |
| **Never twice the same** | Each session chains a random shuffle of real traces from ONE cover class, so there's no fixed fingerprint, nothing loops, and the session's rate never steps mid-flow the way a mixture's does. |
| **Cover classes** | Web browsing by default; video too once the budget reaches 6 GB/day - a video capture is the better downstream disguise, but its upstream is too sparse to carry a handshake, so the two get paired. |
| **Self-contained** | The recorder pulls from real open sources using its own TLS stack - no yt-dlp, ffmpeg, tcpdump or python. Video sources are regional (PeerTube globally; Rutube/OK.ru, Aparat, Bilibili, puhutv domestically), and `--hls-cmd` can hand off to an external extractor if you want one, without Mirage depending on it. |
| **No demand following** | Steering big records to the moments your data is waiting was implemented, measured at **0.699** separability against a 0.544 control, and switched OFF (`ALIGN_ALPHA_PERMILLE = 0`). A rate that tracks demand is the signal Proteus exists to remove, so the wire is identical busy or idle - enforced by a test. Throughput comes from choosing SMOOTHER cover instead. |
| **Not every carrier** | Seven carriers wear the envelope. Plain TCP, obfs-tcp, dnstt and WebRTC do not, and nothing warns you - see [proteus.md](docs/proteus.md). |

### What it costs, plainly

Cover runs for as long as a session is open, busy or idle, so the envelope's rate is also a
**ceiling on your throughput**. That is not a tuning problem, it is what constant-rate cover
means. (Per session-day: a client connected two hours a day pays for two hours, not
twenty-four.)

| budget | cover bill | sustained |
|---|---|---|
| 2.5 GB/day (default) | 2.5 GB/day | ~0.23 Mbit/s |
| 6 GB/day (video cover) | 6 GB/day | ~0.56 Mbit/s |

Set it directly - a number in GB/day, or `unlimited` for "I do not care, go fast":

```json
{ "proteus": true, "proteus_max_gb_day": 40 }
```

**Your throughput IS your cover budget, 1:1.** A record leaves on a schedule token whether
or not you have data, so user bytes displace padding instead of adding to it. That identity
is exactly what makes an idle tunnel and a busy one look alike - and it means the envelope's
rate is also your ceiling. There is no arrangement of this design that avoids it.

So the speed is a spending decision, not a property of the tool:

| cover you wear | sustained | you pay | status |
|---|---|---|---|
| browse (the default classes) | ~1 Mbit/s | 2.5-6 GB/day | measured |
| a real 1080p stream | ~5 Mbit/s | ~2 GB/hour connected | not yet validated |
| a real 4K stream | 15-25 Mbit/s | 7-11 GB/hour connected | not yet validated |

At the default budget Proteus is a low-bandwidth channel - messaging, text, light browsing.
It is not *inherently* one: browse cover is slow because web pages are small, and the
budget is what admits a faster class. The video rows above are what the arithmetic says a
real stream's envelope would carry; **they have not been run end to end**, so treat them as
the design's intent rather than a shipped capability. A deployment that needs line rate and
will not pay for it should run Reality or Shadowsocks-2022 *without* Proteus and accept
that flow shape is then exposed to traffic analysis.

Raising the budget also buys **latency** for browse cover - bounding the silent gaps is what
stops short transfers waiting for the next burst. It does **not** for video: a video capture
waits each segment's true duration, so the tunnel inherits a stall the length of one segment
(measured 5.8 s on PeerTube, 10 s on Aparat), and a bigger budget only buys a fatter variant
of the same stream. Video buys throughput; browse buys latency. See
[proteus.md](docs/proteus.md) for the measurements and the concavity argument behind it.

Want a *specific* envelope - your own site, a particular stream? Record it with
`mirage-cover-record` and set `proteus_profile`; that pins the library and turns
auto-sourcing off. See [cover sources](tools/cover-sources/README.md).

One switch turns on the whole strong posture: `"paranoid": true`. Details in the
**[feature reference](docs/features.md)** and **[operator guide](docs/operators.md)**.

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
mirage-client client.json      # then point your apps at socks5h://127.0.0.1:1080
```

Or run `mirage-client-gui`, paste the invite, click **Connect**. The desktop app
keeps you in control of both ends: save and switch **profiles**, force a fresh
**re-discover** walk, reconnect, and flip **Paranoid** on, with a live view of the
carrier, the rendezvous channels, and the bridges it has found.

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
| **Reality (+ Proteus)** | Real TLS to a real site, wearing a real traffic shape | The default. Survives active probing *and* traffic analysis. |
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

**Encrypted SNI (ECH)** - on CDN-fronted TLS carriers (meek / DoH / WebSocket), the real
inner hostname is encrypted with RFC 9180 HPKE, so a censor watching the CDN edge can't see
which site you are really reaching. Delivered in the invite or set in config. (It hides the
SNI, but currently rides a non-browser TLS fingerprint - see the
[ECH caveat](docs/features.md#layers).)

**Finding bridges** - epoch-rotated rendezvous over **Nostr**, **DNS TXT**, and the
**BitTorrent DHT**, so there's no single list to seize.

**Two ways to use it** - a local **SOCKS5 proxy**, or a **TUN VPN** that captures every TCP
*and* UDP flow from the whole device with no per-app setup.

**Multi-hop** - chain up to **3 bridges** into an onion circuit, each hop authenticated
separately, so no single bridge sees both who you are and where you're going.

**Paranoid mode** - one switch puts on the strongest posture at once: Reality carrier,
handshake padding, fail-closed, and **Proteus** (see above). Set
`"paranoid": true` in config, pass `--paranoid` to `mirage-client`, or flip the toggle in
the GUI.

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
