# Mirage documentation

Mirage is a **censorship-resistance framework stack**: interchangeable carriers, bridge
discovery, authenticated session crypto, and optional onion routing, behind a local SOCKS5
proxy or a whole-device VPN.

These docs come in two layers. Start at the top; go down as far as you need.

## Usability layer - get it working

| Doc | For |
|---|---|
| **[Getting started](getting-started.md)** | You have an invite and want to be online. |
| **[Install the desktop app](install.md)** | AppImage / `.deb` / `.dmg` / `.msi`, and the unsigned-alpha warning steps. |
| **[Operator guide](operators.md)** | You're running a bridge for other people. |
| **[Feature reference](features.md)** | Everything in the box: carriers, discovery, defenses, binaries. |
| **[Configuration](configuration.md)** | Every config key, what it does, and its default. |
| **[Building & platforms](building.md)** | Supported targets, cross-compiling, routers (ARM/MIPS), and mobile. |

## Depth layer - how and why

| Doc | For |
|---|---|
| **[Internals](internals.md)** | Architecture, wire format, and what Mirage changes vs. existing protocols. |
| **[Security model](security-model.md)** | The threat model, what is defended, and what is *not*. |

---

## The one thing to know first

**There are no build-time feature flags.** Every carrier, every discovery channel, the
graphical client, and the TUN VPN are compiled into the standard build. What you actually
use is selected at **runtime, in a JSON config file**.

So when the docs say "enable Reality" or "turn on TUN mode", that always means *set a key in
your config* - never *recompile with a flag*.

```sh
cargo build --release --workspace     # this is the whole build. no --features.
```

## Vocabulary

| Term | Meaning |
|---|---|
| **Bridge** | The server an operator runs. Clients tunnel through it to reach the internet. |
| **Client** | The local daemon on your machine. Exposes a SOCKS5 proxy and/or a TUN device. |
| **Carrier** | The wire shape a session rides in - Reality, WebRTC, DNS, etc. Swappable. |
| **Session** | The authenticated, encrypted channel between client and bridge, independent of carrier. |
| **Invite** | A `mirage://...` string containing everything a client needs to reach one bridge. |
| **Discovery channel** | Where clients look up bridges (Nostr / DNS TXT / DHT) when they have no invite. |
| **Circuit** | A chain of up to 3 bridges (onion routing), so no single hop sees both ends. |
| **Cohort** | A set of bridges an operator runs together, sharing discovery and rotation. |
