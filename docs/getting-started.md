# Getting started

Goal: get your traffic through a Mirage bridge. You need **an invite** - a `mirage://...`
string from whoever runs the bridge. Everything else has a sane default.

- [1. Install](#1-install)
- [2. Connect](#2-connect)
- [3. Point your apps at it](#3-point-your-apps-at-it)
- [4. Whole-device VPN (optional)](#4-whole-device-vpn-optional)
- [5. When a network blocks you](#5-when-a-network-blocks-you)
- [Troubleshooting](#troubleshooting)

---

## 1. Install

Grab the archive for your platform from [releases](../../../releases) and verify it before
you run it - a censor's cheapest attack is handing you a modified build:

```sh
sha256sum -c SHA256SUMS.txt
gh attestation verify <archive> --owner <ORG>     # Sigstore build provenance
```

Or build it yourself (no feature flags - one build has everything):

```sh
cargo build --release --workspace
```

---

## 2. Connect

### Graphical client

```sh
mirage-client-gui
```

Paste the invite (or click **Browse...** to pick a `client.json`), then click **Connect**. It shows
live connection status and which carrier it settled on.

Install it from the native installer for your platform - **AppImage/`.deb`** (Linux),
**`.dmg`** (macOS), or **`.msi`** (Windows) - see **[install.md](install.md)** (installers are
unsigned during the alpha; that page has the one-time step to open past the OS warning). Each bundles
the GUI and its `mirage-client` daemon. To build it yourself:
`cargo build --release -p mirage-client-gui` (no system libraries needed).

### Command line

Write `client.json`:

```json
{
  "local_bind": "127.0.0.1:1080",
  "invite": "mirage://..."
}
```

Run it:

```sh
mirage-client client.json
```

That's the whole minimum config. The invite carries the bridge address, its public key, your
capability token, and which carriers that bridge offers - so you don't configure carriers by
hand.

**Multiple bridges.** Use `invites` (plural) instead, and the client will hold them all,
health-check them, and fail over automatically:

```json
{
  "local_bind": "127.0.0.1:1080",
  "invites": ["mirage://...", "mirage://..."]
}
```

---

## 3. Point your apps at it

The client is a standard **SOCKS5** proxy on `127.0.0.1:1080`.

```sh
curl --proxy socks5h://127.0.0.1:1080 https://example.com
```

> **Use `socks5h`, not `socks5`.** The `h` makes the *proxy* resolve DNS. Plain `socks5`
> resolves hostnames on your machine, which leaks every site you visit to the local network
> - exactly what you're trying to avoid.

**Firefox:** Settings -> Network Settings -> Manual proxy -> SOCKS v5 `127.0.0.1:1080`, and
tick **"Proxy DNS when using SOCKS v5"**.

**Chrome/Chromium:**

```sh
chromium --proxy-server="socks5://127.0.0.1:1080" \
         --host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"
```

---

## 4. Whole-device VPN (optional)

TUN mode captures **every TCP and UDP flow from the entire machine** - no per-app proxy
setup. It is compiled into the standard client; you turn it on in config:

```json
{
  "local_bind": "127.0.0.1:1080",
  "invite": "mirage://...",
  "tun_enabled": true
}
```

On start the client opens the TUN device **and installs the OS routes that make the kernel
actually send your traffic through it** - a split-default that captures everything, plus a
per-bridge bypass route so the encrypted carrier packets to the bridge don't loop back into the
tunnel. It restores your original routing table when it exits. If it cannot install those
routes it **fails closed**: it prints an error and refuses to run, rather than leaving an
interface up that would leak your traffic in clear.

It needs elevated privileges for the network device and the routing table:

| Platform | Backend | Requirement |
|---|---|---|
| Linux | `/dev/net/tun` + `iproute2` | `CAP_NET_ADMIN` (or root) - `sudo setcap cap_net_admin+ep ./mirage-client`, or run with `sudo` |
| macOS | `utun` + `/sbin/route` | root - run with `sudo` |
| Windows | Wintun + `netsh` | **Administrator** - launch from an elevated terminal (Wintun and route changes both require it), and keep `wintun.dll` next to the `.exe` |

> macOS and Windows routing is newly wired and modelled on how WireGuard/OpenVPN drive those
> platforms; if you hit a routing quirk on your setup, please file it. The SOCKS5 listener runs
> alongside TUN on every platform, so apps can always use it directly.

Tunables: `tun_name`, `tun_address`, `tun_netmask`, `tun_mtu` - see
[configuration](configuration.md).

---

## 5. When a network blocks you

Mirage holds several carriers and picks what works. If a network is hostile, the useful
knobs are:

| Situation | Try |
|---|---|
| Everything blocked but web browsing | `meek_front_domain` (CDN-fronted) |
| QUIC allowed | `hysteria2_enabled` / `h3_enabled` |
| Video calls work | `webrtc_signaling_host` |
| Only DNS escapes | `dnstt_enabled` + `dnstt_domain`, or `doh_front_domain` |
| Aggressive ML flow classifier | `pad_enabled: true` (padding + timing jitter) |

You don't have to guess blindly - the client scores carriers on live success and prefers
what has been working. Details in [features](features.md).

**No invite at all?** Set a discovery channel and the client will find bridges itself:

```json
{
  "local_bind": "127.0.0.1:1080",
  "nostr_relays": ["wss://relay.example"],
  "dht_enabled": true
}
```

---

## Troubleshooting

**"connection refused" from curl** - the client isn't running or is bound elsewhere. Check
`local_bind`.

**Connects, but no traffic** - you're probably using `socks5` instead of `socks5h`, or the
bridge can't reach the destination.

**TUN mode won't start** - it fails closed on purpose, so it tells you why. Almost always it's
privileges: Linux needs `CAP_NET_ADMIN`/root (grant it with `setcap`, above, or run under
`sudo`), macOS needs `sudo`, and Windows needs an **elevated** (Administrator) terminal - the
Wintun adapter and the route changes both require it. Mirage does **not** pop its own UAC
prompt; start it already-elevated. The client logs the exact reason at startup - run it in a
terminal and read the first ten lines. It will never silently bring up a tunnel that leaks your
traffic.

**All carriers fail on one network but work on another** - that network is blocking your
current carrier. Try the table above; start with `meek` or `dnstt`.

**Windows: "failed to load wintun.dll"** - the DLL must be in the same directory as
`mirage-client.exe`.

---

Next: **[Feature reference](features.md)** * **[Configuration](configuration.md)** *
**[Security model](security-model.md)**
