# Getting started

To connect through a Mirage bridge, get a `mirage://...` invite from its
operator. It carries the bridge credentials and initial connection details.

- [1. Install](#1-install)
- [2. Connect](#2-connect)
- [3. Point your apps at it](#3-point-your-apps-at-it)
- [4. Whole-device VPN (optional)](#4-whole-device-vpn-optional)
- [5. When a network blocks you](#5-when-a-network-blocks-you)
- [Troubleshooting](#troubleshooting)

---

## 1. Install

Download the archive for your platform from [releases](../../../releases) and
verify it before running it:

```sh
sha256sum -c SHA256SUMS.txt
gh attestation verify <archive> --owner <ORG>     # Sigstore build provenance
```

Or build the standard workspace:

```sh
cargo build --release --workspace
```

---

## 2. Connect

### Graphical client

```sh
mirage-client-gui                 # or: mirage-client-gui client.json  (opens already connecting)
```

Paste the invite (or click **Browse...** to pick a `client.json`), then click **Connect** (or
press **Enter** in the field). A connection orb shows live status, the carrier it settled on, and
the bridge it is using; click the **SOCKS address** to copy it. Passing a `client.json` on the
command line opens the app already connecting to it.

The app is built to keep you in control of both ends:

- **Profiles** - save an invite or `client.json` under a name and switch between
  them. Profiles are stored locally; treat those files as bearer secrets.
- **Re-discover** - force the client to walk its rendezvous channels (DHT / Nostr / DNS) again
  right now instead of waiting for the next periodic sweep. The **Discovery** panel shows which
  channels are in play and how many bridges it has found.
- **Reconnect** - drop and re-establish the tunnel.
- **Paranoid** - enable Reality, Proteus, and fail-closed settings without
  editing config. The bridge must have Proteus on too, or the session will not come up.

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

The invite carries the bridge address, its public key, your
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

> **Use `socks5h`.** The `h` makes the proxy resolve hostnames. Plain `socks5`
> uses your local resolver and may expose DNS outside the tunnel.

**Firefox:** Settings -> Network Settings -> Manual proxy -> SOCKS v5 `127.0.0.1:1080`, and
tick **"Proxy DNS when using SOCKS v5"**.

**Chrome/Chromium:**

```sh
chromium --proxy-server="socks5://127.0.0.1:1080" \
         --host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"
```

---

## 4. Whole-device VPN (optional)

TUN mode routes device traffic through the client without per-app proxy setup.
It is included in the standard client; enable it in config:

```json
{
  "local_bind": "127.0.0.1:1080",
  "invite": "mirage://...",
  "tun_enabled": true
}
```

On start the client opens the TUN device and installs split-default routes, plus a
per-bridge bypass route so the encrypted carrier packets to the bridge don't loop back into the
tunnel. It restores the previous routes when it exits. If route installation
fails, the client reports the error and refuses to start TUN mode. See the
[security model](security-model.md) for DNS and route limitations.

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

Discovery refreshes bridge records associated with an invite. It does not
provide public, anonymous bridge credentials. Keep the invite in the config
when enabling discovery channels:

```json
{
  "local_bind": "127.0.0.1:1080",
  "invite": "mirage://...",
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

**TUN mode won't start** - check the startup error. One common cause is missing
privileges: Linux needs `CAP_NET_ADMIN`/root (grant it with `setcap`, above, or run under
`sudo`), macOS needs `sudo`, and Windows needs an **elevated** (Administrator) terminal - the
Wintun adapter and the route changes both require it. Mirage does not open a UAC
prompt; start it elevated. Run the client in a terminal to see the startup error.

**All carriers fail on one network but work on another** - that network is blocking your
current carrier. Try the table above; start with `meek` or `dnstt`.

**Windows: "failed to load wintun.dll"** - the DLL must be in the same directory as
`mirage-client.exe`.

---

Next: **[Feature reference](features.md)** * **[Configuration](configuration.md)** *
**[Security model](security-model.md)**
