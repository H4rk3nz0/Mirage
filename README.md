<p align="center">
  <img src="assets/mirage-banner.svg" alt="Mirage" width="640">
</p>

<p align="center">
  <a href="docs/getting-started.md">Getting started</a> ·
  <a href="docs/operators.md">Run a bridge</a> ·
  <a href="docs/features.md">Features</a> ·
  <a href="docs/security-model.md">Security model</a>
</p>

# Mirage

Mirage is an alpha-stage censorship-circumvention proxy. Applications can use its
local SOCKS5 listener, or it can route device traffic through a TUN interface.
Clients connect to privately operated bridges using an invite. A hybrid
Noise-XX/ML-KEM session runs over a choice of carriers, including Reality-style
TLS, HTTP/3, WebSocket, and DNS-based transports. Bridges can also be found
through rotating rendezvous records on Nostr, DNS TXT, and the BitTorrent DHT.

**Status:** `0.1.8-alpha.1`. Wire formats and configuration can change. The
traffic-disguise claims have important limits; see [Security and
evidence](#security-and-evidence).

## Start

To connect, get a `mirage://...` invite from a bridge operator and put it in
`client.json`:

```json
{
  "local_bind": "127.0.0.1:1080",
  "invite": "mirage://..."
}
```

```sh
mirage-client client.json
```

Point applications at `socks5h://127.0.0.1:1080` so hostname resolution goes
through the bridge. The desktop client, `mirage-client-gui`, accepts the same
invite and can manage profiles and reconnects. For whole-device routing, see
the [TUN setup](docs/getting-started.md#4-whole-device-vpn-optional).

To operate a bridge, run the setup wizard and share the invite it creates:

```sh
mirage-setup
mirage-bridge bridge.json
```

The [client guide](docs/getting-started.md) and [operator guide](docs/operators.md)
cover installation, configuration, and troubleshooting.

## What is in the stack

| Layer | Role |
|---|---|
| Session | Noise-XX with ML-KEM-768, authenticated frames, and capability-token access. |
| Carrier | Moves the session over a network path; the client can configure several and fail over. |
| Discovery | Epoch-rotated, invite-gated bridge records over Nostr, DNS TXT, or the DHT. |
| Circuit | Optional onion routing across up to three bridges. |
| Ingress | Local SOCKS5 or a TUN-based device VPN. |

The standard build includes the available carriers. Configuration chooses which
ones a client and bridge use:

| Carrier | Transport |
|---|---|
| Reality-style | TLS-like TCP with forwarding of unauthorized probes to a configured cover site |
| Hysteria2, MASQUE | QUIC and HTTP/3 |
| WebRTC | DTLS/SCTP data channel |
| WebSocket, meek | HTTP upgrade and CDN-fronted HTTPS |
| Shadowsocks-2022, VLESS | Compatible proxy transports |
| DoH, dnstt | HTTPS DNS and plain DNS tunneling |
| obfs | Opaque TCP |

These carriers have different fingerprints, performance, and deployment
requirements. [Features](docs/features.md) describes each one and its settings.
The [security model](docs/security-model.md) explains what each can and cannot
conceal.

## Proteus traffic shaping

Proteus is an optional layer that records traffic from a cover workload and
replays its record sizes, directions, and timing. Each scheduled record is sent
whether or not application data is waiting; data replaces padding inside that
record. The schedule therefore does not need to follow the application's
momentary demand. Enable it on **both** the client and bridge:

```json
{ "proteus": true }
```

Each side can source and refresh its cover library automatically. A custom
library can be recorded with `mirage-cover-record` and selected with
`proteus_profile`; see [cover sources](tools/cover-sources/README.md).
Proteus does not pace every carrier; check the [carrier
list](docs/proteus.md#which-carriers-actually-wear-it).

Cover traffic runs for the lifetime of a session, including idle periods. Its
rate is an upper bound on incompressible user throughput, before framing and
retransmission. The configured GB/day figure is a rate expressed as a
24-hour equivalent; traffic is incurred only while connected.

| Cover budget | Approximate wire-rate ceiling |
|---|---:|
| 2.5 GB/day (default) | 0.23 Mbit/s |
| 6 GB/day | 0.56 Mbit/s |

```json
{ "proteus": true, "proteus_max_gb_day": 40 }
```

A higher budget can admit faster cover, but it cannot remove the cover-rate
bound. The current browser-like cover is suitable mainly for low-bandwidth
work. Video cover can offer more bytes but has shown multi-second gaps; a
high-rate video path has **not** been validated end to end. Interactive and
bulk streams can use different cover classes. See [Proteus](docs/proteus.md)
and the [cover scheduling analysis](docs/cover-scheduling.md).

## Security and evidence

Mirage authenticates sessions, forwards unauthorized Reality-style probes to a
cover destination, and can hide destination knowledge across multiple bridges.
It does **not** guarantee that its traffic is indistinguishable from ordinary
TLS, HTTP/3, or video traffic. Probe timing can differ from the cover site.
Proteus's finite trace library can repeat across sessions, and its timing
behavior still has measured residuals. Earlier cover measurements also missed
long-lived connections; the corrected cover-class figures remain provisional.
A matched comparison against genuine traffic from the same origin is still
needed.

The optional printable preamble for opaque carriers addresses a published
first-payload entropy heuristic. It is not a general disguise for those
carriers. A single exit bridge sees destinations; a global observer watching
both ends can correlate traffic. TUN mode has platform-specific DNS and routing
limits. Read the [security model](docs/security-model.md) before relying on
Mirage in a high-risk setting.

The [cover-native research proposal](docs/cover-native-proposal.md) explores a
higher-rate application-based carrier. It is a design and evaluation plan,
not an implemented transport.

## Install and build

Release archives for Linux, macOS, and Windows are available on the
[releases page](../../releases). Verify the archive and its build attestation
before running it:

```sh
sha256sum -c SHA256SUMS.txt
gh attestation verify <archive> --owner <ORG>
```

To build with the pinned Rust toolchain:

```sh
cargo build --release --workspace
```

See [building](docs/building.md) for platform details and the Nix path.
The [documentation index](docs/) links to configuration, internals, and
operator procedures.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
