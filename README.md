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

Mirage is a self-hosted proxy for networks that block ordinary routes to the
internet. A client accepts application traffic through SOCKS5 or a TUN
interface, encrypts it, and sends it to an operator's bridge. The exit bridge
opens the destination connection. The encrypted session can use different
carriers, so an operator can choose a path that works on a given network.

Mirage is alpha software. Its wire formats and configuration may change, and
its traffic has not been shown indistinguishable from a matched real service.
Read the [security model](docs/security-model.md) before using it in a hostile
network.

## Quick start

Install a [release archive](../../releases) or [build from source](#releases-and-development).
To connect, obtain a `mirage://...` invite from the bridge operator. The invite
contains the bridge's identity, an access credential, and initial connection
details. Store it as a secret.

Create `client.json`:

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
through the bridge. For example:

```sh
curl --proxy socks5h://127.0.0.1:1080 https://example.com
```

Run `mirage-client-gui` to connect through the desktop client. It accepts the
same invite and manages profiles and reconnects. TUN mode is available for
device routing; its DNS and platform limits are described in the
[client guide](docs/getting-started.md#4-whole-device-vpn-optional).

To run a bridge, you need a publicly reachable address and port. Use the setup
wizard and share the invite it creates through a private channel:

```sh
mirage-setup
mirage-bridge bridge.json
```

The optional admin UI (`mirage-bridge bridge.json --admin-ui`) stores its
one-run access URL in a private file. Manual runs place it beside the config;
the generated systemd service uses its state directory. The URL is not printed
to service logs. See the [operator instructions](docs/operators.md#8-admin-web-ui-optional).

The [client guide](docs/getting-started.md) covers GUI, TUN, and troubleshooting.
The [operator guide](docs/operators.md) covers service installation, access,
rotation, and multi-hop deployments.

## How the stack fits together

Mirage has two separate cover goals. A carrier should start with protocol bytes
that make sense for its claimed service, rather than unexplained ciphertext.
Proteus separately shapes sizes, directions, and timing after the connection
starts. Passing either check alone does not establish that the whole flow
matches genuine use of that service.

```text
application -> SOCKS5 / TUN -> Mirage client -> carrier -> bridge -> destination
                                     |                     |
                              encrypted session      optional relay circuit
```

The session authenticates the bridge and protects payloads independently of the
carrier. Discovery updates a bridge's address for clients that already hold an
invite; it is not a public bridge directory. A circuit can cross up to three
bridges. Separate operators are needed if the purpose is to prevent one party
from seeing both the client and destination.

| Layer | Role |
|---|---|
| Ingress | Local SOCKS5 proxy or a TUN interface for device traffic. |
| Session | Noise-XX with ML-KEM-768, authenticated frames, and capability-token access. |
| Carrier | Network transport for the session. Clients can configure several for failover. |
| Discovery | Invite-gated bridge updates through Nostr, DNS TXT, or the DHT. |
| Circuit | Optional onion routing through up to three bridges. |

The standard build includes the carriers below. Configuration determines which
ones a client and bridge use. They differ in reachability, cost, and observable
behavior; none is a universal disguise.

| Carrier | Wire transport | Main constraint |
|---|---|---|
| Reality-style | TLS-like TCP; unauthorized probes are forwarded to a cover site | Probe timing and lifecycle can differ from the cover site. |
| Hysteria2 | QUIC over UDP | Requires a usable UDP path; obfuscation changes its wire appearance. |
| MASQUE | HTTP/3 over QUIC | Requires UDP and a suitable HTTP/3 deployment. |
| WebRTC | DTLS/SCTP data channel | Requires signaling and ICE; a data channel is not a video call. |
| WebSocket | HTTP upgrade over TCP | Visible HTTP and TLS details must fit the hosting setup. |
| meek | CDN-fronted HTTPS polling | Adds latency and depends on a working front. |
| Shadowsocks-2022, VLESS | Proxy protocol framing | Does not by itself hide demand-shaped flow statistics. |
| DoH, dnstt | HTTPS DNS or plain DNS queries | Lower throughput and higher overhead. |
| obfs | Opaque TCP | Raw ciphertext can be blocked by entropy filters. |

See [features](docs/features.md) for enablement and [configuration](docs/configuration.md)
for the settings. [Internals](docs/internals.md) covers the session and wire
formats.

## Proteus traffic shaping

Proteus is an optional layer that records traffic from a cover workload and
replays its record sizes, directions, and timing. Each scheduled record is sent
whether or not application data is waiting; data replaces padding inside that
record. The schedule is chosen without consulting the application's momentary
demand. Enable it on both the client and bridge; a framing mismatch prevents
the session from working:

```json
{ "proteus": true }
```

Each side can source and refresh its cover library automatically. A custom
library can be recorded with `mirage-cover-record` and selected with
`proteus_profile`; pinning a profile disables automatic sourcing. The profile
must match the claimed cover host. See [cover sources](tools/cover-sources/README.md).
Proteus does not pace every carrier; check the [carrier
list](docs/proteus.md#which-carriers-actually-wear-it).

Cover traffic runs for the lifetime of a session, including idle periods. The
usable user rate cannot exceed the cover's replaceable bytes after framing and
loss. The configured GB/day figure expresses a continuous rate as a 24-hour
equivalent; traffic is incurred only while connected.

| Cover budget | Approximate wire-rate ceiling |
|---|---:|
| 2.5 GB/day (default) | 0.23 Mbit/s |
| 6 GB/day | 0.56 Mbit/s |

```json
{ "proteus": true, "proteus_max_gb_day": 40 }
```

A higher budget can admit faster cover, but it cannot remove the cover-rate
bound. Browser-like cover offers short gaps at modest rates. Segmented video
can offer more bytes but has shown multi-second gaps, so it may stall an
interactive stream. A high-rate video path has not been validated end to end.
The [cover scheduling analysis](docs/cover-scheduling.md) explains why both
the cumulative service rate and gap structure matter. The measurements there
are provisional because the original capture tool omitted long-lived flows.

Proteus is a tradeoff, not a required setting. Leaving it off avoids the cover
bandwidth bill and pacing delay, while exposing more demand-shaped traffic.
`"paranoid": true` enables Proteus with other restrictive client settings;
the bridge must still be configured compatibly. See [Proteus](docs/proteus.md)
for the carrier coverage and measured residual signal.

## Security and evidence

Mirage authenticates sessions and restricts access with invite-carried
credentials. The Reality-style carrier forwards unauthorized probes to a cover
destination. Multi-hop circuits can separate client and destination knowledge
across bridge operators.

Those controls do not prove that a connection blends into ordinary traffic:

| Observation | Current limit |
|---|---|
| Active probing | Forwarded Reality probes can differ from the cover site's response timing and connection lifecycle. |
| Passive flow analysis | Proteus uses a finite trace library; repetitions and measured timing residuals remain. No matched real-origin versus tunnel result establishes indistinguishability. |
| First-payload entropy | The optional printable preamble addresses one published TCP heuristic. It does not turn an opaque carrier into native TLS or QUIC. |
| Bridge trust | A single exit bridge sees destinations. Separate operators and a multi-hop circuit reduce what one operator can correlate. |
| End-to-end observation | An observer watching both ends can correlate volume and timing. |
| Device routing | TUN behavior depends on OS routes and DNS configuration; the client does not cover every platform leak path. |

Earlier cover-class captures omitted long-lived connections. Their corrected
numbers remain provisional; the [measurement notes](docs/measurement-methodology.md)
and [security model](docs/security-model.md) explain the evidence and open
problems. Report a concrete security weakness using the process in the
[security model](docs/security-model.md#reporting-a-weakness).

The [cover-native proposal](docs/cover-native-proposal.md) studies a genuine
application carrier with encrypted object slots and demand-independent
scheduling. It is unimplemented. Its proposed throughput gain requires a real
high-rate cover workload and is bounded by that workload's usable body bytes.

## Releases and development

The [releases page](../../releases) carries archives for Linux, macOS, and
Windows. Check [building and platforms](docs/building.md) for the target matrix,
mobile status, and Nix builds. Verify a downloaded archive and its build
attestation before running it:

```sh
sha256sum -c SHA256SUMS.txt
gh attestation verify <archive> --owner <ORG>
```

Replace `<archive>` with the downloaded file and `<ORG>` with the GitHub owner
of the release repository.

Build from source with the toolchain in [rust-toolchain.toml](rust-toolchain.toml):

```sh
cargo build --release --workspace
```

The standard workspace build includes the carriers, GUI, and TUN support;
runtime configuration selects what to use. Before submitting a change, run:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets
cargo audit --deny warnings
```

The audit command requires `cargo-audit` (CI pins version `0.22.1`). The
narrowly triaged warnings are documented in [.cargo/audit.toml](.cargo/audit.toml);
new untriaged advisories fail CI. CI also checks release workflows.
Releases require a tag matching the workspace version, using
`vMAJOR.MINOR.PATCH` or `vMAJOR.MINOR.PATCH-alpha.N` (likewise `beta` or `rc`).

The [documentation index](docs/) links to the configuration reference,
internals, platform notes, measurements, and operator procedures.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
