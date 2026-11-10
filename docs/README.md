# Mirage documentation

Mirage provides a local SOCKS5 proxy or TUN interface backed by an encrypted
session to a bridge. It supports several carriers and discovery methods.

## Setup and operation

| Doc | For |
|---|---|
| **[Getting started](getting-started.md)** | Connect with a bridge invite. |
| **[Install the desktop app](install.md)** | Desktop packages and signing status. |
| **[Operator guide](operators.md)** | Run a bridge. |
| **[Feature reference](features.md)** | Carriers, discovery methods, and binaries. |
| **[Configuration](configuration.md)** | Runtime settings and defaults. |
| **[Building and platforms](building.md)** | Build targets, routers, and mobile clients. |

## Design and measurements

| Doc | For |
|---|---|
| **[Internals](internals.md)** | Architecture and wire format. |
| **[Security model](security-model.md)** | Threats, assumptions, and limitations. |
| **[Proteus](proteus.md)** | Replay shaping, measurements, and cost. |
| **[Proteus 2.0](proteus-2.0.md)** | Traffic shaping design and measurement results. |
| **[Cover selection](cover-scheduling.md)** | Queueing analysis and corrections to the original measurements. |
| **[Measurement methodology](measurement-methodology.md)** | How measurement failures were found and corrected. |
| **[Cover-native transport proposal](cover-native-proposal.md)** | High-throughput research design; unimplemented and unvalidated. |

## Build and configuration

The standard workspace build includes the carriers, discovery methods, desktop
client, and TUN support. Select the components you use in the JSON configuration.

```sh
cargo build --release --workspace
```

## Vocabulary

| Term | Meaning |
|---|---|
| **Bridge** | The server an operator runs. Clients tunnel through it to reach the internet. |
| **Client** | The local daemon on your machine. Exposes a SOCKS5 proxy and/or a TUN device. |
| **Carrier** | The transport carrying a session, such as Reality, WebRTC, or DNS. |
| **Session** | The authenticated, encrypted channel between client and bridge, independent of carrier. |
| **Invite** | A `mirage://...` string containing everything a client needs to reach one bridge. |
| **Discovery channel** | Where invite holders refresh bridge records (Nostr / DNS TXT / DHT). |
| **Circuit** | A chain of up to 3 bridges (onion routing), so no single hop sees both ends. |
| **Cohort** | A set of bridges an operator runs together, sharing discovery and rotation. |
