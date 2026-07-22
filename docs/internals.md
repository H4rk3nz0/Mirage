# Internals

How Mirage is built, what crosses the wire, and what it changes versus the
protocols it borrows from. This is the map for contributors and for anyone
auditing the claims in the [security model](security-model.md).

Mirage is a **framework stack**, not a single protocol: a session layer, a
pluggable carrier layer, and a discovery layer, each independently swappable.

## Layers

```
        +---------------------------------------------+
  app -> | SOCKS5  /  TUN netstack   (client ingress)   |
        +---------------------------------------------+
        | Session: Noise-XX + ML-KEM-768 + AEAD frames |  <- end-to-end auth + PQ
        +---------------------------------------------+
        | Circuit (optional): up to 3 onion hops       |  <- per-hop tokens
        +---------------------------------------------+
        | Carrier: Reality / WS / QUIC / meek / dnstt... |  <- wire mimicry
        +---------------------------------------------+
        | Discovery: Nostr / DNS-TXT / DHT rendezvous  |  <- finding bridges
        +---------------------------------------------+
```

Each layer is a set of crates:

- **Ingress** - `socks5`, `tun` (a userspace smoltcp netstack that terminates
  every TCP/UDP flow off an OS TUN device).
- **Session** - `session`, `crypto`. The client<->bridge cryptographic core.
- **Circuit / onion** - `circuit`, `onion`, `runtime`. Multi-hop telescoping.
- **Carriers** - `transport` (the `ClientTransport` trait) plus one crate per
  carrier: `transport-reality`, `-ws`, `-hysteria2`, `-masque`, `-meek`,
  `-shadowsocks`, `-vless`, `-doh`, `-dnstt`, `-webrtc`, `-obfs`, `-pad`,
  `-mux`. A bridge classifies inbound connections with `transport-mux`.
- **Discovery** - `discovery` plus `discovery-nostr`, `discovery-dns-txt`,
  `discovery-dht`.
- **Adaptivity** - `router`, `adversary`. Learns which carrier works on the
  current network and steers accordingly.
- **Roles** - `client`, `bridge`, `client-gui`, and the operator tools
  (`mirage-setup`, `-keygen`, `-publish`, `-rotate`, `-cohort-refresh`).

## Session layer

Every client<->bridge session is a **Noise-XX** handshake hybridised with
**ML-KEM-768**: the two Diffie-Hellman shared secrets and the post-quantum KEM
secret are mixed into the traffic keys, so a future quantum adversary who
recorded the session still cannot decrypt it. Application data flows in
double-AEAD frames with a per-epoch time ratchet (a BLAKE3 key chain), so
traffic keys roll forward and old keys cannot decrypt new frames.

Access is gated by **single-use capability tokens** minted from the operator
key. Tokens are **forward-secret and epoch-scoped**: an online issuer that is
compromised cannot forge tokens for past epochs. Spent tokens are burned in a
replay set; clients honour signed **revocations** and drop revoked bridges.

## Carrier layer

A carrier's only job is to move an opaque byte stream while looking like
something else on the wire. The contract is the `ClientTransport` trait (dial ->
duplex stream); the session layer rides inside.

- **Reality** performs a *real* TLS 1.3 handshake to a *real* cover site: a
  browser-accurate ClientHello (matching JA3/JA4, a cipher-suite set where every
  offered ECDHE suite is also negotiable, and a 0.5-RTT NewSessionTicket like a
  genuine server issues), a real ServerHello/Certificate/Finished flight
  size-matched to the cover. An unauthenticated prober is transparently
  forwarded to the cover and sees exactly the cover's TLS.
- **WebSocket** is a browser-accurate Upgrade; the pre-session auth token rides
  in a `Cookie` (where a long opaque value is ordinary), not in a Mirage-shaped
  subprotocol.
- **QUIC carriers** (Hysteria2, MASQUE/H3) obfuscate datagrams to pass as
  ordinary QUIC.
- **meek / DoH** domain-front through a CDN. **dnstt** tunnels over DNS.
- **obfs-tcp** is the lightest carrier: uniform-random bytes, no cover (see the
  security model's note on entropy blocking).

Pre-session **knocks** (obfs-tcp, WebSocket) are keyed on the per-bridge invite
secret when one is provisioned, so a prober with only the scraped public key
cannot forge them.

## Discovery layer

Bridges are found without a central directory. Announcements - sealed bridge
descriptors - are published to Nostr relays, DNS-TXT apexes, and the BitTorrent
mainline DHT under **per-epoch rendezvous points** derived from a secret salt
carried in the invite. An observer without the invite can compute neither the
rendezvous location nor the decryption key, and cannot correlate an operator's
announcements across epochs.

The DHT rendezvous uses **additive Ed25519 key blinding** (the scheme Tor v3
onion services use): the operator holds a long-term identity key; each epoch's
publishing key is a public blinding of it. An invite-holder can derive the
per-epoch *public* key - enough to locate and verify a record - but not the
signing key, so cohort members can read the rendezvous yet cannot forge or evict
it. Nostr per-epoch author keys are derived from an operator secret for the same
reason.

## Multi-hop

A circuit telescopes through up to three bridges. The client extends one hop at
a time, running a fresh per-hop handshake and presenting a per-hop capability
token; each hop can unwrap only its own onion layer. Cells are fixed-size so hop
count and payload length don't leak. No single hop learns both the client and
the destination.

## What Mirage changes vs. the protocols it borrows

- **Reality** (vs. the original): browser-accurate ClientHello *and* a matching
  negotiable cipher set and session-ticket behaviour, plus an epoch-ratcheted
  anti-probe MAC so a leaked public key doesn't enable bridge enumeration.
- **Discovery** (vs. Tor bridges / static lists): no directory; per-epoch,
  salt-gated, key-blinded rendezvous across three independent channels.
- **Session** (vs. a plain Noise tunnel): ML-KEM hybrid, time-ratcheted frames,
  and forward-secret single-use tokens with revocation.
- **VPN** (vs. "bring up a TUN"): the client installs and later restores the
  capture routes itself, and fails closed if it cannot.

## Testing

The core is exercised by ~1,800 unit/integration tests and a Podman-based
end-to-end cluster (`scripts/podman-e2e/`) that stands up real bridges and
drives each carrier over the loopback network. Crypto-critical paths (the
session handshake, DHT key blinding, the onion peel) have dedicated adversarial
tests.
