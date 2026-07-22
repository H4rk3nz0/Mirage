# Mirage - Quickstart

Deploy a Mirage proxy from a clean checkout: a **single bridge + client**
(standalone) or a **two-bridge cohort** (fleet). Copy-paste configs included.

**Status: 0.1.3-alpha.1, early alpha. APIs, config fields, and wire formats
may change before 0.1.0-stable. Test on non-hostile networks first.**

---

## What you get in this alpha

| Feature | Status |
|---------|--------|
| Post-quantum Noise-XX + ML-KEM-768 handshake | [ok] |
| SOCKS5-over-Mirage proxy | [ok] |
| Transparent system-wide VPN (TUN device, no per-app config) | [ok] build `mirage-client --features tun`, set `"tun_enabled": true`, run with `CAP_NET_ADMIN`. TCP **and** UDP (DNS/QUIC) tunneled. |
| Multi-hop onion relay (per-hop capability-token auth) | [ok] relay engine + bridge-to-bridge dialer; operator-enabled. No single hop sees both source and destination. |
| Reality TLS carrier (DPI bypass) | [ok] |
| obfs-tcp transport (signature bypass) | [ok] |
| Shadowsocks-2022 carrier (`2022-blake3-chacha20-poly1305`) | [ok] new in alpha.2 |
| WebSocket tunnel carrier (CDN-fronted, RFC 6455) | [ok] new in alpha.2 |
| Meek HTTP long-poll carrier (domain-fronted) | [ok] new in alpha.2 |
| VLESS framing layer (UUID auth, no overhead crypto) | [ok] new in alpha.2 |
| Single-port protocol mux (auto-detects transport on 443) | [ok] new in alpha.2 |
| Hysteria2 QUIC carrier (UDP/BBR, auth-token protected) | [ok] new in alpha.2 |
| DoH tunnel carrier (DNS-over-HTTPS mimicry) | [ok] new in alpha.2 |
| Per-transport Prometheus metrics (9 transport buckets) | [ok] new in alpha.2 |
| Gossip safety warning (public `gossip_bind` without `gossip_bind_public_ok`) | [ok] new in alpha.2 |
| Adaptive client routing (EMA latency per bridge entry) | [ok] new in alpha.2 |
| Multi-bridge client pool (`MultiEntryPool`) | [ok] |
| Cohort P2P gossip (4 event types) | [ok] |
| Probe-scan detection + cross-bridge soft-block | [ok] |
| Token-burn propagation (cross-bridge replay prevention) | [ok] |
| Load-signal gossip (route around overloaded peers) | [ok] |
| Liveness heartbeats (distinguish dead from idle) | [ok] |
| Persistent on-disk replay log | [ok] |
| Session refresh tokens | [ok] |
| Per-invite claim service | [ok] |
| Prometheus metrics | [ok] |

---

## Prerequisites

```
# The repo pins its toolchain in rust-toolchain.toml (currently 1.86);
# rustup reads it automatically, so you only need rustup installed.
cargo build --release             # from repo root
```

Binaries land in `target/release/`:
- `mirage-bridge` - bridge daemon
- `mirage-client` - client daemon (SOCKS5 local proxy)
- `mirage-keygen` - key + invite generator
- `mirage-publish` - Nostr/DNS/DHT announcement publisher

---

## Minimal single-bridge setup (no cohort)

### 1. Generate key material

```sh
./target/release/mirage-keygen \
  --bridge-endpoint 1.2.3.4:8443 \
  --tokens 16 \
  > bootstrap.json
```

The output contains:
- `bridge_x25519_sk_hex` - bridge X25519 static secret
- `bridge_ed25519_pk_hex` / `bridge_ed25519_sk_hex` - bridge Ed25519 identity
- `operator_ed25519_pk_hex` - operator trust anchor
- `invite` - share this with clients

### 2. Write bridge config (`bridge.json`)

```json
{
  "bind": "0.0.0.0:8443",
  "bridge_x25519_sk_hex": "<from bootstrap.json>",
  "bridge_ed25519_pk_hex": "<from bootstrap.json>",
  "bridge_ed25519_sk_hex": "<from bootstrap.json>",
  "operator_ed25519_pk_hex": "<from bootstrap.json>",
  "replay_log_path": "/var/lib/mirage/replay.log",
  "max_concurrent_sessions": 4096,
  "anonymize_target_logs": true
}
```

### 3. Run the bridge

```sh
./target/release/mirage-bridge bridge.json
```

Add `--admin-ui` to also serve a local admin web UI on `http://127.0.0.1:3825`
(live counters, edit the config, restart the service). It prints a one-time
tokenized URL; keep it on loopback. See [operators.md §8](docs/operators.md#8-admin-web-ui-optional).

### 4. Write client config (`client.json`)

```json
{
  "local_bind": "127.0.0.1:1080",
  "invite": "<invite string from bootstrap.json>"
}
```

### 5. Run the client

```sh
./target/release/mirage-client client.json
# Now curl --proxy socks5h://127.0.0.1:1080 https://example.com
```

---

## Two-bridge cohort setup (alpha cooperation features)

The cohort cooperation stack is the distinguishing feature of Mirage:
multiple bridges coordinate so a probe that gets blocked at one bridge
is instantly blocked at all others, and a token burned at one bridge
cannot be replayed at any peer.

### 1. Generate keys for both bridges

```sh
./target/release/mirage-keygen \
  --bridge-endpoint 1.2.3.4:8443 \
  --cohort-endpoint 5.6.7.8:8443 \
  --tokens 16 \
  > cohort.json
```

`cohort.json` contains sections for `bridge` (primary) and `cohort[]`
(peers). Grab each bridge's `bridge_ed25519_pk_hex` - you need both
pks in both bridges' `gossip_authorized_peer_pks` lists.

### 2. Bridge A config (`bridge-a.json`)

```json
{
  "bind": "0.0.0.0:8443",
  "bridge_x25519_sk_hex": "<bridge-A x25519 sk>",
  "bridge_ed25519_pk_hex": "<bridge-A ed25519 pk>",
  "bridge_ed25519_sk_hex": "<bridge-A ed25519 sk>",
  "operator_ed25519_pk_hex": "<operator pk>",
  "replay_log_path": "/var/lib/mirage/bridge-a-replay.log",

  "gossip_bind": "0.0.0.0:9443",
  "gossip_peers": ["5.6.7.8:9443"],
  "gossip_authorized_peer_pks": [
    "<bridge-A ed25519 pk>",
    "<bridge-B ed25519 pk>"
  ],
  "gossip_probe_threshold": 5
}
```

### 3. Bridge B config (`bridge-b.json`)

Mirror config for bridge B, with gossip_peers pointing at A.

```json
{
  "bind": "0.0.0.0:8443",
  "bridge_x25519_sk_hex": "<bridge-B x25519 sk>",
  "bridge_ed25519_pk_hex": "<bridge-B ed25519 pk>",
  "bridge_ed25519_sk_hex": "<bridge-B ed25519 sk>",
  "operator_ed25519_pk_hex": "<operator pk>",
  "replay_log_path": "/var/lib/mirage/bridge-b-replay.log",

  "gossip_bind": "0.0.0.0:9443",
  "gossip_peers": ["1.2.3.4:9443"],
  "gossip_authorized_peer_pks": [
    "<bridge-A ed25519 pk>",
    "<bridge-B ed25519 pk>"
  ]
}
```

### 4. Start both bridges

```sh
./target/release/mirage-bridge bridge-a.json &
./target/release/mirage-bridge bridge-b.json &
```

On startup each bridge logs:

```
INFO cohort gossip: P2P transport bound  bind=0.0.0.0:9443 authorized_pks=2
INFO cohort gossip: full cooperation stack active (probe-defense, replay-coord, distress, heartbeat)
```

### 5. Client config with multi-entry pool

A client can hold connections to both bridges simultaneously, routing
around whichever is down or overloaded:

```json
{
  "local_bind": "127.0.0.1:1080",
  "invite": "<multi-bridge invite from cohort.json>"
}
```

---

## Reality TLS carrier (recommended for censored networks)

Add to bridge config:

```json
{
  "reality_enabled": true,
  "reality_cover_addrs": [
    "www.cloudflare.com:443",
    "www.fastly.com:443",
    "www.akamai.com:443",
    "www.edgecast.com:443"
  ]
}
```

Add to client config:

```json
{
  "reality_enabled": true,
  "reality_sni": "www.cloudflare.com",
  "reality_tls_fingerprint": "chrome-desktop"
}
```

---

## Single-port protocol mux (alpha.2)

The bridge can listen on a single port (443) and auto-detect any supported
transport based on the first bytes of each connection. Authentication
failures are transparently forwarded to a cover destination so the bridge
is indistinguishable from the cover service.

Add to bridge config:

```json
{
  "mux_enabled": true,
  "reality_cover_addrs": ["www.cloudflare.com:443"]
}
```

`mux_enabled` defaults to `true`. With it on, a single `bind` port handles
Reality TLS, HTTP/WebSocket, obfs-tcp, Shadowsocks-2022, and VLESS clients
simultaneously - no per-transport port assignment needed.

---

## Shadowsocks-2022 carrier (alpha.2)

Shadowsocks-2022 (`2022-blake3-chacha20-poly1305`) presents as high-entropy
opaque bytes with no detectable header. All traffic appears as random noise.

Generate a 32-byte PSK:

```sh
openssl rand -hex 32
```

Add to bridge config:

```json
{
  "ss2022_psk_hex": "<32-byte hex PSK>"
}
```

Add to client config:

```json
{
  "ss2022_psk_hex": "<same 32-byte hex PSK>"
}
```

The client will use SS-2022 as the carrier instead of Reality TLS when this
field is set. Both sides must use the same PSK.

---

## WebSocket carrier (alpha.2)

WebSocket tunnels the Mirage session over HTTP/1.1 upgrade. Effective behind
CDNs (Cloudflare, Fastly) that proxy WebSocket connections.

Add to bridge config:

```json
{
  "ws_enabled": true
}
```

Add to client config:

```json
{
  "ws_enabled": true,
  "ws_path": "/"
}
```

For CDN fronting, point the CDN origin at the bridge IP and configure the
client's `invite` to use the CDN hostname. The bridge serves cover traffic
on non-WS connections so the CDN origin cannot distinguish bridge from a
normal HTTP server.

---

## VLESS carrier (alpha.2)

VLESS uses UUID-based auth with zero overhead cryptography - the Noise-XX
session provides all security. Widely supported by existing infrastructure.

Add to bridge config:

```json
{
  "vless_uuid_hex": "<UUID - accepts standard format with dashes or plain 32-char hex>"
}
```

Both formats are accepted: `deadbeef12345678deadbeef12345678` and
`deadbeef-1234-5678-dead-beefdeadbeef`. Use `mirage-keygen --vless` to
generate a ready-to-paste UUID.

VLESS clients send the standard VLESS header; the bridge validates the UUID
and upgrades the connection to a Mirage session.

---

## Hysteria2 QUIC carrier (alpha.2)

Hysteria2 runs over UDP/QUIC with BBR congestion control, making it effective
on throttled or high-loss networks. Auth is a BLAKE3-derived 32-byte token sent
before the Noise session (auth is inside Noise). By default the TLS cert is
self-signed; to remove the self-signed-cert tell from active probers, serve a
real leaf cert with `hysteria2_cert_der_path` + `hysteria2_key_der_path` (set
both or neither).

Add to bridge config:

```json
{
  "hysteria2_bind": "0.0.0.0:8444",
  "hysteria2_send_rate_mbps": 100
}
```

Optional hardening: set `"hysteria2_brutal": true` for loss-immune BRUTAL
congestion control (only on genuinely hostile/lossy links - a constant send rate
is itself a tell), and `"hysteria2_cert_der_path"` / `"hysteria2_key_der_path"`
to serve a real cert. See [docs/configuration.md](docs/configuration.md#carriers-bridge-side).

Add to client config:

```json
{
  "hysteria2_enabled": true,
  "hysteria2_send_rate_mbps": 50
}
```

The client resolves the bridge address from the invite and connects via QUIC on
the `hysteria2_bind` port. TCP and QUIC transports can coexist on the same bridge.

---

## DoH tunnel carrier (alpha.2)

DNS-over-HTTPS mimicry: the connection looks like a HTTPS POST to `/dns-query`
with `Content-Type: application/dns-message`. Effective against middleboxes that
whitelist DoH resolvers (Cloudflare 1.1.1.1, Google 8.8.8.8).

No explicit config needed - the mux auto-detects DoH requests by path + content-type.
The client sends the standard 72-byte auth frame before the Noise session.

To use a CDN-fronted DoH path, point the CDN origin at the bridge and configure:

```json
{
  "ws_enabled": true
}
```

(The mux handles both WS and DoH on the same HTTP listener.)

---

## Metrics (optional)

```json
{
  "metrics_bind": "127.0.0.1:9100"
}
```

Then `curl http://127.0.0.1:9100/metrics` for Prometheus text.

---

## Security notes for alpha operators

1. **Keep `bridge_ed25519_sk_hex` secret.** It signs gossip events;
   a leaked key lets an adversary publish fake probe/burn/distress
   events to your cohort.

2. **`gossip_authorized_peer_pks` must be exact.** Events from
   unlisted keys are silently dropped. If a peer's events aren't
   propagating, verify both sides have each other's pk listed.

3. **`replay_log_path` prevents replay across restarts.** Without
   it, a restart resets the replay set and a previously-burned token
   could be replayed. Always set this in production.

4. **gossip port (`gossip_bind`) should NOT be publicly accessible.**
   Bind to a management-network or VPN interface, or firewall it to
   cohort peer IPs only. The gossip protocol authenticates events
   cryptographically but the TCP listener itself has no authentication
   layer - a flood of inbound connections would exhaust the
   `max_inbound_connections=64` cap. The bridge emits a `WARN` at
   startup if `gossip_bind` resolves to a public address; suppress it
   only by also setting `gossip_bind_public_ok: true` in the config.

5. **Alpha limitations:** Gossip peer keys are static (set at startup).
   Dynamic peer authorization (authorized-key negotiation, key rotation
   across cohort) is deferred to 0.2. For alpha, regenerating keys
   requires updating all peer configs simultaneously.

---

## Known alpha limitations

- No Tor hidden-service endpoints (v0.2 roadmap)
- Gossip peer authorization is static at startup
- Distress/liveness dashboards not yet surfaced in metrics endpoint
- `MultiEntryPool` client path uses latency-EMA routing; distress-signal weighted
  routing from cohort gossip is v0.2
- Hysteria2 defaults to a self-signed TLS cert; client skips cert verification (auth
  is via the Noise session inside - correct by design, but looks scary in logs). Serve
  a real cert with `hysteria2_cert_der_path`/`hysteria2_key_der_path` to avoid it.

---

## Reporting issues

File bugs at the project issue tracker. When reporting:
- Include `RUST_LOG=debug` output (with any bridge/operator keys redacted)
- Note which cooperation events are or are not appearing in logs
- Include the relevant config sections (redact all `_sk_` fields)
