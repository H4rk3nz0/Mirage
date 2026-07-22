# Operator guide

Running a bridge means other people's traffic exits through your server. This page takes you
from a bare VPS to a bridge people can actually use, and covers the choices that matter.

- [1. What you need](#1-what-you-need)
- [2. Run the wizard](#2-run-the-wizard)
- [3. Install it as a service](#3-install-it-as-a-service)
- [4. Hand out access](#4-hand-out-access)
- [5. Let clients find you automatically](#5-let-clients-find-you-automatically)
- [6. Multi-hop](#6-multi-hop)
- [7. Operating it](#7-operating-it)

---

## 1. What you need

- A server with a **public IP**. Anything from a $5 VPS upward.
- A port. **443 is the best choice** - it's where HTTPS lives, so it's the least
  interesting port on the internet.
- The `mirage-bridge` and `mirage-setup` binaries.

> **Where you host matters more than any config.** A bridge in a jurisdiction that honours
> takedown requests from the censoring country is a bridge with a short life.

---

## 2. Run the wizard

```sh
mirage-setup
```

It asks what it can't infer, and infers the rest. It will:

1. **Preflight your bind address** - tells you immediately if the port is taken, needs root,
   or isn't bindable, instead of failing after you've answered everything.
2. **Ask for a profile** rather than thirty questions:

| Profile | Carriers | Use when |
|---|---|---|
| **Balanced** | Reality + Hysteria2 | Default. Right for most operators. |
| **Max reach** | Everything, incl. DNS + CDN fallbacks | Users are on genuinely hostile networks. |
| **Stealth** | Reality only, padding on | You want the smallest possible footprint. |
| **Behind a CDN** | WebSocket + meek | You're fronting through nginx or Cloudflare. |
| **Custom** | You pick each one | You know exactly what you want. |

3. **Show you a review** of every choice before it writes anything.
4. **Write `bridge.json` + `client.json` at `0600`** - they contain your bridge's private
   keys. It refuses to silently overwrite an existing config, because replacing a bridge's
   identity key invalidates every invite you've already handed out.
5. **Offer a hardened systemd unit.**

### The questions that actually matter

**Public address.** What clients dial. This must be routable - the wizard rejects `0.0.0.0`,
because a wildcard is a bind-only placeholder no client can connect to.

**Reality cover domain.** When an unauthenticated scanner probes your port, the bridge gives
it a *real* TLS session with this host. So a prober sees an ordinary website, not a bridge.
Use a real, popular HTTPS site that is plausible for your server to talk to. To also match
the cover's *certificate* (so a probe that compares the two sees the same leaf), set
`reality_tls_mode = "borrow"` - the bridge fetches the cover's real leaf cert at startup.
It still needs `reality_tls_signing_sk_hex`; see the Reality rows in
[configuration.md](configuration.md#carriers-bridge-side).

**Probe decoy (`shadow_target`).** Unrecognised connections get forwarded here. Without it,
a scanner learns your port is "something unusual that isn't a normal server" - which is
exactly the signal you don't want to give.

**Padding.** Costs bandwidth, defeats ML flow classifiers. **The client must set
`pad_enabled` too** - it's an end-to-end agreement, not a server-side switch.

---

## 3. Install it as a service

The wizard writes a systemd unit with the hardening a key-holding, internet-facing daemon
should have (`DynamicUser`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`, a syscall
filter, and `CAP_NET_BIND_SERVICE` only when your port needs it):

```sh
sudo install -Dm600 bridge.json /etc/mirage/bridge.json
sudo install -Dm644 mirage-bridge.service /etc/systemd/system/mirage-bridge.service
sudo systemctl daemon-reload && sudo systemctl enable --now mirage-bridge
journalctl -u mirage-bridge -f
```

Open the port:

```sh
sudo ufw allow 443/tcp && sudo ufw allow 443/udp   # UDP is needed for Hysteria2 / HTTP-3
```

---

## 4. Hand out access

The wizard prints an **invite** - a `mirage://...` string with the bridge address, its public
key, capability tokens, and the carriers you enabled. That single string is all a user needs.

```sh
mirage-client client.json      # or paste the invite into mirage-client-gui
```

Invites are **bearer credentials**: anyone holding one can use your bridge. Send them over a
channel the censor can't read, and prefer one invite per person so you can reason about
who's using what.

Mint more later without touching the running bridge:

```sh
mirage-keygen --bridge-endpoint <host:port> --write-client-config client.json
```

If your bridge uses **port-hopping** (`derived_port_base`/`derived_port_range` in
`bridge.json`), mint invites that carry the matching hop parameters so clients can follow the
rotation - otherwise they only ever dial the static `bind` port:

```sh
mirage-keygen --bridge-endpoint <host:port> --port-base <N> --port-range <N> \
  --write-client-config client.json
```

**Rotation.** `mirage-rotate` rolls keys on a schedule. Rotating the bridge identity key
invalidates outstanding invites, which is exactly what you want after a suspected
compromise - and exactly what you don't want by accident.

---

## 5. Let clients find you automatically

Invites are point-to-point. **Discovery channels** let a client with no invite find bridges
by looking in a rendezvous location that rotates every epoch.

```sh
mirage-publish --daemon --from keygen.json --dht \
  --relay wss://relay.damus.io
```

| Channel | Trade-off |
|---|---|
| **DHT** (BEP-44) | No relay list to block; slower, and the DHT is public. |
| **Nostr** | Fast and reliable; relays can be blocked or can log. |
| **DNS TXT** | Works wherever DNS works; needs a domain you control. |

Run `mirage-publish` **on your workstation, not the bridge** - the operator signing key
should never sit on an internet-facing box.

> Discovery is inherently a trade-off: anything that lets users find you also lets a censor
> enumerate you. Mirage rotates rendezvous locations per epoch to raise that cost, but it
> does not eliminate it. See the [security model](security-model.md).

---

## 6. Multi-hop

A relay-enabled bridge can be a middle hop in a circuit of up to 3 bridges. Each hop is
authenticated separately and can only unwrap its own layer, so **no single bridge sees both
who the user is and where they're going**.

The wizard asks; in config it's:

```json
{ "circuit_relay_enabled": true }
```

Relaying costs bandwidth and makes you carry traffic you can't inspect. That's the point -
but decide deliberately.

---

## 7. Operating it

**Watch it.**

```sh
journalctl -u mirage-bridge -f
```

Set `metrics_bind` for counters - **bind it to localhost**, never a public interface.

**Privacy of your own logs.** `anonymize_client_logs` and `anonymize_target_logs` are on by
default. Leave them on: a seized bridge with verbose logs deanonymizes your users
retroactively. The best defence against a subpoena is not having the data.

**Don't become an open proxy.** `allow_private_network_targets` and
`allow_loopback_targets` default to `false` - that's what stops a client using your bridge to
reach `127.0.0.1` or your cloud metadata endpoint. Turning them on is almost always wrong.

**Abuse.** You are the exit for other people's traffic. Expect complaints, publish contact
info for your host, and consider the rate-limit knobs (`rate_limit_per_ip_per_minute`,
`max_concurrent_per_ip`).

**Capacity.** `max_concurrent_sessions` defaults to 4096. Real limits are usually bandwidth
and file descriptors (`LimitNOFILE`) before CPU.

Every knob: **[configuration](configuration.md)**.

---

## 8. Admin web UI (optional)

Instead of hand-editing `bridge.json`, run a small **local web UI** to see live counters, edit the
config, and restart the service from a browser:

```sh
mirage-bridge bridge.json --admin-ui        # serves on http://127.0.0.1:3825
```

Pass an address to override the default: `--admin-ui 127.0.0.1:9000`. On start-up the bridge prints
a one-time URL with an access token in the fragment, e.g.

```
Mirage bridge admin UI:  http://127.0.0.1:3825/#t=1a2b3c...
```

Open that URL (the token never leaves your machine - it isn't sent to the server or logged). The UI:

- shows the live dashboard (sessions, per-transport counts, Reality probes, rate-limit drops);
- lets you edit every config field, grouped by section, and **Save** (written atomically, `0600`);
- **Restart**s the `mirage-bridge` systemd unit to apply changes (set the unit name with
  `admin_service` if yours differs).

It is **loopback-only and token-gated by design** - it can read and write your bridge config,
including key material. Keep it on `127.0.0.1` (SSH-forward a port to reach it remotely); never bind
it to a public interface. Secret fields (`*_sk_hex`, PSKs, salts, the relay token) are masked in the
browser and preserved on save - the UI can neither display nor overwrite a secret you don't retype.

You can also enable it from the config file instead of the flag: `"admin_bind": "127.0.0.1:3825"`.

## 9. Paranoid mode + cover sources (optional)

For the strongest posture, set `"paranoid": true` in `bridge.json` (and clients set it too). It forces
the Reality carrier, strict anti-probe, and **replay pacing**: authenticated sessions wear the packet
sizes/timing of a real recorded video stream instead of a generated shape.

Build the trace library the pacer replays with `mirage-cover-record` - a self-contained binary (no
yt-dlp, ffmpeg, tcpdump, or python; it fetches a real HLS video over its own TLS stack and reads the
wire envelope off the TLS record framing):

```sh
mirage-cover-record /opt/mirage/library --mode video  --count 20   # streaming-video envelope
mirage-cover-record /opt/mirage/library --mode browse --count 20   # web-browsing envelope
mirage-cover-record /opt/mirage/library --loop 30 --max 40         # self-driving (systemd unit)
```

Each class lands in `library/<class>/`. Point `reality_pace_profile` at the class dir that matches
your Reality pretext (a video/CDN host -> `library/video`; a general site -> `library/browse`) on
both the bridge and the clients (ship it with the client config). Both ends must run paranoid/replay
for the shape to match. Per session the pacer chains a random shuffle of several traces, so nothing
loops. Details: [`tools/cover-sources/README.md`](../tools/cover-sources/README.md).
