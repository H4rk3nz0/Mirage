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

**An announcement expires every epoch (1 hour).** Publishing once by hand gives you a
deployment that stops being discoverable within the hour, which is the easiest way to get
this wrong. So publishing has to repeat, and `mirage-setup` writes you a systemd timer that
does it:

```sh
sudo install -Dm600 keygen.json /etc/mirage/keygen.json
sudo install -Dm644 mirage-publish.service mirage-publish.timer /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now mirage-publish.timer
systemctl list-timers mirage-publish.timer      # confirm the next fire time
```

The timer fires one minute past every hour **in UTC**, because an epoch is
`unix_secs / 3600` and boundaries therefore land on the UTC hour. That suffix is not
decoration: on a host at +05:30 an unqualified `*:01:00` fires at 11:31 UTC - 31 minutes
into the epoch instead of 1 - and a DST host drifts by an hour twice a year. Each run
publishes `--epochs 0,1` (current + next), so a late or missed run still leaves a valid
announcement covering the following hour.

A one-shot on a timer rather than `mirage-publish --daemon`: the operator secret is then
resident for the seconds a publish takes instead of for the life of a process. The daemon
mode still exists if you prefer one long-running process.

| Channel | Trade-off |
|---|---|
| **DHT** (BEP-44) | No relay list to block; slower, and the DHT is public. |
| **Nostr** | Fast and reliable; relays can be blocked or can log. |
| **DNS TXT** | Works wherever DNS works; needs a domain you control **and** a server that accepts RFC 2136 dynamic updates (BIND, Knot, PowerDNS, deSEC). Rotates like the others once configured. |

### Rotating DNS TXT

Give `mirage-publish` a zone and a TSIG key and it writes the epoch's record itself:

```sh
mirage-publish --from keygen.json \
  --dns-server ns1.example.org:53 --dns-zone example.org \
  --tsig-name mirage-key. --tsig-secret-file /etc/mirage/tsig.key
```

`mirage-setup` asks for these and bakes them into the timer. One protocol rather than a
per-provider HTTP client: provider APIs change auth and record semantics on their own
schedule, and each one is a dependency that fails silently at 3am.

Each publish REPLACES the record set at the name rather than appending - without that, a
republish every hour would pile up stale announcements until the answer no longer fit.

Two things worth knowing:

- **Keep the secret in a file, never on the command line.** `--tsig-secret` exists but warns:
  `/proc/<pid>/cmdline` is world-readable (mode 444), so any local user can read the key while
  the process runs - hourly, under the timer. A systemd unit under `/etc/systemd/system` is
  world-readable too, which is why `mirage-setup` writes `tsig.key` at `0600` and points the
  unit at it with `--tsig-secret-file`. This is the same reason the operator key has always
  come from `--from <file>` rather than a flag.
- The TSIG key is less dangerous than the operator key - announcements stay operator-signed,
  so a stolen TSIG key cannot forge one that verifies - but it can delete your records and
  take the channel offline.
- `--dns-apex` exists for delegating discovery to a subdomain: update zone `example.org` but
  hang the records off `d.example.org`.

**Where you install the timer is a security decision.** It reads the operator Ed25519
secret, and whoever holds that key can forge future announcements - redirecting every client
that discovers this bridge. The bridge daemon deliberately does not hold it, which is why
this is a separate unit. Installing it on the bridge host is supported and is what a
single-host deployment will do; it collapses that separation, so a bridge compromise then
yields the signing key too. A separate operator host with outbound access to the relays and
no inbound exposure is stronger.

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

## 9. Proteus + paranoid mode (optional)

**Proteus** makes authenticated sessions wear the packet sizes and timing of a *real recorded flow*
instead of their own. Turn it on:

```json
{ "proteus": true }
```

on the bridge and on clients. That is the whole procedure. With no library configured the daemon
records and refreshes its own cover in-process - nothing to install, nothing to ship. The default
2.5 GB/day budget sources a browse class plus a dense upstream class; 6 GB/day or more adds video,
because a video capture is the better downstream disguise while its upstream is too sparse to carry
a handshake, so Proteus pairs the two. Per session it chains a random shuffle of several traces, so
nothing loops.

### Budget for it before you enable it

Cover runs for as long as a session is open, busy or idle, and the envelope's rate is therefore also
a ceiling on every client's throughput. The two are the same quantity, 1:1 - user bytes displace
padding rather than adding to it, which is precisely what makes an idle tunnel and a busy one look
alike:

| budget | cover bill per client | sustained throughput |
|---|---|---|
| 2.5 GB/day (default) | 2.5 GB/day | ~0.23 Mbit/s |
| 6 GB/day (adds video cover) | 6 GB/day | ~0.56 Mbit/s |

Multiply by your client count, and by the fraction of the day a client is actually connected - this
is a per session-day figure, so a client online two hours a day costs two hours of cover, not
twenty-four.

Set `proteus_max_gb_day` to your own number, or `"unlimited"`. Since the
relationship is 1:1, that number IS the throughput you are buying: ~2 GB/hour connected gets a
client roughly 5 Mbit/s, ~7-11 GB/hour gets 15-25 Mbit/s, because at those budgets the recorder can
use real video cover rather than page loads.

**The budget also sets worst-case latency, not just throughput - for browse cover.** Cheap cover
cannot also be smooth: a page load is either fast, which costs, or waiting, which is a gap the
tunnel stalls inside, so a client complaining that browsing is laggy needs a bigger budget, not a
shaping knob. There is not one; see [Proteus](proteus.md) for why that is a theorem rather than a
missing feature.

**Video cover is the exception, and it does not respond to the budget at all.** A video capture
waits each segment's true duration, so the tunnel inherits a stall that long - measured 5.8 s on
the default PeerTube sources and 10 s on Aparat and Turkey's NTV. No HLS source publishes segments
under the 2 s ceiling. Raising the budget buys a fatter variant of the same stream with the same
segments, so it changes nothing here. If clients need low latency, keep the budget below the
6 GB/day video threshold and stay on browse cover.

A budget is a THROUGHPUT and LATENCY choice, not a concealment one - a censor-vantage matrix
measured every budget indistinguishable FROM EACH OTHER - so pick the cheapest one your users can
tolerate rather than the biggest one you can afford. That is a statement about budgets, not a claim
that the tunnel is undetectable: a replicated measurement still finds a small residual activity
signal (about AUC 0.57 against a 0.53 control) on every budget tested. See [Proteus](proteus.md). If your deployment needs line rate and will not pay for it, run
the Reality carrier WITHOUT Proteus and accept that flow shape is then exposed to traffic analysis.

Note also that Proteus does not cover every carrier. Reality, WebSocket, Shadowsocks-2022,
Hysteria2, h3, meek and DoH wear the envelope; plain TCP, obfs-tcp, dnstt and WebRTC do not, on
either end, and nothing warns you. `mirage-keygen --proteus` advertises that the BRIDGE paces - it
does not promise that the carrier a given client picks is one of the seven.

Proteus is a per-connection property: **both ends must have it on**, or one side frames and the other
does not and the session hangs rather than merely looking different.

For the strongest posture set `"paranoid": true` instead, which turns on Proteus along with the
Reality carrier and strict anti-probe.

Generate invites with `mirage-keygen --proteus` so they advertise that this bridge requires
pacing. A client without Proteus then refuses the invite up front with the reason, instead of
failing inside a handshake and looking like an unreachable bridge - a paced bridge cannot serve an
unpaced client, so the session fails outright rather than falling back.

Clients pull this bridge's cover library over the tunnel once connected and stop recording their
own, which also makes replay *joint* (both ends replaying one captured flow rather than two
unrelated ones).

If you want a *specific* envelope - your own site, a particular stream, an upload endpoint you
control - record it with `mirage-cover-record` and set `proteus_profile`. Setting that path turns
auto-sourcing off, so set `proteus_profile_up` to a dense capture as well or downloads inherit a
20x slowdown. Details, including per-site target-conditioned replay and the bandwidth cost of a
given profile: [`tools/cover-sources/README.md`](../tools/cover-sources/README.md) and
[Proteus](proteus.md).
