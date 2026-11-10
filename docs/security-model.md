# Security model

Mirage is a proxy for networks that restrict access to the open internet. This
page describes its threat model, controls, and known limits. Its traffic has
not been shown indistinguishable from a matched real service.

## Adversaries

| Adversary | Capability | Mirage's stance |
|---|---|---|
| **Passive DPI** | Reads every packet on the wire, matches signatures and flow statistics | Primary target. Some carriers carry valid protocol framing, but a matched real-service indistinguishability result has not been established. |
| **Active prober** | Connects to a suspected bridge and pokes it to confirm | Invite-gated and forwarded to cover on the Reality path. Indistinguishability is unproven: response timing and cross-arm behavior retain measured differences. |
| **Censor who holds an invite** | Obtained a real invite (leak, insider, purchased) | Partly defended. Can find and read the rendezvous, but **cannot forge or poison** it, and cannot silently escalate to writing bridge records. |
| **Malicious bridge operator** | Runs a bridge you connect through | An exit bridge sees destinations and any application traffic that lacks end-to-end encryption. Multi-hop separates client and destination knowledge across operators. |
| **Global passive adversary** | Observes both ends of every link at once | Not defended; timing and volume can correlate the ends. |

## What is defended

**Carrier mimicry.** The carriers aim to match allowed protocols on the wire.
Reality sends a TLS 1.3-shaped handshake; WebSocket auth rides in a `Cookie`;
some QUIC carriers use ordinary QUIC framing. A Firefox ClientHello template
matches a measured JA3, but that alone does not validate the complete live
handshake or flow. The Reality probe splice has measured timing and lifecycle
residuals, and the optional Wu printable prefix is recognizable to a classifier
stronger than the published exemption it targets. Do not treat these carriers
as proven indistinguishable from a real service. See [Proteus 2.0](proteus-2.0.md)
and the [cover-native proposal](cover-native-proposal.md).

**Anti-probe knocks.** Before a Mirage session starts, the client proves it
belongs. When the operator provisions a per-bridge obfuscation secret (carried
only inside the confidential invite), the obfs-tcp and WebSocket knocks are
keyed on **that secret** - so an active prober who merely scraped the bridge's
public key from a discovery record **cannot** mint a valid knock. Without a
provisioned secret they fall back to a public-key-derived knock (a scanner
filter, not a secret) and the Reality carrier's stronger anti-probe still holds.

**Invite-gated discovery.** Bridges announce over Nostr, DNS-TXT, and the
BitTorrent DHT under per-epoch rendezvous points derived from a secret salt.
An observer without the invite cannot derive those rendezvous points from the
public records alone. The DHT rendezvous uses **Tor-style key
blinding**: the operator holds the write key, and invite-holders can derive the
per-epoch *read* key (to find and verify the record) but **cannot derive the
write key** - so a cohort member cannot forge or evict the operator's bridge
descriptor. Nostr per-epoch author keys are likewise derived from an operator
secret, not the shared invite salt.

**Exit-side SSRF containment.** A bridge's exit refuses to proxy to loopback,
RFC1918/CGNAT/ULA private ranges, and always-forbidden ranges (link-local, the
cloud-metadata endpoint, multicast). Loopback and private networks are two
**independent** opt-ins, so enabling one never silently re-admits the other, and
metadata/link-local is refused regardless. DNS names are resolved once and the
validated IPs are dialed directly to avoid a second lookup during the dial.

**Multi-hop onion routing.** Chain up to three bridges; each hop authenticates
with its own single-use capability token and can peel only its own layer, so no
single hop sees both the client and the destination.

**Forward-secure capability tokens + revocation.** Bridge access tokens are
epoch-scoped and carry an inline operator-to-epoch-subkey certificate, minted
offline when the invite is generated (a fresh subkey per token, so an invite's
batch cannot be linked into a cohort at the terminating bridge). The bridge
verifies the certificate chain against the operator key, with a grace window for
the previous key during rotation. Clients honour signed revocations and drop a
revoked bridge from their pool.

**TUN route installation.** In TUN mode the client installs split-default
routes and a bypass route for each bridge IP, then restores the previous routes
on exit. If it cannot install the required routes, it refuses to start TUN
mode. This check does not cover every DNS or platform routing behavior; see
the limitations below.

## What is NOT defended (non-goals)

**A global passive adversary that watches both ends.** An observer of the
client and destination links can correlate timing and volume. Mirage does not
claim to prevent this.

**End-to-end traffic-analysis / website fingerprinting.** Padding and
constant-rate cover raise the cost of flow-shape classifiers but do not make
flows information-theoretically indistinguishable. Treat shaping as
defence-in-depth, not a guarantee.

**The bridge you exit through sees your destination.** A single bridge learns
where it connects on your behalf. Client IPs are masked in ordinary logs by
default, but a live bridge still sees its peers. Use separate operators and
multi-hop if bridge-side correlation is in your threat model.

**Raw-ciphertext entropy blocking, for obfs-tcp specifically.** The obfs-tcp
carrier is uniform-random from the first byte with no protocol cover, so a censor
that blocks all high-entropy flows will flag it. Mirage does not hide that;
instead the client's self-adversary grades obfs-tcp's egress with the same
heuristic and steers off it on networks where it would be flagged. Use a
cover-bearing carrier (Reality, meek, WebSocket) where entropy blocking is in
play.

**TUN routing quirks off the beaten path.** Whole-device routing is wired on
Linux, macOS, and Windows and modelled on how WireGuard/OpenVPN drive each
platform, but it captures via routes only - it does not (yet) manage DNS
resolvers on macOS or install a firewall kill-switch. Bridge-exclusion routes
are also pinned once at start, so a bridge whose IP is *rotated in* mid-session
becomes unreachable in TUN mode until you restart (the existing pool keeps
working, and SOCKS mode is unaffected). On an unusual multi-homed or split-DNS
setup, prefer the SOCKS5 proxy (with `socks5h://`) where the resolver is
unambiguous. If routes can't be installed the client fails closed rather than
leak.

**Endpoint compromise.** Mirage protects traffic in transit. It cannot help if
your device is compromised, or if you log into an account that identifies you.

## Reporting a weakness

If you find a way to distinguish, block, or de-anonymize Mirage traffic that
this page claims is defended, that's a real bug - open an issue with a concrete
reproduction (a capture, a distinguisher, or a test).
