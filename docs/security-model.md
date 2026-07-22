# Security model

Mirage is a framework stack for reaching the open internet from a network that
tries to stop you. This page states plainly **who it defends against, how, and
where it stops**. Anti-censorship tools that overpromise get people hurt, so the
non-goals are as important as the guarantees.

## Adversaries

| Adversary | Capability | Mirage's stance |
|---|---|---|
| **Passive DPI** | Reads every packet on the wire, matches signatures and flow statistics | Primary target. Carriers mimic real protocols byte-for-byte; no Mirage-unique bytes on the wire. |
| **Active prober** | Connects to a suspected bridge and pokes it to confirm | Defended. A bridge is indistinguishable from its cover service to anyone who can't already prove they hold an invite. |
| **Censor who holds an invite** | Obtained a real invite (leak, insider, purchased) | Partly defended. Can find and read the rendezvous, but **cannot forge or poison** it, and cannot silently escalate to writing bridge records. |
| **Malicious bridge operator** | Runs a bridge you connect through | Sees your traffic on a single hop. Use **multi-hop** so no one hop sees both you and your destination. |
| **Global passive adversary** | Observes both ends of every link at once | **Not defended** - see non-goals. No low-latency system defeats this. |

## What is defended

**Carrier indistinguishability.** Every carrier is built to match a real
protocol on the wire - Reality is a real TLS 1.3 handshake to a real cover site
(with a browser-accurate ClientHello, a matching cipher-suite set, and a
0.5-RTT session ticket like a genuine server issues); WebSocket auth rides in a
`Cookie`, not a Mirage-shaped subprotocol; QUIC carriers obfuscate to look like
ordinary QUIC. There is no constant byte pattern that flags "this is Mirage."

**Anti-probe knocks.** Before a Mirage session starts, the client proves it
belongs. When the operator provisions a per-bridge obfuscation secret (carried
only inside the confidential invite), the obfs-tcp and WebSocket knocks are
keyed on **that secret** - so an active prober who merely scraped the bridge's
public key from a discovery record **cannot** mint a valid knock. Without a
provisioned secret they fall back to a public-key-derived knock (a scanner
filter, not a secret) and the Reality carrier's stronger anti-probe still holds.

**Unlinkable discovery.** Bridges announce over Nostr, DNS-TXT, and the
BitTorrent DHT under per-epoch rendezvous points derived from a secret salt, so
an observer without the invite can neither locate a rendezvous nor cluster an
operator's announcements across time. The DHT rendezvous uses **Tor-style key
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
validated IPs are dialed directly, closing DNS-rebind.

**Multi-hop onion routing.** Chain up to three bridges; each hop authenticates
with its own single-use capability token and can peel only its own layer, so no
single hop sees both the client and the destination.

**Forward-secret capability tokens + revocation.** Bridge access tokens are
epoch-scoped; compromising an online issuer cannot forge tokens for past epochs.
Clients honour signed revocations and drop a revoked bridge from their pool.

**Whole-device VPN, fail-closed.** In TUN mode the client installs the OS routes
that actually capture traffic (a split-default) and a bypass route for each
bridge IP, and restores them on exit. If it cannot install those routes it
**refuses to run** rather than bring up an interface that would leak your
traffic in clear.

## What is NOT defended (non-goals)

**A global passive adversary that watches both ends.** If someone can observe
your link *and* the destination's link simultaneously, packet timing and volume
correlate the two regardless of how the middle is disguised. No low-latency
transport (Mirage, Tor, a VPN) defeats this; Mirage does not claim to.

**End-to-end traffic-analysis / website fingerprinting.** Padding and
constant-rate cover raise the cost of flow-shape classifiers but do not make
flows information-theoretically indistinguishable. Treat shaping as
defence-in-depth, not a guarantee.

**The bridge you exit through sees your destination.** A single bridge is a
proxy: it learns where you're going (though logs are anonymized by default). If
your threat is the bridge operator, use multi-hop.

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
