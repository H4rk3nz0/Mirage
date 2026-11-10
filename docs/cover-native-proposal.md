# Cover-native transport proposal

Status: design proposal. It has not been implemented or validated. Revised 10 November 2026.

Here “wire entropy masking” means two separate properties: recognizable, valid
carrier bytes rather than raw ciphertext from byte zero, and a joint flow of
sizes, directions, timings, connection events, and lifetimes that belongs to
the claimed cover workload. Mirage's Proteus mainly addresses the second;
`wu_preamble` targets one published first-payload randomness heuristic. Neither
property follows from the other.

## Assessment of the current stack

Mirage's session/carrier/discovery separation is useful. Its authenticated
Noise + ML-KEM session and capability-gated discovery add protections beyond
the lightweight [VLESS](https://xtls.github.io/en/development/protocols/vless.html)
+ [REALITY](https://github.com/XTLS/REALITY/blob/main/README.en.md) path. Proteus
also makes a meaningful design choice: a slot is emitted whether or not user
bytes are waiting, and queued user bytes displace padding without changing the
chosen slot's size or deadline. The demand-independent scheduling invariant in
`crates/transport-reality/src/pacer.rs` is worth preserving.

The current evidence supports a narrower security claim than some top-level
wording suggests:

* The cover-class measurements used a recorder that omitted open, long-lived
  connections; the correction is documented in `cover-scheduling.md`. The
  re-take is still provisional. AUC values against another replay/control are
  not a matched **real-origin versus tunnel** test.
* A finite, verbatim trace library repeats. A real captured sample has genuine
  structure once; repeated samples have a cross-session fingerprint. TLS
  handshake, origin choice, flow lifetime, ACKs, and replay boundaries also
  contribute to the observable distribution.
* The Reality-like path has a bespoke copied-certificate/invite-key verification
  branch (`crates/transport-reality/src/carrier.rs`). A standard TLS client cannot
  validate that branch as an ordinary origin connection. Unauthorized probes
  can be forwarded, but the bridge-to-cover setup creates a response-time
  difference already measured in `proteus-2.0.md`.
* The optional Wu prefix clears the cheap exemption described by
  [Wu et al.](https://www.usenix.org/conference/usenixsecurity23/presentation/wu-mingshi)
  for first TCP payloads. `crates/common/src/wu_preamble.rs` makes its first
  base64url character encode the exact prefix length. A passive observer can
  check that correlation and the following ciphertext boundary. Applying it
  before every obfuscated QUIC datagram is outside that paper's measured TCP
  condition and does not create a native QUIC packet.

The README's “upgrade to Reality” claim is defensible for *some security
properties*, not general speed. At 2.5 decimal GB per day of continuously
connected cover, the wire budget is about 0.23 Mbit/s. An incompressible user
stream cannot exceed the cover's available payload slots. Direct-copy VLESS +
REALITY can be much faster when flow-shape defense is not required.

| Stack | Strong point | Binding limitation |
|---|---|---|
| VLESS + REALITY | Lightweight TLS-like access and a fast direct data path | No demand-independent flow envelope by default; flow analysis remains possible |
| Mirage Reality + Proteus | Payload displaces scheduled padding; inner hybrid session | Finite replay pool, provisional real-cover evidence, and cover-rate ceiling |
| Proposed encrypted sync carrier | Real H3/application syntax, valid opaque objects, reliable high-rate cover candidate | Needs a cooperating service and real heavy-use population; rate remains cover-bounded |

## The capacity constraint

For a fixed observable slot schedule, let slot `i` carry `s_i` bytes on the wire
and require `h_i` bytes of carrier, framing, authentication, and padding-control
overhead. Demand-independent wire behavior requires the same slot even when the
user queue is empty. Therefore, over interval `T`,

`delivered_user_bytes(T) <= sum_{i in T} max(0, s_i - h_i)`.

More efficient packing can recover wasted capacity, and a transport that avoids
connection-level head-of-line blocking can improve useful throughput under loss.
Neither creates new bytes at a fixed cover budget. Higher sustained throughput
for incompressible traffic requires a higher-rate *genuine* cover class, more
valid concurrent cover flows, or a larger bill. Five Mbit/s alone costs at least
2.25 decimal GB per connected hour, before framing, loss, and retransmission.

Gap percentiles alone are insufficient for admission or buffer sizing. Define
`S(t)` as cumulative usable cover-slot bytes and `A(t)` as cumulative admitted
user bytes. Queue backlog is driven by the largest positive service deficit over
*all* preceding windows:

`Q(t) = max(0, sup_{u <= t} [A(t)-A(u) - (S(t)-S(u))])`.

First require long-run `arrival rate < usable service rate`; then evaluate
short-window deficits against explicit burst models. A 10-second HLS silence is
one important deficit, but many low-service intervals can be worse. Little's
law relates means in a stable queue; it does not prove stability from a gap
quantile. See the corrected `cover-scheduling.md`.

The square-root law is likewise conditional. It applies to particular covert
packet insertion models. If payload replaces padding byte for byte under a
demand-independent, *correctly distributed* cover process, the payload can add
zero observable divergence and positive linear capacity is possible. Mirage's
unmeasured term is divergence of its generated cover process from genuine cover,
especially over many sessions. Requiring a `1/sqrt(t)` rate decay without
measuring the real workload might itself create a fingerprint. These are
questions for a matched reference experiment, not a universal rate formula.

For a simple insertion channel with innocent output law `P0` and an inserted
packet law `Q`, using insertion fraction `a` gives
`Pa=(1-a)P0+aQ` and, for small `a`, approximately
`D(Pa||P0)=a^2 chi2(Q||P0)/2`. Over `n` independent observations, bounded
divergence forces `a=O(1/sqrt(n))`. This is the square-root regime under its
stated assumptions ([Wang, Wornell, and Zheng](https://arxiv.org/abs/1506.03236)).
If an existing encrypted body slot is replaced and its *entire observable
output law* remains `P0`, then `Q=P0` to that observer and this insertion
argument has zero divergence. The rate is instead bounded by body-slot bytes;
any mismatch in metadata or application behavior restores a detection term.

## The mathematical route to near-cover-rate goodput

Positive-rate payload substitution is possible under an independently
generated, valid cover process. Define
`Z` as everything the censor can observe outside protected body contents:
endpoint and account priors, DNS and handshake, packet sizes/times/directions,
ACKs/retries, flow count, and lifetime. Let `M` be arbitrary tunnel demand.
An ideal carrier meets both conditions:

`P_tunnel(Z | public network state) = P_real(Z | public network state)`, and
`P_tunnel(Z | M, public network state) = P_tunnel(Z | public network state)`.

Suppose both paths use the same application and transport code. The cover
controller cannot read `M`, and every emitted body is a valid equal-length
encrypted object. Under those assumptions, the body-content distinction is
bounded by the application and TLS/QUIC encryption. In this
idealized model, a passive detector's advantage is at most cover-metadata
distribution mismatch plus cryptographic and implementation side channels.
That is a design obligation, not a measured property of Mirage.

Schematic coupling bound for a passive observer:

`TV(P_tunnel(wire), P_real(wire)) <= TV(P_tunnel(Z), P_real(Z)) + epsilon_crypto + epsilon_implementation`.

The first term is zero only when the *joint* cover process is correct; matching
individual packet histograms does not suffice. Account behavior belongs to
the first term. The implementation term includes content-dependent CPU/storage
work and packetization that bypass the ideal encryption argument.

Session starts and stops are part of `Z`: launching a sync session because a
proxy request arrived violates the first equality even if every later packet
is perfectly shaped. A real application launch or precommitted background
policy must create the opportunity before demand is known.

Formal steganography has positive capacity even under exact distribution equality
([Wang and Moulin](https://arxiv.org/abs/cs/0702161));
[minimum-entropy coupling](https://arxiv.org/abs/2210.14889) gives a general
distribution-preserving coding perspective. Neither result supplies a model of
real network/application traces or creates bandwidth beyond the available
cover bytes. Encoding bulk data through visible schedule choices would be
limited by the schedule's entropy and its causal/application constraints.

For one direction, with real cover rate `R_cover`, mean replaceable body
fraction `f_body`, inner framing efficiency `eta_frame`, and delivered fraction
under loss/flow control `eta_net`, the working target is
`R_user ≈ R_cover * f_body * eta_frame * eta_net`, with each factor at most 1.
At saturation, preallocated equal-length filler lets payload consume nearly
every usable body byte; idle sessions still pay for every scheduled byte.
Efficient batching, larger validated object chunks, independent H3 streams,
and sufficient QUIC flow credit can raise the last two factors without changing
the cover schedule. For example, 20 Mbit/s over a 100 ms path needs roughly
250 kB of in-flight credit just to fill the bandwidth-delay product; a smaller
credit window silently caps goodput. All dummy and payload paths must consume
credit, ACKs, retries, and application storage work in the same way.

The cover content's *semantic redundancy* determines how much can be replaced.
If an `n`-bit slot must let the receiver recover both independent original
content `X` and a hidden message `M`, given receiver side information `S`,
lossless recovery requires `H(M) <= n - H(X | S) + o(n)` bits. Unpredictable
live media with no shared copy of `X` leaves little room; cached or
reconstructible content can leave nearly the whole slot. In the proposed
scratch-object sync workload, no original media item must be recovered: an
arbitrary encrypted object is itself valid application content. This is the
high-capacity opening, provided its *object activity* matches real users.

Queueing remains a separate constraint. A cover controller samples a genuine
high-rate workload independently of demand; an admission controller accepts
only traffic whose directional backlog and delay tails fit that workload's
measured service curve. Within an existing slot it can choose an interactive
inner frame before a bulk frame, because that changes protected content only;
it cannot pull the slot forward. For slot `i` of usable capacity `c_i`, choose
per-stream allocations `x_ij >= 0` with `sum_j x_ij <= c_i` to minimize a
weighted completion-time or tail-delay objective. A work-conserving choice
fills all available capacity whenever backlog exists, while deadline-first
interactive and fair bulk allocation affect only encrypted contents. The
outer `(time_i, size_i, direction_i)` stays fixed. Multiple naturally
occurring independent H3 streams can smooth aggregate service gaps. For `N`
equal-rate streams with independent per-window service of mean `mu` and
standard deviation `sigma`, aggregate
mean is `N*mu` while standard deviation is `sqrt(N)*sigma`, so relative
variation falls as `1/sqrt(N)`. Shared congestion or application timers can
erase that gain. Creating extra flows beyond the real application's
concurrency distribution is a fingerprint. This improves *usable fraction and
delay* at a given cover rate; high absolute throughput
still requires genuinely high-rate cover. At 100 Mbit/s the cover bill is at
least 45 decimal GB per connected hour before overhead.

Mirage's present mux writes into an opaque paced byte stream. Bounded mux
batches let a newly arrived interactive stream join the next fairness pass,
but bytes already staged in `PacedChannel` cannot be reordered. Its 256 KiB
write bound represents roughly 15 seconds of wire bytes at a 141 kbit/s
cover rate. Strict low-latency service therefore requires selecting inner
streams *at the cover token deadline*, or exposing token credit to the mux so
it cannot write far ahead. Native independent H3 streams are the cleaner
long-term interface; simply lowering the queue bound could instead throttle
a high-rate path. None of these scheduling choices may advance an outer token.

For longitudinal cover, matching one flow is insufficient. KL divergence of
the joint 1-to-`n`-session distributions is the sum of conditional divergences
given prior sessions; it is not generally `n` times a measured single-window
error. Repeated traces or account patterns can be stronger than a single-flow
detector. Structural equality in the application state machine is therefore
the route to a *small* mismatch term, and held-out real-versus-tunnel tests at
1, 10, and 100 sessions are the attempted falsification.

## Prior art and the remaining research gap

The proposed design runs the cover application
on both public and authorized paths. For each producer output chunk, the
authorized path substitutes a same-length inner ciphertext chunk immediately
before the standard TLS/H3 stack encrypts it. The producer still executes,
including while the user queue is empty; its output determines every slot.
Public users receive the original bytes. This is a dual execution path in one
real service, not a protocol lookalike attached to a separate bridge. **That
core technique is prior art**: [Balboa](https://arxiv.org/abs/2104.05871)
rewrites TLS-protected application data and restores the original content before
the receiving application sees it. Its authors measured timing differences from
the rewrite. [Huma (NDSS 2026)](https://cs.uwaterloo.ca/~s4kamali/publications/huma/)
uses a participating website and prepares covert responses in the background
to reduce such timing anomalies. The Mirage proposal cannot claim live cover
replacement or deferred preparation as its invention.

[Telepath](https://ecommons.cornell.edu/entities/publication/48d5daec-d223-4795-8a87-a65dc6a301b2)
also makes application semantics a first-class requirement: substitution that
changes what a real application subsequently does is detectable even when the
encrypted flow looks plausible. Its Minecraft design is different from object
sync, but the constraint is the same. The opaque-object choice below is a
proposed way to keep sync's validity and integrity checks normal, not a claim
to invent application-aware substitution.

Cloud storage as a censorship-resistant tunnel is also established prior art:
[CloudTransport](https://dedis.cs.yale.edu/dissent/papers/cloudtransport.pdf)
used ordinary cloud client libraries and shared storage accounts for a
general-purpose proxy. [Skyhook (FOCI 2024)](https://www.petsymposium.org/foci/2024/foci-2024-0011.php)
revisited its latency, account, and operating-cost tradeoffs and narrowed the
cloud path to short bootstrapping messages. The design below is therefore **not
a new cloud-storage transport**. Its untested question is whether a cooperating,
high-rate, end-to-end-encrypted *sync application* with native H3 and a
demand-independent object schedule can beat those limitations while matching
real user behavior over long sessions. If that population does not exist, the
cloud branch has no security claim and should remain a signaling path.

The security argument has two parts, each with a separate assumption. First,
the authorized and public cover controllers must produce the *same distribution*
of lengths, timings, requests, responses, connection lifetimes and transport
feedback conditional on public network state. Second, given equal-length
plaintext and fresh nonces, secure TLS/QUIC AEAD makes encryption of cover
bytes and encryption of substituted ciphertext computationally
indistinguishable to a passive observer without keys. Under both assumptions,
the observer receives the cover distribution regardless of tunnel demand. The
first assumption is difficult and must be tested; the second follows from the
standard authenticated-encryption security model, provided content-dependent
compression, caching, error paths, and packetization are excluded. If the
receiving cover application parses the body, the original content must be
restored before it sees the bytes, as in Balboa. That requires a shared content
model or another source of the original content and may defeat high-rate live
media. A censor with TLS keys, a trusted interception root, or a leaked
invitation is outside the passive claim.

A schematic proof obligation for a bounded passive distinguisher is:
`advantage <= metadata-distribution mismatch + AEAD advantage + implementation
side channels`. “Metadata” includes endpoint and account priors, both
directions, handshake, transport feedback, and lifetime, not merely a record
size histogram. The first and third terms are empirical and deployment
dependent; neither is currently bounded for Mirage.

This avoids trying to encode throughput into packet timings or sizes. Generic
black-box steganography through cover-document selection has an exponential
sampling cost in the number of hidden bits per document
([Dedić et al.](https://cs-web.bu.edu/faculty/reyzin/bbstego.html)). The encrypted
body of a live cover workload is the large capacity channel; its metadata is
generated by the real application and carries no intentionally encoded bits.
The ambition is near full *existing body-byte* capacity with no extra
payload-dependent metadata, not a claim that the wire can exceed its budget.

[QUICstep (PETS 2026)](https://gfw.report/publications/pets26a/en/) shows a
different high-throughput route for a *handshake-only* QUIC-SNI censor: establish
through a protected path, then migrate the native QUIC connection. It leaves
the bulk application's visible traffic on the native path, so it does not meet
Mirage's stronger full-flow cover requirement against traffic analysis. It is
a useful threat-specific comparison, not a substitute for the cover-native
branch.

For high throughput, the first candidates are common **reliable** workloads
with real audiences: large object delivery, cloud backup upload, and live
media on an origin that actually serves those workloads. A software download
may offer high downstream rate but little upstream and an unusual long-session
prior. [Low-Latency HLS](https://developer.apple.com/documentation/http-live-streaming/enabling-low-latency-http-live-streaming-hls)
offers partial media segments as short as hundreds of milliseconds, but the
actual request/response and buffer behavior must be captured; fragment size
alone does not prove a smooth service curve. Video-call or cloud-gaming covers
are tempting high-rate choices but their loss tolerance can differ from a
reliable proxy, allowing selective disruption. The first deployment should use
reliable H3 data and test **each direction** against a genuine reference class.
Selective loss or corruption must also be tested against *utility* of the real
cover application; a proxy that fails while the nominal cover still works can
be disrupted even without reliable classification, as shown by
[differential degradation attacks](https://arxiv.org/abs/2409.06247).

## Proposed target: encrypted object sync

The high-throughput research branch uses a cooperating end-to-end encrypted
object-sync service with a real user population. File bodies are
opaque ciphertext in the *application protocol itself*, so arbitrary client
data can form a valid object after the service's normal client-side encryption.
The client and bridge act as ordinary sync devices sharing a scratch account;
objects carry inner Mirage frames, with random encrypted filler when no frames
wait. Payload or filler fills a fixed-length object plaintext **before** the
sync application's normal client-side encryption; its IV, tag, object hash, and
integrity checks are then generated normally. A normal sync client and provider
stack generate requests, H3 frames,
ACKs, retries, metadata operations, and deletion behavior. The provider can
route or store ciphertext without learning Mirage's destinations. It still
sees account identifiers, device links, object metadata, and activity times;
the provider is a trust and correlation point. This is
stronger than pretending a media body is decodable: the cover application
already treats the object bytes as opaque and uses a reliable channel.
Even if a local TLS interceptor decrypts the outer H3 session, the object body
still has valid application-level encryption and integrity structure. The
interceptor can see and classify sync metadata, so this is a narrower benefit
than full traffic indistinguishability.

The controller precommits an upload/download and object-lifetime plan using
only the account's public cover state, measured path capacity, clock, and a
secret seed. It never sees proxy queue depth. User bytes replace filler inside
already planned object chunks; chunk size, count, order, retry policy, and
session lifetime remain cover-driven. The sync service handles flow control and
retransmission through its normal H3 implementation. Map independent Mirage
streams to independent QUIC streams or chunk objects so one lost object does not
block unrelated streams. This needs a new session/carrier interface; the current
`dial -> duplex stream` abstraction would hide QUIC's per-stream progress.

There are two operating regimes. **Opportunistic** embedding uses real user
sync activity and has the strongest cover provenance, but available rate can be
zero and no tunnel latency can be promised. **Precommitted** scratch-object
activity buys predictable service at a real bandwidth and storage cost, but its
account-level behavior is generated cover and can be distinguished if the
population does not naturally contain similar activity. Never describe the
second regime as distribution-preserving until a real-user longitudinal study
supports it. In either regime, the session must keep sending the planned
objects after the proxy queue empties; otherwise demand leaks into timing.

Prepare both filler and any available inner frames in a bounded ring **before**
each cover deadline. The deadline path selects a ready, equal-length chunk and
hands it to the normal application/H3 stack; it never waits for proxy work.
If covert data is late, filler wins and the opportunity is lost. The fill worker
must be isolated so its CPU/cache pressure cannot move the cover producer's
timing under load. This is an implementation hypothesis prompted by Balboa's
measured rewrite delays and Huma's deferred preparation, not a new secrecy
primitive. A CPU-saturated idle/busy wire comparison is required.

The proposal combines an application-valid opaque-object substrate, a
causal firebreak between user
demand and cover scheduling, native H3 streams, Mirage's hybrid authenticated
inner session, and explicit service-curve admission with longitudinal
real-user tests. Balboa, Huma, CloudTransport, Skyhook, and Telepath cover
parts of this design. The combination needs implementation and evidence before
any security claim. A dedicated scratch account with no normal peers
is easy to profile; the desired collateral and anonymity set require a large
cooperating service and matched genuine accounts. Continuous bidirectional
multi-megabit sync may be rare even there. If the real distribution does not
contain the desired rate and duration, the target fails rather than silently
modulating the cover to meet demand.

## Secondary path: origin-integrated H3 slots

Build one opt-in carrier around a **genuine HTTPS/HTTP/3 origin** controlled by
the bridge operator or a cooperating provider. The public origin serves real
content and completes normal TLS/QUIC handshakes with a valid certificate.
Unauthenticated requests continue through the ordinary application. The client
uses the same origin and transport stack, with invitation proof carried inside
encrypted application data. This removes the copied-certificate exception and
the extra cover-hop timing from this carrier. It does require a real domain and
normal hosting; a small dedicated origin can be blocked cheaply. A shared CDN
edge improves collateral resistance only with provider cooperation: a CDN that
terminates TLS, caches public responses, and forwards authorized ones on a
distinct path can create its own timing fingerprint. Both paths must use the
same cache and routing policy, or the origin must terminate TLS directly.

The first transport proof should use a large, reliable object response and a
separately validated upload: their request choreography does not depend on the
downloaded body being decoded. A later high-rate, low-gap candidate is a
*reliable, progressive, live media response* over H3, plus a separately
measured low-rate interactive request lane. A real encoder/producer and H3
server determine chunk production, flow control, concurrency, and connection
lifetime. In an authorized response, Mirage replaces the producer's body bytes
with inner-session ciphertext and cover padding at the same byte length. The
producer continues running while the tunnel is idle.
An unauthorized response sends the actual media bytes. A public session
cookie and an invitation proof should occupy the same ordinary, fixed-length
encrypted request field. The proof is bound to a fresh TLS exporter and epoch,
so replays on another connection fail; an invalid proof follows the normal
public response path. The client chooses requests and session length from a
cover policy fixed before user traffic is observed. A second, independently
validated upload workload is required before
claiming high *upstream* throughput; the low-rate lane cannot carry large
uploads. A media workload is acceptable only if a client can keep its genuine
request behavior while receiving substituted bodies, or if its response is a
single progressive stream whose request behavior does not depend on decoding.
No class is accepted solely because its bitrate looks attractive.

The observable contract is conditional independence:

`P(wire_trace | user_demand, public_network_state, cover_policy)
 = P(wire_trace | public_network_state, cover_policy)`.

Queue depth may choose **which encrypted stream's bytes fill the next existing
slot**, but cannot choose the slot size, emission time, request count, bitrate
ladder, origin, flow count, or session stop time. Session lifetime must be
sampled before user demand arrives and allowed to finish naturally, even if
the last user stream closes. Legitimate congestion feedback
may change the cover producer's rate, because a real H3 session does that too;
the payload queue must have no causal path into that feedback. Compression is
disabled on substituted binary bodies so different payload bytes cannot change
the body's length. The same [HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html)
and [QUIC congestion-control](https://www.rfc-editor.org/rfc/rfc9002.html) stacks
handle authorized and public traffic, including ACKs and loss recovery. The
prototype must verify at an on-path tap that equal application slots really
produce comparable packet traces after segmentation and retransmission.

Keep the current inner authenticated hybrid session; use a
[TLS exporter](https://www.rfc-editor.org/rfc/rfc9266.html) to bind its transcript
to the outer session **when the bridge itself terminates TLS**. Never rely on a
CDN's exporter unless the CDN is an explicit trusted endpoint in the protocol.
Use standard [TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html) and real
protocol headers for the first-byte entropy posture. [ECH](https://www.rfc-editor.org/rfc/rfc9849.html)
helps only where a real shared-hosting deployment and anonymity set exist. The
Wu TCP posture remains a narrow, separately tested fallback.
QUIC Initial protection does not hide its ClientHello from an on-path censor:
the Initial keys are derivable from public values, and deployed censors have
been measured inspecting QUIC SNI
([Zohaib et al., USENIX Security 2025](https://www.usenix.org/system/files/usenixsecurity25-zohaib.pdf)).
Therefore the H3 version needs a genuine, current client handshake and a
plausible SNI/ECH deployment; opaque application data alone cannot repair a
distinguishable Initial.

This design borrows the principle of using a real cover implementation rather
than just copying its syntax. It is a proposed Mirage architecture, not a claim
of priority over prior covert-channel work. Earlier work documented that even
apparently perfect media mimicry can fail when a loss-tolerant cover carries a
loss-intolerant proxy; the reliable H3 workload is chosen to avoid that specific
[channel mismatch](https://doi.org/10.1145/2508859.2516742).

## Implementation sequence and gates

1. **Establish a real baseline.** Capture at least two independent browsers or
   clients against the same public origin from multiple vantage points. Include
   DNS, handshake, H3 settings, both directions, ACKs, retransmissions, flow
   starts/stops, and connection lifetimes. Use held-out days and versions. Reject
   workloads with poor usable service curves or rare, identifying behavior.
2. **Prototype the encrypted sync carrier behind an explicit flag.** Use a
   cooperating service's real H3 client, certificate, account and object
   lifecycle. Precompute valid equal-length objects and keep its producer
   running when the proxy queue is empty. Reuse Mirage's inner session and add
   a compatibility adapter for `ClientTransport`. Expose independent reliable
   QUIC streams or independent sync objects to the session layer; wrapping all
   Mirage streams inside one ordered carrier byte stream would reintroduce
   head-of-line blocking and erase the main under-loss transport gain. Do not
   introduce a new home-grown cipher.
3. **Prove demand independence in code and on the wire.** The cover controller's
   APIs receive cover policy and public network feedback, not stream backlog.
   Compare idle, steady, bursty, and adversarial user-demand traces at an on-path
   packet tap. Run active probes without invitations and with expired or revoked
   invitations; check byte, timing, and lifecycle differences.
4. **Pre-register a matched detection trial.** Compare real public sessions and
   authorized tunnel sessions at matched origin, client, time, RTT, loss, and
   vantage. Freeze the detector before a held-out test split by account, day,
   client version, and origin. Report AUC *and* true-positive rate at a
   pre-registered low false-positive rate **per account**, with confidence
   intervals, at 1, 10, and 100 sessions. Calibrate a sequential detector's
   threshold on complete real account histories, not individual windows.
   Include real-versus-real null controls, unseen content, and active-probe
   follow-up. With zero false positives, about 30,000 independent genuine
   account histories are needed merely to put a one-sided 95% upper bound near
   `10^-4` on the false-positive probability (the binomial rule of three);
   smaller studies must report their weaker bound. AUC near 0.5 is
   insufficient for a long-lived system.
5. **Report performance and cost together.** Compare VLESS + REALITY, existing
   Proteus at equal wire budgets, and the new carrier. Report directional
   goodput, 50th/95th/99th completion times, loss sensitivity, CPU, bytes spent
   while idle, and GB of wire per GB of delivered user data. Under selective
   loss, delay, and throttling, compare both tunnel *and real sync utility* to
   catch differential degradation. A throughput claim
   must state whether it is a higher cover budget, better slot utilization, or
   reduced loss/head-of-line cost.

Until those gates pass, the expected gains are *hypotheses*: stronger ordinary
TLS/probe behavior, less cross-session replay, and better useful throughput for
a validated high-rate cover or under packet loss. The hard constraints remain
the cover byte bill, the need for a genuine public service, and the censor's
ability to block a small dedicated origin.
