# Proteus 2.0

What the traffic shaper is, what each mechanism does, and the measurement that
justifies it. Written to be read without knowing how it was arrived at; the
history and the failure modes behind it are in `measurement-methodology.md`.

---

## The design in one paragraph

Proteus replays real captured traffic rather than generating plausible-looking
traffic. A capture supplies the record sizes, the inter-record gaps, how many
concurrent connections to open, and when to open them. Payload is displaced into
padding inside a record whose size was already fixed by the capture, so the wire is
identical whether the session is idle or saturated. Where one cover class cannot
serve every kind of traffic, carriers of different classes run side by side.

---

## The governing rule

> **Demand must not have a path into any scheduling decision, and the enforcement is
> at the signature rather than in a test.**

Five scheduling decisions could each have leaked payload information. None is
guarded by a check; in each case the argument through which demand could arrive was
removed:

| decision | enforcement |
|---|---|
| how many carriers | `flow_starts.len()` — the captured flow count. No count parameter exists. |
| when a carrier opens | recorded arrival offsets. No queue input. |
| what a carrier emits, and when | `carrier_schedules(&self)` takes no other argument. |
| whether an emission is due | `next_due()` returns the instant. There is no `is_due(now)` to read a clock with. |
| a stream's class | `ClassifiedStream::accept()` takes a port and a hint, never a byte count. |

The last is the sharpest form: adding a byte count to `accept()` breaks every call
site, which is a louder alarm than any test or review comment. Where the reach is
absent rather than guarded, reintroducing it is noisy.

This generalises the earlier fix that disabled demand-following record steering,
which had been measured at 0.699 separability against a 0.544 control.

---

## Mechanisms

### Replay of a captured envelope

**What it does.** Record sizes and inter-record gaps come from a packet capture of a
real browser, not from a generative model.

**Why.** A generated "video-like" pattern is always subtly wrong and subtly-wrong is
detectable. A recorded envelope carries no invented structure to be wrong about.

**Measurement.** The size marginal is preserved by construction —
`emitted = real + pad = token` — so the realised size distribution is identical with
and without payload.

### Displacement, not modulation

**What it does.** Payload fills the space a record was already going to occupy.
`available` selects only the real/pad split; it cannot move a record's size or its
instant.

**Why.** Rate that tracks demand is the signal Proteus exists to remove.

**Measurement.** Asserted by test under idle, saturated, and varying payload, with
emission instants compared bit-identically. Mutation-verified: letting payload change
the observable size is caught.

### Multi-carrier replay

**What it does.** One emitter per captured flow. The carrier count, the order records
interleave across carriers, and when each carrier opens all come from the capture.

**Why.** A capture of a real page contains several concurrent connections whose
activity alternates. Replaying them serially produces a shape real traffic never
makes. Opening all carriers at t=0 leaks nothing but is still an arrival pattern the
cover class does not produce; opening one when the queue deepens leaks demand.

**Measurement.** The parser was discarding both: it sorted by `(flow, time)` and
rebased each flow to start after the previous ended. The capture tap was worse — it
timed every connection from its own start, so two traces were mutually unplaceable
and the interleaving was destroyed before parsing.

### Heterogeneous carriers

**What it does.** Interactive streams ride browse-class carriers; bulk streams ride
video-class carriers. Class is fixed when a stream is accepted and cannot change.

**Why.** No single cover class clears both the throughput floor and the latency
bound. Nothing requires all carriers to wear the same profile, and a host running a
browser and a video player at once is ordinary traffic — so the composite is *more*
plausible cover than either alone.

**Measurement.** See the cover-class table below.

**Unknown ports default to Interactive**, deliberately: misrouting bulk onto
browse-class costs throughput, misrouting interactive onto video-class costs a
ten-second stall.

### Deficit permutation — implemented, OFF

**What it does.** Reorders records within a window while tracking a deficit against
the trace's size histogram, so the realised marginal converges to the trace's exactly.
Recovers envelope lost to `min(demand, token)` mismatch.

**Why it is off.** It makes record *order* depend on payload — trading marginal
divergence for ordering divergence. That is the mechanism, not a defect, but it
contradicts the governing rule above, so it is opt-in and disabled.

**Gate.** Enabling requires the `W` sweep against DeltaACF with a real-traffic baseline:
DeltaACF inside the natural between-trace spread **and** separability at or below the
estimator floor at adequate n. Both, not either. Not run.

The deficit cap is two-sided. A one-sided cap was shipped and wrong: every pick
advances the total, raising what every other size is due, so choosing large records
repeatedly pushes small ones into deficit without tripping an upward-only guard.

---

## Load-bearing measurements

### 1. The capacity statistic is the gap bound

> **High-quantile inter-record gap x offered rate.**

Not mean rate, not record-size CV, not duty cycle, not idle fraction. All four rank
the cover classes differently and all four are wrong.

**Why.** Each rejected proxy summarises the cover's *marginal distribution*. The
binding constraint is a property of the *tunnel's queue*: during a gap the tunnel
cannot transmit while the application keeps offering, so by Little's law delay is
bounded iff the gap is bounded — regardless of rate. Mean rate and idle fraction are
integrals over a distribution whose tail is the entire story.

The quantity is a **product of two measured values** and no single time constant can
express it: a 900 ms gap absorbs ~11 kB at 100 kbps offered and ~340 kB at 3 Mbps.

**PROVISIONAL — cover-class numbers.** A 60-cell matrix (5 reps, 2 players, 3 buffer
settings) gives worst-case gap by class: browse **95.6 ms**, live audio **338.8 ms**,
segmented video **~10 s**. The gap bound for segmented video is set by segment
duration and is unchanged by player or buffer depth across six cells. Earlier figures
in `cover-scheduling.md` were taken with a defective tap and are marked provisional
pending re-take; the Little's law argument does not depend on them.

**`GAP_QUANTILE = 0.99` is wrong for segmented video** by 3-4 orders of magnitude —
its gap distribution is bimodal and p99 sits inside the fast mode. Documented at the
constant. Not fixed.

### 2. Cover-host choice is a latency decision

A splice does not add cost, it **relocates** cost out of the connect phase into the
response phase, because its own setup to the cover happens after the prober's connect
has returned:

    cover host : connect 17.84 + post-connect 14.11 = 31.95 ms
    bridge     : connect  0.09 + post-connect 31.89 = 31.98 ms

The bridge's post-connect cost equals the cover's *entire* cost to within 0.06 ms.
The totals matched only because the bridge's own connect was free on loopback — two
errors of equal size cancelling. Modelled at the cover's distance, the same run
separates 15 of 17 probe classes at N=1.

**Consequence.** The tell scales with **bridge<->cover RTT**, not prober<->bridge RTT. A
bridge co-located with its cover host is far harder to separate on timing. Pick a
cover host that is network-close to the bridge. Not enforced at startup.

### 3. Probe partition, and what the fix does not cover

An endpoint that answers some probe classes locally and forwards the rest can be split
on that alone, with **no reference capture of the host it fronts**. Both probe decoys
now default to `reality_cover_addr` verbatim:

| `http_shadow_target` | `http11` bytes | gap statistic G |
|---|---|---|
| unset | 0 vs 0 | 10.74 |
| a plausible other host `:80` | 406 vs 0 | 10.90 |
| cover host `:80` | 173 vs 0 | 0.23 |
| **`reality_cover_addr`** | **0 vs 0** | **0.47** (p=1.0) |

Row 2 is why "point it at a plaintext-HTTP server" is not the fix — the observable is
cost, not content. Row 3 is why the port matters: a TLS port answers a plaintext GET
with silence, its `:80` with a 301, so fixing the timing opened a byte channel.
**Forward, do not emulate.**

**Residual.** The cross-arm comparator still separates classes on byte-level and
lifecycle differences. Closing the partition removes the tell available to a prober
who knows only the bridge's address; it does not make the bridge indistinguishable
from the host it fronts. Strictly weaker, not gone.

### 4. M is a property of the cover host's role

Every site's **document** origin opens exactly one connection — they serve HTTP/2, and
h2 multiplexes an origin onto one connection by design. Concurrency lives on **asset**
origins. From one capture: `en.wikipedia.org` 1, `wikimedia.org` 6,
`upload.wikimedia.org` 5.

Two consequences:

- **A bridge fronting a document origin justifies M=1.** Multi-carrier replay against
  it would be a distinguisher, not cover. That makes heterogeneous carriers the *only*
  remaining throughput lever there, so the design leans harder on cover class per
  carrier rather than on carrier count.
- **Front an asset/CDN origin.** The capture justifies M=5-6, and CDN endpoints see
  enormous connection volume from diverse clients, which is where you want to hide.

### 5. Measurement failure modes

Full write-up in `measurement-methodology.md`. The two that generalise furthest:

**A self-consistent test cannot detect that the reasoning is wrong.** If a test's
expected value comes from the same reasoning as the code, it detects drift from that
reasoning and never that the reasoning was wrong. The pinned Firefox JA3 was a strict
subset of the real browser — 12 of 17 extensions — and passed. Only a capture revealed
it. Applies to every golden-output test anywhere.

**Confirm the precondition held before reading the result.** A green result from a test
whose condition never existed is not evidence. Four domains: a stale process holding a
port, a config field recognised but not applied, a capture that verified playback but
not recording, and a mutation that never compiled or never executed.

*Corollary, because it inverts:* in mutation testing a false green **deletes a working
assertion** rather than shipping a bad result. Before trusting a mutation's verdict,
confirm the mutated line executed.

---

## What 2.0 does not do

Measured against the objectives 2.0 was planned against. This section exists because
the plan file that held them has been removed, and a shipped release should carry its
own shortfalls rather than leave them in a document nobody reads next.

### Structural gaps — the ones that bound what 2.0 can claim

**Constant rate. The square-root law is not addressed.** Under a divergence budget,
covert capacity grows as `sqrt(2*epsilon*N / I)` while a constant-rate channel accumulates
evidence *linearly*. A constant-rate covert channel is therefore asymptotically
detectable by construction, and the correct rate law is `r(t) ∝ 1/sqrt(I*t)` —
sessions should get quieter as they age. 2.0 replays at the capture's rate for as long
as the session lasts. **This is a structural property, not a tuning issue**: no amount
of envelope fidelity fixes it, and it caps how long a single session should be trusted
to run. Nothing in 2.0 measures or bounds that horizon.

**Repetition is unsolved, and cannot be solved by collecting more traces.** With `n`
traces and `m` observed flows, collision probability is `1 - exp(-m^2/2n)`; holding it
under delta requires `n >~ m^2/2delta`, which at m=10³ and delta=0.01 is **5x10⁷ traces**. No
achievable library reaches that. The intended fix is to make the replay distribution
*continuous* by kernel-smoothing the empirical measure with the cover's own measured
jitter — replaying structure verbatim while smoothing only continuous parameters. 2.0
does verbatim replay with **no smoothing at all**, so a sufficiently patient observer
sees the same trace twice.

**The intrinsic dimension of the trace manifold was never estimated, and it decides
whether smoothing can work at all.** The smoothing bandwidth is bounded above by
natural jitter and below by pool sparsity (`h >~ n^(-1/k)*diam`). The dimension `k`
dominates that lower bound, not the pool size `n`: at k=10, growing the pool
1000-fold shrinks inter-atom spacing by ~2x. If `k` is high the interval is empty and
smoothed replay cannot work for any achievable library — which would mean abandoning
this architecture for a structural generative model. **That measurement has not been
made, so it is not known whether the repetition fix above is even available.**

**The model-error floor `D0` is unbounded.** Total evidence is `N*(D0 + D_payload)`
where `D0` is irreducible mismatch — recorder artefacts, staleness, protocol-version
differences. `D0` does not shrink with pool size, smoothing, or rate reduction, and
once it dominates, detection time is set by model error alone and the entire shaping
apparatus is irrelevant. 2.0 improves several contributors to `D0` (real browser
captures, a capture-derived fingerprint, joint direction sourcing) without ever
measuring the floor, so there is no evidence about whether shaping is the binding
constraint.

### Workstream status against the plan

| | intent | status |
|---|---|---|
| **W0** | joint direction sourcing | **partial** — the joint timeline carries both directions and the tiled-schedule refusal ships; `profile_digest` still does not compare directions |
| **W1** | cover-class capacity survey | **partial** — the gap/rate axis is measured (60-cell matrix); *displacement slack* and the *within-class jitter kernel* (>=50 captures of one page) are not |
| **W2** | joint (up, down) divergence | **not done** — no classifier has been run on the joint distribution |
| **W3** | real-traffic reference class | **not done** — the gate every number was supposed to pass |
| **W4** | smoothed, partitioned pool | **not done** — see the repetition and dimension gaps above |
| **W5** | divergence token bucket | **not done** — the budget is still implicit |
| **W6** | multi-carrier allocation | **done** — capture-derived carriers, heterogeneous classes, live-path join |
| **W7** | WebRTC rate-modulation channel | **not done** — needs a second peer; the second embedding channel is unexplored |
| **W8** | throughput and stability wins | **partial** — profile-derived buffer sizing and DRR ship; other items untouched |
| **W9** | deficit permutation | **implemented, off** — the `W`/DeltaACF gate has not been run |
| **W-new** | four-class re-take with the fixed tap | **in progress** |

### What this means for the claim

2.0 is a **fidelity and integrity release**, not a capacity or unlinkability release.
What it improves is how faithfully a single session resembles its capture, and how much
of that claim is actually verified rather than asserted. What it does not improve is
how many sessions can share a library before repeating, how long one session can safely
run, or whether the shaping matters relative to model error.

Read the security claim accordingly: **strong on per-session envelope fidelity and on
active-probe resistance; unquantified on long-run and cross-session linkability.**

---

## State of play

**Shipped and verified.** Replay envelope; displacement; multi-carrier replay with
capture-derived M, ramp and interleaving; heterogeneous carriers with accept-time
classification; the live-path join (`ScheduleStream::for_carrier`,
`PacedChannel::spawn_for_carrier`); probe decoy defaults; the Firefox ClientHello
template, JA3-matched to a real capture field for field. Behavioural claims are
mutation-verified.

**Provisional.** `cover-scheduling.md`'s numbers, pending the re-take. The cover-class
table above, at n=5 from one network position.

**Implemented but off.** Deficit permutation, pending the `W` sweep.

**Known wrong, not fixed.** `GAP_QUANTILE` for bimodal classes, documented at the
constant. Cover-host RTT proximity is a recommendation with no startup check.
`CYCLE_GAP = 0.05` in `refill_replay` is a hand-picked timing value inserted at the
replay wrap — the same defect class as the inter-flow gap removed from `from_csv`
this release, flagged at the site and tracked for 2.1 because changing replay timing
needs its own measurement.

**Blocked, and on what.**

| item | blocked on |
|---|---|
| probe suite N=1 figures | a bridge deployed at real network distance — an address |
| `W` sweep / permuter | the DeltaACF baseline from the running matrix |
| Chrome ClientHello template | a Chrome packet capture; only Firefox is installed |
| trace library at scale | a re-take with the fixed tap (`started_at_s`) |
| carrier-count sweep | not driveable through the CONNECT tap; needs a raw capture |

**Next session starts here**, not from archaeology.
