# Pre-registered probe re-runs

Written **before** the runs below were executed. The point of this file is that
it cannot be edited afterwards to match whatever the numbers turned out to be —
if a class listed here comes back null, that is a result and it stays recorded.

---

## 2026-08-09 (2) — does setting `http_shadow_target` collapse the partition?

Written before the config was changed.

### Setup

Identical to the first bridge run, with one field added:
`http_shadow_target` pointed at a real plaintext-HTTP host. Same 17 classes,
n=100 per arm, same cover host. Only that field differs.

### Registered prediction

`http11` was the sole locally-handled class (21.3 ms against a 32.0 ms bulk),
giving G = 10.74, p = 0.0002 on the bridge against G = 0.08, p = 1.0 on the real
cover host.

1. **`http11` median moves from 21.3 ms to within 2 ms of the bulk (~32.0 ms).**
2. **G drops to the control's neighbourhood.** Stated numerically in advance:

| outcome | criterion |
|---|---|
| **collapse** | G < 2.0 **and** p > 0.05 |
| **partial fix** | G drops below 10.74 but p <= 0.05 |
| **no fix** | G within noise of 10.74 |

3. **Nothing else regresses**: lifecycle and bytes stay matched on all 17 classes.

### The failure mode, named in advance

**A partial fix is the interesting outcome, not a disappointment.** The
two-cluster fit was dominated by `http11` because it was the only fast class. If
G drops but stays significant, that means a *second* class is answered locally and
was masked by the larger gap — the statistic finds the biggest split, so a smaller
one only becomes visible once the first is removed.

That would make this an iterative instrument: fix the class it names, re-run, see
what surfaces. Worth knowing in advance so a partial collapse is read as "next
leak revealed" rather than "the fix didn't work."

### Committed in advance

- If `http11` does not move, the config field does not do what its own warning
  says, which is a larger finding than the leak.
- If G collapses, the defect is closed **and** the statistic is confirmed to track
  a real mechanism rather than a coincidence of that one run.
- Result recorded below either way.

### RESULT — NO FIX, by the pre-registered criterion

3400 observations, `http_shadow_target = example.com:80`, everything else identical.

| | run 1 (unset) | run 2 (set) | pre-registered criterion |
|---|---|---|---|
| bridge G | 10.74 | **10.90** | "no fix" = within noise of 10.74 |
| bridge p | 0.0002 | 0.0002 | |
| `http11` median | 21.3 ms | **12.9 ms** | predicted ~32.0 ms |
| cover control G | 0.08 | 0.32 (p=1.0) | passes both runs |

`http11` moved, so the field does something — but **further from the bulk, not
toward it**. Prediction 1 fails; prediction 2 lands on "no fix"; prediction 3
holds (lifecycle and bytes still matched on all 17).

### Why, and the design finding

The decoy sits at a **different network distance from the cover host**. Forwarding
HTTP probes to `example.com:80` swaps one anomalous latency (21.3 ms, answered
locally) for another (12.9 ms, one RTT to a different host). The partition
survives because the observable was never "does the endpoint answer plausibly" —
it is **"does it cost what the cover host costs."**

So the warning's remedy is under-specified. "Set `http_shadow_target` to a
plaintext-HTTP decoy" is not sufficient; the decoy has to be **the same host, or
one at the same distance**. Any other choice trades a detectable local answer for
a detectable wrong-distance answer, and the statistic cannot tell the difference
because there is none worth telling.

**Predicted fix, untested:** `http_shadow_target` pointed at the cover host's own
port 80 — here `www.wikipedia.org:80`. Then the HTTP path pays the same RTT as the
TLS path and the partition should collapse to control levels. That is the next
run, and this prediction is on the record before it.

### THIRD RUN — the predicted fix, confirmed

Same 17 classes, n=100, `http_shadow_target = www.wikipedia.org:80`.

| | run 1 (unset) | run 2 (`example.com:80`) | run 3 (cover host) |
|---|---|---|---|
| bridge **G** | 10.74 | 10.90 | **0.23** |
| bridge **p** | 0.0002 | 0.0002 | **1.0000** |
| verdict | leak | no fix | **collapse** |
| cover control G | 0.08 | 0.32 | 0.57 (p=0.9985) |

Collapse criterion was pre-registered as **G < 2.0 and p > 0.05**. Measured
G = 0.23, p = 1.0 — and now *below* the real cover host's own 0.57, which is
where a splice that forwards uniformly should land. Both arms unimodal.

`http11` median, the class that carried the leak:

| run | target | bridge | cover |
|---|---|---|---|
| 1 | unset | 21.3 ms | 33.4 ms |
| 2 | `example.com:80` | 13.5 ms | 32.4 ms |
| 3 | `www.wikipedia.org:80` | **32.0 ms** | **31.9 ms** |

Wrong by -12 ms, wrong by -19 ms, then matched to 0.1 ms. The prediction was
recorded before the run and the direction, the magnitude, and the mechanism all
held.

### The fix opened a byte-level tell — characterised before any further change

`http11` response length, median, all three runs:

| run | `http_shadow_target` | bridge | cover |
|---|---|---|---|
| 1 | unset | 0 | 0 — matched |
| 2 | `example.com:80` | 406 | 0 |
| 3 | cover host `:80` | 173 | 0 |

Run 1 matched on bytes and failed on timing; run 3 inverted it. `www.wikipedia.org:443`
is a TLS port and returns NOTHING to a plaintext `GET`. Forwarding those probes to
`:80` fetches a real 301 body, so the bridge now answers with 173 bytes the host it
claims to be would never send.

The partition statistic cannot see this — it scores timing only. Recorded here
because it is a **regression introduced by the timing fix**, and because a content
tell is cheaper to exploit than the timing one it replaced: 173-vs-0 is deterministic
at n=1 given a single reference fetch of the real host, where the timing partition
needed ~100 probes.

**Hypothesis for the correct fix, recorded before testing:** failed HTTP probes
should be raw-spliced to the cover host on **:443**, not :80. Then the real host
receives plaintext HTTP on a TLS port and does exactly what it does for the cover
arm — returns nothing, FIN, after one RTT — so bytes AND timing match because it
is the genuine host producing both. This contradicts the existing startup warning
("`http_shadow_target` MUST speak plaintext HTTP"), which assumed the goal was a
plausible HTTP answer. The measurement says the goal is to behave like the cover
host's TLS port, and for plaintext input that means answering nothing.

Predicted: `http11` bytes 0 vs 0, timing ~32 ms both arms, partition G < 2.

#### RESULT — confirmed on all three predicted quantities

n=30, `http_shadow_target = www.wikipedia.org:443`:

| | predicted | measured |
|---|---|---|
| `http11` bytes | 0 vs 0 | **0 vs 0** |
| `http11` timing | ~32 ms both | **32.0 vs 31.9 ms** |
| partition G | < 2 | **0.47, p=0.9993** |

Lifecycle `fin` on both arms. The bridge is genuinely forwarding, not failing fast —
a local failure would answer in microseconds, and this pays the full round trip.

`http11` remains SEPARABLE on timing alone (AUC=0.769, gap +0.2 ms), which is a far
weaker tell than the categorical 173-vs-0 it replaced: bytes need no timing
resolution and no repeated sampling.

Shipped as the default: both decoys now take `reality_cover_addr` verbatim, and the
bridge warns on a different host AND on the right host at a different port — the
latter because `<cover>:80` passed every existing check while still leaking, which
is the same "fires on absence, not on wrongness" defect this suite keeps finding.

---

## 2026-08-09 — PRE-REGISTERED: distance-matched re-run

**Question.** Of the 8 classes `compare.py` still separates on the fixed bridge, how
many are properties of the bridge and how many are the placement confound?

The bridge is on loopback; the cover host is ~17.8 ms away. Five classes carry a
CONSTANT offset of that size:

| class | bridge | cover | delta |
|---|---|---|---|
| `connect-close` | 0.1 ms | 17.8 ms | -17.8 |
| `silence` | 2010.0 ms | 2025.9 ms | -16.0 |
| `trunc-1` | 2009.9 ms | 2027.0 ms | -17.0 |
| `trunc-5` | 2009.9 ms | 2026.0 ms | -16.0 |
| `trunc-half` | 2010.0 ms | 2026.8 ms | -16.8 |

`connect-close` names the mechanism: it is pure TCP connect. The timeout classes are
the prober's 2.0 s constant plus that same connect. AUC = 0.000 on all five is the
signature of a constant shift, not of a behaviour.

**Predictions, before the run:**

1. All five collapse to `ok` when both arms sit at equal distance. If any survives,
   it is a real bridge property that happened to be the same magnitude as the
   confound — which would be worth knowing and is not what I expect.
2. `http11` stays SEPARABLE on bytes (173 vs 0). Distance matching cannot fix a
   content difference.
3. `appdata-first` and `http2-preface` are the genuinely uncertain pair: deltas of
   +0.0 and +0.1 ms with AUC ~= 0.63, p* ~= 0.03. Too small to be the confound and
   too small to be an extra hop. I expect **at most one** survives; if both do, the
   residual is real and sub-millisecond, which points at local processing cost
   rather than routing.

**Failure mode, pre-registered:** if the distance-matched run comes back with MORE
separable classes than 8, the local cover is not a valid stand-in for the remote one
and the run measures the stand-in, not the bridge. That result invalidates the run
rather than reporting a regression.

### RESULT — the run was INVALID as scoped, per the pre-registered failure mode

13 of 17 classes separated, up from 8. The pre-registration said that outcome
invalidates the run rather than reporting a regression, and it does. The proof is
in the lifecycle column: `fin vs rst` on `random-16`, `random-512`, `random-4096`
and `http2-preface`. The local Python TLS server sends RST on handshake failure
where the real host sends FIN. And at loopback resolution AUC >= 0.92 came with
gaps of ±0.0-0.1 ms — any two distinct programs separate at that resolution.

**Distance matching via a stand-in cover is not possible.** It matches distance
and destroys server identity in the same step, and the second effect dominates.

**What was still valid.** The four timeout-dominated classes are insensitive to
which server sits behind the port, so the stand-in can validly speak to them:

| class | remote (run 3) | matched | |
|---|---|---|---|
| `silence` | SEPARABLE, -16.0 ms | ok, AUC 0.495 | collapsed |
| `trunc-1` | SEPARABLE, -17.0 ms | ok, AUC 0.449 | collapsed |
| `trunc-5` | SEPARABLE, -16.0 ms | ok, AUC 0.552 | collapsed |
| `trunc-half` | SEPARABLE, -16.8 ms | ok, AUC 0.435 | collapsed |

Prediction 1 confirmed for those four: pure placement confound.

### The correction that is NOT valid, and the earlier conclusion it overturns

The next obvious move — subtract each arm's own TCP setup, since distance is an
additive per-arm constant — is wrong for a splice, by 17.8 ms. Decomposed:

    cover  : connect 17.84 + post-connect 14.11 = 31.95 ms
    bridge : connect  0.09 + post-connect 31.89 = 31.98 ms

The bridge's POST-CONNECT cost equals the cover's ENTIRE cost, connect included,
to within **0.06 ms**. A splice does not shift cost by a constant; it RELOCATES
cost from the connect phase into the response phase, because its own TCP setup to
the cover happens after the prober's connect has completed. Subtracting per-arm
connect flagged 14 of 17 classes at AUC=1.000, every one an artifact.

**This overturns the first bridge run's conclusion.** That 32.0-vs-32.0 total was
recorded as "the splice forwards and pays the same round trip, so it is
timing-indistinguishable." It is not. The totals matched because the bridge's own
connect was FREE on loopback while it paid the cover's full cost afterwards — two
errors of the same size cancelling. The correct correction ADDS the missing
distance to the bridge (`compare.py --deploy-at-cover-distance`):

| | measured on loopback | modelled at the cover's distance |
|---|---|---|
| separable classes | 8 of 17 | **15 of 17** |
| typical gap | +0.0 to +0.2 ms | **+17.8 ms** |
| AUC | ~0.6 | **1.000** |
| probes to tell | 8-148 | **1** |

### The deployment rule this implies — stated with its assumption

The model assumes prober→bridge grows to the cover's distance while
bridge→cover stays as measured. Under that assumption the splice is separable at
N=1. But the decomposition shows what the tell is actually proportional to: it is
the **bridge<->cover RTT**, not the prober<->bridge RTT. A bridge co-located with its
cover host pays ~0 for the splice and totals 17.8 + 14.1 ~= 31.9 ms against the
genuine host's 31.95 — indistinguishable. A bridge far from its cover host is
separable on a single probe.

So cover-host selection is a latency decision, not only a plausibility one:
**pick a cover host that is network-close to the bridge.** That is checkable at
startup (measure RTT to `reality_cover_addr` and warn when it is large relative
to the cover's own response time) and is the next thing worth building. It is NOT
yet implemented, and the N=1 figure above is a model, not a measurement — the
honest test is a bridge actually deployed at distance from its prober.

---

### What is NOT fixed

`compare.py` still separates **9 of 17 classes** cross-arm on this run. The
partition statistic and the cross-arm comparator answer different questions:

- **partition** — "does this endpoint answer some classes locally?" Now: no.
- **compare** — "does this endpoint respond identically to the real host?" Still: no.

Closing the partition removes the tell that needs no reference arm — the one a
prober can use knowing nothing but the bridge's address. The residual 9 are
byte-level and lifecycle differences that require a synchronised capture of the
genuine host to exploit. Strictly weaker, not gone. Both numbers belong in any
honest statement of where this stands.

### What this says about the config field

`http_shadow_target` unset produces a warning naming a prober-exploitable
inconsistency. Set carelessly, it produces a *different* prober-exploitable
inconsistency and **no warning at all** — the warning fires on absence, not on
wrongness. Same shape as `checked_days` measuring age where correctness was
needed.

It should either default to the cover host, or refuse a value whose distance from
the prober differs materially from the cover host's — the generic-fallback and
tiled-schedule treatment, now justified by measurement rather than by analogy.

---

## 2026-08-09 — FIRST RUN AGAINST A REAL BRIDGE

Written before the bridge was started. The suite has been validated against a
null at two sample sizes and catches three synthetic splice mitigations; it has
never been pointed at Mirage.

### Setup

A real `mirage-bridge` with `reality_cover_addr = www.wikipedia.org:443`, probed
as the `bridge` arm; `www.wikipedia.org:443` probed as the `cover` arm.
Interleaved ABAB in-session, 17 classes, **n = 100 per arm**, Bonferroni across
classes.

### Registered prediction

The structural argument says a splice cannot answer before it has been to the
real host and back, so:

1. **The floor / support tests FIRE.** The gap should be positive and roughly one
   RTT from this machine to the cover host — order 10-30 ms.
2. **Timing AUC does NOT fire**, or fires far more weakly. AUC is a rank statistic
   and both arms carry the network path; the discriminator is support, not centre.
3. **Lifecycle matches** — the RST-vs-FIN oracle was fixed, and if it regressed
   that is a separate and larger finding.

Prediction 1 is the one that matters. It is the claim the entire probe workstream
was built to test.

### Committed in advance

- **If the floor/support tests do not fire**, the structural claim is wrong for
  this architecture and gets recorded as such. Not "underpowered", not "needs the
  cover-host-state variants first" — wrong, unless n is genuinely inadequate,
  which at n=100 it is not.
- **If AUC fires and the floor does not**, the mechanism is not what I claimed and
  the explanation needs rebuilding from the data.
- **A compelling mechanism is not evidence.** `record-badmac` had the strongest
  prior in the suite and reversed from 0.746 to 0.445 at n=100. The floor result
  may do the same. It is a hypothesis until this run.
- Result recorded below either way, including a null.

### RESULT — prediction falsified, by a flaw in my own setup

3400 observations, n=100 per arm, both arms healthy (1700/1700).

**Prediction 1 (floor fires, gap ~ +one RTT): WRONG, and wrong in sign.** The gap
is **negative** across every class that showed one: -15.8, -10.6, -16.8, -16.2,
-20.6, -17.1 ms. The bridge answers *faster* than the cover host.

**Cause: I put the bridge on loopback** (`127.0.0.1:19443`) and the cover host is
~15-30 ms away. A local endpoint against a remote one separates on RTT alone, and
that has nothing to do with splicing. This is the **symmetric-reference** error —
the same defect as comparing degraded-Mirage against healthy-reference — and the
run cannot speak to the structural claim either way.

**The structural claim is NOT falsified. It is untested.** Recording it as
falsified would be as wrong as recording it as confirmed: the experiment could not
have detected it, because a confound larger than the effect ran in the opposite
direction.

**Prediction 2 (AUC does not fire): WRONG.** AUC = 0.000 on six classes — perfect
separation, driven entirely by the same RTT confound.

**Prediction 3 (lifecycle matches): CORRECT, and it is the one real result here.**
Every class matched on lifecycle (fin/fin, timeout/timeout) and on response bytes
(7 vs 7, 0 vs 0). **The RST-vs-FIN oracle has not regressed.** That is a genuine
pass and it is independent of the RTT confound, because lifecycle is categorical.

### CORRECTION — the confound does not cover the whole table

Splitting the classes by median lifetime shows two distinct populations, and only
one is confounded:

| probe | bridge | cover | reading |
|---|---|---|---|
| `hello-plain` | 32.0 ms | 32.0 ms | **forwards** — inherits cover RTT |
| `hello-alpn-h2` | 32.0 ms | 32.0 ms | **forwards** |
| `record-badmac` | 32.2 ms | 32.4 ms | **forwards** |
| `appdata-first` | 32.0 ms | 31.9 ms | **forwards** |
| `http11` | 21.3 ms | 33.4 ms | handled locally |
| `connect-close` | 0.1 ms | 17.9 ms | handled locally |
| `trunc-5` | 2010.1 ms | 2026.0 ms | handled locally |
| `silence` | 2010.1 ms | 2026.3 ms | handled locally |

**The structural claim FAILS to fire where it was predicted to, for a good
reason.** On every TLS-shaped probe the splice genuinely forwards, so it inherits
the real host's RTT and is timing-**indistinguishable** — 32.0 vs 32.0 ms, min
31.43 vs 31.39 ms. There is no RTT floor to detect because the bridge pays the
same RTT the real host does. That is the architecture working, and it is a genuine
pass, not an artifact.

**The separations are all on classes the splice does NOT forward**, and their
*magnitudes* are confounded by loopback placement (a local bridge closes in
0.1 ms; a remote one could not).

### The finding that survives the confound

**Mirage treats probe classes differently: TLS-shaped input is forwarded, other
input is handled locally.** That selectivity is observable independent of any RTT
magnitude — a prober who sends a valid ClientHello *and* an HTTP/1.1 request to the
same endpoint sees one answer at cover-host latency and the other not, and the real
host answers both at cover-host latency.

This is a *relative* measurement — bridge-vs-bridge across probe classes, then
compared to cover-vs-cover across the same classes — so it is immune to where the
bridge sits. It is also not what either the structural prediction or the floor
statistic was looking for: the tell is **which probes get forwarded**, not how fast
any one of them is answered.

That is the result of this run, and no synthetic could have produced it, because
synthetics have no forwarding path.

### FORMALISED — the partition statistic, and what it took to get right

`partition.py`. Per-class median latencies within ONE arm; largest gap over mean
gap; null by simulating from a lognormal matched to the observed medians. No
reference arm, so a censor can run it against a suspect endpoint alone.

Three corrections were needed, each caught by scoring the **real cover host as a
control** — a statistic that needs no reference still benefits from one while it
is being validated:

1. **Timed-out classes.** Their value is the prober's own timeout constant, so the
   largest gap fell between "timed out" and "responded". Fired on the real host at
   p=0.0007. Excluded.
2. **`connect-close`.** Never sends data, so it measures TCP setup rather than
   response latency and sits apart on every endpoint. Fired on the real host at
   p=0.0002. Excluded — not a latency class.
3. **Direction.** An unsigned largest-gap statistic cannot tell "answered locally"
   from "the server worked harder". The real host answers `http11` in 33.4 ms
   against 32.0 ms for everything else, because serving HTTP costs more than
   rejecting a malformed record. Only a gap BELOW the bulk indicates local
   handling. Made directional.

**Final result:**

| arm | G | p | reading |
|---|---|---|---|
| bridge | **10.74** | **0.0002** | two clusters — `http11` local at 21.3 ms vs 32.0 ms |
| cover | 0.08 | 1.0000 | one cluster — uniform cost |

**Mirage forwards eleven of twelve scored probe classes** — including
`record-badmac`, `appdata-first`, `random-*` and `http2-preface`, all at the cover
host's exact latency. **Only plain HTTP/1.1 is short-circuited.** The splice is
nearly complete; one class leaks.

### The bridge predicted its own leak

At startup, unprompted, the probed bridge logged:

> `shadow_target is set but http_shadow_target is not: opaque (Unknown) probes are
> shadow-forwarded while failed WebSocket/meek/DoH probes are dropped +
> probe-scored - an inconsistency an active prober can exploit. Set
> http_shadow_target to a plaintext-HTTP decoy for consistent active-probe
> resistance across all transports.`

`http_shadow_target` was not set. The probe suite independently measured exactly
the defect the codebase already warns about, from the outside, with no knowledge
of the configuration.

That is mutual validation: the warning is real rather than defensive boilerplate,
and the suite detects a genuine defect rather than an artifact. **The fix is a
config field, not code** — and the next run should set it and confirm the
partition collapses.

### The one residual worth following

`appdata-first`: gap **+0.3 ms** and AUC 0.702, p\*=0.000. Positive gap despite the
bridge being local — i.e. slower than its own baseline predicts. That is the shape
a forwarding hop would produce, showing through against the confound rather than
because of it. `random-512` and `random-4096` are similar but weaker (+0.1 ms).

Not a finding. A lead, and by this file's own standing rule a lead is a power
problem until it survives a properly-controlled run.

### Corrected design for the re-run

The bridge and the cover host must be at **comparable network distance from the
prober**. Options, cheapest first:

1. Probe a bridge on a remote host, cover host as-is.
2. Keep the bridge local and use a **local** cover host (a real TLS server on
   loopback) as its `reality_cover_addr`, so both arms are loopback.

Option 2 is available immediately and removes the confound entirely: the splice's
extra hop is then loopback-to-loopback, so any remaining gap is processing rather
than propagation — a *weaker* test of the structural claim, but an unconfounded
one.

### What this run cost and bought

~35 minutes. It bought a confirmed non-regression on the lifecycle oracle, one
lead, and the discovery that the harness needs distance-matched arms — which the
synthetic work could never have surfaced, because synthetics have no network.

---

## 2026-08-08 — three elevated classes at n=100

### Why these three, and why pre-registering matters

A null control (both arms pointed at `www.wikipedia.org:443`, n=22 per arm,
17 classes, Bonferroni-corrected) returned **no separable classes**. Three sat
visibly above the rest without reaching corrected significance:

| class | AUC | p (Bonferroni x17) |
|---|---|---|
| `record-badmac` | 0.746 | 0.089 |
| `hello-plain` | 0.723 | 0.191 |
| `random-512` | 0.700 | 0.388 |

Raising n across all 17 classes pays the multiplicity penalty again. Re-running
**three pre-registered classes** does not, because the hypothesis is fixed before
the data exists. That only holds if the selection is recorded first — hence this
file.

`record-badmac` is additionally the strongest *a priori* candidate in the whole
suite: a well-formed TLS record with a garbage payload is the case where a real
server and a raw splice most plausibly diverge in **when they give up**. A real
stack decrypts, fails authentication, and alerts; a splice forwards bytes to an
upstream that does its own thing on its own schedule. If any class in this suite
carries a real oracle, mechanism says it is this one.

### Registered hypothesis

**H0:** each class is indistinguishable between the two arms.

**Test:** Mann-Whitney AUC on connection-lifetime, two-sided, **n = 100 per arm**,
Bonferroni corrected across **3** classes (not 17 — these are pre-registered).

**Reject H0 at:** corrected p < 0.05.

**This run is still a NULL.** Both arms remain `www.wikipedia.org:443`. Rejecting
H0 here would mean the *tool* is still finding structure that cannot exist, not
that a bridge is separable. A clean result licenses the tool at n=100; a dirty one
sends it back for repair before any bridge is measured.

### Committed in advance

- If all three come back null, the suite is licensed for its first real run.
- If any rejects, **the tool is broken**, not the target — and the specific class
  is quarantined until the cause is found. It will not be reported as a finding
  against any system.
- Result recorded below either way, including a null.

### RESULT — null on all three, tool licensed

600 observations, n=100 per arm, both arms `www.wikipedia.org:443`.

| class | AUC @ n=22 | **AUC @ n=100** | p (Bonferroni x3) | verdict |
|---|---|---|---|---|
| `record-badmac` | 0.746 | **0.445** | 0.528 | null |
| `hello-plain` | 0.723 | **0.480** | 1.000 | null |
| `random-512` | 0.700 | **0.489** | 1.000 | null |

All three collapsed to ~0.5. Every one was small-sample noise, including the
class with the strongest mechanistic argument behind it — `record-badmac` moved
0.746 → 0.445, i.e. it did not merely fail to reach significance, it reversed
direction, which is what noise does and a real effect does not.

**Both prior commitments discharged:**

- All three null ⇒ **the suite is licensed for its first real run** at n>=100
  with these thresholds.
- Nothing quarantined; no class was reported as a finding against any system.

**What this cost, and what it bought.** Three classes at n=100 took ~4 minutes.
Had they been carried forward from the n=22 run as "elevated, worth watching",
they would have been three standing suspicions about a system that has not been
measured yet — and the temptation to read a later bridge run as confirming them
would have been considerable. Pre-registering and killing them is cheaper than
carrying them.

**Standing rule from this exercise:** an elevated-but-not-significant class in a
*null* is **not weak evidence of a defect. It is evidence of insufficient n, and
nothing else.** There is no partial credit and no such thing as a soft lead.
Resolve it in the null — raise n until it is significant or dead — before it can
be mistaken for a finding against a real target.

`record-badmac` is the teaching case: strongest mechanistic argument in the suite,
the one worth betting on, and it went 0.746 → **0.445**. A real effect sharpens
with n; noise wanders. The plausible mechanism is precisely what makes an elevated
number dangerous, because it is what turns a random draw into a standing
suspicion.
