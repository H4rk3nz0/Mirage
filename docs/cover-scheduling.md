# Cover selection is a queueing problem

> ##  PROVISIONAL — the numbers in this document are suspect
>
> **The instrument that produced them was defective.** `browser_capture.py` wrote a
> connection's trace only when that connection *closed*, so every connection still
> open when the browser exited was silently absent. Measured after the fix: a 45 s
> video session produced 47 connection files across 22 hosts and **not one of them
> was the video stream** — the short-lived background connections closed and were
> recorded, the long-lived one carrying the payload vanished.
>
> Every capture behind this document was taken with that tap. The four-class table,
> the gap distributions, and the duty-cycle findings are therefore drawn from a
> biased subsample: **short-lived connections only**, in a study whose whole subject
> is long-lived streaming behaviour.
>
> **The latency ranking has already changed.** Browse's worst gap was 122 ms in the
> table below and 4971 ms in the first re-take; both were the capture window rather
> than the page. Trimmed to the burst the page load actually is, it is **95.6 ms** —
> which puts browse **ahead of live audio (338 ms)** and every video class on the
> gap bound, the axis this document argues is the one that matters. The class that
> fails the throughput floor is the class with the best latency, which sharpens the
> workload-split argument rather than softening it.
>
> **What is already known to be wrong.** The segmented-HLS row was re-measured at
> library defaults across two independent players and moved from a 877 ms worst gap
> to **~10 s**, with 5-6 gaps over one second per 50 s where the original reported
> zero. See Limitations. That single row carried the document's headline conclusion.
>
> **What is probably still right.** The *mechanisms* — that cover choice bounds queue
> delay, that the capacity-relevant statistic is a gap bound rather than a rate, a
> CV, or a duty cycle — are arguments from Little's law and do not depend on which
> connections got written. The *rankings and magnitudes* do.
>
> Not retracted, because the reasoning is separable from the numbers and worth
> keeping. Not citable until re-measured with the fixed tap.

*A result from Mirage's cover-class measurements, 2026-08-08. Stated separately
from the implementation because it applies to any traffic-shaped circumvention
system, not just this one.*

## Claim

Systems that shape traffic to imitate a cover class choose that class on
**realism** — how hard the shaped flow is to distinguish from real traffic of
that type. That is necessary and it is not sufficient, because it says nothing
about whether the resulting tunnel is *usable*.

Usability is a queueing property. A shaped tunnel's service rate is fixed by the
cover envelope, not by the link, so the cover's **silence structure** determines
queue delay. We measured four plausible statistics for choosing between cover
classes. Four rank the classes differently and are all wrong. The one that
survives is:

> **The high-quantile inter-record gap of the cover, multiplied by the offered
> rate.**

Not the mean rate, not the record-size variance, not the duty cycle, not the idle
fraction.

## Why the others cannot work

Each rejected statistic is a summary of the cover's **marginal distribution**. The
binding constraint is a property of the **tunnel's queue**.

During a gap the tunnel cannot transmit, but the application keeps offering, so
bytes accumulate at the offered rate. By Little's law the resulting delay is
bounded iff the gap is bounded — *regardless of rate*. A high mean rate does not
rescue a long gap, and a low mean rate is not fatal if gaps are short.

Mean rate and idle fraction are integrals over a distribution whose **tail is the
entire story**. They average away the only part that matters. Record-size variance
is a statement about the marginal that the shaping engine preserves exactly (see
below), so it carries no information about capacity at all.

The precise quantity is a **product of two measured values**, and no single
time constant can express it: a 900 ms gap absorbs ~11 kB at 100 kbps offered and
~340 kB at 3 Mbps.

## Measurements

Firefox 153.0.3, headless, fresh profile, through an HTTP CONNECT proxy that
forwards bytes unchanged (no TLS termination). TLS record framing parsed from the
5-byte header, so sizes are what crossed the wire rather than an artefact of
socket-read coalescing. All four classes captured the same day, same method, same
network position.

| | browse page load | buffered progressive video | live audio stream | segmented adaptive video (HLS) |
|---|---|---|---|---|
| **sustained rate** | **23-141 kbps**(1) | 11.87 Mbps | 139 kbps | 3.51 Mbps |
| burst rate | 2.07 Mbps(1) | 11.87 Mbps | 139 kbps | 3.51 Mbps |
| gap p50 | 0.94 ms | 0.15 ms | 3.0 ms | 0.00 ms |
| gap p99 | 122 ms | 2 ms | 917 ms | 840 ms |
| **gap max** | 122 ms | **15014 ms** | 1633 ms | **877 ms** |
| gaps > 1 s | 0 | yes | 3 | **0** |
| span idle (>0.5 s) | 0% | 94.3% | 8.5% | 80.8% |
| record-size CV^2 | 1.33 | 0.06 | 0.49 | 0.77 |

(1) A page load is a 0.34 s burst, not a stream. Sustained rate is the burst
  amortised over the interval between navigations: 88 kB per load gives ~141 kbps
  at a page every 5 s and ~23 kbps at every 30 s. The burst figure is reported
  separately because quoting it as this class's rate is precisely the error this
  document is about — it is the only row where the two differ by an order of
  magnitude, and it is the class that fails the throughput floor.

^2 **For engines that preserve the size marginal by construction, this row cannot
  apply at all** — it is not a weak proxy but a non-applicable one. Where payload
  displaces padding inside a fixed token (`emitted = real + pad = token`), the
  realised size distribution is identical with and without payload, so it carries
  no information about capacity by construction. Included here to show it also
  ranks the classes backwards even taken at face value.

### The decisive comparison

**Buffered progressive video and segmented adaptive video have similar idle
fractions — 94.3% and 80.8% — and completely different usability.** What separates
them is the gap bound: 15 s against 0.877 s. Any statistic that summarises "how
much of the time is this cover silent" scores them as near-equivalent. They are
not.

### How each proxy fails

- **Record-size CV.** Browse has the *highest* CV (1.33) and the lowest capacity;
  buffered video has the *lowest* (0.06) and 1200x the throughput. Ranks the
  classes backwards. For engines that preserve the size marginal by construction —
  where payload displaces padding within a fixed token — it is not merely a weak
  proxy but carries no capacity information at all.
- **Mean rate.** Ranks buffered video first (11.87 Mbps). That class stalls for
  15 seconds at a time.
- **Duty cycle / idle fraction.** Scores buffered video and segmented video as
  comparable (94% vs 81%). Their worst-case delays differ by 17x.
- **Burst magnitude.** Follows mean rate; same failure.

## Consequence for system design

1. **Select cover by high-quantile gap, then by rate.** A class that fails the
   throughput floor is unusable, but among classes that clear it, the gap bound
   decides. Quantile rather than maximum: the max is one observation and would
   size every buffer for an outlier.
2. **Derive queue parameters from the profile, not from constants.** Buffer sizing,
   admission thresholds and rate limits should be computed as
   `gap_quantile x offered_rate` from the cover actually in use. In Mirage a single
   0.5 s constant was spanning a 120x range of real gap structures (122 ms to
   15 s) and could not have been right for more than one of them.
3. ~~**Segmented adaptive streaming is the strong class**~~ — **WITHDRAWN.** The
   sub-second gap bound was an artifact of a non-default player buffer. At library
   defaults, across two independent players, the gap bound is ~10 s: segment
   cadence is *not* independent of buffer depth, and both players burst then idle
   for a full segment duration. Segmented and buffered video are one class on this
   axis, not two. On current measurements **no class clears both the throughput
   floor and the latency bound**, which is a design constraint rather than a
   selection criterion — see "What 2.0 does not do" in `proteus-2.0.md`.

## Limitations

- **One capture per class**, one network position, one browser build. The gap
  structures are mechanistic rather than incidental, but the specific numbers are
  not population estimates.
- ~~**The HLS capture used `maxBufferLength: 10`**, below library default.~~
  **RE-MEASURED AT DEFAULTS ACROSS TWO PLAYERS — the prediction was wrong.**

  The prediction was that cadence is set by segment duration rather than buffer
  depth, so a deeper buffer should mean more segments in flight rather than longer
  gaps. It does not. Both players, at their own library defaults, on the same
  10 s-segment stream (`tools/cover-sources/hls/capture.sh`):

  | player | default | down-records | median gap | p99 | **max** |
  |---|---|---|---|---|---|
  | hls.js | `maxBufferLength=30` | 7312 | 0.00 ms | 1.3 ms | **10007 ms** |
  | Shaka | `bufferingGoal=10` | 4441 | 0.00 ms | 2.8 ms | **10213 ms** |

  Against 877 ms at `maxBufferLength: 10`, that is an **11x** increase, and the
  named failure mode is the one that happened: **the player switches strategy.**
  Both fetch a burst back-to-back (median gap 0.00 ms) then idle for one full
  segment duration. Fetch-aggressively-then-idle *is* the buffered-video structure
  returning, and it is not a quirk of one implementation — two independent players
  do it.

  The idles are **mid-trace and periodic**, 5-6 per 50 s at ~10 s spacing, not
  truncation artifacts of stopping the capture; each was checked against the end of
  its own trace.

- **`GAP_QUANTILE = 0.99` is the wrong statistic for this class, by 3-4 orders of
  magnitude.** The gap distribution here is *bimodal* — intra-burst gaps near zero,
  inter-segment gaps near 10 s — and the long gaps are only 0.08-0.11% of the
  sample, so p99 sits inside the fast mode and never sees them:

  | | p99 | p99.9 | max | p99 underestimates by |
  |---|---|---|---|---|
  | hls.js | 1.3 ms | 141.6 ms | 10007 ms | **7507x** |
  | Shaka | 2.8 ms | 9654 ms | 10213 ms | **3657x** |

  A receive buffer sized from `cover_gap_secs(0.99)` for segmented video would be
  provisioned for a 1.3 ms stall against a real 10 s one. This is the same defect
  as the fixed 0.5 s constant it replaced — a single summary that cannot span the
  classes it is applied to — and it survived because every class measured until now
  had a unimodal gap distribution. The quantile needs to be per-class, or the
  statistic needs to be the mode-aware one (largest gap, or the upper mode's
  location) rather than a fixed quantile.
- **The CONNECT tap** adds a loopback hop to timings and suppresses HTTP/3.
  Preferable is a raw on-path capture; that requires packet-capture privileges.
- **The driver-cadence defect recurred after being documented here.** The warning
  below was written, and a later browse capture reintroduced exactly the same
  artifact (navigating every ~18 s, producing a 12974 ms worst gap). A warning is
  not a control. `tools/cover-sources/hls/check_driver_artifact.py` now refuses
  such a trace outright. See `docs/measurement-methodology.md` §2.
- **A control was run and mattered.** The first video capture used a page that
  seeked forward every 8 s, producing 8 long gaps in 75 s — one per seek. The
  seek-free re-measure produced exactly one gap, of 15 s, confirming that seeking
  multiplied burst *count* but not gap *structure*. Without that control the
  finding would have been an artefact of the instrument. Any capture that drives a
  player needs the equivalent.

## Relation to prior framing

The circumvention literature treats cover selection as a detectability question:
how realistic is the imitation, and what does a classifier achieve against it.
That is the right question for security and it is silent on throughput and
latency, which is why systems ship with cover classes that are defensible and
unusable, or usable and undefended.

Framing cover scheduling as a queueing problem with a latency bound makes the
trade explicit, and it makes cover selection a *measurable* decision with a
principled statistic rather than a matter of taste.
