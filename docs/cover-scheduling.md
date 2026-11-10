# Cover selection is a queueing problem

> **Measurement status: provisional.** The original `browser_capture.py` wrote
> traces only when connections closed. Long-lived streams still open at browser
> shutdown were omitted. In one 45-second retake, none of 47 saved connection
> files contained the video stream. The four-class table, gap distributions,
> and duty-cycle findings below are therefore biased toward short connections.
>
> Later retakes changed the ranking: a page-load browse burst had a 95.6 ms
> worst gap after trimming the capture window, while segmented HLS had roughly
> 10-second gaps across two players rather than the reported 877 ms. The
> original queueing argument also overstated what gap percentiles imply about
> delay. Treat the old tables as a record of the experiment, not validated
> cover-selection evidence. Re-measurement with the fixed tap is pending.

The original cover-class measurements were taken on 8 August 2026.

## Corrected claim

Systems that shape traffic to imitate a cover class choose that class on
**realism** — how hard the shaped flow is to distinguish from real traffic of
that type. That is necessary and it is not sufficient, because it says nothing
about whether the resulting tunnel is *usable*.

Usability is a queueing property. Let `A(t)` be cumulative admitted payload bytes
and `S(t)` the cumulative usable payload capacity of scheduled cover slots. In a
fluid queue, backlog at time `t` is the largest positive deficit over preceding
windows:

`Q(t) = max(0, sup_{0 <= u <= t} [A(t)-A(u) - (S(t)-S(u))])`.

For a constant offered rate `a`, measure `sup_{u < t} [a(t-u) -
(S(t)-S(u))]` over the capture and its replay boundaries. A large inter-record
gap creates one such deficit, but a run of low service across smaller gaps can
create a larger one. A profile whose long-run usable service rate is at or below
`a` has no finite steady-state backlog bound. The measured gap tail is a
diagnostic, not a sufficient capacity statistic.

## Why the other summaries were insufficient

Each rejected statistic is a summary of the cover's **marginal distribution**. The
binding constraint is a property of the **tunnel's queue**.

During a gap the tunnel cannot transmit, but the application keeps offering, so
bytes accumulate at the offered rate. Whether the queue recovers depends on
later *surplus* service. Little's law relates mean backlog, arrival rate, and
mean delay **for a stable queue**; it does not establish stability or a delay
bound from a gap percentile. Even bounded gaps can accompany unbounded backlog
when offered rate exceeds service rate. Conversely, an unbounded gap
distribution may still yield finite mean delay under suitable tail and load
conditions.

Mean rate is necessary to establish a capacity margin, but it does not describe
short-window deficits. Idle fraction and gap percentiles each lose temporal
ordering. Record-size variance alone also loses that ordering. Compute the
service-deficit curve and test it against representative arrival processes.

A 900 ms gap accumulates ~11 kB at 100 kbps offered and ~340 kB at 3 Mbps.
Those figures describe the backlog *at the end of that gap*, not the maximum
backlog or delay over a whole flow.

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

^2 A *size marginal alone* does not describe service over time. Where payload
  displaces padding inside fixed tokens (`emitted = real + pad = token`), the
  realised size distribution is identical with and without payload. That protects
  the size marginal from demand leakage; it does not make record sizes irrelevant
  to capacity, which depends on both their sizes and their schedule.

### A comparison that motivated the original hypothesis

The defective capture suggested buffered progressive video and segmented video
had similar idle fractions but very different longest gaps (15 s and 0.877 s).
The segmented-video result was overturned by the re-take (~10 s gaps). This
comparison cannot support a usability ranking.

### How each proxy fails

- **Record-size CV.** It omits token rate and temporal ordering; two schedules
  can have the same size marginal and radically different queue deficits.
- **Mean rate.** Ranks buffered video first (11.87 Mbps). That class stalls for
  15 seconds at a time.
- **Duty cycle / idle fraction.** It does not say how long service stays below
  arrivals or how quickly the queue can recover.
- **Burst magnitude.** Follows mean rate; same failure.

## Consequence for system design

1. **First establish a rate margin, then measure service deficits.** Compute usable
   capacity after framing overhead and evaluate its cumulative service over
   windows from milliseconds to complete sessions. Test queueing under explicit
   arrival models; a gap quantile is only one diagnostic.
2. **Derive queue parameters from the profile and workload.** Buffer sizing and
   admission should use the maximum or a stated tail quantile of the backlog
   generated by the service curve under a chosen arrival envelope. The former
   fixed 0.5 s constant and the later fixed p99 gap both miss long HLS stalls.
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

- **The former `GAP_QUANTILE = 0.99` was wrong for this class, by 3-4 orders of
  magnitude.** The gap distribution here is *bimodal* — intra-burst gaps near zero,
  inter-segment gaps near 10 s — and the long gaps are only 0.08-0.11% of the
  sample, so p99 sits inside the fast mode and never sees them:

  | | p99 | p99.9 | max | p99 underestimates by |
  |---|---|---|---|---|
  | hls.js | 1.3 ms | 141.6 ms | 10007 ms | **7507x** |
  | Shaka | 2.8 ms | 9654 ms | 10213 ms | **3657x** |

  A receive buffer sized from the former `cover_gap_secs(0.99)` for segmented video would be
  provisioned for a 1.3 ms stall against a real 10 s one. This is the same defect
  as the fixed 0.5 s constant it replaced — a single summary that cannot span the
  classes it is applied to — and it survived because every class measured until now
  had a unimodal gap distribution. The runtime now uses the measured maximum
  as a conservative interim input to its bounded receive-buffer control. A
  service-curve and arrival model are still needed for principled admission.
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
