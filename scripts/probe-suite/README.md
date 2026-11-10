# Probe suite

Does this bridge answer like the host it claims to be?

    probe.py   <bridge host:port> <cover host:port> <out-dir> [--rounds N]
    compare.py <out-dir> [--deploy-at-cover-distance]   # bridge vs the real host
    partition.py <out-dir>                              # the bridge against itself

`PREREGISTERED.md` holds the predictions and outcomes, written before each run.

Active probing is what actually kills deployed circumvention systems. Passive
traffic analysis of a well-shaped tunnel is not on that list, yet this repository
had sixteen files of traffic-analysis tooling and zero for probing before this.

## The two statistics answer different questions, and are blind to each other

| | asks | needs | catches |
|---|---|---|---|
| `partition.py` | does this endpoint answer some probe classes locally? | **nothing but the bridge's address** | local handling, via timing modality |
| `compare.py` | does it respond identically to the real host? | a synchronised capture of the genuine host | bytes, lifecycle, timing |

`partition.py` is the cheaper attack to defend against: an adversary runs it
knowing only that a host is suspicious.

**They do not cover for each other, and a fix validated by one can open a hole the
other sees.** Measured: setting `http_shadow_target` to the cover host on :80
collapsed the partition from G=10.74 to G=0.23 (p=1.0) and simultaneously took
`http11` response bytes from 0-vs-0 to **173-vs-0**, because the cover's :443
returns nothing to a plaintext GET while its :80 returns a 301. The timing tell was
closed and a byte tell was opened, and `partition.py` is structurally incapable of
seeing it because it scores timing only.

So: **any fix validated by one statistic must be re-run against the other before
it is called done.** A byte difference is also the worse of the two — it is
categorical, so it needs no timing resolution and no repeated sampling.

## Do not distance-match with a stand-in server

This is the first thing anyone tries and it does not work. Write it down before
someone spends an afternoon on it.

The problem is real: a bridge under test on loopback and the cover host it fronts
17.8 ms away are not comparable, and five probe classes separated at AUC=0.000
purely on that offset. The obvious repair is to stand up a local TLS server as the
cover so both arms are equidistant.

**It matches distance and destroys server identity in the same step, and the second
effect dominates.** Tried, n=100:

- separable classes went **8 → 13**, not down
- `random-16`, `random-512`, `random-4096`, `http2-preface` showed `fin vs rst` —
  the Python stand-in RSTs on handshake failure where the real host FINs
- AUC >= 0.92 with gaps of ±0.0-0.1 ms: at loopback resolution *any* two distinct
  programs separate perfectly

The only classes that validated were the four timeout-dominated ones (`silence`,
`trunc-1`, `trunc-5`, `trunc-half`), which collapsed to `ok` — precisely because
they do not care what is behind the port. That subset is the whole valid yield of a
stand-in run, and it confirmed those four were pure placement confound.

## Do not subtract per-arm connect time either

The next obvious move, and it is wrong for a splice by 17.8 ms. Distance looks like
an additive per-arm constant, so removing it should not be able to manufacture a
difference. Applied to real data it flagged 14 of 17 classes at AUC=1.000, every
one an artifact.

The decomposition says why:

    cover  : connect 17.84 + post-connect 14.11 = 31.95 ms
    bridge : connect  0.09 + post-connect 31.89 = 31.98 ms

The bridge's post-connect cost equals the cover's **entire** cost, connect
included, to within 0.06 ms. **A splice does not shift cost by a constant — it
relocates cost out of the connect phase into the response phase**, because its own
TCP setup to the cover happens after the prober's connect has already returned.
Subtracting each arm's own connect removes 17.8 ms the cover legitimately paid and
0.09 ms from a bridge that pays the same 17.8 ms later.

`--deploy-at-cover-distance` is the correction that holds: it ADDS the missing
distance to the bridge, modelling it sitting where a real bridge would sit.

### What that decomposition overturned

A 32.0-vs-32.0 total was previously recorded as "the splice forwards and pays the
same round trip, so it is timing-indistinguishable." It was two errors of equal
size cancelling: the bridge's own connect was free on loopback while it paid the
cover's in full. Modelled at cover distance the same run separates 15 of 17 classes
at N=1.

This is the third clean-looking null in this project that turned out to be an
artifact, and the first found by **decomposition** rather than by a control arm.
Worth keeping as a technique: when two totals agree suspiciously well, split them
into phases and check that the phases agree too.

## Geometry is a measurement parameter, not a detail

The tell is proportional to **bridge<->cover RTT**, not prober<->bridge RTT. A bridge
co-located with its cover host totals ~31.9 ms against the genuine host's 31.95 and
is indistinguishable; a bridge far from its cover host is separable on one probe.

Two consequences:

- **Results from a loopback bridge do not transfer.** Any number produced against
  `127.0.0.1` is a lower bound on the real gap, and the current N=1 figure is a
  model, not a measurement. The honest test needs a bridge genuinely remote from
  the prober with a known bridge<->cover RTT — ideally at two or three distances, so
  the slope is measured rather than a single point.
- **Cover-host selection is a latency decision**, not only a plausibility one.
  Pick a cover host that is network-close to the bridge. This is not yet enforced
  or checked at startup.

## Rules the tools enforce

- **Rejection is not a pass.** A bridge that cleanly refuses a malformed probe has
  told the prober it is not a web server. The criterion is indistinguishability.
- **Always run the null first**: point both arms at the same real host and confirm
  `compare.py` reports no difference. A comparator that finds structure in the null
  is measuring itself. The first null run of this tool produced 5 fabricated
  oracles at n=3; `MIN_N_FOR_TIMING=20` and Bonferroni correction came from that.
- **Refuse rather than report** when a run cannot mean what it says. A run with no
  successful real-host observations is a broken reference arm, not a suspicious
  bridge.
- **Pre-register.** Numeric criteria for each outcome, including the failure mode,
  go in `PREREGISTERED.md` before the run. The stand-in result above was called
  invalid by a criterion written before it was seen, which is the only reason it
  was not reported as a regression.
