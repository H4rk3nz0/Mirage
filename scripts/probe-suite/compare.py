#!/usr/bin/env python3
"""Score a probe run: does the bridge answer like the real host, per probe class?

    compare.py <out-dir>

PASS CRITERION IS INDISTINGUISHABILITY, NOT REJECTION.

A bridge that cleanly refuses a malformed probe has told the prober it is not a
web server. What matters is whether the two arms are separable, so each probe
class is scored on the three things a prober can actually observe:

  lifecycle   fin / rst / timeout / silence / connect-refused
  bytes       response length, and the first bytes returned
  timing      time to first byte and to close

`lifecycle` is listed first because that is where this project's previously-found
oracle lived: a bridge sent RST where the real host sent FIN, 15/15 separable, and
no amount of traffic shaping downstream mattered because the prober never got
that far.

ALWAYS RUN THE NULL FIRST. Point both arms at the same real host and confirm this
tool reports no difference. A comparator that finds structure in the null is
measuring itself, and every number it prints afterwards is that self-measurement
plus noise.
"""
import json
import statistics as st
import sys
from collections import defaultdict


def load(path):
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


# Below this many observations per arm, a timing AUC is not evidence.
#
# Measured, not guessed: with n=3 per arm and no real difference at all, the
# probability that |AUC-0.5| exceeds 0.35 by chance is **20%** per probe class.
# Across 17 classes that predicts ~3.4 spurious findings, and the first null run
# of this tool produced 5. Every one was the comparator measuring itself.
#
#   n=3  -> 20.0%      n=10 -> 0.5%
#   n=5  ->  5.6%      n=20 -> ~0%
#
# So the tool refuses to score timing below this rather than printing a number
# that looks like a finding. Increase --rounds to raise n.
MIN_N_FOR_TIMING = 20

# WHAT THE FLOOR GAP MEANS, and a threshold that was wrong.
#
# Both arms have a floor: the prober is remote from both. What separates them is
# the EXTRA HOP a splice must make:
#
#     bridge floor ~ RTT(prober, bridge) + RTT(bridge, cover) + processing
#     cover  floor ~ RTT(prober, cover)  + processing
#
# so the gap is approximately RTT(bridge, cover) - the leg a real server does not
# have. The interpretable quantity is therefore the GAP, not either absolute
# floor.
#
# A first version thresholded on the cover arm's ABSOLUTE floor being under 5 ms,
# on the theory that only a locally-answering server is diagnostic. That is wrong
# for every real deployment: a remote cover host has an RTT floor of its own, so
# the rule marked the test uninformative always. Corrected to report the gap and
# let the permutation test decide, which is what it was for.
#
# The class genuinely IS uninformative when the cover's own response is
# network-bound on ITS side (a CDN going to origin), because then both arms carry
# comparable extra latency. That shows up as a large gap VARIANCE rather than a
# small gap, and is flagged as such.
GAP_NOISE_RATIO = 0.5


def auc_p_two_sided(auc, na, nb):
    """Normal-approximation two-sided p-value for a Mann-Whitney AUC.

    Used only to apply a multiple-comparison correction: the suite tests ~17
    probe classes at once, so an uncorrected per-class threshold produces
    findings at a rate set by the number of classes rather than by the evidence.
    """
    if auc is None or na == 0 or nb == 0:
        return None
    import math
    mu = 0.5
    sigma = math.sqrt((na + nb + 1) / (12.0 * na * nb))
    if sigma == 0:
        return 1.0
    z = abs(auc - mu) / sigma
    return math.erfc(z / math.sqrt(2.0))


def _q(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(p * len(xs)))]


def response_floor(a, b, iters=2000, seed=17):
    """Is the bridge's response FLOOR structurally above the real host's?

    THE STRUCTURAL TEST, and it asks a different question from AUC.

    A real server answering a malformed record does local work: parse, fail,
    alert. Microseconds, floor at ~0. A SPLICE cannot answer until it has been to
    the real host and back, so its support starts at one network RTT.

    That difference is structural, not tunable: delay can be ADDED to the fast
    side, but a floor cannot be REMOVED from the slow side. A splice can therefore
    equalise means, medians and AUC by adding jitter and still never produce a
    sub-millisecond reply, while the host it claims to be produces them routinely.

    STATISTIC, and why the obvious ones fail:

      - Raw `min()` is an extreme order statistic with high variance. Comparing
        the two arms' minima flagged a NULL run (both arms the same host, floors
        31.4 vs 31.3 ms) because one of 100 samples happened to land lower. That
        is manufacturing a finding out of sampling noise.
      - A fixed rate threshold hides the consequence: P=0.11 sounds negligible and
        means ~26 probes to distinguish, which is nothing for a censor.

    So: a PERMUTATION test on the low-quantile gap, which has no null by
    construction, and the effect size reported as probes-to-distinguish rather
    than a rate.

    Returns (p_value, n_to_distinguish, bridge_floor, cover_floor) or None.
    """
    import math
    import random as _r
    if len(a) < 10 or len(b) < 10:
        return None
    Q = 0.05
    bf, cf = _q(a, Q), _q(b, Q)
    observed = bf - cf

    rng = _r.Random(seed)
    pool = list(a) + list(b)
    na = len(a)
    hits = 0
    for _ in range(iters):
        rng.shuffle(pool)
        if abs(_q(pool[:na], Q) - _q(pool[na:], Q)) >= abs(observed):
            hits += 1
    pval = (hits + 1) / (iters + 1)

    # Probes to see one reply below the bridge's floor, at 95% confidence. This
    # is the number that matters: the region is unreachable for a splice, so a
    # single observation inside it is decisive.
    rate = sum(1 for x in b if x < bf) / len(b)
    if rate <= 0:
        n = float("inf")
    elif rate >= 1:
        n = 1.0
    else:
        n = math.log(0.05) / math.log(1 - rate)
    return pval, n, bf, cf


def support_deficit(a, b, iters=4000, seed=29):
    """Does the real host produce responses in a region the bridge never reaches?

    THE GENERAL FORM OF THE FLOOR RESULT.

    Every mitigation a splice operator reaches for - jitter to match medians, a
    fixed added delay, clamping every reply to the server's p05 - makes the
    bridge's support a strict SUBSET of the server's. None of them repair that,
    because location and scale matching cannot create mass where there is none.
    So the durable question is not "do the distributions differ in centre or
    spread" but:

        is the bridge's response distribution absolutely continuous
        with respect to the server's?

    Statistic: how many cover observations fall below the bridge's minimum. Under
    H0 (same distribution) that count is small and its null is obtained by
    permutation, so no distributional assumption is needed.

    This catches the case the p05-gap test provably cannot: a CLAMP matches the
    boundary exactly (same p05, same median, AUC 0.488) while having zero density
    below it where the server has several percent. The gap is a location; the
    clamp's signature is entirely in the shape below that location.

    Returns (p_value, n_to_distinguish, deficit_count) or None.
    """
    import math
    import random as _r
    if len(a) < 20 or len(b) < 20:
        return None
    m = min(a)
    observed = sum(1 for x in b if x < m)

    rng = _r.Random(seed)
    pool = list(a) + list(b)
    na = len(a)
    hits = 0
    for _ in range(iters):
        rng.shuffle(pool)
        pa, pb = pool[:na], pool[na:]
        if sum(1 for x in pb if x < min(pa)) >= observed:
            hits += 1
    pval = (hits + 1) / (iters + 1)

    rate = observed / len(b)
    if rate <= 0:
        n = float("inf")
    elif rate >= 1:
        n = 1.0
    else:
        n = math.log(0.05) / math.log(1 - rate)
    return pval, n, observed


def mannwhitney_auc(a, b):
    """AUC via rank sum. 0.5 = indistinguishable, 1.0 = perfectly separable."""
    if not a or not b:
        return None
    merged = sorted([(v, 0) for v in a] + [(v, 1) for v in b])
    ranks, i = {}, 0
    # average ranks for ties, or ties alone would look like separation
    while i < len(merged):
        j = i
        while j + 1 < len(merged) and merged[j + 1][0] == merged[i][0]:
            j += 1
        r = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[k] = r
        i = j + 1
    ra = sum(ranks[k] for k, (_, g) in enumerate(merged) if g == 0)
    na, nb = len(a), len(b)
    u = ra - na * (na + 1) / 2.0
    return u / (na * nb)


def connect_cost(rows, arm):
    """Median TCP setup cost for one arm, in seconds.

    Prefers the per-observation `connect_s` field. Runs collected before that
    field existed fall back to the `connect-close` probe class, which sends
    nothing and so measures setup alone - the accident that exposed the confound
    in the first place.

    Returns None when neither is available, and the caller then refuses to
    subtract rather than subtracting zero: a silent no-op that still prints
    "corrected" is exactly the silent-wrong failure this suite exists to avoid.
    """
    direct = [r["connect_s"] for r in rows
              if r["arm"] == arm and r.get("connect_s") is not None]
    if direct:
        return st.median(direct)
    fallback = [r["close_s"] for r in rows
                if r["arm"] == arm and r["probe"] == "connect-close" and r["close_s"]]
    return st.median(fallback) if fallback else None


def deploy_at_cover_distance(rows):
    """Model the bridge sitting where a real bridge would sit: at the cover's distance.

    THE CORRECTION THAT IS NOT VALID HERE, AND WHY. The obvious move is to
    subtract each arm's own TCP setup cost, on the reasoning that distance is an
    additive per-arm constant and removing it cannot manufacture a difference.
    That reasoning is wrong for a splice, and it was wrong here by 17.8 ms.

    Measured decomposition, bridge on loopback, cover host 17.8 ms away:

        cover  : connect 17.84 + post-connect 14.11 = 31.95 ms
        bridge : connect  0.09 + post-connect 31.89 = 31.98 ms

    The bridge's POST-CONNECT cost equals the cover's ENTIRE cost, connect
    included, to within 0.06 ms - because the splice does its own TCP setup to
    the cover after the prober's connect has already completed. A splice does not
    shift cost by a constant; it RELOCATES cost from the connect phase into the
    response phase. Subtracting each arm's own connect therefore removes 17.8 ms
    the cover legitimately paid and 0.09 ms from a bridge that pays the same
    17.8 ms later, creating the gap it was meant to remove. Applied to real data
    it flagged 14 of 17 classes at AUC=1.000, every one an artifact.

    THE CONSEQUENCE, which corrects an earlier conclusion of this project. That
    32.0-vs-32.0 total was read as "the splice forwards and pays the same round
    trip, so it is timing-indistinguishable." It is not. The totals matched only
    because the bridge's own connect was FREE (loopback) while it paid the
    cover's full cost afterwards - two errors of the same size cancelling. A
    bridge actually deployed D milliseconds from the prober pays D + 31.95 where
    the genuine host pays 31.95.

    So the correction is to ADD the missing distance to the bridge, not subtract
    it from the cover: charge the bridge the cover's connect cost, which is what
    it would pay if it sat where the host it fronts sits.

    LIMITS. This models the mean, not per-observation jitter, and it assumes the
    prober-to-bridge and prober-to-cover paths would have similar variance. It
    cannot correct timeout-dominated classes, whose latency is the prober's own
    constant rather than the path.
    """
    ccost = {arm: connect_cost(rows, arm) for arm in ("bridge", "cover")}
    if any(v is None for v in ccost.values()):
        return None, ccost
    deficit = ccost["cover"] - ccost["bridge"]
    if deficit <= 0:
        # The bridge is already at or beyond the cover's distance; nothing to add.
        return list(rows), ccost
    out = []
    for r in rows:
        r = dict(r)
        if r["arm"] == "bridge":
            for k in ("first_byte_s", "close_s"):
                if r.get(k) is not None:
                    r[k] = r[k] + deficit
        out.append(r)
    return out, ccost


def main(outdir, deploy=False):
    rows = load(f"{outdir}/probes.jsonl")
    if deploy:
        corrected, ccost = deploy_at_cover_distance(rows)
        shown = {k: ("n/a" if v is None else f"{v*1000:.2f}ms") for k, v in ccost.items()}
        if corrected is None:
            print(f"REFUSING to model deployment: no connect cost for one arm ({shown}).")
            print("Re-run the probe to collect `connect_s`, or keep `connect-close` in the suite.")
            return
        d = (ccost["cover"] - ccost["bridge"]) * 1000
        print(f"deployment-modelled: bridge connect={shown['bridge']}, "
              f"cover connect={shown['cover']}; charged the bridge the {d:+.2f}ms "
              f"it would pay sitting at the cover's distance.")
        print("A bridge under test on loopback gets its own setup for free while still "
              "paying the cover's in full; without this the two cancel.\n")
        rows = corrected
    by = defaultdict(lambda: {"bridge": [], "cover": []})
    for r in rows:
        by[r["probe"]][r["arm"]].append(r)

    n_classes = max(1, len(by))
    print(f"{'probe':<18} {'lifecycle':<20} {'bytes':<10} {'timing':<20} "
          f"{'floor probes-to-tell':<24} verdict")
    print("-" * 116)
    worst, findings, underpowered, uninformative = 0.5, [], [], []
    for probe in sorted(by):
        b, c = by[probe]["bridge"], by[probe]["cover"]
        if not b or not c:
            continue

        bl = sorted({x["close"] for x in b})
        cl = sorted({x["close"] for x in c})
        life_same = bl == cl
        life = f"{'/'.join(bl)} vs {'/'.join(cl)}"[:25] if not life_same else "/".join(bl)[:25]

        bb = [x["bytes"] for x in b]
        cb = [x["bytes"] for x in c]
        bytes_same = (st.median(bb) == st.median(cb))
        bstr = f"{st.median(bb):.0f} vs {st.median(cb):.0f}"

        # Time to FIRST BYTE, not lifetime. A splice's round trip shows up in
        # when it can first answer; connection lifetime is dominated by teardown
        # and can be identical while first-byte differs by an RTT. Scoring the
        # wrong observable makes the tool blind to the structural case.
        def _t(x):
            return x["first_byte_s"] if x["first_byte_s"] is not None else x["close_s"]
        bt = [_t(x) for x in b if _t(x) is not None]
        ct = [_t(x) for x in c if _t(x) is not None]
        n = min(len(bt), len(ct))
        timing_bad = False
        if n < MIN_N_FOR_TIMING:
            tstr = f"n={n} (need {MIN_N_FOR_TIMING})"
            underpowered.append(probe)
        else:
            auc = mannwhitney_auc(bt, ct)
            pv = auc_p_two_sided(auc, len(bt), len(ct))
            # Bonferroni across the classes actually tested.
            timing_bad = pv is not None and pv * n_classes < 0.05
            worst = max(worst, max(auc, 1 - auc))
            tstr = f"AUC={auc:.3f} p*={min(1.0, pv * n_classes):.3f}"

        # Response-floor test on time-to-first-byte, which is where a splice's
        # RTT floor lives. Falls back to lifetime when no bytes came back.
        bf = [x["first_byte_s"] if x["first_byte_s"] is not None else x["close_s"]
              for x in b if (x["first_byte_s"] or x["close_s"]) is not None]
        cf = [x["first_byte_s"] if x["first_byte_s"] is not None else x["close_s"]
              for x in c if (x["first_byte_s"] or x["close_s"]) is not None]
        fl = response_floor(bf, cf)
        floor_bad = False
        if fl is None or n < MIN_N_FOR_TIMING:
            fstr = "n/a"
        else:
            fp, n_dist, bfloor, cfloor = fl
            # Flag when a censor could distinguish inside a practical probe
            # budget. 1000 probes to one endpoint is trivial for a censor and
            # cheap enough to run against every suspected host.
            # BOTH: the gap must be statistically real (permutation) AND
            # practically reachable (probe budget). Either alone produces
            # findings in a null.
            floor_bad = (fp * n_classes < 0.05) and n_dist < 1000
            nstr = "inf" if n_dist == float("inf") else f"{n_dist:.0f}"
            gap_ms = (bfloor - cfloor) * 1000.0
            fstr = f"gap={gap_ms:+.1f}ms p*={min(1.0, fp*n_classes):.3f} N={nstr}"

        # Support test: the general form, which survives mitigations that defeat
        # the location-based floor gap.
        sd = support_deficit(bf, cf) if n >= MIN_N_FOR_TIMING else None
        support_bad = False
        if sd is not None:
            sp, sn, scount = sd
            support_bad = (sp * n_classes < 0.05) and sn < 1000
            fstr += f" | sup p*={min(1.0, sp*n_classes):.3f} N={'inf' if sn==float('inf') else f'{sn:.0f}'}"

        bad = (not life_same) or (not bytes_same) or timing_bad or floor_bad or support_bad
        verdict = "SEPARABLE" if bad else "ok"
        if bad:
            findings.append(probe)
        print(f"{probe:<18} {life:<20} {bstr:<10} {tstr:<20} {fstr:<24} {verdict}")

    print("-" * 116)
    if underpowered:
        print(f"UNDERPOWERED (timing not scored): {len(underpowered)} of {n_classes} classes")
        print(f"  Raise --rounds. At n=3 per arm a class separates by chance 20% of")
        print(f"  the time; printing an AUC there is fabricating a finding.")
    if uninformative:
        print(f"FLOOR TEST UNINFORMATIVE for {len(uninformative)} of {n_classes} classes:")
        print(f"  {', '.join(uninformative)}")
        print("  The real host is network-bound on these too, so there is no")
        print("  local-vs-RTT contrast. Not evidence of safety - just silence.")
    print(f"worst timing AUC among scored classes: {worst:.3f}")
    if findings:
        print(f"SEPARABLE probe classes: {', '.join(findings)}")
        print("  Each is a way a prober tells this endpoint from the host it claims")
        print("  to be. Rejecting a probe cleanly is not a pass.")
    else:
        print("no probe class separated the two arms on lifecycle, bytes or timing.")
    print()
    print("Interpretation depends entirely on whether the NULL was run: point both")
    print("arms at the same real host and this table must come back all-ok. If it")
    print("does not, the tool is measuring itself.")
    return 0


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    sys.exit(main(args[0], deploy="--deploy-at-cover-distance" in sys.argv))
