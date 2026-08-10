#!/usr/bin/env python3
"""Does one endpoint answer some probe classes locally and forward others?

    partition.py <out-dir> [--arm bridge|cover|both]

THE STATISTIC THAT NEEDS NO REFERENCE ARM.

Every other test in this suite compares a bridge to the real cover host, which
requires a synchronised capture, distance-matched arms, and a reference that can
actually answer. This one compares an endpoint's probe classes TO EACH OTHER.

The reasoning, from the first real bridge run:

  A real host forwards nothing, because nothing is a forward - it is just serving.
  Every probe class costs one round trip, so the per-class latencies form ONE
  cluster.

  A splice forwards TLS-shaped input to its cover host (paying that host's RTT,
  which is why it is timing-indistinguishable there - measured 32.0 vs 32.0 ms)
  and answers everything else locally, in microseconds. Its per-class latencies
  form TWO clusters, separated by roughly the upstream RTT.

So the tell is the PARTITION, not the latency. That is:

  - measurable from the suspect endpoint alone
  - immune to where the bridge sits, since it is within-arm
  - a design target rather than a tunable threshold: "no probe class is answered
    locally" is a property that can be verified, not a statistic to tune

STATISTIC. Sort the per-class median latencies and take the largest gap between
consecutive values, normalised by the mean gap:

    G = max_gap / mean_gap

Under unimodality G is O(1) even for modest n. A two-cluster structure makes one
gap dominate. The null is obtained by simulating n draws from a lognormal fitted
to the observed medians - unimodal by construction, matched in location and scale
- so the test asks "is this gap larger than a unimodal distribution of the same
shape would produce."
"""
import argparse
import json
import math
import random
import statistics as st
from collections import defaultdict


def per_class_medians(rows, arm):
    """Per-class median latency, EXCLUDING classes that timed out.

    A timed-out class carries no latency information - its value is the prober's
    own timeout constant, identical on both arms. Including them made the largest
    gap fall between "timed out" and "responded", which is a real partition and
    the wrong one: it fired on the real cover host too (G=15.9, p=0.0007), where
    by construction there is no local handling to find.

    Caught by scoring the cover arm as a built-in control. A statistic that needs
    no reference arm still benefits from one while it is being validated.
    """
    # `connect-close` never sends data, so it measures TCP setup rather than
    # response latency and sits apart on EVERY endpoint - it split the real cover
    # host into two clusters at p=0.0002, where there is nothing to find. Not a
    # latency class; excluded.
    NOT_A_LATENCY_CLASS = {"connect-close"}
    by = defaultdict(list)
    timed_out = defaultdict(int)
    seen = defaultdict(int)
    for r in rows:
        if r["arm"] != arm or r["probe"] in NOT_A_LATENCY_CLASS:
            continue
        seen[r["probe"]] += 1
        if r.get("close") == "timeout":
            timed_out[r["probe"]] += 1
            continue
        t = r.get("first_byte_s") or r.get("close_s")
        if t:
            by[r["probe"]].append(t)
    # Drop a class if most of its observations timed out: the survivors are a
    # biased tail, not a latency estimate.
    return {
        k: st.median(v)
        for k, v in by.items()
        if v and timed_out[k] <= seen[k] * 0.5
    }


def gap_stat(vals):
    """Largest gap BELOW the main cluster, over the mean gap.

    DIRECTIONAL, and it has to be. Local handling makes a class anomalously
    FAST - it skipped the upstream. A class that is anomalously SLOW is just one
    the server does more work for, which is ordinary: the real cover host answers
    `http11` in 33.4 ms against 32.0 ms for everything else, because serving an
    HTTP request costs more than rejecting a malformed TLS record.

    An unsigned largest-gap statistic flags both and cannot tell them apart. It
    scored the real cover host at p=0.0002 on exactly that slow outlier. So the
    gap is only counted when it sits below the bulk - i.e. in the lower half of
    the sorted medians.

    Returns (G, split_point).
    """
    xs = sorted(vals)
    if len(xs) < 4:
        return None, None
    gaps = [xs[i + 1] - xs[i] for i in range(len(xs) - 1)]
    mean_gap = sum(gaps) / len(gaps)
    if mean_gap <= 0:
        return None, None
    # Only gaps in the lower half: a fast minority split off from the bulk.
    lower = range(len(gaps) // 2)
    candidates = [k for k in lower]
    if not candidates:
        return None, None
    i = max(candidates, key=lambda k: gaps[k])
    return gaps[i] / mean_gap, (xs[i] + xs[i + 1]) / 2.0


def p_value(vals, iters=4000, seed=13):
    """Null: same n, drawn from a lognormal matched to these medians."""
    g, _ = gap_stat(vals)
    if g is None:
        return None, None
    logs = [math.log(v) for v in vals if v > 0]
    if len(logs) < 4:
        return None, None
    mu, sigma = st.mean(logs), (st.pstdev(logs) or 1e-6)
    rng = random.Random(seed)
    hits = 0
    for _ in range(iters):
        sim = [math.exp(rng.gauss(mu, sigma)) for _ in range(len(vals))]
        sg, _ = gap_stat(sim)
        if sg is not None and sg >= g:
            hits += 1
    return g, (hits + 1) / (iters + 1)


def report(rows, arm):
    med = per_class_medians(rows, arm)
    if len(med) < 4:
        print(f"{arm}: too few classes")
        return
    g, p = p_value(list(med.values()))
    _, split = gap_stat(list(med.values()))
    print(f"\n=== {arm} ===")
    print(f"  gap statistic G = {g:.2f}   p = {p:.4f}   "
          f"({'TWO CLUSTERS - local handling present' if p < 0.05 else 'one cluster - uniform cost'})")
    if p < 0.05:
        fast = sorted([k for k, v in med.items() if v < split], key=lambda k: med[k])
        slow = sorted([k for k, v in med.items() if v >= split], key=lambda k: med[k])
        print(f"  split at {split*1000:.1f} ms")
        print(f"  LOCAL   ({len(fast):2d}): {', '.join(fast)}")
        print(f"  FORWARD ({len(slow):2d}): {', '.join(slow)}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir")
    ap.add_argument("--arm", default="both")
    a = ap.parse_args()
    rows = [json.loads(l) for l in open(f"{a.outdir}/probes.jsonl") if l.strip()]
    for arm in (["bridge", "cover"] if a.arm == "both" else [a.arm]):
        report(rows, arm)
