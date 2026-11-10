#!/usr/bin/env python3
"""Emit the TIMING observable for the same pooled/one-class comparison.

The project's distinguisher is size-only - all 14 features derive from record
sizes - so the size measurement says nothing about gaps. This projects each
schedule onto its inter-record GAP sequence (microseconds, clamped to the u32 the
classifier reads) so the SAME estimator - Mann-Whitney AUC, permutation null,
max-T correction over 14 features - can be run over the timing axis instead.

It is an auxiliary view, not the project's shipped metric: the feature names
still say "size" and mean "gap". Read it as "does the gap sequence separate",
nothing more.
"""
import os, glob

CHAIN_LEN = 8
MASK = (1 << 64) - 1


def seeded_order(n, seed):
    s = seed & MASK

    def nxt():
        nonlocal s
        s = (s + 0x9E3779B97F4A7C15) & MASK
        z = s
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK
        return (z ^ (z >> 31)) & MASK

    v = list(range(n))
    for i in range(n - 1, 0, -1):
        j = nxt() % (i + 1)
        v[i], v[j] = v[j], v[i]
    return v


def gaps_of(path):
    """Downstream inter-record gaps in microseconds, clamped to 30 s."""
    ts = []
    for line in open(path):
        f = line.strip().split(",")
        if len(f) < 3:
            continue
        try:
            t, d = float(f[-3]), int(f[-1])
        except ValueError:
            continue
        if d > 0:
            ts.append(t)
    out = []
    for a, b in zip(ts, ts[1:]):
        out.append(max(0, min(int((b - a) * 1e6), 30_000_000)))
    return out


def traces_in(d):
    return sorted(glob.glob(os.path.join(d, "*.csv")))


def chain(pool, seed):
    out = []
    for i in seeded_order(len(pool), seed)[:CHAIN_LEN]:
        out.extend(gaps_of(pool[i]))
    return out


lib = "auc/lib"
classes = sorted(
    d for d in glob.glob(lib + "/*")
    if os.path.isdir(d) and os.path.basename(d) != "upstream"
)
per = {os.path.basename(c): traces_in(c) for c in classes}
pooled_pool = [t for c in classes for t in traces_in(c)]

out = {"g_pooled": [], "g_one_browse": [], "g_one_video": [],
       "g_ref_browse": [], "g_ref_video": []}
for s in range(40):
    out["g_pooled"] += chain(pooled_pool, s)
    out["g_one_browse"] += chain(per["browse"], s)
    out["g_one_video"] += chain(per["video"], s)
for s in range(1000, 1040):
    out["g_ref_browse"] += chain(per["browse"], s)
    out["g_ref_video"] += chain(per["video"], s)

for k, v in out.items():
    open(f"auc/{k}.txt", "w").write("\n".join(map(str, v)))
    print(f"  {k}: {len(v)} gaps")
