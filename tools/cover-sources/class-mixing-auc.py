#!/usr/bin/env python3
"""Reproduce the class-mixing separability measurement in docs/proteus.md.

Builds the record-size sequences the pacer would replay, two ways - one class per
session (what `read_profile` does) versus every class pooled into one chain (what
it used to do) - then scores each against an independently drawn reference with
the project's own distinguisher.

    mirage-cover-record ./lib --mode browse --sources global --realtime --count 6
    mirage-cover-record ./lib --mode video  --sources global --realtime --low-bitrate --count 4
    python3 tools/cover-sources/class-mixing-auc.py          # writes auc/*.txt
    cargo run -p mirage-adversary --example flow_auc -- auc/pooled.txt auc/ref_browse.txt 300
    cargo run -p mirage-adversary --example flow_auc -- auc/one_browse.txt auc/ref_browse.txt 300

Measured: pooled scored 0.807 against a real browse session and 0.759 against a
real video one (1.000 when 16 windows are pooled); one-class scored 0.511/0.517,
which is the null control. Size axis only - every feature derives from record
sizes, so this says nothing about timing.

COVER sessions use seeds 0..39; REFERENCE sessions use seeds 1000..1039, so a
cover file is never byte-identical to the reference it is scored against - the
comparison has to be between two independently-drawn populations, not a file
against itself.
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


def sizes_of(path):
    out = []
    for line in open(path):
        f = line.strip().split(",")
        if len(f) < 3:
            continue
        try:
            sz, d = int(f[-2]), int(f[-1])
        except ValueError:
            continue
        if d > 0:
            out.append(sz)
    return out


def traces_in(d):
    return sorted(glob.glob(os.path.join(d, "*.csv")))


def chain(pool, seed):
    out = []
    for i in seeded_order(len(pool), seed)[:CHAIN_LEN]:
        out.extend(sizes_of(pool[i]))
    return out


lib = "auc/lib"
classes = sorted(
    d for d in glob.glob(lib + "/*")
    if os.path.isdir(d) and os.path.basename(d) != "upstream"
)
per = {os.path.basename(c): traces_in(c) for c in classes}
pooled_pool = [t for c in classes for t in traces_in(c)]

out = {"pooled": [], "one_browse": [], "one_video": [], "ref_browse": [], "ref_video": []}
for s in range(40):
    out["pooled"] += chain(pooled_pool, s)
    out["one_browse"] += chain(per["browse"], s)
    out["one_video"] += chain(per["video"], s)
for s in range(1000, 1040):
    out["ref_browse"] += chain(per["browse"], s)
    out["ref_video"] += chain(per["video"], s)

for k, v in out.items():
    open(f"auc/{k}.txt", "w").write("\n".join(map(str, v)))
    print(f"  {k}: {len(v)} records")
