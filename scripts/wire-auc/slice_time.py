#!/usr/bin/env python3
"""Slice a capture into TIME windows, keeping the empty ones.

Two bugs this fixes, both found by review rather than by the tools:

1. Record-count windowing makes `record_count` constant by construction, so its
   AUC is 0.500 tautologically and `total_bytes` is perfectly collinear with
   `mean_size`. Time windows make both real features again.

2. Dropping windows that captured nothing conditions the whole analysis on the
   carrier being up - which is a payload-dependent variable, because carrier
   outages are load-correlated. Every AUC computed that way measures "residual
   GIVEN the carrier survived"; the unconditional figure is worse. An outage is
   not missing data, it is the observation.

Output: one line per window, space-separated record sizes. An empty line is a
window in which nothing crossed the wire.
"""
import sys, collections

E = sys.argv[1] if len(sys.argv) > 1 else "."
DIR = int(sys.argv[2]) if len(sys.argv) > 2 else 1
WIN = float(sys.argv[3]) if len(sys.argv) > 3 else 5.0

marks = []
for line in open(f"{E}/marks.tsv"):
    phase, a, b = line.split()
    marks.append((phase, float(a), float(b)))

rows = []
for line in open(f"{E}/records.tsv"):
    t, d, s = line.split()
    if int(d) == DIR:
        rows.append((float(t), int(s)))
rows.sort()

out = collections.defaultdict(list)
for phase, a, b in marks:
    t = a
    while t < b:
        end = min(t + WIN, b)
        sizes = [s for (ts, s) in rows if t <= ts < end]
        out[phase].append(sizes)
        t = end

for phase, wins in out.items():
    empties = sum(1 for w in wins if not w)
    with open(f"{E}/tw_{phase}.txt", "w") as fh:
        for w in wins:
            fh.write(" ".join(map(str, w)) + "\n")
    print(f"  {phase:<7} {len(wins):3d} windows of {WIN}s, {empties} empty "
          f"({100.0*empties/max(len(wins),1):.0f}%)", file=sys.stderr)
