#!/usr/bin/env python3
"""Split the captured wire into IDLE and ACTIVE windows for the distinguisher.

Reads the relay's record log and the phase marks, then writes one file of record
sizes per class. Only DOWNSTREAM records are emitted by default: that is the
direction carrying the fetched payload, so it is where activity would show.
"""
import sys, collections

E = sys.argv[1] if len(sys.argv) > 1 else "."
DIR = int(sys.argv[2]) if len(sys.argv) > 2 else 1  # 1=down, -1=up

marks = []
for line in open(f"{E}/marks.tsv"):
    phase, a, b = line.split()
    marks.append((phase, float(a), float(b)))

rows = []
for line in open(f"{E}/records.tsv"):
    t, d, s = line.split()
    rows.append((float(t), int(d), int(s)))

by_phase = collections.defaultdict(list)
for phase, a, b in marks:
    n = 0
    for t, d, s in rows:
        if d == DIR and a <= t < b:
            by_phase[phase].append(s)
            n += 1
    print(f"  {phase:6s} {b - a:5.1f}s -> {n} records", file=sys.stderr)

for phase, sizes in by_phase.items():
    with open(f"{E}/wire_{phase}.txt", "w") as fh:
        fh.write("\n".join(map(str, sizes)))
    print(f"  wrote wire_{phase}.txt: {len(sizes)} records", file=sys.stderr)
