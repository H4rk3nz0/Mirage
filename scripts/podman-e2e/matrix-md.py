#!/usr/bin/env python3
"""Render tier-matrix.sh's matrix.tsv as the markdown table docs/proteus.md carries.

Hand-transcribing 30 rows invites exactly one transcription error, and a wrong
number in a doc about detectability is worse than no number. Run this instead:

    scripts/podman-e2e/matrix-md.py <matrix.tsv>

The CONTROL row is emitted first and separately, because every other row means
nothing without it: it is what the harness scored with no user traffic to find,
so a cell inside the control's band is not a result. Cells at or below it are
flagged rather than left for the reader to compare by eye.
"""

import sys
from collections import defaultdict

# The estimator's floor when nothing separates, by flows-per-class. Mirrors
# mirage_adversary::flow_classifier::noise_floor - measure() maximises
# max(auc, 1-auc) over 14 features on the sample it reports, so it scores above
# 0.5 on data with nothing in it, and more so the smaller the sample.
#
# This is why one measured control cannot certify the whole matrix: the control
# runs at ONE (tier, carrier) and every other cell has its own flow count. A cell
# with a third of the control's flows has a materially higher floor.
NOISE_FLOOR_POINTS = [(16, 0.681), (30, 0.617), (66, 0.574), (150, 0.552)]


def noise_floor(flows):
    """Estimated floor at `flows` per class; log-linear between measured points."""
    import math

    n = max(int(flows), 1)
    if n <= NOISE_FLOOR_POINTS[0][0]:
        return NOISE_FLOOR_POINTS[0][1]
    for (n0, f0), (n1, f1) in zip(NOISE_FLOOR_POINTS, NOISE_FLOOR_POINTS[1:]):
        if n <= n1:
            t = (math.log(n) - math.log(n0)) / (math.log(n1) - math.log(n0))
            return f0 + t * (f1 - f0)
    # Past the calibrated range hold the last value rather than extrapolating
    # toward 0.5 - understating the floor is the direction that turns noise into
    # a finding.
    return NOISE_FLOOR_POINTS[-1][1]


FLOOR_SLACK = 0.005  # a cell this close to its floor is within the noise


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2

    rows = []
    with open(sys.argv[1], encoding="utf-8") as fh:
        header = fh.readline()
        if not header.startswith("tier\t"):
            print("not a matrix.tsv (no tier header)", file=sys.stderr)
            return 2
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 7:
                continue
            rows.append(parts)

    if not rows:
        print("no rows yet", file=sys.stderr)
        return 1

    # (tier, carrier) -> {direction: (flows, separator, accuracy)}, plus ratio.
    cells = defaultdict(dict)
    ratios = {}
    order = []
    for tier, carrier, direction, flows, sep, acc, ratio in rows:
        key = (tier, carrier)
        if key not in ratios:
            order.append(key)
        ratios[key] = ratio
        if direction in ("up", "down"):
            cells[key][direction] = (flows, sep, acc)
        else:
            # A FAILED row: the separator column carries the reason.
            cells[key]["failed"] = sep

    def acc_of(key, direction):
        got = cells[key].get(direction)
        return float(got[2]) if got else None

    control = next((k for k in order if k[0] == "CONTROL"), None)
    floor = None
    if control:
        got = [a for a in (acc_of(control, "up"), acc_of(control, "down")) if a is not None]
        floor = max(got) if got else None

    out = []
    if control:
        up, down = cells[control].get("up"), cells[control].get("down")
        out.append(
            "**Control** (same host, same libraries, same window count, "
            "no user traffic in the active windows): "
            f"up {up[2] if up else '-'}, down {down[2] if down else '-'}, "
            f"throughput ratio {ratios[control]}x. "
            "Nothing existed to detect, so that is this run's floor."
        )
        out.append("")

    out.append("| tier | carrier | up | down | best separator (down) | ACTIVE/IDLE |")
    out.append("|---|---|---|---|---|---|")
    for key in order:
        if key[0] == "CONTROL":
            continue
        tier, carrier = key
        if "failed" in cells[key]:
            out.append(f"| {tier} | {carrier} | - | - | {cells[key]['failed']} | - |")
            continue
        up, down = cells[key].get("up"), cells[key].get("down")

        def fmt(got):
            if not got:
                return "-"
            flows, _sep, acc = got
            # Two floors apply and the cell has to clear BOTH: the run's own
            # measured control (real conditions, but at the control's sample
            # size) and the estimator's floor at THIS cell's sample size. Using
            # the control alone certifies a sparse cell against too low a bar.
            bar = noise_floor(int(flows))
            if floor is not None:
                bar = max(bar, floor)
            mark = " (at floor)" if float(acc) <= bar + FLOOR_SLACK else ""
            return f"{acc} ({flows} flows){mark}"

        sep = down[1] if down else (up[1] if up else "-")
        out.append(
            f"| {tier} | {carrier} | {fmt(up)} | {fmt(down)} | `{sep}` | {ratios[key]}x |"
        )

    out.append("")
    if floor is not None:
        out.append(
            f"Read every cell against two floors. This run's control scored {floor:.3f} "
            "with nothing to find; separately, the estimator maximises over 14 features "
            "and so scores above 0.5 on any data at all - 0.681 at 16 flows per class, "
            "0.552 at 150. A cell is marked *(at floor)* when it clears neither, which "
            "means it is indistinguishable from no signal at its own sample size."
        )
    else:
        out.append(
            "No control row in this run, so cells are marked against the estimator's "
            "floor for their sample size only (0.681 at 16 flows per class, 0.552 at "
            "150). Run the matrix with its NULL CONTROL cell for a measured floor."
        )
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
