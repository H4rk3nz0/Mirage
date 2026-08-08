#!/usr/bin/env python3
"""Refuse a capture that cannot mean what it appears to mean.

    check_capture.py <run-dir>            -> exit 0 usable, 1 refused, 2 unreadable

WHY THIS EXISTS

A capture can pass every structural guard and still have observed nothing. It
happened: a stale process held the relay's port, the relay could not bind, the
client connected straight to the leftover bridge, and the run produced real byte
transfers, clock-bound phases, a stable clock, zero outages and a complete
manifest - with an empty records.tsv. Every green check was truthful. The
observer was simply attached to nothing.

`run.sh` now asserts the ports are free and the relay is LISTENING, which closes
that exact path. This closes the shape of it: PARTIAL observer failure, where the
relay binds, records something, and then stops - a case no liveness check at
startup can see, because at startup everything was fine.

The rule is a floor, not a model. Under Proteus the carrier emits continuously by
construction: an idle tunnel is not a quiet one, that is the entire premise. So a
window of wall-clock time with almost no records in it is not a quiet network, it
is a broken observer, and the run should say so rather than hand a near-empty
matrix to a classifier that will happily score it.
"""
import json
import os
import sys

# Records per second of measured window time, below which the observer is assumed
# broken rather than the wire assumed quiet. Deliberately far under what pacing
# actually produces (the self-test fixture yields ~29/s over its windows) so this
# fires on failure, never on a merely sparse envelope.
MIN_RECORDS_PER_SEC = float(os.environ.get("MIN_RECORDS_PER_SEC", "1.0"))


def fail(msg):
    print(f"REFUSING: {msg}")
    return 1


def main(d):
    def path(n):
        return os.path.join(d, n)

    try:
        manifest = json.load(open(path("manifest.json")))
    except Exception as e:
        print(f"cannot read manifest: {e}")
        return 2

    problems = []

    # --- windows -------------------------------------------------------------
    marks = []
    try:
        for line in open(path("marks.tsv")).read().splitlines()[1:]:
            f = line.split("\t")
            if len(f) >= 4:
                marks.append((f[0], float(f[1]), float(f[2]), f[3] == "1"))
    except Exception as e:
        return fail(f"marks.tsv unreadable ({e}) - the run has no window boundaries")
    if not marks:
        return fail("marks.tsv has no windows - nothing was measured")

    measured_secs = sum(stop - start for _, start, stop, _ in marks)

    # --- observations --------------------------------------------------------
    try:
        n_records = sum(1 for _ in open(path("records.tsv")))
    except Exception:
        n_records = 0

    rate = n_records / measured_secs if measured_secs > 0 else 0.0
    if rate < MIN_RECORDS_PER_SEC:
        problems.append(
            f"only {n_records} records over {measured_secs:.1f}s of windows "
            f"({rate:.2f}/s, floor {MIN_RECORDS_PER_SEC:.2f}/s). Under Proteus the "
            f"carrier emits continuously, so this is an observer that stopped "
            f"seeing the wire, not a quiet network."
        )

    # --- offered load, per ACTIVE window ------------------------------------
    # Intended load is not evidence. An active phase whose generator died is a
    # window labelled active that is actually idle, and every number computed
    # over the two classes is then computed over a mislabelled one.
    offered = {}
    try:
        for line in open(path("offered.tsv")).read().splitlines()[1:]:
            f = line.split("\t")
            if len(f) >= 4:
                offered[f[0]] = offered.get(f[0], 0) + int(float(f[3]))
    except Exception:
        pass

    active_idx = [i + 1 for i, m in enumerate(marks) if m[0] == "active"]
    starved = [i for i in active_idx if offered.get(str(i), 0) <= 0]
    if starved:
        problems.append(
            f"{len(starved)} of {len(active_idx)} ACTIVE windows offered zero bytes "
            f"(phases {starved}) - they are labelled active and were idle."
        )

    # --- the guards that must have RUN ---------------------------------------
    # Absence and success are the same shape for most guards, so their output is
    # asserted rather than their intent. `finalise_run` was defined and never
    # called for two rounds; a manifest missing `offset_at_end` looked exactly
    # like a complete one.
    clock = manifest.get("clock", {})
    if "offset_at_end" not in clock:
        problems.append(
            "manifest has no clock.offset_at_end - the end-of-run clock guard "
            "never ran, so the monotonic/wall join is unverified."
        )
    elif not clock.get("offset_stable", False):
        problems.append(
            f"clock offset drifted {clock.get('offset_drift_secs', 0)*1000:.0f} ms "
            f"during the run - do not join the relay and daemon timelines."
        )
    if not manifest.get("complete", False):
        problems.append("manifest is not marked complete - the run did not finish.")

    branch = manifest.get("trace", {}).get("branch")
    if not branch or branch == "UNKNOWN":
        problems.append(
            "manifest does not record which shaping branch was live - the capture "
            "cannot be attributed to target-conditioned or generic cover."
        )

    if problems:
        print("REFUSING: this capture cannot mean what it appears to mean.")
        for p in problems:
            print(f"  - {p}")
        return 1

    down = sum(1 for m in marks if m[3])
    print(
        f"capture usable: {len(marks)} windows, {measured_secs:.1f}s, "
        f"{n_records} records ({rate:.1f}/s), branch={branch}"
        + (f", {down} tagged carrier_down" if down else "")
    )
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
