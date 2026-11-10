#!/usr/bin/env python3
"""Refuse a capture whose gap structure is the DRIVER's, not the traffic's.

    check_driver_artifact.py <out-dir> <host-sub> <window_s> [interval_s] [burst|continuous]

WHY THIS EXISTS, and why it is a check rather than a warning in a document.

The cover-class measurements ask what the silence structure of real traffic looks
like. A driver that acts on a timer writes its own period into that structure, and
the result is indistinguishable from a finding unless someone thinks to look.

It has now happened twice in this project:

  - a video capture that seeked forward every 8 s produced 8 long gaps in 75 s,
    one per seek. Caught by a control, documented, and a warning was written.
  - a browse capture that navigated every ~18 s produced a 12974 ms worst gap.
    Same defect, caught after the fact, by the person who wrote the warning.

The warning existed and did not prevent the second instance. Knowing a rule does
not stop the reach for the convenient pattern, so the harness has to refuse rather
than the operator having to remember.

THE CHECK, and why the obvious version of it does not work.

The first version tried to DETECT contamination: flag any gap within 20% of the
driver's declared interval. It passed both known-bad captures. The browse driver
acted every 18 s but its idle was 12.97 s - interval minus page-load time - so
nothing matched, and a rule keyed to the nominal period cannot know the load time.
Trying to recognise the artifact requires modelling exactly what was not modelled.

So the rules PROHIBIT rather than detect:

  1. A periodic driver invalidates a gap measurement, full stop. If the page
     declares any repeating action, refuse - do not attempt to subtract it. This
     is not detectable in general: HLS shows 8 regularly-spaced ~10 s gaps that
     are the genuine class structure, and a browse timer shows 8 regularly-spaced
     gaps that are the instrument. Spacing alone cannot separate them; only the
     driver knows, so the driver must declare and the harness must refuse.

  2. The trace must span a meaningful fraction of the capture window. The buffered
     capture spanned 0.5 s of a 75 s window - a 30 MB file arriving at 541 Mbps
     and then nothing - and no gap statistic can see that, because within those
     0.5 s the gaps look perfect.

Neither proves a trace is clean. They refuse the two shapes that have actually
fooled this project, which is worth more than another sentence in a document.
"""
import csv
import glob
import os
import statistics as st
import sys


def load_gaps(outdir, host_sub):
    ts = []
    for meta in sorted(glob.glob(f"{outdir}/conn-*.meta")):
        kv = dict(l.split("=", 1) for l in open(meta).read().splitlines() if "=" in l)
        if host_sub not in kv.get("host", ""):
            continue
        c = meta.replace(".meta", ".csv")
        if not os.path.exists(c):
            continue
        rows = list(csv.reader(open(c)))[1:]
        ts += [float(r[0]) for r in rows if len(r) >= 3 and r[2] == "1"]
    ts.sort()
    return ts, [b - a for a, b in zip(ts, ts[1:])]


def main(outdir, host_sub, window, interval, shape="continuous"):
    ts, gaps = load_gaps(outdir, host_sub)
    if len(gaps) < 20:
        print(f"REFUSE: only {len(gaps)} gaps on '{host_sub}' - not a usable trace")
        return 2
    span = ts[-1] - ts[0]
    big = sorted((g for g in gaps if g > 1.0), reverse=True)
    # Deliberately NOT the consumable line. `raw=` is prefixed so no downstream
    # parser can match it by accident; the authoritative figures are emitted once,
    # below, already corrected. parse_stats previously matched a summary printed
    # next to a correction and silently took the uncorrected one - browse entered
    # the cover table at 4967 ms while the corrected 95.6 ms sat two lines lower.
    # One representation, no way to pick the stale one.
    print(f"  raw(pre-correction) span={span:.1f}s gaps={len(gaps)} "
          f"median={st.median(gaps)*1000:.2f}ms max={max(gaps)*1000:.1f}ms >1s={len(big)}")

    # Values a consumer may use. Corrections are applied before this is emitted,
    # and `trimmed=` records that one happened so a reader can tell.
    def emit(g, sp, trimmed=0, untrimmed=None):
        extra = f" trimmed={trimmed}"
        if untrimmed is not None:
            extra += f" untrimmed_max={untrimmed*1000:.1f}ms"
        print(f"  RESULT span={sp:.1f}s gaps={len(g)} median={st.median(g)*1000:.2f}ms "
              f"max={max(g)*1000:.1f}ms >1s={sum(1 for x in g if x > 1.0)}{extra}")

    if interval > 0:
        print(f"REFUSE: the driver acts every {interval}s. A periodic driver writes its own "
              f"period into the gap structure, and that contribution cannot be separated "
              f"from the cover's afterwards - regularly spaced gaps are the genuine "
              f"structure of segmented video and the instrument's signature in a timed "
              f"browse, and they look identical. Drive the class once and stop.")
        return 3

    if shape == "burst":
        # A page load is a burst followed by whatever the browser does afterwards -
        # a beacon, a keepalive, a late straggler. Those later records are real,
        # but the gap BETWEEN the burst and them is a property of how long the
        # capture kept listening, not of the class. Measured: browse reported a
        # 4971 ms worst gap across three reps, which is when recording stopped
        # rather than anything the page did.
        #
        # So report the burst's own gaps, and say how much was trimmed rather than
        # trimming silently. The cut is at the first gap over one second - the
        # point where the page load has demonstrably ended.
        cut = next((i for i, g in enumerate(gaps) if g > 1.0), None)
        if cut is not None:
            burst = gaps[:cut]
            if len(burst) >= 20:
                emit(burst, ts[cut] - ts[0], trimmed=len(gaps) - cut, untrimmed=max(gaps))
                print("  OK: burst class; span rule not applicable.")
                return 0
            else:
                print(f"  burst class: only {len(burst)} gaps before the first >1s gap - "
                      f"burst too short to characterise")
                return 5
        # A page load is a burst by nature: it finishes and the connection goes
        # quiet, and that IS the class. Applying the continuity rule here refused
        # a correct capture (5.6 s of a 30 s window), which is the guard being
        # wrong rather than the trace. Only classes declared continuous - a
        # stream that should still be arriving at the end of the window - are
        # held to it.
        emit(gaps, span)
        print("  OK: burst class; span rule not applicable.")
        return 0

    if span < 0.5 * window:
        print(f"REFUSE: the trace spans {span:.1f}s of a {window:.0f}s capture "
              f"({100*span/window:.1f}%). Whatever it recorded finished early; the class "
              f"was not observed for the window it was measured over.")
        return 4

    emit(gaps, span)
    print("  OK: no gap attributable to driver cadence.")
    return 0


if __name__ == "__main__":
    a = sys.argv[1:]
    if len(a) < 3:
        print(__doc__.strip().splitlines()[2])
        sys.exit(1)
    sys.exit(main(a[0], a[1], float(a[2]),
                  float(a[3]) if len(a) > 3 else 0.0,
                  a[4] if len(a) > 4 else "continuous"))
