#!/bin/bash
# Start a capture run with an intact evidence chain.
#
# WHY THIS EXISTS
#
# The previous harness wrote logs to a fixed path and deleted them at start, so
# each run destroyed the evidence of the one before it. Claims were made from
# runs whose logs no longer existed, and nothing in the analysis path could
# detect that - the analysis only ever sees what survived. That is a different
# class of error from a bad statistic: it produces a confident answer about a
# run you can no longer inspect.
#
# So: every run gets a UUID and its own directory. Nothing is ever deleted or
# overwritten. `feature_alpha` refuses to analyse a capture whose manifest is
# missing or whose checksums do not match.
#
# WHAT THE MANIFEST CARRIES, and why each item is there rather than assumed:
#
#   clock_offset      - the relay and phase marks use CLOCK_MONOTONIC; the
#                       client/bridge logs use wall-clock UTC. Joining window
#                       boundaries onto carrier events needs the offset, and
#                       without it the join silently matches nothing and reads
#                       as "no outages coincided with empty windows". Measured
#                       and recorded, not inferred.
#   build_hash        - a code change between runs is otherwise invisible, and
#                       two runs get compared as if they measured one system.
#   config_sha        - "the pinned run" is unreproducible without the exact
#                       config that produced it.
#   trace_sha + path  - "pinned to one trace" is unverifiable after the fact
#                       unless the trace itself is identified.
#   planned vs actual - phase durations must not depend on payload; asserting
#                       that needs both numbers, not just the intent.
#
# usage: WIN=20 PAIRS=8 scripts/wire-auc/newrun.sh <config-dir> <runs-root>
set -uo pipefail
CFG="$(cd "${1:?need config dir}" && pwd)"
ROOT="${2:?need runs root}"
WIN="${WIN:-20}"
PAIRS="${PAIRS:-8}"
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

# Refuse to put a run somewhere that does not survive.
#
# Every guard in this file assumes the run directory is still there to be
# re-inspected: checksums to re-verify, logs to re-read, a manifest to compare a
# later run against. A whole session's captures were lost to an agent scratchpad
# that is cleared between turns - and nothing detected it, because an analysis
# only ever sees what survived. That is the same failure as the `rm -f` this
# script was written to replace, one layer down: it is not enough for the harness
# to stop deleting evidence if the filesystem underneath deletes it instead.
# Resolved WITHOUT requiring the directory to exist: a runs-root is usually being
# created for the first time, and `cd`-ing to it to canonicalise fails, yielding
# an empty string that matches no pattern and lets an ephemeral path straight
# through. That is a check that passes hardest exactly when it is needed - the
# same fail-open shape as the fallback and the comment parser.
ROOT_ABS="$(python3 -c 'import os,sys;print(os.path.abspath(os.path.expanduser(sys.argv[1])))' "$ROOT" 2>/dev/null)"
if [ -z "$ROOT_ABS" ]; then
  echo "REFUSING: cannot resolve '$ROOT' to an absolute path."
  echo "  A run whose location is unknown cannot be re-opened or verified."
  exit 2
fi
# CI and the self-test fixture legitimately run in a throwaway directory: they
# assert the harness works and then discard everything. That is a DELIBERATE
# choice, spelled out, rather than the silent default that lost a session's
# captures - the same shape as `proteus_generic_cover_ok`.
case "${ALLOW_EPHEMERAL_RUNS:-0}${ROOT_ABS}" in
  1*) ;;
  0/tmp/*|0/var/tmp/*|0/dev/shm/*|0*/scratchpad|0*/scratchpad/*)
    echo "REFUSING: $ROOT_ABS is an ephemeral location."
    echo "  Run directories must outlive the session that made them - every"
    echo "  integrity check here assumes the run can be re-opened later."
    echo "  A whole session's captures were lost this way, and nothing detected"
    echo "  it: an analysis only ever sees what survived."
    echo "  Pass a runs-root on durable storage, or set ALLOW_EPHEMERAL_RUNS=1"
    echo "  if this run is a self-test whose output is meant to be discarded."
    exit 2 ;;
esac
ROOT="$ROOT_ABS"

RUN_ID="$(python3 -c 'import uuid;print(uuid.uuid4())')"
D="$ROOT/$RUN_ID"
mkdir -p "$D" || { echo "cannot create $D"; exit 1; }
echo "run $RUN_ID -> $D"

sha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

# (The run is CLOSED by run.sh, which re-samples the clock and sets
#  clock.offset_at_end / offset_stable / complete. It used to be a function
#  here that nothing ever called.)

TRACE_DIR="$(python3 -c "
import json;print(json.load(open('$CFG/client.json')).get('proteus_profile',''))" )"
TRACE_LIST="$(ls "$TRACE_DIR" 2>/dev/null | tr '\n' ',')"
TRACE_SHA="$(cat "$TRACE_DIR"/*.csv 2>/dev/null | sha256sum | cut -d' ' -f1)"
BUILD_HASH="$(sha "$REPO/target/release/mirage-client")"

# Snapshot the configs INTO the run directory: the originals will be edited.
cp "$CFG/bridge.json" "$CFG/client.json" "$D/" 2>/dev/null

# The clock offset, captured once, at the start, in one process.
python3 - "$D" "$RUN_ID" "$WIN" "$PAIRS" "$TRACE_DIR" "$TRACE_LIST" "$TRACE_SHA" "$BUILD_HASH" <<'PY'
import json, sys, time, os
d, run_id, win, pairs, tdir, tlist, tsha, bhash = sys.argv[1:9]
mono, wall = time.monotonic(), time.time()
json.dump({
    "run_id": run_id,
    "clock": {
        # wall = monotonic + offset. Both timelines can now be joined.
        "monotonic_at_start": mono,
        "wall_at_start": wall,
        "offset_wall_minus_monotonic": wall - mono,
    },
    "planned": {"window_secs": float(win), "pairs": int(pairs)},
    "build": {"mirage_client_sha256": bhash},
    "config": {
        "bridge_sha256": None,
        "client_sha256": None,
    },
    "trace": {"dir": tdir, "files": tlist, "sha256_concat": tsha},
    "phases": [],
    "carrier_events": [],
    "complete": False,
}, open(os.path.join(d, "manifest.json"), "w"), indent=2)
print("  manifest written")
PY

python3 - "$D" <<'PY'
import json, sys, hashlib, os
d = sys.argv[1]
m = json.load(open(os.path.join(d, "manifest.json")))
for k, f in (("bridge_sha256", "bridge.json"), ("client_sha256", "client.json")):
    p = os.path.join(d, f)
    if os.path.exists(p):
        m["config"][k] = hashlib.sha256(open(p, "rb").read()).hexdigest()
json.dump(m, open(os.path.join(d, "manifest.json"), "w"), indent=2)
PY

# RESOLVED config, not the file as written. A snapshot of an under-specified
# config is a faithful record of an ambiguous state: `stream_mux_enabled` was
# absent from the client config and defaulted to true, which silently decided
# that the whole capture ran on ONE carrier - a fact that changed the meaning of
# every number and was invisible in the snapshot.
# Config is POSITIONAL and comes first; `--check-config` after it. Getting this
# backwards writes a usage message into the file and, with `|| true` swallowing
# the exit code, ships a usage error as if it were a resolved config. Verify the
# output is a config summary rather than trusting that the command ran.
"$REPO/target/release/mirage-client" "$D/client.json" --check-config \
  > "$D/resolved-client.txt" 2>&1 || true
"$REPO/target/release/mirage-bridge" "$D/bridge.json" --check-config \
  > "$D/resolved-bridge.txt" 2>&1 || true
for f in resolved-client resolved-bridge; do
  if grep -qi "^usage:" "$D/$f.txt" 2>/dev/null; then
    echo "  WARNING: $f.txt is a usage error, not a resolved config - do not treat it as evidence"
  fi
done

# WHICH trace set the pacer resolved to, not which library root was configured.
#
# Proteus wears `<root>/<cover-host>/` when it exists and silently falls back to
# the generic class when it does not. Recording the configured root alone does
# not distinguish the two, and the fallback is the mode the pacer's own selection
# comment calls separable: every capture taken before this ran GENERIC, and the
# manifest of each one looked complete. The branch is a property of the run, so
# it belongs in the run's manifest.
python3 - "$D" <<'PY'
import json, os, re, sys
d = sys.argv[1]
mp = os.path.join(d, "manifest.json")
m = json.load(open(mp))
txt = ""
try:
    txt = open(os.path.join(d, "resolved-client.txt")).read()
except OSError:
    pass
mo = re.search(r"^\s*shaping:\s*(\S+)", txt, re.M)
branch = mo.group(1) if mo else "UNKNOWN"
m["trace"]["branch"] = branch
m["trace"]["branch_line"] = next(
    (l.strip() for l in txt.splitlines() if l.strip().startswith("shaping:")), None
)
json.dump(m, open(mp, "w"), indent=2)
if branch == "UNKNOWN":
    print("  WARNING: could not determine the shaping branch - the run cannot say whether it")
    print("           wore target-conditioned or generic cover. Treat results as unattributed.")
elif branch == "GENERIC":
    print("  NOTE: shaping branch is GENERIC - the envelope does not match the claimed cover")
    print("        host. Valid to measure, but it is NOT the shippable configuration.")
else:
    print(f"  shaping branch: {branch}")
PY

# Offered load per window, written by the load generator itself. Intended load
# is not evidence: if the generator dies or stalls mid-phase, the active class
# silently becomes partly idle and nothing downstream can tell. The analysis
# asserts this is non-zero across every active window.
: > "$D/offered.tsv"

echo "  run dir prepared; capture writes into $D and never outside it"
echo "$D"
