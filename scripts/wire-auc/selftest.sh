#!/bin/bash
# Exercise the WHOLE capture path against a synthetic fixture. No network.
#
# usage: scripts/wire-auc/selftest.sh
#
# WHY THIS EXISTS
#
# The harness was "structurally verified" - syntax checked, guards tested one at a
# time, by hand, on a machine whose state was then wiped. That is not the same as
# knowing it runs. The distinction matters because the next real capture is
# expensive, gates everything downstream, and produces an artifact that gets
# inherited for months: discovering a capture-path defect AFTER holding the
# recording is the worst possible ordering.
#
# So this builds a complete fixture from nothing - a hand-written trace library, a
# loopback origin, keygen'd configs, no cover host and no outbound traffic - runs
# newrun.sh and run.sh end to end, and asserts every artifact the analysis depends
# on actually appeared and is well formed.
#
# It is deliberately fast and small (2 pairs x 3 s). It is not a measurement and
# its AUCs would be meaningless; it answers "does the capture path work", which is
# a different question and the one that has never been answered.
set -uo pipefail
E="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$E/../.." && pwd)"
R="$ROOT/target/release"

FIX="$(mktemp -d -t mirage-selftest-XXXXXX)"
# Reap anything still holding this fixture's paths, then remove it.
#
# A run that exits at the port check has no pids recorded, so its trap cleans
# nothing - and one leaked relay or bridge then poisons every subsequent run by
# holding a port. Matching on $FIX (a fresh mktemp path that appears in no other
# process's command line) is specific enough to be safe, unlike `pkill -f
# mirage-client`, which matches any command line that merely mentions the string.
cleanup() {
  pkill -f "$FIX" 2>/dev/null
  sleep 1
  [ "${KEEP_FIXTURE:-0}" = 1 ] && { echo "kept: $FIX"; return; }
  rm -rf "$FIX"
}
trap cleanup EXIT

FAIL=0
ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=1; }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }

echo "fixture: $FIX"
for b in mirage-keygen mirage-bridge mirage-client; do
  [ -x "$R/$b" ] || { echo "missing $R/$b - cargo build --release first"; exit 2; }
done

# --- 1. a hand-written trace library -----------------------------------------
#
# Three chained traces with provenance headers, written by hand rather than
# recorded: the point is to remove the network dependency, and a synthetic
# envelope exercises the same code path a real one does. Dense enough upstream to
# carry a Noise handshake (see MIN_UPSTREAM_TOKENS_PER_SEC) - a sparse fixture
# would fail for a reason that has nothing to do with the harness.
LIB="$FIX/lib/browse"; mkdir -p "$LIB"
python3 - "$LIB" <<'PY'
import sys, os
lib = sys.argv[1]
for n in range(3):
    rows, t = [], 0.0
    for i in range(400):
        # alternating up/down with plausible record sizes; ~40 tokens/s each way
        rows.append(f"{t:.6f},{1200 + (i*37) % 300},1")
        t += 0.0125
        rows.append(f"{t:.6f},{80 + (i*13) % 120},-1")
        t += 0.0125
    hdr = (
        "# mirage-cover-trace v1\n"
        "# recorded_at_unix=1754524800\n"
        "# recorded_at=2025-08-07T00:00:00Z\n"
        "# cover_host=selftest.invalid\n"
        "# source_url=https://selftest.invalid/synthetic\n"
        "# http_version=1.1\n"
        "# alpn=none\n"
        "# recorder=selftest-fixture\n"
    )
    open(os.path.join(lib, f"{n}.csv"), "w").write(hdr + "t,size,dir\n" + "\n".join(rows) + "\n")
print(f"  wrote 3 synthetic traces")
PY

# --- 2. configs, with no cover host and nothing outbound ---------------------
CFG="$FIX/cfg"; mkdir -p "$CFG"
"$R/mirage-keygen" --bridge-endpoint 127.0.0.1:18443 \
  --write-bridge-config "$CFG/bridge.json" \
  --write-client-config "$CFG/client.json" >/dev/null 2>&1 \
  || { echo "keygen failed"; exit 2; }

python3 - "$CFG" "$LIB" <<'PY'
import json, sys
cfg, lib = sys.argv[1], sys.argv[2]
for name in ("bridge.json", "client.json"):
    p = f"{cfg}/{name}"
    d = json.load(open(p))
    # Replay pacing on both ends - a mismatch HANGS the session rather than
    # degrading, so the fixture would fail confusingly if only one end paced.
    d["proteus"] = "replay"
    d["proteus_profile"] = lib
    # No Reality, so no cover host and no outbound TLS. The pacer's per-host
    # lookup is therefore NoCoverHost, not Generic - the fixture must not trip
    # the pinned-library refusal, which is about a MISMATCH, not about pacing
    # without a claimed host.
    d.pop("reality_enabled", None)
    d.pop("reality_sni", None)
    d.pop("reality_cover_addr", None)
    # The client REFUSES a raw-TCP carrier without an obfuscated transport,
    # because its magic is a cleartext censor signature. That refusal is correct
    # and must not be weakened; the fixture opts out explicitly because it runs
    # entirely on loopback with nothing on the wire to censor.
    #
    # Consequence to keep straight: what the relay records here are carrier
    # FRAMES, not TLS records. The fixture asserts the capture PATH produces its
    # artifacts - it is not a measurement, and its numbers mean nothing.
    d["allow_insecure_raw"] = True
    json.dump(d, open(p, "w"), indent=2)
print("  configs written (loopback raw carrier, no cover host, replay both ends)")
PY

# The bridge listens where the relay forwards, and must be allowed to reach the
# loopback origin. `allow_loopback_targets` defaults to FALSE - correct for a real
# bridge, where forwarding to 127.0.0.1 turns it into a probe of its own host, and
# fatal for a fixture whose whole point is that nothing leaves the machine. Named
# here rather than discovered from a hang.
python3 - "$CFG" <<'PY'
import json, sys
p = f"{sys.argv[1]}/bridge.json"
d = json.load(open(p))
d["bind"] = "127.0.0.1:18444"
d["allow_loopback_targets"] = True
# `mux_enabled` defaults TRUE and classifies each connection by first bytes to
# pick a transport. The fixture's carrier is raw, which matches no transport, so
# the mux proxies it to the cover destination and the handshake dies as
# `early eof` - a failure that reads like a broken tunnel rather than a config
# mismatch. Off here because the fixture deliberately runs one bare carrier.
d["mux_enabled"] = False
json.dump(d, open(p, "w"), indent=2)
print("  bridge: bind 18444, loopback allowed, mux off (fixture runs a bare carrier)")
PY

# --- 3. the real scripts, end to end -----------------------------------------
echo "--- newrun.sh ---"
RUNROOT="$FIX/runs"
D="$(ALLOW_EPHEMERAL_RUNS=1 bash "$E/newrun.sh" "$CFG" "$RUNROOT" 2>&1 | tail -1)"
if [ ! -d "$D" ]; then
  echo "newrun.sh did not produce a run dir"; exit 1
fi
echo "--- run.sh (2 pairs x 3s) ---"
WIN=3 PAIRS=2 bash "$E/run.sh" "$D" 2>&1 | sed 's/^/  /'

# --- 4. assertions on the artifacts the analysis depends on ------------------
echo "--- artifacts ---"
check "manifest exists"           "[ -s '$D/manifest.json' ]"
check "configs snapshotted"       "[ -s '$D/client.json' ] && [ -s '$D/bridge.json' ]"
check "marks.tsv has 4 phases"    "[ \$(tail -n +2 '$D/marks.tsv' | wc -l) -eq 4 ]"
check "both classes present"      "tail -n +2 '$D/marks.tsv' | cut -f1 | sort -u | tr '\n' ' ' | grep -q 'active idle'"
check "carrier.tsv written"       "[ -s '$D/carrier.tsv' ]"
check "offered.tsv written"       "[ -s '$D/offered.tsv' ]"
check "records.tsv non-empty"     "[ -s '$D/records.tsv' ]"
check "client log kept"           "[ -f '$D/client.log' ]"
check "bridge log kept"           "[ -f '$D/bridge.log' ]"

# Phase duration must not depend on payload: every window within 25% of WIN.
check "phases are clock-bound" "awk -F'\t' 'NR>1{d=\$3-\$2; if(d<2.25||d>3.75) bad=1} END{exit bad}' '$D/marks.tsv'"

# The manifest must carry an attributable branch rather than a guess.
check "manifest records branch" \
  "python3 -c \"import json;b=json.load(open('$D/manifest.json'))['trace'].get('branch');assert b,'no branch';print()\" >/dev/null 2>&1"

# The clock guard must have closed the run.
check "clock offset re-sampled" \
  "python3 -c \"import json;c=json.load(open('$D/manifest.json'))['clock'];assert 'offset_at_end' in c\" >/dev/null 2>&1"

# The build gate must reject a tampered manifest - the check that turns a
# recorded hash into an enforced one.
echo "--- refusals ---"
python3 - "$D" <<'PY'
import json, sys
p = f"{sys.argv[1]}/manifest.json"
m = json.load(open(p)); m["build"]["mirage_client_sha256"] = "0" * 64
json.dump(m, open(p, "w"), indent=2)
PY
if WIN=1 PAIRS=1 bash "$E/run.sh" "$D" >/dev/null 2>&1; then
  bad "run.sh accepts a manifest whose build hash does not match"
else
  ok "run.sh refuses a mismatched build hash"
fi

# And newrun.sh must refuse an ephemeral root when NOT explicitly opted in.
if bash "$E/newrun.sh" "$CFG" "$FIX/nope" >/dev/null 2>&1; then
  bad "newrun.sh accepts an ephemeral runs-root without opt-in"
else
  ok "newrun.sh refuses an ephemeral runs-root"
fi

# --- 5. NEGATIVE tests: the refusals must actually fire ----------------------
#
# A fixture that only exercises the happy path is one notch short, which is the
# shape every defect this session has taken. Defect 3 in particular LOOKED like a
# happy path: green guards, real transfers, complete manifest, and no wire
# observations. So each refusal is driven with input that should trigger it.
echo "--- negative tests ---"
NEG="$FIX/neg"; mkdir -p "$NEG"

mkneg() { # $1=name; builds a minimal, VALID run dir then lets the caller break it
  rm -rf "$NEG/$1"; mkdir -p "$NEG/$1"
  python3 - "$NEG/$1" <<'PY'
import json, sys
d = sys.argv[1]
json.dump({
    "clock": {"offset_wall_minus_monotonic": 0.0, "offset_at_end": 0.0,
              "offset_drift_secs": 0.0, "offset_stable": True},
    "build": {"mirage_client_sha256": "x"},
    "trace": {"branch": "GENERIC"},
    "complete": True,
}, open(f"{d}/manifest.json", "w"))
open(f"{d}/marks.tsv", "w").write(
    "phase\tstart\tstop\tdown\nactive\t0.0\t10.0\t0\nidle\t10.0\t20.0\t0\n")
open(f"{d}/offered.tsv", "w").write(
    "phase_idx\tt_start\tt_end\tbytes\tcurl_exit\n1\t0.0\t1.0\t48000\t0\n")
open(f"{d}/records.tsv", "w").write("".join(f"{i*0.1}\t1\t1200\n" for i in range(200)))
PY
}
neg() { # $1=label; $2=dir - must be REFUSED
  if python3 "$E/check_capture.py" "$2" >/dev/null 2>&1; then
    bad "$1 (accepted a capture it should refuse)"
  else
    ok "$1"
  fi
}

# POSITIVE CONTROL. Do not remove it as redundant - it is the only test here that
# can fail if `check_capture.py` becomes broken in the direction of refusing too
# much. A script that refused EVERY capture would pass all seven negative tests
# below, report seven greens, and quietly make the harness unusable. Every one of
# those tests asserts a refusal; this is the only one that asserts an acceptance.
mkneg baseline
if python3 "$E/check_capture.py" "$NEG/baseline" >/dev/null 2>&1; then
  ok "a well-formed capture is accepted (no false refusal)"
else
  bad "a well-formed capture is accepted (no false refusal)"
  python3 "$E/check_capture.py" "$NEG/baseline" | sed 's/^/       /'
fi

# The observer saw (almost) nothing - defect 3's partial-failure twin, which no
# startup liveness check can catch because at startup everything was fine.
mkneg blind; : > "$NEG/blind/records.tsv"
neg "refuses a capture with no wire observations" "$NEG/blind"

mkneg sparse
python3 -c "open('$NEG/sparse/records.tsv','w').write(''.join(f'{i*0.1}\t1\t1200\n' for i in range(5)))"
neg "refuses an implausibly low record rate" "$NEG/sparse"

# An ACTIVE window that offered nothing is labelled active and was idle.
mkneg noload
python3 -c "open('$NEG/noload/offered.tsv','w').write('phase_idx\tt_start\tt_end\tbytes\tcurl_exit\n')"
neg "refuses an active window with zero offered load" "$NEG/noload"

# The guard that never ran. Absence of the field reads exactly like a complete
# manifest, which is how it went unnoticed for two rounds.
mkneg noclock
python3 -c "
import json;p='$NEG/noclock/manifest.json';m=json.load(open(p));del m['clock']['offset_at_end'];json.dump(m,open(p,'w'))"
neg "refuses a manifest whose clock guard never ran" "$NEG/noclock"

mkneg unattr
python3 -c "
import json;p='$NEG/unattr/manifest.json';m=json.load(open(p));m['trace']['branch']='UNKNOWN';json.dump(m,open(p,'w'))"
neg "refuses a capture with an unattributable shaping branch" "$NEG/unattr"

mkneg incomplete
python3 -c "
import json;p='$NEG/incomplete/manifest.json';m=json.load(open(p));m['complete']=False;json.dump(m,open(p,'w'))"
neg "refuses a run that did not finish" "$NEG/incomplete"

# And the port guard: occupy the relay's port, then assert run.sh refuses rather
# than running a capture whose observer cannot attach. This is defect 3 exactly.
# The setup must be VERIFIED, not assumed. On the first attempt the squatter
# could not bind - the capture's own relay had not released the port yet - so
# run.sh refused for a different reason and the test passed without ever creating
# the condition it claims to test. A negative test that passes because its setup
# failed is worse than no test: it reports coverage it does not have.
for _ in $(seq 1 20); do
  ss -ltn 2>/dev/null | grep -q "127.0.0.1:18443 " || break
  sleep 1
done
python3 -c "
import socket,time,sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
try:
    s.bind(('127.0.0.1',18443)); s.listen(1)
except OSError as e:
    print(f'squat-failed: {e}'); sys.exit(1)
print('squat-bound', flush=True); time.sleep(25)" > "$FIX/squat.log" 2>&1 &
SQUAT=$!
sleep 2
if ! grep -q squat-bound "$FIX/squat.log" 2>/dev/null; then
  bad "port-guard test SETUP failed - could not occupy 18443, so nothing was tested"
  cat "$FIX/squat.log" | sed 's/^/       /'
else
  if WIN=1 PAIRS=1 bash "$E/run.sh" "$D" >/dev/null 2>&1; then
    bad "run.sh runs a capture while the relay's port is taken"
  else
    ok "run.sh refuses when the observer's port is already held"
  fi
fi
kill "$SQUAT" 2>/dev/null

echo
if [ "$FAIL" -eq 0 ]; then
  echo "capture path OK - every artifact the analysis reads was produced"
else
  echo "capture path BROKEN - do not spend a real capture on this harness"
fi
exit "$FAIL"
