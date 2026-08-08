#!/bin/bash
# Censor-vantage ACTIVE vs IDLE measurement on a real paced tunnel.
#
# usage: WIN=20 PAIRS=8 scripts/wire-auc/run.sh <run-dir>
#        <run-dir> comes from newrun.sh, which prints it as its last line.
#
# A relay sits between a real mirage-client and a real mirage-bridge and logs
# every TLS record that crosses, by direction, with a timestamp - the observable a
# DPI box has. Windows alternate in MATCHED PAIRS with a randomised order inside
# each pair, the way scripts/podman-e2e/cover-traffic.sh does it, so a slow drift
# in the environment cannot correlate with the label and be learned instead of
# activity.
#
# THREE PROPERTIES THIS SCRIPT EXISTS TO HOLD, each learned by losing data:
#
# 1. NOTHING IS EVER DELETED. The previous version wrote to fixed paths beside
#    itself and `rm -f`'d them at startup, so every run destroyed the evidence of
#    the one before it and claims were made from runs whose logs no longer
#    existed. Everything now lands in the run directory, which newrun.sh created
#    and which nothing here removes.
#
# 2. CARRIER STATE NEVER ABORTS THE RUN. It used to `exit 1` on a failed probe,
#    which discarded three otherwise-complete captures. A tunnel that drops is
#    DATA - it is the outage behaviour under study - so an outage is timestamped,
#    reconnection is attempted with bounded backoff, and the run continues to its
#    wall-clock deadline. Windows overlapping an outage are TAGGED, not dropped.
#    A run with three outages that completes is worth more than ten clean runs.
#
# 3. PHASE DURATION DOES NOT DEPEND ON PAYLOAD. The active phase used to loop
#    curl until a deadline, so a single hung request could overrun the window by
#    its whole timeout and make the active class systematically longer than the
#    idle one - a difference a classifier can learn that has nothing to do with
#    activity. The load generator now runs as a child that is HARD-KILLED at the
#    boundary; the phase is `sleep $WIN` and nothing else.
#
# And the thing all three serve: OFFERED LOAD IS RECORDED, not assumed. Intended
# load is not evidence. If the generator stalls or dies mid-phase, an "active"
# window is quietly part idle, every downstream number is computed over a
# mislabelled class, and nothing in the analysis can tell. Each request appends to
# offered.tsv; the analysis asserts every active window carries bytes.
set -uo pipefail
E="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$E/../.." && pwd)"
R="$ROOT/target/release"
WIN="${WIN:-20}"
PAIRS="${PAIRS:-8}"
D="${1:?need a run dir - make one with newrun.sh}"
[ -f "$D/manifest.json" ] || { echo "no manifest in $D - not a run dir"; exit 2; }

now() { python3 -c 'import time;print(f"{time.monotonic():.6f}")'; }

# The binary that is about to run must be the one the manifest recorded.
#
# The manifest carried a build hash from the start, and nothing ever compared it
# to anything - which made it documentation rather than enforcement. A rebuild
# between `newrun.sh` and here silently produces a capture attributed to the
# wrong code, and that is invisible afterwards precisely because the manifest
# looks complete.
RECORDED="$(python3 -c "
import json;print(json.load(open('$D/manifest.json'))['build']['mirage_client_sha256'] or '')")"
ACTUAL="$(sha256sum "$R/mirage-client" 2>/dev/null | cut -d' ' -f1)"
if [ -z "$ACTUAL" ]; then
  echo "FATAL: $R/mirage-client is missing - build it before capturing"; exit 2
fi
if [ "$RECORDED" != "$ACTUAL" ]; then
  echo "FATAL: mirage-client was rebuilt after this run dir was created."
  echo "  manifest: ${RECORDED:-<none>}"
  echo "  on disk : $ACTUAL"
  echo "  A capture attributed to the wrong build is worse than no capture."
  echo "  Start a fresh run with newrun.sh."
  exit 2
fi
echo "build hash verified against manifest"

# The ports must be FREE before anything starts.
#
# A stale bridge left over from an earlier run holds 18443, the relay cannot bind,
# and the client connects straight to the stale bridge instead. The tunnel then
# works perfectly - real bytes, real phases, a complete manifest, a stable clock,
# zero outages - while the observer is attached to nothing and records.tsv stays
# empty. Every other guard passes. This is the worst failure shape in the harness:
# a capture that looks healthy in every respect except that it measured nothing.
#
# It became reachable when pattern-killing was removed: `pkill -f mirage-bridge`
# was a hazard that could kill an operator's editor, but it did clear stale
# processes. Replacing it with pid tracking traded a loud danger for a silent one,
# so the silence is closed here explicitly.
for p in 18443 18444 1080 18080; do
  if ss -ltn 2>/dev/null | grep -q "127.0.0.1:$p "; then
    echo "FATAL: 127.0.0.1:$p is already in use before this run started."
    echo "  A leftover process on this port makes the capture measure the WRONG"
    echo "  endpoints - usually silently, with a tunnel that works and a relay"
    echo "  that sees nothing. Stop it and re-run."
    echo "  Holder:"
    ss -ltnp 2>/dev/null | grep "127.0.0.1:$p " | sed 's/^/    /'
    exit 2
  fi
done

# Kill ONLY what this script started, by pid.
#
# `pkill -f mirage-client` matches any process whose command line merely mentions
# the string - a wrapper script, an editor, a shell that ran sha256sum on the
# binary. It killed this script's own parent during testing. Pattern-killing by a
# substring that appears in ordinary command lines is not a cleanup, it is a
# grenade; the harness knows the pids it spawned, so it uses them.
ORIGIN_PID=""; BRIDGE_PID=""; CLIENT_PID=""; RELAY_PID=""; LOADPID=""
kill_pid() { [ -n "${1:-}" ] && kill -0 "$1" 2>/dev/null && kill "${2:--TERM}" "$1" 2>/dev/null; }

# Signal, wait for the process to actually go, then escalate.
#
# A signal sent is not a process gone. `kill -INT` on the relay's
# `asyncio.serve_forever` is not promptly honoured, so it kept LISTENING for
# seconds after the run ended and the next run refused to start because its port
# was taken. Waiting on the pid rather than on a fixed `sleep` is the difference
# between a cleanup that works and one that usually works.
reap() { # pid, first-signal
  local pid="${1:-}" sig="${2:--TERM}" i
  [ -n "$pid" ] || return 0
  kill "$sig" "$pid" 2>/dev/null || return 0
  for i in $(seq 1 30); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.2
  done
  kill -9 "$pid" 2>/dev/null
  for i in $(seq 1 10); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.2
  done
}

# Everything below writes into $D. Nothing is removed.
: > "$D/marks.tsv"
: > "$D/offered.tsv"
: > "$D/carrier.tsv"
printf 'phase\tstart_mono\tstop_mono\tcarrier_down\n' >> "$D/marks.tsv"
printf 'phase_idx\tt_start\tt_end\tbytes\tcurl_exit\n' >> "$D/offered.tsv"
printf 'event\tt_mono\tdetail\n' >> "$D/carrier.tsv"

cleanup() {
  kill_pid "$LOADPID" -9
  reap "$RELAY_PID" -INT        # -INT so relay.py flushes records.tsv, then escalate
  reap "$BRIDGE_PID"; reap "$CLIENT_PID"; reap "$ORIGIN_PID"
}
trap cleanup EXIT

python3 -c "
import http.server, socketserver
P=b'MIRAGE'*8000
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(s):
        s.send_response(200); s.send_header('Content-Length',str(len(P))); s.end_headers(); s.wfile.write(P)
    def log_message(s,*a): pass
socketserver.TCPServer.allow_reuse_address=True
socketserver.TCPServer(('127.0.0.1',18080),H).serve_forever()" > "$D/origin.log" 2>&1 &
ORIGIN_PID=$!

start_bridge() {
  RUST_LOG=warn "$R/mirage-bridge" "$D/bridge.json" >> "$D/bridge.log" 2>&1 &
  BRIDGE_PID=$!
  for _ in $(seq 1 30); do ss -ltn 2>/dev/null | grep -q 18444 && return 0; sleep 1; done
  return 1
}
start_client() {
  RUST_LOG=warn "$R/mirage-client" "$D/client.json" >> "$D/client.log" 2>&1 &
  CLIENT_PID=$!
  for _ in $(seq 1 30); do ss -ltn 2>/dev/null | grep -q ":1080" && return 0; sleep 1; done
  return 1
}

# The bridge profiles its Reality cover flight before binding; do not race it.
if ! start_bridge; then
  echo "BRIDGE NEVER BOUND"; tail -n 5 "$D/bridge.log"
  printf 'fatal\t%s\tbridge never bound\n' "$(now)" >> "$D/carrier.tsv"
  exit 1
fi

python3 "$E/relay.py" 18443 18444 "$D/records.tsv" > "$D/relay.log" 2>&1 &
RELAY_PID=$!
sleep 1
# And the relay must actually be LISTENING, not merely spawned. `&` reports that a
# process started, never that it bound; the observer failing to attach is exactly
# the case that produces a healthy-looking capture of nothing.
if ! kill -0 "$RELAY_PID" 2>/dev/null || ! ss -ltn 2>/dev/null | grep -q "127.0.0.1:18443 "; then
  echo "FATAL: the relay did not bind 18443 - nothing would be observed."
  tail -n 3 "$D/relay.log"
  exit 2
fi
echo "relay attached on 18443 -> 18444"
start_client || echo "  client slow to bind; continuing anyway"

# A health check, not a load request. It was sharing the load generator's 25 s
# timeout, which made every failed probe cost 25 s - and with four reconnect
# attempts behind it, a single outage cost ~115 s of wall clock. "Bounded
# backoff" bounded the ATTEMPT COUNT and not the TIME, so a run with outages ran
# far past its planned duration: the opposite of continuing to a wall-clock
# deadline. The fixture found this on its first execution.
PROBE_TIMEOUT="${PROBE_TIMEOUT:-5}"
probe() {
  curl -s --socks5-hostname 127.0.0.1:1080 -o /dev/null \
    -m "$PROBE_TIMEOUT" http://127.0.0.1:18080/
}

# An initial failure is an outage like any other, not a reason to refuse to
# measure. It is recorded and the run proceeds - a capture that begins with the
# carrier down and recovers is a legitimate observation of exactly the behaviour
# this harness exists to characterise.
if probe; then
  printf 'up\t%s\tinitial probe\n' "$(now)" >> "$D/carrier.tsv"
  echo "tunnel up; measuring $PAIRS pairs x ${WIN}s"
else
  printf 'down\t%s\tinitial probe failed\n' "$(now)" >> "$D/carrier.tsv"
  echo "TUNNEL DOWN at start - recording the outage and continuing to the deadline"
  tail -n 4 "$D/client.log"; tail -n 4 "$D/bridge.log"
fi

# Bounded backoff, capped attempts, every transition timestamped. Bounded because
# an unbounded retry loop inside a fixed-length phase silently converts an active
# window into a window of retries.
# Bounded in BOTH attempts and wall clock. The second bound is the load-bearing
# one: recovery time is unbounded in principle, and a run whose length depends on
# how badly the carrier misbehaved is no longer a fixed-duration experiment. When
# the budget runs out the outage is recorded as ongoing and the run moves on -
# the windows are already tagged, so a persistent outage becomes data rather than
# an ever-growing delay.
BACKOFF_MAX=4
RECONNECT_BUDGET="${RECONNECT_BUDGET:-30}"
reconnect() {
  local why="$1" delay=1 i started
  started="$(now)"
  printf 'down\t%s\t%s\n' "$started" "$why" >> "$D/carrier.tsv"
  for i in $(seq 1 "$BACKOFF_MAX"); do
    # Fail CLOSED: an unresolvable elapsed time counts as budget exhausted. The
    # natural spelling (`[ "$(...)" = 1 ]`) treats a failed substitution as "not
    # over budget" and retries forever - the same empty-string-matches-nothing
    # shape as the ephemeral-path check and the comment parser.
    OVER="$(python3 -c "print(1 if $(now) - $started > $RECONNECT_BUDGET else 0)" 2>/dev/null)"
    if [ "${OVER:-1}" = 1 ]; then
      printf 'still_down\t%s\treconnect budget %ss exhausted after %d attempt(s)\n' \
        "$(now)" "$RECONNECT_BUDGET" "$i" >> "$D/carrier.tsv"
      return 1
    fi
    sleep "$delay"
    kill -0 "$BRIDGE_PID" 2>/dev/null || start_bridge
    kill -0 "$CLIENT_PID" 2>/dev/null || start_client
    if probe; then
      printf 'up\t%s\trecovered after %d attempt(s)\n' "$(now)" "$i" >> "$D/carrier.tsv"
      return 0
    fi
    delay=$((delay * 2))
  done
  printf 'still_down\t%s\tgave up after %d attempts\n' "$(now)" "$BACKOFF_MAX" >> "$D/carrier.tsv"
  return 1
}

# The load generator. Runs as a CHILD so the parent can kill it exactly on the
# window boundary; it never decides when the phase ends. Every request appends
# its own byte count, so a phase that produced no load is visible as such rather
# than being indistinguishable from an idle one.
load_loop() {
  local idx="$1"
  while :; do
    local t0 b rc
    t0="$(now)"
    b="$(curl -s --socks5-hostname 127.0.0.1:1080 -m 25 -o /dev/null \
           -w '%{size_download}' http://127.0.0.1:18080/ 2>/dev/null)"
    rc=$?
    printf '%s\t%s\t%s\t%s\t%s\n' "$idx" "$t0" "$(now)" "${b:-0}" "$rc" >> "$D/offered.tsv"
  done
}

PHASE_IDX=0
for i in $(seq 1 "$PAIRS"); do
  if [ $((RANDOM % 2)) -eq 0 ]; then ORDER="idle active"; else ORDER="active idle"; fi
  for phase in $ORDER; do
    PHASE_IDX=$((PHASE_IDX + 1))
    START="$(now)"
    DOWN=0

    if [ "$phase" = active ]; then
      load_loop "$PHASE_IDX" &
      LOADPID=$!
      # The window is the clock, not the load. Hard-kill at the boundary so the
      # phase is exactly WIN seconds whatever the requests were doing.
      sleep "$WIN"
      kill -9 "$LOADPID" 2>/dev/null
      wait "$LOADPID" 2>/dev/null
      LOADPID=""
      # Did any load actually land? A zero here means the window is labelled
      # active and is not.
      if ! awk -F'\t' -v p="$PHASE_IDX" '$1==p && $4+0>0 {f=1} END{exit !f}' "$D/offered.tsv"; then
        DOWN=1
        printf 'no_load\t%s\tphase %d offered zero bytes\n' "$START" "$PHASE_IDX" >> "$D/carrier.tsv"
      fi
    else
      sleep "$WIN"
    fi

    STOP="$(now)"
    # Check carrier health AFTER the window rather than during it: probing mid
    # window would itself put traffic on the wire and contaminate an idle phase
    # with the measurement of whether it is idle.
    if ! probe; then
      DOWN=1
      reconnect "post-phase probe failed (phase $PHASE_IDX)" || true
    fi
    printf '%s\t%s\t%s\t%s\n' "$phase" "$START" "$STOP" "$DOWN" >> "$D/marks.tsv"
  done
  echo "  pair $i/$PAIRS"
done

reap "$RELAY_PID" -INT
RELAY_PID=""

# Close the run: re-sample the clock and assert the offset held.
#
# This lived in newrun.sh as a function that was DEFINED AND NEVER CALLED - a
# guard written, hand-checked once in isolation, and never wired to anything. It
# would have stayed silent forever, and the absence of `offset_at_end` in a
# manifest looks exactly like a manifest that is simply complete. It belongs
# here, at the point the run actually ends, and the self-test asserts it ran.
#
# The offset is ~1.79e9 s - an epoch-origin mismatch (monotonic-since-boot vs
# wall-clock-since-1970), not drift. A fixed offset joins cleanly, but the two
# timelines still diverge under NTP correction, so an offset sampled only at the
# start is right at the start of a long run and wrong at the end.
python3 - "$D" <<'PYEOF'
import json, sys, time, os
d = sys.argv[1]
mp = os.path.join(d, "manifest.json")
m = json.load(open(mp))
mono, wall = time.monotonic(), time.time()
end_off = wall - mono
start_off = m["clock"]["offset_wall_minus_monotonic"]
drift = abs(end_off - start_off)
m["clock"]["offset_at_end"] = end_off
m["clock"]["offset_drift_secs"] = drift
# 50 ms: far above scheduler noise, far below anything that would misattribute a
# window. If NTP stepped mid-run, the join is not safe and the run is not usable.
m["clock"]["offset_stable"] = drift < 0.050
m["complete"] = True
json.dump(m, open(mp, "w"), indent=2)
print(f"  clock offset drift over run: {drift*1000:.1f} ms "
      f"({'stable' if drift < 0.050 else 'UNSTABLE - do not join timelines'})")
PYEOF

# Does this capture mean what it appears to mean? A run can pass every structural
# guard and still have observed nothing.
python3 "$E/check_capture.py" "$D" | sed 's/^/  /'
CAPTURE_OK=${PIPESTATUS[0]}

REC=$(wc -l < "$D/records.tsv" 2>/dev/null || echo 0)
OUT=$(grep -c '^down' "$D/carrier.tsv" 2>/dev/null || echo 0)
TAG=$(awk -F'\t' 'NR>1 && $4==1' "$D/marks.tsv" 2>/dev/null | wc -l)
echo "records: $REC   outages: $OUT   windows tagged carrier_down: $TAG"
echo "run completed to its deadline; nothing discarded"
# Exit non-zero on an unusable capture. Completing and being usable are different
# claims, and the run must not report success for a capture the analysis would
# have to refuse - the whole point is that a clean-looking run of nothing is the
# failure that survives review.
exit "$CAPTURE_OK"
