#!/usr/bin/env bash
# Does Proteus actually hide USER ACTIVITY behind its cover envelope?
#
# The pacer emits one record per schedule token whether or not the app has data,
# so in principle the wire looks the same whether you are idle or downloading.
# That is the whole claim behind "constant cover traffic". This measures it on a
# real cluster, from the censor's vantage point (tcpdump on the carrier), instead
# of trusting the design.
#
#   Phase IDLE   : tunnel up, ZERO user traffic, capture the carrier.
#   Phase ACTIVE : same tunnel, genuine HTTP transfers through the SOCKS proxy.
#
# Then run the project's own learned distinguisher over the two captures. An AUC
# near 0.5 means an observer cannot tell an idle tunnel from a busy one - the
# property the always-on cover posture is supposed to provide. An AUC near 1.0
# means user activity modulates the envelope and the cover is cosmetic.
#
# NEGATIVE CONTROL, run it before trusting any number: `NULL_CONTROL=1` runs the
# identical protocol with no user traffic in the ACTIVE windows. There is nothing
# to detect, so the reported AUC must come back ~0.5. If it does not, the harness
# is measuring its own structure and every separability number it prints is
# inflated by that amount. This is not hypothetical - strict idle/active
# alternation used to put the cover replay's loop position in lockstep with the
# window label (a 38 s trace against a 40 s cycle advances 2 s per cycle), which
# the distinguisher can learn instead of user activity. Windows are randomised
# now; the control is what proves that was enough.
#
# CONFOUND, read before trusting a number: on a paced carrier the envelope is only
# a few hundred kbit/s, so the client's own background maintenance (token refresh,
# bridge probes) is NOT a rounding error on the wire - one refresh is a visible
# burst. Its period is jittered (90-180 s), so a short phase can catch one in IDLE
# and none in ACTIVE, which swamps the activity signal being measured and can even
# invert it (a run showing ACTIVE/IDLE < 1.0 is this, not a miracle). Use phases of
# several minutes so both phases average over the same maintenance, and check
# cap/client.log for how many refreshes landed in each before drawing conclusions.
#
# Usage:  scripts/podman-e2e/cover-traffic.sh <cover-library-dir> [seconds]
set -uo pipefail

LIB="${1:-}"
SECS="${2:-45}"
[ -d "$LIB" ] || { echo "usage: $0 <cover-library-dir> [seconds]"; exit 2; }
LIB="$(cd "$LIB" && pwd)"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK=/tmp/mirage-cover
NET=mirage-cover-net
SUBNET=10.89.43.0/24
BRIDGE_IP=10.89.43.10
CLIENT_IP=10.89.43.20
DEST_IP=10.89.43.30
IMG=localhost/mirage-e2e:latest
CARRIER_PORT=8443
# Which carrier to measure: reality (default), ws, ss2022, hysteria2, h3.
#
# meek and DoH are deliberately absent. Both need real CDN domain-fronting, and
# there is no origin to front inside this cluster - standing up a fake one would
# measure the fake, not the carrier. They are covered instead by a paced
# client-server pair test in crates/transport-meek, which proves the framing is
# symmetric and carries data but is NOT a censor-vantage separability number.
#
# LIB_UP optionally supplies a SEPARATE upstream cover library (see
# proteus_profile_up) so a dwelled downstream can be paired with a dense
# upstream - which is what ships, and what the tier matrix passes.
CARRIER="${CARRIER:-reality}"
LIB_UP="${LIB_UP:-}"
[ -n "$LIB_UP" ] && LIB_UP="$(cd "$LIB_UP" && pwd)"

say() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
cleanup() {
  podman rm -f mirage-cb mirage-cc mirage-cd >/dev/null 2>&1 || true
  podman network rm "$NET" >/dev/null 2>&1 || true
}
# ONE INSTANCE AT A TIME, enforced rather than assumed.
#
# Every run shares fixed container names (mirage-cb/cc/cd), one podman network,
# and $WORK - including cap/slices.txt, the file that says which window each
# packet belongs to. Two instances therefore interleave their phase marks into
# one file and each computes spans over the other's timeline. Observed: a
# control cell reporting 9477 seconds of "idle" inside an 880-second capture,
# and a throughput ratio of 22.65x in a run with no user traffic at all. The
# byte counts were fine; only the timeline was nonsense, which is the kind of
# corruption that looks like a finding rather than a bug.
#
# A second instance now refuses to start instead of silently poisoning both.
exec 9>"$WORK.lock" 2>/dev/null || exec 9>/tmp/mirage-cover.lock
if ! flock -n 9; then
  echo "REFUSING: another cover-traffic.sh is already running."
  echo "  They share container names, the podman network and $WORK, so two runs"
  echo "  corrupt each other's captures and phase marks. Wait for it, or:"
  echo "    pkill -f cover-traffic.sh; pkill -f tier-matrix.sh"
  exit 3
fi

trap cleanup EXIT
cleanup

say "1. Image (with tcpdump for the censor-side capture)"
mkdir -p "$WORK/build" "$WORK/cfg" "$WORK/cap"
cp "$ROOT/target/release/mirage-bridge" "$ROOT/target/release/mirage-client" \
   "$ROOT/target/release/mirage-keygen" "$WORK/build/"
cp "$(dirname "$0")/Containerfile" "$(dirname "$0")/udp_socks_test.py" "$WORK/build/"
podman build -t "$IMG" "$WORK/build" >/dev/null || { echo "image build failed"; exit 1; }

say "2. Matched configs: $CARRIER carrier + replay pacing on BOTH ends"
KEYGEN_FLAGS=""
[ "$CARRIER" = ws ] && KEYGEN_FLAGS="--ws"
[ "$CARRIER" = hysteria2 ] && KEYGEN_FLAGS="--hysteria2"
[ "$CARRIER" = ss2022 ] && KEYGEN_FLAGS="--ss2022"
# hysteria2 is QUIC over UDP; everything else here is TCP. The capture filter and
# the readiness probe both have to follow, or the measurement silently records an
# empty file and reports a confident number over nothing.
CAP_PROTO=tcp; SS_FLAG=-ltn
CAP_FILTER="tcp and host $BRIDGE_IP and port $CARRIER_PORT"
# h3/MASQUE is QUIC over UDP like hysteria2, so it needs the UDP filter and the
# UDP readiness probe. Measuring it with the TCP filter records an empty file
# and then reports a confident number over nothing.
if [ "$CARRIER" = h3 ]; then
  CAP_PROTO=udp; SS_FLAG=-lun
  CAP_FILTER="udp and host $BRIDGE_IP"
fi
if [ "$CARRIER" = hysteria2 ]; then
  CAP_PROTO=udp; SS_FLAG=-lun
  # NO port in the UDP filter: hysteria2 supports epoch-derived UDP port hopping,
  # so the carrier does not sit on a fixed port. Filtering on one captures almost
  # nothing and the run reports a confident AUC over an empty file.
  CAP_FILTER="udp and host $BRIDGE_IP"
fi
# shellcheck disable=SC2086
"$ROOT/target/release/mirage-keygen" --bridge-endpoint "$BRIDGE_IP:$CARRIER_PORT" $KEYGEN_FLAGS \
  --write-bridge-config "$WORK/cfg/bridge.json" \
  --write-client-config "$WORK/cfg/client.json" >/dev/null || { echo "keygen failed"; exit 1; }

python3 - "$WORK/cfg/bridge.json" "$WORK/cfg/client.json" "$CARRIER" "$LIB_UP" <<'PY'
import json,sys
b=json.load(open(sys.argv[1])); c=json.load(open(sys.argv[2]))
carrier=sys.argv[3]; lib_up=sys.argv[4]
if carrier == "reality":
    # Reality carrier (TLS-classified by the bridge mux) to a real cover host.
    b.update({"reality_enabled":True,"reality_cover_addr":"www.wikipedia.org:443",
              "reality_client_hello_timeout_secs":10,"reality_cover_duration_cap_secs":30})
    c.update({"reality_enabled":True,"reality_sni":"www.wikipedia.org"})
elif carrier == "ws":
    # keygen already wrote the matching ws entry; paranoid would force reality
    # back on, so it stays off for this carrier.
    b["ws_enabled"]=True; c["ws_enabled"]=True
elif carrier == "ss2022":
    # keygen --ss2022 wrote the shared PSK into both configs. wu_evasion is NOT
    # optional here: the client refuses to start with SS-2022 as its only
    # transport otherwise, because an SS-2022 wire is uniform random from byte 0
    # - the exact Wu-2023 fully-encrypted signature that got obfs4 dropped. That
    # refusal is correct, so the harness measures the configuration an operator
    # would actually deploy rather than one the client declines to run.
    b["wu_evasion"]=True; c["wu_evasion"]=True
elif carrier == "h3":
    # QUIC listener on the same host:port as the TCP bind.
    b.update({"h3_enabled":True,"h3_hostname":"cdn.example.com"})
    c.update({"h3_enabled":True,"h3_hostname":"cdn.example.com"})
else:
    # hysteria2: keygen wrote the entry; nothing else to enable.
    pass
if lib_up:
    for d in (b,c):
        d["proteus_profile_up"]="/profile_up"
# Paranoid turns Proteus on; the profile is PINNED to the mounted library rather
# than auto-sourced, because a measurement needs a known envelope (and these
# containers have no route out to record one). BOTH ends must pace, or only one
# direction wears the envelope.
for d in (b,c):
    d.update({"proteus":"replay","proteus_profile":"/profile"})
# COVER_SYNC=1: let the CLIENT self-source instead of pinning, so the
# bridge->client library sync path is the thing under test.
import os
if os.environ.get("COVER_SYNC") == "1":
    c.pop("proteus_profile", None)
    if carrier == "reality":
        d["paranoid"]=True
    # A low-bitrate cover envelope has multi-second idle gaps, and handshake bytes
    # can only leave on a schedule token. The default 10s handshake budget is a
    # fast-network default, not a paced-carrier one - raise it so the measurement
    # exercises the steady state rather than dying in the handshake.
    d["handshake_timeout_secs"] = 120
# In-cluster destination is a private IP; let the bridge exit reach it.
b["allow_private_network_targets"]=True
json.dump(b,open(sys.argv[1],'w'),indent=2); json.dump(c,open(sys.argv[2],'w'),indent=2)
PY

say "3. Cluster: dest + bridge + client (cover library mounted at /profile)"
# Pin the MTU. Container-to-container traffic on one host never crosses a real
# 1500-byte wire, so without this a 16 KB TLS record can traverse the veth as ONE
# packet and the capture shows sizes no censor could ever observe - turning offload
# off is not enough on its own.
podman network create --subnet "$SUBNET" --opt mtu=1500 "$NET" >/dev/null
podman run -d --name mirage-cd --network "$NET" --ip "$DEST_IP" "$IMG" sh -c \
  'python3 -c "import sys; b=b\"MIRAGE_COVER_OK\"*8000; sys.stdout.buffer.write(b\"HTTP/1.1 200 OK\r\nContent-Length: \"+str(len(b)).encode()+b\"\r\nConnection: close\r\n\r\n\"+b)" > /resp; \
   exec socat TCP-LISTEN:80,reuseaddr,fork EXEC:"cat /resp"' >/dev/null
UP_MOUNT=()
[ -n "$LIB_UP" ] && UP_MOUNT=(-v "$LIB_UP:/profile_up:ro,Z")
podman run -d --name mirage-cb --network "$NET" --ip "$BRIDGE_IP" --cap-add NET_ADMIN "${UP_MOUNT[@]}" \
  -e RUST_LOG="${RUST_LOG:-info,mirage_transport_reality=debug}" \
  -v "$LIB:/profile:ro,Z" -v "$WORK/cfg/bridge.json:/bridge.json:ro,Z" \
  "$IMG" mirage-bridge /bridge.json >/dev/null
CC_EXTRA=()
if [ "${COVER_SYNC:-0}" = 1 ]; then
  # Seed the client with its OWN small bootstrap library, writable, at the
  # default state path. It needs SOMETHING to pace its first connection - the
  # sync cannot bootstrap itself, because fetching needs a tunnel and a paced
  # tunnel needs a library. What the sync then proves is that the client
  # CONVERGES on the bridge's traces and stops recording.
  rm -rf "$WORK/bootstrap"; mkdir -p "$WORK/bootstrap/cover/browse" "$WORK/bootstrap/cover/upstream"
  cp "$LIB"/browse/*.csv "$WORK/bootstrap/cover/browse/" 2>/dev/null || true
  cp "${LIB_UP:-$LIB/browse}"/*.csv "$WORK/bootstrap/cover/upstream/" 2>/dev/null || true
  chmod -R 0777 "$WORK/bootstrap"
  CC_EXTRA=(-e MIRAGE_STATE_DIR=/bootstrap -v "$WORK/bootstrap:/bootstrap:Z")
fi
podman run -d --name mirage-cc --network "$NET" --ip "$CLIENT_IP" --cap-add NET_RAW,NET_ADMIN "${UP_MOUNT[@]}" "${CC_EXTRA[@]}" \
  -e RUST_LOG="${RUST_LOG:-info,mirage_transport_reality=debug}" \
  -v "$LIB:/profile:ro,Z" -v "$WORK/cfg/client.json:/client.json:ro,Z" \
  "$IMG" mirage-client /client.json --management-bind 127.0.0.1:19443 >/dev/null

say "4. Wait for the carrier to come up"
for i in $(seq 1 40); do
  podman exec mirage-cb sh -c "ss $SS_FLAG 2>/dev/null | grep -q ':$CARRIER_PORT'" && break
  sleep 0.5
done
sleep 8
# Prove the tunnel actually carries traffic before measuring anything about it.
#
# The budget is 600s, not 150s, and that is not slack for a slow machine - it is
# the envelope. Setup and the first transfer both ride the paced channel, so a
# realistic browse cover (90% silent, gaps to 12s) genuinely needs minutes to
# push 120 KB including handshake, claim and mux open. At 150s this check failed
# 5 runs in 6 while the SAME configuration passed 3 of 3 at 600s - which read as
# "the WebSocket carrier is broken" for three rounds when the carrier was fine
# and merely slow. Timing it is part of the result, so report how long it took.
T0=$(date +%s)
OUT="$(podman exec mirage-cc curl -s --max-time ${TUNNEL_CHECK_SECS:-600} --socks5 127.0.0.1:1080 http://$DEST_IP/ 2>&1)"
TUNNEL_SECS=$(( $(date +%s) - T0 ))
BYTES=$(printf %s "$OUT" | wc -c)
if printf %s "$OUT" | grep -q MIRAGE_COVER_OK && [ "$BYTES" -ge 100000 ]; then
  echo "  tunnel OK: $BYTES bytes through the $CARRIER carrier in ${TUNNEL_SECS}s"
else
  echo "  FAIL: tunnel did not carry traffic ($BYTES bytes)"
  # BOTH logs. A carrier failure is almost always a disagreement between the two
  # ends - pacing on one side only, a seed mismatch, a knock the other end did
  # not accept - and the client's half of that story reads as "it just did not
  # work". Dumping only the client is why the WebSocket failure went three
  # rounds without a cause.
  echo "  ---- client (mirage-cc) ----"; podman logs --tail 40 mirage-cc 2>&1 | sed 's/^/  cc| /'
  echo "  ---- bridge (mirage-cb) ----"; podman logs --tail 40 mirage-cb 2>&1 | sed 's/^/  cb| /'
  exit 1
fi
# THROUGHPUT_ONLY=1: measure how fast the tunnel actually moves data through this
# envelope, then stop. No capture, no distinguisher.
#
# Separate from the separability run on purpose. They answer different questions
# and one is 30x cheaper: separability needs 900 s of packets, throughput needs a
# handful of transfers. Reuses the cluster and config setup above so the tunnel
# under test is byte-for-byte the one the separability matrix measures.
#
# Why this matters at all: the envelope is simultaneously the disguise AND the
# bandwidth budget. A record leaves per schedule token whether or not the app has
# data, so app bytes displace padding rather than adding to it - which means the
# envelope's rate is also the ceiling on the user's throughput. A tier is
# therefore a THROUGHPUT choice, and this is the measurement that shows it.
if [ "${THROUGHPUT_ONLY:-0}" = 1 ]; then
  say "5. Throughput: ${THROUGHPUT_RUNS:-5} transfers of the dest's 120000-byte body"
  RUNS="${THROUGHPUT_RUNS:-5}"
  TIMES=""
  OKN=0
  for i in $(seq 1 "$RUNS"); do
    # --max-time generous on purpose: a slow carrier must report as SLOW, not as
    # a failure. Timing out here would hide exactly the number being measured.
    R="$(podman exec mirage-cc sh -c \
      "s=\$(date +%s%N); b=\$(curl -s --max-time 120 --socks5 127.0.0.1:1080 http://$DEST_IP/ | wc -c); e=\$(date +%s%N); echo \"\$b \$(( (e - s) / 1000000 ))\"" 2>/dev/null)"
    B="$(echo "$R" | awk '{print $1+0}')"
    MS="$(echo "$R" | awk '{print $2+0}')"
    if [ "$B" -ge 100000 ] && [ "$MS" -gt 0 ]; then
      KBPS=$(( B / MS ))          # bytes/ms == KB/s
      TIMES="$TIMES $MS"
      OKN=$(( OKN + 1 ))
      printf "  run %d: %d bytes in %d ms = %d KB/s\n" "$i" "$B" "$MS" "$KBPS"
    else
      printf "  run %d: FAILED (%d bytes)\n" "$i" "$B"
    fi
  done
  if [ "$OKN" -eq 0 ]; then
    echo "  RESULT ${CARRIER} - - - failed"
    exit 1
  fi
  # Median, not mean: one stall from a scheduling hiccup should not move the
  # headline number.
  MED=$(echo $TIMES | tr ' ' '\n' | sort -n | awk '{a[NR]=$1} END{print (NR%2)?a[(NR+1)/2]:int((a[NR/2]+a[NR/2+1])/2)}')
  MEDKB=$(( 120000 / MED ))
  # Report the SPREAD as well. A replayed browse envelope is bursty by
  # construction - roughly 90% silent with reading gaps - so an identical
  # transfer takes very different times depending on whether it lands in a burst
  # or has to wait for the next one. Measured 7.6 s to 15.3 s across three runs
  # of the same cell. A median on its own would present that as a steady rate it
  # is not, and the spread is what a user actually feels.
  FAST=$(echo $TIMES | tr ' ' '\n' | sort -n | head -1)
  SLOW=$(echo $TIMES | tr ' ' '\n' | sort -n | tail -1)
  FASTKB=$(( 120000 / FAST ))
  SLOWKB=$(( 120000 / SLOW ))
  # One machine-readable line the driver greps, so a table cannot be mistyped.
  echo "  RESULT ${CARRIER} ${MED} ${MEDKB} ${OKN}/${RUNS} ${FASTKB} ${SLOWKB}"
  exit 0
fi

# Confirm pacing is actually ENGAGED - a replay profile that fails to load leaves
# the carrier unpaced and would make the whole measurement meaningless.
CLIENT_LOG_PLAIN() { podman logs mirage-cc 2>&1 | sed 's/\x1b\[[0-9;]*m//g'; }
# Two different shapers, two different log lines: byte-stream carriers log the
# selected replay profile, QUIC carriers log datagram shaping per DIRECTION. And a
# QUIC carrier may legitimately shape only one direction - QUIC's 1200-byte
# datagram floor is larger than any upstream record a browse or video capture
# contains (measured: browse upstream maxes ~600 B), so upstream is refused with a
# reason rather than faked. Require SOME endpoint to be shaping, and print what
# each decided, instead of failing on a carrier that is behaving correctly.
BRIDGE_LOG_PLAIN() { podman logs mirage-cb 2>&1 | sed 's/\x1b\[[0-9;]*m//g'; }
SHAPED=0
for side in cc cb; do
  L=$(podman logs "mirage-$side" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
  if printf %s "$L" | grep -qE "replay profile selected|datagram shaping from the replay cover"; then
    SHAPED=1
    printf "  %s shaping: %s\n" "$side" \
      "$(printf %s "$L" | grep -m1 -oE 'up_tokens_per_sec=[0-9.]+|direction="[a-z]+" records=[0-9]+ max_size=[0-9]+ mean_gap_ms=[0-9]+')"
  fi
  if printf %s "$L" | grep -q "cannot be size-shaped"; then
    printf "  %s UNSHAPED (refused): %s\n" "$side" \
      "$(printf %s "$L" | grep -m1 -oE 'direction="[a-z]+" records=[0-9]+ needed=[0-9]+')"
  fi
done
if [ "$SHAPED" = 0 ]; then
  echo "  FAIL: no endpoint engaged pacing - measurement would be meaningless"
  echo "  --- client log (last 20) ---"; CLIENT_LOG_PLAIN | tail -20; exit 1
fi

SLICE="${SLICE:-20}"
CYCLES=$(( SECS / (SLICE * 2) )); [ "$CYCLES" -lt 3 ] && CYCLES=3

# Segmentation offload must be OFF or the capture is fiction: with GSO/TSO/GRO on,
# tcpdump sees 16 KB super-segments the kernel has not split yet, so the packet-size
# distribution a censor would actually observe is invisible. This is the difference
# between measuring the wire and measuring a kernel buffer.
# Offload must be off on BOTH ends: segmentation happens on the SENDER, so the
# bridge's setting governs the downstream sizes and the client's governs upstream.
# Disabling only the capturing side leaves half the measurement fictional (which is
# how the first wire-faithful attempt still showed 16 KB "packets" downstream).
for c in mirage-cc mirage-cb; do
  # Apply each flag separately: veth rejects some (tx/sg) and a combined call
  # fails wholesale, silently leaving segmentation on.
  for f in tso gso gro; do
    podman exec "$c" ethtool -K eth0 "$f" off >/dev/null 2>&1 || true
  done
  podman exec "$c" sh -c "ethtool -k eth0 2>/dev/null | grep -q 'generic-segmentation-offload: off'" \
    || echo "  WARNING: $c segmentation offload still ON - its SENT packet sizes are not wire-faithful"
done
podman exec mirage-cc sh -c "ethtool -k eth0 2>/dev/null | grep -E 'tcp-segmentation|generic-segmentation|generic-receive' | sed 's/^/  client offload: /'" || true

echo "  capture filter: $CAP_FILTER"
# COMPILE the filter (-d dumps the BPF program and exits) rather than trying to
# capture a packet with it. The old check ran `timeout 3 tcpdump -c 1` and treated
# any rc>1 as a bad filter - but `timeout` returns 124 when the command simply ran
# out of time, which on a realistically bursty cover envelope is the NORMAL case:
# a browse session is ~90% silent with gaps up to 45 s, so a 3 s sample routinely
# sees nothing. That made a healthy run abort with "tcpdump rejected the filter".
# Compiling answers the question actually being asked - is this filter valid - and
# needs no traffic at all.
podman exec mirage-cc sh -c "tcpdump -d '$CAP_FILTER' >/dev/null 2>&1"; RC=$?
[ "$RC" -ne 0 ] && { echo "  FAIL: tcpdump rejected the filter (rc=$RC)"; exit 1; }

say "5. Randomised capture: ${CYCLES} x ${SLICE}s idle + ${CYCLES} x ${SLICE}s active"
# Capture straight to a HOST file over the exec pipe, using the SAME $CAP_FILTER
# that was validated above. This line previously hardcoded a tcp filter while the
# script printed $CAP_FILTER, so a UDP carrier was measured through a TCP filter
# and produced one packet - the printed filter and the used filter must be the
# same string, or the log is describing a run that did not happen.
podman exec mirage-cc tcpdump -i eth0 -nn -tt -q -l "$CAP_FILTER" > "$WORK/cap/all.txt" 2>/dev/null &
TCPDUMP_PID=$!
sleep 2
: > "$WORK/cap/slices.txt"

# RANDOMISED ASSIGNMENT, not strict alternation. Read this before "simplifying"
# it back into an alternating loop.
#
# The cover envelope is a REPLAY of a captured trace, looped. The lean library's
# browse traces span 13-38 s; alternating fixed 20 s windows gives a 40 s cycle.
# A 38 s trace against a 40 s cycle advances only 2 s of trace per cycle, so
# after 15 cycles it has not walked through its own period once - which means
# "where the replay is in its loop" is a near-deterministic function of the
# window index, and therefore of the LABEL. The distinguisher will happily learn
# that instead of user activity, and it reports the result as separability.
#
# The first fix was to randomise which windows get the treatment, so the beat
# becomes noise in both classes rather than signal in one. That is necessary and
# it is NOT sufficient, which a control caught: a flat shuffle decorrelates the
# label from loop position ACROSS runs, but each individual run still draws its
# own imbalance. With 15 windows per class that is about 1/sqrt(15), a quarter of
# the class, and it is systematic WITHIN the run - so a classifier finds it and
# pooling windows amplifies it.
#
# Measured, with NO user traffic at all: one control run scored 0.623 per window
# and grew to 0.875 when 64 windows were pooled (excess over floor +0.194), while
# another control on the same library stayed below its floor throughout. That
# spread is the draw, not the shaper.
#
# So: MATCHED PAIRS. Emit windows two at a time, one idle and one active in a
# random order within each pair, so adjacent windows sit at almost the same point
# in the replay loop. Counts stay balanced by construction.
#
# READ THIS BEFORE CREDITING THE PAIRING WITH ANYTHING. It is a PRECONDITION, not
# a fix, and on its own it changed nothing: two control runs under this design
# still reported "SEPARABLE" at 0.642 and 0.563 with no user traffic at all.
# Pairing only helps if the ANALYSIS differences within pairs, and the analysis
# below does not - it buckets every idle window against every active window as
# two independent samples, which throws the pairing away. Exploiting it needs a
# one-sample test on within-pair differences, which is a different estimator from
# the max-over-features AUC used here.
#
# The false positives those controls showed turned out to have a different cause
# anyway: `noise_floor` is ONE number compared against the best of FOURTEEN
# features, and the extremes (`max_size`, `size_range`) have a heavier-tailed
# sampling distribution than that pooled estimate allows for. Both control
# "leaks" above were won by `max_size`. See `examples/feature_floor` and the
# per-feature section in docs/proteus.md.
command -v shuf >/dev/null || { echo "  FAIL: shuf not found - window order cannot be randomised, and a fixed order is exactly the confound the control exists to catch"; exit 1; }
ORDER=$(for _ in $(seq 1 "$CYCLES"); do printf 'idle\nactive\n' | shuf; done)
[ -n "$ORDER" ] || { echo "  FAIL: empty window order"; exit 1; }

# NULL_CONTROL=1 runs the identical protocol with NO user traffic in the ACTIVE
# windows. There is then nothing to detect, so an honest harness must report AUC
# ~0.5; anything higher is the harness measuring its own structure, and every
# number it produces in normal mode is inflated by that much. Run it whenever
# the phase length, the cover library or the window order changes.
[ "${NULL_CONTROL:-0}" = 1 ] && echo "  NULL CONTROL: active windows carry NO user traffic (expect AUC ~0.5)"

# Transfer accounting. `|| true` on the curl kept one failed fetch from killing a
# window, which is right - but swallowing ALL of them means a tunnel that dies
# mid-run produces active windows carrying nothing but cover. Idle and active are
# then genuinely identical, the distinguisher correctly reports ~0.5, and a DEAD
# TUNNEL is published as perfect cover. That is the worst failure this harness
# can have, so the transfers are counted and checked below.
ACTIVE_OK=0
ACTIVE_FAIL=0
for label in $ORDER; do
  echo "$label $(date +%s.%N)" >> "$WORK/cap/slices.txt"
  if [ "$label" = active ] && [ "${NULL_CONTROL:-0}" != 1 ]; then
    counts=$(podman exec mirage-cc sh -c \
      "ok=0; bad=0; end=\$(( \$(date +%s) + $SLICE )); while [ \$(date +%s) -lt \$end ]; do if curl -s -o /dev/null --max-time 10 --socks5 127.0.0.1:1080 http://$DEST_IP/; then ok=\$((ok+1)); else bad=\$((bad+1)); fi; done; echo \"\$ok \$bad\"" 2>/dev/null)
    ACTIVE_OK=$(( ACTIVE_OK + $(echo "$counts" | awk '{print $1+0}') ))
    ACTIVE_FAIL=$(( ACTIVE_FAIL + $(echo "$counts" | awk '{print $2+0}') ))
  else
    sleep "$SLICE"
  fi
done
echo "end $(date +%s.%N)" >> "$WORK/cap/slices.txt"
podman exec mirage-cc pkill tcpdump >/dev/null 2>&1 || true
wait "$TCPDUMP_PID" 2>/dev/null || true
sleep 0.5
NCAP=$(wc -l < "$WORK/cap/all.txt")
echo "  captured $NCAP packets across $(( CYCLES * 2 )) randomised windows"

if [ "${NULL_CONTROL:-0}" != 1 ]; then
  echo "  active-window transfers: $ACTIVE_OK ok, $ACTIVE_FAIL failed"
  if [ "$ACTIVE_OK" -eq 0 ]; then
    echo "  FAIL: not one transfer succeeded in any active window. The active phase"
    echo "        carried only cover, so idle and active are the same traffic and any"
    echo "        AUC from this run would report a DEAD TUNNEL as perfect cover."
    exit 1
  fi
  # NOT a majority-success test. A curl that hits --max-time still transferred
  # up to that timeout's worth of real user data, so it contributes to the ACTIVE
  # class exactly like a completed one; what it signals is a carrier SLOWER than
  # the timeout, not a dead tunnel. Requiring most transfers to complete threw
  # away perfectly good cells for the slow carriers (hysteria2 at 12 s and ws at
  # 24 s per 120 KB against a 10 s timeout, while reality at 7 s passed) - it was
  # measuring carrier speed and calling it tunnel death.
  #
  # A genuinely dead tunnel is caught by the two checks that bracket this: zero
  # successes above, and the post-capture liveness probe below.
  if [ "$ACTIVE_FAIL" -gt "$ACTIVE_OK" ]; then
    echo "  NOTE: $ACTIVE_FAIL of $(( ACTIVE_OK + ACTIVE_FAIL )) transfers hit the 10s timeout -"
    echo "        this carrier is slower than the timeout under its envelope. The"
    echo "        active windows still carry user traffic, so the cell stands."
  fi
  # And it must still be alive AFTER the capture: a tunnel that died in the last
  # window would pass the counts above while the tail of the capture is wrong.
  if ! podman exec mirage-cc sh -c \
      "curl -s -o /dev/null --max-time 15 --socks5 127.0.0.1:1080 http://$DEST_IP/" 2>/dev/null; then
    echo "  FAIL: the tunnel is not usable after the capture, so it died at some"
    echo "        point during it and an unknown tail of the ACTIVE class is cover."
    exit 1
  fi
  echo "  tunnel still live after the capture"
fi
if [ "$NCAP" -lt 100 ]; then
  echo "  FAIL: capture is essentially empty ($NCAP packets) - the filter is not matching the"
  echo "        carrier. Any separability number from this would be fiction."
  echo "  --- what is actually on the wire (3s unfiltered) ---"
  podman exec mirage-cc sh -c "timeout 3 tcpdump -i eth0 -nn -q -c 200 2>/dev/null | grep -oE 'UDP|tcp' | sort | uniq -c" || true
  podman exec mirage-cc sh -c "timeout 3 tcpdump -i eth0 -nn -q -c 5 2>/dev/null" || true
  echo "  --- what the client actually dialled ---"
  CLIENT_LOG_PLAIN | grep -iE "pool entry|mode=|carrier|transport" | head -6
  exit 1
fi

say "7. Extract the censor's view and measure separability"
python3 - "$WORK/cap/all.txt" "$WORK/cap/slices.txt" "$CLIENT_IP" "$WORK/cap" <<'PYEOF'
import sys, re
cap, slices, client_ip, outdir = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
marks = []
for line in open(slices):
    lbl, ts = line.split()
    marks.append((lbl, float(ts)))
def label_at(t):
    lbl = None
    for l, ts in marks:
        if ts <= t:
            lbl = l
        else:
            break
    return None if lbl in (None, "end") else lbl
pat_tcp = re.compile(r"^(\d+\.\d+) IP ([\d.]+)\.(\d+) > ([\d.]+)\.(\d+): tcp (\d+)")
pat_udp = re.compile(r"^(\d+\.\d+) IP ([\d.]+)\.(\d+) > ([\d.]+)\.(\d+): UDP, length (\d+)")
buckets = {"idle": {"up": [], "down": [], "all": []},
           "active": {"up": [], "down": [], "all": []}}
for line in open(cap, errors="ignore"):
    m = pat_tcp.match(line.strip()) or pat_udp.match(line.strip())
    if not m:
        continue
    ts, src, _, dst, _, ln = m.groups()
    ts = float(ts); ln = int(ln)
    lbl = label_at(ts)
    if lbl is None:
        continue
    b = buckets[lbl]
    b["all"].append((ts, ln))
    (b["up"] if src == client_ip else b["down"]).append(ln)
def dump(name, v):
    open("%s/%s.sizes" % (outdir, name), "w").write("\n".join(map(str, v)) + "\n")
    return len(v)
rates = {}
for lbl in ("idle", "active"):
    b = buckets[lbl]
    n_up = dump(lbl + "_up", b["up"]); n_dn = dump(lbl + "_down", b["down"])
    tot = sum(x[1] for x in b["all"])
    span = 0.0
    for i, (l, ts) in enumerate(marks[:-1]):
        if l == lbl:
            span += marks[i + 1][1] - ts
    rates[lbl] = tot / span / 1024 if span > 0 else 0.0
    print("  %-6s up=%d down=%d bytes=%d over %.0fs = %.1f KiB/s"
          % (lbl.upper(), n_up, n_dn, tot, span, rates[lbl]))
for lbl in ("idle","active"):
    mx=max((x[1] for x in buckets[lbl]["all"]), default=0)
    if mx > 1500:
        print("  WARNING: %s max packet %d B exceeds the MTU - capture is NOT wire-faithful" % (lbl, mx))
if rates["idle"] > 0:
    print("  throughput ratio ACTIVE/IDLE = %.2fx  (1.0 = activity invisible)"
          % (rates["active"] / rates["idle"]))
PYEOF

for d in up down; do
  I="$WORK/cap/idle_$d.sizes"; A="$WORK/cap/active_$d.sizes"
  n=$(( $(wc -l < "$I") < $(wc -l < "$A") ? $(wc -l < "$I") : $(wc -l < "$A") ))
  # Size the window to target a FLOW COUNT, not a divisor.
  #
  # This used to be n/6 clamped to [20,300], i.e. "at least 6 flows". The
  # estimator maximises over 14 features, so its floor is a function of flows per
  # class - about 0.76 at 6 flows and 0.55 at 150. Aiming at 6 guaranteed a floor
  # so high that nothing could be distinguished from it, and the 300 clamp meant a
  # dense capture produced FEWER flows than a sparse one.
  #
  # Target ~120 flows per class, with the window floored at 40 records so each
  # flow still carries enough to make its features meaningful (40 is what
  # noise_floor was calibrated at) and capped at 300 so a very dense capture does
  # not build enormous windows.
  w=$(( n / 120 )); [ "$w" -lt 40 ] && w=40; [ "$w" -gt 300 ] && w=300
  echo "-- $d (window=$w) --"
  # stderr is KEPT: flow_auc refuses (exit 3) when a class is under-sampled, and
  # that refusal is the only thing standing between a broken capture and a
  # confident published number. Discarding it hid the one message that mattered.
  (cd "$ROOT" && cargo run -q -p mirage-adversary --example flow_auc -- "$I" "$A" "$w") \
    || echo "  (no verdict for $d - see the refusal above)"
done
# Keep both daemons' logs so a residual wire artefact can be attributed to the
# code path that produced it instead of guessed at.
podman logs mirage-cc > "$WORK/cap/client.log" 2>&1 || true
podman logs mirage-cb > "$WORK/cap/bridge.log" 2>&1 || true
echo "  logs saved: $WORK/cap/{client,bridge}.log"

echo
echo "AUC ~0.5 => an observer cannot tell idle from active (cover works)."
echo "AUC ~1.0 => user activity modulates the envelope (cover is cosmetic)."
if [ "${NULL_CONTROL:-0}" = 1 ]; then
  echo
  echo "This was the NULL CONTROL: no user traffic existed to detect, so anything"
  echo "above ~0.5 here is the harness's own floor and every ordinary run is"
  echo "inflated by it. Reference runs, lean library, 15+15 randomised 20s windows:"
  echo "  ss2022   ratio 1.12x   up 0.538   down 0.526"
  echo "  reality  ratio 0.91x   up 0.548   down 0.520"
else
  echo "Floor: NULL_CONTROL runs on this host measured 0.52-0.55 across two"
  echo "carriers. A result in that band is indistinguishable from no signal,"
  echo "however it is phrased."
fi
echo "captures + size files kept in $WORK/cap"
