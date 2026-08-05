#!/bin/bash
# Censor-vantage ACTIVE vs IDLE measurement on a real paced tunnel.
#
# usage: WIN=20 PAIRS=8 scripts/wire-auc/run.sh
#        (expects cfg/bridge.json and cfg/client.json beside this script)
#
# A relay sits between a real mirage-client and a real mirage-bridge and logs
# every TLS record that crosses, by direction, with a timestamp - the observable a
# DPI box has. Windows alternate in MATCHED PAIRS with a randomised order inside
# each pair, the way scripts/podman-e2e/cover-traffic.sh does it, so a slow drift
# in the environment cannot correlate with the label and be learned instead of
# activity.
set -uo pipefail
E="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$E/../.." && pwd)"
R="$ROOT/target/release"
WIN="${WIN:-20}"
PAIRS="${PAIRS:-8}"

pkill -f mirage-bridge 2>/dev/null; pkill -f mirage-client 2>/dev/null
pkill -f "$E/relay.py" 2>/dev/null; pkill -f socketserver 2>/dev/null
sleep 1
rm -f "$E/records.tsv" "$E/marks.tsv" "$E"/{origin,bridge,client,relay}.log

cleanup() {
  pkill -INT -f "$E/relay.py" 2>/dev/null
  sleep 2
  pkill -f mirage-bridge 2>/dev/null; pkill -f mirage-client 2>/dev/null
  pkill -f socketserver 2>/dev/null
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
socketserver.TCPServer(('127.0.0.1',18080),H).serve_forever()" > "$E/origin.log" 2>&1 &

RUST_LOG=warn "$R/mirage-bridge" "$E/cfg/bridge.json" > "$E/bridge.log" 2>&1 &
# The bridge profiles its Reality cover flight before binding; do not race it.
for _ in $(seq 1 30); do ss -ltn 2>/dev/null | grep -q 18444 && break; sleep 1; done
ss -ltn 2>/dev/null | grep -q 18444 || { echo "BRIDGE NEVER BOUND"; tail -n 5 "$E/bridge.log"; exit 1; }

python3 "$E/relay.py" 18443 18444 "$E/records.tsv" > "$E/relay.log" 2>&1 &
sleep 1
RUST_LOG=warn "$R/mirage-client" "$E/cfg/client.json" > "$E/client.log" 2>&1 &
for _ in $(seq 1 30); do ss -ltn 2>/dev/null | grep -q ":1080" && break; sleep 1; done

# Prove the tunnel carries traffic before measuring anything over it.
if ! curl -s --socks5-hostname 127.0.0.1:1080 -o /dev/null -m 90 http://127.0.0.1:18080/; then
  echo "TUNNEL DOWN - no measurement is possible"
  tail -n 6 "$E/client.log"; tail -n 6 "$E/bridge.log"
  exit 1
fi
echo "tunnel up; measuring $PAIRS pairs x ${WIN}s"

: > "$E/marks.tsv"
for i in $(seq 1 "$PAIRS"); do
  if [ $((RANDOM % 2)) -eq 0 ]; then ORDER="idle active"; else ORDER="active idle"; fi
  for phase in $ORDER; do
    START=$(python3 -c 'import time;print(f"{time.monotonic():.6f}")')
    if [ "$phase" = active ]; then
      DEADLINE=$(python3 -c "import time;print(time.monotonic()+$WIN)")
      while python3 -c "import time,sys;sys.exit(0 if time.monotonic() < $DEADLINE else 1)"; do
        curl -s --socks5-hostname 127.0.0.1:1080 -o /dev/null -m 25 http://127.0.0.1:18080/ || true
      done
    else
      sleep "$WIN"
    fi
    STOP=$(python3 -c 'import time;print(f"{time.monotonic():.6f}")')
    printf '%s\t%s\t%s\n' "$phase" "$START" "$STOP" >> "$E/marks.tsv"
  done
  echo "  pair $i/$PAIRS"
done

pkill -INT -f "$E/relay.py" 2>/dev/null
sleep 3
echo "records: $(wc -l < "$E/records.tsv" 2>/dev/null || echo 0)"
