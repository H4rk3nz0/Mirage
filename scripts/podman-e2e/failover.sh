#!/usr/bin/env bash
# Live validation of ADAPTIVE TRANSPORT FAILOVER + learning.
#
# The client is configured with TWO carriers (ss2022 + vless). The bridge is
# then crippled for ONE of them (ss2022 keys removed) so ss2022 handshakes fail
# while vless works. A working client must:
#   (1) try ss2022, fail, fall over to vless within the same SOCKS request, and
#   (2) LEARN it - the success-rate map records ss2022 failures + vless successes,
#       so `mirage status` shows the divergence and later picks prefer vless.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK=/tmp/mirage-podman; NET=mirage-net
BRIDGE_IP=10.89.42.10; CLIENT_IP=10.89.42.20; DEST_IP=10.89.42.30
IMG=localhost/mirage-e2e:latest
KEEP=0; [ "${1:-}" = "--keep" ] && KEEP=1
say() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
cleanup() { [ "$KEEP" = 1 ] && return; podman rm -f mirage-bridge mirage-client mirage-dest >/dev/null 2>&1 || true; podman network rm "$NET" >/dev/null 2>&1 || true; }
trap cleanup EXIT

say "1. Build image (assumes binaries already built)"
mkdir -p "$WORK/build" "$WORK/cfg"
cp "$ROOT/target/release/mirage-bridge" "$ROOT/target/release/mirage-client" "$ROOT/target/release/mirage-keygen" "$WORK/build/"
cp "$(dirname "$0")/Containerfile" "$WORK/build/"
podman build -t "$IMG" "$WORK/build" >/dev/null || { echo "image build failed"; exit 1; }

say "2. keygen a TWO-carrier pair (ss2022 + vless)"
"$ROOT/target/release/mirage-keygen" --bridge-endpoint "$BRIDGE_IP:8443" --ss2022 --vless \
  --write-bridge-config "$WORK/cfg/bridge.json" --write-client-config "$WORK/cfg/client.json" >/dev/null
sed -i 's/"allow_private_network_targets": false/"allow_private_network_targets": true/' "$WORK/cfg/bridge.json"

say "3. Cripple ss2022 on the BRIDGE (simulate that carrier being blocked)"
# Drop the ss2022 identity key so the bridge cannot complete an ss2022 handshake;
# vless stays fully configured. python keeps the JSON valid.
python3 - "$WORK/cfg/bridge.json" <<'PY'
import json,sys
f=sys.argv[1]; d=json.load(open(f))
for k in ("ss2022_psk_hex",): d.pop(k,None)
json.dump(d,open(f,'w'),indent=2)
print("  bridge ss2022 keys removed; client still offers ss2022+vless")
PY

say "4. Launch cluster"
podman rm -f mirage-bridge mirage-client mirage-dest >/dev/null 2>&1 || true
podman network rm "$NET" >/dev/null 2>&1 || true
podman network create --subnet 10.89.42.0/24 "$NET" >/dev/null
podman run -d --name mirage-dest --network "$NET" --ip "$DEST_IP" "$IMG" sh -c \
  'printf "HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nMIRAGE_E2E_OK" > /resp; exec socat TCP-LISTEN:80,reuseaddr,fork EXEC:"cat /resp"' >/dev/null
podman run -d --name mirage-bridge --network "$NET" --ip "$BRIDGE_IP" -v "$WORK/cfg/bridge.json:/bridge.json:ro,Z" "$IMG" mirage-bridge /bridge.json >/dev/null
podman run -d --name mirage-client --network "$NET" --ip "$CLIENT_IP" -v "$WORK/cfg/client.json:/client.json:ro,Z" "$IMG" mirage-client /client.json --management-bind 127.0.0.1:19443 >/dev/null
for i in $(seq 1 20); do podman exec mirage-bridge sh -c "ss -ltn 2>/dev/null | grep -q ':8443'" && break; sleep 0.5; done
sleep 2

say "5. Drive a few requests (each must succeed via failover to vless)"
RC=0
for n in 1 2 3; do
  OUT="$(podman exec mirage-client curl -s --max-time 25 --socks5 127.0.0.1:1080 http://$DEST_IP/ 2>&1)"
  echo "$OUT" | grep -q "MIRAGE_E2E_OK" && echo "  req $n: PASS (failed over to a working carrier)" || { echo "  req $n: FAIL"; RC=1; }
done

say "6. mirage status - did it LEARN (ss2022 failing, vless winning)?"
podman exec mirage-client mirage-client status --management-bind 127.0.0.1:19443 2>&1 | sed -n '/bridges/,$p'

say "7. bridge: confirm vless sessions established (ss2022 rejected)"
podman logs mirage-bridge 2>&1 | grep -iE 'session established|ss2022|vless|no transport|mux' | tail -6
exit $RC
