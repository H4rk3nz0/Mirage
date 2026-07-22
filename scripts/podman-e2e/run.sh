#!/usr/bin/env bash
# End-to-end Mirage validation on a rootless Podman cluster.
#
# Phase 1 (default):  client -- Mirage tunnel --> bridge --> public dest
#   Proves the real binaries handshake + tunnel SOCKS5 traffic to the internet.
#
# Usage:  scripts/podman-e2e/run.sh [--keep]
#   --keep   leave containers + network running for inspection (else teardown).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK=/tmp/mirage-podman
NET=mirage-net
SUBNET=10.89.42.0/24
BRIDGE_IP=10.89.42.10
CLIENT_IP=10.89.42.20
IMG=localhost/mirage-e2e:latest
TARGET_URL="${TARGET_URL:-https://httpbin.org/ip}"
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

say() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
cleanup() {
  [ "$KEEP" = 1 ] && { echo "(--keep: leaving cluster up; \`podman rm -f mirage-bridge mirage-client; podman network rm $NET\` to clean)"; return; }
  podman rm -f mirage-bridge mirage-client mirage-dest >/dev/null 2>&1 || true
  podman network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

say "1. Build release binaries (if needed)"
if [ ! -x "$ROOT/target/release/mirage-bridge" ] || [ ! -x "$ROOT/target/release/mirage-client" ]; then
  (cd "$ROOT" && cargo build --release -p mirage-bridge -p mirage-client) || exit 1
fi

say "2. Build runtime image"
mkdir -p "$WORK/build"
cp "$ROOT/target/release/mirage-bridge" "$ROOT/target/release/mirage-client" \
   "$ROOT/target/release/mirage-keygen" "$WORK/build/"
cp "$(dirname "$0")/Containerfile" "$(dirname "$0")/udp_socks_test.py" "$WORK/build/"
podman build -t "$IMG" "$WORK/build" >/dev/null || { echo "image build failed"; exit 1; }

say "3. Generate matched bridge+client config (invite baked with bridge IP)"
mkdir -p "$WORK/cfg"
# Transport: default keygen pair is Raw (plain Noise). The bridge mux does NOT
# classify Raw, so disable the mux on the bridge to accept Raw directly. This
# is the simplest fully-working end-to-end path for the baseline test.
# (To exercise SS-2022, pass --ss2022 to keygen and keep the mux on.)
TRANSPORT="${TRANSPORT:-raw}"
MUX_OFF=0
case "$TRANSPORT" in
  raw)       KEYGEN_FLAGS="";            MUX_OFF=1 ;;  # plain Noise - not mux-classified
  ss2022)    KEYGEN_FLAGS="--ss2022"     ;;
  ws)        KEYGEN_FLAGS="--ws"         ;;
  vless)     KEYGEN_FLAGS="--vless"      ;;
  reality)   KEYGEN_FLAGS="";            REALITY=1 ;;  # TLS-classified; config injected below
  vless-reality) KEYGEN_FLAGS="--vless"; REALITY=1 ;;  # VLESS overlay over the Reality carrier
  hysteria2) KEYGEN_FLAGS="--hysteria2"  ;;  # QUIC/UDP - separate listener
  h3)        KEYGEN_FLAGS="";            H3=1; MUX_OFF=1 ;;  # QUIC/HTTP3 - config injected; raw fallback needs mux off
  dnstt)     KEYGEN_FLAGS="";            DNSTT=1; MUX_OFF=1 ;;  # DNS tunnel - config injected; raw fallback needs mux off
  meek)      KEYGEN_FLAGS="--meek meek.local" ;;  # needs CDN fronting (best-effort)
  doh)       KEYGEN_FLAGS="--doh dns.local"   ;;
  *) echo "unknown TRANSPORT=$TRANSPORT"; exit 1 ;;
esac
"$ROOT/target/release/mirage-keygen" --bridge-endpoint "$BRIDGE_IP:8443" $KEYGEN_FLAGS \
  --write-bridge-config "$WORK/cfg/bridge.json" \
  --write-client-config "$WORK/cfg/client.json" >/dev/null || { echo "keygen failed"; exit 1; }
if [ "$MUX_OFF" = 1 ]; then
  sed -i 's/^{/{\n  "mux_enabled": false,/' "$WORK/cfg/bridge.json"
fi
if [ "$TRANSPORT" = ss2022 ]; then
  # SS-2022 as the sole outer carrier trips the entropy-DPI guard; the test network
  # has no such DPI, so permit it (a real deployment pairs SS with a mimicry carrier).
  python3 - "$WORK/cfg/client.json" <<'PY'
import json,sys
c=json.load(open(sys.argv[1])); c["allow_ss2022_outer"]=True
json.dump(c,open(sys.argv[1],'w'),indent=2)
PY
fi
if [ "${REALITY:-0}" = 1 ]; then
  # Reality (ephemeral cert) isn't a keygen flag - inject matching config.
  python3 - "$WORK/cfg/bridge.json" "$WORK/cfg/client.json" <<'PY'
import json,sys
b=json.load(open(sys.argv[1])); c=json.load(open(sys.argv[2]))
# A real, high-traffic cover (www.example.com is now rejected fail-closed as a
# placeholder - see the bridge's reality cover-host validation).
b.update({"reality_enabled":True,"reality_cover_addr":"www.wikipedia.org:443",
          "reality_client_hello_timeout_secs":10,"reality_cover_duration_cap_secs":30})
c.update({"reality_enabled":True,"reality_sni":"www.wikipedia.org"})
json.dump(b,open(sys.argv[1],'w'),indent=2); json.dump(c,open(sys.argv[2],'w'),indent=2)
PY
fi
if [ "${PARANOID:-0}" = 1 ]; then
  # Paranoid mode: config-driven strong posture. Use with TRANSPORT=reality (for the
  # reality cover config) and MIRAGE_REALITY_PACE_PROFILE=<lib> (mounted at /profile).
  python3 - "$WORK/cfg/bridge.json" "$WORK/cfg/client.json" <<'PY'
import json,sys
for p in sys.argv[1:3]:
    d=json.load(open(p)); d.update({"paranoid":True,"reality_pace_profile":"/profile"})
    json.dump(d,open(p,'w'),indent=2)
PY
fi
if [ "${H3:-0}" = 1 ]; then
  # HTTP/3 (MASQUE) - QUIC listener on the same host:port as the TCP bind.
  python3 - "$WORK/cfg/bridge.json" "$WORK/cfg/client.json" <<'PY'
import json,sys
b=json.load(open(sys.argv[1])); c=json.load(open(sys.argv[2]))
b.update({"h3_enabled":True,"h3_hostname":"cdn.example.com"})
c.update({"h3_enabled":True,"h3_hostname":"cdn.example.com"})
json.dump(b,open(sys.argv[1],'w'),indent=2); json.dump(c,open(sys.argv[2],'w'),indent=2)
PY
fi
if [ "${DNSTT:-0}" = 1 ]; then
  # Full DNS tunnel - bridge answers tunnel queries on UDP:5353 for t.example.com;
  # client sends DNS queries directly to the bridge (direct mode, no resolver).
  python3 - "$WORK/cfg/bridge.json" "$WORK/cfg/client.json" "$BRIDGE_IP" <<'PY'
import json,sys
b=json.load(open(sys.argv[1])); c=json.load(open(sys.argv[2])); bip=sys.argv[3]
b.update({"dnstt_enabled":True,"dnstt_domain":"t.example.com","dnstt_bind":"0.0.0.0:5353"})
c.update({"dnstt_enabled":True,"dnstt_domain":"t.example.com","dnstt_resolver":bip+":5353"})
json.dump(b,open(sys.argv[1],'w'),indent=2); json.dump(c,open(sys.argv[2],'w'),indent=2)
PY
fi
if [ "${GECKO_OBFS:-0}" = 1 ]; then
  # Gecko/Salamander QUIC obfuscation on the QUIC carriers (h3 / hysteria2):
  # every datagram XOR-scrambled + handshake packets fragmented.
  python3 - "$WORK/cfg/bridge.json" "$WORK/cfg/client.json" <<'PY'
import json,sys
b=json.load(open(sys.argv[1])); c=json.load(open(sys.argv[2]))
b.update({"quic_obfs_password":"mirage-gecko-test"})
c.update({"quic_obfs_password":"mirage-gecko-test"})
json.dump(b,open(sys.argv[1],'w'),indent=2); json.dump(c,open(sys.argv[2],'w'),indent=2)
PY
fi
# Self-contained test: the dest is an in-cluster container (private IP), so let
# the bridge exit reach it (default policy denies private targets for SSRF).
sed -i 's/"allow_private_network_targets": false/"allow_private_network_targets": true/' "$WORK/cfg/bridge.json"

say "4. Network + containers"
DEST_IP=10.89.42.30
podman rm -f mirage-bridge mirage-client mirage-dest >/dev/null 2>&1 || true
podman network rm "$NET" >/dev/null 2>&1 || true
podman network create --subnet "$SUBNET" "$NET" >/dev/null
# Destination: an HTTP server returning a LARGE body (~104 KiB of a repeated
# marker). Large enough to exercise record-splitting / large-transfer paths
# WITHOUT depending on any external service. One EXEC per connection.
podman run -d --name mirage-dest --network "$NET" --ip "$DEST_IP" "$IMG" sh -c \
  'python3 -c "import sys; b=b\"MIRAGE_E2E_OK\"*8000; sys.stdout.buffer.write(b\"HTTP/1.1 200 OK\r\nContent-Length: \"+str(len(b)).encode()+b\"\r\nConnection: close\r\n\r\n\"+b)" > /resp; \
   exec socat TCP-LISTEN:80,reuseaddr,fork EXEC:"cat /resp"' >/dev/null
# Optional: forward the shaper-v2 envelope-pacing opt-in to BOTH endpoints so a
# reality run can be validated with pacing on (MIRAGE_REALITY_PACE=video|browse|replay).
# For replay, also mount the real-capture profile CSV and point both ends at it.
# No-op when unset - the default carrier byte path is unchanged.
PACE_ARG=()
[ -n "${MIRAGE_REALITY_PACE:-}" ] && PACE_ARG=(-e "MIRAGE_REALITY_PACE=$MIRAGE_REALITY_PACE")
if [ -n "${MIRAGE_REALITY_PACE_PROFILE:-}" ]; then
  # Mount the profile path (a single trace file OR a directory library) at /profile;
  # the carrier's read_profile handles either (a dir = a random trace per session).
  PACE_ARG+=(-e "MIRAGE_REALITY_PACE_PROFILE=/profile" \
             -v "$MIRAGE_REALITY_PACE_PROFILE:/profile:ro,Z")
fi
podman run -d --name mirage-bridge --network "$NET" --ip "$BRIDGE_IP" \
  "${PACE_ARG[@]}" \
  -v "$WORK/cfg/bridge.json:/bridge.json:ro,Z" "$IMG" mirage-bridge /bridge.json >/dev/null
podman run -d --name mirage-client --network "$NET" --ip "$CLIENT_IP" \
  "${PACE_ARG[@]}" \
  -v "$WORK/cfg/client.json:/client.json:ro,Z" "$IMG" \
  mirage-client /client.json --management-bind 127.0.0.1:19443 >/dev/null

say "5. Wait for readiness"
for i in $(seq 1 20); do
  podman exec mirage-bridge sh -c "ss -ltn 2>/dev/null | grep -q ':8443'" && break
  sleep 0.5
done
sleep 2

RC=0
say "6a. In-cluster LARGE round-trip (~104 KiB): SOCKS5 -> tunnel -> bridge -> dest"
OUT="$(podman exec mirage-client curl -s --max-time 25 --socks5 127.0.0.1:1080 http://$DEST_IP/ 2>&1)"
BYTES=$(printf %s "$OUT" | wc -c)
if printf %s "$OUT" | grep -q "MIRAGE_E2E_OK" && [ "$BYTES" -ge 100000 ]; then
  echo -e "  \033[1;32mPASS\033[0m: $BYTES bytes routed intact through the bridge [$TRANSPORT]"
else
  echo -e "  \033[1;31mFAIL\033[0m: in-cluster large round-trip ($BYTES bytes)"; echo "$OUT" | head -2; RC=1
fi

say "6b. Real external HTTPS via tunnel: $TARGET_URL (egress + remote DNS + TLS) - informational"
OUT2="$(podman exec mirage-client curl -s --max-time 25 --socks5-hostname 127.0.0.1:1080 "$TARGET_URL" 2>&1)"
if printf %s "$OUT2" | grep -q '"origin"'; then
  echo -e "  \033[1;32mPASS\033[0m: $(printf %s "$OUT2" | tr -d '\n ') via tunnel [$TRANSPORT]"
else
  # External service may be down (e.g. httpbin 503) - do NOT fail the run on it;
  # the self-contained large test (6a) is the authoritative tunnel check.
  echo -e "  \033[1;33mSKIP\033[0m: external target unavailable (not a tunnel failure): $(printf %s "$OUT2" | grep -oiE '503|timed out|refused|could not resolve' | head -1)"
fi

say "7. mirage status (per-transport learning, live)"
podman exec mirage-client mirage-client status --management-bind 127.0.0.1:19443 2>&1 | head -13 || true

say "8. UDP-over-TCP: SOCKS5 UDP ASSOCIATE -> DNS query to 8.8.8.8 over the tunnel"
UOUT="$(podman exec mirage-client python3 /usr/local/bin/udp_socks_test.py 2>&1)"
if echo "$UOUT" | grep -q "PASS:"; then
  echo -e "  \033[1;32mPASS\033[0m: $(echo "$UOUT" | grep PASS) [$TRANSPORT]"
else
  echo -e "  \033[1;31mFAIL\033[0m: UDP-over-tunnel"; echo "$UOUT" | head -4; RC=1
fi

say "diagnostics"
echo "--- bridge logs (tail) ---"; podman logs --tail 15 mirage-bridge 2>&1
echo "--- client logs (tail) ---"; podman logs --tail 15 mirage-client 2>&1

exit ${RC:-1}
