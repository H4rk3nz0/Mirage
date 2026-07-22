#!/usr/bin/env bash
# WebRTC-transport end-to-end on a rootless Podman cluster, WITH an on-the-wire
# DTLS ClientHello capture + fingerprint assertion.
#
#   client --(SOCKS5)--> mirage-client ==(WebRTC: DTLS/SCTP data channel)==>
#       mirage-bridge --> in-cluster dest
#
# It proves (a) SOCKS traffic tunnels over the real WebRTC transport between two
# containers, and (b) the DTLS ClientHello on the wire is the Chrome/libwebrtc
# fingerprint (record 0xfeff, 11-suite cipher list, 9-entry sig-algs, X25519-first
# groups, 6 permuted extensions, NO GREASE, NO SNI).
#
# Requires binaries built with the webrtc feature:
#   cargo build --release -p mirage-bridge -p mirage-client --features webrtc
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK=/tmp/mirage-podman-webrtc
NET=mirage-webrtc-net
SUBNET=10.89.43.0/24
BRIDGE_IP=10.89.43.10
CLIENT_IP=10.89.43.20
DEST_IP=10.89.43.30
IMG=localhost/mirage-e2e-webrtc:latest
PCAP_HOST="$WORK/dtls_webrtc.pcap"
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

say() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
cleanup() {
  podman exec mirage-bridge sh -c 'kill $(cat /tmp/td.pid) 2>/dev/null' >/dev/null 2>&1 || true
  [ "$KEEP" = 1 ] && { echo "(--keep: cluster left up)"; return; }
  podman rm -f mirage-bridge mirage-client mirage-dest >/dev/null 2>&1 || true
  podman network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

say "1. Require webrtc-feature binaries"
for b in mirage-bridge mirage-client mirage-keygen; do
  [ -x "$ROOT/target/release/$b" ] || { echo "missing target/release/$b (build with --features webrtc)"; exit 1; }
done

say "2. Build runtime image (adds tcpdump for capture)"
mkdir -p "$WORK/build"
cp "$ROOT/target/release/mirage-bridge" "$ROOT/target/release/mirage-client" \
   "$ROOT/target/release/mirage-keygen" "$WORK/build/"
cp "$(dirname "$0")/udp_socks_test.py" "$WORK/build/" 2>/dev/null || true
cat > "$WORK/build/Containerfile" <<'EOF'
FROM docker.io/library/archlinux:latest
RUN pacman -Sy --noconfirm --needed curl iptables iproute2 socat python tcpdump \
    && pacman -Scc --noconfirm
COPY mirage-bridge mirage-client mirage-keygen /usr/local/bin/
ENV RUST_LOG=info
EOF
podman build -t "$IMG" "$WORK/build" >/dev/null || { echo "image build failed"; exit 1; }

say "3. Generate config (Raw invite) + inject WebRTC on both ends"
mkdir -p "$WORK/cfg"
"$ROOT/target/release/mirage-keygen" --bridge-endpoint "$BRIDGE_IP:8443" \
  --write-bridge-config "$WORK/cfg/bridge.json" \
  --write-client-config "$WORK/cfg/client.json" >/dev/null || { echo "keygen failed"; exit 1; }
python3 - "$WORK/cfg/bridge.json" "$WORK/cfg/client.json" "$BRIDGE_IP" <<'PY'
import json,sys
bp,cp,bip=sys.argv[1],sys.argv[2],sys.argv[3]
b=json.load(open(bp)); c=json.load(open(cp))
# Bridge: enable the WebRTC signaling endpoint (mux stays ON to route it); allow
# reaching the in-cluster private dest (SSRF guard off for the test).
b.update({"webrtc_enabled":True,"webrtc_ice_servers":[],
          "allow_private_network_targets":True})
# Client: use ONLY the WebRTC transport (signaling over the bridge mux port).
c.update({"webrtc_signaling_host":f"{bip}:8443","webrtc_path":"/webrtc/offer",
          "webrtc_ice_servers":[]})
json.dump(b,open(bp,'w'),indent=2); json.dump(c,open(cp,'w'),indent=2)
PY

say "4. Network + containers"
podman rm -f mirage-bridge mirage-client mirage-dest >/dev/null 2>&1 || true
podman network rm "$NET" >/dev/null 2>&1 || true
podman network create --subnet "$SUBNET" "$NET" >/dev/null
podman run -d --name mirage-dest --network "$NET" --ip "$DEST_IP" "$IMG" sh -c \
  'python3 -c "import sys; b=b\"MIRAGE_WEBRTC_OK\"*6000; sys.stdout.buffer.write(b\"HTTP/1.1 200 OK\r\nContent-Length: \"+str(len(b)).encode()+b\"\r\nConnection: close\r\n\r\n\"+b)" > /resp; \
   exec socat TCP-LISTEN:80,reuseaddr,fork EXEC:"cat /resp"' >/dev/null
podman run -d --name mirage-bridge --network "$NET" --ip "$BRIDGE_IP" --cap-add NET_RAW \
  -v "$WORK/cfg/bridge.json:/bridge.json:ro,Z" "$IMG" mirage-bridge /bridge.json >/dev/null
podman run -d --name mirage-client --network "$NET" --ip "$CLIENT_IP" \
  -v "$WORK/cfg/client.json:/client.json:ro,Z" "$IMG" \
  mirage-client /client.json --management-bind 127.0.0.1:19443 >/dev/null

say "5. Start DTLS capture inside the bridge container (UDP on eth0)"
# NB: rootless podman's "any" pseudo-interface does NOT capture (no promisc);
# the container's real veth is eth0. Exclude mDNS (5353); keep the muxed
# STUN+DTLS+SCTP UDP that the ICE/DTLS data channel rides on.
# --immediate-mode: deliver packets from the kernel ring to userspace as they
# arrive (else a short burst sits undelivered and is lost on kill). -U: write
# each packet to the pcap immediately (no userspace write buffering).
podman exec -d mirage-bridge sh -c \
  'tcpdump -i eth0 --immediate-mode -U -w /tmp/dtls.pcap "udp and not port 5353" >/tmp/td.log 2>&1 & echo $! > /tmp/td.pid'
sleep 1
podman exec mirage-bridge sh -c 'head -2 /tmp/td.log 2>/dev/null'

say "6. Wait for bridge readiness, then restart client for a FRESH handshake"
for i in $(seq 1 20); do
  podman exec mirage-bridge sh -c "ss -ltn 2>/dev/null | grep -q ':8443'" && break
  sleep 0.5
done
sleep 2
# The client may establish its WebRTC session eagerly at startup (before the
# capture began). Restart it now - with the capture already running - so the
# DTLS handshake for the next request is captured in full.
podman restart mirage-client >/dev/null 2>&1
sleep 3

RC=0
say "7. SOCKS5 round-trip through the WebRTC tunnel (client -> bridge -> dest)"
OUT="$(podman exec mirage-client curl -s --max-time 30 --socks5 127.0.0.1:1080 http://$DEST_IP/ 2>&1)"
sleep 1  # let tcpdump drain the handshake+data packets to disk before we stop it
BYTES=$(printf %s "$OUT" | wc -c)
if printf %s "$OUT" | grep -q "MIRAGE_WEBRTC_OK" && [ "$BYTES" -ge 50000 ]; then
  echo -e "  \033[1;32mPASS\033[0m: $BYTES bytes tunneled over WebRTC/DTLS"
else
  echo -e "  \033[1;31mFAIL\033[0m: WebRTC tunnel round-trip ($BYTES bytes)"; echo "$OUT" | head -3; RC=1
fi

say "8. Stop capture + copy pcap out"
podman exec mirage-bridge sh -c 'kill $(cat /tmp/td.pid) 2>/dev/null; sleep 0.3' || true
podman cp mirage-bridge:/tmp/dtls.pcap "$PCAP_HOST" 2>/dev/null && echo "pcap: $PCAP_HOST"

say "9. Verify the DTLS ClientHello fingerprint on the wire"
# WebRTC muxes STUN + DTLS on ONE ICE UDP port, which defeats tshark's field
# extraction (the conversation gets bound to STUN). So we find the ClientHello
# record by its raw byte signature and assert the fingerprint bytes directly.
# ClientHello record header = 16 (handshake) fe ff (DTLS 1.0) 00 00 (epoch 0).
if command -v tshark >/dev/null 2>&1 && [ -f "$PCAP_HOST" ]; then
  echo "  total packets captured: $(tcpdump -r "$PCAP_HOST" 2>/dev/null | wc -l)"
  # Pull the full UDP payload (not data.data - tshark dissects some frames as
  # dtls, emptying data.data) of every frame carrying a ClientHello record.
  HEX=$(tshark -r "$PCAP_HOST" -Y "udp contains 16:fe:ff:00:00" -T fields \
        -e udp.payload 2>/dev/null | tr -d ':\n' | tr 'A-F' 'a-f')
  chk() { echo "$HEX" | grep -oiqE "$1"; }
  PASS=1
  # Each check pins a LENGTH prefix immediately before the list, so a GREASE
  # value (which would inflate the length and prepend 0x?a?a) cannot slip past:
  #   - cipher list: 0x0016 (22 B = 11 suites) then the exact suites, no prefix
  #   - groups:      0x0006 (6 B = 3 groups) then X25519/P256/P384, no prefix
  #   - sig-algs:    0x0012 (18 B = 9 schemes) then the exact codes incl PSS
  chk "16feff" \
    && echo "  [ok] record version 16 fe ff (handshake, DTLS 1.0)" \
    || { echo "  [!!] record version not 0xfeff"; PASS=0; }
  chk "0016c02bc02fcca9cca8c009c013c00ac014009c002f0035" \
    && echo "  [ok] exact 11-suite Chrome cipher list (no GREASE cipher)" \
    || { echo "  [!!] cipher list / GREASE mismatch"; PASS=0; }
  chk "0006001d00170018" \
    && echo "  [ok] supported_groups X25519/P256/P384 (no GREASE group)" \
    || { echo "  [!!] groups / GREASE mismatch"; PASS=0; }
  chk "0012040308040401050308050501080606010201" \
    && echo "  [ok] 9-entry signature_algorithms incl RSA-PSS + SHA-1 tail" \
    || { echo "  [!!] sig-algs mismatch"; PASS=0; }
  if [ "$PASS" = 1 ] && [ -n "$HEX" ]; then
    echo -e "  \033[1;32mPASS\033[0m: on-wire DTLS ClientHello is the exact Chrome fingerprint"
  else
    echo -e "  \033[1;31mFAIL\033[0m: fingerprint mismatch (or no fresh ClientHello captured)"; RC=1
  fi
else
  echo "  (tshark unavailable or no pcap; skipping wire assertion)"
fi

say "diagnostics"
echo "--- bridge logs ---"; podman logs --tail 12 mirage-bridge 2>&1
echo "--- client logs ---"; podman logs --tail 12 mirage-client 2>&1
exit ${RC:-1}
