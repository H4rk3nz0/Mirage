#!/bin/bash
# Capture browser cover traces by RAW on-path packet capture.
#
#   capture_traces.sh <out-dir> <urls-file> [seconds-per-page]
#
# Replaces the hand-rolled recorder for trace capture. The recorder offers no
# ALPN and writes HTTP/1.1 request lines itself, so its traces are h1 recordings
# of hosts that serve h2 to every real browser - a constant model-error floor no
# amount of shaping reduces. A real browser captured on the wire has the right
# framing, multiplexing and upstream cadence because it genuinely speaks the
# protocol.
#
# Needs CAP_NET_RAW via the `wireshark` group. If the group was added in this
# login session, run under: echo '<cmd>' | newgrp wireshark
#
# PER PAGE it records:
#   <n>.pcap        the raw capture, RETAINED - so the conversion can be
#                   re-derived if the trace format changes, without recapturing
#   <n>.csv         t,size,dir with a provenance header
#   <n>.meta        url, host, connection count, browser, capture time
#
# Connection count is logged per page because "how many carriers is realistic"
# is a property of the cover, not of the protocol: one measured page opened 3
# concurrent h2 connections to a single origin, against a reasoned-from-defaults
# expectation of 1. Whether that is stable across pages decides if the carrier
# count can be a constant or must come from the trace.
set -uo pipefail
OUT="${1:?need out dir}"; URLS="${2:?need urls file}"; SECS="${3:-12}"
HERE="$(cd "$(dirname "$0")" && pwd)"
IFACE="$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'dev \K\S+' | head -1)"
[ -n "$IFACE" ] || { echo "cannot determine egress interface"; exit 2; }
mkdir -p "$OUT"

PROFILE="$OUT/.ffprofile"
mkdir -p "$PROFILE"
cat > "$PROFILE/user.js" <<'PREFS'
// No proxy: the capture must see what the browser actually puts on the wire.
// DoH off so name resolution does not add flows to a resolver we are not
// capturing; telemetry/update/safebrowsing off because they generate their own
// connections that are not the page and would otherwise fill the library with
// browser-vendor traffic (measured: 44 of 45 connections in a 75s session).
user_pref("network.trr.mode", 5);
user_pref("toolkit.telemetry.enabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("app.update.enabled", false);
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);
user_pref("media.volume_scale", "0.0");
PREFS

n=0
while read -r url; do
  case "$url" in ""|\#*) continue ;; esac
  n=$((n+1))
  host="$(echo "$url" | awk -F/ '{print $3}')"
  # BOTH address families. Filtering on one IPv4 address silently captured
  # nothing for hosts the browser reached over IPv6 - two of the first four
  # pages came back with zero connections and looked like a browser failure
  # rather than a filter that could not see them.
  addrs="$(getent ahosts "$host" | awk '{print $1}' | sort -u)"
  if [ -z "$addrs" ]; then echo "  [$n] $host - DNS failed, skipping"; continue; fi
  filt=""
  for a in $addrs; do
    [ -n "$filt" ] && filt="$filt or "
    filt="${filt}host $a"
  done
  ip="$(echo "$addrs" | head -1)"

  # Filter to the TARGET HOST only. Without this the library fills with
  # browser-vendor chatter rather than the site under study.
  dumpcap -i "$IFACE" -f "($filt) and tcp port 443" -w "$OUT/$n.pcap" \
          -a duration:"$SECS" -q >/dev/null 2>&1 &
  cap=$!
  sleep 2
  timeout "$((SECS - 3))" firefox --headless --profile "$PROFILE" \
    --screenshot /dev/null "$url" >/dev/null 2>&1
  wait "$cap" 2>/dev/null

  conns=$(tshark -r "$OUT/$n.pcap" -Y "tcp.flags.syn==1 && tcp.flags.ack==0" 2>/dev/null | wc -l)
  python3 "$HERE/pcap_to_trace.py" "$OUT/$n.pcap" "$(echo "$addrs" | tr "\n" "," | sed "s/,$//")" "$OUT/$n.csv" "$url" "$host" "$conns"
  recs=$(($(wc -l < "$OUT/$n.csv") - 9))
  printf "  [%2d] %-42s conns=%-3s records=%s\n" "$n" "$host" "$conns" "$recs"
done < "$URLS"
echo "captured $n pages into $OUT (pcaps retained)"
