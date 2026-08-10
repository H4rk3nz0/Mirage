#!/usr/bin/env bash
# Capture a segmented-video cover trace at LIBRARY DEFAULTS, through the on-path tap.
#
#   capture.sh <player: hlsjs|shaka> <out-dir> [seconds]
#
# Drives Firefox headless at tools/cover-sources/hls/player.html with its proxy
# pointed at browser_capture.py, so the TLS record envelope of a real player
# fetching real segments is recorded without terminating TLS.
#
# REFUSES TO PRODUCE A TRACE unless the page reports VERDICT:OK. A headless video
# run fails silently in several ways that all leave a healthy-looking directory
# behind - autoplay blocked, stream 404, player stuck on one rendition, page loaded
# but never played. Every one yields a capture of nothing. The page checks that
# playback actually advanced and that segments were actually fetched; this script
# treats anything but OK as a failed run and says so.
set -u

PLAYER="${1:?usage: capture.sh <hlsjs|shaka|browse|buffered|audio|hls> <out-dir> [seconds]}"
OUT="${2:?usage: capture.sh <hlsjs|shaka> <out-dir> [seconds]}"
SECS="${3:-60}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="${TAP_PORT:-18080}"

command -v firefox >/dev/null || { echo "firefox not found"; exit 1; }

# Player libraries are fetched on demand rather than vendored: they are third-party
# minified bundles, and pinning them here would put 1.2 MB of someone else's
# licensed code in an AGPL tree for no benefit. Versions are pinned in the URLs so
# a re-run measures the same players.
fetch() {  # fetch <file> <url>
  [ -s "$HERE/$1" ] && return 0
  echo "== fetching $1"
  curl -fsSL --max-time 120 -o "$HERE/$1" "$2" || { echo "could not fetch $1"; return 1; }
}
fetch hls.min.js "https://cdn.jsdelivr.net/npm/hls.js@1.5.17/dist/hls.min.js" || exit 1
fetch shaka-player.compiled.js "https://cdn.jsdelivr.net/npm/shaka-player@4.11.2/dist/shaka-player.compiled.js" || exit 1
mkdir -p "$OUT" || exit 1

echo "== starting tap on 127.0.0.1:$PORT"
CAPTURE_BROWSER="firefox-$PLAYER" python3 "$HERE/../browser_capture.py" "$PORT" "$OUT" &
TAP=$!
trap 'kill $TAP 2>/dev/null' EXIT
for _ in $(seq 1 20); do ss -ltn 2>/dev/null | grep -q ":$PORT " && break; sleep 0.5; done
ss -ltn 2>/dev/null | grep -q ":$PORT " || { echo "tap failed to listen on $PORT"; exit 1; }

# A throwaway profile: the proxy must be set in prefs (Firefox has no
# --proxy-server), and a fresh profile keeps a warm cache from making the first
# run unrepresentative.
PROF="$(mktemp -d)"
trap 'kill $TAP 2>/dev/null; rm -rf "$PROF"' EXIT
cat > "$PROF/user.js" <<EOF
user_pref("network.proxy.type", 1);
user_pref("network.proxy.ssl", "127.0.0.1");
user_pref("network.proxy.ssl_port", $PORT);
user_pref("network.proxy.http", "127.0.0.1");
user_pref("network.proxy.http_port", $PORT);
user_pref("network.proxy.allow_hijacking_localhost", false);
// HTTP/3 would bypass the TCP tap entirely and the carrier is TCP+TLS.
user_pref("network.http.http3.enable", false);
user_pref("media.autoplay.default", 0);
user_pref("media.autoplay.blocking_policy", 0);
// Without this, page console output never reaches stdout and the run looks like
// a failure that produced trace files - which is precisely the ambiguity the
// verdict exists to remove.
user_pref("devtools.console.stdout.content", true);
user_pref("browser.shell.checkDefaultBrowser", false);
EOF
# Carrier-count axis: cap concurrent connections per origin when asked. Left at
# the browser default otherwise, which is the shipping configuration.
if [ -n "${MAX_CONN_PER_SERVER:-}" ]; then
  cat >> "$PROF/user.js" <<EOF
user_pref("network.http.max-persistent-connections-per-server", $MAX_CONN_PER_SERVER);
user_pref("network.http.max-urgent-start-excessive-connections-per-host", $MAX_CONN_PER_SERVER);
// Through a CONNECT proxy every origin connection is a proxy connection, so the
// per-server cap does not bind - measured, capping it at 1 and at 6 both yielded
// one connection. This is the pref that actually applies on the proxied path.
user_pref("network.http.max-persistent-connections-per-proxy", $MAX_CONN_PER_SERVER);
user_pref("network.http.max-connections", $((MAX_CONN_PER_SERVER * 8)));
EOF
fi
cat >> "$PROF/user.js" <<EOF
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("toolkit.telemetry.enabled", false);
EOF

# Two pages: player.html compares PLAYERS on one class, classes.html compares
# CLASSES with one player each. Same tap, same verdict discipline.
# The first argument is either a bare player name (player.html, the two-player
# comparison) or a class plus extra query axes (classes.html, the matrix driver).
case "$PLAYER" in
  hlsjs|shaka) URL="file://$HERE/player.html?player=$PLAYER&secs=$SECS" ;;
  *)           URL="file://$HERE/classes.html?cls=$PLAYER&secs=$SECS" ;;
esac
LOG="$OUT/browser.log"
echo "== running $PLAYER for ${SECS}s (defaults; no buffer knobs set)"
timeout $((SECS + 60)) firefox --headless --profile "$PROF" --no-remote \
  --new-instance "$URL" > "$LOG" 2>&1 &
FF=$!

# The page writes its verdict to the console; Firefox mirrors page console output
# to stdout in headless mode.
VERDICT=""
for _ in $(seq 1 $(( (SECS + 45) * 2 )) ); do
  if grep -q "VERDICT:" "$LOG" 2>/dev/null; then
    VERDICT="$(grep -m1 -o 'VERDICT:[A-Z]*.*' "$LOG")"
    break
  fi
  kill -0 $FF 2>/dev/null || break
  sleep 0.5
done
kill $FF 2>/dev/null; wait $FF 2>/dev/null

SUMMARY="$(grep -m1 -o 'SUMMARY:{.*}' "$LOG" 2>/dev/null | sed 's/^SUMMARY://')"
echo "== $VERDICT"
[ -n "$SUMMARY" ] && echo "$SUMMARY" | python3 -m json.tool 2>/dev/null

case "$VERDICT" in
  VERDICT:OK*)
    [ -n "$SUMMARY" ] && printf '%s\n' "$SUMMARY" > "$OUT/player-summary.json"
    n=$(ls "$OUT"/conn-*.csv 2>/dev/null | wc -l)
    echo "== OK: $n connection trace(s) in $OUT"
    ;;
  *)
    echo "== FAILED - not producing a trace. This is the correct outcome for a run"
    echo "   that did not actually play video; see $LOG."
    exit 2
    ;;
esac
