#!/usr/bin/env bash
# mirage-ephemeral - one-command DISPOSABLE (burner) Mirage bridge.
#
# Generates a fresh operator + bridge keypair and a single-use invite entirely
# in a private temp dir, starts the bridge, prints the invite, and SHREDS every
# key + config when it exits. Nothing persists: kill it (Ctrl+C) and the bridge
# identity is gone forever. For one-off / high-risk use where you don't want a
# long-lived bridge or any key material left on disk.
#
# The generated bridge runs the raw Noise+ML-KEM transport (no Reality cover, so
# no cover host is needed). It is functional but NOT cover-camouflaged - use a
# persistent `mirage-setup` bridge with Reality for a durable, DPI-resistant
# deployment. This is a burner.
#
# Usage:
#   mirage-ephemeral                              # bind 0.0.0.0:8443
#   mirage-ephemeral --endpoint <ip:port>         # advertise this address in the invite
#   mirage-ephemeral --endpoint 203.0.113.7:443 --ttl-hours 6
#   mirage-ephemeral --keep                       # do NOT shred on exit (debug only)
#
# Requires: mirage-keygen + mirage-bridge on PATH or under ./target/{release,debug}.

set -euo pipefail

die() { echo "mirage-ephemeral: $*" >&2; exit 1; }

ENDPOINT="0.0.0.0:8443"
TTL_HOURS=""
KEEP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --endpoint) shift; [ $# -gt 0 ] || die "--endpoint needs host:port"; ENDPOINT="$1" ;;
    --ttl-hours) shift; [ $# -gt 0 ] || die "--ttl-hours needs a number"; TTL_HOURS="$1" ;;
    --keep) KEEP=1 ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
  shift
done

# Locate the two binaries: PATH first, then a local build.
find_bin() {
  local name="$1"
  if command -v "$name" >/dev/null 2>&1; then command -v "$name"; return; fi
  for d in target/release target/debug; do
    [ -x "$d/$name" ] && { printf '%s\n' "$PWD/$d/$name"; return; }
  done
  die "$name not found on PATH or under ./target/{release,debug} (build it first: cargo build --release)"
}
KEYGEN="$(find_bin mirage-keygen)"
BRIDGE="$(find_bin mirage-bridge)"

# Private, in-memory-if-possible workspace. Prefer a tmpfs (/dev/shm) so keys
# never touch persistent storage; fall back to $TMPDIR.
if [ -d /dev/shm ] && [ -w /dev/shm ]; then
  WORK="$(mktemp -d /dev/shm/mirage-eph.XXXXXX)"
else
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/mirage-eph.XXXXXX")"
fi
chmod 700 "$WORK"

cleanup() {
  if [ "$KEEP" -eq 1 ]; then
    echo "mirage-ephemeral: --keep set; leaving $WORK (contains secrets!)" >&2
    return
  fi
  # Best-effort shred of every file, then remove the dir.
  if command -v shred >/dev/null 2>&1; then
    find "$WORK" -type f -exec shred -u {} + 2>/dev/null || true
  fi
  rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

CFG="$WORK/bridge.json"
OUT="$WORK/keygen.json"

# Generate the ephemeral identity + a ready bridge config + the invite.
KEYGEN_ARGS=(--bridge-endpoint "$ENDPOINT" --write-bridge-config "$CFG")
[ -n "$TTL_HOURS" ] && KEYGEN_ARGS+=(--token-ttl-hours "$TTL_HOURS")
"$KEYGEN" "${KEYGEN_ARGS[@]}" >"$OUT" 2>/dev/null \
  || die "mirage-keygen failed (try: $KEYGEN --bridge-endpoint $ENDPOINT)"

INVITE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["invite"]["url"])' "$OUT" 2>/dev/null)" \
  || die "could not extract invite URL from keygen output"
[ -n "$INVITE" ] || die "keygen produced an empty invite"

cat >&2 <<EOF

  +- mirage-ephemeral: disposable bridge running on ${ENDPOINT}
  |  Give this invite to your client(s):
  |
     ${INVITE}
  |
  |  Everything is in ${WORK} and is SHREDDED when you stop this
  |  process (Ctrl+C). No key material persists.
  +-

EOF

# Run the bridge in the foreground; cleanup fires on any exit.
exec "$BRIDGE" "$CFG"
