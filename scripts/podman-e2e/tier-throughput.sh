#!/usr/bin/env bash
# How fast does a tunnel actually move data through each cost tier's envelope?
#
# The separability matrix (tier-matrix.sh) answers "can a censor see the user".
# This answers the other half: "what does the user get". They are different
# questions and this one is ~30x cheaper - separability needs 900 s of packets
# per cell, throughput needs a handful of transfers.
#
# It is worth measuring precisely because the two are the SAME dial. A record
# leaves per schedule token whether or not the app has data, so app bytes
# displace padding rather than adding to it: total bytes on the wire are the same
# idle or busy, which is the point, but it also means the envelope's rate is the
# ceiling on the user's throughput. Buying a cheaper envelope buys a slower
# tunnel, and no amount of tuning separates the two.
#
# Usage:
#   scripts/podman-e2e/tier-throughput.sh <lib-root> [runs-per-cell]
#
# <lib-root> holds one cover library per tier, as tier-matrix.sh expects:
#   <lib-root>/tier_lean/  <lib-root>/tier_balanced/
#
# Serial like the matrix, and for the same reason: two clusters on one host
# contend for the NIC and the scheduler, and here that contention IS the quantity
# being measured.
set -u

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LIBROOT="${1:-}"
RUNS="${2:-5}"
[ -d "$LIBROOT" ] || { echo "usage: $0 <lib-root> [runs-per-cell]"; exit 2; }
LIBROOT="$(cd "$LIBROOT" && pwd)"

TIERS="${TIERS:-lean balanced}"
CARRIERS="${CARRIERS:-reality ws ss2022 hysteria2 h3}"
OUT="${OUT:-$LIBROOT/throughput.tsv}"

printf 'tier\tcarrier\tmedian_ms\tmedian_kbps\tbest_kbps\tworst_kbps\tcompleted\n' > "$OUT"

for tier in $TIERS; do
  LIB="$LIBROOT/tier_$tier"
  if [ ! -d "$LIB" ]; then
    echo "SKIP tier=$tier (no library at $LIB)"
    continue
  fi
  for carrier in $CARRIERS; do
    echo "=== tier=$tier carrier=$carrier (${RUNS} transfers) ==="
    LOG="$LIBROOT/tput_${tier}_${carrier}.log"
    # Same LIB_UP pairing the matrix uses, so this measures the configuration
    # that actually ships rather than a downstream-only one.
    UP=""
    [ -d "$LIB/upstream" ] && UP="$LIB/upstream"
    THROUGHPUT_ONLY=1 THROUGHPUT_RUNS="$RUNS" CARRIER="$carrier" LIB_UP="$UP" \
      "$ROOT/scripts/podman-e2e/cover-traffic.sh" "$LIB" 60 > "$LOG" 2>&1
    RC=$?

    LINE="$(grep -oP '^  RESULT \K.*' "$LOG" | tail -1)"
    if [ -z "$LINE" ]; then
      # A cell that produced no number appears as a failure rather than
      # vanishing - an absent row reads as "not run".
      REASON="$(grep -oP '  FAIL: \K.*' "$LOG" | head -1)"
      [ -z "$REASON" ] && REASON="no result (rc=$RC)"
      printf '%s\t%s\t-\t-\t-\t-\tFAILED: %s\n' "$tier" "$carrier" "$REASON" >> "$OUT"
      echo "  FAILED: $REASON"
      continue
    fi
    MED="$(echo "$LINE" | awk '{print $2}')"
    KBPS="$(echo "$LINE" | awk '{print $3}')"
    DONE="$(echo "$LINE" | awk '{print $4}')"
    FASTKB="$(echo "$LINE" | awk '{print $5}')"
    SLOWKB="$(echo "$LINE" | awk '{print $6}')"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$tier" "$carrier" "$MED" "$KBPS" "$FASTKB" "$SLOWKB" "$DONE" >> "$OUT"
    echo "  median ${MED} ms = ${KBPS} KB/s (best ${FASTKB}, worst ${SLOWKB}, ${DONE} completed)"
  done
done

echo
echo "== throughput by tier and carrier =="
column -t -s"$(printf '\t')" < "$OUT"
echo
echo "120000-byte body per transfer, median of $RUNS, through the same paced"
echo "envelope the separability matrix measures. A tier is a bandwidth budget and"
echo "therefore a throughput ceiling - that is the trade this table prices."
