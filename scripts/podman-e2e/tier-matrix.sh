#!/usr/bin/env bash
# Separability of every Proteus cost tier against every measurable carrier.
#
# Runs cover-traffic.sh once per (tier, carrier) cell and collects the learned
# distinguisher's verdict into one table. The question each cell answers is the
# same one cover-traffic.sh always asks - can an observer tell an IDLE tunnel
# from a BUSY one - so a cell near 0.5 means the tier's envelope hides user
# activity and a cell near 1.0 means it does not.
#
# The FIRST row is a NULL CONTROL cell: the same protocol with no user traffic at
# all, so there is nothing to detect and whatever it scores is this run's noise
# floor. It is measured here, in-run, rather than cited from elsewhere, because a
# floor from another host or another day does not bound these cells. Read every
# row against it: a cell at or below the CONTROL row is not a result.
#
# Runs are SERIAL on purpose. The measurement is about packet timing, and three
# clusters capturing on one host would contend for the NIC and the scheduler,
# perturbing exactly what is being measured. Parallelism here would buy wall
# clock at the cost of the result meaning anything.
#
# Usage:
#   scripts/podman-e2e/tier-matrix.sh <lib-root> [seconds-per-cell]
#
# <lib-root> holds one cover library per tier:
#   <lib-root>/tier_lean/  <lib-root>/tier_balanced/
# each recorded by mirage-cover-record at that tier. Carriers default to the five
# cover-traffic.sh can actually stand up. meek and DoH are excluded because they
# need real CDN domain-fronting and there is no origin to front in-cluster -
# faking one would measure the fake.
set -u

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LIBROOT="${1:-}"
# 900 s, not less. The harness fixes its phase at 20 s and scales the CYCLE
# count, and the distinguisher needs >= 16 flows per class to mean anything. At
# 900 s a measured run yielded 43 downstream and 15 upstream flows; at 600 s the
# upstream direction lands around 10 and its verdict is noise. An underpowered
# cell is worse than a missing one, because it still prints a number.
SECS="${2:-900}"
[ -d "$LIBROOT" ] || { echo "usage: $0 <lib-root> [seconds-per-cell]"; exit 2; }
LIBROOT="$(cd "$LIBROOT" && pwd)"

TIERS="${TIERS:-lean balanced}"
CARRIERS="${CARRIERS:-reality ws ss2022 hysteria2 h3}"
OUT="${OUT:-$LIBROOT/matrix.tsv}"

printf 'tier\tcarrier\tdirection\tflows\tseparator\taccuracy\tratio\n' > "$OUT"

# Run one cell and append its rows. `$4` non-empty runs it as the NULL CONTROL:
# same protocol, no user traffic in the active windows, so there is nothing to
# detect and whatever it scores is this run's noise floor.
run_cell() {
  tier="$1"; carrier="$2"; lib="$3"; nullctl="${4:-}"
  LOG="$LIBROOT/run_${tier}_${carrier}.log"
  # LIB_UP is the point: the shipped default pairs a dwelled downstream with a
  # DENSE upstream class, because reading gaps destroy upstream capacity and a
  # tunnel's flow control rides upstream. Measuring without it measures a
  # configuration nobody ships, and measures it 20x slower.
  UP=""
  [ -d "$lib/upstream" ] && UP="$lib/upstream"
  CARRIER="$carrier" LIB_UP="$UP" NULL_CONTROL="${nullctl:-0}" \
    "$ROOT/scripts/podman-e2e/cover-traffic.sh" "$lib" "$SECS" > "$LOG" 2>&1
  RC=$?

  RATIO="$(grep -oP 'throughput ratio ACTIVE/IDLE = \K[0-9.]+' "$LOG" | tail -1)"
  [ -z "$RATIO" ] && RATIO="-"

  # cover-traffic.sh emits an "-- up --" / "-- down --" block per direction,
  # each followed by its flow counts and best separator. Pair them up rather
  # than grepping separately, so a missing block cannot silently shift a
  # number onto the wrong direction.
  awk -v tier="$tier" -v carrier="$carrier" -v ratio="$RATIO" '
    /^-- (up|down) \(/ { dir = ($2 == "up") ? "up" : "down"; flows=""; next }
    /flows=/ && dir != "" {
      match($0, /mirage flows=[0-9]+/); m = substr($0, RSTART, RLENGTH)
      sub(/mirage flows=/, "", m); flows = m; next
    }
    /BEST separator:/ && dir != "" {
      match($0, /separator: [a-z_]+/); sep = substr($0, RSTART+11, RLENGTH-11)
      match($0, /accuracy [0-9.]+/); acc = substr($0, RSTART+9, RLENGTH-9)
      printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", tier, carrier, dir, flows, sep, acc, ratio
      dir = ""
    }
  ' "$LOG" >> "$OUT"

  if ! grep -q "BEST separator" "$LOG"; then
    # A cell that produced no verdict must appear in the table as a failure,
    # not vanish - an absent row reads as "not run" and a silently dropped
    # carrier would make the matrix look cleaner than the evidence supports.
    REASON="$(grep -oP '  FAIL: \K.*' "$LOG" | head -1)"
    [ -z "$REASON" ] && REASON="no verdict (rc=$RC)"
    printf '%s\t%s\t-\t-\tFAILED: %s\t-\t%s\n' "$tier" "$carrier" "$REASON" "$RATIO" >> "$OUT"
    echo "  FAILED: $REASON"
  fi
}

# THE FLOOR ROW, measured first and in this same run.
#
# Every accuracy below is a distinguisher's score on ONE host under ONE load,
# and a distinguisher always scores something. Quoting a cell without knowing
# what the harness scores when there is nothing to find invites reading noise
# as a result. So the matrix measures its own floor first, on the same host, the
# same libraries and the same window count as the cells that follow - and a cell
# at or under that floor is not a result however small the number looks.
CONTROL_TIER="$(echo "$TIERS" | awk '{print $1}')"
CONTROL_CARRIER="$(echo "$CARRIERS" | awk '{print $1}')"
CONTROL_LIB="$LIBROOT/tier_$CONTROL_TIER"
if [ -d "$CONTROL_LIB" ]; then
  echo "=== NULL CONTROL tier=$CONTROL_TIER carrier=$CONTROL_CARRIER (${SECS}s, no user traffic) ==="
  run_cell "CONTROL" "$CONTROL_CARRIER" "$CONTROL_LIB" 1
fi

for tier in $TIERS; do
  LIB="$LIBROOT/tier_$tier"
  if [ ! -d "$LIB" ]; then
    echo "SKIP tier=$tier (no library at $LIB)"
    continue
  fi
  for carrier in $CARRIERS; do
    echo "=== tier=$tier carrier=$carrier (${SECS}s) ==="
    run_cell "$tier" "$carrier" "$LIB"
  done
done

echo
echo "== matrix =="
column -t -s "$(printf '\t')" "$OUT"
echo
echo "accuracy 0.5 = an observer cannot tell idle from active; 1.0 = fully separable"
echo "logs: $LIBROOT/run_<tier>_<carrier>.log"
