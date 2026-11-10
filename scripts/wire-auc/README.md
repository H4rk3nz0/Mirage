# Censor-vantage separability, without root or containers

Measures whether a censor watching a paced Mirage tunnel can tell an ACTIVE
session from an IDLE one, reading the real wire.

This is the same question `scripts/podman-e2e/cover-traffic.sh` answers, for
hosts where that one cannot run. It needs **no root, no containers, and no packet
capture privileges** - which matters more than it sounds, because `tcpdump`
usually needs `CAP_NET_RAW`, rootless podman needs kernel overlayfs plus a loaded
`tun` driver, and a machine missing any of those has no way to check its own
tunnel otherwise.

## How it sees the wire

A small TCP relay sits between a real `mirage-client` and a real `mirage-bridge`,
forwards bytes unchanged, and logs every TLS record by direction and time. That is
the DPI box's exact observable, and it needs no privileges because the relay is
just a socket both endpoints agreed to talk through.

It parses the **5-byte TLS record header** rather than counting socket reads. The
kernel coalesces, so read() sizes are an artefact of buffering; record sizes are
what actually crossed. This is the same reasoning behind `RecordTap` in
`mirage-cover`.

What it does NOT see: IP/TCP headers, retransmits, or segmentation. For those,
use the podman harness on a host that can run it.

## Running it

Needs a release build and a matched config pair whose **client dials the relay's
port while the bridge binds a different one**, so every byte of the session
crosses the relay:

```sh
cargo build --release -p mirage-bridge -p mirage-client
mirage-keygen --bridge-endpoint 127.0.0.1:18443 \
  --write-bridge-config cfg/bridge.json --write-client-config cfg/client.json
# then in cfg/bridge.json: "bind": "127.0.0.1:18444"
# and in BOTH: "proteus": "replay", "proteus_profile": "<a trace library>"
# plus the carrier, e.g. reality_enabled on both ends.

WIN=20 PAIRS=8 scripts/wire-auc/run.sh          # captures records.tsv + marks.tsv
python3 scripts/wire-auc/slice.py <dir> 1       # 1 = downstream, -1 = upstream
cargo run -p mirage-adversary --example flow_auc -- \
  <dir>/wire_active.txt <dir>/wire_idle.txt 50
```

Windows alternate in **matched pairs with a randomised order inside each pair**,
as the podman harness does, so a slow drift in the environment cannot correlate
with the label and be learned instead of activity.

## Reading the result

Measured on a paced Reality carrier, 8 pairs of 20 s windows, 7076 records:

```
BEST separator: total_bytes   accuracy 0.584   (0.5 = indistinguishable)
FLOOR at 30 flows/class:      0.617
VERDICT: indistinguishable - at or below this sample size's floor
pooled: 1 window 0.584 (floor 0.617) | 4 windows 0.661 (floor 0.681)
```

Two things to check before believing any run of this:

- **Sample size.** 30-34 flows per class puts the estimator's own floor at 0.617,
  well above the 0.552 a few hundred flows gives. Raise `PAIRS` for a tighter
  bound; the estimator refuses outright below 16 flows per class rather than
  return a number it cannot support.
- **Dropped windows.** If the carrier re-establishes mid-run, some windows capture
  zero records and are silently excluded, leaving the classes unbalanced. `slice.py`
  prints the per-window record count - read it. A run with empty windows in the
  middle measured something other than what it claims to.
