#!/usr/bin/env python3
"""Enumerate the cover-capture space and run it once, unattended.

    matrix.py <out-dir> [--secs 60] [--reps 5] [--only class=hls,...] [--dry-run]

WHY A MATRIX AND NOT MORE CAPTURES.

Every cover-class number this project has produced came from a single capture of a
single configuration, and each one was later found to be a property of that
configuration rather than of the class:

  - the HLS gap bound was a property of `maxBufferLength: 10`, not of HLS
  - the browse gap bound was a property of a driver that navigated on a timer
  - the buffered-video row was a property of a file small enough to finish instantly

Each was found one at a time, and each cost a round of measure-conclude-discover.
A one-off capture cannot distinguish "property of the class" from "property of this
cell" because it has no other cell to compare against. The space has to be
enumerated for the question to terminate.

AXES

  class    browse | audio | hls | buffered | hetero | webrtc
  mode     single | sustained | throttled      (how the driver drives it)
  player   native | hlsjs | shaka              (hls only)
  buffer   default | short | long              (players with a buffer knob)
  carriers 1 | 3 | 6 | trace                   (how many concurrent connections)
  rep      0..n-1                              (variance within a cell)

THE `hetero` CLASS IS THE ONE THAT VALIDATES THE ARCHITECTURE. Every other cell
measures one cover class in isolation, which answers whether each carrier is
individually faithful. The design's actual claim is different: that a browse-class
carrier and a video-class carrier running from ONE HOST read as a browser plus a
video player rather than as something else. That is a joint-observability question
and no single-class cell can answer it - a pair can be implausible while both
halves are perfect.

Inapplicable combinations are SKIPPED WITH A REASON rather than silently dropped,
so the table shows what was not run and why. `webrtc` is declared and skipped: it
needs a second peer, which this harness does not have, and a cell that quietly
became something else would be worse than a missing one.

EVERY CELL IS GUARDED. Each capture goes through `hls/check_driver_artifact.py`,
which refuses a periodic driver or a trace that spans less than half its window.
A refused cell is recorded as refused, with its reason, and excluded from the
aggregate - not dropped, because "this cell cannot be measured this way" is a
result.

RESUMABLE. Results append to `results.jsonl` as each cell finishes. Re-running
skips cells already present, so a three-hour run survives an interruption.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
HLS = os.path.join(HERE, "hls")

# Host substring identifying the connection that carries the class's payload.
# Everything else in a capture is browser background traffic.
# Whether a class should still be transmitting at the end of the window. A page
# load is a burst and finishing early is correct; a stream that stops early did
# not run. The guard needs telling which, because it cannot infer it.
SHAPE = {"browse": "burst", "audio": "continuous",
         "hls": "continuous", "buffered": "continuous",
         "hetero": "continuous"}

HOSTS = {
    "hetero": "wikipedia.org",          # both hosts; joint observability is scored separately
    "browse": "",   # per-site; resolved from the cell below
    "audio": "somafm.com",
    "hls": "mux.dev",
    "buffered": "test-videos.co.uk",
}


# M IS A SITE AXIS, NOT A PREF AXIS.
#
# Forcing the connection count through browser prefs was tried and does not work:
# `max-persistent-connections-per-server` does not bind through a CONNECT proxy
# (every origin connection is a proxy connection, and 1 and 6 both yielded one
# connection), and `max-persistent-connections-per-proxy` varied backwards - M=1
# produced 5 connections and M=6 produced 1.
#
# But M never needed forcing. It is already in the capture: `connections.json`
# records `concurrent_open_2s` per host, and different sites naturally produce
# different concurrency - a subresource-heavy page opens more connections than a
# CDN-consolidated one. So sweeping SITES sweeps M, from data already being
# collected, with no proxy problem and no pref that lies.
BROWSE_SITES = {
    # name: url. Chosen to span the concurrency range rather than for content.
    "wikipedia": "https://en.wikipedia.org/wiki/Queueing_theory",
    "mdn": "https://developer.mozilla.org/en-US/docs/Web/HTTP",
    "archlinux": "https://wiki.archlinux.org/title/Main_page",
    "gnu": "https://www.gnu.org/software/coreutils/",
}


def cells(reps):
    """Enumerate the space, with skips carrying reasons."""
    out = []
    for rep in range(reps):
        # The composite: two cover classes from one host, concurrently. This is
        # the configuration whose plausibility the design claims.
        out.append({"cls": "hetero", "mode": "sustained", "player": "native",
                    "buffer": "default", "carriers": "trace", "rep": rep})
        for site in BROWSE_SITES:
            out.append({"cls": "browse", "mode": "single", "player": "native",
                        "buffer": "default", "carriers": "trace", "site": site,
                        "rep": rep})
        for n in ():
            cell = {"cls": "browse", "mode": "single", "player": "native",
                    "buffer": "default", "carriers": n, "rep": rep}
            if n != "trace":
                # NOT SHIPPED AS A WORKING AXIS. Forcing the connection count was
                # attempted two ways and neither demonstrably controls it:
                #   max-persistent-connections-per-server: 1 and 6 both gave one
                #     connection - through a CONNECT proxy every origin connection
                #     is a proxy connection, so the per-server cap does not bind
                #   max-persistent-connections-per-proxy: varied, but BACKWARDS -
                #     M=1 produced 5 connections to the origin and M=6 produced 1
                # An axis whose knob cannot be shown to move the thing it names
                # produces cells that look measured and are not, so it is skipped
                # with its reason rather than reported. Driving M needs either a
                # raw capture (no proxy, so per-server binds) or a browser
                # automation API that controls pooling directly.
                cell["skip"] = (f"carrier count {n} not demonstrably controllable "
                                "through the CONNECT tap; see cells() for the two "
                                "prefs tried and what they measured")
            out.append(cell)
        out.append({"carriers": "trace", "cls": "audio", "mode": "sustained", "player": "native",
                    "buffer": "default", "rep": rep})
        for player in ("hlsjs", "shaka"):
            for buf in ("default", "short", "long"):
                out.append({"carriers": "trace", "cls": "hls", "mode": "sustained", "player": player,
                            "buffer": buf, "rep": rep})
        out.append({"carriers": "trace", "cls": "hls", "mode": "sustained", "player": "native",
                    "buffer": "default", "rep": rep,
                    "skip": "Firefox has no native HLS; the cell is not applicable"})
        for mode in ("sustained", "throttled"):
            out.append({"carriers": "trace", "cls": "buffered", "mode": mode, "player": "native",
                        "buffer": "default", "rep": rep})
        out.append({"carriers": "trace", "cls": "webrtc", "mode": "sustained", "player": "native",
                    "buffer": "default", "rep": rep,
                    "skip": "needs a second peer; no loopback WebRTC peer in this harness"})
    return out


def key(c):
    return (f"{c['cls']}/{c['mode']}/{c['player']}/{c['buffer']}"
            f"/{c.get('site', '-')}/{c['rep']}")


def run_cell(c, outdir, secs, port):
    """One capture. Returns a result dict; never raises."""
    d = os.path.join(outdir, key(c).replace("/", "_"))
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d, exist_ok=True)
    # The carrier-count axis is REAL, not cosmetic: it caps Firefox's persistent
    # connections per server, which is what determines how many concurrent
    # connections a page actually opens. "trace" leaves the browser default, which
    # is the shipping configuration and has to be measured alongside the forced
    # counts rather than assumed to resemble one of them.
    env = dict(os.environ, TAP_PORT=str(port))

    # capture.sh routes non-player names to classes.html; pass the axes through.
    url_args = (f"{c['cls']}&player={c['player']}&buffer={c['buffer']}"
                f"&mode={c['mode']}&rep={c['rep']}")
    if c.get("site"):
        url_args += f"&site={c['site']}"
    try:
        p = subprocess.run(
            ["bash", os.path.join(HLS, "capture.sh"), url_args, d, str(secs)],
            capture_output=True, text=True, timeout=secs + 180, env=env)
        log = p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return {**c, "status": "timeout", "reason": "capture exceeded its own deadline"}

    verdict = re.search(r"VERDICT:(OK|FAIL)([^\n\"]*)", log)
    if not verdict or verdict.group(1) != "OK":
        return {**c, "status": "driver-fail",
                "reason": (verdict.group(2).strip() if verdict else "no verdict")}

    summary = {}
    m = re.search(r"SUMMARY:(\{.*?\})\s*\"?\s*$", log, re.M)
    if m:
        try:
            summary = json.loads(m.group(1).replace('\\"', '"'))
        except json.JSONDecodeError:
            pass

    interval = summary.get("driver_interval_s", 0) or 0
    g = subprocess.run(
        [sys.executable, os.path.join(HLS, "check_driver_artifact.py"),
         d, (BROWSE_SITES[c["site"]].split("/")[2] if c["cls"] == "browse" and c.get("site")
             else HOSTS[c["cls"]]),
         str(secs), str(interval), SHAPE[c["cls"]]],
        capture_output=True, text=True)
    stats = parse_stats(g.stdout)
    if g.returncode != 0:
        return {**c, "status": "refused", **stats,
                "reason": first_refuse(g.stdout), "config": summary.get("config_readback")}
    host_for_m = HOSTS.get(c["cls"], "")
    if c["cls"] == "browse" and c.get("site"):
        host_for_m = BROWSE_SITES[c["site"]].split("/")[2]
    m = read_measured_m(d, host_for_m)
    return {**c, "status": "ok", **stats, "config": summary.get("config_readback"), **m}


def read_measured_m(outdir, host_sub):
    """M as the capture reports it: concurrent opens to the target origin.

    The carrier count a profile justifies, read rather than forced. `connections`
    counts every connection to the host over the whole capture, which includes
    sequential reuse; `concurrent_open_2s` counts only those opened within 2 s of
    the first, which is the parallelism M actually refers to.
    """
    f = os.path.join(outdir, "connections.json")
    if not os.path.exists(f) or not host_sub:
        return {}
    try:
        rows = json.load(open(f))
    except (OSError, json.JSONDecodeError):
        return {}
    hit = [r for r in rows if host_sub in r.get("host", "")]
    # M IS A PROPERTY OF THE COVER HOST'S ROLE, NOT OF THE SITE.
    #
    # Measured: every site's DOCUMENT origin opens exactly one connection, because
    # they all serve HTTP/2 and h2 multiplexes an origin onto one connection by
    # design. The concurrency is on the ASSET origins - wikipedia's document
    # origin opened 1 while wikimedia.org opened 6 and upload.wikimedia.org
    # opened 5, in the same capture.
    #
    # So a bridge whose cover host is a document origin justifies M=1, and
    # multi-carrier replay against it would be unrealistic. A bridge fronting an
    # asset/CDN origin justifies M=5-6. Both are recorded, because which one
    # applies is a deployment choice and the number has to follow it.
    browserish = ("mozilla", "googleapis", "gvt1", "openh264", "firefox", "google.com")
    external = [r for r in rows if not any(k in r.get("host", "") for k in browserish)]
    peak = max(external, key=lambda r: r["concurrent_open_2s"], default=None)
    out = {}
    if hit:
        out.update({"m_total": sum(r["connections"] for r in hit),
                    "m_concurrent": sum(r["concurrent_open_2s"] for r in hit)})
    if peak:
        out.update({"m_peak_origin": peak["host"], "m_peak": peak["concurrent_open_2s"],
                    "origins": len(external)})
    return out


def parse_stats(text):
    """Whole-trace stats, OVERRIDDEN by the burst figures when the class is a burst.

    The guard prints both: a whole-trace summary and, for burst classes, the
    burst's own gaps after trimming post-burst stragglers. Reading only the first
    put browse in the table at 4967 ms - the capture window - when the page load
    it measures has a 95.6 ms worst gap. The correction existed in the guard's
    output and never reached the table, which is the same shape as a value being
    computed and not consumed.
    """
    # Matches the guard's single authoritative line ONLY. The pre-correction
    # figures are printed with a `raw(pre-correction)` prefix precisely so this
    # cannot match them - reading the uncorrected value is what put browse in the
    # table at 4967 ms instead of 95.6 ms.
    m = re.search(r"RESULT span=([\d.]+)s gaps=(\d+) median=([\d.]+)ms "
                  r"max=([\d.]+)ms >1s=(\d+) trimmed=(\d+)"
                  r"(?: untrimmed_max=([\d.]+)ms)?", text)
    if not m:
        return {}
    out = {"span_s": float(m.group(1)), "gaps": int(m.group(2)),
           "median_ms": float(m.group(3)), "max_ms": float(m.group(4)),
           "gaps_over_1s": int(m.group(5)), "trimmed_records": int(m.group(6))}
    if m.group(7):
        out["untrimmed_max_ms"] = float(m.group(7))
    return out


def first_refuse(text):
    for line in text.splitlines():
        if line.startswith("REFUSE"):
            return line[len("REFUSE: "):].strip()
    return "refused"


def table(rows):
    """One table. Aggregated per cell-without-rep, so variance is visible."""
    groups = {}
    for r in rows:
        k = (r["cls"], r["mode"], r["player"], r["buffer"])
        groups.setdefault(k, []).append(r)
    print(f"\n{'class':9} {'mode':10} {'player':7} {'buffer':8} {'n':>3} {'ok':>3} "
          f"{'median':>9} {'max gap':>11} {'>1s':>4}  note")
    print("-" * 104)
    for k in sorted(groups):
        rs = groups[k]
        ok = [r for r in rs if r["status"] == "ok"]
        note = ""
        if not ok:
            st = {r["status"] for r in rs}
            note = f"{'/'.join(sorted(st))}: {rs[0].get('reason', '')[:44]}"
            print(f"{k[0]:9} {k[1]:10} {k[2]:7} {k[3]:8} {len(rs):3d} {0:3d} "
                  f"{'-':>9} {'-':>11} {'-':>4}  {note}")
            continue
        med = sorted(r["median_ms"] for r in ok)
        mx = sorted(r["max_ms"] for r in ok)
        over = sorted(r["gaps_over_1s"] for r in ok)
        cfg = ok[0].get("config") or {}
        if cfg:
            note = ",".join(f"{a}={b}" for a, b in cfg.items())
        print(f"{k[0]:9} {k[1]:10} {k[2]:7} {k[3]:8} {len(rs):3d} {len(ok):3d} "
              f"{med[len(med)//2]:8.2f}ms {mx[len(mx)//2]:10.1f}ms "
              f"{over[len(over)//2]:4d}  {note[:40]}")
    print("-" * 104)
    print("median across reps; a cell with ok=0 was never measurable in that "
          "configuration and its reason is shown.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir")
    ap.add_argument("--secs", type=int, default=60)
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--port", type=int, default=18090)
    ap.add_argument("--only", default="")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    os.makedirs(a.outdir, exist_ok=True)
    results_path = os.path.join(a.outdir, "results.jsonl")
    done = {}
    if os.path.exists(results_path):
        for line in open(results_path):
            if line.strip():
                r = json.loads(line)
                done[key(r)] = r

    plan = cells(a.reps)
    if a.only:
        want = dict(kv.split("=", 1) for kv in a.only.split(","))
        plan = [c for c in plan if all(str(c.get(k)) == v for k, v in want.items())]

    todo = [c for c in plan if key(c) not in done and "skip" not in c]
    est = len(todo) * (a.secs + 25) / 60.0
    print(f"{len(plan)} cells, {len(done)} already done, {len(todo)} to run "
          f"(~{est:.0f} min at {a.secs}s each)")
    if a.dry_run:
        for c in plan:
            print(f"  {key(c):48} {'SKIP: ' + c['skip'] if 'skip' in c else ''}")
        return 0

    for c in plan:
        k = key(c)
        if k in done:
            continue
        if "skip" in c:
            r = {**c, "status": "skipped", "reason": c["skip"]}
        else:
            t0 = time.time()
            r = run_cell(c, a.outdir, a.secs, a.port)
            r["elapsed_s"] = round(time.time() - t0, 1)
            print(f"  {k:48} {r['status']:12} {r.get('reason','')[:40]}", flush=True)
        with open(results_path, "a") as f:
            f.write(json.dumps(r) + "\n")
        done[k] = r

    table([done[key(c)] for c in plan if key(c) in done])
    print(f"\nrows: {results_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
