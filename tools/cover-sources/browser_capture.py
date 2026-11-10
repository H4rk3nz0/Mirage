#!/usr/bin/env python3
"""On-path tap for capturing a REAL BROWSER's TLS record envelope.

    browser_capture.py <listen_port> <out_dir>

WHY THIS EXISTS

Mirage's own recorder offers no ALPN and hand-writes HTTP/1.1 request lines,
while every major cover host serves HTTP/2 to a real browser. The recorded
envelope therefore has the wrong framing, multiplexing and upstream cadence for
the site it names - a constant model-error floor `D0` that no amount of shaping,
smoothing or rate reduction reduces. The fix is to stop synthesising the envelope
and capture one from a browser that genuinely speaks the protocol.

WHAT THIS IS, precisely

An HTTP CONNECT proxy that forwards bytes UNCHANGED and records the TLS record
framing as it passes. It is not a TLS terminator and not a MITM: it never sees
plaintext, never presents a certificate, and never rewrites a byte. The browser's
ClientHello arrives at the origin exactly as the browser wrote it, which is what
makes the capture usable for fingerprint re-derivation as well as for the
envelope.

WHY NOT tcpdump

Raw capture is better and should be preferred where available. It needs
CAP_NET_RAW; on this machine `dumpcap` is root:wireshark 0754 and the invoking
user is not in that group. This path needs no privileges at all.

CAVEATS, because they change what the capture means:

  - One extra loopback hop. Sub-millisecond, but record TIMINGS carry it.
  - Proxying suppresses HTTP/3. For Mirage that is correct rather than a
    limitation - the carrier is TCP+TLS, so the TCP path is the one to model -
    but it does mean this capture cannot tell you what the browser would have
    done over QUIC.
  - Connection reuse and parallelism through a proxy may differ slightly from
    direct. Relevant to the `M` question (how many concurrent connections is
    realistic), so treat connection COUNT from this capture as indicative and
    confirm it against a raw capture before relying on it.

OUTPUT, per connection:
  <out>/conn-<n>.csv       t,size,dir   (dir: 1 = down/from-origin, -1 = up)
  <out>/conn-<n>.meta      host, port, first-seen, browser, record counts
  <out>/conn-<n>.hello     raw ClientHello bytes, verbatim, for fingerprinting
"""
import atexit
import json
import os
import signal
import socket
import socketserver
import sys
import threading
import time

OUT = None
BROWSER = os.environ.get("CAPTURE_BROWSER", "unknown")

# Process-wide epoch. Every connection's row timestamps are relative to its OWN
# start, which makes each trace self-consistent and makes the connections
# mutually incomparable: there is no way to tell from two conn-*.csv files which
# records interleaved with which.
#
# That matters because a real multi-connection page load ALTERNATES - request on
# one connection, response on another, subresource on a third - and that
# alternation is joint structure a replay has to reproduce. Recovering it needs
# per-record flow attribution on a COMMON clock, and without this epoch the
# information is destroyed at capture time, not at parse time.
EPOCH = time.monotonic()
_seq = 0
_seq_lock = threading.Lock()


def next_id():
    global _seq
    with _seq_lock:
        _seq += 1
        return _seq


def pump(src, dst, direction, rows, hello_sink, t0):
    """Copy one direction, emitting a row per COMPLETE TLS record.

    Parsing the 5-byte record header rather than counting socket reads matters:
    the kernel coalesces, so read() sizes are an artefact of buffering while
    record sizes are what actually crossed the wire.
    """
    buf = bytearray()
    try:
        while True:
            chunk = src.recv(65536)
            if not chunk:
                break
            dst.sendall(chunk)
            buf += chunk
            while len(buf) >= 5:
                total = 5 + ((buf[3] << 8) | buf[4])
                if len(buf) < total:
                    break
                rows.append((time.monotonic() - t0, total, direction))
                # The very first upstream record is the ClientHello (handshake,
                # content type 0x16). Keep it verbatim - this is the artifact the
                # fingerprint work needs, and it is only correct because nothing
                # here rewrites bytes.
                if direction == -1 and buf[0] == 0x16 and not hello_sink:
                    hello_sink.append(bytes(buf[:total]))
                del buf[:total]
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        cl = self.request
        head = b""
        while b"\r\n\r\n" not in head:
            b = cl.recv(1)
            if not b:
                return
            head += b
            if len(head) > 8192:
                return
        line = head.split(b"\r\n", 1)[0].decode("latin1")
        parts = line.split()
        if len(parts) < 2 or parts[0].upper() != "CONNECT":
            cl.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            return
        hostport = parts[1]
        host, _, port = hostport.rpartition(":")
        try:
            up = socket.create_connection((host, int(port)), timeout=15)
        except OSError:
            cl.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return
        cl.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        n = next_id()
        rows, hello = [], []
        t0 = time.monotonic()
        # Register BEFORE pumping, so a connection still open at shutdown is
        # still written.
        #
        # This used to write only after both pumps joined - i.e. only when the
        # connection CLOSED - and that silently lost exactly the connections
        # worth capturing. Measured: a 45 s hls.js session produced 47 connection
        # files, 22 hosts, and NOT ONE of them the video stream. The short-lived
        # Mozilla background connections (telemetry, safebrowsing, settings) all
        # closed and were recorded; the one long-lived connection carrying the
        # segments was still open when the browser exited, so it vanished.
        #
        # The failure is silent and looks like success: a healthy directory full
        # of traces, none of them the traffic under study. Any capture taken with
        # the previous version under-represents long-lived connections, which is
        # the population this library exists to model.
        # Keyed by connection id: the value holds mutable row/hello lists, so it
        # cannot live in a set.
        with _live_lock:
            _live[n] = (n, host, port, rows, hello, t0)
        try:
            up_t = threading.Thread(target=pump, args=(cl, up, -1, rows, hello, t0))
            down_t = threading.Thread(target=pump, args=(up, cl, 1, rows, hello, t0))
            up_t.start()
            down_t.start()
            up_t.join()
            down_t.join()
        finally:
            with _live_lock:
                _live.pop(n, None)
        for s in (cl, up):
            try:
                s.close()
            except OSError:
                pass

        if len(rows) < 4:
            return  # not a real session; do not litter the output
        write_conn(n, host, port, rows, hello, closed=True, started_at=t0 - EPOCH)

    # -- end handle --


_live = {}
_live_lock = threading.Lock()
# Written-once bookkeeping. `flush_live()` can be reached from the SIGTERM
# handler AND from serve_forever()'s finally, and both ran: the second call
# reopened an already-written CSV with "w", truncating it, and os._exit() killed
# the process before it could rewrite. That left a 0-byte trace beside a .meta
# claiming 3161 records - a file that lies about itself, which is worse than a
# missing one. Guarded by a lock and skipped if already done.
_written = set()
_write_lock = threading.Lock()


def write_conn(n, host, port, rows, hello, closed, started_at=0.0):
    """Persist one connection. `closed=False` means it was still open at shutdown.

    Recorded explicitly rather than left implicit: an open-at-shutdown trace is
    truncated by the capture, not by the peer, so its LAST gap is an artifact of
    when the browser was killed and must not be read as a cover-traffic gap.
    """
    if len(rows) < 4:
        return
    with _write_lock:
        if n in _written:
            return
        _written.add(n)
    rows = sorted(rows, key=lambda r: r[0])
    base = os.path.join(OUT, f"conn-{n:03d}")
    # Write-then-rename: a reader must never see a half-written trace, and a
    # 0-byte CSV next to a populated .meta is indistinguishable from a real
    # capture of nothing.
    tmp = base + ".csv.tmp"
    with open(tmp, "w") as f:
        f.write("t,size,dir\n")
        for t, sz, d in rows:
            f.write(f"{t:.6f},{sz},{d}\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, base + ".csv")
    ups = sum(1 for r in rows if r[2] < 0)
    with open(base + ".meta", "w") as f:
        f.write(
            f"host={host}\nport={port}\nbrowser={BROWSER}\n"
            f"records={len(rows)}\nup={ups}\ndown={len(rows)-ups}\n"
            f"span_s={rows[-1][0]-rows[0][0]:.3f}\n"
            # Offset of this connection's t=0 from the capture's epoch. Add it to
            # every row timestamp to place all connections on one timeline.
            f"started_at_s={started_at:.6f}\n"
            f"closed={'true' if closed else 'false'}\n"
            f"captured_at_unix={int(time.time())}\n"
        )
    if hello:
        with open(base + ".hello", "wb") as f:
            f.write(hello[0])


def write_index():
    """Per-host connection counts, as a first-class output rather than a file count.

    `M` - how many concurrent carriers a cover profile justifies - is this number,
    and it was previously implicit in how many conn-*.csv files happened to name a
    given host. Something a downstream tool has to reconstruct by globbing is not
    an output; it is a side effect that any change to the file layout silently
    breaks. Written explicitly, with the epoch offsets that make concurrency
    measurable rather than merely countable.
    """
    import collections
    by = collections.defaultdict(list)
    for meta in sorted(glob_meta()):
        kv = dict(l.split("=", 1) for l in open(meta).read().splitlines() if "=" in l)
        if "host" in kv:
            by[kv["host"].strip()].append(float(kv.get("started_at_s", 0.0)))
    rows = []
    for host, starts in sorted(by.items(), key=lambda kv: -len(kv[1])):
        starts.sort()
        # Concurrency is not the same as the total count: connections opened
        # minutes apart are sequential reuse, not parallelism. Count those whose
        # opens fall within 2 s of the first as the concurrent burst.
        concurrent = sum(1 for s in starts if s - starts[0] <= 2.0)
        rows.append({"host": host, "connections": len(starts),
                     "concurrent_open_2s": concurrent,
                     "first_open_s": round(starts[0], 3),
                     "opens_s": [round(x, 3) for x in starts]})
    with open(os.path.join(OUT, "connections.json"), "w") as f:
        json.dump(rows, f, indent=2)


def glob_meta():
    import glob as _g
    return _g.glob(os.path.join(OUT, "conn-*.meta"))


def flush_live():
    """Write every still-open connection. Called on shutdown."""
    with _live_lock:
        snapshot = list(_live.values())
    for (n, host, port, rows, hello, t0) in snapshot:
        try:
            write_conn(n, host, port, list(rows), hello, closed=False, started_at=t0 - EPOCH)
        except OSError:
            pass
    if snapshot:
        print(f"flushed {len(snapshot)} still-open connection(s)", flush=True)
    try:
        write_index()
    except OSError:
        pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    port, OUT = int(sys.argv[1]), sys.argv[2]
    os.makedirs(OUT, exist_ok=True)

    def _bye(_signum=None, _frame=None):
        flush_live()
        os._exit(0)

    # SIGTERM is how the capture scripts stop this, and daemon threads die with
    # the process - so without an explicit flush every open connection is lost.
    signal.signal(signal.SIGTERM, _bye)
    signal.signal(signal.SIGINT, _bye)
    atexit.register(flush_live)

    print(f"capture proxy on {port} -> {OUT}", flush=True)
    try:
        Server(("127.0.0.1", port), Handler).serve_forever()
    finally:
        flush_live()
