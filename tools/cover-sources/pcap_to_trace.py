#!/usr/bin/env python3
"""Convert a raw pcap into a Proteus trace, with provenance.

    pcap_to_trace.py <pcap> <server-ip> <out.csv> <url> <host> <conns>

Emits `t,size,dir` for every complete TLS record, direction relative to the
CLIENT (-1 = up/client->server, 1 = down), with the `#` provenance header the
pacer's parser ignores.

Why records and not packets: the pacer replays TLS record envelopes. A packet is
an artefact of MTU and coalescing; a record is what the endpoint actually chose to
emit. Reassembling the byte stream per direction and walking the 5-byte record
headers gives the latter.

Both directions come from ONE capture, which is where the joint-structure
correctness fix is enforced: request-response causality at one RTT only survives
if the two directions are the same flow, and a schedule built from two unrelated
captures emits shapes real traffic never produces.
"""
import subprocess
import sys
import time


def main():
    pcap, ips, out, url, host, conns = sys.argv[1:7]
    # Comma-separated: a host commonly has both A and AAAA records and the
    # browser picks one. Accepting only one family captures nothing for the other.
    addrs = [a for a in ips.split(",") if a]
    ipfilter = " || ".join(f"ip.addr=={a}" if ":" not in a else f"ipv6.addr=={a}"
                           for a in addrs)

    # tshark gives us reassembled per-direction payload in order; we walk record
    # headers ourselves rather than trusting a dissector's record boundaries.
    cmd = [
        "tshark", "-r", pcap, "-Y", f"tcp.port==443 && ({ipfilter})",
        "-T", "fields", "-e", "frame.time_epoch", "-e", "ip.dst", "-e", "ipv6.dst",
        # PER-STREAM index. Buffering by direction alone concatenates the byte
        # streams of every concurrent connection, so record-header walking runs
        # across splice points and invents records - the first converted trace had
        # a 63627-byte "record" against a 16413-byte TLS maximum. With 3-4
        # concurrent connections to one origin this is the normal case, not an
        # edge case.
        "-e", "tcp.stream", "-e", "tcp.payload",
    ]
    try:
        raw = subprocess.run(cmd, capture_output=True, text=True, timeout=120).stdout
    except Exception as e:
        print(f"tshark failed: {e}", file=sys.stderr)
        raw = ""

    # Per-direction byte accumulators, so record boundaries survive segmentation.
    # Keyed by (tcp.stream, direction): record boundaries only mean anything
    # within a single connection.
    buf = {}
    rows = []
    t0 = None
    for line in raw.splitlines():
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        ts = float(parts[0])
        dst = parts[1] or parts[2]          # v4 or v6, whichever this frame has
        stream, payload = parts[3], parts[4].replace(":", "")
        if not payload:
            continue
        if t0 is None:
            t0 = ts
        d = 1 if dst not in addrs else -1   # to us = down, to server = up
        try:
            data = bytes.fromhex(payload)
        except ValueError:
            continue
        key = (stream, d)
        b = buf.setdefault(key, bytearray())
        b += data
        while len(b) >= 5:
            total = 5 + ((b[3] << 8) | b[4])
            # A record longer than the TLS maximum means the stream is desynced
            # (capture gap, or a non-TLS flow on 443). Drop this stream rather
            # than emit invented records.
            if total > 16413 + 512:
                buf[key] = bytearray()
                break
            if len(b) < total:
                break
            # Timestamped at the segment that completed the record - when it was
            # observable on the wire.
            rows.append((ts - t0, total, d))
            del b[:total]

    rows.sort(key=lambda r: r[0])
    with open(out, "w") as f:
        f.write(
            "# mirage-cover-trace v1\n"
            f"# recorded_at_unix={int(time.time())}\n"
            f"# cover_host={host}\n"
            f"# source_url={url.replace(',', '%2C')}\n"
            "# http_version=h2\n"
            "# alpn=h2,http/1.1\n"
            "# recorder=browser-capture/firefox\n"
            f"# connections={conns}\n"
            "t,size,dir\n"
        )
        for t, sz, d in rows:
            f.write(f"{t:.6f},{sz},{d}\n")


if __name__ == "__main__":
    main()
