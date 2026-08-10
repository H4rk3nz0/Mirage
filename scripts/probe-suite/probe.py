#!/usr/bin/env python3
"""Adversarial probe suite: does the bridge answer like the host it claims to be?

    probe.py <bridge host:port> <cover host:port> <out-dir> [--rounds N]

WHY THIS EXISTS

Active probing is what actually kills deployed circumvention systems - Shadowsocks,
obfs, and every centralised proxy that ever shipped. Passive traffic analysis of a
well-shaped tunnel is not on that list. Yet this repository has sixteen files of
traffic-analysis tooling and, before this one, zero for adversarial probing. That
ratio is inverted against the threat.

WHAT "PASS" MEANS HERE, and why the obvious criterion is wrong

**Rejection is not a pass.** A bridge that cleanly refuses a malformed probe has
told the prober it is not a web server. The criterion is
*byte-and-timing indistinguishability from the real cover host* under the same
probe: same response bytes, same connection lifecycle (FIN vs RST vs timeout vs
silence), same timing distribution.

Mirage's earlier RST-vs-FIN oracle was a rejection, and it was 15/15 separable.

THE COMPARISON MUST BE INTERLEAVED AND IN-SESSION

Every probe is sent to BOTH targets back to back, in randomised order, within the
same run. Not two runs compared afterwards: that reintroduces the sequential-block
confound where anything drifting in time (network, load, CDN node) correlates with
the label and gets learned instead of the difference under study.

This is the same lesson as the traffic work, where comparing Mirage against Mirage
made any defect shared by both arms structurally invisible. Here the negative class
is the real host, probed identically, at the same moment.

THIS TOOL REFUSES RATHER THAN REPORTS when it cannot mean what it says. A run with
no successful real-host observations is not a run with a suspicious bridge - it is
a run with a broken reference arm, and reporting it as the former is exactly the
failure that produced a healthy-looking capture of nothing in the traffic harness.
"""
import argparse
import json
import os
import random
import socket
import ssl
import struct
import sys
import time

# ---------------------------------------------------------------- probe classes

def _client_hello(sni: str, alpn=None, version=b"\x03\x03") -> bytes:
    """A minimal but well-formed TLS 1.2/1.3 ClientHello."""
    exts = b""
    host = sni.encode()
    sn = b"\x00\x00" + struct.pack(">H", len(host) + 5) + struct.pack(">H", len(host) + 3) \
         + b"\x00" + struct.pack(">H", len(host)) + host
    exts += sn
    exts += b"\x00\x2b\x00\x03\x02\x03\x04"                     # supported_versions
    exts += b"\x00\x0a\x00\x04\x00\x02\x00\x1d"                 # supported_groups x25519
    exts += b"\x00\x0d\x00\x04\x00\x02\x04\x03"                 # sig_algs
    if alpn:
        protos = b"".join(bytes([len(p)]) + p for p in alpn)
        exts += b"\x00\x10" + struct.pack(">H", len(protos) + 2) + struct.pack(">H", len(protos)) + protos
    body = version + os.urandom(32) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" \
           + struct.pack(">H", len(exts)) + exts
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def probes(sni: str):
    """The probe classes. Cover-host-state variants are first, deliberately.

    An endpoint that behaves differently when its cover host is UNREACHABLE, SLOW,
    or RECOVERING is an oracle available on demand - a prober does not have to wait
    for a real outage, they can induce one. The slow case is the subtler and more
    dangerous of the three: a splice that times out on its own deadline rather than
    the real host's produces the same oracle with a quieter signature, and a suite
    that only tests hard-down passes it cleanly.
    """
    return [
        ("hello-plain",        _client_hello(sni)),
        ("hello-alpn-h2",      _client_hello(sni, alpn=[b"h2", b"http/1.1"])),
        ("hello-alpn-bogus",   _client_hello(sni, alpn=[b"mirage/1"])),
        ("hello-sni-mismatch", _client_hello("not-the-cover-host.invalid")),
        ("hello-tls10",        _client_hello(sni, version=b"\x03\x01")),
        # Truncated at each record boundary: a real stack stalls waiting for the
        # rest; a state machine that validates eagerly may answer early.
        ("trunc-5",            _client_hello(sni)[:5]),
        ("trunc-half",         _client_hello(sni)[: len(_client_hello(sni)) // 2]),
        ("trunc-1",            _client_hello(sni)[:1]),
        # Valid framing, garbage payload: exercises "is this parsed or spliced".
        ("record-badmac",      b"\x16\x03\x03\x00\x20" + os.urandom(32)),
        ("appdata-first",      b"\x17\x03\x03\x00\x20" + os.urandom(32)),
        # Wrong protocol entirely, spoken directly at the port.
        ("http11",             b"GET / HTTP/1.1\r\nHost: " + sni.encode() + b"\r\n\r\n"),
        ("http2-preface",      b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
        # Random bytes at several lengths - the Wu-2023 fully-encrypted shape.
        ("random-16",          os.urandom(16)),
        ("random-512",         os.urandom(512)),
        ("random-4096",        os.urandom(4096)),
        # Connect and say nothing / connect and close immediately.
        ("silence",            b""),
        ("connect-close",      None),
    ]


# ---------------------------------------------------------------- observation

def observe(host, port, payload, read_timeout=6.0):
    """Send one probe; record what a prober can actually see.

    Records bytes, the connection LIFECYCLE, and timings. Lifecycle is the part
    that carried Mirage's previous oracle: FIN, RST, timeout and silence are four
    distinguishable outcomes and a real web server picks among them differently
    from a proxy that is rejecting you.
    """
    t0 = time.monotonic()
    out = {
        "connect_error": None, "connect_s": None,
        "first_byte_s": None, "close_s": None,
        "bytes": 0, "head": "", "close": None,
    }
    try:
        s = socket.create_connection((host, port), timeout=6.0)
    except OSError as e:
        out["connect_error"] = type(e).__name__
        out["close"] = "connect-refused"
        return out
    # TCP setup, recorded SEPARATELY from response latency.
    #
    # Without this, every latency here is "distance to the endpoint + work the
    # endpoint did", and the two are not separable after the fact. Measured, that
    # confound WAS the finding: against a bridge on loopback and a cover host
    # 17.8 ms away, five probe classes separated at AUC=0.000 purely because the
    # arms sat at different distances. `connect-close` happened to isolate it
    # (0.1 ms vs 17.8 ms), but only by accident of being the one class that sends
    # nothing.
    #
    # The obvious repair - re-run with a LOCAL stand-in cover - does not work: it
    # matches distance and destroys server identity at the same time. Tried, and
    # the stand-in sent RST where the real host sends FIN, so 13 of 17 classes
    # separated on the stand-in's quirks.
    #
    # Recording setup separately lets `compare.py --deploy-at-cover-distance`
    # charge the BRIDGE the distance it would pay in a real deployment, against
    # the real cover host's own data. Note the correction ADDS to the bridge
    # rather than subtracting from the cover: a splice relocates cost from the
    # connect phase into the response phase, so a per-arm subtraction is not
    # valid here. See that function for the measured decomposition.
    out["connect_s"] = time.monotonic() - t0
    s.settimeout(read_timeout)
    try:
        if payload is None:
            s.close()
            out["close"] = "local-close"
            return out
        if payload:
            s.sendall(payload)
        buf = b""
        while True:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                out["close"] = "timeout"
                break
            except ConnectionResetError:
                out["close"] = "rst"
                break
            except OSError:
                out["close"] = "error"
                break
            if out["first_byte_s"] is None and chunk:
                out["first_byte_s"] = time.monotonic() - t0
            if not chunk:
                out["close"] = "fin"
                break
            buf += chunk
            if len(buf) > 65536:
                out["close"] = "truncated-by-probe"
                break
        out["bytes"] = len(buf)
        out["head"] = buf[:48].hex()
    finally:
        out["close_s"] = time.monotonic() - t0
        try:
            s.close()
        except OSError:
            pass
    return out


# ---------------------------------------------------------------- run

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bridge")
    ap.add_argument("cover")
    ap.add_argument("outdir")
    ap.add_argument("--rounds", type=int, default=8)
    # Read timeout dominates wall clock: classes that legitimately hang
    # (silence, truncated handshakes) wait it out on BOTH arms every round.
    ap.add_argument("--timeout", type=float, default=6.0)
    # Restrict to named classes. Only legitimate for PRE-REGISTERED
    # re-runs - selecting classes after seeing results and then not
    # paying the multiplicity penalty is exactly how a null becomes a
    # finding. See PREREGISTERED.md.
    ap.add_argument("--only", default=None,
                    help="comma-separated probe class names")
    a = ap.parse_args()

    bh, bp = a.bridge.rsplit(":", 1)
    ch, cp = a.cover.rsplit(":", 1)
    os.makedirs(a.outdir, exist_ok=True)
    sni = ch

    selected = probes(sni)
    if a.only:
        want = {x.strip() for x in a.only.split(",")}
        selected = [(n, p) for n, p in selected if n in want]
        missing = want - {n for n, _ in selected}
        if missing:
            print(f"unknown probe classes: {sorted(missing)}")
            return 2
    rows = []
    for rnd in range(a.rounds):
        for name, payload in selected:
            # Randomised order WITHIN the pair, so a slow drift cannot align with
            # the label. Both arms are probed back to back, same round, same
            # network conditions.
            arms = [("bridge", bh, int(bp)), ("cover", ch, int(cp))]
            random.shuffle(arms)
            for arm, h, p in arms:
                r = observe(h, p, payload, read_timeout=a.timeout)
                r.update(round=rnd, probe=name, arm=arm)
                rows.append(r)

    path = os.path.join(a.outdir, "probes.jsonl")
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")

    # ---- REFUSALS. A run that cannot mean what it says must say so. ----
    cover_ok = sum(1 for r in rows if r["arm"] == "cover" and r["connect_error"] is None)
    bridge_ok = sum(1 for r in rows if r["arm"] == "bridge" and r["connect_error"] is None)
    n_probe = len(selected)

    print(f"wrote {len(rows)} observations to {path}")
    if cover_ok == 0:
        print("REFUSING: no successful observations of the REAL COVER HOST.")
        print("  Every comparison would be against nothing. This is not evidence")
        print("  that the bridge is fine or suspicious - it is a broken reference")
        print("  arm, and reporting it as a result is the same defect as a capture")
        print("  whose relay never attached.")
        return 2
    if cover_ok < n_probe * a.rounds * 0.5:
        print(f"REFUSING: only {cover_ok} cover observations of "
              f"{n_probe * a.rounds} attempted (<50%).")
        print("  The reference arm is too sparse to compare against.")
        return 2
    if bridge_ok == 0:
        print("REFUSING: no successful observations of the BRIDGE.")
        return 2
    print(f"reference arm healthy: cover={cover_ok} bridge={bridge_ok}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
