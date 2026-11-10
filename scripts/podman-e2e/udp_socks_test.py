#!/usr/bin/env python3
"""SOCKS5 UDP ASSOCIATE smoke test: perform a real DNS query over UDP through
the Mirage tunnel (client SOCKS5 :1080 -> UDP-over-TCP -> bridge UDP relay ->
8.8.8.8:53 -> back). Proves UoT works end-to-end. Exit 0 on success."""
import socket
import struct
import sys

PROXY = ("127.0.0.1", 1080)


def udp_associate():
    tcp = socket.create_connection(PROXY, timeout=10)
    tcp.sendall(b"\x05\x01\x00")  # greeting: 1 method, NO_AUTH
    if tcp.recv(2) != b"\x05\x00":
        sys.exit("FAIL: socks5 method negotiation")
    # UDP ASSOCIATE, DST 0.0.0.0:0 (we'll send to many dests)
    tcp.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    rep = tcp.recv(10)  # VER REP RSV ATYP BND.ADDR(4) BND.PORT(2)
    if len(rep) < 10 or rep[1] != 0x00:
        sys.exit(f"FAIL: udp associate rejected: {rep!r}")
    bnd_ip = socket.inet_ntoa(rep[4:8])
    bnd_port = struct.unpack("!H", rep[8:10])[0]
    if bnd_ip == "0.0.0.0":
        bnd_ip = PROXY[0]
    return tcp, (bnd_ip, bnd_port)


def dns_query(name):
    q = b"\xab\xcd" + b"\x01\x00" + b"\x00\x01\x00\x00\x00\x00\x00\x00"
    for part in name.split("."):
        q += bytes([len(part)]) + part.encode()
    q += b"\x00\x00\x01\x00\x01"  # root, QTYPE=A, QCLASS=IN
    return q


def wrap(dst_ip, dst_port, data):
    # SOCKS5 UDP request header: RSV(2) FRAG(1) ATYP DST.ADDR DST.PORT + DATA
    return b"\x00\x00\x00\x01" + socket.inet_aton(dst_ip) + struct.pack("!H", dst_port) + data


def unwrap(buf):
    atyp = buf[3]
    if atyp == 1:
        off = 4 + 4 + 2
    elif atyp == 4:
        off = 4 + 16 + 2
    elif atyp == 3:
        off = 4 + 1 + buf[4] + 2
    else:
        sys.exit("FAIL: bad response ATYP")
    return buf[off:]


def main():
    tcp, relay = udp_associate()
    print(f"udp-associate ok; relay socket = {relay}")
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(10)
    query = dns_query("example.com")
    udp.sendto(wrap("8.8.8.8", 53, query), relay)
    data, _ = udp.recvfrom(65535)
    resp = unwrap(data)
    if resp[:2] == b"\xab\xcd" and len(resp) > len(query):
        print(f"PASS: DNS-over-UDP through tunnel ({len(resp)}-byte answer for example.com)")
        tcp.close()
        sys.exit(0)
    sys.exit(f"FAIL: unexpected DNS response ({len(resp)} bytes): {resp[:16].hex()}")


if __name__ == "__main__":
    main()
