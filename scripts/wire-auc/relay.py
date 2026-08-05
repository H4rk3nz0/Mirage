#!/usr/bin/env python3
"""A censor sitting on the wire between a Mirage client and its bridge.

Forwards bytes unchanged and logs every TLS record it sees, by direction, with a
timestamp - exactly the observable a DPI box has, and exactly what
`flow_classifier` consumes. Parsing the 5-byte record header rather than counting
socket reads matters: the kernel coalesces, so read() sizes are an artefact of
buffering while record sizes are what actually crossed.

    relay.py <listen_port> <forward_port> <out.tsv>

Rows: t_monotonic <TAB> direction (down=1 / up=-1) <TAB> record_size
"""
import asyncio, sys, time, traceback

LISTEN, FORWARD, OUT = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
FH = open(OUT, 'w', buffering=1)
nrows = 0
conns = 0


def flush():
    try:
        FH.flush()
    except Exception:
        pass
    print(f"conns={conns} records={nrows} -> {OUT}", flush=True)


async def pump(reader, writer, direction):
    """Copy one direction, emitting a row per complete TLS record.

    Half-close rather than close: a TLS session can legitimately finish one
    direction first, and tearing down the peer writer on the first EOF kills the
    session under measurement (observed as `early eof` at the client).
    """
    buf = bytearray()
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
            buf += chunk
            while len(buf) >= 5:
                total = 5 + ((buf[3] << 8) | buf[4])
                if len(buf) < total:
                    break
                global nrows
                FH.write(f'{time.monotonic():.6f}\t{direction}\t{total}\n')
                nrows += 1
                del buf[:total]
    except Exception:
        pass
    finally:
        try:
            if writer.can_write_eof():
                writer.write_eof()
        except Exception:
            pass


async def handle(cr, cw):
    global conns
    conns += 1
    try:
        sr, sw = await asyncio.open_connection("127.0.0.1", FORWARD)
    except OSError as e:
        print(f"upstream connect failed: {e}", flush=True)
        cw.close()
        return
    try:
        await asyncio.gather(
            # client -> bridge is UPSTREAM (-1); bridge -> client is DOWNSTREAM (1)
            pump(cr, sw, -1),
            pump(sr, cw, 1),
        )
    except Exception:
        traceback.print_exc()
    finally:
        for w in (cw, sw):
            try:
                w.close()
            except Exception:
                pass


async def main():
    server = await asyncio.start_server(handle, "127.0.0.1", LISTEN)
    print(f"relay {LISTEN} -> {FORWARD}", flush=True)
    async with server:
        await server.serve_forever()


try:
    asyncio.run(main())
except (KeyboardInterrupt, SystemExit):
    pass
finally:
    flush()
