#!/usr/bin/env python3
"""Send bytes at a socket verbatim and print what comes back.

curl is the suite's oracle, but curl is a correct client: it will not put a
space before a colon, send two conflicting Content-Length headers, or dribble
a request line one byte per second. Those are exactly the cases where a
server's behaviour matters, so this exists to be the incorrect client.

    raw.py PORT [--keep] [--drip MS] [--abort N] [--timeout S] < request

--keep       leave the write side open after sending (the server must decide
             the request is complete from its framing, not from EOF)
--drip MS    send one byte at a time, MS milliseconds apart -- slow loris
--abort N    read at most N bytes of the response, then close the socket with
             SO_LINGER 0 so the kernel sends RST. This is how a client that
             walks away mid-response is simulated, and the only way to make
             the server's next write(2) fail with EPIPE or ECONNRESET.
--linger S   after a complete response, watch the connection for S seconds
             and print CLOSED or OPEN. This is how "the server reaped an
             idle keep-alive connection" is observed from the outside.
--timeout S  socket timeout, default 10s. There is always one: a test that
             can block forever on a read is worse than a test that fails.

Prints the response bytes on stdout. Exits 0 if anything came back, 3 if the
server closed without sending a byte, 4 on timeout.
"""
import socket
import struct
import sys
import time

args = sys.argv[1:]
port = int(args.pop(0))
keep = False
drip = None
abort = None
linger = None
timeout = 10.0
while args:
    a = args.pop(0)
    if a == "--keep":
        keep = True
    elif a == "--abort":
        abort = int(args.pop(0))
    elif a == "--linger":
        linger = float(args.pop(0))
        keep = True
    elif a == "--drip":
        drip = float(args.pop(0)) / 1000.0
    elif a == "--timeout":
        timeout = float(args.pop(0))
    else:
        sys.exit("raw.py: unknown argument %r" % a)

data = sys.stdin.buffer.read()

s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
try:
    if drip is None:
        s.sendall(data)
    else:
        for i in range(len(data)):
            s.sendall(data[i : i + 1])
            time.sleep(drip)
    if abort is not None:
        got = b""
        while len(got) < abort:
            b = s.recv(min(4096, abort - len(got)))
            if not b:
                break
            got += b
        # SO_LINGER with a zero timeout makes close() send RST instead of
        # FIN, so the server is mid-body with a peer that is not merely
        # finished but gone.
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                     struct.pack("ii", 1, 0))
        s.close()
        sys.stdout.buffer.write(got)
        sys.exit(0)
    if not keep:
        s.shutdown(socket.SHUT_WR)
    out = b""
    try:
        while True:
            b = s.recv(65536)
            if not b:
                break
            out += b
            # With --keep the server may hold the connection open for the
            # next request, so stop at the end of a complete-looking
            # response rather than waiting for a close that is not coming.
            if keep and b"\r\n\r\n" in out:
                head, body = out.split(b"\r\n\r\n", 1)
                n = None
                for line in head.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        n = int(line.split(b":", 1)[1])
                if n is not None and len(body) >= n:
                    break
    except socket.timeout:
        sys.stdout.buffer.write(out)
        sys.exit(4)
    if linger is not None:
        s.settimeout(linger)
        try:
            sys.stdout.buffer.write(b"CLOSED\n" if not s.recv(1) else b"DATA\n")
        except socket.timeout:
            sys.stdout.buffer.write(b"OPEN\n")
finally:
    s.close()

sys.stdout.buffer.write(out)
sys.exit(0 if out else 3)
