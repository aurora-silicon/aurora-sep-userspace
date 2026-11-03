#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""The helper's request checks, without a device. Run as root (CI container)."""
import os
import socket
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
HELPER = os.path.join(HERE, "..", "aurora-userbag-helper-test")
MAGIC = b"AURORA-USERBAG-1\n"


def ask(payload):
    a, b = socket.socketpair()
    p = subprocess.Popen([HELPER], stdin=b, stdout=b)
    b.close()
    a.sendall(payload)
    a.shutdown(socket.SHUT_WR)
    out = a.recv(256)
    a.close()
    p.wait(timeout=10)
    return out.decode()


def req(*fields):
    return MAGIC + b"".join(f.encode() + b"\0" for f in fields)


cases = [
    (b"nonsense", "refused malformed\n"),
    (MAGIC + b"unlock\0nobody", "refused malformed\n"),
    (req("unlock", "root", "pw"), "refused user\n"),
    (req("unlock", "no-such-user-xyz", "pw"), "refused user\n"),
]
if os.getuid() == 0:
    cases.append((req("unlock", "nobody", "pw"), "error no device\n"))

failed = 0
for payload, want in cases:
    got = ask(payload)
    ok = got == want
    failed += not ok
    print(("ok  " if ok else "FAIL"), repr(payload[:40]), "->", repr(got))
sys.exit(1 if failed else 0)
