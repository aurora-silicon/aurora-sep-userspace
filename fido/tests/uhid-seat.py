#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Through a real /dev/uhid device: per-account credentials, and a hidraw
handle opened under one seat user ends when the seat's user changes.

The test daemon (run-stub-daemon.py --seat-file) is told the seat's user
through a file. Needs root and the uhid module; run by tests/test-uhid.sh.

  sudo python3 tests/uhid-seat.py
"""

import errno
import glob
import os
import select
import struct
import subprocess
import sys
import tempfile
import time

here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(here, ".."))

from aurora_fido import cbor, ctap2, ctaphid  # noqa: E402

PHYS = "HID_PHYS=aurora-fido-test"
CDH = bytes(32)
MAKE = {1: CDH, 2: {"id": "seat.example"}, 3: {"id": b"first"},
        4: [{"type": "public-key", "alg": -7}], 7: {"rk": True}}
failed = 0


def check(ok, what):
    global failed
    print(("PASS " if ok else "FAIL ") + what)
    failed += not ok


def nodes():
    """(path, HID device) of each hidraw node of the test daemon. The HID device
    (its sysfs directory, numbered by the kernel) tells a new node from an old
    one that had the same hidraw number."""
    out = []
    for h in glob.glob("/sys/class/hidraw/hidraw*"):
        try:
            with open(os.path.join(h, "device", "uevent")) as f:
                if PHYS not in f.read().split("\n"):
                    continue
            out.append(("/dev/" + os.path.basename(h),
                        os.path.realpath(os.path.join(h, "device"))))
        except OSError:
            pass
    return out


def wait_for(cond, seconds=10.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        v = cond()
        if v:
            return v
        time.sleep(0.05)
    return None


class Handle:
    """One open hidraw handle speaking CTAPHID."""

    def __init__(self, path):
        self.fd = os.open(path, os.O_RDWR)
        nonce = os.urandom(8)
        self.write(ctaphid.BROADCAST, ctaphid.CMD_INIT, nonce)
        cmd, data = self.read(ctaphid.BROADCAST)
        assert cmd == ctaphid.CMD_INIT and data[:8] == nonce, (cmd, data)
        self.cid = struct.unpack(">I", data[8:12])[0]

    def write(self, cid, cmd, payload):
        for f in ctaphid.frames(cid, cmd, payload):
            os.write(self.fd, b"\0" + f)        # report number 0 first

    def read(self, cid, seconds=10.0):
        """(cmd, payload) of the next message on cid that is not a keepalive."""
        end = time.monotonic() + seconds
        total, cmd, data = None, None, b""
        while True:
            left = end - time.monotonic()
            if left <= 0 or not select.select([self.fd], [], [], left)[0]:
                raise TimeoutError("no answer")
            f = os.read(self.fd, 64)
            if struct.unpack_from(">I", f)[0] != cid:
                continue
            if total is None:
                cmd, total = f[4] & 0x7F, struct.unpack_from(">H", f, 5)[0]
                data = f[7:7 + total]
                if cmd == ctaphid.CMD_KEEPALIVE:
                    total = None
                    continue
            else:
                data += f[5:5 + total - len(data)]
            if len(data) >= total:
                return cmd, data

    def cbor(self, cmd, params=None):
        self.write(self.cid, ctaphid.CMD_CBOR,
                   bytes([cmd]) + (cbor.encode(params) if params is not None else b""))
        c, data = self.read(self.cid)
        assert c == ctaphid.CMD_CBOR, (c, data)
        return data[0], (cbor.decode(data[1:]) if len(data) > 1 else None)

    def dead(self, seconds=10.0):
        """The errno once reads and writes on this handle fail, else None."""
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            try:
                self.write(self.cid, ctaphid.CMD_PING, b"still there?")
                if select.select([self.fd], [], [], 0.05)[0]:
                    os.read(self.fd, 64)
            except OSError as e:
                return e.errno
        return None


def main():
    if os.geteuid() != 0:
        print("needs root (uhid)")
        return 2
    if not wait_for(lambda: not nodes(), 5.0):
        print("another test daemon's device is present")
        return 2
    first, second = 0, 65534            # any two uids
    with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR", "/var/tmp")) as work:
        seat = os.path.join(work, "seat")

        def seat_is(uid):
            with open(seat + ".new", "w") as f:
                f.write("" if uid is None else str(uid))
            os.replace(seat + ".new", seat)

        seat_is(first)
        log = open(os.path.join(work, "daemon.log"), "w")
        daemon = subprocess.Popen(
            [sys.executable, os.path.join(here, "run-stub-daemon.py"), "--state-dir",
             os.path.join(work, "state"), "--touch", "match", "--seat-file", seat],
            stdout=log, stderr=subprocess.STDOUT)
        try:
            node = wait_for(lambda: nodes() and nodes()[0])
            check(node is not None, "device node for the first seat user")
            if node is None:
                return 1
            a = Handle(node[0])
            st, r = a.cbor(ctap2.CMD_MAKE_CREDENTIAL, MAKE)
            check(st == 0, "the first user registers a passkey (status 0x%02x)" % st)
            st, r = a.cbor(ctap2.CMD_GET_ASSERTION, {1: "seat.example", 2: CDH})
            check(st == 0 and r[4]["id"] == b"first", "and signs in with it")

            # The seat's user changes; the first user's process keeps its handle.
            seat_is(second)
            a.write(a.cid, ctaphid.CMD_CBOR,
                    bytes([ctap2.CMD_GET_ASSERTION]) + cbor.encode({1: "seat.example", 2: CDH}))
            try:
                got = a.read(a.cid, 3.0)
            except (TimeoutError, OSError) as e:
                got = e
            check(not isinstance(got, tuple),
                  "a request on the kept handle gets no answer (%r)" % (got,))
            err = a.dead()
            check(err in (errno.ENODEV, errno.EIO),
                  "the kept handle is dead: %s" % (errno.errorcode.get(err) if err else "still alive"))
            new = wait_for(lambda: [n for n in nodes() if n[1] != node[1]])
            check(bool(new), "a new device node is up")
            if not new:
                return 1
            b = Handle(new[0][0])
            st, _ = b.cbor(ctap2.CMD_GET_ASSERTION, {1: "seat.example", 2: CDH})
            check(st == 0x2E, "the second user does not find the first user's passkey "
                  "(status 0x%02x)" % st)
            st, _ = b.cbor(ctap2.CMD_MAKE_CREDENTIAL, {**MAKE, 3: {"id": b"second"}})
            check(st == 0, "and registers its own")
            st, r = b.cbor(ctap2.CMD_GET_ASSERTION, {1: "seat.example", 2: CDH})
            check(st == 0 and r[4]["id"] == b"second" and 5 not in r, "which is the only one it finds")

            # Back to the first user: again a new node, and its passkey is still its own.
            seat_is(first)
            b.write(b.cid, ctaphid.CMD_CBOR, bytes([ctap2.CMD_SELECTION]))
            check(b.dead() in (errno.ENODEV, errno.EIO), "the second user's handle is dead after the change back")
            again = wait_for(lambda: [n for n in nodes() if n[1] != new[0][1]])
            if not again:
                check(False, "a new device node is up")
                return 1
            c = Handle(again[0][0])
            st, r = c.cbor(ctap2.CMD_GET_ASSERTION, {1: "seat.example", 2: CDH})
            check(st == 0 and r[4]["id"] == b"first" and 5 not in r,
                  "the first user finds only its own passkey on the new node")
        finally:
            daemon.terminate()
            daemon.wait(10)
            log.close()
            if failed:
                with open(os.path.join(work, "daemon.log")) as f:
                    print("--- daemon log\n" + f.read())
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
