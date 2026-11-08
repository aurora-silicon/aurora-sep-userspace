# SPDX-License-Identifier: MIT
"""CTAPHID (CTAP 2.1 section 11.2): framing, channels, keepalive and cancel.

One transaction runs at a time, in a worker thread. While it runs, the reader
keeps going: CANCEL on the busy channel cancels it, INIT on that channel
abandons it, and any other request gets CHANNEL_BUSY. The worker's peer
thread sends KEEPALIVE every 100 ms (PROCESSING, or UPNEEDED while Touch ID
is asked for).
"""

import logging
import os
import struct
import threading
import time

from . import ctap2
from .errors import (ERR_CHANNEL_BUSY, ERR_INVALID_CHANNEL, ERR_INVALID_COMMAND,
                     ERR_INVALID_LENGTH, ERR_INVALID_SEQ, ERR_TIMEOUT)

log = logging.getLogger("aurora-fido")

REPORT = 64
INIT_DATA = REPORT - 7
CONT_DATA = REPORT - 5
MAX_PAYLOAD = INIT_DATA + 128 * CONT_DATA     # 7609
BROADCAST = 0xFFFFFFFF

CMD_PING = 0x01
CMD_MSG = 0x03
CMD_LOCK = 0x04
CMD_INIT = 0x06
CMD_WINK = 0x08
CMD_CBOR = 0x10
CMD_CANCEL = 0x11
CMD_KEEPALIVE = 0x3B
CMD_ERROR = 0x3F

CAP_WINK = 0x01
CAP_CBOR = 0x04

KEEPALIVE_PROCESSING = 1
KEEPALIVE_UPNEEDED = 2

ASSEMBLY_TIMEOUT = 0.5
VERSION = (1, 0, 0)


def frames(cid, cmd, payload):
    """The 64-byte reports for one message."""
    out = [struct.pack(">IBH", cid, 0x80 | cmd, len(payload)) + payload[:INIT_DATA]]
    rest, seq = payload[INIT_DATA:], 0
    while rest:
        out.append(struct.pack(">IB", cid, seq) + rest[:CONT_DATA])
        rest, seq = rest[CONT_DATA:], seq + 1
    return [f.ljust(REPORT, b"\0") for f in out]


class _Assembly:
    def __init__(self, cid, cmd, total, data, now):
        self.cid, self.cmd, self.total = cid, cmd, total
        self.data = bytearray(data[:total])
        self.seq = 0
        self.t = now

    def done(self):
        return len(self.data) >= self.total


class _Txn:
    def __init__(self, cid, cmd):
        self.cid, self.cmd = cid, cmd
        self.cancel = threading.Event()
        self.abandoned = False
        self.status = KEEPALIVE_PROCESSING
        self.finished = threading.Event()


class CtapHid:
    def __init__(self, device, authenticator, u2f=None, clock=time.monotonic):
        self.dev = device
        self.auth = authenticator
        self.u2f = u2f
        self.clock = clock
        self.send_lock = threading.Lock()
        self.channels = set()
        self.asm = None
        self.txn = None

    # -- output ---------------------------------------------------------------------

    def send(self, cid, cmd, payload):
        with self.send_lock:
            self._send_locked(cid, cmd, payload)

    def _send_locked(self, cid, cmd, payload):
        for f in frames(cid, cmd, payload):
            self.dev.send(f)

    def error(self, cid, code):
        self.send(cid, CMD_ERROR, bytes([code]))

    # -- input ----------------------------------------------------------------------

    def run(self, stop):
        while not stop.is_set():
            report = self.dev.poll(0.1)
            if self.asm and self.clock() - self.asm.t > ASSEMBLY_TIMEOUT:
                self.error(self.asm.cid, ERR_TIMEOUT)
                self.asm = None
            if report is not None:
                self.packet(report)
        if self.txn:
            self.txn.cancel.set()

    def _busy(self):
        return self.txn is not None and not self.txn.finished.is_set()

    def packet(self, p):
        cid = struct.unpack_from(">I", p)[0]
        if cid == 0:
            return
        b = p[4]
        now = self.clock()
        if b & 0x80:
            cmd = b & 0x7F
            total = struct.unpack_from(">H", p, 5)[0]
            if cmd == CMD_INIT:
                self._init(cid, p[7:7 + min(total, INIT_DATA)], total)
                return
            if cid == BROADCAST or cid not in self.channels:
                self.error(cid, ERR_INVALID_CHANNEL)
                return
            if cmd == CMD_CANCEL:
                if self._busy() and self.txn.cid == cid:
                    log.info("client cancelled")
                    self.txn.cancel.set()
                return
            if self._busy() or (self.asm and self.asm.cid != cid):
                self.error(cid, ERR_CHANNEL_BUSY)
                return
            if self.asm and self.asm.cid == cid:
                # A new request in the middle of one: drop the old one.
                self.asm = None
            if total > MAX_PAYLOAD:
                self.error(cid, ERR_INVALID_LENGTH)
                return
            self.asm = _Assembly(cid, cmd, total, p[7:], now)
        else:
            if self.asm is None:
                return                      # stray continuation: ignore
            if cid != self.asm.cid:
                self.error(cid, ERR_CHANNEL_BUSY)
                return
            if b != self.asm.seq:
                self.error(cid, ERR_INVALID_SEQ)
                self.asm = None
                return
            self.asm.seq += 1
            need = self.asm.total - len(self.asm.data)
            self.asm.data += p[5:5 + min(need, CONT_DATA)]
            self.asm.t = now
        if self.asm and self.asm.done():
            a, self.asm = self.asm, None
            self._dispatch(a.cid, a.cmd, bytes(a.data))

    def _init(self, cid, nonce, total):
        if total != 8:
            self.error(cid, ERR_INVALID_LENGTH)
            return
        if cid == BROADCAST:
            new = self._new_cid()
        else:
            if cid not in self.channels:
                self.error(cid, ERR_INVALID_CHANNEL)
                return
            new = cid
            if self.asm and self.asm.cid == cid:
                self.asm = None
            if self._busy() and self.txn.cid == cid:
                self.txn.abandoned = True
                self.txn.cancel.set()
        caps = CAP_WINK | CAP_CBOR
        self.send(cid, CMD_INIT, bytes(nonce) + struct.pack(">IBBBBB", new, 2, *VERSION, caps))

    def _new_cid(self):
        if len(self.channels) >= 256:
            self.channels.pop()
        while True:
            c = struct.unpack(">I", os.urandom(4))[0]
            if c not in (0, BROADCAST) and c not in self.channels:
                self.channels.add(c)
                return c

    # -- transactions -------------------------------------------------------------------

    def _dispatch(self, cid, cmd, data):
        if cmd == CMD_PING:
            self.send(cid, CMD_PING, data)
        elif cmd == CMD_WINK:
            self.send(cid, CMD_WINK, b"")
        elif cmd == CMD_CBOR:
            self._start(cid, cmd, lambda t: self.auth.handle(data, self._ctx(t)))
        elif cmd == CMD_MSG and self.u2f is not None:
            self._start(cid, cmd, lambda t: self.u2f.handle(data))
        elif cmd == CMD_LOCK:
            self.error(cid, ERR_INVALID_COMMAND)
        else:
            self.error(cid, ERR_INVALID_COMMAND)

    def _ctx(self, txn):
        def up_needed():
            txn.status = KEEPALIVE_UPNEEDED
        return ctap2.Ctx(txn.cancel, up_needed)

    def _start(self, cid, cmd, work):
        txn = _Txn(cid, cmd)
        self.txn = txn

        def worker():
            try:
                resp = work(txn)
            except Exception:                  # never kill the reader
                log.exception("request failed")
                resp = b"\x7f" if cmd == CMD_CBOR else b"\x6f\x00"
            # Under the send lock, so no keepalive can follow the response.
            with self.send_lock:
                txn.finished.set()
                if not txn.abandoned:
                    self._send_locked(cid, cmd, resp)

        def keepalive():
            while not txn.finished.wait(0.1):
                with self.send_lock:
                    if txn.abandoned or txn.finished.is_set():
                        return
                    self._send_locked(cid, CMD_KEEPALIVE, bytes([txn.status]))

        threading.Thread(target=worker, name="ctap-worker", daemon=True).start()
        if cmd == CMD_CBOR:
            threading.Thread(target=keepalive, name="ctap-keepalive", daemon=True).start()
