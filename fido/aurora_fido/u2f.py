# SPDX-License-Identifier: MIT
"""CTAP1/U2F (FIDO U2F raw messages) over CTAPHID_MSG.

U2F has no way to wait for the user inside a request: the client repeats the
request while the authenticator answers "conditions not satisfied" (0x6985).
So a request that needs the user starts one Touch ID prompt in the
background and answers 0x6985 until it finishes; a match is then good for one
operation on that application within 10 seconds. A refused or timed-out
prompt is not restarted while the client keeps polling; a new ceremony (no
request for 3 seconds) starts a new prompt.

Key handles are credential IDs wrapped for the application parameter (the
U2F twin of the CTAP2 rpIdHash), at most 255 bytes. Registration uses self
attestation: a certificate made and signed by the new key itself.
"""

import hashlib
import logging
import os
import struct
import threading
import time

from . import keys, touchid
from .backend import InvalidHandle
from .creds import ID_MAX_U2F, Credential

log = logging.getLogger("aurora-fido")

SW_NO_ERROR = 0x9000
SW_CONDITIONS_NOT_SATISFIED = 0x6985
SW_WRONG_DATA = 0x6A80
SW_WRONG_LENGTH = 0x6700
SW_CLA_NOT_SUPPORTED = 0x6E00
SW_INS_NOT_SUPPORTED = 0x6D00

INS_REGISTER = 0x01
INS_AUTHENTICATE = 0x02
INS_VERSION = 0x03

GRANT_LIFETIME = 10.0
NEW_CEREMONY_GAP = 3.0


def _sw(code, data=b""):
    return data + struct.pack(">H", code)


def parse_apdu(apdu):
    """(cla, ins, p1, p2, data) from a short or extended APDU; ValueError if malformed."""
    if len(apdu) < 4:
        raise ValueError("short")
    cla, ins, p1, p2 = apdu[:4]
    body = apdu[4:]
    if not body:
        return cla, ins, p1, p2, b""
    if body[0] == 0 and len(body) >= 3:
        lc = int.from_bytes(body[1:3], "big")
        data = body[3:3 + lc]
        rest = body[3 + lc:]
        if len(data) != lc or len(rest) not in (0, 2):
            raise ValueError("extended length")
        return cla, ins, p1, p2, data
    if body[0] == 0 and len(body) == 1:
        return cla, ins, p1, p2, b""          # short Le only
    lc = body[0]
    data = body[1:1 + lc]
    rest = body[1 + lc:]
    if len(data) != lc or len(rest) > 1:
        raise ValueError("short length")
    return cla, ins, p1, p2, data


class Presence:
    """The background Touch ID prompt that U2F polls."""

    def __init__(self, verifier, clock=time.monotonic):
        self.verifier = verifier
        self.clock = clock
        self.lock = threading.Lock()
        self.app = None
        self.thread = None
        self.result = None
        self.result_at = 0.0
        self.last_poll = -1e9
        self.cancel = threading.Event()

    def _run(self, prompt, cancel):
        r = self.verifier.verify(prompt, cancel)
        with self.lock:
            self.result, self.result_at = r, self.clock()

    def check(self, app, prompt):
        """True once (consumed) when a fresh match for app exists; else start or keep waiting."""
        with self.lock:
            now = self.clock()
            gap = now - self.last_poll
            self.last_poll = now
            running = self.thread is not None and self.thread.is_alive()
            if self.app == app and self.result == touchid.MATCH \
                    and now - self.result_at <= GRANT_LIFETIME:
                self.result = None
                return True
            if running:
                return False
            if self.app == app and self.result is not None and gap < NEW_CEREMONY_GAP:
                return False          # refused or timed out: no new prompt while polling
            self.app, self.result = app, None
            self.cancel = threading.Event()
            self.thread = threading.Thread(target=self._run, args=(prompt, self.cancel),
                                           name="u2f-touchid", daemon=True)
            self.thread.start()
            return False

    def stop(self):
        self.cancel.set()


class U2F:
    def __init__(self, auth):
        self.auth = auth            # the CTAP2 Authenticator: backend, vault, counter
        self.presence = Presence(auth.verifier)

    def handle(self, apdu):
        try:
            cla, ins, p1, _p2, data = parse_apdu(apdu)
        except ValueError:
            return _sw(SW_WRONG_LENGTH)
        if cla != 0:
            return _sw(SW_CLA_NOT_SUPPORTED)
        try:
            with self.auth.lock:
                if ins == INS_VERSION:
                    return _sw(SW_NO_ERROR, b"U2F_V2") if not data else _sw(SW_WRONG_LENGTH)
                if ins == INS_REGISTER:
                    return self.register(data)
                if ins == INS_AUTHENTICATE:
                    return self.authenticate(p1, data)
        except InvalidHandle:
            return _sw(SW_WRONG_DATA)
        return _sw(SW_INS_NOT_SUPPORTED)

    def register(self, data):
        if len(data) != 64:
            return _sw(SW_WRONG_LENGTH)
        chal, app = data[:32], data[32:]
        if not self.presence.check(app, touchid.Prompt("register", None, "U2F")):
            return _sw(SW_CONDITIONS_NOT_SATISFIED)
        a = self.auth
        handle, point = a.backend.create()
        cred = Credential(handle, os.urandom(32), 1)
        kh = a.vault.wrap(app, cred, ID_MAX_U2F)

        def sign(digest):
            return a.backend.sign(handle, digest)

        cert = keys.self_signed_cert(point, sign, int.from_bytes(os.urandom(8), "big") >> 1)
        sig = sign(hashlib.sha256(b"\x00" + app + chal + kh + point).digest())
        log.info("U2F registration")
        return _sw(SW_NO_ERROR, b"\x05" + point + bytes([len(kh)]) + kh + cert + sig)

    def authenticate(self, p1, data):
        if len(data) < 65 or len(data) != 65 + data[64]:
            return _sw(SW_WRONG_LENGTH)
        chal, app, kh = data[:32], data[32:64], data[65:]
        cred = self.auth.vault.unwrap(app, kh)
        if cred is None:
            return _sw(SW_WRONG_DATA)
        if p1 == 0x07:                                  # check-only
            return _sw(SW_CONDITIONS_NOT_SATISFIED)
        if p1 == 0x03:                                  # enforce user presence
            if not self.presence.check(app, touchid.Prompt("sign-in", None, "U2F")):
                return _sw(SW_CONDITIONS_NOT_SATISFIED)
            up = 0x01
        elif p1 == 0x08:                                # don't enforce
            up = 0x00
        else:
            return _sw(SW_WRONG_DATA)
        ctr = struct.pack(">I", self.auth.counter.next())
        sig = self.auth.backend.sign(
            cred.handle, hashlib.sha256(app + bytes([up]) + ctr + chal).digest())
        return _sw(SW_NO_ERROR, bytes([up]) + ctr + sig)
