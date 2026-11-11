# SPDX-License-Identifier: MIT
"""CTAP1/U2F (FIDO U2F raw messages) over CTAPHID_MSG.

U2F has no way to wait for the user inside a request: the client repeats the
request while the authenticator answers "conditions not satisfied" (0x6985).
So a request that needs the user starts one enclave call in the background
and answers 0x6985 until it finishes:

- authenticate (enforce presence): the credential's own signature over the
  request, which the Secure Enclave makes only after a Touch ID match it
  checked; the client's next poll of the same request gets it.
- register: an enclave-checked touch with the presence key (enclave.py); the
  new credential's key signs nothing until it is used.

A refused or timed-out prompt is not restarted while the client keeps
polling; a new ceremony (no request for 3 seconds) starts a new prompt.

Key handles are credential IDs wrapped for the application parameter (the
U2F twin of the CTAP2 rpIdHash), at most 255 bytes. The registration
signature and its certificate come from a software key this daemon run
makes (U2F attestation proves nothing about the hardware here; see
docs/fido.md). "Don't enforce presence" (p1 0x08) is answered without a
touch and without the UP bit, with a signature that verifies against no
credential, because the enclave signs only after a match.
"""

import hashlib
import logging
import os
import struct
import threading
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

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

# A finished enclave call is handed to the client's next poll within this long.
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


class Background:
    """The background enclave call that U2F polls, one request at a time."""

    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.lock = threading.Lock()
        self.key = None
        self.thread = None
        self.result = None          # (touchid result, value)
        self.result_at = 0.0
        self.last_poll = -1e9
        self.cancel = threading.Event()

    def _run(self, fn, cancel):
        try:
            r = fn(cancel)
        except Exception as e:          # the enclave or the key failed: a refusal
            log.error("U2F: %s", e)
            r = (touchid.UNAVAILABLE, None)
        with self.lock:
            self.result, self.result_at = r, self.clock()

    def poll(self, key, fn):
        """The value once fn(cancel) matched for key (consumed); else None (start or wait)."""
        with self.lock:
            now = self.clock()
            gap = now - self.last_poll
            self.last_poll = now
            running = self.thread is not None and self.thread.is_alive()
            if self.key == key and self.result is not None \
                    and self.result[0] == touchid.MATCH and now - self.result_at <= GRANT_LIFETIME:
                value = self.result[1]
                self.result = None
                return value
            if running:
                return None
            if self.key == key and self.result is not None and gap < NEW_CEREMONY_GAP:
                return None           # refused or timed out: no new prompt while polling
            self.key, self.result = key, None
            self.cancel = threading.Event()
            self.thread = threading.Thread(target=self._run, args=(fn, self.cancel),
                                           name="u2f-enclave", daemon=True)
            self.thread.start()
            return None

    def stop(self):
        self.cancel.set()


class U2F:
    def __init__(self, auth):
        self.auth = auth            # the CTAP2 Authenticator: backend, vault, counter, user
        self.presence = Background()
        self._att = ec.generate_private_key(ec.SECP256R1())
        self._att_point = self._att.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint)
        self._att_cert = keys.self_signed_cert(
            self._att_point, self._att_sign, int.from_bytes(os.urandom(8), "big") >> 1)

    def _att_sign(self, digest):
        return self._att.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))

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
        a = self.auth
        prompt = touchid.Prompt("register", None, "U2F")
        ok = self.presence.poll(("reg", app, chal), lambda cancel: (
            a.user.verify(prompt, cancel), True))
        if ok is None:
            return _sw(SW_CONDITIONS_NOT_SATISFIED)
        handle, point = a.backend.create(a.flags)
        cred = Credential(handle, 1, a.policy)
        kh = a.vault.wrap(app, cred, ID_MAX_U2F)
        sig = self._att_sign(hashlib.sha256(b"\x00" + app + chal + kh + point).digest())
        log.info("U2F registration")
        return _sw(SW_NO_ERROR, b"\x05" + point + bytes([len(kh)]) + kh + self._att_cert + sig)

    def authenticate(self, p1, data):
        if len(data) < 65 or len(data) != 65 + data[64]:
            return _sw(SW_WRONG_LENGTH)
        chal, app, kh = data[:32], data[32:64], data[65:]
        cred = self.auth.vault.unwrap(app, kh)
        if cred is None or not self.auth._usable(cred, "U2F"):
            return _sw(SW_WRONG_DATA)
        if p1 == 0x07:                                  # check-only
            return _sw(SW_CONDITIONS_NOT_SATISFIED)
        if p1 == 0x08:                                  # don't enforce: no enclave signature
            ctr = struct.pack(">I", self.auth.counter.next())
            sig = self.auth._probe_sign(app + b"\x00" + ctr + chal)
            return _sw(SW_NO_ERROR, b"\x00" + ctr + sig)
        if p1 != 0x03:
            return _sw(SW_WRONG_DATA)
        user = self.auth.user
        prompt = touchid.Prompt("sign-in", None, "U2F")

        def job(cancel):
            ctr = struct.pack(">I", self.auth.counter.next())
            try:
                r, sig = user.sign(cred.handle,
                                   hashlib.sha256(app + b"\x01" + ctr + chal).digest(),
                                   prompt, cancel)
            except InvalidHandle:
                return touchid.NO_MATCH, None
            return r, (ctr, sig)

        got = self.presence.poll(("auth", app, chal, kh), job)
        if got is None:
            return _sw(SW_CONDITIONS_NOT_SATISFIED)
        ctr, sig = got
        return _sw(SW_NO_ERROR, b"\x01" + ctr + sig)
