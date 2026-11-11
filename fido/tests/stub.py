# SPDX-License-Identifier: MIT
"""Test-only stand-ins. Not installed; the daemon cannot load them.

StubKeyBackend: software P-256 keys that behave like /dev/sep-key keys with a
biometric access-control list: every sign() and unseal() of such a key asks
a scripted "enclave touch" (match, no-match, timeout, wait until cancelled)
and refuses without a match, the way the kernel's SIGN does. The handle is
the private scalar encrypted under a per-process key (or a key from a file);
the private key is in this process's memory: nothing like the Secure
Enclave.
FileSecret: a master secret in a plain file.
"""

import os
import secrets
import threading

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.exceptions import InvalidTag

import struct

from aurora_fido.backend import (BagLocked, EnclaveCancelled, EnclaveRefused, EnclaveTimeout,
                                 InvalidHandle, KeyBackend, PasswordRefused)

MATCH, NO_MATCH, TIMEOUT, WAIT = "match", "no-match", "timeout", "wait"
# Handle layout: "STUB" | gated flag | nonce[12] | AES-GCM(scalar) (48) | pad
_GATED = 0x01


class StubKeyBackend(KeyBackend):
    """mode: match | no-match | timeout | wait | a callable(handle) -> one of those,
    or a list of those used in turn (the last one repeats)."""

    name = "software-stub (TEST ONLY)"

    def __init__(self, key=None, handle_pad=0, mode=MATCH, flags_supported=0x3,
                 can_unseal=True, can_cancel=True, can_password=True, bag_password=b"pw"):
        self._aead = AESGCM(key or secrets.token_bytes(32))
        self.handle_pad = handle_pad      # make handles longer, like a big SEP record
        self.mode = mode
        self.flags_supported = flags_supported
        self.can_unseal = can_unseal
        self.can_cancel = can_cancel
        self.signs = 0                    # signatures the "enclave" made
        self.touches = 0                  # touch waits the "enclave" ran
        self.creates = 0
        # Interface 4 stand-in: one user key bag (any uid), its password and lock.
        self.can_password = can_password
        self.version = 4 if can_password else 3
        self.pin_reboot_proof = False
        self.bag_password = bag_password
        self.bag_locked = False
        self.password_failures = 0
        self.password_signs = 0
        self._cancel = threading.Event()
        self.lock = threading.Lock()

    def create(self, flags, gated=True):
        priv = ec.generate_private_key(ec.SECP256R1())
        scalar = priv.private_numbers().private_value.to_bytes(32, "big")
        nonce = secrets.token_bytes(12)
        handle = (b"STUB" + bytes([_GATED if gated else 0]) + nonce
                  + self._aead.encrypt(nonce, scalar, b"stub") + b"\0" * self.handle_pad)
        self.creates += 1
        self.last_flags = flags
        return handle, self._point(priv)

    # Interface 4: a SEPK version-2 header (as the kernel writes it) around a stub handle.
    def create_user(self, uid, presence):
        if not self.can_password:
            raise AssertionError("create_user on a stub without interface 4")
        if self.bag_locked:
            raise BagLocked("bag locked")
        inner, point = self.create(0x4 if presence else 0, gated=presence)
        flags = 0x04 if presence else 0x0C
        return (b"SEPK" + bytes([2, flags, 0, 0]) + struct.pack("<II", len(inner), uid)
                + inner, point)

    @staticmethod
    def _user(handle):
        """(inner stub handle, flags) of a version-2 handle, or (handle, None)."""
        if isinstance(handle, bytes) and handle[:5] == b"SEPK\x02" and len(handle) > 16:
            return handle[16:], handle[5]
        return handle, None

    def gated(self, handle):
        inner, uflags = self._user(handle)
        if uflags is not None:
            return uflags == 0x04
        return isinstance(handle, bytes) and handle[:4] == b"STUB" and len(handle) > 4 \
            and bool(handle[4] & _GATED)

    @staticmethod
    def _point(priv):
        return priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    def _priv(self, handle):
        handle, _ = self._user(handle)
        if handle[:4] != b"STUB" or len(handle) < 5 + 12 + 48:
            raise InvalidHandle("not a stub handle")
        try:
            scalar = self._aead.decrypt(handle[5:17], handle[17:65], b"stub")
        except InvalidTag as e:
            raise InvalidHandle("stub handle from another key") from e
        return ec.derive_private_key(int.from_bytes(scalar, "big"), ec.SECP256R1())

    def _next_mode(self, handle):
        m = self.mode
        if isinstance(m, list):
            m = m.pop(0) if len(m) > 1 else m[0]
        if callable(m):
            m = m(handle)
        return m

    def _touch(self, handle):
        """The scripted enclave match for a gated key; raises like the kernel."""
        if self._user(handle)[1] is not None and self.bag_locked:
            raise BagLocked("bag locked")
        if not self.gated(handle):
            return
        with self.lock:
            self.touches += 1
        m = self._next_mode(handle)
        if m == WAIT:
            if self._cancel.wait(30):
                self._cancel.clear()
                raise EnclaveCancelled("cancelled")
            raise EnclaveTimeout("no touch")
        if m == TIMEOUT:
            raise EnclaveTimeout("no touch")
        if m == NO_MATCH:
            raise EnclaveRefused("no Touch ID match")
        if m == "reject":
            raise InvalidHandle("enclave refused the key")
        if m != MATCH:
            raise AssertionError(f"stub mode {m!r}")

    def sign(self, handle, digest):
        priv = self._priv(handle)
        self._touch(handle)
        self.signs += 1
        return priv.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))

    def seal(self, handle, secret):
        self._priv(handle)
        nonce = secrets.token_bytes(12)
        return nonce + AESGCM(self._seal_key(handle)).encrypt(nonce, secret, b"seal")

    def _seal_key(self, handle):
        return self._priv(handle).private_numbers().private_value.to_bytes(32, "big")

    def unseal(self, handle, sealed):
        self._priv(handle)
        self._touch(handle)
        try:
            return AESGCM(self._seal_key(handle)).decrypt(sealed[:12], sealed[12:], b"seal")
        except InvalidTag as e:
            raise InvalidHandle("sealed for another key") from e

    def _password(self, handle, password):
        if self._user(handle)[1] != 0x04:
            raise InvalidHandle("password calls take .userPresence keys under a user bag")
        if self.bag_locked:
            raise BagLocked("bag locked")
        if bytes(password) != self.bag_password:
            self.password_failures += 1
            raise PasswordRefused("wrong password")

    def sign_password(self, handle, digest, password):
        priv = self._priv(handle)
        self._password(handle, password)
        self.signs += 1
        self.password_signs += 1
        return priv.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))

    def unseal_password(self, handle, sealed, password):
        self._priv(handle)
        self._password(handle, password)
        try:
            return AESGCM(self._seal_key(handle)).decrypt(sealed[:12], sealed[12:], b"seal")
        except InvalidTag as e:
            raise InvalidHandle("sealed for another key") from e

    def cancel(self):
        if self.can_cancel:
            self._cancel.set()

    def public(self, handle):
        return self._point(self._priv(handle))


class FileSecret:
    def __init__(self, path):
        self.path = path

    def new(self):
        s = secrets.token_bytes(64)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(s)
        return s

    def load(self):
        if not os.path.exists(self.path):
            return self.new()
        with open(self.path, "rb") as f:
            return f.read()
