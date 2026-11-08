# SPDX-License-Identifier: MIT
"""Test-only stand-ins. Not installed; the daemon cannot load them.

StubKeyBackend: software P-256 keys; the "handle" is the private scalar
encrypted under a per-process key (or a key from a file). The private key is
in this process's memory: nothing like the Secure Enclave.
StubVerifier: answers Touch ID prompts from a script (match, no-match,
timeout, ...).
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

from aurora_fido import touchid
from aurora_fido.backend import InvalidHandle, KeyBackend


class StubKeyBackend(KeyBackend):
    name = "software-stub (TEST ONLY)"
    non_extractable = False

    def __init__(self, key=None, handle_pad=0):
        self._aead = AESGCM(key or secrets.token_bytes(32))
        self.handle_pad = handle_pad      # make handles longer, like a big SEP record
        self.signs = 0
        self.creates = 0

    def create(self):
        priv = ec.generate_private_key(ec.SECP256R1())
        scalar = priv.private_numbers().private_value.to_bytes(32, "big")
        nonce = secrets.token_bytes(12)
        handle = b"STUB" + nonce + self._aead.encrypt(nonce, scalar, b"stub") \
            + b"\0" * self.handle_pad
        self.creates += 1
        return handle, self._point(priv)

    @staticmethod
    def _point(priv):
        return priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    def _priv(self, handle):
        if handle[:4] != b"STUB" or len(handle) < 4 + 12 + 48:
            raise InvalidHandle("not a stub handle")
        try:
            scalar = self._aead.decrypt(handle[4:16], handle[16:64], b"stub")
        except InvalidTag as e:
            raise InvalidHandle("stub handle from another key") from e
        return ec.derive_private_key(int.from_bytes(scalar, "big"), ec.SECP256R1())

    def sign(self, handle, digest):
        self.signs += 1
        return self._priv(handle).sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))

    def public(self, handle):
        return self._point(self._priv(handle))


class StubVerifier(touchid.Verifier):
    """mode: match | no-match | timeout | locked | unavailable | wait (until cancelled)."""

    max_tries = 3

    def __init__(self, mode="match"):
        self.mode = mode
        self.prompts = []
        self.lock = threading.Lock()

    def verify(self, prompt, cancel, waiting=lambda: None):
        with self.lock:
            self.prompts.append(prompt)
        waiting()
        if self.mode == "wait":
            cancel.wait(30)
            return touchid.CANCELLED if cancel.is_set() else touchid.TIMEOUT
        if callable(self.mode):
            return self.mode(prompt, cancel)
        return self.mode


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
