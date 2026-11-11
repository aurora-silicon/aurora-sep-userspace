# SPDX-License-Identifier: MIT
"""User presence and user verification, decided by the Secure Enclave.

Nothing in this daemon decides that a touch happened. Every approval is an
enclave signature with a key whose access-control list needs a Touch ID
match the enclave checked itself (backend.py):

- A credential's own signature (makeCredential's attestation or probe
  signature, getAssertion, U2F) waits for the finger in the kernel's SIGN
  call; that call is the approval. hmac-secret's CredRandom is released by
  UNSEAL the same way (a second touch: the signature covers the output).
- Approvals that sign nothing for a relying party (selection, reset, the
  credential-management token, an excluded credential) are a signature by
  the daemon's presence key over 32 fresh random bytes, checked here
  against the key's public point. The presence key has the same
  access-control list as new credentials.

One prompt is up to max_tries enclave calls: a finger that does not match
(EACCES) gets another try, no finger in the window (ETIMEDOUT) or a cancel
ends it. The kernel cannot tell a Touch ID lockout from a miss (both EACCES),
so a locked-out sensor ends after max_tries quick refusals, and the lockout
itself is the enclave's, shared with the login screen and sudo.
"""

import logging
import os
import threading
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from . import cbor, creds, touchid
from .backend import (BackendError, EnclaveCancelled, EnclaveRefused, EnclaveTimeout,
                      InvalidHandle)

log = logging.getLogger("aurora-fido")

PRESENCE_FILE = "presence.key"
# The kernel waits about a minute for a finger; a CANCEL ends it sooner.
ENCLAVE_WAIT = 60.0


def verify_digest(point, digest, der_sig):
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes(point))
    try:
        pub.verify(der_sig, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        return True
    except (InvalidSignature, ValueError):
        return False


class EnclaveUser:
    """Asks the enclave for a Touch ID-approved signature; shows the notification."""

    def __init__(self, backend, state_dir, flags, notifier=None, user="auto",
                 max_tries=3, timeout=30.0):
        self.backend = backend
        self.state_dir = state_dir
        self.flags = flags                  # SEP_KEY_CREATE_* of new keys
        self.notifier = notifier or touchid.Notifier(False)
        self.user = user
        self.max_tries = max(1, int(max_tries))
        self.timeout = float(timeout)
        self.lock = threading.Lock()
        self._presence = None

    # -- the presence key ----------------------------------------------------------

    def _presence_path(self):
        return os.path.join(self.state_dir, PRESENCE_FILE)

    def presence_key(self, renew=False):
        """(handle, point) of the presence key, made on first use."""
        if self._presence and not renew:
            return self._presence
        path = self._presence_path()
        if not renew:
            try:
                with open(path, "rb") as f:
                    rec = cbor.decode(f.read(8192))
                if (isinstance(rec, dict) and rec.get(3) == self.flags
                        and isinstance(rec.get(1), bytes) and isinstance(rec.get(2), bytes)
                        and self.backend.gated(rec[1])):
                    self._presence = rec[1], rec[2]
                    return self._presence
            except (OSError, cbor.CBORError):
                pass
        handle, point = self.backend.create(self.flags)
        creds.atomic_write(path, cbor.encode({1: handle, 2: bytes(point), 3: self.flags}))
        log.info("made the presence key (Secure Enclave, flags 0x%x)", self.flags)
        self._presence = handle, bytes(point)
        return self._presence

    # -- one prompt ----------------------------------------------------------------------

    def _call(self, fn, cancel):
        """fn() in a thread; ends it on cancel or after the timeout if the kernel can."""
        box = {}
        done = threading.Event()

        def run():
            try:
                box["value"] = fn()
            except BaseException as e:      # handed to the caller
                box["error"] = e
            done.set()

        threading.Thread(target=run, name="sep-key-sign", daemon=True).start()
        deadline = time.monotonic() + min(self.timeout, ENCLAVE_WAIT)
        while not done.wait(0.05):
            if cancel.is_set() or time.monotonic() >= deadline:
                why = touchid.CANCELLED if cancel.is_set() else touchid.TIMEOUT
                self.backend.cancel()
                # With CANCEL the call returns at once; without it the enclave
                # call runs out its own wait and its result is thrown away.
                done.wait(2.0 if self.backend.can_cancel else 0)
                return why, None
        if "error" in box:
            raise box["error"]
        return touchid.MATCH, box["value"]

    def _prompt(self, op, prompt, cancel, waiting):
        """(result, value) of op() under one prompt: up to max_tries enclave calls.

        result is touchid.MATCH (the enclave did it after a match), NO_MATCH,
        TIMEOUT or CANCELLED. InvalidHandle and BackendError propagate.
        """
        with self.lock:
            who = touchid.resolve_user(self.user)
            note = None
            waiting()
            try:
                note = self.notifier.show(who[1] if who else None, prompt.title(),
                                          prompt.detail or "Touch the Touch ID sensor",
                                          min(self.timeout, ENCLAVE_WAIT))
                for attempt in range(1, self.max_tries + 1):
                    try:
                        return self._call(op, cancel)
                    except EnclaveRefused:
                        log.info("%s: the enclave saw no matching finger (try %d of %d)",
                                 prompt.title(), attempt, self.max_tries)
                    except EnclaveTimeout:
                        return touchid.TIMEOUT, None
                    except EnclaveCancelled:
                        return touchid.CANCELLED, None
                return touchid.NO_MATCH, None
            finally:
                self.notifier.close(note)

    def sign(self, handle, digest, prompt, cancel, waiting=lambda: None):
        """(result, DER signature): the enclave signs after it saw a match."""
        return self._prompt(lambda: self.backend.sign(handle, digest), prompt, cancel, waiting)

    def unseal(self, handle, sealed, prompt, cancel, waiting=lambda: None):
        """(result, secret): the enclave releases a sealed secret after a match."""
        return self._prompt(lambda: self.backend.unseal(handle, sealed), prompt, cancel,
                            waiting)

    def verify(self, prompt, cancel, waiting=lambda: None):
        """A Touch ID approval for something that signs nothing: the presence key."""
        for renew in (False, True):
            handle, point = self.presence_key(renew)
            nonce = os.urandom(32)
            try:
                result, sig = self.sign(handle, nonce, prompt, cancel, waiting)
            except InvalidHandle:
                # touchid-current: the enrolled fingers changed, the enclave
                # retired the old presence key. Make a new one once.
                log.info("presence key refused by the enclave; making a new one")
                continue
            if result != touchid.MATCH:
                return result
            if not verify_digest(point, nonce, sig):
                raise BackendError("the presence signature does not verify")
            return touchid.MATCH
        raise BackendError("the enclave refuses a new presence key")
