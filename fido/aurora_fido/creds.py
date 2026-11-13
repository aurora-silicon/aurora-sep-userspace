# SPDX-License-Identifier: MIT
"""Credential IDs, the resident credential store and the signature counter.

All of the daemon's own secrets derive from one 64-byte master secret. The
installed daemon gets it from a record that this Mac's Secure Enclave seals
(aurora-fido-seal), so a copy of /var/lib/aurora-fido is useless on any other
machine. Keys derived from it:

  cred   AES-256-GCM key that wraps credential IDs
  store  AES-256-GCM key that wraps resident credential records

Credential ID, version 1 (every credential, resident or not):

  0x01 | kind | nonce[12] | AES-256-GCM(cred, nonce, payload, aad) (ct || tag)
  aad = "aurora-fido/cred/1" | kind | rpIdHash

  kind 0x00: payload is CBOR {1: key handle, 3: credProtect, 4: policy,
             7: hmac-secret CredRandom pair sealed to the key by the enclave}
             (aurora-fido 0.1 also wrote 2: seed[32] and 6: an enrolled-set
             digest; such credentials are legacy and refused)
  kind 0x01: payload is CBOR {5: ref[16]}, and the kind-0 payload lives in
             handles/<ref>, wrapped with the same key; used when the key
             handle would make the ID longer than the protocol allows
             (1023 bytes for CTAP2, 255 for U2F).

The rpIdHash in the additional data binds an ID to its relying party: an ID
presented for any other RP fails authentication and is treated as unknown.
Nothing in an ID is a secret the host can use: the key handle signs only with
a Touch ID match the enclave checks, and the hmac-secret CredRandom pair is
sealed to that key and released by the enclave only with such a signature.
"""

import hashlib
import os
import secrets
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

from . import cbor

CRED_VERSION = 1
KIND_INLINE = 0
KIND_REF = 1
ID_MAX_CTAP2 = 1023
ID_MAX_U2F = 255


def hkdf(secret, info, length=32):
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None,
                info=info).derive(secret)


def atomic_write(path, data, mode=0o600):
    tmp = f"{path}.tmp.{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC, mode)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    dfd = os.open(os.path.dirname(path) or ".", os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


# Who may approve a credential's use, fixed when it is made (like a macOS
# key's access control): config [touchid] policy. Each one is an access-control
# list the Secure Enclave enforces; the kernel CREATE flag is named next to it.
POLICY_TOUCHID_OR_PASSWORD = 0   # Touch ID, or the user's password checked by the
                                 # enclave (.userPresence, SEP_KEY_CREATE_USER_PRESENCE)
POLICY_TOUCHID_ANY = 1           # Touch ID only, any enrolled finger (.biometryAny)
POLICY_TOUCHID_CURRENT = 2       # Touch ID only, the fingers enrolled now
                                 # (.biometryCurrentSet): an enrolment change retires it
POLICY_TOUCHID_AND_PASSWORD = 3  # Touch ID and the user's password, both checked by the
                                 # enclave in one context (.biometryAny | .and |
                                 # .devicePasscode); keys under the user's bag only
POLICY_TOUCHID_CURRENT_AND_PASSWORD = 4   # the same with .biometryCurrentSet
POLICIES = {"touchid-or-password": POLICY_TOUCHID_OR_PASSWORD,
            "touchid-any": POLICY_TOUCHID_ANY,
            "touchid-current": POLICY_TOUCHID_CURRENT,
            "touchid-and-password": POLICY_TOUCHID_AND_PASSWORD,
            "touchid-current-and-password": POLICY_TOUCHID_CURRENT_AND_PASSWORD}
POLICY_NAMES = {v: k for k, v in POLICIES.items()}
# SEP_KEY_CREATE_* flags for each policy (include/uapi/linux/apple-sep.h):
# BIOMETRY_CURRENT_SET 0x1, BIOMETRY_ANY 0x2, USER_PRESENCE 0x4,
# DEVICE_PASSCODE 0x8, AND 0x10.
POLICY_FLAGS = {POLICY_TOUCHID_OR_PASSWORD: 0x4, POLICY_TOUCHID_ANY: 0x2,
                POLICY_TOUCHID_CURRENT: 0x1,
                POLICY_TOUCHID_AND_PASSWORD: 0x2 | 0x8 | 0x10,
                POLICY_TOUCHID_CURRENT_AND_PASSWORD: 0x1 | 0x8 | 0x10}
# Policies whose every use needs the password as well as the finger.
POLICIES_NEED_PASSWORD = (POLICY_TOUCHID_AND_PASSWORD, POLICY_TOUCHID_CURRENT_AND_PASSWORD)


class Credential:
    """What a credential ID opens to."""

    def __init__(self, handle, cred_protect=1, policy=POLICY_TOUCHID_ANY, sealed=None,
                 legacy=None):
        self.handle = handle
        self.cred_protect = cred_protect
        self.policy = policy
        self.sealed = sealed        # hmac-secret CredRandom pair, sealed to the key
        self.legacy = legacy        # why this credential is refused, or None


class Vault:
    """Wraps and opens credential IDs and resident records."""

    def __init__(self, state_dir, master):
        if len(master) != 64:
            raise ValueError("master secret must be 64 bytes")
        self.state_dir = state_dir
        self.handles_dir = os.path.join(state_dir, "handles")
        os.makedirs(self.handles_dir, mode=0o700, exist_ok=True)
        self._cred = AESGCM(hkdf(master, b"aurora-fido cred v1"))
        self._store = AESGCM(hkdf(master, b"aurora-fido store v1"))

    @staticmethod
    def _aad(kind, rp_id_hash):
        return b"aurora-fido/cred/1" + bytes([kind]) + rp_id_hash

    def _seal(self, kind, rp_id_hash, payload):
        nonce = secrets.token_bytes(12)
        ct = self._cred.encrypt(nonce, cbor.encode(payload), self._aad(kind, rp_id_hash))
        return bytes([CRED_VERSION, kind]) + nonce + ct

    def wrap(self, rp_id_hash, cred, max_len=ID_MAX_CTAP2):
        payload = {1: cred.handle, 3: cred.cred_protect, 4: cred.policy}
        if cred.sealed is not None:
            payload[7] = cred.sealed
        cid = self._seal(KIND_INLINE, rp_id_hash, payload)
        if len(cid) <= max_len:
            return cid
        ref = secrets.token_bytes(16)
        rec = self._seal(KIND_INLINE, rp_id_hash + ref, payload)
        atomic_write(os.path.join(self.handles_dir, ref.hex()), rec)
        return self._seal(KIND_REF, rp_id_hash, {5: ref})

    def _open(self, kind, rp_id_hash, blob):
        if len(blob) < 2 + 12 + 16 or blob[0] != CRED_VERSION or blob[1] != kind:
            return None
        try:
            pt = self._cred.decrypt(blob[2:14], blob[14:], self._aad(kind, rp_id_hash))
            p = cbor.decode(pt)
        except (InvalidTag, cbor.CBORError):
            return None
        return p if isinstance(p, dict) else None

    def unwrap(self, rp_id_hash, cred_id):
        """The Credential behind cred_id for this RP, or None."""
        if not isinstance(cred_id, bytes) or len(cred_id) < 2:
            return None
        if cred_id[1] == KIND_REF:
            p = self._open(KIND_REF, rp_id_hash, cred_id)
            ref = p.get(5) if p else None
            if not isinstance(ref, bytes) or len(ref) != 16:
                return None
            try:
                with open(os.path.join(self.handles_dir, ref.hex()), "rb") as f:
                    rec = f.read(8192)
            except OSError:
                return None
            p = self._open(KIND_INLINE, rp_id_hash + ref, rec)
        else:
            p = self._open(KIND_INLINE, rp_id_hash, cred_id)
        if not p:
            return None
        h, cp = p.get(1), p.get(3, 1)
        pol, sealed = p.get(4, POLICY_TOUCHID_OR_PASSWORD), p.get(7)
        if not (isinstance(h, bytes) and cp in (1, 2, 3) and pol in POLICY_NAMES):
            return None
        if sealed is not None and not isinstance(sealed, bytes):
            return None
        legacy = None
        if 2 in p:
            legacy = "made by aurora-fido 0.1, when the touch was checked outside the enclave"
        elif h[:4] == b"AFSK":
            legacy = "a sealed software key of aurora-fido 0.1"
        return Credential(h, cp, pol, sealed, legacy)

    def seal_record(self, record):
        nonce = secrets.token_bytes(12)
        return nonce + self._store.encrypt(nonce, cbor.encode(record), b"aurora-fido/rk/1")

    def open_record(self, blob):
        try:
            return cbor.decode(self._store.decrypt(blob[:12], blob[12:], b"aurora-fido/rk/1"))
        except (InvalidTag, cbor.CBORError, ValueError):
            return None


class ResidentStore:
    """Discoverable credentials: one sealed record per credential, root-only.

    Record (CBOR map with text keys): rpId, rpIdHash, rpName (optional),
    userId, userName, displayName (optional), credId, pub (65 bytes),
    credProtect, created.
    """

    def __init__(self, vault, state_dir, max_count=256):
        self.vault = vault
        self.dir = os.path.join(state_dir, "resident")
        self.max_count = max_count
        os.makedirs(self.dir, mode=0o700, exist_ok=True)

    @staticmethod
    def _name(cred_id):
        return hashlib.sha256(cred_id).hexdigest()[:40] + ".rk"

    def all(self):
        out = []
        for name in sorted(os.listdir(self.dir)):
            if not name.endswith(".rk"):
                continue
            try:
                with open(os.path.join(self.dir, name), "rb") as f:
                    rec = self.vault.open_record(f.read(65536))
            except OSError:
                continue
            if isinstance(rec, dict) and isinstance(rec.get("credId"), bytes):
                out.append(rec)
        out.sort(key=lambda r: r.get("created", 0), reverse=True)
        return out

    def count(self):
        return sum(1 for n in os.listdir(self.dir) if n.endswith(".rk"))

    def remaining(self):
        return max(0, self.max_count - self.count())

    def for_rp(self, rp_id_hash):
        return [r for r in self.all() if r.get("rpIdHash") == rp_id_hash]

    def find(self, cred_id):
        for r in self.all():
            if r["credId"] == cred_id:
                return r
        return None

    def put(self, record):
        """Store record, replacing one for the same RP and user ID."""
        for old in self.for_rp(record["rpIdHash"]):
            if old.get("userId") == record["userId"]:
                self.delete(old["credId"])
        if self.count() >= self.max_count:
            return False
        record.setdefault("created", time.time_ns())
        atomic_write(os.path.join(self.dir, self._name(record["credId"])),
                     self.vault.seal_record(record))
        return True

    def delete(self, cred_id):
        try:
            os.unlink(os.path.join(self.dir, self._name(cred_id)))
            return True
        except FileNotFoundError:
            return False

    def wipe(self):
        for d in (self.dir, self.vault.handles_dir):
            for name in os.listdir(d):
                os.unlink(os.path.join(d, name))


class Counter:
    """One global signature counter, kept by the host (not by the SEP).

    Root can rewind it. It is kept because relying parties already saw it
    grow; clone detection, its purpose, has nothing to detect here: enclave
    keys cannot be copied.
    """

    def __init__(self, state_dir):
        self.path = os.path.join(state_dir, "counter")
        try:
            with open(self.path) as f:
                self.value = int(f.read().strip() or 0)
        except (OSError, ValueError):
            self.value = 0

    def next(self):
        self.value = (self.value + 1) & 0xFFFFFFFF
        atomic_write(self.path, f"{self.value}\n".encode(), 0o644)
        return self.value
