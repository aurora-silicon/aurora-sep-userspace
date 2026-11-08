# SPDX-License-Identifier: MIT
"""Where credential private keys live.

A KeyBackend creates P-256 keys and signs SHA-256 digests with them. The
daemon only ever holds an opaque key handle; what the handle means is the
backend's business.

Two backends ship, and KeyStore puts them together:

SepKeyBackend: /dev/sep-key from the apple_sep driver, where the private half
is an enclave ref-key that never leaves this Mac's Secure Enclave. The handle
is the kernel's "SEPK" header plus the wrapped ref-key record; it is useless
on any other Mac or any other Linux install on this one. The ioctl layout
follows the apple_sep key interface, versions 1 and 2 (drivers/soc/apple/
key.rs; version 2 only adds a create flag this daemon does not set). If the
kernel reports another version the backend refuses to start instead of
guessing.

SealedKeyBackend: for kernels without /dev/sep-key. P-256 keys made by the
daemon, whose private scalar is AES-256-GCM wrapped under a key derived from
the master secret that this Mac's Secure Enclave seals. A copy of the disk is
useless elsewhere, but the private key is in the daemon's memory while it
signs, so root on this Mac can take a key away. docs/fido.md has the threat
model; `aurora-fido status` says which store is in use.

New credentials go to the Secure Enclave whenever /dev/sep-key works; a
credential made earlier with a sealed key keeps working, since KeyStore picks
the backend from the handle's magic.

Tests also use a software backend from tests/stub.py. It is not installed and
the daemon cannot select it.
"""

import errno
import fcntl
import os
import secrets
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# Linux value; also defined here so the module imports on other systems.
EKEYREJECTED = getattr(errno, "EKEYREJECTED", 129)
PUB_LEN = 65
DIGEST_LEN = 32


class BackendError(Exception):
    pass


class InvalidHandle(BackendError):
    """The handle is not one this backend (this enclave) can use."""


class EnclaveRefused(BackendError):
    """An enclave-gated key: the Secure Enclave's own Touch ID check did not match."""


class EnclaveTimeout(BackendError):
    """An enclave-gated key: no finger within the enclave's wait."""


class KeyBackend:
    name = "abstract"
    #: True when the private key cannot be read by anything on the host.
    non_extractable = False

    def create(self, policy=0):
        """Return (handle: bytes, public_point: 65-byte uncompressed P-256).

        policy: the credential's creds.POLICY_*; only a backend that can
        have the Secure Enclave enforce it looks at it.
        """
        raise NotImplementedError

    def enclave_gated(self, handle):
        """True when signing with handle makes the enclave ask for Touch ID itself."""
        return False

    def sign(self, handle, digest):
        """Return a DER ECDSA-Sig-Value over the 32-byte digest."""
        raise NotImplementedError

    def public(self, handle):
        raise NotImplementedError


def _ioc(direction, magic, nr, size):
    return direction << 30 | size << 16 | magic << 8 | nr


_IOC_WRITE, _IOC_READ = 1, 2
_MAGIC = 0xB1
_HANDLE_MAX = 2048
_SIG_MAX = 72
_INFO = struct.Struct("<IIII")                                    # 16
_CREATE = struct.Struct(f"<II{PUB_LEN}s3s{_HANDLE_MAX}s")          # 2124
_SIGN = struct.Struct(f"<II{DIGEST_LEN}sI{_SIG_MAX}s{_HANDLE_MAX}s")  # 2164
_PUBLIC = _CREATE

IOC_INFO = _ioc(_IOC_READ, _MAGIC, 0x20, _INFO.size)
IOC_CREATE = _ioc(_IOC_READ | _IOC_WRITE, _MAGIC, 0x21, _CREATE.size)
IOC_SIGN = _ioc(_IOC_READ | _IOC_WRITE, _MAGIC, 0x22, _SIGN.size)
IOC_PUBLIC = _ioc(_IOC_READ | _IOC_WRITE, _MAGIC, 0x23, _PUBLIC.size)
IFACE_VERSIONS = (1, 2)
# CREATE flags. Version 2 has BIOMETRY_CURRENT_SET; the others are the names
# proposed to lane SEPKEY (11-08) for the macOS-matching policies and are
# used only if the kernel lists them in INFO flags_supported.
CREATE_BIOMETRY_CURRENT_SET = 0x1     # .biometryCurrentSet
CREATE_BIOMETRY_ANY = 0x2             # .biometryAny (proposed)
HANDLE_FLAG_BIOMETRY = 0x01           # handle byte 5: the record carries a biometric ACL
SEP_MAGIC = b"SEPK"

assert (_INFO.size, _CREATE.size, _SIGN.size) == (16, 2124, 2164)


class SepKeyBackend(KeyBackend):
    """P-256 keys inside the Secure Enclave, through /dev/sep-key."""

    name = "sep-key"
    non_extractable = True

    def __init__(self, path="/dev/sep-key"):
        try:
            self.fd = os.open(path, os.O_RDWR | os.O_CLOEXEC)
        except OSError as e:
            raise BackendError(f"{path}: {e.strerror} (needs the apple_sep "
                               "driver with SEP-resident keys)") from e
        buf = bytearray(_INFO.size)
        try:
            fcntl.ioctl(self.fd, IOC_INFO, buf, True)
        except OSError as e:
            os.close(self.fd)
            raise BackendError(f"{path}: info ioctl failed: {e.strerror}") from e
        version, flags_supported, handle_max, _ = _INFO.unpack(buf)
        self.flags_supported = flags_supported if version >= 2 else 0
        self.enclave_policies = False     # config [keys] enclave_policy
        if version not in IFACE_VERSIONS:
            os.close(self.fd)
            raise BackendError(f"{path}: interface version {version}, this daemon "
                               f"speaks {', '.join(map(str, IFACE_VERSIONS))}")
        self.version = version
        self.handle_max = min(handle_max, _HANDLE_MAX)

    def _call(self, req, buf):
        try:
            fcntl.ioctl(self.fd, req, buf, True)
        except OSError as e:
            if e.errno in (errno.EINVAL, EKEYREJECTED):
                raise InvalidHandle(e.strerror) from e
            if e.errno == errno.EACCES:
                raise EnclaveRefused("no Touch ID match") from e
            if e.errno == errno.ETIMEDOUT:
                raise EnclaveTimeout("no touch") from e
            raise BackendError(e.strerror) from e

    def create_flags(self, policy):
        """The CREATE flag that has the enclave enforce policy, or 0 (daemon checks it)."""
        from .creds import POLICY_TOUCHID_ANY, POLICY_TOUCHID_CURRENT
        want = {POLICY_TOUCHID_CURRENT: CREATE_BIOMETRY_CURRENT_SET,
                POLICY_TOUCHID_ANY: CREATE_BIOMETRY_ANY}.get(policy, 0)
        if self.enclave_policies and want and self.flags_supported & want == want:
            return want
        return 0

    def enclave_gated(self, handle):
        return handle[:4] == SEP_MAGIC and len(handle) > 5 and bool(handle[5] & HANDLE_FLAG_BIOMETRY)

    def create(self, policy=0):
        buf = bytearray(_CREATE.pack(self.create_flags(policy), 0, b"", b"", b""))
        self._call(IOC_CREATE, buf)
        _f, n, point, _r, handle = _CREATE.unpack(buf)
        if not 0 < n <= self.handle_max or point[0] != 4:
            raise BackendError("malformed create reply")
        return handle[:n], point

    def _check(self, handle):
        if not 0 < len(handle) <= self.handle_max:
            raise InvalidHandle("handle length")

    def sign(self, handle, digest):
        self._check(handle)
        if len(digest) != DIGEST_LEN:
            raise ValueError("digest must be 32 bytes")
        buf = bytearray(_SIGN.pack(0, len(handle), digest, 0, b"", handle))
        self._call(IOC_SIGN, buf)
        _f, _n, _d, sig_len, sig, _h = _SIGN.unpack(buf)
        if not 0 < sig_len <= _SIG_MAX:
            raise BackendError("malformed sign reply")
        return sig[:sig_len]

    def public(self, handle):
        self._check(handle)
        buf = bytearray(_PUBLIC.pack(0, len(handle), b"", b"", handle))
        self._call(IOC_PUBLIC, buf)
        return _PUBLIC.unpack(buf)[2]


SEALED_MAGIC = b"AFSK"
_SEALED_VERSION = 1
_SEALED_AAD = SEALED_MAGIC + bytes([_SEALED_VERSION])
_SEALED_LEN = 4 + 1 + 12 + 32 + 16


class SealedKeyBackend(KeyBackend):
    """P-256 keys wrapped under a key derived from the SEP-sealed master secret.

    Handle: "AFSK" | 0x01 | nonce[12] | AES-256-GCM(k, nonce, scalar[32],
    aad = "AFSK" 0x01) (ct || tag), 65 bytes; k = HKDF-SHA256(master,
    info "aurora-fido sealed keys v1"). A new master secret (reset) makes
    every earlier handle unusable, like every credential ID.
    """

    name = "sealed"
    non_extractable = False

    def __init__(self, master=None):
        self._aead = None
        if master is not None:
            self.rekey(master)

    def rekey(self, master):
        if len(master) != 64:
            raise ValueError("master secret must be 64 bytes")
        k = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                 info=b"aurora-fido sealed keys v1").derive(master)
        self._aead = AESGCM(k)

    def _need_key(self):
        if self._aead is None:
            raise BackendError("sealed key store has no master secret")

    def create(self, policy=0):
        self._need_key()
        priv = ec.generate_private_key(ec.SECP256R1())
        scalar = priv.private_numbers().private_value.to_bytes(32, "big")
        nonce = secrets.token_bytes(12)
        handle = _SEALED_AAD + nonce + self._aead.encrypt(nonce, scalar, _SEALED_AAD)
        return handle, self._point(priv)

    @staticmethod
    def _point(priv):
        return priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    def _priv(self, handle):
        self._need_key()
        if len(handle) != _SEALED_LEN or handle[:5] != _SEALED_AAD:
            raise InvalidHandle("not a sealed key handle")
        try:
            scalar = self._aead.decrypt(handle[5:17], handle[17:], _SEALED_AAD)
        except InvalidTag as e:
            raise InvalidHandle("sealed key from another master secret") from e
        return ec.derive_private_key(int.from_bytes(scalar, "big"), ec.SECP256R1())

    def sign(self, handle, digest):
        if len(digest) != DIGEST_LEN:
            raise ValueError("digest must be 32 bytes")
        return self._priv(handle).sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))

    def public(self, handle):
        return self._point(self._priv(handle))


class KeyStore(KeyBackend):
    """New keys from the primary backend; each handle signs with the backend that made it."""

    def __init__(self, primary, sealed, sep=None):
        self.primary = primary
        self.sealed = sealed
        self.sep = sep
        self.name = primary.name
        self.non_extractable = primary.non_extractable

    def rekey(self, master):
        self.sealed.rekey(master)

    def _for(self, handle):
        if handle[:4] == SEP_MAGIC:
            if self.sep is None:
                raise BackendError("this credential's key is in the Secure Enclave, and "
                                   "/dev/sep-key is not available in this kernel")
            return self.sep
        if handle[:4] == SEALED_MAGIC:
            return self.sealed
        raise InvalidHandle("unknown key handle")

    def create(self, policy=0):
        return self.primary.create(policy)

    def enclave_gated(self, handle):
        return self.sep is not None and self.sep.enclave_gated(handle)

    def sign(self, handle, digest):
        return self._for(handle).sign(handle, digest)

    def public(self, handle):
        return self._for(handle).public(handle)


STORES = ("auto", "sep-key", "sealed")


def open_store(store="auto", sep_path="/dev/sep-key", enclave_policy=False):
    """(KeyStore, why /dev/sep-key is not used or None).

    auto: the Secure Enclave when /dev/sep-key works, else sealed keys.
    sep-key: the Secure Enclave or nothing (BackendError).
    sealed: sealed keys for new credentials; SEP credentials still sign.
    """
    if store not in STORES:
        raise BackendError(f"keys: store = {store!r}; use {', '.join(STORES)}")
    sep, why = None, None
    if store == "sealed" and not os.path.exists(sep_path):
        pass
    elif not os.path.exists(sep_path):
        why = f"{sep_path} not present (kernel without Secure Enclave keys)"
        if store == "sep-key":
            raise BackendError(why)
    else:
        # The node exists: any failure is an error, never a quiet fall back
        # to sealed keys (a late or broken driver must not weaken new keys).
        try:
            sep = SepKeyBackend(sep_path)
        except BackendError:
            if store != "sealed":
                raise
        if sep is not None:
            sep.enclave_policies = bool(enclave_policy)
    sealed = SealedKeyBackend()
    primary = sep if (sep is not None and store != "sealed") else sealed
    if store == "sealed" and sep is not None:
        why = "keys: store = sealed in the config"
    return KeyStore(primary, sealed, sep), why
