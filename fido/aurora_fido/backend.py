# SPDX-License-Identifier: MIT
"""Credential keys in the Secure Enclave, with the touch checked by the enclave.

Every credential key is a P-256 key the Secure Enclave makes through
/dev/sep-key (drivers/soc/apple/key.rs). It is created with a biometric
access-control list that the enclave itself enforces: a signature needs a
credential context in which the enclave saw a Touch ID match, and the kernel
makes that context, runs the match and signs inside one SIGN call. The daemon
holds only the handle; it never decides that a touch happened, and neither
does anything else on the host. Root can make the enclave sign only by
getting a finger on the sensor.

There is no other key store. A kernel without /dev/sep-key, or one whose
/dev/sep-key cannot create keys with the access-control list a policy needs,
is refused (BackendError) instead of falling back to keys the host can use.

Handles made before this rule (software keys sealed under the master secret,
"AFSK", and enclave keys without an access-control list) are "legacy": the
daemon refuses them and asks for the credential to be registered again.

Interface versions: 2 (biometric CREATE flags) and 3 (adds CANCEL for a
waiting SIGN or UNSEAL, and SEAL / UNSEAL: a secret sealed to a credential
key that the enclave releases only after a Touch ID match it checked, like a
signature; used for hmac-secret).

Tests use a software backend from tests/stub.py. It is not installed and the
daemon cannot select it.
"""

import errno
import fcntl
import os
import struct

# Linux value; also defined here so the module imports on other systems.
EKEYREJECTED = getattr(errno, "EKEYREJECTED", 129)
PUB_LEN = 65
DIGEST_LEN = 32


class BackendError(Exception):
    pass


class InvalidHandle(BackendError):
    """The handle is not one this enclave can use."""


class EnclaveRefused(BackendError):
    """The enclave's own Touch ID check did not match (or Touch ID is locked out)."""


class EnclaveTimeout(BackendError):
    """No finger within the enclave's wait."""


class EnclaveCancelled(BackendError):
    """The waiting signature was cancelled (SEP_KEY_CANCEL)."""


class KeyBackend:
    name = "abstract"
    #: CREATE flags this backend offers (SEP_KEY_CREATE_*).
    flags_supported = 0
    #: SEAL / UNSEAL: secrets the enclave releases only after a match.
    can_unseal = False
    #: CANCEL: a waiting signature can be ended.
    can_cancel = False

    def create(self, flags):
        """Return (handle: bytes, public_point: 65-byte uncompressed P-256)."""
        raise NotImplementedError

    def gated(self, handle):
        """True when the enclave asks for Touch ID itself to sign with handle."""
        return False

    def sign(self, handle, digest):
        """DER ECDSA-Sig-Value over the 32-byte digest, waiting for a touch."""
        raise NotImplementedError

    def seal(self, handle, secret):
        """secret (<= 64 bytes) sealed to handle's key (no touch: sealing is public-key)."""
        raise BackendError("this kernel cannot seal secrets to a credential key")

    def unseal(self, handle, sealed):
        """The secret seal() sealed, released by the enclave after a match (waits)."""
        raise BackendError("this kernel cannot unseal secrets")

    def cancel(self):
        """End a sign() that is waiting for a touch, if the kernel can."""

    def public(self, handle):
        raise NotImplementedError


def _ioc(direction, magic, nr, size):
    return direction << 30 | size << 16 | magic << 8 | nr


_IOC_NONE, _IOC_WRITE, _IOC_READ = 0, 1, 2
_MAGIC = 0xB1
_HANDLE_MAX = 2048
_SIG_MAX = 72
_SECRET_MAX = 64
_SEALED_MAX = 256
_INFO = struct.Struct("<IIII")                                    # 16
_CREATE = struct.Struct(f"<II{PUB_LEN}s3s{_HANDLE_MAX}s")          # 2124
_SIGN = struct.Struct(f"<II{DIGEST_LEN}sI{_SIG_MAX}s{_HANDLE_MAX}s")  # 2164
_PUBLIC = _CREATE
# struct sep_key_seal, for SEAL (secret in, sealed out) and UNSEAL (sealed in,
# secret out): flags, handle_len, secret_len, sealed_len, secret, sealed, handle
_SEAL = struct.Struct(f"<IIII{_SECRET_MAX}s{_SEALED_MAX}s{_HANDLE_MAX}s")    # 2384

IOC_INFO = _ioc(_IOC_READ, _MAGIC, 0x20, _INFO.size)
IOC_CREATE = _ioc(_IOC_READ | _IOC_WRITE, _MAGIC, 0x21, _CREATE.size)
IOC_SIGN = _ioc(_IOC_READ | _IOC_WRITE, _MAGIC, 0x22, _SIGN.size)
IOC_PUBLIC = _ioc(_IOC_READ | _IOC_WRITE, _MAGIC, 0x23, _PUBLIC.size)
IOC_CANCEL = _ioc(_IOC_NONE, _MAGIC, 0x25, 0)
IOC_SEAL = _ioc(_IOC_READ | _IOC_WRITE, _MAGIC, 0x26, _SEAL.size)
IOC_UNSEAL = _ioc(_IOC_READ | _IOC_WRITE, _MAGIC, 0x27, _SEAL.size)
IFACE_VERSIONS = (2, 3)
# CREATE flags (include/uapi/linux/apple-sep.h).
CREATE_BIOMETRY_CURRENT_SET = 0x1     # .biometryCurrentSet
CREATE_BIOMETRY_ANY = 0x2             # .biometryAny
CREATE_USER_PRESENCE = 0x4            # .userPresence (Touch ID or the user's password)
# INFO features (version 3; the 'reserved' word of version 2).
FEATURE_CANCEL = 0x1
FEATURE_SEAL = 0x2
HANDLE_FLAG_BIOMETRY = 0x01           # handle byte 5: the record carries a biometric ACL
SEP_MAGIC = b"SEPK"
LEGACY_SEALED_MAGIC = b"AFSK"         # software keys of aurora-fido 0.1 (removed)

assert (_INFO.size, _CREATE.size, _SIGN.size) == (16, 2124, 2164)
assert _SEAL.size == 2384


def is_gated_handle(handle):
    """A /dev/sep-key handle whose record carries a biometric access-control list."""
    return (isinstance(handle, bytes) and handle[:4] == SEP_MAGIC and len(handle) > 5
            and bool(handle[5] & HANDLE_FLAG_BIOMETRY))


def legacy_kind(handle):
    """Why a handle is legacy ("sealed", "sep-key without access control"), or None."""
    if not isinstance(handle, bytes):
        return "unknown"
    if handle[:4] == LEGACY_SEALED_MAGIC:
        return "sealed software key"
    if handle[:4] == SEP_MAGIC and not is_gated_handle(handle):
        return "Secure Enclave key without access control"
    if handle[:4] != SEP_MAGIC:
        return "unknown"
    return None


class SepKeyBackend(KeyBackend):
    """P-256 keys inside the Secure Enclave, through /dev/sep-key."""

    name = "sep-key"

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
        version, flags_supported, handle_max, features = _INFO.unpack(buf)
        if version not in IFACE_VERSIONS:
            os.close(self.fd)
            raise BackendError(
                f"{path}: interface version {version}; enclave-checked Touch ID needs "
                f"version {' or '.join(map(str, IFACE_VERSIONS))} (linux#1196 or newer)")
        self.version = version
        self.flags_supported = flags_supported
        self.features = features if version >= 3 else 0
        self.can_cancel = bool(self.features & FEATURE_CANCEL)
        self.can_unseal = bool(self.features & FEATURE_SEAL)
        self.handle_max = min(handle_max, _HANDLE_MAX)

    @staticmethod
    def _error(e):
        if e.errno in (errno.EINVAL, EKEYREJECTED):
            return InvalidHandle(e.strerror)
        if e.errno == errno.EACCES:
            return EnclaveRefused("no Touch ID match")
        if e.errno == errno.ETIMEDOUT:
            return EnclaveTimeout("no touch")
        if e.errno == errno.ECANCELED:
            return EnclaveCancelled("cancelled")
        return BackendError(e.strerror)

    def _call(self, req, buf):
        try:
            fcntl.ioctl(self.fd, req, buf, True)
        except OSError as e:
            raise self._error(e) from e

    def gated(self, handle):
        return is_gated_handle(handle)

    def create(self, flags):
        if not flags or self.flags_supported & flags != flags:
            raise BackendError(f"/dev/sep-key cannot create keys with flags 0x{flags:x}")
        buf = bytearray(_CREATE.pack(flags, 0, b"", b"", b""))
        self._call(IOC_CREATE, buf)
        _f, n, point, _r, handle = _CREATE.unpack(buf)
        if not 0 < n <= self.handle_max or point[0] != 4:
            raise BackendError("malformed create reply")
        handle = handle[:n]
        if not is_gated_handle(handle):
            raise BackendError("the kernel made a key without the access-control list asked for")
        return handle, point

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

    def unseal(self, handle, sealed):
        self._check(handle)
        if not self.can_unseal:
            raise BackendError("this kernel cannot unseal secrets")
        if not 0 < len(sealed) <= _SEALED_MAX:
            raise InvalidHandle("sealed secret length")
        buf = bytearray(_SEAL.pack(0, len(handle), 0, len(sealed), b"", sealed, handle))
        self._call(IOC_UNSEAL, buf)
        _f, _n, secret_len, _sl, secret, _s, _h = _SEAL.unpack(buf)
        if not 0 < secret_len <= _SECRET_MAX:
            raise BackendError("malformed unseal reply")
        return secret[:secret_len]

    def seal(self, handle, secret):
        self._check(handle)
        if not self.can_unseal:
            raise BackendError("this kernel cannot seal secrets to a credential key")
        if not 0 < len(secret) <= _SECRET_MAX:
            raise ValueError("secret length")
        buf = bytearray(_SEAL.pack(0, len(handle), len(secret), 0, secret, b"", handle))
        self._call(IOC_SEAL, buf)
        _f, _n, _sl, sealed_len, _s, sealed, _h = _SEAL.unpack(buf)
        if not 0 < sealed_len <= _SEALED_MAX:
            raise BackendError("malformed seal reply")
        return sealed[:sealed_len]

    def cancel(self):
        if not self.can_cancel:
            return
        try:
            fcntl.ioctl(self.fd, IOC_CANCEL, 0)
        except OSError:
            pass

    def public(self, handle):
        self._check(handle)
        buf = bytearray(_PUBLIC.pack(0, len(handle), b"", b"", handle))
        self._call(IOC_PUBLIC, buf)
        return _PUBLIC.unpack(buf)[2]


STORES = ("auto", "sep-key")


def open_backend(store="auto", sep_path="/dev/sep-key"):
    """The Secure Enclave key backend, or BackendError saying why there is none.

    'auto' and 'sep-key' mean the same now; 'sealed' (aurora-fido 0.1) is refused.
    """
    if store == "sealed":
        raise BackendError("[keys] store = sealed is no longer supported: keys the host "
                           "can unwrap are not a security key. Remove the line; keys live "
                           "in the Secure Enclave only")
    if store not in STORES:
        raise BackendError(f"keys: store = {store!r}; use {', '.join(STORES)}")
    if not os.path.exists(sep_path):
        raise BackendError(f"{sep_path} not present: this kernel has no Secure Enclave "
                           "keys (apple_sep with linux#1196 or newer is needed)")
    sep = SepKeyBackend(sep_path)
    if not sep.flags_supported & (CREATE_BIOMETRY_ANY | CREATE_BIOMETRY_CURRENT_SET):
        raise BackendError(f"{sep_path} cannot make keys with an enclave-checked Touch ID "
                           "access-control list")
    return sep
