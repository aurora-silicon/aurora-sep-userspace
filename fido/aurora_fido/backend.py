# SPDX-License-Identifier: MIT
"""Where credential private keys live.

A KeyBackend creates P-256 keys and signs SHA-256 digests with them. The
daemon only ever holds an opaque key handle; what the handle means is the
backend's business.

SepKeyBackend is the only backend the daemon ships: /dev/sep-key from the
apple_sep driver (lane SEPKEY), where the private half is an enclave ref-key
that never leaves this Mac's Secure Enclave. The handle is the kernel's
"SEPK" header plus the wrapped ref-key record; it is useless on any other Mac
or any other Linux install on this one.

The ioctl layout below follows SEPKEY's interface version 1 draft
(drivers/soc/apple/key.rs). If the kernel reports another version the
backend refuses to start instead of guessing.

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
    """The handle is not one this backend (this enclave) can use."""


class KeyBackend:
    name = "abstract"
    #: True when the private key cannot be read by anything on the host.
    non_extractable = False

    def create(self):
        """Return (handle: bytes, public_point: 65-byte uncompressed P-256)."""
        raise NotImplementedError

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
IFACE_VERSION = 1

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
            raise BackendError(f"{path}: info ioctl failed: {e.strerror}") from e
        version, _flags, handle_max, _ = _INFO.unpack(buf)
        if version != IFACE_VERSION:
            raise BackendError(f"{path}: interface version {version}, "
                               f"this daemon speaks {IFACE_VERSION}")
        self.handle_max = min(handle_max, _HANDLE_MAX)

    def _call(self, req, buf):
        try:
            fcntl.ioctl(self.fd, req, buf, True)
        except OSError as e:
            if e.errno in (errno.EINVAL, EKEYREJECTED):
                raise InvalidHandle(e.strerror) from e
            raise BackendError(e.strerror) from e

    def create(self):
        buf = bytearray(_CREATE.size)
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
