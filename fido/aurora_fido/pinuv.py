# SPDX-License-Identifier: MIT
"""PIN/UV auth protocols 1 and 2 (CTAP 2.1 section 6.5.6 and 6.5.7), authenticator side.

There is no PIN (docs/fido.md says why). The protocols exist here because
CTAP 2.1 routes built-in user verification (Touch ID) through a
pinUvAuthToken (getPinUvAuthTokenUsingUvWithPermissions), credential
management needs that token, and hmac-secret uses the same key agreement.
The token is only a session object: the user verification that relying
parties see is always an enclave-checked touch at the signature itself.
"""

import hashlib
import hmac
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from . import keys


def _hkdf(z, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"\x00" * 32,
                info=info).derive(z)


class Protocol:
    version = 0

    def kdf(self, z):
        raise NotImplementedError

    def encrypt(self, key, data):
        raise NotImplementedError

    def decrypt(self, key, data):
        raise NotImplementedError

    def authenticate(self, key, msg):
        raise NotImplementedError

    def verify(self, key, msg, sig):
        return isinstance(sig, bytes) and hmac.compare_digest(self.authenticate(key, msg), sig)


class ProtocolOne(Protocol):
    version = 1

    def kdf(self, z):
        return hashlib.sha256(z).digest()

    def encrypt(self, key, data):
        if len(data) % 16:
            raise ValueError("length")
        e = Cipher(algorithms.AES(key[-32:]), modes.CBC(b"\x00" * 16)).encryptor()
        return e.update(data) + e.finalize()

    def decrypt(self, key, data):
        if len(data) % 16 or not data:
            raise ValueError("length")
        d = Cipher(algorithms.AES(key[-32:]), modes.CBC(b"\x00" * 16)).decryptor()
        return d.update(data) + d.finalize()

    def authenticate(self, key, msg):
        return hmac.new(key[:32], msg, hashlib.sha256).digest()[:16]


class ProtocolTwo(Protocol):
    version = 2

    def kdf(self, z):
        return _hkdf(z, b"CTAP2 HMAC key") + _hkdf(z, b"CTAP2 AES key")

    def encrypt(self, key, data):
        if len(data) % 16:
            raise ValueError("length")
        iv = os.urandom(16)
        e = Cipher(algorithms.AES(key[-32:]), modes.CBC(iv)).encryptor()
        return iv + e.update(data) + e.finalize()

    def decrypt(self, key, data):
        if len(data) < 32 or len(data) % 16:
            raise ValueError("length")
        d = Cipher(algorithms.AES(key[-32:]), modes.CBC(data[:16])).decryptor()
        return d.update(data[16:]) + d.finalize()

    def authenticate(self, key, msg):
        return hmac.new(key[:32], msg, hashlib.sha256).digest()


PROTOCOLS = {1: ProtocolOne(), 2: ProtocolTwo()}

PERM_MC = 0x01
PERM_GA = 0x02
PERM_CM = 0x04
PERM_BE = 0x08
PERM_LBW = 0x10
PERM_ACFG = 0x20
SUPPORTED_PERMS = PERM_MC | PERM_GA | PERM_CM

TOKEN_LIFETIME = 600.0
UP_LIFETIME = 30.0


class KeyAgreement:
    """The authenticator's ECDH key pair, regenerated when the daemon starts."""

    def __init__(self):
        self.regenerate()

    def regenerate(self):
        self._priv = ec.generate_private_key(ec.SECP256R1())
        self.point = self._priv.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint)

    def cose(self):
        return keys.cose_ecdh(self.point)

    def shared_secret(self, protocol, platform_cose):
        """kdf(ECDH x-coordinate); ValueError for a bad platform key."""
        point = keys.point_from_cose(platform_cose)
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
        z = self._priv.exchange(ec.ECDH(), peer)
        return protocol.kdf(z)


class Token:
    """The pinUvAuthToken and its state (CTAP 2.1 section 6.5.2.1)."""

    def __init__(self, clock):
        self.clock = clock
        self.reset()

    def reset(self):
        self.value = os.urandom(32)
        self.in_use = False
        self.permissions = 0
        self.rp_id = None
        self.user_verified = False
        self.user_present = False
        self.started = 0.0

    def begin(self, permissions, rp_id, verified=True):
        """verified=False: a token for makeCredential/getAssertion only; the
        enclave's touch at each signature is the user verification."""
        self.reset()
        self.in_use = True
        self.permissions = permissions
        self.rp_id = rp_id
        self.user_verified = verified
        self.user_present = verified
        self.started = self.clock()

    def expired(self):
        if not self.in_use:
            return True
        if self.clock() - self.started > TOKEN_LIFETIME:
            self.reset()
            return True
        if self.user_present and self.clock() - self.started > UP_LIFETIME:
            self.user_present = False
        return False

    def check(self, protocol, msg, param, permission, rp_id=None):
        """True when param authenticates msg with this token for permission.

        Binds the token to rp_id on first use if it is not bound yet.
        """
        if self.expired() or not protocol.verify(self.value, msg, param):
            return False
        if not self.permissions & permission:
            return None
        if rp_id is not None:
            if self.rp_id is None:
                self.rp_id = rp_id
            elif self.rp_id != rp_id:
                return None
        return True

    def consumed_by_mc_ga(self):
        """After makeCredential/getAssertion: one ceremony per touch."""
        self.user_present = False
        self.user_verified = False
        self.permissions &= PERM_LBW

