# SPDX-License-Identifier: MIT
"""COSE keys, a little DER, and the self-signed U2F attestation certificate."""

import hashlib
import time

from . import cbor

ES256 = -7
ECDH_ES_HKDF_256 = -25


def cose_es256(point):
    """COSE_Key for an uncompressed P-256 point."""
    if len(point) != 65 or point[0] != 4:
        raise ValueError("not an uncompressed P-256 point")
    return {1: 2, 3: ES256, -1: 1, -2: bytes(point[1:33]), -3: bytes(point[33:])}


def cose_ecdh(point):
    return {1: 2, 3: ECDH_ES_HKDF_256, -1: 1, -2: bytes(point[1:33]),
            -3: bytes(point[33:])}


def point_from_cose(key):
    """The 65-byte point of a P-256 COSE key; ValueError if it is not one."""
    if not isinstance(key, dict) or key.get(1) != 2 or key.get(-1) != 1:
        raise ValueError("not an EC2 P-256 COSE key")
    x, y = key.get(-2), key.get(-3)
    if not (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == len(y) == 32):
        raise ValueError("bad coordinates")
    return b"\x04" + x + y


def encode_cose_es256(point):
    return cbor.encode(cose_es256(point))


# --- DER, just enough for one certificate -------------------------------------

def _der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def der(tag, body):
    return bytes([tag]) + _der_len(len(body)) + body


def der_seq(*parts):
    return der(0x30, b"".join(parts))


def der_int(n):
    b = n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big")
    return der(0x02, b)


def der_oid(dotted):
    parts = [int(p) for p in dotted.split(".")]
    out = bytearray([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        out += bytes(reversed(chunk))
    return der(0x06, bytes(out))


def _name(cn):
    attr = der_seq(der_oid("2.5.4.3"), der(0x0C, cn.encode()))
    return der_seq(der(0x31, attr))


def _utctime(t):
    return der(0x17, time.strftime("%y%m%d%H%M%SZ", time.gmtime(t)).encode())


def _gentime(t):
    return der(0x18, time.strftime("%Y%m%d%H%M%SZ", time.gmtime(t)).encode())


ECDSA_SHA256 = der_seq(der_oid("1.2.840.10045.4.3.2"))
SPKI_P256 = der_seq(der_oid("1.2.840.10045.2.1"), der_oid("1.2.840.10045.3.1.7"))
CERT_CN = "Aurora Touch ID self attestation (not Apple-verified)"


def self_signed_cert(point, sign_digest, serial):
    """A self-signed X.509 v1 certificate for point, signed by the same key.

    sign_digest(digest32) returns a DER ECDSA signature. This is U2F self
    attestation: it proves only that the key holder made the certificate.
    """
    tbs = der_seq(
        der_int(serial),
        ECDSA_SHA256,
        _name(CERT_CN),
        der_seq(_utctime(1767225600), _gentime(4102444800)),  # 2026-01-01 .. 2100-01-01
        _name(CERT_CN),
        der_seq(SPKI_P256, der(0x03, b"\x00" + bytes(point))),
    )
    sig = sign_digest(hashlib.sha256(tbs).digest())
    return der_seq(tbs, ECDSA_SHA256, der(0x03, b"\x00" + sig))
