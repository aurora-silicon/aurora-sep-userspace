# SPDX-License-Identifier: MIT
"""Unit tests: CBOR, CTAP2, PIN/UV token, credential management, hmac-secret, U2F, CTAPHID.

Run from fido/: python3 -m unittest discover -s tests -t .
Software stand-ins for the Secure Enclave and Touch ID come from tests/stub.py.
"""

import hashlib
import hmac
import os
import struct
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

from aurora_fido import cbor, creds, ctap2, ctaphid, keys, pinuv, touchid, u2f  # noqa: E402
from aurora_fido import errors as E  # noqa: E402
from aurora_fido.daemon import build, load_config  # noqa: E402
from stub import FileSecret, StubKeyBackend, StubVerifier  # noqa: E402

CDH = hashlib.sha256(b"client data").digest()


def es256_ok(point, msg, sig):
    return ctap2.verify_es256(point, msg, sig)


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class Rig:
    """An authenticator with stub backend and verifier in a temp state dir."""

    def __init__(self, mode="match", handle_pad=0, attestation="self"):
        self.tmp = tempfile.TemporaryDirectory()
        self.backend = StubKeyBackend(handle_pad=handle_pad)
        self.verifier = StubVerifier(mode)
        cfg = load_config(None)
        cfg.set("authenticator", "attestation", attestation)
        cfg.set("authenticator", "max_resident", "4")
        self.secret = FileSecret(os.path.join(self.tmp.name, "master"))
        self.auth, self.u2f = build(cfg, os.path.join(self.tmp.name, "state"),
                                    self.backend, self.verifier, self.secret)
        self.clock = Clock()
        self.auth.clock = self.clock
        self.auth.started = self.clock()
        self.auth.token.clock = self.clock

    def call(self, cmd, params=None, ctx=None):
        data = bytes([cmd]) + (cbor.encode(params) if params is not None else b"")
        r = self.auth.handle(data, ctx)
        return r[0], (cbor.decode(r[1:]) if len(r) > 1 else None)

    def make(self, rp="example.com", uid=b"user-1", rk=False, ext=None, extra=None):
        p = {1: CDH, 2: {"id": rp, "name": "Example"},
             3: {"id": uid, "name": "ryan", "displayName": "Ryan"},
             4: [{"type": "public-key", "alg": -7}], 7: {"rk": rk}}
        if ext:
            p[6] = ext
        if extra:
            p.update(extra)
        return self.call(ctap2.CMD_MAKE_CREDENTIAL, p)

    def close(self):
        self.tmp.cleanup()


def parse_auth_data(ad):
    rp_hash, flags, ctr = ad[:32], ad[32], struct.unpack(">I", ad[33:37])[0]
    out = {"rp_hash": rp_hash, "flags": flags, "counter": ctr}
    rest = ad[37:]
    if flags & ctap2.FLAG_AT:
        out["aaguid"] = rest[:16]
        n = struct.unpack(">H", rest[16:18])[0]
        out["cred_id"] = rest[18:18 + n]
        key, rest = cbor.decode_prefix(rest[18 + n:])
        out["key"] = key
        out["point"] = keys.point_from_cose(key)
    if flags & ctap2.FLAG_ED:
        out["ext"] = cbor.decode(rest)
    elif rest:
        raise AssertionError("trailing authData")
    return out


class Platform:
    """Client side of the PIN/UV protocol, for tests."""

    def __init__(self, rig, version=2):
        self.rig = rig
        self.proto = pinuv.PROTOCOLS[version]
        self.version = version
        st, r = rig.call(ctap2.CMD_CLIENT_PIN, {1: version, 2: 0x02})
        assert st == 0, st
        peer = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), keys.point_from_cose(r[1]))
        self.priv = ec.generate_private_key(ec.SECP256R1())
        z = self.priv.exchange(ec.ECDH(), peer)
        self.shared = self.proto.kdf(z)
        self.cose = keys.cose_ecdh(self.priv.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint))

    def token(self, perms, rp_id=None):
        p = {1: self.version, 2: 0x06, 3: self.cose, 9: perms}
        if rp_id:
            p[0x0A] = rp_id
        st, r = self.rig.call(ctap2.CMD_CLIENT_PIN, p)
        if st:
            return st, None
        return 0, self.proto.decrypt(self.shared, r[2])

    def auth(self, token, msg):
        return self.proto.authenticate(token, msg)


class CborTest(unittest.TestCase):
    def test_round_trip_and_canonical_order(self):
        v = {"b": 1, 1: [True, False, None, b"\x00", "x"], -1: -500, "aa": {3: 4}}
        enc = cbor.encode(v)
        self.assertEqual(cbor.decode(enc), v)
        # ints (major 0), negative ints (1), then text by length then bytes.
        self.assertEqual(list(cbor.decode(enc).keys()), [1, -1, "b", "aa"])

    def test_cose_key_order(self):
        enc = cbor.encode(keys.cose_es256(b"\x04" + b"\x01" * 64))
        self.assertEqual(enc[:7], bytes([0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01]))

    def test_integer_heads(self):
        for n in (0, 23, 24, 255, 256, 65535, 65536, 2**32, -1, -24, -25, -2**32):
            self.assertEqual(cbor.decode(cbor.encode(n)), n)
        self.assertEqual(cbor.encode(24), b"\x18\x18")

    def test_rejects(self):
        for bad in (b"\x9f\x01\xff", b"\xc1\x00", b"\xf9\x00\x00", b"\xa2\x01\x01\x01\x02",
                    b"\x62\xc3\x28", b"\x01\x02", b"\x5a\xff\xff\xff\xff", b"\xf7", b""):
            with self.assertRaises(cbor.CBORError, msg=bad.hex()):
                cbor.decode(bad)

    def test_depth(self):
        with self.assertRaises(cbor.CBORError):
            cbor.decode(b"\x81" * 20 + b"\x00")


class Ctap2Test(unittest.TestCase):
    def setUp(self):
        self.rig = Rig()

    def tearDown(self):
        self.rig.close()

    def test_get_info(self):
        st, info = self.rig.call(ctap2.CMD_GET_INFO)
        self.assertEqual(st, 0)
        self.assertIn("FIDO_2_1", info[1])
        self.assertIn("U2F_V2", info[1])
        self.assertEqual(info[3], ctap2.AAGUID)
        self.assertTrue(info[4]["uv"] and info[4]["rk"] and info[4]["credMgmt"])
        self.assertTrue(info[4]["pinUvAuthToken"])
        self.assertNotIn("clientPin", info[4])
        self.assertEqual(info[6], [2, 1])
        self.assertEqual(info[0x0A], [{"type": "public-key", "alg": -7}])

    def test_make_credential_self_attestation_and_assertion(self):
        st, r = self.rig.make()
        self.assertEqual(st, 0)
        self.assertEqual(r[1], "packed")
        ad = parse_auth_data(r[2])
        self.assertEqual(ad["rp_hash"], hashlib.sha256(b"example.com").digest())
        self.assertEqual(ad["flags"] & (ctap2.FLAG_UP | ctap2.FLAG_UV | ctap2.FLAG_AT),
                         ctap2.FLAG_UP | ctap2.FLAG_UV | ctap2.FLAG_AT)
        self.assertEqual(ad["key"][3], -7)
        self.assertNotIn("x5c", r[3])
        self.assertTrue(es256_ok(ad["point"], r[2] + CDH, r[3]["sig"]))
        self.assertEqual(len(self.rig.verifier.prompts), 1)
        self.assertEqual(self.rig.verifier.prompts[0].title(),
                         "Touch ID to register with example.com")

        cdh2 = hashlib.sha256(b"login").digest()
        st, a = self.rig.call(ctap2.CMD_GET_ASSERTION, {
            1: "example.com", 2: cdh2, 3: [{"type": "public-key", "id": ad["cred_id"]}]})
        self.assertEqual(st, 0)
        self.assertEqual(a[1]["id"], ad["cred_id"])
        aad = parse_auth_data(a[2])
        self.assertEqual(aad["flags"], ctap2.FLAG_UP | ctap2.FLAG_UV)
        self.assertGreater(aad["counter"], ad["counter"])
        self.assertTrue(es256_ok(ad["point"], a[2] + cdh2, a[3]))
        self.assertNotIn(4, a)
        self.assertEqual(self.rig.verifier.prompts[-1].title(),
                         "Touch ID to sign in to example.com")

    def test_attestation_none(self):
        rig = Rig(attestation="none")
        try:
            st, r = rig.make()
            self.assertEqual((st, r[1], r[3]), (0, "none", {}))
        finally:
            rig.close()

    def test_credential_is_bound_to_rp(self):
        _, r = self.rig.make(rp="a.example")
        cid = parse_auth_data(r[2])["cred_id"]
        st, _ = self.rig.call(ctap2.CMD_GET_ASSERTION, {
            1: "b.example", 2: CDH, 3: [{"type": "public-key", "id": cid}]})
        self.assertEqual(st, E.ERR_NO_CREDENTIALS)

    def test_tampered_credential_id(self):
        _, r = self.rig.make()
        cid = bytearray(parse_auth_data(r[2])["cred_id"])
        cid[20] ^= 1
        st, _ = self.rig.call(ctap2.CMD_GET_ASSERTION, {
            1: "example.com", 2: CDH, 3: [{"type": "public-key", "id": bytes(cid)}]})
        self.assertEqual(st, E.ERR_NO_CREDENTIALS)

    def test_wrong_finger_timeout_cancel(self):
        for mode, code in ((touchid.NO_MATCH, E.ERR_OPERATION_DENIED),
                           (touchid.LOCKED, E.ERR_OPERATION_DENIED),
                           (touchid.UNAVAILABLE, E.ERR_OPERATION_DENIED),
                           (touchid.TIMEOUT, E.ERR_USER_ACTION_TIMEOUT)):
            self.rig.verifier.mode = mode
            st, _ = self.rig.make()
            self.assertEqual(st, code, mode)
        self.assertEqual(self.rig.backend.creates, 0)

        self.rig.verifier.mode = "wait"
        ctx = ctap2.Ctx()
        threading.Timer(0.05, ctx.cancel.set).start()
        st, _ = self.rig.call(ctap2.CMD_MAKE_CREDENTIAL, {
            1: CDH, 2: {"id": "x"}, 3: {"id": b"u"},
            4: [{"type": "public-key", "alg": -7}]}, ctx)
        self.assertEqual(st, E.ERR_KEEPALIVE_CANCEL)

    def test_denied_assertion_signs_nothing(self):
        _, r = self.rig.make()
        cid = parse_auth_data(r[2])["cred_id"]
        signs = self.rig.backend.signs
        self.rig.verifier.mode = touchid.NO_MATCH
        st, _ = self.rig.call(ctap2.CMD_GET_ASSERTION, {
            1: "example.com", 2: CDH, 3: [{"type": "public-key", "id": cid}]})
        self.assertEqual(st, E.ERR_OPERATION_DENIED)
        self.assertEqual(self.rig.backend.signs, signs)

    def test_silent_assertion(self):
        _, r = self.rig.make()
        cid = parse_auth_data(r[2])["cred_id"]
        n = len(self.rig.verifier.prompts)
        st, a = self.rig.call(ctap2.CMD_GET_ASSERTION, {
            1: "example.com", 2: CDH, 3: [{"type": "public-key", "id": cid}],
            5: {"up": False}})
        self.assertEqual(st, 0)
        self.assertEqual(parse_auth_data(a[2])["flags"], 0)
        self.assertEqual(len(self.rig.verifier.prompts), n)

    def test_bad_requests(self):
        self.assertEqual(self.rig.make(extra={4: [{"type": "public-key", "alg": -8}]})[0],
                         E.ERR_UNSUPPORTED_ALGORITHM)
        self.assertEqual(self.rig.make(extra={7: {"up": False}})[0], E.ERR_INVALID_OPTION)
        self.assertEqual(self.rig.call(ctap2.CMD_MAKE_CREDENTIAL, {1: CDH})[0],
                         E.ERR_MISSING_PARAMETER)
        self.assertEqual(self.rig.call(ctap2.CMD_GET_ASSERTION, {1: "x", 2: CDH,
                                                                 5: {"rk": True}})[0],
                         E.ERR_UNSUPPORTED_OPTION)
        self.assertEqual(self.rig.auth.handle(b"\x01\xff"), bytes([E.ERR_INVALID_CBOR]))
        self.assertEqual(self.rig.auth.handle(b"\x01\x01"), bytes([E.ERR_CBOR_UNEXPECTED_TYPE]))
        self.assertEqual(self.rig.auth.handle(b"\x55"), bytes([E.ERR_INVALID_COMMAND]))
        self.assertEqual(self.rig.make(extra={1: b"short"})[0], E.ERR_INVALID_LENGTH)

    def test_exclude_list(self):
        _, r = self.rig.make()
        cid = parse_auth_data(r[2])["cred_id"]
        st, _ = self.rig.make(extra={5: [{"type": "public-key", "id": cid}]})
        self.assertEqual(st, E.ERR_CREDENTIAL_EXCLUDED)
        st, _ = self.rig.make(rp="other.example", extra={5: [{"type": "public-key", "id": cid}]})
        self.assertEqual(st, 0)

    def test_resident_and_next_assertion(self):
        for uid in (b"u1", b"u2", b"u3"):
            st, _ = self.rig.make(uid=uid, rk=True)
            self.assertEqual(st, 0)
        st, _ = self.rig.make(uid=b"u2", rk=True)        # replaces u2
        self.assertEqual(self.rig.auth.store.count(), 3)
        st, a = self.rig.call(ctap2.CMD_GET_ASSERTION, {1: "example.com", 2: CDH})
        self.assertEqual(st, 0)
        self.assertEqual(a[5], 3)
        users = {a[4]["id"]}
        self.assertEqual(a[4].get("name"), "ryan")      # UV done, several accounts
        for _ in range(2):
            st, n = self.rig.call(ctap2.CMD_GET_NEXT_ASSERTION)
            self.assertEqual(st, 0)
            users.add(n[4]["id"])
            self.assertNotIn(5, n)
        self.assertEqual(users, {b"u1", b"u2", b"u3"})
        self.assertEqual(self.rig.call(ctap2.CMD_GET_NEXT_ASSERTION)[0], E.ERR_NOT_ALLOWED)
        self.assertEqual(self.rig.make(uid=b"u4", rk=True)[0], 0)
        self.assertEqual(self.rig.make(uid=b"u5", rk=True)[0], E.ERR_KEY_STORE_FULL)

    def test_cred_protect(self):
        _, r = self.rig.make(uid=b"p3", rk=True, ext={"credProtect": 3})
        ad = parse_auth_data(r[2])
        self.assertEqual(ad["ext"], {"credProtect": 3})
        # Silent discovery does not see a uvRequired credential.
        st, _ = self.rig.call(ctap2.CMD_GET_ASSERTION, {1: "example.com", 2: CDH,
                                                        5: {"up": False}})
        self.assertEqual(st, E.ERR_NO_CREDENTIALS)
        st, _ = self.rig.call(ctap2.CMD_GET_ASSERTION, {1: "example.com", 2: CDH})
        self.assertEqual(st, 0)

    def test_long_handles_use_stored_reference(self):
        rig = Rig(handle_pad=1500)
        try:
            st, r = rig.make()
            ad = parse_auth_data(r[2])
            self.assertLessEqual(len(ad["cred_id"]), creds.ID_MAX_CTAP2)
            self.assertEqual(ad["cred_id"][1], creds.KIND_REF)
            st, a = rig.call(ctap2.CMD_GET_ASSERTION, {
                1: "example.com", 2: CDH, 3: [{"type": "public-key", "id": ad["cred_id"]}]})
            self.assertEqual(st, 0)
            self.assertTrue(es256_ok(ad["point"], a[2] + CDH, a[3]))
        finally:
            rig.close()

    def test_token_one_touch_make_credential(self):
        plat = Platform(self.rig)
        st, tok = plat.token(pinuv.PERM_MC | pinuv.PERM_GA, "example.com")
        self.assertEqual(st, 0)
        n = len(self.rig.verifier.prompts)
        st, r = self.rig.make(extra={8: plat.auth(tok, CDH), 9: 2, 7: {}})
        self.assertEqual(st, 0)
        self.assertEqual(len(self.rig.verifier.prompts), n)    # the token's touch counted
        self.assertTrue(parse_auth_data(r[2])["flags"] & ctap2.FLAG_UV)
        # One ceremony per token: its mc permission is used up.
        st, r = self.rig.make(extra={8: plat.auth(tok, CDH), 9: 2})
        self.assertEqual(st, E.ERR_PIN_AUTH_INVALID)
        self.assertEqual(len(self.rig.verifier.prompts), n)
        # Without a token, the same request asks for Touch ID again.
        st, r = self.rig.make()
        self.assertEqual(st, 0)
        self.assertEqual(len(self.rig.verifier.prompts), n + 1)

    def test_token_survives_silent_preflight(self):
        # Firefox: getPinUvAuthToken (one touch), a silent up=false getAssertion
        # with the token to filter the allow list, then the real getAssertion.
        st, r = self.rig.make()
        cid = parse_auth_data(r[2])["cred_id"]
        allow = [{"type": "public-key", "id": cid}]
        plat = Platform(self.rig)
        st, tok = plat.token(pinuv.PERM_GA, "example.com")
        self.assertEqual(st, 0)
        n = len(self.rig.verifier.prompts)
        st, a = self.rig.call(ctap2.CMD_GET_ASSERTION, {
            1: "example.com", 2: CDH, 3: allow, 5: {"up": False},
            6: plat.auth(tok, CDH), 7: 2})
        self.assertEqual(st, 0)
        self.assertFalse(parse_auth_data(a[2])["flags"] & ctap2.FLAG_UP)
        st, a = self.rig.call(ctap2.CMD_GET_ASSERTION, {
            1: "example.com", 2: CDH, 3: allow, 6: plat.auth(tok, CDH), 7: 2})
        self.assertEqual(st, 0)
        flags = parse_auth_data(a[2])["flags"]
        self.assertTrue(flags & ctap2.FLAG_UP and flags & ctap2.FLAG_UV)
        self.assertEqual(len(self.rig.verifier.prompts), n)    # still one touch
        # The real ceremony used the token up.
        st, _ = self.rig.call(ctap2.CMD_GET_ASSERTION, {
            1: "example.com", 2: CDH, 3: allow, 6: plat.auth(tok, CDH), 7: 2})
        self.assertEqual(st, E.ERR_PIN_AUTH_INVALID)

    def test_token_bad_param_and_rp(self):
        plat = Platform(self.rig, version=1)
        _, tok = plat.token(pinuv.PERM_MC, "example.com")
        self.assertEqual(self.rig.make(extra={8: b"\x00" * 16, 9: 1})[0],
                         E.ERR_PIN_AUTH_INVALID)
        self.assertEqual(self.rig.make(rp="evil.example",
                                       extra={8: plat.auth(tok, CDH), 9: 1})[0],
                         E.ERR_PIN_AUTH_INVALID)
        self.assertEqual(plat.token(0x08)[0], E.ERR_UNAUTHORIZED_PERMISSION)
        self.assertEqual(plat.token(pinuv.PERM_MC)[0], E.ERR_MISSING_PARAMETER)
        self.rig.verifier.mode = touchid.NO_MATCH
        self.assertEqual(plat.token(pinuv.PERM_CM)[0], E.ERR_OPERATION_DENIED)

    def test_token_expires(self):
        plat = Platform(self.rig)
        _, tok = plat.token(pinuv.PERM_MC, "example.com")
        self.rig.clock.t += pinuv.TOKEN_LIFETIME + 1
        self.assertEqual(self.rig.make(extra={8: plat.auth(tok, CDH), 9: 2})[0],
                         E.ERR_PIN_AUTH_INVALID)

    def test_no_pin(self):
        self.assertEqual(self.rig.call(ctap2.CMD_CLIENT_PIN, {1: 2, 2: 0x01})[0],
                         E.ERR_PIN_NOT_SET)
        self.assertEqual(self.rig.call(ctap2.CMD_CLIENT_PIN, {1: 2, 2: 0x03})[0],
                         E.ERR_INVALID_SUBCOMMAND)
        st, r = self.rig.call(ctap2.CMD_CLIENT_PIN, {1: 2, 2: 0x07})
        self.assertEqual((st, r[5]), (0, 3))
        # Old-style "touch to select" probe.
        self.assertEqual(self.rig.make(extra={8: b"", 9: 1})[0], E.ERR_PIN_NOT_SET)

    def test_credential_management(self):
        self.rig.make(rp="a.example", uid=b"ua", rk=True)
        self.rig.make(rp="b.example", uid=b"ub", rk=True)
        self.rig.make(rp="b.example", uid=b"ub2", rk=True)
        plat = Platform(self.rig)
        _, tok = plat.token(pinuv.PERM_CM)

        def cm(sub, params=None, auth=True):
            p = {1: sub}
            if params is not None:
                p[2] = params
            if auth:
                msg = bytes([sub]) + (cbor.encode(params) if params is not None else b"")
                p[3], p[4] = 2, plat.auth(tok, msg)
            return self.rig.call(ctap2.CMD_CRED_MGMT, p)

        st, meta = cm(0x01)
        self.assertEqual((st, meta[1], meta[2]), (0, 3, 1))
        st, rp1 = cm(0x02)
        self.assertEqual((st, rp1[5]), (0, 2))
        st, rp2 = cm(0x03, auth=False)
        self.assertEqual(st, 0)
        self.assertEqual({rp1[3]["id"], rp2[3]["id"]}, {"a.example", "b.example"})
        self.assertEqual(cm(0x03, auth=False)[0], E.ERR_NOT_ALLOWED)

        bh = hashlib.sha256(b"b.example").digest()
        st, c1 = cm(0x04, {1: bh})
        self.assertEqual((st, c1[9]), (0, 2))
        self.assertEqual(c1[8][3], -7)
        st, c2 = cm(0x05, auth=False)
        self.assertEqual(st, 0)

        st, _ = cm(0x07, {2: c2[7], 3: {"id": c2[6]["id"], "name": "renamed"}})
        self.assertEqual(st, 0)
        st, _ = cm(0x06, {2: c1[7]})
        self.assertEqual(st, 0)
        self.assertEqual(self.rig.auth.store.count(), 2)
        self.assertIsNone(self.rig.auth.store.find(c1[7]["id"]))
        self.assertEqual(self.rig.auth.store.find(c2[7]["id"])["userName"], "renamed")

        # Wrong auth, and a token without cm.
        self.assertEqual(self.rig.call(ctap2.CMD_CRED_MGMT,
                                       {1: 0x01, 3: 2, 4: b"\x00" * 32})[0],
                         E.ERR_PIN_AUTH_INVALID)
        _, tok2 = plat.token(pinuv.PERM_GA, "a.example")
        self.assertEqual(self.rig.call(ctap2.CMD_CRED_MGMT,
                                       {1: 0x01, 3: 2, 4: plat.auth(tok2, b"\x01")})[0],
                         E.ERR_PIN_AUTH_INVALID)

    def _hmac_secret(self, plat, salt, cid):
        enc = plat.proto.encrypt(plat.shared, salt)
        hs = {1: plat.cose, 2: enc, 3: plat.proto.authenticate(plat.shared, enc),
              4: plat.version}
        st, a = self.rig.call(ctap2.CMD_GET_ASSERTION, {
            1: "example.com", 2: CDH, 3: [{"type": "public-key", "id": cid}],
            4: {"hmac-secret": hs}})
        self.assertEqual(st, 0)
        ad = parse_auth_data(a[2])
        return plat.proto.decrypt(plat.shared, ad["ext"]["hmac-secret"])

    def test_hmac_secret(self):
        _, r = self.rig.make(ext={"hmac-secret": True})
        ad = parse_auth_data(r[2])
        self.assertEqual(ad["ext"], {"hmac-secret": True})
        cid = ad["cred_id"]
        for version in (1, 2):
            plat = Platform(self.rig, version)
            s1, s2 = os.urandom(32), os.urandom(32)
            o1 = self._hmac_secret(plat, s1, cid)
            o12 = self._hmac_secret(plat, s1 + s2, cid)
            self.assertEqual(len(o1), 32)
            self.assertEqual(o12[:32], o1)
            self.assertNotEqual(o12[32:], o1)
            # Deterministic per credential and salt.
            self.assertEqual(self._hmac_secret(plat, s1, cid), o1)
        # Bad saltAuth.
        plat = Platform(self.rig)
        enc = plat.proto.encrypt(plat.shared, os.urandom(32))
        st, _ = self.rig.call(ctap2.CMD_GET_ASSERTION, {
            1: "example.com", 2: CDH, 3: [{"type": "public-key", "id": cid}],
            4: {"hmac-secret": {1: plat.cose, 2: enc, 3: b"\x00" * 32, 4: 2}}})
        self.assertEqual(st, E.ERR_PIN_AUTH_INVALID)

    def test_reset(self):
        _, r = self.rig.make(rk=True)
        cid = parse_auth_data(r[2])["cred_id"]
        self.rig.clock.t += 11
        self.assertEqual(self.rig.call(ctap2.CMD_RESET)[0], E.ERR_NOT_ALLOWED)
        self.rig.clock.t = self.rig.auth.started + 1
        self.rig.verifier.mode = touchid.NO_MATCH
        self.assertEqual(self.rig.call(ctap2.CMD_RESET)[0], E.ERR_OPERATION_DENIED)
        self.rig.verifier.mode = touchid.MATCH
        self.assertEqual(self.rig.call(ctap2.CMD_RESET)[0], 0)
        self.assertEqual(self.rig.auth.store.count(), 0)
        st, _ = self.rig.call(ctap2.CMD_GET_ASSERTION, {
            1: "example.com", 2: CDH, 3: [{"type": "public-key", "id": cid}]})
        self.assertEqual(st, E.ERR_NO_CREDENTIALS)

    def test_state_survives_restart(self):
        _, r = self.rig.make(rk=True)
        cid = parse_auth_data(r[2])["cred_id"]
        cfg = load_config(None)
        auth2, _ = build(cfg, os.path.join(self.rig.tmp.name, "state"),
                         self.rig.backend, self.rig.verifier, self.rig.secret)
        self.assertEqual(auth2.store.count(), 1)
        self.assertIsNotNone(auth2.vault.unwrap(hashlib.sha256(b"example.com").digest(), cid))
        self.assertGreaterEqual(auth2.counter.value, 1)
        # A different master secret opens nothing.
        other = FileSecret(os.path.join(self.rig.tmp.name, "other"))
        auth3, _ = build(cfg, os.path.join(self.rig.tmp.name, "state"),
                         self.rig.backend, self.rig.verifier, other)
        self.assertEqual(auth3.store.all(), [])
        self.assertIsNone(auth3.vault.unwrap(hashlib.sha256(b"example.com").digest(), cid))

    def test_state_files_are_private(self):
        self.rig.make(rk=True)
        state = os.path.join(self.rig.tmp.name, "state")
        for d in ("resident", "handles"):
            self.assertEqual(os.stat(os.path.join(state, d)).st_mode & 0o077, 0)
        for f in os.listdir(os.path.join(state, "resident")):
            self.assertEqual(os.stat(os.path.join(state, "resident", f)).st_mode & 0o077, 0)


class U2fTest(unittest.TestCase):
    def setUp(self):
        self.rig = Rig()
        self.app = hashlib.sha256(b"https://u2f.example").digest()

    def tearDown(self):
        self.rig.close()

    def apdu(self, ins, p1, data):
        return bytes([0, ins, p1, 0, 0]) + struct.pack(">H", len(data)) + data + b"\x00\x00"

    def poll(self, apdu, tries=50):
        for _ in range(tries):
            r = self.rig.u2f.handle(apdu)
            if r[-2:] != b"\x69\x85":
                return r
            time.sleep(0.01)
        return r

    def test_version_and_errors(self):
        self.assertEqual(self.rig.u2f.handle(b"\x00\x03\x00\x00"), b"U2F_V2\x90\x00")
        self.assertEqual(self.rig.u2f.handle(b"\x80\x03\x00\x00"), b"\x6e\x00")
        self.assertEqual(self.rig.u2f.handle(b"\x00\x09\x00\x00"), b"\x6d\x00")
        self.assertEqual(self.rig.u2f.handle(b"\x00\x01"), b"\x67\x00")

    def test_register_authenticate(self):
        chal = os.urandom(32)
        r = self.poll(self.apdu(u2f.INS_REGISTER, 0, chal + self.app))
        self.assertEqual(r[-2:], b"\x90\x00")
        r = r[:-2]
        self.assertEqual(r[0], 5)
        point, khl = r[1:66], r[66]
        kh = r[67:67 + khl]
        self.assertLessEqual(khl, 255)
        rest = r[67 + khl:]
        self.assertEqual(rest[0], 0x30)
        nlen = rest[1] & 0x7F if rest[1] & 0x80 else 0
        body = int.from_bytes(rest[2:2 + nlen], "big") if nlen else rest[1]
        cert_len = 2 + nlen + body
        cert = x509.load_der_x509_certificate(rest[:cert_len])
        sig = rest[cert_len:]
        self.assertEqual(cert.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint), point)
        cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
                                 ec.ECDSA(hashes.SHA256()))
        self.assertTrue(es256_ok(point, b"\x00" + self.app + chal + kh + point, sig))

        auth = self.apdu(u2f.INS_AUTHENTICATE, 0x07, chal + self.app + bytes([khl]) + kh)
        self.assertEqual(self.rig.u2f.handle(auth), b"\x69\x85")
        other = hashlib.sha256(b"https://other.example").digest()
        bad = self.apdu(u2f.INS_AUTHENTICATE, 0x07, chal + other + bytes([khl]) + kh)
        self.assertEqual(self.rig.u2f.handle(bad), b"\x6a\x80")

        time.sleep(0.05)
        self.rig.u2f.presence.last_poll -= 10          # new ceremony
        auth = self.apdu(u2f.INS_AUTHENTICATE, 0x03, chal + self.app + bytes([khl]) + kh)
        r = self.poll(auth)
        self.assertEqual(r[-2:], b"\x90\x00")
        self.assertEqual(r[0], 1)
        self.assertTrue(es256_ok(point, self.app + r[:5] + chal, r[5:-2]))

    def test_refusal_is_not_reprompted_while_polling(self):
        self.rig.verifier.mode = touchid.NO_MATCH
        apdu = self.apdu(u2f.INS_REGISTER, 0, os.urandom(32) + self.app)
        r = self.poll(apdu, tries=30)
        self.assertEqual(r[-2:], b"\x69\x85")
        self.assertEqual(len(self.rig.verifier.prompts), 1)
        self.assertEqual(self.rig.backend.creates, 0)


class FakeDev:
    def __init__(self):
        self.out = []
        self.cond = threading.Condition()

    def send(self, report):
        with self.cond:
            self.out.append(report)
            self.cond.notify_all()

    def take(self, timeout=3.0):
        end = time.monotonic() + timeout
        with self.cond:
            while not self.out:
                left = end - time.monotonic()
                if left <= 0:
                    raise AssertionError("no report")
                self.cond.wait(left)
            return self.out.pop(0)


def read_msg(dev, skip_keepalive=True):
    while True:
        f = dev.take()
        cid, cmd, n = struct.unpack(">IBH", f[:7])
        data = bytearray(f[7:7 + n])
        while len(data) < n:
            c = dev.take()
            data += c[5:5 + n - len(data)]
        if skip_keepalive and cmd == 0x80 | ctaphid.CMD_KEEPALIVE:
            continue
        return cid, cmd & 0x7F, bytes(data)


class CtapHidTest(unittest.TestCase):
    def setUp(self):
        self.rig = Rig()
        self.dev = FakeDev()
        self.hid = ctaphid.CtapHid(self.dev, self.rig.auth, self.rig.u2f)

    def tearDown(self):
        self.rig.close()

    def send(self, cid, cmd, payload):
        for f in ctaphid.frames(cid, cmd, payload):
            self.hid.packet(f)

    def init(self):
        nonce = os.urandom(8)
        self.send(ctaphid.BROADCAST, ctaphid.CMD_INIT, nonce)
        cid, cmd, data = read_msg(self.dev)
        self.assertEqual((cid, cmd, data[:8]), (ctaphid.BROADCAST, ctaphid.CMD_INIT, nonce))
        self.assertEqual(data[12], 2)
        self.assertTrue(data[16] & ctaphid.CAP_CBOR)
        return struct.unpack(">I", data[8:12])[0]

    def test_init_ping_fragmented(self):
        cid = self.init()
        payload = os.urandom(1000)
        self.send(cid, ctaphid.CMD_PING, payload)
        self.assertEqual(read_msg(self.dev), (cid, ctaphid.CMD_PING, payload))

    def test_cbor_get_info_and_msg(self):
        cid = self.init()
        self.send(cid, ctaphid.CMD_CBOR, bytes([ctap2.CMD_GET_INFO]))
        c, cmd, data = read_msg(self.dev)
        self.assertEqual((c, cmd, data[0]), (cid, ctaphid.CMD_CBOR, 0))
        self.assertIn("FIDO_2_1", cbor.decode(data[1:])[1])
        self.send(cid, ctaphid.CMD_MSG, b"\x00\x03\x00\x00")
        self.assertEqual(read_msg(self.dev), (cid, ctaphid.CMD_MSG, b"U2F_V2\x90\x00"))

    def test_errors(self):
        self.send(0x12345678, ctaphid.CMD_PING, b"x")
        self.assertEqual(read_msg(self.dev)[1:], (ctaphid.CMD_ERROR, bytes([E.ERR_INVALID_CHANNEL])))
        cid = self.init()
        frames = ctaphid.frames(cid, ctaphid.CMD_PING, os.urandom(200))
        self.hid.packet(frames[0])
        bad = bytearray(frames[1])
        bad[4] = 5
        self.hid.packet(bytes(bad))
        self.assertEqual(read_msg(self.dev)[1:], (ctaphid.CMD_ERROR, bytes([E.ERR_INVALID_SEQ])))
        self.send(cid, 0x55, b"")
        self.assertEqual(read_msg(self.dev)[1:], (ctaphid.CMD_ERROR, bytes([E.ERR_INVALID_COMMAND])))

    def test_keepalive_upneeded_busy_and_cancel(self):
        self.rig.verifier.mode = "wait"
        cid = self.init()
        other = self.init()
        req = {1: CDH, 2: {"id": "x"}, 3: {"id": b"u"}, 4: [{"type": "public-key", "alg": -7}]}
        self.send(cid, ctaphid.CMD_CBOR, bytes([ctap2.CMD_MAKE_CREDENTIAL]) + cbor.encode(req))
        c, cmd, data = read_msg(self.dev, skip_keepalive=False)
        self.assertEqual((c, cmd, data), (cid, ctaphid.CMD_KEEPALIVE,
                                          bytes([ctaphid.KEEPALIVE_UPNEEDED])))
        self.send(other, ctaphid.CMD_PING, b"hi")
        while True:
            c, cmd, data = read_msg(self.dev, skip_keepalive=False)
            if c == other:
                break
        self.assertEqual((cmd, data), (ctaphid.CMD_ERROR, bytes([E.ERR_CHANNEL_BUSY])))
        self.send(cid, ctaphid.CMD_CANCEL, b"")
        c, cmd, data = read_msg(self.dev)
        self.assertEqual((c, cmd, data), (cid, ctaphid.CMD_CBOR, bytes([E.ERR_KEEPALIVE_CANCEL])))


class PromptTest(unittest.TestCase):
    def test_titles(self):
        self.assertEqual(touchid.Prompt("sign-in", "ssh:").title(), "Touch ID to sign in to SSH")
        self.assertEqual(touchid.Prompt("register", "pam://mbp").title(),
                         "Touch ID to register with login (mbp)")
        self.assertEqual(touchid.Prompt("sign-in", None).title(),
                         "Touch ID to sign in to a website")


class KeysTest(unittest.TestCase):
    def test_der_oid_and_int(self):
        self.assertEqual(keys.der_oid("1.2.840.10045.2.1").hex(), "06072a8648ce3d0201")
        self.assertEqual(keys.der_int(0x80).hex(), "02020080")
        self.assertEqual(keys.der_int(1).hex(), "020101")

    def test_hmac_compare(self):
        p = pinuv.ProtocolOne()
        k = os.urandom(32)
        self.assertTrue(p.verify(k, b"m", hmac.new(k, b"m", hashlib.sha256).digest()[:16]))
        self.assertFalse(p.verify(k, b"m", b"\x00" * 16))


if __name__ == "__main__":
    unittest.main()
