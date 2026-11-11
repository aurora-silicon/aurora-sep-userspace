# SPDX-License-Identifier: MIT
"""Unit tests: CBOR, CTAP2, PIN/UV token, credential management, hmac-secret, U2F, CTAPHID,
and the rule that every approval is an enclave-checked touch.

Run from fido/: python3 tests/test_ctap.py
The Secure Enclave is stood in for by tests/stub.py: software keys whose
sign() and unseal() refuse without a scripted "enclave touch", as the kernel's
SIGN does for keys with a biometric access-control list.
"""

import hashlib
import hmac
import json
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

from aurora_fido import backend, cbor, creds, ctap2, ctaphid, daemon, enclave, keys  # noqa: E402
from aurora_fido import pinuv, touchid, u2f  # noqa: E402
from aurora_fido import errors as E  # noqa: E402
import stub  # noqa: E402
from stub import FileSecret, StubKeyBackend  # noqa: E402

CDH = hashlib.sha256(b"client data").digest()


def es256_ok(point, msg, sig):
    return ctap2.verify_es256(point, msg, sig)


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class Notes:
    """Records the notifications the daemon would show."""

    def __init__(self):
        self.titles = []

    def show(self, uid, title, body, timeout_s):
        self.titles.append(title)
        return len(self.titles)

    def close(self, handle):
        pass


class Rig:
    """An authenticator on the stub enclave in a temp state dir."""

    def __init__(self, mode=stub.MATCH, handle_pad=0, attestation="self", policy="auto",
                 flags_supported=0x3, can_unseal=True, max_tries=3):
        self.tmp = tempfile.TemporaryDirectory()
        self.backend = StubKeyBackend(handle_pad=handle_pad, mode=mode,
                                      flags_supported=flags_supported, can_unseal=can_unseal)
        cfg = daemon.load_config(None)
        cfg.set("authenticator", "attestation", attestation)
        cfg.set("authenticator", "max_resident", "4")
        cfg.set("touchid", "policy", policy)
        cfg.set("touchid", "user", "root")
        cfg.set("touchid", "max_tries", str(max_tries))
        self.cfg = cfg
        self.state = os.path.join(self.tmp.name, "state")
        os.makedirs(self.state, mode=0o700)
        self.policy, self.note = daemon.resolve_policy(cfg, flags_supported)
        self.user = daemon.enclave_user(cfg, self.backend, self.state, self.policy)
        self.notes = Notes()
        self.user.notifier = self.notes
        self.secret = FileSecret(os.path.join(self.tmp.name, "master"))
        self.legacy = []
        self.auth, self.u2f = daemon.build(cfg, self.state, self.backend, self.user,
                                           self.secret, self.policy,
                                           lambda rp, why: self.legacy.append((rp, why)))
        self.clock = Clock()
        self.auth.clock = self.clock
        self.auth.started = self.clock()
        self.auth.token.clock = self.clock

    @property
    def mode(self):
        return self.backend.mode

    @mode.setter
    def mode(self, m):
        self.backend.mode = m

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

    def ga(self, cid, cdh=CDH, rp="example.com", extra=None):
        p = {1: rp, 2: cdh, 3: [{"type": "public-key", "id": cid}]}
        p.update(extra or {})
        return self.call(ctap2.CMD_GET_ASSERTION, p)

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
        self.assertEqual(info[2], ["credProtect", "hmac-secret"])
        self.assertEqual(info[3], ctap2.AAGUID)
        self.assertTrue(info[4]["uv"] and info[4]["rk"] and info[4]["credMgmt"])
        self.assertTrue(info[4]["pinUvAuthToken"])
        self.assertNotIn("clientPin", info[4])
        self.assertEqual(info[6], [2, 1])
        rig = Rig(can_unseal=False)
        try:
            self.assertEqual(rig.call(ctap2.CMD_GET_INFO)[1][2], ["credProtect"])
        finally:
            rig.close()

    def test_one_enclave_touch_per_ceremony(self):
        st, r = self.rig.make()
        self.assertEqual(st, 0)
        self.assertEqual(r[1], "packed")
        ad = parse_auth_data(r[2])
        self.assertEqual(ad["flags"] & (ctap2.FLAG_UP | ctap2.FLAG_UV | ctap2.FLAG_AT),
                         ctap2.FLAG_UP | ctap2.FLAG_UV | ctap2.FLAG_AT)
        self.assertTrue(es256_ok(ad["point"], r[2] + CDH, r[3]["sig"]))
        # The attestation signature was the enclave's touch-gated one: one touch.
        self.assertEqual((self.rig.backend.touches, self.rig.backend.signs), (1, 1))
        self.assertEqual(self.rig.notes.titles, ["Touch ID to register with example.com"])

        cdh2 = hashlib.sha256(b"login").digest()
        st, a = self.rig.ga(ad["cred_id"], cdh2)
        self.assertEqual(st, 0)
        aad = parse_auth_data(a[2])
        self.assertEqual(aad["flags"], ctap2.FLAG_UP | ctap2.FLAG_UV)
        self.assertGreater(aad["counter"], ad["counter"])
        self.assertTrue(es256_ok(ad["point"], a[2] + cdh2, a[3]))
        self.assertEqual(self.rig.backend.touches, 2)
        self.assertEqual(self.rig.notes.titles[-1], "Touch ID to sign in to example.com")

    def test_keys_carry_the_policy_access_control(self):
        made = []
        orig = self.rig.backend.create
        self.rig.backend.create = lambda flags, **k: made.append(flags) or orig(flags, **k)
        self.rig.make()
        self.assertEqual(made, [creds.POLICY_FLAGS[creds.POLICY_TOUCHID_ANY]])
        rig = Rig(policy="touchid-current")
        try:
            orig2 = rig.backend.create
            rig.backend.create = lambda flags, **k: made.append(flags) or orig2(flags, **k)
            self.assertEqual(rig.make()[0], 0)
            self.assertEqual(made[-1], 0x1)
        finally:
            rig.close()

    def test_attestation_none_still_needs_the_enclave_touch(self):
        rig = Rig(attestation="none")
        try:
            st, r = rig.make()
            self.assertEqual((st, r[1], r[3]), (0, "none", {}))
            self.assertEqual(rig.backend.touches, 1)
            rig.mode = stub.NO_MATCH
            rig.clock.t += 20
            self.assertEqual(rig.make(uid=b"x")[0], E.ERR_OPERATION_DENIED)
        finally:
            rig.close()

    def test_no_match_registers_nothing(self):
        self.rig.mode = stub.NO_MATCH
        st, _ = self.rig.make(rk=True)
        self.assertEqual(st, E.ERR_OPERATION_DENIED)
        self.assertEqual(self.rig.backend.touches, 3)      # max_tries
        self.assertEqual(self.rig.backend.signs, 0)
        self.assertEqual(self.rig.auth.store.count(), 0)

    def test_credential_is_bound_to_rp(self):
        _, r = self.rig.make(rp="a.example")
        cid = parse_auth_data(r[2])["cred_id"]
        self.assertEqual(self.rig.ga(cid, rp="b.example")[0], E.ERR_NO_CREDENTIALS)

    def test_tampered_credential_id(self):
        _, r = self.rig.make()
        cid = bytearray(parse_auth_data(r[2])["cred_id"])
        cid[20] ^= 1
        self.assertEqual(self.rig.ga(bytes(cid))[0], E.ERR_NO_CREDENTIALS)

    def test_wrong_finger_timeout_cancel(self):
        _, r = self.rig.make()
        cid = parse_auth_data(r[2])["cred_id"]
        for mode, code in ((stub.NO_MATCH, E.ERR_OPERATION_DENIED),
                           (stub.TIMEOUT, E.ERR_USER_ACTION_TIMEOUT)):
            self.rig.mode = mode
            self.rig.clock.t += ctap2.REFUSAL_REPLAY_WINDOW + 1   # not a replay
            self.assertEqual(self.rig.ga(cid)[0], code, mode)
        # A miss then a match within one prompt signs.
        self.rig.mode = [stub.NO_MATCH, stub.MATCH]
        self.rig.clock.t += 20
        self.assertEqual(self.rig.ga(cid, hashlib.sha256(b"z").digest())[0], 0)

        self.rig.mode = stub.WAIT
        ctx = ctap2.Ctx()
        threading.Timer(0.05, ctx.cancel.set).start()
        t0 = time.monotonic()
        st, _ = self.rig.call(ctap2.CMD_GET_ASSERTION, {
            1: "example.com", 2: CDH, 3: [{"type": "public-key", "id": cid}]}, ctx)
        self.assertEqual(st, E.ERR_KEEPALIVE_CANCEL)
        self.assertLess(time.monotonic() - t0, 3)

    def test_timeout_cancels_the_enclave_wait(self):
        self.rig.user.timeout = 0.2
        self.rig.mode = stub.WAIT
        t0 = time.monotonic()
        self.assertEqual(self.rig.make()[0], E.ERR_USER_ACTION_TIMEOUT)
        self.assertLess(time.monotonic() - t0, 3)

    def test_denied_assertion_signs_nothing(self):
        _, r = self.rig.make()
        cid = parse_auth_data(r[2])["cred_id"]
        signs = self.rig.backend.signs
        self.rig.mode = stub.NO_MATCH
        self.assertEqual(self.rig.ga(cid)[0], E.ERR_OPERATION_DENIED)
        self.assertEqual(self.rig.backend.signs, signs)

    def test_replayed_refusal_gets_no_new_touch(self):
        _, r = self.rig.make()
        cid = parse_auth_data(r[2])["cred_id"]
        self.rig.mode = stub.NO_MATCH
        self.assertEqual(self.rig.ga(cid)[0], E.ERR_OPERATION_DENIED)
        n = self.rig.backend.touches
        self.rig.clock.t += 2
        self.assertEqual(self.rig.ga(cid)[0], E.ERR_OPERATION_DENIED)
        self.assertEqual(self.rig.backend.touches, n)
        # A new challenge prompts; after the window the same one does too.
        self.rig.mode = stub.MATCH
        self.assertEqual(self.rig.ga(cid, hashlib.sha256(b"new").digest())[0], 0)
        self.rig.mode = stub.NO_MATCH
        self.assertEqual(self.rig.ga(cid)[0], E.ERR_OPERATION_DENIED)
        self.rig.clock.t += ctap2.REFUSAL_REPLAY_WINDOW + 1
        n = self.rig.backend.touches
        self.assertEqual(self.rig.ga(cid)[0], E.ERR_OPERATION_DENIED)
        self.assertGreater(self.rig.backend.touches, n)

    def test_silent_assertion_has_no_enclave_signature(self):
        _, r = self.rig.make()
        ad = parse_auth_data(r[2])
        n = self.rig.backend.touches
        st, a = self.rig.ga(ad["cred_id"], extra={5: {"up": False}})
        self.assertEqual(st, 0)
        self.assertEqual(parse_auth_data(a[2])["flags"], 0)
        self.assertEqual(self.rig.backend.touches, n)
        # The probe answer verifies against no credential key.
        self.assertFalse(es256_ok(ad["point"], a[2] + CDH, a[3]))

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

    def test_exclude_list_takes_an_enclave_touch(self):
        _, r = self.rig.make()
        cid = parse_auth_data(r[2])["cred_id"]
        n = self.rig.backend.touches
        st, _ = self.rig.make(extra={5: [{"type": "public-key", "id": cid}]})
        self.assertEqual(st, E.ERR_CREDENTIAL_EXCLUDED)
        self.assertEqual(self.rig.backend.touches, n + 1)       # the presence key
        st, _ = self.rig.make(rp="other.example", extra={5: [{"type": "public-key", "id": cid}]})
        self.assertEqual(st, 0)

    def test_resident_and_next_assertion(self):
        for uid in (b"u1", b"u2", b"u3"):
            self.assertEqual(self.rig.make(uid=uid, rk=True)[0], 0)
        self.rig.make(uid=b"u2", rk=True)        # replaces u2
        self.assertEqual(self.rig.auth.store.count(), 3)
        st, a = self.rig.call(ctap2.CMD_GET_ASSERTION, {1: "example.com", 2: CDH})
        self.assertEqual(st, 0)
        self.assertEqual(a[5], 3)
        users = {a[4]["id"]}
        self.assertEqual(a[4].get("name"), "ryan")
        n = self.rig.backend.touches
        for _ in range(2):
            st, nx = self.rig.call(ctap2.CMD_GET_NEXT_ASSERTION)
            self.assertEqual(st, 0)
            users.add(nx[4]["id"])
        # Each account's signature is its own enclave touch.
        self.assertEqual(self.rig.backend.touches, n + 2)
        self.assertEqual(users, {b"u1", b"u2", b"u3"})
        self.assertEqual(self.rig.call(ctap2.CMD_GET_NEXT_ASSERTION)[0], E.ERR_NOT_ALLOWED)
        self.assertEqual(self.rig.make(uid=b"u4", rk=True)[0], 0)
        self.assertEqual(self.rig.make(uid=b"u5", rk=True)[0], E.ERR_KEY_STORE_FULL)

    def test_cred_protect(self):
        _, r = self.rig.make(uid=b"p3", rk=True, ext={"credProtect": 3})
        self.assertEqual(parse_auth_data(r[2])["ext"], {"credProtect": 3})
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
            st, a = rig.ga(ad["cred_id"])
            self.assertEqual(st, 0)
            self.assertTrue(es256_ok(ad["point"], a[2] + CDH, a[3]))
        finally:
            rig.close()

    def test_get_assertion_token_takes_no_extra_touch(self):
        _, r = self.rig.make()
        cid = parse_auth_data(r[2])["cred_id"]
        plat = Platform(self.rig)
        n = self.rig.backend.touches
        st, tok = plat.token(pinuv.PERM_GA, "example.com")
        self.assertEqual(st, 0)
        self.assertEqual(self.rig.backend.touches, n)            # no touch for the token
        # Firefox's silent pre-flight with the token: no touch, no flags.
        st, a = self.rig.ga(cid, extra={5: {"up": False}, 6: plat.auth(tok, CDH), 7: 2})
        self.assertEqual((st, parse_auth_data(a[2])["flags"]), (0, 0))
        self.assertEqual(self.rig.backend.touches, n)
        # The real request: one enclave touch, UP and UV.
        st, a = self.rig.ga(cid, extra={6: plat.auth(tok, CDH), 7: 2})
        self.assertEqual(st, 0)
        self.assertEqual(parse_auth_data(a[2])["flags"], ctap2.FLAG_UP | ctap2.FLAG_UV)
        self.assertEqual(self.rig.backend.touches, n + 1)
        # A token does not stand in for the touch: with no finger, nothing signs.
        _, tok = plat.token(pinuv.PERM_GA, "example.com")
        self.rig.mode = stub.NO_MATCH
        st, _ = self.rig.ga(cid, hashlib.sha256(b"q").digest(),
                            extra={6: plat.auth(tok, hashlib.sha256(b"q").digest()), 7: 2})
        self.assertEqual(st, E.ERR_OPERATION_DENIED)

    def test_make_credential_token(self):
        plat = Platform(self.rig)
        st, tok = plat.token(pinuv.PERM_MC | pinuv.PERM_GA, "example.com")
        self.assertEqual(st, 0)
        st, r = self.rig.make(extra={8: plat.auth(tok, CDH), 9: 2, 7: {}})
        self.assertEqual(st, 0)
        self.assertEqual(self.rig.backend.touches, 1)
        self.assertEqual(self.rig.make(extra={8: plat.auth(tok, CDH), 9: 2})[0],
                         E.ERR_PIN_AUTH_INVALID)

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
        self.rig.mode = stub.NO_MATCH
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
        self.assertEqual(self.rig.make(extra={8: b"", 9: 1})[0], E.ERR_PIN_NOT_SET)

    def test_credential_management(self):
        self.rig.make(rp="a.example", uid=b"ua", rk=True)
        self.rig.make(rp="b.example", uid=b"ub", rk=True)
        self.rig.make(rp="b.example", uid=b"ub2", rk=True)
        plat = Platform(self.rig)
        n = self.rig.backend.touches
        _, tok = plat.token(pinuv.PERM_CM)
        self.assertEqual(self.rig.backend.touches, n + 1)       # enclave-checked, presence key

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
        self.assertEqual({rp1[3]["id"], rp2[3]["id"]}, {"a.example", "b.example"})
        bh = hashlib.sha256(b"b.example").digest()
        st, c1 = cm(0x04, {1: bh})
        self.assertEqual((st, c1[9]), (0, 2))
        st, c2 = cm(0x05, auth=False)
        self.assertEqual(cm(0x07, {2: c2[7], 3: {"id": c2[6]["id"], "name": "renamed"}})[0], 0)
        self.assertEqual(cm(0x06, {2: c1[7]})[0], 0)
        self.assertEqual(self.rig.auth.store.count(), 2)
        self.assertEqual(self.rig.auth.store.find(c2[7]["id"])["userName"], "renamed")
        # A token for getAssertion (no touch) cannot manage credentials.
        _, tok2 = plat.token(pinuv.PERM_GA, "a.example")
        self.assertEqual(self.rig.call(ctap2.CMD_CRED_MGMT,
                                       {1: 0x01, 3: 2, 4: plat.auth(tok2, b"\x01")})[0],
                         E.ERR_PIN_AUTH_INVALID)

    def _hmac_secret(self, plat, salt, cid, rig=None):
        rig = rig or self.rig
        enc = plat.proto.encrypt(plat.shared, salt)
        hs = {1: plat.cose, 2: enc, 3: plat.proto.authenticate(plat.shared, enc),
              4: plat.version}
        st, a = rig.ga(cid, extra={4: {"hmac-secret": hs}})
        self.assertEqual(st, 0)
        ad = parse_auth_data(a[2])
        return a, ad, (plat.proto.decrypt(plat.shared, ad["ext"]["hmac-secret"])
                       if "ext" in ad else None)

    def test_hmac_secret_is_released_by_the_enclave(self):
        _, r = self.rig.make(ext={"hmac-secret": True})
        ad = parse_auth_data(r[2])
        self.assertEqual(ad["ext"], {"hmac-secret": True})
        cid = ad["cred_id"]
        for version in (1, 2):
            plat = Platform(self.rig, version)
            s1, s2 = os.urandom(32), os.urandom(32)
            n = self.rig.backend.touches
            a, aad, o1 = self._hmac_secret(plat, s1, cid)
            # Two enclave touches: UNSEAL of the CredRandom, then the signature.
            self.assertEqual(self.rig.backend.touches, n + 2)
            self.assertTrue(es256_ok(ad["point"], a[2] + CDH, a[3]))
            _, _, o12 = self._hmac_secret(plat, s1 + s2, cid)
            self.assertEqual(len(o1), 32)
            self.assertEqual(o12[:32], o1)
            self.assertNotEqual(o12[32:], o1)
            self.assertEqual(self._hmac_secret(plat, s1, cid)[2], o1)
        # No touch, no secret.
        self.rig.mode = stub.NO_MATCH
        plat = Platform(self.rig)
        enc = plat.proto.encrypt(plat.shared, os.urandom(32))
        st, _ = self.rig.ga(cid, extra={4: {"hmac-secret": {
            1: plat.cose, 2: enc, 3: plat.proto.authenticate(plat.shared, enc), 4: 2}}})
        self.assertEqual(st, E.ERR_OPERATION_DENIED)
        # The CredRandom is not in the credential ID in any form the host can open.
        c = self.rig.auth.vault.unwrap(hashlib.sha256(b"example.com").digest(), cid)
        self.assertIsNotNone(c.sealed)
        with self.assertRaises(backend.EnclaveRefused):
            self.rig.backend.unseal(c.handle, c.sealed)

    def test_no_hmac_secret_without_kernel_sealing(self):
        rig = Rig(can_unseal=False)
        try:
            _, r = rig.make(ext={"hmac-secret": True})
            self.assertNotIn("ext", parse_auth_data(r[2]))
        finally:
            rig.close()

    def test_reset(self):
        _, r = self.rig.make(rk=True)
        cid = parse_auth_data(r[2])["cred_id"]
        self.rig.clock.t += 11
        self.assertEqual(self.rig.call(ctap2.CMD_RESET)[0], E.ERR_NOT_ALLOWED)
        self.rig.clock.t = self.rig.auth.started + 1
        self.rig.mode = stub.NO_MATCH
        self.assertEqual(self.rig.call(ctap2.CMD_RESET)[0], E.ERR_OPERATION_DENIED)
        self.rig.mode = stub.MATCH
        self.assertEqual(self.rig.call(ctap2.CMD_RESET)[0], 0)
        self.assertEqual(self.rig.auth.store.count(), 0)
        self.assertEqual(self.rig.ga(cid)[0], E.ERR_NO_CREDENTIALS)

    def test_state_survives_restart(self):
        _, r = self.rig.make(rk=True)
        cid = parse_auth_data(r[2])["cred_id"]
        auth2, _ = daemon.build(self.rig.cfg, self.rig.state, self.rig.backend,
                                self.rig.user, self.rig.secret, self.rig.policy)
        self.assertEqual(auth2.store.count(), 1)
        self.assertIsNotNone(auth2.vault.unwrap(hashlib.sha256(b"example.com").digest(), cid))
        other = FileSecret(os.path.join(self.rig.tmp.name, "other"))
        auth3, _ = daemon.build(self.rig.cfg, self.rig.state, self.rig.backend,
                                self.rig.user, other, self.rig.policy)
        self.assertEqual(auth3.store.all(), [])

    def test_state_files_are_private(self):
        self.rig.make(rk=True)
        for d in ("resident", "handles"):
            self.assertEqual(os.stat(os.path.join(self.rig.state, d)).st_mode & 0o077, 0)


class LegacyTest(unittest.TestCase):
    """Credentials of aurora-fido 0.1 (touch checked outside the enclave) are refused."""

    def setUp(self):
        self.rig = Rig()
        self.rp_hash = hashlib.sha256(b"example.com").digest()

    def tearDown(self):
        self.rig.close()

    def old_id(self, handle, rk=False):
        # The 0.1 payload: handle, seed (host-held hmac-secret key), credProtect.
        v = self.rig.auth.vault
        cid = v._seal(creds.KIND_INLINE, self.rp_hash, {1: handle, 2: os.urandom(32), 3: 1})
        if rk:
            self.rig.auth.store.put({"rpId": "example.com", "rpIdHash": self.rp_hash,
                                     "userId": b"old", "credId": cid,
                                     "pub": b"\x04" + b"\x01" * 64, "credProtect": 1})
        return cid

    def test_old_ids_are_refused_and_reported(self):
        for handle in (b"AFSK\x01" + os.urandom(60),
                       self.rig.backend.create(0x2)[0]):
            self.rig.legacy.clear()
            touches = self.rig.backend.touches
            self.assertEqual(self.rig.ga(self.old_id(handle))[0], E.ERR_NO_CREDENTIALS)
            self.assertEqual(self.rig.backend.touches, touches)
            self.assertEqual(self.rig.legacy[0][0], "example.com")
            self.assertIn("0.1", self.rig.legacy[0][1])

    def test_keys_without_access_control_are_refused(self):
        handle, _ = self.rig.backend.create(0x2, gated=False)
        cid = self.rig.auth.vault.wrap(self.rp_hash, creds.Credential(handle, 1, 1))
        self.assertEqual(self.rig.ga(cid)[0], E.ERR_NO_CREDENTIALS)
        self.assertEqual(self.rig.backend.signs, 0)
        self.assertTrue(self.rig.legacy)

    def test_resident_count_and_log(self):
        self.old_id(b"AFSK\x01" + os.urandom(60), rk=True)
        self.rig.make(uid=b"new", rk=True)
        self.assertEqual(daemon.legacy_resident(self.rig.auth.vault, self.rig.auth.store, self.rig.backend), 1)
        st, a = self.rig.call(ctap2.CMD_GET_ASSERTION, {1: "example.com", 2: CDH})
        self.assertEqual((st, a[4]["id"]), (0, b"new"))
        seen = []
        log = daemon.LegacyLog(self.rig.state, seen.append)
        log("ssh:", "old")
        log("ssh:", "old")
        with open(os.path.join(self.rig.state, "legacy-refused.json")) as f:
            self.assertEqual(json.load(f)["ssh:"]["count"], 2)
        self.assertEqual(seen, [1, 1])


class PolicyTest(unittest.TestCase):
    def cfg(self, policy):
        c = daemon.load_config(None)
        c.set("touchid", "policy", policy)
        return c

    def test_auto_takes_the_best_the_enclave_enforces(self):
        self.assertEqual(daemon.resolve_policy(self.cfg("auto"), 0x3)[0], creds.POLICY_TOUCHID_ANY)
        self.assertIn("no password fallback", daemon.resolve_policy(self.cfg("auto"), 0x3)[1])
        self.assertEqual(daemon.resolve_policy(self.cfg("auto"), 0x7),
                         (creds.POLICY_TOUCHID_OR_PASSWORD, None))

    def test_a_policy_the_enclave_cannot_enforce_is_refused(self):
        with self.assertRaises(daemon.PolicyError) as e:
            daemon.resolve_policy(self.cfg("touchid-or-password"), 0x3)
        self.assertIn("root approve without you", str(e.exception))
        with self.assertRaises(daemon.PolicyError):
            daemon.resolve_policy(self.cfg("touchid-current"), 0x2)
        with self.assertRaises(daemon.PolicyError):
            daemon.resolve_policy(self.cfg("whatever"), 0x3)
        self.assertEqual(daemon.resolve_policy(self.cfg("touchid-current"), 0x3)[0],
                         creds.POLICY_TOUCHID_CURRENT)

    def test_default_config_is_auto(self):
        self.assertEqual(daemon.load_config(None).get("touchid", "policy"), "auto")


class EnclaveUserTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.b = StubKeyBackend()
        self.u = enclave.EnclaveUser(self.b, self.tmp.name, 0x2, user="root")
        self.u.notifier = Notes()

    def tearDown(self):
        self.tmp.cleanup()

    def test_presence_key_is_made_once_and_checked(self):
        ev = threading.Event()
        self.assertEqual(self.u.verify(touchid.Prompt("select", None), ev), touchid.MATCH)
        self.assertEqual(self.b.creates, 1)
        u2 = enclave.EnclaveUser(self.b, self.tmp.name, 0x2, user="root")
        u2.notifier = Notes()
        self.assertEqual(u2.verify(touchid.Prompt("select", None), ev), touchid.MATCH)
        self.assertEqual(self.b.creates, 1)
        # A key the enclave retired (touchid-current after an enrolment change).
        self.b.mode = ["reject", stub.MATCH]
        self.assertEqual(u2.verify(touchid.Prompt("select", None), ev), touchid.MATCH)
        self.assertEqual(self.b.creates, 2)

    def test_a_signature_that_does_not_verify_is_not_a_touch(self):
        self.u.presence_key()
        real = self.b.sign
        self.b.sign = lambda h, d: real(h, hashlib.sha256(d).digest())   # wrong digest
        with self.assertRaises(backend.BackendError):
            self.u.verify(touchid.Prompt("select", None), threading.Event())

    def test_presence_key_for_other_flags_is_replaced(self):
        self.u.presence_key()
        u2 = enclave.EnclaveUser(self.b, self.tmp.name, 0x1, user="root")
        u2.presence_key()
        self.assertEqual(self.b.creates, 2)

    def test_tries(self):
        self.b.mode = stub.NO_MATCH
        h, _ = self.b.create(0x2)
        r, v = self.u.sign(h, b"\x00" * 32, touchid.Prompt("sign-in", "x"), threading.Event())
        self.assertEqual((r, v, self.b.touches), (touchid.NO_MATCH, None, 3))
        self.assertEqual(self.u.notifier.titles, ["Touch ID to sign in to x"])


class U2fTest(unittest.TestCase):
    def setUp(self):
        self.rig = Rig()
        self.app = hashlib.sha256(b"https://u2f.example").digest()

    def tearDown(self):
        self.rig.close()

    def apdu(self, ins, p1, data):
        return bytes([0, ins, p1, 0, 0]) + struct.pack(">H", len(data)) + data + b"\x00\x00"

    def poll(self, apdu, tries=100):
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
        self.assertEqual(self.rig.backend.touches, 1)            # presence key
        r = r[:-2]
        point, khl = r[1:66], r[66]
        kh = r[67:67 + khl]
        rest = r[67 + khl:]
        nlen = rest[1] & 0x7F if rest[1] & 0x80 else 0
        body = int.from_bytes(rest[2:2 + nlen], "big") if nlen else rest[1]
        cert = x509.load_der_x509_certificate(rest[:2 + nlen + body])
        sig = rest[2 + nlen + body:]
        cert.public_key().verify(sig, b"\x00" + self.app + chal + kh + point,
                                 ec.ECDSA(hashes.SHA256()))

        auth = self.apdu(u2f.INS_AUTHENTICATE, 0x07, chal + self.app + bytes([khl]) + kh)
        self.assertEqual(self.rig.u2f.handle(auth), b"\x69\x85")
        other = hashlib.sha256(b"https://other.example").digest()
        bad = self.apdu(u2f.INS_AUTHENTICATE, 0x07, chal + other + bytes([khl]) + kh)
        self.assertEqual(self.rig.u2f.handle(bad), b"\x6a\x80")

        self.rig.u2f.presence.last_poll -= 10          # new ceremony
        auth = self.apdu(u2f.INS_AUTHENTICATE, 0x03, chal + self.app + bytes([khl]) + kh)
        r = self.poll(auth)
        self.assertEqual(r[-2:], b"\x90\x00")
        self.assertEqual(r[0], 1)
        self.assertTrue(es256_ok(point, self.app + r[:5] + chal, r[5:-2]))
        self.assertEqual(self.rig.backend.touches, 2)
        # Don't-enforce: no UP and no enclave signature.
        r = self.rig.u2f.handle(self.apdu(u2f.INS_AUTHENTICATE, 0x08,
                                          chal + self.app + bytes([khl]) + kh))
        self.assertEqual((r[-2:], r[0]), (b"\x90\x00", 0))
        self.assertFalse(es256_ok(point, self.app + r[:5] + chal, r[5:-2]))
        self.assertEqual(self.rig.backend.touches, 2)

    def test_refusal_is_not_reprompted_while_polling(self):
        self.rig.mode = stub.NO_MATCH
        apdu = self.apdu(u2f.INS_REGISTER, 0, os.urandom(32) + self.app)
        r = self.poll(apdu, tries=30)
        self.assertEqual(r[-2:], b"\x69\x85")
        self.assertEqual(self.rig.backend.touches, 3)            # one prompt, max_tries
        self.assertEqual(self.rig.backend.creates, 1)            # only the presence key


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
        self.send(cid, ctaphid.CMD_MSG, b"\x00\x03\x00\x00")
        self.assertEqual(read_msg(self.dev), (cid, ctaphid.CMD_MSG, b"U2F_V2\x90\x00"))

    def test_keepalive_upneeded_busy_and_cancel(self):
        self.rig.mode = stub.WAIT
        cid = self.init()
        other = self.init()
        req = {1: CDH, 2: {"id": "x"}, 3: {"id": b"u"}, 4: [{"type": "public-key", "alg": -7}]}
        self.send(cid, ctaphid.CMD_CBOR, bytes([ctap2.CMD_MAKE_CREDENTIAL]) + cbor.encode(req))
        while True:
            c, cmd, data = read_msg(self.dev, skip_keepalive=False)
            if data == bytes([ctaphid.KEEPALIVE_UPNEEDED]):
                break
        self.assertEqual((c, cmd), (cid, ctaphid.CMD_KEEPALIVE))
        self.send(other, ctaphid.CMD_PING, b"hi")
        while True:
            c, cmd, data = read_msg(self.dev, skip_keepalive=False)
            if c == other:
                break
        self.assertEqual((cmd, data), (ctaphid.CMD_ERROR, bytes([E.ERR_CHANNEL_BUSY])))
        self.send(cid, ctaphid.CMD_CANCEL, b"")
        c, cmd, data = read_msg(self.dev)
        self.assertEqual((c, cmd, data), (cid, ctaphid.CMD_CBOR, bytes([E.ERR_KEEPALIVE_CANCEL])))


class BackendTest(unittest.TestCase):
    def test_no_sep_key_no_service(self):
        with self.assertRaises(backend.BackendError) as e:
            backend.open_backend("auto", "/nonexistent-sep-key")
        self.assertIn("not present", str(e.exception))
        with self.assertRaises(backend.BackendError) as e:
            backend.open_backend("sealed", "/nonexistent-sep-key")
        self.assertIn("no longer supported", str(e.exception))
        with self.assertRaises(backend.BackendError):
            backend.open_backend("bogus")

    def test_ioctl_layout(self):
        self.assertEqual(backend.IOC_SIGN, 0xC874B122)
        self.assertEqual(backend.IOC_CANCEL, 0x0000B125)
        self.assertEqual(backend._SEAL.size, 2384)
        self.assertEqual(backend.IOC_SEAL >> 16 & 0x3FFF, 2384)

    def test_legacy_kind(self):
        self.assertEqual(backend.legacy_kind(b"AFSK\x01xx"), "sealed software key")
        self.assertIn("without access control",
                      backend.legacy_kind(b"SEPK\x01\x00\x00\x00" + b"\x00" * 8))
        self.assertIsNone(backend.legacy_kind(b"SEPK\x01\x01\x00\x00" + b"\x00" * 8))
        self.assertTrue(backend.is_gated_handle(b"SEPK\x01\x03"))

    def test_status_file(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            run = os.path.join(tmp.name, "run")
            daemon.write_status(run, dict(daemon.key_store_info(StubKeyBackend()), ready=True))
            path = os.path.join(run, "status.json")
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o644)
            with open(path) as f:
                st = json.load(f)
            self.assertEqual((st["keys"], st["enforcement"]), ("sep-key", "enclave"))
            self.assertIn("signs only after a Touch ID match it checks itself",
                          st["keys_detail"])
        finally:
            tmp.cleanup()


class CliTest(unittest.TestCase):
    def test_find_device(self):
        from aurora_fido import cli
        tmp = tempfile.TemporaryDirectory()
        try:
            for n, phys in (("hidraw0", "usb-0000:00:14.0-1/input0"), ("hidraw3", "aurora-fido")):
                d = os.path.join(tmp.name, "class/hidraw", n, "device")
                os.makedirs(d)
                with open(os.path.join(d, "uevent"), "w") as f:
                    f.write(f"HID_ID=0003:00001209:00000001\nHID_PHYS={phys}\n")
            self.assertEqual(cli.find_device(tmp.name), "/dev/hidraw3")
        finally:
            tmp.cleanup()

    def test_render_says_state_threat_model_and_legacy(self):
        from aurora_fido import cli
        off = {"enabled": "disabled", "active": "inactive", "device": None, "keys": None,
               "keys_if_enabled": "sep-key", "ready": False, "version": "x", "policy": "auto"}
        t = cli.render(off)
        self.assertIn("Touch ID security key: off", t)
        self.assertIn("sudo aurora-fido enable", t)
        self.assertIn("root on this Mac cannot sign without your finger", t)
        on = dict(off, enabled="enabled", active="active", device="/dev/hidraw5",
                  keys="sep-key", ready=True, policy="touchid-any", hmac_secret=False,
                  legacy_resident=1, legacy_refused_rps=1, legacy_rps=["github.com"])
        t = cli.render(on)
        self.assertIn("/dev/hidraw5", t)
        self.assertIn("Touch ID checked by the Secure Enclave", t)
        self.assertIn("2 credential(s) made by aurora-fido 0.1", t)
        self.assertIn("github.com", t)
        self.assertIn("hmac-secret", t)
        for word in ("demo", "TEST", "sealed", "polkit"):
            self.assertNotIn(word, cli.render(off) + t)

    def test_enable_and_disable_need_root(self):
        from aurora_fido import cli
        if os.geteuid() == 0:
            self.skipTest("running as root")
        self.assertEqual(cli.main(["enable"]), 1)
        self.assertEqual(cli.main(["disable"]), 1)

    def test_enable_refuses_without_the_enclave(self):
        from aurora_fido import cli
        bad = cli.enclave_problems("/nonexistent.conf")
        if os.path.exists("/dev/sep-key"):
            self.skipTest("this machine has /dev/sep-key")
        self.assertEqual(len(bad), 1)
        self.assertIn("/dev/sep-key", bad[0])


class NotifierTest(unittest.TestCase):
    def test_notifier_tries_when_the_bus_is_not_visible_to_root(self):
        n = touchid.Notifier(True)
        calls = []
        n._as_user = lambda uid, argv: calls.append(argv) or type(
            "R", (), {"returncode": 0, "stdout": "7\n", "stderr": ""})()
        real = os.stat

        def fake_stat(path, *a, **k):
            if str(path).startswith("/run/user/"):
                raise PermissionError(13, "denied")
            return real(path, *a, **k)
        os.stat = fake_stat
        try:
            self.assertEqual(n.show(4242, "t", "b", 3), (4242, 7))
        finally:
            os.stat = real
        self.assertEqual(calls[0][0], "notify-send")

    def test_titles(self):
        self.assertEqual(touchid.Prompt("sign-in", "ssh:").title(), "Touch ID to sign in to SSH")
        self.assertEqual(touchid.Prompt("register", "pam://mbp").title(),
                         "Touch ID to register with login (mbp)")


class KeysTest(unittest.TestCase):
    def test_der_oid_and_int(self):
        self.assertEqual(keys.der_oid("1.2.840.10045.2.1").hex(), "06072a8648ce3d0201")
        self.assertEqual(keys.der_int(0x80).hex(), "02020080")

    def test_hmac_compare(self):
        p = pinuv.ProtocolOne()
        k = os.urandom(32)
        self.assertTrue(p.verify(k, b"m", hmac.new(k, b"m", hashlib.sha256).digest()[:16]))
        self.assertFalse(p.verify(k, b"m", b"\x00" * 16))


if __name__ == "__main__":
    unittest.main()
