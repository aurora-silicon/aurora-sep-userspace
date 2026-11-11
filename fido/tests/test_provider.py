# SPDX-License-Identifier: MIT
"""Native front-end (provider.py) on the stub enclave.

Run from fido/: python3 tests/test_provider.py
"""

import hashlib
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aurora_fido import cbor, ctap2  # noqa: E402
from aurora_fido.provider import Provider, ProviderError, rp_id_matches_origin  # noqa: E402
import stub  # noqa: E402
from test_ctap import CDH, Rig, parse_auth_data  # noqa: E402

RP = {"id": "example.com", "name": "Example"}
USER = {"id": b"user-1", "name": "ryan", "displayName": "Ryan"}
ORIGIN = {"origin": "https://login.example.com"}


class ProviderTest(unittest.TestCase):
    def setUp(self):
        self.rig = Rig()
        self.p = Provider(self.rig.auth)

    def tearDown(self):
        self.rig.close()

    def make(self, **kw):
        return self.p.make_credential(CDH, RP, USER, [-7], options=dict(ORIGIN, **kw))

    def test_origin_rule(self):
        ok = [("example.com", "https://example.com"), ("example.com", "https://a.b.example.com"),
              ("localhost", "http://localhost:8080")]
        bad = [("example.com", "http://example.com"), ("example.com", "https://notexample.com"),
               ("a.example.com", "https://example.com"), ("example.com", ""),
               ("com", "https://example.co")]
        for rp, o in ok:
            self.assertTrue(rp_id_matches_origin(rp, o), (rp, o))
        for rp, o in bad:
            self.assertFalse(rp_id_matches_origin(rp, o), (rp, o))

    def test_register_list_and_sign_in(self):
        r = self.make()
        att = cbor.decode(r["attestation_object"])
        ad = parse_auth_data(att["authData"])
        self.assertEqual(ad["rp_hash"], hashlib.sha256(b"example.com").digest())
        lst = self.p.list_credentials("example.com")
        self.assertEqual(len(lst), 1)
        self.assertEqual((lst[0]["id"], lst[0]["user_name"]), (ad["cred_id"], "ryan"))
        signs = self.rig.backend.signs
        self.p.list_credentials("example.com")
        self.assertEqual(self.rig.backend.signs, signs)      # listing touches nothing
        a = self.p.get_assertion(CDH, "example.com", ad["cred_id"], ORIGIN)
        self.assertTrue(ctap2.verify_es256(ad["point"], a["authenticator_data"] + CDH,
                                           a["signature"]))
        self.assertEqual(a["user_handle"], b"user-1")
        self.assertEqual(self.p.list_credentials("other.com"), [])

    def test_wrong_origin_is_refused_before_the_enclave(self):
        with self.assertRaises(ProviderError) as c:
            self.p.make_credential(CDH, RP, USER, [-7], options={"origin": "https://evil.test"})
        self.assertEqual(c.exception.name, "SecurityError")
        self.assertEqual(self.rig.backend.creates, 0)

    def test_no_match_is_not_allowed(self):
        cid = parse_auth_data(cbor.decode(self.make()["attestation_object"])["authData"])["cred_id"]
        self.rig.mode = stub.NO_MATCH
        with self.assertRaises(ProviderError) as c:
            self.p.get_assertion(CDH, "example.com", cid, ORIGIN)
        self.assertEqual(c.exception.name, "NotAllowedError")

    def test_excluded_is_invalid_state(self):
        cid = parse_auth_data(cbor.decode(self.make()["attestation_object"])["authData"])["cred_id"]
        with self.assertRaises(ProviderError) as c:
            self.p.make_credential(CDH, RP, USER, [-7], exclude=[cid], options=ORIGIN)
        self.assertEqual(c.exception.name, "InvalidStateError")

    def test_cancel(self):
        self.rig.mode = stub.WAIT
        ctx = ctap2.Ctx(threading.Event())
        threading.Timer(0.3, ctx.cancel.set).start()
        with self.assertRaises(ProviderError) as c:
            self.p.make_credential(CDH, RP, USER, [-7], options=ORIGIN, ctx=ctx)
        self.assertEqual(c.exception.name, "NotAllowedError")
        self.assertEqual(self.rig.backend.signs, 0)

    def test_info(self):
        i = self.p.get_info()
        self.assertEqual(i["aaguid"], ctap2.AAGUID)
        self.assertIn(-7, i["algorithms"])


if __name__ == "__main__":
    unittest.main()
