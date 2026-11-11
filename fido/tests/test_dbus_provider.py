# SPDX-License-Identifier: MIT
"""D-Bus binding of the native front-end, on a private session bus and the stub enclave.

Run from fido/: dbus-run-session -- python3 tests/test_dbus_provider.py
Skipped without jeepney or a session bus.
"""

import hashlib
import os
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from jeepney import DBusAddress, MessageType, new_method_call
    from jeepney.bus_messages import message_bus
    from jeepney.io.blocking import open_dbus_connection
    from aurora_fido import dbus_provider as dp
    HAVE = bool(os.environ.get("DBUS_SESSION_BUS_ADDRESS"))
except ImportError:
    HAVE = False

from aurora_fido import agent, cbor, ctap2, daemon  # noqa: E402
from aurora_fido.backend import UserBagBackend  # noqa: E402
from aurora_fido.provider import Provider  # noqa: E402
import stub  # noqa: E402
from test_ctap import CDH, parse_auth_data  # noqa: E402

UID = os.getuid()
ORIGIN = {"origin": ("s", "https://example.com")}
RP = {"id": ("s", "example.com"), "name": ("s", "Example")}
USER = {"id": ("ay", b"user-1"), "name": ("s", "ryan")}


@unittest.skipUnless(HAVE, "needs jeepney and a session bus (dbus-run-session)")
class DbusProviderTest(unittest.TestCase):
    def setUp(self, allow_names=()):
        self.tmp = tempfile.TemporaryDirectory()
        self.backend = stub.StubKeyBackend()
        cfg = daemon.load_config(None)
        cfg.set("touchid", "notify", "no")
        state = os.path.join(self.tmp.name, "state")
        os.makedirs(state)
        self.auth, _ = agent.build_agent(cfg, state, UserBagBackend(self.backend, UID),
                                         agent.UserBagSecret(self.backend, UID, state), "root")
        self.svc = dp.ProviderService(Provider(self.auth), allow_names=allow_names)
        self.assertTrue(self.svc.request_name())
        self.t = threading.Thread(target=self.svc.serve_forever, daemon=True)
        self.t.start()
        self.client = open_dbus_connection(bus="SESSION", enable_fds=True)
        self.addr = DBusAddress(dp.PATH, bus_name=dp.BUS_NAME, interface=dp.IFACE)

    def tearDown(self):
        self.client.close()
        self.svc.close()
        self.t.join(2)
        self.tmp.cleanup()

    def call(self, member, sig=None, body=(), conn=None):
        r = (conn or self.client).send_and_get_reply(
            new_method_call(self.addr, member, sig, body), timeout=30)
        if r.header.message_type == MessageType.error:
            from jeepney import HeaderFields
            return r.header.fields[HeaderFields.error_name], r.body
        return None, r.body

    def make(self, options=ORIGIN, req=1):
        return self.call("MakeCredential", "uaya{sv}a{sv}aiaaya{sv}",
                         (req, CDH, RP, USER, [-7], [], options))

    def memfd(self, data):
        fd = os.memfd_create("pw")
        os.write(fd, data)
        return fd

    def test_introspect_and_info(self):
        r = self.client.send_and_get_reply(new_method_call(
            DBusAddress(dp.PATH, bus_name=dp.BUS_NAME, interface="org.freedesktop.DBus.Introspectable"),
            "Introspect"))
        self.assertIn(dp.IFACE, r.body[0])
        err, (info,) = self.call("GetInfo")
        self.assertIsNone(err)
        self.assertEqual(info["aaguid"], ("ay", ctap2.AAGUID))
        self.assertIn("password", info["uv"][1])

    def test_register_list_sign_in_with_touch(self):
        err, (r,) = self.make()
        self.assertIsNone(err, r)
        att = cbor.decode(r["attestation_object"][1])
        ad = parse_auth_data(att["authData"])
        err, (lst,) = self.call("ListCredentials", "saay", ("example.com", []))
        self.assertEqual(len(lst), 1)
        self.assertEqual(lst[0]["id"], ("ay", ad["cred_id"]))
        err, (a,) = self.call("GetAssertion", "uaysaya{sv}", (2, CDH, "example.com", ad["cred_id"], ORIGIN))
        self.assertIsNone(err, a)
        self.assertTrue(ctap2.verify_es256(ad["point"], a["authenticator_data"][1] + CDH,
                                           a["signature"][1]))

    def test_wrong_origin(self):
        err, _ = self.make({"origin": ("s", "https://evil.test")})
        self.assertEqual(err, dp.ERR + "SecurityError")
        self.assertEqual(self.backend.creates, 1)        # only the vault key

    def test_password_by_fd(self):
        self.backend.mode = stub.NO_MATCH                 # nobody touches
        err, _ = self.make(dict(ORIGIN, password_fd=("h", self.memfd(b"nope"))))
        self.assertEqual(err, dp.ERR + "WrongPassword")
        self.assertEqual(self.backend.password_failures, 1)
        err, (r,) = self.make(dict(ORIGIN, password_fd=("h", self.memfd(b"pw"))), req=3)
        self.assertIsNone(err, r)
        self.assertEqual(self.backend.password_signs, 1)

    def test_cancel(self):
        self.backend.mode = stub.WAIT
        out = {}
        th = threading.Thread(target=lambda: out.update(r=self.make(req=7)))
        th.start()
        time.sleep(0.5)
        other = open_dbus_connection(bus="SESSION")
        try:
            # Cancel only works from the connection that started the request.
            self.call("Cancel", "u", (7,), conn=other)
            time.sleep(0.3)
            self.assertTrue(th.is_alive())
            self.call("Cancel", "u", (7,))
        finally:
            other.close()
        th.join(10)
        self.assertEqual(out["r"][0], dp.ERR + "NotAllowedError")
        self.assertEqual(self.backend.signs, 0)


@unittest.skipUnless(HAVE, "needs jeepney and a session bus (dbus-run-session)")
class DbusAllowNamesTest(DbusProviderTest):
    def setUp(self):
        super().setUp(allow_names=("org.example.Portal",))

    def test_only_the_portal(self):
        err, _ = self.call("GetInfo")
        self.assertEqual(err, dp.ERR + "NotAllowedError")
        self.client.send_and_get_reply(message_bus.RequestName("org.example.Portal", 4))
        err, _ = self.call("GetInfo")
        self.assertIsNone(err)

    # The inherited tests run without owning the portal name: all refused.
    def _refused(self):
        err, _ = self.call("GetInfo")
        self.assertEqual(err, dp.ERR + "NotAllowedError")

    test_introspect_and_info = _refused
    test_register_list_sign_in_with_touch = _refused
    test_wrong_origin = _refused
    test_password_by_fd = _refused
    test_cancel = _refused


if __name__ == "__main__":
    unittest.main()
