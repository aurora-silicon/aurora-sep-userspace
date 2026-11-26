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
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from jeepney import DBusAddress, MessageType, new_method_call
    from jeepney.bus_messages import message_bus
    from jeepney.io.blocking import open_dbus_connection
    from jeepney.io import threading as jthreading
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
PORTAL = "org.example.Portal"
ORIGIN = {"origin": ("s", "https://example.com")}
RP = {"id": ("s", "example.com"), "name": ("s", "Example")}
USER = {"id": ("ay", b"user-1"), "name": ("s", "ryan")}


# The calls of a configured portal: the client owns the allowed bus name.
@unittest.skipUnless(HAVE, "needs jeepney and a session bus (dbus-run-session)")
class DbusProviderTest(unittest.TestCase):
    def setUp(self, allow_names=(PORTAL,), own_portal=True):
        self.tmp = tempfile.TemporaryDirectory()
        self.backend = stub.StubKeyBackend()
        self.cfg = cfg = daemon.load_config(None)
        cfg.set("touchid", "notify", "no")
        state = os.path.join(self.tmp.name, "state")
        os.makedirs(state)
        self.auth, _ = agent.build_agent(cfg, state, UserBagBackend(self.backend, UID),
                                         agent.UserBagSecret(self.backend, UID, state), "root")
        self.provider = mock.Mock(wraps=Provider(self.auth))
        self.svc = dp.ProviderService(self.provider, allow_names=allow_names)
        self.assertTrue(self.svc.request_name())
        self.t = threading.Thread(target=self.svc.serve_forever, daemon=True)
        self.t.start()
        # A request and its Cancel come from one connection, in two threads.
        self.client_conn = jthreading.open_dbus_connection(bus="SESSION", enable_fds=True)
        self.client = jthreading.DBusRouter(self.client_conn)
        if own_portal:
            self.client.send_and_get_reply(message_bus.RequestName(PORTAL, 4))
        self.addr = DBusAddress(dp.PATH, bus_name=dp.BUS_NAME, interface=dp.IFACE)

    def tearDown(self):
        self.client.close()
        self.client_conn.close()
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


# A portal is configured, but the client is not it.
@unittest.skipUnless(HAVE, "needs jeepney and a session bus (dbus-run-session)")
class DbusAllowNamesTest(DbusProviderTest):
    def setUp(self):
        super().setUp(own_portal=False)

    def test_only_the_portal(self):
        err, _ = self.call("GetInfo")
        self.assertEqual(err, dp.ERR + "NotAllowedError")
        self.client.send_and_get_reply(message_bus.RequestName(PORTAL, 4))
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


# No portal configured, as by default: every call of the user's own processes
# is refused before the provider (and its vault) sees it.
@unittest.skipUnless(HAVE, "needs jeepney and a session bus (dbus-run-session)")
class DbusNoPortalTest(DbusProviderTest):
    def setUp(self):
        super().setUp(allow_names=(), own_portal=False)

    def test_no_caller_reaches_the_provider(self):
        # Owning a name, any name, does not help.
        self.client.send_and_get_reply(message_bus.RequestName(PORTAL, 4))
        for member, sig, body in (
                ("ListCredentials", "saay", ("example.com", [])),
                ("GetInfo", None, ()),
                ("GetAssertion", "uaysaya{sv}", (2, CDH, "example.com", b"id", ORIGIN)),
                ("Cancel", "u", (1,))):
            err, _ = self.call(member, sig, body)
            self.assertEqual(err, dp.ERR + "NotAllowedError", member)
        err, _ = self.make()
        self.assertEqual(err, dp.ERR + "NotAllowedError")
        self.assertEqual(self.provider.mock_calls, [])
        self.assertEqual(self.backend.signs, 0)

    test_introspect_and_info = DbusAllowNamesTest._refused
    test_register_list_sign_in_with_touch = DbusAllowNamesTest._refused
    test_wrong_origin = DbusAllowNamesTest._refused
    test_password_by_fd = DbusAllowNamesTest._refused
    test_cancel = DbusAllowNamesTest._refused


# The agent's front-end follows [native] portal_names.
@unittest.skipUnless(HAVE, "needs jeepney and a session bus (dbus-run-session)")
class StartDbusTest(unittest.TestCase):
    SHIPPED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "aurora-fido.conf")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        backend = stub.StubKeyBackend()
        self.cfg = daemon.load_config(self.SHIPPED)      # the configuration as installed
        self.cfg.set("touchid", "notify", "no")
        state = os.path.join(self.tmp.name, "state")
        os.makedirs(state)
        self.auth, _ = agent.build_agent(self.cfg, state, UserBagBackend(backend, UID),
                                         agent.UserBagSecret(backend, UID, state), "root")
        self.query = open_dbus_connection(bus="SESSION")

    def tearDown(self):
        self.query.close()
        self.tmp.cleanup()

    def owned(self):
        r = self.query.send_and_get_reply(message_bus.NameHasOwner(dp.BUS_NAME))
        return r.body[0]

    def test_default_config_has_no_front_end(self):
        self.assertEqual(self.cfg.get("native", "portal_names").split(), [])
        self.assertIsNone(agent.start_dbus(self.auth, self.cfg))
        self.assertFalse(self.owned())
        # No config file at all: the same.
        self.assertIsNone(agent.start_dbus(self.auth, daemon.load_config(None)))
        self.assertFalse(self.owned())

    def test_configured_portal_gets_the_front_end(self):
        self.cfg.set("native", "portal_names", PORTAL)
        svc = agent.start_dbus(self.auth, self.cfg)
        try:
            self.assertIsNotNone(svc)
            self.assertEqual(svc.allow_names, (PORTAL,))
            self.assertTrue(self.owned())
        finally:
            svc.close()


if __name__ == "__main__":
    unittest.main()
