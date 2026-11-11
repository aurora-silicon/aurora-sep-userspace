# SPDX-License-Identifier: MIT
"""Per-user agent tests: aurora-fidod's RemoteAuthenticator -> aurora-passkeyd,
on the stub enclave (tests/stub.py). Linux only (SOCK_SEQPACKET, SO_PEERCRED).

Run from fido/: python3 tests/test_agent.py
"""

import hashlib
import os
import socket
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aurora_fido import agent, backend, cbor, creds, ctap2, daemon, remote  # noqa: E402
from aurora_fido import errors as E  # noqa: E402
from aurora_fido.backend import BackendError, BagLocked, UserBagBackend  # noqa: E402
from aurora_fido.provider import Provider, ProviderError  # noqa: E402
import stub  # noqa: E402
from stub import FileSecret, StubKeyBackend  # noqa: E402
from test_ctap import CDH, parse_auth_data  # noqa: E402

UID = os.getuid()


class Agent:
    """One user's aurora-passkeyd on the stub enclave, in a temp dir."""

    def __init__(self, root, name, allowed=None, mode=stub.MATCH, sites=None, flags_supported=0x3,
                 userbag=False, backend=None):
        self.state = os.path.join(root, name, "state")
        os.makedirs(self.state, mode=0o700, exist_ok=True)
        self.backend = backend or StubKeyBackend(mode=mode, flags_supported=flags_supported)
        cfg = daemon.load_config(None)
        cfg.set("touchid", "notify", "no")
        if userbag:      # interface 4: credentials and the vault key under the user's bag
            keys = UserBagBackend(self.backend, UID)
            secret = agent.UserBagSecret(self.backend, UID, self.state)
        else:
            keys = self.backend
            secret = FileSecret(os.path.join(root, name, "vault"))
        self.auth, _ = agent.build_agent(cfg, self.state, keys, secret, "root", sites)
        self.path = os.path.join(root, name, "run", "ctap.sock")
        self.srv = agent.AgentServer(self.auth, self.path,
                                     {UID} if allowed is None else allowed).bind()
        self.t = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.t.start()

    def close(self):
        self.srv.close()
        self.t.join(2)


class Fidod:
    """aurora-fidod's side: RemoteAuthenticator with a scripted seat."""

    def __init__(self, sockets):
        self.active = None
        self.sockets = sockets           # uid -> socket path
        self.auth = remote.RemoteAuthenticator(
            active_uid=lambda: self.active,
            socket_path=lambda uid: self.sockets.get(uid, "/nonexistent/ctap.sock"),
            timeout=10)

    def call(self, cmd, params=None, ctx=None):
        data = bytes([cmd]) + (cbor.encode(params) if params is not None else b"")
        r = self.auth.handle(data, ctx)
        return r[0], (cbor.decode(r[1:]) if len(r) > 1 else None)

    def make(self, rp="example.com", uid=b"user-1", rk=True, ctx=None):
        return self.call(ctap2.CMD_MAKE_CREDENTIAL, {
            1: CDH, 2: {"id": rp, "name": "Example"},
            3: {"id": uid, "name": "ryan", "displayName": "Ryan"},
            4: [{"type": "public-key", "alg": -7}], 7: {"rk": rk}}, ctx)

    def ga(self, rp="example.com", allow=None):
        p = {1: rp, 2: CDH}
        if allow:
            p[3] = [{"type": "public-key", "id": c} for c in allow]
        return self.call(ctap2.CMD_GET_ASSERTION, p)


class AgentTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.agents = []

    def tearDown(self):
        for a in self.agents:
            a.close()
        self.tmp.cleanup()

    def agent(self, name, **kw):
        a = Agent(self.tmp.name, name, **kw)
        self.agents.append(a)
        return a

    def test_info_through_agent_has_no_u2f(self):
        a = self.agent("u")
        f = Fidod({UID: a.path})
        f.active = UID
        st, info = f.call(ctap2.CMD_GET_INFO)
        self.assertEqual(st, 0)
        self.assertNotIn("U2F_V2", info[1])
        self.assertIn("FIDO_2_1", info[1])
        self.assertEqual(info[3], ctap2.AAGUID)
        self.assertTrue(info[4]["rk"])

    def test_passkey_register_and_usernameless_sign_in(self):
        a = self.agent("u")
        f = Fidod({UID: a.path})
        f.active = UID
        st, mc = f.make(rk=True)
        self.assertEqual(st, 0)
        ad = parse_auth_data(mc[2])
        self.assertTrue(ad["flags"] & ctap2.FLAG_UV)
        self.assertEqual(a.auth.store.count(), 1)       # the record is in this user's dir
        st, r = f.ga()                                   # no allow list: discoverable
        self.assertEqual(st, 0)
        self.assertEqual(r[1]["id"], ad["cred_id"])
        self.assertEqual(r[4]["id"], b"user-1")
        self.assertTrue(ctap2.verify_es256(ad["point"], r[2] + CDH, r[3]))
        self.assertGreaterEqual(a.backend.signs, 2)      # attestation + assertion, both "enclave"

    def test_users_do_not_see_each_other(self):
        a, b = self.agent("a"), self.agent("b")
        f = Fidod({UID: a.path})
        f.active = UID
        st, mc = f.make(rk=True)
        self.assertEqual(st, 0)
        cid = parse_auth_data(mc[2])["cred_id"]
        f.sockets[UID] = b.path                           # another user's agent at the seat
        st, _ = f.ga()
        self.assertEqual(st, E.ERR_NO_CREDENTIALS)
        st, _ = f.ga(allow=[cid])                         # a's ID does not open in b's vault
        self.assertEqual(st, E.ERR_NO_CREDENTIALS)
        self.assertEqual(b.backend.signs, 0)

    def test_no_active_user(self):
        a = self.agent("u")
        f = Fidod({UID: a.path})
        f.active = None
        st, _ = f.make()
        self.assertEqual(st, E.ERR_OPERATION_DENIED)
        st, info = f.call(ctap2.CMD_GET_INFO)
        self.assertEqual(st, 0)
        self.assertNotIn("U2F_V2", info[1])
        self.assertEqual(a.backend.creates, 0)

    def test_agent_down_uses_cached_info(self):
        a = self.agent("u")
        f = Fidod({UID: a.path})
        f.active = UID
        st, info = f.call(ctap2.CMD_GET_INFO)
        a.close()
        self.agents.remove(a)
        st2, info2 = f.call(ctap2.CMD_GET_INFO)
        self.assertEqual((st2, info2), (st, info))
        st, _ = f.make()
        self.assertEqual(st, E.ERR_OPERATION_DENIED)

    def test_socket_served_by_another_uid_is_refused(self):
        a = self.agent("u")
        f = Fidod({UID + 1: a.path})                      # seat says uid+1, socket answers as UID
        f.active = UID + 1
        st, _ = f.make()
        self.assertEqual(st, E.ERR_OPERATION_DENIED)
        self.assertEqual(a.backend.creates, 0)

    def test_agent_refuses_unlisted_peer(self):
        a = self.agent("u", allowed={UID + 1})
        f = Fidod({UID: a.path})
        f.active = UID
        st, _ = f.make()
        self.assertEqual(st, E.ERR_OPERATION_DENIED)
        self.assertEqual(a.backend.creates, 0)

    def test_cancel_reaches_the_enclave_wait(self):
        a = self.agent("u", mode=stub.WAIT)
        f = Fidod({UID: a.path})
        f.active = UID
        ups = []
        ctx = ctap2.Ctx(threading.Event(), lambda: ups.append(time.monotonic()))
        threading.Timer(0.5, ctx.cancel.set).start()
        t0 = time.monotonic()
        st, _ = f.make(ctx=ctx)
        self.assertEqual(st, E.ERR_KEEPALIVE_CANCEL)
        self.assertLess(time.monotonic() - t0, 5)
        self.assertTrue(ups, "UPNEEDED keepalive was not relayed")
        self.assertEqual(a.backend.signs, 0)

    def test_fidod_disconnect_cancels(self):
        a = self.agent("u", mode=stub.WAIT)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        s.connect(a.path)
        from aurora_fido import agentproto
        agentproto.send(s, {"t": "req", "d": bytes([ctap2.CMD_SELECTION])})
        self.assertEqual(agentproto.recv(s)["t"], "up")
        s.close()
        deadline = time.monotonic() + 5
        while a.srv.lock.locked() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertFalse(a.srv.lock.locked())
        self.assertEqual(a.backend.signs, 0)

    def test_site_policy_is_written_into_the_key(self):
        conf = os.path.join(self.tmp.name, "sites.conf")
        with open(conf, "w") as f:
            f.write("# rules\nbank.example = touchid-current\nexample = touchid-any\n"
                    "bad line\nweak.example = nothing\n")
        sites = agent.SitePolicy(conf)
        self.assertEqual(sites("login.BANK.example."), creds.POLICY_TOUCHID_CURRENT)
        self.assertEqual(sites("shop.example"), creds.POLICY_TOUCHID_ANY)
        self.assertIsNone(sites("notbank.example.org"))
        self.assertIsNone(sites("weak.example.com"))
        a = self.agent("u", sites=sites)
        f = Fidod({UID: a.path})
        f.active = UID
        st, mc = f.make(rp="login.bank.example")
        self.assertEqual(st, 0)
        self.assertEqual(a.backend.last_flags, creds.POLICY_FLAGS[creds.POLICY_TOUCHID_CURRENT])
        st, r = f.ga(rp="login.bank.example")
        self.assertEqual(st, 0)                           # the credential signs as usual

    def test_site_policy_the_kernel_cannot_make_is_refused(self):
        conf = os.path.join(self.tmp.name, "sites.conf")
        with open(conf, "w") as f:
            f.write("bank.example = touchid-current\n")
        a = self.agent("u", sites=agent.SitePolicy(conf), flags_supported=0x2)
        f = Fidod({UID: a.path})
        f.active = UID
        st, _ = f.make(rp="bank.example")
        self.assertEqual(st, E.ERR_UNSUPPORTED_OPTION)
        self.assertEqual(a.backend.creates, 0)            # no weaker key was made
        st, _ = f.make(rp="other.example")
        self.assertEqual(st, 0)

    def test_vault_key_needs_interface_4(self):
        class Old:
            version = 3
        with self.assertRaises(BackendError) as c:
            agent.UserBagSecret(Old(), UID, self.tmp.name).load()
        self.assertIn("interface 4", str(c.exception))


class UserBagTest(unittest.TestCase):
    """Interface 4: keys and the vault key under the user's own key bag."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.agents = []

    def tearDown(self):
        for a in self.agents:
            a.close()
        self.tmp.cleanup()

    def agent(self, name="u", **kw):
        a = Agent(self.tmp.name, name, userbag=True, **kw)
        self.agents.append(a)
        f = Fidod({UID: a.path})
        f.active = UID
        return a, f

    def test_passkey_is_a_user_presence_key_under_the_bag(self):
        a, f = self.agent()
        st, mc = f.make()
        self.assertEqual(st, 0)
        self.assertEqual(a.auth.policy, creds.POLICY_TOUCHID_OR_PASSWORD)
        cred = a.auth.vault.unwrap(hashlib.sha256(b"example.com").digest(),
                                   parse_auth_data(mc[2])["cred_id"])
        self.assertEqual(backend.user_handle_uid(cred.handle), UID)
        self.assertTrue(backend.is_gated_handle(cred.handle))
        self.assertTrue(os.path.exists(os.path.join(a.state, "vault.key")))
        st, _ = f.ga()
        self.assertEqual(st, 0)

    def test_vault_key_is_a_plain_bag_key_and_reopens(self):
        a, f = self.agent()
        self.assertEqual(f.make()[0], 0)
        with open(os.path.join(a.state, "vault.key"), "rb") as fh:
            rec = cbor.decode(fh.read())
        self.assertTrue(backend.is_user_plain_handle(rec[1]))
        self.assertFalse(backend.is_gated_handle(rec[1]))     # never a credential key
        a.close()
        self.agents.remove(a)
        b, f2 = self.agent(backend=a.backend)                 # agent restart, same enclave
        st, r = f2.ga()
        self.assertEqual(st, 0)                               # records open again

    def test_locked_bag_refuses_everything(self):
        a, f = self.agent()
        self.assertEqual(f.make()[0], 0)
        signs = a.backend.signs
        a.backend.bag_locked = True
        st, _ = f.ga()
        self.assertEqual(st, E.ERR_OPERATION_DENIED)
        self.assertEqual(a.backend.signs, signs)
        with self.assertRaises(BagLocked):
            agent.UserBagSecret(a.backend, UID, a.state).load()  # no vault key while locked
        a.backend.bag_locked = False
        self.assertEqual(f.ga()[0], 0)

    def test_password_route_through_the_native_front_end(self):
        a, f = self.agent(mode=stub.NO_MATCH)                 # no finger at all
        p = Provider(a.auth)
        o = {"origin": "https://example.com"}
        pw = bytearray(b"pw")
        r = p.make_credential(CDH, {"id": "example.com"}, {"id": b"u1", "name": "r"}, [-7],
                              options=o, password=pw)
        self.assertEqual(pw, bytearray(2))                    # wiped
        cid = parse_auth_data(cbor.decode(r["attestation_object"])["authData"])["cred_id"]
        a2 = p.get_assertion(CDH, "example.com", cid, o, password=bytearray(b"pw"))
        self.assertTrue(a2["signature"])
        self.assertEqual(a.backend.password_signs, 2)
        before = a.backend.signs
        with self.assertRaises(ProviderError) as c:
            p.get_assertion(CDH, "example.com", cid, o, password=bytearray(b"nope"))
        self.assertEqual(c.exception.reason, "wrong-password")
        self.assertEqual(a.backend.password_failures, 1)      # counted by the "enclave"
        self.assertEqual(a.backend.signs, before)
        with self.assertRaises(ProviderError):                # and no finger: refused
            p.get_assertion(CDH, "example.com", cid, o)
        self.assertIn("password", p.get_info()["uv"])

    def test_biometric_only_site_rule_is_refused_under_the_bag(self):
        conf = os.path.join(self.tmp.name, "sites.conf")
        with open(conf, "w") as fh:
            fh.write("bank.example = touchid-current\n")
        a, f = self.agent(sites=agent.SitePolicy(conf))
        st, _ = f.make(rp="bank.example")
        self.assertEqual(st, E.ERR_UNSUPPORTED_OPTION)
        self.assertEqual(f.make(rp="other.example")[0], 0)

    def test_another_users_handle_is_refused(self):
        a, _ = self.agent()
        mine = UserBagBackend(a.backend, UID)
        h, _p = a.backend.create_user(UID + 1, True)
        with self.assertRaises(backend.InvalidHandle):
            mine.sign(h, b"\0" * 32)
        self.assertFalse(mine.gated(h))


if __name__ == "__main__":
    unittest.main()
