# SPDX-License-Identifier: MIT
"""Unit tests: the system vault keeps each account's credentials to that account
(owners.py), credentials made before owners were recorded keep working for one
account, and the polkit rule for fingerprint enrolment.

Run from fido/: python3 tests/test_owners.py
"""

import hashlib
import json
import os
import pwd
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)

from aurora_fido import cbor, cli, creds, ctap2, daemon, owners, pinuv, u2f  # noqa: E402
from aurora_fido import errors as E  # noqa: E402
import stub  # noqa: E402
from test_ctap import CDH, Platform, Rig, parse_auth_data  # noqa: E402

ALICE, BOB = 1001, 1002
RP = "example.com"
RP_HASH = hashlib.sha256(RP.encode()).digest()


class Seat:
    """Who is active on seat0, as the test says."""

    def __init__(self, uid=ALICE):
        self.uid = uid

    def __call__(self):
        return self.uid


class OwnedRig(Rig):
    """A Rig whose authenticator is the system vault with owners (as aurora-fidod builds it)."""

    def __init__(self, seat=None, fprint=None, legacy_store=False, **kw):
        super().__init__(**kw)
        self.seat = seat or Seat()
        if legacy_store:
            with open(os.path.join(self.state, "master.sep"), "wb") as f:
                f.write(b"old")
        self.fprint = fprint or os.path.join(self.tmp.name, "fprint")
        self.rebuild()

    def rebuild(self):
        self.owners = owners.Owners(self.state, self.seat, self.fprint)
        self.auth, self.u2f = daemon.build(self.cfg, self.state, self.backend, self.user,
                                           self.secret, self.policy,
                                           lambda rp, why: self.legacy.append((rp, why)),
                                           self.owners)
        self.auth.clock = self.clock
        self.auth.started = self.clock()
        self.auth.token.clock = self.clock

    def cid(self, r):
        return parse_auth_data(r[2])["cred_id"]

    def unowned(self, rk=False, uid=b"old"):
        """A credential as the previous version made it: no owner in its ID."""
        handle, point = self.backend.create(0x2)
        cid = self.auth.vault.wrap(RP_HASH, creds.Credential(handle, 1, 1))
        if rk:
            self.auth.store.put({"rpId": RP, "rpIdHash": RP_HASH, "userId": uid,
                                 "credId": cid, "pub": bytes(point), "credProtect": 1})
        return cid


def apdu(ins, p1, data):
    return bytes([0, ins, p1, 0, 0]) + struct.pack(">H", len(data)) + data + b"\x00\x00"


def owners_file(rig):
    with open(os.path.join(rig.state, owners.FILE)) as f:
        return json.load(f)


def cm_call(rig, plat, tok, sub, params=None, auth=True):
    p = {1: sub}
    if params is not None:
        p[2] = params
    if auth:
        msg = bytes([sub]) + (cbor.encode(params) if params is not None else b"")
        p[3], p[4] = 2, plat.auth(tok, msg)
    return rig.call(ctap2.CMD_CRED_MGMT, p)


class PerAccountTest(unittest.TestCase):
    def setUp(self):
        self.rig = OwnedRig()

    def tearDown(self):
        self.rig.close()

    def test_another_account_cannot_use_a_credential(self):
        st, r = self.rig.make()
        self.assertEqual(st, 0)
        cid = self.rig.cid(r)
        self.assertEqual(self.rig.ga(cid)[0], 0)
        self.rig.seat.uid = BOB
        signs = self.rig.backend.signs
        self.assertEqual(self.rig.ga(cid)[0], E.ERR_NO_CREDENTIALS)
        self.assertEqual(self.rig.backend.signs, signs)       # nothing asked of the enclave
        self.rig.seat.uid = ALICE
        self.assertEqual(self.rig.ga(cid)[0], 0)

    def test_owner_is_inside_the_authenticated_id(self):
        _, r = self.rig.make()
        c = self.rig.auth.vault.unwrap(RP_HASH, self.rig.cid(r))
        self.assertEqual(c.owner, ALICE)

    def test_discoverable_credentials_are_per_account(self):
        self.rig.make(uid=b"alice", rk=True)
        self.rig.seat.uid = BOB
        st, _ = self.rig.call(ctap2.CMD_GET_ASSERTION, {1: RP, 2: CDH})
        self.assertEqual(st, E.ERR_NO_CREDENTIALS)
        self.rig.make(uid=b"bob", rk=True)
        st, a = self.rig.call(ctap2.CMD_GET_ASSERTION, {1: RP, 2: CDH})
        self.assertEqual((st, a[4]["id"], a.get(5)), (0, b"bob", None))
        # The same user ID at the same site, made by another account, replaces
        # only that account's record.
        self.rig.seat.uid = ALICE
        self.rig.make(uid=b"bob", rk=True)
        self.assertEqual(self.rig.auth.store.count(), 3)

    def test_exclude_list_ignores_other_accounts(self):
        _, r = self.rig.make()
        cid = self.rig.cid(r)
        self.rig.seat.uid = BOB
        st, _ = self.rig.make(extra={5: [{"type": "public-key", "id": cid}]})
        self.assertEqual(st, 0)

    def test_credential_management_is_per_account(self):
        self.rig.make(rp="a.example", uid=b"ua", rk=True)
        self.rig.seat.uid = BOB
        self.rig.make(rp="b.example", uid=b"ub", rk=True)
        plat = Platform(self.rig)
        _, tok = plat.token(pinuv.PERM_CM)
        st, meta = cm_call(self.rig, plat, tok, 0x01)
        self.assertEqual((st, meta[1]), (0, 1))
        st, rp = cm_call(self.rig, plat, tok, 0x02)
        self.assertEqual((st, rp[3]["id"], rp[5]), (0, "b.example", 1))
        ah = hashlib.sha256(b"a.example").digest()
        self.assertEqual(cm_call(self.rig, plat, tok, 0x04, {1: ah})[0], E.ERR_NO_CREDENTIALS)
        alice_id = self.rig.auth.store.for_rp(ah)[0]["credId"]
        desc = {"type": "public-key", "id": alice_id}
        self.assertEqual(cm_call(self.rig, plat, tok, 0x06, {2: desc})[0],
                         E.ERR_NO_CREDENTIALS)
        self.assertEqual(cm_call(self.rig, plat, tok, 0x07,
                                 {2: desc, 3: {"id": b"ua", "name": "x"}})[0],
                         E.ERR_NO_CREDENTIALS)
        self.assertEqual(self.rig.auth.store.count(), 2)

    def test_reset_is_refused_while_another_account_has_credentials(self):
        self.rig.make()
        self.rig.seat.uid = BOB
        self.assertEqual(self.rig.call(ctap2.CMD_RESET)[0], E.ERR_NOT_ALLOWED)
        self.rig.seat.uid = ALICE
        self.assertEqual(self.rig.call(ctap2.CMD_RESET)[0], 0)
        self.assertEqual(self.rig.owners.uids, set())
        # Kept across a restart.
        self.rig.make()
        self.rig.rebuild()
        self.rig.seat.uid = BOB
        self.assertEqual(self.rig.call(ctap2.CMD_RESET)[0], E.ERR_NOT_ALLOWED)

    def test_no_active_session_no_service(self):
        _, r = self.rig.make()
        self.rig.seat.uid = None
        self.assertEqual(self.rig.ga(self.rig.cid(r))[0], E.ERR_OPERATION_DENIED)
        self.assertEqual(self.rig.make()[0], E.ERR_OPERATION_DENIED)
        self.assertEqual(self.rig.call(ctap2.CMD_GET_INFO)[0], 0)

    def test_u2f_is_per_account(self):
        app = hashlib.sha256(b"https://u2f.example").digest()

        def poll(a):
            for _ in range(200):
                r = self.rig.u2f.handle(a)
                if r[-2:] != b"\x69\x85":
                    return r
                time.sleep(0.01)
            return r

        r = poll(apdu(u2f.INS_REGISTER, 0, os.urandom(32) + app))
        self.assertEqual(r[-2:], b"\x90\x00")
        khl = r[66]
        kh = r[67:67 + khl]
        check = apdu(u2f.INS_AUTHENTICATE, 0x07, os.urandom(32) + app + bytes([khl]) + kh)
        self.assertEqual(self.rig.u2f.handle(check), b"\x69\x85")     # known
        self.rig.seat.uid = BOB
        self.assertEqual(self.rig.u2f.handle(check), b"\x6a\x80")     # unknown to Bob
        self.rig.seat.uid = None
        self.assertEqual(self.rig.u2f.handle(check), b"\x6a\x80")        # not usable by anyone now

    def test_an_account_owns_nothing_before_its_first_credential(self):
        """Only a finished credential (the touch matched) makes its account one
        that reset has to respect."""
        self.assertEqual(self.rig.make()[0], 0)                   # Alice has one
        self.rig.seat.uid = BOB
        for mode, want in ((stub.TIMEOUT, E.ERR_USER_ACTION_TIMEOUT),
                           (stub.NO_MATCH, E.ERR_OPERATION_DENIED)):
            self.rig.mode = mode
            self.assertEqual(self.rig.make(rk=True)[0], want)
            reg = apdu(u2f.INS_REGISTER, 0, os.urandom(32) + RP_HASH)
            self.assertEqual(self.rig.u2f.handle(reg), b"\x69\x85")
            self.rig.u2f.presence.thread.join(5)
            self.assertEqual(self.rig.u2f.handle(reg), b"\x69\x85")
        self.rig.mode = stub.MATCH
        self.assertEqual(self.rig.owners.uids, {ALICE})
        self.assertEqual(owners_file(self.rig)["uids"], [ALICE])
        self.assertEqual(self.rig.auth.store.count(), 0)
        self.rig.seat.uid = ALICE
        self.rig.auth.started = self.rig.clock()
        self.assertEqual(self.rig.call(ctap2.CMD_RESET)[0], 0)
        # Once the other account does have a credential, reset is refused.
        self.assertEqual(self.rig.make()[0], 0)
        self.rig.seat.uid = BOB
        self.assertEqual(self.rig.make()[0], 0)
        self.assertEqual(owners_file(self.rig)["uids"], [ALICE, BOB])
        self.rig.seat.uid = ALICE
        self.assertEqual(self.rig.call(ctap2.CMD_RESET)[0], E.ERR_NOT_ALLOWED)


class SessionBindingTest(unittest.TestCase):
    """Tokens and continuations belong to the account that made them: a change of
    the seat user drops them, and another account's request cannot use them."""

    def setUp(self):
        self.rig = OwnedRig()
        self.addCleanup(self.rig.close)

    def two_accounts(self):
        self.rig.seat.uid = ALICE
        self.rig.make(rp="a1.example", uid=b"alice1", rk=True)
        self.rig.make(rp="a2.example", uid=b"alice2", rk=True)
        self.rig.seat.uid = BOB
        self.rig.make(rp="b.example", uid=b"bob", rk=True)

    def test_a_cm_token_does_not_cross_to_another_account(self):
        self.two_accounts()
        plat = Platform(self.rig)                       # Bob, active on seat0
        _, tok = plat.token(pinuv.PERM_CM)
        self.assertEqual(cm_call(self.rig, plat, tok, 0x01)[0], 0)
        self.rig.seat.uid = ALICE                       # user switch; Bob's process keeps its fd
        touches = self.rig.backend.touches
        for sub, params in ((0x01, None), (0x02, None),
                            (0x04, {1: hashlib.sha256(b"a1.example").digest()})):
            self.assertEqual(cm_call(self.rig, plat, tok, sub, params)[0], E.ERR_PIN_AUTH_INVALID)
        alice_id = self.rig.auth.store.for_rp(hashlib.sha256(b"a1.example").digest())[0]["credId"]
        self.assertEqual(cm_call(self.rig, plat, tok, 0x06,
                                 {2: {"type": "public-key", "id": alice_id}})[0],
                         E.ERR_PIN_AUTH_INVALID)
        self.assertEqual(self.rig.auth.store.count(), 3)
        self.assertEqual(self.rig.backend.touches, touches)
        # Back to Bob: the token was dropped at the switch, not just hidden.
        self.rig.seat.uid = BOB
        self.assertEqual(cm_call(self.rig, plat, tok, 0x01)[0], E.ERR_PIN_AUTH_INVALID)

    def test_a_ga_token_does_not_cross_to_another_account(self):
        self.rig.seat.uid = ALICE
        _, r = self.rig.make()
        cid = self.rig.cid(r)
        self.rig.seat.uid = BOB
        plat = Platform(self.rig)
        _, tok = plat.token(pinuv.PERM_GA, RP)
        self.rig.seat.uid = ALICE
        st, _ = self.rig.ga(cid, extra={6: plat.auth(tok, CDH), 7: plat.version})
        self.assertEqual(st, E.ERR_PIN_AUTH_INVALID)

    def test_an_enumeration_does_not_continue_for_another_account(self):
        self.two_accounts()
        self.rig.seat.uid = ALICE
        plat = Platform(self.rig)
        _, tok = plat.token(pinuv.PERM_CM)
        st, rp1 = cm_call(self.rig, plat, tok, 0x02)
        self.assertEqual((st, rp1[5]), (0, 2))
        self.rig.seat.uid = BOB
        self.assertEqual(cm_call(self.rig, plat, tok, 0x03, auth=False)[0], E.ERR_NOT_ALLOWED)
        # Nor for Alice again: it was dropped at the switch.
        self.rig.seat.uid = ALICE
        self.assertEqual(cm_call(self.rig, plat, tok, 0x03, auth=False)[0], E.ERR_NOT_ALLOWED)

    def test_a_credential_enumeration_needs_a_session_to_continue(self):
        self.rig.seat.uid = ALICE
        self.rig.make(uid=b"alice1", rk=True)
        self.rig.make(uid=b"alice2", rk=True)
        plat = Platform(self.rig)
        _, tok = plat.token(pinuv.PERM_CM)
        st, c1 = cm_call(self.rig, plat, tok, 0x04, {1: RP_HASH})
        self.assertEqual((st, c1[9]), (0, 2))
        self.rig.seat.uid = None
        self.assertEqual(cm_call(self.rig, plat, tok, 0x05, auth=False)[0], E.ERR_OPERATION_DENIED)
        self.rig.seat.uid = BOB
        self.assertEqual(cm_call(self.rig, plat, tok, 0x05, auth=False)[0], E.ERR_NOT_ALLOWED)

    def test_get_next_assertion_does_not_continue_for_another_account(self):
        self.rig.seat.uid = ALICE
        self.rig.make(uid=b"alice1", rk=True)
        self.rig.make(uid=b"alice2", rk=True)
        st, a = self.rig.call(ctap2.CMD_GET_ASSERTION, {1: RP, 2: CDH})
        self.assertEqual((st, a[5]), (0, 2))
        self.rig.seat.uid = BOB
        signs = self.rig.backend.signs
        self.assertEqual(self.rig.call(ctap2.CMD_GET_NEXT_ASSERTION)[0], E.ERR_NOT_ALLOWED)
        self.assertEqual(self.rig.backend.signs, signs)
        self.rig.seat.uid = ALICE
        self.assertEqual(self.rig.call(ctap2.CMD_GET_NEXT_ASSERTION)[0], E.ERR_NOT_ALLOWED)

    def test_a_u2f_touch_does_not_cross_to_another_account(self):
        app, chal = hashlib.sha256(b"https://u2f.example").digest(), os.urandom(32)
        reg = apdu(u2f.INS_REGISTER, 0, chal + app)
        self.rig.seat.uid = ALICE
        self.assertEqual(self.rig.u2f.handle(reg), b"\x69\x85")       # prompt started
        self.rig.u2f.presence.thread.join(5)                          # and matched
        touches = self.rig.backend.touches
        self.rig.seat.uid = BOB                                       # the same request bytes
        self.assertEqual(self.rig.u2f.handle(reg), b"\x69\x85")
        self.assertEqual(self.rig.owners.uids, set())
        # Bob's own ceremony takes its own touch and makes his own credential.
        self.rig.u2f.presence.thread.join(5)
        r = self.rig.u2f.handle(reg)
        self.assertEqual(r[-2:], b"\x90\x00")
        self.assertEqual(self.rig.backend.touches, touches + 1)
        self.assertEqual(self.rig.owners.uids, {BOB})
        # Nor back to Alice: her finished touch went with the switch.
        self.rig.seat.uid = ALICE
        self.assertEqual(self.rig.u2f.handle(reg), b"\x69\x85")

    def test_a_u2f_prompt_ends_when_the_account_changes(self):
        self.rig.mode = stub.WAIT
        reg = apdu(u2f.INS_REGISTER, 0, os.urandom(32) + RP_HASH)
        self.rig.seat.uid = ALICE
        self.assertEqual(self.rig.u2f.handle(reg), b"\x69\x85")
        waiting, cancel = self.rig.u2f.presence.thread, self.rig.u2f.presence.cancel
        self.assertFalse(cancel.is_set())
        self.rig.seat.uid = BOB
        self.assertEqual(self.rig.call(ctap2.CMD_CLIENT_PIN, {1: 2, 2: 2})[0], 0)
        self.assertTrue(cancel.is_set())
        waiting.join(5)
        self.assertFalse(waiting.is_alive())
        self.assertIsNone(self.rig.u2f.presence.key)

    def test_the_same_account_keeps_its_session(self):
        self.rig.seat.uid = ALICE
        self.rig.make(uid=b"alice1", rk=True)
        self.rig.make(uid=b"alice2", rk=True)
        st, _ = self.rig.call(ctap2.CMD_GET_ASSERTION, {1: RP, 2: CDH})
        self.assertEqual(self.rig.call(ctap2.CMD_GET_NEXT_ASSERTION)[0], 0)

    def test_no_session_no_touch_prompt(self):
        self.rig.seat.uid = ALICE
        plat = Platform(self.rig)
        self.rig.seat.uid = None
        touches = self.rig.backend.touches
        self.assertEqual(self.rig.call(ctap2.CMD_SELECTION)[0], E.ERR_OPERATION_DENIED)
        self.assertEqual(plat.token(pinuv.PERM_CM)[0], E.ERR_OPERATION_DENIED)
        self.assertEqual(self.rig.backend.touches, touches)
        self.assertEqual(self.rig.call(ctap2.CMD_GET_INFO)[0], 0)


class LegacyOwnerTest(unittest.TestCase):
    """Credentials of a store made before owners were recorded."""

    def prints(self, root, *names):
        for n in names:
            d = os.path.join(root, n, "apple-sep", "0")
            os.makedirs(d)
            with open(os.path.join(d, "7"), "wb") as f:
                f.write(b"print")

    def two_users(self):
        """Two passwd names that exist here: root and the test user (or nobody)."""
        me = pwd.getpwuid(os.getuid()).pw_name
        other = "root" if me != "root" else "nobody"
        return (me, os.getuid()), (other, pwd.getpwnam(other).pw_uid)

    def test_single_account_with_prints_keeps_its_credentials(self):
        (me, my_uid), (other, other_uid) = self.two_users()
        tmp = tempfile.mkdtemp()
        try:
            fprint = os.path.join(tmp, "fprint")
            self.prints(fprint, me)
            rig = OwnedRig(seat=Seat(my_uid), fprint=fprint, legacy_store=True)
            try:
                cid = rig.unowned()
                rk = rig.unowned(rk=True)
                self.assertEqual(rig.owners.legacy, my_uid)
                self.assertEqual(rig.ga(cid)[0], 0)
                st, a = rig.call(ctap2.CMD_GET_ASSERTION, {1: RP, 2: CDH})
                self.assertEqual((st, a[1]["id"]), (0, rk))
                rig.seat.uid = other_uid
                self.assertEqual(rig.ga(cid)[0], E.ERR_NO_CREDENTIALS)
                self.assertEqual(rig.call(ctap2.CMD_GET_ASSERTION, {1: RP, 2: CDH})[0],
                                 E.ERR_NO_CREDENTIALS)
                self.assertEqual(rig.call(ctap2.CMD_RESET)[0], E.ERR_NOT_ALLOWED)
                # A second account enrolling later does not change the owner.
                self.prints(fprint, other)
                rig.rebuild()
                self.assertEqual(rig.owners.legacy, my_uid)
                rig.seat.uid = my_uid
                self.assertEqual(rig.ga(cid)[0], 0)
            finally:
                rig.close()
        finally:
            shutil.rmtree(tmp)

    def test_ambiguous_owner_is_refused_until_adopted(self):
        (me, my_uid), (other, other_uid) = self.two_users()
        tmp = tempfile.mkdtemp()
        try:
            fprint = os.path.join(tmp, "fprint")
            self.prints(fprint, me, other)
            rig = OwnedRig(seat=Seat(my_uid), fprint=fprint, legacy_store=True)
            try:
                cid = rig.unowned()
                self.assertTrue(rig.owners.legacy_unassigned)
                self.assertEqual(rig.ga(cid)[0], E.ERR_NO_CREDENTIALS)
                info = daemon.owners_info(rig.owners)
                self.assertTrue(info["legacy_unassigned"])
                text = cli.render({"enabled": "enabled", "active": "active", "device": "x",
                                   "keys": "sep-key", "keys_if_enabled": "sep-key",
                                   "ready": True, "version": "x", "policy": "auto",
                                   "vault": "system", "owners": info})
                self.assertIn("adopt-legacy", text)
                owners.Owners(rig.state, lambda: None, fprint).adopt(my_uid)
                rig.rebuild()
                self.assertEqual(rig.ga(cid)[0], 0)
                rig.seat.uid = other_uid
                self.assertEqual(rig.ga(cid)[0], E.ERR_NO_CREDENTIALS)
            finally:
                rig.close()
        finally:
            shutil.rmtree(tmp)

    def test_new_store_has_no_legacy_credentials(self):
        rig = OwnedRig()
        try:
            self.assertFalse(rig.owners.legacy_store)
            # Even a forged ownerless ID could open for nobody.
            self.assertFalse(rig.owners.owns(ALICE, None))
            with open(os.path.join(rig.state, owners.FILE)) as f:
                self.assertEqual(json.load(f)["legacy_store"], False)
            self.assertEqual(os.stat(os.path.join(rig.state, owners.FILE)).st_mode & 0o077, 0)
        finally:
            rig.close()

    def test_damaged_owners_file_refuses(self):
        rig = OwnedRig(legacy_store=True)
        try:
            with open(os.path.join(rig.state, owners.FILE), "w") as f:
                f.write("{")
            rig.rebuild()
            self.assertFalse(rig.owners.owns(ALICE, None))
            self.assertTrue(rig.owners.others(ALICE))
            # Repairing the legacy owner does not open reset: who made the other
            # credentials is still not known.
            owners.Owners(rig.state, lambda: None, rig.fprint).adopt(ALICE)
            rig.rebuild()
            self.assertTrue(rig.owners.owns(ALICE, None))
            self.assertTrue(rig.owners.others(ALICE))
            self.assertEqual(rig.call(ctap2.CMD_RESET)[0], E.ERR_NOT_ALLOWED)
        finally:
            rig.close()


class PolkitRuleTest(unittest.TestCase):
    RULE = os.path.join(HERE, "..", "40-aurora-fprint-enroll.rules")

    def run_rule(self, action, user="alice", local=True, active=True):
        node = shutil.which("node")
        if not node:
            self.skipTest("no node to evaluate the polkit rule")
        js = """
const fs = require('fs');
let rule = null;
const polkit = {Result: {NO: 'no', YES: 'yes', AUTH_SELF: 'auth_self',
  AUTH_SELF_KEEP: 'auth_self_keep', AUTH_ADMIN: 'auth_admin',
  AUTH_ADMIN_KEEP: 'auth_admin_keep', NOT_HANDLED: null},
  addRule: f => { rule = f; }};
eval(fs.readFileSync(process.argv[1], 'utf8'));
const r = rule({id: process.argv[2]}, {user: process.argv[3],
  local: process.argv[4] === '1', active: process.argv[5] === '1'});
console.log(JSON.stringify(r === undefined ? null : r));
"""
        out = subprocess.run([node, "-e", js, self.RULE, action, user,
                              "1" if local else "0", "1" if active else "0"],
                             capture_output=True, text=True, check=True).stdout
        return json.loads(out)

    def test_enrolment_needs_the_password_every_time(self):
        enroll = "net.reactivated.fprint.device.enroll"
        self.assertEqual(self.run_rule(enroll), "auth_self")
        self.assertEqual(self.run_rule(enroll, active=False), "no")
        self.assertEqual(self.run_rule(enroll, local=False), "no")
        self.assertIsNone(self.run_rule(enroll, user="root"))
        self.assertIsNone(self.run_rule("net.reactivated.fprint.device.verify"))

    def test_installed(self):
        with open(os.path.join(HERE, "..", "Makefile")) as f:
            self.assertIn("40-aurora-fprint-enroll.rules $(DESTDIR)$(POLKITRULESDIR)", f.read())


if __name__ == "__main__":
    unittest.main()
