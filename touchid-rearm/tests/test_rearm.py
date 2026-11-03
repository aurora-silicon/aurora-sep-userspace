#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""End-to-end check of pam_aurora_touchid and aurora-touchid-rearm without a
Mac: real libpam stacks, stand-in modules for pam_unix and pam_fprintd, a
fake lockout device and a socket server that starts the helper per
connection as systemd's Accept=yes does. Run from the Makefile's check."""
import os
import pwd
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOP = HERE.parent
MODULE = TOP / 'pam_aurora_touchid.so'
HELPER = TOP / 'aurora-touchid-rearm-test'
FAKE = HERE / 'pam_fake.so'
DRIVER = HERE / 'pam-stack-check'
MAGIC = b'AURORA-REARM-1\n'
PAM_SUCCESS, PAM_AUTH_ERR = 0, 7
USER = pwd.getpwuid(os.getuid()).pw_name


def system_module(name):
    for d in (os.environ.get('AURORA_TEST_PAM_DIR', '/nonexistent'), '/usr/lib64/security', '/usr/lib/security',
              '/usr/lib/x86_64-linux-gnu/security', '/usr/lib/aarch64-linux-gnu/security'):
        if (Path(d) / name).exists():
            return f'{d}/{name}'
    raise unittest.SkipTest(f'{name} not found')


class Rig:
    def __init__(self, tmp):
        self.tmp = Path(tmp)
        self.device = self.tmp / 'device'
        self.fprint = self.tmp / 'fprint'
        self.conf = self.tmp / 'pam.d'
        self.sock = str(self.tmp / 'rearm.sock')
        self.conf.mkdir()
        (self.fprint / USER / 'apple-sep').mkdir(parents=True)
        (self.conf / 'aurora-touchid-rearm').write_text(
            f'auth required {FAKE} password\naccount required {FAKE}\n')
        self.connections = 0
        self.replies = []
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(self.sock)
        self.server.listen(4)
        self.env = dict(os.environ,
                        AURORA_REARM_TEST_DEVICE=str(self.device),
                        AURORA_REARM_TEST_FPRINT_DIR=str(self.fprint),
                        AURORA_REARM_TEST_CONFDIR=str(self.conf))
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            self.connections += 1
            subprocess.run([HELPER], stdin=conn.fileno(), stdout=conn.fileno(),
                           env=self.env, check=False, timeout=20)
            conn.close()

    def lock(self, state):
        self.device.write_text(state + '\n')

    def state(self):
        return self.device.read_text().strip()

    def stack(self, name, module_line):
        # Authselect's system-auth after authselect-vendor-local: fingerprint,
        # then pam_unix with the re-arm module behind it.
        permit, deny = system_module('pam_permit.so'), system_module('pam_deny.so')
        (self.conf / name).write_text(
            f'auth sufficient {FAKE} finger\n'
            f'auth [success=ok new_authtok_reqd=ok default=2] {FAKE} password\n'
            f'{module_line}\n'
            f'auth sufficient {permit}\n'
            f'auth required {deny}\n')

    def authenticate(self, name, password, finger='nomatch'):
        env = dict(os.environ, AURORA_TEST_PASSWORD='right', AURORA_TEST_FINGER=finger)
        out = subprocess.run([DRIVER, str(self.conf), name, USER, password], env=env,
                             capture_output=True, text=True, check=True, timeout=30)
        return int(out.stdout)

    def direct(self, user, password, raw=None):
        c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        c.connect(self.sock)
        c.sendall(raw if raw is not None else MAGIC + user.encode() + b'\0' + password.encode() + b'\0')
        c.shutdown(socket.SHUT_WR)
        reply = c.recv(256).decode()
        c.close()
        return reply.strip()


class RearmTest(unittest.TestCase):
    def setUp(self):
        os.environ['AURORA_TEST_PASSWORD'] = 'right'
        self.tmpdir = tempfile.TemporaryDirectory()
        self.rig = Rig(self.tmpdir.name)
        self.rig.stack('client', f'-auth optional {MODULE} socket={self.rig.sock}')

    def tearDown(self):
        self.rig.server.close()
        self.tmpdir.cleanup()

    def test_password_rearms_a_lockout(self):
        self.rig.lock('locked')
        self.assertEqual(self.rig.authenticate('client', 'right'), PAM_SUCCESS)
        self.assertEqual(self.rig.state(), 'rearmed')

    def test_wrong_password_never_reaches_the_service(self):
        self.rig.lock('locked')
        self.assertEqual(self.rig.authenticate('client', 'wrong'), PAM_AUTH_ERR)
        self.assertEqual(self.rig.connections, 0)
        self.assertEqual(self.rig.state(), 'locked')

    def test_fingerprint_success_does_not_rearm(self):
        self.rig.lock('locked')
        self.assertEqual(self.rig.authenticate('client', 'right', finger='match'), PAM_SUCCESS)
        self.assertEqual(self.rig.connections, 0)
        self.assertEqual(self.rig.state(), 'locked')

    def test_not_locked_checks_nothing(self):
        self.rig.lock('unlocked')
        self.assertEqual(self.rig.direct(USER, 'wrong'), 'ok not-locked')
        self.assertEqual(self.rig.authenticate('client', 'right'), PAM_SUCCESS)
        self.assertEqual(self.rig.state(), 'unlocked')

    def test_service_rechecks_the_password(self):
        self.rig.lock('locked')
        self.assertEqual(self.rig.direct(USER, 'wrong'), 'refused password')
        self.assertEqual(self.rig.state(), 'locked')

    def test_service_refuses_another_users_account(self):
        if os.getuid() == 0:
            self.skipTest('needs a non-root caller')
        self.rig.lock('locked')
        self.assertEqual(self.rig.direct('root', 'right'), 'refused not the caller\'s account')
        self.assertEqual(self.rig.state(), 'locked')

    def test_service_refuses_a_user_without_prints(self):
        self.rig.lock('locked')
        (self.rig.fprint / USER / 'apple-sep').rmdir()
        self.assertEqual(self.rig.direct(USER, 'right'), 'refused no enrolled fingerprints')
        self.assertEqual(self.rig.state(), 'locked')

    def test_service_refuses_malformed_requests(self):
        self.rig.lock('locked')
        for raw in (b'', b'HELLO', MAGIC + USER.encode(), MAGIC + b'x' * 2000):
            self.assertTrue(self.rig.direct(USER, '', raw=raw).startswith('refused'), raw[:20])
        self.assertEqual(self.rig.state(), 'locked')

    def test_missing_module_keeps_the_stack(self):
        self.rig.stack('nomodule', '-auth optional /nonexistent/pam_aurora_touchid.so')
        self.assertEqual(self.rig.authenticate('nomodule', 'right'), PAM_SUCCESS)
        self.assertEqual(self.rig.authenticate('nomodule', 'wrong'), PAM_AUTH_ERR)

    def test_service_down_keeps_the_stack(self):
        self.rig.stack('down', f'-auth optional {MODULE} socket={self.rig.tmp}/absent.sock')
        self.rig.lock('locked')
        self.assertEqual(self.rig.authenticate('down', 'right'), PAM_SUCCESS)
        self.assertEqual(self.rig.state(), 'locked')


if __name__ == '__main__':
    for f in (MODULE, HELPER, FAKE, DRIVER):
        if not f.exists():
            sys.exit(f'{f} is not built; run make check')
    unittest.main(verbosity=2)
