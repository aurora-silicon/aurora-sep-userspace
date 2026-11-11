#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""TEST ONLY: the real uhid device and CTAPHID/CTAP2 stack with test stand-ins.

By default keys come from tests/stub.py (in this process's memory, not the
Secure Enclave) with a scripted enclave touch, for CI and for hardware runs
before /dev/sep-key is in the running kernel. Never install or ship this.

  --keys stub                       software keys (default)
  --keys sep                        the real /dev/sep-key: the Secure Enclave
                                    checks a real finger inside every signature

  --touch match|no-match|timeout    scripted enclave touch for --keys stub
  --secret file                     master secret in STATE/master (plain file)
  --secret sep --seal-helper PATH   master secret sealed by this Mac's SEP
"""

import argparse
import logging
import os
import sys

here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(here, ".."))
sys.path.insert(0, here)

from aurora_fido import daemon, paths  # noqa: E402
from aurora_fido.backend import open_backend  # noqa: E402
from aurora_fido.uhid import UhidDevice  # noqa: E402
import stub  # noqa: E402
from stub import FileSecret, StubKeyBackend  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state-dir", required=True)
    ap.add_argument("--touch", default="match", choices=(stub.MATCH, stub.NO_MATCH, stub.TIMEOUT))
    ap.add_argument("--keys", choices=("stub", "sep"), default="stub")
    ap.add_argument("--secret", choices=("file", "sep"), default="file")
    ap.add_argument("--seal-helper", default=paths.SEAL_HELPER)
    ap.add_argument("--config", default=None)
    ap.add_argument("--name", default=None)
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(message)s")
    log = logging.getLogger("aurora-fido")
    if a.keys == "sep":
        log.warning("TEST HARNESS: keys in the Secure Enclave (/dev/sep-key), real Touch ID")
    else:
        log.warning("TEST HARNESS: software keys from tests/stub.py, not the Secure Enclave "
                    "(scripted touch: %s)", a.touch)
    name = a.name or ("Aurora Touch ID Security Key (TEST, %s keys)" % a.keys)

    cfg = daemon.load_config(a.config)
    os.umask(0o077)
    os.makedirs(a.state_dir, mode=0o700, exist_ok=True)
    if a.secret == "sep":
        secret = daemon.SealedSecret(a.state_dir, a.seal_helper)
    else:
        secret = FileSecret(os.path.join(a.state_dir, "master"))
    if a.keys == "sep":
        backend = open_backend("sep-key")
    else:
        # The stub's own key is kept next to the state so test credentials survive a restart.
        kpath = os.path.join(a.state_dir, "stub-backend.key")
        if not os.path.exists(kpath):
            with open(kpath, "wb") as f:
                f.write(os.urandom(32))
        with open(kpath, "rb") as f:
            backend = StubKeyBackend(key=f.read(), mode=a.touch)
    policy, note = daemon.resolve_policy(cfg, backend.flags_supported)
    if note:
        log.info("%s", note)
    user = daemon.enclave_user(cfg, backend, a.state_dir, policy)
    auth, u = daemon.build(cfg, a.state_dir, backend, user, secret, policy,
                           daemon.LegacyLog(a.state_dir))
    daemon.serve(auth, u, lambda: UhidDevice(name=name, phys="aurora-fido-test"),
                 info=daemon.key_store_info(backend))
    return 0


if __name__ == "__main__":
    sys.exit(main())
