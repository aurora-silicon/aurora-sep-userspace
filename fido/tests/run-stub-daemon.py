#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""TEST ONLY: the real uhid device and CTAPHID/CTAP2 stack with software keys.

Keys come from tests/stub.py (in this process's memory, not the Secure
Enclave). For CI and for hardware runs before /dev/sep-key exists. Never
install or ship this.

  --touch match|no-match|timeout|locked   scripted Touch ID answer
  --touch fprintd                         real Touch ID through fprintd
  --secret file                           master secret in STATE/master (plain file)
  --secret sep --seal-helper PATH         master secret sealed by this Mac's SEP
"""

import argparse
import logging
import os
import sys

here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(here, ".."))
sys.path.insert(0, here)

from aurora_fido import daemon, touchid  # noqa: E402
from aurora_fido.uhid import UhidDevice  # noqa: E402
from stub import FileSecret, StubKeyBackend, StubVerifier  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state-dir", required=True)
    ap.add_argument("--touch", default="match")
    ap.add_argument("--secret", choices=("file", "sep"), default="file")
    ap.add_argument("--seal-helper", default=daemon.SEAL_HELPER)
    ap.add_argument("--config", default=None)
    ap.add_argument("--name", default="Aurora Touch ID Security Key (TEST, software keys)")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(message)s")
    log = logging.getLogger("aurora-fido")
    log.warning("TEST HARNESS: software keys from tests/stub.py, not the Secure Enclave")

    cfg = daemon.load_config(a.config)
    os.umask(0o077)
    os.makedirs(a.state_dir, mode=0o700, exist_ok=True)
    if a.touch == "fprintd":
        verifier = daemon.fprintd_verifier(cfg)
    else:
        if a.touch not in (touchid.MATCH, touchid.NO_MATCH, touchid.TIMEOUT,
                           touchid.LOCKED, touchid.UNAVAILABLE):
            ap.error("--touch: match, no-match, timeout, locked, unavailable or fprintd")
        verifier = StubVerifier(a.touch)
    if a.secret == "sep":
        secret = daemon.SealedSecret(a.state_dir, a.seal_helper)
    else:
        secret = FileSecret(os.path.join(a.state_dir, "master"))
    # The stub's own key is kept next to the state so test credentials survive a restart.
    kpath = os.path.join(a.state_dir, "stub-backend.key")
    if not os.path.exists(kpath):
        with open(kpath, "wb") as f:
            f.write(os.urandom(32))
    with open(kpath, "rb") as f:
        backend = StubKeyBackend(key=f.read())
    auth, u = daemon.build(cfg, a.state_dir, backend, verifier, secret)
    daemon.serve(auth, u, lambda: UhidDevice(name=a.name, phys="aurora-fido-test"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
