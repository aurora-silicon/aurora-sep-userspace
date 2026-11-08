# SPDX-License-Identifier: MIT
"""aurora-fidod: this Mac's Secure Enclave and Touch ID as a FIDO2/U2F security key.

Runs as root (systemd unit aurora-fido.service). Needs /dev/sep-key (keys in
the Secure Enclave), the SEP trusted-key source (aurora-fido-seal, for the
daemon's own master secret), fprintd (Touch ID) and /dev/uhid. When any of
them is missing it exits instead of degrading.
"""

import argparse
import configparser
import logging
import os
import signal
import subprocess
import sys
import threading

from . import creds, ctap2, ctaphid, touchid, u2f
from .backend import BackendError, SepKeyBackend

log = logging.getLogger("aurora-fido")

STATE_DIR = "/var/lib/aurora-fido"
CONFIG = "/etc/aurora-fido/aurora-fido.conf"
SEAL_HELPER = "/usr/libexec/aurora-fido/aurora-fido-seal"

DEFAULTS = {
    "touchid": {"user": "auto", "timeout": "30", "max_tries": "3", "notify": "yes"},
    "authenticator": {"attestation": "self", "max_resident": "256", "u2f": "yes"},
}


class SealedSecret:
    """The 64-byte master secret, sealed by this Mac's Secure Enclave."""

    def __init__(self, state_dir, helper=SEAL_HELPER):
        self.path = os.path.join(state_dir, "master.sep")
        self.helper = helper

    def _run(self, args, stdin=None):
        r = subprocess.run([self.helper] + args, input=stdin, capture_output=True,
                           timeout=90)
        if r.returncode != 0:
            raise RuntimeError(f"{os.path.basename(self.helper)} {args[0]}: "
                               f"{r.stderr.decode(errors='replace').strip()}")
        return r.stdout

    def new(self):
        rec = self._run(["new"])
        creds.atomic_write(self.path, rec)
        return self.load()

    def load(self):
        if not os.path.exists(self.path):
            return self.new()
        with open(self.path, "rb") as f:
            rec = f.read()
        out = self._run(["unseal"], rec).strip()
        secret = bytes.fromhex(out.decode())
        if len(secret) != 64:
            raise RuntimeError("unsealed secret has the wrong length")
        return secret


def load_config(path):
    cp = configparser.ConfigParser()
    cp.read_dict(DEFAULTS)
    if path and os.path.exists(path):
        cp.read(path)
    return cp


def build(cfg, state_dir, backend, verifier, secret):
    """Wire the authenticator; secret has load() and new()."""
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    max_rk = cfg.getint("authenticator", "max_resident")

    def fresh(master):
        v = creds.Vault(state_dir, master)
        return v, creds.ResidentStore(v, state_dir, max_rk)

    vault, store = fresh(secret.load())
    auth = ctap2.Authenticator(
        backend, verifier, vault, store, creds.Counter(state_dir),
        attestation=cfg.get("authenticator", "attestation"),
        new_vault=lambda: fresh(secret.new()))
    u = u2f.U2F(auth) if cfg.getboolean("authenticator", "u2f") else None
    return auth, u


def serve(auth, u, device_factory):
    dev = device_factory()
    hid = ctaphid.CtapHid(dev, auth, u)
    stop = threading.Event()
    for s in (signal.SIGTERM, signal.SIGINT):
        signal.signal(s, lambda *_: stop.set())
    log.info("security key ready (backend %s)", auth.backend.name)
    try:
        hid.run(stop)
    finally:
        if u:
            u.presence.stop()
        dev.close()
        log.info("security key removed")


def fprintd_verifier(cfg):
    return touchid.FprintdVerifier(
        user=cfg.get("touchid", "user"),
        timeout=cfg.getfloat("touchid", "timeout"),
        max_tries=cfg.getint("touchid", "max_tries"),
        notifier=touchid.Notifier(cfg.getboolean("touchid", "notify")))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="aurora-fidod")
    ap.add_argument("--config", default=CONFIG)
    ap.add_argument("--state-dir", default=STATE_DIR)
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(message)s")
    if os.geteuid() != 0:
        log.error("aurora-fidod runs as root (uhid, sep-key, the sealed secret)")
        return 1
    cfg = load_config(a.config)
    try:
        backend = SepKeyBackend()
    except BackendError as e:
        log.error("no Secure Enclave key backend: %s", e)
        return 1
    try:
        verifier = fprintd_verifier(cfg)
    except ImportError as e:
        log.error("Touch ID needs python3-gobject: %s", e)
        return 1
    os.umask(0o077)
    try:
        auth, u = build(cfg, a.state_dir, backend, verifier, SealedSecret(a.state_dir))
    except (RuntimeError, OSError, subprocess.SubprocessError) as e:
        log.error("cannot open the sealed master secret: %s", e)
        return 1
    from .uhid import UhidDevice
    serve(auth, u, UhidDevice)
    return 0


if __name__ == "__main__":
    sys.exit(main())
