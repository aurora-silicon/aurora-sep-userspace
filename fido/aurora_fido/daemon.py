# SPDX-License-Identifier: MIT
"""aurora-fidod: this Mac's Secure Enclave and Touch ID as a FIDO2/U2F security key.

Runs as root (systemd unit aurora-fido.service, off until `aurora-fido
enable`). Needs the SEP trusted-key source (aurora-fido-seal, for the
daemon's own master secret), fprintd (Touch ID) and /dev/uhid; keys live in
the Secure Enclave through /dev/sep-key, or, on kernels without it, are
sealed under the master secret (see backend.py). When the sealed master
secret, fprintd or uhid is missing it exits instead of degrading.
"""

import argparse
import configparser
import json
import logging
import os
import signal
import subprocess
import sys
import threading

from . import __version__, creds, ctap2, ctaphid, touchid, u2f
from .backend import BackendError, open_store

log = logging.getLogger("aurora-fido")

STATE_DIR = "/var/lib/aurora-fido"
RUN_DIR = "/run/aurora-fido"
CONFIG = "/etc/aurora-fido/aurora-fido.conf"
SEAL_HELPER = "/usr/libexec/aurora-fido/aurora-fido-seal"

DEFAULTS = {
    "touchid": {"user": "auto", "timeout": "30", "max_tries": "3", "notify": "yes"},
    "authenticator": {"attestation": "self", "max_resident": "256", "u2f": "yes"},
    "keys": {"store": "auto"},
}

DEVICE_NAME = "Aurora Touch ID Security Key"


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
        if hasattr(backend, "rekey"):
            backend.rekey(master)
        v = creds.Vault(state_dir, master)
        return v, creds.ResidentStore(v, state_dir, max_rk)

    vault, store = fresh(secret.load())
    auth = ctap2.Authenticator(
        backend, verifier, vault, store, creds.Counter(state_dir),
        attestation=cfg.get("authenticator", "attestation"),
        new_vault=lambda: fresh(secret.new()))
    u = u2f.U2F(auth) if cfg.getboolean("authenticator", "u2f") else None
    return auth, u


def write_status(run_dir, info):
    """World-readable facts for `aurora-fido status` (no secrets)."""
    if not run_dir:
        return
    try:
        os.makedirs(run_dir, mode=0o755, exist_ok=True)
        path = os.path.join(run_dir, "status.json")
        creds.atomic_write(path, json.dumps(info, indent=1).encode() + b"\n", 0o644)
        os.chmod(path, 0o644)
    except OSError as e:
        log.warning("cannot write %s: %s", run_dir, e)


def key_store_info(backend, why=None):
    if backend.name == "sep-key":
        return {"keys": "sep-key",
                "keys_detail": "P-256 keys inside the Secure Enclave (/dev/sep-key); "
                               "the private keys never leave it"}
    return {"keys": "sealed",
            "keys_detail": "P-256 keys wrapped by the SEP-sealed master secret; useless "
                           "off this Mac, but root on this Mac can copy them"
                           + (f" ({why})" if why else "")}


def serve(auth, u, device_factory, run_dir=None, info=None):
    dev = device_factory()
    hid = ctaphid.CtapHid(dev, auth, u)
    stop = threading.Event()
    for s in (signal.SIGTERM, signal.SIGINT):
        signal.signal(s, lambda *_: stop.set())
    log.info("security key ready (keys: %s)", auth.backend.name)
    write_status(run_dir, dict(info or {}, pid=os.getpid(), ready=True))
    try:
        hid.run(stop)
    finally:
        if u:
            u.presence.stop()
        dev.close()
        if run_dir:
            try:
                os.unlink(os.path.join(run_dir, "status.json"))
            except OSError:
                pass
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
    ap.add_argument("--seal-helper", default=SEAL_HELPER)
    ap.add_argument("--run-dir", default=RUN_DIR)
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(message)s")
    if os.geteuid() != 0:
        log.error("aurora-fidod runs as root (uhid, sep-key, the sealed secret)")
        return 1
    cfg = load_config(a.config)
    try:
        backend, why = open_store(cfg.get("keys", "store"))
    except BackendError as e:
        log.error("no key store: %s", e)
        return 1
    if backend.name != "sep-key":
        log.warning("keys are sealed by the Secure Enclave, not kept in it (%s); "
                    "see /usr/share/doc/aurora-fido/fido.md", why)
    try:
        verifier = fprintd_verifier(cfg)
    except ImportError as e:
        log.error("Touch ID needs python3-gobject: %s", e)
        return 1
    os.umask(0o077)
    try:
        auth, u = build(cfg, a.state_dir, backend, verifier,
                        SealedSecret(a.state_dir, a.seal_helper))
    except (RuntimeError, OSError, subprocess.SubprocessError) as e:
        log.error("cannot open the sealed master secret: %s", e)
        return 1
    from .uhid import UhidDevice
    info = dict(key_store_info(backend, why), version=__version__,
                touchid_user=cfg.get("touchid", "user"), u2f=u is not None)
    serve(auth, u, lambda: UhidDevice(name=DEVICE_NAME), a.run_dir, info)
    return 0


if __name__ == "__main__":
    sys.exit(main())
