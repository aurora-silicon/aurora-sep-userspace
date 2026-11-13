# SPDX-License-Identifier: MIT
"""aurora-fidod: this Mac's Secure Enclave and Touch ID as a FIDO2/U2F security key.

Runs as root (systemd unit aurora-fido.service, off until `aurora-fido
enable`). Needs /dev/sep-key with enclave-checked Touch ID keys (linux#1196
or newer), the SEP trusted-key source (aurora-fido-seal, for the daemon's
own master secret, which wraps credential IDs) and /dev/uhid. Every approval
is a Touch ID match the Secure Enclave checks inside a signature
(enclave.py); there is no software fallback. When any of that is missing it
exits instead of degrading.
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
import time

from . import __version__, creds, ctap2, ctaphid, enclave, paths, touchid, u2f
from .backend import BackendError, open_backend

log = logging.getLogger("aurora-fido")

STATE_DIR = paths.STATE_DIR
RUN_DIR = paths.RUN_DIR
CONFIG = paths.CONFIG

DEFAULTS = {
    "touchid": {"user": "auto", "timeout": "30", "max_tries": "3", "notify": "yes",
                "policy": "auto"},
    "authenticator": {"attestation": "self", "max_resident": "256", "u2f": "yes",
                      # system: credentials in STATE_DIR (0.2). user: each request goes to
                      # the passkey agent (aurora-passkeyd) of seat0's active user.
                      "vault": "system"},
    "keys": {"store": "auto"},
}
# Settings of aurora-fido 0.1 that no longer mean anything: the enclave
# always enforces the policy, and the password is never checked outside it.
OBSOLETE = {("keys", "enclave_policy"), ("touchid", "password_timeout")}

DEVICE_NAME = "Aurora Touch ID Security Key"


class SealedSecret:
    """The 64-byte master secret, sealed by this Mac's Secure Enclave."""

    def __init__(self, state_dir, helper=None):
        self.path = os.path.join(state_dir, "master.sep")
        self.helper = helper or paths.SEAL_HELPER

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


class PolicyError(ValueError):
    pass


def resolve_policy(cfg, flags_supported):
    """(policy, note): the credential policy the enclave can enforce here.

    "auto" (the default) is touchid-or-password, macOS's default, when the
    kernel can have the enclave check the user's password, else touchid-any.
    A policy named in the config that the enclave cannot enforce is an error,
    never a weaker policy.
    """
    name = cfg.get("touchid", "policy")
    if name == "auto":
        if flags_supported & creds.POLICY_FLAGS[creds.POLICY_TOUCHID_OR_PASSWORD]:
            return creds.POLICY_TOUCHID_OR_PASSWORD, None
        return creds.POLICY_TOUCHID_ANY, (
            "Touch ID only: this kernel's Secure Enclave interface cannot check your "
            "password, so there is no password fallback (touchid-or-password needs it)")
    if name not in creds.POLICIES:
        raise PolicyError(f"[touchid] policy = {name!r}; use auto, " + ", ".join(creds.POLICIES))
    pol = creds.POLICIES[name]
    if creds.POLICY_FLAGS[pol] & ~flags_supported:
        if pol == creds.POLICY_TOUCHID_OR_PASSWORD:
            raise PolicyError(
                "[touchid] policy = touchid-or-password needs the Secure Enclave to check "
                "your password itself (per-user key bags, SEP_KEY_CREATE_USER_PRESENCE), "
                "which this kernel does not offer. A password checked anywhere else would "
                "let root approve without you. Use policy = auto or touchid-any")
        raise PolicyError(f"[touchid] policy = {name}: this kernel's /dev/sep-key cannot "
                          "make such keys")
    return pol, None


class LegacyLog:
    """Credentials of aurora-fido 0.1 that were presented and refused (root-only file)."""

    def __init__(self, state_dir, on_change=lambda n: None):
        self.path = os.path.join(state_dir, "legacy-refused.json")
        self.on_change = on_change
        try:
            with open(self.path) as f:
                self.seen = json.load(f)
            if not isinstance(self.seen, dict):
                self.seen = {}
        except (OSError, ValueError):
            self.seen = {}

    def __call__(self, rp_id, why):
        e = self.seen.setdefault(str(rp_id)[:256], {"count": 0})
        e["count"] += 1
        e["why"] = why
        e["last"] = int(time.time())
        try:
            creds.atomic_write(self.path, json.dumps(self.seen, indent=1).encode())
        except OSError as err:
            log.warning("cannot write %s: %s", self.path, err)
        self.on_change(len(self.seen))


def legacy_resident(vault, store, backend):
    """How many stored discoverable credentials are legacy (refused)."""
    n = 0
    for rec in store.all():
        c = vault.unwrap(rec["rpIdHash"], rec["credId"])
        if c is None or c.legacy is not None or not backend.gated(c.handle):
            n += 1
    return n


def build(cfg, state_dir, backend, user, secret, policy, on_legacy=lambda rp, why: None):
    """Wire the authenticator; secret has load() and new()."""
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    max_rk = cfg.getint("authenticator", "max_resident")

    def fresh(master):
        v = creds.Vault(state_dir, master)
        return v, creds.ResidentStore(v, state_dir, max_rk)

    vault, store = fresh(secret.load())
    auth = ctap2.Authenticator(
        backend, user, vault, store, creds.Counter(state_dir),
        attestation=cfg.get("authenticator", "attestation"),
        new_vault=lambda: fresh(secret.new()), policy=policy, on_legacy=on_legacy)
    u = u2f.U2F(auth) if cfg.getboolean("authenticator", "u2f") else None
    return auth, u


def enclave_user(cfg, backend, state_dir, policy):
    return enclave.EnclaveUser(
        backend, state_dir, creds.POLICY_FLAGS[policy],
        notifier=touchid.Notifier(cfg.getboolean("touchid", "notify")),
        user=cfg.get("touchid", "user"), max_tries=cfg.getint("touchid", "max_tries"),
        timeout=cfg.getfloat("touchid", "timeout"))


def write_status(run_dir, info):
    """World-readable facts for `aurora-fido status` (no secrets)."""
    if not run_dir:
        return
    try:
        os.makedirs(run_dir, mode=0o755, exist_ok=True)
        os.chmod(run_dir, 0o755)
        path = os.path.join(run_dir, "status.json")
        creds.atomic_write(path, json.dumps(info, indent=1).encode() + b"\n", 0o644)
        os.chmod(path, 0o644)
    except OSError as e:
        log.warning("cannot write %s: %s", run_dir, e)


def key_store_info(backend):
    return {"keys": "sep-key", "enforcement": "enclave",
            "keys_detail": "P-256 keys inside the Secure Enclave (/dev/sep-key); the "
                           "private keys never leave it, and the enclave signs only after "
                           "a Touch ID match it checks itself",
            "hmac_secret": bool(backend.can_unseal),
            "password_keys": bool(getattr(backend, "can_password", False)),
            "pin": ("available" if getattr(backend, "pin_reboot_proof", False)
                    else "not offered: the enclave's wrong-password count does not survive a restart yet")}


def serve(auth, u, device_factory, run_dir=None, info=None):
    dev = device_factory()
    hid = ctaphid.CtapHid(dev, auth, u)
    stop = threading.Event()
    for s in (signal.SIGTERM, signal.SIGINT):
        signal.signal(s, lambda *_: stop.set())
    log.info("security key ready (keys: %s, Touch ID checked by the Secure Enclave)",
             getattr(getattr(auth, "backend", None), "name", "per-user agents"))
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


def serve_per_user(run_dir):
    """The uhid device only; each user's aurora-passkeyd keeps and uses their credentials."""
    from .remote import RemoteAuthenticator
    from .uhid import UhidDevice
    status = {"version": __version__, "vault": "user", "keys": "sep-key",
              "enforcement": "enclave", "u2f": False,
              "keys_detail": "each user's passkey agent (aurora-passkeyd) keeps that user's "
                             "credentials; requests go to seat0's active user"}
    serve(RemoteAuthenticator(), None, lambda: UhidDevice(name=DEVICE_NAME), run_dir, status)
    return 0


POLICY_TEXT = {
    "touchid-or-password": "Touch ID, or your password checked by the Secure Enclave "
                           "when Touch ID does not match, is locked or unavailable",
    "touchid-any": "Touch ID only, any enrolled finger",
    "touchid-current": "Touch ID only, and only the fingers enrolled when a credential "
                       "is made (adding or removing a finger retires it)",
}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="aurora-fidod")
    ap.add_argument("--config", default=CONFIG)
    ap.add_argument("--state-dir", default=STATE_DIR)
    ap.add_argument("--seal-helper", default=paths.SEAL_HELPER)
    ap.add_argument("--run-dir", default=RUN_DIR)
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(message)s")
    if os.geteuid() != 0:
        log.error("aurora-fidod runs as root (uhid, sep-key, the sealed secret)")
        return 1
    cfg = load_config(a.config)
    for sec, key in sorted(OBSOLETE):
        if cfg.has_option(sec, key) and key not in DEFAULTS.get(sec, {}):
            log.warning("[%s] %s in %s has no effect any more: the Secure Enclave always "
                        "checks the touch", sec, key, a.config)
    if cfg.get("authenticator", "vault") == "user":
        return serve_per_user(a.run_dir)
    try:
        backend = open_backend(cfg.get("keys", "store"))
        policy, note = resolve_policy(cfg, backend.flags_supported)
    except (BackendError, ValueError) as e:
        log.error("%s", e)
        return 1
    if note:
        log.info("%s", note)
    os.umask(0o077)
    status = {}
    legacy = LegacyLog(a.state_dir, lambda n: write_status(
        a.run_dir, dict(status, legacy_refused_rps=n)))
    try:
        os.makedirs(a.state_dir, mode=0o700, exist_ok=True)
        user = enclave_user(cfg, backend, a.state_dir, policy)
        auth, u = build(cfg, a.state_dir, backend, user,
                        SealedSecret(a.state_dir, a.seal_helper), policy, legacy)
    except (RuntimeError, OSError, subprocess.SubprocessError) as e:
        log.error("cannot open the sealed master secret: %s", e)
        return 1
    from .uhid import UhidDevice
    pol = creds.POLICY_NAMES[policy]
    status.update(key_store_info(backend), version=__version__,
                  touchid_user=cfg.get("touchid", "user"), u2f=u is not None,
                  policy=pol, policy_detail=POLICY_TEXT[pol] + " (enforced by the Secure Enclave)",
                  policy_note=note, legacy_resident=legacy_resident(auth.vault, auth.store, backend),
                  legacy_refused_rps=len(legacy.seen))
    if status["legacy_resident"] or legacy.seen:
        log.warning("credentials made before the Secure Enclave checked Touch ID are refused "
                    "(%d stored passkeys, %d sites seen); register them again",
                    status["legacy_resident"], len(legacy.seen))
    serve(auth, u, lambda: UhidDevice(name=DEVICE_NAME), a.run_dir, status)
    return 0


if __name__ == "__main__":
    sys.exit(main())
