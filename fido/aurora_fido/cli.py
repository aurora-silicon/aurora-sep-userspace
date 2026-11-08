# SPDX-License-Identifier: MIT
"""aurora-fido: turn the Touch ID security key on or off, and say what it is doing.

  aurora-fido status            (any user) is it on, which key store, which device
  aurora-fido enable            (root) check what it needs, then start it now and at boot
  aurora-fido disable           (root) stop it now and at boot; credentials are kept
  aurora-fido disable --forget  (root) also delete every credential it made

The feature is installed off. Nothing else turns it on.
"""

import argparse
import glob
import json
import os
import shutil
import subprocess
import sys
import time

from . import __version__, paths

UNIT = "aurora-fido.service"

POLICY_TEXT = {
    "touchid-or-password": "Touch ID, or your password when Touch ID does not match, "
                           "is locked or unavailable (the default, as on macOS)",
    "touchid-any": "Touch ID only, any enrolled finger",
    "touchid-current": "Touch ID only, and only the fingers enrolled when a credential "
                       "is made (adding or removing a finger retires it)",
}

THREAT = {
    "sep-key": "Keys live in the Secure Enclave and cannot be copied off this Mac. "
               "The touch is checked by aurora-fidod, so root on this Mac can sign "
               "without one.",
    "sealed": "This kernel has no /dev/sep-key, so keys are software keys wrapped by a "
              "secret only this Mac's Secure Enclave can unseal. A copied disk or backup "
              "is useless elsewhere, but root on this Mac can unwrap and copy the keys. "
              "New keys go into the Secure Enclave once the kernel has /dev/sep-key.",
}


def _systemctl(*args):
    try:
        r = subprocess.run(["systemctl", *args, UNIT], capture_output=True, text=True,
                           timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        return 1, str(e)
    return r.returncode, (r.stdout.strip() or r.stderr.strip())


def _is_nixos():
    return os.path.exists("/etc/NIXOS")


def find_device(sys_root="/sys"):
    """/dev/hidrawN of the security key, or None."""
    for h in sorted(glob.glob(os.path.join(sys_root, "class/hidraw/hidraw*"))):
        try:
            with open(os.path.join(h, "device/uevent")) as f:
                if "HID_PHYS=aurora-fido\n" in f.read():
                    return "/dev/" + os.path.basename(h)
        except OSError:
            continue
    return None


def read_status(path=None):
    path = path or os.path.join(paths.RUN_DIR, "status.json")
    try:
        with open(path) as f:
            st = json.load(f)
        return st if isinstance(st, dict) else None
    except (OSError, ValueError):
        return None


def expected_keys(sep_key="/dev/sep-key"):
    return "sep-key" if os.path.exists(sep_key) else "sealed"


def configured_policy(path=None):
    import configparser
    cp = configparser.ConfigParser()
    try:
        cp.read(path or paths.CONFIG)
    except configparser.Error:
        pass
    return cp.get("touchid", "policy", fallback="touchid-or-password")


def gather():
    _, enabled = _systemctl("is-enabled")
    _, active = _systemctl("is-active")
    st = read_status() if active == "active" else None
    keys = (st or {}).get("keys")
    return {
        "enabled": enabled or "unknown",
        "active": active or "unknown",
        "device": find_device() if active == "active" else None,
        "keys": keys,
        "keys_if_enabled": keys or expected_keys(),
        "ready": bool(st and st.get("ready")),
        "policy": (st or {}).get("policy") or configured_policy(),
        "policy_detail": (st or {}).get("policy_detail"),
        "version": __version__,
    }


def render(s):
    on = s["active"] == "active"
    lines = [f"Touch ID security key: {'ON' if on else 'off'} "
             f"(service {s['active']}, {s['enabled']} at boot)"]
    if on:
        lines.append(f"  device:    {s['device'] or 'not seen yet'}")
        lines.append(f"  key store: {s['keys'] or 'unknown'}")
    else:
        lines.append(f"  key store when enabled: {s['keys_if_enabled']}")
    pol = s.get("policy") or "touchid-or-password"
    lines.append(f"  approval:  {pol}: " + (s.get("policy_detail")
                                         or POLICY_TEXT.get(pol, "unknown policy")))
    lines.append("             (new credentials; set [touchid] policy in " + paths.CONFIG + ")")
    lines.append("  " + THREAT.get(s["keys_if_enabled"], ""))
    if not on:
        lines.append("  Turn it on with: " + ("aurora.fido.enable = true; (NixOS)"
                                              if _is_nixos() else "sudo aurora-fido enable"))
    lines.append(f"  More: {paths.DOC}")
    return "\n".join(lines)


def preflight(seal_helper):
    """Problems that would stop the daemon, as a list of strings."""
    bad = []
    try:
        import gi  # noqa: F401
        gi.require_version("Gio", "2.0")
    except (ImportError, ValueError):
        bad.append("python3-gobject (gi) is missing")
    try:
        import cryptography  # noqa: F401
    except ImportError:
        bad.append("python3-cryptography is missing")
    if not (shutil.which("fprintd-list") or os.path.exists(
            "/usr/share/dbus-1/system-services/net.reactivated.Fprint.service")):
        bad.append("fprintd is not installed (Touch ID)")
    subprocess.run(["modprobe", "uhid"], capture_output=True, timeout=30)
    if not os.path.exists("/dev/uhid"):
        bad.append("/dev/uhid is missing (uhid module)")
    try:
        r = subprocess.run([seal_helper, "check"], capture_output=True, text=True,
                           timeout=90)
        if r.returncode != 0:
            bad.append("the Secure Enclave cannot seal the master secret: "
                       + (r.stderr.strip() or f"{seal_helper} check failed"))
    except (OSError, subprocess.SubprocessError) as e:
        bad.append(f"{seal_helper}: {e}")
    return bad


def wait_ready(timeout=20.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        st = read_status()
        if st and st.get("ready") and find_device():
            return True
        _, active = _systemctl("is-active")
        if active not in ("active", "activating"):
            return False
        time.sleep(0.2)
    return False


def cmd_enable(a):
    if _is_nixos():
        print("On NixOS set aurora.fido.enable = true; and rebuild.")
        return 1
    bad = preflight(a.seal_helper)
    if bad:
        for b in bad:
            print(f"aurora-fido: {b}", file=sys.stderr)
        print("aurora-fido: not enabled", file=sys.stderr)
        return 1
    rc, out = _systemctl("enable", "--now")
    if rc != 0:
        print(f"aurora-fido: systemctl enable --now {UNIT}: {out}", file=sys.stderr)
        return 1
    if not wait_ready():
        print(f"aurora-fido: {UNIT} did not come up; see journalctl -u {UNIT}",
              file=sys.stderr)
        return 1
    print(render(gather()))
    return 0


def cmd_disable(a):
    if _is_nixos():
        print("On NixOS set aurora.fido.enable = false; and rebuild.")
        return 1
    rc, out = _systemctl("disable", "--now")
    if rc != 0:
        print(f"aurora-fido: systemctl disable --now {UNIT}: {out}", file=sys.stderr)
        return 1
    if a.forget:
        shutil.rmtree(a.state_dir, ignore_errors=True)
        if os.path.exists(a.state_dir):
            print(f"aurora-fido: off, but {a.state_dir} could not be deleted", file=sys.stderr)
            return 1
        print(f"Touch ID security key off; every credential it made is deleted "
              f"({a.state_dir}). Sites and SSH keys registered with it no longer work.")
    else:
        print(f"Touch ID security key off. Its credentials are kept in {a.state_dir} "
              "and work again after `aurora-fido enable`.")
    return 0


def cmd_status(a):
    s = gather()
    print(json.dumps(s, indent=1) if a.json else render(s))
    return 0 if s["active"] == "active" else 3


def main(argv=None):
    ap = argparse.ArgumentParser(prog="aurora-fido", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("status", help="is it on, which key store")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_status, root=False)
    p = sub.add_parser("enable", help="turn it on, now and at boot")
    p.set_defaults(fn=cmd_enable, root=True)
    p = sub.add_parser("disable", help="turn it off, now and at boot")
    p.add_argument("--forget", action="store_true",
                   help="also delete every credential it made")
    p.set_defaults(fn=cmd_disable, root=True)
    ap.add_argument("--state-dir", default=paths.STATE_DIR, help=argparse.SUPPRESS)
    ap.add_argument("--seal-helper", default=paths.SEAL_HELPER, help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    if a.root and os.geteuid() != 0:
        print(f"aurora-fido {a.cmd}: run as root (sudo aurora-fido {a.cmd})", file=sys.stderr)
        return 1
    return a.fn(a)
