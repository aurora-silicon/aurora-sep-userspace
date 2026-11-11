# SPDX-License-Identifier: MIT
"""What the user is asked to approve, whose finger it is, and the notification.

The approval itself is not decided here or anywhere else in the daemon: the
Secure Enclave checks the Touch ID match inside each signature (enclave.py,
backend.py). This module only names the request, finds the person at the
keyboard (the active local session on seat0, who is the only one who can
reach the sensor) and shows a desktop notification while the enclave waits.
"""

import html
import logging
import os
import pwd
import subprocess

log = logging.getLogger("aurora-fido")

MATCH = "match"
NO_MATCH = "no-match"
TIMEOUT = "timeout"
CANCELLED = "cancelled"
LOCKED = "locked"
UNAVAILABLE = "unavailable"


class Prompt:
    """What the user is asked to approve."""

    def __init__(self, action, rp, detail=""):
        self.action = action      # "register", "sign-in", "reset", ...
        self.rp = rp              # relying party ID as the client sent it
        self.detail = detail

    def title(self):
        return {
            "register": "Touch ID to register with {rp}",
            "sign-in": "Touch ID to sign in to {rp}",
            "manage": "Touch ID to manage security key credentials",
            "reset": "Touch ID to RESET the security key (deletes all passkeys)",
            "select": "Touch ID to use this security key",
        }.get(self.action, "Touch ID for {rp}").format(rp=display_rp(self.rp))


def display_rp(rp):
    if not rp:
        return "a website"
    if rp.startswith("ssh:"):
        return f"SSH ({rp})" if rp != "ssh:" else "SSH"
    if rp.startswith("pam://"):
        return f"login ({rp[6:]})"
    return rp[:80]


def resolve_user(user="auto"):
    """(name, uid) whose session gets the notification: the config's user, or seat0's."""
    if user and user != "auto":
        try:
            return user, pwd.getpwnam(user).pw_uid
        except KeyError:
            return None
    return seat_user()


def seat_user():
    """(name, uid) of the active local session on seat0, or None."""
    s = seat_session()
    return s[1:] if s else None


def seat_session():
    """(session id, name, uid) of the active local session on seat0, or None."""
    try:
        sid = subprocess.run(
            ["loginctl", "show-seat", "seat0", "-p", "ActiveSession", "--value"],
            capture_output=True, text=True, timeout=5).stdout.strip()
        if not sid:
            return None
        props = subprocess.run(
            ["loginctl", "show-session", sid, "-p", "Name", "-p", "User",
             "-p", "Remote", "-p", "Active", "-p", "Class"],
            capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    p = dict(line.split("=", 1) for line in props.splitlines() if "=" in line)
    if p.get("Remote") != "no" or p.get("Active") != "yes" or p.get("Class") != "user":
        return None
    try:
        return sid, p["Name"], int(p["User"])
    except (KeyError, ValueError):
        return None


class Notifier:
    """Best-effort desktop notification in the user's session."""

    def __init__(self, enabled=True):
        self.enabled = enabled

    def _env(self, uid):
        run = f"/run/user/{uid}"
        return {"PATH": "/usr/bin:/bin", "XDG_RUNTIME_DIR": run,
                "DBUS_SESSION_BUS_ADDRESS": f"unix:path={run}/bus"}

    def _as_user(self, uid, argv):
        pw = pwd.getpwuid(uid)
        cmd = ["setpriv", f"--reuid={uid}", f"--regid={pw.pw_gid}",
               "--init-groups", "--"] + argv
        if os.geteuid() != 0:
            cmd = argv
        return subprocess.run(cmd, env=self._env(uid), capture_output=True,
                              text=True, timeout=5)

    def show(self, uid, title, body, timeout_s):
        if not self.enabled or uid is None:
            return None
        # The unit's capability bounding set has no CAP_DAC_*, so root cannot
        # look inside /run/user/<uid> (0700): only a clear "no such file" skips.
        try:
            os.stat(f"/run/user/{uid}/bus")
        except FileNotFoundError:
            log.info("no session bus for uid %d; no notification", uid)
            return None
        except OSError:
            pass
        try:
            r = self._as_user(uid, [
                "notify-send", "--print-id", "--app-name=Touch ID",
                "--icon=auth-fingerprint-symbolic", "--urgency=critical",
                f"--expire-time={int(timeout_s * 1000)}",
                "--hint=int:transient:1", title, html.escape(body)])
            nid = r.stdout.strip()
            if r.returncode != 0 or not nid.isdigit():
                log.warning("notification for uid %d failed: %s", uid, r.stderr.strip())
                return None
            log.info("notification %s shown to uid %d", nid, uid)
            return uid, int(nid)
        except (OSError, subprocess.SubprocessError, KeyError, ValueError) as e:
            log.warning("notification for uid %d failed: %s", uid, e)
            return None

    def close(self, handle):
        if not handle:
            return
        uid, nid = handle
        try:
            self._as_user(uid, [
                "gdbus", "call", "--session", "--dest", "org.freedesktop.Notifications",
                "--object-path", "/org/freedesktop/Notifications",
                "--method", "org.freedesktop.Notifications.CloseNotification", str(nid)])
        except (OSError, subprocess.SubprocessError, KeyError) as e:
            log.debug("closing notification failed: %s", e)
