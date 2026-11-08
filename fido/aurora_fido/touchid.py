# SPDX-License-Identifier: MIT
"""User presence and user verification: a Touch ID match through fprintd.

One prompt is one fprintd claim, the way pam_fprintd does it: Claim(user),
then VerifyStart("any") up to max_tries times, VerifyStop and Release. The
apple_sep driver treats one open of /dev/sep-bio (one claim) as one prompt,
so this keeps the enclave's match operation and lockout bookkeeping the same
as for sudo or the login screen. No fixed sleeps between touches: the kernel
re-arms the sensor when the finger lifts. A Touch ID lockout ends the prompt
at once; it is never retried here, and nothing here enrols, deletes or
otherwise changes fingerprints.

Whose finger: the user of the active session on seat0 (the person at the
keyboard, who is the only one who can reach the sensor), unless the config
names a user.

Policy (as macOS key access control): a credential made under
"touchid-or-password" (the default) may also be approved with the user's
password when Touch ID does not match, is locked out or is unavailable. The
password is asked by the desktop's polkit agent in the user's own session
(action org.aurora.fido.authenticate, auth_self, never kept), so this daemon
never sees it. "touchid-any" and "touchid-current" credentials take Touch ID
only.
"""

import hashlib
import html
import logging
import os
import pwd
import subprocess
import threading
import time

log = logging.getLogger("aurora-fido")

MATCH = "match"
PASSWORD = "password"       # approved with the password (touchid-or-password only)
NO_MATCH = "no-match"
TIMEOUT = "timeout"
CANCELLED = "cancelled"
LOCKED = "locked"
UNAVAILABLE = "unavailable"


class Prompt:
    """What the user is asked to approve."""

    def __init__(self, action, rp, detail="", allow_password=False):
        self.action = action      # "register", "sign-in", "reset", ...
        self.rp = rp              # relying party ID as the client sent it
        self.detail = detail
        self.allow_password = allow_password

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


class Verifier:
    """Interface: verify(prompt, cancel, waiting) -> one of the results above.

    cancel is a threading.Event set when the client cancels. waiting() is
    called once the user is being asked (the transport then reports
    'user presence needed').
    """

    def verify(self, prompt, cancel, waiting=lambda: None):
        raise NotImplementedError


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


def enrolled_set_digest(user, root="/var/lib/fprint"):
    """SHA-256 over fprintd's stored prints for user (names and contents), or None.

    Any enrolment, deletion or re-enrolment changes it. A "touchid-current"
    credential keeps the digest of the set it was made with and stops
    working when it changes, as a macOS .biometryCurrentSet key does. (With
    the Secure Enclave policy the enclave enforces this instead.)
    """
    base = os.path.join(root, user)
    if not user or "/" in user or not os.path.isdir(base):
        return None
    h = hashlib.sha256(b"aurora-fido enrolled set v1\0")
    n = 0
    for d, dirs, files in os.walk(base):
        dirs.sort()
        for f in sorted(files):
            path = os.path.join(d, f)
            try:
                with open(path, "rb") as fh:
                    data = fh.read(1 << 20)
            except OSError:
                continue
            rel = os.path.relpath(path, base).encode()
            h.update(len(rel).to_bytes(4, "big") + rel + len(data).to_bytes(4, "big") + data)
            n += 1
    return h.digest() if n else None


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
        if not os.path.exists(f"/run/user/{uid}/bus"):
            return None
        try:
            r = self._as_user(uid, [
                "notify-send", "--print-id", "--app-name=Touch ID",
                "--icon=auth-fingerprint-symbolic", "--urgency=critical",
                f"--expire-time={int(timeout_s * 1000)}",
                "--hint=int:transient:1", title, html.escape(body)])
            nid = r.stdout.strip()
            if r.returncode != 0 or not nid.isdigit():
                log.debug("notify-send failed: %s", r.stderr.strip())
                return None
            log.debug("notification %s shown to uid %d", nid, uid)
            return uid, int(nid)
        except (OSError, subprocess.SubprocessError, KeyError, ValueError) as e:
            log.debug("notification failed: %s", e)
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


# fprintd VerifyStatus results that end one try, and those that keep waiting.
_RETRY = {"verify-retry-scan", "verify-swipe-too-short", "verify-finger-not-centered",
          "verify-remove-and-retry"}


class FprintdVerifier(Verifier):
    def __init__(self, user="auto", timeout=30.0, max_tries=3, notifier=None):
        self.user = user
        self.timeout = float(timeout)
        self.max_tries = max(1, int(max_tries))
        self.notifier = notifier or Notifier()
        self._lock = threading.Lock()
        from gi.repository import Gio, GLib  # noqa: F401 (fail at start, not per request)

    def _resolve_user(self):
        if self.user and self.user != "auto":
            try:
                return self.user, pwd.getpwnam(self.user).pw_uid
            except KeyError:
                return None
        return seat_user()

    def verify(self, prompt, cancel, waiting=lambda: None):
        if not self._lock.acquire(timeout=self.timeout):
            return TIMEOUT
        try:
            return self._verify(prompt, cancel, waiting)
        finally:
            self._lock.release()

    def _verify(self, prompt, cancel, waiting):
        from gi.repository import Gio, GLib

        who = self._resolve_user()
        if not who:
            log.warning("no active local user on seat0; refusing %s", prompt.title())
            return UNAVAILABLE
        user, uid = who
        deadline = time.monotonic() + self.timeout

        ctx = GLib.MainContext.new()
        ctx.push_thread_default()
        bus = None
        dev = None
        claimed = False
        sub = None
        note = None
        try:
            bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)

            def call(path, iface, method, args=None, sig=None, timeout_ms=10000):
                v = bus.call_sync("net.reactivated.Fprint", path, iface, method,
                                  args, GLib.VariantType.new(sig) if sig else None,
                                  Gio.DBusCallFlags.NONE, timeout_ms, None)
                return v.unpack() if v is not None else None

            (dev,) = call("/net/reactivated/Fprint/Manager",
                          "net.reactivated.Fprint.Manager", "GetDefaultDevice",
                          sig="(o)")
            dev_iface = "net.reactivated.Fprint.Device"
            try:
                (fingers,) = call(dev, dev_iface, "ListEnrolledFingers",
                                  GLib.Variant("(s)", (user,)), "(as)")
            except GLib.Error:
                fingers = []
            if not fingers:
                log.warning("%s has no enrolled finger; refusing", user)
                return UNAVAILABLE

            # Another prompt (sudo, the lock screen) may hold the reader.
            while True:
                try:
                    call(dev, dev_iface, "Claim", GLib.Variant("(s)", (user,)))
                    claimed = True
                    break
                except GLib.Error as e:
                    if "AlreadyInUse" not in str(e) or time.monotonic() > deadline:
                        log.warning("fprintd claim failed: %s", e.message)
                        return UNAVAILABLE if "AlreadyInUse" not in str(e) else TIMEOUT
                    if cancel.wait(0.2):
                        return CANCELLED

            events = []

            def on_status(_c, _s, _p, _i, _n, params, *_):
                events.append(params.unpack())

            sub = bus.signal_subscribe("net.reactivated.Fprint", dev_iface,
                                       "VerifyStatus", dev, None,
                                       Gio.DBusSignalFlags.NONE, on_status)
            tick = GLib.timeout_source_new(100)
            tick.set_callback(lambda *_: True)
            tick.attach(ctx)

            log.info("asking %s for Touch ID: %s", user, prompt.title())
            note = self.notifier.show(uid, prompt.title(),
                                      prompt.detail or "Touch the Touch ID sensor",
                                      self.timeout)
            waiting()
            tries = 0
            result = None
            while result is None:
                call(dev, dev_iface, "VerifyStart", GLib.Variant("(s)", ("any",)))
                tries += 1
                done = None
                while done is None:
                    ctx.iteration(True)
                    if cancel.is_set():
                        result = CANCELLED
                        break
                    if time.monotonic() > deadline:
                        result = TIMEOUT
                        break
                    while events:
                        status, fin = events.pop(0)
                        log.debug("fprintd: %s done=%s", status, fin)
                        if status == "verify-match":
                            done = MATCH
                        elif status == "verify-no-match":
                            done = NO_MATCH
                        elif status == "verify-lockout":
                            done = LOCKED
                        elif status in _RETRY and not fin:
                            continue
                        elif fin or status in ("verify-disconnected", "verify-unknown-error"):
                            done = UNAVAILABLE
                if result is not None:
                    break
                try:
                    call(dev, dev_iface, "VerifyStop")
                except GLib.Error:
                    pass
                if done == NO_MATCH and tries < self.max_tries:
                    log.info("Touch ID did not match (%d/%d)", tries, self.max_tries)
                    continue
                result = done
            log.info("Touch ID result for %s: %s", user, result)
            return result
        except GLib.Error as e:
            log.warning("fprintd error: %s", e.message)
            return UNAVAILABLE
        finally:
            if bus is not None and dev is not None and claimed:
                for m in ("VerifyStop", "Release"):
                    try:
                        bus.call_sync("net.reactivated.Fprint", dev,
                                      "net.reactivated.Fprint.Device", m, None, None,
                                      Gio.DBusCallFlags.NONE, 5000, None)
                    except GLib.Error:
                        pass
            if sub is not None:
                bus.signal_unsubscribe(sub)
            ctx.pop_thread_default()
            self.notifier.close(note)


POLKIT_ACTION = "org.aurora.fido.authenticate"


class PolkitPassword:
    """The user's password through the polkit agent of the seat0 session."""

    def __init__(self, timeout=60.0):
        self.timeout = float(timeout)
        from gi.repository import Gio, GLib  # noqa: F401

    def verify(self, prompt, cancel, waiting=lambda: None):
        from gi.repository import Gio, GLib

        who = seat_session()
        if not who:
            return UNAVAILABLE
        sid, user, _uid = who
        ctx = GLib.MainContext.new()
        ctx.push_thread_default()
        cid = f"aurora-fido-{os.getpid()}-{time.monotonic_ns()}"
        done = []
        try:
            bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
            subject = ("unix-session", {"session-id": GLib.Variant("s", sid)})
            details = {"polkit.message": f"Use your password: {prompt.title()}",
                       "aurora.fido.rp": display_rp(prompt.rp)}
            log.info("asking %s for the password: %s", user, prompt.title())
            bus.call(
                "org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority",
                "org.freedesktop.PolicyKit1.Authority", "CheckAuthorization",
                GLib.Variant("((sa{sv})sa{ss}us)", (subject, POLKIT_ACTION, details, 1, cid)),
                GLib.VariantType.new("((bba{ss}))"), Gio.DBusCallFlags.NONE,
                int(self.timeout * 1000) + 5000, None,
                lambda b, res: done.append(res))
            waiting()
            deadline = time.monotonic() + self.timeout
            while not done:
                ctx.iteration(False) or time.sleep(0.05)
                if cancel.is_set() or time.monotonic() > deadline:
                    try:
                        bus.call_sync("org.freedesktop.PolicyKit1",
                                      "/org/freedesktop/PolicyKit1/Authority",
                                      "org.freedesktop.PolicyKit1.Authority",
                                      "CancelCheckAuthorization", GLib.Variant("(s)", (cid,)),
                                      None, Gio.DBusCallFlags.NONE, 5000, None)
                    except GLib.Error:
                        pass
                    return CANCELLED if cancel.is_set() else TIMEOUT
            try:
                ((authorized, _challenge, _d),) = bus.call_finish(done[0]).unpack()
            except GLib.Error as e:
                log.warning("polkit: %s", e.message)
                return UNAVAILABLE
            log.info("password for %s: %s", user, "accepted" if authorized else "refused")
            return MATCH if authorized else NO_MATCH
        except GLib.Error as e:
            log.warning("polkit error: %s", e.message)
            return UNAVAILABLE
        finally:
            ctx.pop_thread_default()


class PolicyVerifier(Verifier):
    """Touch ID first; the password too when the prompt's policy allows it."""

    def __init__(self, touch, password=None):
        self.touch = touch
        self.password = password
        self.max_tries = getattr(touch, "max_tries", 3)

    def verify(self, prompt, cancel, waiting=lambda: None):
        r = self.touch.verify(prompt, cancel, waiting)
        if r in (NO_MATCH, LOCKED, UNAVAILABLE) and prompt.allow_password \
                and self.password is not None and not cancel.is_set():
            log.info("Touch ID: %s; this credential also takes the password", r)
            p = self.password.verify(prompt, cancel, waiting)
            return PASSWORD if p == MATCH else (r if p == NO_MATCH else p)
        return r
