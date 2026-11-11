# SPDX-License-Identifier: MIT
"""aurora-passkeyd: one user's passkeys and security-key credentials.

Runs as the user (systemd --user). aurora-fidod keeps the uhid device and
the CTAPHID framing and forwards each CTAP2 request here (remote.py,
agentproto.py). This process owns:
- the user's credential records (in $XDG_DATA_HOME/aurora-passkeys);
- the CTAP2 logic (ctap2.Authenticator, unchanged);
- the calls to /dev/sep-key, which it makes as the user.

On the target kernel (sep-key interface 4) the credential keys are created
under the user's own key bag, and the enclave refuses them to every other
uid, root included (docs/passkeys/DESIGN.md 4.1, 4.2).

The vault key that wraps credential IDs and records is sealed to a key in
the user's bag. That key needs the bag unlocked, but no touch, so records
are unreadable while the user is logged out. This needs interface 4. On an
older kernel the agent refuses to start: it never falls back to a key the
host holds.
"""

import argparse
import contextlib
import logging
import os
import pwd
import signal
import socket
import sys
import threading

from . import __version__, agentproto, cbor, creds, ctap2, daemon
from .errors import ERR_CHANNEL_BUSY, ERR_OPERATION_DENIED
from .backend import BackendError, BagLocked, UserBagBackend, open_backend, user_handle_uid

log = logging.getLogger("aurora-passkeys")

SEP_KEY_IFACE_USER_BAG = 4


def data_dir():
    base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return os.path.join(base, "aurora-passkeys")


def config_dir():
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "aurora-passkeys")


class SitePolicy:
    """Per-site rules for new credentials: ~/.config/aurora-passkeys/sites.conf

        # site = policy      (the site and every name under it)
        bank.example = touchid-current
        corp.example = touchid-any

    The longest matching site wins; no match keeps the default policy. The
    rule is written into the new key's access-control list, so the enclave
    enforces it; a changed rule affects new credentials only (macOS behaviour).
    A malformed line is skipped with a warning, never widened.
    """

    def __init__(self, path):
        self.rules = {}
        try:
            with open(path, encoding="utf-8") as f:
                lines = f.read().splitlines()
        except FileNotFoundError:
            return
        for n, line in enumerate(lines, 1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            site, sep, pol = (x.strip() for x in line.partition("="))
            site = site.lower().rstrip(".")
            if not sep or not site or pol not in creds.POLICIES:
                log.warning("%s:%d: ignored (want 'site = %s')", path, n,
                            " | ".join(sorted(creds.POLICIES)))
                continue
            self.rules[site] = creds.POLICIES[pol]

    def __call__(self, rp_id):
        rp_id = rp_id.lower().rstrip(".")
        best = None
        for site, pol in self.rules.items():
            if (rp_id == site or rp_id.endswith("." + site)) and (
                    best is None or len(site) > len(best[0])):
                best = site, pol
        return best[1] if best else None


def runtime_socket():
    rd = os.environ.get("XDG_RUNTIME_DIR") or "/run/user/%d" % os.getuid()
    return os.path.join(rd, "aurora-passkeys", "ctap.sock")


class UserBagSecret:
    """The vault key (64 bytes that wrap credential IDs and records), sealed
    to a key with no list under the user's own key bag (interface 4,
    SEP_KEY_CREATE_USER with flags 0).

    The enclave opens it with no touch and no password, but only while the
    bag is unlocked (the user logged in with their password). Root cannot
    open it while the user is logged out, and nothing host-readable is kept.
    File vault.key: CBOR {1: key handle, 2: sealed vault key}.
    """

    FILE = "vault.key"

    def __init__(self, sep, uid, state_dir):
        self.sep = sep
        self.uid = uid
        self.path = os.path.join(state_dir, self.FILE)

    def _need_iface(self):
        if not getattr(self.sep, "can_password", False):
            raise BackendError(
                "per-user passkeys need /dev/sep-key interface 4 (keys under your own key "
                "bag, variant-5 key store); this kernel has interface %s"
                % getattr(self.sep, "version", "?"))

    def new(self):
        self._need_iface()
        handle, _point = self.sep.create_user(self.uid, False)
        secret = os.urandom(64)
        sealed = self.sep.seal(handle, secret)
        if self.sep.unseal(handle, sealed) != secret:
            raise BackendError("the enclave did not give the vault key back")
        creds.atomic_write(self.path, cbor.encode({1: handle, 2: sealed}))
        log.info("made the vault key (sealed under your key bag)")
        return secret

    def load(self):
        self._need_iface()
        try:
            with open(self.path, "rb") as f:
                rec = cbor.decode(f.read(8192))
        except FileNotFoundError:
            return self.new()
        if not (isinstance(rec, dict) and isinstance(rec.get(1), bytes)
                and isinstance(rec.get(2), bytes)):
            raise BackendError("%s is damaged" % self.path)
        if user_handle_uid(rec[1]) != self.uid:
            raise BackendError("%s belongs to another user" % self.path)
        return self.sep.unseal(rec[1], rec[2])


class LockedVault:
    """Stands in for the vault between requests: nothing opens without the vault key."""

    def __init__(self, state_dir):
        self.state_dir = state_dir
        self.handles_dir = os.path.join(state_dir, "handles")

    def _locked(self, *_a, **_k):
        raise BackendError("the vault is closed (your key bag is locked)")

    wrap = unwrap = seal_record = open_record = _locked


class VaultGate:
    """Opens the vault for one request and closes it again.

    The vault key is unsealed from the user's bag at the start of every
    request (one enclave key exchange, no touch) and the vault is dropped when
    the request ends. So the key is in this process's memory only during a
    request, and only while the bag is unlocked: once the user logs out or the
    bag locks, the next request cannot open it. (Python frees the key but
    cannot zero it.) One request at a time, across every front-end.
    """

    def __init__(self, auth, secret, state_dir, max_rk):
        self.auth = auth
        self.secret = secret
        self.state_dir = state_dir
        self.max_rk = max_rk
        self.lock = threading.Lock()
        self._close()

    def _close(self):
        v = LockedVault(self.state_dir)
        self.auth.vault = v
        self.auth.store = creds.ResidentStore(v, self.state_dir, self.max_rk)

    @contextlib.contextmanager
    def open(self):
        """Yields True with the vault open, or False when the bag is locked."""
        with self.lock:
            try:
                master = self.secret.load()
            except BagLocked as e:
                log.info("vault stays closed: %s", e)
                yield False
                return
            v = creds.Vault(self.state_dir, master)
            del master
            self.auth.vault = v
            self.auth.store = creds.ResidentStore(v, self.state_dir, self.max_rk)
            try:
                yield True
            finally:
                self._close()


def per_user_info(resp):
    """getInfo from the agent: no U2F_V2 (U2F is not forwarded to agents)."""
    if resp[:1] != b"\x00":
        return resp
    info = cbor.decode(resp[1:])
    info[1] = [v for v in info.get(1, []) if v != "U2F_V2"]
    return b"\x00" + cbor.encode(info)


class AgentServer:
    """Serves CTAP2 requests from aurora-fidod on a Unix SEQPACKET socket.

    allowed_uids: peers that may send requests, normally root (aurora-fidod)
    and the user (`aurora-passkeys` tools). Same-user processes can already
    open the hidraw node, so allowing them here grants nothing new.
    """

    def __init__(self, auth, path, allowed_uids, gate=None):
        self.auth = auth
        self.gate = gate                      # VaultGate: the vault is open only per request
        self.path = path
        self.allowed = set(allowed_uids)
        self.sock = None
        self.stop = threading.Event()
        self.lock = threading.Lock()           # one CTAP request at a time, as a key does

    def bind(self):
        d = os.path.dirname(self.path)
        os.makedirs(d, mode=0o700, exist_ok=True)
        os.chmod(d, 0o700)
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass
        s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        s.bind(self.path)
        os.chmod(self.path, 0o600)
        s.listen(4)
        s.settimeout(0.2)
        self.sock = s
        return self

    def serve_forever(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if self.stop.is_set():
                    break
                raise
            threading.Thread(target=self._conn, args=(conn,), name="agent-conn",
                             daemon=True).start()

    def close(self):
        self.stop.set()
        if self.sock:
            self.sock.close()
        try:
            os.unlink(self.path)
        except OSError:
            pass

    def _conn(self, conn):
        with conn:
            try:
                uid = agentproto.peer_uid(conn)
                if uid not in self.allowed:
                    log.warning("refused a request from uid %d", uid)
                    return
                msg = agentproto.recv(conn)
                if msg is None or msg["t"] != "req":
                    return
                self._request(conn, msg["d"])
            except (OSError, agentproto.ProtocolError) as e:
                log.info("request ended: %s", e)

    def _request(self, conn, data):
        cancel = threading.Event()
        send_lock = threading.Lock()

        def up_needed():
            with send_lock:
                try:
                    agentproto.send(conn, {"t": "up"})
                except OSError:
                    cancel.set()

        def reader():
            # A cancel message, or fidod going away, cancels the request.
            try:
                while not cancel.is_set():
                    m = agentproto.recv(conn)
                    if m is None or m["t"] == "cancel":
                        cancel.set()
            except (OSError, agentproto.ProtocolError):
                cancel.set()

        threading.Thread(target=reader, name="agent-read", daemon=True).start()
        if not self.lock.acquire(timeout=1.0):
            resp = bytes([ERR_CHANNEL_BUSY])
        else:
            try:
                resp = self._handle(data, ctap2.Ctx(cancel, up_needed))
            finally:
                self.lock.release()
        if data[:1] == bytes([ctap2.CMD_GET_INFO]):
            resp = per_user_info(resp)
        with send_lock:
            agentproto.send(conn, {"t": "resp", "d": resp})


    def _handle(self, data, ctx):
        if self.gate is None:
            return self.auth.handle(data, ctx)
        with self.gate.open() as ok:
            # getInfo needs no vault (it only counts the records); the rest does.
            if ok or data[:1] == bytes([ctap2.CMD_GET_INFO]):
                return self.auth.handle(data, ctx)
            return bytes([ERR_OPERATION_DENIED])


def build_agent(cfg, state_dir, backend, secret, user_name, sites=None):
    """The authenticator for one user (no U2F: not forwarded to agents yet)."""
    cfg.set("touchid", "user", user_name)
    policy, note = daemon.resolve_policy(cfg, backend.flags_supported)
    user = daemon.enclave_user(cfg, backend, state_dir, policy)
    auth, _u2f = daemon.build(cfg, state_dir, backend, user, secret, policy)
    auth.policy_for = sites
    return auth, note


def main(argv=None):
    ap = argparse.ArgumentParser(prog="aurora-passkeyd")
    ap.add_argument("--config", default=daemon.CONFIG)
    ap.add_argument("--state-dir", default=None)
    ap.add_argument("--socket", default=None)
    ap.add_argument("--no-dbus", action="store_true", help="no session-bus front-end")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(message)s")
    if os.geteuid() == 0:
        log.error("aurora-passkeyd runs as the user whose passkeys it keeps, not as root")
        return 1
    name = pwd.getpwuid(os.getuid()).pw_name
    state_dir = a.state_dir or data_dir()
    os.umask(0o077)
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    cfg = daemon.load_config(a.config)
    uid = os.getuid()
    try:
        sep = open_backend(cfg.get("keys", "store"))
        secret = UserBagSecret(sep, uid, state_dir)
        secret._need_iface()
        auth, note = build_agent(cfg, state_dir, UserBagBackend(sep, uid), secret, name,
                                 SitePolicy(os.path.join(config_dir(), "sites.conf")))
    except BagLocked as e:
        log.error("%s; aurora-passkeyd starts again when you log in", e)
        return 1
    except (BackendError, ValueError, OSError) as e:
        log.error("%s", e)
        return 1
    if note:
        log.info("%s", note)
    gate = VaultGate(auth, secret, state_dir, cfg.getint("authenticator", "max_resident"))
    srv = AgentServer(auth, a.socket or runtime_socket(), {0, os.getuid()}, gate).bind()
    dbus = None if a.no_dbus else start_dbus(auth, cfg, gate)
    for s in (signal.SIGTERM, signal.SIGINT):
        signal.signal(s, lambda *_: srv.stop.set())
    log.info("aurora-passkeyd %s ready for %s", __version__, name)
    try:
        srv.serve_forever()
    finally:
        srv.close()
        if dbus:
            dbus.close()
    return 0


def start_dbus(auth, cfg, gate=None):
    """The native front-end on the session bus (org.aurora.Passkeys1), if possible.

    [native] portal_names: bus names allowed to call it (a credentials portal);
    empty = any process of this user, which can already reach the security key
    through hidraw, so it grants nothing new."""
    try:
        from . import dbus_provider
        from .provider import Provider
    except ImportError as e:
        log.info("no D-Bus front-end (%s)", e)
        return None
    names = cfg.get("native", "portal_names", fallback="").split()
    try:
        svc = dbus_provider.ProviderService(Provider(auth, gate), allow_names=names)
        if not svc.request_name():
            log.warning("%s is taken; no D-Bus front-end", dbus_provider.BUS_NAME)
            svc.close()
            return None
    except (OSError, KeyError) as e:
        log.info("no session bus (%s); no D-Bus front-end", e)
        return None
    threading.Thread(target=svc.serve_forever, name="passkeys-dbus", daemon=True).start()
    log.info("native front-end on the session bus as %s", dbus_provider.BUS_NAME)
    return svc


if __name__ == "__main__":
    sys.exit(main())
