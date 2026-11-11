# SPDX-License-Identifier: MIT
"""aurora-fidod's side of per-user credentials: forward each CTAP2 request to
the passkey agent of the user who owns the active local session on seat0.

The uhid hidraw node's `uaccess` ACL follows the same logind state, so the
requests a browser sends reach the agent of the person sitting at the Mac.
When no local user is active, or that user's agent is not running, nothing
is signed. getInfo is still answered, from the last agent reply or from a
fixed description, so that browsers keep showing the key. Every other
command gets CTAP2_ERR_OPERATION_DENIED.
"""

import logging
import os
import socket
import threading

from . import agentproto, cbor, ctap2, touchid
from .errors import ERR_OPERATION_DENIED

log = logging.getLogger("aurora-fido")


def agent_socket(uid):
    return "/run/user/%d/aurora-passkeys/ctap.sock" % uid


def static_info():
    """getInfo when no agent answers: the same versions and AAGUID, no credentials.
    U2F is not forwarded to agents (yet), so per-user mode never offers U2F_V2."""
    info = {1: ["FIDO_2_0", "FIDO_2_1"], 3: ctap2.AAGUID,
            4: {"rk": True, "up": True, "uv": True, "plat": False},
            5: 7609}
    return b"\x00" + cbor.encode(info)


class RemoteAuthenticator:
    """Has the same handle(data, ctx) as ctap2.Authenticator; ctaphid.CtapHid uses it unchanged."""

    def __init__(self, active_uid=None, socket_path=agent_socket, timeout=90.0):
        self.active_uid = active_uid or self._seat_uid
        self.socket_path = socket_path
        self.timeout = timeout
        self._info = {}                 # uid -> last getInfo reply (per user: it counts their passkeys)
        self.lock = threading.Lock()

    @staticmethod
    def _seat_uid():
        u = touchid.seat_user()
        return u[1] if u else None

    def _connect(self, uid):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        s.settimeout(self.timeout)
        try:
            s.connect(self.socket_path(uid))
            # The socket lives in the user's runtime dir, but check who answers:
            # only that user's own agent (never another user's process) may serve.
            if agentproto.peer_uid(s) != uid:
                raise PermissionError("agent socket for uid %d served by another uid" % uid)
        except BaseException:
            s.close()
            raise
        return s

    def handle(self, data, ctx=None):
        ctx = ctx or ctap2.Ctx()
        is_info = data[:1] == bytes([ctap2.CMD_GET_INFO])
        uid = self.active_uid()
        if uid is None:
            log.info("no active local session on seat0: request refused")
            return self._fallback(is_info, None)
        try:
            s = self._connect(uid)
        except (OSError, PermissionError) as e:
            log.info("passkey agent of uid %d not reachable (%s): request refused", uid, e)
            return self._fallback(is_info, uid)
        with s:
            try:
                return self._exchange(s, data, ctx, is_info, uid)
            except (OSError, agentproto.ProtocolError) as e:
                log.warning("passkey agent of uid %d failed: %s", uid, e)
                return self._fallback(is_info, uid)

    def _exchange(self, s, data, ctx, is_info, uid):
        agentproto.send(s, {"t": "req", "d": data})
        done = threading.Event()

        def watch_cancel():
            while not done.is_set():
                if ctx.cancel.wait(0.05):
                    try:
                        agentproto.send(s, {"t": "cancel"})
                    except OSError:
                        pass
                    return

        threading.Thread(target=watch_cancel, name="agent-cancel", daemon=True).start()
        try:
            while True:
                msg = agentproto.recv(s)
                if msg is None:
                    raise agentproto.ProtocolError("agent closed the connection")
                if msg["t"] == "up":
                    ctx.on_up_needed()
                elif msg["t"] == "resp":
                    if is_info and msg["d"][:1] == b"\x00":
                        self._info[uid] = msg["d"]
                    return msg["d"]
                else:
                    raise agentproto.ProtocolError("unexpected %r" % msg["t"])
        finally:
            done.set()

    def _fallback(self, is_info, uid):
        if is_info:
            return self._info.get(uid) or static_info()
        return bytes([ERR_OPERATION_DENIED])
