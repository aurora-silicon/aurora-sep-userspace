# SPDX-License-Identifier: MIT
"""D-Bus binding of the native front-end (provider.py) on the session bus.

Interface org.aurora.Passkeys.Provider1 at /org/aurora/Passkeys1, bus name
org.aurora.Passkeys1: the provider a credentials portal (credentialsd's
proposed Provider1, docs/passkeys/CREDENTIALSD-PROVIDER.md) calls for the
"internal" transport.

  GetInfo() -> a{sv}
  ListCredentials(s rp_id, aay allow) -> aa{sv}
  MakeCredential(u req, ay cdh, a{sv} rp, a{sv} user, ai algs, aay exclude, a{sv} options) -> a{sv}
  GetAssertion(u req, ay cdh, s rp_id, ay credential_id, a{sv} options) -> a{sv}
  Cancel(u req)
  signal UserActionNeeded(u req, s kind, a{sv} detail)     kind: "touch"

options: "origin" s (required), "top_origin" s, "rk" b, "extensions" a{sv},
"password_fd" h: a memfd (or pipe) holding the user's login password, which
the enclave checks in place of a touch. It is read once, then the buffer is wiped.
Errors are org.aurora.Passkeys.Error.<DOMException name>, for example
org.aurora.Passkeys.Error.NotAllowedError. A wrong password is
org.aurora.Passkeys.Error.WrongPassword, a call that needs the password too
(a Touch ID AND password credential or site rule) is ...Error.PasswordNeeded,
and a locked key bag is ...Error.Locked.

Callers: only the session's own uid, and, when allow_names is set, only the
current owner of one of those bus names (the portal). Every signature is
still an enclave-checked touch or password; this layer decides nothing.
"""

import logging
import os
import threading

from jeepney import (DBusAddress, HeaderFields, MessageType, new_error, new_method_return,
                     new_signal)
from jeepney.bus_messages import message_bus
from jeepney.io.blocking import open_dbus_connection

from . import ctap2
from .provider import ProviderError

log = logging.getLogger("aurora-passkeys")

BUS_NAME = "org.aurora.Passkeys1"
PATH = "/org/aurora/Passkeys1"
IFACE = "org.aurora.Passkeys.Provider1"
ERR = "org.aurora.Passkeys.Error."
# Provider reasons the portal acts on get their own error names: it asks for
# the password (and calls again) or shows the locked state. Other refusals
# carry their DOMException name.
_REASON_ERRORS = {"wrong-password": "WrongPassword", "password-needed": "PasswordNeeded",
                  "locked": "Locked"}
MAX_PASSWORD = 256

INTROSPECT = f"""<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node>
 <interface name="{IFACE}">
  <method name="GetInfo"><arg type="a{{sv}}" direction="out"/></method>
  <method name="ListCredentials"><arg name="rp_id" type="s"/><arg name="allow" type="aay"/>
   <arg type="aa{{sv}}" direction="out"/></method>
  <method name="MakeCredential"><arg name="req" type="u"/><arg name="cdh" type="ay"/>
   <arg name="rp" type="a{{sv}}"/><arg name="user" type="a{{sv}}"/><arg name="algs" type="ai"/>
   <arg name="exclude" type="aay"/><arg name="options" type="a{{sv}}"/>
   <arg type="a{{sv}}" direction="out"/></method>
  <method name="GetAssertion"><arg name="req" type="u"/><arg name="cdh" type="ay"/>
   <arg name="rp_id" type="s"/><arg name="credential_id" type="ay"/><arg name="options" type="a{{sv}}"/>
   <arg type="a{{sv}}" direction="out"/></method>
  <method name="Cancel"><arg name="req" type="u"/></method>
  <signal name="UserActionNeeded"><arg name="req" type="u"/><arg name="kind" type="s"/>
   <arg name="detail" type="a{{sv}}"/></signal>
 </interface>
 <interface name="org.freedesktop.DBus.Introspectable">
  <method name="Introspect"><arg type="s" direction="out"/></method>
 </interface>
</node>
"""


# -- a{sv} <-> Python ------------------------------------------------------------------------

def variant(v):
    if isinstance(v, bool):
        return ("b", v)
    if isinstance(v, int):
        return ("x", v)
    if isinstance(v, str):
        return ("s", v)
    if isinstance(v, (bytes, bytearray)):
        return ("ay", bytes(v))
    if isinstance(v, dict):
        return ("a{sv}", asv(v))
    if isinstance(v, (list, tuple)):
        if all(isinstance(x, str) for x in v):
            return ("as", list(v))
        if all(isinstance(x, (bytes, bytearray)) for x in v):
            return ("aay", [bytes(x) for x in v])
        if all(isinstance(x, int) and not isinstance(x, bool) for x in v):
            return ("ax", list(v))
        return ("av", [variant(x) for x in v])
    raise TypeError("no D-Bus type for %r" % type(v))


def asv(d):
    return {str(k): variant(v) for k, v in d.items()}


def unvariant(d):
    """a{sv} from jeepney ({k: (sig, value)}) -> plain dict; nested a{sv} too."""
    out = {}
    for k, (sig, v) in d.items():
        out[k] = unvariant(v) if sig == "a{sv}" else v
    return out


def read_password(fd):
    """The password from a file descriptor (FileDescriptor or int), as a bytearray."""
    raw = fd.to_raw_fd() if hasattr(fd, "to_raw_fd") else int(fd)
    try:
        try:
            os.lseek(raw, 0, os.SEEK_SET)
        except OSError:
            pass                                        # a pipe
        buf = bytearray(MAX_PASSWORD + 1)
        n = 0
        while n < len(buf):
            k = os.readv(raw, [memoryview(buf)[n:]])
            if k == 0:
                break
            n += k
    finally:
        os.close(raw)
    if not 0 < n <= MAX_PASSWORD:
        buf[:] = bytes(len(buf))
        raise ProviderError("NotAllowedError", "password length")
    pw = buf[:n]
    buf[:] = bytes(len(buf))
    return pw


# -- the service ----------------------------------------------------------------------------

class ProviderService:
    def __init__(self, provider, bus="SESSION", allow_names=(), uid=None):
        self.provider = provider
        self.conn = open_dbus_connection(bus=bus, enable_fds=True)
        self.query = open_dbus_connection(bus=bus)      # for caller checks only
        self.allow_names = tuple(allow_names)
        self.uid = os.getuid() if uid is None else uid
        self.send_lock = threading.Lock()
        self.query_lock = threading.Lock()
        self.requests = {}                               # (sender, req) -> Ctx
        self.req_lock = threading.Lock()
        self.stop = threading.Event()
        self.emitter = DBusAddress(PATH, interface=IFACE)

    def request_name(self, name=BUS_NAME):
        """Own name on the serving connection (before serve_forever starts)."""
        reply = self.conn.send_and_get_reply(message_bus.RequestName(name, 4))  # DO_NOT_QUEUE
        return reply.body[0] == 1                        # PRIMARY_OWNER

    def _send(self, msg):
        with self.send_lock:
            self.conn.send(msg)

    def _caller_ok(self, sender):
        with self.query_lock:
            uid = self.query.send_and_get_reply(message_bus.GetConnectionUnixUser(sender)).body[0]
            if uid != self.uid:
                return False
            if not self.allow_names:
                return True
            for name in self.allow_names:
                r = self.query.send_and_get_reply(message_bus.GetNameOwner(name))
                if r.header.message_type == MessageType.method_return and r.body[0] == sender:
                    return True
        return False

    def serve_forever(self):
        while not self.stop.is_set():
            try:
                msg = self.conn.receive(timeout=0.5)
            except TimeoutError:
                continue
            except (OSError, ConnectionResetError):
                if self.stop.is_set():
                    break
                raise
            h = msg.header
            if h.message_type != MessageType.method_call:
                continue
            threading.Thread(target=self._dispatch, args=(msg,), name="passkeys-dbus",
                             daemon=True).start()

    def close(self):
        self.stop.set()
        for c in (self.conn, self.query):
            try:
                c.close()
            except OSError:
                pass

    def _dispatch(self, msg):
        h = msg.header.fields
        iface, member = h.get(HeaderFields.interface), h.get(HeaderFields.member)
        sender, path = h.get(HeaderFields.sender), h.get(HeaderFields.path)
        try:
            if path != PATH:
                raise ProviderError("UnknownObject", "no object at %s" % path)
            if iface == "org.freedesktop.DBus.Introspectable" and member == "Introspect":
                self._send(new_method_return(msg, "s", (INTROSPECT,)))
                return
            if iface not in (IFACE, None):
                raise ProviderError("UnknownMethod", "%s.%s" % (iface, member))
            if not self._caller_ok(sender):
                log.warning("refused %s from %s", member, sender)
                raise ProviderError("NotAllowedError", "caller not allowed")
            fn = getattr(self, "m_" + (member or ""), None)
            if fn is None:
                raise ProviderError("UnknownMethod", member or "")
            sig, body = fn(sender, *msg.body)
            self._send(new_method_return(msg, sig, body))
        except ProviderError as e:
            name = _REASON_ERRORS.get(e.reason, e.name)
            self._send(new_error(msg, ERR + name, "s", (str(e),)))
        except Exception as e:                          # never kill the bus loop
            log.exception("%s failed", member)
            self._send(new_error(msg, ERR + "UnknownError", "s", (str(e),)))

    # -- methods ---------------------------------------------------------------------------

    def m_GetInfo(self, sender):
        return "a{sv}", (asv(self.provider.get_info()),)

    def m_ListCredentials(self, sender, rp_id, allow):
        return "aa{sv}", ([asv(c) for c in self.provider.list_credentials(rp_id, allow)],)

    def _ctx(self, sender, req):
        ctx = ctap2.Ctx(threading.Event(), lambda: self._send(new_signal(
            self.emitter, "UserActionNeeded", "usa{sv}", (req, "touch", {}))))
        with self.req_lock:
            if (sender, req) in self.requests:
                raise ProviderError("InvalidStateError", "request id in use")
            self.requests[(sender, req)] = ctx
        return ctx

    def _done(self, sender, req):
        with self.req_lock:
            self.requests.pop((sender, req), None)

    @staticmethod
    def _options(options):
        o = unvariant(options)
        fd = o.pop("password_fd", None)
        return o, (read_password(fd) if fd is not None else None)

    def m_MakeCredential(self, sender, req, cdh, rp, user, algs, exclude, options):
        o, pw = self._options(options)
        ctx = self._ctx(sender, req)
        try:
            r = self.provider.make_credential(bytes(cdh), unvariant(rp), unvariant(user), list(algs),
                                              list(exclude), o, ctx, password=pw)
        finally:
            self._done(sender, req)
        return "a{sv}", (asv(r),)

    def m_GetAssertion(self, sender, req, cdh, rp_id, credential_id, options):
        o, pw = self._options(options)
        ctx = self._ctx(sender, req)
        try:
            r = self.provider.get_assertion(bytes(cdh), rp_id, bytes(credential_id), o, ctx,
                                            password=pw)
        finally:
            self._done(sender, req)
        return "a{sv}", (asv(r),)

    def m_Cancel(self, sender, req):
        with self.req_lock:
            ctx = self.requests.get((sender, req))
        if ctx is not None:
            ctx.cancel.set()
        return "", ()
