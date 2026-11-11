# SPDX-License-Identifier: MIT
"""The native (platform authenticator) front-end of the passkey agent.

These are the methods a credentials portal (credentialsd's proposed
Provider1 interface; docs/passkeys/CREDENTIALSD-PROVIDER.md) calls instead
of CTAP over hidraw. They sit on the same ctap2.Authenticator, so both
front-ends share one vault and one set of rules: every signature is still an
enclave-checked touch inside SEP_KEY_SIGN. The D-Bus binding is a thin layer
on top of this and is not here yet.

Inputs are WebAuthn-shaped (rp/user dicts, a client data hash the portal
computed from the origin), and errors are WebAuthn DOMException names.
"""

import contextlib
import hashlib
from urllib.parse import urlsplit

from . import cbor, ctap2
from . import errors as E


class ProviderError(Exception):
    """name: a WebAuthn DOMException name (NotAllowedError, InvalidStateError, ...)."""

    def __init__(self, name, message="", reason=None):
        super().__init__(message or name)
        self.name = name
        # Finer cause for the portal UI: "wrong-password" (ask again; the enclave
        # counted the try), else None.
        self.reason = reason


# CTAP status -> DOMException name (WebAuthn L3, "authenticatorMakeCredential"/
# "authenticatorGetAssertion" error handling).
_DOM = {
    E.ERR_CREDENTIAL_EXCLUDED: "InvalidStateError",
    E.ERR_UNSUPPORTED_ALGORITHM: "NotSupportedError",
    E.ERR_UNSUPPORTED_OPTION: "NotSupportedError",
    E.ERR_KEY_STORE_FULL: "QuotaExceededError",
}


def rp_id_matches_origin(rp_id, origin):
    """rp_id must be the origin's host or a parent domain of it, over https
    (http only for localhost). The portal checks the registrable-domain
    rule; this is the provider's own check, not a replacement for it."""
    try:
        u = urlsplit(origin)
    except ValueError:
        return False
    host = (u.hostname or "").lower().rstrip(".")
    rp = (rp_id or "").lower().rstrip(".")
    if not host or not rp:
        return False
    if u.scheme != "https" and not (u.scheme == "http" and host == "localhost"):
        return False
    return host == rp or host.endswith("." + rp)


class Provider:
    def __init__(self, auth, gate=None):
        self.auth = auth
        self.gate = gate              # agent.VaultGate: open the vault per call, if given

    @contextlib.contextmanager
    def _open(self, need_vault=True):
        """The vault open for this call (VaultGate); yields whether it opened."""
        if self.gate is None:
            yield True
            return
        with self.gate.open() as ok:
            if not ok and need_vault:
                raise ProviderError("NotAllowedError", "your key bag is locked", "locked")
            yield ok

    def _call(self, cmd, params, ctx):
        r = self.auth.handle(bytes([cmd]) + cbor.encode(params), ctx)
        if r[0] == E.ERR_PIN_INVALID:
            raise ProviderError("NotAllowedError", "wrong password", "wrong-password")
        if r[0] != 0:
            raise ProviderError(_DOM.get(r[0], "NotAllowedError"), "CTAP status 0x%02x" % r[0])
        return cbor.decode(r[1:]) if len(r) > 1 else {}

    @staticmethod
    def _check_origin(rp_id, origin):
        if not rp_id_matches_origin(rp_id, origin):
            raise ProviderError("SecurityError", "rp id %r is not valid for %r" % (rp_id, origin))

    def get_info(self):
        with self._open(need_vault=False) as ok:
            info = self.auth.get_info({}, None)
        return {"aaguid": info[3], "name": "Aurora Passwords",
                "algorithms": [a["alg"] for a in info[0x0A]],
                "extensions": list(info[2]),
                "uv": ["biometric"] + (["password"] if getattr(self.auth.backend,
                                                               "can_password", False) else []),
                "locked": not ok, "rk_remaining": info[0x14]}

    def list_credentials(self, rp_id, allow=()):
        """Display metadata only: no touch and no credential key operation."""
        with self._open():
            return self._list(rp_id, allow)

    def _list(self, rp_id, allow):
        rp_hash = hashlib.sha256(rp_id.encode()).digest()
        out = []
        for rec in self.auth.store.for_rp(rp_hash):
            out.append({"id": rec["credId"], "user_handle": rec["userId"],
                        "user_name": rec.get("userName") or "",
                        "display_name": rec.get("displayName") or "",
                        "created": rec.get("created", 0)})
        known = {c["id"] for c in out}
        for cid in allow or ():
            if cid not in known and self.auth.vault.unwrap(rp_hash, cid) is not None:
                out.append({"id": cid, "user_handle": b"", "user_name": "",
                            "display_name": "", "created": 0})
        return out

    @staticmethod
    def _ctx(ctx, password):
        ctx = ctx or ctap2.Ctx()
        ctx.password = password
        return ctx

    @staticmethod
    def _wipe(password):
        if isinstance(password, bytearray):
            password[:] = bytes(len(password))

    def make_credential(self, cdh, rp, user, params, exclude=(), options=None, ctx=None,
                        password=None):
        """password: the user's login password (bytearray, wiped here) for the
        enclave to check instead of a touch; None = Touch ID."""
        try:
            with self._open():
                return self._make(cdh, rp, user, params, exclude, options,
                                  self._ctx(ctx, password))
        finally:
            self._wipe(password)

    def _make(self, cdh, rp, user, params, exclude, options, ctx):
        o = dict(options or {})
        self._check_origin(rp.get("id"), o.get("origin", ""))
        p = {1: cdh, 2: {k: v for k, v in rp.items() if k in ("id", "name")},
             3: {k: v for k, v in user.items() if k in ("id", "name", "displayName")},
             4: [{"type": "public-key", "alg": a} for a in params],
             7: {"rk": bool(o.get("rk", True))}}
        if exclude:
            p[5] = [{"type": "public-key", "id": c} for c in exclude]
        if o.get("extensions"):
            p[6] = o["extensions"]
        r = self._call(ctap2.CMD_MAKE_CREDENTIAL, p, ctx)
        att = {"fmt": r[1], "attStmt": r[3], "authData": r[2]}
        return {"attestation_object": cbor.encode(att), "transports": ["internal"],
                "extensions": r.get(6, {})}

    def get_assertion(self, cdh, rp_id, credential_id, options=None, ctx=None, password=None):
        try:
            with self._open():
                return self._get(cdh, rp_id, credential_id, options, self._ctx(ctx, password))
        finally:
            self._wipe(password)

    def _get(self, cdh, rp_id, credential_id, options, ctx):
        o = dict(options or {})
        self._check_origin(rp_id, o.get("origin", ""))
        p = {1: rp_id, 2: cdh, 3: [{"type": "public-key", "id": credential_id}]}
        if o.get("extensions"):
            p[4] = o["extensions"]
        r = self._call(ctap2.CMD_GET_ASSERTION, p, ctx)
        if r[1]["id"] != credential_id:
            raise ProviderError("UnknownError", "the authenticator answered for another credential")
        return {"authenticator_data": r[2], "signature": r[3],
                "user_handle": r.get(4, {}).get("id", b""), "extensions": {}}
