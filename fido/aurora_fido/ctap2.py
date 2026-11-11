# SPDX-License-Identifier: MIT
"""The CTAP 2.1 authenticator: every approval is a Touch ID match the Secure Enclave checks.

Commands: makeCredential, getAssertion, getNextAssertion, getInfo, clientPIN
(key agreement, getPinUvAuthTokenUsingUvWithPermissions, getUVRetries only:
there is no PIN, see docs/fido.md), reset, credentialManagement (and the 2.1
preview command number), selection. Extensions: credProtect, and
hmac-secret when the kernel can seal a secret to a credential key.

User presence is never just a touch: the enclave signs only after a match,
so UP and UV are set together, and only on a response whose signature the
enclave made with a finger on the sensor. A request with up=false and no uv
(browsers and libfido2 probing which credentials exist) cannot get an
enclave signature without a touch, so it is answered without one: the
response carries no flags and its signature is made by a throwaway software
key of this daemon run, so it verifies against no credential. Relying
parties reject such assertions for sign-in anyway.
"""

import hashlib
import hmac
import logging
import os
import struct
import threading
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from . import cbor, keys, pinuv, touchid
from .backend import BackendError, InvalidHandle
from .creds import ID_MAX_CTAP2, POLICY_FLAGS, POLICY_TOUCHID_ANY, Credential
from .errors import *  # noqa: F401,F403
from .errors import CtapError

log = logging.getLogger("aurora-fido")

CMD_MAKE_CREDENTIAL = 0x01
CMD_GET_ASSERTION = 0x02
CMD_GET_INFO = 0x04
CMD_CLIENT_PIN = 0x06
CMD_RESET = 0x07
CMD_GET_NEXT_ASSERTION = 0x08
CMD_CRED_MGMT = 0x0A
CMD_SELECTION = 0x0B
CMD_CRED_MGMT_PRE = 0x41

FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_AT = 0x40
FLAG_ED = 0x80

# A fixed AAGUID for this authenticator model. It identifies the software,
# not a certified device: there is no metadata statement behind it.
AAGUID = bytes.fromhex("a0f1d0e5aa5b4a7e9c51f1d0a0c0de01")

RESET_WINDOW = 10.0
# A request that Touch ID just refused (wrong finger, lockout) and that the
# client sends again unchanged is refused again without a new prompt for
# this long. OpenSSH does that: it takes OPERATION_DENIED for "PIN required"
# and signs the same data once more. A hardware key with built-in UV that
# has refused a match does not hand out new tries to a replay either, and
# each extra prompt would spend Touch ID misses towards the lockout. Any new
# request (new challenge, other options) gets a normal prompt.
REFUSAL_REPLAY_WINDOW = 10.0
NEXT_ASSERTION_WINDOW = 30.0
MAX_USER_FIELD = 64


class Ctx:
    """Per-request context from the transport."""

    def __init__(self, cancel=None, on_up_needed=lambda: None):
        self.cancel = cancel or threading.Event()
        self.on_up_needed = on_up_needed


def _rp_hash(rp_id):
    return hashlib.sha256(rp_id.encode()).digest()


def _need(params, key, typ, required=True):
    v = params.get(key)
    if v is None:
        if required:
            raise CtapError(ERR_MISSING_PARAMETER, f"parameter {key}")
        return None
    if not isinstance(v, typ) or (typ is int and isinstance(v, bool)):
        raise CtapError(ERR_CBOR_UNEXPECTED_TYPE, f"parameter {key}")
    return v


def _trunc(s):
    """Truncate a user/RP string to 64 bytes without splitting a character."""
    if not isinstance(s, str):
        return None
    b = s.encode()[:MAX_USER_FIELD]
    return b.decode("utf-8", "ignore")


def _check_descriptor_list(lst, key):
    if lst is None:
        return []
    if not isinstance(lst, list):
        raise CtapError(ERR_CBOR_UNEXPECTED_TYPE, f"parameter {key}")
    out = []
    for d in lst:
        if not isinstance(d, dict):
            raise CtapError(ERR_CBOR_UNEXPECTED_TYPE, "credential descriptor")
        t, i = d.get("type"), d.get("id")
        if not isinstance(t, str) or not isinstance(i, bytes):
            raise CtapError(ERR_MISSING_PARAMETER if t is None or i is None
                            else ERR_CBOR_UNEXPECTED_TYPE, "credential descriptor")
        if t == "public-key":
            out.append(i)
    return out


def _options(params, key):
    opts = params.get(key, {})
    if not isinstance(opts, dict):
        raise CtapError(ERR_CBOR_UNEXPECTED_TYPE, "options")
    for k, v in opts.items():
        if not isinstance(k, str) or not isinstance(v, bool):
            raise CtapError(ERR_CBOR_UNEXPECTED_TYPE, "option")
    return opts


class Authenticator:
    def __init__(self, backend, user, vault, store, counter,
                 attestation="self", new_vault=None, clock=time.monotonic,
                 policy=POLICY_TOUCHID_ANY, on_legacy=lambda rp_id, why: None,
                 policy_for=None):
        self.backend = backend
        self.user = user                  # enclave.EnclaveUser: every approval
        self.policy = policy              # for new credentials (config [touchid] policy)
        self.flags = POLICY_FLAGS[policy]
        # rp_id -> policy for that site's new credentials, or None for the default
        # (per-site rules, aurora-passkeyd); the enclave enforces whichever is chosen.
        self.policy_for = policy_for
        self.on_legacy = on_legacy        # a refused pre-enclave credential was presented
        self.vault = vault
        self.store = store
        self.counter = counter
        self.attestation = attestation
        self.new_vault = new_vault       # reset: returns (vault, store)
        self.clock = clock
        self.started = clock()
        self.key_agreement = pinuv.KeyAgreement()
        self.token = pinuv.Token(clock)
        self.lock = threading.Lock()
        self._next = None                 # getNextAssertion state
        self._cm = None                   # credential management enumeration state
        self._refused = None              # (request digest, when) of the last refusal
        # Signs the answers to silent (up=false) probes; never a credential key.
        self._probe_key = ec.generate_private_key(ec.SECP256R1())

    # -- plumbing ---------------------------------------------------------------

    def handle(self, data, ctx=None):
        """One CTAPHID_CBOR request -> response bytes (status || CBOR)."""
        ctx = ctx or Ctx()
        if not data:
            return bytes([ERR_INVALID_LENGTH])
        cmd = data[0]
        handlers = {
            CMD_MAKE_CREDENTIAL: self.make_credential,
            CMD_GET_ASSERTION: self.get_assertion,
            CMD_GET_INFO: self.get_info,
            CMD_CLIENT_PIN: self.client_pin,
            CMD_RESET: self.reset,
            CMD_GET_NEXT_ASSERTION: self.get_next_assertion,
            CMD_CRED_MGMT: self.cred_mgmt,
            CMD_CRED_MGMT_PRE: self.cred_mgmt,
            CMD_SELECTION: self.selection,
        }
        h = handlers.get(cmd)
        if h is None:
            return bytes([ERR_INVALID_COMMAND])
        if cmd != CMD_GET_NEXT_ASSERTION:
            self._next = None
        if cmd not in (CMD_CRED_MGMT, CMD_CRED_MGMT_PRE):
            self._cm = None
        params = {}
        if len(data) > 1:
            try:
                params = cbor.decode(data[1:], max_depth=6)
            except cbor.CBORTypeError:
                return bytes([ERR_CBOR_UNEXPECTED_TYPE])
            except cbor.CBORError:
                return bytes([ERR_INVALID_CBOR])
            if not isinstance(params, dict):
                return bytes([ERR_CBOR_UNEXPECTED_TYPE])
        try:
            with self.lock:
                resp = h(params, ctx)
        except CtapError as e:
            log.info("command 0x%02x: %s", cmd, e)
            return bytes([e.code])
        except BackendError as e:
            log.error("key backend: %s", e)
            return bytes([ERR_OTHER])
        return b"\x00" + (cbor.encode(resp) if resp is not None else b"")

    @staticmethod
    def request_digest(*parts):
        """A digest that names one request (command, RP, client data, credential list)."""
        h = hashlib.sha256()
        for part in parts:
            b = part if isinstance(part, bytes) else str(part).encode()
            h.update(len(b).to_bytes(4, "big") + b)
        return h.digest()

    def _replayed_refusal(self, prompt, request):
        if request is None or self._refused is None:
            return
        digest, when = self._refused
        now = self.clock()
        if digest == request and now - when <= REFUSAL_REPLAY_WINDOW:
            log.info("%s: repeat of a request Touch ID refused %.1f s ago; "
                     "refused again without a new prompt", prompt.title(), now - when)
            raise CtapError(ERR_OPERATION_DENIED, "repeat of a refused request")

    def _outcome(self, ctx, result, request):
        """Raise the CTAP error for a result that is not a match; remember refusals."""
        if result in (touchid.NO_MATCH, touchid.LOCKED) and request is not None:
            self._refused = (request, self.clock())
        elif result == touchid.MATCH:
            self._refused = None
            return
        if ctx.cancel.is_set() or result == touchid.CANCELLED:
            raise CtapError(ERR_KEEPALIVE_CANCEL, "cancelled")
        if result == touchid.TIMEOUT:
            raise CtapError(ERR_USER_ACTION_TIMEOUT, "no touch")
        raise CtapError(ERR_OPERATION_DENIED, f"Touch ID: {result}")

    def ask(self, ctx, prompt, request=None):
        """An enclave-checked Touch ID approval that signs nothing for an RP (presence key).

        request: request_digest() of the operation; a replay of one that was
        just refused is refused again at once (REFUSAL_REPLAY_WINDOW).
        """
        self._replayed_refusal(prompt, request)
        result = self.user.verify(prompt, ctx.cancel, ctx.on_up_needed)
        self._outcome(ctx, result, request)
        return "touchid"

    def _gated(self, ctx, prompt, cred, op, request=None):
        self._replayed_refusal(prompt, request)
        try:
            result, value = op(prompt, ctx.cancel, ctx.on_up_needed)
        except InvalidHandle as e:
            # The enclave refused the key itself: made by another SEP or
            # install, or a touchid-current key after an enrolment change.
            raise CtapError(ERR_INVALID_CREDENTIAL, str(e)) from e
        self._outcome(ctx, result, request)
        return value

    def _gated_sign(self, ctx, prompt, cred, msg, request=None):
        """The credential's signature over msg: the enclave waits for the finger."""
        digest = hashlib.sha256(msg).digest()
        return self._gated(ctx, prompt, cred,
                           lambda *a: self.user.sign(cred.handle, digest, *a), request)

    def _gated_unseal(self, ctx, prompt, cred, request=None):
        """The credential's sealed hmac-secret CredRandom pair, released after a match."""
        return self._gated(ctx, prompt, cred,
                           lambda *a: self.user.unseal(cred.handle, cred.sealed, *a), request)

    def _probe_sign(self, msg):
        return self._probe_key.sign(msg, ec.ECDSA(hashes.SHA256()))

    def _pin_protocol(self, params, key):
        v = _need(params, key, int)
        p = pinuv.PROTOCOLS.get(v)
        if p is None:
            raise CtapError(ERR_INVALID_PARAMETER, "pinUvAuthProtocol")
        return p

    def _usable(self, cred, rp_id):
        """False for a credential made before the enclave checked the touch."""
        if cred.legacy is None and self.backend.gated(cred.handle):
            return True
        why = cred.legacy or "its key has no enclave access-control list"
        log.warning("refused a credential for %s: %s. Register this key with %s again",
                    rp_id, why, rp_id)
        self.on_legacy(rp_id, why)
        return False

    # -- getInfo -------------------------------------------------------------------

    def get_info(self, _params, _ctx):
        ext = ["credProtect"] + (["hmac-secret"] if self.backend.can_unseal else [])
        return {
            1: ["U2F_V2", "FIDO_2_0", "FIDO_2_1"],
            2: ext,
            3: AAGUID,
            4: {"rk": True, "up": True, "uv": True, "plat": False,
                "credMgmt": True, "credentialMgmtPreview": True,
                "pinUvAuthToken": True, "makeCredUvNotRqd": True},
            5: 7609,
            6: [2, 1],
            7: 16,
            8: ID_MAX_CTAP2,
            9: ["usb"],
            0x0A: [{"type": "public-key", "alg": keys.ES256}],
            0x0E: 1,
            0x14: self.store.remaining(),
        }

    # -- makeCredential --------------------------------------------------------------

    def make_credential(self, p, ctx):
        cdh = _need(p, 1, bytes)
        rp = _need(p, 2, dict)
        user = _need(p, 3, dict)
        algs = _need(p, 4, list)
        exclude = _check_descriptor_list(p.get(5), 5)
        ext = p.get(6, {})
        opts = _options(p, 7)
        auth_param = p.get(8)
        if not isinstance(ext, dict):
            raise CtapError(ERR_CBOR_UNEXPECTED_TYPE, "extensions")
        rp_id = rp.get("id")
        if not isinstance(rp_id, str):
            raise CtapError(ERR_MISSING_PARAMETER if rp_id is None
                            else ERR_CBOR_UNEXPECTED_TYPE, "rp.id")
        uid = user.get("id")
        if not isinstance(uid, bytes):
            raise CtapError(ERR_MISSING_PARAMETER if uid is None
                            else ERR_CBOR_UNEXPECTED_TYPE, "user.id")
        if len(uid) > 64:
            raise CtapError(ERR_INVALID_LENGTH, "user.id")
        if len(cdh) != 32:
            raise CtapError(ERR_INVALID_LENGTH, "clientDataHash")
        if p.get(0x0A) is not None:
            raise CtapError(ERR_INVALID_PARAMETER, "enterprise attestation")

        es256 = False
        for a in algs:
            if not isinstance(a, dict) or not isinstance(a.get("type"), str) \
                    or not isinstance(a.get("alg"), int):
                raise CtapError(ERR_CBOR_UNEXPECTED_TYPE, "pubKeyCredParams")
            if a["type"] == "public-key" and a["alg"] == keys.ES256:
                es256 = True
        if not es256:
            raise CtapError(ERR_UNSUPPORTED_ALGORITHM)

        if opts.get("up") is False:
            raise CtapError(ERR_INVALID_OPTION, "up=false in makeCredential")
        rk = opts.get("rk", False)
        rp_hash = _rp_hash(rp_id)
        prompt = touchid.Prompt("register", rp_id, user_line(user))

        # pinUvAuthParam: empty = "touch to select" probe from old platforms.
        if auth_param is not None:
            if not isinstance(auth_param, bytes):
                raise CtapError(ERR_CBOR_UNEXPECTED_TYPE, "pinUvAuthParam")
            if not auth_param:
                self.ask(ctx, touchid.Prompt("select", rp_id))
                raise CtapError(ERR_PIN_NOT_SET)
            proto = self._pin_protocol(p, 9)
            ok = self.token.check(proto, cdh, auth_param, pinuv.PERM_MC, rp_id)
            if ok is None:
                raise CtapError(ERR_PIN_AUTH_INVALID, "token permission or RP")
            if not ok:
                raise CtapError(ERR_PIN_AUTH_INVALID)

        cred_protect = ext.get("credProtect")
        if cred_protect is not None and cred_protect not in (1, 2, 3):
            cred_protect = None
        hmac_secret = ext.get("hmac-secret") is True and self.backend.can_unseal

        for cid in exclude:
            if self.vault.unwrap(rp_hash, cid) is not None:
                self.ask(ctx, touchid.Prompt("register", rp_id,
                                             "This key is already registered here"))
                self.token.consumed_by_mc_ga()
                raise CtapError(ERR_CREDENTIAL_EXCLUDED)

        if rk and self.store.remaining() <= 0:
            raise CtapError(ERR_KEY_STORE_FULL)

        # The new key, with the enclave's access-control list. It signs
        # nothing without a finger, so making it needs no approval; the
        # approval is its first signature below.
        policy, flags = self.policy, self.flags
        site = self.policy_for(rp_id) if self.policy_for else None
        if site is not None and site != policy:
            policy, flags = site, POLICY_FLAGS[site]
            if flags & ~self.backend.flags_supported:
                # Never a weaker key than the site's rule asks for.
                log.warning("site rule for %s asks for a policy this kernel cannot make", rp_id)
                raise CtapError(ERR_UNSUPPORTED_OPTION, "site policy")
        handle, point = self.backend.create(flags)
        sealed = None
        if hmac_secret:
            # CredRandomWithUV || CredRandomWithoutUV, released by the
            # enclave only together with a touch-approved signature.
            sealed = self.backend.seal(handle, os.urandom(64))
        cred = Credential(handle, cred_protect or 1, policy, sealed)
        cred_id = self.vault.wrap(rp_hash, cred, ID_MAX_CTAP2)

        ext_out = {}
        if cred_protect:
            ext_out["credProtect"] = cred_protect
        if hmac_secret:
            ext_out["hmac-secret"] = True
        flags = FLAG_UP | FLAG_UV | FLAG_AT | (FLAG_ED if ext_out else 0)
        auth_data = (rp_hash + bytes([flags]) + struct.pack(">I", self.counter.next())
                     + AAGUID + struct.pack(">H", len(cred_id)) + cred_id
                     + keys.encode_cose_es256(point)
                     + (cbor.encode(ext_out) if ext_out else b""))

        # One touch: the enclave signs the attestation (or, with
        # attestation = none, the same bytes as a check) only after a match.
        sig = self._gated_sign(ctx, prompt, cred, auth_data + cdh,
                               self.request_digest("mc", rp_hash, cdh, uid,
                                                   sorted(opts.items())))
        if not verify_es256(point, auth_data + cdh, sig):
            raise BackendError("the new key's signature does not verify")
        if auth_param is not None:
            self.token.consumed_by_mc_ga()

        if rk:
            ok = self.store.put({
                "rpId": rp_id, "rpIdHash": rp_hash, "rpName": _trunc(rp.get("name")),
                "userId": uid, "userName": _trunc(user.get("name")),
                "displayName": _trunc(user.get("displayName")),
                "credId": cred_id, "pub": point, "credProtect": cred.cred_protect,
            })
            if not ok:
                raise CtapError(ERR_KEY_STORE_FULL)

        if self.attestation == "none":
            fmt, att = "none", {}
        else:
            fmt, att = "packed", {"alg": keys.ES256, "sig": sig}
        log.info("registered %s credential for %s", "discoverable" if rk else "a", rp_id)
        return {1: fmt, 2: auth_data, 3: att}

    # -- getAssertion ----------------------------------------------------------------

    def get_assertion(self, p, ctx):
        rp_id = _need(p, 1, str)
        cdh = _need(p, 2, bytes)
        allow = _check_descriptor_list(p.get(3), 3)
        ext = p.get(4, {})
        opts = _options(p, 5)
        auth_param = p.get(6)
        if not isinstance(ext, dict):
            raise CtapError(ERR_CBOR_UNEXPECTED_TYPE, "extensions")
        if len(cdh) != 32:
            raise CtapError(ERR_INVALID_LENGTH, "clientDataHash")
        if "rk" in opts:
            raise CtapError(ERR_UNSUPPORTED_OPTION, "rk in getAssertion")
        up = opts.get("up", True)
        uv = opts.get("uv", False)
        rp_hash = _rp_hash(rp_id)

        if auth_param is not None:
            if not isinstance(auth_param, bytes):
                raise CtapError(ERR_CBOR_UNEXPECTED_TYPE, "pinUvAuthParam")
            if not auth_param:
                self.ask(ctx, touchid.Prompt("select", rp_id))
                raise CtapError(ERR_PIN_NOT_SET)
            proto = self._pin_protocol(p, 7)
            ok = self.token.check(proto, cdh, auth_param, pinuv.PERM_GA, rp_id)
            if not ok:
                raise CtapError(ERR_PIN_AUTH_INVALID)
            # The token asks for UV. Its UV is the enclave's touch at the
            # signature, so a silent (up=false) request with it stays silent.
            uv = up

        # Every signature with up (or uv) is a touch the enclave checks, so a
        # request that will be signed that way counts as verified when
        # deciding which credProtect levels are visible.
        touch = up or uv

        found = []
        legacy = 0
        if allow:
            for cid in allow:
                c = self.vault.unwrap(rp_hash, cid)
                if c is None:
                    continue
                if not self._usable(c, rp_id):
                    legacy += 1
                    continue
                if c.cred_protect == 3 and not touch:
                    continue
                found.append((cid, c, self.store.find(cid)))
                break
        else:
            for rec in self.store.for_rp(rp_hash):
                c = self.vault.unwrap(rp_hash, rec["credId"])
                if c is None:
                    continue
                if not self._usable(c, rp_id):
                    legacy += 1
                    continue
                if c.cred_protect >= 2 and not touch:
                    continue
                found.append((rec["credId"], c, rec))
        if not found:
            raise CtapError(ERR_NO_CREDENTIALS,
                            "only credentials made before the enclave checked Touch ID"
                            if legacy else "")

        hs = ext.get("hmac-secret")
        state = {"rp_id": rp_id, "rp_hash": rp_hash, "cdh": cdh, "touch": touch, "up": up,
                 "hs": hs, "rest": found[1:], "total": len(found), "t": self.clock(),
                 "request": self.request_digest("ga", rp_hash, cdh, sorted(opts.items()),
                                                *(allow or ()))}
        resp = self._assertion(found[0], state, ctx, first=True)
        # CTAP 2.1/2.2 getAssertion: the token's flags and permissions are used up
        # only when the response carries UP. A silent pre-flight (up=false, as
        # Firefox sends before the real request) must leave the token usable.
        if auth_param is not None and touch:
            self.token.consumed_by_mc_ga()
        if len(found) > 1:
            self._next = state
        return resp

    def _hmac_secret(self, hs, secret):
        """The hmac-secret output from the enclave-released CredRandom (UV half)."""
        if not isinstance(hs, dict):
            raise CtapError(ERR_INVALID_PARAMETER, "hmac-secret input")
        proto = pinuv.PROTOCOLS.get(hs.get(4, 1))
        if proto is None:
            raise CtapError(ERR_INVALID_PARAMETER, "hmac-secret protocol")
        ka, salt_enc, salt_auth = hs.get(1), hs.get(2), hs.get(3)
        if not isinstance(ka, dict) or not isinstance(salt_enc, bytes) \
                or not isinstance(salt_auth, bytes):
            raise CtapError(ERR_MISSING_PARAMETER, "hmac-secret input")
        try:
            shared = self.key_agreement.shared_secret(proto, ka)
        except ValueError as e:
            raise CtapError(ERR_INVALID_PARAMETER, "hmac-secret key agreement") from e
        if not proto.verify(shared, salt_enc, salt_auth):
            raise CtapError(ERR_PIN_AUTH_INVALID, "hmac-secret saltAuth")
        try:
            salts = proto.decrypt(shared, salt_enc)
        except ValueError as e:
            raise CtapError(ERR_INVALID_LENGTH, "hmac-secret salt") from e
        if len(salts) not in (32, 64):
            raise CtapError(ERR_INVALID_LENGTH, "hmac-secret salt")
        # Every enclave signature has UV, so the UV half of the pair is used.
        key = secret[:32]
        out = b"".join(hmac.new(key, salts[i:i + 32], hashlib.sha256).digest()
                       for i in range(0, len(salts), 32))
        return proto.encrypt(shared, out)

    def _assertion(self, item, state, ctx, first):
        cid, cred, rec = item
        touch = state["touch"]
        hs = state["hs"]
        prompt = touchid.Prompt("sign-in", state["rp_id"],
                                _account_line(rec) if state["total"] > 1 else "")
        ext_out = {}
        if hs is not None:
            if not touch or cred.sealed is None or not self.backend.can_unseal:
                log.info("hmac-secret for %s: not available (no touch, or a credential "
                         "made without it)", state["rp_id"])
            else:
                # The output goes into the signed authData, so the enclave
                # releases the secret first (one touch) and signs after (the
                # second): no secret leaves the enclave without a match.
                secret = self._gated_unseal(ctx, prompt, cred, state["request"])
                ext_out["hmac-secret"] = self._hmac_secret(hs, secret)
                prompt = touchid.Prompt("sign-in", state["rp_id"], "Touch ID again to finish")
        flags = (FLAG_UP if touch and state["up"] else 0) | (FLAG_UV if touch else 0) \
            | (FLAG_ED if ext_out else 0)
        auth_data = (state["rp_hash"] + bytes([flags])
                     + struct.pack(">I", self.counter.next())
                     + (cbor.encode(ext_out) if ext_out else b""))
        if touch:
            sig = self._gated_sign(ctx, prompt, cred, auth_data + state["cdh"],
                                   state["request"])
        else:
            sig = self._probe_sign(auth_data + state["cdh"])
        resp = {1: {"type": "public-key", "id": cid}, 2: auth_data, 3: sig}
        if rec is not None:
            u = {"id": rec["userId"]}
            if touch and state["total"] > 1:
                for k, rk in (("name", "userName"), ("displayName", "displayName")):
                    if rec.get(rk):
                        u[k] = rec[rk]
            resp[4] = u
        if first and state["total"] > 1:
            resp[5] = state["total"]
        return resp

    def get_next_assertion(self, _p, ctx):
        st = self._next
        if not st or not st["rest"] or self.clock() - st["t"] > NEXT_ASSERTION_WINDOW:
            self._next = None
            raise CtapError(ERR_NOT_ALLOWED)
        item = st["rest"].pop(0)
        st["t"] = self.clock()
        return self._assertion(item, st, ctx, first=False)

    # -- clientPIN -----------------------------------------------------------------

    def client_pin(self, p, ctx):
        sub = _need(p, 2, int)
        if sub == 0x02:     # getKeyAgreement
            self._pin_protocol(p, 1)
            return {1: self.key_agreement.cose()}
        if sub == 0x07:     # getUVRetries
            return {5: self.user.max_tries}
        if sub == 0x06:     # getPinUvAuthTokenUsingUvWithPermissions
            proto = self._pin_protocol(p, 1)
            ka = _need(p, 3, dict)
            perms = _need(p, 9, int)
            rp_id = _need(p, 0x0A, str, required=False)
            if perms == 0:
                raise CtapError(ERR_INVALID_PARAMETER, "no permissions")
            if perms & ~pinuv.SUPPORTED_PERMS:
                raise CtapError(ERR_UNAUTHORIZED_PERMISSION)
            if perms & (pinuv.PERM_MC | pinuv.PERM_GA) and rp_id is None:
                raise CtapError(ERR_MISSING_PARAMETER, "rpId")
            try:
                shared = self.key_agreement.shared_secret(proto, ka)
            except ValueError as e:
                raise CtapError(ERR_INVALID_PARAMETER, "keyAgreement") from e
            self.token.reset()
            if perms & ~(pinuv.PERM_MC | pinuv.PERM_GA):
                # Credential management signs nothing an RP could check, so
                # its token takes an enclave-checked touch now (presence key).
                self.ask(ctx, touchid.Prompt("manage", rp_id))
                self.token.begin(perms, rp_id)
            else:
                # makeCredential / getAssertion: each signature waits for its
                # own enclave-checked touch, so the token carries no UV and
                # the one touch happens at the signature, not twice.
                self.token.begin(perms, rp_id, verified=False)
            return {2: proto.encrypt(shared, self.token.value)}
        if sub in (0x01, 0x03, 0x04, 0x05, 0x09):
            # getPINRetries, setPIN, changePIN, getPinToken, ...UsingPin: no PIN.
            raise CtapError(ERR_PIN_NOT_SET if sub in (0x01, 0x05, 0x09)
                            else ERR_INVALID_SUBCOMMAND)
        raise CtapError(ERR_INVALID_SUBCOMMAND)

    # -- reset / selection -------------------------------------------------------------

    def reset(self, _p, ctx):
        if self.clock() - self.started > RESET_WINDOW:
            raise CtapError(ERR_NOT_ALLOWED, "reset only within 10 s of start")
        if self.new_vault is None:
            raise CtapError(ERR_NOT_ALLOWED, "reset not configured")
        self.ask(ctx, touchid.Prompt("reset", None,
                                     "Every passkey and security-key credential "
                                     "made with this Mac stops working"))
        self.store.wipe()
        self._refused = None
        self.vault, self.store = self.new_vault()
        self.token.reset()
        self.key_agreement.regenerate()
        log.warning("authenticator reset: all credentials invalidated")
        return None

    def selection(self, _p, ctx):
        self.ask(ctx, touchid.Prompt("select", None))
        return None

    # -- credentialManagement ------------------------------------------------------------

    def cred_mgmt(self, p, ctx):
        sub = _need(p, 1, int)
        sub_params = p.get(2)
        if sub in (0x03, 0x05):
            return self._cm_next(sub)
        if sub not in (0x01, 0x02, 0x04, 0x06, 0x07):
            raise CtapError(ERR_INVALID_SUBCOMMAND)
        proto = self._pin_protocol(p, 3)
        auth = _need(p, 4, bytes)
        msg = bytes([sub]) + (cbor.encode(sub_params) if sub_params is not None else b"")
        ok = self.token.check(proto, msg, auth, pinuv.PERM_CM)
        if ok is None:
            raise CtapError(ERR_PIN_AUTH_INVALID, "token lacks cm permission")
        if not ok:
            raise CtapError(ERR_PIN_AUTH_INVALID)
        if sub in (0x04, 0x06, 0x07) and not isinstance(sub_params, dict):
            raise CtapError(ERR_MISSING_PARAMETER, "subCommandParams")

        if sub == 0x01:
            if self.token.rp_id is not None:
                raise CtapError(ERR_PIN_AUTH_INVALID, "token bound to an RP")
            return {1: self.store.count(), 2: self.store.remaining()}

        if sub == 0x02:
            if self.token.rp_id is not None:
                raise CtapError(ERR_PIN_AUTH_INVALID, "token bound to an RP")
            rps = {}
            for r in self.store.all():
                rps.setdefault(r["rpIdHash"], r)
            if not rps:
                raise CtapError(ERR_NO_CREDENTIALS)
            items = [({"id": r["rpId"], **({"name": r["rpName"]} if r.get("rpName") else {})},
                      h) for h, r in rps.items()]
            self._cm = ("rp", items[1:])
            return {3: items[0][0], 4: items[0][1], 5: len(items)}

        if sub == 0x04:
            rp_hash = sub_params.get(1)
            if not isinstance(rp_hash, bytes):
                raise CtapError(ERR_MISSING_PARAMETER, "rpIDHash")
            self._token_rp_matches(rp_hash)
            recs = self.store.for_rp(rp_hash)
            if not recs:
                raise CtapError(ERR_NO_CREDENTIALS)
            self._cm = ("cred", recs[1:])
            out = self._cm_cred(recs[0])
            out[9] = len(recs)
            return out

        desc = sub_params.get(2)
        if not isinstance(desc, dict) or not isinstance(desc.get("id"), bytes):
            raise CtapError(ERR_MISSING_PARAMETER, "credentialId")
        rec = self.store.find(desc["id"])
        if rec is None:
            raise CtapError(ERR_NO_CREDENTIALS)
        self._token_rp_matches(rec["rpIdHash"])
        if sub == 0x06:
            self.store.delete(rec["credId"])
            log.info("deleted a discoverable credential for %s", rec["rpId"])
            return None
        user = sub_params.get(3)
        if not isinstance(user, dict) or user.get("id") != rec["userId"]:
            raise CtapError(ERR_INVALID_PARAMETER, "user.id must not change")
        rec["userName"] = _trunc(user.get("name"))
        rec["displayName"] = _trunc(user.get("displayName"))
        self.store.put(rec)
        return None

    def _token_rp_matches(self, rp_hash):
        if self.token.rp_id is not None and _rp_hash(self.token.rp_id) != rp_hash:
            raise CtapError(ERR_PIN_AUTH_INVALID, "token bound to another RP")

    def _cm_cred(self, rec):
        u = {"id": rec["userId"]}
        if rec.get("userName"):
            u["name"] = rec["userName"]
        if rec.get("displayName"):
            u["displayName"] = rec["displayName"]
        return {6: u, 7: {"type": "public-key", "id": rec["credId"]},
                8: keys.cose_es256(rec["pub"]), 0x0A: rec.get("credProtect", 1)}

    def _cm_next(self, sub):
        want = "rp" if sub == 0x03 else "cred"
        if not self._cm or self._cm[0] != want or not self._cm[1]:
            self._cm = None
            raise CtapError(ERR_NOT_ALLOWED)
        item = self._cm[1].pop(0)
        if want == "rp":
            return {3: item[0], 4: item[1]}
        return self._cm_cred(item)


def _account_line(rec):
    if not rec:
        return ""
    name = rec.get("displayName") or rec.get("userName")
    return f"as {name}" if name else ""


def user_line(user):
    name = user.get("displayName") or user.get("name")
    return f"as {name}" if isinstance(name, str) and name else ""


def verify_es256(point, msg, der_sig):
    """Test helper: True when der_sig is a valid ES256 signature of msg."""
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    try:
        pub.verify(der_sig, msg, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False
