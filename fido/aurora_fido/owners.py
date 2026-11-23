# SPDX-License-Identifier: MIT
"""Which Unix account each credential of the system vault belongs to.

With `[authenticator] vault = system` one daemon keeps the credentials of
every account on this Mac. The Secure Enclave cannot tell the accounts
apart: every Linux enrolment is under one enclave user, so any enrolled
finger satisfies any credential's access-control list. So the daemon keeps
them apart itself:

- A request is made for the user who owns the active local session on
  seat0. That is the user the hidraw node's `uaccess` ACL follows (the same
  user `vault = user` forwards requests to). uhid does not tell the daemon
  which process opened the hidraw node, so the seat is the only identity it
  has. With no active local user session, nothing but getInfo is answered.
- A new credential records that uid inside its credential ID (encrypted and
  authenticated under the master secret, creds.py). A credential is found,
  listed, used or deleted only for its own uid; for every other user it
  looks unknown.
- Reset deletes every credential, so it is refused while any other account
  owns credentials here (owners.json lists every uid that made one, added
  when its first credential is finished, that is, after the touch matched).
- A uid is listed with the account name it had. When the uid has another
  name now, or none (the account was removed, or the uid was given to a new
  account), it is not the account that made those credentials: its requests
  are refused, and it still counts for the reset rule. Nothing is deleted or
  reassigned on its own.

Credentials made before owners were recorded carry no uid. They belong to
one account, the "legacy owner", fixed once when this version first opens an
existing store: the only account with prints in /var/lib/fprint. With none
or several such accounts it stays unassigned, those credentials are refused
to everyone (status says so) until root names the owner with
`aurora-fido adopt-legacy USER`.

A damaged owners.json is never guessed at: nobody gets the ownerless
credentials and reset stays refused. adopt-legacy repairs the first part
only; "owners_unknown" stays set (the uids that made credentials are not
known any more), so reset stays refused until `aurora-fido disable --forget`.

File owners.json (root-only, in the state dir):
  {"version": 1, "legacy_store": bool, "legacy": uid or null, "uids": [uid, ...],
   "names": {"uid": account name, ...}, "owners_unknown": bool}
"""

import json
import logging
import os
import pwd

from . import creds, touchid

log = logging.getLogger("aurora-fido")

FILE = "owners.json"
FPRINT_DIR = "/var/lib/fprint"


def seat_uid():
    u = touchid.seat_user()
    return u[1] if u else None


def fprint_accounts(root=FPRINT_DIR):
    """uids of the accounts that have at least one stored print (fprintd keeps
    them in <root>/<user name>/...). Names with no passwd entry are skipped."""
    return sorted(fprint_names(root))


def fprint_names(root=FPRINT_DIR):
    """{uid: account name} of the accounts with at least one stored print."""
    out = {}
    try:
        names = os.listdir(root)
    except OSError:
        return {}
    for name in names:
        top = os.path.join(root, name)
        if os.path.islink(top) or not os.path.isdir(top):
            continue
        has_print = any(files for _d, _s, files in os.walk(top))
        if not has_print:
            continue
        try:
            pw = pwd.getpwnam(name)
        except KeyError:
            continue
        out[pw.pw_uid] = pw.pw_name
    return out


def account_name(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return None


class Owners:
    def __init__(self, state_dir, current=seat_uid, fprint_dir=FPRINT_DIR,
                 name_of=account_name):
        self.path = os.path.join(state_dir, FILE)
        self.current = current          # () -> uid of the request, or None
        self.name_of = name_of          # uid -> the account's name now, or None
        self.legacy_store = False
        self.legacy = None
        self.uids = set()
        self.names = {}                 # uid -> account name when it was recorded
        self._gone_logged = set()
        self.damaged = False
        self.owners_unknown = False
        if not self._load():
            self._first_open(state_dir, fprint_dir)

    def _load(self):
        try:
            with open(self.path) as f:
                d = json.load(f)
        except FileNotFoundError:
            return False
        except (OSError, ValueError):
            d = None
        if not (isinstance(d, dict) and d.get("version") == 1
                and isinstance(d.get("uids"), list)):
            # Never guess owners from a damaged file: nobody gets the
            # ownerless credentials, and reset stays refused.
            log.error("%s is damaged: credentials made before owners were recorded are "
                      "refused, and reset is refused", self.path)
            self.legacy_store, self.legacy, self.damaged = True, None, True
            self.owners_unknown = True
            return True
        self.legacy_store = bool(d.get("legacy_store"))
        legacy = d.get("legacy")
        self.legacy = legacy if isinstance(legacy, int) and legacy >= 0 else None
        self.uids = {u for u in d["uids"] if isinstance(u, int) and u >= 0}
        names = d.get("names")
        if isinstance(names, dict):
            self.names = {int(u): n for u, n in names.items()
                          if u.isdigit() and isinstance(n, str)}
        self.owners_unknown = bool(d.get("owners_unknown"))
        return True

    def _first_open(self, state_dir, fprint_dir):
        # A store made by an older version (it has a master secret already)
        # holds credentials without an owner.
        self.legacy_store = os.path.exists(os.path.join(state_dir, "master.sep"))
        if self.legacy_store:
            accounts = fprint_names(fprint_dir)
            if len(accounts) == 1:
                # Named from the passwd entry just found, not by another lookup
                # that could fail and leave it without a name.
                (self.legacy, name), = accounts.items()
                self.names[self.legacy] = name
                log.info("credentials made before owners were recorded belong to uid %d "
                         "(the only account with prints)", self.legacy)
        self.save()

    def save(self):
        if self.damaged:
            return                  # keep the damaged file for root to look at
        d = {"version": 1, "legacy_store": self.legacy_store, "legacy": self.legacy,
             "uids": sorted(self.uids),
             "names": {str(u): n for u, n in sorted(self.names.items())},
             "owners_unknown": self.owners_unknown}
        creds.atomic_write(self.path, json.dumps(d, indent=1).encode() + b"\n")

    @property
    def legacy_unassigned(self):
        return self.legacy_store and self.legacy is None

    def owns(self, uid, cred_owner):
        """True when the credential (its recorded owner, or None) belongs to uid."""
        if uid is None:
            return False
        if cred_owner is None:
            return self.legacy_store and self.legacy == uid
        return cred_owner == uid

    def _name(self, uid):
        name = self.name_of(uid)
        if name is None:
            self.names.pop(uid, None)
        else:
            self.names[uid] = name

    def add(self, uid, name=None):
        """uid has made a credential here (call it when the credential is
        finished). name: its account name as looked up for the request (else
        it is looked up now)."""
        if uid not in self.uids:
            self.uids.add(uid)
            if uid != self.legacy:
                if name is None:
                    self._name(uid)
                else:
                    self.names[uid] = name
            self.save()

    def gone(self, uid, now=None):
        """True when credentials here were made for uid by an account that had
        another name than uid has now (now: that name, if looked up already):
        the account they belong to is gone."""
        if uid not in self.uids and not (self.legacy_store and self.legacy == uid):
            return False
        was = self.names.get(uid)
        if now is None:
            now = self.name_of(uid)
        if was is not None and was == now:
            return False
        if uid not in self._gone_logged:
            self._gone_logged.add(uid)
            log.warning("uid %d is %s now, and its credentials here were made by %s: "
                        "requests for it are refused (docs: Accounts)", uid,
                        repr(now) if now else "no account",
                        repr(was) if was else "an account whose name was not recorded")
        return True

    def others(self, uid):
        """True when an account other than uid owns (or may own) credentials here."""
        if self.damaged or self.owners_unknown or any(u != uid for u in self.uids):
            return True
        return self.legacy_store and self.legacy != uid

    def cleared(self):
        """After a reset: nobody's credentials are left."""
        self.legacy_store, self.legacy, self.uids = False, None, set()
        self.names = {}
        self.owners_unknown = False
        self.save()

    def adopt(self, uid, name=None):
        """Give the credentials without a recorded owner to uid (root, by hand;
        name: its account name, else looked up)."""
        self.legacy_store, self.legacy, self.damaged = True, uid, False
        if uid not in self.uids:
            if name is None:
                self._name(uid)
            else:
                self.names[uid] = name
        self.save()
