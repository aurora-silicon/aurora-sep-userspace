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
  owns credentials here (owners.json lists every uid that made one).

Credentials made before owners were recorded carry no uid. They belong to
one account, the "legacy owner", fixed once when this version first opens an
existing store: the only account with prints in /var/lib/fprint. With none
or several such accounts it stays unassigned, those credentials are refused
to everyone (status says so) until root names the owner with
`aurora-fido adopt-legacy USER`.

File owners.json (root-only, in the state dir):
  {"version": 1, "legacy_store": bool, "legacy": uid or null, "uids": [uid, ...]}
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
    out = set()
    try:
        names = os.listdir(root)
    except OSError:
        return []
    for name in names:
        top = os.path.join(root, name)
        if os.path.islink(top) or not os.path.isdir(top):
            continue
        has_print = any(files for _d, _s, files in os.walk(top))
        if not has_print:
            continue
        try:
            out.add(pwd.getpwnam(name).pw_uid)
        except KeyError:
            continue
    return sorted(out)


class Owners:
    def __init__(self, state_dir, current=seat_uid, fprint_dir=FPRINT_DIR):
        self.path = os.path.join(state_dir, FILE)
        self.current = current          # () -> uid of the request, or None
        self.legacy_store = False
        self.legacy = None
        self.uids = set()
        self.damaged = False
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
            return True
        self.legacy_store = bool(d.get("legacy_store"))
        legacy = d.get("legacy")
        self.legacy = legacy if isinstance(legacy, int) and legacy >= 0 else None
        self.uids = {u for u in d["uids"] if isinstance(u, int) and u >= 0}
        return True

    def _first_open(self, state_dir, fprint_dir):
        # A store made by an older version (it has a master secret already)
        # holds credentials without an owner.
        self.legacy_store = os.path.exists(os.path.join(state_dir, "master.sep"))
        if self.legacy_store:
            accounts = fprint_accounts(fprint_dir)
            if len(accounts) == 1:
                self.legacy = accounts[0]
                log.info("credentials made before owners were recorded belong to uid %d "
                         "(the only account with prints)", self.legacy)
        self.save()

    def save(self):
        if self.damaged:
            return                  # keep the damaged file for root to look at
        d = {"version": 1, "legacy_store": self.legacy_store, "legacy": self.legacy,
             "uids": sorted(self.uids)}
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

    def add(self, uid):
        if uid not in self.uids:
            self.uids.add(uid)
            self.save()

    def others(self, uid):
        """True when an account other than uid owns (or may own) credentials here."""
        if self.damaged or any(u != uid for u in self.uids):
            return True
        return self.legacy_store and self.legacy != uid

    def cleared(self):
        """After a reset: nobody's credentials are left."""
        self.legacy_store, self.legacy, self.uids = False, None, set()
        self.save()

    def adopt(self, uid):
        """Give the credentials without a recorded owner to uid (root, by hand)."""
        self.legacy_store, self.legacy, self.damaged = True, uid, False
        self.save()
