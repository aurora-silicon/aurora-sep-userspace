# Touch ID key bag tied to the login password (design draft)

**Status: design prototype. Do not package.** It needs the kernel ioctls on
aurora-silicon/linux branch `design/sep-user-keybag`, and three of the
enclave messages behind them are not captured yet. Without them the lock,
the password change and the state read answer "unsupported".

Today the Secure Enclave key bag behind Touch ID is opened at boot with a
secret stored on disk, and nothing ever closes it, so root holds everything
and the screen lock protects nothing at the enclave level. This directory
sketches the userspace half of the macOS model:

- **At login and at the lock screen**, `pam_aurora_userbag` (placed right
  after `pam_unix`) passes the password that was just accepted, once, to
  `aurora-userbag-helper`, which opens the user's bag with it. The enclave
  does the check, mixing the password with its own device key. Nothing is
  stored.
- **On screen lock, sleep and logout**, `aurora-userbag-lockd` follows
  logind (`LockedHint`, `Lock`, `PrepareForSleep`, `SessionRemoved`) and asks
  the kernel to lock the bag: after a grace period for the screen lock, at
  once for sleep and logout.
- **On a password change**, the module's `password` hook passes the old and
  new password so the bag can be re-keyed.

A fingerprint never opens a bag the rules keep closed: pam_fprintd sets no
password, so the module does nothing. The kernel decides when Touch ID may
be offered (after the first password since boot, within 48 h of an unlock,
fewer than five failed matches, and the 156 h / 4 h rule).

## PAM placement (Fedora system-auth / password-auth)

    auth     [success=ok new_authtok_reqd=ok default=2]  pam_unix.so <args>
    -auth    optional                                    pam_aurora_userbag.so
    auth     sufficient                                  pam_permit.so
    ...
    password sufficient                                  pam_unix.so <args>   # becomes:
    password [success=ok default=bad]                    pam_unix.so <args>
    -password optional                                   pam_aurora_userbag.so
    password sufficient                                  pam_permit.so

The same three-line shape as the lockout re-arm (`pam_aurora_touchid`). Both
modules can sit side by side, and once this lands the re-arm becomes part of
the unlock.

## Files

| file | what it is |
| --- | --- |
| `pam_aurora_userbag.c` | the PAM module (auth + password); always `PAM_IGNORE` |
| `aurora-userbag-helper.c` | per-connection root helper; caller must be root or the user; locked memory, wiped |
| `aurora-userbag-lockd.c` | logind follower that sends the locks; never sees a password |
| `userbag-proto.h` | socket request and answer format |
| `userbag-uapi.h` | build copy of the draft kernel ioctls |
| `*.socket`, `*.service` | systemd units |
| `tests/test_helper.py` | request checks without a device (`make check`) |

Still open: the SELinux domain (it should follow `aurora_touchid_rearm_t`),
the logout uid tracking in lockd, and reading the desktop's own "require
password after" delay instead of `GraceSeconds=`.
