# Touch ID lockout and re-arm

After too many failed matches the Secure Enclave stops matching. macOS then
asks for the password, and the password ends the lockout. With the
`apple_sep` driver the same happens:

1. The enclave answers MATCH_RESULT with status 0x1. The driver ends the
   verify with `SEP_BIO_STATUS_LOCKOUT` and refuses every later verify at
   once, without a capture. It records the lockout in
   `/var/lib/aurora-sep-touchid-lockout.bin`, so a restart does not hand
   out a fresh set of attempts.
2. libfprint reports `FP_DEVICE_ERROR_LOCKED_OUT`, fprintd reports
   `verify-lockout`, and pam_fprintd says "Too many failed fingerprint
   attempts. Use your password." and lets the stack ask for the password.
3. The PAM stack accepts the password. `pam_aurora_touchid`, straight
   after pam_unix, hands the user and password to `aurora-touchid-rearm`.
4. `aurora-touchid-rearm` (root, started per connection by
   `aurora-touchid-rearm.socket`) asks the driver whether Touch ID is
   locked. If it is not, it answers at once and checks nothing. If it is,
   it checks that the caller is root or that user, that the user has
   enrolled fingerprints, and that the password verifies through its own
   PAM service (pam_unix alone). Only then does it call `SEP_BIO_REARM` on
   `/dev/sep-bio-rearm`.
5. The driver shows the enclave the stored keybag secret again (a new SCRD
   match credential), as macOS does with the passcode, and matching works
   again.

A fingerprint never re-arms Touch ID: pam_fprintd sets no password, so the
module does nothing. The module always returns `PAM_IGNORE`, so it never
changes a stack's result, and it never prompts. Lock screens that run PAM as
the user, such as Plasma's, go through the socket like everything else.

## Where the module goes

Straight after pam_unix, and reached only when pam_unix accepted the
password. Where pam_unix is `sufficient`, that takes three lines in its
place:

    auth  [success=ok new_authtok_reqd=ok default=2]  pam_unix.so <its arguments>
    -auth optional                                    pam_aurora_touchid.so
    auth  sufficient                                  pam_permit.so

That behaves as `sufficient pam_unix.so` did: a success ends the stack with
success (or with `PAM_NEW_AUTHTOK_REQD`), a failure goes on to the lines
after it. The leading `-` skips the module if it is not installed.
Where pam_unix falls through on success, as in Arch's `system-auth`, the
module goes after the last auth line.

## Files

| file | installed as |
| --- | --- |
| `pam_aurora_touchid.c` | `pam_aurora_touchid.so` in the PAM module directory |
| `aurora-touchid-rearm.c` | `/usr/libexec/aurora-touchid-rearm` |
| `aurora-touchid-rearm.socket`, `aurora-touchid-rearm@.service` | systemd units; enable the socket |
| `aurora-touchid-rearm.pam` | `/usr/lib/pam.d/aurora-touchid-rearm` (or `/etc/pam.d`) |
| `rearm-proto.h` | the request and answer format |
| `tests/` | `make check`: real libpam stacks with stand-ins for pam_unix and pam_fprintd, a fake device, and the service started per connection |

The SELinux policy (the `aurora_touchid_rearm_t` domain and the device and
record labels) is in the `aurora_sep` module the distribution packages ship.

## Checking it

    journalctl -k | grep -E 'locked|re-armed'
    journalctl -t aurora-touchid-rearm
