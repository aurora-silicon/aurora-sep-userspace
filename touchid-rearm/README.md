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
   locked. It goes on when Touch ID is locked, or when the driver sets
   `SEP_BIO_LOCKOUT_FLAG_EVERY_PASSWORD` and either failed matches are
   pending or the caller is root (sudo, gdm, polkit, login). Otherwise it
   answers at once and checks nothing, so a user's own programs get no
   password oracle here. When it goes on, it checks that the caller is root
   or that user, that the user has enrolled prints, and that the password
   verifies through its own PAM service (pam_unix alone). Only then does it
   pass that password in a `SEP_BIO_REARM` call on `/dev/sep-bio-rearm`;
   both userspace and the kernel wipe their temporary copies after the
   request. Without a lockout the call clears pending failed matches, as a
   password does on macOS, and restarts the driver's password clock: Touch
   ID asks for the password again when it has not been used for 156 hours
   and Touch ID has not unlocked for 4 hours, or when nothing has unlocked
   for 48 hours. Drivers without the flag wait for a running capture in
   that call, so the helper calls them only for a lockout.

5. On the first password re-arm, the driver creates a Linux-owned
   FileVault-style KEK/VEK record pair bound to the stable stored Linux
   identity-bag secret and a private Linux FV domain identifier. It proves the
   pair with an option-2 FV unwrap before committing it atomically to the
   existing Linux host-state store. Later re-arms reuse the pair. The returned
   opaque key is wiped without leaving the driver.
6. After the successful unwrap, the driver shows the enclave the stored keybag
   secret again to create a new SCRD match credential, then saves the enclave's
   lockout record. Matching works again only when the unwrap and SCRD steps
   both succeed.

Before installing a build which can provision this pair, back up all Linux SEP
and fingerprint state while the SEP driver and fprintd are stopped. Preserve
`/var/lib/aurora-sep*`, `/var/lib/apple-sep-*`, and `/var/lib/fprint` with
ownership, modes, xattrs and SELinux labels. Store the archive outside those
paths, record its SHA-256, restart the services, and keep the archive until the
new re-arm has passed its finger test. Restoring requires booting the previous
kernel, stopping the same services, restoring the complete set together, and
rebooting with the same `apple_sep.os_uuid_hi/lo` identity.

## Touch ID after a restart

macOS does not take Touch ID after a restart until the password has been
entered once, and neither does Aurora by default. The login screen, lock
screen or `sudo` then says "Your password is required to enable Touch ID."
and asks for the password; Touch ID works after it. To have Touch ID from
the first login instead, set it in `/etc/aurora/touchid.conf`:

    # yes (default, also when the line is missing): the first login or
    #      unlock after boot needs the password, as on macOS.
    # no:  Touch ID works from the first login after boot.
    require_password_after_boot = no

`aurora-touchid-boot.service` reads it once per boot, before the display
manager, user sessions and fprintd start. With `yes` (or no setting) it runs
`aurora-touchid-rearm --boot`, which asks the driver
(`SEP_BIO_REQUIRE_PASSWORD`) to refuse every verify, without a capture,
until the first password authentication; that password reaches the driver
through the same path as a lockout's (steps 3 and 4), and Touch ID works
from then on. Until then pam_fprintd goes straight to the password. Any
value other than `yes` or `no` counts as `yes`. A kernel without the ioctl
keeps Touch ID working from the first login and says so in the journal. The
setting applies from the next boot.

`aurora-touchid-rearm --status` (root) prints what the driver reports:

    locked: waits for the first password since boot
    password after boot: yes

The wait is the host's, kept in the driver's memory only: the enclave is
not involved, and a restart starts over from the setting.

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
| `aurora-touchid-boot.service` | systemd unit; enable it (without it Touch ID works from the first login whatever the setting) |
| `touchid.conf` | `/etc/aurora/touchid.conf` |
| `aurora-touchid-rearm.pam` | `/usr/lib/pam.d/aurora-touchid-rearm` (or `/etc/pam.d`) |
| `rearm-proto.h` | the request and answer format |
| `tests/` | `make check`: real libpam stacks with stand-ins for pam_unix and pam_fprintd, a fake device, and the service started per connection |

The SELinux policy (the `aurora_touchid_rearm_t` domain and the device and
record labels) is in the `aurora_sep` module the distribution packages ship.

## Checking it

    journalctl -k | grep -E 'locked|re-armed'
    journalctl -t aurora-touchid-rearm

Neo install bundles must be built for AArch64. `make bundle` checks the ELF
machine of both the helper and PAM module before installing them into the
archive, and refuses a stale staging directory or archive. Cross builds should
pass their AArch64 compiler and matching `READELF`; the expected machine name
defaults to `AArch64`.
