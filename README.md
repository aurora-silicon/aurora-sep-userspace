# aurora-sep-userspace

Fedora packaging of libfprint for Apple Touch ID on Aurora Silicon kernels, and
SEP-sealed LUKS2 unlock (`luks/`).

The kernel side is the `apple_sep` driver in
[aurora-silicon/linux](https://github.com/aurora-silicon/linux) (`aurora-wip`).
It exposes the fingerprint sensor as the `/dev/sep-bio` misc device, and its ioctl
ABI is `include/uapi/linux/apple-sep.h` (interface versions 4 and 5). The enclave does all
of the matching, so no image, template or key material ever reaches userspace.

Hardware: Apple silicon Macs with Touch ID that the `apple_sep` driver supports.
It is developed on the MacBook Neo (J700, A18 Pro).

## What is here

`libfprint/` holds Fedora's `libfprint-1.94.100-1.fc45` spec, rebuilt as
`libfprint-1.94.100-1.fc45.aurora9` with the `aurora` driver. The build replaces
Fedora's libfprint in place, so fprintd needs no `LD_LIBRARY_PATH` and nothing is
installed under `/usr/local`. The package provides both `libfprint(aurora-sep) = 4` and `= 5`.

| file | what it is |
| --- | --- |
| `libfprint.spec` | Fedora's spec, with a release suffix that sorts above the Fedora build it replaces |
| `libfprint-1.94.100-apple-sep.patch` | the `aurora` driver and the misc-device udev subtype it needs, unchanged from `tools/aurora-sep/patches/` in aurora-silicon/linux at commit `3b2bd35a8591` (blob `bdb15bb1`); this repository maintains it from now on |
| `0002-aurora-report-unusable-captures-as-retries.patch` | reports unusable captures (kernel status RETRY) as libfprint retries during enrolment, verify and identify, so fprintd asks for another touch; fails a rejected enrolment with a reason |
| `0003-hide-lid-covered-readers-while-the-lid-is-closed.patch` | the Touch ID sensor is in the power button, which a closed lid covers: libfprint drops the reader while the lid is closed and probes it again when it opens (details below) |
| `0004-aurora-refuse-unbound-enrollment.patch` | resolves the Unix account and finger, prepares an empty Linux owner context, maps persistence refusals, avoids full-slot garbage collection, and logs single-verify and identify-gallery UUID mismatches |
| `0007-aurora-name-retry-causes-and-keep-waiting.patch` | maps the kernel's retry cause (`guidance` next to a retry: CENTER, TOO_FAST, CLEAN, LIFT_AND_MOVE) onto `FP_DEVICE_RETRY_CENTER_FINGER`, `_TOO_FAST`, `_REMOVE_FINGER`, so fprintd shows a specific prompt; starts the match again silently after a no-finger capture timeout (>= 5 s), as a macOS prompt keeps waiting |
| `0006-aurora-report-finger-lift-and-lockout.patch` | reports `SEP_BIO_GUIDANCE_LIFT` (the last touch's finger is still down; the kernel arms the next capture when it is lifted) as finger present, and names the Touch ID lockout status (8) in failures |
| `0005-aurora-support-v4-and-v5.patch` | accepts only v4 and v5, uses the 136-byte legacy enrol request on v4 and the 144-byte account-bound request plus PREPARE_ENROL on v5; v5 errors never fall back to v4 |
| `aurora_fprintd_lid.te` | SELinux policy permitting fprintd to read the lid switch |
| `fprintd-aurora-touchid.conf` | fprintd drop-in: `DeviceAllow=/dev/sep-bio rw` for the reader, and `DeviceAllow=char-input r` so libfprint can read the lid switch (a deliberate widening: fprintd can read every input device) |
| `apple-sep.h` | a build-time copy of the kernel UAPI header, because distribution kernel headers do not ship it yet |

The system integration lives next to the kernel driver in aurora-silicon/linux,
`tools/aurora-sep/`. That covers the loader and `aurora-sep.service`, fprintd's
device policy, Touch ID activation at boot, the power-button setting and the
optional GNOME login-screen fingerprint. It is packaged there as `aurora-sep`.
Install both packages together.

`fprintd/` contains a Fedora 45 fprintd 1.94.5 spec and patch. The patch
rejects an unknown Aurora target account before fprintd's duplicate check,
requires an explicit delete before re-enrolling the same finger, and makes all
three delete methods keep the host record when device deletion fails, with
virtual-device regression tests. This is a required companion package:
libfprint reports the device error, but stock fprintd 1.94.5 still deletes its
own file. Build the patched fprintd RPM after the aurora libfprint RPM, then
install both before relying on failed-delete recovery.
`fprintd/0002-report-lockout-and-fall-back-to-the-password.patch` reports
`FP_DEVICE_ERROR_LOCKED_OUT` as the new verify result `verify-lockout`; pam_fprintd
then tells the user to use the password and returns at once.
`fprintd/test_account_gate.py` compiles the patched account gate with a
fake passwd lookup and covers missing entries, lookup errors, invalid uid and
name mismatch without a device operation.
The spec is based on [Fedora's f45 fprintd spec](https://src.fedoraproject.org/rpms/fprintd/blob/f45/f/fprintd.spec);
the patch targets [fprintd v1.94.5](https://gitlab.freedesktop.org/libfprint/fprintd/-/tags/v1.94.5).

## Touch ID lockout

`touchid-rearm/` ends a Touch ID lockout after a password authentication, as
macOS does: a PAM module straight after pam_unix and a root service that checks
the password again before it asks the driver to re-arm. See
[touchid-rearm/README.md](touchid-rearm/README.md). `make -C touchid-rearm check`
tests it against real libpam stacks.
It also applies the "Touch ID after a restart" setting (`/etc/aurora/touchid.conf`,
`require_password_after_boot`): by default, as on macOS, the first login or unlock
after boot needs the password; `no` gives Touch ID from the first login.

## SEP-sealed LUKS2 unlock

`luks/` holds `aurora-sep-cryptenroll` and the libcryptsetup token plugin
`libcryptsetup-token-aurora-sep.so`. Together they unlock a LUKS2 volume with
this Mac's Secure Enclave, the way `systemd-cryptenroll --tpm2-device=auto`
does with a TPM, and keep the passphrase keyslot for recovery. The keyslot
secret is wrapped with AES-256-CCM by a kernel `trusted` key that the
`apple_sep` driver seals, and the AES key stays in the kernel (AF_ALG by key
serial). Nothing is enrolled by default. See [docs/luks-sep.md](docs/luks-sep.md).

    make -C luks && sudo make -C luks install
    make -C luks check      # kernel user keys stand in for the SEP

It needs libcryptsetup (2.4 or newer, with external tokens) and json-c. The
checks need root on kernels with `af_alg_restrict`, which let only
CAP_SYS_ADMIN or CAP_NET_ADMIN bind `ccm(aes)` through AF_ALG.
`luks/tests/hw-loop-test.sh` is the hardware test on a loop file.

## Clamshell mode

With the lid closed nobody can touch the sensor, so the reader is not offered:
fprintd lists no device, `sudo`, `pkexec` and other polkit prompts go straight to
the password with no fingerprint prompt and no wait, and lock screens that ask
fprintd for a reader (GNOME Shell, hyprlock, Omarchy's) find none. When the lid
opens the reader is probed again and fprintd exports it (`InterfacesAdded`)
within a fraction of a second; the next request offers the fingerprint. A
fingerprint prompt still waiting when the lid closes ends at once
(`verify-disconnected`), the enclave operation is cancelled, and PAM moves on to
the password.

libfprint follows every input device that reports `SW_LID` (on the J700 the
"Apple SMC power/lid events" device of `macsmc-input`) and reads its state with
`EVIOCGSW`; a machine without a lid switch is unaffected. The behaviour lives
in libfprint, so it is the same on every distribution that installs this build
of it; Omarchy's `libfprint-git` carries the same patch.

A lock screen already on screen when the lid opens picks the reader up the next
time it asks fprintd for one: GNOME when the prompt is reset (for example after
Escape), hyprlock on its next start or resume, Omarchy's lock on its next retry
or user activity.

## Build

On Fedora 45 (aarch64):

    dnf download --source libfprint          # libfprint-1.94.100-1.fc45.src.rpm
    rpm -i libfprint-1.94.100-1.fc45.src.rpm
    cp libfprint/* ~/rpmbuild/SOURCES/
    cp libfprint/libfprint.spec ~/rpmbuild/SPECS/
    dnf builddep ~/rpmbuild/SPECS/libfprint.spec
    rpmbuild -ba ~/rpmbuild/SPECS/libfprint.spec

For the patched fprintd, install the aurora libfprint build and its devel
package in the Fedora build environment, then:

    rpm -i fprintd-1.94.5-*.src.rpm
    cp fprintd/* ~/rpmbuild/SOURCES/
    cp fprintd/fprintd.spec ~/rpmbuild/SPECS/
    dnf builddep ~/rpmbuild/SPECS/fprintd.spec
    rpmbuild -ba ~/rpmbuild/SPECS/fprintd.spec

## Install

    sudo dnf install ./libfprint-1.94.100-1.fc45.aurora9.aarch64.rpm ./fprintd-1.94.5-99.fc45.aurora1.aarch64.rpm ./fprintd-pam-1.94.5-99.fc45.aurora1.aarch64.rpm ./aurora-sep-*.noarch.rpm
    sudo dnf versionlock add libfprint

Reboot afterwards to apply the package and unit changes. The SEP driver attaches
to the enclave once per boot; follow the kernel loader's instructions and reboot
rather than reloading `apple_sep` or restarting its loader. During an existing
desktop session, defer the fprintd and display-manager switch until that reboot. Read `tools/aurora-sep/XART-SAFETY.md` in the kernel tree
before you enable Touch ID on a machine that also runs macOS. Keep the SEP OS
identity used for existing Linux enrolments on the kernel command line
(`apple_sep.os_uuid_hi=` and `apple_sep.os_uuid_lo=`). Without an explicit identity,
the kernel uses `/chosen/apfs-preboot-uuid` when available. On the current Aurora
bootloader this selects the Aurora volume identity: changing to it can make
existing Linux enrolments inaccessible. It does not select the macOS identity.
Keep the existing identity throughout a userspace-only migration.

A Fedora update to a newer libfprint release replaces this build. Rebuild on
top of it, or keep the version lock.

## Licensing

- The libfprint patches are LGPL-2.1-or-later, like libfprint itself
  (`LICENSES/LGPL-2.1-or-later.txt`).
- The fprintd patch is GPL-2.0-or-later, like fprintd
  (`LICENSES/GPL-2.0-or-later.txt`).
- `fprintd/fprintd.spec` is derived from Fedora's MIT-licensed package spec
  (`LICENSES/MIT.txt`).
- `libfprint/libfprint.spec` is derived from Fedora's spec for libfprint. Fedora
  package specs are MIT (`LICENSES/MIT.txt`), and so are our changes to it.
- `libfprint/apple-sep.h` is the kernel UAPI header,
  `GPL-2.0 WITH Linux-syscall-note OR MIT` (`LICENSES/GPL-2.0-only.txt`,
  `LICENSES/Linux-syscall-note.txt`, `LICENSES/MIT.txt`).
- `luks/` is MIT.
- Everything else here is MIT.

## Qualification

The [v4/v5 hardware test plan](docs/sep-v5-test-plan.md) covers existing enrolments,
new enrolment persistence, verification and rollback before the kernel hold is removed.
