# aurora-sep-userspace

Fedora packaging of libfprint for Apple Touch ID on Aurora Silicon kernels.

The kernel side is the `apple_sep` driver in
[aurora-silicon/linux](https://github.com/aurora-silicon/linux) (`aurora-wip`).
It exposes the fingerprint sensor as the `/dev/sep-bio` misc device, and its ioctl
ABI is `include/uapi/linux/apple-sep.h` (interface version 4). The enclave does all
of the matching, so no image, template or key material ever reaches userspace.

Hardware: Apple silicon Macs with Touch ID that the `apple_sep` driver supports.
It is developed on the MacBook Neo (J700, A18 Pro).

## What is here

`libfprint/` holds Fedora's `libfprint-1.94.100-1.fc45` spec, rebuilt as
`libfprint-1.94.100-1.fc45.aurora2` with the `aurora` driver. The build replaces
Fedora's libfprint in place, so fprintd needs no `LD_LIBRARY_PATH` and nothing is
installed under `/usr/local`. The package provides `libfprint(aurora-sep) = 4`.

| file | what it is |
| --- | --- |
| `libfprint.spec` | Fedora's spec, with a release suffix that sorts above the Fedora build it replaces |
| `libfprint-1.94.100-apple-sep.patch` | the `aurora` driver and the misc-device udev subtype it needs, unchanged from `tools/aurora-sep/patches/` in aurora-silicon/linux at commit `3b2bd35a8591` (blob `bdb15bb1`); this repository maintains it from now on |
| `0002-aurora-report-unusable-captures-as-retries.patch` | reports unusable captures (kernel status RETRY) as libfprint retries during enrolment, verify and identify, so fprintd asks for another touch; fails a rejected enrolment with a reason |
| `apple-sep.h` | a build-time copy of the kernel UAPI header, because distribution kernel headers do not ship it yet |

The system integration lives next to the kernel driver in aurora-silicon/linux,
`tools/aurora-sep/`. That covers the loader and `aurora-sep.service`, fprintd's
device policy, Touch ID activation at boot, the power-button setting and the
optional GNOME login-screen fingerprint. It is packaged there as `aurora-sep`.
Install both packages together.

## Build

On Fedora 45 (aarch64):

    dnf download --source libfprint          # libfprint-1.94.100-1.fc45.src.rpm
    rpm -i libfprint-1.94.100-1.fc45.src.rpm
    cp libfprint/* ~/rpmbuild/SOURCES/
    cp libfprint/libfprint.spec ~/rpmbuild/SPECS/
    dnf builddep ~/rpmbuild/SPECS/libfprint.spec
    rpmbuild -ba ~/rpmbuild/SPECS/libfprint.spec

## Install

    sudo dnf install ./libfprint-1.94.100-1.fc45.aurora2.aarch64.rpm ./aurora-sep-*.noarch.rpm
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
- `libfprint/libfprint.spec` is derived from Fedora's spec for libfprint. Fedora
  package specs are MIT (`LICENSES/MIT.txt`), and so are our changes to it.
- `libfprint/apple-sep.h` is the kernel UAPI header,
  `GPL-2.0 WITH Linux-syscall-note OR MIT` (`LICENSES/GPL-2.0-only.txt`,
  `LICENSES/Linux-syscall-note.txt`, `LICENSES/MIT.txt`).
- Everything else here is MIT.
