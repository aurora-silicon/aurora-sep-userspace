# Truncated SEP host-state store

The `apple_sep` driver keeps the Linux host state Touch ID needs (the
identity bag, the FileVault-style record pair a password re-arm provisions,
the SCRD match credential bookkeeping) in a copy-on-write store at
`/var/lib/aurora-sep-host-state.bin`: a 72-block file, one 0x8000-byte
superblock followed by 71 slot blocks.

A power cut while the driver writes that file can leave a **prefix** of it.
The driver refuses any file whose size is not the full store and does not
reinitialise it, because the short file may be the only copy of the host
state. That is the right call for the driver, but it means Touch ID stays
dead across reboots until someone looks at the file: the loader fails the
store validation, no enrolment survives, and every unlock asks for the
password.

`aurora-sep-host-state-repair` runs at boot, before `aurora-sep.service`
loads `apple_sep`, and decides what the prefix is:

| what the file is | what happens |
| --- | --- |
| the full 2359296 bytes | left untouched, not even read past the size |
| empty, or all zero and shorter than a store | left to the driver, which initialises it |
| a short prefix whose superblock validates and whose used slots all end inside the file | copied to the quarantine, then zero-extended back to the full size |
| anything else, including a file that is longer than a store | left in place, unchanged; the driver keeps refusing it, so Touch ID stays off, and the journal says so with the command that resets it (below) |

A short file is normally a prefix cut off during a write, and the
superblock, rewritten in place first, survives the cut: extending the file
back to full size with zero bytes preserves exactly the state the
superblock names. The validation mirrors `Store::decode` in
`drivers/soc/apple/store.rs` — magic, version, geometry, reserved bytes,
slot entries (used flag, kind, length, reserved tail), duplicate keys and
the copy-on-write intent — and the extension only happens when every slot
the superblock names ends inside the file. Anything the format does not
accept is never written, copied or removed at boot.

The driver cannot shorten a full-size store through its own writes, so a
short file whose superblock does not validate, or whose used slot ends past
the cut, is not what a power cut leaves. The helper does not turn it into a
reset of the host state on its own: it leaves the file where it is and logs
a warning, and an administrator decides.

Before the store is changed (zero-extended, or reset by hand), a copy goes
to `/var/lib/aurora-sep-quarantine` (mode 0700, file mode 0600, unique
timestamped names), byte for byte. The directory keeps the newest two
copies, the one just made and the one before it; older copies are old host
states and are deleted. A copy can be restored by copying it back while the
SEP driver is not loaded.

## Resetting a refused store

When the journal shows `left /var/lib/aurora-sep-host-state.bin in place,
unchanged`, the store is not one the driver can use. To start over with
an empty host state:

    sudo /usr/libexec/aurora-sep-host-state-repair --reset

and reboot. `--reset` copies the store to the quarantine and removes it, so
the driver creates a fresh store at the next boot; Touch ID enrolments and
the password re-arm record then have to be set up again. It refuses a store
of the full size. (The path is the install's `LIBEXECDIR`; the log line
names it.)

## Installing

    make -C host-state && sudo make -C host-state install

The unit orders itself before `aurora-sep.service` — the loader shipped
with the kernel in `tools/aurora-sep/` — and is preset-enabled, so the
repair runs on every boot that has a store to look at. NixOS enables it
through the `nixos-aurora` module instead of presets. Distributions that
do not use presets can enable it by hand:

    systemctl enable aurora-sep-host-state-repair.service

`AURORA_SEP_HOST_STATE` and `AURORA_SEP_QUARANTINE` override the store and
the quarantine directory, for tests and unusual installs.

## Testing

    make -C host-state check

builds synthetic stores — a repairable prefix, a slot cut off mid-value,
every kind of refused superblock, a store cut inside its slot table, a file
that is too long — and checks the repair's decision against the driver's
format rules, that a refused store is left unchanged, `--reset`, and that
the quarantine keeps only the newest two copies. The NixOS version of
this helper has also run on a real truncated store: an M1 whose store was
cut to 98430 bytes by a power cut. The prefix was preserved in the
quarantine, Touch ID worked again after the repair, and the enrolled
finger kept matching afterwards.

## Licensing

MIT (`../LICENSES/MIT.txt`). The kernel's `store.rs`, whose validation
this mirrors, is `GPL-2.0-only OR MIT`.
