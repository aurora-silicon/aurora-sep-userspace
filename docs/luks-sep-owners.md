# Volume owners, password changes and recovery (FileVault model)

`aurora-sep-fde` unlocks a LUKS2 volume with a user's password, checked by the Mac's Secure Enclave (SEP). This page covers several users on one volume, who may manage the others, what happens when a password changes, and the recovery key. The unlock path itself is in [luks-sep.md](luks-sep.md) and [luks-sep-initrd.md](luks-sep-initrd.md).

## The model, next to macOS

| macOS (FileVault on Apple silicon) | aurora-sep-fde |
| --- | --- |
| Each user with a secure token has their own wrapped copy of the volume key. | Each user has their own LUKS2 keyslot. Its secret is sealed by the SEP under that user's key bag, which only their password unlocks. |
| Volume owners (secure-token admins, the first user) can add and remove users and approve changes. | A user token marked *owner* may add, remove and reset other users and change who is an owner. root and members of the admin groups (`wheel`, `sudo`, `admin`) become owners when they are added. |
| A standard user with a secure token can unlock and change their own password, nothing else. | An *unlock only* user can unlock and change their own password. Every change to someone else is refused. |
| Granting a secure token needs an existing secure-token user's password. | Every change needs an owner's password. The SEP checks it by opening that owner's token. The secret it yields is the existing key LUKS2 needs to add a keyslot. |
| The user keybag is shared by all of a user's volumes. Changing the password re-wraps it, and the old password stops working. | One key bag per user per Mac. A password change re-wraps it once in the SEP and writes the new wrapped bag to every registered volume. The old password stops opening any of them. |
| Only a secure-token admin can reset another user's FileVault password. A reset without one leaves FileVault on the old password. | `passwd`, GNOME Settings and other PAM password changes update the disk password through `pam_aurora_sep_fde`. A root reset without the old password cannot re-wrap anything, because the SEP needs the old password, so the disk keeps the old one and the module says so. An owner then runs `reset-password`. |
| Personal recovery key: 24 characters, opens the volume and resets a password. | Same format and roles. A choice, like Touch ID after boot: `recovery = offline` (the default, also with no `fde.conf`) or `--offline` also adds a plain keyslot for it, so a Mac whose SEP cannot answer never locks its owner out. `recovery = sep-only` or `--sep-only` keeps every unlock inside the SEP, as FileVault does. `recovery --replace` makes a new key and removes the old one, which is also how an existing key switches between the two. |
| FileVault keeps one volume key per volume; another macOS install on the same Mac cannot open it. | Each sealed secret is bound to the OS install it was enrolled under (the key store OS identity: the `apple_sep.os_uuid` pin, else `/chosen/apfs-preboot-uuid`). Another install on the same Mac gets "this disk key belongs to another OS install" and falls back to the recovery key's offline keyslot or a passphrase. `status` shows the install each token was made under. |
| Failed passwords are counted by the SEP. | Failed passwords are counted by the SEP per bag. A right password clears the count. |

## Commands

All of them run as root. `--auth-user` defaults to the user who ran `sudo`.

    # Installer, or the first user: an existing LUKS passphrase adds the first owner.
    aurora-sep-fde enroll --user alice --unlock-key-file /run/installer-pass /dev/nvme0n1p5

    # An owner adds users. Admins (wheel) become owners and others unlock only.
    # --owner and --no-owner override that.
    sudo aurora-sep-fde add-user --user bob /dev/nvme0n1p5      # asks for alice's, then bob's password
    sudo aurora-sep-fde add-user --user carol --no-owner /dev/nvme0n1p5

    sudo aurora-sep-fde set-owner --user carol --owner /dev/nvme0n1p5
    sudo aurora-sep-fde remove-user --user bob /dev/nvme0n1p5   # never the last owner

    # Password change, on every registered volume. passwd and GNOME do this through PAM.
    aurora-sep-fde change-password --user alice

    # Forgotten password: an owner, or the recovery key, sets a new one.
    sudo aurora-sep-fde reset-password --user carol /dev/nvme0n1p5
    aurora-sep-fde reset-password --user carol --recovery-key-file key.txt /dev/nvme0n1p5

    aurora-sep-fde recovery --unlock-key-file /run/installer-pass /dev/nvme0n1p5   # offline keyslot too (default)
    aurora-sep-fde recovery --sep-only --unlock-key-file /run/installer-pass /dev/nvme0n1p5
    # A new recovery key (and the old one removed), authorized by an owner's password:
    sudo aurora-sep-fde recovery --replace --offline /dev/nvme0n1p5
    aurora-sep-fde remove-passphrase --unlock-key-file /run/installer-pass /dev/nvme0n1p5
    aurora-sep-fde status            # policy, OS install, every registered volume: owners, users, SEP attempt counts
    aurora-sep-fde boot-chain        # what the initramfs boot-chain check decides on this boot

`/etc/aurora-sep/fde-volumes` lists the volumes the tool manages. `enroll`, `add-user` and `recovery` add to it. `sync --user U` writes the bag the SEP holds to every listed volume, which repairs a volume whose header could not be written during a change.

## Configuration: /etc/aurora-sep/fde.conf

    recovery = offline          # or sep-only
    boot-chain = warn           # or require
    admin-groups = wheel sudo admin
    bag-uid-base = 60000        # SEP key bag uid = base + Linux uid

`boot-chain` is checked by the token plugin in the initramfs, before it asks the SEP for a volume key (the root volume). It reads `/sys/firmware/aurora/boot_security/state` (`verified`, `partial`, `unverified`; absent on kernels without the boot record). `warn`, the default, logs one line per boot when the chain is not verified and unlocks anyway. `require` leaves the volume to its passphrase or recovery key unless the chain is verified from Stage 1 on; set it only on a Mac with an enforcing Stage 1 and a signed UKI, or every boot will ask for the passphrase. Dracut and mkinitcpio copy `fde.conf` into the image; rebuild it after a change.

No value depends on the Mac model. The bag uid base keeps disk-encryption bags away from the uids other SEP users of the same Mac use.

## PAM

    password optional pam_aurora_sep_fde.so

This line goes after the module that changes the account password, so it runs only after that change succeeded. Fedora's aurora-sep package adds it to the authselect vendor profile's system-auth, ALARM's aurora-sep-luks to `/etc/pam.d/system-auth` (which `passwd` includes), and NixOS through `aurora.sepLuks.passwordSync` on `security.pam.services.passwd`. The module passes the old and new password to `/usr/libexec/aurora-sep-fde-passwd` on a pipe and never logs them.

## What it relies on and what it does not give

- **Owner rights are enforced by the tool. They are not a cryptographic property.** Any user who can unlock holds a secret that LUKS2 accepts for adding keyslots, and root can write a LUKS2 header directly. The same is true of FileVault, whose owner rules are enforced by macOS. What the SEP does enforce is that no change is possible without some enrolled user's password, and that every guess is counted.
- **Wrong-user attempts.** systemd asks for one password. The token plugin tries it on each user token in turn, so when bob unlocks, a token ahead of his counts a failed attempt on that user's bag. A right password clears that user's count. macOS avoids this by having the user pick their account first. A per-token password hint would avoid it here at the cost of leaking hint bits to anyone holding the header, so it is not done.
- **One install per key.** The OS-install binding is enforced by the kernel, on the OS identity the boot names. With an unsigned kernel command line, root on that install can pin another identity; on the signed-UKI path the command line is signed.
- **Old header copies.** The SEP accepts an older wrapped bag on import. Someone with a copy of the header from before a password change can still open it with the old password. FileVault stores the bag generation in effaceable storage. Linux has no such store yet.
- **Counter across reboots.** The SEP's count lives in the loaded bag. After a reboot the bag is loaded again from the header, which does not record the count.
- **No bag delete.** The SEP keeps a bag until reboot. A reset while the old bag is loaded moves the user to the next bag generation (bag uid + n × 1000000).
- **Macs whose xART guard is on (J616s, M2, M3)** cannot unlock user bags in the initrd. Their root volume asks for the recovery key or a passphrase at boot until the guard design lands. Volumes opened after boot work on every Mac with a SEP.

## Tests

`make -C luks check` runs `tests/test-owners.sh` (owners, a non-owner refused, change on two volumes, the PAM hook, a reset by an owner and by the recovery key, both recovery modes, the attempt counter, damaged tokens), `tests/test-policy.sh` (recovery mode default, `fde.conf` and flags, `--replace`, the OS-install binding and the `os_uuid` pin, `boot-chain` warn/require/absent) and `tests/test-fde.sh` against the file-backed SEP double. `tests/vm/run-all.sh` boots dracut initramfs images in a VM and enters passwords at the prompt, including a second owner's and a changed one.
