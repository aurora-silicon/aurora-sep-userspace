# Unlocking LUKS2 volumes with the Secure Enclave

`aurora-sep-cryptenroll` lets a LUKS2 volume unlock without a passphrase on the Mac it was enrolled on. It works like `systemd-cryptenroll --tpm2-device=auto`, with the Mac's Secure Enclave (SEP) in place of a TPM. Nothing is enabled by default. You enroll the volumes you want.

## How it works

Enrolling adds one keyslot with a random 64-byte secret. That secret is stored in an `aurora-sep` LUKS2 token, encrypted with AES-256-CCM. The AES key is a kernel `trusted` key sealed by the SEP through the `apple_sep` driver, so the token only holds a blob that this Mac's SEP can open. The AES key itself never reaches userspace: the kernel uses it by keyring reference through AF_ALG.

At unlock, `cryptsetup` and `systemd-cryptsetup` load `libcryptsetup-token-aurora-sep.so`, which asks the SEP to unseal the blob and hands the secret to libcryptsetup. If the SEP refuses, you get the normal passphrase prompt.

Your passphrase keyslot stays. The tool refuses to remove the last keyslot that is not bound to the SEP, so a recovery path always exists.

## Requirements

- An Aurora kernel with `apple_sep` and its trusted-key source (the kernel log shows `trusted-keys: registering "trusted" key type backed by the SEP ref-key seal`).
- The SEP key store set up on this Linux install: `/var/lib/aurora-sep-keybag.bin` and `/var/lib/aurora-sep-refkey.bin`, which the `apple_sep` driver creates and keeps. Don't delete or move them.
- cryptsetup 2.4 or newer with external token support (`cryptsetup --help` lists a token plugin path).
- The kernel's AF_ALG interface for root with `ccm(aes)`: `/proc/sys/crypto/af_alg_restrict` at 0 or 1 (1 is the default). Setting it to 2 turns this off.

Check with:

    keyctl add trusted test "new 32" @u && keyctl unlink %trusted:test @u

## Enroll a volume

    sudo aurora-sep-cryptenroll /dev/disk/by-uuid/<LUKS UUID>

It asks for an existing passphrase (or takes `--unlock-key-file=` or `$PASSWORD`), seals a new secret, adds the keyslot and token, and proves the token opens the volume before it finishes.

systemd-cryptsetup tries the token first. The SEP driver starts once `/var/lib` is mounted (aurora-sep.service runs after local-fs.target), so a volume that local-fs.target itself waits for would get the passphrase prompt. Open SEP volumes on first use instead:

    # /etc/crypttab
    data UUID=<LUKS UUID> none luks,noauto
    # /etc/fstab
    /dev/mapper/data /data ext4 noauto,x-systemd.automount,nofail 0 2

The plugin waits up to 60 seconds for the SEP key store (`AURORA_SEP_WAIT` changes that).

To open by hand: `sudo cryptsetup open /dev/... data`.

## Check, re-enroll, remove

    sudo aurora-sep-cryptenroll --status /dev/...
    sudo aurora-sep-cryptenroll --test /dev/...
    sudo aurora-sep-cryptenroll --wipe-slot=sep /dev/...   # new enrolment, old one removed
    sudo aurora-sep-cryptenroll --remove /dev/...

A recovery key in the systemd style works next to it: `systemd-cryptenroll --recovery-key /dev/...`.

## What it is bound to

The sealed key opens only on the same Mac, under the same Linux SEP OS identity (`apple_sep.os_uuid_hi`/`_lo` on the kernel command line) and with the same SEP key store files. It falls back to the passphrase when:

- the volume is moved to another Mac;
- the SEP OS identity changes, for example the pin is dropped from the boot entry or Linux is reinstalled;
- `/var/lib/aurora-sep-keybag.bin` or `/var/lib/aurora-sep-refkey.bin` is lost or replaced;
- the token is copied to another volume (it is tied to the LUKS UUID).

Kernel updates do not change it. Unlike a TPM PCR policy, it does not measure the kernel or initrd.

## Limits

- The root volume is not supported yet. The SEP key store files live in `/var/lib` on the root filesystem, so the initrd cannot reach them before root is open. Root unlock needs a key store location the initrd can read, and that is follow-up work.
- No PIN or Touch ID binding yet. A PIN that the SEP does not enforce would add nothing, so the token has no PIN mode until the SEP can check one.
- As with any dm-crypt volume, the open volume key lives in kernel memory, and root on the running system can read the unsealed secret while the plugin runs. macOS keeps its FileVault key out of the CPU, which Linux dm-crypt cannot do.

## Testing

`make -C luks check` runs unit tests and LUKS2 file-image tests with kernel `user` keys standing in for the SEP (as root where the kernel restricts AF_ALG). `luks/tests/hw-loop-test.sh` is the hardware test: it works on one 64 MiB file under `/var/tmp`, enrolls it, unlocks it with cryptsetup and systemd-cryptsetup, and after a reboot checks unlock again, the recovery passphrase, refused tampered and foreign blobs, and SELinux denials.
