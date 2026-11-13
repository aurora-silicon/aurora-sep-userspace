# Unlocking the root volume with the Secure Enclave

This is the design for opening the root volume, and any other volume the boot needs before `local-fs.target`, with the Secure Enclave from the initrd. It builds on [luks-sep.md](luks-sep.md), which covers data volumes opened after boot.

Status: the userspace and initrd parts are in this repository. The kernel part (a key-store-only attach phase in `apple_sep`) is specified below and is not merged yet. Until a kernel has it, the initrd integration installs the token plugin only and every SEP-sealed volume opened in the initrd asks for its passphrase, exactly as it does today.

## What blocks it today

1. **The key store lives on the volume being unlocked.** `apple_sep` reads its identity key bag and machine reference key from `/var/lib/aurora-sep-keybag.bin` and `/var/lib/aurora-sep-refkey.bin`. Both are needed to unseal a trusted key. On an encrypted root they are inside the volume we are trying to open.
2. **The driver loads after `local-fs.target`.** `aurora-sep.service` loads `apple_sep` once `/var/lib` is mounted, so a volume that `local-fs.target` waits for (a separate `/home`, say) gets the passphrase prompt.
3. **The driver cannot be loaded twice in one boot.** The SEP accepts its shared-memory registration once per boot, and the driver refuses a second attach because a repeated registration can park the SEP (`attach_warm` and `attach_m1` both record a marker for this). So we cannot load the driver in the initrd, unload it, and load it again on the real root.
4. **A loaded driver binds files at probe.** The driver opens the host-state store (`/var/lib/aurora-sep-host-state.bin`) at probe and keeps it open, and with `provision_keybag=1` it creates a new identity when the key bag file is missing. Loaded in the initrd as it is today, it would hold the initramfs copy of the store for the rest of the boot (Touch ID's anti-replay state would be written to a file that disappears at switch-root), and an initrd without the key bag could provision a second identity.

Points 3 and 4 mean the fix has a kernel part. Copying files into the initramfs alone is not safe.

## Design

### Where the sealed secret lives

In the LUKS2 header, as now. The `aurora-sep` token holds the SEP-sealed trusted-key blob, the IV and the AES-256-CCM wrapped keyslot secret, with the LUKS UUID as additional data. Nothing about the token depends on `/var/lib`, so the same token opens the volume in the initrd and on a running system. No re-enrolment is needed to move a volume from "data" to "root".

### What the initrd carries

| Piece | Why |
| --- | --- |
| `apple_sep.ko` and its firmware dependencies | talks to the SEP; registers the `trusted` key source |
| `algif_aead`, `ccm` and the AES modules | the token's AES-256-CCM unwrap runs through AF_ALG with the key referenced by serial |
| `libcryptsetup-token-aurora-sep.so` | the token plugin systemd-cryptsetup loads |
| `/var/lib/aurora-sep-keybag.bin`, `/var/lib/aurora-sep-refkey.bin` (and `-refkey-v2.bin` if present) | read-only copies of the key store, at the same paths the driver uses |
| `aurora-sep-initrd.service` | loads the driver in its key-store-only phase before `cryptsetup-pre.target` |
| a `systemd-cryptsetup@.service` drop-in | gives the plugin a longer SEP wait in the initrd |

The key store copies are never written in the initrd. They are what the driver needs to recover the identity key bag and reach the machine reference key. They are only useful to this Mac's SEP under this Linux OS identity; on an unencrypted root they already sit in the clear in `/var/lib`. The image that carries them must stay readable by root only: dracut and mkinitcpio write `0600` images, and on NixOS they go in through `boot.initrd.secrets` so they never reach the world-readable Nix store.

The host-state store, the Catacomb files and the xART guard files are not copied. Nothing in the initrd needs them.

### Kernel: a key-store-only attach phase

`apple_sep` gets one new module parameter and one new sysfs attribute:

- `keystore_only=1` (default 0). The initrd loads the driver with it. The driver attaches to the SEP and discovers the endpoints as usual, then brings up only what a trusted-key unseal needs:
  - registers the `trusted` key source;
  - reads the identity key bag and machine reference key read-only, and caches both in memory on first use, so later unseals do not depend on `/var/lib` being mounted;
  - does not open the host-state store, does not load the Touch ID identity index, does not restore Catacombs, does not start the sensor or `/dev/sep-bio`;
  - opens the xART store with writes off and never provisions a key bag, whatever `xart_writes` and `provision_keybag` say. An unseal that would need an xART write (the first unlock after a boot policy change) fails, and the volume falls back to its passphrase.
- `complete_attach` (write-only, root, in the device's sysfs directory). Writing `1` after the real root is mounted finishes the attach the way probe would have: opens the host-state store, loads the identity index, reopens the xART store with the configured `xart_writes`, runs the deferred Touch ID bring-up, and clears the key-store-only state. It is idempotent and fails with `-EALREADY` when the driver was not loaded with `keystore_only=1`.

Path lookups from the driver follow PID 1's root, so after switch-root the same `/var/lib/...` paths name the real root's files. The only state that must not cross switch-root is an open file, and in this phase the driver holds none.

`aurora-sep-load` (the loader behind `aurora-sep.service`) checks `/sys/module/apple_sep/parameters/keystore_only`. If the driver is already loaded in that phase it writes `complete_attach` instead of running `modprobe` (which would be a no-op for an already loaded module and would leave Touch ID off). Everything after that, the trusted-key check and the wait for `/dev/sep-bio`, stays the same.

The installers only add the driver to the initrd when `modinfo -F parm apple_sep` lists `keystore_only`. On older kernels the initrd gets the plugin and nothing else, and the boot is unchanged.

### Boot order in the initrd

```
initrd                                        real root
------                                        ---------
aurora-sep-initrd.service                     switch-root
  modprobe apple_sep keystore_only=1          aurora-sep.service
  (os_uuid pin comes from the command line)     aurora-sep-load: keystore_only? -> complete_attach
        |                                       wait for trusted keys, /dev/sep-bio (unchanged)
cryptsetup-pre.target                         aurora-sep-ready.service (Touch ID), fprintd
        |
systemd-cryptsetup@root.service
  token plugin: wait for diag/keystore != unknown (budget 90 s)
  add_key trusted "load <blob>"  -> SEP unseals
  AF_ALG ccm(aes) unwrap -> keyslot secret
  on failure: passphrase prompt (always kept)
```

The plugin waits on the driver's `diag/keystore` attribute before it creates the trusted key. The kernel instantiates keys under one global mutex, and a trusted key created before the SEP key store is up waits inside that mutex for up to 90 s. systemd creates a keyring for every service it starts, so a plugin that called `add_key` early would stall the whole initrd. Waiting on the attribute takes no lock. `keystore` reads `closed` when the key store will not come up this boot; the plugin then gives up at once.

How long the initrd waits depends on the Mac. On the M2 the key store is up about 3 s after the driver loads and a trusted key round-trips after 5 s. On the J700 the SEP starts its applications about 43 s after boot. The initrd budget is 90 s (`AURORA_SEP_WAIT` in the `systemd-cryptsetup@.service` drop-in); after that the passphrase prompt appears.

With the driver loaded from the initrd, volumes opened on the real root before `local-fs.target` (a separate `/home` in `/etc/crypttab`) also unlock through the token, because the key source is already up and the key store is cached. That removes limit (2) for anyone who uses the initrd integration. Without it, the `noauto` plus `x-systemd.automount` advice in luks-sep.md stays.

### Recovery passphrase

Always kept. `aurora-sep-cryptenroll` refuses to remove the last keyslot that is not bound to the SEP. systemd-cryptsetup tries tokens first and prompts for a passphrase when the plugin says no: `-EPERM` (the SEP refused the blob) or `-EAGAIN` (no SEP, or it did not come up in time). A recovery key from `systemd-cryptenroll --recovery-key` works the same way.

### Boot chain check

Before the plugin asks the SEP for a key (in the initrd, and for volumes opened after boot), it reads the boot record (`/sys/firmware/aurora/boot_security/`). With `boot-chain = audit` (the default in `/etc/aurora-sep/fde.conf`, which the image carries) it logs one line per unlock when the chain is not verified from an enforcing Stage 1 on (chain state, first unverified link, volume) and goes on. With `boot-chain = require` it returns `-EPERM` instead, so the passphrase prompt appears unless the chain is verified. `aurora-sep-fde boot-chain` prints the decision for the running boot; `aurora-sep-fde boot-chain require` switches a Mac once it boots verified and rebuilds the initramfs (see [luks-sep-owners.md](luks-sep-owners.md)).

### When the SEP OS identity changes

The sealed key is bound to this Mac's SEP and to the Linux OS identity (`apple_sep.os_uuid_hi`/`_lo`). In the initrd the identity comes from the same kernel command line, because `modprobe` applies `apple_sep.*` command line options. If the pin is dropped, or Linux is reinstalled with a new identity, the SEP refuses to recover the key bag, the unseal fails with `EBADMSG`, the plugin returns `-EPERM` and the passphrase prompt appears. In the key-store-only phase nothing is written to the SEP store and nothing is provisioned, so a wrong lane cannot damage anything. After booting with the passphrase, put the pin back or re-enroll with `aurora-sep-cryptenroll --wipe-slot=sep`.

A boot policy change (a new Stage 1 or boot object) is similar: the first unlock under the new policy needs one xART record rewrite, which the key-store-only phase refuses. That boot asks for the passphrase, `complete_attach` on the real root lets the rewrite through as today, and the next boot unlocks by itself.

### Password unlock under the xART guard

With `keystore_only=2` the initrd also loads a user's saved key bag from the volume's token and unlocks it with the typed password. The enclave writes xART records while it does that. On the Macs whose enclave Linux shares with macOS (M2, M3, M4 Pro) the driver runs its xART guard, which only lets the enclave rewrite records Linux created. It keeps that list in `/var/lib/aurora-sep-xart-owned.bin` on the real root, which the initrd does not have yet (and which may sit inside the volume being opened).

So the initrd runs the guard with an empty list kept in memory:

- every session record that existed when the initrd opened the gigalocker is refused, Linux's own included;
- the shared root records follow the guard level, as on the real root;
- records the enclave creates during the unlock are adopted, in memory only;
- no host file is read or written, the one-time policy-change allowance is left for the real root, and the boot-policy window never opens in the initrd.

`complete_attach` on the real root adds the records the initrd adopted, if they still exist, to the real list before anything else can write them. If the Mac crashes before that, those records stay off the list and later boots protect them like another OS's records. If an unlock needs to rewrite a record from an earlier boot, the guard refuses it, the unlock fails closed, and the prompt falls back to the passphrase or recovery key.

Kernels with this say so in the parameter description (`modinfo -F parm apple_sep`: `keystore_only: ... (under the xART guard too)`). When the running driver applies the guard (`diag/policy` shows `xart_guard=1` or `2`) and the target kernel lacks it, dracut and mkinitcpio warn that password volumes will ask for their passphrase or recovery key in the initrd. They still build the image in password mode, so the next kernel update fixes it without a rebuild by hand.

### When the key store changes

If the driver rewrites the key bag or reference key (a new identity, a repaired bag), the copies in the initramfs are stale until it is rebuilt, and the root falls back to the passphrase. Kernel updates rebuild it anyway. The initrd records a SHA-256 of the copies it carries in `/run/aurora-sep/initrd-keystore.sha256`, and `aurora-sep-initrd-check.service` on the real root compares it with `/var/lib` and logs a warning when the initramfs needs rebuilding.

## How this compares with TPM2 in systemd

| | TPM2 (`systemd-cryptenroll --tpm2-device`) | SEP (`aurora-sep-cryptenroll`) |
| --- | --- | --- |
| sealed object | in the LUKS2 `systemd-tpm2` token | in the LUKS2 `aurora-sep` token |
| initrd pieces | `tpm2-tss` dracut module or mkinitcpio `sd-encrypt` with tss2 libs; TPM driver | this repo's dracut module, mkinitcpio hook or NixOS option; `apple_sep` |
| device wait | `token-timeout=` waits for the TPM device | plugin waits for `diag/keystore` (90 s in the initrd) |
| bound to | the TPM, plus optional PCR policy (measured boot) | the SEP and the Linux OS identity; no boot measurement |
| PIN | `--tpm2-with-pin`, TPM dictionary-attack lockout | none yet (see below) |
| fallback | passphrase or recovery key | passphrase or recovery key |
| state outside the header | none | the key store copies in the initramfs |

The last row is the main difference. A TPM keeps its storage root key inside the chip. The SEP keeps the key bag's protection inside the enclave too, but the wrapped key bag and its reference key live on the host, so the initrd has to carry them.

## What this is and is not, compared with FileVault

This gives a TPM-style automatic unlock: the disk opens on this Mac under this Linux identity and nowhere else. A disk moved to another machine, or a token copied to another volume, stays locked. Anyone who can boot this Linux install on this Mac still gets the volume opened, just as with a TPM2 enrolment without a PIN.

FileVault itself asks for the user's password at boot, and the SEP enforces the attempt limit. The SEP can do that for us too: the identity key bag is unlocked with a passcode (`change_lock_state` with the stored secret today). A PIN mode would enrol a separate key bag whose passcode comes from the user's PIN, so the SEP does the checking and the back-off. That is the next step and needs its own kernel interface; it is not part of this change.

## Packaging

- Fedora (dracut): `90aurora-sep` module. In host-only mode it is included when a LUKS2 device the initramfs opens has an `aurora-sep` token; `add_dracutmodules+=" aurora-sep "` forces it.
- Arch Linux ARM (mkinitcpio): `aurora-sep` install hook for systemd-based images. Add it to `HOOKS` before `sd-encrypt`. The busybox `encrypt` hook cannot use LUKS2 tokens.
- NixOS: `aurora.sepLuks.initrd.enable`, which needs `boot.initrd.systemd.enable = true`.

None of them is on by default, and enrolling a volume does not change the initramfs. After enrolling a volume the initrd opens, rebuild the initramfs (`dracut -f`, `mkinitcpio -P`, `nixos-rebuild`).

## Testing

- `luks/tests/test-initrd.sh` checks the dracut module and the mkinitcpio hook without building an image: inclusion rules, the files they install, and the units.
- `luks/tests/vm/` boots an x86-64 VM whose root is a LUKS2 image file, built with dracut (Fedora) and with mkinitcpio (Arch), with a test build of the plugin that uses kernel `user` keys in place of the SEP. It checks that systemd-cryptsetup in the initrd opens root through the token and switches root, that a tampered token falls back to the passphrase, and that the production plugin on a machine without a SEP falls back to the passphrase without stalling.
- On a Fedora Mac, `luks/tests/hw-initrd-test.sh` needs a kernel with `keystore_only`. It enrolls a small LUKS2 image file, builds a test initramfs that carries it, and adds a one-shot boot entry (a copy of the default, same command line and OS identity pin) whose initrd opens the image through the token only, before switch-root. `verify` then checks the result, that `complete_attach` brought Touch ID up, and SELinux. It never touches the real root.
