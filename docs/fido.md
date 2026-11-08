# Touch ID security key (FIDO2/U2F)

Opt in. The package installs it switched off; nothing turns it on for you.

    sudo aurora-fido enable      # check what it needs, start it now and at every boot
    aurora-fido status           # on or off, which key store, which device
    sudo aurora-fido disable     # off now and at boot; credentials are kept
    sudo aurora-fido disable --forget   # off, and delete every credential it made

On NixOS set `services.aurora-fido.enable = true;` instead (the command then
only reports status). `aurora-fido enable` is `systemctl enable --now
aurora-fido.service` after a check that Touch ID (fprintd and python3-gobject),
`/dev/uhid` and the Secure Enclave's sealing work.

`aurora-fidod` makes the Mac's Secure Enclave and Touch ID look like a
built-in USB security key (the "YubiKey" kind) to Linux. It creates a virtual
FIDO HID device through `/dev/uhid` and speaks CTAP 2.1 and CTAP1/U2F over
CTAPHID, so anything that talks to a USB security key works unchanged:

- WebAuthn and passkeys in Firefox and Chromium,
- SSH security keys from `ssh-keygen -t ecdsa-sk` (P-256; the enclave has no
  Ed25519, so `ed25519-sk` is not offered),
- `pam_u2f` (sudo, login),
- `systemd-cryptenroll --fido2-device` (hmac-secret),
- `fido2-token`, `fido2-cred`, `fido2-assert` from libfido2.

Every operation that needs the user asks for a Touch ID match: user presence
and user verification are the same touch. fprintd does the match, as it does
for sudo and the login screen. fprintd itself only answers "this finger
matches"; it cannot act as a security key, which is why this daemon exists.

Credit: the idea of presenting the Secure Enclave and Touch ID as a built-in
security key came from Erik ([@erikwb](https://github.com/erikwb)) on the
Aurora Discord.

## How it works

| piece | what it does |
| --- | --- |
| `/dev/uhid` | a HID device with the FIDO usage page (`0xF1D0`); udev marks it as a security token, so the logged-in user's browser and tools can open its hidraw node |
| CTAPHID | channels, fragmentation, keepalive (`UPNEEDED` while Touch ID waits), cancel |
| CTAP 2.1 | makeCredential, getAssertion, getNextAssertion, getInfo, clientPIN (key agreement and `getPinUvAuthTokenUsingUvWithPermissions` only), credentialManagement, selection, reset; extensions `credProtect` and `hmac-secret` |
| CTAP1/U2F | register and authenticate, for old relying parties and `pam_u2f` U2F mode |
| Touch ID | fprintd over D-Bus: one prompt is one fprintd claim, like pam_fprintd; a desktop notification says "Touch ID to sign in to *site*" |
| keys | `/dev/sep-key` from the `apple_sep` driver when the kernel has it: P-256 keys created inside the Secure Enclave, the private half never leaves it. Otherwise P-256 keys sealed by the Secure Enclave (below) |
| state | `/var/lib/aurora-fido` (root, 0700): resident credentials, the signature counter, and a master secret sealed by the Secure Enclave |

### Key stores

`aurora-fido status` names the store new credentials use. `store =` in
`[keys]` of `/etc/aurora-fido/aurora-fido.conf` picks it; the default `auto`
takes the best one this kernel offers.

| store | where the private key is | when |
| --- | --- | --- |
| `sep-key` | inside the Secure Enclave, as an enclave ref-key; the daemon holds only the handle the kernel returns, which is useless on any other Mac and on any other Linux install on this one | the kernel has `/dev/sep-key` (apple_sep key interface 1 or 2) |
| `sealed` | a P-256 key made by the daemon; its private scalar is AES-256-GCM wrapped under a key derived from the master secret, which only this Mac's Secure Enclave can unseal. The key is unwrapped in the daemon's memory for each signature | the kernel has no `/dev/sep-key` |

Each credential remembers its store (the handle says which). When a kernel
with `/dev/sep-key` arrives, new credentials go into the Secure Enclave and
older sealed ones keep working. A credential made in the Secure Enclave needs
`/dev/sep-key` to sign; on a kernel without it, that one sign-in fails
("key backend" in the journal) and the others still work.

### Credentials

**Non-resident credentials:** the credential ID is the key handle, encrypted
with AES-256-GCM under a key derived from the daemon's master secret, with
the relying party's ID hash as additional data. An ID only opens for the RP
it was made for. If a handle would make the ID longer than the protocol
allows (1023 bytes for CTAP2, 255 for U2F key handles), the handle is stored
in `/var/lib/aurora-fido/handles/` and the ID carries an encrypted reference
to it.

**Resident credentials (passkeys):** the same credential ID, plus a record
(RP, user ID and names, public key) encrypted under the master secret in
`/var/lib/aurora-fido/resident/`. `fido2-token -L -r`, `-L -k` and `-D`, and
the passkey managers in browser settings, list and delete them with a
Touch ID token (CTAP 2.1 credential management).

**Master secret:** 64 random bytes, sealed by this Mac's Secure Enclave with
the kernel's `trusted` key type (`aurora-fido-seal`, the same sealing as
`aurora-sep-cryptenroll`). A copy of `/var/lib/aurora-fido` opens nothing on
another machine.

**Sealed keys** (store `sealed`): a 65-byte handle, `"AFSK"`, version 1, a
12-byte nonce and the AES-256-GCM wrapped scalar; the wrapping key is
HKDF-SHA256 of the master secret (info `aurora-fido sealed keys v1`). A
reset seals a new master secret, so old sealed keys open no more.

**Signature counter:** one global counter kept by the daemon in
`/var/lib/aurora-fido/counter`, not by the Secure Enclave.

### Attestation

`attestation = self` (default) returns `packed` self attestation: the
statement is signed by the new credential key itself, with no certificate.
U2F registration uses a self-signed certificate made by the new key.
`attestation = none` returns no statement.

This cannot prove to a website that the key lives in Apple hardware. Apple's
attestation needs the Secure Enclave's device attestation key, which a Linux
host does not have. Relying parties that require attestation from a list of
certified authenticators (some enterprise policies) will refuse this key.
The AAGUID `a0f1d0e5-aa5b-4a7e-9c51-f1d0a0c0de01` names this software, not a
certified device.

### Touch ID behaviour

- Whose finger: the user of the active local session on seat0 (whoever is at
  the keyboard and can reach the sensor), or `user =` in the config.
- One request is one prompt: up to `max_tries` (3) touches, then the request
  fails with `CTAP2_ERR_OPERATION_DENIED`. No touch within `timeout` (30 s):
  `CTAP2_ERR_USER_ACTION_TIMEOUT`. Cancel in the browser:
  `CTAP2_ERR_KEEPALIVE_CANCEL`.
- The Touch ID lockout is the enclave's: misses here count with misses at
  sudo or the login screen. A locked-out Touch ID ends the request at once
  (`OPERATION_DENIED`); unlock it the usual way (your password at a sudo or
  login prompt). The daemon never retries past a lockout and never enrols or
  deletes fingerprints.
- No fixed waits between touches: the driver arms the sensor again when the
  finger lifts.
- A request Touch ID has just refused (wrong finger or lockout) that the
  client sends again unchanged, within 30 seconds, is refused again at once,
  with no new prompt and without spending Touch ID tries. OpenSSH does this:
  it reads `OPERATION_DENIED` as "PIN required" and signs the same data once
  more. So a refused `ssh` login costs at most `max_tries` misses, as with a
  hardware key. A new request (a new challenge: the next `ssh`, a page
  reload) prompts normally, and a match clears the refusal.
- U2F has no "please wait" message, so for U2F requests the touch prompt runs
  in the background while the client polls; a match is good for one
  operation within 10 seconds.
- A request with `up=false` and no `uv` (browsers and libfido2 probing for a
  credential) is answered without asking and without the user-present or
  user-verified flags, as CTAP requires. Relying parties reject such
  assertions for sign-in.

There is no PIN. The key reports built-in user verification (`uv`) and the
CTAP 2.1 `pinUvAuthToken` option, so platforms get their tokens with a touch.

## Threat model

Be precise about what the touch protects, because it is not yet the Secure
Enclave that checks it, and the key store matters.

**Sealed store (kernels without `/dev/sep-key`):** the private keys are
software keys. On disk they exist only wrapped under the master secret, and
only this Mac's Secure Enclave unseals that, so a stolen disk, a backup or a
copied `/var/lib/aurora-fido` opens nothing elsewhere. But the daemon unwraps
a key in its own memory to sign, and root on this Mac can unseal the master
secret too: **root can copy the keys off the Mac and keep using them after
losing root**, which a hardware key or the `sep-key` store does not allow.
If that matters for a site, enrol it again (or re-register the SSH key) once
`aurora-fido status` shows the `sep-key` store.

**Secure Enclave store (`sep-key`):** the Touch ID check is made by this daemon in software. The enclave
signs whatever `/dev/sep-key` asks it to sign; it does not know a touch
happened. Root, or anything that can open `/dev/sep-key` or control this
daemon, can sign with these keys without a touch. What `/dev/sep-key` does
give: the private keys never leave the Secure Enclave. They cannot be copied
off this Mac, so a stolen disk, a backup, a credential ID or a leaked
`/var/lib/aurora-fido` is useless anywhere else, and an attacker has to keep
running code on this Mac to use them.

**After the enclave enforces it:** lane SEPKEY is working on keys with a
biometric access-control list that the Secure Enclave itself enforces
(Daybreak research t-5729 and t-5730, SEPKEY stage S1). The kernel then runs
match-then-sign as one enclave operation, and root can no longer sign without
a live matching finger; at most it can redirect the one operation a touch was
meant for. This daemon switches to that interface without changes to its
protocol side.

| actor | `sealed` store | `sep-key` store | with an SEP-enforced ACL |
| --- | --- | --- | --- |
| thief with the disk or a backup | cannot use any key | cannot | cannot |
| website, or another site's credential ID | cannot use a key made for a different RP (ID bound to the RP hash) | cannot | cannot |
| malware running as the desktop user, no root | can send requests; each one still needs your finger (the root daemon checks it), but it can time a request to coincide with a touch you expected for something else; the notification names the site | same | same |
| root on this Mac | **can sign without a touch** | **can sign without a touch** while it is root | cannot sign without a touch; can redirect one touch |
| root after losing root | **keeps any key it copied** | nothing to take away: keys never left the enclave | same |

`hmac-secret` (what `systemd-cryptenroll` uses) is a per-credential secret
derived by the daemon from data it keeps sealed under the master secret, not
by the enclave. A running root can compute it; a disk thief cannot. For LUKS
volumes, `aurora-sep-cryptenroll` (Secure Enclave sealing, see
[luks-sep.md](luks-sep.md)) is the stronger choice; the FIDO2 route is for
setups that already use `systemd-cryptenroll`. The daemon is not in the
initrd, so `--fido2-device` volumes open after boot (data volumes), not the
root volume.

Reset (`fido2-token -R`) invalidates every credential: it deletes the
resident store and seals a new master secret. As CTAP requires, it works only
within 10 seconds of the daemon starting (`systemctl restart aurora-fido`,
then reset) and needs a touch.

### Known limits

- No PIN. OpenSSH's `ssh-keygen -K` (download resident SSH keys) asks for a
  PIN and does not work. Ordinary (non-resident) `ecdsa-sk` keys, the
  default, work.
- For SSH keys made with `-O verify-required`, OpenSSH asks "Enter PIN" at
  each use. Press Enter: it then uses the built-in user verification (one
  touch).
- `pamu2fcfg` needs pam-u2f 1.1.1 or newer to accept self attestation.
- U2F key handles are at most 255 bytes, and Secure Enclave handles are
  longer, so U2F credentials always use the stored-reference form. Deleting
  `/var/lib/aurora-fido/handles` breaks them.

## Install

Distribution packages (`aurora-fido` in fedora-aurora, alarm and the NixOS
module) install it off. From source:

    make -C fido && sudo make -C fido install
    sudo systemctl daemon-reload && sudo udevadm control --reload
    sudo aurora-fido enable

It needs Python 3 with `python3-cryptography` and `python3-gobject`, fprintd
with at least one enrolled finger, the `uhid` module, json-c for the sealing
helper, and the `apple_sep` driver (Secure Enclave sealing). `/dev/sep-key`
is used when the kernel has it. Check:

    aurora-fido status
    fido2-token -L                     # lists "Aurora Touch ID Security Key"
    fido2-token -I /dev/hidrawN        # versions FIDO_2_1 U2F_V2, options uv rk credMgmt

Browsers in Flatpak or Snap need access to hidraw devices, as for any USB
security key.

The HID device uses the pid.codes test product ID `1209:0001`; nothing matches
on it (udev and browsers recognise FIDO devices by the usage page).

## Tests

    make -C fido check                 # unit tests, no root, no hardware
    sudo make -C fido check-uhid       # real uhid device: libfido2, OpenSSH, pam_u2f, cryptenroll
    make -C fido test/aurora-fido-seal && sudo make -C fido check-seal

The tests use `fido/tests/stub.py`: software P-256 keys and a scripted
Touch ID. They are test fixtures only; the stub is not installed and the
daemon cannot select it. `fido/tests/run-stub-daemon.py` runs the real uhid
and CTAP stack on top of them (or on the shipped stores, `--keys sealed` or
`--keys sep`), with real Touch ID if asked (`--touch fprintd`).
`sudo KEYS=sealed make -C fido check-uhid` runs the uhid suite on the sealed
store.
