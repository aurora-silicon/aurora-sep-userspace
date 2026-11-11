# Touch ID security key (FIDO2/U2F)

Opt in. The package installs it switched off; nothing turns it on for you.

    sudo aurora-fido enable      # check the Secure Enclave can enforce Touch ID, start it now and at boot
    aurora-fido status           # on or off, the policy, credentials it refuses
    sudo aurora-fido disable     # off now and at boot; credentials are kept
    sudo aurora-fido disable --forget   # off, and delete every credential it made

On NixOS set `aurora.fido.enable = true;` instead (the command then
only reports status). `aurora-fido enable` is `systemctl enable --now
aurora-fido.service` after a check that `/dev/sep-key` can make keys whose
Touch ID check the Secure Enclave enforces, that `/dev/uhid` exists and that
the Secure Enclave's sealing works. If any of that is missing it refuses and
says why; there is no weaker mode.

`aurora-fidod` makes the Mac's Secure Enclave and Touch ID look like a
built-in USB security key (the "YubiKey" kind) to Linux. It creates a virtual
FIDO HID device through `/dev/uhid` and speaks CTAP 2.1 and CTAP1/U2F over
CTAPHID, so anything that talks to a USB security key works unchanged:

- WebAuthn and passkeys in Firefox and Chromium,
- SSH security keys from `ssh-keygen -t ecdsa-sk` (P-256; the enclave has no
  Ed25519, so `ed25519-sk` is not offered),
- `pam_u2f` (sudo, login),
- `systemd-cryptenroll --fido2-device` (hmac-secret, on kernels that can seal
  a secret to an enclave key),
- `fido2-token`, `fido2-cred`, `fido2-assert` from libfido2.

Credit: the idea of presenting the Secure Enclave and Touch ID as a built-in
security key came from Erik ([@erikwb](https://github.com/erikwb)) on the
Aurora Discord.

## The rule: the enclave decides

Every credential key is a P-256 key the Secure Enclave makes through
`/dev/sep-key`, with a biometric access-control list the enclave enforces.
To sign, the kernel opens a fresh credential context, runs a Touch ID match
in it, has the enclave sign with that context and deletes the context, all
inside one `SEP_KEY_SIGN` call. The enclave refuses the signature for any
context in which it did not see a match itself. The daemon only holds key
handles; it never decides that a touch happened, there is no fprintd or
password check in the daemon, and there is no key the host could use.

| what needs you | how the enclave checks it |
| --- | --- |
| makeCredential | the new key's first signature (the attestation, or with `attestation = none` the same bytes as a check) is touch-gated: one touch |
| getAssertion, U2F authenticate | the credential's signature is touch-gated: one touch |
| hmac-secret | the CredRandom pair is sealed to the credential key and released by `SEP_KEY_UNSEAL`, touch-gated; the signature after it is a second touch |
| selection, reset, the credential-management token, an excluded credential, U2F register | a signature by the daemon's presence key (same access-control list) over 32 fresh random bytes, checked against its public point |

UP and UV are set together, and only on a response the enclave signed after
a match. A request with `up=false` (browsers and libfido2 probing which
credentials exist) is answered without a touch and without UP or UV; its
signature comes from a throwaway key of this daemon run and verifies against
no credential, because the enclave signs nothing without a match. Relying
parties reject such responses for sign-in anyway.

## How it works

| piece | what it does |
| --- | --- |
| `/dev/uhid` | a HID device with the FIDO usage page (`0xF1D0`); udev marks it as a security token, so the logged-in user's browser and tools can open its hidraw node |
| CTAPHID | channels, fragmentation, keepalive (`UPNEEDED` while the enclave waits), cancel |
| CTAP 2.1 | makeCredential, getAssertion, getNextAssertion, getInfo, clientPIN (key agreement and `getPinUvAuthTokenUsingUvWithPermissions` only), credentialManagement, selection, reset; extensions `credProtect` and (when the kernel can seal) `hmac-secret` |
| CTAP1/U2F | register and authenticate, for old relying parties and `pam_u2f` U2F mode |
| Touch ID | the kernel runs the match inside each enclave call; a desktop notification says "Touch ID to sign in to *site*" while it waits |
| keys | `/dev/sep-key` (apple_sep key interface 2 or 3): P-256 keys created inside the Secure Enclave with a biometric access-control list; the private half never leaves it |
| state | `/var/lib/aurora-fido` (root, 0700): resident credential records, the signature counter, the presence key handle, and a master secret sealed by the Secure Enclave that wraps credential IDs |

### Credentials

**Credential ID:** the key handle and the credential's options (credProtect,
policy, the sealed hmac-secret CredRandom pair), encrypted with AES-256-GCM
under a key derived from the daemon's master secret, with the relying
party's ID hash as additional data. An ID only opens for the RP it was made
for. Nothing in it lets the host act without the enclave: the handle signs
only after a match, and the sealed CredRandom opens only after a match. If a
handle would make the ID longer than the protocol allows (1023 bytes for
CTAP2, 255 for U2F key handles), the handle is stored in
`/var/lib/aurora-fido/handles/` and the ID carries an encrypted reference.

**Resident credentials (passkeys):** the same credential ID, plus a record
(RP, user ID and names, public key) encrypted under the master secret in
`/var/lib/aurora-fido/resident/`. `fido2-token -L -r`, `-L -k` and `-D`, and
the passkey managers in browser settings, list and delete them with a
credential-management token, which takes an enclave-checked touch.

**Master secret:** 64 random bytes, sealed by this Mac's Secure Enclave with
the kernel's `trusted` key type (`aurora-fido-seal`, the same sealing as
`aurora-sep-cryptenroll`). It protects the privacy of credential IDs and
resident records (which sites, which accounts), not the keys.

**Signature counter:** one global counter kept by the daemon in
`/var/lib/aurora-fido/counter`. Root can rewind it; see the threat model.

### Attestation

`attestation = self` (default) returns `packed` self attestation, signed by
the new credential key inside the enclave after the touch. U2F registration
uses a certificate and signature from a software key of this daemon run
(U2F has no room for a second touch; the touch is the presence key's).
`attestation = none` returns no statement. Nothing here can prove to a
website that the key lives in Apple hardware: Apple's attestation needs the
Secure Enclave's device attestation key, which a Linux host does not have.
The AAGUID `a0f1d0e5-aa5b-4a7e-9c51-f1d0a0c0de01` names this software.

### Who may approve: the policy

As on macOS, each credential gets an access-control list when it is made,
from `policy =` in `[touchid]` of `/etc/aurora-fido/aurora-fido.conf`. The
enclave enforces it. Changing the setting affects new credentials only.

| policy | approves a request | macOS | `/dev/sep-key` CREATE flag |
| --- | --- | --- | --- |
| `auto` (default) | `touchid-or-password` when the kernel offers it, else `touchid-any` (status says which) | | |
| `touchid-or-password` | Touch ID, or your password checked by the Secure Enclave | `.userPresence` | `SEP_KEY_CREATE_USER_PRESENCE` (not offered yet: refused) |
| `touchid-any` | Touch ID only, any finger enrolled on this install, now or later | `.biometryAny` | `SEP_KEY_CREATE_BIOMETRY_ANY` |
| `touchid-current` | Touch ID only, the fingers enrolled when the credential was made; adding or removing a finger retires it for good | `.biometryCurrentSet` | `SEP_KEY_CREATE_BIOMETRY_CURRENT_SET` |

`touchid-or-password` is refused today, with a message, because the only
passcode the Secure Enclave knows on Linux is a key bag secret root holds: a
password checked by the enclave against that, or checked anywhere outside
the enclave (polkit, PAM), would let root approve without you. It becomes
available when per-user, password-keyed key bags land (below).

### Touch ID behaviour

- One request is one prompt: up to `max_tries` (3) enclave calls; a finger
  that does not match gets another try, then the request fails with
  `CTAP2_ERR_OPERATION_DENIED`. No touch within `timeout` (30 s; the
  enclave call itself waits at most about a minute):
  `CTAP2_ERR_USER_ACTION_TIMEOUT`. Cancel in the browser:
  `CTAP2_ERR_KEEPALIVE_CANCEL`. Ending the enclave's wait early needs a
  kernel with `SEP_KEY_CANCEL` (interface 3); on interface 2 the enclave call
  runs out its own wait and its result is discarded.
- The Touch ID lockout is the enclave's: misses here count with misses at
  sudo or the login screen. The kernel reports a lockout like a miss, so a
  locked-out Touch ID ends the request after `max_tries` quick refusals.
- A request Touch ID has just refused that the client sends again unchanged
  within 10 seconds is refused again at once, without a new prompt.
  OpenSSH does this: it reads `OPERATION_DENIED` as "PIN required" and
  signs the same data once more.
- U2F has no "please wait" message, so for U2F requests the enclave call
  runs in the background while the client polls; its result is handed to
  the next poll of the same request within 10 seconds.
- A getAssertion with several discoverable credentials for one site needs
  one touch per account the platform fetches (getNextAssertion), because
  each account's signature is its own enclave call.
- With a `pinUvAuthToken` (Chromium and Firefox get one before most
  requests): a token for makeCredential/getAssertion is issued without a
  touch and carries no UV of its own; the one touch is the signature's. A
  token with the credential-management permission takes a touch when it is
  issued.

### Existing credentials (migration from 0.1)

aurora-fido 0.1 checked the touch in the daemon (fprintd, or a polkit
password) and kept keys either in the Secure Enclave without an access
control or as software keys sealed under the master secret. Those
credentials are refused now: their keys can sign without a finger, so they
are not security keys. Nothing can upgrade them in place (enclave keys
cannot be exported and re-imported with an access control). Register this
key again with each site and SSH server:

- `aurora-fido status` counts the stored passkeys that are refused and the
  sites where a refused credential was presented (`sudo aurora-fido status`
  lists those sites, from `/var/lib/aurora-fido/legacy-refused.json`).
- SSH: `ssh-keygen -t ecdsa-sk` again and replace the old public key in
  `authorized_keys`. Websites: add the key again in the account's security
  settings and remove the old entry. `pam_u2f`: `pamu2fcfg` again.
- A refused credential looks to the client like an unknown one
  (`CTAP2_ERR_NO_CREDENTIALS`), so a browser says the key is not registered.

## Threat model

What an attacker can do, by who they are. "Root" includes anything that can
run code in the kernel: on these Macs root can load modules and write
`/dev/mem`, so the rows assume root and a compromised kernel are the same
attacker.

| actor | can sign as you? | notes |
| --- | --- | --- |
| thief with the disk or a backup | no | keys never leave the enclave; credential IDs and records are wrapped by an enclave-sealed secret |
| another Mac, another Linux install on this Mac | no | handles are bound to this SEP and this install's identity key bag |
| website, or another site's credential ID | no | IDs are bound to the RP hash |
| malware as the desktop user, no root | only with your touch | it can send requests, and time one to meet a touch you meant for something else; the notification names the site |
| root, or the kernel | only with your touch | the enclave refuses without a match it saw; root can redirect the operation one touch approves (below) |
| root after losing root | nothing | keys never left the enclave; nothing it copied signs |

The cases a strong attacker can still use, and what bounds them:

- **One touch, one other operation (redirect).** Root controls the kernel
  that asks the enclave to sign, so when you touch for site A it can have
  the enclave sign for site B instead. It needs you to touch, and it gets
  what that one matched context allows (next point). Same as macOS against a
  kernel attacker. The notification shows what the daemon asked for, not
  what a compromised kernel asks.
- **Credential context reuse.** One matched credential context is not
  one-use: the enclave accepts every operation the key's access control
  allows for as long as the context exists (macOS behaves the same and
  documents it: a bound `LAContext` signs again without a prompt until it
  is invalidated). The kernel opens a fresh context for each SIGN or UNSEAL
  and deletes it before the call returns, and the enclave refuses a deleted
  context (self-test 4 and the one-touch row on linux#1196). So against
  root in userspace one touch is one operation. A compromised kernel that
  keeps a matched context instead of deleting it can make further
  signatures with that key until it does, but only for keys whose access
  control the touch satisfied and only after you touched. No access-control
  field limits the number of uses; the one age field (`pgcma`) filters
  reused global credentials and is not a bound here.
- **Recorded sensor frames.** The Touch ID sensor talks to the enclave over
  an authenticated, encrypted channel with a per-session key and a sequence
  that advances per message; the AP relays opaque frames and has no way to
  rewind the sequence. A recorded frame, replayed in the same or a later
  session, should fail authentication inside the enclave (Apple Platform
  Security describes the authenticated sensor channel; our reading of the
  host protocol finds no rewind). An injection test with a throwaway
  enrolment is still to run.
- **Signature counter rollback.** The counter is the daemon's file; root
  can rewind it. Counters exist to detect cloned authenticators, and an
  enclave key cannot be cloned, so a rewind gains nothing. Relying parties
  that refuse a counter that goes backwards would refuse later sign-ins
  until it passes their last value again.
- **Key handle replay.** A handle (or a credential ID) copied elsewhere is
  refused by any other enclave; on this Mac it is the same key, still
  touch-gated. A handle cannot be edited to drop its access control: the
  list is inside the enclave's own record, and the header flag only tells
  the kernel to ask for the touch.
- **Denial of service.** Root can always stop the daemon, delete
  credentials, or lock Touch ID out by failing matches. That is not signing.
- **Registration without you.** Making a key needs no touch in the enclave
  (only its first signature does), so root can make keys. A key it makes
  still signs nothing without your finger.
- **Choosing the finger.** `touchid-any` accepts any finger enrolled on this
  install, including one enrolled later; enrolling needs your password at
  the enclave's prompt (the Touch ID enrolment rules), but if that matters,
  use `touchid-current`.

### hmac-secret

The CredRandom pair behind `hmac-secret` (what `systemd-cryptenroll` uses)
is 64 random bytes sealed to the credential key with `SEP_KEY_SEAL` when the
credential is made, kept in the credential ID, and released only by
`SEP_KEY_UNSEAL`, which waits for a match like a signature. Root cannot
compute it without a touch. The signature that follows is a second touch
(the hmac-secret output sits inside the signed data, so the enclave must
release the secret first). On a kernel without `SEP_KEY_SEAL` (interface 2)
`hmac-secret` is not offered at all: getInfo does not list it and
makeCredential ignores the extension, so `systemd-cryptenroll
--fido2-device` refuses the key. It is never computed from a host secret.
The daemon is not in the initrd, so `--fido2-device` volumes open after boot
(data volumes), not the root volume; for that, `aurora-sep-cryptenroll`
([luks-sep.md](luks-sep.md)) seals to the Secure Enclave directly.

## No PIN, and what a real one needs

There is no PIN. `clientPIN` answers `PIN_NOT_SET` for the PIN
subcommands and getInfo has no `clientPin` option. A PIN on a hardware key
is worth having because the key itself checks it and counts wrong tries (8,
then the key locks); a PIN this daemon checked could be tried by root
without limit, so it would be a fake and is not offered.

What an enclave-checked PIN needs, and where each part stands:

1. The enclave verifies the PIN: a dedicated key bag (or Secure Storage
   counter lockbox) whose passcode is the PIN, and credential keys with a
   passcode constraint for that bag, so signing needs a context in which the
   enclave verified it. Per-user, password-keyed bags exist as a design
   draft (linux#921, variant-5 key store: the Neo and the M4 Pro; the M1/M2
   key store refuses them) and prove the core (only the bag's own password,
   never stored, satisfies a key under the bag).
2. The enclave counts wrong tries and the count survives a reboot. Today it
   does not: an imported user bag restarts its count after a reboot
   (measured on the Neo), and the rollback anchors proposed for bag imports
   are enforced by the kernel, not the enclave. macOS keeps the count in the
   Secure Storage Component's counter lockboxes (Apple Platform Security):
   the enclave increments the count before it checks a try, and a lockbox
   that goes past its maximum is erased, which for a PIN means the
   credentials behind it are gone for good, as when a hardware key locks.
   Creating such a lockbox for an extra secret from Linux is not known yet.
3. The PIN never reaches the host in the clear: CTAP sends
   `LEFT(SHA-256(PIN), 16)` encrypted to the authenticator's key agreement
   key, which this daemon holds. Root can read it while you enter it, as it
   could read the PIN a platform sends to a USB key; what the enclave adds is
   that root cannot guess offline or without limit.

Until 2 is solved, `ssh-keygen -K` (download resident keys: OpenSSH asks for a
PIN first) does not work, and keys made with `-O verify-required` ask
"Enter PIN" at each use: press Enter and OpenSSH uses built-in user
verification, the enclave-checked touch. The same work gives
`touchid-or-password` (macOS `.userPresence`): the password is your bag's
passcode, which the enclave checks itself.

### Known limits

- No PIN (above): no `ssh-keygen -K`, no `alwaysUv` with a PIN.
- `touchid-or-password` is refused until the enclave can check your password.
- `pamu2fcfg` needs pam-u2f 1.1.1 or newer to accept self attestation.
- "Installed off" relies on systemd presets (`90-aurora-fido.preset`). A
  packaging that enables units regardless of presets (Debian's
  `dh_installsystemd` default) must pass `--no-enable`.
- U2F key handles are at most 255 bytes, and Secure Enclave handles are
  longer, so U2F credentials always use the stored-reference form. Deleting
  `/var/lib/aurora-fido/handles` breaks them.

## Install

Distribution packages (`aurora-fido` in fedora-aurora, alarm and the NixOS
module) install it off. From source:

    make -C fido && sudo make -C fido install
    sudo systemctl daemon-reload && sudo udevadm control --reload
    sudo aurora-fido enable

It needs Python 3 with `python3-cryptography`, at least one enrolled finger,
the `uhid` module, json-c for the sealing helper, and the `apple_sep`
driver with `/dev/sep-key` (interface 2 or newer, linux#1196). Check:

    aurora-fido status
    fido2-token -L                     # lists "Aurora Touch ID Security Key"
    fido2-token -I /dev/hidrawN        # versions FIDO_2_1 U2F_V2, options uv rk credMgmt

Browsers in Flatpak or Snap need access to hidraw devices, as for any USB
security key.

## Tests

    make -C fido check                 # unit tests, no root, no hardware
    sudo make -C fido check-uhid       # real uhid device: libfido2, OpenSSH, pam_u2f, cryptenroll
    make -C fido test/aurora-fido-seal && sudo make -C fido check-seal

The tests use `fido/tests/stub.py`: software P-256 keys that behave like
touch-gated enclave keys (each signature asks a scripted "enclave touch" and
is refused without a match). They are test fixtures only; the stub is not
installed and the daemon cannot select it. `fido/tests/run-stub-daemon.py`
runs the real uhid and CTAP stack on top of them, or on the real
`/dev/sep-key` (`--keys sep`, every step a real finger):
`sudo KEYS=sep make -C fido check-uhid`.
