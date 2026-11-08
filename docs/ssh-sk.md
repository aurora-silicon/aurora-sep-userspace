# SSH keys that live in the Secure Enclave

`libaurora-sep-sk.so` is an OpenSSH security-key provider. It makes `ecdsa-sk` keys whose private key is created
inside the Mac's Secure Enclave and never leaves it. Every signature is computed by the enclave. It needs an
Aurora kernel with `/dev/sep-key` (interface version 1; version 2 adds enclave-enforced Touch ID policies).

## Try it

    sudo usermod -aG sep-key $USER          # once; log in again
    ssh-keygen -t ecdsa-sk -w /usr/lib64/libaurora-sep-sk.so -f ~/.ssh/id_ecdsa_sep
    export SSH_SK_PROVIDER=/usr/lib64/libaurora-sep-sk.so   # or SecurityKeyProvider in ~/.ssh/config
    ssh -i ~/.ssh/id_ecdsa_sep host                          # Touch ID per login

Sign git commits:

    git config gpg.format ssh
    git config user.signingkey ~/.ssh/id_ecdsa_sep
    git commit -S -m test

With `ssh-agent`, start the agent with `-P /usr/lib64/libaurora-sep-sk.so` (or set `SSH_SK_PROVIDER` before
starting it) and `ssh-add ~/.ssh/id_ecdsa_sep`.

## How it works

- `ssh-keygen -t ecdsa-sk` asks the provider to enrol. The provider asks `/dev/sep-key` for a new P-256 key. The
  kernel has the enclave's key store create it and returns an opaque handle (the enclave's wrapped record) and
  the public point. OpenSSH stores the handle as the security-key "key handle" in the private key file.
- For each signature OpenSSH hands the handle back. The provider builds the digest OpenSSH verifies for
  `sk-ecdsa-sha2-nistp256@openssh.com` keys (SHA-256 of the application hash, flags, counter and message hash)
  and the enclave signs it.
- The handle works only on the Mac that made it, under the Linux install that made it. Anywhere else the enclave
  refuses it (`EKEYREJECTED`).
- Only P-256 (`ecdsa-sk`): the enclave makes no Ed25519 keys. No resident keys: the handle is in the key file. The
  signature counter is always 0 (the enclave keeps none for these keys).

## Touch ID and access policies

A key asks for user presence unless it was made with `-O no-touch-required` (as with any security key). On a kernel
with `/dev/sep-key` version 2 such a key gets an access policy that **the Secure Enclave enforces**, the same ones
macOS offers through `SecAccessControl`. The kernel runs the Touch ID match inside the signing call; without a
fresh match the enclave refuses to sign, root included. One touch gives one signature.

Pick the policy at enrolment with `AURORA_SEP_SK_POLICY`:

| policy | macOS name | who can sign | after you enrol or remove a finger | Linux status |
|---|---|---|---|---|
| `presence` (default) | `.userPresence` | Touch ID **or** your password | still works | waits for an enclave-checked password (below) |
| `any` | `.biometryAny` | any enrolled finger | still works, new fingers too | yes (kernel flag 0x2) |
| `current-set` | `.biometryCurrentSet` | only the fingers enrolled when the key was made | **the key is dead for good** | yes (kernel flag 0x1) |
| `passcode` | `.devicePasscode` | your password only | still works | waits for an enclave-checked password |

    AURORA_SEP_SK_POLICY=current-set ssh-keygen -t ecdsa-sk -w /usr/lib64/libaurora-sep-sk.so -f ~/.ssh/id_ecdsa_sep

The default is `presence`, as on macOS. Until the kernel offers it, the default makes an `any` key and says so. An
explicit policy the kernel does not offer fails the enrolment; there is no software fallback.

**Why no password yet.** On macOS the enclave checks the password itself against your keychain's key bag, so root
cannot fake it. On Linux the only "passcode" the enclave knows today is the secret of the Linux identity key bag,
which root holds. A password path built on it would be root-satisfiable, and checking the password in software would
be too, so neither is offered under the macOS name. It comes with per-user password-keyed key bags.

**Lockout.** After five failed matches Touch ID locks out (as on macOS) and touch-gated keys refuse (`EACCES`) until
Touch ID is unlocked again. On macOS the password is the way back in; with `any`/`current-set` keys on Linux, keep a
second way in.

**Keep a backup key.** No Secure Enclave key can be exported, copied or recovered: a lost Mac, a reinstalled Linux or
(for `current-set`) a changed finger means a lost key. Do what you would do with a hardware security key: make a
second key (another Mac, a FIDO key, or an ordinary key kept offline) and add it to `authorized_keys` next to this one.

On a version 1 kernel the provider falls back to running `fprintd-verify` before each signature. **That check runs on
the host, not in the enclave**: root, or anything that can open `/dev/sep-key` with your key file, can sign without a
touch. What it still guarantees:

| | this provider (sep-key v1) | the earlier sealed key (`aurora-sep-ssh`) |
|---|---|---|
| Private key readable by root or in a memory dump | never | yes, once loaded into the agent |
| Key file or backup usable on another machine | no | no |
| Signing after the attacker loses access to this Mac | no | yes, with a copied key |
| Signing without a touch, by root | yes | yes |

`AURORA_SEP_SK_PRESENCE=deny` refuses every signature that asks for presence (for tests). `AURORA_SEP_SK_DEBUG=1`
prints what the provider does. `AURORA_SEP_SK_DEVICE` overrides `/dev/sep-key` (tests).

## Access

The kernel creates `/dev/sep-key` mode 0600. The package installs a udev rule giving the `sep-key` group read/write
and a sysusers entry creating the group. Members can make keys and sign with handles they hold. A handle is a
capability on this Mac: keep the key file private, as with any SSH key.

## Tests

`make -C sk check` runs the OpenSSH flow against a test build in which software P-256 keys stand in for the enclave:
enrol, `ssh-keygen -Y sign/verify`, tampered message, distinct keys, presence denied and stubbed, rejected handle,
Ed25519 and resident keys refused, `git commit -S` + `verify-commit`, an ssh login through a private `sshd -i`, and
the policy choice.
`sk/tests/test-sk.sh <real provider> hw` runs the same against the enclave (no finger: only no-touch-required keys sign).
