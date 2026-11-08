# SSH keys that live in the Secure Enclave

`libaurora-sep-sk.so` is an OpenSSH security-key provider. It makes `ecdsa-sk` keys whose private key is created
inside the Mac's Secure Enclave and never leaves it. Every signature is computed by the enclave. It needs an
Aurora kernel with `/dev/sep-key` (interface version 1).

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

## Touch ID

A key asks for user presence unless it was made with `-O no-touch-required` (as with any security key). Before
such a signature the provider runs `fprintd-verify` and reports presence only after a match. `-O verify-required`
keys get the same check and report user verification.

**This check runs on the host, not in the enclave.** `/dev/sep-key` version 1 has no access-control policy of its
own. Root, or anything that can open `/dev/sep-key` with your key file, can sign without a touch. What it does
guarantee:

| | this provider (sep-key v1) | the earlier sealed key (`aurora-sep-ssh`) |
|---|---|---|
| Private key readable by root or in a memory dump | never | yes, once loaded into the agent |
| Key file or backup usable on another machine | no | no |
| Signing after the attacker loses access to this Mac | no | yes, with a copied key |
| Signing without a touch, by root | yes | yes |

Signing without a touch stops being possible once the kernel adds an enclave-enforced biometric policy (planned
`/dev/sep-key` flag): then the enclave itself refuses to sign without a fresh match.

`AURORA_SEP_SK_PRESENCE=deny` refuses every signature that asks for presence (for tests). `AURORA_SEP_SK_DEBUG=1`
prints what the provider does. `AURORA_SEP_SK_DEVICE` overrides `/dev/sep-key` (tests).

## Access

The kernel creates `/dev/sep-key` mode 0600. The package installs a udev rule giving the `sep-key` group read/write
and a sysusers entry creating the group. Members can make keys and sign with handles they hold. A handle is a
capability on this Mac: keep the key file private, as with any SSH key.

## Tests

`make -C sk check` runs the OpenSSH flow against a test build in which software P-256 keys stand in for the enclave:
enrol, `ssh-keygen -Y sign/verify`, tampered message, distinct keys, presence denied and stubbed, rejected handle,
Ed25519 and resident keys refused, `git commit -S` + `verify-commit`, and an ssh login through a private `sshd -i`.
`sk/tests/test-sk.sh <real provider> hw` runs the same against the enclave (no finger: only no-touch-required keys sign).
