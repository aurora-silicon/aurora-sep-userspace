# SSH keys sealed to the Secure Enclave, Touch ID for every use

`aurora-sep-ssh` gives you an SSH key that opens only on this Mac and signs only after a Touch ID match. It's the Linux counterpart of a Secure Enclave SSH key on macOS (Secretive and similar tools). It uses only standard OpenSSH pieces: an encrypted key file, `ssh-agent`, `ssh-add -c` and `SSH_ASKPASS`. `ssh`, `git`, `ssh-keygen -Y sign` and anything else that talks to `SSH_AUTH_SOCK` work unchanged.

## sk or ssh

This repository has two ways to keep an SSH key behind the Secure Enclave. Prefer `sk/` where it works:

| | `sk/` (`ecdsa-sk`, [ssh-sk.md](ssh-sk.md)) | `ssh/` (this page) |
| --- | --- | --- |
| Private key | made in the enclave, never leaves it; the enclave signs | ordinary ed25519 key file; its passphrase is sealed to the enclave |
| Touch ID | enforced by the enclave (`/dev/sep-key` version 2) | checked by `fprintd-verify` in the agent's askpass, not by the enclave |
| Key type | `sk-ecdsa-sha2-nistp256@openssh.com` only | ed25519 (`aurora-sep-ssh keygen`) |
| Servers | need OpenSSH 8.2 or later and accept `-sk` keys | any SSH server, and services that accept only plain key types |
| Kernel | `/dev/sep-key` | the `trusted` key type with the `apple_sep` source |

Use `ssh/` when a server or service does not accept `-sk` keys, when you need an Ed25519 key, or
on a kernel without `/dev/sep-key`. Otherwise use `sk/`: its key cannot be copied off the Mac, even by root.

## Try it

    aurora-sep-ssh keygen                  # ~/.ssh/id_ed25519_sep (+ .pub, .sep)
    eval "$(aurora-sep-ssh agent)"         # the Touch ID agent for this shell
    aurora-sep-ssh add                     # touch Touch ID; key loaded
    echo hi > msg && ssh-keygen -Y sign -f ~/.ssh/id_ed25519_sep.pub -n file msg   # touch again
    ssh-copy-id -i ~/.ssh/id_ed25519_sep.pub host && ssh host                     # touch per login

Sign git commits with it:

    git config gpg.format ssh
    git config user.signingkey ~/.ssh/id_ed25519_sep.pub
    git commit -S -m test                  # touch

## How it works

- `keygen` asks the SEP for a fresh sealed AES-256 key (the kernel `trusted` key type with the `apple_sep` source, the same sealing as `aurora-sep-cryptenroll`). It encrypts a random 64-byte passphrase with that key (AES-256-CCM through AF_ALG, so the AES key never reaches userspace) and stores the sealed blob, IV and ciphertext in `KEY.sep`. `ssh-keygen` then writes a normal OpenSSH ed25519 key, encrypted with that passphrase.
- `add` first asks for Touch ID (`fprintd-verify`), whatever sudo's own policy is. It then unseals the passphrase and hands it to `ssh-add` through `SSH_ASKPASS`. Unsealing needs root, because the kernel restricts AF_ALG `ccm(aes)` to `CAP_SYS_ADMIN`. It therefore goes through `sudo`. The key is added with `-c` (confirm).
- `agent` starts a dedicated `ssh-agent` (`$XDG_RUNTIME_DIR/aurora-sep-ssh/agent.sock`) whose `SSH_ASKPASS` is `aurora-sep-ssh-askpass`. For each signature with a confirm-constrained key, the agent runs it. It runs `fprintd-verify` for you, and only a `verify-match` allows the signature. You get a desktop notification when one is waiting.

The additional data is `aurora-sep-ssh:1:<random id>`, so an SSH record can't be used as a LUKS2 token or the other way around.

## What it protects against, and what it does not

The SEP seals the key at rest. It does not hold the key while you use it, and it does not enforce the Touch ID checks. Be clear about what that means:

- At rest: the key file and its `.sep` record are useless on any other machine, or after Linux is reinstalled on this one. Backups and stolen disks don't leak a usable key. The enclave refuses a tampered record.
- In use: `add` unseals the plaintext Ed25519 key into `ssh-agent` memory, as with any agent key.
- The Touch ID checks, at `add` and before each signature, are enforced in software (`fprintd-verify`, run by the CLI and by the agent's askpass). They are not an SEP access-control policy on the key.
- So root can use the key with no finger: by reading the agent's memory, or by running the unseal helper (`aurora-sep-ssh-seal unseal`) directly. Anyone who can become root without a touch can do the same. That includes a process running as you when sudo needs no password for you (a NOPASSWD rule, or a cached sudo ticket). This is not root-proof.
- A process running as you that can't become root can't get a signature without your finger: the agent asks for a Touch ID match for each one, and `ssh-agent` blocks other processes of the same user from tracing it.
- In macOS terms this is a Keychain item that only this Secure Enclave can unlock, not a non-extractable key whose signing happens inside the SEP under a biometric access-control policy. SEP-resident keys of that kind are the follow-up.
- The key is bound to this Mac's SEP, the Linux SEP OS identity (`apple_sep.os_uuid_hi`/`_lo`) and the SEP key store in `/var/lib`, as described in [luks-sep.md](luks-sep.md). If any of them changes, the key no longer opens. Keep another way into the hosts you add it to.
- `AURORA_SEP_SSH_PRESENCE=none` turns the per-use check off (for unattended tests only); `deny` refuses every use.

## Requirements

An Aurora kernel with the `apple_sep` trusted-key source, `algif_aead` (see [luks-sep.md](luks-sep.md)), OpenSSH 8.4 or newer (`SSH_ASKPASS_REQUIRE`), fprintd with an enrolled finger, sudo, and sudo rights for the unseal helper.

## Tests

`make -C ssh check` runs the whole flow with kernel `user` keys standing in for the SEP: keygen, add refused and allowed, a signature with presence stubbed, one refused with presence denied, a tampered record, another record's id, and the key file on its own. Run it as root where AF_ALG is restricted. `tests/test-ssh.sh ssh` with the production helper runs the same steps against the real SEP; it passed on the MacBook Neo and the J616s (fleet27) on 2026-11-08. The live Touch ID path passed on the J616s the same day with a finger on the sensor: `add`, a login per touch, a wrong finger refused, no touch refused after 30 s.
