# SSH keys sealed to the Secure Enclave, Touch ID for every use

`aurora-sep-ssh` gives you an SSH key that opens only on this Mac and signs only after a Touch ID match. It's the Linux counterpart of a Secure Enclave SSH key on macOS (Secretive and similar tools). It uses only standard OpenSSH pieces: an encrypted key file, `ssh-agent`, `ssh-add -c` and `SSH_ASKPASS`. `ssh`, `git`, `ssh-keygen -Y sign` and anything else that talks to `SSH_AUTH_SOCK` work unchanged.

## Try it

    aurora-sep-ssh keygen                  # ~/.ssh/id_ed25519_sep (+ .pub, .sep)
    eval "$(aurora-sep-ssh agent)"         # the Touch ID agent for this shell
    aurora-sep-ssh add                     # sudo: touch Touch ID; key loaded
    echo hi > msg && ssh-keygen -Y sign -f ~/.ssh/id_ed25519_sep.pub -n file msg   # touch again
    ssh-copy-id -i ~/.ssh/id_ed25519_sep.pub host && ssh host                     # touch per login

Sign git commits with it:

    git config gpg.format ssh
    git config user.signingkey ~/.ssh/id_ed25519_sep.pub
    git commit -S -m test                  # touch

## How it works

- `keygen` asks the SEP for a fresh sealed AES-256 key (the kernel `trusted` key type with the `apple_sep` source, the same sealing as `aurora-sep-cryptenroll`). It encrypts a random 64-byte passphrase with that key (AES-256-CCM through AF_ALG, so the AES key never reaches userspace) and stores the sealed blob, IV and ciphertext in `KEY.sep`. `ssh-keygen` then writes a normal OpenSSH ed25519 key, encrypted with that passphrase.
- `add` unseals the passphrase and hands it to `ssh-add` through `SSH_ASKPASS`. Unsealing needs root, because the kernel restricts AF_ALG `ccm(aes)` to `CAP_SYS_ADMIN`. It therefore goes through `sudo`, and with `pam_fprintd` in the PAM stack, `sudo` asks for Touch ID. The key is added with `-c` (confirm).
- `agent` starts a dedicated `ssh-agent` (`$XDG_RUNTIME_DIR/aurora-sep-ssh/agent.sock`) whose `SSH_ASKPASS` is `aurora-sep-ssh-askpass`. For each signature with a confirm-constrained key, the agent runs it. It runs `fprintd-verify` for you, and only a `verify-match` allows the signature. You get a desktop notification when one is waiting.

The additional data is `aurora-sep-ssh:1:<random id>`, so an SSH record can't be used as a LUKS2 token or the other way around.

## What it protects against, and what it does not

- The key file and its `.sep` record are useless on any other machine, or after Linux is reinstalled on this one. Backups and stolen disks don't leak a usable key.
- Malware running as you can't use a loaded key without your finger. Each signature needs a Touch ID match.
- Once loaded, the private key lives in `ssh-agent` memory, as with any agent key. Root can read it. In macOS terms this is a Keychain item that only this Secure Enclave can unlock, not a non-extractable key whose signing happens inside the SEP. Signing inside the SEP would need the SEP's own key services, which is future work.
- The key is bound to this Mac's SEP, the Linux SEP OS identity (`apple_sep.os_uuid_hi`/`_lo`) and the SEP key store in `/var/lib`, as described in [luks-sep.md](luks-sep.md). If any of them changes, the key no longer opens. Keep another way into the hosts you add it to.
- `AURORA_SEP_SSH_PRESENCE=none` turns the per-use check off (for unattended tests only); `deny` refuses every use.

## Requirements

An Aurora kernel with the `apple_sep` trusted-key source, `algif_aead` (see [luks-sep.md](luks-sep.md)), OpenSSH 8.4 or newer (`SSH_ASKPASS_REQUIRE`), fprintd with an enrolled finger, sudo, and a PAM stack with `pam_fprintd` if you want Touch ID for `add`.

## Tests

`make -C ssh check` runs the whole flow with kernel `user` keys standing in for the SEP: keygen, add, a signature with presence stubbed, one refused with presence denied, a tampered record, another record's id, and the key file on its own. Run it as root where AF_ALG is restricted. `tests/test-ssh.sh ssh` with the production helper runs the same steps against the real SEP; it passed 13/13 on the MacBook Neo, fleet27, on 2026-11-08.
