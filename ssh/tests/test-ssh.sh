#!/bin/bash
# shellcheck disable=SC2015 # ok/no always succeed
# SPDX-License-Identifier: MIT
# aurora-sep-ssh end to end with kernel "user" keys standing in for the SEP:
# keygen, agent, add, a confirm-gated signature (presence stubbed), a
# refused one (presence denied), a tampered record, a record from another
# key, and the key file on its own. Run as root where AF_ALG ccm(aes) is
# restricted. Usage: tests/test-ssh.sh BUILD_DIR_WITH_aurora-sep-ssh-seal
set -uo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
build=$(cd "${1:-$here/test}" && pwd)
work=$(mktemp -d "${TMPDIR:-/var/tmp}/aurora-sep-ssh-test.XXXXXX")
pass=0 fail=0
ok() { echo "PASS $*"; pass=$((pass + 1)); }
no() { echo "FAIL $*"; fail=$((fail + 1)); }

lib=$work/libexec
mkdir -p "$lib" "$work/home/.ssh" "$work/run"
cp "$build/aurora-sep-ssh-seal" "$here/aurora-sep-ssh-askpass" "$lib/"
export AURORA_SEP_SSH_LIBEXEC=$lib HOME=$work/home XDG_RUNTIME_DIR=$work/run
tool=$here/aurora-sep-ssh
key=$HOME/.ssh/id_ed25519_sep

cleanup() { "$tool" stop >/dev/null 2>&1; rm -rf "$work"; }
trap cleanup EXIT

if "$tool" keygen -f "$key" -C test >"$work/keygen.out" 2>"$work/keygen.err"; then
	ok "keygen"
else
	no "keygen: $(cat "$work/keygen.err")"; exit 1
fi
[ -f "$key" ] && [ -f "$key.pub" ] && [ -f "$key.sep" ] && ok "key, public key and record written" || no "files"
[ "$(stat -c %a "$key.sep")" = 600 ] && ok "record is 0600" || no "record mode $(stat -c %a "$key.sep")"
head -1 "$key.sep" | grep -qx "aurora-sep-ssh 1" && ok "record header" || no "record header"
if ssh-keygen -y -P "" -f "$key" >/dev/null 2>&1; then no "key opens without the passphrase"; else ok "key file alone does not open"; fi

# A passphrase out of the record opens the key.
p=$(AURORA_SEP_SSH_RECORD=$key.sep "$lib/aurora-sep-ssh-askpass" "Enter passphrase")
if [ ${#p} -eq 128 ] && ssh-keygen -y -P "$p" -f "$key" | cut -d" " -f1,2 | cmp -s - <(cut -d' ' -f1,2 "$key.pub"); then
	ok "unsealed passphrase opens the key (128 hex chars)"
else
	no "unsealed passphrase"
fi
unset p

# Unseal refuses a terminal; a tampered record and another key's record fail.
sed 's/^ct \(..\)/ct ff/' "$key.sep" >"$work/tampered.sep"
if "$lib/aurora-sep-ssh-seal" unseal <"$work/tampered.sep" >/dev/null 2>"$work/t.err"; then
	no "tampered record unsealed"
else
	ok "tampered record refused: $(cat "$work/t.err")"
fi
sed 's/^id \(..\)/id 00/' "$key.sep" >"$work/otherid.sep"
if "$lib/aurora-sep-ssh-seal" unseal <"$work/otherid.sep" >/dev/null 2>/dev/null; then
	no "record with another id unsealed (AAD not bound)"
else
	ok "record bound to its id (AAD)"
fi

# Agent with presence stubbed: add, sign, verify.
eval "$(AURORA_SEP_SSH_PRESENCE=none "$tool" agent 2>/dev/null)"
if AURORA_SEP_SSH_PRESENCE=deny "$tool" add "$key" 2>/dev/null; then
	no "add went ahead although presence was denied"
else
	ssh-add -l >/dev/null 2>&1 && no "key loaded after a denied add" || ok "add refused when presence is denied"
fi
AURORA_SEP_SSH_PRESENCE=none "$tool" add "$key" 2>"$work/add.err" && ok "add" || no "add: $(cat "$work/add.err")"
ssh-add -l | grep -q "ED25519" && ok "agent holds the key" || no "agent list"
echo "hello from the Secure Enclave" >"$work/msg"
if ssh-keygen -Y sign -f "$key.pub" -n file "$work/msg" >/dev/null 2>"$work/sign.err"; then
	ok "signature through the agent (presence stubbed)"
else
	no "sign: $(cat "$work/sign.err")"
fi
echo "test $(cut -d' ' -f1,2 "$key.pub")" >"$work/allowed"
ssh-keygen -Y verify -f "$work/allowed" -I test -n file -s "$work/msg.sig" <"$work/msg" >/dev/null 2>&1 &&
	ok "signature verifies" || no "verify"
"$tool" stop 2>/dev/null

# Agent with presence denied: the key loads, but signing is refused.
eval "$(AURORA_SEP_SSH_PRESENCE=deny "$tool" agent 2>/dev/null)"
AURORA_SEP_SSH_PRESENCE=none "$tool" add "$key" 2>/dev/null
rm -f "$work/msg.sig"
if ssh-keygen -Y sign -f "$key.pub" -n file "$work/msg" >/dev/null 2>&1; then
	no "signed although presence was denied"
else
	ok "signature refused when presence is denied"
fi
"$tool" stop 2>/dev/null

echo "test-ssh: $pass passed, $fail failed"
[ $fail -eq 0 ]
