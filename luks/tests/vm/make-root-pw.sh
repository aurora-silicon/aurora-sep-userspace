#!/bin/sh
# SPDX-License-Identifier: MIT
# Password-mode copy of the VM test root: the same LUKS2 root image enrolled
# with aurora-sep-fde (a user password and a recovery key, then the installer
# passphrase removed: the FileVault end state) against the file-backed enclave
# double, whose state directory the test initramfs carries. A second copy has
# the user token's sealed secret flipped (the enclave refuses it).
# Usage: make-root-pw.sh <root.img> <test build dir> <passphrase file> <out dir>
set -eu
src=$1 B=$2 pass=$3 W=$4
export AURORA_SEP_FDE_MOCK=$W/mock AURORA_SEP_TOKEN_DIR=$B
export AURORA_SEP_FDE_CONF=$W/fde.conf AURORA_SEP_FDE_VOLUMES=$W/fde-volumes
rm -rf "$W/mock"; mkdir -p "$W/mock"
img=$W/root-pw.img
cp "$src" "$img"
# The machine-mode token from make-root.sh goes: this volume opens by password.
cryptsetup --batch-mode token remove --token-id 0 "$img"
printf 'vm user password' >"$W/pw"
printf 'vm wrong password' >"$W/pw-bad"
"$B/aurora-sep-fde" enroll --uid 60300 --label vm --unlock-key-file "$pass" --password-file "$W/pw" "$img"
# A second volume owner, whose password then changes before boot.
printf 'vm second old password' >"$W/pw2-old"
printf 'vm second password' >"$W/pw2"
"$B/aurora-sep-fde" enroll --uid 60302 --owner --label second --unlock-key-file "$pass" --password-file "$W/pw2-old" "$img"
"$B/aurora-sep-fde" change-password --uid 60302 --old-file "$W/pw2-old" --new-file "$W/pw2" "$img"
rm -f "$W/rk"
"$B/aurora-sep-fde" recovery --uid 60301 --unlock-key-file "$pass" --recovery-key-file "$W/rk" "$img"
# The FileVault end state: the installer passphrase goes (the recovery key
# keeps its offline keyslot). The old machine-mode slot has no token now.
"$B/aurora-sep-fde" remove-passphrase --unlock-key-file "$pass" "$img"
cryptsetup luksDump "$img" | sed -n '/^Keyslots:/,/^Digests:/p' | grep -E '^  [0-9]+: ' >"$W/pw-keyslots.txt"
"$B/aurora-sep-fde" status "$img" >"$W/pw-status.txt"
# Boot state: the bags are not in the "enclave" until the token loads them.
rm -f "$W/mock"/live-* "$W/mock"/unlocked-*
cp "$img" "$W/root-pw-tampered.img"
tok=$(cryptsetup luksDump --dump-json-metadata "$img" | python3 -c "
import json,sys; t=json.load(sys.stdin)['tokens']
print([k for k,v in t.items() if v.get('aurora_sep_role')=='user'][0])")
cryptsetup token export --token-id "$tok" "$W/root-pw-tampered.img" |
	python3 -c 'import json,sys; t=json.load(sys.stdin); s=t["aurora_sep_sealed"]; t["aurora_sep_sealed"]=s[:-1]+("0" if s[-1]!="0" else "1"); print(json.dumps(t))' \
	>"$W/pw-tampered.json"
cryptsetup --batch-mode token import --token-id "$tok" --token-replace --json-file "$W/pw-tampered.json" "$W/root-pw-tampered.img"
echo "password-mode root ready"
