#!/bin/bash
# shellcheck disable=SC2015 # ok/no always succeed
# SPDX-License-Identifier: MIT
# aurora-fido-seal with kernel "user" keys standing in for the SEP: a new
# record, unseal, a tampered record, another id, and the daemon's loader.
# Usage: tests/test-seal.sh PATH/TO/test/aurora-fido-seal (as root where
# AF_ALG ccm(aes) is restricted).
set -uo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
seal=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
work=$(mktemp -d "${TMPDIR:-/var/tmp}/aurora-fido-seal.XXXXXX")
trap 'rm -rf "$work"' EXIT
pass=0 fail=0
ok() { echo "PASS $*"; pass=$((pass + 1)); }
no() { echo "FAIL $*"; fail=$((fail + 1)); }

"$seal" new >"$work/rec" 2>"$work/err" && ok "new record" || { no "new: $(cat "$work/err")"; exit 1; }
head -1 "$work/rec" | grep -qx "aurora-fido 1" && ok "record header" || no "header"
s1=$("$seal" unseal <"$work/rec" | cat)
[ ${#s1} -eq 128 ] && ok "unseal gives 64 bytes (hex)" || no "unseal: ${#s1}"
s2=$("$seal" unseal <"$work/rec" | cat)
[ "$s1" = "$s2" ] && ok "unseal is stable" || no "unseal differs"
sed 's/^ct \(..\)/ct ff/' "$work/rec" >"$work/t"
"$seal" unseal <"$work/t" >/dev/null 2>&1 && no "tampered record opened" || ok "tampered record refused"
sed 's/^id \(..\)/id 00/' "$work/rec" >"$work/t"
"$seal" unseal <"$work/t" >/dev/null 2>&1 && no "record with another id opened" || ok "record bound to its id"
sed 's/^aurora-fido 1/aurora-sep-ssh 1/' "$work/rec" >"$work/t"
"$seal" unseal <"$work/t" >/dev/null 2>&1 && no "foreign record type opened" || ok "foreign record type refused"

mkdir -p "$work/state"
out=$(cd "$here" && python3 -c '
import sys
sys.path.insert(0, ".")
from aurora_fido.daemon import SealedSecret
s = SealedSecret(sys.argv[1], sys.argv[2])
a = s.load(); b = s.load(); c = s.new()
print(len(a), a == b, a != c)
' "$work/state" "$seal" 2>&1)
[ "$out" = "64 True True" ] && ok "daemon loader: seal on first start, reopen, new on reset" || no "loader: $out"
[ "$(stat -c %a "$work/state/master.sep")" = 600 ] && ok "master.sep is 0600" || no "mode"

echo "seal: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
