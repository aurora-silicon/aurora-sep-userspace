#!/bin/sh
# SPDX-License-Identifier: MIT
# Password mode (FileVault model) on LUKS2 file images, against the
# file-backed enclave double (SEP_FDE_MOCK). Each $AURORA_SEP_FDE_MOCK
# directory plays one Mac's Secure Enclave. Usage: tests/test-fde.sh <test build dir>
set -eu
B=$(cd "$1" && pwd)
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
export AURORA_SEP_TOKEN_DIR="$B"
MAC_A=$T/mac-a; MAC_B=$T/mac-b; mkdir -p "$MAC_A" "$MAC_B"
export AURORA_SEP_FDE_MOCK="$MAC_A"
export AURORA_SEP_FDE_CONF="$T/fde.conf" AURORA_SEP_FDE_VOLUMES="$T/fde-volumes"
CS0="cryptsetup --disable-locks --batch-mode"
CS="$CS0 --external-tokens-path $B"
F="$B/aurora-sep-fde"
fails=0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1"; fails=$((fails + 1)); }
try() { if "$@" >"$T/out" 2>&1; then return 0; else cat "$T/out" >&2; return 1; fi; }
no() { if "$@" >"$T/out" 2>&1; then cat "$T/out" >&2; return 1; else return 0; fi; }
attempts() { "$F" status "$1" | sed -n "s/.*${2:-bag uid 60200,}.*failed attempts \([0-9]*\).*/\1/p"; }
reboot_mac() { rm -f "$AURORA_SEP_FDE_MOCK"/live-* "$AURORA_SEP_FDE_MOCK"/unlocked-*; }

img=$T/img
truncate -s 32M "$img"
# a key file as luksFormat reads it: every byte, the trailing newline included
printf 'installer passphrase\n' > "$T/pass"
printf 'correct horse battery' > "$T/pw"
printf 'wrong horse' > "$T/bad"
printf 'new staple password' > "$T/pw2"
printf 'after reset password' > "$T/pw3"
$CS0 luksFormat --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
	--luks2-metadata-size 64k --luks2-keyslots-size 2m "$img" "$T/pass"

if try "$F" enroll --uid 60200 --label tester --unlock-key-file "$T/pass" --password-file "$T/pw" "$img"; then pass "enroll password"; else fail "enroll password"; fi
if $CS luksDump "$img" | grep -q 'Sealed by:   Apple Secure Enclave (user key bag)'; then pass "plugin dump hook (password mode)"; else fail "dump hook"; fi
if try "$F" test --password-file "$T/pw" "$img"; then pass "right password opens"; else fail "right password"; fi
if no "$F" test --password-file "$T/bad" "$img"; then pass "wrong password refused"; else fail "wrong password opened"; fi
[ "$(attempts "$img")" = 1 ] && pass "enclave counted one failed attempt" || fail "failed attempts $(attempts "$img")"
if try "$F" test --password-file "$T/pw" "$img"; then pass "right password after a wrong one"; else fail "right after wrong"; fi
[ "$(attempts "$img")" = 0 ] && pass "a right password clears the count" || fail "count not cleared"

reboot_mac
if try "$F" test --password-file "$T/pw" "$img"; then pass "opens after a reboot (bag loaded from the token)"; else fail "after reboot"; fi
if "$F" gate-check --uid 60200 --password-file "$T/pw" "$img" | grep -q 'gate-check: PASS'; then pass "enclave refuses to unseal while the bag is locked, opens after unlock"; else fail "gate-check"; fi

if try "$F" recovery --uid 60201 --unlock-key-file "$T/pass" --recovery-key-file "$T/rk" "$img"; then pass "enroll recovery key"; else fail "enroll recovery"; fi
grep -Eq '^[A-Z2-9]{4}(-[A-Z2-9]{4}){5}$' "$T/rk" && pass "recovery key format XXXX-XXXX-XXXX-XXXX-XXXX-XXXX" || fail "recovery key format"
if try "$F" test --recovery-key-file "$T/rk" "$img"; then pass "recovery key opens"; else fail "recovery key"; fi
tr 'A-Z' 'a-z' < "$T/rk" | tr -d '-' > "$T/rk-typed"
# Never a brick: the recovery key also opens a plain keyslot, with no token
# plugin and no enclave at all (what the passphrase prompt does when the SEP
# cannot answer).
if cryptsetup --disable-locks --batch-mode --disable-external-tokens open --test-passphrase \
	--key-file "$T/rk" "$img"; then pass "recovery key opens its offline keyslot without the SEP"; else fail "offline recovery keyslot"; fi
"$F" status "$img" | grep -q 'offline recovery keyslot [0-9]' && pass "status shows the offline recovery keyslot" || fail "status offline keyslot"
if no "$F" remove-passphrase --unlock-key-file "$T/rk" "$img"; then pass "remove-passphrase keeps the offline recovery keyslot"; else fail "offline keyslot removed"; fi
if try "$F" test --recovery-key-file "$T/rk-typed" "$img"; then pass "recovery key typed in lower case without dashes opens"; else fail "recovery key typed"; fi
[ "$(attempts "$img")" = 0 ] && pass "recovery key never costs the user's bag an attempt" || fail "rk counted on user bag"
"$F" test --password-file "$T/bad" "$img" >/dev/null 2>&1 || true
[ "$(attempts "$img" 'bag uid 60201,')" = 0 ] && pass "a password never costs the recovery bag an attempt" || fail "pw counted on recovery bag"
try "$F" test --password-file "$T/pw" "$img" || fail "reset the user count"

cp "$img" "$T/img-before-change"
if try "$F" change-password --uid 60200 --old-file "$T/bad" --new-file "$T/pw2" "$img"; then fail "change with a wrong old password"; else pass "change refuses a wrong old password"; fi
if try "$F" change-password --uid 60200 --old-file "$T/pw" --new-file "$T/pw2" "$img"; then pass "change password"; else fail "change password"; fi
if try "$F" test --password-file "$T/pw2" "$img"; then pass "new password opens (same keyslot, no re-encryption)"; else fail "new password"; fi
if no "$F" test --password-file "$T/pw" "$img"; then pass "old password refused"; else fail "old password opened"; fi
reboot_mac
if no "$F" test --password-file "$T/pw" "$T/img-before-change"; then pass "old header copy + old password refused after the change"; else fail "replay of old header"; fi
if try "$F" test --password-file "$T/pw2" "$img"; then pass "new password opens after a reboot"; else fail "new pw after reboot"; fi

# Copy the volume to another Mac: nothing opens there, not even the recovery key.
cp "$img" "$T/img-copy"
if AURORA_SEP_FDE_MOCK="$MAC_B" no "$F" test --password-file "$T/pw2" "$T/img-copy"; then pass "copied volume refuses the password on another Mac"; else fail "other Mac opened"; fi
if AURORA_SEP_FDE_MOCK="$MAC_B" no "$F" test --recovery-key-file "$T/rk" "$T/img-copy"; then pass "copied volume refuses the recovery key on another Mac"; else fail "other Mac rk"; fi

if try "$F" reset-password --uid 60200 --recovery-key-file "$T/rk" --new-file "$T/pw3" "$img"; then pass "reset password with the recovery key"; else fail "reset"; fi
if try "$F" test --password-file "$T/pw3" "$img"; then pass "reset password opens"; else fail "reset password open"; fi
if no "$F" test --password-file "$T/pw2" "$img"; then pass "forgotten password slot gone after reset"; else fail "old after reset"; fi
n=$("$F" status "$img" | grep -c ', user ')
[ "$n" = 1 ] && pass "one password token after reset" || fail "password tokens $n"

if try "$F" remove-passphrase --unlock-key-file "$T/pass" "$img"; then pass "remove the installer passphrase"; else fail "remove passphrase"; fi
if no $CS open --test-passphrase --key-file "$T/pass" "$img"; then pass "installer passphrase no longer opens"; else fail "passphrase still opens"; fi
if try "$F" test --password-file "$T/pw3" "$img" && try "$F" test --recovery-key-file "$T/rk" "$img"; then pass "password and recovery key still open"; else fail "after remove"; fi

# A tampered sealed secret is refused.
tok=$($CS luksDump --dump-json-metadata "$img" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(next(k for k,v in d["tokens"].items() if v.get("aurora_sep_role")=="user"))')
$CS token export --token-id "$tok" "$img" > "$T/tok.json"
python3 - "$T/tok.json" <<'PY'
import json,sys
p=sys.argv[1]; d=json.load(open(p)); s=d["aurora_sep_sealed64"]
d["aurora_sep_sealed64"]=s[:40]+("0" if s[40]!="0" else "1")+s[41:]; json.dump(d,open(p,"w"))
PY
cp "$img" "$T/img-tamper"
$CS token remove --token-id "$tok" "$T/img-tamper"
$CS token import --token-id "$tok" --json-file "$T/tok.json" "$T/img-tamper"
if no "$F" test --password-file "$T/pw3" "$T/img-tamper"; then pass "tampered sealed secret refused"; else fail "tamper opened"; fi

# Tokens written before base64 (hex fields) still open.
cp "$img" "$T/img-hex"
$CS token export --token-id "$tok" "$img" >"$T/tok64.json"
python3 - "$T/tok64.json" <<'PY2'
import base64,json,sys
p=sys.argv[1]; d=json.load(open(p))
for k in ("bag","record","sealed"):
    d["aurora_sep_"+k]=base64.b64decode(d.pop("aurora_sep_%s64"%k)).hex()
json.dump(d,open(p,"w"))
PY2
$CS token remove --token-id "$tok" "$T/img-hex"
$CS token import --token-id "$tok" --json-file "$T/tok64.json" "$T/img-hex"
if try "$F" test --password-file "$T/pw3" "$T/img-hex"; then pass "a token in the old hex form still opens"; else fail "hex token"; fi

echo "test-fde: $fails failure(s)"
[ "$fails" = 0 ]
