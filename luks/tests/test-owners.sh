#!/bin/sh
# SPDX-License-Identifier: MIT
# Volume owners, password changes and resets (the FileVault secure-token
# model) on LUKS2 file images, against the file-backed enclave double
# (SEP_FDE_MOCK). Users come from test passwd/group files: alice and bob are
# in wheel (admins), carol is a standard user, dave has no disk password.
# Usage: tests/test-owners.sh <test build dir>
set -eu
B=$(cd "$1" && pwd)
H=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
export AURORA_SEP_TOKEN_DIR="$B"
export AURORA_SEP_FDE_MOCK="$T/mac"; mkdir -p "$AURORA_SEP_FDE_MOCK"
export AURORA_SEP_FDE_CONF="$T/fde.conf" AURORA_SEP_FDE_VOLUMES="$T/fde-volumes"
export AURORA_SEP_FDE_PASSWD="$T/passwd" AURORA_SEP_FDE_GROUP="$T/group"
unset SUDO_USER
CS0="cryptsetup --disable-locks --batch-mode"
F="$B/aurora-sep-fde"
fails=0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1"; fails=$((fails + 1)); }
try() { if "$@" >"$T/out" 2>&1; then return 0; else cat "$T/out" >&2; return 1; fi; }
no() { if "$@" >"$T/out" 2>&1; then cat "$T/out" >&2; return 1; else return 0; fi; }
said() { grep -q "$1" "$T/out"; }
reboot_mac() { rm -f "$AURORA_SEP_FDE_MOCK"/live-* "$AURORA_SEP_FDE_MOCK"/unlocked-*; }
attempts() { "$F" status "$1" | sed -n "s/.*user $2 .*failed attempts \([0-9]*\).*/\1/p"; }
opens() { "$F" test --password-file "$T/$2" "$1" >/dev/null 2>&1; }
owner_of() { "$F" status "$1" | grep -q "user $2 .*, owner,"; }

cat >"$T/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/bash
alice:x:1000:1000:Alice:/home/alice:/bin/bash
bob:x:1001:1001:Bob:/home/bob:/bin/bash
carol:x:1002:1002:Carol:/home/carol:/bin/bash
dave:x:1003:1003:Dave:/home/dave:/bin/bash
EOF
cat >"$T/group" <<'EOF'
root:x:0:
wheel:x:10:alice,bob
alice:x:1000:
bob:x:1001:
carol:x:1002:
dave:x:1003:
EOF
printf 'recovery = offline\n' >"$T/fde.conf"
printf 'installer passphrase\n' >"$T/pass"
printf "root-pw" >"$T/root"
for u in alice bob carol dave; do printf '%s-pw-1' "$u" >"$T/$u"; printf '%s-pw-2' "$u" >"$T/$u.2"; printf '%s-pw-3' "$u" >"$T/$u.3"; done
printf 'not anyones' >"$T/bad"
mk() { truncate -s 32M "$1"; $CS0 luksFormat --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
	--luks2-metadata-size 64k --luks2-keyslots-size 2m "$1" "$T/pass"; }
A=$T/root.img; Bv=$T/home.img
mk "$A"; mk "$Bv"

# ---- owners ----
if try "$F" enroll --user alice --unlock-key-file "$T/pass" --password-file "$T/alice" "$A"; then pass "enroll the first user (alice)"; else fail "enroll alice"; fi
owner_of "$A" alice && pass "the first user is a volume owner" || fail "alice not owner"
grep -qx "$A" "$T/fde-volumes" && pass "volume registered in fde-volumes" || fail "registry"
if try "$F" add-user --user bob --auth-user alice --auth-password-file "$T/alice" --password-file "$T/bob" "$A"; then pass "owner alice adds bob"; else fail "add bob"; fi
owner_of "$A" bob && pass "bob (wheel) becomes an owner" || fail "bob not owner"
if try "$F" add-user --user carol --auth-user alice --auth-password-file "$T/alice" --password-file "$T/carol" "$A"; then pass "owner alice adds carol"; else fail "add carol"; fi
"$F" status "$A" | grep -q "user carol .*unlock only" && pass "carol (standard user) can unlock but is not an owner" || fail "carol role"
if SUDO_USER=bob try "$F" add-user --user root --auth-password-file "$T/bob" --password-file "$T/root" "$A"; then pass "the sudo user (bob) authorizes adding root"; else fail "sudo-user auth"; fi
owner_of "$A" root && pass "root becomes an owner" || fail "root not owner"
for u in alice bob carol; do opens "$A" "$u" && pass "$u's password unlocks" || fail "$u does not unlock"; done
opens "$A" dave.2 && fail "an unknown password unlocked" || pass "a user without a disk password is refused"
opens "$A" bad && fail "wrong password unlocked" || pass "a wrong password is refused"

# ---- a non-owner cannot manage ----
if no "$F" add-user --user dave --auth-user carol --auth-password-file "$T/carol" --password-file "$T/dave" "$A" && said "not an owner"; then pass "non-owner carol cannot add a user"; else fail "carol added dave"; fi
if no "$F" remove-user --user bob --auth-user carol --auth-password-file "$T/carol" "$A" && said "not an owner"; then pass "non-owner carol cannot remove an owner"; else fail "carol removed bob"; fi
if no "$F" set-owner --user carol --owner --auth-user carol --auth-password-file "$T/carol" "$A"; then pass "non-owner carol cannot make herself an owner"; else fail "carol promoted herself"; fi
if no "$F" reset-password --user bob --auth-user carol --auth-password-file "$T/carol" --new-file "$T/bob.3" "$A"; then pass "non-owner carol cannot reset bob's password"; else fail "carol reset bob"; fi
if no "$F" add-user --user dave --auth-user dave --auth-password-file "$T/dave" --password-file "$T/dave" "$A" && said "cannot unlock this volume"; then pass "a user without a disk password cannot authorize"; else fail "dave authorized"; fi
if no "$F" add-user --user dave --auth-user alice --auth-password-file "$T/bad" --password-file "$T/dave" "$A" && said "not accepted"; then pass "an owner's wrong password does not authorize"; else fail "bad owner password authorized"; fi
[ "$(attempts "$A" alice)" -ge 1 ] && pass "the enclave counted the owner's wrong password" || fail "owner attempt not counted"
if no "$F" add-user --user dave --password-file "$T/dave" "$A"; then pass "no authorizing owner, no change"; else fail "unauthorized add"; fi
opens "$A" dave && fail "dave got in" || pass "dave still has no disk password"
opens "$A" alice || fail "clear alice count"

# ---- ownership changes ----
if try "$F" set-owner --user carol --owner --auth-user bob --auth-password-file "$T/bob" "$A" && owner_of "$A" carol; then pass "owner bob makes carol an owner"; else fail "promote carol"; fi
if try "$F" set-owner --user carol --no-owner --auth-user alice --auth-password-file "$T/alice" "$A" && ! owner_of "$A" carol; then pass "owner alice takes it back"; else fail "demote carol"; fi
if try "$F" remove-user --user root --auth-user alice --auth-password-file "$T/alice" "$A"; then pass "owner alice removes root"; else fail "remove root"; fi
if try "$F" remove-user --user bob --auth-user alice --auth-password-file "$T/alice" "$A"; then pass "owner alice removes owner bob"; else fail "remove bob"; fi
opens "$A" bob && fail "removed bob still unlocks" || pass "removed user is refused"
if no "$F" remove-user --user alice --auth-user alice --auth-password-file "$T/alice" "$A" && said "last owner"; then pass "the last owner cannot be removed"; else fail "last owner removed"; fi
if no "$F" set-owner --user alice --no-owner --auth-user alice --auth-password-file "$T/alice" "$A" && said "last owner"; then pass "the last owner cannot give up ownership"; else fail "last owner demoted"; fi
try "$F" add-user --user bob --auth-user alice --auth-password-file "$T/alice" --password-file "$T/bob" "$A" || fail "re-add bob"

# ---- one key bag per user, all volumes ----
if no "$F" enroll --user alice --unlock-key-file "$T/pass" --password-file "$T/bad" "$Bv" && said "wrong password"; then pass "a second volume needs the user's current password (one bag per user)"; else fail "second bag with another password"; fi
if try "$F" enroll --user alice --unlock-key-file "$T/pass" --password-file "$T/alice" "$Bv"; then pass "alice enrolled on a second volume"; else fail "alice second volume"; fi
try "$F" add-user --user carol --auth-user alice --auth-password-file "$T/alice" --password-file "$T/carol" "$Bv" || fail "carol second volume"
[ "$(grep -c img "$T/fde-volumes")" = 2 ] && pass "both volumes registered" || fail "registry count"
cp "$A" "$T/root-before-change.img"

# ---- password change applies ----
if no "$F" change-password --user alice --old-file "$T/bad" --new-file "$T/alice.2"; then pass "change refuses a wrong current password"; else fail "change with wrong old"; fi
if try "$F" change-password --user alice --old-file "$T/alice" --new-file "$T/alice.2" && said "on 2 volume"; then pass "alice changes her password: both volumes re-wrapped"; else fail "change alice"; fi
for v in "$A" "$Bv"; do
	opens "$v" alice.2 && pass "new password opens $(basename "$v")" || fail "new pw $(basename "$v")"
	opens "$v" alice && fail "old password opens $(basename "$v")" || pass "old password refused on $(basename "$v")"
done
reboot_mac
opens "$A" alice && fail "old password after reboot" || pass "old password refused after a reboot"
opens "$Bv" alice.2 && pass "new password opens after a reboot" || fail "new pw after reboot"
opens "$T/root-before-change.img" alice && fail "old header + old password opened" || pass "an old header copy with the old password is refused (bag rollback)"
opens "$A" carol && opens "$A" bob && pass "other users are unaffected" || fail "others broken"

# ---- PAM hook (passwd, GNOME Settings) ----
mkdir -p "$T/pam.d"
# pam_permit stands in for pam_unix (the account password itself).
printf 'password required pam_permit.so\npassword optional %s/pam_aurora_sep_fde.so prompt helper=%s\n' "$H" "$F" >"$T/pam.d/aurora-test"
printf 'password required pam_permit.so\npassword optional %s/pam_aurora_sep_fde.so prompt_new helper=%s\n' "$H" "$F" >"$T/pam.d/aurora-reset"
if try "$B/pam-drive" "$T/pam.d" aurora-test alice "$T/alice.2" "$T/alice.3"; then pass "pam: alice changes her password through PAM"; else fail "pam change"; fi
opens "$A" alice.3 && opens "$Bv" alice.3 && pass "pam: the new password opens both volumes" || fail "pam new pw"
opens "$A" alice.2 && fail "pam: old password still opens" || pass "pam: the old password is refused"
if "$B/pam-drive" "$T/pam.d" aurora-test alice "$T/bad" "$T/alice.2" >"$T/out" 2>&1 && said "could not be changed"; then pass "pam: a wrong current password changes nothing and says so"; else cat "$T/out"; fail "pam wrong old"; fi
opens "$A" alice.3 && pass "pam: still the last good password" || fail "pam after wrong old"
if try "$B/pam-drive" "$T/pam.d" aurora-test dave "$T/dave" "$T/dave.2"; then pass "pam: a user without disk passwords is not affected"; else fail "pam dave"; fi
if "$B/pam-drive" "$T/pam.d" aurora-reset carol "$T/carol.2" "$T/carol.2" >"$T/out" 2>&1 && said "volume owner can reset"; then pass "pam: a reset without the old password leaves the disk password and says how to reset it"; else cat "$T/out"; fail "pam root reset"; fi
opens "$A" carol && pass "pam: carol's disk password is unchanged after an admin reset" || fail "carol changed"

# ---- owner reset (forgotten password) ----
if try "$F" reset-password --user carol --auth-user alice --auth-password-file "$T/alice.3" --new-file "$T/carol.2" "$A"; then pass "owner alice resets carol's password"; else fail "owner reset"; fi
opens "$A" carol.2 && pass "carol's new password opens" || fail "carol new"
opens "$A" carol && fail "carol's forgotten password still opens" || pass "carol's forgotten password is refused"
"$F" status "$A" | grep -q "user carol .*unlock only" && pass "a reset keeps carol a non-owner" || fail "carol role after reset"
[ "$("$F" status "$A" | grep -c 'user carol')" = 1 ] && pass "one token for carol after the reset" || fail "carol tokens"

# ---- recovery key ----
if try "$F" recovery --unlock-key-file "$T/pass" --recovery-key-file "$T/rk" "$A" && said "offline recovery keyslot"; then pass "recovery key, offline slot (recovery = offline)"; else fail "recovery offline"; fi
if "$F" test --recovery-key-file "$T/rk" "$A" >/dev/null 2>&1 && cryptsetup --disable-locks --disable-external-tokens open --test-passphrase --key-file "$T/rk" "$A"; then pass "recovery key opens with and without the SEP"; else fail "recovery opens"; fi
printf 'recovery = sep-only\n' >"$T/fde.conf"
if try "$F" recovery --unlock-key-file "$T/pass" --recovery-key-file "$T/rk2" "$Bv" && ! said "offline"; then pass "recovery = sep-only: no offline slot"; else fail "recovery sep-only"; fi
if cryptsetup --disable-locks --disable-external-tokens open --test-passphrase --key-file "$T/rk2" "$Bv" 2>/dev/null; then fail "sep-only key opened without the SEP"; else pass "sep-only recovery key needs the SEP"; fi
"$F" test --recovery-key-file "$T/rk2" "$Bv" >/dev/null 2>&1 && pass "sep-only recovery key opens through the SEP" || fail "sep-only rk"
printf 'recovery = offline\n' >"$T/fde.conf"
if try "$F" reset-password --user alice --recovery-key-file "$T/rk" --new-file "$T/alice" "$A"; then pass "recovery key resets an owner's password"; else fail "rk reset"; fi
opens "$A" alice && owner_of "$A" alice && pass "alice opens again and is still an owner" || fail "alice after rk reset"

# ---- anti-hammering counter ----
reboot_mac
for i in 1 2 3; do opens "$A" bad || true; done
[ "$(attempts "$A" alice)" -ge 3 ] && pass "three wrong passwords counted by the enclave" || fail "count $(attempts "$A" alice)"
reboot_mac
opens "$A" bad || true
n=$(attempts "$A" alice)
[ "${n:-0}" -ge 4 ] && pass "the count survives a reboot (the double models a persistent enclave counter)" || fail "count after reboot $n"
opens "$A" alice && [ "$(attempts "$A" alice)" = 0 ] && pass "the right password clears the count" || fail "count not cleared"

# ---- damaged slots ----
cp "$A" "$T/dmg.img"
tok=$($CS0 luksDump --dump-json-metadata "$T/dmg.img" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(next(k for k,v in d["tokens"].items() if v.get("aurora_sep_user")=="bob"))')
$CS0 token export --token-id "$tok" "$T/dmg.img" >"$T/tok.json"
python3 - "$T/tok.json" <<'PY'
import json,sys
p=sys.argv[1]; d=json.load(open(p)); d["aurora_sep_bag"]="zz"+d["aurora_sep_bag"][2:]; json.dump(d,open(p,"w"))
PY
$CS0 token remove --token-id "$tok" "$T/dmg.img"
if $CS0 token import --external-tokens-path "$B" --token-id "$tok" --json-file "$T/tok.json" "$T/dmg.img" 2>/dev/null; then :; else
	$CS0 token import --disable-external-tokens --token-id "$tok" --json-file "$T/tok.json" "$T/dmg.img"; fi
"$F" status "$T/dmg.img" | grep -q DAMAGED && pass "a damaged token is reported" || fail "damaged not reported"
opens "$T/dmg.img" alice && opens "$T/dmg.img" carol.2 && pass "other users unlock past a damaged token" || fail "damaged token blocks others"
opens "$T/dmg.img" bob && fail "damaged token opened" || pass "the damaged user is refused (owner resets them)"
cp "$A" "$T/noslot.img"
ks=$("$F" status "$T/noslot.img" | sed -n 's/^token [0-9]*: keyslot \([0-9]*\), user bob .*/\1/p')
$CS0 luksKillSlot -q --key-file "$T/pass" "$T/noslot.img" "$ks" 2>/dev/null || $CS0 luksKillSlot -q "$T/noslot.img" "$ks" </dev/null
if no "$F" add-user --user dave --auth-user bob --auth-password-file "$T/bob" --password-file "$T/dave" "$T/noslot.img"; then pass "a token whose keyslot is gone cannot authorize"; else fail "slotless token authorized"; fi
opens "$T/noslot.img" alice && pass "others still unlock with a destroyed keyslot" || fail "noslot others"

echo "test-owners: $fails failure(s)"
[ "$fails" = 0 ]
