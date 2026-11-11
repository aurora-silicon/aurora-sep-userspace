#!/bin/sh
# SPDX-License-Identifier: MIT
# Disk-key defaults, against the file-backed enclave double (SEP_FDE_MOCK):
# - the recovery key is a choice: an offline LUKS2 keyslot too (default, also
#   with no fde.conf) or SEP only (fde.conf or --sep-only), --replace switches;
# - every sealed secret is bound to the OS install it was made under
#   ($AURORA_SEP_FDE_ROOT/proc/device-tree/chosen/apfs-preboot-uuid, or the
#   apple_sep os_uuid pin);
# - boot-chain = warn | require before the initramfs asks the enclave.
# Usage: tests/test-policy.sh <test build dir>
set -eu
B=$(cd "$1" && pwd)
T=$(mktemp -d)
trap 'rm -rf "${T:?}"' EXIT
export AURORA_SEP_TOKEN_DIR="$B"
export AURORA_SEP_FDE_MOCK="$T/mac"; mkdir -p "$AURORA_SEP_FDE_MOCK"
export AURORA_SEP_FDE_CONF="$T/fde.conf" AURORA_SEP_FDE_VOLUMES="$T/fde-volumes"
export AURORA_SEP_FDE_PASSWD="$T/passwd" AURORA_SEP_FDE_GROUP="$T/group"
unset SUDO_USER AURORA_SEP_FDE_ROOT AURORA_SEP_FDE_MOCK_NO_OS
CS0="cryptsetup --disable-locks --batch-mode"
F="$B/aurora-sep-fde"
fails=0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1"; fails=$((fails + 1)); }
try() { if "$@" >"$T/out" 2>&1; then return 0; else cat "$T/out" >&2; return 1; fi; }
no() { if "$@" >"$T/out" 2>&1; then cat "$T/out" >&2; return 1; else return 0; fi; }
said() { grep -q -- "$1" "$T/out"; }
offline_opens() { $CS0 --disable-external-tokens open --test-passphrase --key-file "$2" "$1" >/dev/null 2>&1; }
new_mac() { rm -rf "${T:?}/mac"; mkdir -p "$T/mac"; }

cat >"$T/passwd" <<'PW'
root:x:0:0:root:/root:/bin/bash
alice:x:1000:1000:Alice:/home/alice:/bin/bash
PW
cat >"$T/group" <<'GR'
root:x:0:
wheel:x:10:alice
alice:x:1000:
GR
printf 'installer passphrase\n' >"$T/pass"
printf 'alice-pw-1' >"$T/alice"

# A fake system root: OS identity, boot record, initramfs marker.
mkos() { # <root> <uuid>
	mkdir -p "$1/proc/device-tree/chosen"
	printf '%s\0' "$2" >"$1/proc/device-tree/chosen/apfs-preboot-uuid"
}
OS_A=$T/os-a; OS_B=$T/os-b
mkos "$OS_A" 4C1E2B3A-1111-4222-8333-944455556666
mkos "$OS_B" 0D9F8E7C-aaaa-4bbb-8ccc-dddddddddddd

newvol() { # <img>
	rm -f "$1"; truncate -s 32M "$1"
	$CS0 luksFormat --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
		--luks2-metadata-size 128k --luks2-keyslots-size 2m "$1" "$T/pass"
}

# ---- recovery key: offline by default ----
rm -f "$T/fde.conf"	# no configuration at all
img=$T/a.img; newvol "$img"
try "$F" enroll --user alice --unlock-key-file "$T/pass" --password-file "$T/alice" "$img" || fail "enroll alice"
if try "$F" recovery --unlock-key-file "$T/pass" --recovery-key-file "$T/rk-a" "$img" && said 'offline recovery keyslot'; then
	pass "no fde.conf: the recovery key gets an offline keyslot"; else fail "default recovery mode"; fi
if offline_opens "$img" "$T/rk-a"; then pass "default recovery key opens without the SEP"; else fail "default offline open"; fi
"$F" status "$img" >"$T/out"
if said 'recovery keys: offline keyslot too (recovery = offline, the default)'; then pass "status names the default recovery mode"; else fail "status default mode"; fi
if no "$F" recovery --unlock-key-file "$T/pass" --recovery-key-file "$T/rk-x" "$img" && said '--replace'; then
	pass "a second recovery key needs --replace"; else fail "second recovery key"; fi
printf '# empty\n' >"$T/fde.conf"
img=$T/b.img; newvol "$img"
if try "$F" recovery --uid 60301 --unlock-key-file "$T/pass" --recovery-key-file "$T/rk-b" "$img" && offline_opens "$img" "$T/rk-b"; then
	pass "fde.conf without the key: offline"; else fail "empty conf"; fi

# ---- SEP only: fde.conf or --sep-only ----
printf 'recovery = sep-only\n' >"$T/fde.conf"
img=$T/c.img; newvol "$img"
if try "$F" recovery --uid 60302 --unlock-key-file "$T/pass" --recovery-key-file "$T/rk-c" "$img" && said 'SEP-only recovery key'; then
	pass "recovery = sep-only: no offline keyslot"; else fail "sep-only conf"; fi
if offline_opens "$img" "$T/rk-c"; then fail "a SEP-only recovery key opened a plain keyslot"; else pass "SEP-only recovery key does not open without the SEP"; fi
if "$F" test --recovery-key-file "$T/rk-c" "$img" >/dev/null 2>&1; then pass "SEP-only recovery key opens through the enclave"; else fail "sep-only through SEP"; fi
"$F" status "$img" >"$T/out"
if said 'SEP only (no offline keyslot)' && said 'recovery keys: SEP only (recovery = sep-only)'; then pass "status shows SEP only"; else fail "status sep-only"; fi
img=$T/d.img; newvol "$img"
if try "$F" recovery --uid 60303 --offline --unlock-key-file "$T/pass" --recovery-key-file "$T/rk-d" "$img" && offline_opens "$img" "$T/rk-d"; then
	pass "--offline overrides recovery = sep-only"; else fail "--offline override"; fi
printf 'recovery = offline\n' >"$T/fde.conf"
img=$T/e.img; newvol "$img"
if try "$F" recovery --uid 60304 --sep-only --unlock-key-file "$T/pass" --recovery-key-file "$T/rk-e" "$img" && ! offline_opens "$img" "$T/rk-e"; then
	pass "--sep-only at enrol time"; else fail "--sep-only flag"; fi
r=0; "$F" recovery --uid 60305 --sep-only --offline --unlock-key-file "$T/pass" "$img" >"$T/out" 2>&1 || r=$?
if [ "$r" = 2 ] && said 'exclude each other'; then pass "--sep-only with --offline refused"; else fail "both flags ($r)"; fi

# ---- --replace switches modes and removes the old key ----
if try "$F" recovery --replace --offline --unlock-key-file "$T/pass" --recovery-key-file "$T/rk-e2" "$img" && said 'old recovery key removed'; then
	pass "--replace makes a new recovery key"; else fail "replace"; fi
if offline_opens "$img" "$T/rk-e2"; then pass "replaced SEP-only key with an offline one"; else fail "replace offline"; fi
if "$F" test --recovery-key-file "$T/rk-e" "$img" >/dev/null 2>&1; then fail "old recovery key still opens"; else pass "old recovery key no longer opens"; fi
n=$("$F" status "$img" | grep -c ', recovery')
[ "$n" = 1 ] && pass "one recovery token after --replace" || fail "recovery tokens $n"
# installer passphrase gone: the owner authorizes the replacement
img=$T/f.img; newvol "$img"
try "$F" enroll --user alice --unlock-key-file "$T/pass" --password-file "$T/alice" "$img" || fail "enroll alice f"
try "$F" recovery --uid 60306 --unlock-key-file "$T/pass" --recovery-key-file "$T/rk-f" "$img" || fail "recovery f"
try "$F" remove-passphrase --unlock-key-file "$T/pass" "$img" || fail "remove passphrase f"
if try "$F" recovery --replace --sep-only --auth-user alice --auth-password-file "$T/alice" --recovery-key-file "$T/rk-f2" "$img"; then
	pass "--replace authorized by a volume owner (no installer passphrase)"; else fail "replace by owner"; fi
if "$F" test --recovery-key-file "$T/rk-f2" "$img" >/dev/null 2>&1 && ! offline_opens "$img" "$T/rk-f" && ! offline_opens "$img" "$T/rk-f2"; then
	pass "old offline keyslot removed, new key SEP only"; else fail "replace by owner result"; fi

# ---- one disk key per OS install ----
new_mac
img=$T/g.img; newvol "$img"
export AURORA_SEP_FDE_ROOT="$OS_A"
try "$F" enroll --user alice --unlock-key-file "$T/pass" --password-file "$T/alice" "$img" || fail "enroll under OS A"
try "$F" recovery --uid 60307 --unlock-key-file "$T/pass" --recovery-key-file "$T/rk-g" "$img" || fail "recovery under OS A"
if $CS0 luksDump --dump-json-metadata "$img" | grep -q '"aurora_sep_os_uuid":"4c1e2b3a-1111-4222-8333-944455556666"'; then
	pass "token records the OS install (lower case)"; else fail "token os uuid"; fi
"$F" status "$img" >"$T/out"
if said 'OS install 4c1e2b3a-1111-4222-8333-944455556666, enclave' && ! said 'another OS install'; then pass "status: this OS install"; else fail "status os A"; fi
if "$F" test --password-file "$T/alice" "$img" >/dev/null 2>&1; then pass "password opens under the same OS install"; else fail "same OS"; fi
export AURORA_SEP_FDE_ROOT="$OS_B"
if no "$F" test --password-file "$T/alice" "$img" && said 'belongs to another OS install on this Mac'; then
	pass "another OS install on the same Mac: password refused, says why"; else fail "other OS password"; fi
if no "$F" test --recovery-key-file "$T/rk-g" "$img"; then pass "another OS install: recovery token refused by the enclave path"; else fail "other OS recovery token"; fi
if offline_opens "$img" "$T/rk-g"; then pass "another OS install: the recovery key's offline keyslot still opens"; else fail "other OS offline"; fi
"$F" status "$img" >"$T/out"
if said '(another OS install)'; then pass "status flags a token from another OS install"; else fail "status other OS"; fi
export AURORA_SEP_FDE_ROOT="$OS_A"
if "$F" test --password-file "$T/alice" "$img" >/dev/null 2>&1; then pass "back on its own OS install it opens again"; else fail "back to OS A"; fi
# the explicit apple_sep os_uuid pin wins over /chosen, as in the driver
P=$T/os-pin; mkos "$P" 0D9F8E7C-AAAA-4BBB-8CCC-DDDDDDDDDDDD
mkdir -p "$P/sys/module/apple_sep/parameters"
printf '%s\n' 5484868924578284066 >"$P/sys/module/apple_sep/parameters/os_uuid_hi"	# 0x4c1e2b3a11114222
printf '%s\n' 9454063063991150182 >"$P/sys/module/apple_sep/parameters/os_uuid_lo"	# 0x8333944455556666
export AURORA_SEP_FDE_ROOT="$P"
if "$F" test --password-file "$T/alice" "$img" >/dev/null 2>&1; then pass "the os_uuid pin selects the OS install"; else fail "os_uuid pin"; fi
"$F" status "$img" >"$T/out" 2>&1 || :
if said 'OS install: 4c1e2b3a-1111-4222-8333-944455556666'; then pass "status prints the pinned OS install"; else fail "status pin"; fi
unset AURORA_SEP_FDE_ROOT
img=$T/h.img; newvol "$img"
if AURORA_SEP_FDE_MOCK_NO_OS=1 no "$F" enroll --uid 60308 --unlock-key-file "$T/pass" --password-file "$T/alice" "$img" && said 'no OS identity'; then
	pass "no OS identity: enrolment refused, says why"; else fail "no OS identity"; fi

# ---- boot-chain = warn | require, in the initramfs ----
new_mac
printf 'recovery = offline\n' >"$T/fde.conf"
img=$T/i.img; newvol "$img"
try "$F" enroll --user alice --unlock-key-file "$T/pass" --password-file "$T/alice" "$img" || fail "enroll i"
I=$T/initrd; mkdir -p "$I/etc" "$I/sys/firmware/aurora/boot_security"; : >"$I/etc/initrd-release"
st() {
	if [ "$1" = absent ]; then rm -f "$T/initrd/sys/firmware/aurora/boot_security/state"
	else printf '%s\n' "$1" >"$T/initrd/sys/firmware/aurora/boot_security/state"; fi
	rm -rf "${T:?}/initrd/run"
}
export AURORA_SEP_FDE_ROOT="$I"
st partial
if try "$F" test --password-file "$T/alice" "$img" && said 'warning: boot chain partial' && said 'boot-chain = warn'; then
	pass "warn (default): unverified chain logged, SEP unlock goes on"; else fail "warn partial"; fi
"$F" test --password-file "$T/alice" "$img" >"$T/out" 2>&1 || fail "warn second open"
if said 'warning: boot chain'; then fail "warn line repeated in the same boot"; else pass "warn logged once per boot"; fi
st absent
if try "$F" test --password-file "$T/alice" "$img" && said 'boot chain unknown'; then pass "warn: no boot record = unknown, unlock goes on"; else fail "warn absent"; fi
st verified
if try "$F" test --password-file "$T/alice" "$img" && ! said 'boot chain'; then pass "verified chain: no warning"; else fail "verified"; fi
printf 'recovery = offline\nboot-chain = require\n' >"$T/fde.conf"
st unverified
if no "$F" test --password-file "$T/alice" "$img" && said 'boot-chain = require'; then pass "require: unverified chain, no SEP unlock"; else fail "require unverified"; fi
if $CS0 --disable-external-tokens open --test-passphrase --key-file "$T/pass" "$img" >/dev/null 2>&1; then pass "require: the passphrase prompt still opens the volume"; else fail "require passphrase"; fi
st absent
if no "$F" test --password-file "$T/alice" "$img"; then pass "require: no boot record, no SEP unlock"; else fail "require absent"; fi
st verified
if try "$F" test --password-file "$T/alice" "$img"; then pass "require: verified chain unlocks"; else fail "require verified"; fi
st unverified
"$F" boot-chain >"$T/out"
if said 'boot chain unverified, boot-chain = require: the initramfs does not ask the Secure Enclave'; then pass "boot-chain command reports the decision"; else fail "boot-chain command"; fi
rm -f "$T/initrd/etc/initrd-release"
if try "$F" test --password-file "$T/alice" "$img"; then pass "require applies only in the initramfs"; else fail "require on the real root"; fi
unset AURORA_SEP_FDE_ROOT

echo "test-policy: $fails failure(s)"
[ "$fails" = 0 ]
