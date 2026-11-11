#!/bin/sh
# SPDX-License-Identifier: MIT
# Disk-key defaults, against the file-backed enclave double (SEP_FDE_MOCK):
# - the recovery key is a choice: an offline LUKS2 keyslot too (default, also
#   with no fde.conf) or SEP only (fde.conf or --sep-only), --replace switches;
# - every sealed secret is bound to the OS install it was made under
#   ($AURORA_SEP_FDE_ROOT/proc/device-tree/chosen/apfs-preboot-uuid, or the
#   apple_sep os_uuid pin);
# - boot-chain = audit | require before every enclave volume unlock, and the
#   boot-chain command that flips it per Mac (guarded on a verified boot).
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

# ---- boot-chain = audit | require, at every unlock ----
new_mac
printf 'recovery = offline\n' >"$T/fde.conf"
img=$T/i.img; newvol "$img"
try "$F" enroll --user alice --unlock-key-file "$T/pass" --password-file "$T/alice" "$img" || fail "enroll i"
I=$T/initrd; BS=$I/sys/firmware/aurora/boot_security
mkdir -p "$I/etc" "$BS"; : >"$I/etc/initrd-release"
st() { # <state|absent> [advisory] [measurements...]
	rm -f "$BS/state" "$BS/advisory" "$BS/measurements"
	[ "$1" = absent ] && return 0
	printf '%s\n' "$1" >"$BS/state"; shift
	[ $# -gt 0 ] && { printf '%s\n' "$1" >"$BS/advisory"; shift; }
	for m in "$@"; do printf '%s\n' "$m" >>"$BS/measurements"; done
	return 0
}
H=0000000000000000000000000000000000000000000000000000000000000000
export AURORA_SEP_FDE_ROOT="$I"
st partial 1 "stage1 audit stage2 verified $H" "stage2 enforce u-boot verified $H"
if try "$F" test --password-file "$T/alice" "$img" && said 'boot-chain = audit: require would refuse the Secure Enclave unlock of' &&
   said 'boot chain partial, advisory, first unverified link: stage1 stage2 (audit, verified)' && said "LUKS UUID $(cryptsetup luksUUID "$img")"; then
	pass "audit (default): one line with chain state, first unverified link and the volume; SEP unlock goes on"; else fail "audit partial"; fi
"$F" test --password-file "$T/alice" "$img" >"$T/out" 2>&1 || fail "audit second open"
if said 'require would refuse'; then pass "audit: a line for every unlock"; else fail "audit line only once"; fi
if [ "$(grep -c 'require would refuse' "$T/out")" = 1 ]; then pass "audit: one line per unlock, not one per token"; else fail "audit line per token"; fi
st partial 0 "stage1 enforce stage2 verified $H" "stage2 enforce u-boot verified $H" "u-boot off kernel unverified $H"
if try "$F" test --password-file "$T/alice" "$img" && said 'first unverified link: u-boot kernel (off, unverified)'; then
	pass "audit: the first link that is not enforced+verified is named"; else fail "first gap later stage"; fi
st absent
if try "$F" test --password-file "$T/alice" "$img" && said 'boot chain none' && said 'no boot record'; then pass "audit: no boot record, unlock goes on"; else fail "audit absent"; fi
st verified 0 "stage1 enforce stage2 verified $H"
if try "$F" test --password-file "$T/alice" "$img" && ! said 'boot-chain ='; then pass "verified chain: no line"; else fail "verified"; fi
st verified 1
if try "$F" test --password-file "$T/alice" "$img" && said 'boot chain verified, advisory'; then pass "verified but advisory counts as not verified"; else fail "advisory verified"; fi
printf 'recovery = offline\nboot-chain = warn\n' >"$T/fde.conf"
st unverified 1
if try "$F" test --password-file "$T/alice" "$img" && said 'boot-chain = audit'; then pass "warn (old name) is audit"; else fail "warn alias"; fi
printf 'recovery = offline\nboot-chain = require\n' >"$T/fde.conf"
st unverified 1 "stage1 off stage2 unverified $H"
if no "$F" test --password-file "$T/alice" "$img" && said 'boot-chain = require: refused the Secure Enclave unlock of' && said 'stage1 stage2 (off, unverified)'; then
	pass "require: unverified chain, no SEP unlock, says why"; else fail "require unverified"; fi
if $CS0 --disable-external-tokens open --test-passphrase --key-file "$T/pass" "$img" >/dev/null 2>&1; then pass "require: the passphrase prompt still opens the volume"; else fail "require passphrase"; fi
st absent
if no "$F" test --password-file "$T/alice" "$img"; then pass "require: no boot record, no SEP unlock"; else fail "require absent"; fi
st verified 0 "stage1 enforce stage2 verified $H"
if try "$F" test --password-file "$T/alice" "$img"; then pass "require: verified chain unlocks"; else fail "require verified"; fi
rm -f "$I/etc/initrd-release"
st unverified 1
if no "$F" test --password-file "$T/alice" "$img"; then pass "require applies on the real root too (non-root volumes)"; else fail "require on the real root"; fi
"$F" status "$img" >"$T/out" 2>&1
if said 'boot chain: unverified, advisory, first unverified link:' && said 'boot-chain = require: the Secure Enclave unlocks nothing'; then pass "status shows the chain, first gap and decision"; else fail "status chain"; fi

# ---- boot-chain audit | require: the per-Mac flip and its guard ----
: >"$T/fde-volumes"
printf '# kept comment\nrecovery = offline\nboot-chain = audit\nadmin-groups = wheel\n' >"$T/fde.conf"
export AURORA_SEP_FDE_INITRAMFS_CMD="$T/regen"
printf '#!/bin/sh\necho regen >>"%s/regen.log"\n' "$T" >"$T/regen"; chmod +x "$T/regen"
"$F" boot-chain >"$T/out" 2>&1
if said 'require can be switched on here: no'; then pass "boot-chain: says require cannot be switched on here"; else fail "boot-chain show"; fi
if no "$F" boot-chain require && said 'refusing boot-chain = require' && grep -q '^boot-chain = audit$' "$T/fde.conf" && [ ! -e "$T/regen.log" ]; then
	pass "require refused on an unverified boot; fde.conf and initramfs untouched"; else fail "require guard"; fi
if try "$F" boot-chain require --force && grep -q '^boot-chain = require$' "$T/fde.conf" && grep -q '^# kept comment$' "$T/fde.conf" &&
   grep -q '^admin-groups = wheel$' "$T/fde.conf" && [ "$(grep -c boot-chain "$T/fde.conf")" = 1 ] && [ "$(wc -l <"$T/regen.log")" = 1 ]; then
	pass "--force switches require, keeps the other lines, rebuilds the initramfs"; else fail "require --force"; fi
if try "$F" boot-chain audit --no-initramfs && grep -q '^boot-chain = audit$' "$T/fde.conf" && [ "$(wc -l <"$T/regen.log")" = 1 ] && said 'not rebuilt'; then
	pass "audit: always allowed; --no-initramfs skips the rebuild"; else fail "audit flip"; fi
printf '#!/bin/sh\nexit 1\n' >"$T/regen"
if no "$F" boot-chain require --force && grep -q '^boot-chain = audit$' "$T/fde.conf" && said 'back to audit'; then
	pass "a failed initramfs rebuild puts the old policy back"; else fail "regen failure rollback"; fi
st verified 0 "stage1 enforce stage2 verified $H"
printf '#!/bin/sh\nexit 0\n' >"$T/regen"
if try "$F" boot-chain require && grep -q '^boot-chain = require$' "$T/fde.conf"; then pass "require on a verified boot needs no --force"; else fail "require verified flip"; fi
"$F" boot-chain audit --no-initramfs >/dev/null 2>&1
st unverified 1
# a registered volume that only the enclave opens: --force must not strand it
j=$T/j.img; newvol "$j"
try "$F" enroll --user alice --unlock-key-file "$T/pass" --password-file "$T/alice" "$j" || fail "enroll j"
printf '%s\n' "$j" >"$T/fde-volumes"
$CS0 luksRemoveKey "$j" "$T/pass" </dev/null >/dev/null 2>&1 || fail "remove j passphrase"
if no "$F" boot-chain require --force && said 'has no passphrase or offline recovery keyslot' && grep -q '^boot-chain = audit$' "$T/fde.conf"; then
	pass "--force refused while a registered volume opens only through the enclave"; else fail "force strand guard"; fi
rm -f "$T/fde-volumes"
ln -sf "$T/fde.conf" "$T/fde-link.conf"
if AURORA_SEP_FDE_CONF="$T/fde-link.conf" no "$F" boot-chain audit && said 'is a link'; then pass "a linked (system-managed) fde.conf is left alone"; else fail "symlink conf"; fi
unset AURORA_SEP_FDE_ROOT AURORA_SEP_FDE_INITRAMFS_CMD

echo "test-policy: $fails failure(s)"
[ "$fails" = 0 ]
