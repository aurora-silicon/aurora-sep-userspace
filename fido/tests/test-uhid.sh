#!/bin/bash
# shellcheck disable=SC2015 # ok/no always succeed
# SPDX-License-Identifier: MIT
# End to end through a real /dev/uhid device with libfido2's tools, OpenSSH
# and (when installed) pam_u2f and systemd-cryptenroll. Software keys and a
# scripted Touch ID from tests/stub.py stand in for the Secure Enclave and
# fprintd. Needs root and the uhid module.
#
#   sudo tests/test-uhid.sh            all checks
#   sudo KEEP=1 tests/test-uhid.sh     keep the work dir for a look afterwards
#   sudo KEYS=sep tests/test-uhid.sh   keys in the Secure Enclave (/dev/sep-key)
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d "${TMPDIR:-/var/tmp}/aurora-fido-uhid.XXXXXX")
pass=0 fail=0 skip=0
ok() { echo "PASS $*"; pass=$((pass + 1)); }
no() { echo "FAIL $*"; fail=$((fail + 1)); }
sk() { echo "SKIP $*"; skip=$((skip + 1)); }
pid=
loopdev=

stop() {
	[ -n "$pid" ] && kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null
	pid=
}
cleanup() {
	stop
	[ -n "$loopdev" ] && { cryptsetup close aurora-fido-test 2>/dev/null; losetup -d "$loopdev"; }
	rm -f /etc/pam.d/aurora-fido-test
	[ -n "${KEEP:-}" ] && echo "work dir: $work" || rm -rf "$work"
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "needs root (uhid)"; exit 2; }
modprobe uhid 2>/dev/null || true
command -v fido2-token >/dev/null || { echo "needs fido2-tools (libfido2)"; exit 2; }

dev=
start() {   # start TOUCH_MODE
	stop
	python3 "$here/run-stub-daemon.py" --state-dir "$work/state" --touch "$1" --keys "${KEYS:-stub}" \
		>>"$work/daemon.log" 2>&1 &
	pid=$!
	dev=
	# Older libfido2 names devices from USB attributes, which a uhid device
	# does not have, so find it by its HID_PHYS and check libfido2 lists it.
	for _ in $(seq 100); do
		for h in /sys/class/hidraw/hidraw*; do
			grep -qx "HID_PHYS=aurora-fido-test" "$h/device/uevent" 2>/dev/null &&
				dev=/dev/$(basename "$h") && break
		done
		[ -n "$dev" ] && fido2-token -L 2>/dev/null | grep -q "^$dev:" && break
		dev=
		sleep 0.1
	done
	[ -n "$dev" ]
}

diagnose() {
	echo "--- daemon log"; cat "$work/daemon.log"
	echo "--- fido2-token -L"; fido2-token -L 2>&1
	echo "--- hidraw"; ls -l /dev/hidraw* 2>&1
	for h in /sys/class/hidraw/hidraw*; do [ -e "$h" ] && echo "$h: $(cat "$h/device/uevent" 2>/dev/null | tr '\n' ' ')"; done
	echo "--- modules"; lsmod | grep -E '^(uhid|hid|hid_generic|hidraw)\b' || true
	echo "--- dmesg"; dmesg 2>/dev/null | tail -15
}

b64() { base64 -w0; }

start match && ok "device appears in fido2-token -L: $dev" || { no "no device"; diagnose; exit 1; }

info=$(fido2-token -I "$dev" 2>&1)
echo "$info" | sed 's/^/    /'
for want in "FIDO_2_1" "U2F_V2" "credMgmt" "uv" "rk" "pinUvAuthToken" "hmac-secret" "credProtect" "es256"; do
	grep -q -- "$want" <<<"$info" && ok "getInfo lists $want" || no "getInfo lacks $want"
done
grep -q -- "clientPin" <<<"$info" && no "getInfo claims a PIN" || ok "no PIN offered"

# makeCredential + verify (packed self attestation), getAssertion + verify.
cdh=$(head -c32 /dev/urandom | b64)
uid=$(head -c16 /dev/urandom | b64)
printf '%s\n%s\n%s\n%s\n' "$cdh" "fido.example" "ryan" "$uid" >"$work/cred.in"
if fido2-cred -M -i "$work/cred.in" -o "$work/cred.out" "$dev" es256 2>"$work/err"; then
	ok "fido2-cred -M (makeCredential)"
else
	no "fido2-cred -M: $(cat "$work/err")"
fi
if fido2-cred -V -i "$work/cred.out" -o "$work/cred.pub" es256 2>"$work/err"; then
	ok "fido2-cred -V: self attestation verifies"
else
	no "fido2-cred -V: $(cat "$work/err")"
fi
credid=$(sed -n 5p "$work/cred.out")
cdh2=$(head -c32 /dev/urandom | b64)
printf '%s\n%s\n%s\n' "$cdh2" "fido.example" "$credid" >"$work/as.in"
if fido2-assert -G -p -i "$work/as.in" -o "$work/as.out" "$dev" 2>"$work/err" &&
	fido2-assert -V -p -i "$work/as.out" "$work/cred.pub" es256 2>>"$work/err"; then
	ok "fido2-assert -G/-V (getAssertion, presence)"
else
	no "fido2-assert: $(cat "$work/err")"
fi
printf '%s\n%s\n%s\n' "$cdh2" "other.example" "$credid" >"$work/as2.in"
fido2-assert -G -i "$work/as2.in" -o /dev/null "$dev" 2>"$work/err" &&
	no "assertion for another RP" || ok "credential refused for another RP: $(tail -1 "$work/err")"

# hmac-secret (what systemd-cryptenroll uses).
printf '%s\n%s\n%s\n%s\n' "$cdh" "hmac.example" "ryan" "$uid" >"$work/hcred.in"
if fido2-cred -M -h -i "$work/hcred.in" -o "$work/hcred.out" "$dev" es256 2>"$work/err"; then
	salt=$(head -c32 /dev/urandom | b64)
	printf '%s\n%s\n%s\n%s\n' "$cdh2" "hmac.example" "$(sed -n 5p "$work/hcred.out")" "$salt" >"$work/has.in"
	h1=$(fido2-assert -G -h -i "$work/has.in" "$dev" 2>/dev/null | tail -1)
	h2=$(fido2-assert -G -h -i "$work/has.in" "$dev" 2>/dev/null | tail -1)
	[ -n "$h1" ] && [ "$h1" = "$h2" ] && ok "hmac-secret: stable 32-byte secret per salt" || no "hmac-secret ($h1 / $h2)"
else
	no "fido2-cred -M -h: $(cat "$work/err")"
fi

# Discoverable credentials and credential management.
printf '%s\n%s\n%s\n%s\n' "$cdh" "passkey.example" "ryan" "$uid" >"$work/rk.in"
fido2-cred -M -r -i "$work/rk.in" -o "$work/rk.out" "$dev" es256 2>"$work/err" &&
	ok "fido2-cred -M -r (passkey)" || no "resident: $(cat "$work/err")"
rps=$(fido2-token -L -r "$dev" 2>"$work/err" </dev/null)
grep -q passkey.example <<<"$rps" && ok "fido2-token -L -r lists passkey.example (credMgmt via Touch ID token)" ||
	no "list RPs: $rps $(cat "$work/err")"
creds=$(fido2-token -L -k passkey.example "$dev" 2>"$work/err" </dev/null)
grep -q "$(sed -n 5p "$work/rk.out")" <<<"$creds" && ok "fido2-token -L -k lists the credential" ||
	no "list creds: $creds $(cat "$work/err")"
printf '%s\n%s\n' "$cdh2" "passkey.example" >"$work/rkas.in"
fido2-assert -G -r -i "$work/rkas.in" -o /dev/null "$dev" 2>"$work/err" &&
	ok "fido2-assert -r (discoverable sign-in)" || no "discoverable assertion: $(cat "$work/err")"
fido2-token -D -i "$(sed -n 5p "$work/rk.out")" "$dev" 2>"$work/err" </dev/null &&
	ok "fido2-token -D deletes it" || no "delete: $(cat "$work/err")"
fido2-token -L -r "$dev" 2>/dev/null </dev/null | grep -q passkey.example &&
	no "still listed after delete" || ok "gone after delete"

# OpenSSH security keys.
if command -v ssh-keygen >/dev/null; then
	if SSH_SK_PROVIDER=internal ssh-keygen -q -t ecdsa-sk -N "" -O "device=$dev" \
		-O application=ssh:aurora-test -f "$work/id_ecdsa_sk" </dev/null 2>"$work/err"; then
		ok "ssh-keygen -t ecdsa-sk"
		echo hello >"$work/msg"
		echo "test@aurora $(cut -d' ' -f1,2 "$work/id_ecdsa_sk.pub")" >"$work/allowed"
		if ssh-keygen -q -Y sign -f "$work/id_ecdsa_sk" -n file "$work/msg" </dev/null 2>"$work/err" &&
			ssh-keygen -Y verify -f "$work/allowed" -I test@aurora -n file \
				-s "$work/msg.sig" <"$work/msg" >/dev/null 2>>"$work/err"; then
			ok "ssh-keygen -Y sign/verify with the sk key"
		else
			no "ssh sign: $(cat "$work/err")"
		fi
	else
		no "ssh-keygen ecdsa-sk: $(cat "$work/err")"
	fi
else
	sk "no ssh-keygen"
fi

# pam_u2f: register with pamu2fcfg, authenticate through PAM (pamtester, or
# tests/pam-auth.py where pamtester is not packaged). pamu2fcfg accepts self
# attestation from pam-u2f 1.1.1 on.
pamlib=$(find /usr/lib /lib /usr/lib64 -name pam_u2f.so 2>/dev/null | head -1)
u2fver=$(pamu2fcfg --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
if [ -z "$pamlib" ] || ! command -v pamu2fcfg >/dev/null; then
	sk "pam_u2f/pamu2fcfg not installed"
elif [ "$(printf '%s\n1.1.1\n' "$u2fver" | sort -V | head -1)" != 1.1.1 ]; then
	sk "pamu2fcfg $u2fver cannot verify self attestation (needs pam-u2f 1.1.1 or newer)"
elif pamu2fcfg -u root -o pam://aurora-test -i pam://aurora-test >"$work/u2f_keys" 2>"$work/err" </dev/null; then
	ok "pamu2fcfg $u2fver registers"
	printf 'auth required %s authfile=%s origin=pam://aurora-test appid=pam://aurora-test cue\n' \
		"$pamlib" "$work/u2f_keys" >/etc/pam.d/aurora-fido-test
	if command -v pamtester >/dev/null; then
		pamauth=(pamtester aurora-fido-test root authenticate)
	else
		pamauth=(python3 "$here/pam-auth.py" aurora-fido-test root)
	fi
	"${pamauth[@]}" >"$work/pam.out" 2>&1 </dev/null &&
		ok "pam_u2f authenticates ($(basename "${pamauth[0]}"))" || no "pam_u2f: $(cat "$work/pam.out")"
else
	no "pamu2fcfg: $(cat "$work/err")"
fi

# systemd-cryptenroll on a LUKS2 loop file.
if command -v systemd-cryptenroll >/dev/null && command -v cryptsetup >/dev/null && command -v losetup >/dev/null; then
	truncate -s 32M "$work/luks.img"
	echo -n "test-passphrase" >"$work/pass"
	if cryptsetup luksFormat -q --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
		"$work/luks.img" "$work/pass" 2>"$work/err" && loopdev=$(losetup -f --show "$work/luks.img"); then
		if PASSWORD=test-passphrase systemd-cryptenroll --fido2-device="$dev" \
			--fido2-with-client-pin=no "$loopdev" >"$work/enroll.out" 2>&1 </dev/null; then
			ok "systemd-cryptenroll --fido2-device"
			plugin=$(find /usr/lib /usr/lib64 -name libcryptsetup-token-systemd-fido2.so 2>/dev/null | head -1)
			attach=$(find /usr/lib/systemd /lib/systemd -maxdepth 1 -name systemd-cryptsetup 2>/dev/null | head -1)
			if [ -n "$plugin" ] && cryptsetup open --token-only "$loopdev" aurora-fido-test 2>"$work/err" </dev/null; then
				ok "LUKS2 volume opens with the security key (cryptsetup, systemd-fido2 token)"
				cryptsetup close aurora-fido-test
			elif [ -n "$attach" ] && "$attach" attach aurora-fido-test "$loopdev" - \
				"fido2-device=$dev,headless=true" >>"$work/err" 2>&1 </dev/null; then
				ok "LUKS2 volume opens with the security key (systemd-cryptsetup attach)"
				cryptsetup close aurora-fido-test
			elif [ -z "$plugin" ] && [ -z "$attach" ]; then
				sk "no systemd FIDO2 token plugin or systemd-cryptsetup to open the volume"
			else
				no "token open: $(cat "$work/err")"
			fi
		else
			no "cryptenroll: $(cat "$work/enroll.out")"
		fi
	else
		sk "cannot make a LUKS2 loop device: $(cat "$work/err")"
	fi
else
	sk "systemd-cryptenroll/cryptsetup not installed"
fi

# A refused Touch ID: nothing is made or signed.
start no-match || no "restart with a refusing Touch ID"
fido2-cred -M -i "$work/cred.in" -o /dev/null "$dev" es256 2>"$work/err" &&
	no "makeCredential without a match" || {
	grep -qi "denied" "$work/err" && ok "wrong finger: makeCredential refused ($(tail -1 "$work/err"))" ||
		no "wrong finger: unexpected error $(cat "$work/err")"
}
fido2-assert -G -p -i "$work/as.in" -o /dev/null "$dev" 2>"$work/err" &&
	no "assertion without a match" || ok "wrong finger: getAssertion refused ($(tail -1 "$work/err"))"
start timeout || no "restart with a timing-out Touch ID"
fido2-assert -G -p -i "$work/as.in" -o /dev/null "$dev" 2>"$work/err" &&
	no "assertion after a timeout" || {
	grep -qi "timeout" "$work/err" && ok "no touch: user action timeout ($(tail -1 "$work/err"))" ||
		no "timeout: unexpected error $(cat "$work/err")"
}
stop
grep -q "TEST HARNESS" "$work/daemon.log" && ok "harness says what keys it uses: $(grep -m1 -o 'TEST HARNESS: .*' "$work/daemon.log")" || no "harness warning missing"

echo
echo "uhid: $pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ]
