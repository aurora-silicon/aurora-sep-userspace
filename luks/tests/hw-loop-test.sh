#!/bin/sh
# SPDX-License-Identifier: MIT
# Hardware test of SEP-sealed LUKS2 unlock on an Aurora Mac (root, apple_sep loaded,
# aurora-sep-cryptenroll and the token plugin installed).
#
# It only ever touches ONE 64 MiB file under /var/tmp/aurora-sep-luks-test and
# the loop device it creates for it. No other disk, keyslot or crypttab entry.
#
#   hw-loop-test.sh seal      create the volume, enroll the SEP, unlock it two ways
#   (reboot)
#   hw-loop-test.sh unseal    unlock after the reboot, recovery passphrase, wrong-volume,
#                             SELinux denials since boot
#   hw-loop-test.sh cleanup   close everything and delete the directory
set -u
D=/var/tmp/aurora-sep-luks-test
IMG=$D/volume.img
NAME=aurora-sep-luks-test
fails=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; fails=$((fails + 1)); }
need_root() { [ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }; }

avc_count() {
	journalctl -b -o cat 2>/dev/null | grep -c -E 'avc:  denied|SELINUX_ERR' || true
}

close_all() {
	umount "$D/mnt" 2>/dev/null
	for n in $NAME $NAME-sd; do
		[ -e /dev/mapper/$n ] && cryptsetup close $n
	done
	if [ -f "$D/loop" ]; then
		losetup -d "$(cat "$D/loop")" 2>/dev/null
		rm -f "$D/loop"
	fi
}

attach_loop() {
	l=$(losetup -f --show "$IMG") || return 1
	echo "$l" > "$D/loop"
	echo "$l"
}

# Open with the token only, write or check the marker, close.
token_roundtrip() { # $1 = write|check
	dev=$(attach_loop) || { fail "loop attach"; return; }
	if cryptsetup open --token-only --token-type aurora-sep "$dev" $NAME; then
		pass "cryptsetup open --token-only (SEP unseal, dm-crypt active)"
	else
		fail "cryptsetup open --token-only"; close_all; return
	fi
	mkdir -p "$D/mnt"
	if [ "$1" = write ]; then
		mkfs.ext4 -q /dev/mapper/$NAME && mount /dev/mapper/$NAME "$D/mnt" &&
			cat /proc/sys/kernel/random/boot_id > "$D/mnt/sealed-at-boot" &&
			pass "wrote marker inside the encrypted volume" || fail "mkfs/mount/write"
	else
		mount -o ro /dev/mapper/$NAME "$D/mnt" && [ -s "$D/mnt/sealed-at-boot" ] &&
			pass "marker readable (sealed at boot $(cat "$D/mnt/sealed-at-boot"))" ||
			fail "marker check"
	fi
	close_all
}

# The crypttab path: systemd-cryptsetup in its own service context and SELinux domain.
systemd_roundtrip() {
	dev=$(attach_loop) || { fail "loop attach"; return; }
	if systemd-run --quiet --wait --collect --unit=$NAME-attach \
		/usr/lib/systemd/systemd-cryptsetup attach $NAME-sd "$dev" - headless=true,token-timeout=90; then
		[ -e /dev/mapper/$NAME-sd ] && pass "systemd-cryptsetup attach via the token (headless)" ||
			fail "systemd-cryptsetup attach left no mapping"
	else
		fail "systemd-cryptsetup attach"
	fi
	systemd-run --quiet --wait --collect --unit=$NAME-detach \
		/usr/lib/systemd/systemd-cryptsetup detach $NAME-sd >/dev/null 2>&1
	close_all
}

seal() {
	need_root
	[ -e "$D" ] && { echo "$D exists; run cleanup first"; exit 2; }
	mkdir -m 0700 -p "$D"
	cat /proc/sys/kernel/random/boot_id > "$D/boot-seal"
	avc_count > "$D/avc-seal-start"
	truncate -s 64M "$IMG"
	head -c 24 /dev/urandom | base64 > "$D/recovery"
	cryptsetup luksFormat -q --type luks2 "$IMG" "$D/recovery" && pass "luksFormat (recovery passphrase in keyslot 0)" ||
		{ fail "luksFormat"; exit 1; }
	if aurora-sep-cryptenroll --unlock-key-file="$D/recovery" "$IMG"; then
		pass "aurora-sep-cryptenroll"
	else
		fail "aurora-sep-cryptenroll"; exit 1
	fi
	cryptsetup luksDump "$IMG" | sed -n '/^Tokens:/,/^Digests:/p'
	token_roundtrip write
	systemd_roundtrip
	aurora-sep-cryptenroll --test "$IMG" | grep -q 'opens its keyslot' && pass "aurora-sep-cryptenroll --test" ||
		fail "--test"
	echo "new AVC/SELINUX_ERR since start: $(( $(avc_count) - $(cat "$D/avc-seal-start") ))"
	[ "$(avc_count)" = "$(cat "$D/avc-seal-start")" ] && pass "no new SELinux denials ($(getenforce))" ||
		fail "new SELinux denials"
	echo "seal: $fails failure(s)"
}

unseal() {
	need_root
	[ -f "$D/boot-seal" ] || { echo "no sealed volume; run seal first"; exit 2; }
	avc0=$(avc_count)
	if [ "$(cat /proc/sys/kernel/random/boot_id)" != "$(cat "$D/boot-seal")" ]; then
		pass "running in a later boot than the seal"
	else
		echo "NOTE same boot as the seal (no reboot in between)"
	fi
	token_roundtrip check
	systemd_roundtrip

	# Recovery passphrase with every token plugin disabled.
	dev=$(attach_loop)
	cryptsetup open --test-passphrase --disable-external-tokens --key-file "$D/recovery" "$dev" &&
		pass "recovery passphrase opens with tokens disabled" || fail "recovery passphrase"
	close_all

	# Same header under another volume UUID (stand-in for a copied or moved token).
	cp "$IMG" "$D/clone.img"
	cryptsetup luksUUID -q --uuid 6b7a0d6a-1111-4222-8333-944455556666 "$D/clone.img"
	dev=$(losetup -f --show "$D/clone.img")
	if cryptsetup open --test-passphrase --token-only "$dev" 2>/dev/null; then
		fail "token opened a volume it was not enrolled for"
	else
		pass "token refused on another volume UUID; passphrase fallback follows"
	fi
	cryptsetup open --test-passphrase --key-file "$D/recovery" "$dev" && pass "clone opens with recovery" || fail "clone recovery"
	losetup -d "$dev"; rm -f "$D/clone.img"

	# Blobs the SEP must not turn into this volume's secret, on a same-UUID copy:
	#  tampered: the enclave's own ECIES check refuses the blob (kernel EBADMSG);
	#  foreign:  a valid blob of another sealed key unseals, then AES-CCM refuses it.
	for kind in tampered foreign; do
		cp "$IMG" "$D/swap.img"
		tok=$(cryptsetup luksDump "$D/swap.img" | awk '/aurora-sep/{sub(":","",$1); print $1; exit}')
		cryptsetup token export --token-id "$tok" "$D/swap.img" > "$D/token.json"
		if [ $kind = foreign ]; then
			k=$(keyctl add trusted aurora-sep-luks-test-foreign "new 32" @s)
			keyctl pipe "$k" > "$D/foreign.blob"; keyctl unlink "$k" @s >/dev/null
		fi
		python3 - "$D/token.json" $kind "$D/foreign.blob" <<'EOF'
import json, sys
p, kind, blobf = sys.argv[1:4]
t = json.load(open(p))
b = t["sep-blob"]
if kind == "tampered":
    i = len(b) // 2
    b = b[:i] + ("0" if b[i] != "0" else "1") + b[i + 1:]
else:
    b = open(blobf).read().strip()
t["sep-blob"] = b
json.dump(t, open(p, "w"))
EOF
		cryptsetup token remove --token-id "$tok" "$D/swap.img"
		cryptsetup token import --json-file "$D/token.json" "$D/swap.img"
		dev=$(losetup -f --show "$D/swap.img")
		if cryptsetup open --test-passphrase --token-only "$dev" 2>/dev/null; then
			fail "$kind blob opened the volume"
		else
			pass "$kind SEP blob refused"
		fi
		cryptsetup open --test-passphrase --key-file "$D/recovery" "$dev" || fail "$kind copy recovery"
		losetup -d "$dev"; rm -f "$D/swap.img" "$D/token.json" "$D/foreign.blob"
	done
	dmesg | grep 'trusted-keys' | tail -4 | sed 's/^/  kernel: /'

	echo "AVC/SELINUX_ERR this boot: $(avc_count) (before the test: $avc0)"
	[ "$(avc_count)" = "$avc0" ] && pass "no new SELinux denials ($(getenforce))" || fail "new SELinux denials"
	echo "unseal: $fails failure(s)"
}

cleanup() {
	need_root
	close_all
	rm -rf "$D"
	pass "removed $D"
}

case "${1:-}" in
	seal) seal ;;
	unseal) unseal ;;
	cleanup) cleanup ;;
	*) echo "usage: $0 seal|unseal|cleanup"; exit 2 ;;
esac
[ "$fails" = 0 ]
