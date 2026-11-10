#!/bin/sh
# SPDX-License-Identifier: MIT
# Hardware test of SEP unlock in the initrd, on a Fedora Mac whose kernel has
# apple_sep's key-store-only phase. It never touches the real root: a small
# LUKS2 image file enrolled with aurora-sep-cryptenroll rides inside a test
# initramfs, and a one-shot boot entry (a copy of the default entry, same
# kernel and command line, OS identity pin included) opens it from the initrd
# with systemd-cryptsetup, token only, before switch-root. The next boot is
# the normal default again.
#
#   hw-initrd-test.sh prepare   build the image, initramfs and one-shot entry
#   (reboot)
#   hw-initrd-test.sh verify    read the initrd result and the real-root side
#   hw-initrd-test.sh cleanup   remove the entry, initramfs and image
set -eu
W=/var/tmp/aurora-sep-initrd-test
ID=aurora-sep-initrd-test
pass=$W/pass

die() { echo "hw-initrd-test: $*" >&2; exit 1; }

prepare() {
	[ "$(id -u)" = 0 ] || die "run as root"
	grep -q 'apple_sep.os_uuid_hi=' /proc/cmdline || die "no apple_sep.os_uuid pin on this boot; fix the entry first"
	modinfo -F parm apple_sep | grep -q '^keystore_only:' || die "apple_sep in $(uname -r) has no keystore_only"
	[ -s /var/lib/aurora-sep-keybag.bin ] || die "no SEP key store in /var/lib"
	[ -e /usr/lib/dracut/modules.d/90aurora-sep/module-setup.sh ] || die "the aurora-sep dracut module is not installed"
	rm -rf "$W"; mkdir -p "$W/inc/aurora-sep-test" "$W/inc/etc/systemd/system/initrd.target.wants" "$W/inc/usr/lib/aurora-sep-test"
	chmod 700 "$W"
	head -c 24 /dev/urandom | base64 >"$pass"

	img=$W/inc/aurora-sep-test/vol.img
	truncate -s 8M "$img"
	cryptsetup --batch-mode luksFormat --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
		--luks2-metadata-size 64k --luks2-keyslots-size 1m "$img" "$pass"
	aurora-sep-cryptenroll -q --unlock-key-file="$pass" "$img"
	cryptsetup open --test-passphrase --token-only "$img" || die "the token does not open the image on the running system"
	cryptsetup luksUUID "$img" >"$W/uuid"

	cat >"$W/inc/usr/lib/aurora-sep-test/run" <<'EOF'
#!/bin/sh
# Initrd: open the test image through the aurora-sep token only.
mkdir -p /run/aurora-sep-test
out=/run/aurora-sep-test/result
read -r t0 _ </proc/uptime
dev=$(losetup -f --show /aurora-sep-test/vol.img) || { echo "FAIL losetup" >"$out"; exit 0; }
if /usr/lib/systemd/systemd-cryptsetup attach aurora-sep-test "$dev" - headless=true \
	>/run/aurora-sep-test/attach.log 2>&1; then r=PASS; else r=FAIL; fi
read -r t1 _ </proc/uptime
[ -b /dev/mapper/aurora-sep-test ] && echo "mapped" >>/run/aurora-sep-test/attach.log
/usr/lib/systemd/systemd-cryptsetup detach aurora-sep-test >/dev/null 2>&1 || :
losetup -d "$dev" || :
echo "$r token-only unlock in the initrd, uptime $t0 -> $t1 s" >"$out"
EOF
	chmod 755 "$W/inc/usr/lib/aurora-sep-test/run"
	cat >"$W/inc/etc/systemd/system/aurora-sep-test.service" <<'EOF'
[Unit]
Description=aurora-sep initrd unlock test (image file)
DefaultDependencies=no
After=aurora-sep-initrd.service cryptsetup-pre.target
Before=initrd.target
ConditionPathExists=/etc/initrd-release

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=AURORA_SEP_WAIT=90
ExecStart=/usr/lib/aurora-sep-test/run
EOF
	ln -s ../aurora-sep-test.service "$W/inc/etc/systemd/system/initrd.target.wants/aurora-sep-test.service"

	kver=$(uname -r)
	dracut -f --add aurora-sep --install "losetup" --include "$W/inc" / \
		"/boot/initramfs-$ID.img" "$kver"
	chmod 600 "/boot/initramfs-$ID.img"
	lsinitrd "/boot/initramfs-$ID.img" | grep -E 'apple_sep|aurora-sep|keybag|refkey|vol.img' >"$W/lsinitrd.txt"
	grep -q 'apple_sep' "$W/lsinitrd.txt" && grep -q 'aurora-sep-keybag.bin' "$W/lsinitrd.txt" ||
		die "the test initramfs lacks the driver or key store (see $W/lsinitrd.txt)"

	def=$(grubby --info=DEFAULT | sed -n 's/^id="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p')
	src=/boot/loader/entries/$def.conf
	[ -f "$src" ] || die "default entry $src not found"
	grep -q 'apple_sep.os_uuid_hi=' "$src" || die "the default entry has no os_uuid pin"
	sed -e "s|^title .*|title aurora-sep initrd test ($kver)|" \
		-e "s|^initrd .*|initrd /initramfs-$ID.img|" "$src" >"/boot/loader/entries/$ID.conf"
	grep -q '^initrd /initramfs-'"$ID"'.img' "/boot/loader/entries/$ID.conf" || die "entry has no initrd line to replace"
	echo "$def" >"$W/default-entry"
	grub2-reboot "$ID"
	echo "prepared: one-shot entry $ID (copy of $def, initrd /boot/initramfs-$ID.img). Reboot, then run: $0 verify"
}

verify() {
	r=0
	echo "boot: $(uname -r) $(cat /proc/cmdline | grep -o 'BOOT_IMAGE=[^ ]*')"
	if [ -s /run/aurora-sep-test/result ]; then
		cat /run/aurora-sep-test/result
		grep -q '^PASS' /run/aurora-sep-test/result || r=1
		cat /run/aurora-sep-test/attach.log 2>/dev/null
	else
		echo "FAIL no initrd result (the one-shot entry did not boot, or the test unit did not run)"; r=1
	fi
	journalctl -b -o short-monotonic --no-pager | grep -E 'aurora-sep-initrd|aurora-sep-test|trusted-keys|keystore|complete_attach|aurora-sep-load' | head -40
	if [ -c /dev/sep-bio ]; then echo "PASS /dev/sep-bio after complete_attach"; else echo "FAIL /dev/sep-bio missing"; r=1; fi
	systemctl is-active aurora-sep.service || r=1
	systemctl --no-pager status aurora-sep-initrd-check.service 2>/dev/null | tail -3
	echo "SELinux: $(getenforce); AVC this boot: $(ausearch -m AVC,USER_AVC,SELINUX_ERR -ts boot 2>/dev/null | grep -c 'type=AVC')"
	grep -q 'apple_sep.os_uuid_hi=' /proc/cmdline && echo "PASS os_uuid pin on this boot" || { echo "FAIL os_uuid pin missing"; r=1; }
	echo "verify: $([ $r = 0 ] && echo PASS || echo FAIL)"
	return $r
}

cleanup() {
	rm -f "/boot/loader/entries/$ID.conf" "/boot/initramfs-$ID.img"
	grub2-editenv - list | grep -q "^next_entry=$ID" && grub2-editenv - unset next_entry
	rm -rf "$W"
	echo "cleaned: default entry is $(grubby --default-title)"
}

case "${1:-}" in
prepare) prepare ;;
verify) verify ;;
cleanup) cleanup ;;
*) echo "usage: $0 prepare|verify|cleanup" >&2; exit 2 ;;
esac
