#!/bin/bash
# SPDX-License-Identifier: MIT
# Inside a Fedora container: build the token plugin, install the dracut
# module, and build two initramfs images for the distribution kernel, one with
# the test plugin (kernel "user" keys stand in for the SEP) and one with the
# production plugin (trusted keys; the VM has no SEP).
# Usage: build-dracut.sh <source tree> <output dir>
set -euo pipefail
src=$1 out=$2
dnf -y -q install gcc make pkgconf-pkg-config cryptsetup cryptsetup-devel json-c-devel \
	dracut systemd-cryptsetup kernel-core e2fsprogs >/dev/null
kver=$(ls /usr/lib/modules | sort -V | tail -1)
work=$(mktemp -d)
cp -a "$src/luks" "$work/"
make -C "$work/luks" -s all test/libcryptsetup-token-aurora-sep.so
make -C "$work/luks" -s install install-dracut PREFIX=/usr TOKENDIR=/usr/lib64/cryptsetup
tokdir=/usr/lib64/cryptsetup
# Password mode: the test plugin with the enclave double, whose state the
# image carries (pw), and the same with "no SEP on this Mac" (pwnosep).
kinds="test prod"
[ -d "$out/mock" ] && kinds="$kinds pw pwnosep"
for kind in $kinds; do
	extra=()
	if [ "$kind" = prod ]; then
		install -m755 "$work/luks/libcryptsetup-token-aurora-sep.so" "$tokdir/"
	else
		install -m755 "$work/luks/test/libcryptsetup-token-aurora-sep.so" "$tokdir/"
	fi
	case $kind in
	pw | pwnosep)
		mkdir -p "$work/$kind"
		{
			echo "[Service]"
			echo "Environment=AURORA_SEP_FDE_MOCK=/etc/aurora-sep-fde-mock"
			[ "$kind" = pwnosep ] && echo "Environment=AURORA_SEP_FDE_MOCK_NOSEP=1"
		} >"$work/$kind/mock.conf"
		extra=(--include "$out/mock" /etc/aurora-sep-fde-mock
			--include "$work/$kind/mock.conf" /etc/systemd/system/systemd-cryptsetup@.service.d/zz-mock.conf)
		;;
	esac
	dracut -q -f --no-hostonly --no-hostonly-cmdline --add aurora-sep "${extra[@]}" \
		--kver "$kver" "$out/initrd-dracut-$kind.img" 2>"$out/dracut-$kind.log" ||
		{ cat "$out/dracut-$kind.log"; exit 1; }
	lsinitrd "$out/initrd-dracut-$kind.img" >"$out/lsinitrd-$kind.txt"
done
cp "/usr/lib/modules/$kver/vmlinuz" "$out/vmlinuz-dracut"
echo "$kver" >"$out/kver-dracut"
rpm -q dracut systemd cryptsetup >"$out/versions-dracut.txt"
