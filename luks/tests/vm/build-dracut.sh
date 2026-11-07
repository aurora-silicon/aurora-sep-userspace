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
for kind in test prod; do
	if [ "$kind" = test ]; then
		install -m755 "$work/luks/test/libcryptsetup-token-aurora-sep.so" "$tokdir/"
	else
		install -m755 "$work/luks/libcryptsetup-token-aurora-sep.so" "$tokdir/"
	fi
	dracut -q -f --no-hostonly --no-hostonly-cmdline --add aurora-sep \
		--kver "$kver" "$out/initrd-dracut-$kind.img" 2>"$out/dracut-$kind.log" ||
		{ cat "$out/dracut-$kind.log"; exit 1; }
	lsinitrd "$out/initrd-dracut-$kind.img" >"$out/lsinitrd-$kind.txt"
done
cp "/usr/lib/modules/$kver/vmlinuz" "$out/vmlinuz-dracut"
echo "$kver" >"$out/kver-dracut"
rpm -q dracut systemd cryptsetup >"$out/versions-dracut.txt"
