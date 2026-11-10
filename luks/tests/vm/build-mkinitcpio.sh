#!/bin/bash
# SPDX-License-Identifier: MIT
# Inside an Arch Linux container: the mkinitcpio counterpart of
# build-dracut.sh (systemd + sd-encrypt image with the aurora-sep hook).
# Usage: build-mkinitcpio.sh <source tree> <output dir>
set -euo pipefail
src=$1 out=$2
pacman -Sy --noconfirm --needed linux mkinitcpio cryptsetup json-c gcc make pkgconf e2fsprogs >/dev/null
kver=$(ls /usr/lib/modules | grep -v extramodules | sort -V | tail -1)
work=$(mktemp -d)
cp -a "$src/luks" "$work/"
make -C "$work/luks" -s all test/libcryptsetup-token-aurora-sep.so
make -C "$work/luks" -s install install-mkinitcpio PREFIX=/usr TOKENDIR=/usr/lib/cryptsetup
cat >"$work/mkinitcpio.conf" <<CONF
MODULES=(virtio_pci virtio_blk dm_crypt ext4)
HOOKS=(base systemd modconf block keyboard aurora-sep sd-encrypt filesystems)
COMPRESSION=zstd
CONF
for kind in test prod; do
	if [ "$kind" = test ]; then
		install -m755 "$work/luks/test/libcryptsetup-token-aurora-sep.so" /usr/lib/cryptsetup/
	else
		install -m755 "$work/luks/libcryptsetup-token-aurora-sep.so" /usr/lib/cryptsetup/
	fi
	mkinitcpio -k "$kver" -c "$work/mkinitcpio.conf" -g "$out/initrd-mkinitcpio-$kind.img" \
		>"$out/mkinitcpio-$kind.log" 2>&1 || { cat "$out/mkinitcpio-$kind.log"; exit 1; }
	lsinitcpio "$out/initrd-mkinitcpio-$kind.img" >"$out/lsinitcpio-$kind.txt"
done
cp "/usr/lib/modules/$kver/vmlinuz" "$out/vmlinuz-mkinitcpio"
echo "$kver" >"$out/kver-mkinitcpio"
pacman -Q mkinitcpio systemd cryptsetup linux >"$out/versions-mkinitcpio.txt"
