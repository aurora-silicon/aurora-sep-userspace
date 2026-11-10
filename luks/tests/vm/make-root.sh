#!/bin/sh
# SPDX-License-Identifier: MIT
# Build the VM test root: a LUKS2 image file holding an ext4 root whose init
# reports and powers off, enrolled with the test build of the token (kernel
# "user" keys stand in for the SEP). Needs root for device-mapper.
# Usage: make-root.sh <image> <static init> <test build dir> <passphrase file>
set -eu
img=$1 init=$2 B=$3 pass=$4
T=$(mktemp -d)
name=aurora-sep-vm-$$
trap 'cryptsetup close "$name" 2>/dev/null || :; rm -rf "$T"' EXIT
mkdir -p "$T/root/sbin" "$T/root/proc" "$T/root/dev" "$T/root/run" "$T/root/etc"
install -m755 "$init" "$T/root/sbin/vm-init"
# systemd only switches to a root that looks like an OS tree.
printf 'ID=aurora-sep-vm\nNAME="aurora-sep VM test root"\n' >"$T/root/etc/os-release"
rm -f "$img"
truncate -s 64M "$img"
cryptsetup --batch-mode luksFormat --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
	"$img" "$pass"
cryptsetup open --key-file "$pass" "$img" "$name"
mkfs.ext4 -q -L vmroot -d "$T/root" "/dev/mapper/$name"
cryptsetup close "$name"
"$B/aurora-sep-cryptenroll" -q --unlock-key-file="$pass" "$img"
cryptsetup --external-tokens-path "$B" open --test-passphrase --token-only "$img"
cryptsetup luksUUID "$img"
