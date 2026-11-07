#!/bin/bash
# SPDX-License-Identifier: MIT
# Initrd unlock test in x86-64 VMs: a LUKS2 root image file, initramfs images
# built by dracut (Fedora container) and mkinitcpio (Arch Linux container)
# with this tree's module and hook, booted under KVM. Kernel "user" keys stand
# in for the SEP in the test plugin; nothing touches a real disk.
# Needs: docker, qemu-system-x86_64 with KVM, sudo (device-mapper for the
# image), cryptsetup, mkfs.ext4, gcc with static libc, python3.
# Usage: tests/vm/run-all.sh <work dir> [dracut] [mkinitcpio]
set -euo pipefail
here=$(cd "$(dirname "$0")/../.." && pwd)
src=$(cd "$here/.." && pwd)
W=$(mkdir -p "$1" && cd "$1" && pwd)
shift
builders=("$@")
[ ${#builders[@]} -gt 0 ] || builders=(dracut mkinitcpio)

# The test enrolment tool and plugin, built on this host.
rm -rf "$W/host" && mkdir -p "$W/host" && cp -a "$here" "$W/host/luks"
make -C "$W/host/luks" -s test/aurora-sep-cryptenroll test/libcryptsetup-token-aurora-sep.so
gcc -static -O2 -o "$W/vm-init" "$here/tests/vm/vm-init.c"

printf 'vm recovery passphrase' >"$W/pass"
sudo sh "$here/tests/vm/make-root.sh" "$W/root.img" "$W/vm-init" "$W/host/luks/test" "$W/pass" |
	tail -1 >"$W/root.uuid"
sudo chown "$(id -u):$(id -g)" "$W/root.img"
echo "root image $(cat "$W/root.uuid")"

# Same volume with the token's sealed secret flipped.
cp "$W/root.img" "$W/root-tampered.img"
cryptsetup token export --token-id 0 "$W/root-tampered.img" |
	python3 -c 'import json,sys; t=json.load(sys.stdin); s=t["sealed-secret"]; t["sealed-secret"]=s[:-1]+("0" if s[-1]!="0" else "1"); print(json.dumps(t))' \
	>"$W/tampered.json"
cryptsetup --batch-mode token import --token-id 0 --token-replace --json-file "$W/tampered.json" "$W/root-tampered.img"

for b in "${builders[@]}"; do
	# AURORA_SEP_VM_REUSE=1 keeps initramfs images from an earlier run.
	if [ "${AURORA_SEP_VM_REUSE:-0}" = 1 ] && [ -e "$W/initrd-$b-prod.img" ]; then continue; fi
	case $b in
	dracut) image=registry.fedoraproject.org/fedora:45 ;;
	mkinitcpio) image=archlinux:base-devel ;;
	*) echo "unknown builder $b" >&2; exit 2 ;;
	esac
	docker run --rm --network host -v "$src:/src:ro" -v "$W:/out" "$image" \
		bash "/src/luks/tests/vm/build-$b.sh" /src /out
	sudo chown -R "$(id -u):$(id -g)" "$W"
done

python3 "$here/tests/vm/run-vm-tests.py" "$W" "${builders[@]}"
