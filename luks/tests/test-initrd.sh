#!/bin/bash
# SPDX-License-Identifier: MIT
# Unprivileged checks for the dracut module and the mkinitcpio hook: run each
# against a fake system root with stubbed installer helpers and record what
# it would put in the image. The real image builds and VM boots are in
# tests/vm/. Usage: tests/test-initrd.sh
set -u
here=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d)
mkdir -p "$T/bin"
trap 'rm -rf "$T"' EXIT
fails=0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1"; fails=$((fails + 1)); }
has() { grep -qxF -- "$2" "$1"; }

for f in "$here"/initrd/aurora-sep-initrd-load "$here"/initrd/aurora-sep-initrd-check; do
	if sh -n "$f"; then pass "sh -n $(basename "$f")"; else fail "sh -n $(basename "$f")"; fi
done
for f in "$here"/initrd/dracut/module-setup.sh "$here"/initrd/mkinitcpio/aurora-sep; do
	if bash -n "$f"; then pass "bash -n $(basename "$f")"; else fail "bash -n $(basename "$f")"; fi
done

# A fake root with the plugin and a key store; fake modinfo/cryptsetup.
mkroot() {
	local r=$1
	mkdir -p "$r/usr/lib64/cryptsetup" "$r/usr/lib/cryptsetup" "$r/var/lib" "$T/bin"
	: >"$r/usr/lib64/cryptsetup/libcryptsetup-token-aurora-sep.so"
	: >"$r/usr/lib/cryptsetup/libcryptsetup-token-aurora-sep.so"
	printf 'keybag' >"$r/var/lib/aurora-sep-keybag.bin"
	printf 'refkey' >"$r/var/lib/aurora-sep-refkey.bin"
}
cat >"$T/bin/modinfo" <<'EOF'
#!/bin/sh
# FAKE_PARMS lists apple_sep's parameters, one per line.
[ "${FAKE_PARMS+x}" ] || exit 1
printf '%s\n' "$FAKE_PARMS"
EOF
cat >"$T/bin/cryptsetup" <<'EOF'
#!/bin/sh
# luksDump of FAKE_TOKEN_DEV shows an aurora-sep token.
[ "$1" = luksDump ] || exit 1
echo "Tokens:"
if [ "$2" = "${FAKE_TOKEN_DEV:-}" ]; then echo "  0: aurora-sep"; else echo "  0: systemd-tpm2"; fi
EOF
chmod +x "$T/bin/modinfo" "$T/bin/cryptsetup"
PARMS_NEW=$(printf 'os_uuid_hi:OS identity\nkeystore_only:Attach for the key store only\n')
PARMS_OLD=$(printf 'os_uuid_hi:OS identity\nxart_writes:writes\n')

# ---- dracut ----
dracut_run() { # <log> <check|install|installkernel> ; env: FAKE_PARMS, hostonly, FAKE_TOKEN_DEV
	local log=$1 fn=$2
	(
		PATH="$T/bin:$PATH"
		dracutsysrootdir=$T/root
		initdir=$T/initdir
		kernel=7.3.0-test
		systemdsystemunitdir=/usr/lib/systemd/system
		SYSTEMCTL=systemctl_stub
		AURORA_SEP_INITRD_DIR=$here/initrd
		declare -A host_fs_types=(["/dev/nvme0n1p5"]=crypto_LUKS ["/dev/nvme0n1p4"]=ext4)
		inst_library() { echo "lib $1" >>"$log"; }
		inst_simple() {
			echo "file ${2:-$1}" >>"$log"
			mkdir -p "$initdir$(dirname "${2:-$1}")"
			cp "$dracutsysrootdir$1" "$initdir${2:-$1}" 2>/dev/null || cp "$1" "$initdir${2:-$1}" 2>/dev/null || :
		}
		inst_script() { echo "script $2" >>"$log"; }
		inst_multiple() { echo "bin $*" >>"$log"; }
		instmods() { echo "mod $*${omit_drivers:+ (omit $omit_drivers)}" >>"$log"; }
		omit_drivers=' apple_sep '  # aurora-sep's dracut.conf.d
		dwarning() { echo "warn $*" >>"$log"; }
		require_binaries() { command -v "$@" >/dev/null; }
		for_each_host_dev_fs() {
			local d r=1
			for d in "${!host_fs_types[@]}"; do "$1" "$d" "${host_fs_types[$d]}" && r=0; done
			return $r
		}
		systemctl_stub() { echo "systemctl $*" >>"$log"; }
		# shellcheck source=/dev/null
		. "$here/initrd/dracut/module-setup.sh"
		"$fn"
	)
}

mkroot "$T/root"
rm -rf "$T/initdir"; : >"$T/d.log"
FAKE_PARMS=$PARMS_NEW dracut_run "$T/d.log" install
if has "$T/d.log" "lib /usr/lib64/cryptsetup/libcryptsetup-token-aurora-sep.so"; then pass "dracut: token plugin"; else fail "dracut: token plugin"; fi
if has "$T/d.log" "file /usr/lib/systemd/system/systemd-cryptsetup@.service.d/aurora-sep.conf"; then pass "dracut: cryptsetup wait drop-in"; else fail "dracut: drop-in"; fi
if has "$T/d.log" "file /var/lib/aurora-sep-keybag.bin" && has "$T/d.log" "file /var/lib/aurora-sep-refkey.bin"; then pass "dracut: key store copies"; else fail "dracut: key store copies"; fi
if grep -q "refkey-v2" "$T/d.log"; then fail "dracut: absent refkey-v2 must be skipped"; else pass "dracut: absent refkey-v2 skipped"; fi
if [ "$(stat -c %a "$T/initdir/var/lib/aurora-sep-keybag.bin" 2>/dev/null || stat -f %Lp "$T/initdir/var/lib/aurora-sep-keybag.bin")" = 600 ]; then pass "dracut: key bag copy is 0600"; else fail "dracut: key bag mode"; fi
if has "$T/d.log" "file /usr/lib/systemd/system/aurora-sep-initrd.service" && has "$T/d.log" "script /usr/lib/aurora-sep/aurora-sep-initrd-load"; then pass "dracut: initrd unit and loader"; else fail "dracut: unit/loader"; fi
if has "$T/d.log" "systemctl -q --root $T/initdir add-wants cryptsetup-pre.target aurora-sep-initrd.service"; then pass "dracut: unit wanted by cryptsetup-pre.target"; else fail "dracut: add-wants"; fi
sums=$T/initdir/usr/lib/aurora-sep/initrd-keystore.sha256
if [ "$(wc -l <"$sums")" = 2 ] && grep -q '  /var/lib/aurora-sep-keybag.bin$' "$sums"; then pass "dracut: key store hashes recorded"; else fail "dracut: hashes"; fi
if (cd "$T/root" && sed 's|  /|  |' "$sums" | sha256sum -c --status); then pass "dracut: recorded hashes match the copies"; else fail "dracut: hash mismatch"; fi

: >"$T/d.log"; FAKE_PARMS=$PARMS_NEW dracut_run "$T/d.log" installkernel
if grep -q "^mod apple_sep$" "$T/d.log" && grep -q "^mod algif_aead ccm" "$T/d.log"; then pass "dracut: apple_sep and AF_ALG ccm modules"; else fail "dracut: modules"; fi

rm -rf "$T/initdir"; : >"$T/d.log"
FAKE_PARMS=$PARMS_OLD dracut_run "$T/d.log" install
FAKE_PARMS=$PARMS_OLD dracut_run "$T/d.log" installkernel
if grep -q "^mod apple_sep$" "$T/d.log" || grep -q "aurora-sep-initrd.service" "$T/d.log" || grep -q "keybag" "$T/d.log"; then
	fail "dracut: a kernel without keystore_only must not get the driver, unit or key store"
else
	pass "dracut: kernel without keystore_only gets the plugin only"
fi
if grep -q "^warn aurora-sep: apple_sep in 7.3.0-test has no key-store-only phase" "$T/d.log"; then pass "dracut: says why"; else fail "dracut: warning"; fi
if has "$T/d.log" "lib /usr/lib64/cryptsetup/libcryptsetup-token-aurora-sep.so"; then pass "dracut: plugin still installed on an old kernel"; else fail "dracut: plugin on old kernel"; fi

rm -rf "$T/initdir"; : >"$T/d.log"; rm "$T/root/var/lib/aurora-sep-keybag.bin"
FAKE_PARMS=$PARMS_NEW dracut_run "$T/d.log" install
if grep -q "aurora-sep-initrd.service\|refkey" "$T/d.log"; then fail "dracut: no key bag means no unit"; else pass "dracut: no key store, no unit"; fi
mkroot "$T/root"

r=0; hostonly=1 FAKE_TOKEN_DEV=/dev/nvme0n1p5 dracut_run /dev/null check || r=$?
if [ "$r" = 0 ]; then pass "dracut check: host-only image with a SEP token includes the module"; else fail "dracut check with token ($r)"; fi
r=0; hostonly=1 FAKE_TOKEN_DEV=/dev/sdz dracut_run /dev/null check || r=$?
if [ "$r" = 255 ]; then pass "dracut check: no SEP token, only on request"; else fail "dracut check without token ($r)"; fi
r=0; hostonly='' dracut_run /dev/null check || r=$?
if [ "$r" = 255 ]; then pass "dracut check: generic image, only on request"; else fail "dracut check generic ($r)"; fi
rm "$T/root/usr/lib64/cryptsetup/libcryptsetup-token-aurora-sep.so" "$T/root/usr/lib/cryptsetup/libcryptsetup-token-aurora-sep.so"
r=0; hostonly=1 FAKE_TOKEN_DEV=/dev/nvme0n1p5 dracut_run /dev/null check || r=$?
if [ "$r" = 1 ]; then pass "dracut check: no plugin, no module"; else fail "dracut check without plugin ($r)"; fi

# ---- mkinitcpio ----
cpio_run() { # <log> ; env: FAKE_PARMS ; the fake root is the real / here, so use a chroot-free stub set
	local log=$1
	(
		PATH="$T/bin:$PATH"
		KERNELVERSION=7.3.0-test
		BUILDROOT=$T/build
		AURORA_SEP_INITRD_DIR=$here/initrd
		add_binary() { echo "bin $1" >>"$log"; }
		add_module() { echo "mod $1" >>"$log"; }
		add_file() { echo "file ${2:-$1} ${3:-}" >>"$log"; }
		add_dir() { mkdir -p "$BUILDROOT$1"; echo "dir $1" >>"$log"; }
		add_symlink() { echo "link $1 -> $2" >>"$log"; }
		error() { echo "error $*" >>"$log"; }
		warning() { echo "warn $*" >>"$log"; }
		# The hook reads the live system's paths; point them at the fake root.
		# shellcheck source=/dev/null
		. <(sed -e "s|/usr/lib/cryptsetup/|$T/root/usr/lib/cryptsetup/|" \
			-e "s|\[\[ ! -s /var/lib|[[ ! -s $T/root/var/lib|" \
			-e "s|\[\[ -s \$f \]\]|[[ -s $T/root\$f ]]|" \
			-e "s|<\"\$f\"|<\"$T/root\$f\"|" "$here/initrd/mkinitcpio/aurora-sep")
		build
	)
}
mkroot "$T/root"
rm -rf "$T/build"; : >"$T/m.log"
FAKE_PARMS=$PARMS_NEW cpio_run "$T/m.log"
if grep -q "^bin .*/libcryptsetup-token-aurora-sep.so$" "$T/m.log"; then pass "mkinitcpio: token plugin"; else fail "mkinitcpio: plugin"; fi
if has "$T/m.log" "mod apple_sep" && has "$T/m.log" "mod algif_aead?" && has "$T/m.log" "mod ccm?"; then pass "mkinitcpio: apple_sep and AF_ALG ccm modules"; else fail "mkinitcpio: modules"; fi
if has "$T/m.log" "file /var/lib/aurora-sep-keybag.bin 0600" && has "$T/m.log" "file /var/lib/aurora-sep-refkey.bin 0600"; then pass "mkinitcpio: key store copies 0600"; else fail "mkinitcpio: key store"; fi
if has "$T/m.log" "link /usr/lib/systemd/system/cryptsetup-pre.target.wants/aurora-sep-initrd.service -> ../aurora-sep-initrd.service"; then pass "mkinitcpio: unit wanted by cryptsetup-pre.target"; else fail "mkinitcpio: wants link"; fi
if has "$T/m.log" "file /usr/lib/systemd/system/systemd-cryptsetup@.service.d/aurora-sep.conf "; then pass "mkinitcpio: cryptsetup wait drop-in"; else fail "mkinitcpio: drop-in"; fi
if [ "$(wc -l <"$T/build/usr/lib/aurora-sep/initrd-keystore.sha256")" = 2 ]; then pass "mkinitcpio: key store hashes recorded"; else fail "mkinitcpio: hashes"; fi

rm -rf "$T/build"; : >"$T/m.log"
FAKE_PARMS=$PARMS_OLD cpio_run "$T/m.log"
if grep -q "mod apple_sep$\|keybag\|aurora-sep-initrd.service" "$T/m.log"; then fail "mkinitcpio: old kernel must get the plugin only"; else pass "mkinitcpio: kernel without keystore_only gets the plugin only"; fi

# ---- units and loader ----
u=$here/initrd/aurora-sep-initrd.service
if grep -qx 'Before=cryptsetup-pre.target' "$u" && grep -qx 'DefaultDependencies=no' "$u" && grep -qx 'ConditionPathExists=/etc/initrd-release' "$u"; then pass "initrd unit ordering"; else fail "initrd unit ordering"; fi
if grep -q 'modprobe apple_sep keystore_only=1' "$here/initrd/aurora-sep-initrd-load"; then pass "loader asks for the key-store-only phase"; else fail "loader params"; fi
if grep -q 'xart_writes\|provision_keybag' "$here/initrd/aurora-sep-initrd-load"; then fail "loader must not pass write options"; else pass "loader passes no write options"; fi

# The loader never fails the boot, with or without a working modprobe.
mkdir -p "$T/lbin"
printf '#!/bin/sh\necho "$*" >>"%s/modprobe.calls"\nexit 1\n' "$T" >"$T/lbin/modprobe"; chmod +x "$T/lbin/modprobe"
printf '#!/bin/sh\nprintf "%%s\\n" "$FAKE_PARMS"\n' >"$T/lbin/modinfo"; chmod +x "$T/lbin/modinfo"
if [ -e /sys/module/apple_sep ]; then
	echo "SKIP loader checks: apple_sep is loaded on this machine"
else
	if FAKE_PARMS=$PARMS_NEW PATH="$T/lbin:$PATH" sh "$here/initrd/aurora-sep-initrd-load" 2>/dev/null; then pass "loader exits 0 when modprobe fails"; else fail "loader exit status"; fi
	if grep -qx 'apple_sep keystore_only=1' "$T/modprobe.calls"; then pass "loader modprobes with keystore_only=1"; else fail "loader modprobe call"; fi
	rm -f "$T/modprobe.calls"
	if FAKE_PARMS=$PARMS_OLD PATH="$T/lbin:$PATH" sh "$here/initrd/aurora-sep-initrd-load" 2>/dev/null && [ ! -e "$T/modprobe.calls" ]; then
		pass "loader leaves a driver without keystore_only alone"
	else
		fail "loader must not load an old driver"
	fi
fi

# The real-root check: matching and stale copies.
mkdir -p "$T/run"
printf 'abc' >"$T/kb"
sha256sum "$T/kb" >"$T/run/sums"
sed "s|/run/aurora-sep/initrd-keystore.sha256|$T/run/sums|" "$here/initrd/aurora-sep-initrd-check" >"$T/check"
if sh "$T/check" 2>&1 | grep -q 'matches'; then pass "check: current copy"; else fail "check: current copy"; fi
printf 'abd' >"$T/kb"
if sh "$T/check" 2>&1 | grep -q '^<4>aurora-sep: the initramfs carries an old copy'; then pass "check: stale copy warns"; else fail "check: stale copy"; fi

echo "test-initrd: $fails failure(s)"
[ "$fails" = 0 ]
