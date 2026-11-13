#!/bin/bash
# SPDX-License-Identifier: MIT
# dracut module: open LUKS2 volumes that carry an aurora-sep token with the
# Mac's Secure Enclave from the initrd, the root volume included.
# See aurora-sep-cryptenroll(8) and docs/luks-sep-initrd.md.

# Shared files, installed by `make install-initrd`.
: "${AURORA_SEP_INITRD_DIR:=/usr/lib/aurora-sep/initrd}"

_aurora_sep_plugin() {
    local d
    for d in /usr/lib64/cryptsetup /usr/lib/cryptsetup /usr/lib/*-linux-gnu*/cryptsetup; do
        if [[ -e $dracutsysrootdir$d/libcryptsetup-token-aurora-sep.so ]]; then
            echo "$d/libcryptsetup-token-aurora-sep.so"
            return 0
        fi
    done
    return 1
}

# The driver must have its key-store-only phase. A driver loaded here without
# it could not finish its attach on the real root (the SEP takes one attach
# per boot), so on older kernels only the plugin goes in.
_aurora_sep_kernel_ok() {
    modinfo -k "$kernel" -F parm apple_sep 2>/dev/null | grep -q '^keystore_only:'
}

# keystore_only=2 also unlocks per-user key bags in the initrd, for volumes
# sealed to a user's password (aurora-sep-fde, the FileVault model).
_aurora_sep_kernel_user_bags() {
    modinfo -k "$kernel" -F parm apple_sep 2>/dev/null | grep -q '^keystore_only:.*per-user key bags'
}

# The Macs whose enclave Linux shares with macOS (M2, M3, M4 Pro) run the
# driver's xART guard. Older drivers keep xART read-only in the initrd there,
# so a user's bag cannot be loaded before the real root; newer ones say in
# keystore_only's description that the initrd unlock works under the guard.
_aurora_sep_kernel_guarded_bags() {
    modinfo -k "$kernel" -F parm apple_sep 2>/dev/null | grep -q '^keystore_only:.*per-user key bags.*xART guard'
}

# Whether the running driver applies the guard (diag/policy: xart_guard=N).
_aurora_sep_guard_on() {
    local f
    for f in "${AURORA_SEP_SYSFS:-/sys}"/bus/platform/drivers/apple_sep/*/diag/policy; do
        [[ -r $f ]] && grep -Eq '(^|[[:space:]])xart_guard=[1-9]' "$f" && return 0
    done
    return 1
}

_aurora_sep_has_token() {
    [[ $2 == crypto_LUKS ]] || return 1
    cryptsetup luksDump "$1" 2>/dev/null | grep -Eq '^[[:space:]]+[0-9]+: aurora-sep$'
}

_aurora_sep_has_password_token() {
    [[ $2 == crypto_LUKS ]] || return 1
    cryptsetup luksDump --dump-json-metadata "$1" 2>/dev/null |
        grep -Eq '"aurora_sep_mode":[[:space:]]*"password"'
}

# Password-mode volumes the host opens, or aurora_sep_password_unlock="yes"
# in dracut.conf.d for volumes the build host cannot see (an installer
# target, an image file).
_aurora_sep_wants_user_bags() {
    [[ ${aurora_sep_password_unlock:-} == yes ]] && return 0
    [[ ${hostonly:-} ]] && for_each_host_dev_fs _aurora_sep_has_password_token && return 0
    return 1
}

check() {
    _aurora_sep_plugin >/dev/null || return 1
    # Host-only images take it when a LUKS2 device they open has a SEP token.
    if [[ $hostonly ]] && require_binaries cryptsetup >/dev/null 2>&1; then
        for_each_host_dev_fs _aurora_sep_has_token && return 0
    fi
    return 255
}

depends() {
    echo crypt systemd
    return 0
}

installkernel() {
    # AES-256-CCM through AF_ALG, by key serial. Whatever is built in or
    # missing is skipped.
    hostonly='' instmods algif_aead ccm ctr aes aes_generic aes-ce-ccm aes-ce-cipher || :
    if _aurora_sep_kernel_ok; then
        # aurora-sep's own dracut.conf.d omits apple_sep from every image,
        # because a driver without this phase must not load before the root.
        # This one has it, and this module is the one that loads it.
        omit_drivers='' hostonly='' instmods apple_sep
    fi
    return 0
}

install() {
    local plugin f mode sums=""

    plugin=$(_aurora_sep_plugin) || return 1
    inst_library "$plugin"
    inst_simple "$AURORA_SEP_INITRD_DIR/aurora-sep-cryptsetup.conf" \
        "$systemdsystemunitdir/systemd-cryptsetup@.service.d/aurora-sep.conf"
    # The disk-key policy (boot-chain = audit | require) applies in the initrd.
    if [[ -r $dracutsysrootdir/etc/aurora-sep/fde.conf ]]; then
        inst_simple /etc/aurora-sep/fde.conf
    fi

    if ! _aurora_sep_kernel_ok; then
        dwarning "aurora-sep: apple_sep in $kernel has no key-store-only phase; volumes sealed by the Secure Enclave will ask for their passphrase in the initrd"
        return 0
    fi
    mode=1
    if _aurora_sep_wants_user_bags; then
        if _aurora_sep_kernel_user_bags; then
            mode=2
            if _aurora_sep_guard_on && ! _aurora_sep_kernel_guarded_bags; then
                dwarning "aurora-sep: this Mac runs the xART guard, and apple_sep in $kernel keeps xART read-only in the initrd under it; volumes sealed to a password will ask for their passphrase or recovery key there"
            fi
        else
            dwarning "aurora-sep: apple_sep in $kernel cannot unlock a user's key bag in the initrd; volumes sealed to a password will ask for their passphrase or recovery key there"
        fi
    fi
    # Machine-sealed tokens need the key store copies; password tokens carry
    # their wrapped bag in the LUKS2 header and need none.
    if [[ ! -s $dracutsysrootdir/var/lib/aurora-sep-keybag.bin && $mode == 1 ]]; then
        dwarning "aurora-sep: this system has no Secure Enclave key store in /var/lib yet; volumes sealed by it will ask for their passphrase in the initrd"
        return 0
    fi

    # Read-only copies of the key store at the paths the driver reads. Only
    # this Mac's SEP under this Linux OS identity can use them. dracut writes
    # the image 0600.
    for f in /var/lib/aurora-sep-keybag.bin /var/lib/aurora-sep-refkey.bin \
        /var/lib/aurora-sep-refkey-v2.bin; do
        [[ -s $dracutsysrootdir$f ]] || continue
        inst_simple "$f"
        chmod 0600 "$initdir$f"
        sums+="$(sha256sum <"$dracutsysrootdir$f" | cut -d' ' -f1)  $f"$'\n'
    done
    mkdir -p "$initdir/usr/lib/aurora-sep"
    printf '%s' "$sums" >"$initdir/usr/lib/aurora-sep/initrd-keystore.sha256"
    printf 'AURORA_SEP_KEYSTORE_ONLY=%s\n' "$mode" >"$initdir/usr/lib/aurora-sep/initrd.conf"

    inst_script "$AURORA_SEP_INITRD_DIR/aurora-sep-initrd-load" \
        /usr/lib/aurora-sep/aurora-sep-initrd-load
    inst_simple "$AURORA_SEP_INITRD_DIR/aurora-sep-initrd.service" \
        "$systemdsystemunitdir/aurora-sep-initrd.service"
    inst_multiple modprobe modinfo mkdir
    # cryptsetup-pre.target is passive: nothing pulls it in unless a unit
    # ordered before it does. The unit Wants= it, so start the unit itself
    # from sysinit.target; then systemd-cryptsetup@ (After= the target) waits.
    $SYSTEMCTL -q --root "$initdir" add-wants cryptsetup-pre.target aurora-sep-initrd.service
    $SYSTEMCTL -q --root "$initdir" add-wants sysinit.target aurora-sep-initrd.service
}
