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

_aurora_sep_has_token() {
    [[ $2 == crypto_LUKS ]] || return 1
    cryptsetup luksDump "$1" 2>/dev/null | grep -Eq '^[[:space:]]+[0-9]+: aurora-sep$'
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
    local plugin f sums=""

    plugin=$(_aurora_sep_plugin) || return 1
    inst_library "$plugin"
    inst_simple "$AURORA_SEP_INITRD_DIR/aurora-sep-cryptsetup.conf" \
        "$systemdsystemunitdir/systemd-cryptsetup@.service.d/aurora-sep.conf"

    if ! _aurora_sep_kernel_ok; then
        dwarning "aurora-sep: apple_sep in $kernel has no key-store-only phase; volumes sealed by the Secure Enclave will ask for their passphrase in the initrd"
        return 0
    fi
    if [[ ! -s $dracutsysrootdir/var/lib/aurora-sep-keybag.bin ]]; then
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

    inst_script "$AURORA_SEP_INITRD_DIR/aurora-sep-initrd-load" \
        /usr/lib/aurora-sep/aurora-sep-initrd-load
    inst_simple "$AURORA_SEP_INITRD_DIR/aurora-sep-initrd.service" \
        "$systemdsystemunitdir/aurora-sep-initrd.service"
    inst_multiple modprobe modinfo mkdir
    $SYSTEMCTL -q --root "$initdir" add-wants cryptsetup-pre.target aurora-sep-initrd.service
}
