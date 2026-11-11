/* SPDX-License-Identifier: MIT */
/*
 * What the running boot says about itself, for the disk-key policy:
 * - the OS install the Secure Enclave key store serves (its OS identity,
 *   the same selection the apple_sep driver makes: the explicit
 *   apple_sep.os_uuid_hi/_lo pin, else /chosen/apfs-preboot-uuid);
 * - the boot chain state the kernel reports
 *   (/sys/firmware/aurora/boot_security/state: verified, partial, unverified);
 * - the "boot-chain" policy in fde.conf: warn (default) or require.
 *
 * $AURORA_SEP_FDE_ROOT (ignored in setuid callers) prefixes every path, for
 * the tests.
 */
#ifndef AURORA_SEP_BOOT_H
#define AURORA_SEP_BOOT_H

#include <stddef.h>

#define SEP_BOOT_UUID_LEN	36

enum sep_boot_chain_policy {
	SEP_BOOT_CHAIN_WARN = 0,	/* say so when the chain is not verified, unlock anyway */
	SEP_BOOT_CHAIN_REQUIRE = 1,	/* no SEP unlock unless the chain is verified */
};

/* Lower-case 8-4-4-4-12 UUID; -ENOENT when the boot names no OS identity. */
int sep_boot_os_uuid(char out[SEP_BOOT_UUID_LEN + 1]);

/* "verified", "partial", "unverified" (or whatever the kernel wrote);
 * -ENOENT when this kernel has no boot record. */
int sep_boot_chain_state(char *out, size_t size);

/* boot-chain = warn | require in fde.conf ($AURORA_SEP_FDE_CONF); warn when
 * the file or the key is missing or the value is unknown. */
enum sep_boot_chain_policy sep_boot_chain_policy(void);
const char *sep_boot_chain_policy_name(enum sep_boot_chain_policy p);

/* Whether this process runs in the initramfs (/etc/initrd-release). */
int sep_boot_in_initrd(void);

/*
 * The gate before a root volume's key is asked of the Secure Enclave.
 * Returns 0 to go on or -EPERM to refuse the SEP unlock (the volume then
 * asks for its passphrase or recovery key). msg gets the one line to log
 * (empty when the chain is verified); *first is 1 the first time this boot
 * the line is due, so callers log it once.
 */
int sep_boot_chain_gate(char *msg, size_t size, int *first);

#endif
