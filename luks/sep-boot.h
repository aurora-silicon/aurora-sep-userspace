/* SPDX-License-Identifier: MIT */
/*
 * What the running boot says about itself, for the disk-key policy:
 * - the OS install the Secure Enclave key store serves (its OS identity,
 *   the same selection the apple_sep driver makes: the explicit
 *   apple_sep.os_uuid_hi/_lo pin, else /chosen/apfs-preboot-uuid);
 * - the boot chain state the kernel reports
 *   (/sys/firmware/aurora/boot_security/state: verified, partial, unverified);
 * - the "boot-chain" policy in fde.conf: audit (default) or require.
 *
 * $AURORA_SEP_FDE_ROOT (ignored in setuid callers) prefixes every path, for
 * the tests.
 */
#ifndef AURORA_SEP_BOOT_H
#define AURORA_SEP_BOOT_H

#include <stddef.h>

#define SEP_BOOT_UUID_LEN	36

enum sep_boot_chain_policy {
	SEP_BOOT_CHAIN_AUDIT = 0,	/* log what require would refuse, unlock anyway ("warn" too) */
	SEP_BOOT_CHAIN_REQUIRE = 1,	/* no SEP unlock unless the chain is verified */
};

/* What the boot record says, as the gate reads it. */
struct sep_boot_chain {
	int present;		/* the kernel has a boot record */
	char state[32];		/* verified, partial, unverified; "none" without a record */
	int advisory;		/* 1 unless an enforcing Stage 1 verified Stage 2; -1 unknown */
	int verified;		/* state verified and not advisory: the only state require accepts */
	char first_gap[160];	/* the first link not enforced and verified; empty when verified */
};

/* Lower-case 8-4-4-4-12 UUID; -ENOENT when the boot names no OS identity. */
int sep_boot_os_uuid(char out[SEP_BOOT_UUID_LEN + 1]);

/* "verified", "partial", "unverified" (or whatever the kernel wrote);
 * -ENOENT when this kernel has no boot record. */
int sep_boot_chain_state(char *out, size_t size);

/* The record in /sys/firmware/aurora/boot_security (state, advisory,
 * measurements). Never fails: no record reads as not verified. */
void sep_boot_chain_read(struct sep_boot_chain *c);

/* boot-chain = audit | require in fde.conf ($AURORA_SEP_FDE_CONF); audit when
 * the file or the key is missing or the value is unknown ("warn", the old
 * name, is audit). */
enum sep_boot_chain_policy sep_boot_chain_policy(void);
const char *sep_boot_chain_policy_name(enum sep_boot_chain_policy p);
/* fde.conf with boot-chain set to p, other lines kept (temp file + rename). */
int sep_boot_chain_policy_write(enum sep_boot_chain_policy p);
/* The fde.conf path the two above use. */
void sep_boot_conf_path(char *buf, size_t size);

/* Whether this process runs in the initramfs (/etc/initrd-release). */
int sep_boot_in_initrd(void);

/*
 * The gate before a volume's key is asked of the Secure Enclave, at every
 * unlock (initramfs and real root). Returns 0 to go on or -EPERM to refuse
 * the SEP unlock (the volume then asks for its passphrase or recovery key).
 * When the chain is not verified, msg gets the one line for this unlock
 * (chain state, first unverified link, the volume), which is also sent to
 * syslog as SEP_BOOT_LOG_IDENT; empty when the chain is verified.
 */
#define SEP_BOOT_LOG_IDENT	"aurora-sep-boot-chain"
int sep_boot_chain_gate(const char *volume, char *msg, size_t size);

#endif
