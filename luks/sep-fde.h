/* SPDX-License-Identifier: MIT */
/*
 * Password mode of the "aurora-sep" LUKS2 token: the FileVault model.
 *
 * A LUKS2 keyslot opens with a random 64-byte secret. The Secure Enclave seals
 * that secret to a P-256 key it keeps under a per-user key bag whose secret is
 * the user's password. The enclave opens the sealed secret only while that bag
 * is unlocked, and only the password unlocks it: the enclave checks it,
 * entangles it with its own UID key and counts failed attempts. The token keeps
 * the wrapped bag, the key's record and the sealed secret; none of them opens
 * without the password, and none opens on another Mac.
 *
 * A recovery key (FileVault style, 24 characters) is a second bag of its own
 * with its own keyslot, so a forgotten password does not lose the volume.
 *
 * Kernel interface: SEP_BIO_KEYBAG_* (linux#921) and SEP_BIO_FDE_* on
 * /dev/sep-bio-rearm (root). Both are draft ABIs; the structures are copied
 * here so the tool builds against any kernel headers.
 */
#ifndef AURORA_SEP_FDE_H
#define AURORA_SEP_FDE_H

#include <stddef.h>
#include <stdint.h>

#define SEP_FDE_MODE		"password"
#define SEP_FDE_DEV		"/dev/sep-bio-rearm"
#define SEP_FDE_SECRET_BYTES	64
#define SEP_FDE_PASS_LEN	(2 * SEP_FDE_SECRET_BYTES)
#define SEP_FDE_PASSWORD_MAX	256
/* FileVault-style recovery key: 6 groups of 4 from a 32-symbol alphabet. */
#define SEP_FDE_RK_GROUPS	6
#define SEP_FDE_RK_CHARS	(SEP_FDE_RK_GROUPS * 4)
#define SEP_FDE_RK_LEN		(SEP_FDE_RK_CHARS + SEP_FDE_RK_GROUPS - 1)
#define SEP_FDE_UID_MIN		10

#define SEP_FDE_ROLE_USER	"user"
#define SEP_FDE_ROLE_RECOVERY	"recovery"

struct fde_token {
	uint32_t uid;
	char role[16];
	char label[64];
	uint8_t *bag;
	size_t bag_len;
	uint8_t *record;
	size_t record_len;
	uint8_t *sealed;
	size_t sealed_len;
	/* Recovery tokens: the plain LUKS2 keyslot that takes the same recovery
	 * key without the enclave (-1: none), so a Mac whose SEP cannot answer
	 * never locks its owner out. */
	int offline_keyslot;
};

struct fde_state {
	uint32_t bag_state;		/* 0 locked since boot, 1 unlocked, 2 locking, 3 locked */
	uint32_t failed_attempts;
	uint32_t lock_phase;
};

void fde_token_free(struct fde_token *t);
/* -ENOENT when the JSON is an aurora-sep token of another mode. */
int fde_token_parse(const char *json, struct fde_token *t);
/* malloc'd JSON; keyslots are assigned by libcryptsetup. */
char *fde_token_build(const struct fde_token *t);

/* Enclave operations. Errors: -EACCES refused (wrong password, no bag),
 * -EKEYREJECTED the enclave refused a record/blob, -ENODEV no SEP. */
int fde_bag_create(uint32_t uid, const char *pw, size_t pw_len);
int fde_bag_unlock(uint32_t uid, const char *pw, size_t pw_len);
int fde_bag_lock(uint32_t uid);
int fde_bag_change(uint32_t uid, const char *old_pw, size_t old_len,
		   const char *new_pw, size_t new_len);
int fde_bag_export(uint32_t uid, uint8_t **blob, size_t *len);
int fde_bag_import(uint32_t uid, const uint8_t *blob, size_t len);
int fde_bag_state(uint32_t uid, struct fde_state *st);
int fde_key_create(uint32_t uid, uint8_t **record, size_t *len);
int fde_seal(uint32_t uid, const uint8_t *record, size_t record_len,
	     const uint8_t *secret, size_t secret_len, uint8_t **sealed, size_t *len);
int fde_unseal(uint32_t uid, const uint8_t *record, size_t record_len,
	       const uint8_t *sealed, size_t sealed_len, uint8_t *out, size_t out_size,
	       size_t *out_len);

/*
 * Unlock: load the token's bag if the enclave does not hold it, unlock it with
 * the password, open the sealed secret, lock the bag again. -EACCES means the
 * password was wrong (the enclave counted it), -EPERM that the token cannot be
 * used on this Mac or OS (bag or record refused).
 */
int fde_open_token(const struct fde_token *t, const char *pw, size_t pw_len,
		   uint8_t secret[SEP_FDE_SECRET_BYTES]);

/*
 * Make a bag for uid with the password, a sealing key under it, and seal
 * secret; fill t (bag exported last). The bag is locked again on return.
 */
int fde_enroll(uint32_t uid, const char *role, const char *pw, size_t pw_len,
	       const uint8_t secret[SEP_FDE_SECRET_BYTES], struct fde_token *t);

/*
 * Wait up to wait_s seconds for the enclave's re-arm node at early boot (the
 * key store can take most of a minute on some Macs). 0 when it is there,
 * -ENODEV when this machine has no SEP driver or its key store stayed closed,
 * -ETIMEDOUT otherwise.
 */
int fde_wait_ready(int wait_s);

int fde_recovery_key_new(char out[SEP_FDE_RK_LEN + 1]);
/* Canonical form of a typed recovery key (case, spaces and dashes ignored);
 * -EINVAL when the input is not shaped like one. */
int fde_recovery_key_normalize(const char *in, size_t in_len, char out[SEP_FDE_RK_LEN + 1]);

#endif
