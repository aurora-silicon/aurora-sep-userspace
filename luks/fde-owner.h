/* SPDX-License-Identifier: MIT */
/*
 * Volume owners for password-mode "aurora-sep" LUKS2 tokens (the FileVault
 * secure-token model).
 *
 * Every user who may unlock a volume has their own keyslot. Its secret is
 * sealed by the Secure Enclave under that user's key bag, which only the
 * user's password unlocks (sep-fde.h). A user token marked "owner" may also
 * add, remove and reset other users and change who is an owner; the others
 * can only unlock and change their own password. root and members of the
 * admin groups (wheel, sudo, admin by default) become owners when they are
 * added. Every change to another user needs an existing owner's password,
 * checked by the enclave: adding a keyslot needs a secret LUKS2 already
 * accepts, and the tool gets one only by opening that owner's token.
 *
 * One key bag per user per Mac, shared by all of that user's volumes: a
 * password change re-wraps the bag once in the enclave and writes the new
 * wrapped bag into every registered volume that has a token for the user.
 *
 * The enclave keeps a bag until reboot and cannot delete one, so a user who
 * gets a new bag while the old one is loaded (an owner reset) moves to the
 * next bag generation: bag uid = base + Linux uid + n * 1000000. Tokens find
 * their user by "aurora_sep_linux_uid".
 *
 * Configuration: /etc/aurora-sep/fde.conf (key = value):
 *   recovery = offline | sep-only   offline (default): the recovery key also
 *                                   opens a plain keyslot, so a Mac whose SEP
 *                                   cannot answer never locks its owner out;
 *                                   sep-only: FileVault's strict form.
 *   admin-groups = wheel sudo admin groups whose members become owners
 *   bag-uid-base = 60000            enclave bag uid = base + Linux uid
 * Volumes: /etc/aurora-sep/fde-volumes, one device or image path per line,
 * kept by the tool (enrol adds, the last token removed drops the line).
 */
#ifndef AURORA_SEP_FDE_OWNER_H
#define AURORA_SEP_FDE_OWNER_H

#include <stddef.h>
#include <stdint.h>
#include <libcryptsetup.h>

#include "sep-fde.h"

#define FDE_CONF_PATH		"/etc/aurora-sep/fde.conf"
#define FDE_VOLUMES_PATH	"/etc/aurora-sep/fde-volumes"
#define FDE_BAG_UID_BASE	60000u
#define FDE_ADMIN_GROUPS	"wheel sudo admin"
#define FDE_NAME_MAX		64
#define FDE_TOKENS_MAX		32
/* Bag generations for users re-made while the enclave holds the old bag. */
#define FDE_BAG_GEN_STRIDE	1000000u
#define FDE_BAG_GENERATIONS	16

struct fde_conf {
	uint32_t bag_uid_base;
	int recovery_sep_only;
	char admin_groups[256];
	char volumes_file[4096];
	/* Tests only (unset in setuid callers): alternative passwd/group files. */
	char passwd_file[4096];
	char group_file[4096];
};

struct fde_user {
	char name[FDE_NAME_MAX];
	uint32_t uid;		/* Linux uid */
	uint32_t bag_uid;	/* enclave key bag uid */
	int admin;		/* root or a member of an admin group */
};

/* Defaults, then the config file ($AURORA_SEP_FDE_CONF when not setuid). */
int fde_conf_load(struct fde_conf *c);

/* A user by name or numeric uid. -ENOENT when there is no such user. */
int fde_user_lookup(const struct fde_conf *c, const char *who, struct fde_user *u);

/* Registered volumes: a NULL-terminated malloc'd array, free with fde_strv_free. */
char **fde_volumes_list(const struct fde_conf *c);
void fde_strv_free(char **v);
int fde_volumes_add(const struct fde_conf *c, const char *path);
int fde_volumes_drop(const struct fde_conf *c, const char *path);

/* libcryptsetup context of a LUKS2 volume (honours $AURORA_SEP_TOKEN_DIR). */
int fde_load(struct crypt_device **cd, const char *device);

/* Token helpers. Owner is read from "aurora_sep_owner"; tokens written
 * before owners existed count as owners (they were the volume's only user). */
int fde_find_token(struct crypt_device *cd, long bag_uid, const char *role, struct fde_token *t);
int fde_token_keyslot(struct crypt_device *cd, int token);
/* u's user token (by Linux uid; by bag uid for tokens without an account). */
int fde_find_user_token(struct crypt_device *cd, const struct fde_user *u, struct fde_token *t);
int fde_replace_token(struct crypt_device *cd, int tok, const struct fde_token *t);
int fde_count_owners(struct crypt_device *cd);

/*
 * Opens auth's user token with auth's password. require_owner: refuse
 * (-EPERM) unless the token is an owner's. On success secret holds the
 * keyslot secret, usable as the existing key for keyslot changes.
 * Errors: -ENOENT no token for auth on this volume, -EACCES wrong password
 * (the enclave counted it), -EPERM not an owner or the enclave refused.
 */
int fde_auth_owner(struct crypt_device *cd, const struct fde_user *auth, const char *pw,
		   size_t pw_len, int require_owner, uint8_t secret[SEP_FDE_SECRET_BYTES]);

/*
 * Adds a user token for u, opened with pw, as a new keyslot; existing is a
 * key LUKS2 accepts. The user's key bag is reused when the enclave or another
 * registered volume has it (pw must then be the user's current password),
 * otherwise made. Returns the keyslot.
 */
int fde_add_user(struct crypt_device *cd, const struct fde_conf *c, const char *existing,
		 size_t elen, const struct fde_user *u, const char *pw, size_t pw_len, int owner,
		 const char *label);

/* Removes a user token and its keyslot (no secret needed; the caller checks
 * authority). Refuses (-EBUSY) to remove the last owner. */
int fde_remove_user(struct crypt_device *cd, const struct fde_user *u);

/*
 * Changes u's password everywhere: the enclave checks old and re-wraps the
 * bag; the new wrapped bag goes into device (may be NULL) and every
 * registered volume with a token for u. *updated counts the volumes written.
 * -EACCES: old password wrong. -ENOENT: u has no token anywhere.
 */
int fde_change_password(const struct fde_conf *c, const char *device, const struct fde_user *u,
			const char *old_pw, size_t old_len, const char *new_pw, size_t new_len,
			int *updated);

/*
 * Owner reset: a new bag and keyslot for u with new_pw, added with the
 * owner's secret, then u's old keyslot removed. The owner flag is kept.
 */
int fde_reset_by_owner(struct crypt_device *cd, const struct fde_conf *c,
		       const uint8_t owner_secret[SEP_FDE_SECRET_BYTES], const struct fde_user *u,
		       const char *new_pw, size_t new_len);

/* Writes the newest wrapped bag of u the enclave accepts into every
 * registered volume (after a partial failure). */
int fde_sync_bag(const struct fde_conf *c, const struct fde_user *u, int *updated);

#endif
