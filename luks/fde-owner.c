// SPDX-License-Identifier: MIT
/*
 * Volume owners for password-mode aurora-sep LUKS2 tokens. See fde-owner.h.
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>

#include "fde-owner.h"
#include "sep-seal.h"

/* ---- configuration ------------------------------------------------------ */

static char *trim(char *s)
{
	char *e;

	while (isspace((unsigned char)*s))
		s++;
	e = s + strlen(s);
	while (e > s && isspace((unsigned char)e[-1]))
		*--e = '\0';
	return s;
}

int fde_conf_load(struct fde_conf *c)
{
	const char *path = secure_getenv("AURORA_SEP_FDE_CONF");
	const char *e;
	char line[512];
	FILE *f;

	memset(c, 0, sizeof(*c));
	c->bag_uid_base = FDE_BAG_UID_BASE;
	snprintf(c->admin_groups, sizeof(c->admin_groups), "%s", FDE_ADMIN_GROUPS);
	snprintf(c->volumes_file, sizeof(c->volumes_file), "%s", FDE_VOLUMES_PATH);
	if ((e = secure_getenv("AURORA_SEP_FDE_VOLUMES")) && *e)
		snprintf(c->volumes_file, sizeof(c->volumes_file), "%s", e);
	if ((e = secure_getenv("AURORA_SEP_FDE_PASSWD")) && *e)
		snprintf(c->passwd_file, sizeof(c->passwd_file), "%s", e);
	if ((e = secure_getenv("AURORA_SEP_FDE_GROUP")) && *e)
		snprintf(c->group_file, sizeof(c->group_file), "%s", e);
	f = fopen(path && *path ? path : FDE_CONF_PATH, "re");
	if (!f)
		return errno == ENOENT ? 0 : -errno;
	while (fgets(line, sizeof(line), f)) {
		char *k = trim(line), *v;

		if (!*k || *k == '#' || !(v = strchr(k, '=')))
			continue;
		*v++ = '\0';
		k = trim(k);
		v = trim(v);
		if (!strcmp(k, "recovery")) {
			if (!strcmp(v, "sep-only"))
				c->recovery_sep_only = 1;
			else if (!strcmp(v, "offline"))
				c->recovery_sep_only = 0;
			else
				fprintf(stderr, "aurora-sep-fde: fde.conf: unknown recovery mode '%s'\n", v);
		} else if (!strcmp(k, "boot-chain")) {
			if (!strcmp(v, "require"))
				c->boot_chain_require = 1;
			else if (!strcmp(v, "warn"))
				c->boot_chain_require = 0;
			else
				fprintf(stderr, "aurora-sep-fde: fde.conf: unknown boot-chain policy '%s' (warn)\n", v);
		} else if (!strcmp(k, "admin-groups")) {
			snprintf(c->admin_groups, sizeof(c->admin_groups), "%s", v);
		} else if (!strcmp(k, "bag-uid-base")) {
			char *end;
			unsigned long b = strtoul(v, &end, 10);

			if (*end || b < SEP_FDE_UID_MIN || b > 0x7fff0000ul)
				fprintf(stderr, "aurora-sep-fde: fde.conf: bad bag-uid-base '%s'\n", v);
			else
				c->bag_uid_base = (uint32_t)b;
		}
	}
	fclose(f);
	return 0;
}

/* ---- users -------------------------------------------------------------- */

static int find_passwd(const struct fde_conf *c, const char *name, long uid, struct fde_user *u,
		       gid_t *gid)
{
	struct passwd *pw = NULL;
	FILE *f = NULL;

	if (c->passwd_file[0]) {
		f = fopen(c->passwd_file, "re");
		if (!f)
			return -errno;
		while ((pw = fgetpwent(f)))
			if (name ? !strcmp(pw->pw_name, name) : pw->pw_uid == (uid_t)uid)
				break;
	} else {
		pw = name ? getpwnam(name) : getpwuid((uid_t)uid);
	}
	if (pw) {
		snprintf(u->name, sizeof(u->name), "%s", pw->pw_name);
		u->uid = pw->pw_uid;
		*gid = pw->pw_gid;
	}
	if (f)
		fclose(f);
	return pw ? 0 : -ENOENT;
}

static int group_has(struct group *g, const char *user, gid_t primary)
{
	if (g->gr_gid == primary)
		return 1;
	for (char **m = g->gr_mem; m && *m; m++)
		if (!strcmp(*m, user))
			return 1;
	return 0;
}

static int is_admin(const struct fde_conf *c, const char *user, uid_t uid, gid_t primary)
{
	char list[sizeof(c->admin_groups)], *save = NULL;
	int admin = uid == 0;

	snprintf(list, sizeof(list), "%s", c->admin_groups);
	for (char *gname = strtok_r(list, " \t,", &save); gname && !admin;
	     gname = strtok_r(NULL, " \t,", &save)) {
		struct group *g;

		if (c->group_file[0]) {
			FILE *f = fopen(c->group_file, "re");

			if (!f)
				continue;
			while ((g = fgetgrent(f)))
				if (!strcmp(g->gr_name, gname)) {
					admin = group_has(g, user, primary);
					break;
				}
			fclose(f);
		} else if ((g = getgrnam(gname))) {
			admin = group_has(g, user, primary);
		}
	}
	return admin;
}

int fde_user_lookup(const struct fde_conf *c, const char *who, struct fde_user *u)
{
	char *end;
	long uid;
	gid_t gid = 0;
	int r;

	memset(u, 0, sizeof(*u));
	if (!who || !*who)
		return -EINVAL;
	uid = strtol(who, &end, 10);
	r = *end ? find_passwd(c, who, -1, u, &gid) : find_passwd(c, NULL, uid, u, &gid);
	if (r)
		return r;
	if ((uint64_t)c->bag_uid_base + u->uid > INT32_MAX)
		return -ERANGE;
	u->bag_uid = c->bag_uid_base + u->uid;
	u->admin = is_admin(c, u->name, u->uid, gid);
	return 0;
}

/* ---- registered volumes ------------------------------------------------- */

void fde_strv_free(char **v)
{
	for (char **p = v; p && *p; p++)
		free(*p);
	free(v);
}

char **fde_volumes_list(const struct fde_conf *c)
{
	char line[4096], **v = calloc(1, sizeof(char *));
	size_t n = 0;
	FILE *f;

	if (!v)
		return NULL;
	f = fopen(c->volumes_file, "re");
	if (!f)
		return v;
	while (fgets(line, sizeof(line), f)) {
		char *s = trim(line), **nv;

		if (!*s || *s == '#')
			continue;
		nv = realloc(v, (n + 2) * sizeof(char *));
		if (!nv)
			break;
		v = nv;
		v[n] = strdup(s);
		if (!v[n])
			break;
		v[++n] = NULL;
	}
	fclose(f);
	return v;
}

/* A stable name: /dev/disk/by-uuid/<LUKS UUID> for block devices, the
 * absolute path for image files. */
static int canonical(const char *path, char *out, size_t n)
{
	struct crypt_device *cd;
	struct stat st;
	char real[PATH_MAX];

	if (stat(path, &st))
		return -errno;
	if (S_ISBLK(st.st_mode) && fde_load(&cd, path) == 0) {
		const char *uuid = crypt_get_uuid(cd);

		if (uuid)
			snprintf(out, n, "/dev/disk/by-uuid/%s", uuid);
		crypt_free(cd);
		if (uuid)
			return 0;
	}
	if (!realpath(path, real))
		return -errno;
	snprintf(out, n, "%s", real);
	return 0;
}

static int same_volume(const char *a, const char *b)
{
	struct stat sa, sb;

	if (!strcmp(a, b))
		return 1;
	return !stat(a, &sa) && !stat(b, &sb) &&
	       (S_ISBLK(sa.st_mode) ? sa.st_rdev == sb.st_rdev
				   : sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino);
}

static int rewrite_volumes(const struct fde_conf *c, const char *add, const char *drop)
{
	char tmp[4200], name[PATH_MAX];
	char **v = fde_volumes_list(c);
	int found = 0, fd, r = 0;
	FILE *f;
	char *dir = strdup(c->volumes_file), *slash;

	if (!v || !dir) {
		free(dir);
		fde_strv_free(v);
		return -ENOMEM;
	}
	slash = strrchr(dir, '/');
	if (slash && slash != dir) {
		*slash = '\0';
		mkdir(dir, 0755);
	}
	free(dir);
	if (add && canonical(add, name, sizeof(name)))
		snprintf(name, sizeof(name), "%s", add);
	snprintf(tmp, sizeof(tmp), "%s.tmp", c->volumes_file);
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0) {
		fde_strv_free(v);
		return -errno;
	}
	f = fdopen(fd, "w");
	fputs("# Volumes with aurora-sep password tokens (aurora-sep-fde keeps this list).\n", f);
	for (char **p = v; *p; p++) {
		if (drop && same_volume(*p, drop))
			continue;
		if (add && same_volume(*p, name))
			found = 1;
		fprintf(f, "%s\n", *p);
	}
	if (add && !found)
		fprintf(f, "%s\n", name);
	if (fflush(f) || fsync(fileno(f)))
		r = -EIO;
	fclose(f);
	fde_strv_free(v);
	if (!r && rename(tmp, c->volumes_file))
		r = -errno;
	if (r)
		unlink(tmp);
	return r;
}

int fde_volumes_add(const struct fde_conf *c, const char *path)
{
	return rewrite_volumes(c, path, NULL);
}

int fde_volumes_drop(const struct fde_conf *c, const char *path)
{
	return rewrite_volumes(c, NULL, path);
}

/* ---- tokens ------------------------------------------------------------- */

int fde_load(struct crypt_device **cd, const char *device)
{
	const char *dir = secure_getenv("AURORA_SEP_TOKEN_DIR");
	int r;

	if (dir && *dir)
		crypt_token_set_external_path(dir);
	r = crypt_init(cd, device);
	if (r < 0)
		return r;
	r = crypt_load(*cd, CRYPT_LUKS2, NULL);
	if (r < 0)
		crypt_free(*cd);
	return r;
}

int fde_token_keyslot(struct crypt_device *cd, int token)
{
	for (int ks = 0; ks < crypt_keyslot_max(CRYPT_LUKS2); ks++)
		if (crypt_token_is_assigned(cd, token, ks) == 0)
			return ks;
	return -ENOENT;
}

int fde_find_token(struct crypt_device *cd, long bag_uid, const char *role, struct fde_token *t)
{
	for (int tok = 0; tok < FDE_TOKENS_MAX; tok++) {
		const char *type, *json;

		if (crypt_token_status(cd, tok, &type) == CRYPT_TOKEN_INACTIVE || !type ||
		    strcmp(type, SEP_SEAL_TOKEN_TYPE))
			continue;
		if (crypt_token_json_get(cd, tok, &json) < 0 || fde_token_parse(json, t) < 0)
			continue;
		if ((bag_uid < 0 || t->uid == (uint32_t)bag_uid) && !strcmp(t->role, role))
			return tok;
		fde_token_free(t);
	}
	return -ENOENT;
}

/* A token belongs to u by its Linux uid, or (tokens made with --uid and no
 * account) by its bag uid. */
static int token_is_users(const struct fde_token *t, const struct fde_user *u)
{
	if (strcmp(t->role, SEP_FDE_ROLE_USER))
		return 0;
	if (u->name[0] && t->linux_uid >= 0)
		return t->linux_uid == (int64_t)u->uid;
	return t->uid == u->bag_uid;
}

int fde_find_user_token(struct crypt_device *cd, const struct fde_user *u, struct fde_token *t)
{
	for (int tok = 0; tok < FDE_TOKENS_MAX; tok++) {
		const char *type, *json;

		if (crypt_token_status(cd, tok, &type) == CRYPT_TOKEN_INACTIVE || !type ||
		    strcmp(type, SEP_SEAL_TOKEN_TYPE))
			continue;
		if (crypt_token_json_get(cd, tok, &json) < 0 || fde_token_parse(json, t) < 0)
			continue;
		if (token_is_users(t, u))
			return tok;
		fde_token_free(t);
	}
	return -ENOENT;
}

int fde_replace_token(struct crypt_device *cd, int tok, const struct fde_token *t)
{
	int ks = fde_token_keyslot(cd, tok);
	char *json;
	int r;

	if (ks < 0)
		return ks;
	json = fde_token_build(t);
	if (!json)
		return -ENOMEM;
	r = crypt_token_json_set(cd, tok, json);
	free(json);
	if (r < 0)
		return r;
	return crypt_token_assign_keyslot(cd, tok, ks) < 0 ? -EIO : 0;
}

static int is_owner(const struct fde_token *t)
{
	return !strcmp(t->role, SEP_FDE_ROLE_USER) && t->owner != 0;
}

int fde_count_owners(struct crypt_device *cd)
{
	int n = 0;

	for (int tok = 0; tok < FDE_TOKENS_MAX; tok++) {
		const char *type, *json;
		struct fde_token t;

		if (crypt_token_status(cd, tok, &type) == CRYPT_TOKEN_INACTIVE || !type ||
		    strcmp(type, SEP_SEAL_TOKEN_TYPE) || crypt_token_json_get(cd, tok, &json) < 0 ||
		    fde_token_parse(json, &t) < 0)
			continue;
		n += is_owner(&t) && fde_token_keyslot(cd, tok) >= 0;
		fde_token_free(&t);
	}
	return n;
}

static void hex_pass(const uint8_t secret[SEP_FDE_SECRET_BYTES], char out[SEP_FDE_PASS_LEN + 1])
{
	sep_hex_encode(secret, SEP_FDE_SECRET_BYTES, out, SEP_FDE_PASS_LEN + 1);
}

int fde_auth_owner(struct crypt_device *cd, const struct fde_user *auth, const char *pw,
		   size_t pw_len, int require_owner, uint8_t secret[SEP_FDE_SECRET_BYTES])
{
	struct fde_token t;
	int tok, r;

	tok = fde_find_user_token(cd, auth, &t);
	if (tok < 0)
		return -ENOENT;
	if (require_owner && !is_owner(&t)) {
		fde_token_free(&t);
		return -EPERM;
	}
	r = fde_open_token(&t, pw, pw_len, secret);
	fde_token_free(&t);
	if (r == -EACCES || r == -ENODEV)
		return r;
	if (r)
		return -EPERM;
	/* The secret must open the token's own keyslot: a token copied from
	 * elsewhere or a destroyed keyslot never authorizes a change. */
	{
		char pass[SEP_FDE_PASS_LEN + 1];
		int ks = fde_token_keyslot(cd, tok);

		hex_pass(secret, pass);
		r = ks < 0 ? ks : crypt_activate_by_passphrase(cd, NULL, ks, pass, SEP_FDE_PASS_LEN, 0);
		sep_wipe(pass, sizeof(pass));
	}
	if (r < 0) {
		sep_wipe(secret, SEP_FDE_SECRET_BYTES);
		return -EPERM;
	}
	return 0;
}

/* u's wrapped bags on the registered volumes (and dev), with their bag uids. */
struct bags {
	uint8_t *b[64];
	size_t n[64];
	uint32_t uid[64];
	int count;
};

static void bags_free(struct bags *bs)
{
	for (int i = 0; i < bs->count; i++)
		free(bs->b[i]);
	bs->count = 0;
}

static void bags_add_volume(const char *path, const struct fde_user *u, struct bags *bs)
{
	struct crypt_device *cd;
	struct fde_token t;

	if (bs->count >= 64 || fde_load(&cd, path))
		return;
	if (fde_find_user_token(cd, u, &t) >= 0) {
		bs->b[bs->count] = t.bag;
		bs->n[bs->count] = t.bag_len;
		bs->uid[bs->count++] = t.uid;
		t.bag = NULL;
		fde_token_free(&t);
	}
	crypt_free(cd);
}

static void bags_collect(const struct fde_conf *c, const char *dev, const struct fde_user *u,
			 struct bags *bs)
{
	char **v = fde_volumes_list(c);

	bs->count = 0;
	if (dev)
		bags_add_volume(dev, u, bs);
	for (char **p = v; p && *p; p++)
		if (!dev || !same_volume(*p, dev))
			bags_add_volume(*p, u, bs);
	fde_strv_free(v);
}

/*
 * Make the enclave hold u's current bag, unlocked with pw: one it holds, else
 * one of u's wrapped bags on the volumes that pw unlocks. Returns 1 and the
 * bag uid in *bag_uid when such a bag is live and unlocked, 0 when u has no
 * bag (the caller makes one), -EACCES when u has bags pw does not unlock.
 */
static int bag_prepare(const struct fde_conf *c, const char *dev, const struct fde_user *u,
		       const char *pw, size_t pw_len, uint32_t *bag_uid)
{
	struct fde_state st;
	struct bags bs;
	int r = 0, seen = 0;

	bags_collect(c, dev, u, &bs);
	for (int i = 0; i < bs.count && r != 1; i++) {
		if (fde_bag_state(bs.uid[i], &st) < 0 && fde_bag_import(bs.uid[i], bs.b[i], bs.n[i]))
			continue;
		seen = 1;
		if (fde_bag_unlock(bs.uid[i], pw, pw_len) == 0) {
			*bag_uid = bs.uid[i];
			r = 1;
		}
	}
	bags_free(&bs);
	if (r == 1)
		return 1;
	return seen ? -EACCES : 0;
}

/* Writes blob (bag bag_uid) into u's tokens of that bag on every registered
 * volume and on dev. */
static int bag_propagate(const struct fde_conf *c, const char *dev, const struct fde_user *u,
			 uint32_t bag_uid, const uint8_t *blob, size_t len, int *updated,
			 int *failed)
{
	char **v = fde_volumes_list(c);
	char **all;
	size_t n = 0;

	for (char **p = v; p && *p; p++)
		n++;
	all = calloc(n + 2, sizeof(char *));
	if (!all) {
		fde_strv_free(v);
		return -ENOMEM;
	}
	n = 0;
	if (dev)
		all[n++] = (char *)dev;
	for (char **p = v; p && *p; p++)
		if (!dev || !same_volume(*p, dev))
			all[n++] = *p;
	*updated = *failed = 0;
	for (size_t i = 0; i < n; i++) {
		struct crypt_device *cd;
		struct fde_token t;
		uint8_t *nb = NULL;
		int tok;

		if (fde_load(&cd, all[i]))
			continue;
		tok = fde_find_user_token(cd, u, &t);
		if (tok >= 0 && t.uid != bag_uid) {
			/* another bag of u (made by a reset): not this one */
		} else if (tok >= 0 && t.bag_len == len && !memcmp(t.bag, blob, len)) {
			(*updated)++;	/* already current */
		} else if (tok >= 0) {
			nb = malloc(len);
			if (nb) {
				memcpy(nb, blob, len);
				free(t.bag);
				t.bag = nb;
				t.bag_len = len;
			}
			if (nb && fde_replace_token(cd, tok, &t) == 0) {
				(*updated)++;
			} else {
				(*failed)++;
				fprintf(stderr, "aurora-sep-fde: could not write the new key bag to %s\n",
					all[i]);
			}
		}
		if (tok >= 0)
			fde_token_free(&t);
		crypt_free(cd);
	}
	free(all);
	fde_strv_free(v);
	return *failed ? -EIO : 0;
}

static int add_slot_and_token(struct crypt_device *cd, const char *existing, size_t elen,
			      const uint8_t secret[SEP_FDE_SECRET_BYTES], const struct fde_token *t)
{
	struct crypt_pbkdf_type pbkdf = {
		.type = CRYPT_KDF_PBKDF2, .hash = "sha512", .iterations = 1000,
		.flags = CRYPT_PBKDF_NO_BENCHMARK,
	};
	char pass[SEP_FDE_PASS_LEN + 1];
	char *json;
	int ks, tok, r;

	r = crypt_set_pbkdf_type(cd, &pbkdf);
	if (r < 0)
		return r;
	hex_pass(secret, pass);
	ks = crypt_keyslot_add_by_passphrase(cd, CRYPT_ANY_SLOT, existing, elen, pass, SEP_FDE_PASS_LEN);
	if (ks >= 0 && crypt_activate_by_passphrase(cd, NULL, ks, pass, SEP_FDE_PASS_LEN, 0) < 0) {
		crypt_keyslot_destroy(cd, ks);
		ks = -EIO;
	}
	sep_wipe(pass, sizeof(pass));
	if (ks < 0)
		return ks;
	json = fde_token_build(t);
	if (!json) {
		crypt_keyslot_destroy(cd, ks);
		return -ENOMEM;
	}
	tok = crypt_token_json_set(cd, CRYPT_ANY_TOKEN, json);
	free(json);
	if (tok < 0 || (r = crypt_token_assign_keyslot(cd, tok, ks)) < 0) {
		if (tok >= 0)
			crypt_token_json_set(cd, tok, NULL);
		crypt_keyslot_destroy(cd, ks);
		return tok < 0 ? tok : r;
	}
	return ks;
}

/*
 * A new bag for u. The enclave keeps a bag until reboot and has no delete,
 * and it refuses to make a second bag under a uid it holds; a user who needs
 * a new bag while the old one is loaded (a reset after their token was
 * tried this boot) gets the next generation: base + uid + n * stride.
 */
static int bag_create_fresh(const struct fde_user *u, const char *pw, size_t pw_len,
			    const uint8_t secret[SEP_FDE_SECRET_BYTES], struct fde_token *t)
{
	struct fde_state st;
	int r = -EBUSY;

	for (uint32_t gen = 0; gen < FDE_BAG_GENERATIONS; gen++) {
		uint64_t uid = (uint64_t)u->bag_uid + (uint64_t)gen * FDE_BAG_GEN_STRIDE;

		if (uid > INT32_MAX)
			break;
		if (fde_bag_state((uint32_t)uid, &st) == 0)
			continue;	/* held by the enclave this boot */
		r = fde_enroll((uint32_t)uid, SEP_FDE_ROLE_USER, pw, pw_len, secret, t);
		if (r != -EACCES && r != -EEXIST)
			return r;
	}
	return r;
}

int fde_add_user(struct crypt_device *cd, const struct fde_conf *c, const char *existing,
		 size_t elen, const struct fde_user *u, const char *pw, size_t pw_len, int owner,
		 const char *label)
{
	uint8_t secret[SEP_FDE_SECRET_BYTES];
	struct fde_token t;
	uint32_t bag_uid = 0;
	int r, ks;

	char rk[SEP_FDE_RK_LEN + 1];

	/* A password shaped like a recovery key goes only to recovery tokens
	 * at the unlock prompt, so it could never open this token. */
	if (!pw_len || pw_len > SEP_FDE_PASSWORD_MAX || fde_recovery_key_normalize(pw, pw_len, rk) == 0)
		return -EINVAL;
	if (fde_find_user_token(cd, u, &t) >= 0) {
		fde_token_free(&t);
		return -EEXIST;
	}
	if (getrandom(secret, sizeof(secret), 0) != (ssize_t)sizeof(secret))
		return -EIO;
	r = u->name[0] ? bag_prepare(c, NULL, u, pw, pw_len, &bag_uid) : 0;
	if (r == 1)
		r = fde_enroll_in_bag(bag_uid, SEP_FDE_ROLE_USER, pw, pw_len, secret, &t);
	else if (r == 0)
		r = bag_create_fresh(u, pw, pw_len, secret, &t);
	if (r) {
		if (bag_uid)
			fde_bag_lock(bag_uid);
		sep_wipe(secret, sizeof(secret));
		return r;
	}
	t.owner = owner ? 1 : 0;
	if (u->name[0]) {
		t.linux_uid = u->uid;
		snprintf(t.user, sizeof(t.user), "%s", u->name);
	}
	snprintf(t.label, sizeof(t.label), "%s", label ? label : u->name);
	ks = add_slot_and_token(cd, existing, elen, secret, &t);
	sep_wipe(secret, sizeof(secret));
	if (ks >= 0 && u->name[0]) {
		/* Keys made under the bag may change its wrapped form: keep every
		 * volume of this user on the same bag. */
		int up = 0, failed = 0;

		bag_propagate(c, NULL, u, t.uid, t.bag, t.bag_len, &up, &failed);
	}
	fde_token_free(&t);
	return ks;
}

int fde_remove_user(struct crypt_device *cd, const struct fde_user *u)
{
	struct fde_token t;
	int tok, ks, owner;

	tok = fde_find_user_token(cd, u, &t);
	if (tok < 0)
		return -ENOENT;
	owner = is_owner(&t);
	fde_token_free(&t);
	if (owner && fde_count_owners(cd) <= 1)
		return -EBUSY;
	ks = fde_token_keyslot(cd, tok);
	crypt_token_json_set(cd, tok, NULL);
	if (ks >= 0)
		return crypt_keyslot_destroy(cd, ks);
	return 0;
}

int fde_change_password(const struct fde_conf *c, const char *device, const struct fde_user *u,
			const char *old_pw, size_t old_len, const char *new_pw, size_t new_len,
			int *updated)
{
	char rk[SEP_FDE_RK_LEN + 1];
	uint8_t *blob = NULL;
	uint32_t bag_uid = 0;
	size_t len = 0;
	int r, failed = 0;

	*updated = 0;
	if (!new_len || new_len > SEP_FDE_PASSWORD_MAX)
		return -EINVAL;
	if (fde_recovery_key_normalize(new_pw, new_len, rk) == 0)
		return -EINVAL;	/* would be routed to recovery tokens at the prompt */
	/* Find the bag the old password opens (the enclave checks it). */
	r = bag_prepare(c, device, u, old_pw, old_len, &bag_uid);
	if (r == 0)
		return -ENOENT;
	if (r < 0)
		return r == -ENODEV ? r : -EACCES;
	fde_bag_lock(bag_uid);
	/* The enclave checks the old password again and re-wraps the bag;
	 * sealed secrets and keyslots stay, so no data is at risk. */
	r = fde_bag_change(bag_uid, old_pw, old_len, new_pw, new_len);
	if (r)
		return r == -ENODEV ? r : -EACCES;
	r = fde_bag_export(bag_uid, &blob, &len);
	fde_bag_lock(bag_uid);
	if (r)
		return r;
	r = bag_propagate(c, device, u, bag_uid, blob, len, updated, &failed);
	free(blob);
	return r;
}

int fde_reset_by_owner(struct crypt_device *cd, const struct fde_conf *c,
		       const uint8_t owner_secret[SEP_FDE_SECRET_BYTES], const struct fde_user *u,
		       const char *new_pw, size_t new_len)
{
	char opass[SEP_FDE_PASS_LEN + 1], rk[SEP_FDE_RK_LEN + 1];
	uint8_t secret[SEP_FDE_SECRET_BYTES];
	struct fde_token old, t;
	struct fde_user nu = *u;
	int otok, oks, ks, r;

	(void)c;
	if (!new_len || new_len > SEP_FDE_PASSWORD_MAX ||
	    fde_recovery_key_normalize(new_pw, new_len, rk) == 0)
		return -EINVAL;
	otok = fde_find_user_token(cd, u, &old);
	if (otok < 0)
		return -ENOENT;
	oks = fde_token_keyslot(cd, otok);
	if (getrandom(secret, sizeof(secret), 0) != (ssize_t)sizeof(secret)) {
		fde_token_free(&old);
		return -EIO;
	}
	/* The forgotten password's bag cannot be re-wrapped (the enclave needs
	 * the old password); the user gets a new bag. */
	if (!u->name[0])
		nu.bag_uid = old.uid;
	r = bag_create_fresh(&nu, new_pw, new_len, secret, &t);
	if (r) {
		fde_token_free(&old);
		sep_wipe(secret, sizeof(secret));
		return r;
	}
	t.owner = old.owner;
	t.linux_uid = old.linux_uid;
	snprintf(t.user, sizeof(t.user), "%s", old.user);
	snprintf(t.label, sizeof(t.label), "%s", old.label[0] ? old.label : u->name);
	fde_token_free(&old);
	hex_pass(owner_secret, opass);
	/* New slot first, old one removed only after the new one opens: the
	 * user is never left without a way in. */
	ks = add_slot_and_token(cd, opass, SEP_FDE_PASS_LEN, secret, &t);
	sep_wipe(opass, sizeof(opass));
	sep_wipe(secret, sizeof(secret));
	if (ks >= 0) {
		crypt_token_json_set(cd, otok, NULL);
		if (oks >= 0)
			crypt_keyslot_destroy(cd, oks);
	}
	fde_token_free(&t);
	return ks < 0 ? ks : 0;
}

int fde_sync_bag(const struct fde_conf *c, const struct fde_user *u, int *updated)
{
	struct fde_state st;
	struct bags bs;
	uint8_t *blob = NULL;
	size_t len = 0;
	int failed = 0, r = -ENOENT;

	*updated = 0;
	/* Only the enclave knows which of u's bags is current: the one it holds. */
	bags_collect(c, NULL, u, &bs);
	for (int i = 0; i < bs.count && r == -ENOENT; i++) {
		if (fde_bag_state(bs.uid[i], &st) < 0)
			continue;
		r = fde_bag_export(bs.uid[i], &blob, &len);
		if (!r)
			r = bag_propagate(c, NULL, u, bs.uid[i], blob, len, updated, &failed);
		free(blob);
	}
	bags_free(&bs);
	return r;
}
