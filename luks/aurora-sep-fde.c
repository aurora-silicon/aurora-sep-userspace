// SPDX-License-Identifier: MIT
/*
 * aurora-sep-fde: FileVault-style LUKS2 unlock. The keyslot secret is sealed
 * by the Secure Enclave to a key under a per-user key bag that only the user's
 * password unlocks; a recovery key is a second bag with its own keyslot.
 *
 *   aurora-sep-fde enroll   --user U [--owner|--no-owner] --unlock-key-file F [--password-file P] DEVICE
 *   aurora-sep-fde add-user --user U [--owner|--no-owner] [--auth-user A] [--auth-password-file F]
 *                           [--password-file P] DEVICE
 *   aurora-sep-fde remove-user --user U [--auth-user A] [--auth-password-file F] DEVICE
 *   aurora-sep-fde set-owner --user U --owner|--no-owner [--auth-user A] [--auth-password-file F] DEVICE
 *   aurora-sep-fde recovery [--uid N] --unlock-key-file F [--recovery-key-file OUT]
 *                           [--sep-only|--offline] DEVICE
 *   aurora-sep-fde change-password --user U [--old-file O --new-file P] [DEVICE]
 *   aurora-sep-fde reset-password  --user U (--recovery-key-file R | [--auth-user A]
 *                           [--auth-password-file F]) [--new-file P] DEVICE
 *   aurora-sep-fde passwd-hook --user U   (old and new password on stdin, NUL-terminated)
 *   aurora-sep-fde sync     --user U
 *   aurora-sep-fde test     [--password-file P | --recovery-key-file R] [--name MAPPING] DEVICE
 *   aurora-sep-fde remove-passphrase --unlock-key-file F DEVICE
 *   aurora-sep-fde gate-check --user U [--password-file P] DEVICE
 *   aurora-sep-fde status   [DEVICE]
 *
 * --uid N names an enclave bag uid directly (tests, enrolments made before
 * --user existed). --auth-user defaults to $SUDO_USER: changes to other users
 * need an owner's password, checked by the enclave (fde-owner.h).
 *
 * Root only (the key-bag ioctls are on the root-only re-arm node). Secrets
 * come from files (tests, installers) or the terminal with echo off; they are
 * never logged or stored.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <sys/random.h>
#include <json-c/json.h>
#include <libcryptsetup.h>

#include "fde-owner.h"
#include "sep-fde.h"
#include "sep-seal.h"

#define SECRET_MAX 1024

struct opts {
	const char *cmd, *device, *unlock_key_file, *password_file, *old_file, *new_file,
		*recovery_key_file, *label, *name, *user, *auth_user, *auth_password_file;
	long uid;
	int quiet, sep_only, offline, owner;	/* owner: -1 default, 0 no, 1 yes */
	struct fde_conf conf;
};

static void die_usage(void)
{
	fputs("usage: aurora-sep-fde enroll|add-user|remove-user|set-owner|recovery|change-password|\n"
	      "       reset-password|passwd-hook|sync|test|remove-passphrase|gate-check|status\n"
	      "       [options] [DEVICE]\n", stderr);
	exit(2);
}

static int read_file(const char *path, char *buf, size_t size, size_t *len)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	ssize_t n;

	if (fd < 0)
		return -errno;
	n = read(fd, buf, size);
	close(fd);
	if (n < 0)
		return -EIO;
	if ((size_t)n == size)
		return -E2BIG;
	*len = (size_t)n;
	return 0;
}

static int read_tty(const char *prompt, char *buf, size_t size, size_t *len)
{
	struct termios old, raw;
	FILE *tty = fopen("/dev/tty", "r+");
	int r = 0;

	if (!tty)
		return -ENOTTY;
	fputs(prompt, tty);
	fflush(tty);
	tcgetattr(fileno(tty), &old);
	raw = old;
	raw.c_lflag &= ~(tcflag_t)ECHO;
	tcsetattr(fileno(tty), TCSAFLUSH, &raw);
	if (!fgets(buf, (int)size, tty))
		r = -EIO;
	tcsetattr(fileno(tty), TCSAFLUSH, &old);
	fputc('\n', tty);
	fclose(tty);
	if (r)
		return r;
	*len = strcspn(buf, "\n");
	buf[*len] = '\0';
	return 0;
}

/* A secret from a file (as is, a trailing newline dropped) or the terminal. */
static int get_secret(const char *file, const char *prompt, int confirm, char *buf, size_t *len)
{
	char again[SECRET_MAX];
	size_t n2 = 0;
	int r;

	if (file) {
		r = read_file(file, buf, SECRET_MAX, len);
		if (!r && *len && buf[*len - 1] == '\n')
			(*len)--;
		return r ? r : (*len ? 0 : -EINVAL);
	}
	r = read_tty(prompt, buf, SECRET_MAX, len);
	if (r || !confirm)
		return r ? r : (*len ? 0 : -EINVAL);
	r = read_tty("Verify: ", again, sizeof(again), &n2);
	if (!r && (n2 != *len || memcmp(again, buf, n2)))
		r = -EINVAL;
	sep_wipe(again, sizeof(again));
	return r ? r : (*len ? 0 : -EINVAL);
}

/*
 * An existing LUKS passphrase from --unlock-key-file is a key file in the
 * cryptsetup sense: every byte counts, a trailing newline included (as with
 * "cryptsetup luksFormat DEV FILE" and systemd-cryptenroll --unlock-key-file).
 */
static int get_key(const char *file, const char *prompt, char *buf, size_t *len)
{
	int r;

	if (!file)
		return get_secret(NULL, prompt, 0, buf, len);
	r = read_file(file, buf, SECRET_MAX, len);
	return r ? r : (*len ? 0 : -EINVAL);
}

#define load fde_load
#define token_keyslot fde_token_keyslot
#define find_token fde_find_token
#define replace_token fde_replace_token

static void hex_pass(const uint8_t secret[SEP_FDE_SECRET_BYTES], char out[SEP_FDE_PASS_LEN + 1])
{
	sep_hex_encode(secret, SEP_FDE_SECRET_BYTES, out, SEP_FDE_PASS_LEN + 1);
}

/* Adds a keyslot for secret (high entropy: minimal PBKDF2) and its token. */
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

/* Proves a keyslot opens with secret before the tool reports success. */
static int verify_slot(struct crypt_device *cd, int ks, const uint8_t secret[SEP_FDE_SECRET_BYTES])
{
	char pass[SEP_FDE_PASS_LEN + 1];
	int r;

	hex_pass(secret, pass);
	r = crypt_activate_by_passphrase(cd, NULL, ks, pass, SEP_FDE_PASS_LEN, 0);
	sep_wipe(pass, sizeof(pass));
	return r < 0 ? r : 0;
}

/*
 * The recovery key also opens a plain LUKS2 keyslot (the distribution's
 * default PBKDF), so the volume opens at the passphrase prompt when this
 * Mac's SEP cannot answer at all (no driver, a refused key store, another OS
 * identity after a reinstall). The key has about 120 bits of entropy, so an
 * offline slot does not weaken it. --sep-only leaves it out (FileVault's
 * strict form: every unlock goes through the enclave).
 */
static int add_offline_recovery_slot(struct crypt_device *cd, long uid, const char *existing,
				     size_t elen, const char *rk)
{
	struct fde_token t;
	int tok, ks, r;

	r = crypt_set_pbkdf_type(cd, NULL);
	if (r < 0)
		return r;
	ks = crypt_keyslot_add_by_passphrase(cd, CRYPT_ANY_SLOT, existing, elen, rk, strlen(rk));
	if (ks < 0)
		return ks;
	r = crypt_activate_by_passphrase(cd, NULL, ks, rk, strlen(rk), 0);
	tok = find_token(cd, uid, SEP_FDE_ROLE_RECOVERY, &t);
	if (r >= 0 && tok >= 0) {
		t.offline_keyslot = ks;
		r = replace_token(cd, tok, &t);
	} else if (r >= 0) {
		r = tok;
	}
	if (tok >= 0)
		fde_token_free(&t);
	if (r < 0) {
		crypt_keyslot_destroy(cd, ks);
		return r;
	}
	return ks;
}

static int cmd_enroll(struct crypt_device *cd, const struct opts *o, int recovery)
{
	uint8_t secret[SEP_FDE_SECRET_BYTES];
	char existing[SECRET_MAX], pw[SECRET_MAX], rk[SEP_FDE_RK_LEN + 1];
	struct fde_token t, other;
	size_t elen = 0, plen = 0;
	int ks, r;

	if (o->uid < SEP_FDE_UID_MIN)
		return -EINVAL;
	if (find_token(cd, o->uid, recovery ? SEP_FDE_ROLE_RECOVERY : SEP_FDE_ROLE_USER, &other) >= 0) {
		fde_token_free(&other);
		fprintf(stderr, "aurora-sep-fde: uid %ld already has a %s token on this volume\n",
			o->uid, recovery ? "recovery" : "password");
		return -EEXIST;
	}
	r = get_key(o->unlock_key_file, "Existing LUKS passphrase: ", existing, &elen);
	if (r)
		return r;
	if (recovery) {
		r = fde_recovery_key_new(rk);
		memcpy(pw, rk, strlen(rk));
		plen = strlen(rk);
	} else {
		r = get_secret(o->password_file, "New password: ", 1, pw, &plen);
		if (!r && fde_recovery_key_normalize(pw, plen, rk) == 0) {
			fprintf(stderr, "aurora-sep-fde: that password has the shape of a recovery key; choose another\n");
			r = -EINVAL;
		}
	}
	if (!r && getrandom(secret, sizeof(secret), 0) != (ssize_t)sizeof(secret))
		r = -EIO;
	if (!r)
		r = fde_enroll((uint32_t)o->uid, recovery ? SEP_FDE_ROLE_RECOVERY : SEP_FDE_ROLE_USER,
			       pw, plen, secret, &t);
	sep_wipe(pw, sizeof(pw));
	if (r) {
		fprintf(stderr, "aurora-sep-fde: the Secure Enclave refused the enrolment (%s)\n", strerror(-r));
		goto out;
	}
	if (o->label)
		snprintf(t.label, sizeof(t.label), "%s", o->label);
	ks = add_slot_and_token(cd, existing, elen, secret, &t);
	fde_token_free(&t);
	if (ks < 0) {
		r = ks;
		fprintf(stderr, "aurora-sep-fde: adding the keyslot failed (%s)\n", strerror(-r));
		goto out;
	}
	r = verify_slot(cd, ks, secret);
	if (r)
		goto out;
	if (recovery && !o->sep_only) {
		int oks = add_offline_recovery_slot(cd, o->uid, existing, elen, rk);

		if (oks < 0) {
			r = oks;
			fprintf(stderr, "aurora-sep-fde: adding the offline recovery keyslot failed (%s)\n",
				strerror(-r));
			goto out;
		}
		if (!o->quiet)
			printf("offline recovery keyslot %d (opens at the passphrase prompt without the SEP)\n", oks);
	}
	if (recovery) {
		if (o->recovery_key_file) {
			int fd = open(o->recovery_key_file, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);

			if (fd < 0 || write(fd, rk, strlen(rk)) != (ssize_t)strlen(rk)) {
				r = -EIO;
				fprintf(stderr, "aurora-sep-fde: cannot write the recovery key file\n");
			}
			if (fd >= 0)
				close(fd);
		} else {
			printf("Recovery key (write it down; it is shown once):\n\n    %s\n\n", rk);
		}
	}
	if (!r && !o->quiet)
		printf("enrolled: keyslot %d, %s, bag uid %ld\n", ks,
		       recovery ? "recovery key" : "password", o->uid);
out:
	sep_wipe(secret, sizeof(secret));
	sep_wipe(existing, sizeof(existing));
	sep_wipe(rk, sizeof(rk));
	return r;
}

static const char *errname(int r)
{
	switch (r) {
	case -EACCES: return "wrong password (the Secure Enclave counted the attempt)";
	case -EPERM: return "not allowed";
	case -ENOENT: return "no such token";
	case -EEXIST: return "already enrolled";
	case -EBUSY: return "that is the last owner of this volume";
	case -ENODEV: return "no Secure Enclave key store";
	default: return strerror(-r);
	}
}

/* The target user (--user, or a bare enclave bag uid with --uid). */
static int target_user(const struct opts *o, struct fde_user *u)
{
	int r;

	memset(u, 0, sizeof(*u));
	if (o->user) {
		r = fde_user_lookup(&o->conf, o->user, u);
		if (r)
			fprintf(stderr, "aurora-sep-fde: no user '%s'\n", o->user);
		return r;
	}
	if (o->uid < SEP_FDE_UID_MIN) {
		fprintf(stderr, "aurora-sep-fde: name the user with --user\n");
		return -EINVAL;
	}
	u->bag_uid = (uint32_t)o->uid;
	return 0;
}

/*
 * The owner authorizing a change: --auth-user, else the user who ran sudo.
 * The enclave checks that owner's password by opening their token; the
 * secret it yields is the existing key the change is made with.
 */
static int authorize(struct crypt_device *cd, const struct opts *o, uint8_t secret[SEP_FDE_SECRET_BYTES],
		     struct fde_user *auth)
{
	const char *who = o->auth_user ? o->auth_user : getenv("SUDO_USER");
	char pw[SECRET_MAX], prompt[160];
	size_t plen = 0;
	int r;

	if (!who || !*who) {
		fprintf(stderr, "aurora-sep-fde: name the volume owner who authorizes this with --auth-user\n");
		return -EPERM;
	}
	r = fde_user_lookup(&o->conf, who, auth);
	if (r) {
		fprintf(stderr, "aurora-sep-fde: no user '%s'\n", who);
		return r;
	}
	snprintf(prompt, sizeof(prompt), "Password of volume owner %s: ", auth->name);
	r = get_secret(o->auth_password_file, prompt, 0, pw, &plen);
	if (r)
		return r;
	r = fde_auth_owner(cd, auth, pw, plen, 1, secret);
	sep_wipe(pw, sizeof(pw));
	if (r == -ENOENT)
		fprintf(stderr, "aurora-sep-fde: %s cannot unlock this volume, so cannot authorize changes\n",
			auth->name);
	else if (r == -EPERM)
		fprintf(stderr, "aurora-sep-fde: %s is not an owner of this volume\n", auth->name);
	else if (r)
		fprintf(stderr, "aurora-sep-fde: %s's password was not accepted (%s)\n", auth->name, errname(r));
	return r;
}

static int want_owner(const struct opts *o, const struct fde_user *u)
{
	return o->owner >= 0 ? o->owner : u->admin;
}

/* First users, with the installer's LUKS passphrase. The first user token on
 * a volume is always an owner. */
static int cmd_enroll_user(struct crypt_device *cd, const struct opts *o)
{
	char existing[SECRET_MAX], pw[SECRET_MAX];
	size_t elen = 0, plen = 0;
	struct fde_user u;
	int owner, ks, r;

	r = target_user(o, &u);
	if (r)
		return r;
	owner = fde_count_owners(cd) == 0 ? 1 : want_owner(o, &u);
	if (!u.name[0] && o->owner < 0)
		owner = 1;
	r = get_key(o->unlock_key_file, "Existing LUKS passphrase: ", existing, &elen);
	if (!r)
		r = get_secret(o->password_file, "Password: ", 1, pw, &plen);
	if (!r) {
		ks = fde_add_user(cd, &o->conf, existing, elen, &u, pw, plen, owner, o->label);
		r = ks < 0 ? ks : 0;
	}
	sep_wipe(existing, sizeof(existing));
	sep_wipe(pw, sizeof(pw));
	if (r) {
		fprintf(stderr, "aurora-sep-fde: enrolment failed (%s)\n",
			r == -EINVAL ? "the password is empty, too long or shaped like a recovery key" : errname(r));
		return r;
	}
	if (u.name[0] && fde_volumes_add(&o->conf, o->device))
		fprintf(stderr, "aurora-sep-fde: could not register %s in %s\n", o->device, o->conf.volumes_file);
	if (!o->quiet)
		printf("enrolled: keyslot %d, %s%s, bag uid %u, %s\n", ks, u.name[0] ? "user " : "password",
		       u.name, u.bag_uid, owner ? "volume owner" : "unlock only");
	return 0;
}

static int cmd_add_user(struct crypt_device *cd, const struct opts *o)
{
	uint8_t secret[SEP_FDE_SECRET_BYTES];
	char existing[SEP_FDE_PASS_LEN + 1], pw[SECRET_MAX], prompt[160];
	struct fde_user u, auth;
	size_t plen = 0;
	int owner, ks, r;

	r = target_user(o, &u);
	if (r)
		return r;
	owner = want_owner(o, &u);
	r = authorize(cd, o, secret, &auth);
	if (r)
		return r;
	snprintf(prompt, sizeof(prompt), "Password of %s: ", u.name[0] ? u.name : "the new user");
	r = get_secret(o->password_file, prompt, 0, pw, &plen);
	if (!r) {
		sep_hex_encode(secret, SEP_FDE_SECRET_BYTES, existing, sizeof(existing));
		ks = fde_add_user(cd, &o->conf, existing, SEP_FDE_PASS_LEN, &u, pw, plen, owner, o->label);
		r = ks < 0 ? ks : 0;
	}
	sep_wipe(secret, sizeof(secret));
	sep_wipe(existing, sizeof(existing));
	sep_wipe(pw, sizeof(pw));
	if (r) {
		fprintf(stderr, "aurora-sep-fde: adding %s failed (%s)\n", u.name,
			r == -EINVAL ? "the password is empty, too long or shaped like a recovery key" : errname(r));
		return r;
	}
	if (u.name[0])
		fde_volumes_add(&o->conf, o->device);
	if (!o->quiet)
		printf("added %s: keyslot %d, bag uid %u, %s (authorized by %s)\n", u.name, ks, u.bag_uid,
		       owner ? "volume owner" : "unlock only", auth.name);
	return 0;
}

static int cmd_remove_user(struct crypt_device *cd, const struct opts *o)
{
	uint8_t secret[SEP_FDE_SECRET_BYTES];
	struct fde_user u, auth;
	struct fde_token t;
	int r;

	r = target_user(o, &u);
	if (r)
		return r;
	if (fde_find_user_token(cd, &u, &t) < 0) {
		fprintf(stderr, "aurora-sep-fde: %s has no password on this volume\n", u.name);
		return -ENOENT;
	}
	fde_token_free(&t);
	r = authorize(cd, o, secret, &auth);
	sep_wipe(secret, sizeof(secret));
	if (r)
		return r;
	r = fde_remove_user(cd, &u);
	if (r) {
		fprintf(stderr, "aurora-sep-fde: removing %s failed (%s)\n", u.name, errname(r));
		return r;
	}
	if (!o->quiet)
		printf("removed %s (authorized by %s)\n", u.name, auth.name);
	return 0;
}

static int cmd_set_owner(struct crypt_device *cd, const struct opts *o)
{
	uint8_t secret[SEP_FDE_SECRET_BYTES];
	struct fde_user u, auth;
	struct fde_token t;
	int tok, r;

	if (o->owner < 0)
		die_usage();
	r = target_user(o, &u);
	if (r)
		return r;
	tok = fde_find_user_token(cd, &u, &t);
	if (tok < 0) {
		fprintf(stderr, "aurora-sep-fde: %s has no password on this volume\n", u.name);
		return -ENOENT;
	}
	r = authorize(cd, o, secret, &auth);
	sep_wipe(secret, sizeof(secret));
	if (!r && !o->owner && t.owner != 0 && fde_count_owners(cd) <= 1)
		r = -EBUSY;
	if (!r) {
		t.owner = o->owner;
		r = replace_token(cd, tok, &t);
	}
	fde_token_free(&t);
	if (r) {
		fprintf(stderr, "aurora-sep-fde: changing %s failed (%s)\n", u.name, errname(r));
		return r;
	}
	if (!o->quiet)
		printf("%s is %s (authorized by %s)\n", u.name, o->owner ? "a volume owner" : "no longer a volume owner",
		       auth.name);
	return 0;
}

static int cmd_change(const struct opts *o)
{
	char old[SECRET_MAX], nw[SECRET_MAX];
	size_t olen = 0, nlen = 0;
	struct fde_user u;
	int up = 0, r;

	r = target_user(o, &u);
	if (r)
		return r;
	r = get_secret(o->old_file, "Current password: ", 0, old, &olen);
	if (!r)
		r = get_secret(o->new_file, "New password: ", 1, nw, &nlen);
	if (!r)
		r = fde_change_password(&o->conf, o->device, &u, old, olen, nw, nlen, &up);
	sep_wipe(old, sizeof(old));
	sep_wipe(nw, sizeof(nw));
	if (r)
		fprintf(stderr, "aurora-sep-fde: password change failed (%s)\n",
			r == -EINVAL ? "the new password is empty, too long or shaped like a recovery key"
				     : errname(r));
	else if (!o->quiet)
		printf("password changed for %s (bag uid %u) on %d volume(s)\n", u.name[0] ? u.name : "bag",
		       u.bag_uid, up);
	return r;
}

/*
 * PAM password-change hook (pam_aurora_sep_fde): the old and new passwords
 * arrive on stdin, each NUL-terminated. A user without tokens is not an
 * error. Exit 0 changed or nothing to do, 1 failed.
 */
static int read_nul(int fd, char *buf, size_t size, size_t *len)
{
	size_t n = 0;

	while (n < size) {
		ssize_t k = read(fd, buf + n, 1);

		if (k <= 0)
			return -EIO;
		if (!buf[n]) {
			*len = n;
			return 0;
		}
		n++;
	}
	return -E2BIG;
}

static int cmd_passwd_hook(const struct opts *o)
{
	char old[SECRET_MAX], nw[SECRET_MAX];
	size_t olen = 0, nlen = 0;
	struct fde_user u;
	int up = 0, r;

	r = target_user(o, &u);
	if (r)
		return r;
	r = read_nul(0, old, sizeof(old), &olen);
	if (!r)
		r = read_nul(0, nw, sizeof(nw), &nlen);
	if (!r)
		r = fde_change_password(&o->conf, NULL, &u, old, olen, nw, nlen, &up);
	sep_wipe(old, sizeof(old));
	sep_wipe(nw, sizeof(nw));
	if (r == -ENOENT)
		return 0;
	if (r)
		fprintf(stderr, "aurora-sep-fde: the disk password of %s was not changed (%s)\n", u.name,
			errname(r));
	else
		printf("aurora-sep-fde: disk password of %s changed on %d volume(s)\n", u.name, up);
	return r;
}

static int cmd_sync(const struct opts *o)
{
	struct fde_user u;
	int up = 0, r;

	r = target_user(o, &u);
	if (!r)
		r = fde_sync_bag(&o->conf, &u, &up);
	if (r == -ENOENT)
		fprintf(stderr, "aurora-sep-fde: the enclave holds no key bag for %s this boot; "
			"unlock or change the password first\n", u.name);
	else if (r)
		fprintf(stderr, "aurora-sep-fde: sync failed (%s)\n", errname(r));
	else if (!o->quiet)
		printf("key bag of %s written to %d volume(s)\n", u.name, up);
	return r;
}

/* FileVault "reset password with the recovery key": a new bag and keyslot for
 * the user, opened with the recovery keyslot; the old ones are removed. */
static int reset_with_recovery(struct crypt_device *cd, const struct opts *o, const struct fde_user *u)
{
	uint8_t rsecret[SEP_FDE_SECRET_BYTES];
	char in[SECRET_MAX], rk[SEP_FDE_RK_LEN + 1], nw[SECRET_MAX];
	struct fde_token rt;
	size_t ilen = 0, nlen = 0;
	int rtok, r;

	rtok = find_token(cd, -1, SEP_FDE_ROLE_RECOVERY, &rt);
	if (rtok < 0) {
		fprintf(stderr, "aurora-sep-fde: no recovery key on this volume\n");
		return rtok;
	}
	r = get_secret(o->recovery_key_file, "Recovery key: ", 0, in, &ilen);
	if (!r)
		r = fde_recovery_key_normalize(in, ilen, rk);
	sep_wipe(in, sizeof(in));
	if (!r)
		r = fde_open_token(&rt, rk, strlen(rk), rsecret);
	sep_wipe(rk, sizeof(rk));
	fde_token_free(&rt);
	if (r) {
		fprintf(stderr, "aurora-sep-fde: the recovery key was not accepted (%s)\n", errname(r));
		return r;
	}
	r = get_secret(o->new_file, "New password: ", 1, nw, &nlen);
	if (!r)
		r = fde_reset_by_owner(cd, &o->conf, rsecret, u, nw, nlen);
	sep_wipe(nw, sizeof(nw));
	sep_wipe(rsecret, sizeof(rsecret));
	return r;
}

static int cmd_reset(struct crypt_device *cd, const struct opts *o)
{
	uint8_t secret[SEP_FDE_SECRET_BYTES];
	char nw[SECRET_MAX];
	struct fde_user u, auth;
	size_t nlen = 0;
	const char *by = "the recovery key";
	int r;

	r = target_user(o, &u);
	if (r)
		return r;
	if (o->recovery_key_file) {
		r = reset_with_recovery(cd, o, &u);
	} else {
		r = authorize(cd, o, secret, &auth);
		if (!r) {
			by = auth.name;
			r = get_secret(o->new_file, "New password: ", 1, nw, &nlen);
			if (!r)
				r = fde_reset_by_owner(cd, &o->conf, secret, &u, nw, nlen);
			sep_wipe(nw, sizeof(nw));
		}
		sep_wipe(secret, sizeof(secret));
	}
	if (r)
		fprintf(stderr, "aurora-sep-fde: password reset failed (%s)\n", errname(r));
	else if (!o->quiet)
		printf("password reset for %s (bag uid %u) by %s\n", u.name[0] ? u.name : "bag", u.bag_uid, by);
	return r;
}

static int cmd_test(struct crypt_device *cd, const struct opts *o)
{
	char in[SECRET_MAX];
	size_t n = 0;
	int r;

	r = get_secret(o->recovery_key_file ? o->recovery_key_file : o->password_file,
		       o->recovery_key_file ? "Recovery key: " : "Password: ", 0, in, &n);
	if (r)
		return r;
	r = crypt_activate_by_token_pin(cd, o->name, SEP_SEAL_TOKEN_TYPE, CRYPT_ANY_TOKEN, in, n, NULL, 0);
	sep_wipe(in, sizeof(in));
	if (r >= 0) {
		printf("opens keyslot %d through the Secure Enclave%s%s\n", r,
		       o->name ? ", active as /dev/mapper/" : "", o->name ? o->name : "");
		return 0;
	}
	printf("refused (%s)\n", r == -ENOANO ? "wrong password or recovery key" : strerror(-r));
	return r;
}

/* Removes the plain passphrase slot once a password and a recovery token
 * exist and both are assigned, as FileVault has no unlock that bypasses the
 * enclave. */
static int cmd_remove_passphrase(struct crypt_device *cd, const struct opts *o)
{
	struct fde_token t;
	char pass[SECRET_MAX];
	size_t n = 0;
	int ks, r;

	r = find_token(cd, -1, SEP_FDE_ROLE_USER, &t);
	if (r < 0)
		goto refuse;
	fde_token_free(&t);
	r = find_token(cd, -1, SEP_FDE_ROLE_RECOVERY, &t);
	if (r < 0)
		goto refuse;
	fde_token_free(&t);
	r = get_key(o->unlock_key_file, "Passphrase to remove: ", pass, &n);
	if (r)
		return r;
	ks = crypt_activate_by_passphrase(cd, NULL, CRYPT_ANY_SLOT, pass, n, 0);
	sep_wipe(pass, sizeof(pass));
	if (ks < 0)
		return ks;
	for (int tok = 0; tok < 32; tok++)
		if (crypt_token_is_assigned(cd, tok, ks) == 0) {
			fprintf(stderr, "aurora-sep-fde: keyslot %d belongs to a token; not removing it\n", ks);
			return -EBUSY;
		}
	if (find_token(cd, -1, SEP_FDE_ROLE_RECOVERY, &t) >= 0) {
		int offline = t.offline_keyslot;

		fde_token_free(&t);
		if (offline == ks) {
			fprintf(stderr, "aurora-sep-fde: keyslot %d is the offline recovery keyslot; not removing it\n", ks);
			return -EBUSY;
		}
	}
	r = crypt_keyslot_destroy(cd, ks);
	if (!r && !o->quiet)
		printf("removed passphrase keyslot %d\n", ks);
	return r;
refuse:
	fprintf(stderr, "aurora-sep-fde: enrol a password and a recovery key first\n");
	return -EPERM;
}

/*
 * The enclave's own gate, for hardware qualification: with the bag LOCKED the
 * enclave must refuse to open the sealed secret; after the password unlocks
 * it, the same request must succeed. The secret is compared to nothing and
 * never printed; it is wiped at once.
 */
#define GATE_WAIT_S 120

static int cmd_gate_check(struct crypt_device *cd, const struct opts *o)
{
	uint8_t out[SEP_FDE_SECRET_BYTES];
	char pw[SECRET_MAX];
	struct fde_state st;
	struct fde_token t;
	size_t plen = 0, n = 0;
	int locked_r, open_r, r;

	{
		struct fde_user u;

		if (target_user(o, &u) || fde_find_user_token(cd, &u, &t) < 0)
			return -ENOENT;
	}
	r = get_secret(o->password_file, "Password: ", 0, pw, &plen);
	if (r)
		goto out;
	if (fde_bag_state(t.uid, &st) < 0 && fde_bag_import(t.uid, t.bag, t.bag_len) < 0) {
		r = -EPERM;
		goto out;
	}
	/* Start from an unlocked bag, so the lock below is a real transition. */
	if (fde_bag_unlock(t.uid, pw, plen) < 0) {
		r = -EPERM;
		goto out;
	}
	fde_bag_lock(t.uid);
	/*
	 * The key store keeps a bag in its locking phase (class keys usable)
	 * for a grace period after the lock transition, whatever the reason,
	 * and reports it locked when that ends. Wait for that, bounded.
	 */
	{
		struct timespec t0, t1;
		int waited = -1;

		clock_gettime(CLOCK_MONOTONIC, &t0);
		for (int i = 0; i < GATE_WAIT_S * 2; i++) {
			if (fde_bag_state(t.uid, &st) == 0 && st.lock_phase == 1) {
				clock_gettime(CLOCK_MONOTONIC, &t1);
				waited = (int)(t1.tv_sec - t0.tv_sec);
				break;
			}
			usleep(500000);
		}
		if (waited < 0)
			printf("gate: the enclave did not report the bag locked within %d s\n", GATE_WAIT_S);
		else
			printf("gate: the enclave reported the bag locked %d s after the lock\n", waited);
	}
	locked_r = fde_unseal(t.uid, t.record, t.record_len, t.sealed, t.sealed_len,
			      out, sizeof(out), &n);
	sep_wipe(out, sizeof(out));
	printf("gate: unseal with the bag locked: %s\n",
	       locked_r ? "REFUSED by the enclave (correct)" : "OPENED (gate FAILED)");
	r = fde_bag_unlock(t.uid, pw, plen);
	open_r = r ? r : fde_unseal(t.uid, t.record, t.record_len, t.sealed, t.sealed_len,
				    out, sizeof(out), &n);
	sep_wipe(out, sizeof(out));
	fde_bag_lock(t.uid);
	printf("gate: unseal after the password unlocked the bag: %s\n",
	       open_r ? "refused (FAILED)" : "opened (correct)");
	r = (locked_r && !open_r) ? 0 : -EIO;
	printf("gate-check: %s\n", r ? "FAIL" : "PASS");
out:
	sep_wipe(pw, sizeof(pw));
	fde_token_free(&t);
	return r;
}

static int status_one(struct crypt_device *cd, const char *device)
{
	int found = 0;

	if (device)
		printf("%s: %d volume owner(s)\n", device, fde_count_owners(cd));
	for (int tok = 0; tok < FDE_TOKENS_MAX; tok++) {
		const char *type, *json;
		struct fde_token t;
		struct fde_state st;
		int ks;

		if (crypt_token_status(cd, tok, &type) == CRYPT_TOKEN_INACTIVE || !type ||
		    strcmp(type, SEP_SEAL_TOKEN_TYPE) || crypt_token_json_get(cd, tok, &json) < 0)
			continue;
		if (fde_token_parse(json, &t) < 0) {
			if (strstr(json, "\"aurora_sep_mode\""))
				printf("token %d: DAMAGED password token (ignored at unlock; remove it with "
				       "cryptsetup token remove --token-id %d)\n", tok, tok);
			continue;
		}
		found++;
		ks = token_keyslot(cd, tok);
		printf("token %d: keyslot %d, %s", tok, ks, t.role);
		if (!strcmp(t.role, SEP_FDE_ROLE_USER)) {
			int lbl = t.label[0] && strcmp(t.label, t.user);

			printf(" %s%s%s, %s", t.user, t.user[0] && lbl ? " " : "", lbl ? t.label : "",
			       t.owner != 0 ? "owner" : "unlock only");
		} else if (t.label[0]) {
			printf(" %s", t.label);
		}
		printf(", bag uid %u, bag %zu B, record %zu B, sealed %zu B", t.uid, t.bag_len,
		       t.record_len, t.sealed_len);
		if (ks < 0)
			printf(", NO KEYSLOT (damaged)");
		if (t.offline_keyslot >= 0)
			printf(", offline recovery keyslot %d", t.offline_keyslot);
		if (fde_bag_state(t.uid, &st) == 0)
			printf(", enclave: bag state %u, failed attempts %u\n", st.bag_state, st.failed_attempts);
		else
			printf(", enclave: bag not loaded\n");
		fde_token_free(&t);
	}
	if (!found)
		printf("no aurora-sep password tokens\n");
	return 0;
}

static int cmd_status(struct crypt_device *cd, const struct opts *o)
{
	char **v;

	if (cd)
		return status_one(cd, NULL);
	v = fde_volumes_list(&o->conf);
	for (char **p = v; v && *p; p++) {
		struct crypt_device *c2;

		if (fde_load(&c2, *p)) {
			printf("%s: not available\n", *p);
			continue;
		}
		status_one(c2, *p);
		crypt_free(c2);
	}
	if (!v || !*v)
		printf("no registered volumes (%s)\n", o->conf.volumes_file);
	fde_strv_free(v);
	return 0;
}

/* Recovery tokens get their own bag uid per volume, so two volumes can have
 * recovery keys made in the same boot. */
static long recovery_bag_uid(struct crypt_device *cd, const struct fde_conf *c)
{
	const char *uuid = crypt_get_uuid(cd);
	uint32_t h = 2166136261u;

	for (const char *p = uuid ? uuid : ""; *p; p++)
		h = (h ^ (uint8_t)*p) * 16777619u;
	return (long)c->bag_uid_base - 1 - (long)(h % 9000);
}

int main(int argc, char **argv)
{
	static const struct option lo[] = {
		{ "uid", required_argument, NULL, 'u' },
		{ "user", required_argument, NULL, 'U' },
		{ "auth-user", required_argument, NULL, 'A' },
		{ "auth-password-file", required_argument, NULL, 'a' },
		{ "owner", no_argument, NULL, 'O' },
		{ "no-owner", no_argument, NULL, 'X' },
		{ "label", required_argument, NULL, 'l' },
		{ "unlock-key-file", required_argument, NULL, 'k' },
		{ "password-file", required_argument, NULL, 'p' },
		{ "old-file", required_argument, NULL, 'o' },
		{ "new-file", required_argument, NULL, 'n' },
		{ "recovery-key-file", required_argument, NULL, 'r' },
		{ "name", required_argument, NULL, 'N' },
		{ "quiet", no_argument, NULL, 'q' },
		{ "sep-only", no_argument, NULL, 'S' },
		{ "offline", no_argument, NULL, 'F' },
		{ NULL, 0, NULL, 0 },
	};
	struct opts o = { .uid = -1, .owner = -1 };
	struct crypt_device *cd = NULL;
	int c, r, need_dev;

	if (argc < 2)
		die_usage();
	o.cmd = argv[1];
	optind = 2;
	while ((c = getopt_long(argc, argv, "q", lo, NULL)) != -1) {
		switch (c) {
		case 'u': o.uid = strtol(optarg, NULL, 10); break;
		case 'U': o.user = optarg; break;
		case 'A': o.auth_user = optarg; break;
		case 'a': o.auth_password_file = optarg; break;
		case 'O': o.owner = 1; break;
		case 'X': o.owner = 0; break;
		case 'l': o.label = optarg; break;
		case 'k': o.unlock_key_file = optarg; break;
		case 'p': o.password_file = optarg; break;
		case 'o': o.old_file = optarg; break;
		case 'n': o.new_file = optarg; break;
		case 'r': o.recovery_key_file = optarg; break;
		case 'N': o.name = optarg; break;
		case 'q': o.quiet = 1; break;
		case 'S': o.sep_only = 1; break;
		case 'F': o.offline = 1; break;
		default: die_usage();
		}
	}
	r = fde_conf_load(&o.conf);
	if (r)
		fprintf(stderr, "aurora-sep-fde: cannot read the configuration (%s)\n", strerror(-r));
	/* recovery = sep-only in fde.conf, unless --offline asks otherwise */
	if (o.conf.recovery_sep_only && !o.offline)
		o.sep_only = 1;
	need_dev = strcmp(o.cmd, "change-password") && strcmp(o.cmd, "passwd-hook") &&
		   strcmp(o.cmd, "sync") && strcmp(o.cmd, "status");
	if (optind == argc - 1)
		o.device = argv[optind];
	else if (optind != argc || need_dev)
		die_usage();
	if (o.device && strcmp(o.cmd, "change-password") && strcmp(o.cmd, "passwd-hook") &&
	    strcmp(o.cmd, "sync")) {
		r = load(&cd, o.device);
		if (r < 0) {
			fprintf(stderr, "aurora-sep-fde: %s is not a LUKS2 volume (%s)\n", o.device, strerror(-r));
			return 1;
		}
	}
	if (o.user && strcmp(o.cmd, "recovery")) {
		struct fde_user u;

		if (fde_user_lookup(&o.conf, o.user, &u)) {
			fprintf(stderr, "aurora-sep-fde: no user '%s'\n", o.user);
			if (cd)
				crypt_free(cd);
			return 1;
		}
		o.uid = u.bag_uid;
	}
	if (!strcmp(o.cmd, "enroll"))
		r = cmd_enroll_user(cd, &o);
	else if (!strcmp(o.cmd, "recovery")) {
		if (o.uid < 0)
			o.uid = recovery_bag_uid(cd, &o.conf);
		r = cmd_enroll(cd, &o, 1);
		if (!r)
			fde_volumes_add(&o.conf, o.device);
	} else if (!strcmp(o.cmd, "add-user"))
		r = cmd_add_user(cd, &o);
	else if (!strcmp(o.cmd, "remove-user"))
		r = cmd_remove_user(cd, &o);
	else if (!strcmp(o.cmd, "set-owner"))
		r = cmd_set_owner(cd, &o);
	else if (!strcmp(o.cmd, "change-password"))
		r = cmd_change(&o);
	else if (!strcmp(o.cmd, "passwd-hook"))
		r = cmd_passwd_hook(&o);
	else if (!strcmp(o.cmd, "sync"))
		r = cmd_sync(&o);
	else if (!strcmp(o.cmd, "reset-password"))
		r = cmd_reset(cd, &o);
	else if (!strcmp(o.cmd, "test"))
		r = cmd_test(cd, &o);
	else if (!strcmp(o.cmd, "remove-passphrase"))
		r = cmd_remove_passphrase(cd, &o);
	else if (!strcmp(o.cmd, "gate-check"))
		r = cmd_gate_check(cd, &o);
	else if (!strcmp(o.cmd, "status"))
		r = cmd_status(cd, &o);
	else
		die_usage();
	if (cd)
		crypt_free(cd);
	return r ? 1 : 0;
}
