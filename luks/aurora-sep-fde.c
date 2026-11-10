// SPDX-License-Identifier: MIT
/*
 * aurora-sep-fde: FileVault-style LUKS2 unlock. The keyslot secret is sealed
 * by the Secure Enclave to a key under a per-user key bag that only the user's
 * password unlocks; a recovery key is a second bag with its own keyslot.
 *
 *   aurora-sep-fde enroll   --uid N [--label NAME] --unlock-key-file F [--password-file P] DEVICE
 *   aurora-sep-fde recovery --uid N --unlock-key-file F [--recovery-key-file OUT] DEVICE
 *   aurora-sep-fde change-password --uid N [--old-file O --new-file P] DEVICE
 *   aurora-sep-fde reset-password  --uid N [--recovery-key-file R --new-file P] DEVICE
 *   aurora-sep-fde test     [--password-file P | --recovery-key-file R] [--name MAPPING] DEVICE
 *   aurora-sep-fde remove-passphrase --unlock-key-file F DEVICE
 *   aurora-sep-fde gate-check --uid N [--password-file P] DEVICE
 *   aurora-sep-fde status   DEVICE
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

#include "sep-fde.h"
#include "sep-seal.h"

#define SECRET_MAX 1024

struct opts {
	const char *cmd, *device, *unlock_key_file, *password_file, *old_file, *new_file,
		*recovery_key_file, *label, *name;
	long uid;
	int quiet;
};

static void die_usage(void)
{
	fputs("usage: aurora-sep-fde enroll|recovery|change-password|reset-password|test|"
	      "remove-passphrase|status [options] DEVICE\n", stderr);
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

static int load(struct crypt_device **cd, const char *device)
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

static int token_keyslot(struct crypt_device *cd, int token)
{
	for (int ks = 0; ks < crypt_keyslot_max(CRYPT_LUKS2); ks++)
		if (crypt_token_is_assigned(cd, token, ks) == 0)
			return ks;
	return -ENOENT;
}

/* The password-mode token of role for uid (uid < 0: any), or -ENOENT. */
static int find_token(struct crypt_device *cd, long uid, const char *role, struct fde_token *t)
{
	for (int tok = 0; tok < 32; tok++) {
		const char *type, *json;

		if (crypt_token_status(cd, tok, &type) == CRYPT_TOKEN_INACTIVE || !type ||
		    strcmp(type, SEP_SEAL_TOKEN_TYPE))
			continue;
		if (crypt_token_json_get(cd, tok, &json) < 0 || fde_token_parse(json, t) < 0)
			continue;
		if ((uid < 0 || t->uid == (uint32_t)uid) && !strcmp(t->role, role))
			return tok;
		fde_token_free(t);
	}
	return -ENOENT;
}

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

/* Replaces a token's JSON and keeps it on its keyslot. */
static int replace_token(struct crypt_device *cd, int tok, const struct fde_token *t)
{
	int ks = token_keyslot(cd, tok);
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

static int cmd_change(struct crypt_device *cd, const struct opts *o)
{
	char old[SECRET_MAX], nw[SECRET_MAX], rk[SEP_FDE_RK_LEN + 1];
	struct fde_state st;
	struct fde_token t;
	uint8_t *bag = NULL;
	size_t olen = 0, nlen = 0, blen = 0;
	int tok, r;

	tok = find_token(cd, o->uid, SEP_FDE_ROLE_USER, &t);
	if (tok < 0)
		return tok;
	r = get_secret(o->old_file, "Current password: ", 0, old, &olen);
	if (!r)
		r = get_secret(o->new_file, "New password: ", 1, nw, &nlen);
	if (!r && fde_recovery_key_normalize(nw, nlen, rk) == 0)
		r = -EINVAL;
	if (!r && fde_bag_state(t.uid, &st) < 0)
		r = fde_bag_import(t.uid, t.bag, t.bag_len) ? -EPERM : 0;
	/* The enclave checks the old password and rewraps the bag; the sealed
	 * secret and the keyslot do not change, so no data is at risk. */
	if (!r)
		r = fde_bag_change(t.uid, old, olen, nw, nlen);
	if (!r)
		r = fde_bag_export(t.uid, &bag, &blen);
	fde_bag_lock(t.uid);
	sep_wipe(old, sizeof(old));
	sep_wipe(nw, sizeof(nw));
	if (!r) {
		free(t.bag);
		t.bag = bag;
		t.bag_len = blen;
		r = replace_token(cd, tok, &t);
	}
	fde_token_free(&t);
	if (r)
		fprintf(stderr, "aurora-sep-fde: password change failed (%s)\n", strerror(-r));
	else if (!o->quiet)
		printf("password changed for bag uid %ld\n", o->uid);
	return r;
}

/* FileVault "reset password with the recovery key": a new bag and keyslot for
 * the user, opened with the recovery keyslot; the old ones are removed. */
static int cmd_reset(struct crypt_device *cd, const struct opts *o)
{
	uint8_t rsecret[SEP_FDE_SECRET_BYTES], usecret[SEP_FDE_SECRET_BYTES];
	char in[SECRET_MAX], rk[SEP_FDE_RK_LEN + 1], nw[SECRET_MAX], rpass[SEP_FDE_PASS_LEN + 1];
	struct fde_token rt, ut, nt;
	size_t ilen = 0, nlen = 0;
	int rtok, utok, oldks = -1, ks, r;

	rtok = find_token(cd, -1, SEP_FDE_ROLE_RECOVERY, &rt);
	if (rtok < 0) {
		fprintf(stderr, "aurora-sep-fde: no recovery key on this volume\n");
		return rtok;
	}
	utok = find_token(cd, o->uid, SEP_FDE_ROLE_USER, &ut);
	if (utok >= 0) {
		oldks = token_keyslot(cd, utok);
		fde_token_free(&ut);
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
		fprintf(stderr, "aurora-sep-fde: the recovery key was not accepted (%s)\n", strerror(-r));
		return r;
	}
	r = get_secret(o->new_file, "New password: ", 1, nw, &nlen);
	if (!r && getrandom(usecret, sizeof(usecret), 0) != (ssize_t)sizeof(usecret))
		r = -EIO;
	if (!r)
		r = fde_enroll((uint32_t)o->uid, SEP_FDE_ROLE_USER, nw, nlen, usecret, &nt);
	sep_wipe(nw, sizeof(nw));
	if (!r) {
		hex_pass(rsecret, rpass);
		ks = add_slot_and_token(cd, rpass, SEP_FDE_PASS_LEN, usecret, &nt);
		fde_token_free(&nt);
		r = ks < 0 ? ks : verify_slot(cd, ks, usecret);
	}
	if (!r && utok >= 0) {
		crypt_token_json_set(cd, utok, NULL);
		if (oldks >= 0)
			crypt_keyslot_destroy(cd, oldks);
	}
	sep_wipe(rsecret, sizeof(rsecret));
	sep_wipe(usecret, sizeof(usecret));
	sep_wipe(rpass, sizeof(rpass));
	if (r)
		fprintf(stderr, "aurora-sep-fde: password reset failed (%s)\n", strerror(-r));
	else if (!o->quiet)
		printf("password reset for bag uid %ld with the recovery key\n", o->uid);
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

	if (find_token(cd, o->uid, SEP_FDE_ROLE_USER, &t) < 0)
		return -ENOENT;
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

static int cmd_status(struct crypt_device *cd)
{
	int found = 0;

	for (int tok = 0; tok < 32; tok++) {
		const char *type, *json;
		struct fde_token t;
		struct fde_state st;

		if (crypt_token_status(cd, tok, &type) == CRYPT_TOKEN_INACTIVE || !type ||
		    strcmp(type, SEP_SEAL_TOKEN_TYPE) || crypt_token_json_get(cd, tok, &json) < 0 ||
		    fde_token_parse(json, &t) < 0)
			continue;
		found++;
		printf("token %d: keyslot %d, %s, bag uid %u%s%s, bag %zu B, record %zu B, sealed %zu B",
		       tok, token_keyslot(cd, tok), t.role, t.uid, t.label[0] ? " " : "", t.label,
		       t.bag_len, t.record_len, t.sealed_len);
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

int main(int argc, char **argv)
{
	static const struct option lo[] = {
		{ "uid", required_argument, NULL, 'u' },
		{ "label", required_argument, NULL, 'l' },
		{ "unlock-key-file", required_argument, NULL, 'k' },
		{ "password-file", required_argument, NULL, 'p' },
		{ "old-file", required_argument, NULL, 'o' },
		{ "new-file", required_argument, NULL, 'n' },
		{ "recovery-key-file", required_argument, NULL, 'r' },
		{ "name", required_argument, NULL, 'N' },
		{ "quiet", no_argument, NULL, 'q' },
		{ NULL, 0, NULL, 0 },
	};
	struct opts o = { .uid = -1 };
	struct crypt_device *cd;
	int c, r;

	if (argc < 2)
		die_usage();
	o.cmd = argv[1];
	optind = 2;
	while ((c = getopt_long(argc, argv, "q", lo, NULL)) != -1) {
		switch (c) {
		case 'u': o.uid = strtol(optarg, NULL, 10); break;
		case 'l': o.label = optarg; break;
		case 'k': o.unlock_key_file = optarg; break;
		case 'p': o.password_file = optarg; break;
		case 'o': o.old_file = optarg; break;
		case 'n': o.new_file = optarg; break;
		case 'r': o.recovery_key_file = optarg; break;
		case 'N': o.name = optarg; break;
		case 'q': o.quiet = 1; break;
		default: die_usage();
		}
	}
	if (optind != argc - 1)
		die_usage();
	o.device = argv[optind];
	r = load(&cd, o.device);
	if (r < 0) {
		fprintf(stderr, "aurora-sep-fde: %s is not a LUKS2 volume (%s)\n", o.device, strerror(-r));
		return 1;
	}
	if (!strcmp(o.cmd, "enroll"))
		r = cmd_enroll(cd, &o, 0);
	else if (!strcmp(o.cmd, "recovery"))
		r = cmd_enroll(cd, &o, 1);
	else if (!strcmp(o.cmd, "change-password"))
		r = cmd_change(cd, &o);
	else if (!strcmp(o.cmd, "reset-password"))
		r = cmd_reset(cd, &o);
	else if (!strcmp(o.cmd, "test"))
		r = cmd_test(cd, &o);
	else if (!strcmp(o.cmd, "remove-passphrase"))
		r = cmd_remove_passphrase(cd, &o);
	else if (!strcmp(o.cmd, "gate-check"))
		r = cmd_gate_check(cd, &o);
	else if (!strcmp(o.cmd, "status"))
		r = cmd_status(cd);
	else
		die_usage();
	crypt_free(cd);
	return r ? 1 : 0;
}
