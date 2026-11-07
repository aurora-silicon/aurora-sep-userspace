// SPDX-License-Identifier: MIT
/*
 * aurora-sep-cryptenroll: enroll the Apple Secure Enclave as a LUKS2 unlock
 * method, like systemd-cryptenroll --tpm2-device=auto does for a TPM.
 *
 * A new keyslot gets a random 64-byte secret. The secret is stored in an
 * "aurora-sep" token, wrapped by an AES key sealed by this Mac's SEP. Existing
 * passphrase and recovery keyslots are never touched, and the last keyslot
 * that is not SEP-bound can never be removed.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <json-c/json.h>
#include <libcryptsetup.h>

#include "sep-seal.h"

#define MAX_PASS 8192

enum mode { M_ENROLL, M_REMOVE, M_TEST, M_STATUS };

static const char *arg_unlock_key_file;
static int arg_wipe;
static int arg_quiet;

static void usage(FILE *f)
{
	fprintf(f,
		"Usage: aurora-sep-cryptenroll [OPTIONS] DEVICE\n\n"
		"Enroll this Mac's Secure Enclave as an unlock method of a LUKS2 volume.\n\n"
		"  (default)                 enroll: add a SEP-sealed keyslot and token\n"
		"      --wipe-slot=sep       with enroll: remove older SEP enrolments once\n"
		"                            the new one is proven\n"
		"      --remove              remove every SEP enrolment (keyslot and token)\n"
		"      --test                unseal each SEP token and check its keyslot\n"
		"      --status              list SEP tokens and keyslots\n"
		"      --unlock-key-file=F   existing passphrase or key file that authorizes\n"
		"                            the enrolment (else $PASSWORD, else a prompt)\n"
		"  -q, --quiet               only print errors\n"
		"  -h, --help                show this help\n");
}

static void info(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void info(const char *fmt, ...)
{
	va_list ap;

	if (arg_quiet)
		return;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

static int read_file(const char *path, char **out, size_t *len)
{
	char *buf;
	ssize_t n;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	buf = malloc(MAX_PASS);
	if (!buf) {
		close(fd);
		return -ENOMEM;
	}
	n = read(fd, buf, MAX_PASS);
	close(fd);
	if (n <= 0 || n == MAX_PASS) {
		sep_wipe(buf, MAX_PASS);
		free(buf);
		return n < 0 ? -errno : -EINVAL;
	}
	*out = buf;
	*len = (size_t)n;
	return 0;
}

static int prompt_pass(const char *dev, char **out, size_t *len)
{
	struct termios old, quiet;
	char *buf = NULL;
	size_t cap = 0;
	ssize_t n;
	int tty;
	FILE *f;

	f = fopen("/dev/tty", "r+e");
	if (!f)
		return -ENOTTY;
	tty = fileno(f);
	fprintf(f, "Current passphrase for %s: ", dev);
	fflush(f);
	if (tcgetattr(tty, &old) == 0) {
		quiet = old;
		quiet.c_lflag &= ~(tcflag_t)ECHO;
		tcsetattr(tty, TCSAFLUSH, &quiet);
	}
	n = getline(&buf, &cap, f);
	tcsetattr(tty, TCSAFLUSH, &old);
	fputc('\n', f);
	fclose(f);
	if (n <= 0) {
		free(buf);
		return -EINVAL;
	}
	if (buf[n - 1] == '\n')
		buf[--n] = '\0';
	*out = buf;
	*len = (size_t)n;
	return 0;
}

static int get_unlock_pass(const char *dev, char **out, size_t *len)
{
	const char *env = getenv("PASSWORD");

	if (arg_unlock_key_file)
		return read_file(arg_unlock_key_file, out, len);
	if (env) {
		*out = strdup(env);
		*len = strlen(env);
		return *out ? 0 : -ENOMEM;
	}
	return prompt_pass(dev, out, len);
}

/* Keyslots assigned to a token, from its JSON. Returns count, fills slots. */
static int token_slots(struct crypt_device *cd, int token, int *slots, int max)
{
	struct json_object *o, *arr;
	const char *json;
	int n = 0;

	if (crypt_token_json_get(cd, token, &json) < 0)
		return 0;
	o = json_tokener_parse(json);
	if (!o)
		return 0;
	if (json_object_object_get_ex(o, "keyslots", &arr) &&
	    json_object_is_type(arr, json_type_array)) {
		for (size_t i = 0; i < json_object_array_length(arr) && n < max; i++) {
			const char *s = json_object_get_string(json_object_array_get_idx(arr, i));

			if (s)
				slots[n++] = atoi(s);
		}
	}
	json_object_put(o);
	return n;
}

static int is_sep_token(struct crypt_device *cd, int token)
{
	const char *type;

	return crypt_token_status(cd, token, &type) != CRYPT_TOKEN_INACTIVE &&
	       type && !strcmp(type, SEP_SEAL_TOKEN_TYPE);
}

static int slot_is_sep(struct crypt_device *cd, int slot)
{
	int slots[64];

	for (int t = 0; t < crypt_token_max(CRYPT_LUKS2); t++) {
		if (!is_sep_token(cd, t))
			continue;
		for (int i = 0, n = token_slots(cd, t, slots, 64); i < n; i++)
			if (slots[i] == slot)
				return 1;
	}
	return 0;
}

/* Active keyslots that do not belong to an aurora-sep token. */
static int count_other_slots(struct crypt_device *cd)
{
	int n = 0;

	for (int s = 0; s < crypt_keyslot_max(CRYPT_LUKS2); s++) {
		crypt_keyslot_info ki = crypt_keyslot_status(cd, s);

		if ((ki == CRYPT_SLOT_ACTIVE || ki == CRYPT_SLOT_ACTIVE_LAST) &&
		    !slot_is_sep(cd, s))
			n++;
	}
	return n;
}

static int remove_sep(struct crypt_device *cd, int except_token)
{
	int slots[64], removed = 0, r;

	if (count_other_slots(cd) < 1) {
		fprintf(stderr, "Refusing: no passphrase or recovery keyslot would remain.\n");
		return -EPERM;
	}
	for (int t = 0; t < crypt_token_max(CRYPT_LUKS2); t++) {
		int n;

		if (t == except_token || !is_sep_token(cd, t))
			continue;
		n = token_slots(cd, t, slots, 64);
		for (int i = 0; i < n; i++) {
			r = crypt_keyslot_destroy(cd, slots[i]);
			if (r < 0) {
				fprintf(stderr, "Removing keyslot %d failed: %s\n", slots[i], strerror(-r));
				return r;
			}
			info("Removed SEP keyslot %d.\n", slots[i]);
		}
		r = crypt_token_json_set(cd, t, NULL);
		if (r < 0) {
			fprintf(stderr, "Removing token %d failed: %s\n", t, strerror(-r));
			return r;
		}
		info("Removed SEP token %d.\n", t);
		removed++;
	}
	if (!removed)
		info("No SEP enrolment found.\n");
	return 0;
}

static int test_token(struct crypt_device *cd, int token)
{
	uint8_t secret[SEP_SEAL_SECRET_BYTES];
	char aad[128], pass[SEP_SEAL_PASS_LEN + 1];
	struct sep_sealed s;
	const char *json;
	size_t len = 0;
	int slots[64], n, r;

	r = crypt_token_json_get(cd, token, &json);
	if (r < 0)
		return r;
	r = sep_seal_aad(crypt_get_uuid(cd), aad, sizeof(aad));
	if (r < 0)
		return r;
	r = sep_token_parse(json, &s);
	if (r < 0)
		return r;
	r = sep_unseal_secret(aad, &s, SEP_SEAL_WAIT_DEFAULT, secret, sizeof(secret), &len);
	sep_sealed_free(&s);
	if (r < 0)
		return r;
	sep_hex_encode(secret, len, pass, sizeof(pass));
	sep_wipe(secret, sizeof(secret));
	n = token_slots(cd, token, slots, 64);
	r = -ENOENT;
	for (int i = 0; i < n; i++) {
		r = crypt_activate_by_passphrase(cd, NULL, slots[i], pass, strlen(pass), 0);
		if (r >= 0)
			break;
	}
	sep_wipe(pass, sizeof(pass));
	return r < 0 ? r : 0;
}

static int enroll(struct crypt_device *cd, const char *dev)
{
	struct crypt_pbkdf_type pbkdf = {
		.type = CRYPT_KDF_PBKDF2,
		.hash = "sha512",
		.iterations = 1000,
		.flags = CRYPT_PBKDF_NO_BENCHMARK,
	};
	uint8_t secret[SEP_SEAL_SECRET_BYTES];
	char pass[SEP_SEAL_PASS_LEN + 1], aad[128];
	struct sep_sealed s = { 0 };
	char *old = NULL, *json = NULL;
	size_t old_len = 0;
	int slot = -1, token = -1, r;

	r = sep_seal_aad(crypt_get_uuid(cd), aad, sizeof(aad));
	if (r < 0)
		return r;
	r = get_unlock_pass(dev, &old, &old_len);
	if (r < 0) {
		fprintf(stderr, "No unlock passphrase: %s\n", strerror(-r));
		return r;
	}
	r = crypt_activate_by_passphrase(cd, NULL, CRYPT_ANY_SLOT, old, old_len, 0);
	if (r < 0) {
		fprintf(stderr, "The passphrase does not unlock %s.\n", dev);
		goto out;
	}

	if (getrandom(secret, sizeof(secret), 0) != sizeof(secret)) {
		r = -EIO;
		goto out;
	}
	r = sep_seal_secret(aad, secret, sizeof(secret), &s);
	if (r < 0) {
		fprintf(stderr, "The Secure Enclave could not seal a key: %s\n", strerror(-r));
		if (r == -ENODEV)
			fprintf(stderr, "Is the apple_sep driver loaded with its trusted-key source?\n");
		goto out;
	}
	sep_hex_encode(secret, sizeof(secret), pass, sizeof(pass));

	/* The secret is high entropy: a slow KDF adds nothing (as systemd does for TPM2). */
	r = crypt_set_pbkdf_type(cd, &pbkdf);
	if (r < 0)
		goto out;
	r = crypt_keyslot_add_by_passphrase(cd, CRYPT_ANY_SLOT, old, old_len, pass,
					    SEP_SEAL_PASS_LEN);
	if (r < 0) {
		fprintf(stderr, "Adding a keyslot failed: %s\n", strerror(-r));
		goto out;
	}
	slot = r;

	json = sep_token_build(&s);
	if (!json) {
		r = -ENOMEM;
		goto rollback;
	}
	r = crypt_token_json_set(cd, CRYPT_ANY_TOKEN, json);
	if (r < 0) {
		fprintf(stderr, "Writing the token failed: %s\n", strerror(-r));
		goto rollback;
	}
	token = r;
	r = crypt_token_assign_keyslot(cd, token, slot);
	if (r < 0)
		goto rollback;

	/* Prove the stored token opens its keyslot through the SEP. */
	r = test_token(cd, token);
	if (r < 0) {
		fprintf(stderr, "The new enrolment did not open the volume: %s\n", strerror(-r));
		goto rollback;
	}
	info("Enrolled the Secure Enclave in keyslot %d (token %d).\n", slot, token);
	if (arg_wipe) {
		r = remove_sep(cd, token);
		if (r < 0)
			goto out;
	}
	r = 0;
	goto out;

rollback:
	if (token >= 0)
		crypt_token_json_set(cd, token, NULL);
	if (slot >= 0)
		crypt_keyslot_destroy(cd, slot);
out:
	sep_wipe(secret, sizeof(secret));
	sep_wipe(pass, sizeof(pass));
	if (old) {
		sep_wipe(old, old_len);
		free(old);
	}
	free(json);
	sep_sealed_free(&s);
	return r;
}

static int status(struct crypt_device *cd)
{
	int slots[64], found = 0;

	for (int t = 0; t < crypt_token_max(CRYPT_LUKS2); t++) {
		if (!is_sep_token(cd, t))
			continue;
		found++;
		printf("token %d: aurora-sep, keyslots", t);
		for (int i = 0, n = token_slots(cd, t, slots, 64); i < n; i++)
			printf(" %d", slots[i]);
		printf("\n");
	}
	printf("%d SEP enrolment(s), %d other keyslot(s)\n", found, count_other_slots(cd));
	return 0;
}

int main(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "wipe-slot", required_argument, NULL, 'w' },
		{ "remove", no_argument, NULL, 'r' },
		{ "test", no_argument, NULL, 't' },
		{ "status", no_argument, NULL, 's' },
		{ "unlock-key-file", required_argument, NULL, 'k' },
		{ "quiet", no_argument, NULL, 'q' },
		{ "help", no_argument, NULL, 'h' },
		{}
	};
	struct crypt_device *cd = NULL;
	enum mode mode = M_ENROLL;
	const char *dev;
	int c, r, fails = 0, tested = 0;

	while ((c = getopt_long(argc, argv, "qh", opts, NULL)) != -1) {
		switch (c) {
		case 'w':
			if (strcmp(optarg, "sep")) {
				fprintf(stderr, "--wipe-slot only takes 'sep'.\n");
				return 2;
			}
			arg_wipe = 1;
			break;
		case 'r': mode = M_REMOVE; break;
		case 't': mode = M_TEST; break;
		case 's': mode = M_STATUS; break;
		case 'k': arg_unlock_key_file = optarg; break;
		case 'q': arg_quiet = 1; break;
		case 'h': usage(stdout); return 0;
		default: usage(stderr); return 2;
		}
	}
	if (optind != argc - 1) {
		usage(stderr);
		return 2;
	}
	dev = argv[optind];

	r = crypt_init(&cd, dev);
	if (r < 0) {
		fprintf(stderr, "Cannot open %s: %s\n", dev, strerror(-r));
		return 1;
	}
	r = crypt_load(cd, CRYPT_LUKS2, NULL);
	if (r < 0) {
		fprintf(stderr, "%s is not a LUKS2 volume.\n", dev);
		crypt_free(cd);
		return 1;
	}

	switch (mode) {
	case M_ENROLL:
		r = enroll(cd, dev);
		break;
	case M_REMOVE:
		r = remove_sep(cd, -1);
		break;
	case M_STATUS:
		r = status(cd);
		break;
	case M_TEST:
		for (int t = 0; t < crypt_token_max(CRYPT_LUKS2); t++) {
			if (!is_sep_token(cd, t))
				continue;
			tested++;
			r = test_token(cd, t);
			if (r < 0)
				fails++;
			printf("token %d: %s\n", t, r < 0 ? strerror(-r) : "opens its keyslot");
		}
		r = (!tested || fails) ? -ENOENT : 0;
		break;
	}
	crypt_free(cd);
	return r < 0 ? 1 : 0;
}
