// SPDX-License-Identifier: MIT
/*
 * aurora-fido-seal: seals aurora-fidod's master secret to this Mac's Secure Enclave.
 *
 *   aurora-fido-seal new       seal 64 fresh random bytes, print the record
 *   aurora-fido-seal unseal    read a record on stdin, print the secret (hex)
 *                              if this Secure Enclave opens it
 *   aurora-fido-seal check     exit 0 when the SEP trusted-key source works
 *
 * The secret is AES-256-CCM encrypted with a kernel "trusted" key that only
 * this Mac's SEP can unseal, as aurora-sep-cryptenroll does for LUKS2. The
 * additional data is "aurora-fido:1:<id>", so a FIDO record, an SSH record
 * and a LUKS2 token can never stand in for each other. Root only.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/random.h>

#include "sep-seal.h"

#define RECORD_MAGIC	"aurora-fido 1"
#define RECORD_MAX	(16 * 1024)
#define ID_BYTES	16
#define AAD_MAX		64
#define WAIT_S		60

static int record_aad(const char *id_hex, char *aad, size_t n)
{
	int r = snprintf(aad, n, "aurora-fido:1:%s", id_hex);

	return (r < 0 || (size_t)r >= n) ? -ENOBUFS : 0;
}

static const char *explain(int r)
{
	switch (r) {
	case -ENODEV:
	case -ENOENT:
		return "no SEP trusted-key source (is apple_sep loaded with its key store?)";
	case -EBADMSG:
	case -EINVAL:
	case -EKEYREJECTED:
	case -EIO:
		return "refused: sealed on another Mac or Linux install, or the record was changed";
	case -EPERM:
	case -EACCES:
		return "needs root (AF_ALG ccm(aes) is limited to CAP_SYS_ADMIN)";
	default:
		return strerror(-r);
	}
}

static int cmd_new(void)
{
	uint8_t secret[SEP_SEAL_SECRET_BYTES], id[ID_BYTES];
	char id_hex[2 * ID_BYTES + 1], aad[AAD_MAX], iv_hex[2 * SEP_SEAL_IV_BYTES + 1];
	char *ct_hex = NULL;
	struct sep_sealed s;
	int r;

	if (getrandom(secret, sizeof(secret), 0) != sizeof(secret) ||
	    getrandom(id, sizeof(id), 0) != sizeof(id))
		return -EIO;
	sep_hex_encode(id, sizeof(id), id_hex, sizeof(id_hex));
	r = record_aad(id_hex, aad, sizeof(aad));
	if (r < 0)
		goto out;
	/* Seals, then proves the stored form opens with a freshly loaded key. */
	r = sep_seal_secret(aad, secret, sizeof(secret), &s);
	if (r < 0)
		goto out;
	ct_hex = malloc(2 * s.ct_len + 1);
	if (!ct_hex) {
		r = -ENOMEM;
		goto free_sealed;
	}
	sep_hex_encode(s.iv, sizeof(s.iv), iv_hex, sizeof(iv_hex));
	sep_hex_encode(s.ct, s.ct_len, ct_hex, 2 * s.ct_len + 1);
	printf("%s\nid %s\nblob %s\niv %s\nct %s\n", RECORD_MAGIC, id_hex,
	       s.blob_hex, iv_hex, ct_hex);
	r = fflush(stdout) ? -errno : 0;
	free(ct_hex);
free_sealed:
	sep_sealed_free(&s);
out:
	sep_wipe(secret, sizeof(secret));
	return r;
}

/* Parse "key value" lines; values point into buf. */
static int parse_record(char *buf, char **id, struct sep_sealed *s)
{
	const size_t ct_hex = 2 * (SEP_SEAL_SECRET_BYTES + SEP_SEAL_TAG_BYTES);
	char *line, *save = NULL, *blob = NULL, *iv = NULL, *ct = NULL;
	uint8_t idb[ID_BYTES];
	int first = 1;

	*id = NULL;
	memset(s, 0, sizeof(*s));
	for (line = strtok_r(buf, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		char *sp;

		if (first) {
			if (strcmp(line, RECORD_MAGIC))
				return -EPROTONOSUPPORT;
			first = 0;
			continue;
		}
		sp = strchr(line, ' ');
		if (!sp)
			return -EINVAL;
		*sp++ = '\0';
		if (!strcmp(line, "id"))
			*id = sp;
		else if (!strcmp(line, "blob"))
			blob = sp;
		else if (!strcmp(line, "iv"))
			iv = sp;
		else if (!strcmp(line, "ct"))
			ct = sp;
	}
	if (!*id || strlen(*id) != 2 * ID_BYTES || !blob ||
	    strlen(blob) > SEP_SEAL_BLOB_HEX_MAX || !iv || !ct ||
	    strlen(ct) != ct_hex)
		return -EINVAL;
	if (sep_hex_decode(*id, idb, sizeof(idb)) != ID_BYTES)
		return -EINVAL;
	if (sep_hex_decode(iv, s->iv, sizeof(s->iv)) != SEP_SEAL_IV_BYTES)
		return -EINVAL;
	s->ct_len = ct_hex / 2;
	s->ct = malloc(s->ct_len);
	s->blob_hex = strdup(blob);
	if (!s->ct || !s->blob_hex)
		return -ENOMEM;
	if (sep_hex_decode(ct, s->ct, s->ct_len) != (long)s->ct_len)
		return -EINVAL;
	return 0;
}

static int cmd_unseal(void)
{
	uint8_t secret[SEP_SEAL_SECRET_BYTES + SEP_SEAL_TAG_BYTES];
	char out[2 * SEP_SEAL_SECRET_BYTES + 1], aad[AAD_MAX];
	char *buf, *id;
	struct sep_sealed s = { 0 };
	size_t len = 0, got;
	int r;

	if (isatty(STDOUT_FILENO)) {
		fprintf(stderr, "aurora-fido-seal: refusing to print the secret to a terminal\n");
		return -EPERM;
	}
	buf = calloc(1, RECORD_MAX + 1);
	if (!buf)
		return -ENOMEM;
	while ((got = fread(buf + len, 1, RECORD_MAX - len, stdin)) > 0)
		len += got;
	if (ferror(stdin) || len == 0 || len == RECORD_MAX) {
		r = -EINVAL;
		goto out;
	}
	r = parse_record(buf, &id, &s);
	if (r < 0)
		goto out;
	r = record_aad(id, aad, sizeof(aad));
	if (r < 0)
		goto out;
	r = sep_unseal_secret(aad, &s, WAIT_S, secret, sizeof(secret), &len);
	if (r < 0)
		goto out;
	if (len != SEP_SEAL_SECRET_BYTES) {
		r = -EIO;
		goto out;
	}
	sep_hex_encode(secret, len, out, sizeof(out));
	printf("%s\n", out);
	r = fflush(stdout) ? -errno : 0;
out:
	sep_wipe(secret, sizeof(secret));
	sep_wipe(out, sizeof(out));
	sep_sealed_free(&s);
	sep_wipe(buf, RECORD_MAX);
	free(buf);
	return r;
}

static int cmd_check(void)
{
	static const uint8_t probe[SEP_SEAL_SECRET_BYTES] = { 1 };
	struct sep_sealed s;
	int r;

	r = sep_seal_secret("aurora-fido:1:check", probe, sizeof(probe), &s);
	if (r == 0)
		sep_sealed_free(&s);
	return r;
}

int main(int argc, char **argv)
{
	int r;

	if (argc != 2) {
		fprintf(stderr, "usage: aurora-fido-seal new | unseal < record | check\n");
		return 2;
	}
	if (!strcmp(argv[1], "new"))
		r = cmd_new();
	else if (!strcmp(argv[1], "unseal"))
		r = cmd_unseal();
	else if (!strcmp(argv[1], "check"))
		r = cmd_check();
	else {
		fprintf(stderr, "usage: aurora-fido-seal new | unseal < record | check\n");
		return 2;
	}
	if (r == -ENOENT && geteuid() != 0)
		r = -EPERM;
	if (r < 0) {
		fprintf(stderr, "aurora-fido-seal %s: %s (%d)\n", argv[1], explain(r), r);
		return 1;
	}
	return 0;
}
