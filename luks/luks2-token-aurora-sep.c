// SPDX-License-Identifier: MIT
/*
 * libcryptsetup external LUKS2 token "aurora-sep": the keyslot secret is
 * AES-256-GCM wrapped by a key that only this Mac's Secure Enclave can unseal.
 * cryptsetup and systemd-cryptsetup load it as
 * <token plugin dir>/libcryptsetup-token-aurora-sep.so.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libcryptsetup.h>

#include "sep-seal.h"

#define TOKEN_VERSION "1.0"

/* Seconds to wait for the SEP at early boot; AURORA_SEP_WAIT overrides. */
static int wait_seconds(void)
{
	const char *e = secure_getenv("AURORA_SEP_WAIT");
	char *end;
	long v;

	if (!e || !*e)
		return SEP_SEAL_WAIT_DEFAULT;
	v = strtol(e, &end, 10);
	if (*end || v < 0 || v > 600)
		return SEP_SEAL_WAIT_DEFAULT;
	return (int)v;
}

const char *cryptsetup_token_version(void)
{
	return TOKEN_VERSION;
}

int cryptsetup_token_open_pin(struct crypt_device *cd, int token, const char *pin,
			      size_t pin_size, char **buffer, size_t *buffer_len,
			      void *usrptr)
{
	uint8_t secret[SEP_SEAL_SECRET_BYTES];
	struct sep_sealed s;
	const char *json, *uuid;
	char aad[128], *pass;
	size_t len = 0;
	int r;

	(void)usrptr;
	/* No PIN mode yet: a PIN would not be enforced by the SEP. */
	if (pin && pin_size)
		return -ENOANO;

	r = crypt_token_json_get(cd, token, &json);
	if (r < 0)
		return r;
	uuid = crypt_get_uuid(cd);
	r = sep_seal_aad(uuid, aad, sizeof(aad));
	if (r < 0)
		return r;
	r = sep_token_parse(json, &s);
	if (r < 0) {
		crypt_log(cd, CRYPT_LOG_ERROR, "aurora-sep: malformed token\n");
		return r;
	}

	r = sep_unseal_secret(aad, &s, wait_seconds(), secret, sizeof(secret), &len);
	sep_sealed_free(&s);
	if (r == -ENODEV || r == -ETIMEDOUT) {
		crypt_logf(cd, CRYPT_LOG_VERBOSE,
			  "aurora-sep: the Secure Enclave key store is not available\n");
		return -EAGAIN;
	}
	if (r < 0) {
		/*
		 * EBADMSG covers a blob sealed by another Mac, another OS identity
		 * or a tampered token. Not usable here; fall back to a passphrase.
		 */
		crypt_logf(cd, CRYPT_LOG_VERBOSE,
			  "aurora-sep: the Secure Enclave did not unseal this token (%s)\n",
			  strerror(-r));
		sep_wipe(secret, sizeof(secret));
		return -EPERM;
	}
	if (len != SEP_SEAL_SECRET_BYTES) {
		sep_wipe(secret, sizeof(secret));
		return -EINVAL;
	}

	pass = malloc(SEP_SEAL_PASS_LEN + 1);
	if (!pass) {
		sep_wipe(secret, sizeof(secret));
		return -ENOMEM;
	}
	sep_hex_encode(secret, len, pass, SEP_SEAL_PASS_LEN + 1);
	sep_wipe(secret, sizeof(secret));
	*buffer = pass;
	*buffer_len = SEP_SEAL_PASS_LEN;
	return 0;
}

int cryptsetup_token_open(struct crypt_device *cd, int token, char **buffer,
			  size_t *buffer_len, void *usrptr)
{
	return cryptsetup_token_open_pin(cd, token, NULL, 0, buffer, buffer_len, usrptr);
}

void cryptsetup_token_buffer_free(void *buffer, size_t buffer_len)
{
	sep_wipe(buffer, buffer_len);
	free(buffer);
}

int cryptsetup_token_validate(struct crypt_device *cd, const char *json)
{
	struct sep_sealed s;
	int r;

	r = sep_token_parse(json, &s);
	if (r < 0)
		crypt_log(cd, CRYPT_LOG_DEBUG, "aurora-sep: token JSON rejected\n");
	sep_sealed_free(&s);
	return r;
}

void cryptsetup_token_dump(struct crypt_device *cd, const char *json)
{
	struct sep_sealed s;

	if (sep_token_parse(json, &s) < 0) {
		crypt_logf(cd, CRYPT_LOG_NORMAL, "\taurora-sep:  malformed\n");
		return;
	}
	crypt_logf(cd, CRYPT_LOG_NORMAL, "\tSealed by:   Apple Secure Enclave (trusted key)\n");
	crypt_logf(cd, CRYPT_LOG_NORMAL, "\tSEP blob:    %zu bytes\n", strlen(s.blob_hex) / 2);
	crypt_logf(cd, CRYPT_LOG_NORMAL, "\tWrap:        aes-256-gcm\n");
	sep_sealed_free(&s);
}
