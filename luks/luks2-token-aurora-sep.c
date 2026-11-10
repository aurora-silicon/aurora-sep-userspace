// SPDX-License-Identifier: MIT
/*
 * libcryptsetup external LUKS2 token "aurora-sep": the keyslot secret is
 * AES-256-CCM wrapped by a key that only this Mac's Secure Enclave can unseal.
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
#include "sep-fde.h"

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

/*
 * Password mode (FileVault model). The PIN libcryptsetup passes is the user's
 * password, or the recovery key for a recovery token. A recovery-key-shaped
 * entry goes only to recovery tokens and anything else only to user tokens,
 * so typing the recovery key never costs the user's bag a failed attempt.
 * -ENOENT: not a password-mode token.
 */
static int open_password_mode(struct crypt_device *cd, const char *json, const char *pin,
			      size_t pin_size, char **buffer, size_t *buffer_len)
{
	uint8_t secret[SEP_FDE_SECRET_BYTES];
	char rk[SEP_FDE_RK_LEN + 1];
	struct fde_token t;
	const char *pw = pin;
	size_t pw_len = pin_size;
	int is_rk, r;
	char *pass;

	r = fde_token_parse(json, &t);
	if (r == -ENOENT)
		return r;
	if (r < 0) {
		crypt_log(cd, CRYPT_LOG_ERROR, "aurora-sep: malformed password token\n");
		return r;
	}
	if (!pin || !pin_size) {
		fde_token_free(&t);
		return -ENOANO;
	}
	/*
	 * Without a usable enclave every password token must say so, whatever
	 * the PIN looks like: one -ENOANO (from the token of the other role)
	 * would make libcryptsetup report "PIN needed" and systemd ask again
	 * forever, never reaching the passphrase prompt where the recovery
	 * key's offline keyslot opens the volume.
	 */
	r = fde_wait_ready(wait_seconds());
	if (r < 0) {
		fde_token_free(&t);
		crypt_logf(cd, CRYPT_LOG_VERBOSE,
			  "aurora-sep: the Secure Enclave key store is not available\n");
		return -EAGAIN;
	}
	is_rk = fde_recovery_key_normalize(pin, pin_size, rk) == 0;
	if (is_rk != !strcmp(t.role, SEP_FDE_ROLE_RECOVERY)) {
		fde_token_free(&t);
		sep_wipe(rk, sizeof(rk));
		return -ENOANO;
	}
	if (is_rk) {
		pw = rk;
		pw_len = strlen(rk);
	}
	r = fde_open_token(&t, pw, pw_len, secret);
	sep_wipe(rk, sizeof(rk));
	fde_token_free(&t);
	if (r == -ENODEV || r == -ETIMEDOUT) {
		crypt_logf(cd, CRYPT_LOG_VERBOSE,
			  "aurora-sep: the Secure Enclave key store is not available\n");
		return -EAGAIN;
	}
	if (r == -EACCES)
		return -ENOANO;		/* wrong password; the enclave counted it */
	if (r < 0) {
		crypt_logf(cd, CRYPT_LOG_VERBOSE,
			  "aurora-sep: this Mac's Secure Enclave did not accept this token (%s)\n",
			  strerror(-r));
		return -EPERM;
	}
	pass = malloc(SEP_FDE_PASS_LEN + 1);
	if (!pass) {
		sep_wipe(secret, sizeof(secret));
		return -ENOMEM;
	}
	sep_hex_encode(secret, sizeof(secret), pass, SEP_FDE_PASS_LEN + 1);
	sep_wipe(secret, sizeof(secret));
	*buffer = pass;
	*buffer_len = SEP_FDE_PASS_LEN;
	return 0;
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
	r = crypt_token_json_get(cd, token, &json);
	if (r < 0)
		return r;
	r = open_password_mode(cd, json, pin, pin_size, buffer, buffer_len);
	if (r != -ENOENT)
		return r;
	/* Machine mode has no PIN: a PIN would not be enforced by the SEP. */
	if (pin && pin_size)
		return -ENOANO;
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
	struct fde_token t;
	struct sep_sealed s;
	int r;

	r = fde_token_parse(json, &t);
	fde_token_free(&t);
	if (r != -ENOENT) {
		if (r < 0)
			crypt_log(cd, CRYPT_LOG_DEBUG, "aurora-sep: password token JSON rejected\n");
		return r;
	}
	r = sep_token_parse(json, &s);
	if (r < 0)
		crypt_log(cd, CRYPT_LOG_DEBUG, "aurora-sep: token JSON rejected\n");
	sep_sealed_free(&s);
	return r;
}

void cryptsetup_token_dump(struct crypt_device *cd, const char *json)
{
	struct fde_token t;
	struct sep_sealed s;

	if (fde_token_parse(json, &t) == 0) {
		crypt_logf(cd, CRYPT_LOG_NORMAL, "\tSealed by:   Apple Secure Enclave (user key bag)\n");
		crypt_logf(cd, CRYPT_LOG_NORMAL, "\tUnlock:      %s\n",
			   strcmp(t.role, SEP_FDE_ROLE_RECOVERY) ? "password" : "recovery key");
		crypt_logf(cd, CRYPT_LOG_NORMAL, "\tBag uid:     %u%s%s\n", t.uid,
			   t.label[0] ? "  " : "", t.label);
		crypt_logf(cd, CRYPT_LOG_NORMAL, "\tBag/record:  %zu / %zu bytes\n", t.bag_len, t.record_len);
		fde_token_free(&t);
		return;
	}
	if (sep_token_parse(json, &s) < 0) {
		crypt_logf(cd, CRYPT_LOG_NORMAL, "\taurora-sep:  malformed\n");
		return;
	}
	crypt_logf(cd, CRYPT_LOG_NORMAL, "\tSealed by:   Apple Secure Enclave (trusted key)\n");
	crypt_logf(cd, CRYPT_LOG_NORMAL, "\tSEP blob:    %zu bytes\n", strlen(s.blob_hex) / 2);
	crypt_logf(cd, CRYPT_LOG_NORMAL, "\tWrap:        aes-256-ccm\n");
	sep_sealed_free(&s);
}
