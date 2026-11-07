// SPDX-License-Identifier: MIT
/* Unit tests for sep-seal.c, built with kernel "user" keys in place of SEP trusted keys. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/keyctl.h>
#include "sep-seal.h"

static int fails;
#define CHECK(cond, what) do { \
	if (cond) printf("PASS %s\n", what); \
	else { printf("FAIL %s (line %d)\n", what, __LINE__); fails++; } \
} while (0)

int main(void)
{
	uint8_t secret[SEP_SEAL_SECRET_BYTES], out[SEP_SEAL_SECRET_BYTES + 16], raw[8];
	const char *aad = "aurora-sep:1:5f0c3c3e-0000-4000-8000-000000000001";
	struct sep_sealed s, p;
	size_t len = 0;
	char hex[17], *json, *bad;
	int r;

	/* Build roots and containers may block the keyring (seccomp): skip, not fail. */
	if (syscall(SYS_add_key, "user", "aurora-sep-probe", "x", 1, KEY_SPEC_THREAD_KEYRING) < 0 &&
	    (errno == ENOSYS || errno == EPERM || errno == EACCES)) {
		printf("SKIP kernel keyring unavailable (%s)\n", strerror(errno));
		return 77;
	}

	for (size_t i = 0; i < sizeof(secret); i++)
		secret[i] = (uint8_t)(i * 7 + 3);

	sep_hex_encode((const uint8_t *)"\x00\x01\xab\xff", 4, hex, sizeof(hex));
	CHECK(!strcmp(hex, "0001abff"), "hex encode");
	CHECK(sep_hex_decode("0001ABff", raw, sizeof(raw)) == 4 && raw[2] == 0xab, "hex decode");
	CHECK(sep_hex_decode("abc", raw, sizeof(raw)) == -EINVAL, "hex rejects odd length");
	CHECK(sep_hex_decode("zz", raw, sizeof(raw)) == -EINVAL, "hex rejects non-hex");
	CHECK(sep_seal_aad("", hex, sizeof(hex)) == -EINVAL, "aad needs a LUKS UUID");

	r = sep_seal_secret(aad, secret, sizeof(secret), &s);
	CHECK(r == 0, "seal (AF_ALG gcm(aes) by key serial)");
	if (r) {
		printf("seal failed: %s\n", strerror(-r));
		return 1;
	}
	CHECK(s.ct_len == sizeof(secret) + SEP_SEAL_TAG_BYTES, "ciphertext carries the tag");
	CHECK(memcmp(s.ct, secret, 16), "ciphertext differs from the secret");

	r = sep_unseal_secret(aad, &s, 0, out, sizeof(out), &len);
	CHECK(r == 0 && len == sizeof(secret) && !memcmp(out, secret, len), "unseal round trip");

	r = sep_unseal_secret("aurora-sep:1:other-volume", &s, 0, out, sizeof(out), &len);
	CHECK(r == -EBADMSG, "another volume's UUID is refused (EBADMSG)");

	s.ct[5] ^= 1;
	r = sep_unseal_secret(aad, &s, 0, out, sizeof(out), &len);
	CHECK(r == -EBADMSG, "tampered ciphertext is refused");
	s.ct[5] ^= 1;

	json = sep_token_build(&s);
	CHECK(json && strstr(json, "\"type\":\"aurora-sep\"") && strstr(json, "\"keyslots\":[]"),
	      "token JSON has type and keyslots");
	r = json ? sep_token_parse(json, &p) : -1;
	CHECK(r == 0 && !strcmp(p.blob_hex, s.blob_hex) && p.ct_len == s.ct_len &&
	      !memcmp(p.ct, s.ct, s.ct_len) && !memcmp(p.iv, s.iv, sizeof(s.iv)),
	      "token JSON round trip");
	if (r == 0) {
		r = sep_unseal_secret(aad, &p, 0, out, sizeof(out), &len);
		CHECK(r == 0 && !memcmp(out, secret, sizeof(secret)), "unseal from parsed token");
		/* A different sealed key (another Mac's SEP) cannot open this token. */
		struct sep_sealed other;
		if (sep_seal_secret(aad, secret, sizeof(secret), &other) == 0) {
			free(p.blob_hex);
			p.blob_hex = strdup(other.blob_hex);
			r = sep_unseal_secret(aad, &p, 0, out, sizeof(out), &len);
			CHECK(r == -EBADMSG, "another sealed key cannot open the token");
			sep_sealed_free(&other);
		}
		sep_sealed_free(&p);
	}

	if (json) {
		bad = strdup(json);
		memcpy(strstr(bad, "aurora-sep\""), "aurora-xep", 10);
		CHECK(sep_token_parse(bad, &p) == -EINVAL, "wrong token type rejected");
		free(bad);
		bad = strdup(json);
		*strstr(bad, "\"aurora-sep-version\":1") = ' ';
		CHECK(sep_token_parse(bad, &p) < 0, "broken JSON rejected");
		free(bad);
		bad = strdup(json);
		strstr(bad, "\"aurora-sep-version\":1")[21] = '2';
		CHECK(sep_token_parse(bad, &p) == -EPROTONOSUPPORT, "unknown version rejected");
		free(bad);
		bad = strdup(json);
		strstr(bad, "\"sealed-secret\":\"")[17] = 'g';
		CHECK(sep_token_parse(bad, &p) == -EINVAL, "non-hex ciphertext rejected");
		free(bad);
		free(json);
	}
	CHECK(sep_seal_secret(aad, secret, SEP_SEAL_SECRET_BYTES + 1, &p) == -EINVAL,
	      "oversized secret rejected");

	sep_sealed_free(&s);
	printf("%s: %d failure(s)\n", fails ? "FAIL" : "PASS", fails);
	return fails ? 1 : 0;
}
