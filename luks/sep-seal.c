// SPDX-License-Identifier: MIT
/*
 * SEP-sealed LUKS2 keyslot secrets: keyring, AF_ALG and token JSON helpers
 * shared by the libcryptsetup token plugin and aurora-sep-cryptenroll.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/if_alg.h>
#include <linux/keyctl.h>
#include <json-c/json.h>

#include "sep-seal.h"

#ifndef ALG_SET_KEY_BY_KEY_SERIAL
#define ALG_SET_KEY_BY_KEY_SERIAL 7
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif

void sep_wipe(void *p, size_t n)
{
	if (p)
		explicit_bzero(p, n);
}

void sep_sealed_free(struct sep_sealed *s)
{
	if (!s)
		return;
	free(s->blob_hex);
	if (s->ct) {
		sep_wipe(s->ct, s->ct_len);
		free(s->ct);
	}
	memset(s, 0, sizeof(*s));
}

int sep_hex_encode(const uint8_t *in, size_t n, char *out, size_t out_size)
{
	static const char digits[] = "0123456789abcdef";

	if (out_size < 2 * n + 1)
		return -ENOBUFS;
	for (size_t i = 0; i < n; i++) {
		out[2 * i] = digits[in[i] >> 4];
		out[2 * i + 1] = digits[in[i] & 0xf];
	}
	out[2 * n] = '\0';
	return 0;
}

static int hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

long sep_hex_decode(const char *in, uint8_t *out, size_t out_size)
{
	size_t len = strlen(in);

	if (len == 0 || len % 2 || len / 2 > out_size)
		return -EINVAL;
	for (size_t i = 0; i < len / 2; i++) {
		int hi = hexval(in[2 * i]), lo = hexval(in[2 * i + 1]);

		if (hi < 0 || lo < 0)
			return -EINVAL;
		out[i] = (uint8_t)(hi << 4 | lo);
	}
	return (long)(len / 2);
}

static int is_hex(const char *s, size_t min, size_t max)
{
	size_t n = strlen(s);

	if (n < min || n > max || n % 2)
		return 0;
	for (size_t i = 0; i < n; i++)
		if (hexval(s[i]) < 0)
			return 0;
	return 1;
}

int sep_seal_aad(const char *luks_uuid, char *out, size_t out_size)
{
	int n;

	if (!luks_uuid || !*luks_uuid)
		return -EINVAL;
	n = snprintf(out, out_size, "%s:%d:%s", SEP_SEAL_TOKEN_TYPE,
		     SEP_SEAL_VERSION, luks_uuid);
	return (n < 0 || (size_t)n >= out_size) ? -ENOBUFS : 0;
}

static int32_t add_key_sys(const char *type, const char *desc, const void *payload,
			   size_t plen)
{
	long r = syscall(SYS_add_key, type, desc, payload, plen,
			 KEY_SPEC_THREAD_KEYRING);

	return r < 0 ? -errno : (int32_t)r;
}

static long keyctl_sys(int op, unsigned long a, unsigned long b, unsigned long c,
		       unsigned long d)
{
	long r = syscall(SYS_keyctl, op, a, b, c, d);

	return r < 0 ? -errno : r;
}

static void key_desc(char *buf, size_t n)
{
	static unsigned int seq;
	uint32_t rnd = 0;

	(void)!getrandom(&rnd, sizeof(rnd), 0);
	snprintf(buf, n, "aurora-sep-luks:%d:%u:%08x", (int)getpid(), seq++, rnd);
}

void sep_key_drop(int32_t serial)
{
	if (serial <= 0)
		return;
	if (keyctl_sys(KEYCTL_INVALIDATE, (unsigned long)serial, 0, 0, 0) < 0)
		(void)keyctl_sys(KEYCTL_REVOKE, (unsigned long)serial, 0, 0, 0);
	(void)keyctl_sys(KEYCTL_UNLINK, (unsigned long)serial,
			 (unsigned long)(long)KEY_SPEC_THREAD_KEYRING, 0, 0);
}

#ifdef SEP_SEAL_TEST_USER_KEYS
int sep_key_new(int32_t *serial, char **blob_hex)
{
	uint8_t key[SEP_SEAL_KEY_BYTES];
	char desc[96];
	int32_t s;

	if (getrandom(key, sizeof(key), 0) != sizeof(key))
		return -EIO;
	*blob_hex = malloc(2 * sizeof(key) + 1);
	if (!*blob_hex)
		return -ENOMEM;
	sep_hex_encode(key, sizeof(key), *blob_hex, 2 * sizeof(key) + 1);
	key_desc(desc, sizeof(desc));
	s = add_key_sys(SEP_SEAL_KEY_TYPE, desc, key, sizeof(key));
	sep_wipe(key, sizeof(key));
	if (s < 0) {
		free(*blob_hex);
		*blob_hex = NULL;
		return s;
	}
	*serial = s;
	return 0;
}

int sep_key_load(const char *blob_hex, int wait_s, int32_t *serial)
{
	uint8_t key[SEP_SEAL_KEY_BYTES];
	char desc[96];
	long n;
	int32_t s;

	(void)wait_s;
	n = sep_hex_decode(blob_hex, key, sizeof(key));
	if (n != SEP_SEAL_KEY_BYTES)
		return -EINVAL;
	key_desc(desc, sizeof(desc));
	s = add_key_sys(SEP_SEAL_KEY_TYPE, desc, key, sizeof(key));
	sep_wipe(key, sizeof(key));
	if (s < 0)
		return s;
	*serial = s;
	return 0;
}
#else
/*
 * The 'trusted' key type is registered by apple_sep once the SEP is up, which
 * can be tens of seconds into boot (the module itself loads once /var/lib is
 * mounted). add_key() fails with ENODEV until then. Only wait when this
 * machine has an SEP at all: the driver is loaded, or the device-tree SEP
 * node exists as a platform device.
 */
static int sep_present(void)
{
	glob_t g = { 0 };
	int found;

	if (access("/sys/module/apple_sep", F_OK) == 0)
		return 1;
	found = glob("/sys/bus/platform/devices/*.sep", GLOB_NOSORT, NULL, &g) == 0 &&
		g.gl_pathc > 0;
	globfree(&g);
	return found;
}

static int32_t add_trusted_wait(const char *payload, int wait_s)
{
	struct timespec step = { 0, 250 * 1000 * 1000 };
	long tries = (long)wait_s * 4;
	char desc[96];
	int32_t s;

	for (;;) {
		key_desc(desc, sizeof(desc));
		s = add_key_sys(SEP_SEAL_KEY_TYPE, desc, payload, strlen(payload));
		if (s != -ENODEV || tries-- <= 0 || !sep_present())
			return s;
		nanosleep(&step, NULL);
	}
}

int sep_key_new(int32_t *serial, char **blob_hex)
{
	char *buf;
	long need, got;
	int32_t s;

	s = add_trusted_wait("new 32", 0);
	if (s < 0)
		return s;
	need = keyctl_sys(KEYCTL_READ, (unsigned long)s, 0, 0, 0);
	if (need <= 0 || need > SEP_SEAL_BLOB_HEX_MAX) {
		sep_key_drop(s);
		return need < 0 ? (int)need : -EIO;
	}
	buf = calloc(1, (size_t)need + 1);
	if (!buf) {
		sep_key_drop(s);
		return -ENOMEM;
	}
	got = keyctl_sys(KEYCTL_READ, (unsigned long)s, (unsigned long)buf,
			 (unsigned long)need, 0);
	if (got != need || !is_hex(buf, 2, SEP_SEAL_BLOB_HEX_MAX)) {
		free(buf);
		sep_key_drop(s);
		return got < 0 ? (int)got : -EIO;
	}
	*serial = s;
	*blob_hex = buf;
	return 0;
}

int sep_key_load(const char *blob_hex, int wait_s, int32_t *serial)
{
	size_t n = strlen(blob_hex);
	char *payload;
	int32_t s;

	if (!is_hex(blob_hex, 2, SEP_SEAL_BLOB_HEX_MAX))
		return -EINVAL;
	payload = malloc(n + 6);
	if (!payload)
		return -ENOMEM;
	memcpy(payload, "load ", 5);
	memcpy(payload + 5, blob_hex, n + 1);
	s = add_trusted_wait(payload, wait_s);
	free(payload);
	if (s < 0)
		return s;
	*serial = s;
	return 0;
}
#endif

int sep_aead(int32_t serial, int encrypt, const uint8_t iv[SEP_SEAL_IV_BYTES],
	     const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t in_len,
	     uint8_t *out, size_t out_size, size_t *out_len)
{
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "aead",
		/*
		 * CCM, not GCM: since af_alg_restrict (default 1) the kernel's AEAD
		 * allowlist holds only ccm(aes), for CAP_SYS_ADMIN/CAP_NET_ADMIN.
		 */
		.salg_name = "ccm(aes)",
	};
	size_t res_len, buf_len, io_len;
	uint8_t *buf = NULL;
	char cbuf[CMSG_SPACE(sizeof(uint32_t)) * 2 +
		  CMSG_SPACE(sizeof(struct af_alg_iv) + 16)] = { 0 };
	struct msghdr msg = { 0 };
	struct cmsghdr *c;
	struct iovec iov;
	struct af_alg_iv *aiv;
	int tfm = -1, op = -1, r;
	ssize_t n;

	if (!encrypt && in_len < SEP_SEAL_TAG_BYTES)
		return -EINVAL;
	res_len = encrypt ? in_len + SEP_SEAL_TAG_BYTES : in_len - SEP_SEAL_TAG_BYTES;
	if (out_size < res_len)
		return -ENOBUFS;
	/*
	 * Read exactly AAD || result: AF_ALG keeps waiting for another request
	 * while the read buffer has room left.
	 */
	io_len = aad_len + res_len;
	buf_len = aad_len + (encrypt ? res_len : in_len);
	buf = calloc(1, buf_len);
	if (!buf)
		return -ENOMEM;
	memcpy(buf, aad, aad_len);
	memcpy(buf + aad_len, in, in_len);

	tfm = socket(AF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (tfm < 0 || bind(tfm, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		goto fail;
	if (setsockopt(tfm, SOL_ALG, ALG_SET_KEY_BY_KEY_SERIAL, &serial,
		       sizeof(serial)) < 0)
		goto fail;
	if (setsockopt(tfm, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL,
		       SEP_SEAL_TAG_BYTES) < 0)
		goto fail;
	op = accept4(tfm, NULL, 0, SOCK_CLOEXEC);
	if (op < 0)
		goto fail;

	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);
	c = CMSG_FIRSTHDR(&msg);
	c->cmsg_level = SOL_ALG;
	c->cmsg_type = ALG_SET_OP;
	c->cmsg_len = CMSG_LEN(sizeof(uint32_t));
	*(uint32_t *)CMSG_DATA(c) = encrypt ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;
	c = CMSG_NXTHDR(&msg, c);
	c->cmsg_level = SOL_ALG;
	c->cmsg_type = ALG_SET_IV;
	c->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + 16);
	aiv = (struct af_alg_iv *)CMSG_DATA(c);
	/*
	 * ccm(aes) takes the 16-byte counter block: flags byte L' = L - 1 for a
	 * 15 - L byte nonce (12 bytes, L = 3), the nonce, then a zero counter.
	 */
	aiv->ivlen = 16;
	memset(aiv->iv, 0, 16);
	aiv->iv[0] = 15 - SEP_SEAL_IV_BYTES - 1;
	memcpy(aiv->iv + 1, iv, SEP_SEAL_IV_BYTES);
	c = CMSG_NXTHDR(&msg, c);
	c->cmsg_level = SOL_ALG;
	c->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
	c->cmsg_len = CMSG_LEN(sizeof(uint32_t));
	*(uint32_t *)CMSG_DATA(c) = (uint32_t)aad_len;

	iov.iov_base = buf;
	iov.iov_len = aad_len + in_len;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if (sendmsg(op, &msg, 0) != (ssize_t)(aad_len + in_len))
		goto fail;
	n = read(op, buf, io_len);
	if (n < 0)
		goto fail;
	if ((size_t)n != aad_len + res_len) {
		errno = EIO;
		goto fail;
	}
	memcpy(out, buf + aad_len, res_len);
	*out_len = res_len;
	r = 0;
	goto out;
fail:
	r = errno ? -errno : -EIO;
out:
	if (op >= 0)
		close(op);
	if (tfm >= 0)
		close(tfm);
	sep_wipe(buf, buf_len);
	free(buf);
	return r;
}

int sep_unseal_secret(const char *aad, const struct sep_sealed *in, int wait_s,
		      uint8_t *out, size_t out_size, size_t *out_len)
{
	int32_t k = 0;
	int r;

	r = sep_key_load(in->blob_hex, wait_s, &k);
	if (r < 0)
		return r;
	r = sep_aead(k, 0, in->iv, (const uint8_t *)aad, strlen(aad), in->ct,
		     in->ct_len, out, out_size, out_len);
	sep_key_drop(k);
	return r;
}

int sep_seal_secret(const char *aad, const uint8_t *secret, size_t secret_len,
		    struct sep_sealed *out)
{
	uint8_t check[SEP_SEAL_SECRET_BYTES + SEP_SEAL_TAG_BYTES];
	size_t check_len = 0;
	int32_t k = 0;
	int r;

	memset(out, 0, sizeof(*out));
	if (secret_len > SEP_SEAL_SECRET_BYTES)
		return -EINVAL;
	if (getrandom(out->iv, sizeof(out->iv), 0) != sizeof(out->iv))
		return -EIO;
	out->ct_len = secret_len + SEP_SEAL_TAG_BYTES;
	out->ct = malloc(out->ct_len);
	if (!out->ct)
		return -ENOMEM;
	r = sep_key_new(&k, &out->blob_hex);
	if (r < 0)
		goto fail;
	r = sep_aead(k, 1, out->iv, (const uint8_t *)aad, strlen(aad), secret,
		     secret_len, out->ct, out->ct_len, &out->ct_len);
	sep_key_drop(k);
	if (r < 0)
		goto fail;

	/* Prove the stored form opens: a fresh key from the blob, not the cached one. */
	r = sep_unseal_secret(aad, out, 0, check, sizeof(check), &check_len);
	if (r < 0)
		goto fail;
	if (check_len != secret_len || memcmp(check, secret, secret_len)) {
		r = -EIO;
		goto fail;
	}
	sep_wipe(check, sizeof(check));
	return 0;
fail:
	sep_wipe(check, sizeof(check));
	sep_sealed_free(out);
	return r;
}

static const char *jstr(struct json_object *o, const char *key)
{
	struct json_object *v;

	if (!json_object_object_get_ex(o, key, &v) ||
	    !json_object_is_type(v, json_type_string))
		return NULL;
	return json_object_get_string(v);
}

int sep_token_parse(const char *json, struct sep_sealed *out)
{
	const size_t ct_hex = 2 * (SEP_SEAL_SECRET_BYTES + SEP_SEAL_TAG_BYTES);
	struct json_object *o, *v;
	const char *type, *cipher, *blob, *iv, *ct;
	int r = -EINVAL;

	memset(out, 0, sizeof(*out));
	o = json_tokener_parse(json);
	if (!o)
		return -EINVAL;
	type = jstr(o, "type");
	cipher = jstr(o, "cipher");
	blob = jstr(o, "sep-blob");
	iv = jstr(o, "iv");
	ct = jstr(o, "sealed-secret");
	if (!type || strcmp(type, SEP_SEAL_TOKEN_TYPE))
		goto out;
	if (!json_object_object_get_ex(o, "aurora-sep-version", &v) ||
	    !json_object_is_type(v, json_type_int) ||
	    json_object_get_int(v) != SEP_SEAL_VERSION) {
		r = -EPROTONOSUPPORT;
		goto out;
	}
	if (!cipher || strcmp(cipher, SEP_SEAL_CIPHER)) {
		r = -EPROTONOSUPPORT;
		goto out;
	}
	if (!blob || !is_hex(blob, 2, SEP_SEAL_BLOB_HEX_MAX) || !iv ||
	    strlen(iv) != 2 * SEP_SEAL_IV_BYTES || !is_hex(iv, 2, 64) || !ct ||
	    strlen(ct) != ct_hex || !is_hex(ct, 2, ct_hex))
		goto out;
	out->blob_hex = strdup(blob);
	out->ct_len = ct_hex / 2;
	out->ct = malloc(out->ct_len);
	if (!out->blob_hex || !out->ct) {
		r = -ENOMEM;
		goto out;
	}
	sep_hex_decode(iv, out->iv, sizeof(out->iv));
	sep_hex_decode(ct, out->ct, out->ct_len);
	r = 0;
out:
	json_object_put(o);
	if (r < 0)
		sep_sealed_free(out);
	return r;
}

char *sep_token_build(const struct sep_sealed *s)
{
	char iv[2 * SEP_SEAL_IV_BYTES + 1];
	char *ct, *res = NULL;
	struct json_object *o;

	ct = malloc(2 * s->ct_len + 1);
	if (!ct)
		return NULL;
	sep_hex_encode(s->iv, sizeof(s->iv), iv, sizeof(iv));
	sep_hex_encode(s->ct, s->ct_len, ct, 2 * s->ct_len + 1);
	o = json_object_new_object();
	if (o) {
		json_object_object_add(o, "type", json_object_new_string(SEP_SEAL_TOKEN_TYPE));
		json_object_object_add(o, "keyslots", json_object_new_array());
		json_object_object_add(o, "aurora-sep-version", json_object_new_int(SEP_SEAL_VERSION));
		json_object_object_add(o, "cipher", json_object_new_string(SEP_SEAL_CIPHER));
		json_object_object_add(o, "sep-blob", json_object_new_string(s->blob_hex));
		json_object_object_add(o, "iv", json_object_new_string(iv));
		json_object_object_add(o, "sealed-secret", json_object_new_string(ct));
		res = strdup(json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN));
		json_object_put(o);
	}
	free(ct);
	return res;
}
