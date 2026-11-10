// SPDX-License-Identifier: MIT
/*
 * Password mode of the "aurora-sep" LUKS2 token (FileVault model): enclave
 * operations, token JSON and recovery keys. See sep-fde.h.
 *
 * Built with -DSEP_FDE_MOCK the enclave is replaced by a file-backed test
 * double under $AURORA_SEP_FDE_MOCK that models the same rules (a bag opens
 * only with its password on the "Mac" that made it, failed attempts are
 * counted, an old bag is refused after a password change, a sealed secret
 * opens only while its bag is unlocked). It is for the unit and LUKS2 image
 * tests only and protects nothing.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glob.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <json-c/json.h>

#include "sep-fde.h"
#include "sep-seal.h"

#define BAG_MAX		4096	/* SEP_KEYBAG_BLOB_MAX: a fresh user bag wraps to 1504 bytes */
#define RECORD_MAX	2048
#define SEALED_MAX	256

void fde_token_free(struct fde_token *t)
{
	if (!t)
		return;
	free(t->bag);
	free(t->record);
	free(t->sealed);
	memset(t, 0, sizeof(*t));
}

/* ---- token JSON -------------------------------------------------------- */

static const char *jstr(struct json_object *o, const char *key)
{
	struct json_object *v;

	if (!json_object_object_get_ex(o, key, &v) || !json_object_is_type(v, json_type_string))
		return NULL;
	return json_object_get_string(v);
}

static int jhex(struct json_object *o, const char *key, size_t max, uint8_t **out, size_t *len)
{
	const char *s = jstr(o, key);
	size_t n;
	long r;

	if (!s)
		return -EINVAL;
	n = strlen(s);
	if (n == 0 || n % 2 || n / 2 > max)
		return -EINVAL;
	*out = malloc(n / 2);
	if (!*out)
		return -ENOMEM;
	r = sep_hex_decode(s, *out, n / 2);
	if (r != (long)(n / 2)) {
		free(*out);
		*out = NULL;
		return -EINVAL;
	}
	*len = n / 2;
	return 0;
}

/*
 * Base64 (RFC 4648, padded). A wrapped user bag is about 1.5 KB; in hex a
 * token took about 4 KB, so the default 16 KiB LUKS2 metadata area held only
 * two of them. Tokens written as hex ("aurora_sep_bag") still parse.
 */
static const char b64_alphabet[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_val(char c)
{
	const char *p = c ? strchr(b64_alphabet, c) : NULL;

	return p ? (int)(p - b64_alphabet) : -1;
}

static int jb64(struct json_object *o, const char *key, size_t max, uint8_t **out, size_t *len)
{
	const char *s = jstr(o, key);
	size_t n, pad = 0, olen, j = 0;

	if (!s)
		return -EINVAL;
	n = strlen(s);
	if (n == 0 || n % 4)
		return -EINVAL;
	if (s[n - 1] == '=')
		pad++;
	if (s[n - 2] == '=')
		pad++;
	olen = n / 4 * 3 - pad;
	if (olen == 0 || olen > max)
		return -EINVAL;
	*out = malloc(olen);
	if (!*out)
		return -ENOMEM;
	for (size_t i = 0; i < n; i += 4) {
		int v[4];
		uint32_t w;

		for (int k = 0; k < 4; k++) {
			v[k] = (s[i + k] == '=' && i + 4 == n && k >= 2) ? 0 : b64_val(s[i + k]);
			if (v[k] < 0)
				goto bad;
		}
		w = (uint32_t)v[0] << 18 | (uint32_t)v[1] << 12 | (uint32_t)v[2] << 6 | (uint32_t)v[3];
		for (int k = 0; k < 3 && j < olen; k++)
			(*out)[j++] = (uint8_t)(w >> (16 - 8 * k));
	}
	*len = olen;
	return 0;
bad:
	free(*out);
	*out = NULL;
	return -EINVAL;
}

/* "<key>64" in base64, or "<key>" in hex (tokens written before 0.3). */
static int jbin(struct json_object *o, const char *key, size_t max, uint8_t **out, size_t *len)
{
	char k64[64];

	snprintf(k64, sizeof(k64), "%s64", key);
	if (jstr(o, k64))
		return jb64(o, k64, max, out, len);
	return jhex(o, key, max, out, len);
}

int fde_token_parse(const char *json, struct fde_token *t)
{
	struct json_object *o, *v;
	const char *s;
	int64_t uid;
	int r = -EINVAL;

	memset(t, 0, sizeof(*t));
	o = json_tokener_parse(json);
	if (!o)
		return -EINVAL;
	s = jstr(o, "type");
	if (!s || strcmp(s, SEP_SEAL_TOKEN_TYPE))
		goto out;
	s = jstr(o, "aurora_sep_mode");
	if (!s || strcmp(s, SEP_FDE_MODE)) {
		r = -ENOENT;
		goto out;
	}
	if (!json_object_object_get_ex(o, "aurora_sep_uid", &v) || !json_object_is_type(v, json_type_int))
		goto out;
	uid = json_object_get_int64(v);
	if (uid < SEP_FDE_UID_MIN || uid > INT32_MAX)
		goto out;
	t->uid = (uint32_t)uid;
	s = jstr(o, "aurora_sep_role");
	if (!s || (strcmp(s, SEP_FDE_ROLE_USER) && strcmp(s, SEP_FDE_ROLE_RECOVERY)))
		goto out;
	snprintf(t->role, sizeof(t->role), "%s", s);
	s = jstr(o, "aurora_sep_label");
	snprintf(t->label, sizeof(t->label), "%s", s ? s : "");
	t->offline_keyslot = -1;
	t->owner = -1;
	t->linux_uid = -1;
	if (json_object_object_get_ex(o, "aurora_sep_owner", &v)) {
		if (!json_object_is_type(v, json_type_boolean))
			goto out;
		t->owner = json_object_get_boolean(v) ? 1 : 0;
	}
	if (json_object_object_get_ex(o, "aurora_sep_linux_uid", &v)) {
		if (!json_object_is_type(v, json_type_int))
			goto out;
		t->linux_uid = json_object_get_int64(v);
		if (t->linux_uid < 0 || t->linux_uid > UINT32_MAX)
			goto out;
	}
	s = jstr(o, "aurora_sep_user");
	snprintf(t->user, sizeof(t->user), "%s", s ? s : "");
	if (json_object_object_get_ex(o, "aurora_sep_offline_keyslot", &v)) {
		if (!json_object_is_type(v, json_type_int))
			goto out;
		uid = json_object_get_int64(v);
		if (uid < 0 || uid > 31)
			goto out;
		t->offline_keyslot = (int)uid;
	}
	if (jbin(o, "aurora_sep_bag", BAG_MAX, &t->bag, &t->bag_len) ||
	    jbin(o, "aurora_sep_record", RECORD_MAX, &t->record, &t->record_len) ||
	    jbin(o, "aurora_sep_sealed", SEALED_MAX, &t->sealed, &t->sealed_len))
		goto out;
	r = 0;
out:
	json_object_put(o);
	if (r)
		fde_token_free(t);
	return r;
}

static int jset_b64(struct json_object *o, const char *key, const uint8_t *b, size_t n)
{
	char *e = malloc((n + 2) / 3 * 4 + 1);
	size_t j = 0;

	if (!e)
		return -ENOMEM;
	for (size_t i = 0; i < n; i += 3) {
		uint32_t w = (uint32_t)b[i] << 16;

		if (i + 1 < n)
			w |= (uint32_t)b[i + 1] << 8;
		if (i + 2 < n)
			w |= b[i + 2];
		e[j++] = b64_alphabet[w >> 18 & 63];
		e[j++] = b64_alphabet[w >> 12 & 63];
		e[j++] = i + 1 < n ? b64_alphabet[w >> 6 & 63] : '=';
		e[j++] = i + 2 < n ? b64_alphabet[w & 63] : '=';
	}
	e[j] = '\0';
	json_object_object_add(o, key, json_object_new_string(e));
	free(e);
	return 0;
}

char *fde_token_build(const struct fde_token *t)
{
	struct json_object *o = json_object_new_object();
	char *out = NULL;

	if (!o)
		return NULL;
	json_object_object_add(o, "type", json_object_new_string(SEP_SEAL_TOKEN_TYPE));
	json_object_object_add(o, "keyslots", json_object_new_array());
	json_object_object_add(o, "aurora_sep_version", json_object_new_int(3));
	json_object_object_add(o, "aurora_sep_mode", json_object_new_string(SEP_FDE_MODE));
	json_object_object_add(o, "aurora_sep_role", json_object_new_string(t->role));
	json_object_object_add(o, "aurora_sep_uid", json_object_new_int64(t->uid));
	if (t->label[0])
		json_object_object_add(o, "aurora_sep_label", json_object_new_string(t->label));
	if (!strcmp(t->role, SEP_FDE_ROLE_USER) && t->owner >= 0)
		json_object_object_add(o, "aurora_sep_owner", json_object_new_boolean(t->owner));
	if (t->linux_uid >= 0)
		json_object_object_add(o, "aurora_sep_linux_uid", json_object_new_int64(t->linux_uid));
	if (t->user[0])
		json_object_object_add(o, "aurora_sep_user", json_object_new_string(t->user));
	if (t->offline_keyslot >= 0)
		json_object_object_add(o, "aurora_sep_offline_keyslot",
				       json_object_new_int(t->offline_keyslot));
	if (jset_b64(o, "aurora_sep_bag64", t->bag, t->bag_len) ||
	    jset_b64(o, "aurora_sep_record64", t->record, t->record_len) ||
	    jset_b64(o, "aurora_sep_sealed64", t->sealed, t->sealed_len))
		goto out;
	out = strdup(json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN));
out:
	json_object_put(o);
	return out;
}

/* ---- recovery keys ----------------------------------------------------- */

static const char rk_alphabet[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

int fde_recovery_key_new(char out[SEP_FDE_RK_LEN + 1])
{
	uint8_t r[SEP_FDE_RK_CHARS];
	size_t j = 0;

	if (getrandom(r, sizeof(r), 0) != (ssize_t)sizeof(r))
		return -EIO;
	for (size_t i = 0; i < SEP_FDE_RK_CHARS; i++) {
		if (i && i % 4 == 0)
			out[j++] = '-';
		out[j++] = rk_alphabet[r[i] & 31];
	}
	out[j] = '\0';
	sep_wipe(r, sizeof(r));
	return 0;
}

int fde_recovery_key_normalize(const char *in, size_t in_len, char out[SEP_FDE_RK_LEN + 1])
{
	size_t n = 0, j = 0;

	for (size_t i = 0; i < in_len; i++) {
		char c = in[i];

		if (c == '-' || c == ' ' || c == '\t' || c == '\n' || c == '\r')
			continue;
		if (c >= 'a' && c <= 'z')
			c = (char)(c - 'a' + 'A');
		if (!strchr(rk_alphabet, c) || c == '\0' || n == SEP_FDE_RK_CHARS)
			goto bad;
		if (n && n % 4 == 0)
			out[j++] = '-';
		out[j++] = c;
		n++;
	}
	if (n != SEP_FDE_RK_CHARS)
		goto bad;
	out[j] = '\0';
	return 0;
bad:
	sep_wipe(out, SEP_FDE_RK_LEN + 1);
	return -EINVAL;
}

#ifndef SEP_FDE_MOCK
/* ---- the enclave: /dev/sep-bio-rearm ----------------------------------- */

#define SEP_BIO_IOC_MAGIC 0xB1
#define KB_SECRET_MAX 256

struct kb_state {
	uint32_t uid, bag_state, biometry, failed_matches;
	uint64_t since_password_s, since_unlock_s;
	uint32_t enclave_lock_state, lock_phase;
};
struct kb_unlock {
	uint32_t uid, secret_len;
	uint8_t secret[KB_SECRET_MAX];
};
struct kb_lock {
	uint32_t uid, reason, grace_s, reserved;
};
struct kb_change {
	uint32_t uid, old_len, new_len, reserved;
	uint8_t old_secret[KB_SECRET_MAX], new_secret[KB_SECRET_MAX];
};
struct kb_blob {
	uint32_t uid, len;
	uint8_t data[BAG_MAX];
};
/* The ioctl numbers encode these sizes: they must match <linux/apple-sep.h>. */
_Static_assert(sizeof(struct kb_blob) == 8 + 4096, "struct sep_keybag_blob");
struct fde_key_req {
	uint32_t uid, record_len;
	uint8_t record[RECORD_MAX];
};
struct fde_seal_req {
	uint32_t uid, record_len, secret_len, sealed_len;
	uint8_t secret[64];
	uint8_t sealed[SEALED_MAX];
	uint8_t record[RECORD_MAX];
};

#define KB_STATE   _IOWR(SEP_BIO_IOC_MAGIC, 0x30, struct kb_state)
#define KB_UNLOCK  _IOW(SEP_BIO_IOC_MAGIC, 0x31, struct kb_unlock)
#define KB_LOCK    _IOW(SEP_BIO_IOC_MAGIC, 0x32, struct kb_lock)
#define KB_CHANGE  _IOW(SEP_BIO_IOC_MAGIC, 0x33, struct kb_change)
#define KB_CREATE  _IOW(SEP_BIO_IOC_MAGIC, 0x34, struct kb_unlock)
#define KB_EXPORT  _IOWR(SEP_BIO_IOC_MAGIC, 0x35, struct kb_blob)
#define KB_IMPORT  _IOW(SEP_BIO_IOC_MAGIC, 0x36, struct kb_blob)
#define FDE_CREATE _IOWR(SEP_BIO_IOC_MAGIC, 0x37, struct fde_key_req)
#define FDE_SEAL   _IOWR(SEP_BIO_IOC_MAGIC, 0x38, struct fde_seal_req)
#define FDE_UNSEAL _IOWR(SEP_BIO_IOC_MAGIC, 0x39, struct fde_seal_req)
#define KB_LOCK_LOGOUT 3

static int sep_ioctl(unsigned long cmd, void *arg)
{
	int fd = open(SEP_FDE_DEV, O_RDWR | O_CLOEXEC);
	int r;

	if (fd < 0)
		return errno == ENOENT ? -ENODEV : -errno;
	r = ioctl(fd, cmd, arg) < 0 ? -errno : 0;
	close(fd);
	return r;
}

/*
 * At early boot the password is typed while the enclave may still be coming
 * up: the re-arm node appears when the key store opens (with apple_sep
 * keystore_only=2 in the initrd, or after the full attach). Wait only while
 * a SEP driver is there and its key store is not decided; once it reads
 * "open" the node follows within the same bring-up step.
 */
static int sep_driver_present(void)
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

int fde_wait_ready(int wait_s)
{
	struct timespec step = { 0, 250 * 1000 * 1000 };
	long tries = (long)wait_s * 4, open_grace = 8;

	for (;;) {
		if (access(SEP_FDE_DEV, F_OK) == 0)
			return 0;
		if (!sep_driver_present())
			return -ENODEV;
		switch (sep_keystore_state()) {
		case SEP_KEYSTORE_CLOSED:
			return -ENODEV;
		case SEP_KEYSTORE_OPEN:
			/* A driver without the initrd user-bag phase never
			 * publishes the node here. */
			if (open_grace-- <= 0)
				return -ENODEV;
			break;
		default:
			break;
		}
		if (tries-- <= 0)
			return -ETIMEDOUT;
		nanosleep(&step, NULL);
	}
}

static int secret_req(unsigned long cmd, uint32_t uid, const char *pw, size_t n)
{
	struct kb_unlock req = { .uid = uid, .secret_len = (uint32_t)n };
	int r;

	if (n == 0 || n > KB_SECRET_MAX)
		return -EINVAL;
	memcpy(req.secret, pw, n);
	r = sep_ioctl(cmd, &req);
	sep_wipe(&req, sizeof(req));
	return r;
}

int fde_bag_create(uint32_t uid, const char *pw, size_t n)
{
	return secret_req(KB_CREATE, uid, pw, n);
}

int fde_bag_unlock(uint32_t uid, const char *pw, size_t n)
{
	return secret_req(KB_UNLOCK, uid, pw, n);
}

int fde_bag_lock(uint32_t uid)
{
	struct kb_lock req = { .uid = uid, .reason = KB_LOCK_LOGOUT };

	return sep_ioctl(KB_LOCK, &req);
}

int fde_bag_change(uint32_t uid, const char *old_pw, size_t old_len,
		   const char *new_pw, size_t new_len)
{
	struct kb_change *req;
	int r;

	if (!old_len || old_len > KB_SECRET_MAX || !new_len || new_len > KB_SECRET_MAX)
		return -EINVAL;
	req = calloc(1, sizeof(*req));
	if (!req)
		return -ENOMEM;
	req->uid = uid;
	req->old_len = (uint32_t)old_len;
	req->new_len = (uint32_t)new_len;
	memcpy(req->old_secret, old_pw, old_len);
	memcpy(req->new_secret, new_pw, new_len);
	r = sep_ioctl(KB_CHANGE, req);
	sep_wipe(req, sizeof(*req));
	free(req);
	return r;
}

int fde_bag_export(uint32_t uid, uint8_t **blob, size_t *len)
{
	struct kb_blob req = { .uid = uid };
	int r = sep_ioctl(KB_EXPORT, &req);

	if (r)
		return r;
	if (req.len == 0 || req.len > BAG_MAX)
		return -EPROTO;
	*blob = malloc(req.len);
	if (!*blob)
		return -ENOMEM;
	memcpy(*blob, req.data, req.len);
	*len = req.len;
	return 0;
}

int fde_bag_import(uint32_t uid, const uint8_t *blob, size_t len)
{
	struct kb_blob req = { .uid = uid, .len = (uint32_t)len };

	if (!len || len > BAG_MAX)
		return -EINVAL;
	memcpy(req.data, blob, len);
	return sep_ioctl(KB_IMPORT, &req);
}

int fde_bag_state(uint32_t uid, struct fde_state *st)
{
	struct kb_state req = { .uid = uid };
	int r = sep_ioctl(KB_STATE, &req);

	if (r)
		return r;
	st->bag_state = req.bag_state;
	st->failed_attempts = req.failed_matches;
	st->lock_phase = req.lock_phase;
	return 0;
}

int fde_key_create(uint32_t uid, uint8_t **record, size_t *len)
{
	struct fde_key_req *req = calloc(1, sizeof(*req));
	int r;

	if (!req)
		return -ENOMEM;
	req->uid = uid;
	r = sep_ioctl(FDE_CREATE, req);
	if (!r && (req->record_len == 0 || req->record_len > RECORD_MAX))
		r = -EPROTO;
	if (!r) {
		*record = malloc(req->record_len);
		if (*record) {
			memcpy(*record, req->record, req->record_len);
			*len = req->record_len;
		} else {
			r = -ENOMEM;
		}
	}
	free(req);
	return r;
}

static int seal_req(int seal, uint32_t uid, const uint8_t *record, size_t record_len,
		    const uint8_t *in, size_t in_len, uint8_t *out, size_t out_size, size_t *out_len)
{
	struct fde_seal_req *req;
	int r;

	if (!record_len || record_len > RECORD_MAX || !in_len ||
	    in_len > (seal ? sizeof(req->secret) : SEALED_MAX))
		return -EINVAL;
	req = calloc(1, sizeof(*req));
	if (!req)
		return -ENOMEM;
	req->uid = uid;
	req->record_len = (uint32_t)record_len;
	memcpy(req->record, record, record_len);
	if (seal) {
		req->secret_len = (uint32_t)in_len;
		memcpy(req->secret, in, in_len);
	} else {
		req->sealed_len = (uint32_t)in_len;
		memcpy(req->sealed, in, in_len);
	}
	r = sep_ioctl(seal ? FDE_SEAL : FDE_UNSEAL, req);
	if (!r) {
		const uint8_t *src = seal ? req->sealed : req->secret;
		size_t n = seal ? req->sealed_len : req->secret_len;

		if (n == 0 || n > out_size)
			r = -EPROTO;
		else {
			memcpy(out, src, n);
			*out_len = n;
		}
	}
	sep_wipe(req, sizeof(*req));
	free(req);
	return r;
}

int fde_seal(uint32_t uid, const uint8_t *record, size_t record_len,
	     const uint8_t *secret, size_t secret_len, uint8_t **sealed, size_t *len)
{
	uint8_t buf[SEALED_MAX];
	int r = seal_req(1, uid, record, record_len, secret, secret_len, buf, sizeof(buf), len);

	if (r)
		return r;
	*sealed = malloc(*len);
	if (!*sealed)
		return -ENOMEM;
	memcpy(*sealed, buf, *len);
	return 0;
}

int fde_unseal(uint32_t uid, const uint8_t *record, size_t record_len,
	       const uint8_t *sealed, size_t sealed_len, uint8_t *out, size_t out_size,
	       size_t *out_len)
{
	return seal_req(0, uid, record, record_len, sealed, sealed_len, out, out_size, out_len);
}

#else
/* ---- test double (SEP_FDE_MOCK) ---------------------------------------- */

/* The double is always ready unless a test says this "Mac" has no SEP. */
int fde_wait_ready(int wait_s)
{
	(void)wait_s;
	return getenv("AURORA_SEP_FDE_MOCK_NOSEP") ? -ENODEV : 0;
}

/* SHA-256 (FIPS 180-4), small and slow; the double needs a PRF and a MAC. */
struct sha { uint32_t h[8]; uint8_t b[64]; uint64_t n; size_t l; };
static const uint32_t K[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
static void sha_block(struct sha *s)
{
	uint32_t w[64], a, b, c, d, e, f, g, h;

	for (int i = 0; i < 16; i++)
		w[i] = (uint32_t)s->b[4 * i] << 24 | (uint32_t)s->b[4 * i + 1] << 16 |
		       (uint32_t)s->b[4 * i + 2] << 8 | s->b[4 * i + 3];
	for (int i = 16; i < 64; i++)
		w[i] = w[i - 16] + (ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3)) +
		       w[i - 7] + (ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10));
	a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3];
	e = s->h[4]; f = s->h[5]; g = s->h[6]; h = s->h[7];
	for (int i = 0; i < 64; i++) {
		uint32_t t1 = h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
		uint32_t t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
		h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	}
	s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
	s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}
static void sha_init(struct sha *s)
{
	static const uint32_t iv[8] = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
					0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
	memcpy(s->h, iv, sizeof(iv));
	s->n = 0;
	s->l = 0;
}
static void sha_add(struct sha *s, const void *p, size_t n)
{
	const uint8_t *d = p;

	while (n--) {
		s->b[s->l++] = *d++;
		s->n += 8;
		if (s->l == 64) {
			sha_block(s);
			s->l = 0;
		}
	}
}
static void sha_end(struct sha *s, uint8_t out[32])
{
	uint64_t n = s->n;
	uint8_t one = 0x80, z = 0;

	sha_add(s, &one, 1);
	while (s->l != 56)
		sha_add(s, &z, 1);
	for (int i = 7; i >= 0; i--)
		s->b[s->l++] = (uint8_t)(n >> (8 * i));
	sha_block(s);
	for (int i = 0; i < 8; i++) {
		out[4 * i] = (uint8_t)(s->h[i] >> 24);
		out[4 * i + 1] = (uint8_t)(s->h[i] >> 16);
		out[4 * i + 2] = (uint8_t)(s->h[i] >> 8);
		out[4 * i + 3] = (uint8_t)s->h[i];
	}
}

static uint8_t devkey[32];

static void rnd(void *b, size_t n)
{
	if (getrandom(b, n, 0) != (ssize_t)n)
		abort();
}

static const char *mock_dir(void)
{
	return getenv("AURORA_SEP_FDE_MOCK");
}

static int mock_path(char *buf, size_t n, const char *what, uint32_t uid)
{
	const char *d = mock_dir();

	if (!d || !*d)
		return -ENODEV;
	snprintf(buf, n, "%s/%s-%u", d, what, uid);
	return 0;
}

static int rd(const char *p, uint8_t *b, size_t max, size_t *n)
{
	FILE *f = fopen(p, "rb");

	if (!f)
		return -ENOENT;
	*n = fread(b, 1, max, f);
	fclose(f);
	return 0;
}

static int wr(const char *p, const uint8_t *b, size_t n)
{
	FILE *f = fopen(p, "wb");

	if (!f)
		return -errno;
	fwrite(b, 1, n, f);
	return fclose(f) ? -EIO : 0;
}

static int mock_init(void)
{
	char p[4096];
	size_t n = 0;

	if (mock_path(p, sizeof(p), "devkey", 0))
		return -ENODEV;
	if (rd(p, devkey, sizeof(devkey), &n) == 0 && n == sizeof(devkey))
		return 0;
	if (getrandom(devkey, sizeof(devkey), 0) != sizeof(devkey))
		return -EIO;
	return wr(p, devkey, sizeof(devkey));
}

static void prf(const char *label, const void *a, size_t an, const void *b, size_t bn, uint8_t out[32])
{
	struct sha s;

	sha_init(&s);
	sha_add(&s, devkey, sizeof(devkey));
	sha_add(&s, label, strlen(label) + 1);
	sha_add(&s, a, an);
	if (b)
		sha_add(&s, b, bn);
	sha_end(&s, out);
}

/* bag blob: "MKBG" uid ver salt[16] verifier[32] mac[32] */
#define MB_LEN (4 + 4 + 4 + 16 + 32 + 32)

static uint32_t get_u32(const char *what, uint32_t uid)
{
	char p[4096];
	uint8_t b[4];
	size_t n = 0;

	if (mock_path(p, sizeof(p), what, uid) || rd(p, b, 4, &n) || n != 4)
		return 0;
	return (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
}

static void put_u32(const char *what, uint32_t uid, uint32_t v)
{
	char p[4096];
	uint8_t b[4] = { (uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24) };

	if (!mock_path(p, sizeof(p), what, uid))
		wr(p, b, 4);
}

static int flag(const char *what, uint32_t uid, int set)
{
	char p[4096];

	if (mock_path(p, sizeof(p), what, uid))
		return 0;
	if (set > 0)
		return wr(p, (const uint8_t *)"1", 1);
	if (set == 0)
		return unlink(p);
	return access(p, F_OK) == 0;
}

static void make_bag(uint32_t uid, uint32_t ver, const char *pw, size_t n, uint8_t bag[MB_LEN])
{
	memcpy(bag, "MKBG", 4);
	memcpy(bag + 4, &uid, 4);
	memcpy(bag + 8, &ver, 4);
	rnd(bag + 12, 16);
	prf("verifier", bag, 28, pw, n, bag + 28);
	prf("bagmac", bag, 60, NULL, 0, bag + 60);
}

static int live_bag(uint32_t uid, uint8_t bag[MB_LEN])
{
	char p[4096];
	size_t n = 0;

	if (mock_init() || mock_path(p, sizeof(p), "live", uid))
		return -ENODEV;
	if (rd(p, bag, MB_LEN, &n) || n != MB_LEN)
		return -EACCES;
	return 0;
}

static int store_live(uint32_t uid, const uint8_t bag[MB_LEN])
{
	char p[4096];

	if (mock_path(p, sizeof(p), "live", uid))
		return -ENODEV;
	return wr(p, bag, MB_LEN);
}

static int check_pw(uint32_t uid, const uint8_t bag[MB_LEN], const char *pw, size_t n)
{
	uint8_t v[32];

	prf("verifier", bag, 28, pw, n, v);
	if (memcmp(v, bag + 28, 32)) {
		put_u32("fail", uid, get_u32("fail", uid) + 1);
		return -EACCES;
	}
	put_u32("fail", uid, 0);
	return 0;
}

int fde_bag_create(uint32_t uid, const char *pw, size_t n)
{
	uint8_t bag[MB_LEN];
	uint32_t ver;

	if (mock_init())
		return -ENODEV;
	if (!n || n > SEP_FDE_PASSWORD_MAX)
		return -EINVAL;
	/* As the enclave: no second bag under a uid it holds until reboot. */
	if (live_bag(uid, bag) == 0)
		return -EACCES;
	ver = get_u32("ver", uid) + 1;
	make_bag(uid, ver, pw, n, bag);
	put_u32("ver", uid, ver);
	flag("unlocked", uid, 0);
	return store_live(uid, bag);
}

int fde_bag_unlock(uint32_t uid, const char *pw, size_t n)
{
	uint8_t bag[MB_LEN];
	int r = live_bag(uid, bag);

	if (r)
		return r;
	r = check_pw(uid, bag, pw, n);
	if (!r)
		flag("unlocked", uid, 1);
	return r;
}

int fde_bag_lock(uint32_t uid)
{
	uint8_t bag[MB_LEN];
	int r = live_bag(uid, bag);

	if (!r)
		flag("unlocked", uid, 0);
	return r;
}

int fde_bag_change(uint32_t uid, const char *old_pw, size_t old_len,
		   const char *new_pw, size_t new_len)
{
	uint8_t bag[MB_LEN];
	uint32_t ver;
	int r = live_bag(uid, bag);

	if (r)
		return r;
	r = check_pw(uid, bag, old_pw, old_len);
	if (r)
		return r;
	ver = get_u32("ver", uid) + 1;
	make_bag(uid, ver, new_pw, new_len, bag);
	put_u32("ver", uid, ver);
	return store_live(uid, bag);
}

int fde_bag_export(uint32_t uid, uint8_t **blob, size_t *len)
{
	uint8_t bag[MB_LEN];
	int r = live_bag(uid, bag);

	if (r)
		return r;
	*blob = malloc(MB_LEN);
	if (!*blob)
		return -ENOMEM;
	memcpy(*blob, bag, MB_LEN);
	*len = MB_LEN;
	return 0;
}

int fde_bag_import(uint32_t uid, const uint8_t *blob, size_t len)
{
	uint8_t mac[32];
	uint32_t buid, ver;

	if (mock_init())
		return -ENODEV;
	if (len != MB_LEN || memcmp(blob, "MKBG", 4))
		return -EACCES;
	prf("bagmac", blob, 60, NULL, 0, mac);
	memcpy(&buid, blob + 4, 4);
	memcpy(&ver, blob + 8, 4);
	/* Another Mac, another uid, or a bag older than the last password change. */
	if (memcmp(mac, blob + 60, 32) || buid != uid || ver < get_u32("ver", uid))
		return -EACCES;
	flag("unlocked", uid, 0);
	return store_live(uid, blob);
}

int fde_bag_state(uint32_t uid, struct fde_state *st)
{
	uint8_t bag[MB_LEN];
	int r = live_bag(uid, bag);

	if (r)
		return r;
	st->bag_state = flag("unlocked", uid, -1) ? 1 : 3;
	st->failed_attempts = get_u32("fail", uid);
	st->lock_phase = st->bag_state == 1 ? 0 : 1;
	return 0;
}

/* record: "MKRK" uid id[16] mac[32] */
#define MR_LEN (4 + 4 + 16 + 32)

int fde_key_create(uint32_t uid, uint8_t **record, size_t *len)
{
	uint8_t bag[MB_LEN], *rec;
	int r = live_bag(uid, bag);

	if (r)
		return r;
	if (!flag("unlocked", uid, -1))
		return -EACCES;
	rec = malloc(MR_LEN);
	if (!rec)
		return -ENOMEM;
	memcpy(rec, "MKRK", 4);
	memcpy(rec + 4, &uid, 4);
	rnd(rec + 8, 16);
	prf("record", rec, 24, NULL, 0, rec + 24);
	*record = rec;
	*len = MR_LEN;
	return 0;
}

static int record_ok(uint32_t uid, const uint8_t *rec, size_t n, const uint8_t bag[MB_LEN])
{
	uint8_t mac[32];
	uint32_t ruid;

	if (n != MR_LEN || memcmp(rec, "MKRK", 4))
		return -EINVAL;
	memcpy(&ruid, rec + 4, 4);
	(void)bag;
	prf("record", rec, 24, NULL, 0, mac);
	/* Another Mac's record (other device key) or another bag's. */
	return ruid == uid && !memcmp(mac, rec + 24, 32) ? 0 : -EKEYREJECTED;
}

/* The per-key secret, kept in a file named by the key id, survives a
 * password change as the enclave's key does. */
static int key_secret(const uint8_t *rec, uint8_t ks[32], int create)
{
	char p[4096], name[64];
	size_t n = 0;

	sep_hex_encode(rec + 8, 16, name, sizeof(name));
	if (mock_path(p, sizeof(p), "key", 0))
		return -ENODEV;
	snprintf(p + strlen(p), sizeof(p) - strlen(p), "-%s", name);
	if (rd(p, ks, 32, &n) == 0 && n == 32)
		return 0;
	if (!create)
		return -EKEYREJECTED;
	prf("keysecret", rec, 24, NULL, 0, ks);
	return wr(p, ks, 32);
}

static void xor_stream(const uint8_t ks[32], const uint8_t nonce[16], uint8_t *buf, size_t n)
{
	for (size_t off = 0; off < n; off += 32) {
		uint8_t block[32], ctr[17];

		memcpy(ctr, nonce, 16);
		ctr[16] = (uint8_t)(off / 32);
		prf("stream", ks, 32, ctr, sizeof(ctr), block);
		for (size_t i = 0; i < 32 && off + i < n; i++)
			buf[off + i] ^= block[i];
	}
}

int fde_seal(uint32_t uid, const uint8_t *record, size_t record_len,
	     const uint8_t *secret, size_t secret_len, uint8_t **sealed, size_t *len)
{
	uint8_t bag[MB_LEN], ks[32], *out;
	int r = live_bag(uid, bag);

	if (r)
		return r;
	if (!flag("unlocked", uid, -1))
		return -EKEYREJECTED;
	r = record_ok(uid, record, record_len, bag);
	if (r || (r = key_secret(record, ks, 1)))
		return r;
	if (!secret_len || secret_len > 64)
		return -EINVAL;
	out = malloc(16 + secret_len + 32);
	if (!out)
		return -ENOMEM;
	rnd(out, 16);
	memcpy(out + 16, secret, secret_len);
	xor_stream(ks, out, out + 16, secret_len);
	prf("tag", ks, 32, out, 16 + secret_len, out + 16 + secret_len);
	*sealed = out;
	*len = 16 + secret_len + 32;
	return 0;
}

int fde_unseal(uint32_t uid, const uint8_t *record, size_t record_len,
	       const uint8_t *sealed, size_t sealed_len, uint8_t *out, size_t out_size,
	       size_t *out_len)
{
	uint8_t bag[MB_LEN], ks[32], tag[32];
	size_t n;
	int r = live_bag(uid, bag);

	if (r)
		return r;
	if (!flag("unlocked", uid, -1))
		return -EKEYREJECTED;
	r = record_ok(uid, record, record_len, bag);
	if (r || (r = key_secret(record, ks, 0)))
		return r;
	if (sealed_len < 16 + 1 + 32)
		return -EINVAL;
	n = sealed_len - 16 - 32;
	prf("tag", ks, 32, sealed, 16 + n, tag);
	if (memcmp(tag, sealed + 16 + n, 32) || n > out_size)
		return -EKEYREJECTED;
	memcpy(out, sealed + 16, n);
	xor_stream(ks, sealed, out, n);
	*out_len = n;
	return 0;
}
#endif

/* ---- flows -------------------------------------------------------------- */

int fde_open_token(const struct fde_token *t, const char *pw, size_t pw_len,
		   uint8_t secret[SEP_FDE_SECRET_BYTES])
{
	struct fde_state st;
	size_t n = 0;
	int r;

	if (!pw_len || pw_len > SEP_FDE_PASSWORD_MAX)
		return -EINVAL;
	/* Load the saved bag only when the enclave holds none for this uid, so
	 * a wrong password is counted once. */
	if (fde_bag_state(t->uid, &st) < 0) {
		r = fde_bag_import(t->uid, t->bag, t->bag_len);
		if (r == -ENODEV)
			return r;
		if (r < 0)
			return -EPERM;
	}
	r = fde_bag_unlock(t->uid, pw, pw_len);
	if (r == -ENODEV)
		return r;
	if (r < 0)
		return -EACCES;
	r = fde_unseal(t->uid, t->record, t->record_len, t->sealed, t->sealed_len,
		       secret, SEP_FDE_SECRET_BYTES, &n);
	fde_bag_lock(t->uid);
	if (r < 0 || n != SEP_FDE_SECRET_BYTES) {
		sep_wipe(secret, SEP_FDE_SECRET_BYTES);
		return r == -ENODEV ? r : -EPERM;
	}
	return 0;
}

int fde_enroll_in_bag(uint32_t uid, const char *role, const char *pw, size_t pw_len,
		      const uint8_t secret[SEP_FDE_SECRET_BYTES], struct fde_token *t)
{
	uint8_t check[SEP_FDE_SECRET_BYTES];
	size_t n = 0;
	int r;

	memset(t, 0, sizeof(*t));
	t->offline_keyslot = -1;
	t->owner = -1;
	t->linux_uid = -1;
	t->uid = uid;
	snprintf(t->role, sizeof(t->role), "%s", role);
	r = fde_bag_unlock(uid, pw, pw_len);
	if (r)
		goto fail;
	r = fde_key_create(uid, &t->record, &t->record_len);
	if (r)
		goto fail;
	r = fde_seal(uid, t->record, t->record_len, secret, SEP_FDE_SECRET_BYTES,
		     &t->sealed, &t->sealed_len);
	if (r)
		goto fail;
	r = fde_unseal(uid, t->record, t->record_len, t->sealed, t->sealed_len,
		       check, sizeof(check), &n);
	if (!r && (n != SEP_FDE_SECRET_BYTES || memcmp(check, secret, n)))
		r = -EIO;
	sep_wipe(check, sizeof(check));
	if (r)
		goto fail;
	r = fde_bag_export(uid, &t->bag, &t->bag_len);
	if (r)
		goto fail;
	fde_bag_lock(uid);
	return 0;
fail:
	fde_bag_lock(uid);
	fde_token_free(t);
	return r;
}

int fde_enroll(uint32_t uid, const char *role, const char *pw, size_t pw_len,
	       const uint8_t secret[SEP_FDE_SECRET_BYTES], struct fde_token *t)
{
	int r;

	memset(t, 0, sizeof(*t));
	r = fde_bag_create(uid, pw, pw_len);
	if (r)
		return r;
	return fde_enroll_in_bag(uid, role, pw, pw_len, secret, t);
}
