// SPDX-License-Identifier: MIT
/*
 * OpenSSH security-key provider for keys that live in the Apple Secure
 * Enclave (/dev/sep-key, Aurora kernels).
 *
 *   ssh-keygen -t ecdsa-sk -w /usr/lib64/libaurora-sep-sk.so
 *
 * The enclave creates a P-256 key and keeps the private half. The opaque
 * handle the kernel returns becomes the security-key "key handle", which
 * OpenSSH stores in the private key file and hands back for every signature.
 * The handle works only on the Mac that made it.
 *
 * Signatures follow the FIDO/U2F layout OpenSSH verifies for
 * sk-ecdsa-sha2-nistp256@openssh.com:
 *   ECDSA-P256( SHA-256( SHA-256(application) || flags || counter || SHA-256(data) ) )
 * The enclave signs that outer digest.
 *
 * User presence: on a kernel with /dev/sep-key version 2, a key that asks for
 * presence or verification (the default for ecdsa-sk keys) is made with
 * SEP_KEY_CREATE_BIOMETRY_CURRENT_SET. The enclave then refuses every
 * signature without a fresh Touch ID match of a currently enrolled finger,
 * which the kernel runs inside the sign call. On a version 1 kernel the
 * provider falls back to asking fprintd-verify on the host, which root can
 * bypass. docs/ssh-sk.md has the details.
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "sk-api.h"
#include "sep-key.h"

#define SK_EXPORT __attribute__((visibility("default")))

static void dbg(const char *fmt, ...)
{
	va_list ap;

	if (!getenv("AURORA_SEP_SK_DEBUG"))
		return;
	va_start(ap, fmt);
	fputs("aurora-sep-sk: ", stderr);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
}

static void say(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fputs("aurora-sep-sk: ", stderr);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
}

static int sha256(const void *a, size_t alen, uint8_t out[32])
{
	unsigned int n = 32;

	return EVP_Digest(a, alen, out, &n, EVP_sha256(), NULL) == 1 && n == 32 ? 0 : -1;
}

/* ---------- backend: the enclave, or software keys in test builds ---------- */

#ifndef AURORA_SEP_SK_TEST

static int open_device(void)
{
	const char *path = getenv("AURORA_SEP_SK_DEVICE");
	int fd = open(path && *path ? path : SEP_KEY_DEVICE, O_RDWR | O_CLOEXEC);

	if (fd < 0)
		dbg("open %s: %s", path && *path ? path : SEP_KEY_DEVICE, strerror(errno));
	return fd;
}

static int device_error(int err)
{
	switch (err) {
	case ENOENT:
	case ENODEV:
	case ENXIO:
		return SSH_SK_ERR_DEVICE_NOT_FOUND;
	case EKEYREJECTED:
		say("the Secure Enclave refused this key: it was made on another Mac or by an earlier Linux install");
		return SSH_SK_ERR_GENERAL;
	case EACCES:
	case EPERM:
		say("no access to %s (is your user in the sep-key group?)", SEP_KEY_DEVICE);
		return SSH_SK_ERR_DEVICE_NOT_FOUND;
	default:
		return SSH_SK_ERR_GENERAL;
	}
}

/* SEP_KEY_CREATE_* bits the kernel accepts; 0 on a version 1 kernel. */
static uint32_t backend_create_flags(void)
{
	struct sep_key_info info = { 0 };
	int fd = open_device();

	if (fd < 0)
		return 0;
	if (ioctl(fd, SEP_KEY_GET_INFO, &info) != 0)
		info.flags_supported = 0;
	close(fd);
	return info.version >= 2 ? info.flags_supported : 0;
}

static int backend_create(uint8_t pub[SEP_KEY_PUB_LEN], uint8_t **handle, size_t *handle_len,
			  uint32_t flags)
{
	struct sep_key_create *req;
	int fd, ret;

	fd = open_device();
	if (fd < 0)
		return device_error(errno);
	req = calloc(1, sizeof(*req));
	if (!req) {
		close(fd);
		return SSH_SK_ERR_GENERAL;
	}
	req->flags = flags;
	if (ioctl(fd, SEP_KEY_CREATE, req) != 0) {
		ret = device_error(errno);
		dbg("SEP_KEY_CREATE: %s", strerror(errno));
		goto out;
	}
	if (req->handle_len == 0 || req->handle_len > SEP_KEY_HANDLE_MAX ||
	    req->public_key[0] != 0x04) {
		ret = SSH_SK_ERR_GENERAL;
		goto out;
	}
	*handle = malloc(req->handle_len);
	if (!*handle) {
		ret = SSH_SK_ERR_GENERAL;
		goto out;
	}
	memcpy(*handle, req->handle, req->handle_len);
	*handle_len = req->handle_len;
	memcpy(pub, req->public_key, SEP_KEY_PUB_LEN);
	ret = 0;
out:
	free(req);
	close(fd);
	return ret;
}

static int backend_sign(const uint8_t *handle, size_t handle_len, const uint8_t digest[32],
			uint8_t *der, size_t *der_len)
{
	struct sep_key_sign *req;
	int fd, ret;

	if (handle_len == 0 || handle_len > SEP_KEY_HANDLE_MAX)
		return SSH_SK_ERR_GENERAL;
	fd = open_device();
	if (fd < 0)
		return device_error(errno);
	req = calloc(1, sizeof(*req));
	if (!req) {
		close(fd);
		return SSH_SK_ERR_GENERAL;
	}
	req->handle_len = (uint32_t)handle_len;
	memcpy(req->handle, handle, handle_len);
	memcpy(req->digest, digest, 32);
	if (ioctl(fd, SEP_KEY_SIGN, req) != 0) {
		if (errno == EACCES)
			say("no Touch ID match; the Secure Enclave did not sign");
		else if (errno == ETIMEDOUT)
			say("no touch in time; the Secure Enclave did not sign");
		ret = device_error(errno);
		dbg("SEP_KEY_SIGN: %s", strerror(errno));
		goto out;
	}
	if (req->sig_len == 0 || req->sig_len > SEP_KEY_SIG_MAX) {
		ret = SSH_SK_ERR_GENERAL;
		goto out;
	}
	memcpy(der, req->signature, req->sig_len);
	*der_len = req->sig_len;
	ret = 0;
out:
	free(req);
	close(fd);
	return ret;
}

#else /* AURORA_SEP_SK_TEST: software P-256 keys stand in for the enclave */

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/param_build.h>

/* Test handle: "TSTK" || private scalar (32) || public point (65). Never shipped. */
#define TEST_HANDLE_LEN (4 + 32 + SEP_KEY_PUB_LEN)

static uint32_t backend_create_flags(void)
{
	return 0;
}

static int backend_create(uint8_t pub[SEP_KEY_PUB_LEN], uint8_t **handle, size_t *handle_len,
			  uint32_t flags)
{
	EVP_PKEY *pkey = EVP_EC_gen("P-256");
	BIGNUM *priv = NULL;
	size_t publen = 0;
	uint8_t *h = NULL;
	int ret = SSH_SK_ERR_GENERAL;

	(void)flags;
	if (!pkey)
		return ret;
	if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, pub,
					     SEP_KEY_PUB_LEN, &publen) || publen != SEP_KEY_PUB_LEN)
		goto out;
	if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv))
		goto out;
	h = calloc(1, TEST_HANDLE_LEN);
	if (!h || BN_bn2binpad(priv, h + 4, 32) != 32)
		goto out;
	memcpy(h, "TSTK", 4);
	memcpy(h + 36, pub, SEP_KEY_PUB_LEN);
	*handle = h;
	*handle_len = TEST_HANDLE_LEN;
	h = NULL;
	ret = 0;
out:
	free(h);
	BN_clear_free(priv);
	EVP_PKEY_free(pkey);
	return ret;
}

static int backend_sign(const uint8_t *handle, size_t handle_len, const uint8_t digest[32],
			uint8_t *der, size_t *der_len)
{
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	BIGNUM *priv = NULL;
	size_t len = SEP_KEY_SIG_MAX;
	int ret = SSH_SK_ERR_GENERAL;

	if (getenv("AURORA_SEP_SK_TEST_REJECT"))
		return SSH_SK_ERR_GENERAL; /* stands in for EKEYREJECTED */
	if (handle_len != TEST_HANDLE_LEN || memcmp(handle, "TSTK", 4) != 0)
		return ret;
	priv = BN_bin2bn(handle + 4, 32, NULL);
	bld = OSSL_PARAM_BLD_new();
	if (!priv || !bld ||
	    !OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "P-256", 0) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, priv) ||
	    !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, handle + 36,
					      SEP_KEY_PUB_LEN))
		goto out;
	params = OSSL_PARAM_BLD_to_param(bld);
	ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (!params || !ctx || EVP_PKEY_fromdata_init(ctx) <= 0 ||
	    EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0)
		goto out;
	EVP_PKEY_CTX_free(ctx);
	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!ctx || EVP_PKEY_sign_init(ctx) <= 0 ||
	    EVP_PKEY_sign(ctx, der, &len, digest, 32) <= 0)
		goto out;
	*der_len = len;
	ret = 0;
out:
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	BN_clear_free(priv);
	return ret;
}

#endif

/* ---------- user presence ---------- */

/*
 * Whether the handle is a /dev/sep-key version 2 biometric key: the enclave
 * itself refuses to sign without a fresh Touch ID match, so no host check is
 * needed. Handle layout: "SEPK", version, flags (bit 0), ...
 */
static int enclave_enforced(const uint8_t *handle, size_t len)
{
	return len > 12 && memcmp(handle, "SEPK", 4) == 0 && handle[4] == 1 && (handle[5] & 1);
}

/*
 * 0 when presence was shown, -1 when it was refused or could not be asked.
 * AURORA_SEP_SK_PRESENCE: unset or "fprintd" asks fprintd-verify; "deny"
 * refuses; test builds also accept "test-allow".
 */
static int ask_presence(const char *application)
{
	const char *mode = getenv("AURORA_SEP_SK_PRESENCE");
	int status, devnull;
	pid_t pid;

	if (mode && strcmp(mode, "deny") == 0)
		return -1;
#ifdef AURORA_SEP_SK_TEST
	if (mode && strcmp(mode, "test-allow") == 0)
		return 0;
#endif
	if (mode && *mode && strcmp(mode, "fprintd") != 0) {
		say("unknown AURORA_SEP_SK_PRESENCE=%s; refusing", mode);
		return -1;
	}
	say("touch Touch ID to sign with your Secure Enclave key (%s)", application);
	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		devnull = open("/dev/null", O_RDWR);
		if (devnull >= 0) {
			dup2(devnull, 0);
			dup2(devnull, 1);
		}
		execlp("fprintd-verify", "fprintd-verify", (char *)NULL);
		_exit(127);
	}
	while (waitpid(pid, &status, 0) < 0) {
		if (errno != EINTR)
			return -1;
	}
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
		return 0;
	say("no Touch ID match; not signing");
	return -1;
}

/* ---------- DER signature to raw r, s ---------- */

static int der_int(const uint8_t **p, const uint8_t *end, uint8_t **out, size_t *out_len)
{
	size_t len;

	if (end - *p < 2 || (*p)[0] != 0x02)
		return -1;
	len = (*p)[1];
	*p += 2;
	if (len == 0 || len > 33 || (size_t)(end - *p) < len)
		return -1;
	while (len > 1 && (*p)[0] == 0x00) {
		(*p)++;
		len--;
	}
	*out = malloc(len);
	if (!*out)
		return -1;
	memcpy(*out, *p, len);
	*out_len = len;
	*p += len;
	return 0;
}

static int split_der_sig(const uint8_t *der, size_t der_len, struct sk_sign_response *r)
{
	const uint8_t *p = der, *end = der + der_len;

	if (der_len < 8 || p[0] != 0x30 || p[1] != der_len - 2)
		return -1;
	p += 2;
	if (der_int(&p, end, &r->sig_r, &r->sig_r_len) != 0 ||
	    der_int(&p, end, &r->sig_s, &r->sig_s_len) != 0 || p != end)
		return -1;
	return 0;
}

/* ---------- OpenSSH middleware ABI ---------- */

SK_EXPORT uint32_t sk_api_version(void)
{
	return SSH_SK_VERSION_MAJOR;
}

SK_EXPORT int sk_enroll(uint32_t alg, const uint8_t *challenge, size_t challenge_len,
			const char *application, uint8_t flags, const char *pin,
			struct sk_option **options, struct sk_enroll_response **enroll_response)
{
	struct sk_enroll_response *resp;
	uint8_t pub[SEP_KEY_PUB_LEN];
	uint32_t kflags;
	int ret;

	(void)challenge;
	(void)challenge_len;
	(void)pin;
	(void)options;
	if (!enroll_response || !application)
		return SSH_SK_ERR_GENERAL;
	*enroll_response = NULL;
	if (alg != SSH_SK_ECDSA) {
		say("the Secure Enclave makes P-256 keys only: use ssh-keygen -t ecdsa-sk");
		return SSH_SK_ERR_UNSUPPORTED;
	}
	if (flags & SSH_SK_RESIDENT_KEY) {
		say("resident keys are not supported; the key handle lives in the key file");
		return SSH_SK_ERR_UNSUPPORTED;
	}
	resp = calloc(1, sizeof(*resp));
	if (!resp)
		return SSH_SK_ERR_GENERAL;
	/*
	 * A key that wants presence or verification gets the enclave-enforced
	 * Touch ID policy when the kernel offers it.
	 */
	kflags = 0;
	if ((flags & (SSH_SK_USER_PRESENCE_REQD | SSH_SK_USER_VERIFICATION_REQD)) &&
	    (backend_create_flags() & SEP_KEY_CREATE_BIOMETRY_CURRENT_SET))
		kflags = SEP_KEY_CREATE_BIOMETRY_CURRENT_SET;
	ret = backend_create(pub, &resp->key_handle, &resp->key_handle_len, kflags);
	if (ret != 0) {
		free(resp);
		return ret;
	}
	resp->public_key = malloc(SEP_KEY_PUB_LEN);
	if (!resp->public_key) {
		free(resp->key_handle);
		free(resp);
		return SSH_SK_ERR_GENERAL;
	}
	memcpy(resp->public_key, pub, SEP_KEY_PUB_LEN);
	resp->public_key_len = SEP_KEY_PUB_LEN;
	/* What every signature will ask for: presence and/or verification. */
	resp->flags = flags & (SSH_SK_USER_PRESENCE_REQD | SSH_SK_USER_VERIFICATION_REQD);
	dbg("enrolled %s, handle %zu bytes, flags 0x%02x, %s", application,
	    resp->key_handle_len, resp->flags,
	    kflags ? "Touch ID enforced by the Secure Enclave" : "no enclave policy");
	*enroll_response = resp;
	return 0;
}

SK_EXPORT int sk_sign(uint32_t alg, const uint8_t *data, size_t data_len,
		      const char *application, const uint8_t *key_handle, size_t key_handle_len,
		      uint8_t flags, const char *pin, struct sk_option **options,
		      struct sk_sign_response **sign_response)
{
	uint8_t apphash[32], msghash[32], signed_data[32 + 1 + 4 + 32], digest[32];
	uint8_t der[SEP_KEY_SIG_MAX];
	struct sk_sign_response *resp;
	uint8_t sig_flags = 0;
	size_t der_len = 0;
	int ret;

	(void)pin;
	(void)options;
	if (!sign_response || !application || !key_handle)
		return SSH_SK_ERR_GENERAL;
	*sign_response = NULL;
	if (alg != SSH_SK_ECDSA)
		return SSH_SK_ERR_UNSUPPORTED;
	if (flags & (SSH_SK_USER_PRESENCE_REQD | SSH_SK_USER_VERIFICATION_REQD)) {
		if (enclave_enforced(key_handle, key_handle_len)) {
			const char *mode = getenv("AURORA_SEP_SK_PRESENCE");

			if (mode && strcmp(mode, "deny") == 0)
				return SSH_SK_ERR_GENERAL;
			say("touch Touch ID to sign with your Secure Enclave key (%s)", application);
		} else if (ask_presence(application) != 0) {
			return SSH_SK_ERR_GENERAL;
		}
		sig_flags = flags & (SSH_SK_USER_PRESENCE_REQD | SSH_SK_USER_VERIFICATION_REQD);
	}
	if (sha256(application, strlen(application), apphash) != 0 ||
	    sha256(data, data_len, msghash) != 0)
		return SSH_SK_ERR_GENERAL;
	/* No signature counter: the enclave keeps none for these keys. */
	memcpy(signed_data, apphash, 32);
	signed_data[32] = sig_flags;
	memset(signed_data + 33, 0, 4);
	memcpy(signed_data + 37, msghash, 32);
	if (sha256(signed_data, sizeof(signed_data), digest) != 0)
		return SSH_SK_ERR_GENERAL;

	ret = backend_sign(key_handle, key_handle_len, digest, der, &der_len);
	if (ret != 0)
		return ret;
	resp = calloc(1, sizeof(*resp));
	if (!resp)
		return SSH_SK_ERR_GENERAL;
	if (split_der_sig(der, der_len, resp) != 0) {
		free(resp->sig_r);
		free(resp->sig_s);
		free(resp);
		return SSH_SK_ERR_GENERAL;
	}
	resp->flags = sig_flags;
	resp->counter = 0;
	dbg("signed for %s, flags 0x%02x", application, sig_flags);
	*sign_response = resp;
	return 0;
}

SK_EXPORT int sk_load_resident_keys(const char *pin, struct sk_option **options,
				    struct sk_resident_key ***rks, size_t *nrks)
{
	(void)pin;
	(void)options;
	if (rks)
		*rks = NULL;
	if (nrks)
		*nrks = 0;
	return SSH_SK_ERR_UNSUPPORTED;
}
