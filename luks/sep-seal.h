/* SPDX-License-Identifier: MIT */
/*
 * Wrap a LUKS2 keyslot secret with a key sealed by the Apple Secure Enclave.
 *
 * The kernel's "trusted" key type, backed by the apple_sep driver's 'applesep'
 * source, holds a 32-byte AES key that only this Mac's SEP can unseal. The key
 * never reaches userspace: AF_ALG uses it by keyring serial
 * (ALG_SET_KEY_BY_KEY_SERIAL) to AES-256-GCM encrypt or decrypt the keyslot
 * secret.
 */
#ifndef AURORA_SEP_SEAL_H
#define AURORA_SEP_SEAL_H

#include <stddef.h>
#include <stdint.h>

#define SEP_SEAL_TOKEN_TYPE	"aurora-sep"
#define SEP_SEAL_VERSION	1
#define SEP_SEAL_KEY_BYTES	32
#define SEP_SEAL_IV_BYTES	12
#define SEP_SEAL_TAG_BYTES	16
/* Keyslot secret: 64 random bytes, handed to libcryptsetup as 128 hex chars. */
#define SEP_SEAL_SECRET_BYTES	64
#define SEP_SEAL_PASS_LEN	(2 * SEP_SEAL_SECRET_BYTES)
/* Upper bound on a sealed trusted-key blob in hex (MAX_BLOB_SIZE is 512). */
#define SEP_SEAL_BLOB_HEX_MAX	4096

/*
 * The key type is "trusted" in every installed build. The unit tests build the
 * same code with SEP_SEAL_TEST_USER_KEYS, which swaps in "user" keys whose
 * payload is the raw AES key, so the AF_ALG and LUKS2 paths run on any Linux.
 */
#ifdef SEP_SEAL_TEST_USER_KEYS
#define SEP_SEAL_KEY_TYPE	"user"
#else
#define SEP_SEAL_KEY_TYPE	"trusted"
#endif

/* Seconds to wait for the SEP trusted-key source to register at boot. */
#define SEP_SEAL_WAIT_DEFAULT	60

struct sep_sealed {
	char *blob_hex;				/* sealed AES key, from the kernel */
	uint8_t iv[SEP_SEAL_IV_BYTES];
	uint8_t *ct;				/* ciphertext || tag */
	size_t ct_len;
};

void sep_wipe(void *p, size_t n);
void sep_sealed_free(struct sep_sealed *s);

int sep_hex_encode(const uint8_t *in, size_t n, char *out, size_t out_size);
/* Returns decoded length, or -EINVAL. */
long sep_hex_decode(const char *in, uint8_t *out, size_t out_size);

/* Additional data that binds a token to one LUKS2 volume. */
int sep_seal_aad(const char *luks_uuid, char *out, size_t out_size);

/*
 * Ask the SEP for a fresh sealed AES key. On success *serial is a key in the
 * calling thread's keyring and *blob_hex the sealed blob (malloc'd).
 */
int sep_key_new(int32_t *serial, char **blob_hex);
/* Load a sealed blob; the SEP unseals it. Waits up to wait_s for the source. */
int sep_key_load(const char *blob_hex, int wait_s, int32_t *serial);
void sep_key_drop(int32_t serial);

/* AES-256-GCM through AF_ALG with the key referenced by serial. */
int sep_aead(int32_t serial, int encrypt, const uint8_t iv[SEP_SEAL_IV_BYTES],
	     const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t in_len,
	     uint8_t *out, size_t out_size, size_t *out_len);

/*
 * Seal: new SEP key, random IV, encrypt the secret, then prove the blob
 * unseals with a freshly loaded key before returning it.
 */
int sep_seal_secret(const char *aad, const uint8_t *secret, size_t secret_len,
		    struct sep_sealed *out);
/* Unseal into out (SEP_SEAL_SECRET_BYTES). */
int sep_unseal_secret(const char *aad, const struct sep_sealed *in, int wait_s,
		      uint8_t *out, size_t out_size, size_t *out_len);

/* Token JSON <-> struct. */
int sep_token_parse(const char *json, struct sep_sealed *out);
/* Returns malloc'd JSON (keyslot assigned later by libcryptsetup). */
char *sep_token_build(const struct sep_sealed *s);

#endif
