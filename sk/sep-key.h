/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note OR MIT */
/*
 * /dev/sep-key interface (versions 1 and 2), as in the Aurora kernel's
 * include/uapi/linux/apple-sep.h. Kept here so the provider builds without
 * the kernel headers installed; the sizes are checked at compile time.
 */
#ifndef AURORA_SEP_KEY_H
#define AURORA_SEP_KEY_H

#include <linux/ioctl.h>
#include <linux/types.h>

#ifndef SEP_KEY_IFACE_VERSION
#define SEP_KEY_IFACE_VERSION 1
#define SEP_KEY_HANDLE_MAX 2048
#define SEP_KEY_PUB_LEN    65
#define SEP_KEY_DIGEST_LEN 32
#define SEP_KEY_SIG_MAX    72

struct sep_key_info {
	__u32 version;
	__u32 flags_supported;
	__u32 handle_max;
	__u32 reserved;
};

struct sep_key_create {
	__u32 flags;
	__u32 handle_len;
	__u8  public_key[SEP_KEY_PUB_LEN];
	__u8  reserved[3];
	__u8  handle[SEP_KEY_HANDLE_MAX];
};

struct sep_key_sign {
	__u32 flags;
	__u32 handle_len;
	__u8  digest[SEP_KEY_DIGEST_LEN];
	__u32 sig_len;
	__u8  signature[SEP_KEY_SIG_MAX];
	__u8  handle[SEP_KEY_HANDLE_MAX];
};

struct sep_key_public {
	__u32 flags;
	__u32 handle_len;
	__u8  public_key[SEP_KEY_PUB_LEN];
	__u8  reserved[3];
	__u8  handle[SEP_KEY_HANDLE_MAX];
};

#define SEP_KEY_IOC_MAGIC 0xB1
#define SEP_KEY_GET_INFO _IOR(SEP_KEY_IOC_MAGIC, 0x20, struct sep_key_info)
#define SEP_KEY_CREATE   _IOWR(SEP_KEY_IOC_MAGIC, 0x21, struct sep_key_create)
#define SEP_KEY_SIGN     _IOWR(SEP_KEY_IOC_MAGIC, 0x22, struct sep_key_sign)
#define SEP_KEY_PUBLIC   _IOWR(SEP_KEY_IOC_MAGIC, 0x23, struct sep_key_public)
#endif

_Static_assert(sizeof(struct sep_key_info) == 16, "sep_key_info ABI");
_Static_assert(sizeof(struct sep_key_create) == 2124, "sep_key_create ABI");
_Static_assert(sizeof(struct sep_key_sign) == 2164, "sep_key_sign ABI");
_Static_assert(sizeof(struct sep_key_public) == 2124, "sep_key_public ABI");

#ifndef SEP_KEY_CREATE_BIOMETRY_CURRENT_SET
/* Version 2: signing needs a Touch ID match the enclave itself checks. */
#define SEP_KEY_CREATE_BIOMETRY_CURRENT_SET 0x1	/* fingers enrolled at creation */
#endif
#ifndef SEP_KEY_CREATE_BIOMETRY_ANY
#define SEP_KEY_CREATE_BIOMETRY_ANY 0x2		/* any enrolled finger, now or later */
#define SEP_KEY_CREATE_USER_PRESENCE 0x4	/* Touch ID or password (reserved) */
#define SEP_KEY_CREATE_DEVICE_PASSCODE 0x8	/* password only (reserved) */
#endif

#define SEP_KEY_DEVICE "/dev/sep-key"

#endif
