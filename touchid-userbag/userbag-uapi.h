/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Build-time copy of the DRAFT key-bag ioctls in include/uapi/linux/apple-sep.h
 * on aurora-silicon/linux branch design/sep-user-keybag. Not a stable ABI.
 */
#ifndef AURORA_USERBAG_UAPI_H
#define AURORA_USERBAG_UAPI_H

#include <linux/ioctl.h>
#include <linux/types.h>

#ifndef SEP_BIO_KEYBAG_STATE
#define SEP_KEYBAG_SECRET_MAX 256

struct sep_keybag_unlock {
	__u32 uid;
	__u32 secret_len;
	__u8  secret[SEP_KEYBAG_SECRET_MAX];
};

#define SEP_KEYBAG_LOCK_SCREEN  1
#define SEP_KEYBAG_LOCK_SUSPEND 2
#define SEP_KEYBAG_LOCK_LOGOUT  3

struct sep_keybag_lock {
	__u32 uid;
	__u32 reason;
	__u32 grace_s;
	__u32 reserved;
};

struct sep_keybag_state {
	__u32 uid;
	__u32 bag_state;
	__u32 biometry;
	__u32 failed_matches;
	__u64 since_password_s;
	__u64 since_unlock_s;
	__u32 enclave_lock_state;
	__u32 reserved;
};

struct sep_keybag_change {
	__u32 uid;
	__u32 old_len;
	__u32 new_len;
	__u32 reserved;
	__u8  old_secret[SEP_KEYBAG_SECRET_MAX];
	__u8  new_secret[SEP_KEYBAG_SECRET_MAX];
};

#define SEP_BIO_KEYBAG_STATE  _IOWR(0xB1, 0x10, struct sep_keybag_state)
#define SEP_BIO_KEYBAG_UNLOCK _IOW(0xB1, 0x11, struct sep_keybag_unlock)
#define SEP_BIO_KEYBAG_LOCK   _IOW(0xB1, 0x12, struct sep_keybag_lock)
#define SEP_BIO_KEYBAG_CHANGE _IOW(0xB1, 0x13, struct sep_keybag_change)
#define SEP_BIO_KEYBAG_CREATE _IOW(0xB1, 0x14, struct sep_keybag_unlock)
#endif

#ifndef USERBAG_DEVICE
#define USERBAG_DEVICE "/dev/sep-bio-rearm"
#endif

#endif
