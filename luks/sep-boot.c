// SPDX-License-Identifier: MIT
/* Boot facts for the disk-key policy. See sep-boot.h. */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "sep-boot.h"

#define CONF_PATH	"/etc/aurora-sep/fde.conf"
#define PARAM_HI	"/sys/module/apple_sep/parameters/os_uuid_hi"
#define PARAM_LO	"/sys/module/apple_sep/parameters/os_uuid_lo"
#define CHOSEN_UUID	"/proc/device-tree/chosen/apfs-preboot-uuid"
#define CHAIN_STATE	"/sys/firmware/aurora/boot_security/state"
#define INITRD_RELEASE	"/etc/initrd-release"
#define WARNED		"/run/aurora-sep/boot-chain-warned"

static void path(char *buf, size_t n, const char *p)
{
	const char *root = secure_getenv("AURORA_SEP_FDE_ROOT");

	snprintf(buf, n, "%s%s", root ? root : "", p);
}

static int read_small(const char *p, char *buf, size_t size)
{
	char full[4096];
	ssize_t n;
	int fd;

	path(full, sizeof(full), p);
	fd = open(full, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	n = read(fd, buf, size - 1);
	close(fd);
	if (n < 0)
		return -EIO;
	buf[n] = '\0';
	/* device-tree strings end in NUL; sysfs values in a newline */
	while (n > 0 && (buf[n - 1] == '\0' || isspace((unsigned char)buf[n - 1])))
		buf[--n] = '\0';
	return n ? 0 : -ENOENT;
}

static int read_u64(const char *p, uint64_t *v)
{
	char buf[32], *end;
	int r = read_small(p, buf, sizeof(buf));

	if (r)
		return r;
	errno = 0;
	*v = strtoull(buf, &end, 0);
	return errno || *end ? -EINVAL : 0;
}

static int canonical_uuid(const char *in, char out[SEP_BOOT_UUID_LEN + 1])
{
	if (strlen(in) != SEP_BOOT_UUID_LEN)
		return -EINVAL;
	for (int i = 0; i < SEP_BOOT_UUID_LEN; i++) {
		int dash = i == 8 || i == 13 || i == 18 || i == 23;

		if (dash ? in[i] != '-' : !isxdigit((unsigned char)in[i]))
			return -EINVAL;
		out[i] = (char)tolower((unsigned char)in[i]);
	}
	out[SEP_BOOT_UUID_LEN] = '\0';
	return 0;
}

int sep_boot_os_uuid(char out[SEP_BOOT_UUID_LEN + 1])
{
	uint64_t hi = 0, lo = 0;
	char buf[128];

	/* The driver's order: an explicit pin (either half non-zero) wins. */
	if (read_u64(PARAM_HI, &hi) == 0 && read_u64(PARAM_LO, &lo) == 0 && (hi || lo)) {
		uint8_t b[16];

		for (int i = 0; i < 8; i++) {
			b[i] = (uint8_t)(hi >> (56 - 8 * i));
			b[8 + i] = (uint8_t)(lo >> (56 - 8 * i));
		}
		snprintf(out, SEP_BOOT_UUID_LEN + 1,
			 "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			 b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11],
			 b[12], b[13], b[14], b[15]);
		return 0;
	}
	if (read_small(CHOSEN_UUID, buf, sizeof(buf)) == 0 && canonical_uuid(buf, out) == 0)
		return 0;
	return -ENOENT;
}

int sep_boot_chain_state(char *out, size_t size)
{
	return read_small(CHAIN_STATE, out, size);
}

enum sep_boot_chain_policy sep_boot_chain_policy(void)
{
	const char *conf = secure_getenv("AURORA_SEP_FDE_CONF");
	enum sep_boot_chain_policy p = SEP_BOOT_CHAIN_WARN;
	char full[4096], line[512];
	FILE *f;

	if (conf && *conf)
		snprintf(full, sizeof(full), "%s", conf);
	else
		path(full, sizeof(full), CONF_PATH);
	f = fopen(full, "re");
	if (!f)
		return p;
	while (fgets(line, sizeof(line), f)) {
		char *k = line, *v, *e;

		while (isspace((unsigned char)*k))
			k++;
		if (*k == '#' || !(v = strchr(k, '=')))
			continue;
		for (e = v; e > k && isspace((unsigned char)e[-1]); e--)
			;
		*e = '\0';
		v++;
		while (isspace((unsigned char)*v))
			v++;
		for (e = v + strlen(v); e > v && isspace((unsigned char)e[-1]); e--)
			;
		*e = '\0';
		if (strcmp(k, "boot-chain"))
			continue;
		p = !strcmp(v, "require") ? SEP_BOOT_CHAIN_REQUIRE : SEP_BOOT_CHAIN_WARN;
	}
	fclose(f);
	return p;
}

const char *sep_boot_chain_policy_name(enum sep_boot_chain_policy p)
{
	return p == SEP_BOOT_CHAIN_REQUIRE ? "require" : "warn";
}

int sep_boot_in_initrd(void)
{
	char full[4096];

	path(full, sizeof(full), INITRD_RELEASE);
	return access(full, F_OK) == 0;
}

/* 1 the first time this boot; the marker lives in /run (a tmpfs per boot). */
static int first_time(void)
{
	char dir[4096], full[4096];
	int fd;

	path(dir, sizeof(dir), "/run");
	mkdir(dir, 0755);	/* there on a real system; a test root may lack it */
	path(dir, sizeof(dir), "/run/aurora-sep");
	path(full, sizeof(full), WARNED);
	mkdir(dir, 0755);
	fd = open(full, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
	if (fd < 0)
		return errno != EEXIST;	/* no /run at all: log every time */
	close(fd);
	return 1;
}

int sep_boot_chain_gate(char *msg, size_t size, int *first)
{
	enum sep_boot_chain_policy p = sep_boot_chain_policy();
	char state[64];

	msg[0] = '\0';
	*first = 0;
	if (sep_boot_chain_state(state, sizeof(state)))
		snprintf(state, sizeof(state), "unknown");
	if (!strcmp(state, "verified"))
		return 0;
	*first = first_time();
	if (p == SEP_BOOT_CHAIN_REQUIRE) {
		snprintf(msg, size,
			 "aurora-sep: boot chain %s, and boot-chain = require: the Secure Enclave "
			 "will not unlock this volume; enter its passphrase or recovery key",
			 state);
		return -EPERM;
	}
	snprintf(msg, size,
		 "aurora-sep: warning: boot chain %s (not verified from Stage 1 on); unlocking "
		 "with the Secure Enclave anyway (boot-chain = warn)",
		 state);
	return 0;
}
