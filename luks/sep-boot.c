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
#include <syslog.h>
#include <sys/stat.h>

#include "sep-boot.h"

#define CONF_PATH	"/etc/aurora-sep/fde.conf"
#define PARAM_HI	"/sys/module/apple_sep/parameters/os_uuid_hi"
#define PARAM_LO	"/sys/module/apple_sep/parameters/os_uuid_lo"
#define CHOSEN_UUID	"/proc/device-tree/chosen/apfs-preboot-uuid"
#define CHAIN_DIR	"/sys/firmware/aurora/boot_security"
#define CHAIN_STATE	CHAIN_DIR "/state"
#define CHAIN_ADVISORY	CHAIN_DIR "/advisory"
#define CHAIN_MEAS	CHAIN_DIR "/measurements"
#define INITRD_RELEASE	"/etc/initrd-release"

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

/* The first measurement line ("stage policy component verdict sha256") that
 * is not an enforced, verified link, as "stage component (policy, verdict)". */
static void first_gap(char *out, size_t size)
{
	char full[4096], line[512];
	FILE *f;

	out[0] = '\0';
	path(full, sizeof(full), CHAIN_MEAS);
	f = fopen(full, "re");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		char stage[32], policy[16], comp[64], verdict[16];

		if (sscanf(line, "%31s %15s %63s %15s", stage, policy, comp, verdict) != 4)
			continue;
		if (!strcmp(policy, "enforce") && !strcmp(verdict, "verified"))
			continue;
		snprintf(out, size, "%s %s (%s, %s)", stage, comp, policy, verdict);
		break;
	}
	fclose(f);
}

void sep_boot_chain_read(struct sep_boot_chain *c)
{
	char buf[16];

	memset(c, 0, sizeof(*c));
	c->advisory = -1;
	if (sep_boot_chain_state(c->state, sizeof(c->state))) {
		snprintf(c->state, sizeof(c->state), "none");
		snprintf(c->first_gap, sizeof(c->first_gap),
			 "no boot record (the boot chain reports nothing from Stage 1 on)");
		return;
	}
	c->present = 1;
	if (read_small(CHAIN_ADVISORY, buf, sizeof(buf)) == 0 && (!strcmp(buf, "0") || !strcmp(buf, "1")))
		c->advisory = buf[0] == '1';
	c->verified = !strcmp(c->state, "verified") && c->advisory == 0;
	if (c->verified)
		return;
	first_gap(c->first_gap, sizeof(c->first_gap));
	if (!c->first_gap[0])
		snprintf(c->first_gap, sizeof(c->first_gap), "%s",
			 c->advisory ? "stage1 (not an enforcing Stage 1: the record is advisory)" :
				       "unknown (the record lists no unverified link)");
}

void sep_boot_conf_path(char *buf, size_t size)
{
	const char *conf = secure_getenv("AURORA_SEP_FDE_CONF");

	if (conf && *conf)
		snprintf(buf, size, "%s", conf);
	else
		path(buf, size, CONF_PATH);
}

/* The key of an fde.conf line ("key = value"), or NULL for comments. */
static const char *conf_key(const char *line, size_t *len)
{
	const char *k = line, *e;

	while (isspace((unsigned char)*k))
		k++;
	if (*k == '#' || !(e = strchr(k, '=')))
		return NULL;
	while (e > k && isspace((unsigned char)e[-1]))
		e--;
	*len = (size_t)(e - k);
	return k;
}

enum sep_boot_chain_policy sep_boot_chain_policy(void)
{
	enum sep_boot_chain_policy p = SEP_BOOT_CHAIN_AUDIT;
	char full[4096], line[512];
	FILE *f;

	sep_boot_conf_path(full, sizeof(full));
	f = fopen(full, "re");
	if (!f)
		return p;
	while (fgets(line, sizeof(line), f)) {
		size_t klen;
		const char *k = conf_key(line, &klen);
		char *v, *e;

		if (!k || klen != strlen("boot-chain") || strncmp(k, "boot-chain", klen))
			continue;
		v = strchr(line, '=') + 1;
		while (isspace((unsigned char)*v))
			v++;
		for (e = v + strlen(v); e > v && isspace((unsigned char)e[-1]); e--)
			;
		*e = '\0';
		p = !strcmp(v, "require") ? SEP_BOOT_CHAIN_REQUIRE : SEP_BOOT_CHAIN_AUDIT;
	}
	fclose(f);
	return p;
}

const char *sep_boot_chain_policy_name(enum sep_boot_chain_policy p)
{
	return p == SEP_BOOT_CHAIN_REQUIRE ? "require" : "audit";
}

int sep_boot_chain_policy_write(enum sep_boot_chain_policy p)
{
	char full[4096], tmp[4200], line[512];
	FILE *in, *out;
	int fd, done = 0, r = 0;

	sep_boot_conf_path(full, sizeof(full));
	snprintf(tmp, sizeof(tmp), "%s.XXXXXX", full);
	fd = mkostemp(tmp, O_CLOEXEC);
	if (fd < 0)
		return -errno;
	out = fdopen(fd, "w");
	if (!out) {
		r = -errno;
		close(fd);
		unlink(tmp);
		return r;
	}
	in = fopen(full, "re");
	while (in && fgets(line, sizeof(line), in)) {
		size_t klen;
		const char *k = conf_key(line, &klen);

		if (k && klen == strlen("boot-chain") && !strncmp(k, "boot-chain", klen)) {
			if (!done)
				fprintf(out, "boot-chain = %s\n", sep_boot_chain_policy_name(p));
			done = 1;
			continue;
		}
		fputs(line, out);
	}
	if (in)
		fclose(in);
	if (!done)
		fprintf(out, "boot-chain = %s\n", sep_boot_chain_policy_name(p));
	if (fflush(out) || fchmod(fd, 0644) || fsync(fd))
		r = -errno;
	if (fclose(out) && !r)
		r = -errno;
	if (!r && rename(tmp, full))
		r = -errno;
	if (r)
		unlink(tmp);
	return r;
}

int sep_boot_in_initrd(void)
{
	char full[4096];

	path(full, sizeof(full), INITRD_RELEASE);
	return access(full, F_OK) == 0;
}

int sep_boot_chain_gate(const char *volume, char *msg, size_t size)
{
	enum sep_boot_chain_policy p = sep_boot_chain_policy();
	struct sep_boot_chain c;

	msg[0] = '\0';
	sep_boot_chain_read(&c);
	if (c.verified)
		return 0;
	if (!volume || !*volume)
		volume = "this volume";
	if (p == SEP_BOOT_CHAIN_REQUIRE)
		snprintf(msg, size,
			 "aurora-sep: boot-chain = require: refused the Secure Enclave unlock of %s "
			 "(boot chain %s%s, first unverified link: %s); enter its passphrase or recovery key",
			 volume, c.state, c.advisory == 1 ? ", advisory" : "", c.first_gap);
	else
		snprintf(msg, size,
			 "aurora-sep: boot-chain = audit: require would refuse the Secure Enclave unlock of %s "
			 "(boot chain %s%s, first unverified link: %s); unlocking anyway",
			 volume, c.state, c.advisory == 1 ? ", advisory" : "", c.first_gap);
	return p == SEP_BOOT_CHAIN_REQUIRE ? -EPERM : 0;
}

void sep_boot_chain_log(const char *msg)
{
	openlog(SEP_BOOT_LOG_IDENT, LOG_PID, LOG_AUTH);
	syslog(LOG_WARNING, "%s", msg);
	closelog();
}
