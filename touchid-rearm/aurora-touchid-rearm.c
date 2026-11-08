// SPDX-License-Identifier: GPL-2.0-only
/*
 * aurora-touchid-rearm: end a Touch ID lockout after a password
 * authentication.
 *
 * systemd starts one per connection to /run/aurora-touchid-rearm.sock
 * (aurora-touchid-rearm.socket), with the connection on stdin and stdout.
 * pam_aurora_touchid connects after pam_unix has accepted a password and sends
 * the user and that password (rearm-proto.h). This program trusts neither:
 *
 *  - Touch ID must be locked, or the driver must ask for every password
 *    (SEP_BIO_LOCKOUT_FLAG_EVERY_PASSWORD) and either failed matches are
 *    pending or the caller is root; otherwise it answers at once and checks
 *    nothing, so the socket is no new password oracle for users while Touch
 *    ID works. A password clears pending failed matches and restarts the
 *    driver's password clock (Touch ID asks for the password again after 156
 *    hours without one), as a password does on macOS.
 *  - The caller must be root or the user named.
 *  - The user must have enrolled fingerprints with fprintd.
 *  - The password must verify through the "aurora-touchid-rearm" PAM service,
 *    which is pam_unix alone.
 *
 * Only then does it ask the apple_sep driver to re-arm Touch ID
 * (SEP_BIO_REARM on /dev/sep-bio-rearm, root only). Lock screens that run
 * PAM as the user, such as Plasma's, can re-arm only through here.
 *
 * Two more modes, both for root:
 *
 *  --boot    aurora-touchid-boot.service runs it once per boot, before any
 *            login. With "require_password_after_boot = yes" in
 *            /etc/aurora/touchid.conf it asks the driver to refuse Touch ID
 *            until the first password since boot (SEP_BIO_REQUIRE_PASSWORD),
 *            as macOS does after a restart. That is the default, also when
 *            the file or the key is missing; "no" leaves Touch ID working
 *            from the first login.
 *  --status  prints what the driver reports: locked or not, why, and the
 *            failed matches since the last match or password.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <syslog.h>
#include <unistd.h>

#include <security/pam_appl.h>

#include "rearm-proto.h"

#ifndef SEP_BIO_LOCKOUT_STATE
#include <linux/ioctl.h>
#include <linux/types.h>
struct sep_bio_lockout {
	__u32 locked;
	__u32 failures;
	__u32 reason;
	__u32 flags;
};
#define SEP_BIO_LOCKOUT_STATE _IOR(0xB1, 0x0e, struct sep_bio_lockout)
#endif
#ifndef SEP_BIO_LOCKOUT_FLAG_EVERY_PASSWORD
#define SEP_BIO_LOCKOUT_FLAG_EVERY_PASSWORD 1
#endif
#ifndef SEP_BIO_LOCKOUT_FLAG_AFTER_BOOT
#define SEP_BIO_LOCKOUT_FLAG_AFTER_BOOT 2
#endif
#ifndef SEP_BIO_REQUIRE_PASSWORD
#define SEP_BIO_REQUIRE_PASSWORD _IO(0xB1, 0x10)
#endif

#ifndef SEP_BIO_REARM_SECRET_MAX
#define SEP_BIO_REARM_SECRET_MAX 1024
struct sep_bio_rearm {
	__u32 secret_len;
	__u32 reserved;
	__u8 secret[SEP_BIO_REARM_SECRET_MAX];
};
#endif

#ifdef SEP_BIO_REARM
#undef SEP_BIO_REARM
#endif
#define SEP_BIO_REARM _IOW(0xB1, 0x0f, struct sep_bio_rearm)

#define SERVICE        "aurora-touchid-rearm"
#define REARM_DEVICE   "/dev/sep-bio-rearm"
#define FPRINT_DIR     "/var/lib/fprint"
#define CONF_FILE      "/etc/aurora/touchid.conf"
/* How long --boot waits for the driver to register its re-arm node. */
#define BOOT_WAIT_S    30

enum lock_state { NOT_LOCKED, LOCKED, NO_DEVICE, STATE_ERROR };

#ifdef AURORA_REARM_TEST
/*
 * Test build only: the device is a state file holding "locked" or
 * "unlocked", optionally followed by the failed-match count and the driver's
 * flags ("unlocked 2 1"), re-arming writes "rearmed", PAM reads its stacks
 * from $AURORA_REARM_TEST_CONFDIR, and $AURORA_REARM_TEST_PEER stands in for
 * the caller's uid. The installed program has none of this.
 */
static const char *test_env(const char *name, const char *fallback)
{
	const char *v = getenv(name);

	return v && *v ? v : fallback;
}

static enum lock_state lockout_state(unsigned *failures, unsigned *flags)
{
	char buf[32] = "";
	FILE *f = fopen(test_env("AURORA_REARM_TEST_DEVICE", REARM_DEVICE), "r");

	*failures = 0;
	*flags = 0;
	if (!f)
		return NO_DEVICE;
	if (!fgets(buf, sizeof(buf), f))
		buf[0] = '\0';
	fclose(f);
	if (strncmp(buf, "unlocked ", 9) == 0) {
		char *end;

		*failures = (unsigned)strtoul(buf + 9, &end, 10);
		*flags = (unsigned)strtoul(end, NULL, 10);
	}
	/* "required": the driver waits for the first password since boot. */
	if (strncmp(buf, "required", 8) == 0) {
		*flags = SEP_BIO_LOCKOUT_FLAG_EVERY_PASSWORD | SEP_BIO_LOCKOUT_FLAG_AFTER_BOOT;
		return LOCKED;
	}
	return strncmp(buf, "locked", 6) == 0 ? LOCKED : NOT_LOCKED;
}

/* "old-driver" in the device file stands in for a kernel without the ioctl. */
static int require_password(void)
{
	char buf[32] = "";
	const char *path = test_env("AURORA_REARM_TEST_DEVICE", REARM_DEVICE);
	FILE *f = fopen(path, "r");

	if (!f)
		return -1;
	if (!fgets(buf, sizeof(buf), f))
		buf[0] = '\0';
	fclose(f);
	if (strncmp(buf, "old-driver", 10) == 0) {
		errno = ENOTTY;
		return -1;
	}
	f = fopen(path, "w");
	if (!f)
		return -1;
	fputs("required\n", f);
	return fclose(f);
}

static const char *device_path(void)
{
	return test_env("AURORA_REARM_TEST_DEVICE", REARM_DEVICE);
}

#define conf_file() test_env("AURORA_REARM_TEST_CONF", CONF_FILE)

static uid_t peer_uid(uid_t peer)
{
	const char *v = getenv("AURORA_REARM_TEST_PEER");

	return v && *v ? (uid_t)strtoul(v, NULL, 10) : peer;
}

static int rearm(const char *password)
{
	FILE *f = fopen(test_env("AURORA_REARM_TEST_DEVICE", REARM_DEVICE), "w");

	(void)password;
	if (!f)
		return -1;
	fputs("rearmed\n", f);
	return fclose(f);
}

static int pam_open(const char *user, const struct pam_conv *conv, pam_handle_t **h)
{
	return pam_start_confdir(SERVICE, user, conv,
				 test_env("AURORA_REARM_TEST_CONFDIR", NULL), h);
}

#define fprint_dir() test_env("AURORA_REARM_TEST_FPRINT_DIR", FPRINT_DIR)
#else
static enum lock_state lockout_state(unsigned *failures, unsigned *flags)
{
	struct sep_bio_lockout st = { 0 };
	int fd = open(REARM_DEVICE, O_RDONLY | O_CLOEXEC);
	int ret;

	*failures = 0;
	*flags = 0;
	if (fd < 0)
		return errno == ENOENT ? NO_DEVICE : STATE_ERROR;
	ret = ioctl(fd, SEP_BIO_LOCKOUT_STATE, &st);
	close(fd);
	if (ret < 0)
		return STATE_ERROR;
	*failures = st.failures;
	*flags = st.flags;
	return st.locked ? LOCKED : NOT_LOCKED;
}

#define peer_uid(peer) (peer)

static int rearm(const char *password)
{
	struct sep_bio_rearm request = { 0 };
	size_t len = strlen(password);
	int fd;
	int ret, saved;

	if (len == 0 || len > sizeof(request.secret)) {
		errno = EINVAL;
		return -1;
	}
	request.secret_len = (__u32)len;
	memcpy(request.secret, password, len);
	fd = open(REARM_DEVICE, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		ret = -1;
	else
		ret = ioctl(fd, SEP_BIO_REARM, &request);
	saved = errno;
	if (fd >= 0)
		close(fd);
	explicit_bzero(&request, sizeof(request));
	errno = saved;
	return ret;
}

static int pam_open(const char *user, const struct pam_conv *conv, pam_handle_t **h)
{
	return pam_start(SERVICE, user, conv, h);
}

static int require_password(void)
{
	int fd = open(REARM_DEVICE, O_RDONLY | O_CLOEXEC);
	int ret, saved;

	if (fd < 0)
		return -1;
	ret = ioctl(fd, SEP_BIO_REQUIRE_PASSWORD);
	saved = errno;
	close(fd);
	errno = saved;
	return ret;
}

static const char *device_path(void)
{
	return REARM_DEVICE;
}

#define fprint_dir() FPRINT_DIR
#define conf_file() CONF_FILE
#endif

static void answer(const char *line)
{
	size_t len = strlen(line);

	while (len > 0) {
		ssize_t n = write(STDOUT_FILENO, line, len);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return;
		line += n;
		len -= (size_t)n;
	}
}

/* A name fprintd could have made a directory of. */
static int plausible_user(const char *user)
{
	size_t len = strlen(user);

	return len > 0 && len < 256 && !strchr(user, '/') &&
	       strcmp(user, ".") != 0 && strcmp(user, "..") != 0;
}

/* fprintd keeps a user's prints under /var/lib/fprint/<user>/. */
static int has_prints(const char *user)
{
	char path[512];
	struct dirent *e;
	DIR *d;
	int found = 0;

	if (snprintf(path, sizeof(path), "%s/%s", fprint_dir(), user) >= (int)sizeof(path))
		return 0;
	d = opendir(path);
	if (!d)
		return 0;
	while (!found && (e = readdir(d)))
		found = strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0;
	closedir(d);
	return found;
}

static int conv_password(int n, const struct pam_message **msg,
			 struct pam_response **resp, void *data)
{
	struct pam_response *r;

	if (n <= 0 || n > PAM_MAX_NUM_MSG)
		return PAM_CONV_ERR;
	r = calloc((size_t)n, sizeof(*r));
	if (!r)
		return PAM_BUF_ERR;
	for (int i = 0; i < n; i++) {
		if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF) {
			r[i].resp = strdup(data);
			if (!r[i].resp) {
				for (int j = 0; j < i; j++)
					free(r[j].resp);
				free(r);
				return PAM_BUF_ERR;
			}
		} else if (msg[i]->msg_style == PAM_PROMPT_ECHO_ON) {
			for (int j = 0; j < i; j++)
				free(r[j].resp);
			free(r);
			return PAM_CONV_ERR;
		}
	}
	*resp = r;
	return PAM_SUCCESS;
}

static int password_verifies(const char *user, char *password)
{
	struct pam_conv conv = { conv_password, password };
	pam_handle_t *h = NULL;
	int ret;

	if (pam_open(user, &conv, &h) != PAM_SUCCESS)
		return 0;
	ret = pam_authenticate(h, PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK);
	if (ret == PAM_SUCCESS) {
		ret = pam_acct_mgmt(h, PAM_SILENT);
		/* The password is right; it only has to be changed. */
		if (ret == PAM_NEW_AUTHTOK_REQD)
			ret = PAM_SUCCESS;
	}
	pam_end(h, ret);
	return ret == PAM_SUCCESS;
}

static int serve(char *req, size_t len, uid_t peer)
{
	size_t magic = strlen(AURORA_REARM_MAGIC);
	const char *user;
	char *password, *end;
	struct passwd *pw;
	unsigned failures, flags;
	int locked = 0;

	if (len < magic || memcmp(req, AURORA_REARM_MAGIC, magic) != 0) {
		answer("refused malformed request\n");
		return 1;
	}
	user = req + magic;
	end = memchr(req + magic, '\0', len - magic);
	if (!end || end + 1 >= req + len) {
		answer("refused malformed request\n");
		return 1;
	}
	password = end + 1;
	if (!memchr(password, '\0', (size_t)(req + len - password))) {
		answer("refused malformed request\n");
		return 1;
	}

	peer = peer_uid(peer);
	switch (lockout_state(&failures, &flags)) {
	case NOT_LOCKED:
		/*
		 * An older driver's re-arm waits for a running capture, so call
		 * it only for a lockout there. A user's own lock screen gets no
		 * password check while nothing is pending: that would let any
		 * of the user's programs test passwords here without the
		 * stack's delays.
		 */
		if ((flags & SEP_BIO_LOCKOUT_FLAG_EVERY_PASSWORD) && (failures > 0 || peer == 0))
			break;
		answer("ok not-locked\n");
		return 0;
	case NO_DEVICE:
		answer("ok not-locked\n");
		return 0;
	case STATE_ERROR:
		syslog(LOG_ERR, "cannot read the Touch ID lockout from " REARM_DEVICE ": %m");
		answer("error the lockout is unreadable\n");
		return 1;
	case LOCKED:
		locked = 1;
		break;
	}

	if (!plausible_user(user) || !(pw = getpwnam(user))) {
		answer("refused unknown user\n");
		return 1;
	}
	if (peer != 0 && peer != pw->pw_uid) {
		syslog(LOG_WARNING, "refused a re-arm for %s from uid %u", user, (unsigned)peer);
		answer("refused not the caller's account\n");
		return 1;
	}
	if (!has_prints(user)) {
		answer("refused no enrolled fingerprints\n");
		return 1;
	}
	if (!password_verifies(user, password)) {
		syslog(LOG_WARNING, "refused a re-arm for %s (uid %u asked): the password did not verify",
		       user, (unsigned)peer);
		answer("refused password\n");
		return 1;
	}
	if (rearm(password) < 0) {
		syslog(LOG_ERR, "the driver did not re-arm Touch ID for %s: %m", user);
		answer("error the driver did not re-arm\n");
		return 1;
	}
	if (locked && (flags & SEP_BIO_LOCKOUT_FLAG_AFTER_BOOT) && failures == 0) {
		syslog(LOG_NOTICE, "Touch ID armed by the first password since boot (%s)", user);
		answer("ok armed\n");
	} else if (locked) {
		syslog(LOG_NOTICE, "Touch ID re-armed after the password of %s (%u failed matches before it)",
		       user, failures);
		answer("ok rearmed\n");
	} else if (failures > 0) {
		syslog(LOG_NOTICE, "the password of %s cleared %u failed Touch ID matches", user, failures);
		answer("ok cleared\n");
	} else {
		syslog(LOG_DEBUG, "noted a password authentication of %s for Touch ID", user);
		answer("ok noted\n");
	}
	return 0;
}

/*
 * The value of "require_password_after_boot" in the configuration: 1 for yes
 * (also when the file or the key is missing: macOS's behaviour is the
 * default), 0 for no, -1 when the file says something else, which --boot
 * treats as yes: a setting meant to tighten Touch ID must not loosen it by a
 * typo.
 */
static int conf_require_password(void)
{
	char line[256];
	int value = 1;
	FILE *f = fopen(conf_file(), "r");

	if (!f)
		return 1;
	while (fgets(line, sizeof(line), f)) {
		char *p = line, *key, *val, *end;

		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == '#' || *p == '\n' || *p == '\0')
			continue;
		key = p;
		p = strchr(p, '=');
		if (!p) {
			value = -1;
			continue;
		}
		end = p;
		while (end > key && (end[-1] == ' ' || end[-1] == '\t'))
			end--;
		*end = '\0';
		val = p + 1;
		while (*val == ' ' || *val == '\t')
			val++;
		end = val + strcspn(val, " \t\r\n#");
		*end = '\0';
		if (strcmp(key, "require_password_after_boot") != 0)
			continue;
		if (strcmp(val, "yes") == 0 || strcmp(val, "true") == 0 || strcmp(val, "1") == 0)
			value = 1;
		else if (strcmp(val, "no") == 0 || strcmp(val, "false") == 0 || strcmp(val, "0") == 0)
			value = 0;
		else
			value = -1;
	}
	fclose(f);
	return value;
}

static int boot(void)
{
	int want = conf_require_password();
	struct stat st;

	if (want == 0) {
		syslog(LOG_INFO, "Touch ID works from the first login (require_password_after_boot = no)");
		printf("Touch ID works from the first login after boot\n");
		return 0;
	}
	if (want < 0)
		syslog(LOG_WARNING, "%s: require_password_after_boot is neither yes nor no; asking for the password after boot",
		       conf_file());
	/* The driver registers the node when the Secure Enclave comes up. */
	for (int i = 0; i < BOOT_WAIT_S * 10 && stat(device_path(), &st) < 0; i++)
		usleep(100000);
	if (require_password() < 0) {
		if (errno == ENOENT) {
			syslog(LOG_INFO, "no Touch ID re-arm node (%s); nothing to require", device_path());
			printf("no Touch ID on this machine\n");
			return 0;
		}
		if (errno == ENOTTY || errno == EINVAL) {
			syslog(LOG_WARNING, "this kernel cannot make Touch ID wait for the password after boot; Touch ID works from the first login");
			printf("this kernel cannot make Touch ID wait for the password after boot\n");
			return 0;
		}
		syslog(LOG_ERR, "cannot make Touch ID wait for the password after boot: %m");
		return 1;
	}
	syslog(LOG_NOTICE, "Touch ID waits for the first password since boot (require_password_after_boot = yes)");
	printf("Touch ID waits for the first password since boot\n");
	return 0;
}

static int status(void)
{
	unsigned failures, flags;

	switch (lockout_state(&failures, &flags)) {
	case NO_DEVICE:
		printf("no Touch ID re-arm node\n");
		return 0;
	case STATE_ERROR:
		fprintf(stderr, "cannot read the Touch ID lockout from %s: %s\n", device_path(), strerror(errno));
		return 1;
	case LOCKED:
		if ((flags & SEP_BIO_LOCKOUT_FLAG_AFTER_BOOT) && failures == 0)
			printf("locked: waits for the first password since boot\n");
		else if (flags & SEP_BIO_LOCKOUT_FLAG_AFTER_BOOT)
			printf("locked: waits for the first password since boot, and %u failed matches\n", failures);
		else
			printf("locked: too many failed matches, or the password is due (%u failed matches)\n", failures);
		break;
	case NOT_LOCKED:
		printf("not locked (%u failed matches since the last match or password)\n", failures);
		break;
	}
	printf("password after boot: %s\n", conf_require_password() == 0 ? "no" : "yes");
	return 0;
}

int main(int argc, char **argv)
{
	/* One byte more than a request may have, to see a longer one. */
	char req[AURORA_REARM_MAX_REQUEST + 2];
	struct timeval tv = { .tv_sec = AURORA_REARM_TIMEOUT_S };
	struct ucred cred = { 0 };
	socklen_t cl = sizeof(cred);
	size_t len = 0;
	int ret;

	openlog(SERVICE, LOG_PID, LOG_AUTHPRIV);
	if (argc == 2 && strcmp(argv[1], "--boot") == 0)
		return boot();
	if (argc == 2 && strcmp(argv[1], "--status") == 0)
		return status();
	if (argc != 1) {
		fprintf(stderr, "usage: %s [--boot | --status]\n", argv[0]);
		return 2;
	}
	if (getsockopt(STDIN_FILENO, SOL_SOCKET, SO_PEERCRED, &cred, &cl) < 0) {
		syslog(LOG_ERR, "stdin is not a socket connection: %m");
		return 1;
	}
	setsockopt(STDIN_FILENO, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	/* Read to the end: the module shuts its side down after the request. */
	for (;;) {
		ssize_t n = read(STDIN_FILENO, req + len, sizeof(req) - 1 - len);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		len += (size_t)n;
		if (len == sizeof(req) - 1)
			break;
	}
	if (len > AURORA_REARM_MAX_REQUEST) {
		explicit_bzero(req, sizeof(req));
		answer("refused malformed request\n");
		return 1;
	}
	req[len] = '\0';
	ret = serve(req, len, cred.uid);
	explicit_bzero(req, sizeof(req));
	return ret;
}
