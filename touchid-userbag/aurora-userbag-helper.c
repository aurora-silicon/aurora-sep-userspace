// SPDX-License-Identifier: GPL-2.0-only
/*
 * aurora-userbag-helper (DESIGN DRAFT): open or re-key a user's Secure
 * Enclave key bag with a password a PAM stack has just accepted.
 *
 * systemd starts one per connection to /run/aurora-userbag.sock with the
 * connection on stdin/stdout (Accept=yes). The request format is in
 * userbag-proto.h. This program:
 *
 *  - accepts the request only from root or from the user it names
 *    (SO_PEERCRED), so one user cannot probe another's bag;
 *  - does not check the password itself: the enclave is the check. A wrong
 *    password simply fails to open the bag, and the enclave's own attempt
 *    counter and delays apply, as on macOS;
 *  - keeps the password in locked memory for the one ioctl and wipes it.
 *    Nothing is written to disk and nothing outlives the connection.
 *
 * The ioctls are on the root-only node /dev/sep-bio-rearm. Until the kernel
 * implements them the helper answers "error unsupported".
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include "userbag-proto.h"
#include "userbag-uapi.h"

static void answer(const char *line)
{
	ssize_t n = write(STDOUT_FILENO, line, strlen(line));

	(void)n;
}

/* Splits "<magic><op>\0<user>\0<secret>\0[<new>\0]"; fields point into buf. */
static int split(char *buf, size_t len, const char **op, const char **user,
		 const char **secret, const char **new_secret)
{
	size_t magic = strlen(AURORA_USERBAG_MAGIC);
	const char *field[4] = { NULL };
	size_t at, n = 0;

	if (len < magic || memcmp(buf, AURORA_USERBAG_MAGIC, magic) != 0)
		return -1;
	at = magic;
	while (at < len && n < 4) {
		char *end = memchr(buf + at, '\0', len - at);

		if (!end)
			return -1;
		field[n++] = buf + at;
		at = (size_t)(end - buf) + 1;
	}
	if (at != len || n < 3)
		return -1;
	*op = field[0];
	*user = field[1];
	*secret = field[2];
	*new_secret = field[3];
	return 0;
}

static int caller_may_ask(uid_t target)
{
	struct ucred cred;
	socklen_t len = sizeof(cred);

	if (getsockopt(STDIN_FILENO, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0)
		return 0;
	return cred.uid == 0 || cred.uid == target;
}

static const char *do_unlock(int fd, uid_t uid, const char *secret)
{
	struct sep_keybag_unlock req = { .uid = uid };
	size_t len = strlen(secret);
	const char *res = "ok unlocked\n";

	if (len == 0 || len > sizeof(req.secret))
		return "refused secret length\n";
	req.secret_len = (__u32)len;
	memcpy(req.secret, secret, len);
	if (ioctl(fd, SEP_BIO_KEYBAG_UNLOCK, &req) != 0) {
		if (errno == ENOENT)
			res = "ok no-bag\n";
		else if (errno == EACCES)
			res = "refused enclave\n";
		else if (errno == ENOTTY || errno == EOPNOTSUPP)
			res = "error unsupported\n";
		else
			res = "error driver\n";
	}
	explicit_bzero(&req, sizeof(req));
	return res;
}

static const char *do_change(int fd, uid_t uid, const char *old, const char *new_secret)
{
	struct sep_keybag_change req = { .uid = uid };
	size_t ol = strlen(old), nl = new_secret ? strlen(new_secret) : 0;
	const char *res = "ok changed\n";

	if (ol == 0)
		/* root set the password: TODO record "out of step" for recovery. */
		return "refused no old password\n";
	if (ol > sizeof(req.old_secret) || nl == 0 || nl > sizeof(req.new_secret))
		return "refused secret length\n";
	req.old_len = (__u32)ol;
	req.new_len = (__u32)nl;
	memcpy(req.old_secret, old, ol);
	memcpy(req.new_secret, new_secret, nl);
	if (ioctl(fd, SEP_BIO_KEYBAG_CHANGE, &req) != 0)
		res = (errno == ENOTTY || errno == EOPNOTSUPP) ? "error unsupported\n" :
		      errno == EACCES ? "refused enclave\n" : "error driver\n";
	explicit_bzero(&req, sizeof(req));
	return res;
}

int main(void)
{
	static char buf[AURORA_USERBAG_MAX_REQUEST + 1];
	const char *op, *user, *secret, *new_secret, *res;
	struct passwd *pw;
	size_t len = 0;
	int fd;

	openlog("aurora-userbag-helper", LOG_PID, LOG_AUTHPRIV);
	/* The password must never reach swap or a core file. */
	if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0)
		syslog(LOG_WARNING, "mlockall: %m");
	while (len < sizeof(buf) - 1) {
		ssize_t n = read(STDIN_FILENO, buf + len, sizeof(buf) - 1 - len);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		len += (size_t)n;
	}
	if (split(buf, len, &op, &user, &secret, &new_secret) != 0) {
		answer("refused malformed\n");
		goto out;
	}
	pw = getpwnam(user);
	if (!pw || pw->pw_uid < 1000) {
		answer("refused user\n");
		goto out;
	}
	if (!caller_may_ask(pw->pw_uid)) {
		syslog(LOG_NOTICE, "refused a request for %s from another user", user);
		answer("refused caller\n");
		goto out;
	}
	fd = open(USERBAG_DEVICE, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		answer("error no device\n");
		goto out;
	}
	if (strcmp(op, "unlock") == 0)
		res = do_unlock(fd, pw->pw_uid, secret);
	else if (strcmp(op, "change") == 0)
		res = do_change(fd, pw->pw_uid, secret, new_secret);
	else
		res = "refused op\n";
	close(fd);
	syslog(LOG_INFO, "%s for %s: %.*s", op, user, (int)strcspn(res, "\n"), res);
	answer(res);
out:
	explicit_bzero(buf, sizeof(buf));
	return 0;
}
