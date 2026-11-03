// SPDX-License-Identifier: GPL-2.0-only
/*
 * pam_aurora_userbag (DESIGN DRAFT): hand a just-accepted password to the
 * root helper that opens the user's Secure Enclave key bag with it.
 *
 * auth:      goes straight after pam_unix and runs only when pam_unix
 *            accepted the password. Sends "unlock" with PAM_USER and
 *            PAM_AUTHTOK. A fingerprint sets no PAM_AUTHTOK, so a finger
 *            never opens a bag that the rules say is closed.
 * password:  after pam_unix updated the password (the second chauthtok
 *            pass), sends "change" with PAM_OLDAUTHTOK and PAM_AUTHTOK so
 *            the bag follows the new password.
 *
 * The module keeps nothing. Its copy of the request is wiped after the send.
 * It always returns PAM_IGNORE, never prompts, and never changes a stack's
 * result. Unlocking the bag is a side effect of a login, not a condition of
 * it: a failed unlock only means Touch ID stays unavailable.
 *
 * Arguments: "debug", "socket=PATH" (tests).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include "userbag-proto.h"

struct opts {
	const char *path;
	int debug;
};

static void parse(pam_handle_t *pamh, int argc, const char **argv, struct opts *o)
{
	o->path = AURORA_USERBAG_SOCKET;
	o->debug = 0;
	for (int i = 0; i < argc; i++) {
		if (strcmp(argv[i], "debug") == 0)
			o->debug = 1;
		else if (strncmp(argv[i], "socket=", 7) == 0)
			o->path = argv[i] + 7;
		else
			pam_syslog(pamh, LOG_ERR, "unknown option %s", argv[i]);
	}
}

static int put(char *buf, size_t cap, size_t *at, const char *s)
{
	size_t n = strlen(s) + 1;

	if (*at + n > cap)
		return -1;
	memcpy(buf + *at, s, n);
	*at += n;
	return 0;
}

static int send_all(int fd, const char *buf, size_t len)
{
	while (len > 0) {
		ssize_t n = send(fd, buf, len, MSG_NOSIGNAL);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return -1;
		buf += n;
		len -= (size_t)n;
	}
	return 0;
}

/* Sends one request; returns the answer line or NULL. */
static const char *ask(const struct opts *o, const char *op, const char *user,
		       const char *secret, const char *new_secret, char *reply,
		       size_t reply_len)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	struct timeval tv = { .tv_sec = AURORA_USERBAG_TIMEOUT_S };
	char req[AURORA_USERBAG_MAX_REQUEST];
	size_t at = strlen(AURORA_USERBAG_MAGIC), got = 0;
	int fd, ok = 0;

	if (strlen(o->path) >= sizeof(addr.sun_path))
		return NULL;
	memcpy(addr.sun_path, o->path, strlen(o->path) + 1);
	memcpy(req, AURORA_USERBAG_MAGIC, at);
	if (put(req, sizeof(req), &at, op) || put(req, sizeof(req), &at, user) ||
	    put(req, sizeof(req), &at, secret) ||
	    (new_secret && put(req, sizeof(req), &at, new_secret))) {
		explicit_bzero(req, sizeof(req));
		return NULL;
	}

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd >= 0) {
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
		if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0 &&
		    send_all(fd, req, at) == 0 && shutdown(fd, SHUT_WR) == 0)
			ok = 1;
	}
	explicit_bzero(req, sizeof(req));
	while (ok && got + 1 < reply_len) {
		ssize_t n = read(fd, reply + got, reply_len - 1 - got);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		got += (size_t)n;
	}
	if (fd >= 0)
		close(fd);
	if (!ok || got == 0)
		return NULL;
	reply[got] = '\0';
	reply[strcspn(reply, "\n")] = '\0';
	return reply;
}

static void report(pam_handle_t *pamh, const struct opts *o, const char *user,
		   const char *answer)
{
	if (!answer) {
		if (o->debug)
			pam_syslog(pamh, LOG_DEBUG, "no key-bag service at %s", o->path);
	} else if (strncmp(answer, "ok", 2) == 0) {
		if (o->debug)
			pam_syslog(pamh, LOG_DEBUG, "key bag of %s: %s", user, answer);
	} else {
		pam_syslog(pamh, LOG_NOTICE, "key bag of %s: %s", user, answer);
	}
}

static const char *item(pam_handle_t *pamh, int type)
{
	const void *v = NULL;

	if (pam_get_item(pamh, type, &v) != PAM_SUCCESS || !v || !*(const char *)v)
		return NULL;
	return v;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
				   const char **argv)
{
	char reply[AURORA_USERBAG_MAX_REPLY];
	const char *user, *tok;
	struct opts o;

	(void)flags;
	parse(pamh, argc, argv, &o);
	user = item(pamh, PAM_USER);
	tok = item(pamh, PAM_AUTHTOK);
	if (!user || !tok)
		return PAM_IGNORE;
	report(pamh, &o, user, ask(&o, "unlock", user, tok, NULL, reply, sizeof(reply)));
	return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
			      const char **argv)
{
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
				const char **argv)
{
	char reply[AURORA_USERBAG_MAX_REPLY];
	const char *user, *old, *tok;
	struct opts o;

	/* Only the second pass, after pam_unix has stored the new password. */
	if (!(flags & PAM_UPDATE_AUTHTOK))
		return PAM_IGNORE;
	parse(pamh, argc, argv, &o);
	user = item(pamh, PAM_USER);
	old = item(pamh, PAM_OLDAUTHTOK);
	tok = item(pamh, PAM_AUTHTOK);
	/*
	 * root running "passwd user" gives no old password. The bag cannot be
	 * re-keyed then; the helper records it as out of step and the next
	 * login runs the recovery path (DESIGN.md, "Recovery").
	 */
	if (!user || !tok)
		return PAM_IGNORE;
	report(pamh, &o, user,
	       ask(&o, "change", user, old ? old : "", tok, reply, sizeof(reply)));
	return PAM_IGNORE;
}
