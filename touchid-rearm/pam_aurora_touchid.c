// SPDX-License-Identifier: GPL-2.0-only
/*
 * pam_aurora_touchid: re-arm Touch ID after a password authentication.
 *
 * After too many failed matches the Secure Enclave stops matching, and the
 * apple_sep driver refuses every verify until a password authentication, as
 * macOS asks for the password. This module goes in an auth stack straight
 * after pam_unix, where it runs only when pam_unix has accepted a password.
 * It hands the user and that password to aurora-touchid-rearm, which runs as
 * root, checks the password again itself and only then re-arms Touch ID.
 *
 * It never changes the stack's result: it always returns PAM_IGNORE, and
 * does nothing without a password (PAM_AUTHTOK), so a fingerprint
 * authentication never re-arms Touch ID. It never prompts.
 *
 * Arguments: "debug" logs each step; "socket=PATH" names another service
 * socket (for tests).
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
#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include "rearm-proto.h"

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

/* Returns the service's answer line, or NULL when there was none. */
static const char *ask(pam_handle_t *pamh, const char *path, const char *user,
		       const char *password, char *reply, size_t reply_len,
		       int debug)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	struct timeval tv = { .tv_sec = AURORA_REARM_TIMEOUT_S };
	char req[AURORA_REARM_MAX_REQUEST];
	size_t magic = strlen(AURORA_REARM_MAGIC);
	size_t ulen = strlen(user) + 1, plen = strlen(password) + 1;
	size_t got = 0;
	int fd, ok = 0;

	if (strlen(path) >= sizeof(addr.sun_path) ||
	    magic + ulen + plen > sizeof(req))
		return NULL;
	memcpy(addr.sun_path, path, strlen(path) + 1);

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return NULL;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		/* Not installed or not running: nothing to re-arm. */
		if (debug)
			pam_syslog(pamh, LOG_DEBUG, "no re-arm service at %s: %m", path);
		close(fd);
		return NULL;
	}

	memcpy(req, AURORA_REARM_MAGIC, magic);
	memcpy(req + magic, user, ulen);
	memcpy(req + magic + ulen, password, plen);
	if (send_all(fd, req, magic + ulen + plen) == 0 && shutdown(fd, SHUT_WR) == 0)
		ok = 1;
	explicit_bzero(req, sizeof(req));

	while (ok && got + 1 < reply_len) {
		ssize_t n = read(fd, reply + got, reply_len - 1 - got);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		got += (size_t)n;
	}
	close(fd);
	if (!ok || got == 0)
		return NULL;
	reply[got] = '\0';
	reply[strcspn(reply, "\n")] = '\0';
	return reply;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
				   const char **argv)
{
	const char *path = AURORA_REARM_SOCKET;
	const void *user = NULL, *tok = NULL;
	char reply[AURORA_REARM_MAX_REPLY];
	const char *answer;
	int debug = 0;

	(void)flags;
	for (int i = 0; i < argc; i++) {
		if (strcmp(argv[i], "debug") == 0)
			debug = 1;
		else if (strncmp(argv[i], "socket=", 7) == 0)
			path = argv[i] + 7;
		else
			pam_syslog(pamh, LOG_ERR, "unknown option %s", argv[i]);
	}

	if (pam_get_item(pamh, PAM_USER, &user) != PAM_SUCCESS || !user ||
	    !*(const char *)user)
		return PAM_IGNORE;
	/* Only a password stack sets this; a fingerprint does not. */
	if (pam_get_item(pamh, PAM_AUTHTOK, &tok) != PAM_SUCCESS || !tok ||
	    !*(const char *)tok) {
		if (debug)
			pam_syslog(pamh, LOG_DEBUG, "no password in this authentication");
		return PAM_IGNORE;
	}

	answer = ask(pamh, path, user, tok, reply, sizeof(reply), debug);
	if (!answer)
		return PAM_IGNORE;
	if (strcmp(answer, "ok rearmed") == 0)
		pam_syslog(pamh, LOG_INFO, "Touch ID re-armed after the password of %s",
			   (const char *)user);
	else if (strncmp(answer, "ok", 2) == 0) {
		if (debug)
			pam_syslog(pamh, LOG_DEBUG, "re-arm service: %s", answer);
	} else
		pam_syslog(pamh, LOG_NOTICE, "Touch ID not re-armed: %s", answer);
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
