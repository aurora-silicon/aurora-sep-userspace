// SPDX-License-Identifier: MIT
/*
 * pam_aurora_sep_fde: keep the disk password of Secure Enclave LUKS2 volumes
 * equal to the login password (macOS: changing a FileVault user's password
 * changes their unlock password).
 *
 *   password optional pam_aurora_sep_fde.so
 *
 * placed after the module that changes the password (pam_unix), so it runs
 * only when that change succeeded. In the PAM_UPDATE_AUTHTOK pass it hands
 * the old and new password to "aurora-sep-fde passwd-hook --user <user>",
 * which re-wraps the user's key bag in the enclave and writes it to every
 * registered volume: the old password stops opening them, the new one does.
 *
 * Without the old password (root running passwd for someone else, chpasswd)
 * nothing can be re-wrapped: the enclave needs the old password. The module
 * then says so; a volume owner resets the disk password with
 * "aurora-sep-fde reset-password --user <user>" (macOS has the same rule:
 * only a secure-token holder can reset another user's FileVault password).
 *
 * Options: helper=/path (default /usr/libexec/aurora-sep-fde-passwd, which is
 * aurora-sep-fde), prompt / prompt_new (ask for the missing passwords, or only
 * the new one, as a stand-alone stack does; for tests), debug.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/auxv.h>
#include <sys/wait.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>

#define HELPER_DEFAULT "/usr/libexec/aurora-sep-fde-passwd"

extern char **environ;

static int write_all(int fd, const char *b, size_t n)
{
	while (n) {
		ssize_t k = write(fd, b, n);

		if (k < 0 && errno == EINTR)
			continue;
		if (k <= 0)
			return -1;
		b += k;
		n -= (size_t)k;
	}
	return 0;
}

static int run_helper(pam_handle_t *ph, const char *helper, const char *user, const char *old,
		      const char *nw, int debug)
{
	char *argv[] = { (char *)helper, "passwd-hook", "--user", (char *)user, "--quiet", NULL };
	char *envp[16];
	int in[2], out[2], status = 0, n = 0;
	char msg[512];
	ssize_t got = 0;
	pid_t pid;

	/* A clean environment; the test variables only when not setuid. */
	envp[n++] = "PATH=/usr/sbin:/usr/bin:/sbin:/bin";
	if (!getauxval(AT_SECURE))
		for (char **e = environ; *e && n < 15; e++)
			if (!strncmp(*e, "AURORA_SEP_", 11))
				envp[n++] = *e;
	envp[n] = NULL;
	if (pipe2(in, O_CLOEXEC) || pipe2(out, O_CLOEXEC))
		return -1;
	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		dup2(in[0], 0);
		dup2(out[1], 1);
		dup2(out[1], 2);
		execve(helper, argv, envp);
		_exit(127);
	}
	close(in[0]);
	close(out[1]);
	{
		void (*old_pipe)(int) = signal(SIGPIPE, SIG_IGN);

		write_all(in[1], old, strlen(old) + 1);
		write_all(in[1], nw, strlen(nw) + 1);
		signal(SIGPIPE, old_pipe);
	}
	close(in[1]);
	while (got < (ssize_t)sizeof(msg) - 1) {
		ssize_t k = read(out[0], msg + got, sizeof(msg) - 1 - (size_t)got);

		if (k <= 0)
			break;
		got += k;
	}
	msg[got] = '\0';
	close(out[0]);
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;
	if (got && (debug || !WIFEXITED(status) || WEXITSTATUS(status)))
		pam_syslog(ph, LOG_NOTICE, "%s", msg);
	if (!WIFEXITED(status) || WEXITSTATUS(status))
		return -1;
	return 0;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *ph, int flags, int argc, const char **argv)
{
	const char *helper = HELPER_DEFAULT, *user = NULL;
	const void *old = NULL, *nw = NULL;
	char *asked_old = NULL, *asked_new = NULL;
	int prompt = 0, prompt_new = 0, debug = 0, r;

	for (int i = 0; i < argc; i++) {
		if (!strncmp(argv[i], "helper=", 7))
			helper = argv[i] + 7;
		else if (!strcmp(argv[i], "prompt"))
			prompt = prompt_new = 1;
		else if (!strcmp(argv[i], "prompt_new"))
			prompt_new = 1;
		else if (!strcmp(argv[i], "debug"))
			debug = 1;
	}
	if (flags & PAM_PRELIM_CHECK)
		return PAM_SUCCESS;
	if (!(flags & PAM_UPDATE_AUTHTOK))
		return PAM_IGNORE;
	if (pam_get_user(ph, &user, NULL) != PAM_SUCCESS || !user || !*user)
		return PAM_IGNORE;
	pam_get_item(ph, PAM_OLDAUTHTOK, &old);
	pam_get_item(ph, PAM_AUTHTOK, &nw);
	if (prompt && !old && pam_prompt(ph, PAM_PROMPT_ECHO_OFF, &asked_old, "Current password: ") == PAM_SUCCESS)
		old = asked_old;
	if (prompt_new && !nw && pam_prompt(ph, PAM_PROMPT_ECHO_OFF, &asked_new, "New password: ") == PAM_SUCCESS)
		nw = asked_new;
	if (!nw) {
		r = PAM_IGNORE;
	} else if (!old) {
		/* An administrator's reset: the enclave cannot re-wrap the bag
		 * without the old password. */
		if (access(helper, X_OK) == 0) {
			pam_syslog(ph, LOG_NOTICE,
				   "disk password of %s not changed (no old password); a volume owner can "
				   "run: aurora-sep-fde reset-password --user %s DEVICE", user, user);
			pam_info(ph, "The disk password of %s is unchanged. A volume owner can reset it "
				 "with: aurora-sep-fde reset-password --user %s", user, user);
		}
		r = PAM_IGNORE;
	} else if (access(helper, X_OK)) {
		r = PAM_IGNORE;
	} else if (run_helper(ph, helper, user, old, nw, debug)) {
		pam_error(ph, "The disk password of %s could not be changed; it still opens with the "
			  "old password.", user);
		r = PAM_AUTHTOK_ERR;
	} else {
		r = PAM_SUCCESS;
	}
	if (asked_old) {
		explicit_bzero(asked_old, strlen(asked_old));
		free(asked_old);
	}
	if (asked_new) {
		explicit_bzero(asked_new, strlen(asked_new));
		free(asked_new);
	}
	return r;
}
