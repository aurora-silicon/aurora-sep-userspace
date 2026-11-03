// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test stand-ins, never installed. "password" behaves like pam_unix: it
 * gets the password (storing it as PAM_AUTHTOK) and succeeds if it is
 * $AURORA_TEST_PASSWORD. "finger" behaves like pam_fprintd: it succeeds
 * without a password if $AURORA_TEST_FINGER is "match", and otherwise
 * returns PAM_AUTHINFO_UNAVAIL.
 */
#include <stdlib.h>
#include <string.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#include <security/pam_ext.h>
#include <security/pam_modules.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
				   const char **argv)
{
	const char *want = getenv("AURORA_TEST_PASSWORD");
	const char *finger = getenv("AURORA_TEST_FINGER");
	const char *tok = NULL;

	(void)flags;
	if (argc == 1 && strcmp(argv[0], "finger") == 0)
		return finger && strcmp(finger, "match") == 0 ? PAM_SUCCESS
							     : PAM_AUTHINFO_UNAVAIL;
	if (pam_get_authtok(pamh, PAM_AUTHTOK, &tok, NULL) != PAM_SUCCESS || !tok)
		return PAM_AUTH_ERR;
	return want && strcmp(tok, want) == 0 ? PAM_SUCCESS : PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
			      const char **argv)
{
	(void)pamh; (void)flags; (void)argc; (void)argv;
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
				const char **argv)
{
	(void)pamh; (void)flags; (void)argc; (void)argv;
	return PAM_SUCCESS;
}
