// SPDX-License-Identifier: GPL-2.0-only
/* Test driver: pam-stack-check CONFDIR SERVICE USER PASSWORD; prints the
 * pam_authenticate result as a number. Never installed. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>

static int conv(int n, const struct pam_message **msg, struct pam_response **resp, void *data)
{
	struct pam_response *r = calloc((size_t)n, sizeof(*r));

	if (!r)
		return PAM_BUF_ERR;
	for (int i = 0; i < n; i++)
		if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF)
			r[i].resp = strdup(data);
	*resp = r;
	return PAM_SUCCESS;
}

int main(int argc, char **argv)
{
	struct pam_conv c = { conv, NULL };
	pam_handle_t *h = NULL;
	int ret;

	if (argc != 5)
		return 2;
	c.appdata_ptr = argv[4];
	if (pam_start_confdir(argv[2], argv[3], &c, argv[1], &h) != PAM_SUCCESS)
		return 2;
	ret = pam_authenticate(h, 0);
	printf("%d\n", ret);
	pam_end(h, ret);
	return 0;
}
