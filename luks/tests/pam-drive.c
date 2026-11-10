// SPDX-License-Identifier: MIT
/*
 * Runs pam_chauthtok for a user against a PAM config directory, answering
 * the module's prompts from files: what passwd does when a user changes
 * their password. Usage: pam-drive CONFDIR SERVICE USER OLD_FILE NEW_FILE
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>

static char *slurp(const char *p)
{
	char buf[1024];
	FILE *f = fopen(p, "r");
	size_t n;

	if (!f)
		return NULL;
	n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';
	buf[strcspn(buf, "\n")] = '\0';
	return strdup(buf);
}

static char *answers[2];

static int conv(int n, const struct pam_message **m, struct pam_response **resp, void *d)
{
	static int asked;
	struct pam_response *r = calloc((size_t)n, sizeof(*r));

	(void)d;
	for (int i = 0; i < n; i++) {
		if (m[i]->msg_style == PAM_PROMPT_ECHO_OFF)
			r[i].resp = strdup(answers[asked++ ? 1 : 0]);
		else
			printf("pam: %s\n", m[i]->msg);
	}
	*resp = r;
	return PAM_SUCCESS;
}

int main(int argc, char **argv)
{
	struct pam_conv c = { conv, NULL };
	pam_handle_t *ph;
	int r;

	if (argc != 6)
		return 2;
	answers[0] = slurp(argv[4]);
	answers[1] = slurp(argv[5]);
	if (!answers[0] || !answers[1])
		return 2;
	r = pam_start_confdir(argv[2], argv[3], &c, argv[1], &ph);
	if (r != PAM_SUCCESS)
		return 3;
	r = pam_chauthtok(ph, 0);
	printf("pam_chauthtok: %s\n", pam_strerror(ph, r));
	pam_end(ph, r);
	return r == PAM_SUCCESS ? 0 : 1;
}
