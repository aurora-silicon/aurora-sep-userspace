// SPDX-License-Identifier: MIT
/*
 * PID 1 of the VM test root: report what the root is mounted from and power
 * off. Reaching it at all means the initrd opened the LUKS2 root and switched
 * to it.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/reboot.h>

int main(void)
{
	char line[512], dev[256] = "?", mnt[256];
	FILE *f, *con = fopen("/dev/console", "w");

	if (!con)
		con = stdout;
	mount("proc", "/proc", "proc", 0, NULL);
	f = fopen("/proc/self/mounts", "r");
	while (f && fgets(line, sizeof(line), f))
		if (sscanf(line, "%255s %255s", dev, mnt) == 2 && !strcmp(mnt, "/"))
			break;
	if (f)
		fclose(f);
	fprintf(con, "\nAURORA-SEP-VM-ROOT %s\n", dev);
	f = fopen("/run/aurora-sep/initrd-keystore.sha256", "r");
	fprintf(con, "AURORA-SEP-VM-RUN %s\n", f ? "keystore-sums" : "none");
	fflush(con);
	sync();
	reboot(RB_POWER_OFF);
	return 0;
}
