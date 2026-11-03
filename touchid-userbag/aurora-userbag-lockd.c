// SPDX-License-Identifier: GPL-2.0-only
/*
 * aurora-userbag-lockd (DESIGN DRAFT): lock users' Secure Enclave key bags
 * when logind says the screen locked, the machine is going to sleep, or the
 * user logged out. It never sees a password; it only sends locks.
 *
 *  - Session LockedHint -> true (GNOME, KDE, hyprlock and others set it) and
 *    the Session "Lock" signal (loginctl lock-session): lock that session's
 *    user after the grace period. The kernel keeps the deadline; a Touch ID
 *    or password unlock inside it cancels the lock, as on macOS.
 *  - Manager PrepareForSleep(true): lock every user at once. A delay
 *    inhibitor is held so the lock reaches the enclave before the suspend;
 *    it is released after the locks and taken again on resume.
 *  - Manager SessionRemoved: when the user has no session left, lock with
 *    reason LOGOUT, so only the password opens the bag again.
 *
 * Grace period: GraceSeconds= in /etc/aurora/touchid-userbag.conf, default
 * 10 (what macOS 26 does on the Neo when "require password" is immediate).
 * TODO: read the desktop's own "require password after" setting per user.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <unistd.h>

#include <systemd/sd-bus.h>

#include "userbag-uapi.h"

#define CONF "/etc/aurora/touchid-userbag.conf"

static unsigned grace_s = 10;
static int sleep_lock = -1;

static void read_conf(void)
{
	char line[128];
	FILE *f = fopen(CONF, "re");

	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		unsigned v;

		if (sscanf(line, "GraceSeconds=%u", &v) == 1 && v <= 3600)
			grace_s = v;
	}
	fclose(f);
}

static void lock_uid(uint32_t uid, uint32_t reason, uint32_t grace)
{
	struct sep_keybag_lock req = { .uid = uid, .reason = reason, .grace_s = grace };
	int fd = open(USERBAG_DEVICE, O_RDWR | O_CLOEXEC);

	if (fd < 0) {
		syslog(LOG_WARNING, "open %s: %m", USERBAG_DEVICE);
		return;
	}
	if (ioctl(fd, SEP_BIO_KEYBAG_LOCK, &req) != 0)
		syslog(errno == ENOTTY || errno == EOPNOTSUPP ? LOG_DEBUG : LOG_WARNING,
		       "lock uid %u (reason %u): %m", uid, reason);
	close(fd);
}

/* Every user with a session, from ListUsers. */
static void for_each_user(sd_bus *bus, uint32_t reason, uint32_t grace)
{
	sd_bus_message *reply = NULL;
	uint32_t uid;
	const char *name, *path;

	if (sd_bus_call_method(bus, "org.freedesktop.login1", "/org/freedesktop/login1",
			       "org.freedesktop.login1.Manager", "ListUsers", NULL,
			       &reply, "") < 0)
		return;
	if (sd_bus_message_enter_container(reply, 'a', "(uso)") > 0) {
		while (sd_bus_message_read(reply, "(uso)", &uid, &name, &path) > 0)
			lock_uid(uid, reason, grace);
	}
	sd_bus_message_unref(reply);
}

static int session_uid(sd_bus *bus, const char *path, uint32_t *uid)
{
	sd_bus_error err = SD_BUS_ERROR_NULL;
	sd_bus_message *reply = NULL;
	const char *upath;
	int r;

	r = sd_bus_get_property(bus, "org.freedesktop.login1", path,
				"org.freedesktop.login1.Session", "User", &err, &reply, "(uo)");
	if (r >= 0)
		r = sd_bus_message_read(reply, "(uo)", uid, &upath);
	sd_bus_message_unref(reply);
	sd_bus_error_free(&err);
	return r < 0 ? r : 0;
}

static int take_sleep_lock(sd_bus *bus)
{
	sd_bus_message *reply = NULL;
	int fd = -1;

	if (sd_bus_call_method(bus, "org.freedesktop.login1", "/org/freedesktop/login1",
			       "org.freedesktop.login1.Manager", "Inhibit", NULL, &reply,
			       "ssss", "sleep", "Aurora Touch ID",
			       "lock the Secure Enclave key bags before sleep", "delay") >= 0 &&
	    sd_bus_message_read(reply, "h", &fd) >= 0)
		fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
	sd_bus_message_unref(reply);
	return fd;
}

static int on_sleep(sd_bus_message *m, void *data, sd_bus_error *e)
{
	sd_bus *bus = data;
	int start;

	(void)e;
	if (sd_bus_message_read(m, "b", &start) < 0)
		return 0;
	if (start) {
		for_each_user(bus, SEP_KEYBAG_LOCK_SUSPEND, 0);
		if (sleep_lock >= 0)
			close(sleep_lock);
		sleep_lock = -1;
	} else if (sleep_lock < 0) {
		sleep_lock = take_sleep_lock(bus);
	}
	return 0;
}

static int on_lock_signal(sd_bus_message *m, void *data, sd_bus_error *e)
{
	uint32_t uid;

	(void)e;
	if (session_uid(data, sd_bus_message_get_path(m), &uid) == 0)
		lock_uid(uid, SEP_KEYBAG_LOCK_SCREEN, grace_s);
	return 0;
}

static int on_properties(sd_bus_message *m, void *data, sd_bus_error *e)
{
	const char *iface, *prop;
	int locked;
	uint32_t uid;

	(void)e;
	if (sd_bus_message_read(m, "s", &iface) < 0 ||
	    strcmp(iface, "org.freedesktop.login1.Session") != 0)
		return 0;
	if (sd_bus_message_enter_container(m, 'a', "{sv}") <= 0)
		return 0;
	while (sd_bus_message_enter_container(m, 'e', "sv") > 0) {
		if (sd_bus_message_read(m, "s", &prop) < 0)
			return 0;
		if (strcmp(prop, "LockedHint") == 0 &&
		    sd_bus_message_read(m, "v", "b", &locked) >= 0) {
			if (locked && session_uid(data, sd_bus_message_get_path(m), &uid) == 0)
				lock_uid(uid, SEP_KEYBAG_LOCK_SCREEN, grace_s);
		} else {
			sd_bus_message_skip(m, "v");
		}
		sd_bus_message_exit_container(m);
	}
	return 0;
}

static int on_session_removed(sd_bus_message *m, void *data, sd_bus_error *e)
{
	(void)m;
	(void)e;
	/*
	 * TODO: SessionRemoved carries no uid and the session object is gone.
	 * Keep a session -> uid map from SessionNew, and lock with LOGOUT when
	 * a uid's last session leaves (ListUsers no longer lists it).
	 */
	(void)data;
	return 0;
}

int main(void)
{
	sd_bus *bus = NULL;
	int r;

	openlog("aurora-userbag-lockd", LOG_PID, LOG_AUTHPRIV);
	read_conf();
	r = sd_bus_open_system(&bus);
	if (r < 0) {
		syslog(LOG_ERR, "system bus: %s", strerror(-r));
		return 1;
	}
	sd_bus_match_signal(bus, NULL, "org.freedesktop.login1", "/org/freedesktop/login1",
			    "org.freedesktop.login1.Manager", "PrepareForSleep", on_sleep, bus);
	sd_bus_match_signal(bus, NULL, "org.freedesktop.login1", "/org/freedesktop/login1",
			    "org.freedesktop.login1.Manager", "SessionRemoved",
			    on_session_removed, bus);
	sd_bus_match_signal(bus, NULL, "org.freedesktop.login1", NULL,
			    "org.freedesktop.login1.Session", "Lock", on_lock_signal, bus);
	sd_bus_match_signal(bus, NULL, "org.freedesktop.login1", NULL,
			    "org.freedesktop.DBus.Properties", "PropertiesChanged",
			    on_properties, bus);
	sleep_lock = take_sleep_lock(bus);

	for (;;) {
		r = sd_bus_process(bus, NULL);
		if (r < 0)
			break;
		if (r > 0)
			continue;
		if (sd_bus_wait(bus, UINT64_MAX) < 0)
			break;
	}
	sd_bus_unref(bus);
	return 1;
}
