# SPDX-License-Identifier: GPL-2.0-only
# DESIGN DRAFT: not packaged by any distribution yet.
CC ?= cc
CFLAGS ?= -O2 -g -D_FORTIFY_SOURCE=2 -fstack-protector-strong
WARN ?= -Wall -Wextra -Werror
CFLAGS += -std=gnu11 $(WARN)
PREFIX ?= /usr
LIBEXECDIR ?= $(PREFIX)/libexec
PAMDIR ?= $(PREFIX)/lib64/security
UNITDIR ?= $(PREFIX)/lib/systemd/system

all: pam_aurora_userbag.so aurora-userbag-helper aurora-userbag-lockd

pam_aurora_userbag.so: pam_aurora_userbag.c userbag-proto.h
	$(CC) $(CFLAGS) $(LDFLAGS) -fPIC -shared -o $@ $< -lpam

aurora-userbag-helper: aurora-userbag-helper.c userbag-proto.h userbag-uapi.h
	$(CC) $(CFLAGS) $(LDFLAGS) -fPIE -pie -o $@ $<

aurora-userbag-lockd: aurora-userbag-lockd.c userbag-uapi.h
	$(CC) $(CFLAGS) $(LDFLAGS) -fPIE -pie -o $@ $< -lsystemd

# Test build: the device is a path that does not exist. Never installed.
aurora-userbag-helper-test: aurora-userbag-helper.c userbag-proto.h userbag-uapi.h
	$(CC) $(CFLAGS) '-DUSERBAG_DEVICE="/nonexistent/sep-bio-rearm"' -o $@ $<

check: aurora-userbag-helper-test pam_aurora_userbag.so
	python3 tests/test_helper.py

install: all
	install -Dm0755 aurora-userbag-helper $(DESTDIR)$(LIBEXECDIR)/aurora-userbag-helper
	install -Dm0755 aurora-userbag-lockd $(DESTDIR)$(LIBEXECDIR)/aurora-userbag-lockd
	install -Dm0755 pam_aurora_userbag.so $(DESTDIR)$(PAMDIR)/pam_aurora_userbag.so
	install -Dm0644 aurora-userbag.socket $(DESTDIR)$(UNITDIR)/aurora-userbag.socket
	install -Dm0644 aurora-userbag@.service $(DESTDIR)$(UNITDIR)/aurora-userbag@.service
	install -Dm0644 aurora-userbag-lockd.service $(DESTDIR)$(UNITDIR)/aurora-userbag-lockd.service

clean:
	rm -f pam_aurora_userbag.so aurora-userbag-helper aurora-userbag-lockd aurora-userbag-helper-test

.PHONY: all check install clean
