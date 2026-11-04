# SPDX-License-Identifier: GPL-2.0-only
CC ?= cc
CFLAGS ?= -O2 -g -D_FORTIFY_SOURCE=2 -fstack-protector-strong
# Distribution builds pass their own flags and WARN="-Wall -Wextra".
WARN ?= -Wall -Wextra -Werror
CFLAGS += -std=gnu11 $(WARN)
PREFIX ?= /usr
LIBEXECDIR ?= $(PREFIX)/libexec
PAMDIR ?= $(PREFIX)/lib64/security
PAMCONFDIR ?= $(PREFIX)/lib/pam.d
UNITDIR ?= $(PREFIX)/lib/systemd/system
DOCDIR ?= $(PREFIX)/share/doc/aurora-touchid-rearm
READELF ?= readelf
EXPECTED_ELF_MACHINE ?= AArch64
BUNDLE_ROOT ?= $(CURDIR)/stage-root
BUNDLE ?= $(CURDIR)/aurora-touchid-rearm.tar.zst
BUNDLE_ELFS := pam_aurora_touchid.so aurora-touchid-rearm

all: pam_aurora_touchid.so aurora-touchid-rearm

pam_aurora_touchid.so: pam_aurora_touchid.c rearm-proto.h
	$(CC) $(CFLAGS) $(LDFLAGS) -fPIC -shared -o $@ $< -lpam

aurora-touchid-rearm: aurora-touchid-rearm.c rearm-proto.h
	$(CC) $(CFLAGS) $(LDFLAGS) -fPIE -pie -o $@ $< -lpam

# Test build: fake device, PAM stacks from a directory. Never installed.
aurora-touchid-rearm-test: aurora-touchid-rearm.c rearm-proto.h
	$(CC) $(CFLAGS) -DAURORA_REARM_TEST -o $@ $< -lpam

tests/pam_fake.so: tests/pam_fake.c
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $< -lpam

tests/pam-stack-check: tests/pam-stack-check.c
	$(CC) $(CFLAGS) -o $@ $< -lpam

check: pam_aurora_touchid.so aurora-touchid-rearm-test tests/pam_fake.so tests/pam-stack-check
	python3 tests/test_rearm.py

install: all
	install -Dm0755 aurora-touchid-rearm $(DESTDIR)$(LIBEXECDIR)/aurora-touchid-rearm
	install -Dm0755 pam_aurora_touchid.so $(DESTDIR)$(PAMDIR)/pam_aurora_touchid.so
	install -Dm0644 aurora-touchid-rearm.pam $(DESTDIR)$(PAMCONFDIR)/aurora-touchid-rearm
	install -Dm0644 aurora-touchid-rearm.socket $(DESTDIR)$(UNITDIR)/aurora-touchid-rearm.socket
	install -Dm0644 aurora-touchid-rearm@.service $(DESTDIR)$(UNITDIR)/aurora-touchid-rearm@.service
	install -Dm0644 README.md $(DESTDIR)$(DOCDIR)/README.md

# A Neo bundle must never silently contain host-architecture binaries. Keep
# this gate next to the archive operation so an ad-hoc build command cannot
# package an x86-64 PAM module as happened in the first touchid3 kit.
verify-bundle-elf: all
	@for elf in $(BUNDLE_ELFS); do \
		machine=`$(READELF) -h "$$elf" | sed -n 's/^[[:space:]]*Machine:[[:space:]]*//p'`; \
		if test "$$machine" != "$(EXPECTED_ELF_MACHINE)"; then \
			echo "error: $$elf ELF machine is '$$machine', expected '$(EXPECTED_ELF_MACHINE)'" >&2; \
			exit 1; \
		fi; \
		echo "$$elf: ELF machine $$machine"; \
	done

bundle: verify-bundle-elf
	@test ! -e "$(BUNDLE_ROOT)" || { echo "error: $(BUNDLE_ROOT) already exists" >&2; exit 1; }
	@test ! -e "$(BUNDLE)" || { echo "error: $(BUNDLE) already exists" >&2; exit 1; }
	$(MAKE) install DESTDIR="$(BUNDLE_ROOT)"
	tar --zstd -C "$(BUNDLE_ROOT)" -cf "$(BUNDLE)" .

clean:
	rm -f pam_aurora_touchid.so aurora-touchid-rearm aurora-touchid-rearm-test tests/pam_fake.so tests/pam-stack-check

.PHONY: all check install verify-bundle-elf bundle clean
