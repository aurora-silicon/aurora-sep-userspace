# SPDX-License-Identifier: MIT
# Recovers a truncated /var/lib/aurora-sep-host-state.bin before the SEP
# loader runs. See README.md for the failure and the validation.
PYTHON ?= python3
PREFIX ?= /usr
LIBEXECDIR ?= $(PREFIX)/libexec
UNITDIR ?= $(PREFIX)/lib/systemd/system
PRESETDIR ?= $(PREFIX)/lib/systemd/system-preset
DOCDIR ?= $(PREFIX)/share/doc/aurora-sep-host-state

# Generated from the install paths: always regenerated (FORCE), so that
# `make install LIBEXECDIR=...` after a plain `make` never ships stale paths.
aurora-sep-host-state-repair.service.out: aurora-sep-host-state-repair.service FORCE
	sed 's|@LIBEXECDIR@|$(LIBEXECDIR)|' $< > $@

FORCE:

all: aurora-sep-host-state-repair.service.out

# Unit tests: no root, no hardware (synthetic stores in a temporary
# directory, through AURORA_SEP_HOST_STATE and AURORA_SEP_QUARANTINE).
check:
	$(PYTHON) tests/test_repair.py

install: all
	install -Dm755 aurora-sep-host-state-repair $(DESTDIR)$(LIBEXECDIR)/aurora-sep-host-state-repair
	install -Dm0644 aurora-sep-host-state-repair.service.out $(DESTDIR)$(UNITDIR)/aurora-sep-host-state-repair.service
	install -Dm0644 90-aurora-sep-host-state-repair.preset $(DESTDIR)$(PRESETDIR)/90-aurora-sep-host-state-repair.preset
	install -Dm0644 README.md $(DESTDIR)$(DOCDIR)/README.md

clean:
	rm -f aurora-sep-host-state-repair.service.out

.PHONY: all check install clean
