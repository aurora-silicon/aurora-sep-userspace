# SPDX-License-Identifier: MIT
# aurora-fido: this Mac's Secure Enclave and Touch ID as a FIDO2/U2F security key.

CC ?= cc
PKG_CONFIG ?= pkg-config
PYTHON ?= python3
CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Werror=implicit-function-declaration \
	-D_FORTIFY_SOURCE=2 -fstack-protector-strong -I../luks
DEPS_CFLAGS = $(shell $(PKG_CONFIG) --cflags json-c)
DEPS_LIBS = $(shell $(PKG_CONFIG) --libs json-c)

PREFIX ?= /usr
LIBEXECDIR ?= $(PREFIX)/libexec/aurora-fido
PYDIR ?= $(PREFIX)/lib/aurora-fido
UNITDIR ?= $(PREFIX)/lib/systemd/system
UDEVRULESDIR ?= $(PREFIX)/lib/udev/rules.d
SYSCONFDIR ?= /etc
DOCDIR ?= $(PREFIX)/share/doc/aurora-fido
BINDIR ?= $(PREFIX)/bin
PRESETDIR ?= $(PREFIX)/lib/systemd/system-preset

SEAL := aurora-fido-seal
SRC := aurora-fido-seal.c ../luks/sep-seal.c ../luks/sep-seal.h
PY := $(wildcard aurora_fido/*.py)

all: $(SEAL) aurora-fidod aurora-fido aurora-fido.service.out

$(SEAL): $(SRC)
	$(CC) $(CFLAGS) $(DEPS_CFLAGS) -fPIE -pie -Wl,-z,relro,-z,now -o $@ \
		aurora-fido-seal.c ../luks/sep-seal.c $(LDFLAGS) $(DEPS_LIBS)

# Kernel "user" keys stand in for the SEP, as in luks/ and ssh/.
test/$(SEAL): $(SRC)
	mkdir -p test
	$(CC) $(CFLAGS) -DSEP_SEAL_TEST_USER_KEYS $(DEPS_CFLAGS) -o $@ \
		aurora-fido-seal.c ../luks/sep-seal.c $(DEPS_LIBS)

aurora-fidod aurora-fido: %: %.in
	sed -e 's|@PYDIR@|$(PYDIR)|' -e 's|@LIBEXECDIR@|$(LIBEXECDIR)|' $< > $@
	chmod 755 $@

aurora-fido.service.out: aurora-fido.service
	sed 's|@LIBEXECDIR@|$(LIBEXECDIR)|' $< > $@

# Unit tests: no root, no hardware (software keys, scripted Touch ID).
check:
	$(PYTHON) tests/test_ctap.py

# As root: the real uhid device with libfido2, OpenSSH, pam_u2f, cryptenroll.
check-uhid:
	bash tests/test-uhid.sh

# As root where AF_ALG ccm(aes) is restricted: the sealed master secret.
check-seal: test/$(SEAL)
	bash tests/test-seal.sh test/$(SEAL)

install: all
	install -Dm755 aurora-fidod $(DESTDIR)$(LIBEXECDIR)/aurora-fidod
	install -Dm755 aurora-fido $(DESTDIR)$(BINDIR)/aurora-fido
	install -Dm644 90-aurora-fido.preset $(DESTDIR)$(PRESETDIR)/90-aurora-fido.preset
	install -Dm755 $(SEAL) $(DESTDIR)$(LIBEXECDIR)/$(SEAL)
	for f in $(PY); do install -Dm644 $$f $(DESTDIR)$(PYDIR)/$$f; done
	install -Dm644 aurora-fido.service.out $(DESTDIR)$(UNITDIR)/aurora-fido.service
	install -Dm644 60-aurora-fido.rules $(DESTDIR)$(UDEVRULESDIR)/60-aurora-fido.rules
	install -Dm644 aurora-fido.conf $(DESTDIR)$(SYSCONFDIR)/aurora-fido/aurora-fido.conf
	install -Dm644 ../docs/fido.md $(DESTDIR)$(DOCDIR)/fido.md

clean:
	rm -rf $(SEAL) test aurora-fidod aurora-fido aurora-fido.service.out aurora_fido/__pycache__ tests/__pycache__

.PHONY: all check check-uhid check-seal install clean
