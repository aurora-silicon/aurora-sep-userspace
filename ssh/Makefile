# SPDX-License-Identifier: MIT
# aurora-sep-ssh: SSH keys sealed to the Secure Enclave, Touch ID per use.

CC ?= cc
PKG_CONFIG ?= pkg-config
CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Werror=implicit-function-declaration \
	-D_FORTIFY_SOURCE=2 -fstack-protector-strong -I../luks
DEPS_CFLAGS := $(shell $(PKG_CONFIG) --cflags json-c)
DEPS_LIBS := $(shell $(PKG_CONFIG) --libs json-c)

PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
LIBEXECDIR ?= $(PREFIX)/libexec/aurora-sep-ssh
DOCDIR ?= $(PREFIX)/share/doc/aurora-sep-ssh

SEAL := aurora-sep-ssh-seal
SRC := aurora-sep-ssh-seal.c ../luks/sep-seal.c ../luks/sep-seal.h

all: $(SEAL)

$(SEAL): $(SRC)
	$(CC) $(CFLAGS) $(DEPS_CFLAGS) -fPIE -pie -Wl,-z,relro,-z,now -o $@ \
		aurora-sep-ssh-seal.c ../luks/sep-seal.c $(LDFLAGS) $(DEPS_LIBS)

# Kernel "user" keys stand in for the SEP, as in luks/ (root needed where
# the kernel restricts AF_ALG ccm(aes)).
test/$(SEAL): $(SRC)
	mkdir -p test
	$(CC) $(CFLAGS) -DSEP_SEAL_TEST_USER_KEYS $(DEPS_CFLAGS) -o $@ \
		aurora-sep-ssh-seal.c ../luks/sep-seal.c $(DEPS_LIBS)

check: test/$(SEAL) $(SEAL)
	bash tests/test-ssh.sh test

install: all
	install -Dm755 aurora-sep-ssh $(DESTDIR)$(BINDIR)/aurora-sep-ssh
	install -Dm755 aurora-sep-ssh-askpass $(DESTDIR)$(LIBEXECDIR)/aurora-sep-ssh-askpass
	install -Dm755 $(SEAL) $(DESTDIR)$(LIBEXECDIR)/$(SEAL)
	install -Dm644 ../docs/ssh-sep.md $(DESTDIR)$(DOCDIR)/ssh-sep.md

clean:
	rm -rf $(SEAL) test

.PHONY: all check install clean
