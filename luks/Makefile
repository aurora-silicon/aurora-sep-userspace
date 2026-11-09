# SPDX-License-Identifier: MIT
# SEP-sealed LUKS2 unlock: libcryptsetup token plugin + enrolment tool.

CC ?= cc
PKG_CONFIG ?= pkg-config
CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Werror=implicit-function-declaration -fPIC \
	-D_FORTIFY_SOURCE=2 -fstack-protector-strong
DEPS_CFLAGS := $(shell $(PKG_CONFIG) --cflags libcryptsetup json-c)
DEPS_LIBS := $(shell $(PKG_CONFIG) --libs libcryptsetup json-c)

PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man
# Must match `cryptsetup --help` "LUKS2 external token plugin path".
TOKENDIR ?= $(shell $(PKG_CONFIG) --variable=libdir libcryptsetup)/cryptsetup

PLUGIN := libcryptsetup-token-aurora-sep.so
TOOL := aurora-sep-cryptenroll
FDE := aurora-sep-fde

all: $(PLUGIN) $(TOOL) $(FDE)

$(PLUGIN): luks2-token-aurora-sep.c sep-seal.c sep-seal.h sep-fde.c sep-fde.h token.sym
	$(CC) $(CFLAGS) $(DEPS_CFLAGS) -shared -Wl,--version-script=token.sym \
		-Wl,-z,relro,-z,now -o $@ luks2-token-aurora-sep.c sep-seal.c sep-fde.c $(LDFLAGS) $(DEPS_LIBS)

$(FDE): aurora-sep-fde.c sep-fde.c sep-fde.h sep-seal.c sep-seal.h
	$(CC) $(CFLAGS) $(DEPS_CFLAGS) -fPIE -pie -Wl,-z,relro,-z,now -o $@ \
		aurora-sep-fde.c sep-fde.c sep-seal.c $(LDFLAGS) $(DEPS_LIBS)

$(TOOL): aurora-sep-cryptenroll.c sep-seal.c sep-seal.h
	$(CC) $(CFLAGS) $(DEPS_CFLAGS) -fPIE -pie -Wl,-z,relro,-z,now -o $@ \
		aurora-sep-cryptenroll.c sep-seal.c $(LDFLAGS) $(DEPS_LIBS)

# Test builds swap the SEP trusted key for a kernel "user" key, so the AF_ALG,
# token and LUKS2 paths run on any Linux >= 6.2. Kernels with af_alg_restrict
# need root (CAP_SYS_ADMIN or CAP_NET_ADMIN) to bind ccm(aes).
test/$(PLUGIN): luks2-token-aurora-sep.c sep-seal.c sep-seal.h sep-fde.c sep-fde.h token.sym
	mkdir -p test
	$(CC) $(CFLAGS) -DSEP_SEAL_TEST_USER_KEYS -DSEP_FDE_MOCK $(DEPS_CFLAGS) -shared \
		-Wl,--version-script=token.sym -o $@ luks2-token-aurora-sep.c sep-seal.c sep-fde.c $(DEPS_LIBS)

# Password mode against the file-backed enclave double (sep-fde.c, SEP_FDE_MOCK).
test/$(FDE): aurora-sep-fde.c sep-fde.c sep-fde.h sep-seal.c sep-seal.h
	mkdir -p test
	$(CC) $(CFLAGS) -DSEP_SEAL_TEST_USER_KEYS -DSEP_FDE_MOCK $(DEPS_CFLAGS) -o $@ \
		aurora-sep-fde.c sep-fde.c sep-seal.c $(DEPS_LIBS)

test/$(TOOL): aurora-sep-cryptenroll.c sep-seal.c sep-seal.h
	mkdir -p test
	$(CC) $(CFLAGS) -DSEP_SEAL_TEST_USER_KEYS $(DEPS_CFLAGS) -o $@ \
		aurora-sep-cryptenroll.c sep-seal.c $(DEPS_LIBS)

test/test-seal: tests/test-seal.c sep-seal.c sep-seal.h
	mkdir -p test
	$(CC) $(CFLAGS) -DSEP_SEAL_TEST_USER_KEYS $(DEPS_CFLAGS) -I. -o $@ \
		tests/test-seal.c sep-seal.c $(DEPS_LIBS)

check: test/test-seal test/$(PLUGIN) test/$(TOOL) test/$(FDE) $(PLUGIN) $(TOOL) $(FDE)
	./test/test-seal
	sh tests/test-luks.sh test
	sh tests/test-fde.sh test
	@nm -D --defined-only $(PLUGIN) | grep -q 'cryptsetup_token_open@@CRYPTSETUP_TOKEN_1.0' \
		&& echo "PASS plugin exports the CRYPTSETUP_TOKEN_1.0 ABI"

install: all
	install -Dm755 $(TOOL) $(DESTDIR)$(BINDIR)/$(TOOL)
	install -Dm755 $(FDE) $(DESTDIR)$(BINDIR)/$(FDE)
	install -Dm755 $(PLUGIN) $(DESTDIR)$(TOKENDIR)/$(PLUGIN)
	install -Dm644 aurora-sep-cryptenroll.8 $(DESTDIR)$(MANDIR)/man8/aurora-sep-cryptenroll.8

clean:
	rm -rf $(PLUGIN) $(TOOL) $(FDE) test

.PHONY: all check install clean
