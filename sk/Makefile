# SPDX-License-Identifier: MIT
# OpenSSH security-key provider for Secure Enclave keys (/dev/sep-key).

CC ?= cc
PKG_CONFIG ?= pkg-config
CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Werror=implicit-function-declaration -fPIC \
	-fvisibility=hidden -D_FORTIFY_SOURCE=2 -fstack-protector-strong
DEPS_CFLAGS := $(shell $(PKG_CONFIG) --cflags libcrypto)
DEPS_LIBS := $(shell $(PKG_CONFIG) --libs libcrypto)

PREFIX ?= /usr
LIBDIR ?= $(PREFIX)/lib
UDEVRULESDIR ?= $(PREFIX)/lib/udev/rules.d
SYSUSERSDIR ?= $(PREFIX)/lib/sysusers.d

LIB := libaurora-sep-sk.so
SRC := sk-aurora-sep.c sk-api.h sep-key.h

all: $(LIB)

$(LIB): $(SRC)
	$(CC) $(CFLAGS) $(DEPS_CFLAGS) -shared -Wl,-z,relro,-z,now -o $@ \
		sk-aurora-sep.c $(LDFLAGS) $(DEPS_LIBS)

# Test build: software P-256 keys stand in for the enclave, and presence can
# be stubbed. Never install it.
test/$(LIB): $(SRC)
	mkdir -p test
	$(CC) $(CFLAGS) -DAURORA_SEP_SK_TEST $(DEPS_CFLAGS) -shared -o $@ \
		sk-aurora-sep.c $(DEPS_LIBS)

check: $(LIB) test/$(LIB)
	@for s in sk_api_version sk_enroll sk_sign sk_load_resident_keys; do \
		nm -D --defined-only $(LIB) | grep -qw $$s || { echo "FAIL $(LIB) lacks $$s"; exit 1; }; \
	done; echo "PASS $(LIB) exports the OpenSSH sk API"
	@test "$$(nm -D --defined-only $(LIB) | grep -c ' T ')" = 4 \
		&& echo "PASS nothing else exported" || { echo "FAIL extra exports"; exit 1; }
	sh tests/test-sk.sh test/$(LIB)

install: all
	install -Dm755 $(LIB) $(DESTDIR)$(LIBDIR)/$(LIB)
	install -Dm644 70-aurora-sep-key.rules $(DESTDIR)$(UDEVRULESDIR)/70-aurora-sep-key.rules
	install -Dm644 aurora-sep-key.sysusers $(DESTDIR)$(SYSUSERSDIR)/aurora-sep-key.conf

clean:
	$(RM) $(LIB) test/$(LIB)

.PHONY: all check install clean
