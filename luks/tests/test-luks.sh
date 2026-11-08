#!/bin/sh
# SPDX-License-Identifier: MIT
# Unprivileged LUKS2 tests on a regular file, using the test builds (kernel
# "user" keys stand in for the SEP). Usage: tests/test-luks.sh <test build dir>
set -eu
B=$(cd "$1" && pwd)
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
CS0="cryptsetup --disable-locks --batch-mode"
CS="$CS0 --external-tokens-path $B"
fails=0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1"; fails=$((fails + 1)); }
try() { if "$@" >"$T/out" 2>&1; then return 0; else cat "$T/out" >&2; return 1; fi; }

img=$T/img
truncate -s 32M "$img"
printf 'recovery passphrase' > "$T/pass"
$CS0 luksFormat --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
	--luks2-metadata-size 64k --luks2-keyslots-size 1m "$img" "$T/pass"

if try "$B/aurora-sep-cryptenroll" --unlock-key-file="$T/pass" "$img"; then pass "enroll"; else fail "enroll"; fi
if $CS luksDump "$img" | grep -q 'aurora-sep'; then pass "luksDump shows the token"; else fail "luksDump"; fi
if $CS luksDump "$img" | grep -q 'Sealed by:   Apple Secure Enclave'; then pass "plugin dump hook"; else fail "plugin dump hook"; fi
if try $CS open --test-passphrase --token-only "$img"; then pass "cryptsetup opens through the token plugin"; else fail "token open"; fi
if try $CS open --test-passphrase --key-file "$T/pass" "$img"; then pass "recovery passphrase still opens"; else fail "recovery passphrase"; fi
if PASSWORD='wrong' "$B/aurora-sep-cryptenroll" "$img" >/dev/null 2>&1; then fail "wrong passphrase must not enroll"; else pass "wrong passphrase refused"; fi
if "$B/aurora-sep-cryptenroll" --test "$img" | grep -q 'opens its keyslot'; then pass "--test"; else fail "--test"; fi

# Same header under another UUID: the token is bound to its volume.
cp "$img" "$T/clone"
$CS0 luksUUID --uuid 6b7a0d6a-1111-4222-8333-944455556666 "$T/clone"
if $CS open --test-passphrase --token-only "$T/clone" >/dev/null 2>&1; then fail "token must not open a re-UUIDed clone"; else pass "token bound to the LUKS UUID"; fi
if try $CS open --test-passphrase --key-file "$T/pass" "$T/clone"; then pass "clone still opens with the recovery passphrase"; else fail "clone recovery"; fi

# Re-enroll with --wipe-slot=sep: one SEP enrolment remains and it works.
if try env PASSWORD='recovery passphrase' "$B/aurora-sep-cryptenroll" --wipe-slot=sep "$img"; then pass "re-enroll with --wipe-slot=sep"; else fail "re-enroll"; fi
n=$("$B/aurora-sep-cryptenroll" --status "$img" | grep -c '^token ')
[ "$n" = 1 ] && pass "exactly one SEP token after wipe" || fail "token count $n"
if try $CS open --test-passphrase --token-only "$img"; then pass "new token opens"; else fail "new token open"; fi

# Never remove the last non-SEP keyslot.
$CS0 luksRemoveKey "$img" "$T/pass"
if "$B/aurora-sep-cryptenroll" --remove "$img" >/dev/null 2>&1; then fail "--remove must refuse without a recovery slot"; else pass "--remove refuses to strand the volume"; fi
if try $CS open --test-passphrase --token-only "$img"; then pass "token still opens after refused remove"; else fail "token after refused remove"; fi
if PASSWORD=x "$B/aurora-sep-cryptenroll" --wipe-slot=sep "$img" >/dev/null 2>&1; then fail "enroll needs a passphrase"; else pass "enroll needs a passphrase slot"; fi

# Fresh volume: remove works and the token is gone.
rm -f "$img"; truncate -s 32M "$img"
$CS0 luksFormat --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 "$img" "$T/pass"
try "$B/aurora-sep-cryptenroll" -q --unlock-key-file="$T/pass" "$img" || fail "enroll 2"
if try "$B/aurora-sep-cryptenroll" --remove "$img"; then pass "--remove"; else fail "--remove"; fi
if $CS luksDump "$img" | grep -q 'aurora-sep'; then fail "token left after remove"; else pass "token gone after remove"; fi
if $CS open --test-passphrase --token-only "$img" >/dev/null 2>&1; then fail "token-only open after remove"; else pass "no token unlock after remove"; fi
if try $CS open --test-passphrase --key-file "$T/pass" "$img"; then pass "passphrase opens after remove"; else fail "passphrase after remove"; fi

echo "test-luks: $fails failure(s)"
[ "$fails" = 0 ]
