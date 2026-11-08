#!/bin/sh
# SPDX-License-Identifier: MIT
# OpenSSH end-to-end checks for libaurora-sep-sk.so.
#   sh tests/test-sk.sh <provider.so> [hw]
# With the test build, software P-256 keys stand in for the enclave. With "hw"
# the real provider talks to /dev/sep-key; presence is never stubbed there, so
# only no-touch-required keys are used and no finger is needed.
set -eu
P=$(realpath "$1")
MODE=${2:-test}
T=$(mktemp -d)
trap 'rm -rf -- "${T:?}"' EXIT
pass=0; fail=0
ok() { echo "PASS $*"; pass=$((pass + 1)); }
bad() { echo "FAIL $*"; fail=$((fail + 1)); }
export SSH_SK_PROVIDER="$P"
unset SSH_AUTH_SOCK

# 1. enrol a key that needs no touch
if ssh-keygen -q -t ecdsa-sk -w "$P" -O no-touch-required -N '' -C sepkey-test -f "$T/id" </dev/null; then
	ok "enrol ecdsa-sk (no-touch-required)"
else
	bad "enrol ecdsa-sk"; echo "$pass passed, $fail failed"; exit 1
fi
grep -q '^sk-ecdsa-sha2-nistp256@openssh.com ' "$T/id.pub" && ok "public key type sk-ecdsa-sha2-nistp256" || bad "public key type"

# 2. ssh-keygen -Y sign / verify
printf 'aurora sep key test\n' > "$T/msg"
echo "tester $(cut -d' ' -f1,2 "$T/id.pub")" > "$T/allowed"
if ssh-keygen -q -Y sign -f "$T/id" -n file "$T/msg" </dev/null >/dev/null 2>"$T/sign.err"; then
	ok "ssh-keygen -Y sign"
else
	bad "ssh-keygen -Y sign: $(cat "$T/sign.err")"
fi
ssh-keygen -Y verify -f "$T/allowed" -I tester -n file -s "$T/msg.sig" < "$T/msg" >/dev/null 2>&1 \
	&& ok "ssh-keygen -Y verify" || bad "ssh-keygen -Y verify"
printf 'tampered\n' | ssh-keygen -Y verify -f "$T/allowed" -I tester -n file -s "$T/msg.sig" >/dev/null 2>&1 \
	&& bad "a tampered message verified" || ok "tampered message refused"

# 3. a second key signs too, and its signature does not verify as the first
ssh-keygen -q -t ecdsa-sk -w "$P" -O no-touch-required -N '' -f "$T/id2" </dev/null
cp "$T/msg" "$T/msg2"
ssh-keygen -q -Y sign -f "$T/id2" -n file "$T/msg2" </dev/null >/dev/null 2>&1
ssh-keygen -Y verify -f "$T/allowed" -I tester -n file -s "$T/msg2.sig" < "$T/msg2" >/dev/null 2>&1 \
	&& bad "key 2 verified as key 1" || ok "keys are distinct"

# 4. presence: refused when denied; the test build can stub it
ssh-keygen -q -t ecdsa-sk -w "$P" -N '' -f "$T/idp" </dev/null
cp "$T/msg" "$T/msgp"
AURORA_SEP_SK_PRESENCE=deny ssh-keygen -q -Y sign -f "$T/idp" -n file "$T/msgp" </dev/null >/dev/null 2>&1 \
	&& bad "signed with presence denied" || ok "presence denied -> no signature"
if [ "$MODE" = test ]; then
	AURORA_SEP_SK_PRESENCE=test-allow ssh-keygen -q -Y sign -f "$T/idp" -n file "$T/msgp" </dev/null >/dev/null 2>&1 \
		&& ok "presence stubbed -> signature" || bad "presence stubbed signature"
	echo "tester $(cut -d' ' -f1,2 "$T/idp.pub")" > "$T/allowedp"
	ssh-keygen -Y verify -f "$T/allowedp" -I tester -n file -s "$T/msgp.sig" < "$T/msgp" 2>&1 | grep -q 'Good' \
		&& ok "presence signature verifies" || bad "presence signature verify"
	AURORA_SEP_SK_TEST_REJECT=1 ssh-keygen -q -Y sign -f "$T/id" -n file "$T/msg2" </dev/null >/dev/null 2>&1 \
		&& bad "signed with a rejected handle" || ok "rejected handle -> no signature"
fi

# 5. Ed25519 and resident keys are refused
ssh-keygen -q -t ed25519-sk -w "$P" -N '' -f "$T/ided" </dev/null >/dev/null 2>&1 \
	&& bad "ed25519-sk enrolled" || ok "ed25519-sk refused"
ssh-keygen -q -t ecdsa-sk -w "$P" -O resident -N '' -f "$T/idr" </dev/null >/dev/null 2>&1 \
	&& bad "resident key enrolled" || ok "resident key refused"

# 6. git commit signing
if command -v git >/dev/null; then
	mkdir "$T/repo" "$T/home"
	G="git -C $T/repo -c user.name=t -c user.email=t@example.invalid -c gpg.format=ssh -c user.signingkey=$T/id -c gpg.ssh.allowedSignersFile=$T/allowed"
	HOME="$T/home" git init -q "$T/repo"
	if HOME="$T/home" $G commit -q -S --allow-empty -m signed 2>"$T/git.err"; then
		ok "git commit -S"
		HOME="$T/home" $G verify-commit HEAD >/dev/null 2>&1 && ok "git verify-commit" || bad "git verify-commit"
	else
		bad "git commit -S: $(cat "$T/git.err")"
	fi
else
	echo "SKIP git not installed"
fi

# 7. ssh login through a private sshd in inetd mode (no port, no system config)
SSHD=$(command -v sshd || ls /usr/sbin/sshd 2>/dev/null || true)
if [ -n "$SSHD" ] && [ -z "${AURORA_SEP_SK_NO_SSHD:-}" ]; then
	ssh-keygen -q -t ed25519 -N '' -f "$T/hostkey"
	echo "no-touch-required $(cut -d' ' -f1,2 "$T/id.pub")" > "$T/authorized_keys"
	chmod 600 "$T/authorized_keys"
	cat > "$T/sshd_config" <<-EOF
	HostKey $T/hostkey
	AuthorizedKeysFile $T/authorized_keys
	PubkeyAuthentication yes
	PasswordAuthentication no
	KbdInteractiveAuthentication no
	UsePAM no
	StrictModes no
	PidFile none
	EOF
	if ssh -F none -i "$T/id" -o IdentitiesOnly=yes -o BatchMode=yes -o SecurityKeyProvider="$P" \
		-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
		-o ProxyCommand="$SSHD -i -e -f $T/sshd_config" "$(id -un)@sepkey-test" \
		'echo sepkey-login-ok' 2>"$T/ssh.err" | grep -q sepkey-login-ok; then
		ok "ssh login with the key"
	else
		bad "ssh login: $(tr '\n' ' ' < "$T/ssh.err" | cut -c1-400)"
	fi
	echo "no-touch-required $(cut -d' ' -f1,2 "$T/id2.pub")" > "$T/authorized_keys"
	ssh -F none -i "$T/id" -o IdentitiesOnly=yes -o BatchMode=yes -o SecurityKeyProvider="$P" \
		-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
		-o ProxyCommand="$SSHD -i -e -f $T/sshd_config" "$(id -un)@sepkey-test" true 2>/dev/null \
		&& bad "login with a key that is not authorised" || ok "unauthorised key refused"
else
	echo "SKIP sshd login"
fi

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
