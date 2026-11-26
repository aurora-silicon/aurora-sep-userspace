#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Run aurora-touchid-accounts against fake getent and fprintd-delete.
# Usage: test_touchid_accounts.sh path/to/aurora-touchid-accounts
set -eu

script=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/storage"

# The passwd database: alice 1001, carol 1004 (her record says 1003),
# frank 1006; erin's lookup fails; everyone else is unknown.
cat >"$work/bin/getent" <<'EOF'
#!/bin/sh
case "$2" in
alice) echo "alice:x:1001:1001::/home/alice:/bin/sh" ;;
carol) echo "carol:x:1004:1004::/home/carol:/bin/sh" ;;
frank) echo "frank:x:1006:1006::/home/frank:/bin/sh" ;;
erin) exit 1 ;;
*) exit 2 ;;
esac
EOF
# Deleting dave's prints fails, as with the reader unavailable.
cat >"$work/bin/fprintd-delete" <<EOF
#!/bin/sh
echo "\$1" >>"$work/deleted"
[ "\$1" != dave ] || exit 1
rm -rf "$work/storage/\$1/apple-sep"
EOF
chmod +x "$work/bin/getent" "$work/bin/fprintd-delete"

account() {
	# account NAME [UID]: a stored print, and a record unless UID is "legacy".
	mkdir -p "$work/storage/$1/apple-sep/serial"
	echo print >"$work/storage/$1/apple-sep/serial/7"
	[ "$2" = legacy ] && return
	printf '[Account]\nUID=%s\nInstance=11111111-1111-4111-8111-111111111111\n\n[Prints]\napple-sep/serial/7=11111111-1111-4111-8111-111111111111\n' \
		"$2" >"$work/storage/$1/account"
}

account alice 1001
account bob 1002
account carol 1003
account dave 1005
account erin 1007
account frank legacy
account gina legacy

status=0
PATH="$work/bin:$PATH" STATE_DIRECTORY="$work/storage:/unused" "$script" >"$work/out" 2>&1 || status=$?

fail() { echo "FAIL: $*"; cat "$work/out"; exit 1; }

[ "$status" -eq 1 ] || fail "exit status $status, expected 1 for dave"
deleted=$(sort "$work/deleted" | tr '\n' ' ')
[ "$deleted" = "bob carol dave gina " ] || fail "deleted '$deleted'"

# Live accounts, a failed lookup and adoptable prints are untouched.
for user in alice erin frank; do
	[ -f "$work/storage/$user/apple-sep/serial/7" ] || fail "$user lost a print"
done
grep -q '^UID=1001$' "$work/storage/alice/account" || fail "alice's record changed"
[ ! -e "$work/storage/frank/account" ] || fail "frank's prints got a record"

# Removed and re-created accounts lose their prints and records.
for user in bob carol gina; do
	[ ! -e "$work/storage/$user" ] || fail "$user's storage is still there"
done

# dave's prints could not be deleted: they stay, bound to nothing.
[ -f "$work/storage/dave/apple-sep/serial/7" ] || fail "dave's print vanished"
grep -q '^UID=$' "$work/storage/dave/account" || fail "dave's record kept a uid"
if grep -q '11111111-1111-4111-8111-111111111111' "$work/storage/dave/account"; then
	fail "dave's record kept its instance"
fi
[ "$(stat -c %a "$work/storage/dave/account")" = 600 ] || fail "dave's record is not 0600"

echo "aurora-touchid-accounts: all checks passed"
