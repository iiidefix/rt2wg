#!/bin/sh
# Installs rt2wg as a systemd service for one WireGuard interface, asking for
# each environment variable and writing the answers to
# /etc/default/rt2wg-<iface>.
#
# usage, as root: ./install.sh   (in the directory "make" builds in dist/,
#                                 or the tarball's unpacked copy of it)
#
# It installs the rt2wg binary and rt2wg@.service unit that sit next to it.
# Each question offers the current value from the env file, or the built-in
# default; press enter to keep it, or enter "-" to reset it to the default.
# Lines in the env file that rt2wg doesn't read are kept.
# Without a terminal on stdin, nothing is asked and current values are kept.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
bin=$here/rt2wg
unit=$here/rt2wg@.service
for f in "$bin" "$unit"; do
	if [ ! -f "$f" ]; then
		echo "$f: not found; run make and use the install.sh in dist/" >&2
		exit 1
	fi
done

if [ "$(id -u)" -ne 0 ]; then
	echo "run as root" >&2
	exit 1
fi

cleanup=
trap 'rm -f $cleanup' EXIT

interactive=
[ -t 0 ] && interactive=1

# ask VAR PROMPT DEFAULT: sets VAR to the answer, or DEFAULT on enter.
ask() {
	if [ -n "$interactive" ]; then
		printf '%s [%s]: ' "$2" "$3"
		read -r answer || answer=
	else
		answer=
	fi
	case "$answer" in
		*[[:space:]\"\'\\]*) echo "no spaces, quotes or backslashes, please" >&2; ask "$@"; return ;;
	esac
	eval "$1=\${answer:-\$3}"
}

# current VAR: prints VAR's value in the env file, without quotes.
current() {
	[ -f "$envfile" ] || return 0
	sed -n "s/^[[:space:]]*$1=//p" "$envfile" | tail -n 1 | sed 's/^"\(.*\)"$/\1/; s/^'\''\(.*\)'\''$/\1/'
}

# --- Interface

def_iface=$(ip -o link show type wireguard 2>/dev/null | awk -F': ' 'NR == 1 { print $2 }')
ask iface "WireGuard interface" "${def_iface:-wg0}"
if ! ip link show dev "$iface" >/dev/null 2>&1; then
	echo "note: $iface doesn't exist yet; the service fails and restarts every 5 s until it does"
fi

envfile=/etc/default/rt2wg-$iface

# --- Environment variables

# For each variable: built-in default, then the question.
set -- \
	WG_CONF_PATH "/etc/wireguard/$iface.conf" "wg-style config file listing the peers" \
	WG_ROUTE_TABLES main "Routing tables to monitor, in rank order (names, ids, or all)" \
	LOG_LEVEL info "Log level (info or debug)"

[ -f "$envfile" ] && echo "current settings from $envfile"

tmp=$(mktemp)
cleanup="$cleanup $tmp $tmp.new"
[ -f "$envfile" ] && cat "$envfile" >"$tmp"
[ -s "$tmp" ] || echo "# rt2wg settings for $iface; see the README for each variable." >"$tmp"

while [ $# -gt 0 ]; do
	var=$1 def=$2 question=$3
	shift 3
	cur=$(current "$var")
	while :; do
		ask value "$question" "${cur:-$def}"
		[ "$value" = - ] && value=$def
		case "$var=$value" in
			LOG_LEVEL=info | LOG_LEVEL=debug | WG_CONF_PATH=* | WG_ROUTE_TABLES=*) break ;;
			*) echo "expected info or debug" >&2 ;;
		esac
		[ -n "$interactive" ] || { value=$def; break; }
	done
	if [ "$var" = WG_CONF_PATH ]; then
		[ -r "$value" ] || echo "note: $value doesn't exist yet; rt2wg won't start without it"
		case "$value" in
			/home/* | /root/* | /run/user/*) echo "warning: the service can't read $value (ProtectHome=yes)" >&2 ;;
		esac
	fi
	# Drop the old setting; write the new one only if it isn't the default.
	grep -v "^[[:space:]]*$var=" "$tmp" >"$tmp.new" || :
	mv "$tmp.new" "$tmp"
	[ "$value" = "$def" ] || echo "$var=$value" >>"$tmp"
done

# --- Install

install -m 0755 "$bin" /usr/local/bin/rt2wg
install -m 0644 "$unit" /etc/systemd/system/
install -d -m 0755 /etc/default
install -m 0644 "$tmp" "$envfile"
echo "wrote $envfile:"
sed 's/^/  /' "$envfile"

systemctl daemon-reload
systemctl enable "rt2wg@$iface"
systemctl restart "rt2wg@$iface"
echo "rt2wg@$iface is enabled and (re)started; logs: journalctl -u rt2wg@$iface"
