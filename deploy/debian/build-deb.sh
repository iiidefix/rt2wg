#!/bin/sh
# Builds a Debian package for one target architecture: cross-compile with Go,
# then pack with dpkg-deb. No debhelper or Debian build tree needed.
#
# usage: deploy/debian/build-deb.sh [arch]   (default: this machine's)
#
# arch is Debian's name for the target: "dpkg --print-architecture" on it
# (amd64, arm64, armhf, armel, i386, riscv64, ...). armhf is built for ARMv6,
# so one package runs on Raspberry Pi OS on every Pi as well as on Debian.
# The package lands in dist/.
set -eu

arch=${1:-$(dpkg --print-architecture)}
goarm=
case "$arch" in
	amd64) goarch=amd64 ;;
	i386) goarch=386 ;;
	arm64) goarch=arm64 ;;
	armhf) goarch=arm goarm=6 ;;
	armel) goarch=arm goarm=5 ;;
	riscv64) goarch=riscv64 ;;
	ppc64el) goarch=ppc64le ;;
	s390x) goarch=s390x ;;
	mips64el) goarch=mips64le ;;
	loong64) goarch=loong64 ;;
	*) echo "unsupported Debian arch: $arch" >&2; exit 2 ;;
esac

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"

# A tag on HEAD (v1.2.3) is the version; otherwise the commit time, after a
# "~" so that a snapshot sorts before the release it leads up to.
if tag=$(git describe --tags --exact-match 2>/dev/null); then
	version=${tag#v}
else
	version=0.0.0~git$(git log -1 --format=%cd --date=format:%Y%m%d%H%M%S)
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

pkg=$work/pkg
mkdir -p "$pkg/DEBIAN" "$pkg/usr/bin" "$pkg/usr/lib/systemd/system" \
	"$pkg/usr/share/doc/rt2wg"
CGO_ENABLED=0 GOOS=linux GOARCH=$goarch GOARM=$goarm \
	go build -trimpath -ldflags='-s -w' -o "$pkg/usr/bin/rt2wg" ./cmd/rt2wg
# Packages install to /usr/bin, not /usr/local/bin as install.sh does.
sed 's|/usr/local/bin/rt2wg|/usr/bin/rt2wg|' deploy/rt2wg@.service \
	>"$pkg/usr/lib/systemd/system/rt2wg@.service"
chmod 0644 "$pkg/usr/lib/systemd/system/rt2wg@.service"
install -m 0644 LICENSE "$pkg/usr/share/doc/rt2wg/copyright"

cat >"$pkg/DEBIAN/control" <<EOF
Package: rt2wg
Version: $version-1
Architecture: $arch
Maintainer: $(git log -1 --format='%an <%ae>')
Installed-Size: $(du -sk "$pkg/usr" | cut -f1)
Recommends: wireguard-tools
Section: net
Priority: optional
Description: Keeps WireGuard AllowedIPs in sync with the routing table
 Assigns the destinations of kernel routes whose gateway is a WireGuard
 peer's tunnel address to that peer's AllowedIPs, so the routes carry
 traffic. One instance runs per interface: systemctl enable --now rt2wg@wg0.
EOF

# The unit is a template, so nothing is enabled on install: the interface
# is the operator's choice. Upgrades restart the running instances; removal
# stops them.
cat >"$pkg/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
[ "$1" = configure ] || exit 0
[ -d /run/systemd/system ] || exit 0
systemctl daemon-reload
if [ -e /etc/systemd/system/rt2wg@.service ]; then
	echo "warning: /etc/systemd/system/rt2wg@.service (from install.sh) overrides the packaged unit; remove it and /usr/local/bin/rt2wg" >&2
fi
[ -z "$2" ] || systemctl try-restart 'rt2wg@*.service' || :
EOF
cat >"$pkg/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
[ "$1" = remove ] || exit 0
[ -d /run/systemd/system ] || exit 0
systemctl stop 'rt2wg@*.service' || :
EOF
# Purge drops the instances' enable links; /etc/default/rt2wg-* stay, as
# the operator wrote them.
cat >"$pkg/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
case "$1" in
	purge) rm -f /etc/systemd/system/*.wants/rt2wg@*.service ;;
	remove) ;;
	*) exit 0 ;;
esac
[ -d /run/systemd/system ] || exit 0
systemctl daemon-reload || :
EOF
chmod 0755 "$pkg/DEBIAN/postinst" "$pkg/DEBIAN/prerm" "$pkg/DEBIAN/postrm"

mkdir -p dist
out=dist/rt2wg_$version-1_$arch.deb
dpkg-deb --root-owner-group -Zxz --build "$pkg" "$out" >/dev/null
echo "$out"
