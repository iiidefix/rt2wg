#!/bin/sh
# Builds an OpenWrt apk package (OpenWrt 25.12 and later) for one target
# architecture, without the OpenWrt SDK: cross-compile with Go, then pack
# with apk-tools v3 "apk mkpkg".
#
# usage: deploy/openwrt/build-apk.sh [arch]   (default x86_64)
#
# arch is the router's package architecture, OpenWrt's own name: the contents
# of /etc/apk/arch or DISTRIB_ARCH in /etc/openwrt_release on the router
# (x86_64, aarch64_cortex-a53, arm_cortex-a7_neon-vfpv4, mipsel_24kc, ...).
# "apk --print-arch" prints a different name that apk will not install.
# Set APK to an apk-tools v3 binary to skip downloading Alpine's apk.static.
# The package lands in dist/.
set -eu

arch=${1:-x86_64}
goarm=
gomips=
gomips64=
go386=
# The CPU and FPU in the arch name decide the Go target: hard float only
# where OpenWrt builds for an FPU (vfp/neon on ARM, 24kf on MIPS, SSE2 from
# the Pentium 4 on), since hard-float code dies with SIGILL without one.
case "$arch" in
	*_vfp* | *_neon* | *_24kf*) fpu=hardfloat ;;
	*) fpu=softfloat ;;
esac
case "$arch" in
	x86_64) goarch=amd64 ;;
	i386_pentium4*) goarch=386 go386=sse2 ;;
	i386_*) goarch=386 go386=softfloat ;;
	aarch64_*) goarch=arm64 ;;
	arm_cortex-a*) goarch=arm goarm=7 ;;
	arm_arm1176* | arm_mpcore*) goarch=arm goarm=6 ;;
	arm_*) goarch=arm goarm=5 ;;
	mipsel_*) goarch=mipsle gomips=$fpu ;;
	mips_*) goarch=mips gomips=$fpu ;;
	mips64el_*) goarch=mips64le gomips64=$fpu ;;
	mips64_*) goarch=mips64 gomips64=$fpu ;;
	riscv64_*) goarch=riscv64 ;;
	loongarch64_*) goarch=loong64 ;;
	*) echo "unsupported OpenWrt arch: $arch" >&2; exit 2 ;;
esac
# GOARM=5 is always soft float; for ARMv6 and ARMv7 Go assumes a VFP.
if [ "$fpu" = softfloat ] && [ "$goarch" = arm ] && [ "$goarm" != 5 ]; then
	goarm=$goarm,softfloat
fi

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"

# A tag on HEAD (v1.2.3) is the version; otherwise the commit time.
if tag=$(git describe --tags --exact-match 2>/dev/null); then
	version=${tag#v}
else
	version=0.0.0_git$(git log -1 --format=%cd --date=format:%Y%m%d%H%M%S)
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

if [ -z "${APK:-}" ]; then
	mirror=https://dl-cdn.alpinelinux.org/alpine/latest-stable/main/x86_64
	v=$(curl -fsS "$mirror/APKINDEX.tar.gz" | tar -xzO APKINDEX |
		awk '/^P:apk-tools-static$/ { f = 1 } f && /^V:/ { print substr($0, 3); f = 0 }')
	curl -fsS -o "$work/apk-static.apk" "$mirror/apk-tools-static-$v.apk"
	tar -xzf "$work/apk-static.apk" -C "$work" sbin/apk.static 2>/dev/null
	APK=$work/sbin/apk.static
fi

pkg=$work/pkg
mkdir -p "$pkg/usr/bin" "$pkg/etc/init.d" "$pkg/etc/config" "$pkg/lib/upgrade/keep.d"
CGO_ENABLED=0 GOOS=linux GOARCH=$goarch GOARM=$goarm GOMIPS=$gomips GOMIPS64=$gomips64 GO386=$go386 \
	go build -trimpath -ldflags='-s -w' -o "$pkg/usr/bin/rt2wg" ./cmd/rt2wg
install -m 0755 deploy/openwrt/rt2wg.init "$pkg/etc/init.d/rt2wg"
install -m 0644 deploy/openwrt/rt2wg.config "$pkg/etc/config/rt2wg"
# sysupgrade keeps these but not the binary, so on first boot the init
# script reinstalls the package from the url in /etc/config/rt2wg.
cat >"$pkg/lib/upgrade/keep.d/rt2wg" <<'EOF'
/etc/config/rt2wg
/etc/init.d/rt2wg
/etc/rc.d/S95rt2wg
EOF

# Enable and start on install, as OpenWrt's own packages do; files under
# /etc are kept by apk on upgrade, so local config edits survive.
cat >"$work/post-install" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT:-}" ] && exit 0
/etc/init.d/rt2wg enable
/etc/init.d/rt2wg start
exit 0
EOF
cat >"$work/post-upgrade" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT:-}" ] && exit 0
/etc/init.d/rt2wg restart
exit 0
EOF
cat >"$work/pre-deinstall" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT:-}" ] && exit 0
/etc/init.d/rt2wg stop
/etc/init.d/rt2wg disable
exit 0
EOF

mkdir -p dist
# Named after the OpenWrt arch, like OpenWrt's own packages.
out=dist/rt2wg-${version}_$arch.apk
"$APK" mkpkg \
	-I "name:rt2wg" \
	-I "version:$version-r1" \
	-I "description:Keeps WireGuard AllowedIPs in sync with the routing table" \
	-I "arch:$arch" \
	-I "license:GPL-3.0-or-later" \
	-I "depends:kmod-wireguard" \
	-I "build-time:$(date +%s)" \
	-s "post-install:$work/post-install" \
	-s "post-upgrade:$work/post-upgrade" \
	-s "pre-deinstall:$work/pre-deinstall" \
	-F "$pkg" \
	-o "$out"
echo "$out"
