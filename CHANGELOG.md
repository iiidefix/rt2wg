# Changelog

All notable changes to rt2wg. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## Unreleased

## 0.3.0 - 2026-10-18

### Changed

- Route dumps are filtered by the kernel (Linux 4.20+), so a pass no longer
  parses every route in every table. With 100,000 unrelated routes, a dump
  went from 40 MB and 400,000 allocations to 0.3 MB and 850, about 10 times
  faster.
- Computing AllowedIPs looks up gateway owners in an index instead of
  scanning every peer for every route: about 6 times faster with 7 times less
  memory for 64 peers and 4,096 routes.
- An event pass starts no sooner than 100 ms after the previous pass, so a
  burst of route changes or a churning monitored table cannot keep a core
  busy. An isolated event is still handled at once.

## 0.2.4 - 2026-10-17

### Added

- OpenWrt: `mips64` and `mips64el` targets.

### Changed

- OpenWrt: the apk file is named after the OpenWrt arch
  (`rt2wg-<version>_<arch>.apk`, e.g. `_arm_cortex-a7_neon-vfpv4`) instead
  of the Go target, like OpenWrt's own packages.

### Fixed

- OpenWrt: the build follows the FPU in the arch name. ARMv6 and ARMv7
  targets without `vfp` or `neon` (e.g. `arm_cortex-a9`) are built soft-float
  instead of crashing with an illegal instruction, `mipsel_24kc_24kf` is
  built hard-float, and `i386_pentium4` uses SSE2.

## 0.2.3 - 2026-10-17

### Added

- `deploy/debian/build-deb.sh` builds a Debian package
  (`dist/rt2wg_<version>-1_<arch>.deb`) for a Debian arch name. The package
  installs `/usr/bin/rt2wg` and the `rt2wg@.service` template; upgrades
  restart running instances and removal stops them. `armhf` is built for
  ARMv6 so it runs on every Raspberry Pi.

## 0.2.2 - 2026-10-17

### Added

- OpenWrt: the package survives sysupgrade. Set `url` in the new `package`
  section of `/etc/config/rt2wg`; sysupgrade keeps the config and init
  script, and on first boot the init script reinstalls the package from
  `url`. `/etc/init.d/rt2wg upgrade` installs it on demand.

## 0.2.1 - 2026-10-17

### Changed

- OpenWrt: the apk file name drops the `-r1` release suffix
  (`rt2wg-<version>_<target>.apk`).

## 0.2.0 - 2026-10-17

### Added

- `make` builds rt2wg and bundles it with the systemd unit and
  `install.sh` into `dist/rt2wg-<version>-linux-<arch>.tar.gz`.
  `install.sh` installs the service for one interface, asking for each
  setting and writing them to `/etc/default/rt2wg-<iface>`.
- OpenWrt: `i386`, `riscv64` and `loongarch64` targets.

### Changed

- OpenWrt: the apk file is named after the Go target (`amd64`, `armv7`,
  `mipsle`, ...) instead of the OpenWrt arch.

### Fixed

- OpenWrt: ARM targets other than Cortex-A and ARM1176 are built for ARMv5
  instead of ARMv7.

## 0.1.0 - 2026-10-16

Initial release.

### Added

- The rt2wg daemon: keeps each managed peer's AllowedIPs equal to its static
  prefixes plus the routed prefixes of routes whose gateway it owns, across
  the monitored tables in rank order.
- `rt2wg@.service` systemd template unit, one instance per WireGuard
  interface; SIGHUP reloads the config.
- OpenWrt apk build script, procd init script and UCI config.

