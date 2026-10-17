# rt2wg

Keeps the AllowedIPs of WireGuard peers in sync with the kernel routing table.

A routing daemon (BIRD, FRR, or plain `ip route`) installs routes on a
WireGuard interface with a peer's tunnel address as the gateway:

```bash
ip route add 192.168.50.0/24 via 10.0.0.2 dev wg0
```

WireGuard drops that traffic unless `192.168.50.0/24` is in some peer's
AllowedIPs. rt2wg adds it to the peer that owns `10.0.0.2`, moves it when the
route changes gateway, and removes it when the route goes away.

## Build and install

```bash
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o rt2wg ./cmd/rt2wg
install -m 0755 rt2wg /usr/local/bin/
install -m 0644 deploy/rt2wg@.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now rt2wg@wg0
```

Or run `make`, which bundles the binary, the unit and an install script into
`dist/rt2wg-<version>-linux-<arch>.tar.gz` (`make GOARCH=arm64`, or
`GOARCH=arm GOARM=7`, to cross-compile). Unpack it on the target and run
`./install.sh` as root in the unpacked directory: it does the same as above
for one interface after asking for each variable below, and writes the
answers to `/etc/default/rt2wg-<iface>`. Run it again to change them.

One instance runs per WireGuard interface. Reload the config with
`systemctl reload rt2wg@wg0` (SIGHUP).

### Raspberry Pi

Cross-compile on another machine and copy the binary to the Pi:

```bash
# 64-bit Raspberry Pi OS (Pi 3, 4, 5, Zero 2 W)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o rt2wg-linux-arm64 ./cmd/rt2wg

# 32-bit Raspberry Pi OS on Pi 2, 3, 4, Zero 2 W
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -ldflags='-s -w' -o rt2wg-linux-armv7 ./cmd/rt2wg

# Pi 1 and Zero / Zero W
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 go build -trimpath -ldflags='-s -w' -o rt2wg-linux-armv6 ./cmd/rt2wg
```

Run `uname -m` on the Pi to check: `aarch64` means arm64, and `armv7l` or
`armv6l` means 32-bit.

### OpenWrt

On OpenWrt 25.12 and later, build an apk package for the router's
architecture: `DISTRIB_ARCH` in the router's `/etc/openwrt_release`
(default `x86_64`):

```bash
deploy/openwrt/build-apk.sh arm_cortex-a7_neon-vfpv4
```

This cross-compiles rt2wg and packs it with Alpine's static apk-tools
(downloaded on each run; set `APK` to use your own apk-tools v3) into
`dist/`. The package is unsigned, so install it with:

```bash
apk add --allow-untrusted rt2wg-*.apk
```

Installing enables and starts the service; `/etc/config/rt2wg` is kept
across upgrades.

Each `instance` section in `/etc/config/rt2wg` runs rt2wg for one interface
(`interface`, default the section name), with optional `tables` and
`log_level` instead of the environment variables. The netifd interface name
must match the WireGuard device name, which is how netifd names it anyway.

Peers are read from the interface's `wireguard_<iface>` sections in
`/etc/config/network` (`public_key`, `allowed_ips`, `disabled`), written to
`/var/run/rt2wg/<iface>.conf` and passed as `WG_CONF_PATH`. `reload_config`
or `/etc/init.d/rt2wg reload` regenerates the file and sends SIGHUP; the
instance also reloads when its interface comes up or goes down. Logs go to
`logread`.

## Configuration

Environment variables only (put overrides in `/etc/default/rt2wg-<iface>`):

| Variable | Default | Meaning |
|---|---|---|
| `WG_INTERFACE` | `wg0` | WireGuard interface to manage (the unit sets it to the instance name). |
| `WG_CONF_PATH` | `/etc/wireguard/$WG_INTERFACE.conf` | wg-style config file listing the peers. |
| `WG_ROUTE_TABLES` | `main` | Routing tables to monitor, in rank order: names, ids, or `all`. |
| `LOG_LEVEL` | `info` | `debug` logs every relevant route event and pass. |

Example: `WG_ROUTE_TABLES=bird,main,all` prefers routes in table `bird`, then
`main`, then any other table.

## How peers get prefixes

- A peer's **tunnel prefixes** are its `AllowedIPs` from the config file,
  except default prefixes (`0.0.0.0/0`, `::/0`).
- A route's gateway belongs to the peer with the most specific tunnel prefix
  containing it.
- Each routed prefix goes to exactly one peer. When several routes share a
  destination, the winner is the one in the lowest-ranked table, then the one
  with the lowest metric, then the peer with the lowest public key.
- Default routes, multipath routes, routes without a gateway, routes in
  unmonitored tables, and routes whose destination is exactly a peer's tunnel
  prefix are never synced.

## What rt2wg will and will not touch

These follow from a deliberate choice to keep no state between passes: each
pass derives every peer's AllowedIPs from the config and the routing table
alone.

- **Peers in the config** get exactly their config `AllowedIPs` plus the
  routed prefixes they own. **Anything you add with `wg set ... allowed-ips`
  is removed** within 30 seconds. Put permanent prefixes in the config file.
- **Peers not in the config are never written.** If you remove a peer from
  the config and reload, it keeps whatever AllowedIPs it had, including
  prefixes rt2wg gave it. Remove the peer from the device yourself.
- **Full-tunnel peers** keep `0.0.0.0/0` / `::/0`, but those prefixes never
  make the peer the owner of a gateway. Otherwise every gateway would match
  the full-tunnel peer and all routed prefixes would land on it.
- **On shutdown nothing is reverted.** The routes still exist, so stripping
  prefixes would blackhole traffic during a restart.
- rt2wg never creates or removes peers, routes, addresses or interfaces.

## Tests

```bash
go test ./...                          # unit tests, no privileges
go test -tags e2e ./e2e                # end-to-end, as root, needs WireGuard (~35 s)
```

The end-to-end test runs in its own network namespace and leaves the host
untouched.

## License

Copyright (C) 2026 iiidefix

rt2wg is free software: you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version. See `LICENSE`.

If you would like to use rt2wg under a different license, contact the author.
