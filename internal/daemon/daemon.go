// Package daemon runs reconcile passes: it owns the config, watches route
// events and applies desired AllowedIPs to the WireGuard device.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync/atomic"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"rt2wg/internal/config"
	"rt2wg/internal/desired"
	"rt2wg/internal/tables"
)

const (
	tickInterval     = 30 * time.Second
	resubscribeDelay = 2 * time.Second
	eventBuffer      = 100
	receiveBuffer    = 4 << 20
	dumpAttempts     = 3
)

// Daemon keeps the AllowedIPs of one WireGuard interface's managed peers in
// sync with the kernel routing table.
type Daemon struct {
	iface    string
	confPath string
	tables   *tables.Set
	wg       *wgctrl.Client
	log      *slog.Logger

	cfg *config.Config // owned by the run loop

	// ifindex is the interface index seen by the last pass; the only state
	// shared between goroutines.
	ifindex atomic.Int32
	trigger chan struct{} // capacity 1: pending triggers merge
}

// New returns a Daemon for iface with an already loaded config.
func New(iface, confPath string, ts *tables.Set, cfg *config.Config, wg *wgctrl.Client, log *slog.Logger) *Daemon {
	return &Daemon{
		iface:    iface,
		confPath: confPath,
		tables:   ts,
		cfg:      cfg,
		wg:       wg,
		log:      log,
		trigger:  make(chan struct{}, 1),
	}
}

// Run does the startup pass, starts the event watcher and runs passes until
// ctx is cancelled. hup delivers SIGHUP.
func (d *Daemon) Run(ctx context.Context, hup <-chan os.Signal) {
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	d.pass("startup")
	go d.watch(ctx)

	for {
		select {
		case <-ctx.Done():
			d.log.Info("shutting down")
			return
		case <-d.trigger:
			d.pass("event")
		case <-ticker.C:
			d.pass("ticker")
		case <-hup:
			d.reload()
			d.pass("sighup")
		}
	}
}

func (d *Daemon) reload() {
	cfg, err := config.Load(d.confPath)
	if err != nil {
		d.log.Error("config reload failed, keeping previous config", "err", err)
		return
	}
	d.cfg = cfg
	d.log.Info("config loaded", "path", d.confPath, "peers", len(cfg.Peers))
}

// requestPass triggers a pass without blocking; it merges with a pending one.
func (d *Daemon) requestPass() {
	select {
	case d.trigger <- struct{}{}:
	default:
	}
}

// pass is one reconcile run (REC-1..13).
func (d *Daemon) pass(reason string) {
	link, err := netlink.LinkByName(d.iface)
	if err != nil {
		d.log.Error("interface lookup failed", "err", err)
		return
	}
	idx := link.Attrs().Index
	if old := d.ifindex.Swap(int32(idx)); int(old) != idx {
		d.log.Info("interface index tracked", "index", idx)
	}

	routes, err := listRoutes(idx)
	if err != nil {
		d.log.Error("route dump failed", "err", err)
		return
	}
	dev, err := d.wg.Device(d.iface)
	if err != nil {
		d.log.Error("device read failed", "err", err)
		return
	}
	current := make(map[wgtypes.Key][]netip.Prefix, len(dev.Peers))
	for _, p := range dev.Peers {
		current[p.PublicKey] = normalizeIPNets(p.AllowedIPs)
	}

	want := desired.Desired(d.cfg, d.tables, routes)
	var changes []wgtypes.PeerConfig
	var changed []wgtypes.Key
	for _, p := range d.cfg.Peers {
		cur, ok := current[p.Key]
		if !ok {
			d.log.Debug("absent peer: in config but not on device", "peer", shortKey(p.Key))
			continue
		}
		if slices.Equal(cur, want[p.Key]) {
			continue
		}
		changes = append(changes, wgtypes.PeerConfig{
			PublicKey:         p.Key,
			UpdateOnly:        true,
			ReplaceAllowedIPs: true,
			AllowedIPs:        ipNets(want[p.Key]),
		})
		changed = append(changed, p.Key)
	}

	if len(changes) > 0 {
		if err := d.wg.ConfigureDevice(d.iface, wgtypes.Config{Peers: changes}); err != nil {
			d.log.Error("configure device failed", "err", err)
		} else {
			for _, k := range changed {
				added, removed := diff(current[k], want[k])
				d.log.Info("AllowedIPs updated", "peer", shortKey(k),
					"prefixes", len(want[k]), "added", added, "removed", removed)
			}
		}
	}
	d.log.Debug("pass", "reason", reason, "routes", len(routes), "changes", len(changes))
}

// listRoutes lists routes on the interface from all tables (NL-3, NL-4).
func listRoutes(idx int) ([]netlink.Route, error) {
	filter := &netlink.Route{LinkIndex: idx, Table: unix.RT_TABLE_UNSPEC}
	var err error
	for range dumpAttempts {
		var routes []netlink.Route
		routes, err = netlink.RouteListFiltered(netlink.FAMILY_ALL, filter,
			netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
		if !errors.Is(err, netlink.ErrDumpInterrupted) {
			return routes, err
		}
	}
	return nil, fmt.Errorf("route dump still interrupted after %d attempts: %w", dumpAttempts, err)
}

// watch subscribes to route events and triggers passes for relevant ones,
// resubscribing until ctx is cancelled (NL-5..7).
func (d *Daemon) watch(ctx context.Context) {
	for {
		d.subscribeOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(resubscribeDelay):
		}
		d.log.Warn("resubscribing to route events")
	}
}

// subscribeOnce runs one subscription until its channel closes or ctx ends.
func (d *Daemon) subscribeOnce(ctx context.Context) {
	ch := make(chan netlink.RouteUpdate, eventBuffer)
	done := make(chan struct{})
	defer close(done) // releases the subscription's socket
	err := netlink.RouteSubscribeWithOptions(ch, done, netlink.RouteSubscribeOptions{
		ReceiveBufferSize: receiveBuffer,
		ErrorCallback: func(err error) {
			if ctx.Err() == nil {
				d.log.Warn("route subscription error", "err", err)
			}
		},
	})
	if err != nil {
		d.log.Error("route subscribe failed", "err", err)
		return
	}
	d.requestPass() // catch up on anything missed while unsubscribed
	for {
		select {
		case <-ctx.Done():
			return
		case u, ok := <-ch:
			if !ok {
				return
			}
			if !desired.Relevant(d.tables, u) {
				continue
			}
			d.log.Debug("route event", "type", eventType(u.Type), "table", u.Table,
				"dst", u.Dst, "gw", u.Gw)
			d.requestPass()
		}
	}
}

func eventType(t uint16) string {
	switch t {
	case unix.RTM_NEWROUTE:
		return "add"
	case unix.RTM_DELROUTE:
		return "del"
	}
	return fmt.Sprint(t)
}

func normalizeIPNets(ns []net.IPNet) []netip.Prefix {
	ps := make([]netip.Prefix, 0, len(ns))
	for i := range ns {
		if p, ok := desired.PrefixFromIPNet(&ns[i]); ok {
			ps = append(ps, p)
		}
	}
	return config.Normalize(ps)
}

func ipNets(ps []netip.Prefix) []net.IPNet {
	out := make([]net.IPNet, len(ps))
	for i, p := range ps {
		out[i] = desired.IPNetFromPrefix(p)
	}
	return out
}

// diff counts prefixes in want but not cur (added) and in cur but not want.
func diff(cur, want []netip.Prefix) (added, removed int) {
	for _, p := range want {
		if !slices.Contains(cur, p) {
			added++
		}
	}
	for _, p := range cur {
		if !slices.Contains(want, p) {
			removed++
		}
	}
	return added, removed
}

// short identifies a peer in logs by the first 8 characters of its key.
func shortKey(k wgtypes.Key) string { return k.String()[:8] }
