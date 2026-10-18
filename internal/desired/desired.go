// Package desired computes each peer's AllowedIPs from the config, the
// monitored tables and the kernel routes. Everything here is pure.
package desired

import (
	"bytes"
	"cmp"
	"net"
	"net/netip"
	"slices"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"rt2wg/internal/config"
	"rt2wg/internal/tables"
)

// Desired returns the AllowedIPs every peer in the config should have: its
// static prefixes plus the routed prefixes it owns. Each list is normalized.
// Lists of peers that own no routed prefix share memory with cfg; treat the
// result as read-only.
func Desired(cfg *config.Config, ts *tables.Set, routes []netlink.Route) map[wgtypes.Key][]netip.Prefix {
	cands := make([]candidateRoute, 0, len(routes))
	for i := range routes {
		if c, ok := candidate(cfg, ts, &routes[i]); ok {
			cands = append(cands, c)
		}
	}
	// Sorted by destination, the winning route comes first among those that
	// share one (DES-4), and each peer's routed prefixes come out in order.
	slices.SortFunc(cands, func(a, b candidateRoute) int {
		if c := config.ComparePrefix(a.dst, b.dst); c != 0 {
			return c
		}
		return a.compare(b, cfg)
	})
	winners := slices.CompactFunc(cands, func(a, b candidateRoute) bool { return a.dst == b.dst })

	// Merge each peer's sorted static prefixes with its routed prefixes into
	// a list allocated once at its final size.
	count := make([]int, len(cfg.Peers))
	for _, w := range winners {
		count[w.owner]++
	}
	lists := make([][]netip.Prefix, len(cfg.Peers))
	static := make([][]netip.Prefix, len(cfg.Peers)) // not yet merged
	for i, p := range cfg.Peers {
		static[i] = p.Static
		if count[i] > 0 {
			lists[i] = make([]netip.Prefix, 0, len(p.Static)+count[i])
		}
	}
	for _, w := range winners {
		l, st := lists[w.owner], static[w.owner]
		for len(st) > 0 {
			c := config.ComparePrefix(st[0], w.dst)
			if c > 0 {
				break
			}
			if c < 0 {
				l = append(l, st[0])
			}
			st = st[1:]
		}
		lists[w.owner], static[w.owner] = append(l, w.dst), st
	}
	out := make(map[wgtypes.Key][]netip.Prefix, len(cfg.Peers))
	for i, p := range cfg.Peers {
		if count[i] == 0 {
			// Clipped so appending to the result cannot write into cfg.
			out[p.Key] = slices.Clip(p.Static)
		} else {
			out[p.Key] = append(lists[i], static[i]...)
		}
	}
	return out
}

// PrefixFromIPNet converts a netlink destination to a normalized prefix.
// IPv4 addresses in 16-byte form are treated as IPv4.
func PrefixFromIPNet(n *net.IPNet) (netip.Prefix, bool) {
	if n == nil {
		return netip.Prefix{}, false
	}
	a, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	a = a.Unmap()
	ones, bits := n.Mask.Size()
	if bits == 0 {
		return netip.Prefix{}, false
	}
	if a.Is4() && bits == 128 {
		ones -= 96
	}
	if ones < 0 || ones > a.BitLen() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, ones).Masked(), true
}

// candidateRoute is a route that passed every DES-2 filter, reduced to what
// decides its routed prefix's owner.
type candidateRoute struct {
	dst    netip.Prefix
	owner  int32 // index in cfg.Peers
	rank   int32
	metric int
}

// candidate reports whether r is a candidate route (DES-2). The output
// interface is filtered when listing. The cheapest checks go first.
func candidate(cfg *config.Config, ts *tables.Set, r *netlink.Route) (candidateRoute, bool) {
	if r.Gw == nil || len(r.MultiPath) > 0 {
		return candidateRoute{}, false
	}
	rank, ok := ts.Rank(r.Table)
	if !ok {
		return candidateRoute{}, false
	}
	dst, ok := PrefixFromIPNet(r.Dst)
	if !ok || config.IsDefault(dst) || cfg.IsTunnelPrefix(dst) {
		return candidateRoute{}, false
	}
	gw, ok := netip.AddrFromSlice(r.Gw)
	if !ok {
		return candidateRoute{}, false
	}
	owner, ok := cfg.OwnerIndex(gw)
	if !ok {
		return candidateRoute{}, false
	}
	return candidateRoute{dst, int32(owner), int32(rank), r.Priority}, true
}

// compare orders c before o if c is preferred as the winning route: lower
// table rank, then lower metric, then the byte-wise lower public key.
func (c candidateRoute) compare(o candidateRoute, cfg *config.Config) int {
	if c.rank != o.rank {
		return int(c.rank - o.rank)
	}
	if c.metric != o.metric {
		return cmp.Compare(c.metric, o.metric)
	}
	return bytes.Compare(cfg.Peers[c.owner].Key[:], cfg.Peers[o.owner].Key[:])
}

// IPNetFromPrefix converts a prefix to the net.IPNet form wgctrl expects,
// with IPv4 in 4-byte form.
func IPNetFromPrefix(p netip.Prefix) net.IPNet {
	return net.IPNet{
		IP:   p.Addr().AsSlice(),
		Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen()),
	}
}

// Relevant reports whether a route event should trigger a pass: any change in
// a monitored table, whatever its interface or gateway (NL-6). This catches
// routes moved off the WireGuard interface and routes that become multipath.
func Relevant(ts *tables.Set, u netlink.RouteUpdate) bool {
	_, ok := ts.Rank(u.Table)
	return ok
}
