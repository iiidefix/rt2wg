// Package desired computes each peer's AllowedIPs from the config, the
// monitored tables and the kernel routes. Everything here is pure.
package desired

import (
	"bytes"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"rt2wg/internal/config"
	"rt2wg/internal/tables"
)

// Desired returns the AllowedIPs every peer in the config should have: its
// static prefixes plus the routed prefixes it owns. Each list is normalized.
func Desired(cfg *config.Config, ts *tables.Set, routes []netlink.Route) map[wgtypes.Key][]netip.Prefix {
	out := make(map[wgtypes.Key][]netip.Prefix, len(cfg.Peers))
	for _, p := range cfg.Peers {
		out[p.Key] = append([]netip.Prefix(nil), p.Static...)
	}
	// Pick the winning route per destination (DES-4).
	winners := map[netip.Prefix]candidateRoute{}
	for _, r := range routes {
		c, ok := candidate(cfg, ts, r)
		if !ok {
			continue
		}
		if w, seen := winners[c.dst]; !seen || c.beats(w) {
			winners[c.dst] = c
		}
	}
	for dst, w := range winners {
		out[w.owner] = append(out[w.owner], dst)
	}
	for k, ps := range out {
		out[k] = config.Normalize(ps)
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
	dst          netip.Prefix
	owner        wgtypes.Key
	rank, metric int
}

// candidate reports whether r is a candidate route (DES-2). The output
// interface is filtered when listing.
func candidate(cfg *config.Config, ts *tables.Set, r netlink.Route) (candidateRoute, bool) {
	dst, ok := PrefixFromIPNet(r.Dst)
	if !ok || config.IsDefault(dst) {
		return candidateRoute{}, false
	}
	rank, ok := ts.Rank(r.Table)
	if !ok {
		return candidateRoute{}, false
	}
	gw, ok := netip.AddrFromSlice(r.Gw)
	if !ok || len(r.MultiPath) > 0 {
		return candidateRoute{}, false
	}
	owner, ok := cfg.Owner(gw.Unmap())
	if !ok || cfg.IsTunnelPrefix(dst) {
		return candidateRoute{}, false
	}
	return candidateRoute{dst, owner, rank, r.Priority}, true
}

// beats reports whether c is preferred over o as the winning route: lower
// table rank, then lower metric, then the byte-wise lower public key.
func (c candidateRoute) beats(o candidateRoute) bool {
	if c.rank != o.rank {
		return c.rank < o.rank
	}
	if c.metric != o.metric {
		return c.metric < o.metric
	}
	return bytes.Compare(c.owner[:], o.owner[:]) < 0
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
