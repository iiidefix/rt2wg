package desired

import (
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"rt2wg/internal/config"
	"rt2wg/internal/tables"
)

const (
	key1 = "YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
	key2 = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="
)

// fixture: peer1 = 10.0.0.2/32, fd00::2/128; peer2 = 10.0.0.3/32, fd00::3/128,
// 10.0.5.0/24; peer3 is full-tunnel. Tables: 100, main, 1000.
type fixture struct {
	cfg        *config.Config
	tables     *tables.Set
	p1, p2, p3 wgtypes.Key
}

func setup(t *testing.T) fixture {
	t.Helper()
	k3, _ := wgtypes.GeneratePrivateKey()
	in := "[Peer]\nPublicKey = " + key1 + "\nAllowedIPs = 10.0.0.2/32, fd00::2/128\n" +
		"[Peer]\nPublicKey = " + key2 + "\nAllowedIPs = 10.0.0.3/32, fd00::3/128, 10.0.5.0/24\n" +
		"[Peer]\nPublicKey = " + k3.PublicKey().String() + "\nAllowedIPs = 10.0.0.4/32, 0.0.0.0/0\n"
	cfg, err := config.Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	ts, err := tables.Parse("100,main,1000", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return fixture{cfg, ts, cfg.Peers[0].Key, cfg.Peers[1].Key, cfg.Peers[2].Key}
}

// route builds a netlink route as the kernel reports it: IPv4 in 16-byte form.
func route(dst, gw string, table, metric int) netlink.Route {
	r := netlink.Route{Table: table, Priority: metric}
	if dst != "" {
		_, n, err := net.ParseCIDR(dst)
		if err != nil {
			panic(err)
		}
		if n.IP.To4() != nil {
			n.IP = n.IP.To16()
		}
		r.Dst = n
	}
	if gw != "" {
		r.Gw = net.ParseIP(gw)
	}
	return r
}

func pfx(ss ...string) []netip.Prefix {
	out := []netip.Prefix{}
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func check(t *testing.T, got map[wgtypes.Key][]netip.Prefix, want map[wgtypes.Key][]netip.Prefix) {
	t.Helper()
	for k, w := range want {
		if !reflect.DeepEqual(got[k], w) {
			t.Errorf("peer %s: got %v, want %v", k.String()[:8], got[k], w)
		}
	}
}

func TestRouteViaPeerIsAddedToThatPeer(t *testing.T) {
	f := setup(t)
	got := Desired(f.cfg, f.tables, []netlink.Route{
		route("198.51.100.0/24", "10.0.0.2", 254, 0),
	})
	check(t, got, map[wgtypes.Key][]netip.Prefix{
		f.p1: pfx("10.0.0.2/32", "198.51.100.0/24", "fd00::2/128"),
		f.p2: pfx("10.0.0.3/32", "10.0.5.0/24", "fd00::3/128"),
		f.p3: pfx("0.0.0.0/0", "10.0.0.4/32"),
	})
}

func TestNonCandidateRoutesAreIgnored(t *testing.T) {
	multipath := route("198.51.100.0/24", "", 254, 0)
	multipath.MultiPath = []*netlink.NexthopInfo{{Gw: net.ParseIP("10.0.0.2")}, {Gw: net.ParseIP("10.0.0.3")}}
	cases := map[string]netlink.Route{
		"default route":                route("0.0.0.0/0", "10.0.0.2", 254, 0),
		"IPv6 default route":           route("::/0", "fd00::2", 254, 0),
		"no destination":               route("", "10.0.0.2", 254, 0),
		"unmonitored table":            route("198.51.100.0/24", "10.0.0.2", 200, 0),
		"directly connected":           route("198.51.100.0/24", "", 254, 0),
		"multipath":                    multipath,
		"unknown gateway":              route("198.51.100.0/24", "10.9.9.9", 254, 0),
		"gateway only in a default":    route("198.51.100.0/24", "192.0.2.1", 254, 0),
		"another peer's tunnel prefix": route("10.0.0.3/32", "10.0.0.2", 254, 0),
		"another peer's /24":           route("10.0.5.0/24", "10.0.0.2", 254, 0),
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			got := Desired(f.cfg, f.tables, []netlink.Route{r})
			for _, p := range f.cfg.Peers {
				if !reflect.DeepEqual(got[p.Key], p.Static) {
					t.Errorf("peer %s: got %v, want static %v", p.Key.String()[:8], got[p.Key], p.Static)
				}
			}
		})
	}
}

func TestIPv6AndGatewayInsideSubnet(t *testing.T) {
	f := setup(t)
	got := Desired(f.cfg, f.tables, []netlink.Route{
		route("fd10::/48", "fd00::3", 254, 0),
		route("192.168.50.0/24", "10.0.5.9", 1000, 0), // inside peer2's /24
	})
	check(t, got, map[wgtypes.Key][]netip.Prefix{
		f.p1: pfx("10.0.0.2/32", "fd00::2/128"),
		f.p2: pfx("10.0.0.3/32", "10.0.5.0/24", "192.168.50.0/24", "fd00::3/128", "fd10::/48"),
	})
}

func TestEachRoutedPrefixHasOneOwner(t *testing.T) {
	cases := map[string]struct {
		routes []netlink.Route
		winner func(fixture) wgtypes.Key
	}{
		"lower table rank wins over lower metric": {
			[]netlink.Route{
				route("203.0.113.0/24", "10.0.0.3", 254, 0),
				route("203.0.113.0/24", "10.0.0.2", 100, 50),
			},
			func(f fixture) wgtypes.Key { return f.p1 },
		},
		"lower metric wins in the same table": {
			[]netlink.Route{
				route("10.9.0.0/16", "10.0.0.2", 254, 10),
				route("10.9.0.0/16", "10.0.0.3", 254, 5),
			},
			func(f fixture) wgtypes.Key { return f.p2 },
		},
		"lowest public key breaks a full tie": {
			[]netlink.Route{
				route("10.9.0.0/16", "10.0.0.2", 254, 7),
				route("10.9.0.0/16", "10.0.0.3", 254, 7),
			},
			func(f fixture) wgtypes.Key { return f.p2 }, // key2 sorts before key1
		},
		"tie result does not depend on route order": {
			[]netlink.Route{
				route("10.9.0.0/16", "10.0.0.3", 254, 7),
				route("10.9.0.0/16", "10.0.0.2", 254, 7),
			},
			func(f fixture) wgtypes.Key { return f.p2 },
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			got := Desired(f.cfg, f.tables, c.routes)
			dst, _ := PrefixFromIPNet(c.routes[0].Dst)
			winner := c.winner(f)
			for _, p := range f.cfg.Peers {
				has := false
				for _, q := range got[p.Key] {
					has = has || q == dst
				}
				if has != (p.Key == winner) {
					t.Errorf("peer %s has %s = %v", p.Key.String()[:8], dst, has)
				}
			}
		})
	}
}

func TestDuplicateRoutesYieldOneEntry(t *testing.T) {
	f := setup(t)
	got := Desired(f.cfg, f.tables, []netlink.Route{
		route("198.51.100.0/24", "10.0.0.2", 254, 0),
		route("198.51.100.0/24", "10.0.0.2", 254, 0),
		route("198.51.100.0/24", "10.0.0.2", 100, 0),
	})
	check(t, got, map[wgtypes.Key][]netip.Prefix{
		f.p1: pfx("10.0.0.2/32", "198.51.100.0/24", "fd00::2/128"),
	})
}

func TestFullTunnelPeerKeepsDefaultPrefix(t *testing.T) {
	f := setup(t)
	got := Desired(f.cfg, f.tables, nil)
	check(t, got, map[wgtypes.Key][]netip.Prefix{f.p3: pfx("0.0.0.0/0", "10.0.0.4/32")})
}
