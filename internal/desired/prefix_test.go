package desired

import (
	"net"
	"net/netip"
	"testing"
)

func TestPrefixConversion(t *testing.T) {
	cases := map[string]struct {
		in   *net.IPNet
		want string
	}{
		"16-byte IPv4":      {&net.IPNet{IP: net.ParseIP("198.51.100.7").To16(), Mask: net.CIDRMask(24, 32)}, "198.51.100.0/24"},
		"16-byte IPv4 mask": {&net.IPNet{IP: net.ParseIP("198.51.100.7").To16(), Mask: net.CIDRMask(120, 128)}, "198.51.100.0/24"},
		"4-byte IPv4":       {&net.IPNet{IP: net.ParseIP("10.0.0.2").To4(), Mask: net.CIDRMask(32, 32)}, "10.0.0.2/32"},
		"IPv6":              {&net.IPNet{IP: net.ParseIP("fd10::1"), Mask: net.CIDRMask(48, 128)}, "fd10::/48"},
		"IPv4 default":      {&net.IPNet{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)}, "0.0.0.0/0"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p, ok := PrefixFromIPNet(c.in)
			if !ok || p != netip.MustParsePrefix(c.want) {
				t.Fatalf("PrefixFromIPNet = %v, %v; want %s", p, ok, c.want)
			}
			back := IPNetFromPrefix(p)
			if back.String() != c.want {
				t.Errorf("IPNetFromPrefix = %s; want %s", back.String(), c.want)
			}
			if p.Addr().Is4() && (len(back.IP) != 4 || len(back.Mask) != 4) {
				t.Errorf("IPv4 IPNet not in 4-byte form: %#v", back)
			}
		})
	}
	if _, ok := PrefixFromIPNet(nil); ok {
		t.Error("PrefixFromIPNet(nil) reported ok")
	}
}
