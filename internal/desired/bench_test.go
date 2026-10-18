package desired

import (
	"fmt"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"rt2wg/internal/config"
	"rt2wg/internal/tables"
)

// BenchmarkDesired models a router with 64 peers and 4096 routes on the
// WireGuard interface, spread over the peers and two monitored tables.
func BenchmarkDesired(b *testing.B) {
	const peers, routes = 64, 4096
	var in strings.Builder
	for i := range peers {
		k, _ := wgtypes.GeneratePrivateKey()
		fmt.Fprintf(&in, "[Peer]\nPublicKey = %s\nAllowedIPs = 10.0.%d.1/32, fd00::%x/128\n",
			k.PublicKey(), i, i+1)
	}
	cfg, err := config.Parse(strings.NewReader(in.String()))
	if err != nil {
		b.Fatal(err)
	}
	ts, err := tables.Parse("100,main", b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	rs := make([]netlink.Route, 0, routes)
	for i := range routes {
		table := 254
		if i%3 == 0 {
			table = 100
		}
		r := route(fmt.Sprintf("172.%d.%d.0/24", 16+i/256%16, i%256), fmt.Sprintf("10.0.%d.1", i%peers), table, i%7)
		if i%4 == 0 {
			r = route(fmt.Sprintf("fd%02x:%x::/48", i/256%256, i), fmt.Sprintf("fd00::%x", i%peers+1), table, 0)
		}
		rs = append(rs, r)
	}
	b.ReportAllocs()
	for b.Loop() {
		Desired(cfg, ts, rs)
	}
}
