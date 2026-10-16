package desired

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestRelevantEventIsAnyChangeInAMonitoredTable(t *testing.T) {
	f := setup(t)
	multipath := route("198.51.100.0/24", "", 254, 0)
	multipath.MultiPath = []*netlink.NexthopInfo{{Gw: net.ParseIP("10.0.0.2")}}
	onWG := route("198.51.100.0/24", "10.0.0.2", 254, 0)
	onWG.LinkIndex = 7
	onEth := route("198.51.100.0/24", "192.0.2.1", 254, 0)
	onEth.LinkIndex = 2

	cases := map[string]struct {
		r    netlink.Route
		want bool
	}{
		"on wg interface":            {onWG, true},
		"moved to another interface": {onEth, true},
		"multipath":                  {multipath, true},
		"table id above 255":         {route("100.64.0.0/10", "10.0.0.2", 1000, 0), true},
		"unmonitored table":          {route("198.51.100.0/24", "10.0.0.2", 200, 0), false},
	}
	for name, c := range cases {
		if got := Relevant(f.tables, netlink.RouteUpdate{Route: c.r}); got != c.want {
			t.Errorf("%s: Relevant = %v; want %v", name, got, c.want)
		}
	}
}
