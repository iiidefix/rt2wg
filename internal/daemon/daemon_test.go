package daemon

import (
	"net/netip"
	"testing"
)

func TestDiff(t *testing.T) {
	p := func(ss ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, s := range ss {
			out = append(out, netip.MustParsePrefix(s))
		}
		return out
	}
	cases := []struct {
		cur, want      []netip.Prefix
		added, removed int
	}{
		{nil, nil, 0, 0},
		{p("10.0.0.1/32"), p("10.0.0.1/32"), 0, 0},
		{nil, p("10.0.0.1/32", "fd00::/64"), 2, 0},
		{p("10.0.0.1/32", "fd00::/64"), nil, 0, 2},
		{p("10.0.0.0/24", "10.0.0.1/32", "fd00::/64"), p("10.0.0.0/16", "10.0.0.1/32", "fd01::/64"), 2, 2},
		{p("10.0.0.0/24"), p("10.0.0.0/25"), 1, 1}, // same address, other length
	}
	for _, c := range cases {
		if a, r := diff(c.cur, c.want); a != c.added || r != c.removed {
			t.Errorf("diff(%v, %v) = %d, %d; want %d, %d", c.cur, c.want, a, r, c.added, c.removed)
		}
	}
}
