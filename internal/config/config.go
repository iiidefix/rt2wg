// Package config parses wg-style WireGuard config files into peers and their
// static prefixes, and answers which peer owns a gateway.
package config

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Peer is a [Peer] section: a public key and its static prefixes, normalized
// (masked, unmapped, sorted, deduplicated).
type Peer struct {
	Key    wgtypes.Key
	Static []netip.Prefix
}

// Config is the set of peers rt2wg manages, in file order. It must not be
// modified after Parse, which indexes the tunnel prefixes.
type Config struct {
	Peers []Peer

	tunnel map[netip.Prefix]int // tunnel prefix -> index in Peers
	// Distinct tunnel prefix lengths per family, longest first, so Owner
	// needs one map lookup per length instead of a scan of every peer.
	bits4, bits6 []int
}

// Load reads and parses the config file at path.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cfg, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Parse parses a wg-style config. Any error rejects the whole file.
func Parse(r io.Reader) (*Config, error) {
	type section struct {
		line   int
		key    *wgtypes.Key
		static []netip.Prefix
	}
	var peers []*section
	var cur *section // nil outside [Peer] sections

	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			cur = nil
			if strings.EqualFold(strings.TrimSpace(line[1:len(line)-1]), "peer") {
				cur = &section{line: n}
				peers = append(peers, cur)
			}
			continue
		}
		if cur == nil {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected key = value", n)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch strings.ToLower(k) {
		case "publickey":
			key, err := wgtypes.ParseKey(v)
			if err != nil {
				return nil, fmt.Errorf("line %d: invalid PublicKey: %w", n, err)
			}
			cur.key = &key
		case "allowedips":
			for _, entry := range strings.Split(v, ",") {
				entry = strings.TrimSpace(entry)
				if entry == "" {
					continue
				}
				p, err := parsePrefix(entry)
				if err != nil {
					return nil, fmt.Errorf("line %d: invalid AllowedIPs entry %q", n, entry)
				}
				cur.static = append(cur.static, p)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	cfg := &Config{}
	seenKey := map[wgtypes.Key]bool{}
	staticOwner := map[netip.Prefix]int{} // prefix -> line of the peer that has it
	for _, s := range peers {
		if s.key == nil {
			return nil, fmt.Errorf("line %d: [Peer] without PublicKey", s.line)
		}
		if seenKey[*s.key] {
			return nil, fmt.Errorf("line %d: duplicate peer %s", s.line, s.key)
		}
		seenKey[*s.key] = true
		static := Normalize(s.static)
		for _, p := range static {
			if other, dup := staticOwner[p]; dup {
				return nil, fmt.Errorf("line %d: static prefix %s already belongs to the peer at line %d", s.line, p, other)
			}
			staticOwner[p] = s.line
		}
		cfg.Peers = append(cfg.Peers, Peer{Key: *s.key, Static: static})
	}
	cfg.index()
	return cfg, nil
}

// index builds the tunnel prefix lookup. Parse has already rejected a static
// prefix shared by two peers, so each tunnel prefix has one peer.
func (c *Config) index() {
	c.tunnel = map[netip.Prefix]int{}
	for i, peer := range c.Peers {
		for _, p := range peer.Static {
			if IsDefault(p) {
				continue
			}
			c.tunnel[p] = i
			if p.Addr().Is4() {
				c.bits4 = append(c.bits4, p.Bits())
			} else {
				c.bits6 = append(c.bits6, p.Bits())
			}
		}
	}
	for _, bits := range []*[]int{&c.bits4, &c.bits6} {
		slices.SortFunc(*bits, func(a, b int) int { return b - a })
		*bits = slices.Compact(*bits)
	}
}

// parsePrefix parses CIDR notation or a bare IP (a host prefix).
func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Normalize returns ps masked, with IPv4-mapped addresses unmapped, sorted by
// address then prefix length, and deduplicated. Invalid prefixes are dropped.
func Normalize(ps []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ps))
	for _, p := range ps {
		if !p.IsValid() {
			continue
		}
		a, bits := p.Addr(), p.Bits()
		if a.Is4In6() {
			a, bits = a.Unmap(), bits-96
			if bits < 0 {
				continue
			}
		}
		out = append(out, netip.PrefixFrom(a, bits).Masked())
	}
	slices.SortFunc(out, ComparePrefix)
	return slices.Compact(out)
}

// ComparePrefix orders prefixes by address, then prefix length.
func ComparePrefix(a, b netip.Prefix) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	return a.Bits() - b.Bits()
}

// IsDefault reports whether p is a default prefix (0.0.0.0/0 or ::/0).
func IsDefault(p netip.Prefix) bool { return p.Bits() == 0 }

// Owner returns the peer whose tunnel prefix (a non-default static prefix)
// contains gw most specifically.
func (c *Config) Owner(gw netip.Addr) (wgtypes.Key, bool) {
	if i, ok := c.OwnerIndex(gw); ok {
		return c.Peers[i].Key, true
	}
	return wgtypes.Key{}, false
}

// OwnerIndex is Owner returning the owner's index in Peers.
func (c *Config) OwnerIndex(gw netip.Addr) (int, bool) {
	gw = gw.Unmap()
	bits := c.bits6
	if gw.Is4() {
		bits = c.bits4
	}
	for _, b := range bits {
		p, err := gw.Prefix(b)
		if err != nil {
			continue
		}
		if i, ok := c.tunnel[p]; ok {
			return i, true
		}
	}
	return 0, false
}

// IsTunnelPrefix reports whether p is exactly some peer's tunnel prefix.
func (c *Config) IsTunnelPrefix(p netip.Prefix) bool {
	_, ok := c.tunnel[p]
	return ok
}
