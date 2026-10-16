package config

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	key1 = "YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
	key2 = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="
)

func mustKey(t *testing.T, s string) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.ParseKey(s)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func prefixes(t *testing.T, ss ...string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func TestParsesWgQuickStyleConfig(t *testing.T) {
	in := `
[Interface]
PrivateKey = ignored
Address = 10.0.0.1/24

[peer]  ; mixed-case section
publickey = ` + key1 + ` # trailing comment
ALLOWEDIPS = 10.0.0.2/32, fd00::2/128,
AllowedIPs = 10.0.9.7/24 ; masked to 10.0.9.0/24
AllowedIPs = 10.0.0.2
Endpoint = 192.0.2.1:51820

# full-tunnel peer
[Peer]
PublicKey = ` + key2 + `
AllowedIPs = 10.0.0.3, 0.0.0.0/0, ::/0
`
	cfg, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []Peer{
		{Key: mustKey(t, key1), Static: prefixes(t, "10.0.0.2/32", "10.0.9.0/24", "fd00::2/128")},
		{Key: mustKey(t, key2), Static: prefixes(t, "0.0.0.0/0", "10.0.0.3/32", "::/0")},
	}
	if !reflect.DeepEqual(cfg.Peers, want) {
		t.Errorf("Peers =\n%v\nwant\n%v", cfg.Peers, want)
	}
}

func TestInvalidConfigsAreRejectedWithLineNumbers(t *testing.T) {
	cases := map[string]struct{ in, wantLine string }{
		"missing key":    {"[Peer]\nAllowedIPs = 10.0.0.2\n", "line 1"},
		"bad key":        {"[Peer]\nPublicKey = nope\n", "line 2"},
		"bad prefix":     {"[Peer]\nPublicKey = " + key1 + "\nAllowedIPs = 10.0.0.2, 10.0.0.300/32\n", "line 3"},
		"duplicate peer": {"[Peer]\nPublicKey = " + key1 + "\n[Peer]\nPublicKey = " + key1 + "\n", "line 3"},
		"line without =": {"[Peer]\nPublicKey = " + key1 + "\nAllowedIPs\n", "line 3"},
		"shared static":  {"[Peer]\nPublicKey = " + key1 + "\nAllowedIPs = 10.0.0.0/24\n[Peer]\nPublicKey = " + key2 + "\nAllowedIPs = 10.0.0.7/24\n", "line 4"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(c.in))
			if err == nil {
				t.Fatal("Parse succeeded; want error")
			}
			if !strings.Contains(err.Error(), c.wantLine) {
				t.Errorf("error %q does not mention %q", err, c.wantLine)
			}
		})
	}
}

func TestLineWithoutEqualsOutsidePeerIsIgnored(t *testing.T) {
	if _, err := Parse(strings.NewReader("[Interface]\nPostUp\n")); err != nil {
		t.Fatal(err)
	}
}

func TestOwnerIsMostSpecificTunnelPrefix(t *testing.T) {
	in := "[Peer]\nPublicKey = " + key1 + "\nAllowedIPs = 10.0.0.2/32, fd00::2/128, 10.0.5.0/24\n" +
		"[Peer]\nPublicKey = " + key2 + "\nAllowedIPs = 10.0.0.0/24, 0.0.0.0/0, ::/0\n"
	cfg, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	k1, k2 := mustKey(t, key1), mustKey(t, key2)
	cases := map[string]*wgtypes.Key{
		"10.0.0.2":        &k1, // /32 beats the /24
		"10.0.0.3":        &k2, // inside peer2's /24
		"10.0.5.77":       &k1, // inside peer1's /24
		"fd00::2":         &k1,
		"::ffff:10.0.0.2": &k1, // IPv4-mapped
		"192.0.2.1":       nil, // only a default prefix matches
		"2001:db8::1":     nil,
	}
	for gw, want := range cases {
		got, ok := cfg.Owner(netip.MustParseAddr(gw))
		switch {
		case want == nil && ok:
			t.Errorf("Owner(%s) = %s; want none", gw, got)
		case want != nil && (!ok || got != *want):
			t.Errorf("Owner(%s) = %s, %v; want %s", gw, got, ok, want)
		}
	}
}
