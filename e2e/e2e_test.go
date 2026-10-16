//go:build e2e

// End-to-end acceptance tests (requirements §10.2). Run as root:
//
//	sudo go test -tags e2e ./e2e
//
// The test re-executes itself in a fresh network namespace, so nothing it
// creates touches the host's interfaces or routes.
package e2e

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	wgName    = "rt2wgtest0"
	dummyName = "rt2wgdummy0"
	inNetns   = "RT2WG_E2E_IN_NETNS"
	deadline  = 500 * time.Millisecond // "visible within about 0.5 s"
)

var binary string

func TestMain(m *testing.M) {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "e2e tests need root; skipping")
		os.Exit(0)
	}
	if os.Getenv(inNetns) == "" {
		// Re-exec in a new network namespace.
		cmd := exec.Command(os.Args[0], os.Args[1:]...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		cmd.Env = append(os.Environ(), inNetns+"=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
		if err := cmd.Run(); err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				os.Exit(ee.ExitCode())
			}
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	dir, err := os.MkdirTemp("", "rt2wg-e2e")
	if err != nil {
		panic(err)
	}
	binary = filepath.Join(dir, "rt2wg")
	build := exec.Command("go", "build", "-o", binary, "../cmd/rt2wg")
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "building rt2wg:", err)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// env is the test interface with two peers, plus a dummy interface.
type env struct {
	t            *testing.T
	wg           *wgctrl.Client
	link, dummy  netlink.Link
	peer1, peer2 wgtypes.Key
	confPath     string
}

func setupEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t}
	var err error
	if e.wg, err = wgctrl.New(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.wg.Close() })

	must(t, netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: wgName}}))
	t.Cleanup(func() { deleteLink(wgName) })
	must(t, netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: dummyName}}))
	t.Cleanup(func() { deleteLink(dummyName) })

	e.link = linkByName(t, wgName)
	e.dummy = linkByName(t, dummyName)
	for _, a := range []string{"10.0.0.1/24", "fd00::1/64"} {
		addr, _ := netlink.ParseAddr(a)
		addr.Flags = syscall.IFA_F_NODAD
		must(t, netlink.AddrAdd(e.link, addr))
	}
	addr, _ := netlink.ParseAddr("192.0.2.254/24")
	must(t, netlink.AddrAdd(e.dummy, addr))
	must(t, netlink.LinkSetUp(e.link))
	must(t, netlink.LinkSetUp(e.dummy))

	priv, _ := wgtypes.GeneratePrivateKey()
	k1, _ := wgtypes.GeneratePrivateKey()
	k2, _ := wgtypes.GeneratePrivateKey()
	e.peer1, e.peer2 = k1.PublicKey(), k2.PublicKey()
	must(t, e.wg.ConfigureDevice(wgName, wgtypes.Config{
		PrivateKey: &priv,
		Peers: []wgtypes.PeerConfig{
			{PublicKey: e.peer1, AllowedIPs: ipnets("10.0.0.2/32", "fd00::2/128")},
			{PublicKey: e.peer2, AllowedIPs: ipnets("10.0.0.3/32", "fd00::3/128")},
		},
	}))

	e.confPath = filepath.Join(t.TempDir(), wgName+".conf")
	conf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.0.0.1/24, fd00::1/64

[Peer]
PublicKey = %s
AllowedIPs = 10.0.0.2/32, fd00::2/128

[Peer]
PublicKey = %s
AllowedIPs = 10.0.0.3/32, fd00::3/128
`, priv, e.peer1, e.peer2)
	must(t, os.WriteFile(e.confPath, []byte(conf), 0o600))
	return e
}

// daemon is a running rt2wg process.
type daemon struct {
	cmd    *exec.Cmd
	mu     sync.Mutex
	stderr bytes.Buffer
	done   chan error
}

func (d *daemon) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.stderr.Write(p)
}

func (d *daemon) log() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.stderr.String()
}

func (e *env) start() *daemon {
	e.t.Helper()
	d := &daemon{done: make(chan error, 1)}
	d.cmd = exec.Command(binary)
	d.cmd.Env = append(os.Environ(),
		"WG_INTERFACE="+wgName,
		"WG_CONF_PATH="+e.confPath,
		"WG_ROUTE_TABLES=100,main,1000",
		"LOG_LEVEL=debug",
	)
	d.cmd.Stderr = d
	must(e.t, d.cmd.Start())
	go func() { d.done <- d.cmd.Wait() }()
	e.t.Cleanup(func() {
		if d.cmd.ProcessState == nil {
			d.cmd.Process.Kill()
			<-d.done
		}
		if e.t.Failed() {
			e.t.Logf("rt2wg log:\n%s", d.log())
		}
	})
	return d
}

// allowed returns a peer's current AllowedIPs.
func (e *env) allowed(peer wgtypes.Key) []netip.Prefix {
	e.t.Helper()
	dev, err := e.wg.Device(wgName)
	if err != nil {
		e.t.Fatal(err)
	}
	for _, p := range dev.Peers {
		if p.PublicKey == peer {
			var out []netip.Prefix
			for _, n := range p.AllowedIPs {
				a, _ := netip.AddrFromSlice(n.IP)
				ones, _ := n.Mask.Size()
				out = append(out, netip.PrefixFrom(a.Unmap(), ones))
			}
			return out
		}
	}
	e.t.Fatalf("peer %s not on device", peer)
	return nil
}

// waitHas waits until peer has (want=true) or lacks (want=false) prefix.
func (e *env) waitHas(peer wgtypes.Key, prefix string, want bool) {
	e.t.Helper()
	e.waitHasWithin(peer, prefix, want, deadline)
}

func (e *env) waitHasWithin(peer wgtypes.Key, prefix string, want bool, deadline time.Duration) {
	e.t.Helper()
	p := netip.MustParsePrefix(prefix)
	start := time.Now()
	for {
		if slices.Contains(e.allowed(peer), p) == want {
			return
		}
		if time.Since(start) > deadline {
			e.t.Fatalf("after %v: peer %s has %s = %v; want %v (AllowedIPs %v)",
				deadline, peer.String()[:8], prefix, !want, want, e.allowed(peer))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (e *env) route(dst, gw string, table, metric int) *netlink.Route {
	_, n, err := net.ParseCIDR(dst)
	if err != nil {
		e.t.Fatal(err)
	}
	return &netlink.Route{LinkIndex: e.link.Attrs().Index, Dst: n, Gw: net.ParseIP(gw), Table: table, Priority: metric}
}

func TestAcceptance(t *testing.T) {
	e := setupEnv(t)
	p1, p2 := e.peer1, e.peer2

	must(t, netlink.RouteAdd(e.route("198.51.100.0/24", "10.0.0.2", 254, 0)))
	d := e.start()

	step(t, "E1 route before startup is applied by the startup pass", func(t *testing.T) {
		// Includes process start-up, so allow more than the per-change deadline.
		e.waitHasWithin(p1, "198.51.100.0/24", true, 3*time.Second)
	})
	step(t, "E2 changed gateway moves the prefix", func(t *testing.T) {
		must(t, netlink.RouteChange(e.route("198.51.100.0/24", "10.0.0.3", 254, 0)))
		e.waitHas(p2, "198.51.100.0/24", true)
		e.waitHas(p1, "198.51.100.0/24", false)
	})
	step(t, "E3 IPv6 route is added", func(t *testing.T) {
		must(t, netlink.RouteAdd(e.route("fd10::/48", "fd00::3", 254, 0)))
		e.waitHas(p2, "fd10::/48", true)
	})
	step(t, "E4 default route and unmonitored table are ignored", func(t *testing.T) {
		must(t, netlink.RouteAdd(e.route("0.0.0.0/0", "10.0.0.2", 254, 0)))
		must(t, netlink.RouteAdd(e.route("198.51.200.0/24", "10.0.0.2", 200, 0)))
		// A later route acts as a barrier: once it is applied, every earlier
		// change has been through a pass.
		sentinel := e.route("172.16.99.0/24", "10.0.0.2", 254, 0)
		must(t, netlink.RouteAdd(sentinel))
		e.waitHas(p1, "172.16.99.0/24", true)
		for _, p := range []string{"0.0.0.0/0", "198.51.200.0/24"} {
			if slices.Contains(e.allowed(p1), netip.MustParsePrefix(p)) {
				t.Errorf("peer1 got %s", p)
			}
		}
		must(t, netlink.RouteDel(sentinel))
		e.waitHas(p1, "172.16.99.0/24", false)
	})
	table100 := e.route("203.0.113.0/24", "10.0.0.2", 100, 0)
	step(t, "E5 table rank decides a conflict", func(t *testing.T) {
		must(t, netlink.RouteAdd(table100))
		must(t, netlink.RouteAdd(e.route("203.0.113.0/24", "10.0.0.3", 254, 0)))
		e.waitHas(p1, "203.0.113.0/24", true)
		e.waitHas(p2, "203.0.113.0/24", false)
	})
	metric5 := e.route("10.9.0.0/16", "10.0.0.3", 254, 5)
	step(t, "E6 metric decides a conflict", func(t *testing.T) {
		must(t, netlink.RouteAdd(e.route("10.9.0.0/16", "10.0.0.2", 254, 10)))
		must(t, netlink.RouteAdd(metric5))
		e.waitHas(p2, "10.9.0.0/16", true)
		e.waitHas(p1, "10.9.0.0/16", false)
	})
	step(t, "E7 table id above 255", func(t *testing.T) {
		must(t, netlink.RouteAdd(e.route("100.64.0.0/10", "10.0.0.2", 1000, 0)))
		e.waitHas(p1, "100.64.0.0/10", true)
	})
	step(t, "E8 deleting the table-rank winner fails over immediately", func(t *testing.T) {
		must(t, netlink.RouteDel(table100))
		e.waitHas(p2, "203.0.113.0/24", true)
		e.waitHas(p1, "203.0.113.0/24", false)
	})
	step(t, "E9 deleting the metric winner fails over immediately", func(t *testing.T) {
		must(t, netlink.RouteDel(metric5))
		e.waitHas(p1, "10.9.0.0/16", true)
		e.waitHas(p2, "10.9.0.0/16", false)
	})
	step(t, "E10 a burst of 200 routes is coalesced", func(t *testing.T) {
		before := len(d.log())
		var burst []*netlink.Route
		for i := range 200 {
			burst = append(burst, e.route(fmt.Sprintf("10.200.%d.0/24", i), "10.0.0.2", 254, 0))
		}
		for _, r := range burst {
			must(t, netlink.RouteAdd(r))
		}
		e.waitCount(p1, "10.200.0.0/16", 200)
		for _, r := range burst {
			must(t, netlink.RouteDel(r))
		}
		e.waitCount(p1, "10.200.0.0/16", 0)
		passes := 0
		for _, line := range strings.Split(d.log()[before:], "\n") {
			if strings.Contains(line, "msg=pass ") && strings.Contains(line, "reason=event") {
				passes++
			}
		}
		t.Logf("400 route events, %d event passes", passes)
		if passes == 0 || passes >= 50 {
			t.Errorf("%d event passes for 400 events; want far fewer", passes)
		}
	})
	step(t, "E11 a route moved to another interface is removed immediately", func(t *testing.T) {
		moved := e.route("198.51.100.0/24", "192.0.2.1", 254, 0)
		moved.LinkIndex = e.dummy.Attrs().Index
		must(t, netlink.RouteReplace(moved))
		e.waitHas(p2, "198.51.100.0/24", false)
	})
	step(t, "E12 SIGHUP reloads the config and keeps state", func(t *testing.T) {
		s1, s2 := e.allowed(p1), e.allowed(p2)
		must(t, d.cmd.Process.Signal(syscall.SIGHUP))
		d.waitLog(t, "reason=sighup", 2*time.Second)
		if !strings.Contains(d.log(), "config loaded") || strings.Count(d.log(), "config loaded") < 2 {
			t.Error("config was not reloaded")
		}
		if !slices.Equal(s1, e.allowed(p1)) || !slices.Equal(s2, e.allowed(p2)) {
			t.Error("state changed on SIGHUP")
		}
	})
	step(t, "E13 conflicts do not flap across ticks", func(t *testing.T) {
		must(t, netlink.RouteAdd(table100))
		must(t, netlink.RouteAdd(metric5))
		e.waitHas(p1, "203.0.113.0/24", true)
		e.waitHas(p2, "10.9.0.0/16", true)
		time.Sleep(100 * time.Millisecond) // let trailing event passes finish
		before := len(d.log())
		time.Sleep(tickInterval + 2*time.Second)
		window := d.log()[before:]
		if !strings.Contains(window, "reason=ticker") {
			t.Error("no ticker pass in the window")
		}
		if strings.Contains(window, "AllowedIPs updated") {
			t.Errorf("updates while idle:\n%s", window)
		}
	})
	step(t, "E14 SIGTERM exits cleanly and leaves AllowedIPs", func(t *testing.T) {
		s1, s2 := e.allowed(p1), e.allowed(p2)
		must(t, d.cmd.Process.Signal(syscall.SIGTERM))
		select {
		case err := <-d.done:
			if err != nil {
				t.Fatalf("exit: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("rt2wg did not exit")
		}
		log := d.log()
		if !strings.Contains(log, "shutting down") {
			t.Error("no shutting down log")
		}
		if strings.Contains(log, "level=WARN") {
			t.Errorf("warnings logged:\n%s", log)
		}
		if !slices.Equal(s1, e.allowed(p1)) || !slices.Equal(s2, e.allowed(p2)) {
			t.Error("AllowedIPs changed on shutdown")
		}
	})
}

const tickInterval = 30 * time.Second

// waitCount waits until peer has exactly n AllowedIPs inside within.
func (e *env) waitCount(peer wgtypes.Key, within string, n int) {
	e.t.Helper()
	w := netip.MustParsePrefix(within)
	start := time.Now()
	for {
		got := 0
		for _, p := range e.allowed(peer) {
			if w.Contains(p.Addr()) && p.Bits() >= w.Bits() {
				got++
			}
		}
		if got == n {
			return
		}
		if time.Since(start) > deadline {
			e.t.Fatalf("after %v: peer %s has %d prefixes in %s; want %d", deadline, peer.String()[:8], got, within, n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (d *daemon) waitLog(t *testing.T, s string, timeout time.Duration) {
	t.Helper()
	start := time.Now()
	for !strings.Contains(d.log(), s) {
		if time.Since(start) > timeout {
			t.Fatalf("log never contained %q", s)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func step(t *testing.T, name string, f func(t *testing.T)) {
	t.Helper()
	if !t.Run(name, f) {
		t.FailNow()
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func linkByName(t *testing.T, name string) netlink.Link {
	t.Helper()
	l, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func deleteLink(name string) {
	if l, err := netlink.LinkByName(name); err == nil {
		netlink.LinkDel(l)
	}
}

func ipnets(ss ...string) []net.IPNet {
	var out []net.IPNet
	for _, s := range ss {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			panic(err)
		}
		out = append(out, *n)
	}
	return out
}
