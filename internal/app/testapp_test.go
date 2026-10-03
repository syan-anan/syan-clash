package app

import (
	"net"
	"path/filepath"
	"strconv"
	"testing"

	"vvpn/internal/config"
	"vvpn/internal/core"
)

// freePort finds a loopback port nothing is listening on. Tests need real
// ports because the profile refuses port 0 ("let the OS choose" is not a
// thing a proxy client can promise across restarts).
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

// newTestApp builds a real App on a temporary configuration: the built-in
// engine runs, no external core is involved, and every file it writes stays
// inside the test's temporary directory.
func newTestApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	cfg := config.Default()
	cfg.Core.ID = ""
	cfg.Core.AutoStart = false
	cfg.Inbound.SOCKS5Addr = "127.0.0.1:" + strconv.Itoa(freePort(t))
	cfg.Inbound.HTTPAddr = "127.0.0.1:" + strconv.Itoa(freePort(t))
	cfg.Core.Port = freePort(t)
	profile := core.DefaultProfile()
	profile.Inbounds = []core.Inbound{{Type: core.InboundMixed, Tag: "mixed-in", Listen: "127.0.0.1", Port: freePort(t)}}
	profile.Nodes = []core.Node{
		{Name: "香港 01", Type: core.TypeSocks5, Server: "127.0.0.1", Port: 1080},
		{Name: "香港 02 - IEPL", Type: core.TypeSocks5, Server: "127.0.0.1", Port: 1081},
		{Name: "美国 01", Type: core.TypeSocks5, Server: "127.0.0.1", Port: 1082},
	}
	profile.Groups = []core.Group{{Name: "PROXY", Type: core.GroupSelect, Members: []string{"香港 01", "香港 02 - IEPL", "美国 01"}}}
	profile.Final = "PROXY"
	cfg.Core.Profile = &profile
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatalf("save test config: %v", err)
	}
	a, err := New(cfgPath, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Stop)
	return a
}
