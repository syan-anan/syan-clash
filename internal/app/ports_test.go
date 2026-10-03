package app

import (
	"net"
	"strconv"
	"strings"
	"testing"

	"vvpn/internal/config"
	"vvpn/internal/core"
)

// A busy port is the normal case on a machine that already runs another proxy
// client; the report has to say so instead of claiming the port is ours.
func TestConflictMovesReportsBusyPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	busy := ln.Addr().String()

	cfg := config.Default()
	cfg.Inbound.HTTPAddr = busy

	var got *PortMove
	for _, m := range conflictMoves(cfg) {
		if m.Kind == "http" && m.OldAddr == busy {
			m := m
			got = &m
		}
	}
	if got == nil {
		t.Fatalf("busy port %s was not reported as a conflict", busy)
	}
	if got.NewAddr == busy {
		t.Fatalf("replacement must differ from the busy address")
	}
	if portBusy(got.NewAddr) {
		t.Errorf("suggested replacement %s is busy too", got.NewAddr)
	}
}

func TestNextFreeAddrMovesToAFreeNeighbour(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	next, ok := NextFreeAddr(addr)
	if !ok {
		t.Fatalf("NextFreeAddr(%s) found nothing", addr)
	}
	if portBusy(next) {
		t.Fatalf("NextFreeAddr returned a busy address: %s", next)
	}
	_, oldStr, _ := net.SplitHostPort(addr)
	_, newStr, _ := net.SplitHostPort(next)
	oldPort, _ := strconv.Atoi(oldStr)
	newPort, _ := strconv.Atoi(newStr)
	if newPort <= oldPort {
		t.Errorf("expected a port above %d, got %d", oldPort, newPort)
	}
	if !strings.HasPrefix(next, "127.0.0.1:") {
		t.Errorf("host part was not preserved: %s", next)
	}
}

// Every copy of a port has to move together: the built-in engine reads
// config.Inbound, the external core reads config.Core.Port, and the compiled
// core config comes from the profile's own inbounds.
func TestApplyPortMovesRewritesEveryCopy(t *testing.T) {
	cfg := config.Default()
	cfg.Inbound.HTTPAddr = "127.0.0.1:7890"
	cfg.Inbound.SOCKS5Addr = "127.0.0.1:7891"
	cfg.Core.Port = 7899
	cfg.Core.Profile = &core.Profile{Inbounds: []core.Inbound{
		{Type: core.InboundMixed, Tag: "mixed-in", Listen: "127.0.0.1", Port: 7890},
		{Type: core.InboundSocks, Tag: "socks-in", Listen: "127.0.0.1", Port: 7891},
	}}

	applyPortMoves(&cfg, []PortMove{
		{Kind: "http", OldAddr: "127.0.0.1:7890", NewAddr: "127.0.0.1:17890"},
		{Kind: "socks", OldAddr: "127.0.0.1:7891", NewAddr: "127.0.0.1:17891"},
		{Kind: "core", OldAddr: "127.0.0.1:7899", NewAddr: "127.0.0.1:17899"},
	})

	if cfg.Inbound.HTTPAddr != "127.0.0.1:17890" {
		t.Errorf("http addr = %s", cfg.Inbound.HTTPAddr)
	}
	if cfg.Inbound.SOCKS5Addr != "127.0.0.1:17891" {
		t.Errorf("socks addr = %s", cfg.Inbound.SOCKS5Addr)
	}
	if cfg.Core.Port != 17899 {
		t.Errorf("core port = %d", cfg.Core.Port)
	}
	ports := map[int]bool{}
	for _, in := range cfg.Core.Profile.Inbounds {
		ports[in.Port] = true
	}
	if !ports[17890] || !ports[17891] {
		t.Errorf("profile inbounds did not follow the move: %v", ports)
	}
}

// A subscription that points external-controller at its own mixed-port used to
// cost the core its proxy listener: mihomo binds the controller first, the
// mixed listener then fails with "Only one usage of each socket address", and
// the client went on to advertise that control API as if it were a proxy.
func TestCoreAPIAddrNeverCollidesWithTheMixedPort(t *testing.T) {
	cfg := config.Default()
	cfg.Core.Port = 2900
	cfg.Core.Profile = &core.Profile{ClashAPI: "127.0.0.1:2900"}

	api := coreAPIAddr(cfg)
	if port, ok := addrPort(api); !ok || port == coreMixedPort(cfg) {
		t.Fatalf("control address %s shares the core's proxy port %d", api, coreMixedPort(cfg))
	}
	if api != "127.0.0.1:2901" {
		t.Errorf("expected the port above the mixed listener, got %s", api)
	}

	// A controller the subscription keeps somewhere else is honoured as is.
	cfg.Core.Profile = &core.Profile{ClashAPI: "127.0.0.1:2911"}
	if got := coreAPIAddr(cfg); got != "127.0.0.1:2911" {
		t.Errorf("a non-colliding control port was rewritten: %s", got)
	}

	// Even the client's own default has to give way when the user picked it as
	// the core port.
	cfg.Core.Port = 2898
	cfg.Core.Profile = &core.Profile{ClashAPI: "127.0.0.1:2898"}
	if got := coreAPIAddr(cfg); got == "127.0.0.1:2898" {
		t.Errorf("control port still collides with the mixed port: %s", got)
	}

	// And the compiled profile must actually carry the two distinct ports.
	cfg.Core.Port = 2900
	cfg.Core.Profile = &core.Profile{ClashAPI: "127.0.0.1:2900"}
	a := &App{cfg: cfg}
	p := a.coreProfile()
	if p.ClashAPI == "" {
		t.Fatal("the compiled profile has no control address")
	}
	apiPort, _ := addrPort(p.ClashAPI)
	if apiPort == a.corePort() {
		t.Errorf("compiled profile puts the control API and the proxy on %d", apiPort)
	}
}

// A port that is free stays where it is; the repair must not shuffle a working
// configuration around.
func TestApplyPortMovesLeavesUnrelatedPortsAlone(t *testing.T) {
	cfg := config.Default()
	cfg.Inbound.HTTPAddr = "127.0.0.1:17890"
	cfg.Inbound.SOCKS5Addr = "127.0.0.1:17891"
	cfg.Core.Port = 17899

	applyPortMoves(&cfg, []PortMove{{Kind: "http", OldAddr: "127.0.0.1:7890", NewAddr: "127.0.0.1:17890"}})

	if cfg.Inbound.SOCKS5Addr != "127.0.0.1:17891" || cfg.Core.Port != 17899 {
		t.Errorf("unrelated ports moved: socks=%s core=%d", cfg.Inbound.SOCKS5Addr, cfg.Core.Port)
	}
}

// A port that is merely free is not necessarily available: the configuration may
// already reserve it for something else. Sliding a busy inbound onto the core's
// own proxy port used to produce a profile that failed its own validation
// ("core.port is already used by inbound.socks5_addr"), which left the client
// unable to save anything at all - and the trigger is as ordinary as another
// program holding the inbound's port.
func TestConflictMovesDodgePortsTheConfigReserves(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	busy := ln.Addr().String()
	_, portStr, _ := net.SplitHostPort(busy)
	base, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port %q: %v", portStr, err)
	}

	cfg := config.Default()
	cfg.Inbound.HTTPAddr = busy
	cfg.Inbound.SOCKS5Addr = busy
	cfg.Core.Port = base + 1
	cfg.Core.Profile = &core.Profile{Inbounds: []core.Inbound{
		{Type: core.InboundMixed, Tag: "mixed-in", Listen: "127.0.0.1", Port: base + 2},
	}}

	moves := conflictMoves(cfg)
	if len(moves) == 0 {
		t.Fatalf("the busy inbound at %s was not moved at all", busy)
	}
	for _, m := range moves {
		port, ok := addrPort(m.NewAddr)
		if !ok {
			t.Fatalf("replacement %q is not host:port", m.NewAddr)
		}
		if port == base+1 {
			t.Errorf("%s moved onto the core port %d: %+v", m.OldAddr, base+1, m)
		}
		if port == base+2 {
			t.Errorf("%s moved onto the profile inbound port %d: %+v", m.OldAddr, base+2, m)
		}
		if portBusy(m.NewAddr) {
			t.Errorf("%s moved onto a busy port: %+v", m.OldAddr, m)
		}
	}

	// The repaired configuration is the thing that actually has to hold up:
	// this is the check the client runs on every save.
	applyPortMoves(&cfg, moves)
	if err := cfg.Validate(); err != nil {
		t.Errorf("the repaired configuration does not validate: %v", err)
	}
}

// The A/B that makes the test above meaningful: on the same busy port, the
// plain search takes the very next port and the reserved-aware search skips it.
// Without this pair the regression test could pass for the wrong reason.
func TestNextFreeAddrAvoidingSkipsReservedPorts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	busy := ln.Addr().String()
	_, portStr, _ := net.SplitHostPort(busy)
	base, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port %q: %v", portStr, err)
	}

	naive, ok := NextFreeAddr(busy)
	if !ok {
		t.Fatalf("NextFreeAddr(%s) found nothing", busy)
	}
	naivePort, _ := addrPort(naive)
	if naivePort != base+1 {
		t.Skipf("port %d is not free here (the plain search picked %s); the comparison needs it", base+1, naive)
	}

	got, ok := nextFreeAddrAvoiding(busy, map[int]bool{base + 1: true})
	if !ok {
		t.Fatalf("nextFreeAddrAvoiding(%s) found nothing", busy)
	}
	if p, _ := addrPort(got); p == base+1 {
		t.Errorf("the reserved-aware search still returned the reserved port %d", base+1)
	}
	if portBusy(got) {
		t.Errorf("the reserved-aware search returned a busy port: %s", got)
	}
}
