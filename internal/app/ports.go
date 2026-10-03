package app

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"vvpn/internal/config"
	"vvpn/internal/core"
)

// Desktop proxy clients all ship the same well-known defaults: 7890/7891 for
// the proxy inbounds and 9090 for a controller. On a machine that already runs
// another client those ports are taken, and a client that insists on them
// either refuses to start or quietly loses to the other one. Everything in
// this file exists so syan-clash slides onto a free port instead: it probes the
// ports, shows the conflicts in the console, and repairs them at startup and
// on demand.

// portScanLimit bounds the search for a free port, so a machine with something
// on every port fails fast instead of spinning.
const portScanLimit = 200

// PortEntry describes one listener the client wants to own.
type PortEntry struct {
	Kind  string `json:"kind"`
	Label string `json:"label"`
	Addr  string `json:"addr"`
	Busy  bool   `json:"busy"`
	Mine  bool   `json:"mine"`
	// Blocked is the only state worth acting on: somebody else holds the port.
	Blocked bool `json:"blocked"`
	// Next is a free address above Addr, filled in when Blocked.
	Next string `json:"next,omitempty"`
}

// PortMove is one applied relocation.
type PortMove struct {
	Kind    string `json:"kind"`
	OldAddr string `json:"old_addr"`
	NewAddr string `json:"new_addr"`
}

// portBusy reports whether addr is already taken. Binding is the only test
// that also covers a wildcard listener owned by another process, which is
// exactly the collision that matters here.
func portBusy(addr string) bool {
	if strings.TrimSpace(addr) == "" {
		return false
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return true
	}
	_ = ln.Close()
	return false
}

// NextFreeAddr returns the first free address above addr, host part preserved.
// The desktop entry point uses it for the console port, which is bound outside
// the configuration.
func NextFreeAddr(addr string) (string, bool) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 {
		return "", false
	}
	for i := 1; i <= portScanLimit; i++ {
		candidate := port + i
		if candidate > 65535 {
			break
		}
		next := net.JoinHostPort(host, strconv.Itoa(candidate))
		if !portBusy(next) {
			return next, true
		}
	}
	return "", false
}

func addrPort(addr string) (int, bool) {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 {
		return 0, false
	}
	return port, true
}

// coreMixedPort is the port the external core's proxy inbound listens on: the
// configured core port, or the client default when the configuration is silent.
func coreMixedPort(cfg config.Config) int {
	if cfg.Core.Port > 0 {
		return cfg.Core.Port
	}
	return config.Default().Core.Port
}

// coreAPIAddr is the control address the external core will be given. It has
// its own port on purpose: 9090 is what another Clash-family client holds, and
// the console in this process is a third socket again.
//
// A subscription's YAML can point external-controller at the very port it uses
// for mixed-port, and honouring that verbatim costs the core its proxy
// listener: mihomo binds the controller first, then logs "Start Mixed server
// error" and keeps running with no way in, while the client hands that same
// address to the system proxy as if it were a proxy. The control socket is the
// one the client cannot work without, so a collision moves the controller to
// the client's own port - which is never the proxy port.
func coreAPIAddr(cfg config.Config) string {
	api := core.DefaultClashAPI
	if p := cfg.Core.Profile; p != nil && strings.TrimSpace(p.ClashAPI) != "" {
		api = strings.TrimSpace(p.ClashAPI)
	}
	mixed := coreMixedPort(cfg)
	port, ok := addrPort(api)
	if !ok || port != mixed {
		return api
	}
	// Slide the controller one port up. The result is a pure function of the
	// configuration and never a probe, so every caller - the profile compiler,
	// the port report and the startup repair - agrees on the same address
	// whether or not the core is already running. A fixed fallback such as
	// 2898 is exactly what another Clash-family client on this machine is
	// likely to hold, and a controller that cannot bind leaves the client with
	// no way into its own core; a busy candidate is repaired by conflictMoves
	// like every other port.
	if mixed+1 > 65535 {
		return core.DefaultClashAPI
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(mixed+1))
}

// loopbackAddr keeps the port of addr but forces the host to 127.0.0.1. The
// core's control socket is an administrative interface: a subscription that
// asks for 0.0.0.0 must not be able to open it to the local network.
func loopbackAddr(addr string) string {
	port, ok := addrPort(addr)
	if !ok {
		return core.DefaultClashAPI
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

// PortReport lists every port the client is configured to own and whether it
// is free, ours, or somebody else's.
func (a *App) PortReport() []PortEntry {
	cfg := a.Config()
	// The suggestion shown next to a blocked port has to be the same one the
	// repair would apply, so it is computed against the same reserved set.
	reserved := reservedPorts(cfg)
	mine := map[string]bool{}
	if strings.TrimSpace(cfg.Inbound.HTTPAddr) != "" {
		mine[cfg.Inbound.HTTPAddr] = true
	}
	if strings.TrimSpace(cfg.Inbound.SOCKS5Addr) != "" {
		mine[cfg.Inbound.SOCKS5Addr] = true
	}
	if a.RunningCoreID() != "" {
		mine[fmt.Sprintf("127.0.0.1:%d", a.corePort())] = true
	}

	entries := []PortEntry{
		{Kind: "http", Label: "HTTP / 混合入口", Addr: cfg.Inbound.HTTPAddr},
		{Kind: "socks", Label: "SOCKS5 入口", Addr: cfg.Inbound.SOCKS5Addr},
		{Kind: "core", Label: "内核混合端口", Addr: fmt.Sprintf("127.0.0.1:%d", a.corePort())},
	}
	if api := coreAPIAddr(cfg); api != "" {
		if a.RunningCoreID() != "" {
			mine[api] = true
		}
		entries = append(entries, PortEntry{Kind: "core-api", Label: "内核控制接口", Addr: api})
	}
	if addr := a.ConsoleAddr(); addr != "" {
		// The console answers this very request, so it is always ours.
		mine[addr] = true
		entries = append(entries, PortEntry{Kind: "console", Label: "控制台", Addr: addr})
	}
	for i := range entries {
		e := &entries[i]
		if strings.TrimSpace(e.Addr) == "" {
			continue
		}
		e.Mine = mine[e.Addr]
		e.Busy = portBusy(e.Addr)
		e.Blocked = e.Busy && !e.Mine
		if e.Blocked {
			if next, ok := nextFreeAddrAvoiding(e.Addr, reserved); ok {
				e.Next = next
			}
		}
	}
	return entries
}

// conflictMoves pairs every port somebody else already holds with a free
// replacement. One function, so the startup repair and the console's one-click
// repair can never disagree about what a conflict is.
//
// A replacement has to dodge every port the configuration already reserves,
// not just the ones that happen to be busy. Sliding 4301 onto 4302 looks
// free but is useless when 4302 is the core's own proxy port: the repaired
// profile then fails its own validation with "core.port is already used by
// inbound.socks5_addr", and from that moment nothing can be saved at all.
// The reserved set also absorbs each move as it is made, so two relocations
// never land on each other.
func conflictMoves(cfg config.Config) []PortMove {
	reserved := reservedPorts(cfg)
	var moves []PortMove
	add := func(kind, addr string) {
		if strings.TrimSpace(addr) == "" || !portBusy(addr) {
			return
		}
		next, ok := nextFreeAddrAvoiding(addr, reserved)
		if !ok {
			return
		}
		if port, ok := addrPort(next); ok {
			reserved[port] = true
		}
		moves = append(moves, PortMove{Kind: kind, OldAddr: addr, NewAddr: next})
	}
	add("http", cfg.Inbound.HTTPAddr)
	add("socks", cfg.Inbound.SOCKS5Addr)
	if cfg.Core.Port > 0 {
		add("core", fmt.Sprintf("127.0.0.1:%d", cfg.Core.Port))
	}
	// Only movable when the profile exists: that is where the address lives.
	if cfg.Core.Profile != nil {
		add("core-api", coreAPIAddr(cfg))
	}
	return moves
}

// reservedPorts collects every port the configuration already writes down.
// The core's proxy port and its controller are in here even when nothing is
// listening on them yet: they are reserved by the document, not by a socket,
// and that is exactly the distinction a busy-port check cannot make.
func reservedPorts(cfg config.Config) map[int]bool {
	out := map[int]bool{}
	keep := func(addr string) {
		if p, ok := addrPort(addr); ok {
			out[p] = true
		}
	}
	keep(cfg.Inbound.HTTPAddr)
	keep(cfg.Inbound.SOCKS5Addr)
	keep(cfg.API.Addr)
	if cfg.Core.Port > 0 {
		out[cfg.Core.Port] = true
	}
	if cfg.Core.Profile != nil {
		keep(cfg.Core.Profile.ClashAPI)
		for _, in := range cfg.Core.Profile.Inbounds {
			if in.Port > 0 {
				out[int(in.Port)] = true
			}
		}
	}
	return out
}

// nextFreeAddrAvoiding is NextFreeAddr with a reserved set in the way: the
// first free candidate that the configuration has not already spoken for.
func nextFreeAddrAvoiding(addr string, reserved map[int]bool) (string, bool) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 {
		return "", false
	}
	for i := 1; i <= portScanLimit; i++ {
		candidate := port + i
		if candidate > 65535 {
			break
		}
		if reserved[candidate] {
			continue
		}
		next := net.JoinHostPort(host, strconv.Itoa(candidate))
		if !portBusy(next) {
			return next, true
		}
	}
	return "", false
}

// applyPortMoves rewrites every place a port is written down: the built-in
// engine reads config.Inbound, the external core reads config.Core.Port, and
// the profile keeps its own copy of the inbounds the core is compiled from.
func applyPortMoves(cfg *config.Config, moves []PortMove) {
	byPort := map[int]string{}
	for _, m := range moves {
		oldPort, okOld := addrPort(m.OldAddr)
		newPort, okNew := addrPort(m.NewAddr)
		if !okOld || !okNew {
			continue
		}
		byPort[oldPort] = m.NewAddr
		switch m.Kind {
		case "http":
			cfg.Inbound.HTTPAddr = m.NewAddr
		case "socks":
			cfg.Inbound.SOCKS5Addr = m.NewAddr
		case "core":
			cfg.Core.Port = newPort
		case "core-api":
			if cfg.Core.Profile != nil {
				cfg.Core.Profile.ClashAPI = m.NewAddr
			}
		}
	}
	if cfg.Core.Profile == nil {
		return
	}
	for i := range cfg.Core.Profile.Inbounds {
		in := &cfg.Core.Profile.Inbounds[i]
		next, ok := byPort[int(in.Port)]
		if !ok {
			continue
		}
		if port, ok := addrPort(next); ok {
			in.Port = port
		}
	}
}

// avoidPortConflicts runs before the built-in listeners start, so a port that
// another client already owns can never stop syan-clash from coming up. The old
// value is never kept: a client that silently loses a port race is worse than
// one that moves and says so.
func (a *App) avoidPortConflicts() {
	cfg := a.Config()
	moves := conflictMoves(cfg)
	if len(moves) == 0 {
		return
	}
	applyPortMoves(&cfg, moves)
	a.mu.Lock()
	a.cfg = cfg
	a.mu.Unlock()
	for _, m := range moves {
		a.log.Warnf("端口 %s 已被其它程序占用，自动改用 %s", m.OldAddr, m.NewAddr)
	}
	if err := config.Save(a.cfgPath, cfg); err != nil {
		a.log.Warnf("端口调整未能写入配置文件：%v", err)
	}
}

// RelocatePorts moves every conflicted port onto a free one and applies the
// change; the console's "改用空闲端口" button calls it. Ports that are free or
// already ours are left alone.
func (a *App) RelocatePorts() ([]PortMove, error) {
	moves := make([]PortMove, 0, 4)
	for _, e := range a.PortReport() {
		if e.Blocked && e.Next != "" {
			moves = append(moves, PortMove{Kind: e.Kind, OldAddr: e.Addr, NewAddr: e.Next})
		}
	}
	if len(moves) == 0 {
		return nil, nil
	}
	cfg := a.Config()
	applyPortMoves(&cfg, moves)
	coreWasRunning := a.RunningCoreID() != ""
	if err := a.Reload(cfg); err != nil {
		return nil, err
	}
	// A running core keeps the configuration it was compiled with, so a moved
	// core port only takes effect after that core is restarted.
	if coreWasRunning && cfg.Core.ID != "" {
		a.cores.StopAll()
		go func(id string) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			if _, err := a.StartCore(ctx, id); err != nil {
				a.log.Warnf("改用新端口后重启内核失败：%v", err)
			}
		}(cfg.Core.ID)
	}
	for _, m := range moves {
		a.log.Warnf("端口 %s 已被占用，改用 %s", m.OldAddr, m.NewAddr)
	}
	return moves, nil
}
