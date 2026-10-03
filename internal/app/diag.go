package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"vvpn/internal/aisession"
	"vvpn/internal/config"
	"vvpn/internal/diag"
)

// DiagProber is the probe engine behind the 诊断 page. It is created on first
// use and reads its limits from the live configuration, so editing the
// timeout or the concurrency in the settings takes effect on the next probe
// instead of after a restart.
func (a *App) DiagProber() *diag.Prober {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.diagProber == nil {
		a.diagProber = diag.New(diag.Options{
			ProxyAddr:    func() string { return a.diagProxyAddr() },
			FallbackAddr: func() string { return a.diagFallbackAddr() },
			TimeoutMS:    func() int { return a.Config().Diagnostics.ProbeTimeoutMS },
			Concurrency:  func() int { return a.Config().Diagnostics.MaxConcurrency },
			CacheTTL: func() time.Duration {
				return time.Duration(a.Config().Diagnostics.CacheTTLSec) * time.Second
			},
			// The AI panel asks the session endpoints as the signed-in user when
			// a login was captured; without one it honestly reports 黄绿.
			AICookies: aisession.Cookies,
		})
	}
	return a.diagProber
}

// diagProxyAddr is the kernel's mixed port: the path that actually leaves
// through the node the user selected.
func (a *App) diagProxyAddr() string {
	cfg := a.Config()
	if cfg.Core.Port <= 0 {
		return ""
	}
	return fmt.Sprintf("127.0.0.1:%d", cfg.Core.Port)
}

// diagFallbackAddr is the client's own mixed port. It is used when the kernel
// is not running, so the panel still answers "through the client" instead of
// silently reporting a direct connection.
func (a *App) diagFallbackAddr() string {
	return strings.TrimSpace(a.Config().Inbound.HTTPAddr)
}

// DiagSettings is the diagnostics block in force.
func (a *App) DiagSettings() config.Diagnostics { return a.Config().Diagnostics }

// DiagExternalOn reports whether external probing is allowed at all.
func (a *App) DiagExternalOn() bool { return a.Config().Diagnostics.ExternalOn() }

// DiagDelayNode times one node against one URL through the running core. It is
// the Delayer the latency matrix drives.
func (a *App) DiagDelayNode(ctx context.Context, node, rawURL string, timeoutMS int) (int, error) {
	id := a.RunningCoreID()
	if id == "" {
		return 0, fmt.Errorf("内核没有在运行")
	}
	delays, err := a.CoreDelay(ctx, id, node, rawURL, timeoutMS)
	if err != nil {
		return 0, err
	}
	if d, ok := delays[node]; ok {
		return d, nil
	}
	// A group answers with a member map; report the best member so the cell
	// still shows something meaningful.
	best := 0
	for _, d := range delays {
		if d <= 0 {
			continue
		}
		if best == 0 || d < best {
			best = d
		}
	}
	if best == 0 {
		return 0, fmt.Errorf("节点 %s 没有返回延迟", node)
	}
	return best, nil
}

// DiagNodeNames lists the member names the matrix should test by default: the
// current group's members, minus the group's own name and the core built-ins.
func (a *App) DiagNodeNames(group string) []string {
	profile := a.Profile()
	group = strings.TrimSpace(group)
	if group == "" {
		group = profile.Final
	}
	var members []string
	for _, g := range profile.Groups {
		if g.Name == group {
			members = g.Members
			break
		}
	}
	if len(members) == 0 && len(profile.Groups) > 0 {
		members = profile.Groups[0].Members
	}
	names := make([]string, 0, len(members))
	for _, m := range members {
		if IsBuiltinGroup(m) {
			continue
		}
		names = append(names, m)
	}
	return names
}
