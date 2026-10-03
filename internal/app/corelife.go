package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"vvpn/internal/config"
	"vvpn/internal/core"
)

// The built-in engine and an external core deliberately listen on different
// ports: the built-in engine keeps the client-facing addresses from the
// configuration (inbound.http_addr / socks5_addr, 7890/7891 by default) and the
// core gets core.port (7899 by default). Nothing has to hand a listener over,
// so the two never collide, both can run at the same time, and starting or
// stopping a core can never leave the client without a working entry point.

// StartCore starts an external core on its own port and remembers the choice.
func (a *App) StartCore(ctx context.Context, id string) (core.CoreStatus, error) {
	status, err := a.cores.Start(ctx, id, a.coreProfile())
	if err != nil {
		return status, err
	}
	a.rememberCore(id)
	// The core is up, so "proxy" traffic goes to it from now on. The repair
	// runs in the background because mihomo needs a moment before its
	// control API answers, and the user should not wait for that.
	a.syncUpstream()
	a.startCoreRepair(id)
	return status, nil
}

// StopCore stops an external core. The built-in engine keeps running
// throughout, so there is nothing to hand back.
// CoreVersions lists the binaries of one core that exist on disk: the live one
// plus the archived releases an update replaced. It backs the rollback list in
// the console.
func (a *App) CoreVersions(id string) ([]core.CoreVersion, error) {
	return a.cores.CoreVersions(id)
}

func (a *App) StopCore(id string) error {
	err := a.cores.Stop(id)
	// No core means no upstream: "proxy" traffic falls back to the
	// configured outbound instead of dialling a port nothing listens on.
	a.syncUpstream()
	return err
}

// EnsureCore returns a running core id, starting the configured core when it is
// installed but stopped.
//
// The master switch depends on this: "system proxy on" only means "traffic goes
// through a node" while a core is actually running, and keeping the core warm
// is what makes the next click instant instead of a process start.
func (a *App) EnsureCore(ctx context.Context) (string, error) {
	if id := a.RunningCoreID(); id != "" {
		return id, nil
	}
	id := a.Config().Core.ID
	if id == "" {
		id = "mihomo"
	}
	spec, ok := core.Lookup(id)
	if !ok {
		return "", fmt.Errorf("未知内核 %q", id)
	}
	if !a.cores.Installed(spec) {
		return "", fmt.Errorf("内核 %s 尚未安装，无法通过节点转发流量", id)
	}
	if _, err := a.StartCore(ctx, id); err != nil {
		return "", err
	}
	return id, nil
}

// RunningCoreID names the core currently serving traffic, preferring the one
// the configuration selected.
func (a *App) RunningCoreID() string {
	if id := a.Config().Core.ID; id != "" {
		if _, _, running := a.cores.ControlAPI(id); running {
			return id
		}
	}
	for _, st := range a.cores.Status() {
		if st.Running {
			return st.ID
		}
	}
	return ""
}

// CoreAddr is the local entry point of the running core, "" when none runs.
func (a *App) CoreAddr() string {
	if a.RunningCoreID() == "" {
		return ""
	}
	return fmt.Sprintf("127.0.0.1:%d", a.corePort())
}

// corePort is the port the external core's proxy inbound must listen on.
// It is the same value coreAPIAddr() refuses to collide with, so the two are
// computed in one place instead of drifting apart.
func (a *App) corePort() int { return coreMixedPort(a.Config()) }

// ActiveInbound is the address pair applications should use right now: the
// running core's mixed port while a core is up, the built-in listeners
// otherwise.
//
// The built-in pair is read back from the listeners themselves, not from the
// configuration: when a port was taken the listener slid to a neighbour, and
// handing the system proxy the configured address would point every
// application at a socket nobody is listening on.
func (a *App) ActiveInbound() (httpAddr, socksAddr string) {
	if addr := a.CoreAddr(); addr != "" {
		return addr, addr
	}
	cfg := a.Config()
	httpAddr, socksAddr = cfg.Inbound.HTTPAddr, cfg.Inbound.SOCKS5Addr
	a.mu.Lock()
	srv := a.srv
	a.mu.Unlock()
	if srv == nil {
		return httpAddr, socksAddr
	}
	if bound := srv.Bound("mixed"); bound != "" {
		// One socket carries both protocols, so both answers are the same
		// address - exactly what the configuration asked for.
		return bound, bound
	}
	if bound := srv.Bound("http"); bound != "" {
		httpAddr = bound
	}
	if bound := srv.Bound("socks5"); bound != "" {
		socksAddr = bound
	}
	return httpAddr, socksAddr
}

// CoreAPIAddr is the external-controller address the core is given: the socket
// the client drives the core through. It is deliberately not the client's own
// console port - those are two different sockets that both belong to this
// process, and the about card used to print the wrong one under this name.
func (a *App) CoreAPIAddr() string {
	return coreAPIAddr(a.Config())
}

// coreProfile is the profile an external core is compiled from: the effective
// profile with its proxy listener moved onto the core's own port. TUN and any
// other inbound the user enabled survive untouched.
func (a *App) coreProfile() core.Profile {
	port := a.corePort()
	p := EffectiveProfile(a.Config())
	// The core must fetch any missing geodata through the same mirror the
	// client uses (and the client, not the core, decides when to fetch at all).
	p.GeoMirror = a.Config().Core.Mirror
	// The controller address is the client's, not the subscription's: a
	// provider's YAML points it at 9090 - or at 0.0.0.0, which would open the
	// core's control socket to the whole local network. It is always loopback
	// plus the client's own port, and it always carries the client's random
	// secret, so nothing else on the machine can drive the core.
	p.ClashAPI = loopbackAddr(coreAPIAddr(a.Config()))
	p.ClashSecret = a.CoreSecret()
	inbounds := make([]core.Inbound, 0, len(p.Inbounds)+1)
	moved := false
	for _, in := range p.Inbounds {
		switch in.Type {
		case core.InboundMixed, core.InboundSocks, core.InboundHTTP:
			if moved {
				continue
			}
			moved = true
			in.Type = core.InboundMixed
			in.Listen = "127.0.0.1"
			in.Port = port
			if in.Tag == "" {
				in.Tag = "mixed-in"
			}
			inbounds = append(inbounds, in)
		default:
			inbounds = append(inbounds, in)
		}
	}
	if !moved {
		inbounds = append(inbounds, core.Inbound{
			Type: core.InboundMixed, Tag: "mixed-in", Listen: "127.0.0.1", Port: port,
		})
	}
	p.Inbounds = inbounds
	return p
}

// ensureCoreSecret generates the control-API secret once per install and
// writes it to disk immediately, so every later start reuses the same value.
func (a *App) ensureCoreSecret() {
	a.mu.Lock()
	if a.cfg.Core.Secret != "" {
		a.mu.Unlock()
		return
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		a.mu.Unlock()
		a.log.Warnf("生成内核 API 密钥失败：%v", err)
		return
	}
	a.cfg.Core.Secret = hex.EncodeToString(buf)
	cfg := a.cfg
	a.mu.Unlock()
	if err := config.Save(a.cfgPath, cfg); err != nil {
		a.log.Warnf("保存内核 API 密钥失败：%v", err)
		return
	}
	a.log.Infof("已为内核控制接口生成随机密钥")
}

// CoreSecret is the bearer token the external core's control API requires.
func (a *App) CoreSecret() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg.Core.Secret
}

// EnsureGeo completes the geodata files an external core needs before it will
// accept a configuration that mentions GEOIP/GEOSITE rules.
func (a *App) EnsureGeo(ctx context.Context, id string) ([]string, error) {
	if _, ok := core.Lookup(id); !ok {
		return nil, fmt.Errorf("未知内核：%s", id)
	}
	return a.cores.EnsureGeo(ctx, id, a.Config().Core.Mirror)
}

// GeoStatus reports the geodata files of one core, for the UI to display.
func (a *App) GeoStatus(id string) []core.GeoFileStatus {
	if _, ok := core.Lookup(id); !ok {
		return nil
	}
	return a.cores.GeoStatus(id)
}

// CoreGeoReady tells the UI whether a core can start without downloading
// anything first.
func (a *App) CoreGeoReady(id string) bool { return a.cores.GeoReady(id) }

// rememberCore persists which core the user started, so a later profile change
// restarts the core that is actually running.
func (a *App) rememberCore(id string) {
	a.mu.Lock()
	if a.cfg.Core.ID == id {
		a.mu.Unlock()
		return
	}
	a.cfg.Core.ID = id
	cfg := a.cfg
	a.mu.Unlock()
	if err := config.Save(a.cfgPath, cfg); err != nil {
		a.log.Warnf("保存内核选择失败：%v", err)
	}
}
