// Package app wires configuration, logging, the routing engine and the proxy
// core into one long-lived object that main() and the control API drive.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"vvpn/internal/config"
	"vvpn/internal/core"
	"vvpn/internal/diag"
	"vvpn/internal/logbus"
	"vvpn/internal/netutil"
	"vvpn/internal/proxy"
	"vvpn/internal/rules"
	"vvpn/internal/sysproxy"
)

// App is the running client.
type App struct {
	version string

	mu        sync.Mutex
	cfgPath   string
	cfg       config.Config
	engine    *rules.Engine
	srv       *proxy.Server
	cores     *core.Supervisor
	log       *logbus.Bus
	subs      []Subscription
	panelSess PanelSession
	// diagProber is the probe engine behind the 诊断 page. Created lazily so a
	// headless run that never opens the page pays nothing for it.
	diagProber *diag.Prober
	started    time.Time

	// node is the node the running core sends traffic through. The watcher
	// refreshes it in the background so the status poll - which the console
	// runs every couple of seconds - never has to wait on the core.
	node nodeTracker
	// repairWarn is the last set of selector groups the core refused to
	// switch, so the watcher can report a persistent refusal once instead of
	// every tick.
	repairWarn string

	// windowOpener and quitFn are wired by the desktop build. Headless runs
	// leave them nil, which is how the API knows the feature is unavailable.
	windowOpener func() error
	quitFn       func()

	// consoleAddr is the address the control console actually listens on. It is
	// set by the desktop entry point, because the console port comes from a flag
	// rather than the configuration file.
	consoleAddr string

	// guardRunning mirrors the lifetime of the invisible system-proxy guard
	// copy. The supervisor that owns it lives in cmd/desktop and reports
	// here, because the settings card has to be able to say whether "on"
	// means "a guard is alive" or "a guard will be started on the next tick".
	guardRunning bool

	// hostInfo is what the desktop shell knows and the app cannot: the versions
	// of the pieces the shell embedded. The about card shows it.
	hostInfo map[string]string
	// buildStamp and buildCommit are stamped by the linker at build time, so a
	// bug report can name the exact binary it came from.
	buildStamp  string
	buildCommit string
}

// Status is the UI-facing summary of the running client.
type Status struct {
	Version        string `json:"version"`
	StartedAt      string `json:"started_at"`
	UptimeSec      int64  `json:"uptime_sec"`
	ConfigPath     string `json:"config_path"`
	SOCKS5Addr     string `json:"socks5_addr"`
	HTTPAddr       string `json:"http_addr"`
	AllowLAN       bool   `json:"allow_lan"`
	AuthEnabled    bool   `json:"auth_enabled"`
	Outbound       string `json:"outbound"`
	OutboundName   string `json:"outbound_name"`
	RuleCount      int    `json:"rule_count"`
	ActiveConns    int    `json:"active_conns"`
	TotalConns     uint64 `json:"total_conns"`
	SystemProxy    bool   `json:"system_proxy"`
	SystemProxySrv string `json:"system_proxy_server,omitempty"`
	// SystemProxyOwned separates "the OS proxy is on" from "this client is
	// the one that turned it on". Only the second one may be switched off
	// again: on a machine running a second proxy client the switch is up and
	// belongs to that client.
	SystemProxyOwned bool `json:"system_proxy_owned"`
	// Engine names what serves traffic right now: "builtin" or the id of the
	// running external core. ActiveHTTP/ActiveSOCKS are the addresses to point
	// applications at for that engine.
	Engine      string `json:"engine"`
	CoreAddr    string `json:"core_addr,omitempty"`
	ActiveHTTP  string `json:"active_http"`
	ActiveSOCKS string `json:"active_socks"`
	// Process metrics for the client and the external core it started. They
	// are always present and always numbers, so the console can render the
	// status card without null checks; 0 means "not readable" or "not running".
	ClientRSSBytes uint64 `json:"client_rss_bytes"`
	ClientThreads  int    `json:"client_threads"`
	ClientHandles  int    `json:"client_handles"`
	CoreRSSBytes   uint64 `json:"core_rss_bytes"`
	CoreThreads    int    `json:"core_threads"`
	CoreHandles    int    `json:"core_handles"`
}

// New loads (or creates) the configuration and starts the proxy core.
func New(cfgPath, version string) (*App, error) {
	cfg, err := config.LoadOrCreate(cfgPath)
	if err != nil {
		return nil, err
	}
	a := &App{
		version: version,
		cfgPath: cfgPath,
		cfg:     cfg,
		log:     logbus.New(cfg.Log.Capacity, logbus.ParseLevel(cfg.Log.Level)),
		started: time.Now(),
	}
	a.cores = core.NewSupervisor(coreDir(cfgPath, cfg.Core.Dir), a.log)
	a.ensureCoreSecret()
	// The system proxy is a machine-wide setting that outlives this process:
	// recording where it was found is what lets a crash or a kill be undone.
	sysproxy.SetStatePath(sysproxy.DefaultStatePath(cfgPath))
	if err := a.loadSubs(); err != nil {
		a.log.Warnf("读取订阅列表失败：%v", err)
	}
	if err := a.loadPanel(); err != nil {
		a.log.Warnf("读取小白会话失败：%v", err)
	}
	// Node ownership is in-memory only, so it has to be rebuilt from the saved
	// subscriptions; otherwise re-importing one would duplicate its servers.
	rebuildNodeSources(a.subs, a.Profile().Nodes)
	a.log.Infof("syan-clash %s starting (config %s)", version, cfgPath)
	// Another proxy client on the same machine owns 7890/7891 by default.
	// Sliding off a taken port beats refusing to start.
	a.avoidPortConflicts()
	if err := a.startLocked(); err != nil {
		return nil, err
	}
	a.autostartCore(cfg)
	// A previous run that was killed left the registry pointing at our port
	// with nothing behind it; undo that before the user notices.
	a.cleanupLeftoverSystemProxy()
	return a, nil
}

// coreDir resolves the core working directory relative to the config file, so
// a portable install keeps everything in one tree.
func coreDir(cfgPath, dir string) string {
	if dir == "" {
		dir = "cores"
	}
	if filepath.IsAbs(dir) {
		return dir
	}
	return filepath.Join(filepath.Dir(cfgPath), dir)
}

// subsPath is where the saved subscription list lives.
func (a *App) subsPath() string {
	return filepath.Join(filepath.Dir(a.cfgPath), "subscriptions.json")
}

func (a *App) loadSubs() error {
	raw, err := os.ReadFile(a.subsPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var subs []Subscription
	if err := json.Unmarshal(raw, &subs); err != nil {
		return fmt.Errorf("%s: %w", a.subsPath(), err)
	}
	a.mu.Lock()
	a.subs = subs
	a.mu.Unlock()
	return nil
}

// saveSubs writes the subscription list atomically.
func (a *App) saveSubs() error {
	a.mu.Lock()
	snapshot := make([]Subscription, len(a.subs))
	copy(snapshot, a.subs)
	a.mu.Unlock()

	raw, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	path := a.subsPath()
	tmp, err := os.CreateTemp(filepath.Dir(path), ".subs-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func (a *App) autostartCore(cfg config.Config) {
	if cfg.Core.ID == "" || !cfg.Core.AutoStart {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if _, err := a.StartCore(ctx, cfg.Core.ID); err != nil {
			a.log.Warnf("core %s autostart failed: %v", cfg.Core.ID, err)
		}
	}()
}

// EffectiveProfile returns the profile to compile, falling back to a sane
// default when the configuration does not define one.
func EffectiveProfile(cfg config.Config) core.Profile {
	if cfg.Core.Profile != nil {
		return *cfg.Core.Profile
	}
	p := core.DefaultProfile()
	addr := cfg.Inbound.HTTPAddr
	if addr == "" {
		addr = cfg.Inbound.SOCKS5Addr
	}
	if addr != "" {
		p.Inbounds = []core.Inbound{{
			Type:   core.InboundMixed,
			Tag:    "mixed-in",
			Listen: "127.0.0.1",
			Port:   portOf(addr, 2890),
		}}
	}
	return p
}

func portOf(addr string, fallback int) int {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fallback
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil || port <= 0 {
		return fallback
	}
	return port
}

func (a *App) startLocked() error {
	engine, err := rules.New(builtinRules(a.cfg))
	if err != nil {
		return err
	}
	srv, err := proxy.New(a.cfg, a.log, engine)
	if err != nil {
		return err
	}
	if err := srv.Start(); err != nil {
		return err
	}
	a.engine = engine
	a.srv = srv
	return nil
}

// builtinRules derives the built-in engine's rules from the effective profile,
// so a rule the user adds in the UI takes effect whether the client runs with
// an external core or on the built-in engine. Without this the two rule lists
// would drift apart and UI edits would silently do nothing in built-in mode.
func builtinRules(cfg config.Config) []rules.Rule {
	if cfg.Core.Profile == nil {
		return cfg.Rules
	}
	out := make([]rules.Rule, 0, len(cfg.Core.Profile.Rules))
	for _, r := range cfg.Core.Profile.Rules {
		out = append(out, rules.Rule{
			Kind:   r.Kind,
			Value:  r.Value,
			Action: builtinAction(r.Action),
		})
	}
	// A profile without a catch-all would make the engine fall through to its
	// own default, which is fine, but an explicit reject/direct fallback must
	// be preserved.
	return out
}

// builtinAction maps a neutral action onto the built-in engine's vocabulary.
// The engine knows direct/proxy/reject; group names and "proxy" both mean
// "use the configured outbound".
func builtinAction(action string) string {
	switch action {
	case core.ActionDirect:
		return string(rules.ActionDirect)
	case core.ActionReject:
		return string(rules.ActionReject)
	default:
		return string(rules.ActionProxy)
	}
}

// exportRules mirrors the effective profile rules into the legacy top-level
// rule list so both views of the configuration agree.
func exportRules(cfg config.Config) []rules.Rule {
	if cfg.Core.Profile == nil {
		return cfg.Rules
	}
	return builtinRules(cfg)
}

// Reload validates and applies a new configuration, rolling back to the
// previous one if the new listeners cannot be started.
func (a *App) Reload(next config.Config) error {
	next.Normalize()
	// Keep the legacy top-level rule list in step with the profile. The profile
	// is the source of truth; cfg.Rules stays populated so anything reading the
	// raw configuration (the settings page, older tooling, backups) sees the
	// rules that are actually in force.
	next.Rules = exportRules(next)
	if err := next.Validate(); err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	prev := a.cfg
	if a.srv != nil {
		_ = a.srv.Close()
	}
	a.cfg = next
	if err := a.startLocked(); err != nil {
		a.cfg = prev
		if rerr := a.startLocked(); rerr != nil {
			return fmt.Errorf("apply failed (%v) and rollback failed (%w)", err, rerr)
		}
		return fmt.Errorf("apply failed, rolled back to the previous configuration: %w", err)
	}
	a.log.SetLevel(logbus.ParseLevel(next.Log.Level))
	if err := config.Save(a.cfgPath, next); err != nil {
		return fmt.Errorf("configuration applied but not written to %s: %w", a.cfgPath, err)
	}
	a.log.Infof("configuration reloaded")
	return nil
}

// Stop shuts the proxy core down.
func (a *App) Stop() {
	if a.cores != nil {
		a.cores.StopAll()
	}
	a.mu.Lock()
	srv := a.srv
	a.srv = nil
	a.mu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
	a.log.Infof("syan-clash stopped")
}

// SetWindowOpener registers how the desktop build opens (or re-opens) the
// application window.
func (a *App) SetWindowOpener(fn func() error) {
	a.mu.Lock()
	a.windowOpener = fn
	a.mu.Unlock()
}

// OpenWindow asks the host to show the application window. A headless run has
// no window and says so instead of pretending the click worked.
func (a *App) OpenWindow() error {
	a.mu.Lock()
	fn := a.windowOpener
	a.mu.Unlock()
	if fn == nil {
		return errors.New("当前是 headless 运行方式，没有桌面窗口；请直接打开控制台地址")
	}
	return fn()
}

// SetQuitFunc registers the shutdown path used by the tray menu and the UI.
func (a *App) SetQuitFunc(fn func()) {
	a.mu.Lock()
	a.quitFn = fn
	a.mu.Unlock()
}

// CanQuit reports whether this run has a shutdown path at all.
func (a *App) CanQuit() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.quitFn != nil
}

// RequestQuit asks the host to shut the client down.
func (a *App) RequestQuit() bool {
	a.mu.Lock()
	fn := a.quitFn
	a.mu.Unlock()
	if fn == nil {
		return false
	}
	fn()
	return true
}

// Version returns the build version.
func (a *App) Version() string { return a.version }

// ConsoleAddr is the address the control console listens on, "" when the
// process was started without one (the headless core build).
func (a *App) ConsoleAddr() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.consoleAddr
}

// SetConsoleAddr records the listening address once the socket is bound.
func (a *App) SetConsoleAddr(addr string) {
	a.mu.Lock()
	a.consoleAddr = addr
	a.mu.Unlock()
}

// ConfigPath returns the path of the active configuration file.
func (a *App) ConfigPath() string { return a.cfgPath }

// Config returns a copy of the active configuration.
func (a *App) Config() config.Config {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg
}

// Log exposes the log bus.
func (a *App) Log() *logbus.Bus { return a.log }

// Status summarises the running client.
func (a *App) Status() Status {
	// The status poll is also the heartbeat that keeps the entry point
	// pointed at the core: the supervisor's watchdog can restart a crashed
	// core without anyone asking, and a stale upstream would quietly send
	// traffic out of the local machine instead.
	a.syncUpstream()
	a.mu.Lock()
	cfg := a.cfg
	srv := a.srv
	engine := a.engine
	started := a.started
	a.mu.Unlock()

	st := Status{
		Version:     a.version,
		StartedAt:   started.Format(time.RFC3339),
		UptimeSec:   int64(time.Since(started).Seconds()),
		ConfigPath:  a.cfgPath,
		SOCKS5Addr:  cfg.Inbound.SOCKS5Addr,
		HTTPAddr:    cfg.Inbound.HTTPAddr,
		AllowLAN:    cfg.Inbound.AllowLAN,
		AuthEnabled: cfg.Inbound.Username != "" || cfg.Inbound.Password != "",
		Outbound:    cfg.Outbound.Type,
	}
	if engine != nil {
		st.RuleCount = len(engine.Rules())
	}
	if srv != nil {
		st.OutboundName = srv.OutboundName()
		st.ActiveConns, st.TotalConns = srv.Registry().Counts()
	}
	if enabled, server, err := sysproxy.Current(); err == nil {
		st.SystemProxy = enabled
		st.SystemProxySrv = server
	}
	st.SystemProxyOwned = sysproxy.OwnedBy(sysproxy.StatePath(), os.Getpid())
	st.ActiveHTTP, st.ActiveSOCKS = a.ActiveInbound()
	if id := a.RunningCoreID(); id != "" {
		st.Engine = id
		st.CoreAddr = fmt.Sprintf("127.0.0.1:%d", a.corePort())
		// Traffic on the client's own ports is handed to this core, so the
		// exit is the node the core selected - not the built-in engine's
		// outbound, which is only what the fallback path would use.
		if mode := a.node.coreMode(); mode == "direct" {
			// A core in direct mode sends every packet out of the local
			// machine, so naming a node here would be a lie. The mode is the
			// honest answer, and it is what the user asked for anyway.
			st.Outbound = mode
			st.OutboundName = mode
		} else if name := a.SelectedNode(); name != "" {
			st.Outbound = name
			st.OutboundName = name
		} else {
			st.Outbound = "core:" + id
			st.OutboundName = "core:" + id
		}
	} else {
		st.Engine = "builtin"
	}
	a.attachMetrics(&st)
	return st
}

// Connections returns the live and recently closed connections.
func (a *App) Connections() []proxy.ConnInfo {
	a.mu.Lock()
	srv := a.srv
	a.mu.Unlock()
	if srv == nil {
		return nil
	}
	return srv.Registry().Snapshot()
}

// CloseConnection kills one live connection.
func (a *App) CloseConnection(id uint64) bool {
	a.mu.Lock()
	srv := a.srv
	a.mu.Unlock()
	if srv == nil {
		return false
	}
	return srv.Registry().Close(id)
}

// RoutePreview answers "which rule would handle this destination" for the UI.
func (a *App) RoutePreview(ctx context.Context, host string, port uint16) (rules.Result, error) {
	a.mu.Lock()
	engine := a.engine
	a.mu.Unlock()
	if engine == nil {
		return rules.Result{}, errors.New("app: proxy core is not running")
	}
	ip, _ := netip.ParseAddr(host)
	res := engine.Match(host, ip, port)
	if !res.NeedResolve {
		return res, nil
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addr, err := netutil.ResolveHost(rctx, host)
	if err != nil {
		return rules.Result{Action: rules.ActionProxy, Rule: "dns-failed -> proxy", Index: -1}, nil
	}
	return engine.Match(host, addr, port), nil
}

// SetSystemProxy turns the OS-wide proxy on or off. It always publishes the
// entry point of the engine that is serving traffic: the running core's mixed
// port when one is up, the built-in listeners otherwise, so toggling the
// switch keeps working no matter which engine is active.
func (a *App) SetSystemProxy(enabled bool) error {
	return a.SetSystemProxyForced(enabled, false)
}

// SetSystemProxyForced is SetSystemProxy plus the explicit "take the setting
// over even though another program owns it" flag. The UI only reaches for it
// after the user has been told whose proxy is in the way; the takeover is still
// snapshotted, so quitting puts the other program's proxy back.
func (a *App) SetSystemProxyForced(enabled, force bool) error {
	if enabled {
		httpAddr, socksAddr := a.ActiveInbound()
		// The bypass list travels with every write: the registry value and the
		// configuration must never drift apart, and the user edits the list
		// while the switch is already on.
		return sysproxy.EnableForced(httpAddr, socksAddr, a.Config().SysProxy.BypassString(), force)
	}
	return sysproxy.Disable()
}

// Cores exposes the external core supervisor.
func (a *App) Cores() *core.Supervisor { return a.cores }

// CoreStatuses lists every known external core.
func (a *App) CoreStatuses() []core.CoreStatus { return a.cores.Status() }

// RenderCoreConfig compiles the effective profile for a core and returns the
// text that would be written to disk.
func (a *App) RenderCoreConfig(id string) ([]byte, error) {
	return core.Render(id, a.coreProfile())
}
