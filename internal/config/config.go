// Package config holds the client's on-disk configuration model, its
// validation rules and atomic load/save helpers.
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"vvpn/internal/core"
	"vvpn/internal/rules"
)

// Config is the whole client configuration.
type Config struct {
	Inbound  Inbound      `json:"inbound"`
	Outbound Outbound     `json:"outbound"`
	Rules    []rules.Rule `json:"rules"`
	Log      Log          `json:"log"`
	API      API          `json:"api"`
	Core     Core         `json:"core"`

	// Diagnostics configures the P5 probe features: IP purity, unlock checks,
	// the site latency matrix, the speed test and the network tools. Every
	// field is optional; Normalize fills the defaults in.
	Diagnostics Diagnostics `json:"diagnostics,omitempty"`

	// NodeFilter is applied to every imported node list: it drops the nodes the
	// user does not want, cleans the airport's own "info" pseudo-nodes out of
	// the list and renames the rest into a stable, readable form.
	NodeFilter NodeFilter `json:"node_filter,omitempty"`

	// App is the desktop shell's own preference block: how the client behaves
	// as a Windows application, not how it routes. The routing engine never
	// reads it, but keeping it in the same file means "copy the folder" still
	// moves the whole setup.
	App AppSettings `json:"app,omitempty"`

	// SysProxy configures how the Windows system proxy is published. It is
	// separate from Inbound because it is about the OS switch, not the
	// listeners: it only matters while the 系统代理 toggle is on.
	SysProxy SysProxy `json:"sysproxy,omitempty"`

	// Service is the service-mode block (P0-1): whether the invisible
	// system-proxy guard runs, and where the privileged helper listens.
	// The client is fully usable without the service; the service is what
	// makes TUN available without a UAC prompt on every launch.
	Service ServiceSettings `json:"service,omitempty"`

	// WebDAV is the optional remote backup target (P1-11): the client can push
	// its backup zip into a WebDAV directory and pull it back on another
	// machine. The block is inert until url is set, so a configuration that
	// never used the feature keeps behaving exactly as it did.
	WebDAV WebDAVSettings `json:"webdav,omitempty"`

	// portsMigrated records that normalising moved this value off the shared
	// default ports, so the loader can write the migrated result back to disk.
	portsMigrated bool
}

// AppSettings is the desktop shell's preference block. Every field is
// optional and defaults to the plain behaviour.
type AppSettings struct {
	// SilentStart launches the client straight into the tray. The window is
	// still created - the tray icon can bring it up at any time - it just is
	// not shown until the user asks for it.
	SilentStart bool `json:"silent_start,omitempty"`

	// UpdateSource is where a newer build of this client can be found. It
	// accepts either an HTTPS URL to a release manifest (JSON) or a GitHub
	// repository written as "owner/name" (its full github.com URL works too).
	// Empty means this build has no update channel: the about card then says
	// so instead of inventing a version to compare against.
	UpdateSource string `json:"update_source,omitempty"`

	// URLScheme makes this client the program Windows starts for clash://
	// links. It is OFF unless the pointer says otherwise: the scheme is
	// usually already registered by another Clash-family client, and taking
	// it over without being asked would break the client the user actually
	// uses. An explicit true is the only thing that registers it, and the
	// client still refuses to overwrite a registration that belongs to
	// somebody else.
	URLScheme *bool `json:"url_scheme,omitempty"`
}

// URLSchemeEnabled reports whether the user asked this client to own the
// clash:// scheme. Never written means no.
func (s AppSettings) URLSchemeEnabled() bool {
	return s.URLScheme != nil && *s.URLScheme
}

// SysProxy is the OS-proxy preference block. Every field is optional, so a
// configuration written before this block existed keeps behaving exactly as it
// did: an empty list means the built-in default.
type SysProxy struct {
	// Bypass is the ProxyOverride list, one entry per element. Entries are
	// written to the registry joined with ";" - the separator WinINET uses -
	// so an entry must not contain one. An empty list keeps DefaultBypass.
	Bypass []string `json:"bypass,omitempty"`
}

// BypassString renders the list as the semicolon-separated value the registry
// wants, or "" when the user never wrote one. Blank entries are dropped. The
// empty answer is deliberate: "not configured" is resolved to the historical
// default by the sysproxy package (BypassOrDefault), which is the only place
// that has to know what that default is.
func (s SysProxy) BypassString() string {
	parts := make([]string, 0, len(s.Bypass))
	for _, item := range s.Bypass {
		if v := strings.TrimSpace(item); v != "" {
			parts = append(parts, v)
		}
	}
	return strings.Join(parts, ";")
}

// ServiceSettings is the service-mode preference block. Every field is
// optional, so a configuration written before the block existed keeps behaving
// exactly as it did: no service installed, and the system-proxy guard on.
type ServiceSettings struct {
	// ProxyGuard keeps the invisible guard copy of the client alive while the
	// system proxy is on. It is ON unless the pointer says otherwise: the
	// guard is what puts the machine's proxy settings back after a kill, so
	// "never written" has to keep the behaviour it always had.
	ProxyGuard *bool `json:"proxy_guard,omitempty"`

	// Addr is the loopback address the installed service listens on. Nothing
	// in the client needs it to run; it is what the settings page shows and
	// what the service host binds.
	Addr string `json:"addr,omitempty"`

	// Token is the shared secret between the unprivileged client and the
	// privileged service. Without it any local process could ask the service
	// to start a program as SYSTEM. It is generated once, on first install,
	// and lives in the same file as everything else so "copy the folder"
	// still moves a working setup.
	Token string `json:"token,omitempty"`
}

// ProxyGuardEnabled reports whether the invisible system-proxy guard should
// run. A nil pointer means the user never touched the switch, which is on.
func (s ServiceSettings) ProxyGuardEnabled() bool {
	return s.ProxyGuard == nil || *s.ProxyGuard
}

// WebDAVSettings points at a directory on a WebDAV server where backup
// archives are kept. Every field is optional: an empty url means the feature
// is off and the settings page has nothing to talk to.
type WebDAVSettings struct {
	// URL is the directory the backups live in, for example
	// https://dav.example.com/dav/syan-clash/. It must not carry credentials -
	// the username and password have their own fields - and the client
	// normalises it to end with a slash so a file name can be appended
	// directly.
	URL string `json:"url,omitempty"`

	// Username and Password are sent with HTTP Basic auth. The password is
	// never echoed back by the API: the console only learns whether one is
	// stored, and an empty password on save means "keep the stored one".
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	// Enabled is the user's switch. It is deliberately not inferred from URL:
	// a user may keep a target configured but turned off.
	Enabled bool `json:"enabled,omitempty"`
}

// NodeFilter rewrites a subscription's node list on the way in. Every field is
// optional; an all-zero filter leaves the list exactly as the airport sent it.
type NodeFilter struct {
	// Include keeps a node when any pattern matches its original name. An
	// empty list means "keep everything" (the filter is a whitelist only when
	// the user actually wrote one).
	Include []string `json:"include,omitempty"`
	// Exclude drops a node when any pattern matches. Patterns are matched as
	// case-insensitive substrings, which is what people expect from a filter
	// box ("专线", "IEPL", "0.1x").
	Exclude []string `json:"exclude,omitempty"`
	// CleanInfo drops the airport's own pseudo-nodes: the plan cards
	// (remaining traffic, expiry), the official-site / telegram rows, and the
	// "安卓-clashmeta客户端" style placeholders. None of them is a server.
	//
	// It is ON unless the pointer says otherwise. A node list that still holds
	// rows no client can dial is a broken node list, so cleaning is the
	// default and keeping them is the deliberate choice: nil (never written)
	// means on, and only an explicit false preserves the rows.
	CleanInfo *bool `json:"clean_info,omitempty"`
	// Prefix and Suffix are glued onto every surviving name.
	Prefix string `json:"prefix,omitempty"`
	Suffix string `json:"suffix,omitempty"`
	// Rename rules run in order, after prefix/suffix.
	Rename []RenameRule `json:"rename,omitempty"`
}

// RenameRule rewrites node names. From/To is a plain substring replacement
// unless Regex is set, in which case From is a regular expression and To may
// use $1-style capture references (Go regexp.ReplaceAllString).
type RenameRule struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Regex bool   `json:"regex,omitempty"`
}

// CleanInfoEnabled reports whether the airport's information rows are dropped.
// Cleaning is the default; only an explicit false keeps them.
func (f NodeFilter) CleanInfoEnabled() bool {
	return f.CleanInfo == nil || *f.CleanInfo
}

// IsZero reports whether the filter would leave a node list untouched.
func (f NodeFilter) IsZero() bool {
	return !f.CleanInfoEnabled() && len(f.Include) == 0 && len(f.Exclude) == 0 &&
		f.Prefix == "" && f.Suffix == "" && len(f.Rename) == 0
}

// Diagnostics is the configuration block for the probe features. It is a
// struct of plain values with a pointer only where "unset" has to stay
// distinguishable from "explicitly off", so a configuration written by hand
// keeps meaning exactly what it says.
type Diagnostics struct {
	// EnableExternal is the master switch. nil (never written) means on.
	EnableExternal *bool `json:"enable_external,omitempty"`
	// ProbeTimeoutMS is the per-request timeout for every external probe.
	ProbeTimeoutMS int `json:"probe_timeout_ms,omitempty"`
	// MaxConcurrency caps how many probes run at once, 1-8.
	MaxConcurrency int `json:"max_concurrency,omitempty"`
	// CacheTTLSec is how long a probe answer is reused, in seconds.
	CacheTTLSec int           `json:"cache_ttl_sec,omitempty"`
	Matrix      DiagMatrix    `json:"matrix,omitempty"`
	Speedtest   DiagSpeedtest `json:"speedtest,omitempty"`
	// SpeedtestServers lists the LibreSpeed-compatible bases the user added.
	SpeedtestServers []SpeedtestServer `json:"speedtest_servers,omitempty"`
	// UnlockTargets limits the unlock sweep to these service ids.
	UnlockTargets []string `json:"unlock_targets,omitempty"`
	// TraceMaxHops caps the traceroute depth.
	TraceMaxHops int `json:"trace_max_hops,omitempty"`
}

// DiagMatrix configures the site latency matrix job.
type DiagMatrix struct {
	DefaultTimeoutMS   int `json:"default_timeout_ms,omitempty"`
	DefaultConcurrency int `json:"default_concurrency,omitempty"`
	CacheTTLSec        int `json:"cache_ttl_sec,omitempty"`
	MaxCells           int `json:"max_cells,omitempty"`
}

// DiagSpeedtest configures the speed test.
type DiagSpeedtest struct {
	// CapSec is the hard ceiling: the job always produces a result by then.
	CapSec             int `json:"cap_sec,omitempty"`
	DefaultDurationSec int `json:"default_duration_sec,omitempty"`
	Streams            int `json:"streams,omitempty"`
}

// SpeedtestServer is one speed test backend. Kind selects the protocol:
// "cloudflare" uses speed.cloudflare.com's __down/__up/meta endpoints,
// "librespeed" uses the LibreSpeed backend (empty.php / garbage.php / getIP.php).
type SpeedtestServer struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	Base string `json:"base"`
}

// DefaultSpeedtestServers is the built-in backend: no configuration needed and
// reachable from everywhere the client itself can reach.
func DefaultSpeedtestServers() []SpeedtestServer {
	return []SpeedtestServer{{Name: "Cloudflare", Kind: "cloudflare", Base: "https://speed.cloudflare.com"}}
}

// DefaultUnlockTargets are the services the unlock sweep checks unless the
// user narrows the list down.
func DefaultUnlockTargets() []string {
	return []string{"netflix", "disney", "youtube", "chatgpt", "gemini", "claude"}
}

// ExternalOn reports whether external probing is allowed.
func (d Diagnostics) ExternalOn() bool { return d.EnableExternal == nil || *d.EnableExternal }

// WithDefaults fills every unset numeric field and clamps what is out of
// range. It never changes the meaning of a value the user wrote on purpose,
// it only refuses values the probe code could not honour.
func (d Diagnostics) WithDefaults() Diagnostics {
	d.ProbeTimeoutMS = clampInt(d.ProbeTimeoutMS, 8000, 1000, 120000)
	d.MaxConcurrency = clampInt(d.MaxConcurrency, 4, 1, 8)
	d.CacheTTLSec = clampInt(d.CacheTTLSec, 600, 5, 86400)
	d.TraceMaxHops = clampInt(d.TraceMaxHops, 30, 1, 64)
	d.Matrix.DefaultTimeoutMS = clampInt(d.Matrix.DefaultTimeoutMS, 5000, 1000, 60000)
	d.Matrix.DefaultConcurrency = clampInt(d.Matrix.DefaultConcurrency, 4, 1, 8)
	d.Matrix.CacheTTLSec = clampInt(d.Matrix.CacheTTLSec, 120, 0, 3600)
	d.Matrix.MaxCells = clampInt(d.Matrix.MaxCells, 2000, 1, 20000)
	d.Speedtest.Streams = clampInt(d.Speedtest.Streams, 1, 1, 4)
	d.Speedtest.CapSec = clampInt(d.Speedtest.CapSec, 60, 10, 300)
	d.Speedtest.DefaultDurationSec = clampInt(d.Speedtest.DefaultDurationSec, 10, 3, d.Speedtest.CapSec)
	if len(d.SpeedtestServers) == 0 {
		d.SpeedtestServers = DefaultSpeedtestServers()
	}
	if len(d.UnlockTargets) == 0 {
		d.UnlockTargets = DefaultUnlockTargets()
	}
	return d
}

// clampInt returns v when it is inside [lo, hi] and the fallback when it was
// never set (zero), so a deliberate small value is never mistaken for a blank.
func clampInt(v, fallback, lo, hi int) int {
	if v == 0 {
		return fallback
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// Core selects an external proxy core to drive (sing-box, mihomo, ...).
// An empty ID means the built-in lightweight core is used instead.
type Core struct {
	ID        string `json:"id"`
	AutoStart bool   `json:"auto_start"`
	Dir       string `json:"dir"`
	Mirror    string `json:"mirror"`
	// Secret is the random bearer token the external core's control API
	// requires. It is generated once per install and written into the core's
	// generated configuration, so reaching the loopback port is not enough to
	// drive the core.
	Secret string `json:"secret,omitempty"`
	// Port is the local mixed port an external core listens on. It stays
	// distinct from inbound.http_addr / socks5_addr (the built-in engine's
	// listeners) so the two engines never fight over a port and can even run
	// side by side.
	Port    int           `json:"port,omitempty"`
	Profile *core.Profile `json:"profile,omitempty"`
}

// Provider is one proxy-provider definition: a named node list an external
// core loads and refreshes by itself. It is an alias rather than a second
// struct on purpose - the list the mihomo emitter consumes lives in the core
// profile (Config.Core.Profile.Providers), and two parallel types with the same
// field set would be two places for them to drift apart. The alias gives this
// package the name the console layer uses.
type Provider = core.Provider

// ProviderHealthCheck is a proxy provider's optional liveness probe.
type ProviderHealthCheck = core.ProviderHealthCheck

// Providers returns the proxy providers of the active core profile. It reads
// through to the profile rather than storing a second copy, so config.json
// keeps exactly one provider list and the emitters cannot see a stale one.
func (c Config) Providers() []Provider {
	if c.Core.Profile == nil {
		return nil
	}
	return c.Core.Profile.Providers
}

// Inbound configures the local listener(s) applications connect to.
type Inbound struct {
	SOCKS5Addr string `json:"socks5_addr"`
	HTTPAddr   string `json:"http_addr"`
	AllowLAN   bool   `json:"allow_lan"`
	Username   string `json:"username"`
	Password   string `json:"password"`
}

// Outbound selects where "proxy" traffic is sent.
type Outbound struct {
	Type           string  `json:"type"`
	ConnectTimeout int     `json:"connect_timeout_ms"`
	IdleTimeout    int     `json:"idle_timeout_ms"`
	Socks5         *Socks5 `json:"socks5,omitempty"`
}

// Socks5 is an upstream SOCKS5 proxy.
type Socks5 struct {
	Addr     string `json:"addr"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Log configures the in-memory log bus.
type Log struct {
	Level    string `json:"level"`
	Capacity int    `json:"capacity"`
}

// API configures the local control-plane HTTP server.
type API struct {
	Addr  string `json:"addr"`
	Token string `json:"token"`
}

// Default returns a configuration that works with no upstream configured:
// private traffic goes direct, everything else is attempted through the
// "proxy" outbound (which defaults to direct until an upstream is set).
func Default() Config {
	return Config{
		Inbound: Inbound{
			SOCKS5Addr: "127.0.0.1:2891",
			HTTPAddr:   "127.0.0.1:2890",
		},
		Outbound: Outbound{
			Type:           "direct",
			ConnectTimeout: 8000,
			IdleTimeout:    300000,
		},
		Log:  Log{Level: "info", Capacity: 2000},
		API:  API{Addr: "127.0.0.1:3090"},
		Core: Core{Dir: "cores", Port: 2899},
		// 2897 is deliberately outside the family every other client uses
		// (2890/2891/2898/2899/2900/3090) so the service never fights them.
		Service: ServiceSettings{Addr: "127.0.0.1:2897"},
		Rules: []rules.Rule{
			{Kind: rules.KindDomainSuffix, Value: "local", Action: string(rules.ActionDirect)},
			{Kind: rules.KindDomainSuffix, Value: "localhost", Action: string(rules.ActionDirect)},
			{Kind: rules.KindIPCIDR, Value: "127.0.0.0/8", Action: string(rules.ActionDirect)},
			{Kind: rules.KindIPCIDR, Value: "10.0.0.0/8", Action: string(rules.ActionDirect)},
			{Kind: rules.KindIPCIDR, Value: "172.16.0.0/12", Action: string(rules.ActionDirect)},
			{Kind: rules.KindIPCIDR, Value: "192.168.0.0/16", Action: string(rules.ActionDirect)},
			{Kind: rules.KindIPCIDR, Value: "169.254.0.0/16", Action: string(rules.ActionDirect)},
			{Kind: rules.KindIPCIDR, Value: "::1/128", Action: string(rules.ActionDirect)},
			{Kind: rules.KindIPCIDR, Value: "fc00::/7", Action: string(rules.ActionDirect)},
			{Kind: rules.KindFinal, Value: "", Action: string(rules.ActionProxy)},
		},
	}
}

// Normalize fills in defaults for fields a user may have left out.
func (c *Config) Normalize() {
	if c.migrateLegacyPorts() {
		c.portsMigrated = true
	}
	c.Diagnostics = c.Diagnostics.WithDefaults()
	d := Default()
	if strings.TrimSpace(c.Inbound.SOCKS5Addr) == "" {
		c.Inbound.SOCKS5Addr = d.Inbound.SOCKS5Addr
	}
	if strings.TrimSpace(c.Inbound.HTTPAddr) == "" {
		c.Inbound.HTTPAddr = d.Inbound.HTTPAddr
	}
	c.Outbound.Type = strings.ToLower(strings.TrimSpace(c.Outbound.Type))
	if c.Outbound.Type == "" {
		c.Outbound.Type = d.Outbound.Type
	}
	if c.Outbound.ConnectTimeout <= 0 {
		c.Outbound.ConnectTimeout = d.Outbound.ConnectTimeout
	}
	if c.Outbound.IdleTimeout <= 0 {
		c.Outbound.IdleTimeout = d.Outbound.IdleTimeout
	}
	if strings.TrimSpace(c.Log.Level) == "" {
		c.Log.Level = d.Log.Level
	}
	if c.Log.Capacity < 16 {
		c.Log.Capacity = d.Log.Capacity
	}
	if strings.TrimSpace(c.API.Addr) == "" {
		c.API.Addr = d.API.Addr
	}
	c.Core.ID = strings.ToLower(strings.TrimSpace(c.Core.ID))
	if strings.TrimSpace(c.Core.Dir) == "" {
		c.Core.Dir = d.Core.Dir
	}
	if c.Core.Port <= 0 {
		c.Core.Port = d.Core.Port
	}
	if strings.TrimSpace(c.Service.Addr) == "" {
		c.Service.Addr = d.Service.Addr
	}
	// The WebDAV target is user-typed text; trimming the address and the user
	// name here keeps every reader (validator, client, console) looking at the
	// same value. The password is left exactly as typed - leading or trailing
	// spaces can be part of it.
	c.WebDAV.URL = strings.TrimSpace(c.WebDAV.URL)
	c.WebDAV.Username = strings.TrimSpace(c.WebDAV.Username)
	c.healProfile()
	// The chain and provider fields are free-form strings a user, an imported
	// profile or a hand-edited config.json can leave padded; trimming them here
	// means every reader (emitter, console, validator) sees the same value.
	if c.Core.Profile != nil {
		c.Core.Profile.Normalize()
	}
}

// The port family every other desktop proxy client ships (7890/7891/9090).
// syan-clash has its own (2890/2891/3090) so it is not fighting for a port the
// other clients on the machine grabbed first; a stored value that still equals
// one of the old defaults was never customised, so it is moved across. A port
// the user picked themselves is left exactly as it is.
var legacyPorts = map[string]string{
	"127.0.0.1:7890": "127.0.0.1:2890",
	"127.0.0.1:7891": "127.0.0.1:2891",
	"127.0.0.1:9090": "127.0.0.1:3090",
}

const (
	legacyCorePort = 7899
	ownedCorePort  = 2899
)

// legacyClashAPI are the controller addresses an earlier syan-clash build (or an
// imported Clash YAML) could have left in the profile.
var legacyClashAPI = map[string]bool{
	"127.0.0.1:9090": true,
	"127.0.0.1:3090": true,
}

// migrateLegacyPorts rewrites the old defaults in every place a port is stored,
// including the profile's own inbound list and its controller address. It
// reports whether anything moved.
func (c *Config) migrateLegacyPorts() bool {
	moved := false
	if next, ok := legacyPorts[c.Inbound.HTTPAddr]; ok {
		c.Inbound.HTTPAddr = next
		moved = true
	}
	if next, ok := legacyPorts[c.Inbound.SOCKS5Addr]; ok {
		c.Inbound.SOCKS5Addr = next
		moved = true
	}
	if next, ok := legacyPorts[c.API.Addr]; ok {
		c.API.Addr = next
		moved = true
	}
	if c.Core.Port == legacyCorePort {
		c.Core.Port = ownedCorePort
		moved = true
	}
	p := c.Core.Profile
	if p == nil {
		return moved
	}
	// The controller address has its own port on purpose: 9090 is what the
	// other Clash-family client on this machine holds, and the console port is
	// a different socket again.
	if _, ok := legacyClashAPI[p.ClashAPI]; ok {
		p.ClashAPI = core.DefaultClashAPI
		moved = true
	}
	for i := range p.Inbounds {
		next, ok := legacyPorts[fmt.Sprintf("%s:%d", p.Inbounds[i].Listen, p.Inbounds[i].Port)]
		if !ok {
			continue
		}
		if _, portStr, err := net.SplitHostPort(next); err == nil {
			if port, err := strconv.Atoi(portStr); err == nil {
				p.Inbounds[i].Port = port
				moved = true
			}
		}
	}
	return moved
}

// healProfile repairs the two profile mistakes that would otherwise make the
// client refuse to start: a final outbound that no longer exists (because the
// groups were edited or a subscription was removed) and rules pointing at
// groups that are gone.
//
// Starting with a usable configuration is strictly better than failing to start:
// the user can then fix things from the UI, which is where they can see what is
// wrong.
func (c *Config) healProfile() {
	p := c.Core.Profile
	if p == nil {
		return
	}
	known := map[string]bool{
		core.ActionDirect: true,
		core.ActionReject: true,
		core.ActionProxy:  true,
	}
	for _, n := range p.Nodes {
		known[n.Name] = true
	}
	for _, g := range p.Groups {
		known[g.Name] = true
	}

	if p.Final != "" && !known[p.Final] {
		fallback := core.ActionDirect
		if len(p.Groups) > 0 {
			fallback = p.Groups[0].Name
		} else if len(p.Nodes) > 0 {
			fallback = p.Nodes[0].Name
		}
		p.Final = fallback
	}

	// A rule targeting a vanished group would fail validation; send it to the
	// fallback instead, which keeps the rule's intent (route this traffic) and
	// only changes where it goes.
	for i := range p.Rules {
		a := p.Rules[i].Action
		if a == "" || known[a] {
			continue
		}
		if p.Final != "" {
			p.Rules[i].Action = p.Final
		} else {
			p.Rules[i].Action = core.ActionDirect
		}
	}
}

// Validate reports the first configuration problem it finds.
func (c Config) Validate() error {
	if c.Inbound.SOCKS5Addr == "" && c.Inbound.HTTPAddr == "" {
		return fmt.Errorf("inbound: at least one of socks5_addr / http_addr must be set")
	}
	inbounds := []struct{ name, addr string }{
		{"socks5_addr", c.Inbound.SOCKS5Addr},
		{"http_addr", c.Inbound.HTTPAddr},
	}
	for _, in := range inbounds {
		if in.addr == "" {
			continue
		}
		_, port, err := net.SplitHostPort(in.addr)
		if err != nil {
			return fmt.Errorf("inbound.%s: %q is not host:port", in.name, in.addr)
		}
		if port == "" {
			return fmt.Errorf("inbound.%s: %q has no port", in.name, in.addr)
		}
	}
	if c.Core.Port < 1 || c.Core.Port > 65535 {
		return fmt.Errorf("core.port: %d is out of range", c.Core.Port)
	}
	for _, in := range inbounds {
		if in.addr == "" {
			continue
		}
		if _, port, err := net.SplitHostPort(in.addr); err == nil {
			if n, convErr := strconv.Atoi(port); convErr == nil && n == c.Core.Port {
				return fmt.Errorf("core.port: %d is already used by inbound.%s", c.Core.Port, in.name)
			}
		}
	}
	switch c.Outbound.Type {
	case "direct":
	case "socks5":
		if c.Outbound.Socks5 == nil || strings.TrimSpace(c.Outbound.Socks5.Addr) == "" {
			return fmt.Errorf("outbound: type socks5 requires outbound.socks5.addr")
		}
		if _, _, err := net.SplitHostPort(c.Outbound.Socks5.Addr); err != nil {
			return fmt.Errorf("outbound.socks5.addr: %q is not host:port", c.Outbound.Socks5.Addr)
		}
	default:
		return fmt.Errorf("outbound: unknown type %q (supported: direct, socks5)", c.Outbound.Type)
	}
	if _, err := rules.New(c.Rules); err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(c.Log.Level)) {
	case "debug", "info", "warn", "warning", "error":
	default:
		return fmt.Errorf("log.level: unknown level %q", c.Log.Level)
	}
	if _, _, err := net.SplitHostPort(c.API.Addr); err != nil {
		return fmt.Errorf("api.addr: %q is not host:port", c.API.Addr)
	}
	if _, _, err := net.SplitHostPort(c.Service.Addr); err != nil {
		return fmt.Errorf("service.addr: %q is not host:port", c.Service.Addr)
	}
	if c.Core.ID != "" {
		if _, ok := core.Lookup(c.Core.ID); !ok {
			return fmt.Errorf("core.id: unknown core %q", c.Core.ID)
		}
		if c.Core.Profile != nil {
			if err := c.Core.Profile.Validate(); err != nil {
				return err
			}
		}
	}
	return nil
}

// Load reads a config file, applying defaults for missing fields.
func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	cfg := Default()
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// LoadOrCreate reads path, writing the default config when it does not exist.
func LoadOrCreate(path string) (Config, error) {
	cfg, err := Load(path)
	if err == nil {
		// A file that still carried the shared default ports has just been
		// migrated in memory; write it back so what is on disk matches what the
		// client is actually listening on.
		if cfg.portsMigrated {
			_ = Save(path, cfg)
		}
		return cfg, nil
	}
	if !os.IsNotExist(err) {
		return Config{}, err
	}
	def := Default()
	if err := Save(path, def); err != nil {
		return Config{}, err
	}
	return def, nil
}

// Save writes the config atomically so a crash mid-write cannot truncate it.
func Save(path string, cfg Config) error {
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
