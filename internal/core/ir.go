// Package core adapts external proxy cores to one client.
//
// The idea is the "collect the best of each" architecture: the user's intent is
// described once in a neutral model (Profile), and a per-core compiler turns
// that into the core's own native configuration (sing-box JSON, mihomo YAML,
// ...). Swapping or adding a core therefore means adding one emitter, not
// touching the UI.
package core

import (
	"fmt"
	"net"
	"strings"
)

// Node types understood by the neutral model.
const (
	TypeSocks5    = "socks5"
	TypeHTTP      = "http"
	TypeSS        = "ss"
	TypeVMess     = "vmess"
	TypeVLESS     = "vless"
	TypeTrojan    = "trojan"
	TypeHysteria2 = "hysteria2"
)

// Inbound types understood by the neutral model.
const (
	InboundMixed = "mixed"
	InboundSocks = "socks"
	InboundHTTP  = "http"
	InboundTun   = "tun"
)

// Group types.
const (
	GroupSelect   = "select"
	GroupURLTest  = "url-test"
	GroupFallback = "fallback"
)

// TUN stack names the neutral model is willing to emit. "mixed" is deliberately
// absent: it was measured dead on the lab Windows machine (packets entered the
// tunnel and the DIRECT egress never came back), so it is never written into a
// core's configuration even when an imported profile asks for it.
const (
	TunStackGvisor = "gvisor"
	TunStackSystem = "system"
)

// NormalizeTunStack maps any stack name to one this client is willing to run.
// Only "system" is passed through; everything else - including an empty string,
// "mixed" and any unknown name from an imported profile - becomes "gvisor",
// which is the stack verified end-to-end on Windows.
func NormalizeTunStack(s string) string {
	if strings.EqualFold(strings.TrimSpace(s), TunStackSystem) {
		return TunStackSystem
	}
	return TunStackGvisor
}

// Tunnel defaults. They live next to the stack normaliser so the configuration
// layer, the emitters and the console all read the same numbers.
const (
	TunMTUDefault = 9000
	TunMTUMin     = 576
	TunMTUMax     = 65535
)

// NormalizeTunMTU clamps a user-supplied tunnel MTU. Zero means "not
// configured" and stays zero, so the caller can fall back to the inbound's own
// value; anything else is pulled into the range an IP stack can carry.
func NormalizeTunMTU(mtu int) int {
	if mtu == 0 {
		return 0
	}
	if mtu < TunMTUMin {
		return TunMTUMin
	}
	if mtu > TunMTUMax {
		return TunMTUMax
	}
	return mtu
}

// LogLevels are the levels a user can pick for an external core, in the order
// the console shows them. "silent" is mihomo's spelling; Xray maps it to "none".
var LogLevels = []string{"debug", "info", "warn", "error", "silent"}

// NormalizeLogLevel maps anything a user or an imported profile wrote to a
// level the cores accept. It is the single place that decides what "unset" and
// what "unknown" mean - both become "info" - so the emitters, the console and
// the stored value can never disagree.
func NormalizeLogLevel(level string) string {
	trimmed := strings.ToLower(strings.TrimSpace(level))
	switch trimmed {
	case "debug", "info", "warn", "error", "silent":
		return trimmed
	case "warning":
		return "warn"
	default:
		return "info"
	}
}

// SniffEnabled reports the effective sniffer state: on unless the user turned
// it off. Unset is the historical behaviour and has to stay on.
func (p Profile) SniffEnabled() bool { return p.Sniff == nil || *p.Sniff }

// TunMTUFor resolves the MTU written for a tunnel: the user's override when
// there is one, otherwise the inbound's own value, otherwise the default.
func (p Profile) TunMTUFor(inbound int) int {
	if v := NormalizeTunMTU(p.TunMTU); v != 0 {
		return v
	}
	if inbound != 0 {
		return inbound
	}
	return TunMTUDefault
}

// TunAutoRouteFor resolves auto-route the same way: the profile wins, then the
// inbound, so an unset profile keeps whatever the TUN switch wrote.
func (p Profile) TunAutoRouteFor(inbound bool) bool {
	if p.TunAutoRoute != nil {
		return *p.TunAutoRoute
	}
	return inbound
}

// TunStrictRouteFor resolves strict-route: the profile's choice when the user
// made one, otherwise the inbound's own value. mihomo is always called with
// false as the inbound value, because this client has never shipped anything
// else for it - on Windows strict-route installs WFP filter sublayers.
func (p Profile) TunStrictRouteFor(inbound bool) bool {
	if p.TunStrictRoute != nil {
		return *p.TunStrictRoute
	}
	return inbound
}

// TunStrictRouteOn reports mihomo's strict-route. Unset is off, which is the
// only value this client has ever shipped for that core.
func (p Profile) TunStrictRouteOn() bool { return p.TunStrictRouteFor(false) }

// TunDNSHijackOn reports whether the tunnel takes the resolver over. Unset is
// on, which is what the client has always written.
func (p Profile) TunDNSHijackOn() bool {
	return p.TunDNSHijack == nil || *p.TunDNSHijack
}

// Profile is the core-agnostic description of what the user wants running.
// DefaultClashAPI is the control address syan-clash gives an external core. It is
// deliberately not 9090: that is the address every other Clash-family client
// claims, and it is also where a subscription's YAML points the controller. The
// client also keeps it away from its own console port so the two never fight.
const DefaultClashAPI = "127.0.0.1:2898"

type Profile struct {
	Log      string    `json:"log"`
	Inbounds []Inbound `json:"inbounds"`
	DNS      DNS       `json:"dns"`
	Nodes    []Node    `json:"nodes"`
	Groups   []Group   `json:"groups"`
	Rules    []Rule    `json:"rules"`
	// RuleProviders are named external rule lists. A rule with
	// Kind == RuleProviderRef references one by name; the list itself lives in
	// the core's configuration rather than in the rule list.
	RuleProviders []RuleProvider `json:"rule_providers,omitempty"`
	// Providers are named proxy lists the core loads and refreshes by itself
	// (mihomo's "proxy-providers"). A group reaches one through Group.Use; a
	// provider nothing uses is still declared, because the console and the
	// generated configuration have to agree on what exists.
	Providers   []Provider `json:"providers,omitempty"`
	Final       string     `json:"final"`
	ClashAPI    string     `json:"clash_api"`
	ClashSecret string     `json:"clash_secret"`
	// GeoMirror prefixes the geodata download URLs written into a core's
	// configuration. A core that has to fetch geoip/geosite itself should use
	// the same mirror the client uses, because the canonical URLs are
	// frequently unreachable. Empty means "use the built-in mirror list".
	GeoMirror string `json:"geo_mirror,omitempty"`
	// AllowLAN lets the external core accept connections from the local
	// network instead of loopback only (mihomo's allow-lan). Off by default:
	// turning it on is an explicit choice because it exposes the port.
	AllowLAN bool `json:"allow_lan,omitempty"`
	// IPv6 enables IPv6 handling inside the external core. Off by default,
	// matching the conservative defaults of the reference clients.
	IPv6 bool `json:"ipv6,omitempty"`
	// TunStack is the TUN data plane used when TUN mode is on. It lives on the
	// profile rather than only on the inbound so the choice survives the inbound
	// being removed and re-added by the TUN switch, and so it can be picked
	// before TUN is ever turned on. Empty means "gvisor".
	TunStack string `json:"tun_stack,omitempty"`
	// Sniff turns the core's protocol sniffer on or off. It is a pointer because
	// "never configured" has to stay distinguishable from "explicitly off": a
	// configuration written before this field existed must keep producing exactly
	// the document it produced before, and the two cores disagree on what that
	// document is (Xray sniffs by default, mihomo does not).
	Sniff *bool `json:"sniff,omitempty"`
	// TunMTU overrides the MTU written for a TUN inbound. 0 means "use the
	// inbound's own value, or the built-in default".
	TunMTU int `json:"tun_mtu,omitempty"`
	// TunAutoRoute overrides the tunnel's auto-route. nil means "use the
	// inbound's value", which is what the TUN switch writes.
	TunAutoRoute *bool `json:"tun_auto_route,omitempty"`
	// TunStrictRoute is mihomo's strict-route. nil keeps it off, which is the
	// only value this client has ever shipped: on Windows strict-route makes the
	// core install WFP filter sublayers, which is firewall state the client would
	// then have to clean up. Turning it on is an explicit choice, and the console
	// says so next to the switch.
	TunStrictRoute *bool `json:"tun_strict_route,omitempty"`
	// TunDNSHijack keeps the tunnel's resolver hijack. nil means on, which is
	// what the client has always written; false drops the block so only the
	// resolver configured in DNS answers.
	TunDNSHijack *bool `json:"tun_dns_hijack,omitempty"`
}

// Inbound is a local listener the core opens.
type Inbound struct {
	Type        string `json:"type"`
	Tag         string `json:"tag"`
	Listen      string `json:"listen"`
	Port        int    `json:"port"`
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
	Stack       string `json:"stack,omitempty"`
	AutoRoute   bool   `json:"auto_route,omitempty"`
	StrictRoute bool   `json:"strict_route,omitempty"`
	MTU         int    `json:"mtu,omitempty"`
	Device      string `json:"device,omitempty"`
}

// DNS is the resolver configuration shared by both cores.
type DNS struct {
	Enabled     bool     `json:"enabled"`
	Servers     []string `json:"servers"`
	Final       string   `json:"final,omitempty"`
	FakeIP      bool     `json:"fakeip"`
	FakeIPRange string   `json:"fakeip_range,omitempty"`
	Strategy    string   `json:"strategy,omitempty"`
}

// TLS holds the TLS/REALITY parameters of a node.
type TLS struct {
	Enabled     bool     `json:"enabled"`
	ServerName  string   `json:"server_name,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	Insecure    bool     `json:"insecure,omitempty"`
	PublicKey   string   `json:"public_key,omitempty"`
	ShortID     string   `json:"short_id,omitempty"`
}

// Transport is the stream transport of a node.
type Transport struct {
	Type        string            `json:"type"`
	Path        string            `json:"path,omitempty"`
	Host        string            `json:"host,omitempty"`
	ServiceName string            `json:"service_name,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
}

// Node is one upstream server.
type Node struct {
	Name       string     `json:"name"`
	Type       string     `json:"type"`
	Server     string     `json:"server"`
	Port       int        `json:"port"`
	Username   string     `json:"username,omitempty"`
	Password   string     `json:"password,omitempty"`
	Method     string     `json:"method,omitempty"`
	UUID       string     `json:"uuid,omitempty"`
	AlterID    int        `json:"alter_id,omitempty"`
	Security   string     `json:"security,omitempty"`
	Flow       string     `json:"flow,omitempty"`
	TLS        *TLS       `json:"tls,omitempty"`
	Transport  *Transport `json:"transport,omitempty"`
	UDP        bool       `json:"udp,omitempty"`
	SkipVerify bool       `json:"skip_verify,omitempty"`
	// DialerProxy is the outbound this node is dialed through: mihomo connects
	// to that node or proxy group first and reaches this server from there.
	// Empty means "dial it directly", and the emitter then writes no key at all
	// - an empty value would make the core look for an outbound named "".
	DialerProxy string `json:"dialer-proxy,omitempty"`
}

// Group is a proxy group.
type Group struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Members []string `json:"members"`
	// Use names the proxy providers whose live nodes join this group. mihomo
	// merges them with Members, so a group can carry hand-picked nodes and a
	// provider-fed airport list at the same time. Empty means "no provider".
	Use      []string `json:"use,omitempty"`
	URL      string   `json:"url,omitempty"`
	Interval int      `json:"interval,omitempty"`
}

// Provider vehicle types, matching the "type" mihomo uses for both its
// rule-providers and its proxy-providers. The two features share the spelling,
// so they share the constants; ProviderInline only ever applies to a rule
// provider, because a proxy list has to come from somewhere mihomo can fetch.
const (
	ProviderHTTP   = "http"
	ProviderFile   = "file"
	ProviderInline = "inline"
)

// Rule provider behaviours, matching mihomo's rule-providers "behavior".
const (
	ProviderBehaviorDomain    = "domain"
	ProviderBehaviorIPCIDR    = "ipcidr"
	ProviderBehaviorClassical = "classical"
)

// Rule provider payload formats, matching mihomo's rule-providers "format".
const (
	ProviderFormatYAML = "yaml"
	ProviderFormatText = "text"
	ProviderFormatMrs  = "mrs"
)

// RuleProvider is one named rule list a core loads by itself: mihomo writes it
// as a top-level "rule-providers" entry and rules reach it through RULE-SET.
// Keeping the list here instead of inlining every entry into Rules is what lets
// a subscription's tens of thousands of domains stay one editable rule.
//
// Type decides where the list comes from: http downloads URL, file reads Path
// (relative paths resolve against the core's own data directory), inline
// carries the payload in the generated configuration and needs no network at
// all. Behavior tells the core how to read the payload, Format says whether it
// is yaml, text or a compiled mrs blob.
type RuleProvider struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Behavior string   `json:"behavior"`
	Format   string   `json:"format,omitempty"`
	URL      string   `json:"url,omitempty"`
	Path     string   `json:"path,omitempty"`
	Interval int      `json:"interval,omitempty"`
	Payload  []string `json:"payload,omitempty"`
}

// Validate checks one rule provider definition.
func (rp RuleProvider) Validate() error { return rp.validate() }

func (rp RuleProvider) validate() error {
	name := strings.TrimSpace(rp.Name)
	if name == "" {
		return fmt.Errorf("rule provider has no name")
	}
	switch strings.TrimSpace(rp.Type) {
	case ProviderHTTP:
		if strings.TrimSpace(rp.URL) == "" {
			return fmt.Errorf("rule provider %q: type %s needs a url", name, ProviderHTTP)
		}
	case ProviderFile:
		if strings.TrimSpace(rp.Path) == "" {
			return fmt.Errorf("rule provider %q: type %s needs a path", name, ProviderFile)
		}
	case ProviderInline:
		if len(rp.Payload) == 0 {
			return fmt.Errorf("rule provider %q: type %s needs a payload", name, ProviderInline)
		}
	default:
		return fmt.Errorf("rule provider %q has unknown type %q (supported: %s, %s, %s)",
			name, rp.Type, ProviderHTTP, ProviderFile, ProviderInline)
	}
	switch strings.TrimSpace(rp.Behavior) {
	case ProviderBehaviorDomain, ProviderBehaviorIPCIDR, ProviderBehaviorClassical:
	default:
		return fmt.Errorf("rule provider %q has unknown behavior %q (supported: %s, %s, %s)",
			name, rp.Behavior, ProviderBehaviorDomain, ProviderBehaviorIPCIDR, ProviderBehaviorClassical)
	}
	switch strings.TrimSpace(rp.Format) {
	case "", ProviderFormatYAML, ProviderFormatText, ProviderFormatMrs:
	default:
		return fmt.Errorf("rule provider %q has unknown format %q (supported: %s, %s, %s)",
			name, rp.Format, ProviderFormatYAML, ProviderFormatText, ProviderFormatMrs)
	}
	if rp.Interval < 0 {
		return fmt.Errorf("rule provider %q has a negative interval %d", name, rp.Interval)
	}
	return nil
}

// ProviderHealthCheck is the optional liveness probe of a proxy provider:
// mihomo fetches URL every Interval seconds and drops the nodes that fail it.
// Enable is a pointer because "never written" has to stay distinguishable from
// an explicit "off" - unset keeps mihomo's own default, which is on.
type ProviderHealthCheck struct {
	Enable   *bool  `json:"enable,omitempty"`
	URL      string `json:"url,omitempty"`
	Interval int    `json:"interval,omitempty"`
}

// Provider is one named proxy list a core loads and refreshes by itself: mihomo
// writes it as a top-level "proxy-providers" entry and a group reaches it
// through "use". It is the subscription-shaped counterpart of RuleProvider -
// instead of flattening an airport's whole node list into Nodes, the core keeps
// it fresh on its own schedule and the group picks from whatever is alive.
//
// Type decides where the list comes from: http downloads URL (caching it at
// Path when one is given), file reads Path from the core's own data directory.
// An unset type means http, which is what an entry written without one is
// almost always meant to be. Interval is the refresh period in seconds; 0
// leaves mihomo's own default in place rather than pinning a number here.
type Provider struct {
	Name        string               `json:"name"`
	Type        string               `json:"type,omitempty"`
	URL         string               `json:"url,omitempty"`
	Path        string               `json:"path,omitempty"`
	Interval    int                  `json:"interval,omitempty"`
	HealthCheck *ProviderHealthCheck `json:"health_check,omitempty"`
}

// ProviderType resolves the provider's vehicle: an unset type means http.
func (pr Provider) ProviderType() string {
	if t := strings.ToLower(strings.TrimSpace(pr.Type)); t != "" {
		return t
	}
	return ProviderHTTP
}

// Validate checks one proxy provider definition.
func (pr Provider) Validate() error { return pr.validate() }

func (pr Provider) validate() error {
	name := strings.TrimSpace(pr.Name)
	if name == "" {
		return fmt.Errorf("proxy provider has no name")
	}
	switch pr.ProviderType() {
	case ProviderHTTP:
		if strings.TrimSpace(pr.URL) == "" {
			return fmt.Errorf("proxy provider %q: type %s needs a url", name, ProviderHTTP)
		}
	case ProviderFile:
		if strings.TrimSpace(pr.Path) == "" {
			return fmt.Errorf("proxy provider %q: type %s needs a path", name, ProviderFile)
		}
	default:
		return fmt.Errorf("proxy provider %q has unknown type %q (supported: %s, %s)",
			name, pr.Type, ProviderHTTP, ProviderFile)
	}
	if pr.Interval < 0 {
		return fmt.Errorf("proxy provider %q has a negative interval %d", name, pr.Interval)
	}
	if hc := pr.HealthCheck; hc != nil && hc.Interval < 0 {
		return fmt.Errorf("proxy provider %q has a negative health-check interval %d", name, hc.Interval)
	}
	return nil
}

// Rule kinds, matching the semantics of internal/rules so the two layers agree.
const (
	RuleDomain        = "domain"
	RuleDomainSuffix  = "domain-suffix"
	RuleDomainKeyword = "domain-keyword"
	RuleIPCIDR        = "ip-cidr"
	RulePort          = "port"
	RuleGeoIP         = "geoip"
	RuleGeoSite       = "geosite"
	RuleProcessName   = "process-name"
	RuleProcessPath   = "process-path"
	RuleFinal         = "final"
	// RuleProviderRef points at a named entry of Profile.RuleProviders
	// (mihomo's "RULE-SET,<name>,<action>"). The set carries the payload, so a
	// single rule can stand for a whole subscription-sized list instead of
	// thousands of individual rules.
	RuleProviderRef = "rule-provider"
)

// Actions that are not a group name. ActionProxy means "whatever the profile's
// fallback is", which keeps presets and imported rules usable no matter how the
// user named their groups.
const (
	ActionDirect = "direct"
	ActionReject = "reject"
	ActionProxy  = "proxy"
)

// Rule is one routing rule. Action is either direct, reject, or a group name.
type Rule struct {
	Kind      string `json:"kind"`
	Value     string `json:"value"`
	Action    string `json:"action"`
	NoResolve bool   `json:"no_resolve,omitempty"`
}

// Validate checks one rule definition.
func (r Rule) Validate() error { return r.validate() }

// DefaultProfile returns a working profile: mixed inbound on loopback, DNS on,
// direct/block outbounds and a final rule pointing at the first group.
func DefaultProfile() Profile {
	return Profile{
		Log: "info",
		Inbounds: []Inbound{{
			Type:   InboundMixed,
			Tag:    "mixed-in",
			Listen: "127.0.0.1",
			Port:   2890,
		}},
		DNS: DNS{
			Enabled:     true,
			Servers:     []string{"local", "https://223.5.5.5/dns-query"},
			Strategy:    "prefer_ipv4",
			FakeIPRange: "198.18.0.0/15",
		},
		ClashAPI: DefaultClashAPI,
	}
}

// Normalize trims the free-form strings the console, an imported profile or a
// hand-edited configuration can leave padded. It deliberately touches only the
// chain and provider fields this client added: rewriting a node or group name
// that was already there would silently break every rule and group that names
// it, and a working configuration must survive a reload unchanged.
func (p *Profile) Normalize() {
	for i := range p.Nodes {
		p.Nodes[i].DialerProxy = strings.TrimSpace(p.Nodes[i].DialerProxy)
	}
	for i := range p.Groups {
		p.Groups[i].Use = trimList(p.Groups[i].Use)
	}
	for i := range p.Providers {
		pr := &p.Providers[i]
		pr.Name = strings.TrimSpace(pr.Name)
		pr.Type = strings.ToLower(strings.TrimSpace(pr.Type))
		pr.URL = strings.TrimSpace(pr.URL)
		pr.Path = strings.TrimSpace(pr.Path)
		if hc := pr.HealthCheck; hc != nil {
			hc.URL = strings.TrimSpace(hc.URL)
		}
	}
}

// trimList trims every entry and drops the ones that became empty, so a
// hand-written "use: [airport, ' ']" cannot turn into a reference to "".
func trimList(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if t := strings.TrimSpace(s); t != "" {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// FinalTag resolves the outbound used when no rule matches.
func (p Profile) FinalTag() string {
	if p.Final != "" {
		return p.Final
	}
	if len(p.Groups) > 0 {
		return p.Groups[0].Name
	}
	if len(p.Nodes) > 0 {
		return p.Nodes[0].Name
	}
	return ActionDirect
}

// ResolveAction maps a neutral action onto an outbound tag of the given core.
// blockTag is the tag that core uses for "reject".
func (p Profile) ResolveAction(action, blockTag string) string {
	switch strings.TrimSpace(action) {
	case "":
		return p.FinalTag()
	case ActionDirect:
		return "direct"
	case ActionReject:
		return blockTag
	case ActionProxy:
		return p.FinalTag()
	default:
		return action
	}
}

// Validate reports the first problem that would make the profile uncompilable.
func (p Profile) Validate() error {
	if len(p.Inbounds) == 0 {
		return fmt.Errorf("profile: at least one inbound is required")
	}
	for i, in := range p.Inbounds {
		switch in.Type {
		case InboundMixed, InboundSocks, InboundHTTP:
			if in.Listen == "" {
				return fmt.Errorf("profile: inbound #%d has no listen address", i+1)
			}
			if in.Port <= 0 || in.Port > 65535 {
				return fmt.Errorf("profile: inbound #%d has an invalid port %d", i+1, in.Port)
			}
		case InboundTun:
		default:
			return fmt.Errorf("profile: inbound #%d has unknown type %q", i+1, in.Type)
		}
	}
	names := make(map[string]bool, len(p.Nodes)+len(p.Groups))
	for i, n := range p.Nodes {
		if err := n.validate(); err != nil {
			return fmt.Errorf("profile: node #%d: %w", i+1, err)
		}
		if names[n.Name] {
			return fmt.Errorf("profile: duplicate outbound name %q", n.Name)
		}
		names[n.Name] = true
	}
	for i, g := range p.Groups {
		if strings.TrimSpace(g.Name) == "" {
			return fmt.Errorf("profile: group #%d has no name", i+1)
		}
		if names[g.Name] {
			return fmt.Errorf("profile: duplicate outbound name %q", g.Name)
		}
		names[g.Name] = true
		switch g.Type {
		case GroupSelect, GroupURLTest, GroupFallback:
		default:
			return fmt.Errorf("profile: group %q has unknown type %q", g.Name, g.Type)
		}
		if len(g.Members) == 0 {
			return fmt.Errorf("profile: group %q has no members", g.Name)
		}
	}
	for i, g := range p.Groups {
		for _, m := range g.Members {
			if !names[m] {
				return fmt.Errorf("profile: group #%d (%s) references unknown member %q", i+1, g.Name, m)
			}
		}
	}
	// A proxy provider lives in its own namespace, but a name that also names
	// an outbound would make "use" and "dialer-proxy" ambiguous for whoever
	// reads the generated document. Duplicates are compared case-insensitively
	// because "Airport" and "airport" are the same list to a human even though
	// mihomo would treat them as two.
	providerNames := make(map[string]string, len(p.Providers))
	for i, pr := range p.Providers {
		if err := pr.validate(); err != nil {
			return fmt.Errorf("profile: provider #%d: %w", i+1, err)
		}
		name := strings.TrimSpace(pr.Name)
		key := strings.ToLower(name)
		if prev, dup := providerNames[key]; dup {
			return fmt.Errorf("profile: duplicate proxy provider name %q (also written as %q)", name, prev)
		}
		if names[name] {
			return fmt.Errorf("profile: proxy provider %q collides with an outbound of the same name", name)
		}
		providerNames[key] = name
	}
	for i, g := range p.Groups {
		for _, u := range g.Use {
			name := strings.TrimSpace(u)
			if name == "" {
				continue
			}
			if _, ok := providerNames[strings.ToLower(name)]; !ok {
				return fmt.Errorf("profile: group #%d (%s) uses unknown proxy provider %q", i+1, g.Name, name)
			}
		}
	}
	// dialer-proxy may name any outbound: another node or a proxy group. A
	// chain that leads back to its own start would make the core dial itself,
	// so it is refused here rather than left for the core to loop on.
	for i, n := range p.Nodes {
		dp := strings.TrimSpace(n.DialerProxy)
		if dp == "" {
			continue
		}
		if !names[dp] {
			return fmt.Errorf("profile: node #%d (%s) dials through unknown outbound %q", i+1, n.Name, dp)
		}
	}
	if cycle := dialerProxyCycle(p); len(cycle) > 0 {
		return fmt.Errorf("profile: dialer-proxy cycle: %s", strings.Join(cycle, " -> "))
	}
	providers := make(map[string]bool, len(p.RuleProviders))
	for i, rp := range p.RuleProviders {
		if err := rp.validate(); err != nil {
			return fmt.Errorf("profile: rule provider #%d: %w", i+1, err)
		}
		key := strings.ToLower(strings.TrimSpace(rp.Name))
		if providers[key] {
			return fmt.Errorf("profile: duplicate rule provider name %q", rp.Name)
		}
		providers[key] = true
	}
	for i, r := range p.Rules {
		if err := r.validate(); err != nil {
			return fmt.Errorf("profile: rule #%d: %w", i+1, err)
		}
		// A reference to a provider that is not defined would make every
		// generated configuration invalid, so it is caught here rather than
		// left for the core to reject at start-up.
		if r.Kind == RuleProviderRef && !providers[strings.ToLower(strings.TrimSpace(r.Value))] {
			return fmt.Errorf("profile: rule #%d references unknown rule provider %q", i+1, r.Value)
		}
		if r.Action != "" && r.Action != ActionDirect && r.Action != ActionReject &&
			r.Action != ActionProxy && !names[r.Action] {
			return fmt.Errorf("profile: rule #%d targets unknown outbound %q", i+1, r.Action)
		}
	}
	if p.Final != "" && p.Final != ActionDirect && p.Final != ActionReject &&
		p.Final != ActionProxy && !names[p.Final] {
		return fmt.Errorf("profile: final outbound %q is not defined", p.Final)
	}
	return nil
}

// dialerProxyCycle reports a chain of nodes that would end up dialing through
// each other. A node's dialer-proxy may name another node or a proxy group, and
// a group stands for whatever its members are, so a group is expanded into the
// nodes it can select: that is what makes "n1 dials through G while G contains
// n1" a cycle as well as the plain "n1 -> n2 -> n1". The returned slice spells
// the cycle out - the first name is repeated at the end - so the error message
// can point at every node on it.
func dialerProxyCycle(p Profile) []string {
	nodes := make(map[string]bool, len(p.Nodes))
	for _, n := range p.Nodes {
		nodes[n.Name] = true
	}
	// expand resolves one dialer-proxy target into the nodes it can end up
	// being. seen guards the walk against a group that contains itself, which
	// the member check alone cannot rule out.
	var expand func(name string, seen map[string]bool, out *[]string)
	expand = func(name string, seen map[string]bool, out *[]string) {
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		if nodes[name] {
			*out = append(*out, name)
			return
		}
		for _, g := range p.Groups {
			if g.Name != name {
				continue
			}
			for _, m := range g.Members {
				expand(strings.TrimSpace(m), seen, out)
			}
		}
	}
	edges := make(map[string][]string, len(p.Nodes))
	for _, n := range p.Nodes {
		dp := strings.TrimSpace(n.DialerProxy)
		if dp == "" {
			continue
		}
		var targets []string
		expand(dp, map[string]bool{}, &targets)
		if len(targets) > 0 {
			edges[n.Name] = targets
		}
	}
	const (
		white = iota
		gray
		black
	)
	state := make(map[string]int, len(p.Nodes))
	var path []string
	var found []string
	var visit func(name string) bool
	visit = func(name string) bool {
		state[name] = gray
		path = append(path, name)
		for _, next := range edges[name] {
			switch state[next] {
			case gray:
				start := 0
				for i, seen := range path {
					if seen == next {
						start = i
						break
					}
				}
				found = append(append([]string(nil), path[start:]...), next)
				return true
			case white:
				if visit(next) {
					return true
				}
			}
		}
		path = path[:len(path)-1]
		state[name] = black
		return false
	}
	for _, n := range p.Nodes {
		if state[n.Name] == white && visit(n.Name) {
			return found
		}
	}
	return nil
}

// Validate checks one node definition.
func (n Node) Validate() error { return n.validate() }

func (n Node) validate() error {
	if strings.TrimSpace(n.Name) == "" {
		return fmt.Errorf("node has no name")
	}
	if strings.TrimSpace(n.Server) == "" {
		return fmt.Errorf("node %q has no server", n.Name)
	}
	if n.Port <= 0 || n.Port > 65535 {
		return fmt.Errorf("node %q has an invalid port %d", n.Name, n.Port)
	}
	switch n.Type {
	case TypeSocks5, TypeHTTP:
	case TypeSS:
		if n.Method == "" || n.Password == "" {
			return fmt.Errorf("node %q: shadowsocks needs method and password", n.Name)
		}
	case TypeVMess, TypeVLESS:
		if n.UUID == "" {
			return fmt.Errorf("node %q: %s needs a uuid", n.Name, n.Type)
		}
	case TypeTrojan, TypeHysteria2:
		if n.Password == "" {
			return fmt.Errorf("node %q: %s needs a password", n.Name, n.Type)
		}
	default:
		return fmt.Errorf("node %q has unknown type %q", n.Name, n.Type)
	}
	if t := n.Transport; t != nil {
		switch t.Type {
		case "", "tcp", "ws", "grpc", "http":
		default:
			return fmt.Errorf("node %q has unknown transport %q", n.Name, t.Type)
		}
	}
	return nil
}

func (r Rule) validate() error {
	switch r.Kind {
	case RuleDomain, RuleDomainSuffix, RuleDomainKeyword:
		if strings.TrimSpace(r.Value) == "" {
			return fmt.Errorf("%s rule needs a value", r.Kind)
		}
	case RuleIPCIDR:
		if _, _, err := net.ParseCIDR(strings.TrimSpace(r.Value)); err != nil {
			return fmt.Errorf("ip-cidr rule %q is not a CIDR block", r.Value)
		}
	case RulePort:
		if strings.TrimSpace(r.Value) == "" {
			return fmt.Errorf("port rule needs a value")
		}
	case RuleGeoIP, RuleGeoSite:
		if strings.TrimSpace(r.Value) == "" {
			return fmt.Errorf("%s rule needs a country/category code", r.Kind)
		}
	case RuleProcessName, RuleProcessPath:
		if strings.TrimSpace(r.Value) == "" {
			return fmt.Errorf("%s rule needs a process name", r.Kind)
		}
	case RuleProviderRef:
		if strings.TrimSpace(r.Value) == "" {
			return fmt.Errorf("%s rule needs a rule-provider name", r.Kind)
		}
	case RuleFinal:
	default:
		return fmt.Errorf("unknown rule kind %q", r.Kind)
	}
	return nil
}
