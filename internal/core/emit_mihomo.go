package core

import (
	"sort"
	"strconv"
	"strings"
)

// EmitMihomo compiles a profile into a mihomo (Clash.Meta) configuration.
// The returned value is an ordered mapping; render it with yamlEmit.
func EmitMihomo(p Profile) (omap, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	cfg := omap{
		{"mode", "rule"},
		{"log-level", levelOrDefault(p.Log)},
		{"ipv6", p.IPv6},
		{"allow-lan", p.AllowLAN},
	}
	for _, in := range p.Inbounds {
		switch in.Type {
		case InboundMixed:
			cfg = append(cfg, kv{"mixed-port", in.Port})
		case InboundSocks:
			cfg = append(cfg, kv{"socks-port", in.Port})
		case InboundHTTP:
			cfg = append(cfg, kv{"port", in.Port})
		case InboundTun:
			// strict-route stays off unless the user turns it on: on Windows it
			// makes mihomo install WFP filter sublayers, which is firewall state
			// the client then has to clean up, and auto-route already covers the
			// "no traffic escapes the tunnel" case. dns-hijack takes over every
			// resolver request on the tun device, so applications that ignore the
			// DNS settings cannot leak a lookup past the tunnel - dropping it is
			// the "let my own resolver answer" choice.
			tun := omap{
				{"enable", true},
				{"stack", NormalizeTunStack(in.Stack)},
				{"device", deviceOr(in.Device)},
				{"auto-route", p.TunAutoRouteFor(in.AutoRoute)},
				{"auto-detect-interface", true},
				{"strict-route", p.TunStrictRouteOn()},
			}
			if p.TunDNSHijackOn() {
				tun = append(tun, kv{"dns-hijack", []any{"any:53", "tcp://any:53"}})
			}
			tun = append(tun, kv{"mtu", p.TunMTUFor(in.MTU)})
			cfg = append(cfg, kv{"tun", tun})
		}
	}

	// The sniffer is only written when the user actually made a choice: an
	// unset field has to leave the document exactly as it was, and mihomo's own
	// default is "off".
	if p.Sniff != nil {
		cfg = append(cfg, kv{"sniffer", mihomoSniffer(*p.Sniff)})
	}
	// A rule set taken from a subscription very often contains GEOIP/GEOSITE
	// entries, and mihomo refuses to load such a configuration until those
	// databases exist. Point it at the same mirror the client uses so an
	// unavoidable download succeeds, and leave the periodic updater off: the
	// client controls when these files change.
	cfg = append(cfg,
		kv{"geox-url", mihomoGeoURLs(p.GeoMirror)},
		kv{"geo-auto-update", false},
	)
	if p.ClashAPI != "" {
		cfg = append(cfg, kv{"external-controller", p.ClashAPI})
		if p.ClashSecret != "" {
			cfg = append(cfg, kv{"secret", p.ClashSecret})
		}
	}
	if dns, ok := mihomoDNS(p, profileHasTun(p)); ok {
		cfg = append(cfg, kv{"dns", dns})
	}
	proxies := make([]any, 0, len(p.Nodes))
	for _, n := range p.Nodes {
		proxies = append(proxies, mihomoNode(n))
	}
	cfg = append(cfg, kv{"proxies", proxies})
	// proxy-providers is a top-level map of its own, written before the groups
	// that reach into it with "use" and skipped entirely when the profile has
	// none: an empty block would change every existing document for nothing.
	if providers := mihomoProxyProviders(p); len(providers) > 0 {
		cfg = append(cfg, kv{"proxy-providers", providers})
	}
	cfg = append(cfg, kv{"proxy-groups", mihomoGroups(p)})
	// rule-providers is a top-level map in mihomo and has to be present before
	// the rules that name it; a rule whose set is missing makes mihomo refuse
	// the whole document, so the block is only written when there is one.
	if providers := mihomoRuleProviders(p); len(providers) > 0 {
		cfg = append(cfg, kv{"rule-providers", providers})
	}
	cfg = append(cfg, kv{"rules", mihomoRules(p)})
	return cfg, nil
}

// mihomoSniffer renders the protocol sniffer block. The ports are the ones the
// reference client sniffs - plain HTTP, TLS and QUIC - and the destination is
// deliberately not overridden: rewriting it makes the core dial the name it
// sniffed instead of the address the application asked for, which is a routing
// decision the rules are already there to make.
func mihomoSniffer(enabled bool) omap {
	block := omap{{"enable", enabled}}
	if !enabled {
		return block
	}
	return append(block,
		kv{"override-destination", false},
		kv{"sniff", omap{
			{"HTTP", omap{{"ports", []any{80, 8080, 8880}}}},
			{"TLS", omap{{"ports", []any{443, 8443}}}},
			{"QUIC", omap{{"ports", []any{443, 8443}}}},
		}},
	)
}

// mihomoGeoURLs points mihomo's own geodata downloads at the client's mirror.
// Without this a core that needs geoip.metadb fetches it straight from GitHub,
// waits out a 90-second deadline on any restricted network and then refuses to
// start at all.
func mihomoGeoURLs(mirror string) omap {
	prefix := strings.TrimSpace(mirror)
	if prefix == "" && len(DefaultMirrors) > 0 {
		prefix = DefaultMirrors[0]
	}
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	withMirror := func(target string) string {
		if prefix == "" {
			return target
		}
		return prefix + target
	}
	return omap{
		{"geoip", withMirror(GeoURLGeoIP)},
		{"geosite", withMirror(GeoURLGeoSite)},
		{"mmdb", withMirror(GeoURLMMDB)},
		{"asn", withMirror(GeoURLASN)},
	}
}

func mihomoDNS(p Profile, tun bool) (omap, bool) {
	if !p.DNS.Enabled || len(p.DNS.Servers) == 0 {
		return nil, false
	}
	// A tunnel owns the machine's resolver, so the DNS block changes shape
	// with it: fake-ip is mandatory (with redir-host the tunnel has to
	// resolve every name before it can route it, which makes the first
	// lookup depend on the tunnel that is still coming up) and a "system"
	// resolver must never be used (the OS resolver sends its query to the
	// link the tunnel just took over, dns-hijack hands it straight back, and
	// the lookup waits on itself forever).
	fake := p.DNS.FakeIP || tun
	d := omap{{"enable", true}, {"ipv6", false}}
	if fake {
		d = append(d, kv{"enhanced-mode", "fake-ip"}, kv{"fake-ip-range", rangeOrDefault(p.DNS.FakeIPRange)})
		// Names that must keep resolving through the real resolver - the node
		// host names, local discovery, the probes Windows uses to decide
		// whether the machine still has internet - stay out of the fake range.
		// A node answered with a fake address is a tunnel that can never dial.
		d = append(d, kv{"fake-ip-filter", defaultFakeIPFilter()})
	} else {
		d = append(d, kv{"enhanced-mode", "redir-host"})
	}
	servers := make([]any, 0, len(p.DNS.Servers)+2)
	for _, s := range p.DNS.Servers {
		if tun && IsSystemResolver(s) {
			continue
		}
		servers = append(servers, mihomoDNSServer(s))
	}
	if len(servers) == 0 {
		servers = append(servers, "223.5.5.5", "119.29.29.29")
	}
	d = append(d, kv{"nameserver", servers})
	// Bootstrapping resolver: turning an upstream nameserver's own host name
	// into an address must not depend on that server, and plain-IP servers are
	// reachable before the tunnel exists. Without this a DoH-only setup can
	// deadlock on its first lookup.
	d = append(d, kv{"default-nameserver", []any{"223.5.5.5", "119.29.29.29", "1.1.1.1"}})
	return d, true
}

func mihomoDNSServer(addr string) any {
	s := strings.TrimSpace(addr)
	if s == "" || strings.EqualFold(s, "local") {
		return "system"
	}
	return s
}

func mihomoNode(n Node) omap {
	ob := omap{
		{"name", n.Name},
		{"type", mihomoType(n.Type)},
		{"server", n.Server},
		{"port", n.Port},
	}
	switch n.Type {
	case TypeSocks5, TypeHTTP:
		if n.Username != "" {
			ob = append(ob, kv{"username", n.Username})
		}
		if n.Password != "" {
			ob = append(ob, kv{"password", n.Password})
		}
	case TypeSS:
		ob = append(ob, kv{"cipher", n.Method}, kv{"password", n.Password})
	case TypeVMess:
		ob = append(ob, kv{"uuid", n.UUID}, kv{"alterId", n.AlterID})
		ob = append(ob, kv{"cipher", securityOr(n.Security)})
	case TypeVLESS:
		ob = append(ob, kv{"uuid", n.UUID})
		if n.Flow != "" {
			ob = append(ob, kv{"flow", n.Flow})
		}
	case TypeTrojan, TypeHysteria2:
		ob = append(ob, kv{"password", n.Password})
	}
	if t := n.TLS; t != nil && (t.Enabled || t.PublicKey != "") {
		ob = append(ob, kv{"tls", true})
		if t.ServerName != "" {
			ob = append(ob, kv{"servername", t.ServerName}, kv{"sni", t.ServerName})
		}
		if len(t.ALPN) > 0 {
			ob = append(ob, kv{"alpn", toAnySlice(t.ALPN)})
		}
		if t.Fingerprint != "" {
			ob = append(ob, kv{"client-fingerprint", t.Fingerprint})
		}
		if t.PublicKey != "" {
			ob = append(ob, kv{"reality-opts", omap{
				{"public-key", t.PublicKey},
				{"short-id", t.ShortID},
			}})
		}
	}
	if t := n.TLS; t != nil && (t.Insecure || n.SkipVerify) {
		ob = append(ob, kv{"skip-cert-verify", true})
	} else if n.SkipVerify {
		ob = append(ob, kv{"skip-cert-verify", true})
	}
	if tr := n.Transport; tr != nil {
		switch tr.Type {
		case "ws":
			ob = append(ob, kv{"network", "ws"})
			opts := omap{}
			if tr.Path != "" {
				opts = append(opts, kv{"path", tr.Path})
			}
			headers := map[string]any{}
			if tr.Host != "" {
				headers["Host"] = tr.Host
			}
			for k, v := range tr.Headers {
				headers[k] = v
			}
			if len(headers) > 0 {
				opts = append(opts, kv{"headers", headers})
			}
			if len(opts) > 0 {
				ob = append(ob, kv{"ws-opts", opts})
			}
		case "grpc":
			ob = append(ob, kv{"network", "grpc"})
			if tr.ServiceName != "" {
				ob = append(ob, kv{"grpc-opts", omap{{"grpc-service-name", tr.ServiceName}}})
			}
		case "http":
			ob = append(ob, kv{"network", "http"})
			opts := omap{}
			if tr.Host != "" {
				opts = append(opts, kv{"host", []any{tr.Host}})
			}
			if tr.Path != "" {
				opts = append(opts, kv{"path", []any{tr.Path}})
			}
			if len(opts) > 0 {
				ob = append(ob, kv{"http-opts", opts})
			}
		}
	}
	// mihomo dials this node through another outbound when dialer-proxy is set.
	// The key is left out entirely when the user never picked a chain: an empty
	// value would make the core look for an outbound named "".
	if dp := strings.TrimSpace(n.DialerProxy); dp != "" {
		ob = append(ob, kv{"dialer-proxy", dp})
	}
	ob = append(ob, kv{"udp", true})
	return ob
}

func mihomoGroups(p Profile) []any {
	out := make([]any, 0, len(p.Groups))
	for _, g := range p.Groups {
		group := omap{
			{"name", g.Name},
			{"type", g.Type},
			{"proxies", toAnySlice(g.Members)},
		}
		// use names proxy-providers, so it is only written when there is one;
		// mihomo merges those live nodes with the group's own members.
		if use := trimList(g.Use); len(use) > 0 {
			group = append(group, kv{"use", toAnySlice(use)})
		}
		if g.Type != GroupSelect {
			group = append(group, kv{"url", urlOrDefault(g.URL)}, kv{"interval", intervalOrDefault(g.Interval)})
		}
		out = append(out, group)
	}
	return out
}

func mihomoRules(p Profile) []any {
	out := make([]any, 0, len(p.Rules)+1)
	hasFinal := false
	for _, r := range p.Rules {
		action := mihomoAction(p.ResolveAction(r.Action, "REJECT"))
		switch r.Kind {
		case RuleDomain:
			out = append(out, "DOMAIN,"+r.Value+","+action)
		case RuleDomainSuffix:
			out = append(out, "DOMAIN-SUFFIX,"+r.Value+","+action)
		case RuleDomainKeyword:
			out = append(out, "DOMAIN-KEYWORD,"+r.Value+","+action)
		case RuleIPCIDR:
			rule := "IP-CIDR," + r.Value + "," + action
			if r.NoResolve {
				rule += ",no-resolve"
			}
			out = append(out, rule)
		case RulePort:
			out = append(out, "DST-PORT,"+r.Value+","+action)
		case RuleProcessName:
			out = append(out, "PROCESS-NAME,"+r.Value+","+action)
		case RuleProcessPath:
			out = append(out, "PROCESS-PATH,"+r.Value+","+action)
		case RuleGeoIP:
			out = append(out, "GEOIP,"+strings.ToUpper(strings.TrimSpace(r.Value))+","+action)
		case RuleGeoSite:
			out = append(out, "GEOSITE,"+strings.ToLower(strings.TrimSpace(r.Value))+","+action)
		case RuleProviderRef:
			// RULE-SET,<provider>,<action>: the set itself is written into the
			// top-level rule-providers block, not into the rule list.
			out = append(out, "RULE-SET,"+strings.TrimSpace(r.Value)+","+action)
		case RuleFinal:
			out = append(out, "MATCH,"+action)
			hasFinal = true
		}
	}
	if !hasFinal {
		out = append(out, "MATCH,"+mihomoAction(p.FinalTag()))
	}
	return out
}

// mihomoRuleProviders renders the profile's rule sets. mihomo fetches an http
// provider into its own data directory and keeps it fresh on its own schedule,
// so the client only has to describe it; "inline" is emitted verbatim because
// mihomo understands the payload form directly.
func mihomoRuleProviders(p Profile) omap {
	if len(p.RuleProviders) == 0 {
		return nil
	}
	out := make(omap, 0, len(p.RuleProviders))
	for _, rp := range p.RuleProviders {
		name := strings.TrimSpace(rp.Name)
		entry := omap{
			{"type", strings.TrimSpace(rp.Type)},
			{"behavior", strings.TrimSpace(rp.Behavior)},
		}
		if f := strings.TrimSpace(rp.Format); f != "" {
			entry = append(entry, kv{"format", f})
		}
		switch strings.TrimSpace(rp.Type) {
		case ProviderHTTP:
			entry = append(entry, kv{"url", strings.TrimSpace(rp.URL)})
			if path := strings.TrimSpace(rp.Path); path != "" {
				entry = append(entry, kv{"path", path})
			}
			// Without an interval mihomo re-downloads the set on every start,
			// which turns launching the client into a network dependency.
			entry = append(entry, kv{"interval", providerIntervalOrDefault(rp.Interval)})
		case ProviderFile:
			entry = append(entry, kv{"path", strings.TrimSpace(rp.Path)})
		case ProviderInline:
			entry = append(entry, kv{"payload", toAnySlice(rp.Payload)})
		}
		out = append(out, kv{name, entry})
	}
	return out
}

// mihomoProxyProviders renders the profile's proxy lists. mihomo keeps each one
// fresh on its own schedule and a group picks the live nodes out of it with
// "use", so the client only has to describe where the list comes from. The
// entries are sorted by name: the generated document then diffs cleanly between
// runs and the order the user happened to add them in never leaks into it.
func mihomoProxyProviders(p Profile) omap {
	if len(p.Providers) == 0 {
		return nil
	}
	sorted := make([]Provider, len(p.Providers))
	copy(sorted, p.Providers)
	sort.SliceStable(sorted, func(i, j int) bool {
		return strings.TrimSpace(sorted[i].Name) < strings.TrimSpace(sorted[j].Name)
	})
	out := make(omap, 0, len(sorted))
	for _, pr := range sorted {
		name := strings.TrimSpace(pr.Name)
		kind := pr.ProviderType()
		entry := omap{{"type", kind}}
		if kind == ProviderFile {
			entry = append(entry, kv{"path", strings.TrimSpace(pr.Path)})
		} else {
			entry = append(entry, kv{"url", strings.TrimSpace(pr.URL)})
			// A cache path is optional for an http provider: without one mihomo
			// holds the download in memory and re-fetches on every start.
			if path := strings.TrimSpace(pr.Path); path != "" {
				entry = append(entry, kv{"path", path})
			}
		}
		// 0 means "mihomo's own default": writing interval: 0 would make the
		// core re-download the list on every launch.
		if pr.Interval > 0 {
			entry = append(entry, kv{"interval", pr.Interval})
		}
		if hc, ok := mihomoHealthCheck(pr.HealthCheck); ok {
			entry = append(entry, kv{"health-check", hc})
		}
		out = append(out, kv{name, entry})
	}
	return out
}

// mihomoHealthCheck renders a provider's probe block, dropping the keys the
// user left unset so mihomo's own defaults stay in charge of them. A block with
// nothing in it is not written at all.
func mihomoHealthCheck(hc *ProviderHealthCheck) (omap, bool) {
	if hc == nil {
		return nil, false
	}
	out := omap{}
	if hc.Enable != nil {
		out = append(out, kv{"enable", *hc.Enable})
	}
	if url := strings.TrimSpace(hc.URL); url != "" {
		out = append(out, kv{"url", url})
	}
	if hc.Interval > 0 {
		out = append(out, kv{"interval", hc.Interval})
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// providerIntervalOrDefault is 24h: long enough that a restart never blocks on
// the network, short enough that a rule set still tracks its upstream.
func providerIntervalOrDefault(seconds int) int {
	if seconds > 0 {
		return seconds
	}
	return 86400
}

func mihomoAction(action string) string {
	switch action {
	case ActionDirect:
		return "DIRECT"
	case ActionReject, "block":
		return "REJECT"
	default:
		return action
	}
}

func mihomoType(t string) string {
	if t == TypeSocks5 {
		return "socks5"
	}
	return t
}

func deviceOr(name string) string {
	if strings.TrimSpace(name) == "" {
		return "syan-clash0"
	}
	return name
}

// defaultFakeIPFilter lists the names and suffixes that must never be given a
// fake address. The node host names are supplied by the user and therefore
// unknown here, which is why the filter also covers the interfaces and probes
// that have to keep working in every configuration.
func defaultFakeIPFilter() []any {
	return []any{
		"*.lan",
		"*.local",
		"localhost.ptlogin2.qq.com",
		"*.msftconnecttest.com",
		"*.msftncsi.com",
		"*.stun.*",
		"stun.*",
		"time.*.com",
		"ntp.*.com",
		"+.market.xiaomi.com",
		"+.xboxlive.com",
		"xbox.*.microsoft.com",
		"+.srv.nintendo.net",
		"+.stun.playstation.net",
	}
}

func securityOr(s string) string {
	if strings.TrimSpace(s) == "" {
		return "auto"
	}
	return s
}

// levelOrDefault is the mihomo spelling of the shared log-level normaliser.
func levelOrDefault(level string) string { return NormalizeLogLevel(level) }

func rangeOrDefault(r string) string {
	if strings.TrimSpace(r) == "" {
		return "198.18.0.0/15"
	}
	return r
}

func urlOrDefault(u string) string {
	if strings.TrimSpace(u) == "" {
		return "http://www.gstatic.com/generate_204"
	}
	return u
}

func intervalOrDefault(seconds int) int {
	if seconds <= 0 {
		return 300
	}
	return seconds
}

func toAnySlice(in []string) []any {
	out := make([]any, 0, len(in))
	for _, s := range in {
		out = append(out, s)
	}
	return out
}

func parseUint16(s string) (uint16, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil {
		return 0, err
	}
	return uint16(n), nil
}
