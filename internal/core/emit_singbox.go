package core

import (
	"fmt"
	"strings"
)

// EmitSingBox compiles a profile into a sing-box configuration document.
func EmitSingBox(p Profile) (map[string]any, error) {
	doc, _, err := EmitSingBoxWithWarnings(p)
	return doc, err
}

// EmitSingBoxWithWarnings also reports what could not be represented. sing-box
// has no rule-providers of mihomo's shape, so a profile's rule sets become
// route.rule_set entries; a set that has no sing-box equivalent is reported
// instead of leaving a rule pointing at a tag the core cannot resolve.
func EmitSingBoxWithWarnings(p Profile) (map[string]any, []string, error) {
	if err := p.Validate(); err != nil {
		return nil, nil, err
	}
	cfg := map[string]any{
		"log": map[string]any{"level": levelOrDefault(p.Log), "timestamp": true},
	}
	if inbounds := singBoxInbounds(p); len(inbounds) > 0 {
		cfg["inbounds"] = inbounds
	}
	cfg["dns"] = singBoxDNS(p)
	cfg["outbounds"] = singBoxOutbounds(p)
	route, warnings := singBoxRoute(p)
	cfg["route"] = route

	exp := map[string]any{
		"cache_file": map[string]any{"enabled": true, "path": "cache.db"},
	}
	if p.ClashAPI != "" {
		api := map[string]any{"external_controller": p.ClashAPI}
		if p.ClashSecret != "" {
			api["secret"] = p.ClashSecret
		}
		exp["clash_api"] = api
	}
	cfg["experimental"] = exp
	return cfg, warnings, nil
}

func singBoxInbounds(p Profile) []any {
	out := make([]any, 0, len(p.Inbounds))
	for i, in := range p.Inbounds {
		tag := in.Tag
		if tag == "" {
			tag = fmt.Sprintf("%s-in-%d", in.Type, i)
		}
		switch in.Type {
		case InboundMixed, InboundSocks, InboundHTTP:
			ob := map[string]any{
				"type":        in.Type,
				"tag":         tag,
				"listen":      in.Listen,
				"listen_port": in.Port,
			}
			if in.Username != "" || in.Password != "" {
				ob["users"] = []any{map[string]any{"username": in.Username, "password": in.Password}}
			}
			// Unset keeps sing-box's own default (no sniffer), so a profile that
			// never touched the switch emits exactly the document it did before.
			if p.Sniff != nil {
				ob["sniff"] = *p.Sniff
			}
			out = append(out, ob)
		case InboundTun:
			device := in.Device
			if device == "" {
				device = "syan-clash0"
			}
			mtu := p.TunMTUFor(in.MTU)
			stack := in.Stack
			if stack == "" {
				stack = "mixed"
			}
			out = append(out, map[string]any{
				"type":           "tun",
				"tag":            tag,
				"interface_name": device,
				"address":        []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
				"mtu":            mtu,
				"auto_route":     p.TunAutoRouteFor(in.AutoRoute),
				"strict_route":   p.TunStrictRouteFor(in.StrictRoute),
				"stack":          stack,
			})
		}
	}
	return out
}

// singBoxDNS always returns a DNS document: sing-box 1.12+ requires an
// outbound domain resolver, so even a profile with DNS switched off needs at
// least a local resolver to keep the configuration valid.
func singBoxDNS(p Profile) map[string]any {
	servers := make([]any, 0, len(p.DNS.Servers)+1)
	if p.DNS.Enabled {
		for i, s := range p.DNS.Servers {
			servers = append(servers, singBoxDNSServer(fmt.Sprintf("dns-%d", i), s))
		}
	}
	if len(servers) == 0 {
		servers = append(servers, map[string]any{"type": "local", "tag": "dns-0"})
	}
	var rules []any
	if p.DNS.Enabled && p.DNS.FakeIP {
		servers = append(servers, map[string]any{
			"type":        "fakeip",
			"tag":         "dns-fakeip",
			"inet4_range": rangeOrDefault(p.DNS.FakeIPRange),
		})
		rules = append(rules, map[string]any{
			"query_type": []string{"A", "AAAA"},
			"server":     "dns-fakeip",
		})
	}
	dns := map[string]any{"servers": servers}
	if len(rules) > 0 {
		dns["rules"] = rules
	}
	if p.DNS.Enabled && p.DNS.Strategy != "" {
		dns["strategy"] = p.DNS.Strategy
	}
	if p.DNS.Enabled {
		final := p.DNS.Final
		if final == "" && len(p.DNS.Servers) > 0 {
			final = "dns-0"
		}
		if final != "" {
			dns["final"] = final
		}
	}
	return dns
}

// singBoxResolverTag names the DNS server sing-box should use when dialling an
// outbound that was given a hostname.
func singBoxResolverTag(p Profile) string {
	if p.DNS.Enabled && p.DNS.Final != "" {
		return p.DNS.Final
	}
	return "dns-0"
}

func singBoxDNSServer(tag, addr string) map[string]any {
	s := strings.TrimSpace(addr)
	switch {
	case s == "" || strings.EqualFold(s, "local"):
		return map[string]any{"type": "local", "tag": tag}
	case strings.HasPrefix(s, "https://"):
		host := strings.TrimPrefix(s, "https://")
		host = strings.TrimSuffix(host, "/dns-query")
		host = strings.TrimSuffix(host, "/")
		return map[string]any{"type": "https", "tag": tag, "server": host}
	case strings.HasPrefix(s, "tls://"):
		return map[string]any{"type": "tls", "tag": tag, "server": strings.TrimPrefix(s, "tls://")}
	case strings.HasPrefix(s, "quic://"):
		return map[string]any{"type": "quic", "tag": tag, "server": strings.TrimPrefix(s, "quic://")}
	default:
		return map[string]any{"type": "udp", "tag": tag, "server": s}
	}
}

func singBoxOutbounds(p Profile) []any {
	out := make([]any, 0, len(p.Nodes)+len(p.Groups)+2)
	for _, n := range p.Nodes {
		out = append(out, singBoxNode(n))
	}
	for _, g := range p.Groups {
		ob := map[string]any{"tag": g.Name, "outbounds": toAnySlice(g.Members)}
		switch g.Type {
		case GroupSelect:
			ob["type"] = "selector"
			ob["default"] = g.Members[0]
		default:
			// sing-box has no fallback group; urltest with a zero tolerance is
			// the closest equivalent and keeps the config valid.
			ob["type"] = "urltest"
			ob["url"] = urlOrDefault(g.URL)
			ob["interval"] = fmt.Sprintf("%ds", intervalOrDefault(g.Interval))
			if g.Type == GroupFallback {
				ob["tolerance"] = 0
			}
		}
		out = append(out, ob)
	}
	out = append(out,
		map[string]any{"type": "direct", "tag": "direct"},
		map[string]any{"type": "block", "tag": "block"},
	)
	return out
}

func singBoxNode(n Node) map[string]any {
	ob := map[string]any{
		"tag":         n.Name,
		"server":      n.Server,
		"server_port": n.Port,
	}
	switch n.Type {
	case TypeSocks5:
		ob["type"] = "socks"
		ob["version"] = "5"
		if n.Username != "" {
			ob["username"] = n.Username
		}
		if n.Password != "" {
			ob["password"] = n.Password
		}
	case TypeHTTP:
		ob["type"] = "http"
		if n.Username != "" {
			ob["username"] = n.Username
		}
		if n.Password != "" {
			ob["password"] = n.Password
		}
	case TypeSS:
		ob["type"] = "shadowsocks"
		ob["method"] = n.Method
		ob["password"] = n.Password
	case TypeVMess:
		ob["type"] = "vmess"
		ob["uuid"] = n.UUID
		ob["alter_id"] = n.AlterID
		if n.Security != "" {
			ob["security"] = n.Security
		}
	case TypeVLESS:
		ob["type"] = "vless"
		ob["uuid"] = n.UUID
		if n.Flow != "" {
			ob["flow"] = n.Flow
		}
	case TypeTrojan:
		ob["type"] = "trojan"
		ob["password"] = n.Password
	case TypeHysteria2:
		ob["type"] = "hysteria2"
		ob["password"] = n.Password
	}
	if tls, ok := singBoxTLS(n); ok {
		ob["tls"] = tls
	}
	if tr, ok := singBoxTransport(n.Transport); ok {
		ob["transport"] = tr
	}
	return ob
}

func singBoxTLS(n Node) (map[string]any, bool) {
	t := n.TLS
	if t == nil || (!t.Enabled && t.PublicKey == "") {
		return nil, false
	}
	out := map[string]any{"enabled": true}
	if t.ServerName != "" {
		out["server_name"] = t.ServerName
	}
	if len(t.ALPN) > 0 {
		out["alpn"] = toAnySlice(t.ALPN)
	}
	if t.Insecure || n.SkipVerify {
		out["insecure"] = true
	}
	if t.Fingerprint != "" {
		out["utls"] = map[string]any{"enabled": true, "fingerprint": t.Fingerprint}
	}
	if t.PublicKey != "" {
		out["reality"] = map[string]any{
			"enabled":    true,
			"public_key": t.PublicKey,
			"short_id":   t.ShortID,
		}
	}
	return out, true
}

func singBoxTransport(tr *Transport) (map[string]any, bool) {
	if tr == nil {
		return nil, false
	}
	switch tr.Type {
	case "", "tcp":
		return nil, false
	case "ws":
		out := map[string]any{"type": "ws"}
		if tr.Path != "" {
			out["path"] = tr.Path
		}
		headers := map[string]any{}
		if tr.Host != "" {
			headers["Host"] = tr.Host
		}
		for k, v := range tr.Headers {
			headers[k] = v
		}
		if len(headers) > 0 {
			out["headers"] = headers
		}
		return out, true
	case "grpc":
		out := map[string]any{"type": "grpc"}
		if tr.ServiceName != "" {
			out["service_name"] = tr.ServiceName
		}
		return out, true
	case "http":
		out := map[string]any{"type": "http"}
		if tr.Host != "" {
			out["host"] = []string{tr.Host}
		}
		if tr.Path != "" {
			out["path"] = tr.Path
		}
		return out, true
	}
	return nil, false
}

func singBoxRoute(p Profile) (map[string]any, []string) {
	var rules []any
	var ruleSets []any
	var warnings []string
	seen := map[string]bool{}
	// Every rule set is declared up front, the same way mihomo writes its
	// top-level block: a provider the user added should appear in the generated
	// configuration even before a rule names it. usable records the ones
	// sing-box can actually express; the rest are reported when they are used.
	usable := map[string]bool{}
	warned := map[string]bool{}
	providers := make(map[string]RuleProvider, len(p.RuleProviders))
	for _, rp := range p.RuleProviders {
		tag := strings.TrimSpace(rp.Name)
		providers[tag] = rp
		rs, ok := singBoxRuleSet(tag, rp)
		usable[tag] = ok
		if ok && !seen[tag] {
			seen[tag] = true
			ruleSets = append(ruleSets, rs)
		}
	}
	for _, r := range p.Rules {
		if r.Kind == RuleFinal {
			continue
		}
		skip := false
		rule := map[string]any{"outbound": p.ResolveAction(r.Action, "block")}
		switch r.Kind {
		case RuleDomain:
			rule["domain"] = []string{r.Value}
		case RuleDomainSuffix:
			rule["domain_suffix"] = []string{r.Value}
		case RuleDomainKeyword:
			rule["domain_keyword"] = []string{r.Value}
		case RuleIPCIDR:
			rule["ip_cidr"] = []string{r.Value}
		case RulePort:
			rule["port"] = []any{portValue(r.Value)}
		case RuleProcessName:
			rule["process_name"] = []string{r.Value}
		case RuleProcessPath:
			rule["process_path"] = []string{r.Value}
		case RuleGeoIP, RuleGeoSite:
			tag := fmt.Sprintf("%s-%s", r.Kind, strings.ToLower(strings.TrimSpace(r.Value)))
			rule["rule_set"] = []string{tag}
			if !seen[tag] {
				seen[tag] = true
				ruleSets = append(ruleSets, remoteRuleSet(tag, r.Kind, r.Value))
			}
		case RuleProviderRef:
			tag := strings.TrimSpace(r.Value)
			if !usable[tag] {
				// Either the profile names a set that does not exist (Validate already
				// rejects that) or sing-box cannot express it; both mean the rule has
				// to go, because a rule_set tag the core never declared would make it
				// refuse to start. The warning is reported once per set.
				if rp, known := providers[tag]; known && !warned[tag] {
					warned[tag] = true
					warnings = append(warnings, fmt.Sprintf(
						"sing-box 无法表示规则集 %q（type=%s behavior=%s format=%s），引用它的规则已跳过",
						tag, rp.Type, rp.Behavior, rp.Format))
				}
				skip = true
				break
			}
			rule["rule_set"] = []string{tag}
		}
		if skip {
			continue
		}
		rules = append(rules, rule)
	}
	route := map[string]any{
		"final":                   p.FinalTag(),
		"auto_detect_interface":   true,
		"default_domain_resolver": map[string]any{"server": singBoxResolverTag(p)},
	}
	if len(ruleSets) > 0 {
		route["rule_set"] = ruleSets
	}
	if len(rules) > 0 {
		route["rules"] = rules
	}
	return route, warnings
}

// singBoxRuleSet maps one neutral rule provider onto a route.rule_set entry.
// http and file providers become remote/local sets. An inline provider is
// expanded into an inline set, which sing-box only supports for the two
// behaviours whose payload is a plain value list: a classical payload is rule
// text written in mihomo's own syntax, so it is reported rather than guessed at.
func singBoxRuleSet(tag string, rp RuleProvider) (map[string]any, bool) {
	format := "source"
	if strings.TrimSpace(rp.Format) == ProviderFormatMrs {
		format = "binary"
	}
	switch strings.TrimSpace(rp.Type) {
	case ProviderHTTP:
		return map[string]any{
			"type":            "remote",
			"tag":             tag,
			"format":          format,
			"url":             strings.TrimSpace(rp.URL),
			"download_detour": "direct",
			"update_interval": singBoxRuleSetInterval(rp.Interval),
		}, true
	case ProviderFile:
		return map[string]any{
			"type":   "local",
			"tag":    tag,
			"format": format,
			"path":   strings.TrimSpace(rp.Path),
		}, true
	case ProviderInline:
		payload := make([]any, 0, len(rp.Payload))
		for _, v := range rp.Payload {
			if v = strings.TrimSpace(v); v != "" {
				payload = append(payload, v)
			}
		}
		if len(payload) == 0 {
			return nil, false
		}
		var inline map[string]any
		switch strings.TrimSpace(rp.Behavior) {
		case ProviderBehaviorDomain:
			inline = map[string]any{"domain_suffix": payload}
		case ProviderBehaviorIPCIDR:
			inline = map[string]any{"ip_cidr": payload}
		default:
			return nil, false
		}
		return map[string]any{"type": "inline", "tag": tag, "rules": []any{inline}}, true
	}
	return nil, false
}

// singBoxRuleSetInterval keeps the neutral seconds value but always writes a
// concrete one, so sing-box never falls back to its own default.
func singBoxRuleSetInterval(seconds int) string {
	if seconds <= 0 {
		seconds = 86400
	}
	return fmt.Sprintf("%ds", seconds)
}

// remoteRuleSet points at the published sing-box rule-set binaries, which is
// the supported replacement for the removed inline geoip/geosite rules.
func remoteRuleSet(tag, kind, code string) map[string]any {
	repo := "sing-geosite"
	if kind == RuleGeoIP {
		repo = "sing-geoip"
	}
	return map[string]any{
		"type":            "remote",
		"tag":             tag,
		"format":          "binary",
		"url":             fmt.Sprintf("https://raw.githubusercontent.com/SagerNet/%s/rule-set/%s-%s.srs", repo, kind, strings.ToLower(strings.TrimSpace(code))),
		"download_detour": "direct",
		"update_interval": "3d",
	}
}

// portValue converts "80" or "8000-8100" into the int / "a:b" forms sing-box
// accepts for the port rule item.
func portValue(value string) any {
	v := strings.TrimSpace(value)
	if lo, hi, ok := strings.Cut(v, "-"); ok {
		return strings.TrimSpace(lo) + ":" + strings.TrimSpace(hi)
	}
	if n, err := parseUint16(v); err == nil {
		return n
	}
	return v
}
