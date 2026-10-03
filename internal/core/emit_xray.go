package core

import (
	"fmt"
	"strings"
)

// EmitXray compiles a profile into an Xray-core configuration document.
func EmitXray(p Profile) (map[string]any, error) {
	doc, _, err := EmitXrayWithWarnings(p)
	return doc, err
}

// EmitXrayWithWarnings also reports what could not be represented, because Xray
// differs from the Clash-family cores in three ways:
//
//   - no proxy groups: a group name resolves to its first member, so switching
//     nodes at runtime is not possible;
//   - no TUN inbound: TUN needs sing-box or mihomo;
//   - no hysteria2 outbound and no fake-IP DNS: those entries are skipped.
func EmitXrayWithWarnings(p Profile) (map[string]any, []string, error) {
	if err := p.Validate(); err != nil {
		return nil, nil, err
	}
	var warnings []string
	for _, in := range p.Inbounds {
		if in.Type == InboundTun {
			return nil, nil, fmt.Errorf("Xray 不支持 TUN 入站：TUN 模式请改用 sing-box 或 mihomo")
		}
	}

	inbounds := make([]any, 0, len(p.Inbounds))
	for i, in := range p.Inbounds {
		tag := in.Tag
		if tag == "" {
			tag = fmt.Sprintf("%s-in-%d", in.Type, i)
		}
		switch in.Type {
		case InboundSocks:
			inbounds = append(inbounds, xraySocksInbound(tag, in, p.SniffEnabled()))
		case InboundHTTP:
			inbounds = append(inbounds, xrayHTTPInbound(tag, in, p.SniffEnabled()))
		case InboundMixed:
			// Xray has no "mixed" listener, so the single neutral inbound becomes
			// two listeners: SOCKS5 and HTTP on the same port. Clients that only
			// speak HTTP (most CLI tools, many Electron apps) then work too.
			inbounds = append(inbounds, xraySocksInbound(tag, in, p.SniffEnabled()))
			httpInbound := xrayHTTPInbound(tag+"-http", in, p.SniffEnabled())
			// Both listeners cannot share a port in Xray, so the HTTP listener
			// takes the next port; the note tells the user which one it is.
			if in.Port < 65535 {
				httpInbound["port"] = in.Port + 1
				warnings = append(warnings, fmt.Sprintf(
					"Xray 没有 mixed 入站：已拆成 SOCKS5 %s:%d 与 HTTP %s:%d 两个监听",
					in.Listen, in.Port, in.Listen, in.Port+1))
			} else {
				// No room to shift: keep SOCKS5 only rather than emit a
				// configuration that cannot bind.
				warnings = append(warnings, fmt.Sprintf(
					"Xray 没有 mixed 入站：端口 %d 无法为 HTTP 监听留出下一个端口，只生成了 SOCKS5",
					in.Port))
				continue
			}
			inbounds = append(inbounds, httpInbound)
		}
	}

	// Xray has no "final" rule: traffic that matches nothing uses the first
	// outbound, so the profile's final target has to be listed first.
	finalTag := xrayAction(p, p.FinalTag())
	outbounds := xrayOutbounds(p, finalTag, &warnings)
	if len(p.Groups) > 0 {
		warnings = append(warnings, "Xray 没有代理组：规则里的组名会解析为该组第一个节点，运行中无法切换")
	}

	cfg := map[string]any{
		"log":       map[string]any{"loglevel": xrayLogLevel(p.Log)},
		"inbounds":  inbounds,
		"outbounds": outbounds,
	}
	if routing, routingWarnings, ok := xrayRouting(p); ok {
		cfg["routing"] = routing
		warnings = append(warnings, routingWarnings...)
	} else {
		warnings = append(warnings, routingWarnings...)
	}
	if dns, ok := xrayDNS(p); ok {
		cfg["dns"] = dns
	}
	return cfg, warnings, nil
}

// xrayLogLevel spells the shared level in Xray's own vocabulary: it calls the
// warning level "warning", and "silent" is "none".
func xrayLogLevel(level string) string {
	switch NormalizeLogLevel(level) {
	case "warn":
		return "warning"
	case "silent":
		return "none"
	default:
		return NormalizeLogLevel(level)
	}
}

// xraySniffing is the inbound sniffer block. Xray has always shipped with it
// on; the switch exists so a user who wants routing to see only real addresses
// can turn it off. destOverride only means something while the sniffer is on,
// so it is dropped with it.
func xraySniffing(enabled bool) map[string]any {
	if !enabled {
		return map[string]any{"enabled": false}
	}
	return map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}}
}

func xraySocksInbound(tag string, in Inbound, sniff bool) map[string]any {
	settings := map[string]any{
		"auth": "noauth",
		"udp":  true,
	}
	if in.Username != "" || in.Password != "" {
		settings["auth"] = "password"
		settings["accounts"] = []any{map[string]any{"user": in.Username, "pass": in.Password}}
	}
	return map[string]any{
		"tag":      tag,
		"listen":   in.Listen,
		"port":     in.Port,
		"protocol": "socks",
		"settings": settings,
		"sniffing": xraySniffing(sniff),
	}
}

func xrayHTTPInbound(tag string, in Inbound, sniff bool) map[string]any {
	return map[string]any{
		"tag":      tag,
		"listen":   in.Listen,
		"port":     in.Port,
		"protocol": "http",
		"settings": map[string]any{"timeout": 0},
		"sniffing": xraySniffing(sniff),
	}
}

func xrayNode(n Node) (map[string]any, bool) {
	ob := map[string]any{"tag": n.Name}
	switch n.Type {
	case TypeSocks5:
		ob["protocol"] = "socks"
		server := map[string]any{"address": n.Server, "port": n.Port}
		if n.Username != "" || n.Password != "" {
			server["users"] = []any{map[string]any{"user": n.Username, "pass": n.Password}}
		}
		ob["settings"] = map[string]any{"servers": []any{server}}
	case TypeHTTP:
		ob["protocol"] = "http"
		server := map[string]any{"address": n.Server, "port": n.Port}
		if n.Username != "" || n.Password != "" {
			server["users"] = []any{map[string]any{"user": n.Username, "pass": n.Password}}
		}
		ob["settings"] = map[string]any{"servers": []any{server}}
	case TypeSS:
		ob["protocol"] = "shadowsocks"
		ob["settings"] = map[string]any{"servers": []any{map[string]any{
			"address":  n.Server,
			"port":     n.Port,
			"method":   n.Method,
			"password": n.Password,
		}}}
	case TypeVMess:
		ob["protocol"] = "vmess"
		user := map[string]any{"id": n.UUID, "alterId": n.AlterID, "security": securityOr(n.Security)}
		ob["settings"] = map[string]any{"vnext": []any{map[string]any{
			"address": n.Server,
			"port":    n.Port,
			"users":   []any{user},
		}}}
	case TypeVLESS:
		ob["protocol"] = "vless"
		user := map[string]any{"id": n.UUID, "encryption": "none"}
		if n.Flow != "" {
			user["flow"] = n.Flow
		}
		ob["settings"] = map[string]any{"vnext": []any{map[string]any{
			"address": n.Server,
			"port":    n.Port,
			"users":   []any{user},
		}}}
	case TypeTrojan:
		ob["protocol"] = "trojan"
		ob["settings"] = map[string]any{"servers": []any{map[string]any{
			"address":  n.Server,
			"port":     n.Port,
			"password": n.Password,
		}}}
	default:
		// hysteria2 and anything else has no Xray outbound.
		return nil, false
	}
	if stream := xrayStream(n); stream != nil {
		ob["streamSettings"] = stream
	}
	return ob, true
}

func xrayStream(n Node) map[string]any {
	stream := map[string]any{}
	if t := n.TLS; t != nil && (t.Enabled || t.PublicKey != "") {
		switch {
		case t.PublicKey != "":
			stream["security"] = "reality"
			fingerprint := t.Fingerprint
			if fingerprint == "" {
				fingerprint = "chrome"
			}
			reality := map[string]any{
				"serverName":  t.ServerName,
				"publicKey":   t.PublicKey,
				"shortId":     t.ShortID,
				"fingerprint": fingerprint,
			}
			if t.Insecure || n.SkipVerify {
				reality["allowInsecure"] = true
			}
			stream["realitySettings"] = reality
		default:
			stream["security"] = "tls"
			tlsSettings := map[string]any{}
			if t.ServerName != "" {
				tlsSettings["serverName"] = t.ServerName
			}
			if len(t.ALPN) > 0 {
				tlsSettings["alpn"] = toAnySlice(t.ALPN)
			}
			if t.Fingerprint != "" {
				tlsSettings["fingerprint"] = t.Fingerprint
			}
			if t.Insecure || n.SkipVerify {
				tlsSettings["allowInsecure"] = true
			}
			if len(tlsSettings) > 0 {
				stream["tlsSettings"] = tlsSettings
			}
		}
	}
	if tr := n.Transport; tr != nil {
		switch tr.Type {
		case "ws":
			stream["network"] = "ws"
			ws := map[string]any{}
			if tr.Path != "" {
				ws["path"] = tr.Path
			}
			headers := map[string]any{}
			if tr.Host != "" {
				headers["Host"] = tr.Host
			}
			for k, v := range tr.Headers {
				headers[k] = v
			}
			if len(headers) > 0 {
				ws["headers"] = headers
			}
			if len(ws) > 0 {
				stream["wsSettings"] = ws
			}
		case "grpc":
			stream["network"] = "grpc"
			if tr.ServiceName != "" {
				stream["grpcSettings"] = map[string]any{"serviceName": tr.ServiceName}
			}
		case "http":
			stream["network"] = "http"
			http := map[string]any{}
			if tr.Host != "" {
				http["host"] = []string{tr.Host}
			}
			if tr.Path != "" {
				http["path"] = tr.Path
			}
			if len(http) > 0 {
				stream["httpSettings"] = http
			}
		}
	}
	if len(stream) == 0 {
		return nil
	}
	return stream
}

// xrayOutbounds builds the outbound list with the fallback target first.
func xrayOutbounds(p Profile, finalTag string, warnings *[]string) []any {
	direct := map[string]any{"tag": "direct", "protocol": "freedom", "settings": map[string]any{}}
	block := map[string]any{"tag": "block", "protocol": "blackhole", "settings": map[string]any{}}

	var nodes []any
	for _, n := range p.Nodes {
		ob, ok := xrayNode(n)
		if !ok {
			*warnings = append(*warnings, fmt.Sprintf("Xray 不支持节点 %q（%s），已跳过", n.Name, n.Type))
			continue
		}
		nodes = append(nodes, ob)
	}

	first := any(direct)
	switch finalTag {
	case "block":
		first = block
	case "direct":
		first = direct
	default:
		for _, ob := range nodes {
			if m, ok := ob.(map[string]any); ok && m["tag"] == finalTag {
				first = ob
				break
			}
		}
	}
	firstName := ""
	if m, ok := first.(map[string]any); ok {
		firstName, _ = m["tag"].(string)
	}

	out := []any{first}
	for _, ob := range []any{direct, block} {
		if m, ok := ob.(map[string]any); ok && m["tag"] != firstName {
			out = append(out, ob)
		}
	}
	for _, ob := range nodes {
		if m, ok := ob.(map[string]any); ok && m["tag"] != firstName {
			out = append(out, ob)
		}
	}
	return out
}

// xrayRouting renders the rule list. Xray rejects a rule with no conditions, so
// the profile's final target is expressed through the outbound order instead.
func xrayRouting(p Profile) (map[string]any, []string, bool) {
	var warnings []string
	rules := make([]any, 0, len(p.Rules)+1)
	for _, r := range p.Rules {
		if r.Kind == RuleFinal {
			continue
		}
		rule := map[string]any{"type": "field", "outboundTag": xrayAction(p, r.Action)}
		switch r.Kind {
		case RuleDomain:
			rule["domain"] = []string{"full:" + r.Value}
		case RuleDomainSuffix:
			rule["domain"] = []string{"domain:" + strings.TrimPrefix(r.Value, ".")}
		case RuleDomainKeyword:
			rule["domain"] = []string{"keyword:" + r.Value}
		case RuleGeoSite:
			rule["domain"] = []string{"geosite:" + strings.ToLower(strings.TrimSpace(r.Value))}
		case RuleIPCIDR:
			rule["ip"] = []string{r.Value}
		case RuleGeoIP:
			rule["ip"] = []string{"geoip:" + strings.ToUpper(strings.TrimSpace(r.Value))}
		case RulePort:
			rule["port"] = strings.ReplaceAll(r.Value, "-", "-")
		case RuleProcessName:
			rule["process"] = []string{r.Value}
		case RuleProcessPath:
			rule["process"] = []string{r.Value}
		case RuleProviderRef:
			// Xray has no user-supplied rule-set: its routing can only reach
			// the databases the core ships (geoip:/geosite:), so a custom set
			// has nowhere to live. Skipping the rule is the honest translation
			// and the warning says which one went missing.
			warnings = append(warnings, fmt.Sprintf(
				"Xray 不支持自定义规则集：规则 %q 已跳过（用 sing-box 或 mihomo 才能生效）",
				strings.TrimSpace(r.Value)))
			continue
		}
		rules = append(rules, rule)
	}
	if len(rules) == 0 {
		return nil, warnings, false
	}
	return map[string]any{"domainStrategy": "IPIfNonMatch", "rules": rules}, warnings, true
}

// xrayAction maps a neutral action onto an Xray outbound tag. Groups resolve to
// their first member because Xray cannot switch them at runtime.
func xrayAction(p Profile, action string) string {
	if strings.TrimSpace(action) == "" {
		action = p.FinalTag()
	}
	// ActionProxy means the profile fallback, which Xray expresses as the first
	// outbound (see xrayOutbounds); resolving it to the fallback tag keeps the
	// routing rules consistent with the outbound order.
	if action == ActionProxy {
		action = p.FinalTag()
	}
	switch action {
	case ActionDirect:
		return "direct"
	case ActionReject:
		return "block"
	}
	for _, g := range p.Groups {
		if g.Name == action && len(g.Members) > 0 {
			return g.Members[0]
		}
	}
	return action
}

func xrayDNS(p Profile) (map[string]any, bool) {
	if !p.DNS.Enabled || len(p.DNS.Servers) == 0 {
		return nil, false
	}
	servers := make([]any, 0, len(p.DNS.Servers))
	for _, s := range p.DNS.Servers {
		s = strings.TrimSpace(s)
		switch {
		case s == "":
			continue
		case strings.EqualFold(s, "local"):
			servers = append(servers, "localhost")
		case strings.HasPrefix(s, "https://"), strings.HasPrefix(s, "tls://"), strings.HasPrefix(s, "quic://"):
			servers = append(servers, s)
		default:
			servers = append(servers, s)
		}
	}
	if len(servers) == 0 {
		return nil, false
	}
	dns := map[string]any{"servers": servers}
	if s := xrayQueryStrategy(p.DNS.Strategy); s != "" {
		dns["queryStrategy"] = s
	}
	return dns, true
}

// xrayQueryStrategy maps the neutral strategy onto Xray's own vocabulary. The
// two disagree: the neutral names describe a preference between address
// families, Xray names the one family to use. Passing "prefer_ipv4" through
// unchanged produced a configuration Xray rejects, which is why the mapping
// exists. Xray has no "prefer, then fall back" mode, so the preference becomes
// the family it prefers.
func xrayQueryStrategy(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "prefer_ipv4", "ipv4_only":
		return "UseIPv4"
	case "prefer_ipv6", "ipv6_only":
		return "UseIPv6"
	}
	return ""
}
