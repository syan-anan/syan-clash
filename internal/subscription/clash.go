package subscription

import (
	"errors"
	"fmt"
	"strings"

	"vvpn/internal/core"
	"vvpn/internal/yamlmin"
)

// ClashProfile is what an imported Clash configuration yields.
type ClashProfile struct {
	Nodes  []core.Node
	Groups []core.Group
	Rules  []core.Rule
	// RuleProviders are the document's "rule-providers" block: named rule
	// lists the core loads itself and rules reach with RULE-SET.
	RuleProviders []core.RuleProvider
	MixedPort     int
	SocksPort     int
	HTTPPort      int
	AllowLAN      bool
	LogLevel      string
	ClashAPI      string
	Secret        string
}

// ParseClash imports a Clash / mihomo configuration document.
func ParseClash(text string) (ClashProfile, error) {
	doc, err := yamlmin.ParseString(text)
	if err != nil {
		return ClashProfile{}, fmt.Errorf("subscription: clash yaml: %w", err)
	}
	root, ok := yamlmin.AsMap(doc)
	if !ok {
		return ClashProfile{}, errors.New("subscription: clash yaml root is not a mapping")
	}
	var out ClashProfile
	out.MixedPort = mapInt(root, "mixed-port")
	out.SocksPort = mapInt(root, "socks-port")
	out.HTTPPort = mapInt(root, "port")
	out.AllowLAN = mapBool(root, "allow-lan")
	out.LogLevel = mapString(root, "log-level")
	out.ClashAPI = mapString(root, "external-controller")
	out.Secret = mapString(root, "secret")

	if v, ok := root.Get("proxies"); ok {
		items, _ := yamlmin.AsSeq(v)
		for _, item := range items {
			m, isMap := yamlmin.AsMap(item)
			if !isMap {
				continue
			}
			node, isNode := clashNode(m)
			if isNode {
				out.Nodes = append(out.Nodes, node)
			}
		}
	}
	if v, ok := root.Get("proxy-groups"); ok {
		items, _ := yamlmin.AsSeq(v)
		for _, item := range items {
			m, isMap := yamlmin.AsMap(item)
			if !isMap {
				continue
			}
			name := mapString(m, "name")
			groupType := clashGroupType(mapString(m, "type"))
			if name == "" || groupType == "" {
				continue
			}
			out.Groups = append(out.Groups, core.Group{
				Name:     name,
				Type:     groupType,
				Members:  memberList(m, "proxies"),
				URL:      mapString(m, "url"),
				Interval: mapInt(m, "interval"),
			})
		}
	}
	if v, ok := root.Get("rule-providers"); ok {
		if providers, isMap := yamlmin.AsMap(v); isMap {
			for _, entry := range providers {
				if rp, isProvider := clashRuleProvider(entry.K, entry.V); isProvider {
					out.RuleProviders = append(out.RuleProviders, rp)
				}
			}
		}
	}
	if v, ok := root.Get("rules"); ok {
		known := make(map[string]bool, len(out.RuleProviders))
		for _, rp := range out.RuleProviders {
			known[strings.ToLower(rp.Name)] = true
		}
		for _, item := range yamlmin.AsStrings(v) {
			rule, isRule := clashRule(item)
			if !isRule {
				continue
			}
			// A RULE-SET naming a provider the document did not describe would make
			// the whole profile invalid, so the rule is dropped with its provider.
			if rule.Kind == core.RuleProviderRef && !known[strings.ToLower(rule.Value)] {
				continue
			}
			out.Rules = append(out.Rules, rule)
		}
	}
	return out, nil
}

// clashRuleProvider maps one entry of a Clash "rule-providers" block onto the
// neutral rule set. The mapping key is the name the rules reference.
func clashRuleProvider(name string, value any) (core.RuleProvider, bool) {
	m, ok := yamlmin.AsMap(value)
	if !ok {
		return core.RuleProvider{}, false
	}
	rp := core.RuleProvider{
		Name:     strings.TrimSpace(name),
		Type:     strings.ToLower(mapString(m, "type")),
		Behavior: strings.ToLower(mapString(m, "behavior")),
		Format:   strings.ToLower(mapString(m, "format")),
		URL:      mapString(m, "url"),
		Path:     mapString(m, "path"),
		Interval: mapInt(m, "interval"),
	}
	if v, ok := m.Get("payload"); ok {
		rp.Payload = yamlmin.AsStrings(v)
	}
	// "compatible" is mihomo's relaxed http parser; the neutral model has no
	// equivalent vehicle, so it degrades to a plain http download.
	if rp.Type == "compatible" {
		rp.Type = core.ProviderHTTP
	}
	if err := rp.Validate(); err != nil {
		return core.RuleProvider{}, false
	}
	return rp, true
}

// clashNode maps one Clash proxy entry onto a neutral node.
func clashNode(m yamlmin.Map) (core.Node, bool) {
	server := mapString(m, "server")
	port := mapInt(m, "port")
	if server == "" || port == 0 {
		return core.Node{}, false
	}
	node := core.Node{
		Name:   mapString(m, "name"),
		Server: server,
		Port:   port,
		UDP:    mapBool(m, "udp"),
	}
	switch strings.ToLower(mapString(m, "type")) {
	case "ss", "shadowsocks":
		node.Type = core.TypeSS
		node.Method = mapString(m, "cipher")
		node.Password = mapString(m, "password")
	case "socks5", "socks":
		node.Type = core.TypeSocks5
		node.Username = mapString(m, "username")
		node.Password = mapString(m, "password")
	case "http":
		node.Type = core.TypeHTTP
		node.Username = mapString(m, "username")
		node.Password = mapString(m, "password")
	case "vmess":
		node.Type = core.TypeVMess
		node.UUID = mapString(m, "uuid")
		node.AlterID = mapInt(m, "alterId")
		node.Security = mapString(m, "cipher")
	case "vless":
		node.Type = core.TypeVLESS
		node.UUID = mapString(m, "uuid")
		node.Flow = mapString(m, "flow")
	case "trojan":
		node.Type = core.TypeTrojan
		node.Password = mapString(m, "password")
	case "hysteria2", "hy2":
		node.Type = core.TypeHysteria2
		node.Password = mapString(m, "password")
	default:
		return core.Node{}, false
	}
	node.SkipVerify = mapBool(m, "skip-cert-verify")
	node.TLS = clashTLS(m, node.Type)
	node.Transport = clashTransport(m)
	if node.Name == "" {
		node.Name = fmt.Sprintf("%s-%s-%d", node.Type, server, port)
	}
	return node, true
}

func clashTLS(m yamlmin.Map, nodeType string) *core.TLS {
	tls := &core.TLS{
		Enabled:     mapBool(m, "tls"),
		ServerName:  mapString(m, "servername"),
		Fingerprint: mapString(m, "client-fingerprint"),
		Insecure:    mapBool(m, "skip-cert-verify"),
		ALPN:        mapStrings(m, "alpn"),
	}
	if tls.ServerName == "" {
		tls.ServerName = mapString(m, "sni")
	}
	if reality, ok := mapMap(m, "reality-opts"); ok {
		tls.PublicKey = mapString(reality, "public-key")
		tls.ShortID = mapString(reality, "short-id")
	}
	// Trojan and hysteria2 are TLS-only transports in Clash.
	if nodeType == core.TypeTrojan || nodeType == core.TypeHysteria2 {
		tls.Enabled = true
	}
	if !tls.Enabled && tls.PublicKey == "" {
		return nil
	}
	tls.Enabled = true
	return tls
}

func clashTransport(m yamlmin.Map) *core.Transport {
	switch strings.ToLower(mapString(m, "network")) {
	case "ws":
		out := &core.Transport{Type: "ws"}
		if opts, ok := mapMap(m, "ws-opts"); ok {
			out.Path = mapString(opts, "path")
			if headers, ok := mapMap(opts, "headers"); ok {
				out.Host = mapString(headers, "Host")
				if out.Host == "" {
					out.Host = mapString(headers, "host")
				}
			}
		}
		return out
	case "grpc":
		out := &core.Transport{Type: "grpc"}
		if opts, ok := mapMap(m, "grpc-opts"); ok {
			out.ServiceName = mapString(opts, "grpc-service-name")
		}
		return out
	case "http", "h2":
		out := &core.Transport{Type: "http"}
		if opts, ok := mapMap(m, "http-opts"); ok {
			out.Path = firstString(opts, "path")
			out.Host = firstString(opts, "host")
		}
		return out
	default:
		return nil
	}
}

func clashGroupType(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "select":
		return core.GroupSelect
	case "url-test":
		return core.GroupURLTest
	case "fallback":
		return core.GroupFallback
	default:
		return ""
	}
}

// clashRule converts "DOMAIN-SUFFIX,example.com,PROXY" into a neutral rule.
func clashRule(text string) (core.Rule, bool) {
	parts := strings.Split(text, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	if len(parts) < 2 {
		return core.Rule{}, false
	}
	kind, ok := clashRuleKind(parts[0])
	if !ok {
		return core.Rule{}, false
	}
	rule := core.Rule{Kind: kind}
	// MATCH/FINAL carry no value: their second field is the outbound.
	actionIndex := 2
	if kind == core.RuleFinal {
		actionIndex = 1
	} else {
		rule.Value = parts[1]
	}
	switch kind {
	case core.RuleGeoIP:
		rule.Value = strings.ToUpper(rule.Value)
	case core.RuleGeoSite:
		rule.Value = strings.ToLower(rule.Value)
	}
	if len(parts) > actionIndex && parts[actionIndex] != "" {
		rule.Action = clashAction(parts[actionIndex])
	} else {
		rule.Action = "proxy"
	}
	if len(parts) > actionIndex+1 && strings.EqualFold(parts[actionIndex+1], "no-resolve") {
		rule.NoResolve = true
	}
	return rule, true
}

func clashRuleKind(name string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "domain":
		return core.RuleDomain, true
	case "domain-suffix":
		return core.RuleDomainSuffix, true
	case "domain-keyword":
		return core.RuleDomainKeyword, true
	case "ip-cidr", "ip-cidr6":
		return core.RuleIPCIDR, true
	case "dst-port", "src-port", "port":
		return core.RulePort, true
	case "geoip":
		return core.RuleGeoIP, true
	case "geosite":
		return core.RuleGeoSite, true
	case "rule-set":
		return core.RuleProviderRef, true
	case "match", "final":
		return core.RuleFinal, true
	default:
		return "", false
	}
}

// clashAction maps the Clash built-in targets onto neutral actions; anything
// else is a proxy group name and is kept verbatim.
func clashAction(action string) string {
	switch strings.ToUpper(strings.TrimSpace(action)) {
	case "DIRECT":
		return core.ActionDirect
	case "REJECT", "REJECT-DROP":
		return core.ActionReject
	default:
		return strings.TrimSpace(action)
	}
}

func mapString(m yamlmin.Map, key string) string {
	v, ok := m.Get(key)
	if !ok {
		return ""
	}
	return yamlmin.AsString(v)
}

func mapInt(m yamlmin.Map, key string) int {
	v, ok := m.Get(key)
	if !ok {
		return 0
	}
	return yamlmin.AsInt(v)
}

func mapBool(m yamlmin.Map, key string) bool {
	v, ok := m.Get(key)
	if !ok {
		return false
	}
	return yamlmin.AsBool(v)
}

func mapStrings(m yamlmin.Map, key string) []string {
	v, ok := m.Get(key)
	if !ok {
		return nil
	}
	return yamlmin.AsStrings(v)
}

func mapMap(m yamlmin.Map, key string) (yamlmin.Map, bool) {
	v, ok := m.Get(key)
	if !ok {
		return nil, false
	}
	return yamlmin.AsMap(v)
}

func memberList(m yamlmin.Map, key string) []string {
	values := mapStrings(m, key)
	out := make([]string, 0, len(values))
	for _, v := range values {
		if isBuiltinGroupMember(v) {
			continue
		}
		out = append(out, v)
	}
	return out
}

func isBuiltinGroupMember(v string) bool {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "DIRECT", "REJECT", "PASS", "GLOBAL":
		return true
	default:
		return false
	}
}

func firstString(m yamlmin.Map, key string) string {
	if values := mapStrings(m, key); len(values) > 0 {
		return values[0]
	}
	return ""
}
