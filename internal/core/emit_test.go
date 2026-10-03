package core

import (
	"encoding/json"
	"strings"
	"testing"
)

func sampleProfile() Profile {
	return Profile{
		Log:      "debug",
		Inbounds: []Inbound{{Type: InboundMixed, Tag: "mixed-in", Listen: "127.0.0.1", Port: 7890}},
		DNS: DNS{
			Enabled:  true,
			Servers:  []string{"local", "https://223.5.5.5/dns-query"},
			FakeIP:   true,
			Strategy: "prefer_ipv4",
		},
		Nodes: []Node{
			{Name: "ss-1", Type: TypeSS, Server: "1.2.3.4", Port: 8388, Method: "aes-256-gcm", Password: "pw"},
			{
				Name: "vless-1", Type: TypeVLESS, Server: "example.com", Port: 443,
				UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Flow: "xtls-rprx-vision",
				TLS:       &TLS{Enabled: true, ServerName: "example.com", Fingerprint: "chrome", PublicKey: "PUBKEY", ShortID: "ab"},
				Transport: &Transport{Type: "ws", Path: "/ws", Host: "example.com"},
			},
			{
				Name: "hy2-1", Type: TypeHysteria2, Server: "h.example.com", Port: 443, Password: "pw",
				TLS: &TLS{Enabled: true, ServerName: "h.example.com", Insecure: true},
			},
		},
		Groups: []Group{
			{Name: "PROXY", Type: GroupSelect, Members: []string{"ss-1", "vless-1", "AUTO"}},
			{Name: "AUTO", Type: GroupURLTest, Members: []string{"ss-1", "vless-1", "hy2-1"}, Interval: 300},
		},
		Rules: []Rule{
			{Kind: RuleDomainSuffix, Value: "cn", Action: ActionDirect},
			{Kind: RuleGeoSite, Value: "category-ads-all", Action: ActionReject},
			{Kind: RuleIPCIDR, Value: "10.0.0.0/8", Action: ActionDirect, NoResolve: true},
			{Kind: RuleFinal, Value: "", Action: "PROXY"},
		},
		ClashAPI: "127.0.0.1:9090",
	}
}

func TestEmitSingBox(t *testing.T) {
	doc, err := EmitSingBox(sampleProfile())
	if err != nil {
		t.Fatalf("EmitSingBox: %v", err)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	text := string(raw)
	for _, want := range []string{
		`"type":"mixed"`,
		`"listen_port":7890`,
		`"type":"shadowsocks"`,
		`"method":"aes-256-gcm"`,
		`"type":"vless"`,
		`"flow":"xtls-rprx-vision"`,
		`"public_key":"PUBKEY"`,
		`"type":"ws"`,
		`"type":"selector"`,
		`"type":"urltest"`,
		`"type":"block"`,
		`"domain_suffix":["cn"]`,
		`"ip_cidr":["10.0.0.0/8"]`,
		`"rule_set":["geosite-category-ads-all"]`,
		`geosite-category-ads-all.srs`,
		`"final":"PROXY"`,
		`"external_controller":"127.0.0.1:9090"`,
		`"type":"fakeip"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("sing-box config is missing %s\n%s", want, text)
		}
	}
}

func TestEmitMihomoYAML(t *testing.T) {
	doc, err := EmitMihomo(sampleProfile())
	if err != nil {
		t.Fatalf("EmitMihomo: %v", err)
	}
	text := yamlEmit(doc)
	for _, want := range []string{
		"mixed-port: 7890\n",
		"log-level: debug\n",
		"external-controller: 127.0.0.1:9090\n",
		"enhanced-mode: fake-ip\n",
		"nameserver:\n",
		"proxies:\n",
		"  - name: ss-1\n",
		"    type: ss\n",
		"    cipher: aes-256-gcm\n",
		"    reality-opts:\n",
		"      public-key: PUBKEY\n",
		"    client-fingerprint: chrome\n",
		"    ws-opts:\n",
		"      path: \"/ws\"\n",
		"      Host: example.com\n",
		"proxy-groups:\n",
		"    type: url-test\n",
		"rules:\n",
		"  - DOMAIN-SUFFIX,cn,DIRECT\n",
		"  - GEOSITE,category-ads-all,REJECT\n",
		"  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\n",
		"  - MATCH,PROXY\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("mihomo config is missing %q\n%s", want, text)
		}
	}
	if strings.Contains(text, "\t") {
		t.Error("mihomo config contains a tab, which YAML forbids for indentation")
	}
}

func TestMihomoAddsFinalRuleWhenMissing(t *testing.T) {
	p := sampleProfile()
	p.Rules = []Rule{{Kind: RuleDomain, Value: "example.com", Action: ActionDirect}}
	doc, err := EmitMihomo(p)
	if err != nil {
		t.Fatalf("EmitMihomo: %v", err)
	}
	if text := yamlEmit(doc); !strings.Contains(text, "- MATCH,PROXY\n") {
		t.Errorf("missing MATCH fallback rule:\n%s", text)
	}
}

func TestYAMLStringQuoting(t *testing.T) {
	cases := map[string]string{
		"example.com":    "example.com",
		"1.2.3.4:8080":   "1.2.3.4:8080",
		"aes-256-gcm":    "aes-256-gcm",
		"true":           `"true"`,
		"8080":           `"8080"`,
		"hello world":    `"hello world"`,
		"a: b":           `"a: b"`,
		"":               `""`,
		"香港 节点 01":       `"香港 节点 01"`,
		"path/with#hash": "path/with#hash",
		"*star":          `"*star"`,
		"-dash":          `"-dash"`,
		"@at":            `"@at"`,
	}
	for in, want := range cases {
		if got := yamlString(in); got != want {
			t.Errorf("yamlString(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestProfileValidate(t *testing.T) {
	if err := sampleProfile().Validate(); err != nil {
		t.Fatalf("sample profile should be valid: %v", err)
	}
	cases := map[string]func(*Profile){
		"no inbound":        func(p *Profile) { p.Inbounds = nil },
		"unknown node type": func(p *Profile) { p.Nodes[0].Type = "wireguard" },
		"ss without method": func(p *Profile) { p.Nodes[0].Method = "" },
		"unknown member":    func(p *Profile) { p.Groups[0].Members = []string{"nope"} },
		"unknown rule out":  func(p *Profile) { p.Rules[0].Action = "ghost" },
		"bad cidr":          func(p *Profile) { p.Rules[2].Value = "10.0.0.0/99" },
		"duplicate name":    func(p *Profile) { p.Nodes[1].Name = "ss-1" },
	}
	for name, mutate := range cases {
		p := sampleProfile()
		mutate(&p)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: Validate() succeeded, want error", name)
		}
	}
}

func TestRenderErrors(t *testing.T) {
	if _, err := Render("nope", sampleProfile()); err == nil {
		t.Error("Render with an unknown core should fail")
	}
	for _, id := range []string{"sing-box", "mihomo", "xray"} {
		if _, err := Render(id, sampleProfile()); err != nil {
			t.Errorf("Render(%s) = %v", id, err)
		}
	}
}

func TestPortValueForms(t *testing.T) {
	if got := portValue("8080"); got != uint16(8080) {
		t.Errorf("portValue(8080) = %#v", got)
	}
	if got := portValue("8000-8100"); got != "8000:8100" {
		t.Errorf("portValue(range) = %#v", got)
	}
}

func TestProcessRulesEmitPerCore(t *testing.T) {
	p := sampleProfile()
	p.Rules = []Rule{
		{Kind: RuleProcessName, Value: "chrome.exe", Action: ActionDirect},
		{Kind: RuleProcessPath, Value: "C:/Games/steam.exe", Action: "PROXY"},
		{Kind: RuleFinal, Value: "", Action: "PROXY"},
	}

	singbox, err := EmitSingBox(p)
	if err != nil {
		t.Fatalf("EmitSingBox: %v", err)
	}
	raw, _ := json.Marshal(singbox)
	for _, want := range []string{`"process_name":["chrome.exe"]`, `"process_path":["C:/Games/steam.exe"]`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("sing-box config is missing %s", want)
		}
	}

	mihomo, err := EmitMihomo(p)
	if err != nil {
		t.Fatalf("EmitMihomo: %v", err)
	}
	text := yamlEmit(mihomo)
	// mihomo can reference a proxy group directly in a rule, so the group name
	// is kept as-is instead of being resolved to its first member.
	for _, want := range []string{"PROCESS-NAME,chrome.exe,DIRECT", "PROCESS-PATH,C:/Games/steam.exe,PROXY"} {
		if !strings.Contains(text, want) {
			t.Errorf("mihomo config is missing %q\n%s", want, text)
		}
	}

	xray, _, err := EmitXrayWithWarnings(p)
	if err != nil {
		t.Fatalf("EmitXrayWithWarnings: %v", err)
	}
	xraw, _ := json.Marshal(xray)
	if !strings.Contains(string(xraw), `"process":["chrome.exe"]`) {
		t.Errorf("xray config is missing the process rule: %s", xraw)
	}
}

func TestProcessRuleValidation(t *testing.T) {
	p := sampleProfile()
	p.Rules = []Rule{{Kind: RuleProcessName, Value: "  ", Action: ActionDirect}}
	if err := p.Validate(); err == nil {
		t.Error("a process rule without a value should be rejected")
	}
}

func TestEmitXray(t *testing.T) {
	doc, warnings, err := EmitXrayWithWarnings(sampleProfile())
	if err != nil {
		t.Fatalf("EmitXrayWithWarnings: %v", err)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	text := string(raw)
	for _, want := range []string{
		`"protocol":"socks"`,
		`"auth":"noauth"`,
		`"protocol":"freedom"`,
		`"protocol":"blackhole"`,
		`"protocol":"shadowsocks"`,
		`"method":"aes-256-gcm"`,
		`"protocol":"vless"`,
		`"flow":"xtls-rprx-vision"`,
		`"security":"reality"`,
		`"publicKey":"PUBKEY"`,
		`"fingerprint":"chrome"`,
		`"network":"ws"`,
		`"path":"/ws"`,
		`"outboundTag":"direct"`,
		`"outboundTag":"block"`,
		`"domain":["domain:cn"]`,
		`"domain":["geosite:category-ads-all"]`,
		`"ip":["10.0.0.0/8"]`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("xray config is missing %s\n%s", want, text)
		}
	}
	// hysteria2 has no Xray outbound, so it must be reported rather than
	// silently dropped; groups are flattened, TUN is refused, and the mixed
	// inbound is split into SOCKS5 + HTTP.
	joined := strings.Join(warnings, " | ")
	if !strings.Contains(joined, "hy2-1") {
		t.Errorf("missing warning about the unsupported node: %v", warnings)
	}
	if !strings.Contains(joined, "代理组") {
		t.Errorf("missing warning about groups: %v", warnings)
	}
	if !strings.Contains(joined, "HTTP") {
		t.Errorf("missing the note about the split mixed inbound: %v", warnings)
	}
	inbounds, _ := doc["inbounds"].([]any)
	if len(inbounds) != 2 {
		t.Fatalf("a mixed inbound should become SOCKS5 + HTTP, got %d listeners", len(inbounds))
	}
	ports := map[float64]string{}
	for _, raw := range inbounds {
		m, _ := raw.(map[string]any)
		protocol, _ := m["protocol"].(string)
		port, _ := m["port"].(int)
		ports[float64(port)] = protocol
	}
	if ports[7890] != "socks" || ports[7891] != "http" {
		t.Errorf("expected socks on 7890 and http on 7891, got %+v", ports)
	}
}

func TestEmitXrayMixedAtTopPortStaysSocksOnly(t *testing.T) {
	p := sampleProfile()
	p.Inbounds = []Inbound{{Type: InboundMixed, Tag: "in", Listen: "127.0.0.1", Port: 65535}}
	doc, warnings, err := EmitXrayWithWarnings(p)
	if err != nil {
		t.Fatalf("EmitXrayWithWarnings: %v", err)
	}
	inbounds, _ := doc["inbounds"].([]any)
	if len(inbounds) != 1 {
		t.Fatalf("no room for a second listener, so only SOCKS5 should be emitted, got %d", len(inbounds))
	}
	if !strings.Contains(strings.Join(warnings, " "), "只生成了 SOCKS5") {
		t.Errorf("expected an explanation about the port limit, got %v", warnings)
	}
}

func TestEmitXrayRejectsTun(t *testing.T) {
	p := sampleProfile()
	p.Inbounds = append(p.Inbounds, Inbound{Type: InboundTun, Tag: "tun-in"})
	if _, err := EmitXray(p); err == nil {
		t.Fatal("Xray has no TUN inbound; emitting should fail with an explanation")
	}
}

// Xray has no "final" rule and rejects rules without conditions, so the profile
// fallback has to be the first outbound.
func TestEmitXrayFallbackIsFirstOutbound(t *testing.T) {
	doc, _, err := EmitXrayWithWarnings(sampleProfile())
	if err != nil {
		t.Fatalf("EmitXrayWithWarnings: %v", err)
	}
	outbounds, ok := doc["outbounds"].([]any)
	if !ok || len(outbounds) == 0 {
		t.Fatalf("outbounds = %#v", doc["outbounds"])
	}
	first, _ := outbounds[0].(map[string]any)
	// The sample profile ends with "final: PROXY", whose first member is ss-1.
	if first["tag"] != "ss-1" {
		t.Errorf("first outbound = %v, want the fallback target ss-1", first["tag"])
	}
	if first["protocol"] != "shadowsocks" {
		t.Errorf("first outbound protocol = %v", first["protocol"])
	}

	routing, ok := doc["routing"].(map[string]any)
	if !ok {
		t.Fatal("routing block missing")
	}
	rules, _ := routing["rules"].([]any)
	if len(rules) == 0 {
		t.Fatal("expected routing rules from the profile")
	}
	for _, r := range rules {
		rule, ok := r.(map[string]any)
		if !ok {
			t.Fatalf("rule is %T", r)
		}
		if len(rule) < 3 {
			t.Errorf("Xray rejects rules without conditions: %#v", rule)
		}
	}
}

func TestEmitXrayFallbackDirect(t *testing.T) {
	p := sampleProfile()
	p.Final = "direct"
	p.Groups = nil
	p.Rules = []Rule{{Kind: RuleDomainSuffix, Value: "cn", Action: ActionDirect}}
	doc, _, err := EmitXrayWithWarnings(p)
	if err != nil {
		t.Fatalf("EmitXrayWithWarnings: %v", err)
	}
	outbounds := doc["outbounds"].([]any)
	first, _ := outbounds[0].(map[string]any)
	if first["tag"] != "direct" {
		t.Errorf("first outbound = %v, want direct", first["tag"])
	}
	// direct must not be duplicated.
	seen := map[any]int{}
	for _, ob := range outbounds {
		m, _ := ob.(map[string]any)
		seen[m["tag"]]++
	}
	if seen["direct"] != 1 {
		t.Errorf("direct appears %d times, want 1", seen["direct"])
	}
}

func TestEmitXrayOmitsRoutingWhenNoRules(t *testing.T) {
	p := sampleProfile()
	p.Rules = nil
	doc, _, err := EmitXrayWithWarnings(p)
	if err != nil {
		t.Fatalf("EmitXrayWithWarnings: %v", err)
	}
	if _, present := doc["routing"]; present {
		t.Error("an empty rule list must not be emitted, Xray rejects empty routing blocks")
	}
}

func TestXrayGroupResolvesToFirstMember(t *testing.T) {
	p := sampleProfile()
	p.Rules = []Rule{{Kind: RuleDomainSuffix, Value: "cn", Action: "PROXY"}}
	p.Final = "PROXY"
	doc, _, err := EmitXrayWithWarnings(p)
	if err != nil {
		t.Fatalf("EmitXrayWithWarnings: %v", err)
	}
	routing := doc["routing"].(map[string]any)
	rules := routing["rules"].([]any)
	first := rules[0].(map[string]any)
	if got := first["outboundTag"]; got != "ss-1" {
		t.Errorf("group PROXY should resolve to its first member ss-1, got %v", got)
	}
}

// TestEmitMihomoTunIsStable pins the tunnel configuration the client ships.
// The stack has to be gvisor: the mixed stack was measured completely dead on
// Windows (the tunnel accepted packets and the DIRECT egress never returned),
// so emitting it would hand the user a tunnel that silently blackholes every
// connection. strict-route has to stay off so no WFP filter state is created,
// and the DNS block has to carry a plain-IP bootstrap resolver plus a fake-ip
// filter, otherwise a DoH-only setup can deadlock on its very first lookup.
func TestEmitMihomoTunIsStable(t *testing.T) {
	p := sampleProfile()
	p.Inbounds = append(p.Inbounds, Inbound{
		Type: InboundTun, Tag: "tun-in", Stack: "mixed",
		AutoRoute: true, StrictRoute: true, MTU: 9000, Device: "syan-clash0",
	})
	raw, err := Render("mihomo", p)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	text := string(raw)
	for _, want := range []string{
		"enable: true",
		"stack: gvisor",
		"auto-detect-interface: true",
		"strict-route: false",
		"any:53",
		"tcp://any:53",
		"default-nameserver:",
		"223.5.5.5",
		"fake-ip-filter:",
		"*.msftconnecttest.com",
		// The tunnel owns the resolver: redir-host would make the first name
		// resolution depend on a tunnel that is still coming up, and a system
		// resolver would send its query back through dns-hijack into itself.
		"enhanced-mode: fake-ip",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("mihomo tun config is missing %q\n%s", want, text)
		}
	}
	if strings.Contains(text, "stack: mixed") {
		t.Errorf("mihomo must never be handed the dead mixed stack\n%s", text)
	}
	if strings.Contains(text, "- system") {
		t.Errorf("a tunnel profile must not keep the OS resolver\n%s", text)
	}
	if !strings.Contains(text, "https://223.5.5.5/dns-query") {
		t.Errorf("the profile resolver was dropped instead of the OS one\n%s", text)
	}
	// An unknown stack name from an imported profile must not reach the core:
	// mihomo refuses to start on a value it cannot parse.
	p.Inbounds = p.Inbounds[:len(p.Inbounds)-1]
	p.Inbounds = append(p.Inbounds, Inbound{Type: InboundTun, Tag: "tun-in", Stack: "bogus", Device: "syan-clash0"})
	raw, err = Render("mihomo", p)
	if err != nil {
		t.Fatalf("Render(bogus): %v", err)
	}
	if !strings.Contains(string(raw), "stack: gvisor") {
		t.Errorf("an unknown stack must fall back to gvisor\n%s", string(raw))
	}
	if strings.Contains(string(raw), "bogus") {
		t.Errorf("the unknown stack name leaked into the configuration\n%s", string(raw))
	}
}
