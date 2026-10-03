package subscription

import (
	"testing"

	"vvpn/internal/core"
)

// TestParseClashFlowStyleProxies pins the layout real airports serve: every
// proxy is a single-line flow mapping, proxy groups nest flow sequences, and
// trojan nodes carry ws-opts with a headers block.
func TestParseClashFlowStyleProxies(t *testing.T) {
	src := `mixed-port: 7890
proxies:
    - { name: '剩余流量：295.01 GB', type: trojan, server: pro.example, port: 443, password: p, udp: true, skip-cert-verify: false, sni: node.example, network: ws, ws-opts: { path: /images, headers: { Host: node.example } } }
    - { name: 🇯🇵日本🚀HY01, server: 151.248.68.5, port: 58610, sni: iosapps.itunes.apple.com, up: 20, down: 100, skip-cert-verify: true, type: hysteria2, password: p }
proxy-groups:
    - { name: 示例机场, type: select, proxies: [自动选择, 故障转移] }
    - { name: 自动选择, type: url-test, proxies: [剩余流量：295.01 GB, 🇯🇵日本🚀HY01], url: 'http://www.gstatic.com/generate_204', interval: 86400 }
rules:
    - 'DOMAIN,dy11.example.com,自动选择'
    - 'MATCH,示例机场'
`
	p, err := ParseClash(src)
	if err != nil {
		t.Fatalf("ParseClash: %v", err)
	}
	if len(p.Nodes) != 2 {
		t.Fatalf("nodes = %d, want 2 (%+v)", len(p.Nodes), p.Nodes)
	}
	trojan := p.Nodes[0]
	if trojan.Type != core.TypeTrojan || trojan.Server != "pro.example" || trojan.Port != 443 {
		t.Fatalf("node[0] = %+v", trojan)
	}
	if !trojan.UDP {
		t.Fatalf("node[0].UDP = false, want true")
	}
	if trojan.TLS == nil || !trojan.TLS.Enabled || trojan.TLS.ServerName != "node.example" {
		t.Fatalf("node[0].TLS = %+v", trojan.TLS)
	}
	if trojan.Transport == nil || trojan.Transport.Type != "ws" ||
		trojan.Transport.Path != "/images" || trojan.Transport.Host != "node.example" {
		t.Fatalf("node[0].Transport = %+v", trojan.Transport)
	}
	hy := p.Nodes[1]
	if hy.Type != core.TypeHysteria2 || hy.Port != 58610 || hy.Password != "p" {
		t.Fatalf("node[1] = %+v", hy)
	}
	if hy.TLS == nil || hy.TLS.ServerName != "iosapps.itunes.apple.com" {
		t.Fatalf("node[1].TLS = %+v", hy.TLS)
	}
	if len(p.Groups) != 2 {
		t.Fatalf("groups = %d, want 2 (%+v)", len(p.Groups), p.Groups)
	}
	if p.Groups[0].Name != "示例机场" || p.Groups[0].Type != core.GroupSelect {
		t.Fatalf("group[0] = %+v", p.Groups[0])
	}
	if len(p.Groups[0].Members) != 2 || p.Groups[0].Members[0] != "自动选择" {
		t.Fatalf("group[0].Members = %v", p.Groups[0].Members)
	}
	if p.Groups[1].Type != core.GroupURLTest || p.Groups[1].Interval != 86400 || len(p.Groups[1].Members) != 2 {
		t.Fatalf("group[1] = %+v", p.Groups[1])
	}
	if len(p.Rules) != 2 {
		t.Fatalf("rules = %d, want 2 (%+v)", len(p.Rules), p.Rules)
	}
	if p.Rules[0].Kind != core.RuleDomain || p.Rules[0].Action != "自动选择" {
		t.Fatalf("rule[0] = %+v", p.Rules[0])
	}
	if p.Rules[1].Kind != core.RuleFinal || p.Rules[1].Action != "示例机场" {
		t.Fatalf("rule[1] = %+v", p.Rules[1])
	}
}
