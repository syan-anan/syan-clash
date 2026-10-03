package subscription

import (
	"encoding/base64"
	"strings"
	"testing"

	"vvpn/internal/core"
)

const clashSample = `
mixed-port: 7890
allow-lan: false
log-level: warning
external-controller: 127.0.0.1:9090
proxies:
  - name: "香港 01"
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: pw
    udp: true
  - name: vless-ws
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    servername: example.com
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: example.com
  - name: relay
    type: trojan
    server: t.example.com
    port: 443
    password: tpw
    skip-cert-verify: true
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - 香港 01
      - vless-ws
      - DIRECT
  - name: AUTO
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    proxies:
      - vless-ws
      - relay
rules:
  - DOMAIN-SUFFIX,cn,DIRECT
  - GEOIP,CN,DIRECT
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - MATCH,PROXY
`

func TestParseClashProfile(t *testing.T) {
	profile, err := ParseClash(clashSample)
	if err != nil {
		t.Fatalf("ParseClash: %v", err)
	}
	if profile.MixedPort != 7890 || profile.AllowLAN {
		t.Errorf("ports = %d allow-lan=%v", profile.MixedPort, profile.AllowLAN)
	}
	if profile.ClashAPI != "127.0.0.1:9090" {
		t.Errorf("external-controller = %q", profile.ClashAPI)
	}
	if len(profile.Nodes) != 3 {
		t.Fatalf("nodes = %d, want 3 (%+v)", len(profile.Nodes), profile.Nodes)
	}
	ss := profile.Nodes[0]
	if ss.Name != "香港 01" || ss.Type != core.TypeSS || ss.Method != "aes-256-gcm" || !ss.UDP {
		t.Errorf("ss node = %+v", ss)
	}
	vless := profile.Nodes[1]
	if vless.Type != core.TypeVLESS || vless.UUID == "" {
		t.Errorf("vless node = %+v", vless)
	}
	if vless.Transport == nil || vless.Transport.Path != "/ws" || vless.Transport.Host != "example.com" {
		t.Errorf("vless transport = %+v", vless.Transport)
	}
	if vless.TLS == nil || !vless.TLS.Enabled || vless.TLS.ServerName != "example.com" {
		t.Errorf("vless tls = %+v", vless.TLS)
	}
	trojan := profile.Nodes[2]
	if trojan.Type != core.TypeTrojan || !trojan.SkipVerify {
		t.Errorf("trojan node = %+v", trojan)
	}

	if len(profile.Groups) != 2 {
		t.Fatalf("groups = %+v", profile.Groups)
	}
	if got := profile.Groups[0]; got.Type != core.GroupSelect || len(got.Members) != 2 || got.Members[0] != "香港 01" {
		t.Errorf("select group = %+v (DIRECT should be dropped)", got)
	}
	if got := profile.Groups[1]; got.Type != core.GroupURLTest || got.Interval != 300 {
		t.Errorf("url-test group = %+v", got)
	}

	if len(profile.Rules) != 4 {
		t.Fatalf("rules = %+v", profile.Rules)
	}
	if got := profile.Rules[0]; got.Kind != core.RuleDomainSuffix || got.Value != "cn" || got.Action != core.ActionDirect {
		t.Errorf("rule 0 = %+v", got)
	}
	if got := profile.Rules[1]; got.Kind != core.RuleGeoIP || got.Value != "CN" {
		t.Errorf("rule 1 = %+v", got)
	}
	if got := profile.Rules[2]; !got.NoResolve {
		t.Errorf("rule 2 should carry no-resolve: %+v", got)
	}
	if got := profile.Rules[3]; got.Kind != core.RuleFinal || got.Action != "PROXY" {
		t.Errorf("rule 3 = %+v", got)
	}
}

func TestParseClashYieldsValidProfile(t *testing.T) {
	profile, err := ParseClash(clashSample)
	if err != nil {
		t.Fatalf("ParseClash: %v", err)
	}
	// The imported pieces must be directly usable as a core profile.
	p := core.DefaultProfile()
	p.Nodes = profile.Nodes
	p.Groups = profile.Groups
	p.Rules = profile.Rules
	p.Final = "PROXY"
	if err := p.Validate(); err != nil {
		t.Fatalf("imported profile is not valid: %v", err)
	}
}

func TestParseBase64Blob(t *testing.T) {
	links := strings.Join([]string{
		"ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pw")) + "@1.2.3.4:8388#a",
		"socks5://127.0.0.1:1080#b",
	}, "\n")
	blob := base64.StdEncoding.EncodeToString([]byte(links))

	nodes, err := Parse(blob)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes = %d, want 2", len(nodes))
	}
	if nodes[0].Type != core.TypeSS || nodes[1].Type != core.TypeSocks5 {
		t.Fatalf("nodes = %+v", nodes)
	}
}

func TestParsePlainLinesSkipsCommentsAndBadLines(t *testing.T) {
	text := "# comment line\n\nsocks5://127.0.0.1:1080#good\nssr://unsupported\n"
	nodes, err := Parse(text)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(nodes) != 1 || nodes[0].Name != "good" {
		t.Fatalf("nodes = %+v", nodes)
	}
}

func TestParseSingBoxJSON(t *testing.T) {
	doc := `{
	  "outbounds": [
	    {"type":"selector","tag":"PROXY","outbounds":["n1","direct"]},
	    {"type":"vless","tag":"n1","server":"1.2.3.4","server_port":443,
	     "uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls-rprx-vision",
	     "tls":{"enabled":true,"server_name":"example.com","utls":{"enabled":true,"fingerprint":"chrome"}},
	     "transport":{"type":"ws","path":"/ws","headers":{"Host":"example.com"}}},
	    {"type":"direct","tag":"direct"}
	  ]
	}`
	nodes, err := Parse(doc)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("nodes = %+v", nodes)
	}
	node := nodes[0]
	if node.Name != "n1" || node.Type != core.TypeVLESS || node.Port != 443 {
		t.Fatalf("node = %+v", node)
	}
	if node.TLS == nil || node.TLS.Fingerprint != "chrome" {
		t.Fatalf("tls = %+v", node.TLS)
	}
	if node.Transport == nil || node.Transport.Path != "/ws" || node.Transport.Host != "example.com" {
		t.Fatalf("transport = %+v", node.Transport)
	}
}

func TestParseEmptyPayload(t *testing.T) {
	if _, err := Parse("   \n  "); err == nil {
		t.Error("empty payload should fail")
	}
	if _, err := Parse("just some words"); err == nil {
		t.Error("non-link payload should fail")
	}
}
