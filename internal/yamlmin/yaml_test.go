package yamlmin

import (
	"strings"
	"testing"
)

const clashSample = `
# a realistic slice of a Clash/mihomo configuration
mixed-port: 7890
allow-lan: false
log-level: info
external-controller: 127.0.0.1:9090
secret: ""
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.0/15
  nameserver:
    - system
    - https://223.5.5.5/dns-query
  fallback-filter:
    geoip: true
    geoip-code: CN
proxies:
  - name: "香港 01"
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: "p@ss:word"
    udp: true
  - name: vless-ws
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    flow: xtls-rprx-vision
    tls: true
    servername: example.com
    client-fingerprint: chrome
    alpn: [h2, http/1.1]
    reality-opts:
      public-key: PUBKEY
      short-id: ab12
    ws-opts:
      path: /ws
      headers:
        Host: example.com
    udp: true
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - 香港 01
      - vless-ws
      - DIRECT
rules:
  - DOMAIN-SUFFIX,cn,DIRECT
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - MATCH,PROXY
`

func TestParseClashSample(t *testing.T) {
	doc, err := ParseString(clashSample)
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	root, ok := AsMap(doc)
	if !ok {
		t.Fatalf("root is %T, want Map", doc)
	}
	if got := AsInt(mustGet(t, root, "mixed-port")); got != 7890 {
		t.Errorf("mixed-port = %d, want 7890", got)
	}
	if got := AsBool(mustGet(t, root, "allow-lan")); got {
		t.Error("allow-lan should be false")
	}
	if got := AsString(mustGet(t, root, "secret")); got != "" {
		t.Errorf("secret = %q, want empty", got)
	}

	dns, ok := AsMap(mustGet(t, root, "dns"))
	if !ok {
		t.Fatal("dns is not a map")
	}
	ns := AsStrings(mustGet(t, dns, "nameserver"))
	if len(ns) != 2 || ns[0] != "system" || ns[1] != "https://223.5.5.5/dns-query" {
		t.Errorf("nameserver = %v", ns)
	}
	ff, ok := AsMap(mustGet(t, dns, "fallback-filter"))
	if !ok || AsString(mustGet(t, ff, "geoip-code")) != "CN" {
		t.Errorf("fallback-filter geoip-code mismatch: %#v", ff)
	}

	proxies, ok := AsSeq(mustGet(t, root, "proxies"))
	if !ok || len(proxies) != 2 {
		t.Fatalf("proxies = %#v", mustGet(t, root, "proxies"))
	}
	first, _ := AsMap(proxies[0])
	if got := AsString(mustGet(t, first, "name")); got != "香港 01" {
		t.Errorf("first proxy name = %q", got)
	}
	if got := AsString(mustGet(t, first, "password")); got != "p@ss:word" {
		t.Errorf("password = %q, want the quoted value with a colon", got)
	}
	if got := AsInt(mustGet(t, first, "port")); got != 8388 {
		t.Errorf("port = %d", got)
	}
	second, _ := AsMap(proxies[1])
	alpn := AsStrings(mustGet(t, second, "alpn"))
	if len(alpn) != 2 || alpn[0] != "h2" || alpn[1] != "http/1.1" {
		t.Errorf("alpn = %v", alpn)
	}
	ro, ok := AsMap(mustGet(t, second, "reality-opts"))
	if !ok || AsString(mustGet(t, ro, "public-key")) != "PUBKEY" {
		t.Errorf("reality-opts = %#v", ro)
	}
	ws, ok := AsMap(mustGet(t, second, "ws-opts"))
	if !ok || AsString(mustGet(t, ws, "path")) != "/ws" {
		t.Errorf("ws-opts = %#v", ws)
	}
	headers, ok := AsMap(mustGet(t, ws, "headers"))
	if !ok || AsString(mustGet(t, headers, "Host")) != "example.com" {
		t.Errorf("ws headers = %#v", headers)
	}

	groups, ok := AsSeq(mustGet(t, root, "proxy-groups"))
	if !ok || len(groups) != 1 {
		t.Fatalf("proxy-groups = %#v", mustGet(t, root, "proxy-groups"))
	}
	group, _ := AsMap(groups[0])
	if got := AsStrings(mustGet(t, group, "proxies")); len(got) != 3 || got[0] != "香港 01" {
		t.Errorf("group proxies = %v", got)
	}
	rules := AsStrings(mustGet(t, root, "rules"))
	if len(rules) != 3 || rules[1] != "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve" {
		t.Errorf("rules = %v", rules)
	}
}

func mustGet(t *testing.T, m Map, key string) any {
	t.Helper()
	v, ok := m.Get(key)
	if !ok {
		t.Fatalf("key %q not found", key)
	}
	return v
}

func TestParseRejectsBlockScalars(t *testing.T) {
	if _, err := ParseString("key: |\n  text\n"); err == nil {
		t.Error("block scalars should be rejected rather than silently mis-parsed")
	}
}

func TestParseRoundTripsThroughEmit(t *testing.T) {
	original := Map{}.
		Set("name", "节点 1").
		Set("port", 443).
		Set("enabled", true).
		Set("ratio", 0.5).
		Set("empty", nil).
		Set("tags", []any{"a", "b"}).
		Set("nested", Map{}.Set("k", "v").Set("deep", Map{}.Set("x", 1))).
		Set("items", []any{
			Map{}.Set("name", "one").Set("opts", Map{}.Set("path", "/x")),
			Map{}.Set("name", "two"),
		})

	text := Emit(original)
	doc, err := ParseString(text)
	if err != nil {
		t.Fatalf("re-parse failed: %v\n%s", err, text)
	}
	round, ok := AsMap(doc)
	if !ok {
		t.Fatalf("round-tripped root is %T", doc)
	}
	if got := AsString(mustGet(t, round, "name")); got != "节点 1" {
		t.Errorf("name = %q", got)
	}
	if got := AsInt(mustGet(t, round, "port")); got != 443 {
		t.Errorf("port = %d", got)
	}
	if !AsBool(mustGet(t, round, "enabled")) {
		t.Error("enabled should round-trip as true")
	}
	if got := AsStrings(mustGet(t, round, "tags")); len(got) != 2 || got[1] != "b" {
		t.Errorf("tags = %v", got)
	}
	nested, _ := AsMap(mustGet(t, round, "nested"))
	deep, _ := AsMap(mustGet(t, nested, "deep"))
	if got := AsInt(mustGet(t, deep, "x")); got != 1 {
		t.Errorf("nested.deep.x = %d", got)
	}
	items, ok := AsSeq(mustGet(t, round, "items"))
	if !ok || len(items) != 2 {
		t.Fatalf("items = %#v", mustGet(t, round, "items"))
	}
	first, _ := AsMap(items[0])
	opts, ok := AsMap(mustGet(t, first, "opts"))
	if !ok || AsString(mustGet(t, opts, "path")) != "/x" {
		t.Errorf("items[0].opts = %#v", opts)
	}
	if strings.Contains(text, "\t") {
		t.Error("emitted YAML must not contain tabs")
	}
}

func TestParseEmptyAndComments(t *testing.T) {
	doc, err := ParseString("\n# only a comment\n\n")
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	m, ok := AsMap(doc)
	if !ok || len(m) != 0 {
		t.Errorf("empty document = %#v", doc)
	}
}

func TestParseIndentationError(t *testing.T) {
	if _, err := ParseString("a: 1\n   b: 2\n"); err == nil {
		t.Error("inconsistent indentation should be an error")
	}
}
