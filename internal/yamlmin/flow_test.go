package yamlmin

import "testing"

// TestSequenceOfFlowMappings covers the exact shape Clash exports use for their
// proxy tables: block sequence items that are flow mappings, with further flow
// mappings and flow sequences nested inside. Parsing "- { name: x }" as the
// start of a block mapping used to bury every field behind a bogus "{ name"
// key, which silently dropped every proxy of a subscription.
func TestSequenceOfFlowMappings(t *testing.T) {
	src := `proxies:
    - { name: a, type: ss, server: 127.0.0.1, port: 1080, cipher: aes-128-gcm, password: p, udp: true }
    - { name: b, type: trojan, server: x.example, port: 443, password: p, network: ws, ws-opts: { path: /images, headers: { Host: x.example } } }
proxy-groups:
    - { name: 示例机场, type: select, proxies: [自动选择, 故障转移] }
rules:
    - 'MATCH,示例机场'
`
	doc, err := ParseString(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	root, ok := AsMap(doc)
	if !ok {
		t.Fatalf("root is %T, want Map", doc)
	}
	proxies, ok := AsSeq(mustGet(t, root, "proxies"))
	if !ok || len(proxies) != 2 {
		t.Fatalf("proxies = %#v, want 2 items", proxies)
	}
	first, ok := AsMap(proxies[0])
	if !ok {
		t.Fatalf("proxies[0] is %T, want Map", proxies[0])
	}
	if got := AsString(mustGet(t, first, "name")); got != "a" {
		t.Fatalf("proxies[0].name = %q, want a", got)
	}
	if got := AsInt(mustGet(t, first, "port")); got != 1080 {
		t.Fatalf("proxies[0].port = %d, want 1080", got)
	}
	if got := AsBool(mustGet(t, first, "udp")); !got {
		t.Fatalf("proxies[0].udp = false, want true")
	}
	second, ok := AsMap(proxies[1])
	if !ok {
		t.Fatalf("proxies[1] is %T, want Map", proxies[1])
	}
	ws, ok := AsMap(mustGet(t, second, "ws-opts"))
	if !ok {
		t.Fatalf("proxies[1].ws-opts is %T, want Map", mustGet(t, second, "ws-opts"))
	}
	if got := AsString(mustGet(t, ws, "path")); got != "/images" {
		t.Fatalf("ws-opts.path = %q", got)
	}
	headers, ok := AsMap(mustGet(t, ws, "headers"))
	if !ok {
		t.Fatalf("ws-opts.headers is %T, want Map", mustGet(t, ws, "headers"))
	}
	if got := AsString(mustGet(t, headers, "Host")); got != "x.example" {
		t.Fatalf("headers.Host = %q", got)
	}
	groups, ok := AsSeq(mustGet(t, root, "proxy-groups"))
	if !ok || len(groups) != 1 {
		t.Fatalf("proxy-groups = %#v, want 1 item", groups)
	}
	group, ok := AsMap(groups[0])
	if !ok {
		t.Fatalf("proxy-groups[0] is %T, want Map", groups[0])
	}
	members, ok := AsSeq(mustGet(t, group, "proxies"))
	if !ok || len(members) != 2 || AsString(members[0]) != "自动选择" || AsString(members[1]) != "故障转移" {
		t.Fatalf("group members = %#v", members)
	}
}
