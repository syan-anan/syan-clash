package subscription

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"vvpn/internal/core"
)

func TestParseSSSIP002(t *testing.T) {
	userinfo := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pass word"))
	link := "ss://" + userinfo + "@1.2.3.4:8388#%E9%A6%99%E6%B8%AF01"

	node, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if node.Type != core.TypeSS || node.Server != "1.2.3.4" || node.Port != 8388 {
		t.Fatalf("node = %+v", node)
	}
	if node.Method != "aes-256-gcm" || node.Password != "pass word" {
		t.Fatalf("credentials = %q / %q", node.Method, node.Password)
	}
	if node.Name != "香港01" {
		t.Fatalf("name = %q, want the percent-decoded fragment", node.Name)
	}
}

func TestParseSSLegacy(t *testing.T) {
	body := base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:pw@5.6.7.8:443"))
	node, err := ParseLink("ss://" + body + "#legacy")
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if node.Server != "5.6.7.8" || node.Port != 443 || node.Password != "pw" {
		t.Fatalf("node = %+v", node)
	}
	if node.Name != "legacy" {
		t.Fatalf("name = %q", node.Name)
	}
}

func TestParseVMess(t *testing.T) {
	payload := map[string]any{
		"v": "2", "ps": "vmess-1", "add": "example.com", "port": "443",
		"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "aid": "0", "scy": "auto",
		"net": "ws", "type": "none", "host": "example.com", "path": "/v",
		"tls": "tls", "sni": "example.com", "alpn": []string{"h2", "http/1.1"},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	link := "vmess://" + base64.StdEncoding.EncodeToString(raw)

	node, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if node.Type != core.TypeVMess || node.Port != 443 || node.UUID == "" {
		t.Fatalf("node = %+v", node)
	}
	if node.Transport == nil || node.Transport.Type != "ws" || node.Transport.Path != "/v" {
		t.Fatalf("transport = %+v", node.Transport)
	}
	if node.TLS == nil || !node.TLS.Enabled || node.TLS.ServerName != "example.com" {
		t.Fatalf("tls = %+v", node.TLS)
	}
	if len(node.TLS.ALPN) != 2 {
		t.Fatalf("alpn = %v", node.TLS.ALPN)
	}
}

func TestParseVLessReality(t *testing.T) {
	link := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443" +
		"?encryption=none&security=reality&sni=www.example.com&fp=chrome" +
		"&pbk=PUBLICKEY&sid=ab12&flow=xtls-rprx-vision&type=grpc&serviceName=gs#vless-1"

	node, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if node.Type != core.TypeVLESS || node.Flow != "xtls-rprx-vision" {
		t.Fatalf("node = %+v", node)
	}
	if node.TLS == nil || node.TLS.PublicKey != "PUBLICKEY" || node.TLS.ShortID != "ab12" {
		t.Fatalf("reality tls = %+v", node.TLS)
	}
	if node.TLS.Fingerprint != "chrome" {
		t.Fatalf("fingerprint = %q", node.TLS.Fingerprint)
	}
	if node.Transport == nil || node.Transport.Type != "grpc" || node.Transport.ServiceName != "gs" {
		t.Fatalf("transport = %+v", node.Transport)
	}
}

func TestParseTrojanAndHysteria2(t *testing.T) {
	trojan, err := ParseLink("trojan://pw%40ss@1.2.3.4:443?sni=example.com&type=ws&path=%2Fws&host=example.com#trojan-1")
	if err != nil {
		t.Fatalf("trojan: %v", err)
	}
	if trojan.Type != core.TypeTrojan || trojan.Password != "pw@ss" {
		t.Fatalf("trojan node = %+v", trojan)
	}
	if trojan.TLS == nil || !trojan.TLS.Enabled {
		t.Fatalf("trojan should imply TLS: %+v", trojan.TLS)
	}
	if trojan.Transport == nil || trojan.Transport.Path != "/ws" || trojan.Transport.Host != "example.com" {
		t.Fatalf("trojan transport = %+v", trojan.Transport)
	}

	hy2, err := ParseLink("hysteria2://secret@1.2.3.4:8443?sni=example.com&insecure=1#hy2-1")
	if err != nil {
		t.Fatalf("hysteria2: %v", err)
	}
	if hy2.Type != core.TypeHysteria2 || hy2.Password != "secret" || hy2.Port != 8443 {
		t.Fatalf("hy2 node = %+v", hy2)
	}
	if hy2.TLS == nil || !hy2.TLS.Enabled || !hy2.TLS.Insecure {
		t.Fatalf("hy2 tls = %+v", hy2.TLS)
	}
}

func TestParseSocksAndHTTP(t *testing.T) {
	socks, err := ParseLink("socks5://user:pass@127.0.0.1:1080#socks-1")
	if err != nil {
		t.Fatalf("socks: %v", err)
	}
	if socks.Type != core.TypeSocks5 || socks.Username != "user" || socks.Password != "pass" {
		t.Fatalf("socks node = %+v", socks)
	}
	httpNode, err := ParseLink("http://user:pass@127.0.0.1:8080#http-1")
	if err != nil {
		t.Fatalf("http: %v", err)
	}
	if httpNode.Type != core.TypeHTTP || httpNode.Port != 8080 {
		t.Fatalf("http node = %+v", httpNode)
	}
}

func TestParseLinkRejectsUnsupported(t *testing.T) {
	for _, link := range []string{
		"ssr://whatever",
		"tuic://x@1.2.3.4:443",
		"not-a-link",
		"ss://",
	} {
		if _, err := ParseLink(link); err == nil {
			t.Errorf("ParseLink(%q) succeeded, want error", link)
		}
	}
}
