// Package subscription turns subscription payloads into neutral nodes: share
// links (ss/vmess/vless/trojan/hysteria2/socks/http), base64 subscription
// blobs, Clash YAML configurations and sing-box JSON documents.
package subscription

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"vvpn/internal/core"
)

// ParseLink converts one share link into a neutral node.
func ParseLink(link string) (core.Node, error) {
	link = strings.TrimSpace(link)
	if link == "" {
		return core.Node{}, fmt.Errorf("subscription: empty link")
	}
	scheme, rest, ok := strings.Cut(link, "://")
	if !ok {
		return core.Node{}, fmt.Errorf("subscription: %q is not a share link", link)
	}
	switch strings.ToLower(scheme) {
	case "ss":
		return parseSS(rest)
	case "vmess":
		return parseVMess(rest)
	case "vless":
		return parseVLess(rest)
	case "trojan":
		return parseTrojan(rest)
	case "hysteria2", "hy2":
		return parseHysteria2(rest)
	case "socks", "socks5":
		return parseSocks(rest)
	case "http", "https":
		return parseHTTPProxy(rest, strings.ToLower(scheme))
	default:
		return core.Node{}, fmt.Errorf("subscription: unsupported scheme %q", scheme)
	}
}

// decodeBase64 accepts standard and URL-safe base64, with or without padding,
// which is what subscription providers actually emit.
func decodeBase64(s string) (string, bool) {
	s = strings.TrimSpace(s)
	s = strings.NewReplacer("\n", "", "\r", "", " ", "").Replace(s)
	if s == "" {
		return "", false
	}
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		if raw, err := enc.DecodeString(s); err == nil {
			return string(raw), true
		}
	}
	return "", false
}

func splitFragment(s string) (string, string) {
	if i := strings.Index(s, "#"); i >= 0 {
		name, err := url.QueryUnescape(s[i+1:])
		if err != nil {
			name = s[i+1:]
		}
		return s[:i], strings.TrimSpace(name)
	}
	return s, ""
}

func splitHostPort(hostport string) (string, int, error) {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return "", 0, fmt.Errorf("subscription: missing host:port")
	}
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", 0, fmt.Errorf("subscription: %q is not host:port", hostport)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("subscription: invalid port %q", portStr)
	}
	return host, port, nil
}

func nameOrDefault(name, host string, port int) string {
	if strings.TrimSpace(name) != "" {
		return name
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func parseSS(rest string) (core.Node, error) {
	body, name := splitFragment(rest)
	var method, password, hostport string
	if at := strings.LastIndex(body, "@"); at >= 0 {
		userinfo := body[:at]
		hostport = body[at+1:]
		if decoded, ok := decodeBase64(userinfo); ok && strings.Contains(decoded, ":") {
			method, password, _ = strings.Cut(decoded, ":")
		} else {
			method, password, _ = strings.Cut(userinfo, ":")
		}
	} else {
		// Legacy form: the whole body is base64("method:password@host:port").
		decoded, ok := decodeBase64(body)
		if !ok {
			return core.Node{}, fmt.Errorf("subscription: ss link is neither SIP002 nor legacy base64")
		}
		at := strings.LastIndex(decoded, "@")
		if at < 0 {
			return core.Node{}, fmt.Errorf("subscription: ss link has no host part")
		}
		method, password, _ = strings.Cut(decoded[:at], ":")
		hostport = decoded[at+1:]
	}
	if q := strings.Index(hostport, "?"); q >= 0 {
		hostport = hostport[:q]
	}
	host, port, err := splitHostPort(hostport)
	if err != nil {
		return core.Node{}, err
	}
	if method == "" || password == "" {
		return core.Node{}, fmt.Errorf("subscription: ss link is missing method or password")
	}
	return core.Node{
		Name:     nameOrDefault(name, host, port),
		Type:     core.TypeSS,
		Server:   host,
		Port:     port,
		Method:   method,
		Password: password,
		UDP:      true,
	}, nil
}

type vmessJSON struct {
	PS   string `json:"ps"`
	Add  string `json:"add"`
	Port any    `json:"port"`
	ID   string `json:"id"`
	Aid  any    `json:"aid"`
	Scy  string `json:"scy"`
	Net  string `json:"net"`
	Type string `json:"type"`
	Host string `json:"host"`
	Path string `json:"path"`
	TLS  string `json:"tls"`
	SNI  string `json:"sni"`
	ALPN any    `json:"alpn"`
	FP   string `json:"fp"`
}

func parseVMess(rest string) (core.Node, error) {
	body, _ := splitFragment(rest)
	decoded, ok := decodeBase64(body)
	if !ok {
		return core.Node{}, fmt.Errorf("subscription: vmess link is not base64")
	}
	var v vmessJSON
	if err := json.Unmarshal([]byte(decoded), &v); err != nil {
		return core.Node{}, fmt.Errorf("subscription: vmess payload: %w", err)
	}
	port := anyInt(v.Port)
	if v.Add == "" || port == 0 || v.ID == "" {
		return core.Node{}, fmt.Errorf("subscription: vmess link is missing add/port/id")
	}
	node := core.Node{
		Name:     nameOrDefault(v.PS, v.Add, port),
		Type:     core.TypeVMess,
		Server:   v.Add,
		Port:     port,
		UUID:     v.ID,
		AlterID:  anyInt(v.Aid),
		Security: defaultString(v.Scy, "auto"),
		UDP:      true,
	}
	node.Transport = transportFrom(v.Net, v.Type, v.Path, v.Host, "")
	if strings.EqualFold(v.TLS, "tls") || v.SNI != "" {
		node.TLS = &core.TLS{
			Enabled:     true,
			ServerName:  defaultString(v.SNI, v.Host),
			ALPN:        anyStrings(v.ALPN),
			Fingerprint: v.FP,
		}
	}
	return node, nil
}

func parseVLess(rest string) (core.Node, error) {
	u, err := url.Parse("vless://" + rest)
	if err != nil {
		return core.Node{}, fmt.Errorf("subscription: vless link: %w", err)
	}
	host, port, err := splitHostPort(u.Host)
	if err != nil {
		return core.Node{}, err
	}
	q := u.Query()
	uuid := u.User.Username()
	if uuid == "" {
		return core.Node{}, fmt.Errorf("subscription: vless link has no uuid")
	}
	node := core.Node{
		Name:   nameOrDefault(u.Fragment, host, port),
		Type:   core.TypeVLESS,
		Server: host,
		Port:   port,
		UUID:   uuid,
		Flow:   q.Get("flow"),
		UDP:    true,
	}
	node.Transport = transportFrom(q.Get("type"), q.Get("headerType"), q.Get("path"), q.Get("host"), q.Get("serviceName"))
	node.TLS = tlsFromQuery(q)
	return node, nil
}

func parseTrojan(rest string) (core.Node, error) {
	u, err := url.Parse("trojan://" + rest)
	if err != nil {
		return core.Node{}, fmt.Errorf("subscription: trojan link: %w", err)
	}
	host, port, err := splitHostPort(u.Host)
	if err != nil {
		return core.Node{}, err
	}
	password := u.User.Username()
	if pw, ok := u.User.Password(); ok {
		password += ":" + pw
	}
	if password == "" {
		return core.Node{}, fmt.Errorf("subscription: trojan link has no password")
	}
	q := u.Query()
	node := core.Node{
		Name:     nameOrDefault(u.Fragment, host, port),
		Type:     core.TypeTrojan,
		Server:   host,
		Port:     port,
		Password: password,
		UDP:      true,
	}
	node.Transport = transportFrom(q.Get("type"), q.Get("headerType"), q.Get("path"), q.Get("host"), q.Get("serviceName"))
	tls := tlsFromQuery(q)
	if tls == nil {
		tls = &core.TLS{Enabled: true}
	}
	if tls.ServerName == "" {
		tls.ServerName = q.Get("sni")
	}
	node.TLS = tls
	return node, nil
}

func parseHysteria2(rest string) (core.Node, error) {
	u, err := url.Parse("hysteria2://" + rest)
	if err != nil {
		return core.Node{}, fmt.Errorf("subscription: hysteria2 link: %w", err)
	}
	host, port, err := splitHostPort(u.Host)
	if err != nil {
		return core.Node{}, err
	}
	auth := u.User.Username()
	if pw, ok := u.User.Password(); ok {
		auth += ":" + pw
	}
	if auth == "" {
		return core.Node{}, fmt.Errorf("subscription: hysteria2 link has no auth")
	}
	q := u.Query()
	tls := tlsFromQuery(q)
	if tls == nil {
		tls = &core.TLS{Enabled: true}
	}
	if tls.ServerName == "" {
		tls.ServerName = q.Get("sni")
	}
	return core.Node{
		Name:     nameOrDefault(u.Fragment, host, port),
		Type:     core.TypeHysteria2,
		Server:   host,
		Port:     port,
		Password: auth,
		TLS:      tls,
		UDP:      true,
	}, nil
}

func parseSocks(rest string) (core.Node, error) {
	u, err := url.Parse("socks5://" + rest)
	if err != nil {
		return core.Node{}, fmt.Errorf("subscription: socks link: %w", err)
	}
	host, port, err := splitHostPort(u.Host)
	if err != nil {
		return core.Node{}, err
	}
	node := core.Node{
		Name:   nameOrDefault(u.Fragment, host, port),
		Type:   core.TypeSocks5,
		Server: host,
		Port:   port,
		UDP:    true,
	}
	if u.User != nil {
		node.Username = u.User.Username()
		if pw, ok := u.User.Password(); ok {
			node.Password = pw
		}
	}
	return node, nil
}

func parseHTTPProxy(rest, scheme string) (core.Node, error) {
	u, err := url.Parse(scheme + "://" + rest)
	if err != nil {
		return core.Node{}, fmt.Errorf("subscription: http proxy link: %w", err)
	}
	host, port, err := splitHostPort(u.Host)
	if err != nil {
		return core.Node{}, err
	}
	node := core.Node{
		Name:   nameOrDefault(u.Fragment, host, port),
		Type:   core.TypeHTTP,
		Server: host,
		Port:   port,
	}
	if u.User != nil {
		node.Username = u.User.Username()
		if pw, ok := u.User.Password(); ok {
			node.Password = pw
		}
	}
	if scheme == "https" {
		node.TLS = &core.TLS{Enabled: true, ServerName: u.Query().Get("sni")}
	}
	return node, nil
}

// transportFrom maps the link's transport fields onto the neutral transport.
func transportFrom(network, headerType, path, host, serviceName string) *core.Transport {
	network = strings.ToLower(strings.TrimSpace(network))
	switch network {
	case "", "tcp":
		if strings.EqualFold(headerType, "http") {
			return &core.Transport{Type: "http", Path: path, Host: host}
		}
		return nil
	case "ws", "websocket":
		return &core.Transport{Type: "ws", Path: path, Host: host}
	case "grpc":
		return &core.Transport{Type: "grpc", ServiceName: serviceName}
	case "http", "h2", "h2c":
		return &core.Transport{Type: "http", Path: path, Host: host}
	default:
		return nil
	}
}

// tlsFromQuery reads the TLS/REALITY parameters shared by the URL-style links.
func tlsFromQuery(q url.Values) *core.TLS {
	security := strings.ToLower(q.Get("security"))
	reality := security == "reality" || q.Get("pbk") != ""
	tlsEnabled := security == "tls" || reality || q.Get("sni") != "" || q.Get("alpn") != ""
	if !tlsEnabled {
		return nil
	}
	tls := &core.TLS{
		Enabled:     true,
		ServerName:  q.Get("sni"),
		Fingerprint: q.Get("fp"),
		Insecure:    truthy(q.Get("allowInsecure")) || truthy(q.Get("insecure")),
		ALPN:        splitList(q.Get("alpn")),
	}
	if reality {
		tls.PublicKey = q.Get("pbk")
		tls.ShortID = q.Get("sid")
	}
	if tls.ServerName == "" {
		tls.ServerName = q.Get("host")
	}
	return tls
}

func splitList(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '|' })
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func defaultString(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

// anyInt converts the number-or-string values that appear in share links.
func anyInt(v any) int {
	switch t := v.(type) {
	case nil:
		return 0
	case float64:
		return int(t)
	case int:
		return t
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(t))
		if err != nil {
			return 0
		}
		return n
	default:
		return 0
	}
}

func anyStrings(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s := strings.TrimSpace(fmt.Sprint(item)); s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		return splitList(t)
	default:
		return nil
	}
}
