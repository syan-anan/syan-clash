package subscription

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"vvpn/internal/core"
)

// Parse detects the payload format and returns the nodes it contains. It
// accepts, in order of detection: sing-box JSON, Clash YAML, a base64
// subscription blob, and plain share links (one per line).
func Parse(text string) ([]core.Node, error) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return nil, errors.New("subscription: empty payload")
	}
	if trimmed[0] == '{' || trimmed[0] == '[' {
		if nodes, err := parseJSON(trimmed); err == nil && len(nodes) > 0 {
			return nodes, nil
		}
	}
	if looksLikeClash(trimmed) {
		if profile, err := ParseClash(trimmed); err == nil && len(profile.Nodes) > 0 {
			return profile.Nodes, nil
		}
	}
	if decoded, ok := decodeBase64(trimmed); ok && strings.Contains(decoded, "://") {
		return ParseLines(decoded)
	}
	return ParseLines(trimmed)
}

// ParseLines parses one share link per line.
func ParseLines(text string) ([]core.Node, error) {
	var nodes []core.Node
	var firstErr error
	for _, field := range strings.Fields(text) {
		if field == "" || strings.HasPrefix(field, "#") || strings.HasPrefix(field, "//") {
			continue
		}
		node, err := ParseLink(field)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		nodes = append(nodes, node)
	}
	if len(nodes) == 0 {
		if firstErr != nil {
			return nil, firstErr
		}
		return nil, errors.New("subscription: no share links found")
	}
	return nodes, nil
}

func looksLikeClash(text string) bool {
	return strings.HasPrefix(text, "mixed-port:") ||
		strings.HasPrefix(text, "proxies:") ||
		strings.Contains(text, "\nproxies:") ||
		strings.Contains(text, "\nproxy-groups:")
}

// parseJSON reads a sing-box configuration document or a bare outbound list.
func parseJSON(text string) ([]core.Node, error) {
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(text), &doc); err != nil {
		var list []map[string]any
		if err2 := json.Unmarshal([]byte(text), &list); err2 != nil {
			return nil, err
		}
		doc.Outbounds = list
	}
	nodes := make([]core.Node, 0, len(doc.Outbounds))
	for _, ob := range doc.Outbounds {
		if node, ok := nodeFromSingBox(ob); ok {
			nodes = append(nodes, node)
		}
	}
	if len(nodes) == 0 {
		return nil, errors.New("subscription: no usable outbounds in the JSON document")
	}
	return nodes, nil
}

func nodeFromSingBox(ob map[string]any) (core.Node, bool) {
	server := jsonString(ob, "server")
	port := jsonInt(ob, "server_port")
	if server == "" || port == 0 {
		return core.Node{}, false
	}
	node := core.Node{
		Name:   jsonString(ob, "tag"),
		Server: server,
		Port:   port,
		UDP:    true,
	}
	switch jsonString(ob, "type") {
	case "socks":
		node.Type = core.TypeSocks5
		node.Username = jsonString(ob, "username")
		node.Password = jsonString(ob, "password")
	case "http":
		node.Type = core.TypeHTTP
		node.Username = jsonString(ob, "username")
		node.Password = jsonString(ob, "password")
	case "shadowsocks":
		node.Type = core.TypeSS
		node.Method = jsonString(ob, "method")
		node.Password = jsonString(ob, "password")
	case "vmess":
		node.Type = core.TypeVMess
		node.UUID = jsonString(ob, "uuid")
		node.AlterID = jsonInt(ob, "alter_id")
		node.Security = jsonString(ob, "security")
	case "vless":
		node.Type = core.TypeVLESS
		node.UUID = jsonString(ob, "uuid")
		node.Flow = jsonString(ob, "flow")
	case "trojan":
		node.Type = core.TypeTrojan
		node.Password = jsonString(ob, "password")
	case "hysteria2":
		node.Type = core.TypeHysteria2
		node.Password = jsonString(ob, "password")
	default:
		return core.Node{}, false
	}
	if tls, ok := jsonMap(ob, "tls"); ok {
		node.TLS = tlsFromSingBox(tls)
	}
	if tr, ok := jsonMap(ob, "transport"); ok {
		node.Transport = transportFromSingBox(tr)
	}
	if node.Name == "" {
		node.Name = fmt.Sprintf("%s-%s-%d", node.Type, server, port)
	}
	return node, true
}

func tlsFromSingBox(tls map[string]any) *core.TLS {
	out := &core.TLS{
		Enabled:    true,
		ServerName: jsonString(tls, "server_name"),
		Insecure:   jsonBool(tls, "insecure"),
		ALPN:       jsonStrings(tls, "alpn"),
	}
	if utls, ok := jsonMap(tls, "utls"); ok {
		out.Fingerprint = jsonString(utls, "fingerprint")
	}
	if reality, ok := jsonMap(tls, "reality"); ok {
		out.PublicKey = jsonString(reality, "public_key")
		out.ShortID = jsonString(reality, "short_id")
	}
	return out
}

func transportFromSingBox(tr map[string]any) *core.Transport {
	switch jsonString(tr, "type") {
	case "ws":
		out := &core.Transport{Type: "ws", Path: jsonString(tr, "path")}
		if headers, ok := jsonMap(tr, "headers"); ok {
			out.Host = jsonString(headers, "Host")
			if out.Host == "" {
				out.Host = jsonString(headers, "host")
			}
		}
		return out
	case "grpc":
		return &core.Transport{Type: "grpc", ServiceName: jsonString(tr, "service_name")}
	case "http":
		out := &core.Transport{Type: "http", Path: jsonString(tr, "path")}
		if hosts := jsonStrings(tr, "host"); len(hosts) > 0 {
			out.Host = hosts[0]
		}
		return out
	default:
		return nil
	}
}

func jsonString(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func jsonInt(m map[string]any, key string) int {
	if v, ok := m[key]; ok {
		if f, ok := v.(float64); ok {
			return int(f)
		}
	}
	return 0
}

func jsonBool(m map[string]any, key string) bool {
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func jsonMap(m map[string]any, key string) (map[string]any, bool) {
	if v, ok := m[key]; ok {
		if sub, ok := v.(map[string]any); ok {
			return sub, true
		}
	}
	return nil, false
}

func jsonStrings(m map[string]any, key string) []string {
	v, ok := m[key]
	if !ok {
		return nil
	}
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}
