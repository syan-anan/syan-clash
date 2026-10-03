package core

import "strings"

// The resolver vocabulary. It lives beside the neutral model because three
// packages need the same answers: the emitters (which resolvers a core can
// actually use), the app layer (what to refuse before writing a profile) and
// the diagnostics (what to say about each entry in the leak panel).

// DNSStrategies are the resolution strategies the emitters accept. The empty
// string means "let the core decide".
var DNSStrategies = []string{"", "prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only"}

// ValidDNSStrategy reports whether a strategy is one the emitters understand.
func ValidDNSStrategy(s string) bool {
	for _, want := range DNSStrategies {
		if s == want {
			return true
		}
	}
	return false
}

// IsSystemResolver reports whether an entry delegates to the operating system
// instead of naming a server. Under a tunnel those entries are unusable: the OS
// resolver asks the link the tunnel just took over, dns-hijack hands the query
// straight back, and the lookup waits on itself forever.
func IsSystemResolver(addr string) bool {
	switch strings.ToLower(strings.TrimSpace(addr)) {
	case "", "local", "system", "dhcp://system", "dhcp://auto":
		return true
	}
	return false
}

// DNSResolverKind classifies one entry: what the user asked for, and whether
// it travels in clear text.
func DNSResolverKind(addr string) string {
	s := strings.ToLower(strings.TrimSpace(addr))
	switch {
	case IsSystemResolver(s):
		return "system"
	case strings.HasPrefix(s, "https://"), strings.HasPrefix(s, "h3://"):
		return "doh"
	case strings.HasPrefix(s, "tls://"), strings.HasPrefix(s, "dot://"):
		return "dot"
	case strings.HasPrefix(s, "quic://"):
		return "doq"
	case strings.HasPrefix(s, "dhcp://"):
		return "dhcp"
	default:
		return "plain"
	}
}
