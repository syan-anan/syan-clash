package core

import "testing"

func TestIsSystemResolverMatchesEveryDelegation(t *testing.T) {
	for _, s := range []string{"", "  ", "local", "LOCAL", "system", "System", "dhcp://system", "dhcp://auto"} {
		if !IsSystemResolver(s) {
			t.Errorf("IsSystemResolver(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "https://223.5.5.5/dns-query", "tls://8.8.8.8", "223.5.5.5:53"} {
		if IsSystemResolver(s) {
			t.Errorf("IsSystemResolver(%q) = true, want false", s)
		}
	}
}

func TestDNSResolverKindNamesWhatTheUserAskedFor(t *testing.T) {
	cases := map[string]string{
		"1.1.1.1":                      "plain",
		"8.8.8.8:5353":                 "plain",
		"https://dns.google/dns-query": "doh",
		"h3://dns.google/dns-query":    "doh",
		"tls://1.1.1.1:853":            "dot",
		"dot://dns.quad9.net":          "dot",
		"quic://dns.adguard.com":       "doq",
		"dhcp://auto":                  "system",
		"dhcp://eth0":                  "dhcp",
		"system":                       "system",
		"local":                        "system",
	}
	for in, want := range cases {
		if got := DNSResolverKind(in); got != want {
			t.Errorf("DNSResolverKind(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidDNSStrategy(t *testing.T) {
	for _, s := range []string{"", "prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only"} {
		if !ValidDNSStrategy(s) {
			t.Errorf("ValidDNSStrategy(%q) = false", s)
		}
	}
	for _, s := range []string{"fastest", "prefer_ipv4 ", "UseIPv4"} {
		if ValidDNSStrategy(s) {
			t.Errorf("ValidDNSStrategy(%q) = true", s)
		}
	}
}

// Xray names a single address family while the neutral model names a
// preference, so the emitter has to translate. Passing "prefer_ipv4" through
// unchanged produced a configuration Xray refuses to load.
func TestXrayQueryStrategyUsesXraysOwnVocabulary(t *testing.T) {
	cases := map[string]string{
		"":            "",
		"prefer_ipv4": "UseIPv4",
		"ipv4_only":   "UseIPv4",
		"prefer_ipv6": "UseIPv6",
		"ipv6_only":   "UseIPv6",
		"nonsense":    "",
	}
	for in, want := range cases {
		if got := xrayQueryStrategy(in); got != want {
			t.Errorf("xrayQueryStrategy(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEmittedDNSStrategyIsValidForEachCore(t *testing.T) {
	p := DefaultProfile()
	p.DNS.Enabled = true
	p.DNS.Servers = []string{"1.1.1.1"}
	p.DNS.Strategy = "prefer_ipv4"

	xray, err := EmitXray(p)
	if err != nil {
		t.Fatalf("EmitXray: %v", err)
	}
	block, ok := xray["dns"].(map[string]any)
	if !ok {
		t.Fatal("EmitXray produced no dns block")
	}
	if block["queryStrategy"] != "UseIPv4" {
		t.Fatalf("xray queryStrategy = %v, want UseIPv4", block["queryStrategy"])
	}

	sing, err := EmitSingBox(p)
	if err != nil {
		t.Fatalf("EmitSingBox: %v", err)
	}
	singBlock, ok := sing["dns"].(map[string]any)
	if !ok {
		t.Fatal("EmitSingBox produced no dns block")
	}
	// sing-box uses the neutral names verbatim.
	if singBlock["strategy"] != "prefer_ipv4" {
		t.Fatalf("sing-box strategy = %v, want prefer_ipv4", singBlock["strategy"])
	}
}
