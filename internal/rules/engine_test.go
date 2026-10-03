package rules

import (
	"net/netip"
	"testing"
)

func mustEngine(t *testing.T, rs ...Rule) *Engine {
	t.Helper()
	e, err := New(rs)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

func TestMatchDomainSuffix(t *testing.T) {
	e := mustEngine(t, Rule{Kind: KindDomainSuffix, Value: ".example.com", Action: string(ActionDirect)})

	for _, host := range []string{"example.com", "www.example.com", "a.b.example.com", "EXAMPLE.COM."} {
		res := e.Match(host, netip.Addr{}, 443)
		if res.Action != ActionDirect {
			t.Errorf("host %q: action = %q, want direct", host, res.Action)
		}
	}
	for _, host := range []string{"notexample.com", "example.com.evil.net"} {
		res := e.Match(host, netip.Addr{}, 443)
		if res.Action != ActionProxy {
			t.Errorf("host %q: action = %q, want proxy fallback", host, res.Action)
		}
	}
}

func TestMatchDomainKeyword(t *testing.T) {
	e := mustEngine(t,
		Rule{Kind: KindDomainKeyword, Value: "ads", Action: string(ActionReject)},
		Rule{Kind: KindFinal, Value: "", Action: string(ActionProxy)},
	)
	res := e.Match("cdn.ads.example.net", netip.Addr{}, 80)
	if res.Action != ActionReject {
		t.Fatalf("action = %q, want reject", res.Action)
	}
}

func TestMatchIPCIDRNeedsResolution(t *testing.T) {
	e := mustEngine(t,
		Rule{Kind: KindDomainSuffix, Value: "corp.local", Action: string(ActionDirect)},
		Rule{Kind: KindIPCIDR, Value: "10.0.0.0/8", Action: string(ActionDirect)},
		Rule{Kind: KindFinal, Value: "", Action: string(ActionProxy)},
	)

	res := e.Match("intranet.example.com", netip.Addr{}, 443)
	if !res.NeedResolve {
		t.Fatalf("expected NeedResolve for a hostname reaching an ip-cidr rule, got %+v", res)
	}

	res = e.Match("intranet.example.com", netip.MustParseAddr("10.1.2.3"), 443)
	if res.NeedResolve {
		t.Fatalf("resolved address should decide the route, got %+v", res)
	}
	if res.Action != ActionDirect {
		t.Fatalf("action = %q, want direct", res.Action)
	}

	res = e.Match("intranet.example.com", netip.MustParseAddr("203.0.113.9"), 443)
	if res.Action != ActionProxy {
		t.Fatalf("action = %q, want proxy", res.Action)
	}
}

// A domain rule after an ip-cidr rule must still win: the ip rule cannot decide
// without the address, but it must not block the rest of the scan.
func TestDomainRuleAfterIPRuleStillMatches(t *testing.T) {
	e := mustEngine(t,
		Rule{Kind: KindIPCIDR, Value: "10.0.0.0/8", Action: string(ActionDirect)},
		Rule{Kind: KindDomain, Value: "blocked.example", Action: string(ActionReject)},
		Rule{Kind: KindFinal, Value: "", Action: string(ActionProxy)},
	)

	res := e.Match("blocked.example", netip.Addr{}, 443)
	if res.NeedResolve {
		t.Fatalf("a later domain rule decides, so no resolution is needed: %+v", res)
	}
	if res.Action != ActionReject {
		t.Fatalf("action = %q, want reject", res.Action)
	}
}

// When only ip rules could match, the engine asks for resolution.
func TestIPOnlyMatchAsksForResolution(t *testing.T) {
	e := mustEngine(t,
		Rule{Kind: KindIPCIDR, Value: "10.0.0.0/8", Action: string(ActionDirect)},
		Rule{Kind: KindFinal, Value: "", Action: string(ActionProxy)},
	)
	res := e.Match("some.example", netip.Addr{}, 443)
	if !res.NeedResolve {
		t.Fatalf("expected NeedResolve when only ip rules could match: %+v", res)
	}
	res = e.Match("some.example", netip.MustParseAddr("10.9.9.9"), 443)
	if res.NeedResolve || res.Action != ActionDirect {
		t.Fatalf("after resolution: %+v, want direct", res)
	}
}

func TestMatchMappedIPv4(t *testing.T) {
	e := mustEngine(t,
		Rule{Kind: KindIPCIDR, Value: "192.168.0.0/16", Action: string(ActionDirect)},
		Rule{Kind: KindFinal, Value: "", Action: string(ActionProxy)},
	)
	res := e.Match("host.example.com", netip.MustParseAddr("::ffff:192.168.5.5"), 80)
	if res.Action != ActionDirect {
		t.Fatalf("IPv4-mapped address: action = %q, want direct", res.Action)
	}
}

func TestMatchPortAndFinal(t *testing.T) {
	e := mustEngine(t,
		Rule{Kind: KindPort, Value: "8000-8100", Action: string(ActionReject)},
		Rule{Kind: KindFinal, Value: "", Action: string(ActionDirect)},
	)
	if res := e.Match("anything.example", netip.Addr{}, 8080); res.Action != ActionReject {
		t.Fatalf("action = %q, want reject", res.Action)
	}
	if res := e.Match("anything.example", netip.Addr{}, 80); res.Action != ActionDirect {
		t.Fatalf("action = %q, want direct", res.Action)
	}
}

func TestFallbackWithoutFinalRule(t *testing.T) {
	e := mustEngine(t, Rule{Kind: KindDomain, Value: "only.example", Action: string(ActionDirect)})
	res := e.Match("other.example", netip.Addr{}, 443)
	if res.Action != ActionProxy || res.Index != -1 {
		t.Fatalf("fallback = %+v, want proxy with index -1", res)
	}
}

func TestNewRejectsBadRules(t *testing.T) {
	cases := []Rule{
		{Kind: "nope", Value: "x", Action: string(ActionProxy)},
		{Kind: KindIPCIDR, Value: "10.0.0.0/99", Action: string(ActionDirect)},
		{Kind: KindPort, Value: "70000", Action: string(ActionDirect)},
		{Kind: KindFinal, Value: "should-be-empty", Action: string(ActionDirect)},
		{Kind: KindDomain, Value: "x", Action: "explode"},
	}
	for _, c := range cases {
		if _, err := New([]Rule{c}); err == nil {
			t.Errorf("New(%+v) succeeded, want error", c)
		}
	}
}
