package app

import (
	"net/netip"
	"testing"

	"vvpn/internal/config"
	"vvpn/internal/core"
	"vvpn/internal/rules"
)

func netipZero() netip.Addr { return netip.Addr{} }

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return addr
}

// The built-in proxy engine and the neutral profile must agree on rules: a user
// editing rules in the UI expects them to apply no matter which mode runs.
func TestBuiltinRulesFollowTheProfile(t *testing.T) {
	cfg := config.Default()
	cfg.Core.Profile = &core.Profile{
		Inbounds: []core.Inbound{{Type: core.InboundMixed, Tag: "in", Listen: "127.0.0.1", Port: 7890}},
		Rules: []core.Rule{
			{Kind: core.RuleDomain, Value: "blocked.example", Action: core.ActionReject},
			{Kind: core.RuleIPCIDR, Value: "10.0.0.0/8", Action: core.ActionDirect},
			{Kind: core.RuleProcessName, Value: "chrome.exe", Action: core.ActionDirect},
			{Kind: core.RuleGeoSite, Value: "cn", Action: core.ActionDirect},
			{Kind: core.RuleFinal, Value: "", Action: core.ActionProxy},
		},
	}

	got := builtinRules(cfg)
	if len(got) != len(cfg.Core.Profile.Rules) {
		t.Fatalf("builtinRules returned %d rules, want %d", len(got), len(cfg.Core.Profile.Rules))
	}
	engine, err := rules.New(got)
	if err != nil {
		t.Fatalf("the derived rule list must compile: %v", err)
	}

	// The reject rule from the profile must be honoured by the built-in engine.
	res := engine.Match("blocked.example", netipZero(), 443)
	if res.Action != rules.ActionReject {
		t.Errorf("blocked.example -> %q, want reject (the profile rule was ignored)", res.Action)
	}
	// Private addresses stay direct.
	if got := engine.Match("", mustAddr(t, "10.1.2.3"), 443); got.Action != rules.ActionDirect {
		t.Errorf("10.1.2.3 -> %q, want direct", got.Action)
	}
	// Rules the built-in engine cannot evaluate are skipped, not fatal.
	// A host reaching an ip-cidr rule reports NeedResolve first; the caller
	// resolves and matches again, which is what this second call models.
	needResolve := engine.Match("example.com", netipZero(), 443)
	if !needResolve.NeedResolve {
		t.Fatalf("expected NeedResolve before the address is known, got %+v", needResolve)
	}
	if got := engine.Match("example.com", mustAddr(t, "203.0.113.9"), 443); got.Action != rules.ActionProxy {
		t.Errorf("unmatched host -> %q, want the profile's proxy fallback", got.Action)
	}
}

func TestBuiltinRulesWithoutProfileUseLegacyRules(t *testing.T) {
	cfg := config.Default()
	cfg.Rules = []rules.Rule{{Kind: rules.KindDomain, Value: "x.example", Action: string(rules.ActionReject)}}
	got := builtinRules(cfg)
	if len(got) != 1 || got[0].Value != "x.example" {
		t.Fatalf("builtinRules = %+v, want the legacy rule list", got)
	}
}

func TestBuiltinActionMapping(t *testing.T) {
	cases := map[string]string{
		core.ActionDirect: string(rules.ActionDirect),
		core.ActionReject: string(rules.ActionReject),
		core.ActionProxy:  string(rules.ActionProxy),
		"PROXY":           string(rules.ActionProxy),
		"":                string(rules.ActionProxy),
	}
	for in, want := range cases {
		if got := builtinAction(in); got != want {
			t.Errorf("builtinAction(%q) = %q, want %q", in, got, want)
		}
	}
}
