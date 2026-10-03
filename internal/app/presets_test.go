package app

import (
	"testing"

	"vvpn/internal/core"
)

// presetValidation makes sure every built-in preset produces a profile the
// emitters accept — a preset that cannot be compiled would break the client.
func TestPresetsAreValidAndCompilable(t *testing.T) {
	for _, preset := range Presets() {
		if preset.ID == "" || preset.Name == "" || preset.Description == "" {
			t.Errorf("preset %+v is missing metadata", preset)
		}
		if len(preset.Rules) == 0 {
			t.Errorf("preset %s has no rules", preset.ID)
		}
		for i, r := range preset.Rules {
			if err := r.Validate(); err != nil {
				t.Errorf("preset %s rule #%d is invalid: %v", preset.ID, i+1, err)
			}
			if r.Kind == core.RuleFinal {
				t.Errorf("preset %s rule #%d is a catch-all, which presets must not define", preset.ID, i+1)
			}
		}

		// The preset must survive validation and compilation on every core that
		// has an emitter.
		profile := core.DefaultProfile()
		profile.Nodes = []core.Node{{
			Name: "n1", Type: core.TypeSS, Server: "1.2.3.4", Port: 8388,
			Method: "aes-256-gcm", Password: "pw",
		}}
		profile.Groups = []core.Group{{Name: "PROXY", Type: core.GroupSelect, Members: []string{"n1"}}}
		profile.Rules = append(append([]core.Rule{}, preset.Rules...),
			core.Rule{Kind: core.RuleFinal, Value: "", Action: "PROXY"})
		profile.Final = "PROXY"
		if err := profile.Validate(); err != nil {
			t.Errorf("preset %s produces an invalid profile: %v", preset.ID, err)
			continue
		}
		for _, id := range []string{"sing-box", "mihomo", "xray"} {
			if _, err := core.Render(id, profile); err != nil {
				t.Errorf("preset %s cannot be compiled for %s: %v", preset.ID, id, err)
			}
		}
	}
}

func TestPresetIDsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range Presets() {
		if seen[p.ID] {
			t.Errorf("duplicate preset id %q", p.ID)
		}
		seen[p.ID] = true
	}
}

func TestRuleKeyIgnoresWhitespaceAndCase(t *testing.T) {
	a := core.Rule{Kind: " Domain-Suffix ", Value: " Example.COM ", Action: " DIRECT "}
	b := core.Rule{Kind: "domain-suffix", Value: "example.com", Action: "direct"}
	if ruleKey(a) != ruleKey(b) {
		t.Errorf("ruleKey should normalise case and whitespace: %q vs %q", ruleKey(a), ruleKey(b))
	}
	if ruleKey(a) == ruleKey(core.Rule{Kind: "domain-suffix", Value: "example.com", Action: "reject"}) {
		t.Error("ruleKey must distinguish different actions")
	}
}

func TestEnsurePrivateDirect(t *testing.T) {
	// An imported subscription usually replaces the rule list entirely, so the
	// private-network shortcuts have to be re-added or LAN traffic goes remote.
	imported := []core.Rule{
		{Kind: core.RuleDomainSuffix, Value: "cn", Action: core.ActionDirect},
		{Kind: core.RuleFinal, Value: "", Action: "PROXY"},
	}
	got := ensurePrivateDirect(imported)
	if len(got) != len(imported)+len(privateDirectRules) {
		t.Fatalf("got %d rules, want %d", len(got), len(imported)+len(privateDirectRules))
	}
	// The shortcuts must come first so nothing shadows them.
	for i, want := range privateDirectRules {
		if got[i].Kind != want.Kind || got[i].Value != want.Value {
			t.Errorf("rule #%d = %+v, want %+v", i, got[i], want)
		}
	}
	// Running it again must not duplicate anything.
	again := ensurePrivateDirect(got)
	if len(again) != len(got) {
		t.Errorf("ensurePrivateDirect is not idempotent: %d -> %d", len(got), len(again))
	}

	// An existing equivalent rule is respected rather than duplicated.
	existing := []core.Rule{{Kind: core.RuleIPCIDR, Value: "127.0.0.0/8", Action: core.ActionDirect}}
	withExisting := ensurePrivateDirect(existing)
	count := 0
	for _, r := range withExisting {
		if r.Kind == core.RuleIPCIDR && r.Value == "127.0.0.0/8" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("127.0.0.0/8 appears %d times, want 1", count)
	}
}
