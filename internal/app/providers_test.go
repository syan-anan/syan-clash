package app

import (
	"strings"
	"testing"

	"vvpn/internal/core"
)

func providerTestProfile() core.Profile {
	p := core.DefaultProfile()
	p.Nodes = []core.Node{{Name: "n1", Type: core.TypeSS, Server: "1.2.3.4", Port: 8388, Method: "aes-256-gcm", Password: "pw"}}
	p.Groups = []core.Group{{Name: "PROXY", Type: core.GroupSelect, Members: []string{"n1"}}}
	p.Final = "PROXY"
	p.Rules = []core.Rule{{Kind: core.RuleFinal, Value: "", Action: "PROXY"}}
	return p
}

func TestUpsertRuleProviderReplacesInPlace(t *testing.T) {
	p := providerTestProfile()
	first := core.RuleProvider{Name: "ads", Type: core.ProviderHTTP, Behavior: core.ProviderBehaviorClassical, URL: "https://a"}
	var err error
	p, err = upsertRuleProvider(p, first)
	if err != nil {
		t.Fatalf("upsertRuleProvider: %v", err)
	}
	second := core.RuleProvider{Name: "ADS", Type: core.ProviderHTTP, Behavior: core.ProviderBehaviorClassical, URL: "https://b"}
	p, err = upsertRuleProvider(p, second)
	if err != nil {
		t.Fatalf("upsertRuleProvider (replace): %v", err)
	}
	if len(p.RuleProviders) != 1 {
		t.Fatalf("replacing produced %d providers, want 1: %+v", len(p.RuleProviders), p.RuleProviders)
	}
	// The replacement keeps the new url but the original name's casing is gone:
	// the profile now describes exactly what was last submitted.
	if p.RuleProviders[0].URL != "https://b" {
		t.Errorf("the replacement did not take: %+v", p.RuleProviders[0])
	}
}

func TestRemoveRuleProviderTakesItsRulesWithIt(t *testing.T) {
	p := providerTestProfile()
	var err error
	p, err = upsertRuleProvider(p, core.RuleProvider{
		Name: "ads", Type: core.ProviderInline, Behavior: core.ProviderBehaviorDomain,
		Payload: []string{"ads.example"},
	})
	if err != nil {
		t.Fatalf("upsertRuleProvider: %v", err)
	}
	p.Rules = append([]core.Rule{
		{Kind: core.RuleProviderRef, Value: "ads", Action: core.ActionReject},
	}, p.Rules...)
	if err := p.Validate(); err != nil {
		t.Fatalf("the profile should be valid before the removal: %v", err)
	}

	p, removed, err := removeRuleProvider(p, "ads")
	if err != nil {
		t.Fatalf("removeRuleProvider: %v", err)
	}
	if removed != 1 {
		t.Errorf("removed %d rules, want 1", removed)
	}
	if len(p.RuleProviders) != 0 {
		t.Errorf("the provider survived: %+v", p.RuleProviders)
	}
	for _, r := range p.Rules {
		if r.Kind == core.RuleProviderRef {
			t.Errorf("a rule still references the removed provider: %+v", r)
		}
	}
	// Removing it must leave a profile that is still valid and compilable -
	// otherwise deleting a rule set would break the running core.
	if err := p.Validate(); err != nil {
		t.Fatalf("the profile became invalid after the removal: %v", err)
	}
	if _, err := core.Render("mihomo", p); err != nil {
		t.Errorf("mihomo cannot compile the profile after the removal: %v", err)
	}
	if _, _, err := removeRuleProvider(p, "ads"); err == nil {
		t.Error("removing a provider twice must report that it is gone")
	}
}

func TestUpsertRuleProviderRejectsInvalidDefinition(t *testing.T) {
	p := providerTestProfile()
	_, err := upsertRuleProvider(p, core.RuleProvider{Name: "x", Type: core.ProviderHTTP, Behavior: core.ProviderBehaviorDomain})
	if err == nil {
		t.Fatal("a url-less http provider must be rejected")
	}
	if !strings.Contains(err.Error(), "url") {
		t.Errorf("the error should name the missing url, got %v", err)
	}
}
