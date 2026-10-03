package core

import (
	"encoding/json"
	"strings"
	"testing"
)

// providerProfile is the smallest profile that can carry rule sets: one node,
// one group, and the three vehicle types mihomo understands.
func providerProfile() Profile {
	p := Profile{
		Log:      "info",
		Inbounds: []Inbound{{Type: InboundMixed, Tag: "mixed-in", Listen: "127.0.0.1", Port: 7890}},
		Nodes: []Node{
			{Name: "n1", Type: TypeSS, Server: "1.2.3.4", Port: 8388, Method: "aes-256-gcm", Password: "pw"},
		},
		Groups: []Group{{Name: "PROXY", Type: GroupSelect, Members: []string{"n1"}}},
		Final:  "PROXY",
	}
	p.RuleProviders = []RuleProvider{
		{Name: "ads", Type: ProviderHTTP, Behavior: ProviderBehaviorClassical,
			URL: "https://example.com/ads.yaml"},
		{Name: "cn-domains", Type: ProviderInline, Behavior: ProviderBehaviorDomain,
			Payload: []string{"example.cn", "example.com.cn"}},
		{Name: "lan", Type: ProviderFile, Behavior: ProviderBehaviorIPCIDR,
			Path: "ruleset/lan.yaml"},
	}
	p.Rules = []Rule{
		{Kind: RuleProviderRef, Value: "ads", Action: ActionReject},
		{Kind: RuleProviderRef, Value: "cn-domains", Action: ActionDirect},
		{Kind: RuleProviderRef, Value: "lan", Action: ActionDirect},
		{Kind: RuleFinal, Value: "", Action: "PROXY"},
	}
	return p
}

// The whole point of the feature: the set is described once, the rule list only
// names it, and mihomo gets both halves.
func TestMihomoEmitsRuleProvidersAndRuleSetRules(t *testing.T) {
	p := providerProfile()
	doc, err := EmitMihomo(p)
	if err != nil {
		t.Fatalf("EmitMihomo: %v", err)
	}
	text := yamlEmit(doc)
	for _, want := range []string{
		"rule-providers:\n",
		"  ads:\n",
		"    type: http\n",
		"    behavior: classical\n",
		"    url: https://example.com/ads.yaml\n",
		"    interval: 86400\n",
		"  cn-domains:\n",
		"    type: inline\n",
		"    behavior: domain\n",
		"    payload:\n",
		"      - example.cn\n",
		"  lan:\n",
		"    type: file\n",
		"    behavior: ipcidr\n",
		"    path: ruleset/lan.yaml\n",
		"  - RULE-SET,ads,REJECT\n",
		"  - RULE-SET,cn-domains,DIRECT\n",
		"  - RULE-SET,lan,DIRECT\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("mihomo config is missing %q\n%s", want, text)
		}
	}
	// The block must come before the rules that name it: mihomo refuses a
	// document whose RULE-SET has no matching provider.
	if strings.Index(text, "rule-providers:") > strings.Index(text, "rules:") {
		t.Errorf("rule-providers must be written before rules:\n%s", text)
	}
	// An explicit interval is passed through untouched.
	p.RuleProviders[0].Interval = 3600
	doc, err = EmitMihomo(p)
	if err != nil {
		t.Fatalf("EmitMihomo: %v", err)
	}
	if text := yamlEmit(doc); !strings.Contains(text, "    interval: 3600\n") {
		t.Errorf("explicit interval was not honoured:\n%s", text)
	}
}

// A profile without rule sets must not gain an empty block: that would change
// every existing configuration for no reason.
func TestMihomoOmitsRuleProvidersWhenEmpty(t *testing.T) {
	doc, err := EmitMihomo(sampleProfile())
	if err != nil {
		t.Fatalf("EmitMihomo: %v", err)
	}
	if text := yamlEmit(doc); strings.Contains(text, "rule-providers") {
		t.Errorf("an empty profile emitted a rule-providers block:\n%s", text)
	}
}

func TestSingBoxEmitsRuleSetsForProviders(t *testing.T) {
	doc, warnings, err := EmitSingBoxWithWarnings(providerProfile())
	if err != nil {
		t.Fatalf("EmitSingBoxWithWarnings: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	text := string(raw)
	// encoding/json sorts map keys, so each expectation is a single
	// key/value pair rather than a run of them.
	for _, want := range []string{
		`"type":"remote"`,
		`"tag":"ads"`,
		`"tag":"lan"`,
		`"tag":"cn-domains"`,
		`"type":"local"`,
		`"type":"inline"`,
		`"format":"source"`,
		`"download_detour":"direct"`,
		`"update_interval":"86400s"`,
		`"path":"ruleset/lan.yaml"`,
		`"domain_suffix":["example.cn","example.com.cn"]`,
		`"rule_set":["ads"]`,
		`"rule_set":["cn-domains"]`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("sing-box config is missing %s\n%s", want, text)
		}
	}
}

// A classical payload is rule text in mihomo's syntax. sing-box has no inline
// form for it, so the rule has to be dropped *and* reported - a rule pointing
// at a tag that was never declared would make sing-box refuse to start.
func TestSingBoxReportsAndDropsUnrepresentableProvider(t *testing.T) {
	p := providerProfile()
	p.RuleProviders = []RuleProvider{{
		Name: "ads", Type: ProviderInline, Behavior: ProviderBehaviorClassical,
		Payload: []string{"DOMAIN-SUFFIX,ads.example"},
	}}
	p.Rules = []Rule{
		{Kind: RuleProviderRef, Value: "ads", Action: ActionReject},
		{Kind: RuleDomainSuffix, Value: "keep.example", Action: ActionDirect},
		{Kind: RuleFinal, Value: "", Action: "PROXY"},
	}
	doc, warnings, err := EmitSingBoxWithWarnings(p)
	if err != nil {
		t.Fatalf("EmitSingBoxWithWarnings: %v", err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "ads") {
		t.Fatalf("expected one warning naming the dropped set, got %v", warnings)
	}
	raw, _ := json.Marshal(doc)
	text := string(raw)
	if strings.Contains(text, `"rule_set"`) {
		t.Errorf("a rule still references the dropped rule set:\n%s", text)
	}
	if !strings.Contains(text, "keep.example") {
		t.Errorf("the following rule was dropped along with it:\n%s", text)
	}
}

func TestXraySkipsRuleProviderRulesWithWarning(t *testing.T) {
	p := providerProfile()
	p.Inbounds = []Inbound{{Type: InboundSocks, Tag: "in", Listen: "127.0.0.1", Port: 7890}}
	doc, warnings, err := EmitXrayWithWarnings(p)
	if err != nil {
		t.Fatalf("EmitXrayWithWarnings: %v", err)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "ads") && strings.Contains(w, "规则集") {
			found = true
		}
	}
	if !found {
		t.Errorf("Xray did not report the skipped rule set: %v", warnings)
	}
	raw, _ := json.Marshal(doc)
	if strings.Contains(string(raw), "RULE-SET") {
		t.Errorf("Xray config leaked a RULE-SET reference:\n%s", raw)
	}
}

func TestProfileRejectsDanglingRuleProviderReference(t *testing.T) {
	p := providerProfile()
	p.RuleProviders = nil
	err := p.Validate()
	if err == nil {
		t.Fatal("a rule naming an undefined rule provider must be rejected")
	}
	if !strings.Contains(err.Error(), "unknown rule provider") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRuleProviderValidation(t *testing.T) {
	cases := []struct {
		name string
		rp   RuleProvider
		ok   bool
	}{
		{"http needs url", RuleProvider{Name: "a", Type: ProviderHTTP, Behavior: ProviderBehaviorDomain}, false},
		{"file needs path", RuleProvider{Name: "a", Type: ProviderFile, Behavior: ProviderBehaviorDomain}, false},
		{"inline needs payload", RuleProvider{Name: "a", Type: ProviderInline, Behavior: ProviderBehaviorDomain}, false},
		{"unknown type", RuleProvider{Name: "a", Type: "rsync", Behavior: ProviderBehaviorDomain}, false},
		{"unknown behavior", RuleProvider{Name: "a", Type: ProviderHTTP, Behavior: "nope", URL: "u"}, false},
		{"unknown format", RuleProvider{Name: "a", Type: ProviderHTTP, Behavior: ProviderBehaviorDomain, URL: "u", Format: "csv"}, false},
		{"negative interval", RuleProvider{Name: "a", Type: ProviderHTTP, Behavior: ProviderBehaviorDomain, URL: "u", Interval: -1}, false},
		{"no name", RuleProvider{Type: ProviderHTTP, Behavior: ProviderBehaviorDomain, URL: "u"}, false},
		{"http ok", RuleProvider{Name: "a", Type: ProviderHTTP, Behavior: ProviderBehaviorDomain, URL: "u"}, true},
		{"file ok", RuleProvider{Name: "a", Type: ProviderFile, Behavior: ProviderBehaviorIPCIDR, Path: "p"}, true},
		{"inline mrs ok", RuleProvider{Name: "a", Type: ProviderHTTP, Behavior: ProviderBehaviorDomain, URL: "u", Format: ProviderFormatMrs}, true},
	}
	for _, c := range cases {
		err := c.rp.Validate()
		if c.ok && err != nil {
			t.Errorf("%s: unexpected error %v", c.name, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s: expected an error", c.name)
		}
	}
}

func TestProfileRejectsDuplicateRuleProviderNames(t *testing.T) {
	p := providerProfile()
	p.RuleProviders = append(p.RuleProviders, p.RuleProviders[0])
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate rule provider") {
		t.Errorf("expected a duplicate-name error, got %v", err)
	}
}

// A provider the user added has to show up in the generated document even
// before a rule names it, otherwise the UI and the config disagree about what
// exists.
func TestSingBoxDeclaresEveryRepresentableProvider(t *testing.T) {
	p := providerProfile()
	p.Rules = []Rule{{Kind: RuleDomainSuffix, Value: "example.com", Action: ActionDirect}, {Kind: RuleFinal, Value: "", Action: "PROXY"}}
	doc, warnings, err := EmitSingBoxWithWarnings(p)
	if err != nil {
		t.Fatalf("EmitSingBoxWithWarnings: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unreferenced providers must not warn: %v", warnings)
	}
	raw, _ := json.Marshal(doc)
	text := string(raw)
	for _, want := range []string{`"tag":"ads"`, `"tag":"lan"`, `"tag":"cn-domains"`} {
		if !strings.Contains(text, want) {
			t.Errorf("sing-box config is missing %s\n%s", want, text)
		}
	}
	// route.rule_set itself is the declaration block; what must be absent is a
	// *rule* that names one, because no rule does.
	if strings.Count(text, `"rule_set"`) != 1 {
		t.Errorf("route.rules should not reference a rule set, got %d mentions:\n%s", strings.Count(text, `"rule_set"`), text)
	}
}
