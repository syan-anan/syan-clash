package app

import (
	"testing"

	"vvpn/internal/core"
)

// ensurePrivateDirect must be robust no matter what the incoming rule list
// looks like. The loopback shortcut matters most: without it, requests to the
// local machine are sent to a remote node.
func TestEnsurePrivateDirectAlwaysAddsLoopback(t *testing.T) {
	cases := []struct {
		name  string
		rules []core.Rule
	}{
		{"nil", nil},
		{"empty", []core.Rule{}},
		{"only a final rule", []core.Rule{{Kind: core.RuleFinal, Value: "", Action: "PROXY"}}},
		{"provider rules", []core.Rule{
			{Kind: core.RuleGeoSite, Value: "cn", Action: core.ActionDirect},
			{Kind: core.RuleFinal, Value: "", Action: "PROXY"},
		}},
		{"a later conflicting rule", []core.Rule{
			{Kind: core.RuleIPCIDR, Value: "127.0.0.0/8", Action: core.ActionProxy},
			{Kind: core.RuleFinal, Value: "", Action: "PROXY"},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ensurePrivateDirect(c.rules)
			found := false
			for _, r := range got {
				if r.Kind == core.RuleIPCIDR && r.Value == "127.0.0.0/8" && r.Action == core.ActionDirect {
					found = true
					// It has to come before any conflicting rule to take effect.
					if &r != &got[0] {
						// just informational; position is checked separately
						_ = r
					}
				}
			}
			if !found {
				t.Errorf("ensurePrivateDirect did not add the loopback shortcut: %+v", got)
			}
			// Every shortcut must be present.
			for _, want := range privateDirectRules {
				ok := false
				for _, r := range got {
					if ruleIdentity(r) == ruleIdentity(want) {
						ok = true
						break
					}
				}
				if !ok {
					t.Errorf("shortcut %s %s is missing: %+v", want.Kind, want.Value, got)
				}
			}
			// The shortcuts lead, so a provider rule cannot shadow them.
			if len(got) > len(privateDirectRules) {
				for i, want := range privateDirectRules {
					if ruleIdentity(got[i]) != ruleIdentity(want) {
						t.Errorf("rule #%d = %+v, want %+v (shortcuts must come first)", i, got[i], want)
						break
					}
				}
			}
		})
	}
}

// A subscription import must never leave the profile without LAN/loopback
// shortcuts, whatever the provider returned.
func TestImportKeepsPrivateShortcuts(t *testing.T) {
	resetNodeSources()
	profile := core.DefaultProfile()
	profile.Nodes = []core.Node{testNode("n1")}
	profile.Groups = DefaultGroups(profile.Nodes)
	profile.Final = "PROXY"
	// Simulate what an import does to the rule list.
	profile.Rules = ensurePrivateDirect([]core.Rule{
		{Kind: core.RuleGeoSite, Value: "cn", Action: core.ActionDirect},
		{Kind: core.RuleFinal, Value: "", Action: "PROXY"},
	})
	profile.Rules = stripStaleFinal(profile.Rules)

	// The final rule is rebuilt, but the shortcuts must survive.
	hasLoopback := false
	for _, r := range profile.Rules {
		if r.Kind == core.RuleIPCIDR && r.Value == "127.0.0.0/8" {
			hasLoopback = true
		}
	}
	if !hasLoopback {
		t.Errorf("the loopback shortcut was lost: %+v", profile.Rules)
	}
	if err := profile.Validate(); err != nil {
		t.Errorf("the imported profile is invalid: %v", err)
	}
}
