package app

import (
	"testing"

	"vvpn/internal/core"
)

// The bug this guards: removing the only subscription left rules whose action
// still pointed at the removed airport selector, so profile validation failed
// with "rule #N targets unknown outbound" and the deletion answered HTTP 400
// even though the subscription itself was already gone.
func TestRebindStaleTargetsAfterRemovingSubscription(t *testing.T) {
	resetNodeSources()

	nodes := []core.Node{testNode("a1"), testNode("a2")}
	recordNodes("sub-a", nodes)

	profile := core.DefaultProfile()
	profile.Nodes = nodes
	profile.Groups = []core.Group{
		{Name: "机场A", Type: core.GroupSelect, Members: []string{"a1", "a2", "自动选择"}},
		{Name: "自动选择", Type: core.GroupURLTest, Members: []string{"a1", "a2"}, Interval: 300},
	}
	profile.Rules = []core.Rule{
		{Kind: core.RuleDomainSuffix, Value: "netflix.com", Action: "机场A"},
		{Kind: core.RuleDomainSuffix, Value: "example.com", Action: core.ActionDirect},
		{Kind: core.RuleDomainSuffix, Value: "ads.example.net", Action: core.ActionReject},
	}
	profile.Final = "机场A"

	// This mirrors RemoveSubscription's profile surgery.
	profile.Nodes = dropNodesFrom("sub-a", profile.Nodes)
	profile.Groups = mergeGroups(profile.Groups, profile.Nodes)
	forgetNodes("sub-a")
	profile = rebindStaleTargets(profile)
	if len(profile.Groups) == 0 {
		profile.Final = ""
	}

	if err := profile.Validate(); err != nil {
		t.Fatalf("profile invalid after removal (this was the 400): %v", err)
	}
	if got := profile.Rules[0].Action; got != "" {
		t.Errorf("stale rule action = %q, want empty (follow final)", got)
	}
	if got := profile.Rules[1].Action; got != core.ActionDirect {
		t.Errorf("direct rule action rewritten to %q", got)
	}
	if got := profile.Rules[2].Action; got != core.ActionReject {
		t.Errorf("reject rule action rewritten to %q", got)
	}
	if profile.Final != "" {
		t.Errorf("stale final = %q, want empty", profile.Final)
	}
}

// A rule targeting an outbound that still exists keeps its action untouched.
func TestRebindStaleTargetsKeepsLiveTargets(t *testing.T) {
	profile := core.DefaultProfile()
	profile.Nodes = []core.Node{testNode("keep-1"), testNode("keep-2")}
	profile.Groups = []core.Group{{
		Name: "PROXY", Type: core.GroupSelect,
		Members: []string{"keep-1", "keep-2"},
	}}
	profile.Rules = []core.Rule{{Kind: core.RuleDomainSuffix, Value: "x.example", Action: "PROXY"}}
	profile.Final = "PROXY"

	got := rebindStaleTargets(profile)
	if got.Rules[0].Action != "PROXY" || got.Final != "PROXY" {
		t.Errorf("live targets rewritten: action=%q final=%q", got.Rules[0].Action, got.Final)
	}
	if err := got.Validate(); err != nil {
		t.Errorf("validate: %v", err)
	}
}

// Reserved actions ("", direct, reject, proxy) must survive the rebind even
// when no outbound carries that literal name.
func TestRebindStaleTargetsKeepsReservedActions(t *testing.T) {
	profile := core.DefaultProfile()
	profile.Rules = []core.Rule{{Kind: core.RuleDomainSuffix, Value: "y.example", Action: core.ActionProxy}}
	profile.Final = core.ActionDirect
	got := rebindStaleTargets(profile)
	if got.Rules[0].Action != core.ActionProxy {
		t.Errorf("reserved action rewritten: %q", got.Rules[0].Action)
	}
	if got.Final != core.ActionDirect {
		t.Errorf("final direct rewritten: %q", got.Final)
	}
}
