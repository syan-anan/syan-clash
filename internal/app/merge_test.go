package app

import (
	"testing"

	"vvpn/internal/core"
)

func testNode(name string) core.Node {
	return core.Node{Name: name, Type: core.TypeSS, Server: "1.2.3.4", Port: 8388, Method: "aes-256-gcm", Password: "pw"}
}

// Importing a second subscription used to replace the first one's nodes: this
// is the regression that made multi-subscription setups silently lose servers.
func TestSecondSubscriptionKeepsTheFirst(t *testing.T) {
	resetNodeSources()

	first := []core.Node{testNode("a1"), testNode("a2")}
	merged, _ := replaceNodesFrom("sub-a", nil, first)
	recordNodes("sub-a", first)
	if len(merged) != 2 {
		t.Fatalf("after the first import: %d nodes, want 2", len(merged))
	}

	second := []core.Node{testNode("b1")}
	merged, _ = replaceNodesFrom("sub-b", merged, second)
	recordNodes("sub-b", second)

	if len(merged) != 3 {
		t.Fatalf("after the second import: %d nodes, want 3 (%v)", len(merged), nodeNames(merged))
	}
	names := map[string]bool{}
	for _, n := range merged {
		names[n.Name] = true
	}
	for _, want := range []string{"a1", "a2", "b1"} {
		if !names[want] {
			t.Errorf("node %s is missing: %v", want, nodeNames(merged))
		}
	}
}

// Updating a subscription must refresh its own nodes without disturbing others.
func TestReimportReplacesOnlyThatSubscriptionsNodes(t *testing.T) {
	resetNodeSources()

	first := []core.Node{testNode("a1"), testNode("a2")}
	merged, _ := replaceNodesFrom("sub-a", nil, first)
	recordNodes("sub-a", first)
	second := []core.Node{testNode("b1"), testNode("b2")}
	merged, _ = replaceNodesFrom("sub-b", merged, second)
	recordNodes("sub-b", second)

	// The provider of sub-a drops a2 and adds a3.
	updated := []core.Node{testNode("a1"), testNode("a3")}
	merged, changed := replaceNodesFrom("sub-a", merged, updated)
	recordNodes("sub-a", updated)
	if !changed {
		t.Error("a changed node set should report changed")
	}
	names := map[string]bool{}
	for _, n := range merged {
		names[n.Name] = true
	}
	for _, want := range []string{"a1", "a3", "b1", "b2"} {
		if !names[want] {
			t.Errorf("node %s is missing after the update: %v", want, nodeNames(merged))
		}
	}
	if names["a2"] {
		t.Errorf("a2 should have been dropped when its subscription stopped offering it: %v", nodeNames(merged))
	}
}

// Hand-added nodes belong to no subscription and must never be removed.
func TestManualNodesSurviveSubscriptionUpdates(t *testing.T) {
	resetNodeSources()

	manual := testNode("my-own-server")
	existing := []core.Node{manual}
	imported := []core.Node{testNode("a1")}
	merged, _ := replaceNodesFrom("sub-a", existing, imported)
	recordNodes("sub-a", imported)

	names := map[string]bool{}
	for _, n := range merged {
		names[n.Name] = true
	}
	if !names["my-own-server"] {
		t.Errorf("the hand-added node was dropped: %v", nodeNames(merged))
	}
	if !names["a1"] {
		t.Errorf("the imported node is missing: %v", nodeNames(merged))
	}
}

func TestMergeGroupsKeepsEveryNodeReachable(t *testing.T) {
	nodes := []core.Node{testNode("a1"), testNode("a2"), testNode("b1")}
	groups := []core.Group{
		{Name: "PROXY", Type: core.GroupSelect, Members: []string{"a1"}},
		{Name: "AUTO", Type: core.GroupURLTest, Members: []string{"a2"}},
	}
	merged := mergeGroups(groups, nodes)

	referenced := map[string]bool{}
	for _, g := range merged {
		for _, m := range g.Members {
			referenced[m] = true
		}
	}
	for _, n := range nodes {
		if !referenced[n.Name] {
			t.Errorf("node %s is in no group, so the UI cannot reach it", n.Name)
		}
	}
	// Groups must stay valid.
	profile := core.DefaultProfile()
	profile.Nodes = nodes
	profile.Groups = merged
	profile.Rules = []core.Rule{{Kind: core.RuleFinal, Value: "", Action: "PROXY"}}
	profile.Final = "PROXY"
	if err := profile.Validate(); err != nil {
		t.Errorf("merged groups produced an invalid profile: %v", err)
	}
}

func TestMergeGroupsDropsNamesThatNoLongerExist(t *testing.T) {
	nodes := []core.Node{testNode("a1")}
	groups := []core.Group{{Name: "PROXY", Type: core.GroupSelect, Members: []string{"a1", "gone"}}}
	merged := mergeGroups(groups, nodes)
	for _, g := range merged {
		for _, m := range g.Members {
			if m == "gone" {
				t.Errorf("a member that no longer exists was kept: %+v", g)
			}
		}
	}
}
