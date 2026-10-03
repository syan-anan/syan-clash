package app

import (
	"testing"

	"vvpn/internal/core"
)

// Removing a subscription must take its servers with it: leaving them behind
// would silently keep routing to a provider the user just deleted.
func TestDropNodesFromRemovesThatSubscriptionsNodes(t *testing.T) {
	resetNodeSources()

	first := []core.Node{testNode("a1"), testNode("a2")}
	second := []core.Node{testNode("b1")}
	manual := testNode("my-own")

	merged, _ := replaceNodesFrom("sub-a", nil, first)
	recordNodes("sub-a", first)
	merged, _ = replaceNodesFrom("sub-b", merged, second)
	recordNodes("sub-b", second)
	merged = append(merged, manual)

	remaining := dropNodesFrom("sub-b", merged)
	forgetNodes("sub-b")

	names := map[string]bool{}
	for _, n := range remaining {
		names[n.Name] = true
	}
	if names["b1"] {
		t.Errorf("the removed subscription's node survived: %v", nodeNames(remaining))
	}
	for _, want := range []string{"a1", "a2", "my-own"} {
		if !names[want] {
			t.Errorf("node %s should have been kept: %v", want, nodeNames(remaining))
		}
	}
}

// Updating one subscription must not reshuffle the others in the UI.
func TestUpdateKeepsOtherSubscriptionsInPlace(t *testing.T) {
	resetNodeSources()

	first := []core.Node{testNode("a1"), testNode("a2")}
	merged, _ := replaceNodesFrom("sub-a", nil, first)
	recordNodes("sub-a", first)
	second := []core.Node{testNode("b1"), testNode("b2")}
	merged = append(merged, second...)
	// Simulate the provider of sub-a keeping a1 and a2.
	updated, _ := replaceNodesFrom("sub-a", merged, []core.Node{testNode("a1"), testNode("a2")})
	recordNodes("sub-a", updated)

	// b1 and b2 must still come after sub-a's nodes, in their own order.
	pos := map[string]int{}
	for i, n := range updated {
		pos[n.Name] = i
	}
	if pos["b1"] > pos["b2"] {
		t.Errorf("the other subscription's order changed: %v", nodeNames(updated))
	}
	if pos["a1"] > pos["b1"] || pos["a2"] > pos["b1"] {
		t.Errorf("sub-a's nodes moved after sub-b's: %v", nodeNames(updated))
	}
}

// A new subscription is inserted at the front, which is a deliberate,
// predictable place.
func TestNewSubscriptionGoesFirst(t *testing.T) {
	resetNodeSources()
	existing := []core.Node{testNode("manual")}
	merged, _ := replaceNodesFrom("sub-a", existing, []core.Node{testNode("a1")})
	if len(merged) != 2 || merged[0].Name != "a1" || merged[1].Name != "manual" {
		t.Errorf("unexpected order: %v", nodeNames(merged))
	}
}

func TestMergeGroupsIsIdempotent(t *testing.T) {
	nodes := []core.Node{testNode("a1"), testNode("b1")}
	groups := []core.Group{{Name: "PROXY", Type: core.GroupSelect, Members: []string{"a1"}}}
	once := mergeGroups(groups, nodes)
	twice := mergeGroups(once, nodes)
	if len(once) != len(twice) {
		t.Errorf("merging twice changed the group count: %d -> %d", len(once), len(twice))
	}
}
