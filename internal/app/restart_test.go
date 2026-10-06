package app

import (
	"testing"

	"vvpn/internal/core"
)

// Simulates a restart: the ownership map is empty (it is in-memory only), and
// the saved subscriptions carry the node names they contributed.
func TestRebuildNodeSourcesAfterRestart(t *testing.T) {
	resetNodeSources()

	nodes := []core.Node{testNode("a1"), testNode("a2"), testNode("b1"), testNode("manual")}
	subs := []Subscription{
		{Name: "sub-a", NodeNames: []string{"a1", "a2"}},
		{Name: "sub-b", NodeNames: []string{"b1"}},
	}
	rebuildNodeSources(subs, nodes)

	if owner, ok := nodeOwner("a1"); !ok || owner != "sub-a" {
		t.Errorf("a1 owner = %q/%v, want sub-a", owner, ok)
	}
	if owner, ok := nodeOwner("b1"); !ok || owner != "sub-b" {
		t.Errorf("b1 owner = %q/%v, want sub-b", owner, ok)
	}
	// A hand-added node belongs to nobody.
	if owner, ok := nodeOwner("manual"); ok {
		t.Errorf("manual should have no owner, got %q", owner)
	}
}

// The bug this guards: after a restart the ownership map was empty, so an
// update appended the same servers again and validation failed with
// "duplicate outbound name".
func TestUpdateAfterRestartDoesNotDuplicate(t *testing.T) {
	resetNodeSources()

	nodes := []core.Node{testNode("a1"), testNode("a2")}
	subs := []Subscription{{Name: "sub-a", NodeNames: []string{"a1", "a2"}}}
	rebuildNodeSources(subs, nodes)

	// The provider returns the same servers again.
	fresh := []core.Node{testNode("a1"), testNode("a2")}
	merged, _ := replaceNodesFrom("sub-a", nodes, fresh)

	if len(merged) != 2 {
		t.Fatalf("after an update there are %d nodes, want 2 (%v)", len(merged), nodeNames(merged))
	}
	profile := core.DefaultProfile()
	profile.Nodes = merged
	profile.Groups = DefaultGroups(merged)
	if err := profile.Validate(); err != nil {
		t.Errorf("the updated profile is invalid, which is what duplication causes: %v", err)
	}
}

func TestNodeNamesOfIsStable(t *testing.T) {
	nodes := []core.Node{testNode("b"), testNode("a"), testNode("b")}
	got := nodeNamesOf(nodes)
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("nodeNamesOf = %v, want [a b] (deduped, sorted)", got)
	}
}

func TestNamesOfImportedFollowsTheLatestImport(t *testing.T) {
	// A successful import replaces the record: a subscription that was
	// re-pointed at a smaller provider must stop claiming the servers it used
	// to offer, or the next restart hands those names back to it and the other
	// subscription that really provides them shows up empty.
	got := namesOfImported([]string{"old1", "old2"}, []string{"new1"})
	if len(got) != 1 || got[0] != "new1" {
		t.Fatalf("got %v, want [new1]", got)
	}
	// No duplicates when the same name arrives twice.
	again := namesOfImported(got, []string{"new1", "new1"})
	if len(again) != 1 || again[0] != "new1" {
		t.Errorf("namesOfImported duplicated: %v", again)
	}
	// An import that delivered nothing keeps what was known: only a successful
	// import may shrink the record.
	kept := namesOfImported([]string{"a", "b"}, nil)
	if len(kept) != 2 {
		t.Errorf("an empty import wiped the record: %v", kept)
	}
}
