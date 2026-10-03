package app

import (
	"testing"

	"vvpn/internal/core"
)

// The regression that motivated the final dedupe guard: the profile already had
// a server with the same name, the ownership map was empty (fresh start), so the
// import appended a second copy and validation failed with
// "duplicate outbound name".
func TestImportOverSameNamesDoesNotDuplicate(t *testing.T) {
	resetNodeSources()

	// Servers already configured, owned by nobody (as after a restart with no
	// ownership records).
	existing := []core.Node{testNode("sub-tokyo"), testNode("sub-osaka")}
	// The provider returns the same names.
	imported := []core.Node{testNode("sub-tokyo"), testNode("sub-osaka")}

	merged, _ := replaceNodesFrom("sub-one", existing, imported)
	if len(merged) != 2 {
		t.Fatalf("merged has %d nodes, want 2 (%v)", len(merged), nodeNames(merged))
	}

	profile := core.DefaultProfile()
	profile.Nodes = merged
	profile.Groups = DefaultGroups(merged)
	profile.Final = "PROXY"
	if err := profile.Validate(); err != nil {
		t.Errorf("duplicate names survived the merge: %v", err)
	}
}

// Names that are only in the existing list must still be preserved and unique.
func TestMergePreservesUnrelatedNodesExactlyOnce(t *testing.T) {
	resetNodeSources()

	existing := []core.Node{testNode("keep1"), testNode("keep2")}
	imported := []core.Node{testNode("fresh1")}
	merged, _ := replaceNodesFrom("sub-x", existing, imported)

	count := map[string]int{}
	for _, n := range merged {
		count[n.Name]++
	}
	if len(merged) != 3 {
		t.Fatalf("merged = %v, want 3 nodes", nodeNames(merged))
	}
	for name, n := range count {
		if n != 1 {
			t.Errorf("%s appears %d times", name, n)
		}
	}
}

// A duplicate inside the imported payload itself must be collapsed.
func TestDuplicateInsideImportIsCollapsed(t *testing.T) {
	resetNodeSources()
	imported := []core.Node{testNode("a"), testNode("a")}
	merged, _ := replaceNodesFrom("sub-x", nil, imported)
	if len(merged) != 1 {
		t.Errorf("merged = %v, want a single node", nodeNames(merged))
	}
}
