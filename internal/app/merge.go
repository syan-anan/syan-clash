package app

import (
	"sort"
	"strings"
	"sync"

	"vvpn/internal/core"
)

// nodeSource remembers which subscription contributed which node names, so a
// later import can merge with the other subscriptions instead of replacing them.
//
// Without this, importing a second subscription silently dropped the first
// one's nodes: the profile only ever held the most recent import.
var (
	nodeSourceMu sync.Mutex
	nodeSource   = map[string]string{} // node name -> subscription name
)

// recordNodes notes which subscription owns a set of nodes.
func recordNodes(subscription string, nodes []core.Node) {
	nodeSourceMu.Lock()
	defer nodeSourceMu.Unlock()
	for _, n := range nodes {
		nodeSource[n.Name] = subscription
	}
}

// nodeOwner reports which subscription contributed a node, if any.
func nodeOwner(name string) (string, bool) {
	nodeSourceMu.Lock()
	defer nodeSourceMu.Unlock()
	owner, ok := nodeSource[name]
	return owner, ok
}

// renameNodeOwner re-points every node a subscription owns after that
// subscription is renamed. The map is keyed by node name and holds the
// subscription name as its value, so without this the old name would keep
// owning the nodes and the next import under either name would duplicate or
// drop the wrong ones.
func renameNodeOwner(oldName, newName string) {
	if oldName == newName {
		return
	}
	nodeSourceMu.Lock()
	defer nodeSourceMu.Unlock()
	for name, owner := range nodeSource {
		if owner == oldName {
			nodeSource[name] = newName
		}
	}
}

// rebuildNodeSources restores the ownership map after a restart: it is in
// memory only, so without this the client would treat every existing node as
// unowned and re-importing a subscription would duplicate them.
func rebuildNodeSources(subs []Subscription, nodes []core.Node) {
	nodeSourceMu.Lock()
	defer nodeSourceMu.Unlock()
	if len(nodeSource) > 0 {
		return
	}
	byName := map[string]bool{}
	for _, n := range nodes {
		byName[n.Name] = true
	}
	for _, s := range subs {
		for _, name := range s.NodeNames {
			if byName[name] {
				nodeSource[name] = s.Name
			}
		}
	}
}

// replaceNodesFrom swaps the nodes belonging to one subscription while keeping
// every other subscription's nodes. It returns the merged list and whether
// anything changed.
//
// Ordering rule: the subscription's own nodes are rewritten **in the position
// they already occupied**, so updating one subscription does not reshuffle the
// others in the UI. A node the new import no longer provides is dropped, and a
// newly appeared node is appended where the subscription's block ends.
// Nodes the user added by hand (owned by no subscription) are never touched.
func replaceNodesFrom(subscription string, existing, imported []core.Node) ([]core.Node, bool) {
	owned := ownedNames(subscription)

	// Deduplicate the import by name; a duplicate would fail validation later.
	fresh := make([]core.Node, 0, len(imported))
	freshSet := map[string]bool{}
	for _, n := range imported {
		if freshSet[n.Name] {
			continue
		}
		freshSet[n.Name] = true
		fresh = append(fresh, n)
	}

	// Split the existing list into this subscription's block and everything
	// else. The block is replaced wholesale; the rest keeps its order, and the
	// new block is written back at the position the old one occupied.
	var before, after []core.Node
	blockStart := -1
	for _, n := range existing {
		if owned[n.Name] {
			if blockStart < 0 {
				blockStart = len(before)
			}
			continue
		}
		if blockStart < 0 {
			before = append(before, n)
		} else {
			after = append(after, n)
		}
	}
	if blockStart < 0 {
		// Not seen before: the subscription is new, so its nodes go up front.
		blockStart = 0
	}

	changed := false
	if len(owned) != len(fresh) {
		changed = true
	}
	for _, n := range fresh {
		if !owned[n.Name] {
			changed = true
			break
		}
	}

	out := make([]core.Node, 0, len(existing)+len(fresh))
	out = append(out, before[:min(blockStart, len(before))]...)
	out = append(out, fresh...)
	out = append(out, before[min(blockStart, len(before)):]...)
	out = append(out, after...)

	// Final guard, stated simply: the imported definitions always win, and no
	// name may appear twice. Duplicate outbound names are rejected by the
	// neutral model, which would fail the entire import.
	deduped := make([]core.Node, 0, len(out))
	deduped = append(deduped, fresh...)
	kept := make(map[string]bool, len(fresh))
	for _, n := range fresh {
		kept[n.Name] = true
	}
	for _, n := range out {
		if kept[n.Name] {
			// Already have the imported copy of this server.
			changed = true
			continue
		}
		kept[n.Name] = true
		deduped = append(deduped, n)
	}
	return deduped, changed
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ownedNames lists the node names a subscription currently owns.
func ownedNames(subscription string) map[string]bool {
	owned := map[string]bool{}
	nodeSourceMu.Lock()
	defer nodeSourceMu.Unlock()
	for name, owner := range nodeSource {
		if owner == subscription {
			owned[name] = true
		}
	}
	return owned
}

// mergeGroups rebuilds the proxy groups so they reference the merged node list:
// existing groups keep their membership where the member still exists, and every
// node is reachable from at least one group.
func mergeGroups(groups []core.Group, nodes []core.Node) []core.Group {
	nodeAlive := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		nodeAlive[n.Name] = true
	}

	// A member may also be another group: airports nest "自动选择"/"故障转移"
	// under a selector. Dropping a memberless helper orphans every reference
	// to it in turn (the selector above it is then left with dangling
	// members and profile validation rejects the whole thing), so filter to
	// a fixpoint instead of a single pass.
	removed := make(map[string]bool, len(groups))
	for {
		groupAlive := make(map[string]bool, len(groups))
		for _, g := range groups {
			if g.Name != "" && !removed[g.Name] {
				groupAlive[g.Name] = true
			}
		}
		changed := false
		for _, g := range groups {
			if g.Name == "" || removed[g.Name] {
				continue
			}
			live := false
			for _, m := range g.Members {
				if nodeAlive[m] || (groupAlive[m] && !removed[m]) {
					live = true
					break
				}
			}
			if !live {
				removed[g.Name] = true
				changed = true
			}
		}
		if !changed {
			break
		}
	}

	exists := make(map[string]bool, len(groups))
	for _, g := range groups {
		if g.Name != "" && !removed[g.Name] {
			exists[g.Name] = true
		}
	}
	out := make([]core.Group, 0, len(groups))
	for _, g := range groups {
		if g.Name == "" || removed[g.Name] {
			continue
		}
		members := make([]string, 0, len(g.Members))
		for _, m := range g.Members {
			if nodeAlive[m] || exists[m] {
				members = append(members, m)
			}
		}
		g.Members = members
		if len(g.Members) > 0 {
			out = append(out, g)
		}
	}
	if len(out) == 0 {
		return DefaultGroups(nodes)
	}

	// Nodes the groups forgot would be unreachable from the UI.
	referenced := map[string]bool{}
	for _, g := range out {
		for _, m := range g.Members {
			referenced[m] = true
		}
	}
	var orphans []string
	for _, n := range nodes {
		if !referenced[n.Name] {
			orphans = append(orphans, n.Name)
		}
	}
	sort.Strings(orphans)

	for i := range out {
		switch out[i].Type {
		case core.GroupSelect:
			out[i].Members = append(out[i].Members, orphans...)
			return out
		case core.GroupURLTest, core.GroupFallback:
			out[i].Members = append(out[i].Members, orphans...)
		}
	}
	if len(orphans) > 0 {
		out = append(out, core.Group{
			Name: "其他", Type: core.GroupSelect, Members: orphans,
		})
	}
	return out
}

// nodeNames lists node names, for logging and comparisons.
func nodeNames(nodes []core.Node) string {
	names := make([]string, 0, len(nodes))
	for _, n := range nodes {
		names = append(names, n.Name)
	}
	return strings.Join(names, ", ")
}

// resetNodeSources clears the ownership map; used by tests.
func resetNodeSources() {
	nodeSourceMu.Lock()
	defer nodeSourceMu.Unlock()
	nodeSource = map[string]string{}
}
