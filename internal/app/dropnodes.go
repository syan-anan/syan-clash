package app

import "vvpn/internal/core"

// dropNodesFrom removes every node a subscription contributed, keeping the
// original relative order of everything that stays.
func dropNodesFrom(subscription string, existing []core.Node) []core.Node {
	owned := map[string]bool{}
	nodeSourceMu.Lock()
	for name, owner := range nodeSource {
		if owner == subscription {
			owned[name] = true
		}
	}
	nodeSourceMu.Unlock()

	out := make([]core.Node, 0, len(existing))
	for _, n := range existing {
		if owned[n.Name] {
			continue
		}
		out = append(out, n)
	}
	return out
}

// forgetNodes drops the ownership records of one subscription.
func forgetNodes(subscription string) {
	nodeSourceMu.Lock()
	defer nodeSourceMu.Unlock()
	for name, owner := range nodeSource {
		if owner == subscription {
			delete(nodeSource, name)
		}
	}
}
