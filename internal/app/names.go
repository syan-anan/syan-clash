package app

import (
	"sort"

	"vvpn/internal/core"
)

// nodeNamesOf lists the names of a node set, deduplicated and sorted so the
// stored value is stable across imports.
func nodeNamesOf(nodes []core.Node) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		if seen[n.Name] {
			continue
		}
		seen[n.Name] = true
		out = append(out, n.Name)
	}
	sort.Strings(out)
	return out
}

// namesOfImported replaces the subscription's recorded node names with the ones
// the latest import actually delivered.
//
// It used to union the two sets. That made a subscription keep claiming servers
// it no longer offered: after a subscription was re-pointed at a smaller
// provider, the stale names stayed in the record, and on the next restart the
// ownership map handed those names back to it. Every one of them also belonged
// to another subscription, so the 代理组 page showed that other subscription with
// no nodes at all while this one appeared to own everything.
//
// An import that delivered nothing (an empty body, or a fetch that failed after
// the caller already cleared the names) keeps what was known: only a successful
// import may shrink the record.
func namesOfImported(known, imported []string) []string {
	if len(imported) == 0 {
		return known
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(imported))
	for _, name := range imported {
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
