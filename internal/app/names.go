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

// namesOfImported keeps the subscription's recorded node names in step with the
// latest import: names that came back now plus ones already known, which is what
// lets a restart rebuild ownership for every server the subscription provides.
func namesOfImported(known, imported []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(known)+len(imported))
	for _, name := range imported {
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	for _, name := range known {
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
