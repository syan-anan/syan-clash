package diag

import "strings"

// ifaceResolvers is one adapter's configured DNS servers, as the registry
// stores them: a per-adapter copy of NameServer / DhcpNameServer.
type ifaceResolvers struct {
	GUID   string
	Values []string
}

// mergeResolvers flattens everything the machine is configured with into the
// list the panel shows: the machine-wide entries first, then one adapter's
// entries each.
//
// up is the set of adapters that are connected right now, keyed by normalised
// GUID. A nil set means that state could not be read at all, and then nothing
// is filtered: showing one stale entry is a much smaller mistake than hiding
// the resolver the machine is really using.
func mergeResolvers(global []string, perIface []ifaceResolvers, up map[string]bool) []string {
	out := make([]string, 0, len(global)+len(perIface))
	seen := map[string]bool{}
	add := func(raw string) {
		for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
		}) {
			s := strings.TrimSpace(part)
			if s == "" || seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, v := range global {
		add(v)
	}
	for _, it := range perIface {
		if up != nil && !up[normalizeGUID(it.GUID)] {
			continue
		}
		for _, v := range it.Values {
			add(v)
		}
	}
	return out
}

// normalizeGUID makes an adapter identifier comparable whatever form it arrived
// in: the registry keys it with braces, GetAdaptersAddresses also reports it
// with braces, and case is not stable across the two.
func normalizeGUID(s string) string {
	return strings.ToUpper(strings.Trim(strings.TrimSpace(s), "{}"))
}
