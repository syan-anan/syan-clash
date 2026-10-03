package sysproxy

import "strings"

// foreignEntry is the pure half of ForeignOwner: given the proxy string that is
// currently published, it reports the first entry that names something other
// than one of our own inbound addresses. It is kept free of registry access so
// the ownership rule can be tested without touching the machine.
func foreignEntry(server string, ownAddrs ...string) (string, bool) {
	own := make(map[string]bool, len(ownAddrs))
	for _, a := range ownAddrs {
		if a = strings.TrimSpace(a); a != "" {
			own[a] = true
		}
	}
	for _, part := range strings.Split(server, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		addr := part
		if i := strings.Index(part, "="); i >= 0 {
			addr = strings.TrimSpace(part[i+1:])
		}
		if addr == "" || own[addr] {
			continue
		}
		return part, true
	}
	return "", false
}

// ourAddrsFrom pulls the addresses out of a published proxy string, so a
// snapshot can be judged against what this client writes itself.
func ourAddrsFrom(published string) []string {
	var out []string
	for _, part := range strings.Split(published, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if i := strings.Index(part, "="); i >= 0 {
			part = strings.TrimSpace(part[i+1:])
		}
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// oursOnly reports whether a published proxy string names nothing but the
// addresses this client writes itself. It is what separates "the machine had no
// proxy" and "the machine had our own leftover" from "another program owned the
// setting", and the three cases need different exit behaviour.
func oursOnly(published string, ourAddrs ...string) bool {
	_, foreign := foreignEntry(published, ourAddrs...)
	return !foreign
}
