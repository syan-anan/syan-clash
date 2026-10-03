package sysproxy

import "strings"

// DefaultBypass is the ProxyOverride value written when the caller does not
// name one. "<local>" is WinINET's "skip plain host names and the intranet"
// token: it is what syan-clash wrote unconditionally before the list became
// editable, so leaving it in place keeps an untouched install behaving exactly
// as it did.
const DefaultBypass = "<local>"

// BypassOrDefault resolves the ProxyOverride value to write. An empty or blank
// answer means "nothing configured" and gets the historical default - never
// "bypass nothing": Windows reads an empty ProxyOverride as "no bypass list at
// all", which would silently start pushing intranet traffic through the proxy.
func BypassOrDefault(bypass string) string {
	if v := strings.TrimSpace(bypass); v != "" {
		return v
	}
	return DefaultBypass
}
