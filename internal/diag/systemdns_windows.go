//go:build windows

package diag

import (
	"strings"

	"vvpn/internal/winreg"
)

// The two places Windows records resolvers, one per address family.
const (
	tcpipParams  = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"
	tcpip6Params = "SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters"
)

// SystemResolvers lists the DNS servers Windows itself is configured to use.
//
// Windows keeps them in the registry, under the global Tcpip parameters and
// again per adapter; the per-adapter copy is the one the DHCP client writes, so
// both are read. Adapters that are not connected are dropped, because the
// registry keeps them forever and the panel is about what can leak now. This
// reads configuration, not live state: a lease that was just renewed may not be
// reflected yet, which is why the panel calls the result "系统里配置的解析器"
// rather than "当前生效的解析器".
func SystemResolvers() []string {
	var (
		global   []string
		perIface []ifaceResolvers
	)
	for _, base := range []string{tcpipParams, tcpip6Params} {
		global = append(global, readResolverValues(base)...)

		subs, err := winreg.SubKeysMachine(base + "\\Interfaces")
		if err != nil {
			continue
		}
		for _, sub := range subs {
			vals := readResolverValues(base + "\\Interfaces\\" + sub)
			if len(vals) == 0 {
				continue
			}
			perIface = append(perIface, ifaceResolvers{GUID: sub, Values: vals})
		}
	}
	return mergeResolvers(global, perIface, activeAdapters())
}

// readResolverValues reads the two values an adapter stores its resolvers in.
// An empty value is not a resolver, so it is dropped here rather than showing
// up as a blank row.
func readResolverValues(key string) []string {
	var out []string
	for _, name := range []string{"NameServer", "DhcpNameServer"} {
		v, err := winreg.GetMachineString(key, name)
		if err != nil {
			continue
		}
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
