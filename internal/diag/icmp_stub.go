//go:build !windows

package diag

import (
	"net/netip"
	"time"
)

// icmpProbe is only implemented on Windows, which is the only platform this
// client ships for. The stub keeps the package compiling elsewhere and reports
// the same "unavailable" the Windows path reports when the system refuses.
func icmpProbe(dst netip.Addr, ttl, payload int, df bool, timeout time.Duration) (icmpReply, error) {
	return icmpReply{}, errICMPUnavailable
}
