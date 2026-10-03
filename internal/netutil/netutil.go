// Package netutil holds small network helpers shared by the proxy core and the
// control API.
package netutil

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// ResolveHost resolves host to a single address, preferring IPv4 so that
// IPv4-only rules and upstreams keep working on dual-stack machines.
func ResolveHost(ctx context.Context, host string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap(), nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, err
	}
	var fallback netip.Addr
	for _, ip := range ips {
		ip = ip.Unmap()
		if ip.Is4() {
			return ip, nil
		}
		if !fallback.IsValid() {
			fallback = ip
		}
	}
	if fallback.IsValid() {
		return fallback, nil
	}
	return netip.Addr{}, fmt.Errorf("no address for %q", host)
}

// IsLoopback reports whether host is a loopback literal or a loopback name.
func IsLoopback(host string) bool {
	switch host {
	case "", "localhost":
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.IsLoopback()
}

// IsLoopbackAddr reports whether a net.Addr belongs to the loopback interface.
func IsLoopbackAddr(a net.Addr) bool {
	if a == nil {
		return false
	}
	switch v := a.(type) {
	case *net.TCPAddr:
		return v.IP.IsLoopback()
	case *net.UDPAddr:
		return v.IP.IsLoopback()
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return false
	}
	return IsLoopback(host)
}

// JoinHostPort builds "host:port" without the brackets that IPv6 needs.
func JoinHostPort(host string, port uint16) string {
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

// DefaultPortForScheme returns the well known port for a proxy request scheme.
func DefaultPortForScheme(scheme string) uint16 {
	switch scheme {
	case "https", "wss":
		return 443
	case "http", "ws":
		return 80
	default:
		return 80
	}
}

// DialTimeout is the shared dial budget used when no explicit timeout is set.
const DialTimeout = 10 * time.Second

// SplitHostPort is net.SplitHostPort re-exported for callers that need the
// split without importing net themselves.
func SplitHostPort(addr string) (string, string, error) { return net.SplitHostPort(addr) }

// ParsePort converts a decimal port string to a uint16.
func ParsePort(s string) (uint16, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil {
		return 0, fmt.Errorf("netutil: %q is not a port", s)
	}
	return uint16(n), nil
}
