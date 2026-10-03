package app

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"vvpn/internal/core"
)

// The resolver block is one card in the console and one field of the profile.
// Everything here exists so the console can send a half-filled form and get
// back either the stored block or one sentence naming the problem, instead of
// writing something a core would refuse to load.

// DNSConfig returns the resolver block in force.
func (a *App) DNSConfig() core.DNS { return a.Profile().DNS }

// DefaultDNS is the block a fresh profile starts with. The console offers it as
// the target of 恢复默认.
func DefaultDNS() core.DNS { return core.DefaultProfile().DNS }

// SetDNSConfig stores the resolver block and reloads a running core.
//
// DNS.Final is deliberately carried over instead of taken from the request: it
// names an emitter-internal resolver tag (sing-box reads it as a server tag,
// not as an address), so it is not something the console should be editing.
func (a *App) SetDNSConfig(ctx context.Context, dns core.DNS) error {
	profile := a.Profile()
	normalized, err := NormalizeDNS(dns, ProfileHasTun(profile))
	if err != nil {
		return err
	}
	normalized.Final = profile.DNS.Final
	profile.DNS = normalized
	return a.SetProfile(ctx, profile)
}

// ProfileHasTun reports whether a profile routes through a tunnel.
func ProfileHasTun(p core.Profile) bool {
	for _, in := range p.Inbounds {
		if in.Type == core.InboundTun {
			return true
		}
	}
	return false
}

// NormalizeDNS trims, splits and de-duplicates a resolver block and rejects
// what a core cannot load. tun says whether the profile currently routes
// through a tunnel, which is what decides whether a system resolver is merely
// pointless or outright refused.
func NormalizeDNS(dns core.DNS, tun bool) (core.DNS, error) {
	out := core.DNS{
		Enabled:     dns.Enabled,
		FakeIP:      dns.FakeIP,
		FakeIPRange: strings.TrimSpace(dns.FakeIPRange),
		Strategy:    strings.ToLower(strings.TrimSpace(dns.Strategy)),
	}
	seen := make(map[string]bool, len(dns.Servers))
	var system []string
	// The console sends one entry per line, but a pasted blob arrives with
	// commas and semicolons in it. Splitting here means the textarea accepts
	// whatever the user copied out of a README.
	for _, raw := range dns.Servers {
		for _, part := range strings.FieldsFunc(raw, isResolverSeparator) {
			s := strings.TrimSpace(part)
			if s == "" {
				continue
			}
			if strings.ContainsAny(s, " 	") {
				return core.DNS{}, fmt.Errorf("解析器 %q 里有多余的空白，请一行一个", s)
			}
			key := strings.ToLower(s)
			if seen[key] {
				continue
			}
			seen[key] = true
			if core.IsSystemResolver(s) {
				system = append(system, s)
			}
			out.Servers = append(out.Servers, s)
		}
	}
	if tun && len(system) > 0 {
		return core.DNS{}, fmt.Errorf(
			"TUN 已开启，不能用系统解析器（%s）：隧道会劫持 53 端口，系统解析器的查询会被送回它自己，形成自锁。"+
				"请换成纯 IP 或 DoH，例如 223.5.5.5、https://223.5.5.5/dns-query",
			strings.Join(system, "、"))
	}
	if out.Enabled && len(out.Servers) == 0 {
		return core.DNS{}, fmt.Errorf("启用 DNS 至少要有一个解析器；不打算用就先把开关关掉")
	}
	if !core.ValidDNSStrategy(out.Strategy) {
		return core.DNS{}, fmt.Errorf("未知的解析策略 %q（可用：%s）", out.Strategy,
			strings.Join(nonEmptyStrategies(), " / "))
	}
	if out.FakeIPRange != "" {
		if _, err := netip.ParsePrefix(out.FakeIPRange); err != nil {
			return core.DNS{}, fmt.Errorf("fake-ip 网段 %q 不是合法 CIDR，例如 198.18.0.0/15", out.FakeIPRange)
		}
	}
	return out, nil
}

// isResolverSeparator is the set of characters a pasted resolver list uses.
func isResolverSeparator(r rune) bool {
	switch r {
	case '\n', '\r', ',', ';', '|':
		return true
	}
	return false
}

func nonEmptyStrategies() []string {
	out := make([]string, 0, len(core.DNSStrategies))
	for _, s := range core.DNSStrategies {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
