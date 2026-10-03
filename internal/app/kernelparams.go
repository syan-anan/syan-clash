package app

import (
	"context"
	"fmt"
	"strings"

	"vvpn/internal/core"
)

// KernelParams is the kernel page's tuning block in its effective form: every
// value is what a core would actually be handed right now, so the console never
// has to work out which of "never set" and "set to the default" it is looking
// at. The two *Set flags say which controls the user has actually touched, and
// the MTU bounds come from the core layer so the input box and the validator
// cannot drift apart.
type KernelParams struct {
	LogLevel string   `json:"log_level"`
	Levels   []string `json:"levels"`
	Sniff    bool     `json:"sniff"`
	// SniffSet is false while the user has never touched the switch. That state
	// is not the same as "on": mihomo has no sniffer block at all then, which is
	// how every configuration written before this feature existed behaves.
	SniffSet       bool `json:"sniff_set"`
	TunMTU         int  `json:"tun_mtu"`
	TunMTUSet      bool `json:"tun_mtu_set"`
	TunAutoRoute   bool `json:"tun_auto_route"`
	TunStrictRoute bool `json:"tun_strict_route"`
	TunDNSHijack   bool `json:"tun_dns_hijack"`
	TunEnabled     bool `json:"tun_enabled"`
	MTUDefault     int  `json:"mtu_default"`
	MTUMin         int  `json:"mtu_min"`
	MTUMax         int  `json:"mtu_max"`
}

// KernelParamsPatch is a partial update: a nil field is left exactly as it was,
// which is what lets the console save one control without sending the rest of
// the page back. An MTU of 0 means "stop overriding and follow the inbound".
type KernelParamsPatch struct {
	LogLevel       *string `json:"log_level"`
	Sniff          *bool   `json:"sniff"`
	TunMTU         *int    `json:"tun_mtu"`
	TunAutoRoute   *bool   `json:"tun_auto_route"`
	TunStrictRoute *bool   `json:"tun_strict_route"`
	TunDNSHijack   *bool   `json:"tun_dns_hijack"`
}

// IsLogLevel reports whether a string is one of the levels the console offers.
// It is deliberately stricter than core.NormalizeLogLevel: an API that silently
// turns a typo into "info" leaves the user staring at a control that does not
// say what they picked.
func IsLogLevel(level string) bool {
	want := strings.ToLower(strings.TrimSpace(level))
	if want == "warning" {
		want = "warn"
	}
	for _, l := range core.LogLevels {
		if l == want {
			return true
		}
	}
	return false
}

// tunInbound returns the profile's tunnel listener, if it has one.
func tunInbound(p core.Profile) (core.Inbound, bool) {
	for _, in := range p.Inbounds {
		if in.Type == core.InboundTun {
			return in, true
		}
	}
	return core.Inbound{}, false
}

// KernelParams reports the tuning values that are in effect.
func (a *App) KernelParams() KernelParams {
	p := a.Profile()
	tun, hasTun := tunInbound(p)
	inboundMTU, inboundAuto := 0, false
	if hasTun {
		inboundMTU, inboundAuto = tun.MTU, tun.AutoRoute
	}
	return KernelParams{
		LogLevel:       core.NormalizeLogLevel(p.Log),
		Levels:         append([]string{}, core.LogLevels...),
		Sniff:          p.SniffEnabled(),
		SniffSet:       p.Sniff != nil,
		TunMTU:         p.TunMTUFor(inboundMTU),
		TunMTUSet:      p.TunMTU != 0,
		TunAutoRoute:   p.TunAutoRouteFor(inboundAuto),
		TunStrictRoute: p.TunStrictRouteOn(),
		TunDNSHijack:   p.TunDNSHijackOn(),
		TunEnabled:     hasTun,
		MTUDefault:     core.TunMTUDefault,
		MTUMin:         core.TunMTUMin,
		MTUMax:         core.TunMTUMax,
	}
}

// SetKernelParams stores the changes and re-applies the profile, so a running
// core is regenerated and restarted with them - the same path the network
// switches and the DNS block already take.
//
// Values are validated here rather than in the emitters: a level or an MTU the
// core would refuse has to come back as a 400 with the reason, not as a core
// that fails to start.
func (a *App) SetKernelParams(ctx context.Context, patch KernelParamsPatch) (KernelParams, error) {
	profile := a.Profile()
	if patch.LogLevel != nil {
		level := strings.ToLower(strings.TrimSpace(*patch.LogLevel))
		if !IsLogLevel(level) {
			return KernelParams{}, fmt.Errorf("未知的内核日志级别 %q（可选：%s）",
				*patch.LogLevel, strings.Join(core.LogLevels, ", "))
		}
		profile.Log = core.NormalizeLogLevel(level)
	}
	if patch.Sniff != nil {
		v := *patch.Sniff
		profile.Sniff = &v
	}
	if patch.TunMTU != nil {
		v := *patch.TunMTU
		if v != 0 && (v < core.TunMTUMin || v > core.TunMTUMax) {
			return KernelParams{}, fmt.Errorf("隧道 MTU %d 超出范围（%d-%d，0 表示跟随默认）",
				v, core.TunMTUMin, core.TunMTUMax)
		}
		profile.TunMTU = core.NormalizeTunMTU(v)
	}
	if patch.TunAutoRoute != nil {
		v := *patch.TunAutoRoute
		profile.TunAutoRoute = &v
	}
	if patch.TunStrictRoute != nil {
		v := *patch.TunStrictRoute
		profile.TunStrictRoute = &v
	}
	if patch.TunDNSHijack != nil {
		v := *patch.TunDNSHijack
		profile.TunDNSHijack = &v
	}
	if err := a.SetProfile(ctx, profile); err != nil {
		return KernelParams{}, err
	}
	return a.KernelParams(), nil
}
