package app

import (
	"context"
	"errors"

	"vvpn/internal/core"
	"vvpn/internal/elevate"
	"vvpn/internal/wintun"
)

// TunStack reports the TUN data plane the profile asks for. A value the core
// layer would refuse to emit is reported as gvisor, so the UI never shows a
// stack the client is not actually going to run.
func (a *App) TunStack() string {
	return core.NormalizeTunStack(a.Profile().TunStack)
}

// SetTunStack records the TUN data plane and re-applies the profile, so a
// running core picks the new stack up immediately. The value is normalised
// before it is stored: an unknown name cannot reach a core's configuration
// through this preference either.
func (a *App) SetTunStack(ctx context.Context, stack string) error {
	profile := a.Profile()
	profile.TunStack = core.NormalizeTunStack(stack)
	for i := range profile.Inbounds {
		if profile.Inbounds[i].Type == core.InboundTun {
			profile.Inbounds[i].Stack = profile.TunStack
		}
	}
	return a.SetProfile(ctx, profile)
}

// TunEnabled reports whether the profile currently routes through a TUN device.
func (a *App) TunEnabled() bool {
	for _, in := range a.Profile().Inbounds {
		if in.Type == core.InboundTun {
			return true
		}
	}
	return false
}

// SetTunMode adds or removes the TUN inbound. TUN takes over the whole machine,
// so it needs administrator rights; the error explains that when they are
// missing instead of failing deep inside the core.
func (a *App) SetTunMode(ctx context.Context, enabled bool) error {
	profile := a.Profile()
	inbounds := make([]core.Inbound, 0, len(profile.Inbounds)+1)
	for _, in := range profile.Inbounds {
		if in.Type != core.InboundTun {
			inbounds = append(inbounds, in)
		}
	}
	if enabled {
		if !wintun.Supported() {
			return errors.New("当前系统架构不受内置 wintun 驱动支持，TUN 模式不可用")
		}
		if ok, hint := elevate.CanCreateTun(); !ok {
			return errors.New(hint)
		}
		if len(inbounds) == 0 {
			// TUN alone still needs a local entry point for apps that prefer
			// an explicit proxy.
			inbounds = append(inbounds, core.Inbound{
				Type: core.InboundMixed, Tag: "mixed-in", Listen: "127.0.0.1", Port: 2890,
			})
		}
		inbounds = append(inbounds, core.Inbound{
			Type:        core.InboundTun,
			Tag:         "tun-in",
			Stack:       a.TunStack(),
			AutoRoute:   true,
			StrictRoute: false,
			MTU:         9000,
			Device:      "syan-clash0",
		})
	}
	profile.Inbounds = inbounds
	return a.SetProfile(ctx, profile)
}
