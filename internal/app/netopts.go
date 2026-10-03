package app

import "context"

// SetNetworkToggles stores the core-level network switches (LAN access and
// IPv6) and re-applies the profile so a running core picks them up right away.
func (a *App) SetNetworkToggles(ctx context.Context, allowLAN, ipv6 bool) error {
	profile := a.Profile()
	profile.AllowLAN = allowLAN
	profile.IPv6 = ipv6
	return a.SetProfile(ctx, profile)
}
