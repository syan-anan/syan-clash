package app

import (
	"context"
	"testing"

	"vvpn/internal/config"
	"vvpn/internal/core"
)

// The stack choice has to survive a restart and has to be normalised before it
// is stored, because the stored value is what ends up in a core's configuration.
func TestTunStackIsPersistedAndNormalised(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()

	if got := a.TunStack(); got != core.TunStackGvisor {
		t.Fatalf("a fresh client must default to gvisor, got %q", got)
	}
	if err := a.SetTunStack(ctx, "system"); err != nil {
		t.Fatalf("SetTunStack(system): %v", err)
	}
	if got := a.TunStack(); got != core.TunStackSystem {
		t.Fatalf("the choice did not stick in memory: %q", got)
	}
	cfg, err := config.Load(a.ConfigPath())
	if err != nil {
		t.Fatalf("reload the configuration from disk: %v", err)
	}
	if cfg.Core.Profile == nil || cfg.Core.Profile.TunStack != core.TunStackSystem {
		t.Fatal("the choice was not written to the configuration file")
	}

	// An unknown name must never reach a core: it is normalised to the stack
	// this client has verified, both in memory and on disk. "mixed" is the one
	// that matters, because it is a real mihomo value that does not work here.
	if err := a.SetTunStack(ctx, "mixed"); err != nil {
		t.Fatalf("SetTunStack(mixed): %v", err)
	}
	if got := a.TunStack(); got != core.TunStackGvisor {
		t.Fatalf("mixed must not survive as a stack choice, got %q", got)
	}
	cfg, err = config.Load(a.ConfigPath())
	if err != nil {
		t.Fatalf("reload after mixed: %v", err)
	}
	if cfg.Core.Profile.TunStack != core.TunStackGvisor {
		t.Fatalf("the dead stack reached the configuration file: %q", cfg.Core.Profile.TunStack)
	}

	// Case and surrounding space are tolerated: the value travels through JSON
	// and can also be hand-written into the configuration file.
	if err := a.SetTunStack(ctx, "  System  "); err != nil {
		t.Fatalf("SetTunStack(  System  ): %v", err)
	}
	if got := a.TunStack(); got != core.TunStackSystem {
		t.Fatalf("the stack name is not case/space tolerant: %q", got)
	}
}

// Turning TUN on has to use the chosen stack, not a hard-coded one: that is the
// whole point of the preference. The inbound is written before the elevation
// check, so an unelevated test run still proves which stack was picked.
func TestSetTunStackRewritesTheExistingTunInbound(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()
	profile := a.Profile()
	profile.Inbounds = append(profile.Inbounds, core.Inbound{
		Type: core.InboundTun, Tag: "tun-in", Stack: core.TunStackGvisor,
		AutoRoute: true, Device: "syan-clash0",
	})
	if err := a.SetProfile(ctx, profile); err != nil {
		t.Fatalf("SetProfile with a tun inbound: %v", err)
	}
	if err := a.SetTunStack(ctx, "system"); err != nil {
		t.Fatalf("SetTunStack(system): %v", err)
	}
	var stacks []string
	for _, in := range a.Profile().Inbounds {
		if in.Type == core.InboundTun {
			stacks = append(stacks, in.Stack)
		}
	}
	if len(stacks) != 1 || stacks[0] != core.TunStackSystem {
		t.Fatalf("the live tun inbound still carries %v, want [system]", stacks)
	}
}
