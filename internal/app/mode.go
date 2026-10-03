package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// coreModes are the routing modes the Clash-compatible control API accepts.
var coreModes = map[string]bool{"rule": true, "global": true, "direct": true}

// ErrInvalidMode marks a routing mode the client rejects before it ever reaches
// the core. The control plane turns it into a 400, so a typo in the UI reads as
// "bad request" instead of "the core is broken".
var ErrInvalidMode = errors.New("unknown routing mode")

// CoreModes lists the modes the UI may offer, in the order it should show them.
func CoreModes() []string { return []string{"rule", "global", "direct"} }

// CoreMode reads the routing mode of a running core.
func (a *App) CoreMode(ctx context.Context, id string) (string, error) {
	client, err := a.CoreClient(id)
	if err != nil {
		return "", err
	}
	return client.Mode(ctx)
}

// SetCoreMode switches the routing mode of a running core. The value is
// validated here so the UI cannot push a mode the core would reject.
func (a *App) SetCoreMode(ctx context.Context, id, mode string) (string, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if !coreModes[mode] {
		return "", fmt.Errorf("%w %q（可选：rule 规则 / global 全局 / direct 直连）", ErrInvalidMode, mode)
	}
	client, err := a.CoreClient(id)
	if err != nil {
		return "", err
	}
	if err := client.SetMode(ctx, mode); err != nil {
		return "", err
	}
	return mode, nil
}
