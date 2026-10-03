//go:build !windows

package tray

// SetStatus is a no-op on platforms without a notification area.
func SetStatus(State) {}

// SetTooltip is a no-op on platforms without a notification area.
func SetTooltip(string) {}
