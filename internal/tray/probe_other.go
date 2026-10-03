//go:build !windows

package tray

// ProbeHotKey reports false everywhere else: global shortcuts are a Windows
// feature here.
func ProbeHotKey(uint32, uint32) bool { return false }
