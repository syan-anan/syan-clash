//go:build !windows

package sysproxy

import (
	"errors"
	"time"
)

// ErrUnsupported is returned on platforms where the system proxy is not
// implemented yet (macOS networksetup and Linux gsettings are the next steps).
var ErrUnsupported = errors.New("sysproxy: system proxy control is only implemented on Windows")

// ErrForeignOwner is never returned on this platform: there is no system proxy
// to fight over.
var ErrForeignOwner = errors.New("系统代理已被其他程序占用")

// ForeignOwner is not implemented on this platform.
func ForeignOwner(ownAddrs ...string) (string, bool) { return "", false }

// EnableForced is not implemented on this platform.
func EnableForced(httpAddr, socksAddr, bypass string, force bool) error {
	return Enable(httpAddr, socksAddr)
}

// Enable is not implemented on this platform.
func Enable(httpAddr, socksAddr string) error { return ErrUnsupported }

// Disable is not implemented on this platform.
func Disable() error { return ErrUnsupported }

// Restore is not implemented on this platform.
func Restore() (bool, error) { return false, ErrUnsupported }

// Current is not implemented on this platform.
func Current() (bool, string, error) { return false, "", ErrUnsupported }

// OwnerAlive cannot be answered without a platform process API; reporting
// "gone" is the safe answer because every caller only uses it to decide
// whether a leftover may be cleaned up.
func OwnerAlive(pid int) bool { return false }

// WaitForExit reports immediately on platforms with no guard process.
func WaitForExit(pid int, timeout time.Duration) bool { return true }
