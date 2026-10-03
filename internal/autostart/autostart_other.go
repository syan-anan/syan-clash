//go:build !windows

package autostart

import "errors"

// ErrUnsupported is returned where the login entry is not implemented yet.
var ErrUnsupported = errors.New("autostart: only implemented on Windows")

// Enable is not implemented on this platform.
func Enable(executable string, args []string) error { return ErrUnsupported }

// Disable is not implemented on this platform.
func Disable() error { return ErrUnsupported }

// Enabled is not implemented on this platform.
func Enabled() (bool, string) { return false, "" }
