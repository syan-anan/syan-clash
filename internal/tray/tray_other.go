//go:build !windows

package tray

import "errors"

// ErrUnsupported is returned on platforms where the tray is not implemented.
var ErrUnsupported = errors.New("tray: only implemented on Windows")

// MenuItem is one entry in the tray menu.
type MenuItem struct {
	Label  string
	Action func()
}

// Options configures the tray icon.
type Options struct {
	Tooltip  string
	IconPath string
	Items    []MenuItem
	OnClick  func()
}

// Available reports whether a tray icon can be created.
func Available() bool { return false }

// Run is not implemented on this platform.
func Run(opts Options) error { return ErrUnsupported }

// Quit is a no-op on this platform.
func Quit() {}

// Notify is a no-op on this platform.
func Notify(title, message string) {}
