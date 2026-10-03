//go:build !windows

package urlscheme

import "fmt"

// Current always reports an unregistered scheme outside Windows; there is no
// registry to read.
func Current(scheme string) Registration {
	return Registration{Scheme: scheme, Key: KeyPath(scheme)}
}

// Register is not implemented outside Windows.
func Register(scheme, exePath string) (Registration, error) {
	return Registration{Scheme: scheme, Key: KeyPath(scheme)}, fmt.Errorf("urlscheme: 只有 Windows 能注册 URL scheme")
}

// Unregister is not implemented outside Windows.
func Unregister(scheme string) error {
	return fmt.Errorf("urlscheme: 只有 Windows 能注册 URL scheme")
}
