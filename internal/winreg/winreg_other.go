//go:build !windows

package winreg

import "errors"

var errUnsupported = errors.New("winreg: only implemented on Windows")

// SetString is not implemented on this platform.
func SetString(keyPath, name, value string) error { return errUnsupported }

// SetDWORD is not implemented on this platform.
func SetDWORD(keyPath, name string, value uint32) error { return errUnsupported }

// GetString is not implemented on this platform.
func GetString(keyPath, name string) (string, error) { return "", errUnsupported }

// GetDWORD is not implemented on this platform.
func GetDWORD(keyPath, name string) (uint32, error) { return 0, errUnsupported }

// DeleteValue is not implemented on this platform.
func DeleteValue(keyPath, name string) error { return errUnsupported }

// DeleteKey is not implemented on this platform.
func DeleteKey(keyPath string) error { return errUnsupported }
