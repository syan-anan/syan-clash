//go:build !windows

package autostart

// AcquireSingleInstance always succeeds outside Windows.
func AcquireSingleInstance(name string) (bool, error) { return true, nil }

// ReleaseSingleInstance is a no-op outside Windows.
func ReleaseSingleInstance() {}
