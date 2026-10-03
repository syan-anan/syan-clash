//go:build !windows

package winsvc

import "time"

// The SCM does not exist outside Windows: every call reports ErrUnsupported so
// the rest of the client can keep building and running on any platform.

func Query(name string) (Status, error) {
	return Status{}, ErrUnsupported
}

func Install(cfg InstallConfig) error {
	return ErrUnsupported
}

func Uninstall(name string) error {
	return ErrUnsupported
}

func Start(name string) error {
	return ErrUnsupported
}

func Stop(name string) error {
	return ErrUnsupported
}

func WaitForState(name string, want State, timeout time.Duration) (Status, error) {
	return Status{}, ErrUnsupported
}
