//go:build !windows

package winreg

import "errors"

// GetMachineString and SubKeysMachine read the machine registry, which only
// exists on Windows. The stubs keep the rest of the client buildable.
func GetMachineString(keyPath, name string) (string, error) {
	return "", errors.New("winreg: machine registry is Windows-only")
}

func SubKeysMachine(keyPath string) ([]string, error) {
	return nil, errors.New("winreg: machine registry is Windows-only")
}
