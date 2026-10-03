//go:build !windows

package shellopen

import (
	"errors"
	"os/exec"
	"runtime"
)

// Self is Windows-only: the AI sign-in window is an embedded WebView2 control,
// and this package exists so the tree still compiles elsewhere.
func Self(args ...string) error {
	return errors.New("仅 Windows 支持")
}

// Dir opens dir in the platform's file manager. The Windows build is the one
// that ships; this exists so the package still compiles everywhere.
func Dir(dir string) error {
	opener := "xdg-open"
	if runtime.GOOS == "darwin" {
		opener = "open"
	}
	cmd := exec.Command(opener, dir)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
