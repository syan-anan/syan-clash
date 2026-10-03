//go:build windows

package core

import (
	"os/exec"
	"syscall"
)

// hideWindow keeps a spawned core from flashing a console window.
func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000} // CREATE_NO_WINDOW
}
