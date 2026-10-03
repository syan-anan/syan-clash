//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// hideWindow starts the guard with CREATE_NO_WINDOW: the same flag the core
// supervisor uses, so the second copy of the exe never owns a console window.
func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
}
