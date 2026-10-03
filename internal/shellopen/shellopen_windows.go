//go:build windows

// Package shellopen hands a folder to the desktop's file manager. Exactly one
// button uses it ("打开数据目录"), and it never starts a command interpreter:
// explorer.exe is a GUI binary and the child is created without a console
// window either way.
package shellopen

import (
	"os"
	"os/exec"
	"syscall"
)

// createNoWindow keeps a console from flashing for any child that happens to
// be a console program.
const createNoWindow = 0x08000000

// Self launches another copy of this executable with the given arguments. The
// AI sign-in window is the only caller: it needs its own window and its own
// browser profile, and handing it to a separate process means a crash there can
// never take the console down with it. The child is a GUI binary, so the
// no-window flags below are belt and braces rather than a fix for a flash.
func Self(args ...string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

// Dir opens dir in Explorer.
func Dir(dir string) error {
	cmd := exec.Command("explorer.exe", dir)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	if err := cmd.Start(); err != nil {
		return err
	}
	// Explorer hands the request to the already-running shell and exits. The
	// caller has nothing to wait for, but reaping the child keeps the process
	// table tidy instead of leaving a zombie behind every click.
	go func() { _ = cmd.Wait() }()
	return nil
}
