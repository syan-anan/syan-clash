//go:build !windows

package main

import "os/exec"

// hideWindow is a no-op where a child process cannot raise a console window.
func hideWindow(cmd *exec.Cmd) {}
