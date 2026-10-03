//go:build !windows

package core

import "os/exec"

// attachToJob is a no-op outside Windows; there the child is killed explicitly
// on shutdown.
func attachToJob(cmd *exec.Cmd) error { return nil }
