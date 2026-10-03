//go:build !windows

package app

// processByLocalPort is not implemented outside Windows; the core's own
// process metadata is used instead when available.
func processByLocalPort(source string) string { return "" }

// processPathByPID is not implemented outside Windows.
func processPathByPID(pid uint32) string { return "" }

// selfName is not needed outside Windows.
func selfName() string { return "" }
