//go:build !windows

package diag

// SystemResolvers reports the machine's configured resolvers. Reading them is a
// Windows registry walk; elsewhere the panel has nothing to compare against and
// says so by returning nothing.
func SystemResolvers() []string { return nil }
