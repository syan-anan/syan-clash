//go:build !windows

package main

// messageBox has nothing to call where there is no modal dialog API; the same
// text has already gone to the startup log and to stderr.
func messageBox(title, text string) {}
