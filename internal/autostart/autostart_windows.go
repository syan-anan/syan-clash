//go:build windows

// Package autostart manages the per-user "run at login" entry and the
// single-instance guard.
package autostart

import (
	"errors"
	"fmt"
	"strings"

	"vvpn/internal/winreg"
)

const runKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`
const valueName = "syan-clash"

// Enable registers the current executable to start at user login. The entry
// goes straight into HKCU\...\Run through advapi32, so no reg.exe - and no
// console window - is involved.
func Enable(executable string, args []string) error {
	command := quote(executable)
	for _, a := range args {
		command += " " + quote(a)
	}
	if err := winreg.SetString(runKeyPath, valueName, command); err != nil {
		return fmt.Errorf("autostart: %w", err)
	}
	return nil
}

// Disable removes the login entry. A missing value means it was already off,
// which is not an error for the caller.
func Disable() error {
	if err := winreg.DeleteValue(runKeyPath, valueName); err != nil && !errors.Is(err, winreg.ErrNotFound) {
		return fmt.Errorf("autostart: %w", err)
	}
	return nil
}

// Enabled reports whether the login entry exists, and what command it runs.
func Enabled() (bool, string) {
	command, err := winreg.GetString(runKeyPath, valueName)
	if err != nil {
		return false, ""
	}
	return true, command
}

func quote(s string) string {
	if !strings.ContainsAny(s, " \t") {
		return s
	}
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}
