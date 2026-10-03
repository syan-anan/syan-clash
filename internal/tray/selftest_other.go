//go:build !windows

package tray

import "errors"

// ExportStateIcons exists on Windows only: there is no notification icon to
// draw anywhere else.
func ExportStateIcons(string) ([]string, error) {
	return nil, errors.New("tray: icon export is only available on Windows")
}
