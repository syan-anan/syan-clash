// Package winreg is a tiny per-user (HKCU) registry helper built directly on
// advapi32. The client only stores its own settings there, so a handful of
// functions over the Win32 API are all it needs - and, unlike shelling out to
// reg.exe, they never open a console window.
package winreg

import "errors"

// ErrNotFound reports a value (or its key) that does not exist.
var ErrNotFound = errors.New("winreg: value not found")
