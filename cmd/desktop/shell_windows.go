//go:build windows

package main

// User32 entry points shared by the window files. Everything that used to live
// here - finding an installed Edge/Chrome, launching an "--app=" window,
// hunting for browser windows by title, posting WM_CLOSE to them - is gone on
// purpose: the console is embedded (WebView2) and no code path in this client
// may start an external browser window.
var (
	procEnumWindows         = user32.NewProc("EnumWindows")
	procGetClassNameW       = user32.NewProc("GetClassNameW")
	procPostMessageW        = user32.NewProc("PostMessageW")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	procIsIconic            = user32.NewProc("IsIconic")
	procIsWindowVisible     = user32.NewProc("IsWindowVisible")
	procSetWindowPos        = user32.NewProc("SetWindowPos")
)

// swRestore is SW_RESTORE: un-minimise without stealing the size the user set.
const swRestore = 9

// SetWindowPos arguments: raising a window that is already on screen must not
// change its geometry and must not take the keyboard focus away from whatever
// the user is typing in.
const (
	hwndTop       = 0
	swpNoSize     = 0x0001
	swpNoMove     = 0x0002
	swpNoActivate = 0x0010
)
