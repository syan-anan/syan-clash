//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

var (
	dialogUser32    = syscall.NewLazyDLL("user32.dll")
	procMessageBoxW = dialogUser32.NewProc("MessageBoxW")
)

const (
	mbOK            = 0x00000000
	mbIconInfo      = 0x00000040
	mbSetForeground = 0x00010000
)

// messageBox reports a launch problem to the person who double-clicked. It is
// reached from exactly one place: the second launch, when the instance that is
// already running cannot be reached at all. A GUI build has no console, so the
// alternative there is the silent exit the user experiences as "I clicked and
// nothing happened". No automated path calls it, -no-window suppresses it, and
// -dialog-dry-run prints what it would say instead of showing it.
func messageBox(title, text string) {
	t, errT := syscall.UTF16PtrFromString(title)
	m, errM := syscall.UTF16PtrFromString(text)
	if errT != nil || errM != nil {
		return
	}
	_, _, _ = procMessageBoxW.Call(0,
		uintptr(unsafe.Pointer(m)),
		uintptr(unsafe.Pointer(t)),
		uintptr(mbOK|mbIconInfo|mbSetForeground))
}
