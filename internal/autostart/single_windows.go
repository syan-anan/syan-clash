//go:build windows

package autostart

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procCreateMutexW = kernel32.NewProc("CreateMutexW")
	procCloseHandle  = kernel32.NewProc("CloseHandle")
)

// errnoAlreadyExists is ERROR_ALREADY_EXISTS, which CreateMutex reports as a
// non-fatal "the named object already existed" signal rather than a failure.
var errnoAlreadyExists = syscall.Errno(183)

// lockHandle is kept for the lifetime of the process so the mutex stays held.
var lockHandle uintptr

// AcquireSingleInstance takes a named mutex. It returns false when another
// instance already holds it in this login session.
//
// The mutex lives in the Local\ namespace on purpose: it is per session, so
// creating it needs no privilege at all (Global\ does), and two different
// users logged on at the same time are each entitled to their own client.
func AcquireSingleInstance(name string) (bool, error) {
	namePtr, err := syscall.UTF16PtrFromString(`Local\` + name)
	if err != nil {
		return false, err
	}
	// The third return value of Call is the last error captured by the syscall
	// wrapper; querying GetLastError separately would read a later value.
	handle, _, callErr := procCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(namePtr)))
	if handle == 0 {
		return false, fmt.Errorf("autostart: CreateMutex failed: %v", callErr)
	}
	if errors.Is(callErr, errnoAlreadyExists) {
		_, _, _ = procCloseHandle.Call(handle)
		return false, nil
	}
	lockHandle = handle
	return true, nil
}

// ReleaseSingleInstance drops the mutex (the OS also releases it on exit).
func ReleaseSingleInstance() {
	if lockHandle != 0 {
		_, _, _ = procCloseHandle.Call(lockHandle)
		lockHandle = 0
	}
}
