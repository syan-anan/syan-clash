//go:build windows

package main

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"testing"
	"unsafe"
)

// The page draws its own title bar, so the top of the client area has to land
// on the top of the work area. A maximised window keeps its resize border
// outside the work area, which would put the client origin at a negative screen
// coordinate and clip the title bar off the top; WM_NCCALCSIZE insets it back.
// GetClientRect only reports the size, so the test reads the client origin
// through ClientToScreen after maximising a real window on a private desktop.
func TestMaximizedClientCoversTheWorkArea(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	getThreadID := kernel32.NewProc("GetCurrentThreadId")
	getThreadDesktop := user32.NewProc("GetThreadDesktop")
	createDesktop := user32.NewProc("CreateDesktopW")
	setThreadDesktop := user32.NewProc("SetThreadDesktop")
	closeDesktop := user32.NewProc("CloseDesktop")
	peekMessage := user32.NewProc("PeekMessageW")
	clientToScreen := user32.NewProc("ClientToScreen")

	threadID, _, _ := getThreadID.Call()
	original, _, _ := getThreadDesktop.Call(threadID)
	name, err := syscall.UTF16PtrFromString(fmt.Sprintf("syan-maximize-test-%d-%d", os.Getpid(), threadID))
	if err != nil {
		t.Fatal(err)
	}
	const desktopAllAccess = 0x01ff
	desktop, _, callErr := createDesktop.Call(uintptr(unsafe.Pointer(name)), 0, 0, 0, desktopAllAccess, 0)
	if desktop == 0 {
		t.Fatalf("CreateDesktopW: %v", callErr)
	}
	defer closeDesktop.Call(desktop)
	if ok, _, callErr := setThreadDesktop.Call(desktop); ok == 0 {
		t.Fatalf("SetThreadDesktop: %v", callErr)
	}
	defer func() {
		if ok, _, callErr := setThreadDesktop.Call(original); ok == 0 {
			t.Errorf("restore thread desktop: %v", callErr)
		}
	}()

	hwnd, err := createMainWindow("maximize geometry test", 20, 20, 640, 480, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		procDestroyWindow.Call(hwnd)
		var message msg
		// DestroyWindow posts WM_QUIT to this test thread, not the application.
		peekMessage.Call(uintptr(unsafe.Pointer(&message)), 0, 0x0012, 0x0012, 1)
	}()

	procShowWindow.Call(hwnd, swMaximize)
	var message msg
	for i := 0; i < 200; i++ {
		got, _, _ := peekMessage.Call(uintptr(unsafe.Pointer(&message)), 0, 0, 0, 1)
		if got == 0 {
			break
		}
		procTranslate.Call(uintptr(unsafe.Pointer(&message)))
		procDispatch.Call(uintptr(unsafe.Pointer(&message)))
	}
	if !isZoomed(hwnd) {
		t.Fatal("ShowWindow(SW_MAXIMIZE) did not maximise the window")
	}

	var window, client rect
	var origin struct{ X, Y int32 }
	procGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&window)))
	procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&client)))
	clientToScreen.Call(hwnd, uintptr(unsafe.Pointer(&origin)))

	var info monitorInfo
	info.Size = uint32(unsafe.Sizeof(info))
	monitor, _, _ := procMonitorFromWin.Call(hwnd, monitorDefaultToNearest)
	if ok, _, _ := procGetMonitorInfo.Call(monitor, uintptr(unsafe.Pointer(&info))); ok == 0 {
		t.Fatal("GetMonitorInfoW failed")
	}
	workWidth := info.Work.Right - info.Work.Left
	workHeight := info.Work.Bottom - info.Work.Top
	thickness := frameThickness(hwnd)

	// The client origin is the assertion that matters: it is where the page
	// starts, so it decides whether the title bar is on screen or above it.
	if origin.X != info.Work.Left || origin.Y != info.Work.Top {
		t.Errorf("maximised client origin = (%d,%d), want the work area origin (%d,%d)",
			origin.X, origin.Y, info.Work.Left, info.Work.Top)
	}
	if client.Right != workWidth || client.Bottom != workHeight {
		t.Errorf("maximised client size = %dx%d, want the work area %dx%d",
			client.Right, client.Bottom, workWidth, workHeight)
	}
	// The window itself keeps the resize border off the work area, so the
	// maximised frame stays reachable from every edge.
	if window.Left != info.Work.Left-thickness || window.Top != info.Work.Top-thickness ||
		window.Right != info.Work.Right+thickness || window.Bottom != info.Work.Bottom+thickness {
		t.Errorf("maximised window rect = [%d,%d %d,%d], want the work area inflated by %d",
			window.Left, window.Top, window.Right, window.Bottom, thickness)
	}

	procShowWindow.Call(hwnd, swRestore)
	t.Logf("maximised window=[%d,%d %d,%d] clientOrigin=[%d,%d] clientSize=%dx%d work=[%d,%d %d,%d] border=%d",
		window.Left, window.Top, window.Right, window.Bottom,
		origin.X, origin.Y, client.Right, client.Bottom,
		info.Work.Left, info.Work.Top, info.Work.Right, info.Work.Bottom, thickness)
}
