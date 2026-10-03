//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"testing"
	"unsafe"
)

func TestDecodeWindowCommand(t *testing.T) {
	for _, command := range []string{"drag", "min", "max", "close", "selftest-ping"} {
		object, err := json.Marshal(map[string]string{"cmd": command})
		if err != nil {
			t.Fatal(err)
		}
		quoted, err := json.Marshal(string(object))
		if err != nil {
			t.Fatal(err)
		}
		for _, payload := range []string{string(object), string(quoted)} {
			if got := decodeWindowCommand(payload); got != command {
				t.Errorf("decodeWindowCommand(%s) = %q, want %q", payload, got, command)
			}
		}
	}
	for _, payload := range []string{
		``, `null`, `[]`, `"min"`, `{"cmd":`, `{"cmd":3}`, `{"cmd":"unknown"}`,
		`{"note":"min"}`, `{"cmd":"unknown","note":"close"}`,
		`{"cmd":{"nested":"max"}}`, `{"cmd":"MIN"}`, `{"cmd":"min"} trailing`,
	} {
		if got := decodeWindowCommand(payload); got != "" {
			t.Errorf("decodeWindowCommand(%s) = %q, want no command", payload, got)
		}
	}
	if got := decodeWindowCommand(`{"cmd":"min","note":"drag"}`); got != "min" {
		t.Fatalf("unrelated data changed the command: %q", got)
	}
}

type testWebMessageArgs struct {
	vtbl *[5]uintptr
	json []uint16
}

var testGetWebMessageJSON = syscall.NewCallback(func(this, out uintptr) uintptr {
	args := (*testWebMessageArgs)(unsafe.Pointer(this))
	return writeTaskMemString(out, args.json)
})

func sendTestWebMessage(t *testing.T, context *webViewContext, payload string) {
	t.Helper()
	wide, err := syscall.UTF16FromString(payload)
	if err != nil {
		t.Fatal(err)
	}
	args := &testWebMessageArgs{vtbl: &[5]uintptr{4: testGetWebMessageJSON}, json: wide}
	context.invoke(handlerMessage, 0, uintptr(unsafe.Pointer(args)))
	runtime.KeepAlive(args)
}

// A private desktop lets ShowWindow exercise the real Win32 state transitions
// without putting a window on the user's active desktop. Never SwitchDesktop.
func TestWindowCommandsOnIsolatedDesktop(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	getThreadID := kernel32.NewProc("GetCurrentThreadId")
	getThreadDesktop := user32.NewProc("GetThreadDesktop")
	createDesktop := user32.NewProc("CreateDesktopW")
	setThreadDesktop := user32.NewProc("SetThreadDesktop")
	closeDesktop := user32.NewProc("CloseDesktop")
	peekMessage := user32.NewProc("PeekMessageW")
	isWindow := user32.NewProc("IsWindow")
	threadID, _, _ := getThreadID.Call()
	original, _, _ := getThreadDesktop.Call(threadID)
	name, err := syscall.UTF16PtrFromString(fmt.Sprintf("syan-window-test-%d-%d", os.Getpid(), threadID))
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

	oldHooks := windowHooks
	oldMessage, oldCommand, oldCount := lastWebMessage, lastWebCmd, webMessageCount
	defer func() {
		windowHooks = oldHooks
		lastWebMessage, lastWebCmd, webMessageCount = oldMessage, oldCommand, oldCount
	}()
	hwnd, err := createMainWindow("isolated window control test", 20, 20, 640, 480, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		procDestroyWindow.Call(hwnd)
		var message msg
		// DestroyWindow posts WM_QUIT to this test thread, not the application.
		peekMessage.Call(uintptr(unsafe.Pointer(&message)), 0, 0x0012, 0x0012, 1)
	}()
	context := &webViewContext{hwnd: hwnd}
	windowHooks = &windowCallbacks{close: func() bool { return true }}

	sendTestWebMessage(t, context, `"{\"cmd\":\"selftest-ping\"}"`)
	if !context.windowPing {
		t.Fatal("decoded ping did not confirm the window bridge")
	}
	sendTestWebMessage(t, context, `"{\"cmd\":\"min\"}"`)
	if iconic, _, _ := procIsIconic.Call(hwnd); iconic == 0 {
		t.Fatal("string-encoded min did not minimize the window")
	}
	sendTestWebMessage(t, context, `{"cmd":"max"}`)
	if !isZoomed(hwnd) {
		t.Fatal("object max did not maximize the window")
	}
	sendTestWebMessage(t, context, `"{\"cmd\":\"max\"}"`)
	if isZoomed(hwnd) {
		t.Fatal("second max did not restore the window")
	}
	if iconic, _, _ := procIsIconic.Call(hwnd); iconic != 0 {
		t.Fatal("restored window is still minimized")
	}

	sendTestWebMessage(t, context, `{"cmd":"drag"}`)
	var drag msg
	if got, _, _ := peekMessage.Call(uintptr(unsafe.Pointer(&drag)), hwnd, wmNCLButtonDown, wmNCLButtonDown, 1); got == 0 {
		t.Fatal("drag did not queue a native caption mouse-down")
	}
	if drag.WParam != htCaption {
		t.Fatalf("drag hit target = %d, want HTCAPTION", drag.WParam)
	}
	// Removing the message proves dispatch without entering a mouse tracking
	// loop that would require user input to finish.

	sendTestWebMessage(t, context, `{"cmd":"unknown","note":"close"}`)
	var closeMessage msg
	if got, _, _ := peekMessage.Call(uintptr(unsafe.Pointer(&closeMessage)), hwnd, wmClose, wmClose, 1); got != 0 {
		t.Fatal("unrelated close text queued WM_CLOSE")
	}
	sendTestWebMessage(t, context, `"{\"cmd\":\"close\"}"`)
	if got, _, _ := peekMessage.Call(uintptr(unsafe.Pointer(&closeMessage)), hwnd, wmClose, wmClose, 1); got == 0 {
		t.Fatal("close did not queue WM_CLOSE")
	}
	procDispatch.Call(uintptr(unsafe.Pointer(&closeMessage)))
	if visible, _, _ := procIsWindowVisible.Call(hwnd); visible != 0 {
		t.Fatal("close did not hide the window")
	}
	if exists, _, _ := isWindow.Call(hwnd); exists == 0 {
		t.Fatal("close destroyed the window instead of hiding it to the tray")
	}
	t.Log("native min/max/restore/close state verified; drag queued as WM_NCLBUTTONDOWN/HTCAPTION on an inactive desktop")
}
