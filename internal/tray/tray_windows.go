//go:build windows

// Package tray provides a minimal Windows notification-area icon with a menu,
// implemented directly on Shell_NotifyIcon so the client stays dependency free.
package tray

import (
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

var (
	shell32              = syscall.NewLazyDLL("shell32.dll")
	user32               = syscall.NewLazyDLL("user32.dll")
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	procShellNotifyIconW = shell32.NewProc("Shell_NotifyIconW")
	procCreatePopupMenu  = user32.NewProc("CreatePopupMenu")
	procAppendMenuW      = user32.NewProc("AppendMenuW")
	procDestroyMenu      = user32.NewProc("DestroyMenu")
	procTrackPopupMenu   = user32.NewProc("TrackPopupMenu")
	procCreateWindowExW  = user32.NewProc("CreateWindowExW")
	procDefWindowProcW   = user32.NewProc("DefWindowProcW")
	procRegisterClassExW = user32.NewProc("RegisterClassExW")
	procDestroyWindow    = user32.NewProc("DestroyWindow")
	procGetMessageW      = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessageW = user32.NewProc("DispatchMessageW")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procGetCursorPos     = user32.NewProc("GetCursorPos")
	procSetForegroundWin = user32.NewProc("SetForegroundWindow")
	procGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
	procLoadImageW       = user32.NewProc("LoadImageW")
	procLoadIconW        = user32.NewProc("LoadIconW")
	procGetMetrics       = user32.NewProc("GetSystemMetrics")
	procRegisterHotKey   = user32.NewProc("RegisterHotKey")
	procUnregisterHotKey = user32.NewProc("UnregisterHotKey")
)

const (
	nimAdd        = 0x00000000
	nimModify     = 0x00000001
	nimDelete     = 0x00000002
	nimModifyInfo = 0x00000001
	nifInfo       = 0x00000010
	nimSetVersion = 0x00000004
	nifMessage    = 0x00000001
	nifIcon       = 0x00000002
	nifTip        = 0x00000004
	wmApp         = 0x8000
	wmLButtonUp   = 0x0202
	wmRButtonUp   = 0x0205
	wmDestroy     = 0x0002
	tpmLeftAlign  = 0x0000
	tpmBottom     = 0x0020
	tpmRightAlign = 0x0008
	// tpmReturnCmd makes TrackPopupMenu return the chosen command id instead of
	// posting WM_COMMAND to the owner window. Without it the call returns TRUE
	// (1) for every selection, which the caller then reads as "item 1" - so
	// every menu entry silently ran the first one ("打开窗口") and the rest of
	// the menu, including 彻底退出, appeared to do nothing at all.
	tpmReturnCmd   = 0x0100
	mfString       = 0x00000000
	mfSeparator    = 0x00000800
	imageIcon      = 1
	lrLoadFromFile = 0x00000010
	smCxSmIcon     = 49
	smCySmIcon     = 50
	mfChecked      = 0x00000008
	wmHotKey       = 0x0312
)

// Hot-key modifiers, as RegisterHotKey expects them.
const (
	ModAlt     = 0x0001
	ModControl = 0x0002
	ModShift   = 0x0004
	ModWin     = 0x0008
)

// HotKey is one global shortcut. It is registered while the tray owns its
// window, so it works whether or not the client's window is open - that is the
// point of a global shortcut.
type HotKey struct {
	Modifiers  uint32
	VirtualKey uint32
	// Description is only used for log lines when registration fails.
	Description string
	Action      func()
}

type notifyIconData struct {
	Size            uint32
	Wnd             uintptr
	ID              uint32
	Flags           uint32
	CallbackMessage uint32
	Icon            uintptr
	Tip             [128]uint16
	State           uint32
	StateMask       uint32
	Info            [256]uint16
	Version         uint32
	InfoTitle       [64]uint16
	InfoFlags       uint32
	Guid            [16]byte
	BalloonIcon     uintptr
}

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   uintptr
	Icon       uintptr
	Cursor     uintptr
	Background uintptr
	MenuName   *uint16
	ClassName  *uint16
	IconSmall  uintptr
}

type point struct{ X, Y int32 }

// MenuItem is one entry in the tray menu; empty Label means a separator.
type MenuItem struct {
	Label  string
	Action func()
	// Checked draws the menu's check mark. It is what makes the routing mode
	// and the master switch readable at a glance.
	Checked bool
}

// Options configures the tray icon.
type Options struct {
	Tooltip  string
	IconPath string
	// Items is the static menu. DynamicItems, when set, is called just before
	// the menu opens and its result is used instead: the menu then always shows
	// the state the client is in right now (checked mode, master switch).
	Items        []MenuItem
	DynamicItems func() []MenuItem
	OnClick      func()
	// HotKeys are registered for the lifetime of the tray.
	HotKeys []HotKey
	// Logf, when set, receives non-fatal problems (a hot key another program
	// already owns, for example).
	Logf func(format string, args ...any)
}

func logf(opts Options, format string, args ...any) {
	if opts.Logf != nil {
		opts.Logf(format, args...)
	}
}

var (
	// live tracks the one notification icon that is on screen, so SetStatus and
	// SetTooltip can modify it from any goroutine without holding Options.
	liveMu   sync.Mutex
	liveSet  bool
	liveHWND uintptr
	liveID   uint32
	liveIcon uintptr
	liveTip  string

	hotKeyMu sync.Mutex
	hotKeys  = map[uint32]func(){}

	callbacksMu sync.Mutex
	callbacks          = map[uint32]Options{}
	nextID      uint32 = 1

	classOnce sync.Once
	className = syscall.StringToUTF16Ptr("syan-clashTrayWindow")
	wndProc   = syscall.NewCallback(trayWndProc)
)

// Available reports whether the tray could be created in this session.
func Available() bool {
	hwnd, err := createWindow()
	if err != nil {
		return false
	}
	_, _, _ = procDestroyWindow.Call(hwnd)
	return true
}

// Run creates the tray icon and pumps messages until Quit is called. It blocks,
// so callers normally run it on its own goroutine.
func Run(opts Options) error {
	// Win32 windows and their message queue are owned by the thread that
	// created them; Go would otherwise migrate this goroutine between OS
	// threads and the message loop would stop receiving events.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hwnd, err := createWindow()
	if err != nil {
		return err
	}
	icon := loadIcon(opts.IconPath)

	callbacksMu.Lock()
	id := nextID
	nextID++
	callbacks[id] = opts
	callbacksMu.Unlock()

	data := notifyIconData{
		Size:            uint32(unsafe.Sizeof(notifyIconData{})),
		Wnd:             hwnd,
		ID:              id,
		Flags:           nifMessage | nifIcon | nifTip,
		CallbackMessage: wmApp + 1,
		Icon:            icon,
	}
	copyTip(data.Tip[:], opts.Tooltip)
	if ret, _, callErr := procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&data))); ret == 0 {
		return fmt.Errorf("tray: Shell_NotifyIcon(NIM_ADD) failed: %v", callErr)
	}
	liveMu.Lock()
	liveSet, liveHWND, liveID, liveIcon, liveTip = true, hwnd, id, icon, opts.Tooltip
	liveMu.Unlock()
	registered := registerHotKeys(hwnd, opts)
	defer func() {
		liveMu.Lock()
		liveSet = false
		liveMu.Unlock()
		unregisterHotKeys(hwnd, registered)
		_, _, _ = procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&data)))
		_, _, _ = procDestroyWindow.Call(hwnd)
		callbacksMu.Lock()
		delete(callbacks, id)
		callbacksMu.Unlock()
	}()

	var msg struct {
		Hwnd    uintptr
		Message uint32
		WParam  uintptr
		LParam  uintptr
		Time    uint32
		Pt      point
	}
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(ret) <= 0 {
			return nil
		}
		_, _, _ = procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		_, _, _ = procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

// Quit stops the message loop of the tray on this thread.
// Notification icon flags used to raise a balloon/tray toast.
const (
	niifInfo    = 0x00000001
	niifWarning = 0x00000002
)

// Notify raises a balloon/toast from the icon currently in the notification
// area. It never creates a window, never steals focus and is a no-op when no
// icon is on screen: this is the quiet channel the client uses to report a
// problem it cannot show in its own window.
func Notify(title, message string) {
	liveMu.Lock()
	hwnd, id, set := liveHWND, liveID, liveSet
	liveMu.Unlock()
	if !set || hwnd == 0 {
		return
	}
	data := notifyIconData{
		Size:      uint32(unsafe.Sizeof(notifyIconData{})),
		Wnd:       hwnd,
		ID:        id,
		Flags:     nifInfo,
		InfoFlags: niifWarning,
	}
	copyTip(data.Info[:], message)
	copyTip(data.InfoTitle[:], title)
	_, _, _ = procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&data)))
}

func Quit() { _, _, _ = procPostQuitMessage.Call(0) }

// registerHotKeys claims the shortcuts and returns the ids that were taken.
// A combination another program already owns is reported, not fatal: losing a
// shortcut must never stop the client from starting.
func registerHotKeys(hwnd uintptr, opts Options) []uint32 {
	registered := make([]uint32, 0, len(opts.HotKeys))
	for i, hk := range opts.HotKeys {
		if hk.Action == nil || hk.VirtualKey == 0 {
			continue
		}
		id := uint32(i + 1)
		ret, _, callErr := procRegisterHotKey.Call(hwnd, uintptr(id),
			uintptr(hk.Modifiers), uintptr(hk.VirtualKey))
		if ret == 0 {
			logf(opts, "tray: hot key %q could not be registered: %v", hk.Description, callErr)
			continue
		}
		hotKeyMu.Lock()
		hotKeys[id] = hk.Action
		hotKeyMu.Unlock()
		registered = append(registered, id)
	}
	return registered
}

func unregisterHotKeys(hwnd uintptr, ids []uint32) {
	for _, id := range ids {
		_, _, _ = procUnregisterHotKey.Call(hwnd, uintptr(id))
		hotKeyMu.Lock()
		delete(hotKeys, id)
		hotKeyMu.Unlock()
	}
}

func createWindow() (uintptr, error) {
	classOnce.Do(func() {
		instance, _, _ := procGetModuleHandleW.Call(0)
		wc := wndClassEx{
			Size:      uint32(unsafe.Sizeof(wndClassEx{})),
			WndProc:   wndProc,
			Instance:  instance,
			ClassName: className,
		}
		_, _, _ = procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	})
	instance, _, _ := procGetModuleHandleW.Call(0)
	hwnd, _, callErr := procCreateWindowExW.Call(
		0, uintptr(unsafe.Pointer(className)), 0, 0,
		0, 0, 0, 0, 0, 0, instance, 0,
	)
	if hwnd == 0 {
		return 0, fmt.Errorf("tray: CreateWindowEx failed: %v", callErr)
	}
	return hwnd, nil
}

func trayWndProc(hwnd uintptr, msg uint32, wparam, lparam uintptr) uintptr {
	switch msg {
	case wmApp + 1:
		switch uint32(lparam) {
		case wmLButtonUp:
			if opts, ok := currentOptions(wparam); ok && opts.OnClick != nil {
				go opts.OnClick()
			}
		case wmRButtonUp:
			if opts, ok := currentOptions(wparam); ok {
				items := opts.Items
				if opts.DynamicItems != nil {
					items = opts.DynamicItems()
				}
				showMenu(hwnd, items)
			}
		}
		return 0
	case wmHotKey:
		hotKeyMu.Lock()
		action := hotKeys[uint32(wparam)]
		hotKeyMu.Unlock()
		if action != nil {
			go action()
		}
		return 0
	case wmDestroy:
		_, _, _ = procPostQuitMessage.Call(0)
		return 0
	}
	ret, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wparam, lparam)
	return ret
}

func currentOptions(id uintptr) (Options, bool) {
	callbacksMu.Lock()
	defer callbacksMu.Unlock()
	opts, ok := callbacks[uint32(id)]
	return opts, ok
}

func showMenu(hwnd uintptr, items []MenuItem) {
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer func() { _, _, _ = procDestroyMenu.Call(menu) }()

	for i, item := range items {
		if item.Label == "" {
			_, _, _ = procAppendMenuW.Call(menu, mfSeparator, 0, 0)
			continue
		}
		label, _ := syscall.UTF16PtrFromString(item.Label)
		flags := uintptr(mfString)
		if item.Checked {
			flags |= mfChecked
		}
		_, _, _ = procAppendMenuW.Call(menu, flags, uintptr(i+1), uintptr(unsafe.Pointer(label)))
	}

	var pt point
	_, _, _ = procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	_, _, _ = procSetForegroundWin.Call(hwnd)
	// TrackPopupMenu returns the command id; the low word holds it.
	cmd, _, _ := procTrackPopupMenu.Call(menu, tpmLeftAlign|tpmRightAlign|tpmBottom|tpmReturnCmd,
		uintptr(pt.X), uintptr(pt.Y), 0, hwnd, 0)
	// The id is the low word of the return value; the high word is reserved.
	index := int(cmd&0xFFFF) - 1
	if index >= 0 && index < len(items) {
		if action := items[index].Action; action != nil {
			go action()
		}
	}
}

// loadIcon resolves the tray bitmap. Path first (a .ico shipped beside the
// executable), then the icon embedded in the executable's own resources, and
// only then the stock system icon: the notification area is the one place where
// a blank-looking square is immediately obvious.
func loadIcon(path string) uintptr {
	if path != "" {
		p, err := syscall.UTF16PtrFromString(path)
		if err == nil {
			// Ask for the notification area's real metric instead of a fixed
			// 16x16: on a scaled display Windows wants 20 or 24 and stretching
			// a 16px frame is exactly what makes a tray icon look soft.
			cx, _, _ := procGetMetrics.Call(smCxSmIcon)
			cy, _, _ := procGetMetrics.Call(smCySmIcon)
			if cx == 0 {
				cx = 16
			}
			if cy == 0 {
				cy = 16
			}
			icon, _, _ := procLoadImageW.Call(0, uintptr(unsafe.Pointer(p)), imageIcon, cx, cy, lrLoadFromFile)
			if icon != 0 {
				return icon
			}
		}
	}
	if mod, _, _ := procGetModuleHandleW.Call(0); mod != 0 {
		if icon, _, _ := procLoadIconW.Call(mod, 1); icon != 0 {
			return icon
		}
	}
	// Fall back to the generic application icon.
	icon, _, _ := procLoadIconW.Call(0, 32512)
	return icon
}

func copyTip(dst []uint16, s string) {
	src := syscall.StringToUTF16(s)
	n := copy(dst[:len(dst)-1], src)
	dst[n] = 0
}
