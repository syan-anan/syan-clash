//go:build windows

// Command desktop is the real Windows client: an .exe that opens its own
// window, hosts the console UI in an embedded WebView2 control, and owns the
// notification-area icon. It starts the same HTTP control server the headless
// build does, so nothing about the UI or the API changes.
//
// This file owns the window itself: class registration, creation, the message
// pump and the window procedure. The WebView2 control that fills the window
// lives in webview_windows.go and talks to the window through windowHooks.
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	user32             = syscall.NewLazyDLL("user32.dll")
	gdi32              = syscall.NewLazyDLL("gdi32.dll")
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	dwmapi             = syscall.NewLazyDLL("dwmapi.dll")
	procRegisterClass  = user32.NewProc("RegisterClassExW")
	procCreateWindow   = user32.NewProc("CreateWindowExW")
	procDwmSetAttr     = dwmapi.NewProc("DwmSetWindowAttribute")
	procDefWindowProc  = user32.NewProc("DefWindowProcW")
	procGetMessage     = user32.NewProc("GetMessageW")
	procTranslate      = user32.NewProc("TranslateMessage")
	procDispatch       = user32.NewProc("DispatchMessageW")
	procShowWindow     = user32.NewProc("ShowWindow")
	procUpdateWindow   = user32.NewProc("UpdateWindow")
	procPostQuit       = user32.NewProc("PostQuitMessage")
	procDestroyWindow  = user32.NewProc("DestroyWindow")
	procCreateBrush    = gdi32.NewProc("CreateSolidBrush")
	procGetModule      = kernel32.NewProc("GetModuleHandleW")
	procLoadCursor     = user32.NewProc("LoadCursorW")
	procLoadIcon       = user32.NewProc("LoadIconW")
	procLoadImageW     = user32.NewProc("LoadImageW")
	procSendMessage    = user32.NewProc("SendMessageW")
	procGetMetrics     = user32.NewProc("GetSystemMetrics")
	procMonitorFromWin = user32.NewProc("MonitorFromWindow")
	procGetMonitorInfo = user32.NewProc("GetMonitorInfoW")
	procGetWindowRect  = user32.NewProc("GetWindowRect")
	procGetDpiForWin   = user32.NewProc("GetDpiForWindow")
	procGetCursorPos   = user32.NewProc("GetCursorPos")
	procReleaseCapture = user32.NewProc("ReleaseCapture")
	procIsZoomed       = user32.NewProc("IsZoomed")
)

const (
	wsOverlappedWindow = 0x00CF0000
	wsVisible          = 0x10000000
	cwUseDefault       = 0x80000000
	wmDestroy          = 0x0002
	wmSize             = 0x0005
	wmClose            = 0x0010
	wmTimer            = 0x0113
	swHide             = 0
	swShow             = 5
	idcArrow           = 32512
	idiApplication     = 32512

	// Icon metrics and the two slots a window keeps (taskbar/alt-tab uses the
	// big one, the title bar and task switcher list use the small one).
	imageIcon = 1
	// The icon group is emitted as "#1" (winres.json). The name below is what
	// the resource builder used before that, kept as a fallback lookup so
	// renaming the group can never silently downgrade the taskbar to the stock
	// Windows icon again.
	iconGroupName = "APP"
	smCxIcon      = 11
	smCyIcon      = 12
	smCxSmIcon    = 49
	smCySmIcon    = 50
	wmSetIcon     = 0x0080
	iconSmall     = 0
	iconBig       = 1

	// Application-private messages. The window belongs to one thread, so the
	// rest of the program never pokes user32 directly: it posts one of these
	// and lets the message loop do the work on the owning thread.
	wmAppFocus = 0x8001 // surface and focus the window
	wmAppQuit  = 0x8002 // close the window for real (the app is quitting)

	// mainWindowClassName identifies the client's own window. Quitting uses
	// it to tell the client's window apart from an unrelated browser window
	// that merely carries a similar title.
	mainWindowClassName = "syan-clashMainWindow"

	// windowBackgroundColor is the COLORREF of #0a0c11, the UI's own
	// background: painting the window in its final colour from the first
	// frame is what keeps opening it from flashing white.
	windowBackgroundColor = 0x00110c0a

	// The caption and border are drawn by the system, and a light Windows
	// theme paints them white around the dark console - the "white edge" the
	// operator keeps seeing. These DWM attributes (Windows 11 22000+) put the
	// frame back into the console's own palette. Every one of them is
	// best-effort: on an older build DwmSetWindowAttribute simply fails and the
	// stock frame stays, which is exactly today's look.
	dwmwaUseImmersiveDarkMode    = 20
	dwmwaUseImmersiveDarkModeOld = 19
	dwmwaBorderColor             = 34
	dwmwaCaptionColor            = 35
	dwmwaTextColor               = 36
	dwmwaColorNone               = 0xFFFFFFFE

	// Custom frame. The page draws its own title bar, so the whole non-client
	// area is removed in WM_NCCALCSIZE and the resize border is re-implemented
	// in WM_NCHITTEST. WS_CAPTION stays in the window style on purpose: that is
	// what still gives the window snap, its drop shadow and the maximise
	// animation, none of which a WS_POPUP window gets.
	wmNCCalcSize    = 0x0083
	wmNCHitTest     = 0x0084
	wmGetMinMaxInfo = 0x0024
	wmNCLButtonDown = 0x00A1

	htClient      = 0
	htCaption     = 2
	htLeft        = 10
	htRight       = 11
	htTop         = 12
	htTopLeft     = 13
	htTopRight    = 14
	htBottom      = 15
	htBottomLeft  = 16
	htBottomRight = 17

	swMinimize = 6
	swMaximize = 3

	// SetWindowPos flags used to force a client-area recalculation.
	swpNoZOrder     = 0x0004
	swpFrameChanged = 0x0020

	monitorDefaultToNearest = 2
	smCxSizeFrame           = 32
	smCySizeFrame           = 33
	smCxPaddedBorder        = 92
)

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

type msg struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
}

type rect struct {
	Left, Top, Right, Bottom int32
}

// ncCalcSizeParams is NCCALCSIZE_PARAMS up to rgrc, the only part the custom
// frame touches: rgrc[0] is the client rectangle Windows proposes, and the
// window procedure rewrites it to drop the caption and the borders.
type ncCalcSizeParams struct {
	Rgrc [3]rect
}

// monitorInfo is MONITORINFO.
type monitorInfo struct {
	Size    uint32
	Monitor rect
	Work    rect
	Flags   uint32
}

// minMaxInfo is MINMAXINFO.
type minMaxInfo struct {
	Reserved     struct{ X, Y int32 }
	MaxSize      struct{ X, Y int32 }
	MaxPosition  struct{ X, Y int32 }
	MinTrackSize struct{ X, Y int32 }
	MaxTrackSize struct{ X, Y int32 }
}

// windowCallbacks carries the window's lifecycle events. The embedded WebView2
// control depends on all of them: it resizes with the window, drives its
// self-test from a timer, and tears down when the window is destroyed.
type windowCallbacks struct {
	resize  func(width, height int32)
	destroy func()
	timer   func(id uintptr)
	close   func() bool
}

var windowHooks *windowCallbacks

// classBrush is the window class background brush, created once.
var classBrush uintptr

// ncCalcCount and ncCalcWParam are diagnostics for the self-test: they record
// how many times WM_NCCALCSIZE arrived and with which wParam, so a frame that
// is still drawn can be told apart from a message that never arrived at all.
var (
	ncCalcCount  uintptr
	ncCalcWParam uintptr
)

// backgroundBrush returns the class background brush. A class paints its
// background before the first WM_PAINT, so this is what the window shows
// while the embedded browser is still starting.
func backgroundBrush() uintptr {
	if classBrush == 0 {
		classBrush, _, _ = procCreateBrush.Call(windowBackgroundColor)
	}
	return classBrush
}

var windowProc = syscall.NewCallback(func(hwnd uintptr, message uint32, wparam, lparam uintptr) uintptr {
	hooks := windowHooks
	switch message {
	case wmClose:
		// Closing the window hides it instead of destroying it: the tray owns
		// the lifetime (the way every desktop proxy client behaves), and the
		// window must come back instantly, without rebuilding the browser.
		// Quitting posts wmAppQuit, which does destroy it.
		if hooks != nil && hooks.close != nil && hooks.close() {
			procShowWindow.Call(hwnd, swHide)
			return 0
		}
	case wmAppFocus:
		// Surfacing the window is always a user gesture (tray click, global
		// hotkey, a second double-click of the exe), but it must never pull the
		// keyboard focus out of whatever the user is typing in. A hidden or
		// minimised window is restored and focused; a window that is already on
		// screen is only raised - without focus, without resizing, without a
		// z-order fight.
		iconic, _, _ := procIsIconic.Call(hwnd)
		if iconic != 0 {
			procShowWindow.Call(hwnd, swRestore)
			procSetForegroundWindow.Call(hwnd)
			return 0
		}
		visible, _, _ := procIsWindowVisible.Call(hwnd)
		if visible == 0 {
			procShowWindow.Call(hwnd, uintptr(swShow))
			procSetForegroundWindow.Call(hwnd)
			return 0
		}
		procSetWindowPos.Call(hwnd, uintptr(hwndTop), 0, 0, 0, 0,
			uintptr(swpNoMove|swpNoSize|swpNoActivate))
		return 0
	case wmAppQuit:
		procDestroyWindow.Call(hwnd)
		return 0
	case wmTimer:
		if hooks != nil && hooks.timer != nil {
			hooks.timer(wparam)
			return 0
		}
	case wmDestroy:
		if hooks != nil && hooks.destroy != nil {
			hooks.destroy()
		}
		procPostQuit.Call(0)
		return 0
	case wmSize:
		if hooks != nil && hooks.resize != nil {
			width := int32(lparam & 0xFFFF)
			height := int32((lparam >> 16) & 0xFFFF)
			hooks.resize(width, height)
		}
		ret, _, _ := procDefWindowProc.Call(hwnd, uintptr(message), wparam, lparam)
		return ret
	case wmNCCalcSize:
		// wParam FALSE means "just tell me the client rect"; only the TRUE
		// form carries a rectangle to rewrite.
		ncCalcCount++
		ncCalcWParam = wparam
		if wparam != 0 {
			if p := (*ncCalcSizeParams)(unsafe.Pointer(lparam)); p != nil {
				if isZoomed(hwnd) {
					// A maximised window hangs its frame off-screen. Without
					// this the client area would reach under the taskbar.
					fx := frameThickness(hwnd)
					fy := frameThickness(hwnd)
					p.Rgrc[0].Left += fx
					p.Rgrc[0].Right -= fx
					p.Rgrc[0].Top += fy
					p.Rgrc[0].Bottom -= fy
				}
			}
			return 0
		}
	case wmNCHitTest:
		// Resize borders only. Everything else stays HTCLIENT so the page's own
		// title bar receives the clicks that move, minimise, maximise and close
		// the window through the WebView2 message bridge.
		return hitTestResize(hwnd, lparam)
	case wmGetMinMaxInfo:
		applyWorkArea(hwnd, (*minMaxInfo)(unsafe.Pointer(lparam)))
		return 0
	}
	ret, _, _ := procDefWindowProc.Call(hwnd, uintptr(message), wparam, lparam)
	return ret
})

// createMainWindow registers the window class and creates the main window.
// x and y accept cwUseDefault; visible=false creates the window without ever
// showing it, which is how the self-test drives the whole stack without
// putting anything on the user's screen.
func createMainWindow(title string, x, y, width, height int, visible bool) (uintptr, error) {
	instance, _, _ := procGetModule.Call(0)
	className, err := syscall.UTF16PtrFromString(mainWindowClassName)
	if err != nil {
		return 0, err
	}
	titlePtr, err := syscall.UTF16PtrFromString(title)
	if err != nil {
		return 0, err
	}

	bigIcon := moduleIcon(instance, smCxIcon, smCyIcon)
	smallIcon := moduleIcon(instance, smCxSmIcon, smCySmIcon)
	cursor, _, _ := procLoadCursor.Call(0, uintptr(idcArrow))

	wc := wndClassEx{
		Size:       uint32(unsafe.Sizeof(wndClassEx{})),
		WndProc:    windowProc,
		Instance:   instance,
		Icon:       bigIcon,
		Cursor:     cursor,
		Background: backgroundBrush(),
		ClassName:  className,
		IconSmall:  smallIcon,
	}
	ret, _, callErr := procRegisterClass.Call(uintptr(unsafe.Pointer(&wc)))
	if ret == 0 {
		// Registering the same class twice fails with
		// ERROR_CLASS_ALREADY_EXISTS: once a window has been created in this
		// process that is the normal state, not an error.
		if errno, ok := callErr.(syscall.Errno); !ok || errno != 1410 {
			return 0, fmt.Errorf("RegisterClassEx 失败：%v", callErr)
		}
	}

	style := uintptr(wsOverlappedWindow)
	if visible {
		style |= wsVisible
	}
	hwnd, _, callErr := procCreateWindow.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(titlePtr)),
		style,
		uintptr(x), uintptr(y),
		uintptr(width), uintptr(height),
		0, 0, instance, 0,
	)
	if hwnd == 0 {
		return 0, fmt.Errorf("CreateWindowEx 失败：%v", callErr)
	}
	// The class icon covers the window from creation; setting both slots
	// explicitly is what makes the taskbar show the brand icon for the
	// process rather than the stock system one.
	procSendMessage.Call(hwnd, wmSetIcon, iconBig, bigIcon)
	procSendMessage.Call(hwnd, wmSetIcon, iconSmall, smallIcon)

	applyDarkFrame(hwnd)

	// A window that has never been shown has not been through a client-area
	// recalculation yet, and Windows only asks with the "recompute" form of
	// WM_NCCALCSIZE once it is. Asking for it here is what makes the custom
	// frame take effect on the very first paint instead of on the first resize.
	procSetWindowPos.Call(hwnd, 0, 0, 0, 0, 0,
		uintptr(swpNoMove|swpNoSize|swpNoZOrder|swpNoActivate|swpFrameChanged))

	if visible {
		procShowWindow.Call(hwnd, uintptr(swShow))
		procUpdateWindow.Call(hwnd)
	}
	return hwnd, nil
}

// applyDarkFrame paints the window frame in the console's own colours. It runs
// once, right after creation, and it never fails the window: every attribute is
// best-effort, so an older Windows just keeps its stock frame.
func applyDarkFrame(hwnd uintptr) {
	if err := dwmapi.Load(); err != nil {
		return
	}
	dark := int32(1)
	if r, _, _ := procDwmSetAttr.Call(hwnd, dwmwaUseImmersiveDarkMode,
		uintptr(unsafe.Pointer(&dark)), unsafe.Sizeof(dark)); r != 0 {
		// Windows 10 1809..18985 answered attribute 19, not 20.
		procDwmSetAttr.Call(hwnd, dwmwaUseImmersiveDarkModeOld,
			uintptr(unsafe.Pointer(&dark)), unsafe.Sizeof(dark))
	}
	none := uint32(dwmwaColorNone)
	procDwmSetAttr.Call(hwnd, dwmwaBorderColor, uintptr(unsafe.Pointer(&none)), unsafe.Sizeof(none))
	caption := uint32(windowBackgroundColor)
	procDwmSetAttr.Call(hwnd, dwmwaCaptionColor, uintptr(unsafe.Pointer(&caption)), unsafe.Sizeof(caption))
	ink := uint32(0x00f4e9e8) // #e8e9f4, the console's --ink, as a COLORREF
	procDwmSetAttr.Call(hwnd, dwmwaTextColor, uintptr(unsafe.Pointer(&ink)), unsafe.Sizeof(ink))
}

// moduleIcon loads one size of the icon embedded in the executable itself.
//
// rsrc links the .ico in as RT_GROUP_ICON, resource id 1, so nothing has to be
// shipped beside the exe and nothing has to be loaded from disk. Passing the
// wanted metric picks the matching frame out of the multi-size icon instead of
// letting Windows stretch a 32x32 into a blurry title-bar bitmap.
//
// The stock application icon is the fallback for the rare build that was made
// without the resource section.
func moduleIcon(instance uintptr, cx, cy int) uintptr {
	if instance != 0 {
		// Primary lookup: the group is emitted as "#1", i.e. MAKEINTRESOURCE(1).
		icon, _, _ := procLoadImageW.Call(instance, 1, imageIcon,
			uintptr(cx), uintptr(cy), 0)
		if icon != 0 {
			return icon
		}
		// Fallback: the same group used to be emitted under the name "APP".
		if name, err := syscall.UTF16PtrFromString(iconGroupName); err == nil {
			icon, _, _ = procLoadImageW.Call(instance, uintptr(unsafe.Pointer(name)), imageIcon,
				uintptr(cx), uintptr(cy), 0)
			if icon != 0 {
				return icon
			}
		}
	}
	icon, _, _ := procLoadIcon.Call(0, uintptr(idiApplication))
	return icon
}

// runMessageLoop pumps window messages until the window is closed.
func runMessageLoop() {
	var m msg
	for {
		ret, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(ret) <= 0 {
			return
		}
		procTranslate.Call(uintptr(unsafe.Pointer(&m)))
		procDispatch.Call(uintptr(unsafe.Pointer(&m)))
	}
}

// systemMetric reads one GetSystemMetrics value.
func systemMetric(index int) int32 {
	v, _, _ := procGetMetrics.Call(uintptr(index))
	return int32(v)
}

// isZoomed reports whether the window is maximised.
func isZoomed(hwnd uintptr) bool {
	v, _, _ := procIsZoomed.Call(hwnd)
	return v != 0
}

// frameThickness is the width of the invisible resize border, in physical
// pixels: the sizing frame Windows would have drawn plus the padding Windows
// 10+ adds, scaled for the window's DPI. The page's own title bar has no border
// to grab, so this is what still makes the window resizable.
func frameThickness(hwnd uintptr) int32 {
	dpi := int32(96)
	if d, _, _ := procGetDpiForWin.Call(hwnd); d > 0 {
		dpi = int32(d)
	}
	base := systemMetric(smCxSizeFrame) + systemMetric(smCxPaddedBorder)
	if base <= 0 {
		base = 8
	}
	return base * dpi / 96
}

// hitTestResize answers WM_NCHITTEST. lParam carries screen coordinates; only
// the border ring answers with a resize code, everything inside stays HTCLIENT
// so the page keeps receiving its own mouse events.
func hitTestResize(hwnd uintptr, lparam uintptr) uintptr {
	var r rect
	if ok, _, _ := procGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&r))); ok == 0 {
		return htClient
	}
	x := int32(int16(lparam & 0xFFFF))
	y := int32(int16((lparam >> 16) & 0xFFFF))
	t := frameThickness(hwnd)
	left := x < r.Left+t
	right := x >= r.Right-t
	top := y < r.Top+t
	bottom := y >= r.Bottom-t
	switch {
	case top && left:
		return htTopLeft
	case top && right:
		return htTopRight
	case bottom && left:
		return htBottomLeft
	case bottom && right:
		return htBottomRight
	case left:
		return htLeft
	case right:
		return htRight
	case top:
		return htTop
	case bottom:
		return htBottom
	}
	return htClient
}

// applyWorkArea answers WM_GETMINMAXINFO so a maximised frameless window stops
// at the monitor's work area instead of covering the taskbar.
func applyWorkArea(hwnd uintptr, mm *minMaxInfo) {
	if mm == nil {
		return
	}
	mon, _, _ := procMonitorFromWin.Call(hwnd, monitorDefaultToNearest)
	if mon == 0 {
		return
	}
	var mi monitorInfo
	mi.Size = uint32(unsafe.Sizeof(mi))
	if ok, _, _ := procGetMonitorInfo.Call(mon, uintptr(unsafe.Pointer(&mi))); ok == 0 {
		return
	}
	mm.MaxPosition.X = mi.Work.Left
	mm.MaxPosition.Y = mi.Work.Top
	mm.MaxSize.X = mi.Work.Right - mi.Work.Left
	mm.MaxSize.Y = mi.Work.Bottom - mi.Work.Top
}
