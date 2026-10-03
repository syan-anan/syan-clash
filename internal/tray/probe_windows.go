//go:build windows

package tray

// ProbeHotKey reports whether a global shortcut can be claimed right now. It
// registers the combination on the tray's message window and immediately
// releases it, so the answer reflects the current desktop, not a guess.
//
// This is what keeps the client from shipping hot keys that silently do
// nothing because another program got there first.
func ProbeHotKey(modifiers, virtualKey uint32) bool {
	hwnd, err := createWindow()
	if err != nil {
		return false
	}
	defer func() { _, _, _ = procDestroyWindow.Call(hwnd) }()
	const probeID = 0x7FFF
	ret, _, _ := procRegisterHotKey.Call(hwnd, probeID, uintptr(modifiers), uintptr(virtualKey))
	if ret == 0 {
		return false
	}
	_, _, _ = procUnregisterHotKey.Call(hwnd, probeID)
	return true
}
