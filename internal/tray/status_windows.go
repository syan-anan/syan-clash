//go:build windows

package tray

import (
	_ "embed"
	"fmt"
	"math"
	"sync"
	"syscall"
	"unsafe"
)

// statusBaseIcon is the 32x32 logo as raw BGRA. Embedding the pixels instead of
// the .ico keeps the compositor dependency free: the icon is redrawn in memory
// and handed to the shell, no image decoder and no file on disk.
//
//go:embed assets/status-32.bgra
var statusBaseIcon []byte

const statusIconEdge = 32

var (
	gdi32 = syscall.NewLazyDLL("gdi32.dll")

	procCreateDIBSection   = gdi32.NewProc("CreateDIBSection")
	procCreateBitmap       = gdi32.NewProc("CreateBitmap")
	procDeleteObject       = gdi32.NewProc("DeleteObject")
	procCreateIconIndirect = user32.NewProc("CreateIconIndirect")
)

type bitmapInfoHeader struct {
	Size          uint32
	Width         int32
	Height        int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
}

type iconInfo struct {
	Icon     int32
	XHotspot uint32
	YHotspot uint32
	Mask     uintptr
	Color    uintptr
}

// stateColors are the badge colours. Direct is the brand blue, proxy is the
// green every network UI uses for "connected", stopped is the neutral grey and
// error is red.
var stateColors = map[State][4]byte{
	StateStopped: {0x93, 0x8e, 0x8e, 0xff}, // BGRA grey
	StateDirect:  {0xff, 0xa8, 0x6a, 0xff}, // BGRA brand blue #6aa8ff
	StateProxy:   {0x59, 0xc7, 0x35, 0xff}, // BGRA green
	StateError:   {0x3a, 0x45, 0xff, 0xff}, // BGRA red
}

var stateBadgeRing = [4]byte{0x11, 0x0c, 0x0a, 0xcc} // the UI background, mostly opaque

var (
	iconCacheMu sync.Mutex
	iconCache   = map[State]uintptr{}
)

// SetStatus redraws the notification icon. It is safe to call from any
// goroutine and cheap after the first call for a state, because the composed
// icon is cached.
func SetStatus(state State) {
	liveMu.Lock()
	if !liveSet {
		liveMu.Unlock()
		return
	}
	hwnd, id := liveHWND, liveID
	tip := liveTip
	icon := liveIcon
	liveMu.Unlock()

	next := statusIcon(state)
	if next == 0 || next == icon {
		return
	}

	liveMu.Lock()
	if liveSet {
		liveIcon = next
	}
	liveMu.Unlock()

	data := notifyIconData{
		Size:            uint32(unsafe.Sizeof(notifyIconData{})),
		Wnd:             hwnd,
		ID:              id,
		Flags:           nifMessage | nifIcon | nifTip,
		CallbackMessage: wmApp + 1,
		Icon:            next,
	}
	copyTip(data.Tip[:], tip)
	_, _, _ = procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&data)))
}

// SetTooltip replaces the hover text. The text is remembered so a later icon
// change keeps it.
func SetTooltip(text string) {
	liveMu.Lock()
	if !liveSet || liveTip == text {
		liveMu.Unlock()
		return
	}
	liveTip = text
	hwnd, id, icon := liveHWND, liveID, liveIcon
	liveMu.Unlock()

	data := notifyIconData{
		Size:            uint32(unsafe.Sizeof(notifyIconData{})),
		Wnd:             hwnd,
		ID:              id,
		Flags:           nifMessage | nifIcon | nifTip,
		CallbackMessage: wmApp + 1,
		Icon:            icon,
	}
	copyTip(data.Tip[:], text)
	_, _, _ = procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&data)))
}

func statusIcon(state State) uintptr {
	iconCacheMu.Lock()
	defer iconCacheMu.Unlock()
	if icon, ok := iconCache[state]; ok {
		return icon
	}
	icon, err := createIconFromBGRA(composeIcon(state))
	if err != nil {
		return 0
	}
	iconCache[state] = icon
	return icon
}

// composeIcon paints the state badge onto a copy of the base logo. The badge
// sits inside the lower-right corner with a dark ring so it stays readable on
// both the light and the dark taskbar.
func composeIcon(state State) []byte {
	pixels := make([]byte, len(statusBaseIcon))
	copy(pixels, statusBaseIcon)
	color, ok := stateColors[state]
	if !ok {
		return pixels
	}
	const cx, cy = 23.0, 23.0
	drawDisc(pixels, cx, cy, 6.6, stateBadgeRing)
	drawDisc(pixels, cx, cy, 5.2, color)
	return pixels
}

// drawDisc fills a circle with a one-pixel antialiased edge, compositing over
// straight (non-premultiplied) BGRA, which is what CreateIconIndirect expects.
func drawDisc(pixels []byte, cx, cy, radius float64, color [4]byte) {
	for y := 0; y < statusIconEdge; y++ {
		for x := 0; x < statusIconEdge; x++ {
			dx := float64(x) + 0.5 - cx
			dy := float64(y) + 0.5 - cy
			distance := math.Sqrt(dx*dx + dy*dy)
			coverage := radius + 0.5 - distance
			if coverage <= 0 {
				continue
			}
			if coverage > 1 {
				coverage = 1
			}
			blendPixel(pixels, (y*statusIconEdge+x)*4, color, coverage)
		}
	}
}

func blendPixel(pixels []byte, at int, color [4]byte, coverage float64) {
	srcA := float64(color[3]) / 255 * coverage
	dstA := float64(pixels[at+3]) / 255
	outA := srcA + dstA*(1-srcA)
	if outA <= 0 {
		return
	}
	for i := 0; i < 3; i++ {
		src := float64(color[i]) * srcA
		dst := float64(pixels[at+i]) * dstA * (1 - srcA)
		pixels[at+i] = clampByte((src + dst) / outA)
	}
	pixels[at+3] = clampByte(outA * 255)
}

func clampByte(v float64) byte {
	switch {
	case v <= 0:
		return 0
	case v >= 255:
		return 255
	default:
		return byte(v + 0.5)
	}
}

// createIconFromBGRA turns one 32-bit top-down frame into an HICON. The shell
// wants an icon handle, and an icon handle is the only shared object GDI will
// accept here, so a DIB section plus a 1-bit AND mask (all zeros: the alpha
// channel decides the shape) is the shortest correct path.
func createIconFromBGRA(pixels []byte) (uintptr, error) {
	if len(pixels) < statusIconEdge*statusIconEdge*4 {
		return 0, fmt.Errorf("tray: icon frame is %d bytes, want %d", len(pixels), statusIconEdge*statusIconEdge*4)
	}
	header := bitmapInfoHeader{
		Size:      uint32(unsafe.Sizeof(bitmapInfoHeader{})),
		Width:     statusIconEdge,
		Height:    -statusIconEdge, // negative height: rows are stored top-down
		Planes:    1,
		BitCount:  32,
		SizeImage: uint32(statusIconEdge * statusIconEdge * 4),
	}
	var bits uintptr
	color, _, callErr := procCreateDIBSection.Call(0,
		uintptr(unsafe.Pointer(&header)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if color == 0 {
		return 0, fmt.Errorf("tray: CreateDIBSection failed: %v", callErr)
	}
	defer func() { _, _, _ = procDeleteObject.Call(color) }()

	copy(unsafe.Slice((*byte)(unsafe.Pointer(bits)), len(pixels)), pixels)

	mask, _, _ := procCreateBitmap.Call(statusIconEdge, statusIconEdge, 1, 1, 0)
	defer func() {
		if mask != 0 {
			_, _, _ = procDeleteObject.Call(mask)
		}
	}()

	info := iconInfo{Icon: 1, Mask: mask, Color: color}
	icon, _, callErr := procCreateIconIndirect.Call(uintptr(unsafe.Pointer(&info)))
	if icon == 0 {
		return 0, fmt.Errorf("tray: CreateIconIndirect failed: %v", callErr)
	}
	return icon, nil
}
