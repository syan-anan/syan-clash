//go:build windows

package tray

import (
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"
)

// ExportStateIcons renders every notification-icon state and writes it as a PNG
// so the drawing can be checked without putting anything on screen. It also
// builds the real HICON for each state, which is what proves the GDI path
// (DIB section, mask, CreateIconIndirect) actually works.
//
// This exists for the headless verification runs: the icon is drawn in code, so
// "does it look right" has to be answerable from a file.
func ExportStateIcons(dir string) ([]string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	var written []string
	for _, state := range []State{StateStopped, StateDirect, StateProxy, StateError} {
		frame := composeIcon(state)
		icon, err := createIconFromBGRA(frame)
		if err != nil {
			return written, fmt.Errorf("state %d: %w", state, err)
		}
		if icon == 0 {
			return written, fmt.Errorf("state %d: CreateIconIndirect returned a null icon", state)
		}

		img := image.NewNRGBA(image.Rect(0, 0, statusIconEdge, statusIconEdge))
		for y := 0; y < statusIconEdge; y++ {
			for x := 0; x < statusIconEdge; x++ {
				at := (y*statusIconEdge + x) * 4
				to := img.PixOffset(x, y)
				img.Pix[to+0] = frame[at+2] // R
				img.Pix[to+1] = frame[at+1] // G
				img.Pix[to+2] = frame[at+0] // B
				img.Pix[to+3] = frame[at+3] // A
			}
		}
		name := filepath.Join(dir, fmt.Sprintf("P3-tray-icon-%s.png", stateName(state)))
		f, err := os.Create(name)
		if err != nil {
			return written, err
		}
		if err := png.Encode(f, img); err != nil {
			f.Close()
			return written, err
		}
		if err := f.Close(); err != nil {
			return written, err
		}
		written = append(written, name)
	}
	return written, nil
}

func stateName(state State) string {
	switch state {
	case StateStopped:
		return "stopped"
	case StateDirect:
		return "direct"
	case StateProxy:
		return "proxy"
	case StateError:
		return "error"
	default:
		return "unknown"
	}
}
