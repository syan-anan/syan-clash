package control

import (
	"bytes"
	"image"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The QR endpoint is the one place the console gets a picture from the server.
// The tests check the parts that would silently ruin it: a real PNG, a square
// image inside the size clamp, and the locator pattern a scanner needs before
// it can read a single module.

func qrRequest(t *testing.T, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	// handleQR reads nothing from the App, so a zero API is enough and the test
	// stays a pure unit test.
	(&API{}).handleQR(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

func TestQRReturnsAScannablePNG(t *testing.T) {
	rec := qrRequest(t, "/api/qr?size=256&text="+
		"https%3A%2F%2Fdy11.example.com%2Fapi%2Fv1%2Fclient%2Fsubscribe%3Ftoken%3D0123456789abcdef0123456789abcdef")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "image/png" {
		t.Fatalf("content type = %q, want image/png", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("a subscription token must never be cached, got Cache-Control %q", cc)
	}
	img, err := png.Decode(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatalf("body is not a PNG: %v", err)
	}
	b := img.Bounds()
	if b.Dx() != b.Dy() {
		t.Fatalf("QR is %dx%d, want a square", b.Dx(), b.Dy())
	}
	if b.Dx() != 256 {
		t.Fatalf("QR is %dpx, want the requested 256", b.Dx())
	}
	module, ok := finderGeometry(img)
	if !ok {
		t.Fatal("no QR locator pattern found: the image is not a readable code")
	}
	if module < 2 {
		t.Fatalf("modules are %dpx wide, too small to scan", module)
	}
}

func TestQRClampsTheRequestedSize(t *testing.T) {
	cases := []struct {
		query string
		want  int
	}{
		{"size=16", qrMinSize},
		{"size=99999", qrMaxSize},
		{"", 256},
		{"size=abc", 256},
	}
	for _, tc := range cases {
		target := "/api/qr?text=hello"
		if tc.query != "" {
			target += "&" + tc.query
		}
		rec := qrRequest(t, target)
		if rec.Code != http.StatusOK {
			t.Fatalf("%q: status = %d, want 200", tc.query, rec.Code)
		}
		img, err := png.Decode(bytes.NewReader(rec.Body.Bytes()))
		if err != nil {
			t.Fatalf("%q: %v", tc.query, err)
		}
		if got := img.Bounds().Dx(); got != tc.want {
			t.Errorf("%q: width = %d, want %d", tc.query, got, tc.want)
		}
	}
}

func TestQRRejectsEmptyAndOversizedText(t *testing.T) {
	if rec := qrRequest(t, "/api/qr"); rec.Code != http.StatusBadRequest {
		t.Errorf("missing text returned %d, want 400", rec.Code)
	}
	if rec := qrRequest(t, "/api/qr?text=%20%20"); rec.Code != http.StatusBadRequest {
		t.Errorf("blank text returned %d, want 400", rec.Code)
	}
	long := strings.Repeat("a", qrMaxText+1)
	if rec := qrRequest(t, "/api/qr?text="+long); rec.Code != http.StatusBadRequest {
		t.Errorf("oversized text returned %d, want 400", rec.Code)
	}
}

// finderGeometry locates the top-left locator pattern and returns its module
// size in pixels. A locator is a 7x7 module block whose centre row reads
// 1:1:3:1:1 dark/light, which is exactly what a scanner locks onto first.
//
// Everything is compared in modules rather than pixels because the encoder
// scales with rounding: at 256px one module is 5.29px, so the pixel runs are 5
// or 6 long and only the ratio between them is stable.
func finderGeometry(img image.Image) (int, bool) {
	b := img.Bounds()
	dark := func(x, y int) bool {
		r, g, bl, _ := img.At(x, y).RGBA()
		// Rec. 601 luma on the 8-bit channels the PNG decoder hands back.
		return (299*int(r>>8)+587*int(g>>8)+114*int(bl>>8))/1000 < 128
	}
	// The quiet zone guarantees the first dark pixel in raster order is the
	// top-left corner of the top-left locator.
	x0, y0 := -1, -1
	for y := b.Min.Y; y < b.Max.Y && x0 < 0; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			if dark(x, y) {
				x0, y0 = x, y
				break
			}
		}
	}
	if x0 < 0 {
		return 0, false
	}
	// Top row of the locator: 7 modules of dark, then the light separator.
	hrun := 0
	for x := x0; x < b.Max.X && dark(x, y0); x++ {
		hrun++
	}
	if hrun < 14 {
		return 0, false
	}
	m := float64(hrun) / 7
	// The same edge read downwards must be just as long.
	vrun := 0
	for y := y0; y < b.Max.Y && dark(x0, y); y++ {
		vrun++
	}
	if vrun != hrun {
		return 0, false
	}
	// Centre row of the locator: 1:1:3:1:1 modules.
	cy := y0 + int(3.5*m)
	var runs []int
	prev := true
	count := 0
	for x := x0; x < b.Max.X && len(runs) < 5; x++ {
		d := dark(x, cy)
		if d == prev {
			count++
			continue
		}
		runs = append(runs, count)
		prev, count = d, 1
	}
	if len(runs) != 5 {
		return 0, false
	}
	for i, want := range []float64{1, 1, 3, 1, 1} {
		if diff := float64(runs[i])/m - want; diff > 0.35 || diff < -0.35 {
			return 0, false
		}
	}
	// A second locator sits in the top-right corner, against the quiet zone.
	right := -1
	for x := b.Max.X - 1; x >= b.Min.X; x-- {
		if dark(x, y0) {
			right = x
			break
		}
	}
	if right < 0 {
		return 0, false
	}
	rrun := 0
	for x := right; x >= b.Min.X && dark(x, y0); x-- {
		rrun++
	}
	if diff := float64(rrun)/m - 7; diff > 0.35 || diff < -0.35 {
		return 0, false
	}
	return int(m + 0.5), true
}
