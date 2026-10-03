package control

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
)

// The QR endpoint exists so a subscription link can be moved to a phone without
// typing it: 订阅页 and 小白页 show the same image. Rendering happens here
// because the console must not load anything from a CDN, and a QR library in
// JavaScript would be one more thing shipped inside the page.

const (
	qrMinSize = 128
	qrMaxSize = 1024
	// A subscription URL is a few hundred bytes; the cap is generous but still
	// keeps a hostile caller from asking for a 40 000-byte code (the encoder
	// would spend real CPU on it).
	qrMaxText = 2048
)

// handleQR answers GET /api/qr?text=...&size=... with a PNG.
func (h *API) handleQR(w http.ResponseWriter, r *http.Request) {
	text := strings.TrimSpace(r.URL.Query().Get("text"))
	if text == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("缺少 text 参数"))
		return
	}
	if len(text) > qrMaxText {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("内容过长（%d 字节，上限 %d）", len(text), qrMaxText))
		return
	}
	size := 256
	if v, err := strconv.Atoi(r.URL.Query().Get("size")); err == nil {
		size = v
	}
	if size < qrMinSize {
		size = qrMinSize
	}
	if size > qrMaxSize {
		size = qrMaxSize
	}
	// Medium error correction is the usual trade for a short URL: enough
	// redundancy to scan off a screen, not so much that the modules get tiny.
	code, err := qrcode.New(text, qrcode.Medium)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	png, err := code.PNG(size)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	// The payload is a credential-bearing URL: never let anything cache it.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(png)))
	_, _ = w.Write(png)
}
