package control

import (
	"net/http"
	"time"
)

// handleAppWindow shows the desktop window of the running client. Headless
// runs answer 501 so the UI can say "this build has no window" instead of
// silently doing nothing.
func (h *API) handleAppWindow(w http.ResponseWriter, r *http.Request) {
	if err := h.app.OpenWindow(); err != nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

// handleAppQuit stops the whole client, exactly like the tray menu 退出. The
// reply is flushed first so the caller sees confirmation before the socket
// goes away.
func (h *API) handleAppQuit(w http.ResponseWriter, r *http.Request) {
	if !h.app.CanQuit() {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "当前运行方式不支持从界面退出"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "quitting"})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	go func() {
		time.Sleep(300 * time.Millisecond)
		h.app.RequestQuit()
	}()
}
