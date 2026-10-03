package control

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vvpn/internal/shellopen"
)

// The 设置 page needs three things the proxy API has no business knowing:
// where the client keeps its files, whether it should start in the tray, and a
// way to get the log out of the window. They are grouped here because they are
// all "about the program" rather than "about the tunnel".

// appPrefsView is what the 设置 page renders. Every path is absolute and comes
// straight from the running process, so the UI never has to guess where a
// portable install put itself.
type appPrefsView struct {
	SilentStart bool   `json:"silent_start"`
	DataDir     string `json:"data_dir"`
	ConfigPath  string `json:"config_path"`
	LogDir      string `json:"log_dir"`
	ExePath     string `json:"exe_path"`
	// UpdateSource is the release channel the about card checks. Empty means
	// this build has none, which the card says out loud instead of guessing.
	UpdateSource string `json:"update_source"`
}

func (h *API) buildAppPrefs() appPrefsView {
	view := appPrefsView{
		SilentStart:  h.app.SilentStart(),
		DataDir:      h.app.DataDir(),
		ConfigPath:   h.app.ConfigPath(),
		UpdateSource: h.app.UpdateSource(),
	}
	view.LogDir = h.app.LogDir()
	if exe, err := os.Executable(); err == nil {
		view.ExePath = exe
	}
	return view
}

// handleAppPrefs answers GET /api/app/prefs.
func (h *API) handleAppPrefs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.buildAppPrefs())
}

// handleAppPrefsSet answers POST /api/app/prefs. Only the fields actually sent
// are changed, so the endpoint stays usable when more preferences appear.
func (h *API) handleAppPrefsSet(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SilentStart  *bool   `json:"silent_start"`
		UpdateSource *string `json:"update_source"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	if body.SilentStart != nil {
		if err := h.app.SetSilentStart(*body.SilentStart); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
	}
	if body.UpdateSource != nil {
		if err := h.app.SetUpdateSource(strings.TrimSpace(*body.UpdateSource)); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, h.buildAppPrefs())
}

// handleAppOpenDir answers POST /api/app/open-dir. Opening a folder is always a
// click in the 设置 page; nothing here runs on its own, and the child process is
// explorer.exe (a GUI binary), never a command interpreter.
func (h *API) handleAppOpenDir(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Which string `json:"which"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	prefs := h.buildAppPrefs()
	var dir string
	switch strings.ToLower(strings.TrimSpace(body.Which)) {
	case "", "data":
		dir = prefs.DataDir
	case "config":
		dir = filepath.Dir(prefs.ConfigPath)
	case "logs":
		dir = prefs.LogDir
	default:
		writeErr(w, http.StatusBadRequest, fmt.Errorf("unknown directory %q", body.Which))
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if err := shellopen.Dir(dir); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"opened": dir})
}

// handleLogExport answers POST /api/logs/export: it writes what the ring buffer
// holds to a timestamped file next to the configuration and returns the path,
// which is the part the user actually wants ("where did my log go?").
func (h *API) handleLogExport(w http.ResponseWriter, r *http.Request) {
	dir := h.app.LogDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	entries := h.app.Log().Recent(0)
	name := "syan-clash-" + time.Now().Format("20060102-150405") + ".log"
	path := filepath.Join(dir, name)
	var b strings.Builder
	for _, e := range entries {
		fmt.Fprintf(&b, "%s %-5s %s\n", e.Time.Format("2006-01-02 15:04:05.000"), e.Level, e.Msg)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	h.app.Log().Infof("日志已导出到 %s（%d 条）", path, len(entries))
	writeJSON(w, http.StatusOK, map[string]any{"path": path, "entries": len(entries)})
}
