package control

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"vvpn/internal/sysproxy"
)

// The 设置 page edits the system proxy's bypass list. It lives next to
// handleSystemProxy because it is the same setting: the toggle writes the
// ProxyServer value, this writes the ProxyOverride value that sits beside it.

// sysProxyBypassView is what the 网络与系统代理 card renders.
type sysProxyBypassView struct {
	// Bypass is the effective ProxyOverride value: exactly what flipping the
	// system proxy on would write to the registry.
	Bypass string `json:"bypass"`
	// List is the same value split into entries, one per line in the editor.
	List []string `json:"list"`
	// Custom is false while the user has never written a list of their own.
	Custom bool `json:"custom"`
	// Default is what an empty list resolves to.
	Default string `json:"default"`
	// Active and Server describe the OS switch right now, so the card can say
	// whether an edit takes effect immediately or waits for the toggle.
	Active bool   `json:"active"`
	Server string `json:"server"`
}

func (h *API) buildSysProxyBypass() sysProxyBypassView {
	effective := h.app.SysProxyBypass()
	view := sysProxyBypassView{
		Bypass:  effective,
		List:    splitBypassEntries(effective),
		Custom:  len(h.app.SysProxyBypassList()) > 0,
		Default: sysproxy.DefaultBypass,
	}
	if on, server, err := sysproxy.Current(); err == nil {
		view.Active = on
		view.Server = server
	}
	return view
}

// splitBypassEntries turns a bypass list into entries. Both separators are
// accepted because the value has two homes: WinINET stores it ";"-joined in the
// registry, while the settings page shows one entry per line.
func splitBypassEntries(v string) []string {
	out := make([]string, 0, 4)
	for _, part := range strings.FieldsFunc(v, func(r rune) bool {
		return r == ';' || r == '\n' || r == '\r'
	}) {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// handleSysProxyBypassGet answers GET /api/system-proxy/bypass.
func (h *API) handleSysProxyBypassGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.buildSysProxyBypass())
}

// handleSysProxyBypassSet answers POST /api/system-proxy/bypass. The body is the
// raw text the textarea holds, so the UI never has to agree with the server on
// a separator. Saving while the system proxy is on republishes the value; a
// proxy owned by another program is left untouched (see App.SetSysProxyBypass).
func (h *API) handleSysProxyBypassSet(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Bypass string `json:"bypass"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	if err := h.app.SetSysProxyBypass(splitBypassEntries(body.Bypass)); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, h.buildSysProxyBypass())
}
