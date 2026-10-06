// Package control exposes the local control plane: a JSON API plus the
// embedded web UI, served on a loopback address.
package control

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"vvpn/internal/app"
	"vvpn/internal/autostart"
	"vvpn/internal/config"
	"vvpn/internal/core"
	"vvpn/internal/elevate"
	"vvpn/internal/logbus"
	"vvpn/internal/proxy"
	"vvpn/internal/rules"
	"vvpn/internal/subscription"
	"vvpn/internal/sysproxy"
)

//go:embed web
var webFS embed.FS

// API serves the control plane for one App.
type API struct {
	app *app.App
}

// New creates the control plane handler set.
func New(a *app.App) *API { return &API{app: a} }

// Handler returns the fully wired HTTP handler.
func (h *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /api/status", h.handleStatus)
	mux.HandleFunc("GET /api/config", h.handleGetConfig)
	mux.HandleFunc("PUT /api/config", h.handlePutConfig)
	mux.HandleFunc("GET /api/connections", h.handleConnections)
	mux.HandleFunc("POST /api/connections/close", h.handleCloseConnection)
	mux.HandleFunc("GET /api/logs", h.handleLogs)
	mux.HandleFunc("GET /api/logs/stream", h.handleLogStream)
	mux.HandleFunc("GET /api/rules/kinds", h.handleRuleKinds)
	mux.HandleFunc("POST /api/rules/match", h.handleRuleMatch)
	mux.HandleFunc("POST /api/system-proxy", h.handleSystemProxy)
	// The bypass list is the second half of the same setting: the toggle above
	// publishes ProxyServer, this publishes the ProxyOverride that sits with it.
	mux.HandleFunc("GET /api/system-proxy/bypass", h.handleSysProxyBypassGet)
	mux.HandleFunc("POST /api/system-proxy/bypass", h.handleSysProxyBypassSet)
	// P0-1: service mode. The service is the privileged half of the client -
	// the piece that makes TUN available without a UAC prompt on every launch -
	// and the guard switch turns the invisible proxy-guard copy on or off
	// independently of the system proxy toggle.
	mux.HandleFunc("GET /api/system/service", h.handleServiceGet)
	mux.HandleFunc("POST /api/system/service", h.handleServicePost)
	mux.HandleFunc("GET /api/system/proxy-guard", h.handleProxyGuardGet)
	mux.HandleFunc("POST /api/system/proxy-guard", h.handleProxyGuardSet)
	mux.HandleFunc("GET /api/cores", h.handleCores)
	mux.HandleFunc("GET /api/about", h.handleAbout)
	mux.HandleFunc("POST /api/cores/install", h.handleCoreInstall)
	mux.HandleFunc("POST /api/cores/start", h.handleCoreStart)
	mux.HandleFunc("POST /api/cores/stop", h.handleCoreStop)
	mux.HandleFunc("GET /api/cores/geo", h.handleCoreGeo)
	mux.HandleFunc("POST /api/cores/geo", h.handleCoreGeoFetch)
	mux.HandleFunc("GET /api/cores/config", h.handleCoreConfig)
	mux.HandleFunc("GET /api/profile", h.handleGetProfile)
	mux.HandleFunc("PUT /api/profile", h.handlePutProfile)
	mux.HandleFunc("POST /api/subscription/parse", h.handleSubscriptionParse)
	mux.HandleFunc("POST /api/subscription/import", h.handleSubscriptionImport)
	mux.HandleFunc("GET /api/cores/version", h.handleCoreVersion)
	mux.HandleFunc("GET /api/cores/proxies", h.handleCoreProxies)
	mux.HandleFunc("POST /api/cores/select", h.handleCoreSelect)
	mux.HandleFunc("GET /api/cores/delay", h.handleCoreDelay)
	mux.HandleFunc("GET /api/cores/mode", h.handleCoreModeGet)
	mux.HandleFunc("POST /api/cores/mode", h.handleCoreModeSet)
	// The kernel page tuning block (log level, sniffer, tunnel details) is
	// read and written as one small document, so the console never has to
	// send the whole profile back to change one switch.
	mux.HandleFunc("GET /api/cores/params", h.handleKernelParamsGet)
	mux.HandleFunc("POST /api/cores/params", h.handleKernelParamsSet)
	mux.HandleFunc("GET /api/cores/traffic", h.handleCoreTraffic)
	mux.HandleFunc("GET /api/cores/connections", h.handleCoreConnections)
	mux.HandleFunc("POST /api/cores/connections/close", h.handleCoreCloseConnection)
	mux.HandleFunc("GET /api/cores/updates", h.handleCoreUpdates)
	mux.HandleFunc("POST /api/cores/update", h.handleCoreUpdate)
	mux.HandleFunc("GET /api/cores/versions", h.handleCoreVersions)
	mux.HandleFunc("POST /api/cores/versions/activate", h.handleCoreVersionActivate)
	mux.HandleFunc("POST /api/profile/nodes", h.handleAddNode)
	mux.HandleFunc("POST /api/profile/net", h.handleSetNetwork)
	mux.HandleFunc("GET /api/dns", h.handleGetDNS)
	mux.HandleFunc("POST /api/dns", h.handleSetDNS)
	mux.HandleFunc("GET /api/profiles", h.handleProfilesList)
	mux.HandleFunc("POST /api/profiles", h.handleProfilesAction)
	mux.HandleFunc("DELETE /api/profiles", h.handleProfilesDelete)
	mux.HandleFunc("GET /api/profile/nodes/filter", h.handleNodeFilterGet)
	mux.HandleFunc("POST /api/profile/nodes/filter", h.handleNodeFilterSet)
	mux.HandleFunc("GET /api/profile/groups", h.handleGroupList)
	mux.HandleFunc("POST /api/profile/groups", h.handleGroupEdit)
	mux.HandleFunc("GET /api/ports", h.handlePorts)
	mux.HandleFunc("POST /api/ports/relocate", h.handlePortsRelocate)
	mux.HandleFunc("DELETE /api/profile/nodes", h.handleRemoveNode)
	mux.HandleFunc("GET /api/system", h.handleSystemInfo)
	mux.HandleFunc("POST /api/system/tun", h.handleTun)
	mux.HandleFunc("POST /api/system/autostart", h.handleAutostart)
	mux.HandleFunc("GET /api/system/autostart", h.handleAutostartGet)
	mux.HandleFunc("GET /api/subscriptions", h.handleSubscriptions)
	mux.HandleFunc("POST /api/subscriptions", h.handleAddSubscription)
	mux.HandleFunc("DELETE /api/subscriptions", h.handleRemoveSubscription)
	mux.HandleFunc("PATCH /api/subscriptions", h.handleEditSubscription)
	mux.HandleFunc("POST /api/subscriptions/update", h.handleUpdateSubscription)
	mux.HandleFunc("POST /api/subscriptions/auto", h.handleSubscriptionAuto)
	mux.HandleFunc("POST /api/subscriptions/options", h.handleSubscriptionOptions)
	mux.HandleFunc("POST /api/cores/pick", h.handleCorePick)
	// "全部测速" measures a whole group without switching anything, so it
	// gets its own endpoint instead of the picker the 选优 buttons use.
	mux.HandleFunc("POST /api/cores/sweep", h.handleCoreSweep)
	mux.HandleFunc("POST /api/profile/rules", h.handleAddRule)
	mux.HandleFunc("DELETE /api/profile/rules", h.handleRemoveRule)
	// P15: rule sets (mihomo’s rule-providers). A rule of kind
	// "rule-provider" names one of these instead of carrying the payload itself.
	mux.HandleFunc("GET /api/rule-providers", h.handleRuleProviderList)
	mux.HandleFunc("POST /api/rule-providers", h.handleRuleProviderSet)
	mux.HandleFunc("DELETE /api/rule-providers", h.handleRuleProviderDelete)
	// P1-3: proxy sets (mihomo's proxy-providers). A group reaches one through
	// "use" instead of the client copying its nodes into the profile, so the
	// core keeps the list fresh on its own schedule.
	mux.HandleFunc("GET /api/providers", h.handleProxyProviderList)
	mux.HandleFunc("POST /api/providers", h.handleProxyProviderSet)
	mux.HandleFunc("DELETE /api/providers", h.handleProxyProviderDelete)
	mux.HandleFunc("GET /api/backup", h.handleExportBackup)
	mux.HandleFunc("POST /api/backup", h.handleImportBackup)
	// P1-11: the WebDAV backup target. The console keeps a directory of
	// timestamped archives on a WebDAV server so a second machine can restore
	// the same setup. The password is write-only: the GET never echoes it.
	mux.HandleFunc("GET /api/backup/webdav", h.handleWebDAVGet)
	mux.HandleFunc("POST /api/backup/webdav/config", h.handleWebDAVConfigSet)
	mux.HandleFunc("POST /api/backup/webdav/upload", h.handleWebDAVUpload)
	mux.HandleFunc("POST /api/backup/webdav/download", h.handleWebDAVDownload)
	mux.HandleFunc("DELETE /api/backup/webdav", h.handleWebDAVDelete)
	mux.HandleFunc("GET /api/presets", h.handlePresets)
	mux.HandleFunc("POST /api/presets", h.handleApplyPreset)
	mux.HandleFunc("DELETE /api/presets", h.handleRemovePreset)
	mux.HandleFunc("GET /api/cores/processes", h.handleCoreProcesses)
	mux.HandleFunc("GET /api/panel/state", h.handlePanelState)
	mux.HandleFunc("POST /api/panel/login", h.handlePanelLogin)
	// The 记住密码 switch on its own: flipping it off erases a stored password.
	mux.HandleFunc("POST /api/panel/remember-password", h.handlePanelRememberPassword)
	mux.HandleFunc("POST /api/panel/logout", h.handlePanelLogout)
	mux.HandleFunc("GET /api/panel/info", h.handlePanelInfo)
	mux.HandleFunc("GET /api/panel/subscribe", h.handlePanelSubscribe)
	mux.HandleFunc("POST /api/panel/import", h.handlePanelImport)
	mux.HandleFunc("POST /api/panel/base", h.handlePanelSetBase)
	mux.HandleFunc("GET /api/panel/notice", h.handlePanelNotice)
	mux.HandleFunc("POST /api/app/window", h.handleAppWindow)
	mux.HandleFunc("POST /api/app/quit", h.handleAppQuit)

	// P9: the desktop shell's own surface - where the files are, whether the
	// next launch stays in the tray, opening a folder, exporting the log, and
	// the QR image the 订阅 / 小白 pages show for a subscription link.
	// The update check is a read-only GET on purpose: nothing here ever
	// replaces the running exe, it only reports what it found.
	mux.HandleFunc("GET /api/app/update", h.handleAppUpdate)
	mux.HandleFunc("GET /api/app/prefs", h.handleAppPrefs)
	mux.HandleFunc("POST /api/app/prefs", h.handleAppPrefsSet)
	// P2-6: the clash:// link. The switch is off by default and the client
	// refuses to overwrite a registration another client already holds, so a
	// machine running FlyClash or Clash Verge keeps working unchanged.
	mux.HandleFunc("GET /api/app/url-scheme", h.handleURLSchemeGet)
	mux.HandleFunc("POST /api/app/url-scheme", h.handleURLSchemeSet)
	mux.HandleFunc("POST /api/app/url-scheme/handle", h.handleURLSchemeHandle)
	mux.HandleFunc("POST /api/app/open-dir", h.handleAppOpenDir)
	mux.HandleFunc("POST /api/logs/export", h.handleLogExport)
	mux.HandleFunc("GET /api/qr", h.handleQR)

	// P5 diagnostics: the connection panel extras plus the whole 诊断 page.
	mux.HandleFunc("POST /api/cores/connections/close-all", h.handleCloseAllConnections)
	mux.HandleFunc("GET /api/diag/ip", h.handleDiagIP)
	mux.HandleFunc("GET /api/diag/unlock", h.handleDiagUnlock)
	mux.HandleFunc("POST /api/diag/matrix/run", h.handleDiagMatrixRun)
	mux.HandleFunc("GET /api/diag/matrix/status", h.handleDiagMatrixStatus)
	mux.HandleFunc("POST /api/diag/matrix/cancel", h.handleDiagMatrixCancel)
	mux.HandleFunc("POST /api/diag/speedtest/start", h.handleDiagSpeedStart)
	mux.HandleFunc("GET /api/diag/speedtest/status", h.handleDiagSpeedStatus)
	mux.HandleFunc("POST /api/diag/speedtest/cancel", h.handleDiagSpeedCancel)
	mux.HandleFunc("GET /api/diag/speedtest/history", h.handleDiagSpeedHistory)
	mux.HandleFunc("POST /api/diag/dns", h.handleDiagDNS)
	mux.HandleFunc("POST /api/diag/dnsleak", h.handleDiagDNSLeak)
	mux.HandleFunc("POST /api/diag/tcp", h.handleDiagTCP)
	mux.HandleFunc("POST /api/diag/tls", h.handleDiagTLS)
	mux.HandleFunc("POST /api/diag/mtu", h.handleDiagMTU)
	mux.HandleFunc("POST /api/diag/trace/start", h.handleDiagTraceStart)
	mux.HandleFunc("GET /api/diag/trace/status", h.handleDiagTraceStatus)
	mux.HandleFunc("POST /api/diag/trace/cancel", h.handleDiagTraceCancel)
	mux.HandleFunc("POST /api/diag/ai/run", h.handleDiagAIRun)
	mux.HandleFunc("GET /api/diag/ai/status", h.handleDiagAIStatus)
	mux.HandleFunc("POST /api/diag/ai/cancel", h.handleDiagAICancel)
	mux.HandleFunc("POST /api/diag/ai/login", h.handleDiagAILogin)

	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		panic(fmt.Sprintf("control: embedded web assets: %v", err))
	}
	// P2-1: the English dictionary is JSON, and JSON is UTF-8 by definition.
	// Serving it through FileServer sends "application/json" with no charset,
	// and a client that trusts the header then decodes the Chinese keys as
	// Latin-1. Browsers ignore the charset for JSON, but nothing else has to.
	mux.HandleFunc("GET /i18n.en.json", h.handleI18nDict)
	mux.Handle("GET /", http.FileServer(http.FS(sub)))
	return h.withAuth(mux)
}

// withAuth enforces the optional bearer token. Everything is loopback-only by
// default; the token exists for users who expose the API deliberately.
func (h *API) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := h.app.Config().API.Token
		if token != "" && strings.HasPrefix(r.URL.Path, "/api/") {
			got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			if got != token {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or missing API token"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(body)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func (h *API) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.app.Status())
}

func (h *API) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.app.Config())
}

func (h *API) handlePutConfig(w http.ResponseWriter, r *http.Request) {
	var next config.Config
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&next); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid config JSON: %w", err))
		return
	}
	if err := h.app.Reload(next); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"applied": true,
		"status":  h.app.Status(),
	})
}

func (h *API) handleConnections(w http.ResponseWriter, r *http.Request) {
	conns := h.app.Connections()
	if conns == nil {
		conns = []proxy.ConnInfo{}
	}
	writeJSON(w, http.StatusOK, conns)
}

func (h *API) handleCloseConnection(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid id"))
		return
	}
	if !h.app.CloseConnection(id) {
		writeErr(w, http.StatusNotFound, fmt.Errorf("connection %d is not active", id))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"closed": id})
}

func (h *API) handleLogs(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	entries := h.app.Log().Recent(n)
	if entries == nil {
		entries = []logbus.Entry{}
	}
	writeJSON(w, http.StatusOK, entries)
}

func (h *API) handleLogStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, fmt.Errorf("streaming unsupported"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	writeEvent := func(e logbus.Entry) {
		raw, err := json.Marshal(e)
		if err != nil {
			return
		}
		fmt.Fprintf(w, "data: %s\n\n", raw)
	}
	for _, e := range h.app.Log().Recent(100) {
		writeEvent(e)
	}
	flusher.Flush()

	id, ch := h.app.Log().Subscribe()
	defer h.app.Log().Unsubscribe(id)

	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case e, open := <-ch:
			if !open {
				return
			}
			writeEvent(e)
			flusher.Flush()
		case <-heartbeat.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

func (h *API) handleRuleKinds(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"kinds":   rules.Kinds,
		"actions": []string{string(rules.ActionDirect), string(rules.ActionProxy), string(rules.ActionReject)},
	})
}

func (h *API) handleRuleMatch(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Host string `json:"host"`
		Port uint16 `json:"port"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	host := strings.TrimSpace(body.Host)
	if host == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("host is required"))
		return
	}
	res, err := h.app.RoutePreview(r.Context(), host, body.Port)
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (h *API) handleSystemProxy(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
		// Force takes the system proxy over from another program. The UI only
		// sets it after the user has been told whose proxy is in the way.
		Force bool `json:"force"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	if body.Enabled {
		// The master switch promises "traffic goes through a node", so a
		// stopped core is started first: pointing the OS proxy at a client
		// with nothing to route through would be a switch that lies.
		ctx, cancel := context.WithTimeout(r.Context(), 6*time.Minute)
		defer cancel()
		if _, err := h.app.EnsureCore(ctx); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
			return
		}
	}
	if err := h.app.SetSystemProxyForced(body.Enabled, body.Force); err != nil {
		// A system proxy that belongs to another program is not an internal
		// error: it is a conflict the user has to settle, and the answer names
		// the program that owns the setting so the UI can say so.
		// "The switch is up but not ours" is the mirror image of the takeover
		// case: there is nothing of ours to switch off, and switching the other
		// program's proxy off is exactly the damage the takeover prompt
		// promised not to do.
		if errors.Is(err, sysproxy.ErrNotOwner) {
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":     err.Error(),
				"not_owner": true,
			})
			return
		}
		if errors.Is(err, sysproxy.ErrForeignOwner) {
			owner, _ := sysproxy.ForeignOwner()
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":         err.Error(),
				"foreign_owner": owner,
			})
			return
		}
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, h.app.Status())
}

func (h *API) handleCores(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.app.CoreStatuses())
}

// coreRequest is the shared body of the core lifecycle endpoints.
type coreRequest struct {
	ID     string `json:"id"`
	Mirror string `json:"mirror"`
}

func decodeCoreRequest(w http.ResponseWriter, r *http.Request) (coreRequest, bool) {
	var body coreRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return coreRequest{}, false
	}
	if strings.TrimSpace(body.ID) == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("id is required"))
		return coreRequest{}, false
	}
	return body, true
}

func (h *API) handleCoreInstall(w http.ResponseWriter, r *http.Request) {
	body, ok := decodeCoreRequest(w, r)
	if !ok {
		return
	}
	mirror := strings.TrimSpace(body.Mirror)
	if mirror == "" {
		mirror = h.app.Config().Core.Mirror
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Minute)
	defer cancel()
	if err := h.app.Cores().Install(ctx, body.ID, mirror); err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, h.app.Cores().StatusFor(body.ID))
}

func (h *API) handleCoreStart(w http.ResponseWriter, r *http.Request) {
	body, ok := decodeCoreRequest(w, r)
	if !ok {
		return
	}
	// Starting a core can involve a one-off geodata download, so this gets a
	// longer budget than the other control calls.
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Minute)
	defer cancel()
	status, err := h.app.StartCore(ctx, body.ID)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "core": status})
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (h *API) handleCoreStop(w http.ResponseWriter, r *http.Request) {
	body, ok := decodeCoreRequest(w, r)
	if !ok {
		return
	}
	if err := h.app.StopCore(body.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, h.app.Cores().StatusFor(body.ID))
}

// handleCoreVersions lists the core binaries on disk: the live one plus the
// archived releases an update replaced, so the console can offer a rollback
// without another download.
func (h *API) handleCoreVersions(w http.ResponseWriter, r *http.Request) {
	id := h.coreIDFromQuery(r)
	if id == "" {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	versions, err := h.app.CoreVersions(id)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, versions)
}

// handleCoreVersionActivate rolls a core back to an archived binary. The core is
// stopped first: Windows refuses to replace a running executable, and a sharing
// violation is a worse error message than "stopped the core, swapped the file,
// started it again". A core that was running is started again afterwards, so a
// rollback is one call from the console.
func (h *API) handleCoreVersionActivate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID      string `json:"id"`
		Version string `json:"version"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	if strings.TrimSpace(body.ID) == "" || strings.TrimSpace(body.Version) == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("id and version are required"))
		return
	}
	wasRunning := h.app.Cores().StatusFor(body.ID).Running
	if wasRunning {
		if err := h.app.StopCore(body.ID); err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Errorf("stop core before rollback: %w", err))
			return
		}
	}
	activated, err := h.app.Cores().ActivateCoreVersion(body.ID, body.Version)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	out := map[string]any{"activated": activated, "restarted": false}
	if wasRunning {
		ctx, cancel := context.WithTimeout(r.Context(), 6*time.Minute)
		defer cancel()
		if _, err := h.app.StartCore(ctx, body.ID); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{
				"error":     fmt.Sprintf("已回滚到 %s，但重启内核失败：%v", activated.Version, err),
				"activated": activated,
				"restarted": false,
			})
			return
		}
		out["restarted"] = true
	}
	out["core"] = h.app.Cores().StatusFor(body.ID)
	writeJSON(w, http.StatusOK, out)
}

// handleCoreGeo reports the geodata files a core loads at startup: which are
// present, which are intact and how large they are.
func (h *API) handleCoreGeo(w http.ResponseWriter, r *http.Request) {
	id := h.coreIDFromQuery(r)
	if id == "" {
		writeJSON(w, http.StatusOK, map[string]any{"core": "", "ready": true, "files": []any{}})
		return
	}
	files := h.app.GeoStatus(id)
	writeJSON(w, http.StatusOK, map[string]any{
		"core":  id,
		"ready": h.app.CoreGeoReady(id),
		"files": files,
	})
}

// handleCoreGeoFetch downloads whatever geodata a core is missing. The UI calls
// this when a start failed because the databases could not be reached.
func (h *API) handleCoreGeoFetch(w http.ResponseWriter, r *http.Request) {
	body, ok := decodeCoreRequest(w, r)
	if !ok {
		return
	}
	id := strings.TrimSpace(body.ID)
	if id == "" {
		id = h.coreIDFromQuery(r)
	}
	if id == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("id is required"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Minute)
	defer cancel()
	fetched, err := h.app.EnsureGeo(ctx, id)
	payload := map[string]any{
		"core":    id,
		"ready":   h.app.CoreGeoReady(id),
		"fetched": fetched,
		"files":   h.app.GeoStatus(id),
	}
	if err != nil {
		payload["error"] = err.Error()
		writeJSON(w, http.StatusBadGateway, payload)
		return
	}
	writeJSON(w, http.StatusOK, payload)
}

// coreIDFromQuery resolves the core the UI means: an explicit id, else the one
// that is running, else the last one selected.
func (h *API) coreIDFromQuery(r *http.Request) string {
	if id := strings.TrimSpace(r.URL.Query().Get("id")); id != "" {
		return id
	}
	if id := h.app.RunningCoreID(); id != "" {
		return id
	}
	return strings.TrimSpace(h.app.Config().Core.ID)
}

func (h *API) handleCoreConfig(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("id is required"))
		return
	}
	raw, err := h.app.RenderCoreConfig(id)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (h *API) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.app.Profile())
}

func (h *API) handlePutProfile(w http.ResponseWriter, r *http.Request) {
	var profile core.Profile
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20))
	if err := dec.Decode(&profile); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid profile JSON: %w", err))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if err := h.app.SetProfile(ctx, profile); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"applied": true, "nodes": len(profile.Nodes)})
}

// subscriptionRequest carries a raw payload or a URL to fetch.
type subscriptionRequest struct {
	Text string `json:"text"`
}

func (h *API) handleSubscriptionParse(w http.ResponseWriter, r *http.Request) {
	body, ok := decodeSubscription(w, r)
	if !ok {
		return
	}
	nodes, groups, rules, err := previewSubscription(body.Text)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"nodes":  nodes,
		"groups": groups,
		"rules":  rules,
	})
}

func (h *API) handleSubscriptionImport(w http.ResponseWriter, r *http.Request) {
	body, ok := decodeSubscription(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	result, err := h.app.ImportSubscription(ctx, body.Text)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func decodeSubscription(w http.ResponseWriter, r *http.Request) (subscriptionRequest, bool) {
	var body subscriptionRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return subscriptionRequest{}, false
	}
	if strings.TrimSpace(body.Text) == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("text is required"))
		return subscriptionRequest{}, false
	}
	return body, true
}

// previewSubscription parses a payload without touching the running config.
func previewSubscription(text string) ([]core.Node, []core.Group, []core.Rule, error) {
	if strings.Contains(text, "proxies:") || strings.Contains(text, "proxy-groups:") {
		imported, err := subscription.ParseClash(text)
		if err != nil {
			return nil, nil, nil, err
		}
		groups := imported.Groups
		if len(groups) == 0 {
			groups = app.DefaultGroups(imported.Nodes)
		}
		return imported.Nodes, groups, imported.Rules, nil
	}
	nodes, err := subscription.Parse(text)
	if err != nil {
		return nil, nil, nil, err
	}
	return nodes, app.DefaultGroups(nodes), nil, nil
}

func (h *API) handleCoreVersion(w http.ResponseWriter, r *http.Request) {
	version, err := h.app.CoreVersion(r.Context(), r.URL.Query().Get("id"))
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, version)
}

func (h *API) handleCoreProxies(w http.ResponseWriter, r *http.Request) {
	view, err := h.app.CoreProxies(r.Context(), r.URL.Query().Get("id"))
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (h *API) handleCoreSelect(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID    string `json:"id"`
		Group string `json:"group"`
		Name  string `json:"name"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	if body.Group == "" || body.Name == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("group and name are required"))
		return
	}
	if err := h.app.SelectProxy(r.Context(), body.ID, body.Group, body.Name); err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"group": body.Group, "now": body.Name})
}

func (h *API) handleCoreDelay(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	name := strings.TrimSpace(q.Get("name"))
	if name == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("name is required"))
		return
	}
	timeout, _ := strconv.Atoi(q.Get("timeout"))
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	delays, err := h.app.CoreDelay(ctx, q.Get("id"), name, q.Get("url"), timeout)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"delays": delays})
}

func (h *API) handleCoreModeGet(w http.ResponseWriter, r *http.Request) {
	mode, err := h.app.CoreMode(r.Context(), r.URL.Query().Get("id"))
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mode": mode})
}

func (h *API) handleCoreModeSet(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID   string `json:"id"`
		Mode string `json:"mode"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	if body.Mode == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("mode is required"))
		return
	}
	mode, err := h.app.SetCoreMode(r.Context(), body.ID, body.Mode)
	if err != nil {
		// A mode the client itself refuses is the caller's mistake, not the
		// core's: answer 400 so the UI can say "unknown mode" instead of
		// "backend error".
		if errors.Is(err, app.ErrInvalidMode) {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mode": mode})
}

func (h *API) handleCoreTraffic(w http.ResponseWriter, r *http.Request) {
	traffic, err := h.app.CoreTraffic(r.Context(), r.URL.Query().Get("id"))
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, traffic)
}

func (h *API) handleCoreConnections(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("raw") == "1" {
		conns, err := h.app.CoreConnections(r.Context(), r.URL.Query().Get("id"))
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, conns)
		return
	}
	views, up, down, err := h.app.CoreConnectionView(r.Context(), r.URL.Query().Get("id"))
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	if views == nil {
		views = []app.ConnectionView{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"connections":    views,
		"upload_total":   up,
		"download_total": down,
	})
}

func (h *API) handleCoreCloseConnection(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID   string `json:"id"`
		Conn string `json:"conn"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	if body.Conn == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("conn is required"))
		return
	}
	if err := h.app.CoreCloseConnection(r.Context(), body.ID, body.Conn); err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"closed": body.Conn})
}

func (h *API) handleCoreUpdates(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, h.app.CoreUpdates(ctx))
}

func (h *API) handleCoreUpdate(w http.ResponseWriter, r *http.Request) {
	body, ok := decodeCoreRequest(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Minute)
	defer cancel()
	info, err := h.app.UpdateCore(ctx, body.ID, body.Mirror)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "update": info})
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (h *API) handleAddNode(w http.ResponseWriter, r *http.Request) {
	var node core.Node
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
	if err := dec.Decode(&node); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid node JSON: %w", err))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if err := h.app.AddNode(ctx, node); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"added": node.Name, "nodes": len(h.app.Profile().Nodes)})
}

func (h *API) handleRemoveNode(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("name is required"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if err := h.app.RemoveNode(ctx, name); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"removed": name, "nodes": len(h.app.Profile().Nodes)})
}

func (h *API) handleSetNetwork(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AllowLAN *bool `json:"allow_lan"`
		IPv6     *bool `json:"ipv6"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	profile := h.app.Profile()
	allowLAN, ipv6 := profile.AllowLAN, profile.IPv6
	if body.AllowLAN != nil {
		allowLAN = *body.AllowLAN
	}
	if body.IPv6 != nil {
		ipv6 = *body.IPv6
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if err := h.app.SetNetworkToggles(ctx, allowLAN, ipv6); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"allow_lan": allowLAN, "ipv6": ipv6})
}

// handlePorts answers where the client listens and whether anything else got
// there first. Another desktop proxy client on the same machine is the normal
// reason for a conflict.
func (h *API) handlePorts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.app.PortReport())
}

// handlePortsRelocate is the one-click repair for that conflict: every port
// somebody else holds moves to a free one above it.
func (h *API) handlePortsRelocate(w http.ResponseWriter, r *http.Request) {
	moves, err := h.app.RelocatePorts()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"moved": moves, "ports": h.app.PortReport()})
}

func (h *API) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	tunReady, hint := elevate.CanCreateTun()
	writeJSON(w, http.StatusOK, map[string]any{
		"platform":    runtime.GOOS,
		"elevated":    elevate.IsElevated(),
		"tun_ready":   tunReady,
		"tun_hint":    hint,
		"tun_enabled": h.app.TunEnabled(),
		"tun_stack":   h.app.TunStack(),
	})
}

func (h *API) handleAutostart(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	exe, err := os.Executable()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if body.Enabled {
		if err := autostart.Enable(exe, []string{"-config", h.app.ConfigPath()}); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
	} else if err := autostart.Disable(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	enabled, command := autostart.Enabled()
	writeJSON(w, http.StatusOK, map[string]any{"enabled": enabled, "command": command})
}

func (h *API) handleAutostartGet(w http.ResponseWriter, r *http.Request) {
	enabled, command := autostart.Enabled()
	writeJSON(w, http.StatusOK, map[string]any{"enabled": enabled, "command": command})
}

// subscriptionView is a Subscription plus the fields the console would
// otherwise have to recompute: when the next automatic refresh is due and how
// long the interval is.
type subscriptionView struct {
	app.Subscription
	IntervalHours int64  `json:"interval_hours"`
	NextUpdate    string `json:"next_update,omitempty"`
}

func (h *API) handleSubscriptions(w http.ResponseWriter, r *http.Request) {
	subs := h.app.Subscriptions()
	views := make([]subscriptionView, 0, len(subs))
	for _, s := range subs {
		view := subscriptionView{Subscription: s, IntervalHours: int64(app.AutoInterval(s) / time.Hour)}
		if s.Auto {
			if next := s.NextUpdate(); !next.IsZero() {
				view.NextUpdate = next.UTC().Format(time.RFC3339)
			}
		}
		views = append(views, view)
	}
	writeJSON(w, http.StatusOK, views)
}

// handleSubscriptionAuto turns the scheduled refresh of one subscription on or
// off.
func (h *API) handleSubscriptionAuto(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
		Auto bool   `json:"auto"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	if strings.TrimSpace(body.Name) == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("name is required"))
		return
	}
	sub, err := h.app.SetSubscriptionAuto(body.Name, body.Auto)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, subscriptionView{Subscription: sub, IntervalHours: int64(app.AutoInterval(sub) / time.Hour)})
}

// handleSubscriptionOptions answers POST /api/subscriptions/options: store the
// per-subscription fetch options (User-Agent and a refresh interval that
// overrides the provider's own header). It does not fetch — the console follows
// up with /api/subscriptions/update when the operator wants the new agent to
// take effect right away.
func (h *API) handleSubscriptionOptions(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name          string `json:"name"`
		UserAgent     string `json:"user_agent"`
		IntervalHours int64  `json:"interval_hours"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	sub, err := h.app.SetSubscriptionOptions(body.Name, body.UserAgent, body.IntervalHours)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, subscriptionView{Subscription: sub, IntervalHours: int64(app.AutoInterval(sub) / time.Hour)})
}

func (h *API) handleAddSubscription(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	sub, err := h.app.AddSubscription(ctx, body.Name, body.URL)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "subscription": sub})
		return
	}
	writeJSON(w, http.StatusOK, sub)
}

func (h *API) handleRemoveSubscription(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("name is required"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if err := h.app.RemoveSubscription(ctx, name); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"removed": name})
}

// handleEditSubscription answers PATCH /api/subscriptions: rename a saved
// subscription and/or point it at a new link. Both fields are optional, so the
// console sends only what the user actually changed. A rename that collides is
// a client error; an edit that was saved but whose re-import failed is reported
// as a gateway error with the stored subscription in the body, exactly like
// AddSubscription, so the UI can say "saved, refresh failed" instead of "lost".
func (h *API) handleEditSubscription(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name    string `json:"name"`
		NewName string `json:"new_name"`
		URL     string `json:"url"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	if strings.TrimSpace(body.Name) == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("name is required"))
		return
	}
	if strings.TrimSpace(body.NewName) == "" && strings.TrimSpace(body.URL) == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("new_name or url is required"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	sub, err := h.app.EditSubscription(ctx, body.Name, body.NewName, body.URL)
	if err != nil {
		view := subscriptionView{Subscription: sub, IntervalHours: int64(app.AutoInterval(sub) / time.Hour)}
		if errors.Is(err, app.ErrSubscriptionStored) {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "subscription": view})
			return
		}
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, subscriptionView{Subscription: sub, IntervalHours: int64(app.AutoInterval(sub) / time.Hour)})
}

func (h *API) handleUpdateSubscription(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
		All  bool   `json:"all"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	if body.All {
		subs, err := h.app.UpdateAllSubscriptions(ctx)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "subscriptions": subs})
			return
		}
		writeJSON(w, http.StatusOK, subs)
		return
	}
	if body.Name == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("name or all is required"))
		return
	}
	sub, err := h.app.UpdateSubscription(ctx, body.Name)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "subscription": sub})
		return
	}
	writeJSON(w, http.StatusOK, sub)
}

func (h *API) handleCorePick(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID      string `json:"id"`
		Group   string `json:"group"`
		TestURL string `json:"test_url"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	if body.ID == "" || body.Group == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("id and group are required"))
		return
	}
	result, err := h.app.SweepGroup(r.Context(), body.ID, body.Group, body.TestURL)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "result": result})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *API) handleCoreSweep(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID      string `json:"id"`
		Group   string `json:"group"`
		TestURL string `json:"test_url"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	if body.ID == "" || body.Group == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("id and group are required"))
		return
	}
	// A whole-group sweep is one long request against the core: it is the core
	// that fans the members out. Give it room instead of the short budget the
	// single-proxy calls use.
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	result, err := h.app.MeasureGroup(ctx, body.ID, body.Group, body.TestURL, 5000)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "result": result})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *API) handleAddRule(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Kind   string `json:"kind"`
		Value  string `json:"value"`
		Action string `json:"action"`
		Index  int    `json:"index"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if err := h.app.AddRule(ctx, core.Rule{
		Kind:   body.Kind,
		Value:  body.Value,
		Action: body.Action,
	}, body.Index); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": len(h.app.Profile().Rules)})
}

func (h *API) handleRemoveRule(w http.ResponseWriter, r *http.Request) {
	index, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("index")))
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("index is required"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if err := h.app.RemoveRule(ctx, index); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": len(h.app.Profile().Rules)})
}

func (h *API) handleRuleProviderList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"providers": h.app.RuleProviders(),
		// P2-8: how many entries each set carries and when it was last
		// refreshed. Measured per request rather than cached: the core
		// refreshes on its own schedule and the page is the only reader.
		"status": h.app.RuleProviderStats(r.Context()),
		"types":  []string{core.ProviderHTTP, core.ProviderFile, core.ProviderInline},
		"behaviors": []string{
			core.ProviderBehaviorDomain,
			core.ProviderBehaviorIPCIDR,
			core.ProviderBehaviorClassical,
		},
		"formats": []string{core.ProviderFormatYAML, core.ProviderFormatText, core.ProviderFormatMrs},
	})
}

func (h *API) handleRuleProviderSet(w http.ResponseWriter, r *http.Request) {
	var body core.RuleProvider
	// An inline provider carries its whole payload in the request, so the body
	// limit has to be generous; 512 KiB is still far below anything that would
	// be better off as a file or a url.
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if err := h.app.UpsertRuleProvider(ctx, body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": len(h.app.RuleProviders())})
}

func (h *API) handleRuleProviderDelete(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	removed, err := h.app.RemoveRuleProvider(ctx, name)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"removed_rules": removed,
		"providers":     len(h.app.RuleProviders()),
	})
}

func (h *API) handleI18nDict(w http.ResponseWriter, r *http.Request) {
	raw, err := fs.ReadFile(webFS, "web/i18n.en.json")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(raw)
}

func (h *API) handleProxyProviderList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"providers": h.app.ProxyProviders(),
		// ProviderInline is deliberately absent: a proxy list has to come from
		// somewhere the core can fetch, so only these two are offered.
		"types": []string{core.ProviderHTTP, core.ProviderFile},
	})
}

func (h *API) handleProxyProviderSet(w http.ResponseWriter, r *http.Request) {
	var body core.Provider
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if err := h.app.UpsertProxyProvider(ctx, body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": len(h.app.ProxyProviders())})
}

func (h *API) handleProxyProviderDelete(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	dropped, err := h.app.RemoveProxyProvider(ctx, name)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	// dropped_group_uses is what the console reports back: a delete that also
	// unhooked a group is worth saying out loud rather than silently.
	writeJSON(w, http.StatusOK, map[string]any{
		"dropped_group_uses": dropped,
		"providers":          len(h.app.ProxyProviders()),
	})
}

func (h *API) handleExportBackup(w http.ResponseWriter, r *http.Request) {
	raw, err := h.app.ExportBackup()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename="+app.BackupName())
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (h *API) handleImportBackup(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if len(body) == 0 {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("请求体为空：请上传备份 zip"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	result, err := h.app.ImportBackup(ctx, body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *API) handlePresets(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.app.PresetList())
}

func (h *API) handleApplyPreset(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	if strings.TrimSpace(body.ID) == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("id is required"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	view, err := h.app.ApplyPreset(ctx, body.ID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (h *API) handleRemovePreset(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("id is required"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	view, err := h.app.RemovePreset(ctx, id)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (h *API) handleCoreProcesses(w http.ResponseWriter, r *http.Request) {
	procs, err := h.app.SeenProcesses(r.Context(), r.URL.Query().Get("id"))
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	if procs == nil {
		procs = []app.ProcessSeen{}
	}
	writeJSON(w, http.StatusOK, procs)
}

// handleTun answers POST /api/system/tun. Both fields are optional so one
// request can either flip the switch, pick the data plane, or do both in the
// order the UI shows them. The reply carries the state that is actually in
// effect rather than what was asked for, which is what makes the switch in the
// title bar impossible to leave showing a lie.
func (h *API) handleTun(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled *bool  `json:"enabled"`
		Stack   string `json:"stack"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if strings.TrimSpace(body.Stack) != "" {
		if err := h.app.SetTunStack(ctx, body.Stack); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
	}
	if body.Enabled != nil {
		if err := h.app.SetTunMode(ctx, *body.Enabled); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tun_enabled": h.app.TunEnabled(),
		"tun_stack":   h.app.TunStack(),
	})
}
