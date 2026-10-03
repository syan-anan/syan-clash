package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"vvpn/internal/app"
	"vvpn/internal/config"
	"vvpn/internal/diag"
)

// The diagnostics surface is one page in the console and one file here: the
// probes share one gate (the config switch), one job registry and the JSON
// shapes the page renders.
//
// Every external probe answers 403 while diagnostics.enable_external is false.
// The switch exists so a user can cut all outbound probing without stopping
// the client itself.

// diagGated writes the "probing is off" answer and reports whether the caller
// may continue.
func (h *API) diagGated(w http.ResponseWriter) bool {
	if h.app.DiagExternalOn() {
		return true
	}
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "外部探测已在配置中关闭"})
	return false
}

// splitDiagList parses a comma-separated query value.
func splitDiagList(raw string) []string {
	out := []string{}
	for _, part := range strings.Split(raw, ",") {
		if s := strings.TrimSpace(part); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// handleCloseAllConnections drops every connection the running core tracks in
// one request; the panel used to loop single closes, one round trip each.
func (h *API) handleCloseAllConnections(w http.ResponseWriter, r *http.Request) {
	body, ok := decodeCoreRequest(w, r)
	if !ok {
		return
	}
	if err := h.app.CoreCloseAllConnections(r.Context(), body.ID); err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleDiagIP answers GET /api/diag/ip: what the internet thinks this exit
// is. compare=1 adds the direct column so the user can see how far the node is
// from their own line.
func (h *API) handleDiagIP(w http.ResponseWriter, r *http.Request) {
	if !h.diagGated(w) {
		return
	}
	q := r.URL.Query()
	via := diag.ParseVia(q.Get("via"))
	refresh := q.Get("refresh") == "1"
	prober := h.app.DiagProber()
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	rep, _, err := prober.CheckIP(ctx, via, refresh)
	if err != nil && rep.IP == "" {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	if q.Get("compare") == "1" {
		if direct, _, derr := prober.CheckIP(ctx, diag.ViaDirect, refresh); derr == nil {
			rep.Direct = &direct
		}
	}
	writeJSON(w, http.StatusOK, rep)
}

// handleDiagUnlock answers GET /api/diag/unlock: one verdict per service,
// measured through the chosen path.
func (h *API) handleDiagUnlock(w http.ResponseWriter, r *http.Request) {
	if !h.diagGated(w) {
		return
	}
	q := r.URL.Query()
	via := diag.ParseVia(q.Get("via"))
	only := splitDiagList(q.Get("only"))
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	rep, _, err := h.app.DiagProber().ProbeUnlock(ctx, via, only)
	if err != nil && len(rep.Results) == 0 {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// diagMatrixRunBody is the matrix run request.
type diagMatrixRunBody struct {
	Core        string   `json:"core"`
	Group       string   `json:"group"`
	Nodes       []string `json:"nodes"`
	URLs        []string `json:"urls"`
	TimeoutMS   int      `json:"timeout_ms"`
	Concurrency int      `json:"concurrency"`
	OnlyMissing bool     `json:"only_missing"`
}

// handleDiagMatrixRun starts a node-by-site sweep. The response carries the
// job id; cells are visible through the status route while it runs.
func (h *API) handleDiagMatrixRun(w http.ResponseWriter, r *http.Request) {
	if !h.diagGated(w) {
		return
	}
	var body diagMatrixRunBody
	if !decodeDiagBody(w, r, &body) {
		return
	}
	cfg := h.app.DiagSettings()
	sites := diag.ResolveSites(body.URLs)
	if len(sites) == 0 {
		presets := diag.PresetSites()
		if len(presets) > 3 {
			presets = presets[:3]
		}
		sites = presets
	}
	nodes := body.Nodes
	if len(nodes) == 0 {
		nodes = h.app.DiagNodeNames(body.Group)
	}
	if len(nodes) == 0 {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("没有可测的节点"))
		return
	}
	maxCells := cfg.Matrix.MaxCells
	if maxCells <= 0 {
		maxCells = 2000
	}
	if cells := len(nodes) * len(sites); cells > maxCells {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("矩阵过大：%d 节点 × %d 站点 = %d 单元，上限 %d，请缩小范围", len(nodes), len(sites), cells, maxCells))
		return
	}
	conc := clampDiag(body.Concurrency, cfg.Matrix.DefaultConcurrency, 1, 8)
	timeout := clampDiag(body.TimeoutMS, cfg.Matrix.DefaultTimeoutMS, 1000, 10000)
	job, err := h.app.DiagProber().StartMatrix(diagDelayer{h.app}, diag.MatrixRequest{
		Nodes:       nodes,
		Sites:       sites,
		Concurrency: conc,
		TimeoutMS:   timeout,
		OnlyMissing: body.OnlyMissing,
	})
	if err != nil {
		h.writeDiagJobErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"job": job.ID, "total": len(nodes) * len(sites), "concurrency": conc})
}

// handleDiagMatrixStatus returns the incremental snapshot of a matrix sweep.
func (h *API) handleDiagMatrixStatus(w http.ResponseWriter, r *http.Request) {
	h.writeDiagJobStatus(w, r)
}

// handleDiagMatrixCancel stops a running sweep.
func (h *API) handleDiagMatrixCancel(w http.ResponseWriter, r *http.Request) {
	h.writeDiagJobCancel(w, r)
}

// diagSpeedStartBody is the speedtest start request.
type diagSpeedStartBody struct {
	Server    string `json:"server"`
	Base      string `json:"base"`
	Mode      string `json:"mode"`
	Streams   int    `json:"streams"`
	DurationS int    `json:"duration_s"`
}

// handleDiagSpeedStart starts a throughput run against the built-in
// Cloudflare endpoints or a user-supplied LibreSpeed base.
func (h *API) handleDiagSpeedStart(w http.ResponseWriter, r *http.Request) {
	if !h.diagGated(w) {
		return
	}
	var body diagSpeedStartBody
	if !decodeDiagBody(w, r, &body) {
		return
	}
	cfg := h.app.DiagSettings()
	srv, err := resolveSpeedServer(body, cfg.SpeedtestServers)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	via := diag.ParseVia(body.Mode)
	streams := body.Streams
	if streams <= 0 {
		streams = cfg.Speedtest.Streams
	}
	dur := body.DurationS
	if dur <= 0 {
		dur = cfg.Speedtest.DefaultDurationSec
	}
	job, err := h.app.DiagProber().StartSpeedtest(via, srv, streams, dur, cfg.Speedtest.CapSec)
	if err != nil {
		h.writeDiagJobErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"job": job.ID, "server": srv.Name})
}

// handleDiagSpeedStatus returns the live phase, rates and curve of a run.
func (h *API) handleDiagSpeedStatus(w http.ResponseWriter, r *http.Request) {
	h.writeDiagJobStatus(w, r)
}

// handleDiagSpeedCancel stops a running run; the done phase keeps whatever was
// measured so far.
func (h *API) handleDiagSpeedCancel(w http.ResponseWriter, r *http.Request) {
	h.writeDiagJobCancel(w, r)
}

// handleDiagSpeedHistory lists the last few finished runs.
func (h *API) handleDiagSpeedHistory(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"results": h.app.DiagProber().SpeedHistory()})
}

// writeDiagJobStatus is the shared GET ?id= answer for matrix and traceroute
// and speedtest jobs: identity, state, elapsed time and the snapshot.
func (h *API) writeDiagJobStatus(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("id is required"))
		return
	}
	job, ok := h.app.DiagProber().Jobs().Get(id)
	if !ok {
		writeErr(w, http.StatusNotFound, fmt.Errorf("job %s not found", id))
		return
	}
	writeJSON(w, http.StatusOK, job.Status())
}

// writeDiagJobCancel is the shared POST {"id":...} answer.
func (h *API) writeDiagJobCancel(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	if !decodeDiagBody(w, r, &body) {
		return
	}
	id := strings.TrimSpace(body.ID)
	if id == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("id is required"))
		return
	}
	if !h.app.DiagProber().Jobs().Cancel(id) {
		writeErr(w, http.StatusNotFound, fmt.Errorf("job %s not found", id))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": diag.JobCanceled})
}

// writeDiagJobErr maps a start failure: a busy kind is a 409 with the running
// job id, so the page can attach to it instead of starting a second run.
func (h *API) writeDiagJobErr(w http.ResponseWriter, err error) {
	var busy *diag.JobBusyError
	if errors.As(err, &busy) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "job": busy.ID, "busy": true})
		return
	}
	writeErr(w, http.StatusBadGateway, err)
}

// resolveSpeedServer picks the backend for a start request: a name from the
// user's list first, then the two built-ins, then a pasted URL.
func resolveSpeedServer(req diagSpeedStartBody, list []config.SpeedtestServer) (config.SpeedtestServer, error) {
	name := strings.TrimSpace(req.Server)
	base := strings.TrimSpace(req.Base)
	for _, s := range list {
		if strings.EqualFold(name, s.Name) {
			if base != "" {
				s.Base = base
			}
			return s, nil
		}
	}
	token := strings.ToLower(name)
	switch {
	case base != "" && token != "cloudflare":
		return librespeedServer(base), nil
	case token == "librespeed":
		return config.SpeedtestServer{}, fmt.Errorf("LibreSpeed 服务器需要填 base 地址")
	case token == "" || token == "cloudflare":
		for _, s := range list {
			if strings.EqualFold(s.Kind, "cloudflare") {
				return s, nil
			}
		}
		if defs := config.DefaultSpeedtestServers(); len(defs) > 0 {
			return defs[0], nil
		}
		return config.SpeedtestServer{Name: "Cloudflare", Kind: "cloudflare", Base: "https://speed.cloudflare.com"}, nil
	case strings.Contains(token, "://"):
		return librespeedServer(name), nil
	default:
		return config.SpeedtestServer{}, fmt.Errorf("未知的测速服务器: %s", name)
	}
}

// librespeedServer names a custom base after its host, which is what the
// dropdown shows.
func librespeedServer(base string) config.SpeedtestServer {
	name := "LibreSpeed"
	if u, err := url.Parse(base); err == nil && u.Host != "" {
		name = u.Host
	}
	return config.SpeedtestServer{Name: name, Kind: "librespeed", Base: base}
}

// clampDiag applies the shipped bounds to a caller-provided number.
func clampDiag(v, fallback, lo, hi int) int {
	if v <= 0 {
		v = fallback
	}
	if v < lo {
		v = lo
	}
	if v > hi {
		v = hi
	}
	return v
}

// decodeDiagBody reads a JSON body into dest, answering 400 on a bad one.
func decodeDiagBody(w http.ResponseWriter, r *http.Request, dest any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
	if err := dec.Decode(dest); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return false
	}
	return true
}

// diagDelayer adapts the app to the matrix Delayer interface. The app method
// carries the Diag prefix so it cannot be mistaken for the proxy path, hence
// the tiny shim.
type diagDelayer struct{ app *app.App }

func (d diagDelayer) DelayNode(ctx context.Context, node, rawURL string, timeoutMS int) (int, error) {
	return d.app.DiagDelayNode(ctx, node, rawURL, timeoutMS)
}
