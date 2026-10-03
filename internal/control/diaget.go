package control

import (
	"context"
	"net/http"
	"time"

	"vvpn/internal/diag"
)

// F6: the network toolbox. DNS, TCP, TLS and MTU answer in one shot; a
// traceroute is a job because it can take a while and must be cancellable.

// handleDiagDNS answers POST /api/diag/dns.
func (h *API) handleDiagDNS(w http.ResponseWriter, r *http.Request) {
	if !h.diagGated(w) {
		return
	}
	var body struct {
		Name   string `json:"name"`
		Type   string `json:"type"`
		Server string `json:"server"`
		Via    string `json:"via"`
	}
	if !decodeDiagBody(w, r, &body) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	res, err := h.app.DiagProber().ResolveDNS(ctx, body.Name, body.Type, body.Server, diag.ParseVia(body.Via))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handleDiagTCP answers POST /api/diag/tcp.
func (h *API) handleDiagTCP(w http.ResponseWriter, r *http.Request) {
	if !h.diagGated(w) {
		return
	}
	var body struct {
		Host      string `json:"host"`
		Port      int    `json:"port"`
		Via       string `json:"via"`
		TimeoutMS int    `json:"timeout_ms"`
	}
	if !decodeDiagBody(w, r, &body) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	res, err := h.app.DiagProber().TCPPing(ctx, body.Host, body.Port, diag.ParseVia(body.Via), body.TimeoutMS)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handleDiagTLS answers POST /api/diag/tls.
func (h *API) handleDiagTLS(w http.ResponseWriter, r *http.Request) {
	if !h.diagGated(w) {
		return
	}
	var body struct {
		Host string   `json:"host"`
		Port int      `json:"port"`
		Via  string   `json:"via"`
		ALPN []string `json:"alpn"`
	}
	if !decodeDiagBody(w, r, &body) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	res, err := h.app.DiagProber().TLSInspect(ctx, body.Host, body.Port, diag.ParseVia(body.Via), body.ALPN)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handleDiagMTU answers POST /api/diag/mtu.
func (h *API) handleDiagMTU(w http.ResponseWriter, r *http.Request) {
	if !h.diagGated(w) {
		return
	}
	var body struct {
		Host      string `json:"host"`
		Min       int    `json:"min"`
		Max       int    `json:"max"`
		TimeoutMS int    `json:"timeout_ms"`
	}
	if !decodeDiagBody(w, r, &body) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	res, err := h.app.DiagProber().ProbeMTU(ctx, body.Host, body.Min, body.Max, body.TimeoutMS)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handleDiagTraceStart answers POST /api/diag/trace/start.
func (h *API) handleDiagTraceStart(w http.ResponseWriter, r *http.Request) {
	if !h.diagGated(w) {
		return
	}
	var body struct {
		Host      string `json:"host"`
		MaxHops   int    `json:"max_hops"`
		TimeoutMS int    `json:"timeout_ms"`
		Queries   int    `json:"queries"`
	}
	if !decodeDiagBody(w, r, &body) {
		return
	}
	job, err := h.app.DiagProber().StartTrace(diag.TraceRequest{
		Host:      body.Host,
		MaxHops:   body.MaxHops,
		TimeoutMS: body.TimeoutMS,
		Queries:   body.Queries,
	})
	if err != nil {
		h.writeDiagJobErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"job": job.ID})
}

// handleDiagTraceStatus returns the hop list so far.
func (h *API) handleDiagTraceStatus(w http.ResponseWriter, r *http.Request) {
	h.writeDiagJobStatus(w, r)
}

// handleDiagTraceCancel stops a running walk.
func (h *API) handleDiagTraceCancel(w http.ResponseWriter, r *http.Request) {
	h.writeDiagJobCancel(w, r)
}
