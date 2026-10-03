package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"vvpn/internal/app"
	"vvpn/internal/core"
	"vvpn/internal/diag"
)

// The resolver card is one profile field plus one probe. Everything the console
// needs to draw it arrives in a single GET: the stored block, how each entry is
// classified, the machine's own resolvers, and the tunnel state that decides
// whether those resolvers are captured or exposed.

// dnsView is that answer.
type dnsView struct {
	DNS        core.DNS `json:"dns"`
	Kinds      []string `json:"kinds"`
	Tun        bool     `json:"tun"`
	Default    core.DNS `json:"default"`
	Strategies []string `json:"strategies"`
	SystemDNS  []string `json:"system_dns"`
}

// buildDNSView assembles the card's state.
func (h *API) buildDNSView() dnsView {
	profile := h.app.Profile()
	dns := profile.DNS
	view := dnsView{
		DNS:        dns,
		Tun:        app.ProfileHasTun(profile),
		Default:    app.DefaultDNS(),
		Strategies: core.DNSStrategies,
		Kinds:      make([]string, 0, len(dns.Servers)),
		SystemDNS:  diag.SystemResolvers(),
	}
	for _, s := range dns.Servers {
		view.Kinds = append(view.Kinds, core.DNSResolverKind(s))
	}
	if view.SystemDNS == nil {
		view.SystemDNS = []string{}
	}
	return view
}

// handleGetDNS answers GET /api/dns.
func (h *API) handleGetDNS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.buildDNSView())
}

// handleSetDNS answers POST /api/dns. Every field is a pointer so "not sent"
// and "sent as false" stay different things: the card saves one control at a
// time and must not clobber the rest of the block.
func (h *API) handleSetDNS(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled     *bool     `json:"enabled"`
		Servers     *[]string `json:"servers"`
		FakeIP      *bool     `json:"fakeip"`
		FakeIPRange *string   `json:"fakeip_range"`
		Strategy    *string   `json:"strategy"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	next := h.app.DNSConfig()
	if body.Enabled != nil {
		next.Enabled = *body.Enabled
	}
	if body.Servers != nil {
		next.Servers = *body.Servers
	}
	if body.FakeIP != nil {
		next.FakeIP = *body.FakeIP
	}
	if body.FakeIPRange != nil {
		next.FakeIPRange = *body.FakeIPRange
	}
	if body.Strategy != nil {
		next.Strategy = *body.Strategy
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if err := h.app.SetDNSConfig(ctx, next); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, h.buildDNSView())
}

// handleDiagDNSLeak answers POST /api/diag/dnsleak: one row per resolver, with
// what it answered, whether the answer was tampered with, and whether anybody
// on the path could read the question. An empty body is the common case and
// means "the resolvers the profile is configured with".
func (h *API) handleDiagDNSLeak(w http.ResponseWriter, r *http.Request) {
	if !h.diagGated(w) {
		return
	}
	var body struct {
		Via     string   `json:"via"`
		Servers []string `json:"servers"`
		Refresh bool     `json:"refresh"`
	}
	if r.Body != nil {
		// A malformed body is not worth a 400 here: the probe's defaults are
		// the useful answer anyway.
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body)
	}
	servers := body.Servers
	if len(servers) == 0 {
		servers = h.app.DNSConfig().Servers
	}
	profile := h.app.Profile()
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	rep, err := h.app.DiagProber().ProbeDNSLeak(ctx, diag.ParseVia(body.Via), servers,
		app.ProfileHasTun(profile), body.Refresh)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}
