package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"vvpn/internal/app"
	"vvpn/internal/config"
)

// handleNodeFilterGet returns the stored node filter.
func (h *API) handleNodeFilterGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"filter": h.app.NodeFilter()})
}

// handleNodeFilterSet stores a filter and re-derives the node list from the
// pre-filter baseline, then reports how many nodes were kept, dropped and
// renamed. A core that refuses to restart still returns the counts, so the UI
// can say what happened instead of pretending nothing did.
func (h *API) handleNodeFilterSet(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Filter config.NodeFilter `json:"filter"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON: %w", err))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	result, err := h.app.ApplyNodeFilter(ctx, body.Filter)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error":   err.Error(),
			"filter":  body.Filter,
			"nodes":   result.Kept,
			"dropped": result.Dropped,
			"renamed": result.Renamed,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"filter":  body.Filter,
		"nodes":   result.Kept,
		"dropped": result.Dropped,
		"renamed": result.Renamed,
		"names":   result.Names,
	})
}

// handleGroupList returns every proxy group plus the names a member may point
// at, so the UI can build the member picker without a second round trip.
func (h *API) handleGroupList(w http.ResponseWriter, r *http.Request) {
	names := make([]string, 0, len(h.app.Profile().Nodes))
	for _, n := range h.app.Profile().Nodes {
		names = append(names, n.Name)
	}
	groupNames := make([]string, 0, 8)
	for _, g := range h.app.GroupViews() {
		groupNames = append(groupNames, g.Name)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"groups": h.app.GroupViews(),
		"nodes":  names,
		"names":  groupNames,
	})
}

// handleGroupEdit is the single write endpoint for groups:
//
//	{"index":2,"type":"url-test","members":[...],"test_url":...,"interval":300}
//	{"add":true,"name":"流媒体","type":"select","members":[...]}
//	{"remove":"旧组"}
func (h *API) handleGroupEdit(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Index  *int   `json:"index"`
		Add    bool   `json:"add"`
		Remove string `json:"remove"`
		app.GroupEdit
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON: %w", err))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	var err error
	switch {
	case body.Remove != "":
		err = h.app.RemoveGroup(ctx, body.Remove)
	case body.Add:
		err = h.app.AddGroup(ctx, body.GroupEdit)
	case body.Index != nil:
		err = h.app.SetGroup(ctx, *body.Index, body.GroupEdit)
	default:
		writeErr(w, http.StatusBadRequest, fmt.Errorf("需要 index、add 或 remove 之一"))
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": h.app.GroupViews()})
}
