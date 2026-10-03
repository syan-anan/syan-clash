package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// profilesResponse is the shared answer for every profile endpoint: the list
// always travels with the active flag, so the UI never has to guess which
// profile is in force.
func (h *API) profilesResponse() (map[string]any, error) {
	profiles, err := h.app.ListProfiles()
	if err != nil {
		return nil, err
	}
	return map[string]any{"profiles": profiles, "active": h.app.ActiveProfile()}, nil
}

// handleProfilesList returns the saved profiles.
func (h *API) handleProfilesList(w http.ResponseWriter, r *http.Request) {
	body, err := h.profilesResponse()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, body)
}

// handleProfilesAction is the single write endpoint: {action: save|load|delete|rename}.
func (h *API) handleProfilesAction(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name    string `json:"name"`
		Action  string `json:"action"`
		NewName string `json:"new_name"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON: %w", err))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	switch strings.ToLower(strings.TrimSpace(body.Action)) {
	case "save":
		if err := h.app.SaveProfile(body.Name); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
	case "load":
		if err := h.app.LoadProfile(ctx, body.Name); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
	case "delete":
		if err := h.app.DeleteProfile(body.Name); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
	case "rename":
		if err := h.app.RenameProfile(body.Name, body.NewName); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
	default:
		writeErr(w, http.StatusBadRequest, fmt.Errorf("unknown action %q (save/load/delete/rename)", body.Action))
		return
	}
	resp, err := h.profilesResponse()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleProfilesDelete removes one profile by name.
func (h *API) handleProfilesDelete(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("name is required"))
		return
	}
	if err := h.app.DeleteProfile(name); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	resp, err := h.profilesResponse()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}
