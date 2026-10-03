package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"vvpn/internal/urlscheme"
)

// The clash:// card (P2-6). Reading is a plain GET; turning the switch on can
// fail with 409 when another client already owns the scheme, and handling a
// link is the same call the desktop shell makes when the user opens one - so a
// link behaves identically whether it arrived through the shell, through a
// second launch forwarding it, or pasted into the console.

func (h *API) handleURLSchemeGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.app.URLSchemeStatus())
}

func (h *API) handleURLSchemeSet(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	st, err := h.app.SetURLScheme(body.Enabled)
	if err != nil {
		// A scheme owned by another program is a conflict, not a bad request:
		// the caller asked for something reasonable and the machine said no.
		// The current state travels with the error so the console can name the
		// program that holds it instead of showing a bare failure.
		if errors.Is(err, urlscheme.ErrForeignOwner) {
			writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "status": st})
			return
		}
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (h *API) handleURLSchemeHandle(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL string `json:"url"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	if strings.TrimSpace(body.URL) == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("url is required"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	res, err := h.app.HandleURLScheme(ctx, body.URL)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}
