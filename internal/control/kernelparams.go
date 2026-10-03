package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"vvpn/internal/app"
)

// handleKernelParamsGet answers GET /api/cores/params: the tuning values a core
// would be handed right now, plus the bounds the console needs to render the
// MTU box and the level list.
func (h *API) handleKernelParamsGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.app.KernelParams())
}

// handleKernelParamsSet answers POST /api/cores/params. Every field is optional
// so one request can change one control; the reply carries the values that are
// actually stored, which is what the console renders instead of the click.
func (h *API) handleKernelParamsSet(w http.ResponseWriter, r *http.Request) {
	var patch app.KernelParamsPatch
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(&patch); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	out, err := h.app.SetKernelParams(ctx, patch)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
