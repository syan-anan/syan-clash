package control

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"vvpn/internal/app"
	"vvpn/internal/diag"
	"vvpn/internal/shellopen"
)

// P22: the AI 直达页 backend. The page asks one question - which of a group's
// nodes can reach ChatGPT and Gemini - and the run answers it by switching the
// group to each member in turn and putting it back afterwards.

// handleDiagAIRun answers POST /api/diag/ai/run.
func (h *API) handleDiagAIRun(w http.ResponseWriter, r *http.Request) {
	if !h.diagGated(w) {
		return
	}
	var body struct {
		Group       string `json:"group"`
		OnlyMissing bool   `json:"only_missing"`
	}
	if !decodeDiagBody(w, r, &body) {
		return
	}
	if strings.TrimSpace(body.Group) == "" {
		writeErr(w, http.StatusBadRequest, errors.New("group is required"))
		return
	}
	// Only the group resolution runs on the request context; the sweep itself
	// keeps its own job context, so a page that navigates away mid-run does not
	// abandon the restore step.
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	job, err := h.app.StartAIJob(ctx, body.Group, body.OnlyMissing)
	if err != nil {
		h.writeAIErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

// handleDiagAIStatus answers GET /api/diag/ai/status. Without a job id it
// answers the idle shape, which is what the page polls before a run starts.
func (h *API) handleDiagAIStatus(w http.ResponseWriter, r *http.Request) {
	job := strings.TrimSpace(r.URL.Query().Get("job"))
	if job == "" {
		writeJSON(w, http.StatusOK, app.AIStatus{Phase: "idle", Rows: []app.AIRow{}, Errors: []string{}})
		return
	}
	st := h.app.AIStatus(job)
	if st.Job == "" {
		writeErr(w, http.StatusNotFound, errors.New("job "+job+" not found"))
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// handleDiagAICancel answers POST /api/diag/ai/cancel. The worker finishes its
// restore step after the cancel, so the group is never left on a test node.
func (h *API) handleDiagAICancel(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Job string `json:"job"`
	}
	if !decodeDiagBody(w, r, &body) {
		return
	}
	job := strings.TrimSpace(body.Job)
	if job == "" {
		writeErr(w, http.StatusBadRequest, errors.New("job is required"))
		return
	}
	if err := h.app.CancelAIJob(job); err != nil {
		h.writeAIErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"job": job, "canceled": true})
}

// handleDiagAILogin answers POST /api/diag/ai/login: it hands a sign-in request
// to a separate process. The sign-in needs its own window and its own browser
// profile (the console's profile must not collect the operator's AI session),
// so it is a fresh "-ai-login" run rather than anything this server can do
// in-process.
func (h *API) handleDiagAILogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Service string `json:"service"`
	}
	if !decodeDiagBody(w, r, &body) {
		return
	}
	service := strings.ToLower(strings.TrimSpace(body.Service))
	switch service {
	case "chatgpt", "gemini":
	default:
		writeErr(w, http.StatusBadRequest,
			fmt.Errorf("不认识的 AI 服务 %q（只支持 chatgpt / gemini）", service))
		return
	}
	if err := shellopen.Self("-ai-login", service); err != nil {
		writeErr(w, http.StatusBadGateway, fmt.Errorf("打开登录窗口失败：%w", err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"service": service, "started": true})
}

// writeAIErr maps an AI request failure onto the contract's status codes: a
// second run is a 409, a fixable request is a 400, an unknown job is a 404,
// and anything else is the kernel refusing to answer.
func (h *API) writeAIErr(w http.ResponseWriter, err error) {
	var busy *diag.JobBusyError
	if errors.As(err, &busy) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "job": busy.ID, "busy": true})
		return
	}
	var bad *app.AIBadRequestError
	if errors.As(err, &bad) {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	var missing *app.AINotFoundError
	if errors.As(err, &missing) {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	writeErr(w, http.StatusBadGateway, err)
}
