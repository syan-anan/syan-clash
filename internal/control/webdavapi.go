package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"vvpn/internal/app"
	"vvpn/internal/config"
)

// The WebDAV backup endpoints (P1-11). They are a thin shell around the
// app.WebDAV* methods: the control layer owns only the HTTP shape - status
// codes, request bodies and the "the password is never echoed back" rule.
//
// A backup archive can be several megabytes, so upload and download get a
// generous budget; the WebDAV client itself caps every phase at 60s.

const (
	webdavListTimeout     = 90 * time.Second
	webdavTransferTimeout = 5 * time.Minute
	webdavDeleteTimeout   = 90 * time.Second
)

// handleWebDAVGet answers GET /api/backup/webdav with the stored settings plus
// the current directory listing. A listing failure is reported inside the
// document instead of failing the read: the user still needs to see - and be
// able to fix - the address they typed.
func (h *API) handleWebDAVGet(w http.ResponseWriter, r *http.Request) {
	view := h.app.WebDAVConfigView()
	body := map[string]any{
		"enabled":      view.Enabled,
		"url":          view.URL,
		"username":     view.Username,
		"has_password": view.HasPassword,
		"password":     view.Password,
		"files":        []app.WebDAVFile{},
	}
	if strings.TrimSpace(view.URL) != "" {
		ctx, cancel := context.WithTimeout(r.Context(), webdavListTimeout)
		defer cancel()
		files, err := h.app.WebDAVList(ctx)
		if err != nil {
			body["error"] = err.Error()
		} else {
			body["files"] = files
		}
	}
	writeJSON(w, http.StatusOK, body)
}

// handleWebDAVConfigSet answers POST /api/backup/webdav/config.
//
// An empty password means "keep the stored one": the console sends only what
// the user touched, so editing the URL must not wipe the secret. To make that
// explicit the request uses a pointer for enabled too - a body that never
// mentions the switch leaves it alone.
func (h *API) handleWebDAVConfigSet(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL      string `json:"url"`
		Username string `json:"username"`
		Password string `json:"password"`
		Enabled  *bool  `json:"enabled"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	url := strings.TrimSpace(body.URL)
	if url != "" {
		if err := app.ValidateWebDAVURL(url); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
	}
	next := config.WebDAVSettings{
		URL:      url,
		Username: strings.TrimSpace(body.Username),
		Password: body.Password,
	}
	if body.Enabled != nil {
		next.Enabled = *body.Enabled
	} else {
		next.Enabled = h.app.Config().WebDAV.Enabled
	}
	keepPassword := strings.TrimSpace(body.Password) == ""
	if err := h.app.SetWebDAVSettings(next, keepPassword); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	view := h.app.WebDAVConfigView()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":      view.Enabled,
		"url":          view.URL,
		"username":     view.Username,
		"has_password": view.HasPassword,
		"password":     view.Password,
	})
}

// handleWebDAVUpload answers POST /api/backup/webdav/upload: it packs the
// current configuration and stores it in the configured directory.
func (h *API) handleWebDAVUpload(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), webdavTransferTimeout)
	defer cancel()
	file, err := h.app.WebDAVUpload(ctx)
	if err != nil {
		writeErr(w, webdavStatus(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": file.Name, "size": file.Size})
}

// handleWebDAVDownload answers POST /api/backup/webdav/download: it fetches a
// stored archive and applies it through the normal ImportBackup path.
func (h *API) handleWebDAVDownload(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	if strings.TrimSpace(body.Name) == "" {
		writeErr(w, http.StatusBadRequest, errors.New("缺少备份文件名"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), webdavTransferTimeout)
	defer cancel()
	raw, err := h.app.WebDAVDownload(ctx, body.Name)
	if err != nil {
		writeErr(w, webdavStatus(err), err)
		return
	}
	result, err := h.app.ImportBackup(ctx, raw)
	if err != nil {
		// The download worked; the archive itself is bad, which is a request
		// problem rather than a gateway problem.
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// handleWebDAVDelete answers DELETE /api/backup/webdav.
func (h *API) handleWebDAVDelete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	if strings.TrimSpace(body.Name) == "" {
		writeErr(w, http.StatusBadRequest, errors.New("缺少备份文件名"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), webdavDeleteTimeout)
	defer cancel()
	if err := h.app.WebDAVDelete(ctx, body.Name); err != nil {
		writeErr(w, webdavStatus(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": strings.TrimSpace(body.Name)})
}

// webdavStatus maps the two "the user has to fix this" errors to 400; every
// other failure came from the remote server or the network, so it is a 502.
func webdavStatus(err error) int {
	if errors.Is(err, app.ErrWebDAVNotConfigured) || errors.Is(err, app.ErrWebDAVBadName) {
		return http.StatusBadRequest
	}
	return http.StatusBadGateway
}
