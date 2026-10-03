package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"vvpn/internal/panel"
)

// The 小白 page drives a small API that proxies the provider panel through the
// app, so the browser never sees credentials or talks to the panel directly.

type panelLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	// RememberPassword is opt-in and defaults to false: without it the password
	// is used for this login and never written anywhere.
	RememberPassword bool `json:"remember_password"`
}

func (h *API) handlePanelState(w http.ResponseWriter, r *http.Request) {
	state := h.app.PanelState()
	resp := map[string]any{
		"logged_in":         state.LoggedIn,
		"email":             state.Email,
		"base_url":          state.BaseURL,
		"remember_password": state.RememberPassword,
		// The password itself is never echoed back; the page only needs to know
		// whether one is stored, so it can offer "直接登录" instead of a field.
		"password_saved": state.PasswordSaved,
	}
	// Best effort: the welcome banner comes from the panel's public config.
	// A network hiccup must not break the page.
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	if cfg, err := h.app.PanelClient().CommConfig(ctx); err == nil {
		resp["welcome"] = cfg.AppDescription
		resp["site"] = cfg.AppURL
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *API) handlePanelLogin(w http.ResponseWriter, r *http.Request) {
	var body panelLoginRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	info, err := h.app.PanelLogin(ctx, body.Email, body.Password, body.RememberPassword)
	if err != nil {
		writePanelErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"logged_in":         true,
		"user":              info,
		"remember_password": h.app.PanelState().RememberPassword,
		"password_saved":    h.app.PanelState().PasswordSaved,
	})
}

// handlePanelRememberPassword is the "记住密码" switch on its own, so it can be
// flipped without logging in again. Turning it off erases the stored password.
func (h *API) handlePanelRememberPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	if err := h.app.PanelSetRememberPassword(body.Enabled); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	st := h.app.PanelState()
	writeJSON(w, http.StatusOK, map[string]any{
		"remember_password": st.RememberPassword,
		"password_saved":    st.PasswordSaved,
	})
}

// handlePanelSetBase repoints the panel client (the vendor host rotates) and
// answers with the public config so the page can show the site it reached.
func (h *API) handlePanelSetBase(w http.ResponseWriter, r *http.Request) {
	var body struct {
		BaseURL string `json:"base_url"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<15))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	cfg, err := h.app.PanelSetBase(ctx, body.BaseURL)
	if err != nil {
		writePanelErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"base_url":  h.app.PanelState().BaseURL,
		"logged_in": h.app.PanelState().LoggedIn,
		"site":      cfg.AppURL,
		"welcome":   cfg.AppDescription,
	})
}

// handlePanelNotice lists the panel announcements; an empty list is a valid
// answer and the page simply hides the card.
func (h *API) handlePanelNotice(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	notices, err := h.app.PanelNotices(ctx)
	if err != nil {
		writePanelErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"notices": notices})
}

func (h *API) handlePanelLogout(w http.ResponseWriter, r *http.Request) {
	if err := h.app.PanelLogout(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"logged_in": false})
}

func (h *API) handlePanelInfo(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	info, err := h.app.PanelUserInfo(ctx)
	if err != nil {
		writePanelErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (h *API) handlePanelSubscribe(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	sub, err := h.app.PanelSubscribe(ctx)
	if err != nil {
		writePanelErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sub)
}

func (h *API) handlePanelImport(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	result, saved, err := h.app.PanelImport(ctx)
	if err != nil {
		// Nothing was stored, so there is no partial state to describe: the
		// failure belongs to the panel route like any other, and a missing
		// login has to stay 401 instead of turning into "the panel is
		// unreachable" (which sends the user chasing a healthy server).
		if saved.Name == "" && saved.URL == "" {
			writePanelErr(w, err)
			return
		}
		// The import may have partially succeeded (subscription stored but the
		// fetch failed); report both so the UI can explain the state, with the
		// same status every other panel route would have used.
		writeJSON(w, panelErrStatus(err), map[string]any{
			"error":        err.Error(),
			"subscription": saved,
			"result":       result,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"subscription": saved,
		"result":       result,
	})
}

// panelErrStatus is the HTTP status a panel failure maps to: 401 means "log in
// again", 400 means "the console sent something the panel rejects", 504 means
// "the panel did not answer in time" and 502 covers everything else. It is
// split out because the import endpoint answers with a body of its own and must
// still report the same statuses as every other panel route.
func panelErrStatus(err error) int {
	// A caller-fixable input problem is the console's to correct, so it maps to
	// 400: a 502 here would send users chasing a healthy panel.
	var ie *panel.InvalidInputError
	if errors.As(err, &ie) {
		return http.StatusBadRequest
	}
	var pe *panel.Error
	if errors.As(err, &pe) {
		if pe.IsAuth() {
			return http.StatusUnauthorized
		}
		// The panel answers a wrong password with 400 and its own Chinese
		// reason. Passing that through as a 400 keeps the console honest - a
		// 502 would tell the user the panel is broken when in fact the input
		// was wrong - while a genuine upstream failure still maps to 502.
		if pe.Code == http.StatusBadRequest || pe.Code == http.StatusUnprocessableEntity {
			return http.StatusBadRequest
		}
		return http.StatusBadGateway
	}
	if strings.Contains(err.Error(), "context deadline exceeded") {
		return http.StatusGatewayTimeout
	}
	return http.StatusBadGateway
}

// writePanelErr maps panel failures onto HTTP statuses the console understands.
func writePanelErr(w http.ResponseWriter, err error) {
	status := panelErrStatus(err)
	if status == http.StatusGatewayTimeout {
		writeErr(w, status, fmt.Errorf("小白面板响应超时，请稍后重试"))
		return
	}
	// An expired or rejected session is the one failure the user can fix, so it
	// says what to do instead of only repeating the panel's own wording.
	var perr *panel.Error
	if errors.As(err, &perr) && perr.IsAuth() {
		writeErr(w, status, fmt.Errorf("登录已过期或被拒绝，请重新登录（面板原话：%s）", perr.Message))
		return
	}
	writeErr(w, status, err)
}
