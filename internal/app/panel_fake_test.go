package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"vvpn/internal/panel"
)

// fakePanel serves the slice of the vendor API the app layer talks to: the
// public config, the login endpoint, user info and the announcement list. The
// shapes match the captured fixtures in internal/panel/panel_test.go.
func fakePanel(t *testing.T) *httptest.Server {
	t.Helper()
	const token = "tok-test"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/guest/comm/config":
			_, _ = w.Write([]byte(`{"status":"success","data":{"app_url":"https://example.test","app_description":"欢迎","is_captcha":0},"error":null}`))
		case "/passport/auth/login":
			_, _ = w.Write([]byte(`{"status":"success","data":{"token":"` + token + `","is_admin":false},"error":null}`))
		case "/user/info":
			if r.Header.Get("Authorization") != "Bearer "+token {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"status":"fail","message":"Unauthenticated.","data":null}`))
				return
			}
			_, _ = w.Write([]byte(`{"status":"success","data":{"email":"user@example.test","transfer_enable":1024,"balance":100},"error":null}`))
		case "/user/notice/fetch":
			if r.Header.Get("Authorization") != "Bearer "+token {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"status":"fail","message":"Unauthenticated.","data":null}`))
				return
			}
			_, _ = w.Write([]byte(`{"status":"success","data":{"data":[{"id":1,"title":"线路维护","content":"今晚 2 点","created_at":1790000000}],"total":1,"current_page":1},"error":null}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestPanelSetBaseProbesAndPersists(t *testing.T) {
	a := newTestApp(t)
	srv := fakePanel(t)

	// Pretend an old session exists; switching hosts must clear it because a
	// token is only valid on the deployment that issued it.
	a.mu.Lock()
	a.panelSess = PanelSession{BaseURL: "https://old.example.test", Email: "old@example.test", Token: "old-token"}
	a.mu.Unlock()

	cfg, err := a.PanelSetBase(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("PanelSetBase: %v", err)
	}
	if cfg.AppURL != "https://example.test" || cfg.AppDescription != "欢迎" {
		t.Fatalf("probe result not returned: %+v", cfg)
	}
	st := a.PanelState()
	if st.LoggedIn || st.BaseURL != srv.URL {
		t.Fatalf("state after set base: %+v", st)
	}
	raw, err := os.ReadFile(a.panelPath())
	if err != nil {
		t.Fatalf("panel.json: %v", err)
	}
	if !strings.Contains(string(raw), srv.URL) {
		t.Fatalf("panel.json does not persist the new base: %s", raw)
	}
}

func TestPanelSetBaseRejectsInvalidInput(t *testing.T) {
	a := newTestApp(t)
	for _, raw := range []string{"", "   ", "not a url", "ftp://host"} {
		_, err := a.PanelSetBase(context.Background(), raw)
		var ie *panel.InvalidInputError
		if !errors.As(err, &ie) {
			t.Fatalf("PanelSetBase(%q) error = %v, want InvalidInputError", raw, err)
		}
	}
}

func TestPanelLoginRequiresCredentials(t *testing.T) {
	a := newTestApp(t)
	_, err := a.PanelLogin(context.Background(), "", "", false)
	var ie *panel.InvalidInputError
	if !errors.As(err, &ie) {
		t.Fatalf("PanelLogin empty credentials error = %v, want InvalidInputError", err)
	}
}

func TestPanelLoginAndNoticesAgainstFakePanel(t *testing.T) {
	a := newTestApp(t)
	srv := fakePanel(t)
	if _, err := a.PanelSetBase(context.Background(), srv.URL); err != nil {
		t.Fatalf("PanelSetBase: %v", err)
	}
	info, err := a.PanelLogin(context.Background(), "user@example.test", "pw", false)
	if err != nil {
		t.Fatalf("PanelLogin: %v", err)
	}
	if info.Email != "user@example.test" {
		t.Fatalf("user info: %+v", info)
	}
	if !a.PanelState().LoggedIn {
		t.Fatal("state should report a logged-in session")
	}
	notices, err := a.PanelNotices(context.Background())
	if err != nil {
		t.Fatalf("PanelNotices: %v", err)
	}
	if len(notices) != 1 || notices[0].Title != "线路维护" || notices[0].CreatedAt != 1790000000 {
		t.Fatalf("notices: %+v", notices)
	}
}
