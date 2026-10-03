package control

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"vvpn/internal/app"
	"vvpn/internal/config"
	"vvpn/internal/core"
)

// ---------------------------------------------------------------------------
// Status mapping
// ---------------------------------------------------------------------------

// webdavStatus decides whether a failure is the user's typo or the server's
// problem. Getting this backwards sends the user hunting for a server that is
// fine (or editing an address that is fine), which is why it is pinned here.
func TestWebDAVStatusMapping(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"no address yet is a request problem", app.ErrWebDAVNotConfigured, http.StatusBadRequest},
		{"a traversal name is a request problem", app.ErrWebDAVBadName, http.StatusBadRequest},
		{"a wrapped bad name still maps to 400", fmtWrap(app.ErrWebDAVBadName), http.StatusBadRequest},
		{"a remote failure is a gateway problem", errString("WebDAV 上传失败（500）"), http.StatusBadGateway},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := webdavStatus(c.err); got != c.want {
				t.Fatalf("webdavStatus(%v) = %d, want %d", c.err, got, c.want)
			}
		})
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func fmtWrap(err error) error { return wrapErr{err} }

type wrapErr struct{ err error }

func (w wrapErr) Error() string { return "outer: " + w.err.Error() }
func (w wrapErr) Unwrap() error { return w.err }

// ---------------------------------------------------------------------------
// A tiny WebDAV server for the handler tests
// ---------------------------------------------------------------------------

type davStub struct {
	mu    sync.Mutex
	files map[string][]byte
	fail  int
	puts  []string
}

func newDAVStub() *davStub { return &davStub{files: map[string][]byte{}} }

func (d *davStub) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.fail != 0 {
			w.WriteHeader(d.fail)
			_, _ = io.WriteString(w, "stub failure")
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/dav/")
		switch r.Method {
		case "PROPFIND":
			w.Header().Set("Content-Type", "application/xml; charset=utf-8")
			w.WriteHeader(http.StatusMultiStatus)
			_, _ = io.WriteString(w,
				"<?xml version=\"1.0\" encoding=\"utf-8\"?>"+
					"<d:multistatus xmlns:d=\"DAV:\"></d:multistatus>")
		case http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			d.mu.Lock()
			d.files[name] = body
			d.puts = append(d.puts, name)
			d.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
		case http.MethodGet:
			d.mu.Lock()
			data, ok := d.files[name]
			d.mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(data)
		case http.MethodDelete:
			d.mu.Lock()
			_, ok := d.files[name]
			delete(d.files, name)
			d.mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

func controlFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

// newControlApp builds a real App on a temporary configuration so the handlers
// can be exercised over their real HTTP shape. The built-in engine runs; no
// external core is involved.
func newControlApp(t *testing.T) *app.App {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	cfg := config.Default()
	cfg.Core.ID = ""
	cfg.Core.AutoStart = false
	cfg.Inbound.SOCKS5Addr = "127.0.0.1:" + strconv.Itoa(controlFreePort(t))
	cfg.Inbound.HTTPAddr = "127.0.0.1:" + strconv.Itoa(controlFreePort(t))
	cfg.Core.Port = controlFreePort(t)
	profile := core.DefaultProfile()
	profile.Inbounds = []core.Inbound{{Type: core.InboundMixed, Tag: "mixed-in", Listen: "127.0.0.1", Port: controlFreePort(t)}}
	cfg.Core.Profile = &profile
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatalf("save test config: %v", err)
	}
	a, err := app.New(cfgPath, "test")
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	t.Cleanup(a.Stop)
	return a
}

func postJSON(t *testing.T, h http.HandlerFunc, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not JSON (%s): %v", rec.Body.String(), err)
	}
	return out
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func TestWebDAVConfigSetRejectsAnUnusableAddress(t *testing.T) {
	api := New(newControlApp(t))
	for _, bad := range []string{
		"{\"url\":\"dav.example.com/dav/\"}",
		"{\"url\":\"ftp://dav.example.com/dav/\"}",
		"{\"url\":\"https://u:p@dav.example.com/dav/\"}",
		"{\"url\":\"https:///dav/\"}",
	} {
		rec := postJSON(t, api.handleWebDAVConfigSet, bad)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %s -> %d, want 400", bad, rec.Code)
		}
	}
}

func TestWebDAVConfigSetRejectsBadJSON(t *testing.T) {
	api := New(newControlApp(t))
	rec := postJSON(t, api.handleWebDAVConfigSet, "{not json")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", rec.Code)
	}
}

func TestWebDAVGetAndConfigNeverEchoThePassword(t *testing.T) {
	// The target answers 500 so the listing fails fast and deterministically;
	// what is under test is the shape of the two documents, not the listing.
	stub := newDAVStub()
	stub.fail = http.StatusInternalServerError
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	a := newControlApp(t)
	api := New(a)

	rec := postJSON(t, api.handleWebDAVConfigSet,
		"{\"url\":\""+srv.URL+"/dav/\",\"username\":\"alice\",\"password\":\"s3cret\",\"enabled\":true}")
	if rec.Code != http.StatusOK {
		t.Fatalf("config set code = %d, body %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "s3cret") {
		t.Fatalf("the config response echoed the password: %s", rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body["has_password"] != true {
		t.Fatalf("has_password = %v, want true", body["has_password"])
	}

	// The GET path talks to the real target, which does not exist here; the
	// settings must still come back, with the listing error reported inside
	// the document rather than failing the read.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	getRec := httptest.NewRecorder()
	api.handleWebDAVGet(getRec, req)
	if getRec.Code != http.StatusOK {
		t.Fatalf("get code = %d, want 200 even when the listing fails", getRec.Code)
	}
	if strings.Contains(getRec.Body.String(), "s3cret") {
		t.Fatalf("the GET response echoed the password: %s", getRec.Body.String())
	}
	got := decodeBody(t, getRec)
	if got["has_password"] != true || got["url"] != srv.URL+"/dav/" {
		t.Fatalf("get body = %v", got)
	}
	if got["error"] == nil || got["error"] == "" {
		t.Fatalf("a failed listing should be reported in the document, body = %v", got)
	}
}

func TestWebDAVConfigSetKeepsTheStoredPasswordWhenBlank(t *testing.T) {
	a := newControlApp(t)
	api := New(a)

	if rec := postJSON(t, api.handleWebDAVConfigSet,
		"{\"url\":\"https://dav.example.com/dav/\",\"username\":\"alice\",\"password\":\"s3cret\"}"); rec.Code != http.StatusOK {
		t.Fatalf("first save code = %d", rec.Code)
	}
	// Editing only the address must not wipe the secret.
	if rec := postJSON(t, api.handleWebDAVConfigSet,
		"{\"url\":\"https://dav.example.com/other/\",\"username\":\"alice\"}"); rec.Code != http.StatusOK {
		t.Fatalf("second save code = %d, body %s", rec.Code, rec.Body.String())
	}
	if got := a.Config().WebDAV.Password; got != "s3cret" {
		t.Fatalf("password = %q, want it kept", got)
	}
	if got := a.Config().WebDAV.URL; got != "https://dav.example.com/other/" {
		t.Fatalf("url = %q, want the new address", got)
	}
}

func TestWebDAVConfigSetLeavesTheSwitchAloneWhenAbsent(t *testing.T) {
	a := newControlApp(t)
	api := New(a)

	if rec := postJSON(t, api.handleWebDAVConfigSet,
		"{\"url\":\"https://dav.example.com/dav/\",\"enabled\":true}"); rec.Code != http.StatusOK {
		t.Fatalf("first save code = %d", rec.Code)
	}
	if rec := postJSON(t, api.handleWebDAVConfigSet,
		"{\"url\":\"https://dav.example.com/dav/\"}"); rec.Code != http.StatusOK {
		t.Fatalf("second save code = %d", rec.Code)
	}
	if !a.Config().WebDAV.Enabled {
		t.Fatal("the switch was cleared by a body that never mentioned it")
	}
}

func TestWebDAVHandlersRoundTripAgainstAStubServer(t *testing.T) {
	stub := newDAVStub()
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	a := newControlApp(t)
	api := New(a)
	if rec := postJSON(t, api.handleWebDAVConfigSet,
		"{\"url\":\""+srv.URL+"/dav/\",\"enabled\":true}"); rec.Code != http.StatusOK {
		t.Fatalf("config set code = %d, body %s", rec.Code, rec.Body.String())
	}

	upRec := postJSON(t, api.handleWebDAVUpload, "")
	if upRec.Code != http.StatusOK {
		t.Fatalf("upload code = %d, body %s", upRec.Code, upRec.Body.String())
	}
	up := decodeBody(t, upRec)
	name, _ := up["name"].(string)
	if name == "" {
		t.Fatalf("upload body = %v", up)
	}

	downRec := postJSON(t, api.handleWebDAVDownload, "{\"name\":\""+name+"\"}")
	if downRec.Code != http.StatusOK {
		t.Fatalf("download code = %d, body %s", downRec.Code, downRec.Body.String())
	}
	applied := decodeBody(t, downRec)
	if applied["ok"] == false {
		t.Fatalf("download body = %v", applied)
	}

	delReq := httptest.NewRequest(http.MethodDelete, "/", bytes.NewBufferString("{\"name\":\""+name+"\"}"))
	delRec := httptest.NewRecorder()
	api.handleWebDAVDelete(delRec, delReq)
	if delRec.Code != http.StatusOK {
		t.Fatalf("delete code = %d, body %s", delRec.Code, delRec.Body.String())
	}
	stub.mu.Lock()
	left := len(stub.files)
	stub.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d files left on the server", left)
	}
}

func TestWebDAVDownloadRejectsTraversalBeforeTalkingToTheServer(t *testing.T) {
	stub := newDAVStub()
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	a := newControlApp(t)
	api := New(a)
	if rec := postJSON(t, api.handleWebDAVConfigSet,
		"{\"url\":\""+srv.URL+"/dav/\"}"); rec.Code != http.StatusOK {
		t.Fatalf("config set code = %d", rec.Code)
	}
	for _, body := range []string{
		"{\"name\":\"\"}",
		"{\"name\":\"../../etc/passwd\"}",
		"{\"name\":\"sub/dir.zip\"}",
	} {
		rec := postJSON(t, api.handleWebDAVDownload, body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %s -> %d, want 400", body, rec.Code)
		}
		delReq := httptest.NewRequest(http.MethodDelete, "/", bytes.NewBufferString(body))
		delRec := httptest.NewRecorder()
		api.handleWebDAVDelete(delRec, delReq)
		if delRec.Code != http.StatusBadRequest {
			t.Errorf("delete body %s -> %d, want 400", body, delRec.Code)
		}
	}
}

func TestWebDAVUploadMapsARemoteFailureTo502(t *testing.T) {
	stub := newDAVStub()
	stub.fail = http.StatusInternalServerError
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	a := newControlApp(t)
	api := New(a)
	if rec := postJSON(t, api.handleWebDAVConfigSet,
		"{\"url\":\""+srv.URL+"/dav/\"}"); rec.Code != http.StatusOK {
		t.Fatalf("config set code = %d", rec.Code)
	}
	rec := postJSON(t, api.handleWebDAVUpload, "")
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("upload code = %d, want 502, body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "500") {
		t.Fatalf("the response should carry the upstream status, body %s", rec.Body.String())
	}
}

func TestWebDAVHandlersWithoutATargetAre400(t *testing.T) {
	api := New(newControlApp(t))
	if rec := postJSON(t, api.handleWebDAVUpload, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("upload code = %d, want 400", rec.Code)
	}
	if rec := postJSON(t, api.handleWebDAVDownload, "{\"name\":\"a.zip\"}"); rec.Code != http.StatusBadRequest {
		t.Fatalf("download code = %d, want 400", rec.Code)
	}
}
