package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"vvpn/internal/config"
)

// ---------------------------------------------------------------------------
// URL parsing and name hygiene
// ---------------------------------------------------------------------------

func TestParseWebDAVURLNormalisesDirectory(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"https://dav.example.com/dav/syan-clash", "https://dav.example.com/dav/syan-clash/"},
		{"  https://dav.example.com/dav/syan-clash/  ", "https://dav.example.com/dav/syan-clash/"},
		{"https://dav.example.com/dav/syan-clash?x=1#frag", "https://dav.example.com/dav/syan-clash/"},
		{"http://192.168.1.9:8080/dav/", "http://192.168.1.9:8080/dav/"},
		{"https://dav.example.com", "https://dav.example.com/"},
	}
	for _, c := range cases {
		u, err := parseWebDAVURL(c.raw)
		if err != nil {
			t.Fatalf("parseWebDAVURL(%q): %v", c.raw, err)
		}
		if got := u.String(); got != c.want {
			t.Errorf("parseWebDAVURL(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
}

func TestParseWebDAVURLRejects(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want error
		text string
	}{
		{"empty is not configured", "   ", ErrWebDAVNotConfigured, ""},
		{"scheme must be http", "ftp://dav.example.com/x/", nil, "http:// 或 https://"},
		{"host is required", "https:///dav/", nil, "缺少主机名"},
		{"credentials belong in their own fields", "https://u:p@dav.example.com/dav/", nil, "不要包含用户名密码"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseWebDAVURL(c.raw)
			if err == nil {
				t.Fatalf("parseWebDAVURL(%q) returned no error", c.raw)
			}
			if c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			if c.text != "" && !strings.Contains(err.Error(), c.text) {
				t.Fatalf("err = %q, want it to mention %q", err.Error(), c.text)
			}
		})
	}
}

func TestValidateWebDAVURL(t *testing.T) {
	if err := ValidateWebDAVURL("https://dav.example.com/dav/"); err != nil {
		t.Errorf("valid address rejected: %v", err)
	}
	if err := ValidateWebDAVURL("dav.example.com/dav/"); err == nil {
		t.Error("an address with no scheme was accepted")
	}
}

func TestSafeWebDAVNameKeepsNamesInsideTheDirectory(t *testing.T) {
	good := []string{"syan-clash-backup-20261002-120000.zip", "a.zip"}
	for _, n := range good {
		got, err := safeWebDAVName(n)
		if err != nil {
			t.Errorf("safeWebDAVName(%q) = %v", n, err)
			continue
		}
		if got != n {
			t.Errorf("safeWebDAVName(%q) = %q, want it unchanged", n, got)
		}
	}
	bad := []string{"", "   ", ".", "..", "../etc/passwd", "sub/dir.zip", "..\\win.zip", "a/b"}
	for _, n := range bad {
		if _, err := safeWebDAVName(n); !errors.Is(err, ErrWebDAVBadName) {
			t.Errorf("safeWebDAVName(%q) err = %v, want ErrWebDAVBadName", n, err)
		}
	}
}

func TestWebDAVHrefName(t *testing.T) {
	cases := []struct {
		href string
		want string
	}{
		{"/dav/", ""},
		{"https://dav.example.com/dav/", ""},
		{"https://dav.example.com/dav/sub/", ""},
		{"/dav/backup.zip", "backup.zip"},
		{"https://dav.example.com/dav/syan-clash-backup-20261002-120000.zip", "syan-clash-backup-20261002-120000.zip"},
		{"/dav/a%20b.zip", "a b.zip"},
		{"", ""},
		{"   ", ""},
		{"/dav/..", ""},
		{"/dav/.", ""},
	}
	for _, c := range cases {
		if got := webdavHrefName(c.href); got != c.want {
			t.Errorf("webdavHrefName(%q) = %q, want %q", c.href, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// PROPFIND parsing
// ---------------------------------------------------------------------------

var propfindSample = strings.Join([]string{
	"<?xml version=\"1.0\" encoding=\"utf-8\"?>",
	"<d:multistatus xmlns:d=\"DAV:\">",
	"  <d:response><d:href>/dav/</d:href>",
	"    <d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop>",
	"      <d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>",
	"  <d:response><d:href>/dav/syan-clash-backup-20261002-120000.zip</d:href>",
	"    <d:propstat><d:prop>",
	"      <d:getcontentlength>4096</d:getcontentlength>",
	"      <d:getlastmodified>Mon, 02 Oct 2026 12:00:00 GMT</d:getlastmodified>",
	"      <d:resourcetype/>",
	"    </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>",
	"  <d:response><d:href>/dav/syan-clash-backup-20261001-080000.zip</d:href>",
	"    <d:propstat><d:prop>",
	"      <d:getcontentlength>1024</d:getcontentlength>",
	"      <d:resourcetype/>",
	"    </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>",
	"  <d:response><d:href>/dav/sub/</d:href>",
	"    <d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop>",
	"      <d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>",
	"</d:multistatus>",
}, "\n")

func TestParseWebDAVMultiStatusSkipsCollectionsAndSorts(t *testing.T) {
	files, err := parseWebDAVMultiStatus([]byte(propfindSample))
	if err != nil {
		t.Fatalf("parseWebDAVMultiStatus: %v", err)
	}
	names := make([]string, 0, len(files))
	for _, f := range files {
		names = append(names, f.Name)
	}
	want := "syan-clash-backup-20261001-080000.zip,syan-clash-backup-20261002-120000.zip"
	if got := strings.Join(names, ","); got != want {
		t.Fatalf("names = %q, want %q (collections skipped, order stable)", got, want)
	}
	if files[1].Size != 4096 {
		t.Errorf("size = %d, want 4096", files[1].Size)
	}
	if files[1].Modified != "2026-10-02T12:00:00Z" {
		t.Errorf("modified = %q, want it normalised to RFC3339", files[1].Modified)
	}
	if files[0].Modified != "" {
		t.Errorf("a response with no getlastmodified should leave Modified empty, got %q", files[0].Modified)
	}
}

func TestParseWebDAVMultiStatusRejectsGarbage(t *testing.T) {
	if _, err := parseWebDAVMultiStatus([]byte("not xml at all")); err == nil {
		t.Fatal("garbage was accepted as a multistatus document")
	}
}

func TestParseWebDAVMultiStatusToleratesOtherNamespacePrefixes(t *testing.T) {
	raw := strings.Join([]string{
		"<?xml version=\"1.0\"?>",
		"<multistatus xmlns=\"DAV:\">",
		"  <response><href>/dav/plain.zip</href><propstat><prop>",
		"    <getcontentlength>7</getcontentlength><resourcetype/>",
		"  </prop></propstat></response>",
		"</multistatus>",
	}, "\n")
	files, err := parseWebDAVMultiStatus([]byte(raw))
	if err != nil {
		t.Fatalf("parseWebDAVMultiStatus: %v", err)
	}
	if len(files) != 1 || files[0].Name != "plain.zip" || files[0].Size != 7 {
		t.Fatalf("files = %+v", files)
	}
}

// ---------------------------------------------------------------------------
// The transport must never inherit another program's proxy
// ---------------------------------------------------------------------------

func TestWebDAVTransportDoesNotInheritEnvironmentProxy(t *testing.T) {
	if webdavTransport.Proxy != nil {
		t.Fatal("webdavTransport.Proxy is set: a backup could be routed through HTTP_PROXY left behind by another client")
	}
	if webdavTransport.DialContext == nil {
		t.Fatal("webdavTransport has no DialContext, so no connect timeout")
	}
	if webdavTransport.TLSHandshakeTimeout <= 0 || webdavTransport.ResponseHeaderTimeout <= 0 {
		t.Fatal("webdavTransport is missing a phase timeout")
	}
}

// ---------------------------------------------------------------------------
// A fake WebDAV directory
// ---------------------------------------------------------------------------

type fakeDAV struct {
	mu        sync.Mutex
	user      string
	pass      string
	files     map[string][]byte
	authSeen  []string
	depthSeen []string
	putTypes  []string
}

func newFakeDAV(user, pass string) *fakeDAV {
	return &fakeDAV{user: user, pass: pass, files: map[string][]byte{}}
}

func (f *fakeDAV) add(name string, data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[name] = data
}

func (f *fakeDAV) has(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.files[name]
	return ok
}

func (f *fakeDAV) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.files)
}

func (f *fakeDAV) requests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.authSeen)
}

func (f *fakeDAV) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.authSeen = append(f.authSeen, r.Header.Get("Authorization"))
		f.mu.Unlock()

		if f.user != "" || f.pass != "" {
			u, p, ok := r.BasicAuth()
			if !ok || u != f.user || p != f.pass {
				w.Header().Set("WWW-Authenticate", "Basic realm=\"dav\"")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, "denied")
				return
			}
		}

		if r.Method == "PROPFIND" {
			f.mu.Lock()
			f.depthSeen = append(f.depthSeen, r.Header.Get("Depth"))
			names := make([]string, 0, len(f.files))
			sizes := map[string]int{}
			for n, b := range f.files {
				names = append(names, n)
				sizes[n] = len(b)
			}
			f.mu.Unlock()
			sort.Strings(names)

			var b strings.Builder
			b.WriteString("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n")
			b.WriteString("<d:multistatus xmlns:d=\"DAV:\">\n")
			b.WriteString("<d:response><d:href>/dav/</d:href><d:propstat><d:prop>" +
				"<d:resourcetype><d:collection/></d:resourcetype></d:prop>" +
				"<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>\n")
			for _, n := range names {
				fmt.Fprintf(&b, "<d:response><d:href>/dav/%s</d:href><d:propstat><d:prop>"+
					"<d:getcontentlength>%d</d:getcontentlength>"+
					"<d:getlastmodified>Mon, 02 Oct 2026 12:00:00 GMT</d:getlastmodified>"+
					"<d:resourcetype/></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>\n",
					n, sizes[n])
			}
			b.WriteString("</d:multistatus>\n")
			w.Header().Set("Content-Type", "application/xml; charset=utf-8")
			w.WriteHeader(http.StatusMultiStatus)
			_, _ = io.WriteString(w, b.String())
			return
		}

		name := strings.TrimPrefix(r.URL.Path, "/dav/")
		switch r.Method {
		case http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			f.mu.Lock()
			f.files[name] = body
			f.putTypes = append(f.putTypes, r.Header.Get("Content-Type"))
			f.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
		case http.MethodGet:
			f.mu.Lock()
			data, ok := f.files[name]
			f.mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = io.WriteString(w, "missing")
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(data)
		case http.MethodDelete:
			f.mu.Lock()
			_, ok := f.files[name]
			delete(f.files, name)
			f.mu.Unlock()
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

func clientFor(t *testing.T, rawURL, user, pass string) *webdavClient {
	t.Helper()
	c, err := newWebDAVClient(config.WebDAVSettings{URL: rawURL, Username: user, Password: pass})
	if err != nil {
		t.Fatalf("newWebDAVClient: %v", err)
	}
	return c
}

func TestWebDAVClientRoundTrip(t *testing.T) {
	dav := newFakeDAV("alice", "s3cret")
	srv := httptest.NewServer(dav.handler())
	defer srv.Close()

	c := clientFor(t, srv.URL+"/dav/", "alice", "s3cret")
	ctx := context.Background()

	payload := []byte("PK\x03\x04 pretend zip")
	if err := c.put(ctx, "syan-clash-backup-20261002-120000.zip", payload); err != nil {
		t.Fatalf("put: %v", err)
	}
	if !dav.has("syan-clash-backup-20261002-120000.zip") {
		t.Fatal("the upload did not land under the expected name")
	}
	dav.mu.Lock()
	gotType := ""
	if len(dav.putTypes) > 0 {
		gotType = dav.putTypes[0]
	}
	dav.mu.Unlock()
	if gotType != "application/zip" {
		t.Errorf("PUT Content-Type = %q, want application/zip", gotType)
	}

	back, err := c.get(ctx, "syan-clash-backup-20261002-120000.zip")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(back) != string(payload) {
		t.Fatalf("downloaded %q, want %q", back, payload)
	}

	files, err := c.list(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(files) != 1 || files[0].Name != "syan-clash-backup-20261002-120000.zip" || files[0].Size != int64(len(payload)) {
		t.Fatalf("list = %+v", files)
	}
	dav.mu.Lock()
	depths := append([]string(nil), dav.depthSeen...)
	dav.mu.Unlock()
	if len(depths) == 0 {
		t.Fatal("the server saw no PROPFIND")
	}
	for _, d := range depths {
		if d != "1" {
			t.Fatalf("PROPFIND Depth = %q, want 1", d)
		}
	}

	if err := c.delete(ctx, "syan-clash-backup-20261002-120000.zip"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if dav.count() != 0 {
		t.Fatal("the file is still there after delete")
	}

	dav.mu.Lock()
	auths := append([]string(nil), dav.authSeen...)
	dav.mu.Unlock()
	if len(auths) == 0 {
		t.Fatal("the server saw no requests at all")
	}
	for i, a := range auths {
		if !strings.HasPrefix(a, "Basic ") {
			t.Fatalf("request %d carried Authorization %q, want HTTP Basic", i, a)
		}
	}
}

func TestWebDAVClientRejectsBadStatusWithActionableText(t *testing.T) {
	cases := []struct {
		code int
		text string
	}{
		{http.StatusUnauthorized, "401 未授权"},
		{http.StatusForbidden, "403 被拒绝"},
		{http.StatusNotFound, "404 不存在"},
		{http.StatusConflict, "409 冲突"},
		{http.StatusInternalServerError, "500"},
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(c.code)
			_, _ = io.WriteString(w, "server says no")
		}))
		client := clientFor(t, srv.URL+"/dav/", "", "")
		err := client.put(context.Background(), "a.zip", []byte("x"))
		srv.Close()
		if err == nil {
			t.Fatalf("%d: put returned no error", c.code)
		}
		if !strings.Contains(err.Error(), c.text) {
			t.Errorf("%d: err = %q, want it to mention %q", c.code, err.Error(), c.text)
		}
	}
}

func TestWebDAVClientMasksStoredPasswordInErrors(t *testing.T) {
	const secret = "sup3r-s3cret-value"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "rejected for "+secret)
	}))
	defer srv.Close()

	c := clientFor(t, srv.URL+"/dav/", "alice", secret)
	err := c.put(context.Background(), "a.zip", []byte("x"))
	if err == nil {
		t.Fatal("put returned no error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("the stored password leaked into the error: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "***") {
		t.Fatalf("err = %q, want the password replaced by ***", err.Error())
	}
}

func TestWebDAVClientConnectionFailureIsWrapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	dead := srv.URL
	srv.Close()

	c := clientFor(t, dead+"/dav/", "", "")
	_, err := c.list(context.Background())
	if err == nil {
		t.Fatal("list returned no error for a dead server")
	}
	if !strings.Contains(err.Error(), "连接 WebDAV 失败") {
		t.Fatalf("err = %q, want the connect wrapper", err.Error())
	}
}

// ---------------------------------------------------------------------------
// App level: settings, masking, and a full upload/list/download/delete cycle
// ---------------------------------------------------------------------------

func TestWebDAVConfigViewNeverEchoesThePassword(t *testing.T) {
	a := newTestApp(t)
	if err := a.SetWebDAVSettings(config.WebDAVSettings{
		URL:      "https://dav.example.com/dav/",
		Username: "alice",
		Password: "s3cret",
		Enabled:  true,
	}, false); err != nil {
		t.Fatalf("SetWebDAVSettings: %v", err)
	}
	v := a.WebDAVConfigView()
	if v.Password == "s3cret" {
		t.Fatal("the view echoed the stored password")
	}
	if !v.HasPassword {
		t.Fatal("has_password is false although a password is stored")
	}
	if v.Password != webdavMask {
		t.Errorf("password = %q, want the mask", v.Password)
	}
	if !v.Enabled || v.URL != "https://dav.example.com/dav/" || v.Username != "alice" {
		t.Errorf("view = %+v", v)
	}
}

func TestSetWebDAVSettingsKeepsTheStoredPasswordWhenBlank(t *testing.T) {
	a := newTestApp(t)
	if err := a.SetWebDAVSettings(config.WebDAVSettings{URL: "https://dav.example.com/dav/", Username: "alice", Password: "s3cret"}, false); err != nil {
		t.Fatalf("first save: %v", err)
	}
	if err := a.SetWebDAVSettings(config.WebDAVSettings{URL: "https://dav.example.com/dav/", Username: "alice"}, true); err != nil {
		t.Fatalf("second save: %v", err)
	}
	if got := a.Config().WebDAV.Password; got != "s3cret" {
		t.Fatalf("password = %q, want it kept", got)
	}
	if err := a.SetWebDAVSettings(config.WebDAVSettings{URL: "https://dav.example.com/dav/", Username: "alice", Password: "new-one"}, false); err != nil {
		t.Fatalf("third save: %v", err)
	}
	if got := a.Config().WebDAV.Password; got != "new-one" {
		t.Fatalf("password = %q, want it replaced", got)
	}
}

func TestWebDAVSettingsArePersisted(t *testing.T) {
	a := newTestApp(t)
	if err := a.SetWebDAVSettings(config.WebDAVSettings{URL: "https://dav.example.com/dav/", Username: "alice", Password: "s3cret", Enabled: true}, false); err != nil {
		t.Fatalf("SetWebDAVSettings: %v", err)
	}
	reloaded, err := config.Load(a.ConfigPath())
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if reloaded.WebDAV.URL != "https://dav.example.com/dav/" || reloaded.WebDAV.Username != "alice" || reloaded.WebDAV.Password != "s3cret" || !reloaded.WebDAV.Enabled {
		t.Fatalf("reloaded = %+v", reloaded.WebDAV)
	}
}

func TestWebDAVNotConfiguredIsReported(t *testing.T) {
	a := newTestApp(t)
	if _, err := a.WebDAVList(context.Background()); !errors.Is(err, ErrWebDAVNotConfigured) {
		t.Fatalf("list err = %v, want ErrWebDAVNotConfigured", err)
	}
	if _, err := a.WebDAVUpload(context.Background()); !errors.Is(err, ErrWebDAVNotConfigured) {
		t.Fatalf("upload err = %v, want ErrWebDAVNotConfigured", err)
	}
	if _, err := a.WebDAVDownload(context.Background(), "a.zip"); !errors.Is(err, ErrWebDAVNotConfigured) {
		t.Fatalf("download err = %v, want ErrWebDAVNotConfigured", err)
	}
	if err := a.WebDAVDelete(context.Background(), "a.zip"); !errors.Is(err, ErrWebDAVNotConfigured) {
		t.Fatalf("delete err = %v, want ErrWebDAVNotConfigured", err)
	}
}

func TestWebDAVBadNameIsRejectedBeforeAnyRequest(t *testing.T) {
	dav := newFakeDAV("", "")
	srv := httptest.NewServer(dav.handler())
	defer srv.Close()

	a := newTestApp(t)
	if err := a.SetWebDAVSettings(config.WebDAVSettings{URL: srv.URL + "/dav/"}, false); err != nil {
		t.Fatalf("SetWebDAVSettings: %v", err)
	}
	for _, bad := range []string{"", "../escape.zip", "sub/dir.zip"} {
		if _, err := a.WebDAVDownload(context.Background(), bad); !errors.Is(err, ErrWebDAVBadName) {
			t.Errorf("download(%q) err = %v, want ErrWebDAVBadName", bad, err)
		}
		if err := a.WebDAVDelete(context.Background(), bad); !errors.Is(err, ErrWebDAVBadName) {
			t.Errorf("delete(%q) err = %v, want ErrWebDAVBadName", bad, err)
		}
	}
	if n := dav.requests(); n != 0 {
		t.Fatalf("a rejected name still reached the server (%d requests)", n)
	}
}

func TestWebDAVBackupRoundTripThroughTheApp(t *testing.T) {
	dav := newFakeDAV("alice", "s3cret")
	srv := httptest.NewServer(dav.handler())
	defer srv.Close()

	a := newTestApp(t)
	if err := a.SetWebDAVSettings(config.WebDAVSettings{URL: srv.URL + "/dav/", Username: "alice", Password: "s3cret", Enabled: true}, false); err != nil {
		t.Fatalf("SetWebDAVSettings: %v", err)
	}
	ctx := context.Background()

	up, err := a.WebDAVUpload(ctx)
	if err != nil {
		t.Fatalf("WebDAVUpload: %v", err)
	}
	if up.Name == "" || up.Size <= 0 {
		t.Fatalf("uploaded file = %+v", up)
	}
	if !strings.HasPrefix(up.Name, "syan-clash-backup-") || !strings.HasSuffix(up.Name, ".zip") {
		t.Errorf("backup name = %q, want the syan-clash-backup-<timestamp>.zip shape", up.Name)
	}

	files, err := a.WebDAVList(ctx)
	if err != nil {
		t.Fatalf("WebDAVList: %v", err)
	}
	if len(files) != 1 || files[0].Name != up.Name {
		t.Fatalf("list = %+v, want just %q", files, up.Name)
	}

	raw, err := a.WebDAVDownload(ctx, up.Name)
	if err != nil {
		t.Fatalf("WebDAVDownload: %v", err)
	}
	if int64(len(raw)) != up.Size {
		t.Fatalf("downloaded %d bytes, uploaded %d", len(raw), up.Size)
	}
	if len(raw) < 2 || string(raw[:2]) != "PK" {
		t.Fatalf("the downloaded archive does not look like a zip")
	}

	if err := a.WebDAVDelete(ctx, up.Name); err != nil {
		t.Fatalf("WebDAVDelete: %v", err)
	}
	if dav.count() != 0 {
		t.Fatal("the backup is still on the server after delete")
	}
	if err := a.WebDAVDelete(ctx, up.Name); err == nil {
		t.Fatal("deleting a file that is gone returned no error")
	}
}
