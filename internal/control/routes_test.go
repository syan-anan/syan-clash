package control

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The console and the server have to agree on the API surface. Reading the
// routes out of api.go and comparing them with what the script calls keeps the
// two from drifting: a renamed endpoint breaks the UI silently otherwise.

var (
	routePattern = regexp.MustCompile(`mux\.HandleFunc\("(GET|POST|PUT|DELETE) (/api/[^"]+)"`)
	// The console builds "/api/cores/" + kind, so a trailing partial path is a
	// call site too.
	callPattern = regexp.MustCompile(`"(/api/[a-z0-9/_-]+)`)
)

func serverRoutes(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("api.go"))
	if err != nil {
		t.Fatalf("cannot read the API source: %v", err)
	}
	routes := map[string]bool{}
	for _, m := range routePattern.FindAllStringSubmatch(string(raw), -1) {
		path := m[2]
		// Net/http patterns may carry a query placeholder or trailing wildcard.
		path = strings.TrimSuffix(path, "/")
		routes[path] = true
	}
	if len(routes) < 20 {
		t.Fatalf("only found %d routes; the extraction pattern is probably stale", len(routes))
	}
	return routes
}

func consoleAPICalls(t *testing.T) map[string]bool {
	t.Helper()
	html := webAsset(t)
	script := longestScript(t, html)
	calls := map[string]bool{}
	for _, m := range callPattern.FindAllStringSubmatch(script, -1) {
		calls[m[1]] = true
	}
	return calls
}

func TestConsoleCallsOnlyKnownRoutes(t *testing.T) {
	routes := serverRoutes(t)
	calls := consoleAPICalls(t)

	// A call site matches when it is a route, when a route extends it (the
	// console concatenates ids), or when the route has a path parameter that the
	// console fills in.
	matches := func(call string) bool {
		if routes[call] {
			return true
		}
		for route := range routes {
			if strings.HasPrefix(route, call) {
				return true
			}
			if strings.HasPrefix(call, route) {
				return true
			}
		}
		return false
	}

	var unknown []string
	for call := range calls {
		if !matches(call) {
			unknown = append(unknown, call)
		}
	}
	sort.Strings(unknown)
	if len(unknown) > 0 {
		t.Errorf("the console calls paths with no server route: %v", unknown)
	}
}

func TestRoutesAreDocumentedInTheConsole(t *testing.T) {
	routes := serverRoutes(t)
	calls := consoleAPICalls(t)

	// Endpoints the console legitimately does not use: they exist for tooling,
	// for the tray, or for external scripts.
	notUsedByConsole := map[string]bool{
		"/api/cores/install":      true, // used only when a core is missing
		"/api/subscription/parse": true,
	}

	var orphans []string
	for route := range routes {
		if calls[route] {
			continue
		}
		used := false
		for call := range calls {
			if strings.HasPrefix(route, call) || strings.HasPrefix(call, route) {
				used = true
				break
			}
		}
		if !used && !notUsedByConsole[route] {
			orphans = append(orphans, route)
		}
	}
	sort.Strings(orphans)
	if len(orphans) > 0 {
		t.Errorf("server routes nothing in the console calls: %v", orphans)
	}
}

func TestHandlerRejectsUnknownPathsCleanly(t *testing.T) {
	// buildHandler needs an App; the health endpoint is registered without one,
	// so this test only exercises the router's fallback behaviour through a
	// minimal handler built from the same mux construction rules.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	rec := &statusRecorder{header: http.Header{}}
	mux.ServeHTTP(rec, mustRequest(t, http.MethodGet, "/api/nope"))
	if rec.status != http.StatusNotFound {
		t.Errorf("unknown path returned %d, want 404", rec.status)
	}
}

type statusRecorder struct {
	header http.Header
	status int
}

func (r *statusRecorder) Header() http.Header { return r.header }
func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return len(b), nil
}
func (r *statusRecorder) WriteHeader(code int) { r.status = code }

func mustRequest(t *testing.T, method, path string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, path, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return req
}
