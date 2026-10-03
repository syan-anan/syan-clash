// Package aisession stores the sign-in cookies captured from the embedded
// browser, so the diagnostics panel can ask the AI services as the signed-in
// user instead of as a stranger.
//
// The cookies live beside the configuration, in ai-session.json, and they are
// written by "syan-clash.exe -ai-login <service>": that opens the embedded
// browser on the service's sign-in page and reads the cookie jar back out
// through the DevTools protocol. Nothing in this package talks to the network -
// it only owns the file.
package aisession

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Cookie is one cookie as it was captured.
type Cookie struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Domain string `json:"domain,omitempty"`
	Path   string `json:"path,omitempty"`
}

// file is the on-disk shape of the store.
type file struct {
	SavedAt string              `json:"saved_at,omitempty"`
	Cookies map[string][]Cookie `json:"cookies"`
}

var (
	mu   sync.Mutex
	path string
)

// SetPath names the file the client reads and the capture writes. An empty path
// disables the store, which is what a test wants.
func SetPath(p string) {
	mu.Lock()
	path = p
	mu.Unlock()
}

// Path reports the file in use.
func Path() string {
	mu.Lock()
	defer mu.Unlock()
	return path
}

// DefaultPath is the store beside the configuration file.
func DefaultPath(cfgPath string) string {
	if cfgPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(cfgPath), "ai-session.json")
}

// Load reads the whole store. A missing or unreadable file is not an error: it
// means nobody has signed in yet, which is a normal state and not a failure.
func Load() map[string][]Cookie {
	p := Path()
	if p == "" {
		return nil
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var f file
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil
	}
	return f.Cookies
}

// Save writes the store atomically, so an interrupted capture can never leave a
// truncated file behind for the probes to read. The file is owner-only: it
// holds live session cookies.
func Save(cookies map[string][]Cookie) error {
	p := Path()
	if p == "" {
		return nil
	}
	payload, err := json.MarshalIndent(file{
		SavedAt: time.Now().Format(time.RFC3339),
		Cookies: cookies,
	}, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Cookies turns the stored cookies for one service into what net/http wants.
// A cookie with no domain is sent to the endpoint's own host, which is what the
// capture produces for host-only cookies.
func Cookies(service string) []*http.Cookie {
	stored := Load()[service]
	if len(stored) == 0 {
		return nil
	}
	out := make([]*http.Cookie, 0, len(stored))
	for _, c := range stored {
		if c.Name == "" {
			continue
		}
		hc := &http.Cookie{Name: c.Name, Value: c.Value, Path: c.Path}
		if hc.Path == "" {
			hc.Path = "/"
		}
		if d := strings.TrimPrefix(c.Domain, "."); d != "" {
			hc.Domain = d
		}
		out = append(out, hc)
	}
	return out
}
