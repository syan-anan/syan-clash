package clashapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Mode and SetMode speak the /configs endpoint of the Clash-compatible API.
// The wire format is pinned here so a core-side change cannot slip through
// without the client noticing.
func TestModeRoundTrip(t *testing.T) {
	var patchBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/configs" {
			t.Errorf("unexpected path %s", r.URL.Path)
			return
		}
		switch r.Method {
		case http.MethodGet:
			_, _ = io.WriteString(w, `{"mode":"rule","port":7890}`)
		case http.MethodPatch:
			raw, _ := io.ReadAll(r.Body)
			patchBody = string(raw)
			_, _ = io.WriteString(w, "{}")
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	}))
	defer srv.Close()

	c := New(strings.TrimPrefix(srv.URL, "http://"), "")
	mode, err := c.Mode(context.Background())
	if err != nil || mode != "rule" {
		t.Fatalf("Mode() = %q, %v; want \"rule\", nil", mode, err)
	}
	if err := c.SetMode(context.Background(), "global"); err != nil {
		t.Fatalf("SetMode: %v", err)
	}
	var sent map[string]string
	if err := json.Unmarshal([]byte(patchBody), &sent); err != nil || sent["mode"] != "global" {
		t.Errorf("SetMode body = %s (err %v); want {\"mode\":\"global\"}", patchBody, err)
	}
}

// The rule-set report is what the console shows as "条目 / 更新". The payload
// below was captured from mihomo v1.19.31 answering GET /providers/rules, and
// it is wrapped in a "providers" object: the first version of this decoder
// assumed the map was the whole body, so a real core reported every set as
// "unknown" while the unit test - written against an invented payload - stayed
// green. The field names are pinned here for the same reason.
func TestRuleProvidersDecodesTheCoreReport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/providers/rules" {
			t.Errorf("unexpected path %s", r.URL.Path)
			return
		}
		_, _ = io.WriteString(w, `{"providers":{"ads":{"behavior":"Domain","format":"YamlRule","name":"ads","ruleCount":12345,"type":"Rule","vehicleType":"HTTP","updatedAt":"2026-10-03T11:32:56.5503834+08:00"}}}`)
	}))
	defer srv.Close()

	c := New(strings.TrimPrefix(srv.URL, "http://"), "")
	got, err := c.RuleProviders(context.Background())
	if err != nil {
		t.Fatalf("RuleProviders: %v", err)
	}
	ads, ok := got["ads"]
	if !ok {
		t.Fatalf("the ads set is missing from %+v", got)
	}
	if ads.RuleCount != 12345 {
		t.Errorf("RuleCount = %d, want 12345", ads.RuleCount)
	}
	if ads.Vehicle != "HTTP" {
		t.Errorf("Vehicle = %q, want HTTP", ads.Vehicle)
	}
	if ads.UpdatedAt == "" {
		t.Error("updatedAt was dropped")
	}
}

// The unwrapped shape still works: the wrapper is the core's business, and a
// decoder that only understands today's wrapper is one core release away from
// reporting every count as unknown again.
func TestRuleProvidersAcceptsAnUnwrappedReport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"ads":{"behavior":"domain","name":"ads","ruleCount":7,"type":"Rule","vehicleType":"HTTP"}}`)
	}))
	defer srv.Close()

	c := New(strings.TrimPrefix(srv.URL, "http://"), "")
	got, err := c.RuleProviders(context.Background())
	if err != nil {
		t.Fatalf("RuleProviders: %v", err)
	}
	if got["ads"].RuleCount != 7 {
		t.Errorf("RuleCount = %d, want 7 (report %+v)", got["ads"].RuleCount, got)
	}
}

// A core that knows no rule sets answers with an empty map, not an error: the
// console has to be able to render the list either way.
func TestRuleProvidersAcceptsAnEmptyReport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{}`)
	}))
	defer srv.Close()

	c := New(strings.TrimPrefix(srv.URL, "http://"), "")
	got, err := c.RuleProviders(context.Background())
	if err != nil {
		t.Fatalf("RuleProviders: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d entries from an empty report", len(got))
	}
}
