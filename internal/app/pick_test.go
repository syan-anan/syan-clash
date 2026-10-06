package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"vvpn/internal/clashapi"
)

// newFakeCore points a client at a stand-in control API.
func newFakeCore(t *testing.T, h http.HandlerFunc) *clashapi.Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return clashapi.New(strings.TrimPrefix(srv.URL, "http://"), "")
}

// "全部测速" reports the group; it does not move the selection. The core answers
// a whole group in one request, so this also pins that the sweep does not fall
// back to asking for the members one at a time when the core can do the work.
func TestMeasureMembersUsesTheGroupCallAndNeverSwitches(t *testing.T) {
	var groupCalls, memberCalls, puts int32
	client := newFakeCore(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/group/PROXY/delay":
			atomic.AddInt32(&groupCalls, 1)
			_ = json.NewEncoder(w).Encode(map[string]int{"a": 120, "b": 40, "DIRECT": 5, "dead": 0})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/proxies/"):
			atomic.AddInt32(&memberCalls, 1)
			_, _ = w.Write([]byte(`{"delay":1}`))
		case r.Method == http.MethodPut:
			atomic.AddInt32(&puts, 1)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})

	table := map[string]clashapi.Proxy{
		"PROXY": {Name: "PROXY", Type: "Selector", Now: "a", All: []string{"a", "b", "DIRECT", "dead"}},
	}
	res := measureMembers(context.Background(), client, table, table["PROXY"], "PROXY", "", 5000)

	if groupCalls != 1 {
		t.Errorf("the group endpoint was called %d times, want 1", groupCalls)
	}
	if memberCalls != 0 {
		t.Errorf("the sweep asked for %d members one by one despite the group endpoint", memberCalls)
	}
	if puts != 0 {
		t.Errorf("a measurement switched the group %d times", puts)
	}
	if res.Delays["a"] != 120 || res.Delays["b"] != 40 {
		t.Errorf("delays = %v, want a:120 b:40", res.Delays)
	}
	if len(res.Failed) != 1 || res.Failed[0] != "dead" {
		t.Errorf("failed = %v, want [dead]", res.Failed)
	}
}

// A core that predates /group/{name}/delay answers 404. The sweep still has to
// come back with numbers, so it walks the members instead.
func TestMeasureMembersFallsBackToThePerMemberWalk(t *testing.T) {
	var groupCalls, memberCalls int32
	client := newFakeCore(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/group/PROXY/delay":
			atomic.AddInt32(&groupCalls, 1)
			http.NotFound(w, r)
		case strings.HasPrefix(r.URL.Path, "/proxies/"):
			atomic.AddInt32(&memberCalls, 1)
			_, _ = w.Write([]byte(`{"delay":77}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})

	table := map[string]clashapi.Proxy{
		"PROXY": {Name: "PROXY", Type: "Selector", Now: "a", All: []string{"a", "b"}},
	}
	res := measureMembers(context.Background(), client, table, table["PROXY"], "PROXY", "", 5000)

	if groupCalls != 1 || memberCalls != 2 {
		t.Errorf("group calls = %d, member calls = %d; want 1 and 2", groupCalls, memberCalls)
	}
	if res.Delays["a"] != 77 || res.Delays["b"] != 77 {
		t.Errorf("delays = %v, want a:77 b:77", res.Delays)
	}
}

// DIRECT and REJECT sit in GLOBAL on every profile. Picking one does not move
// the traffic to a faster server - DIRECT turns the proxy off - so the fastest
// real node wins even when the built-in outbound measures lower.
func TestBestMemberSkipsTheBuiltinOutbounds(t *testing.T) {
	all := []string{"DIRECT", "REJECT", "香港 01", "日本 02"}
	delays := map[string]int{"DIRECT": 3, "REJECT": 4, "香港 01": 180, "日本 02": 90}
	if got := bestMember(all, delays); got != "日本 02" {
		t.Errorf("bestMember = %q, want 日本 02", got)
	}
	if got := bestMember(all, map[string]int{"DIRECT": 3, "REJECT": 4}); got != "" {
		t.Errorf("bestMember = %q, want empty when only the built-in outbounds answered", got)
	}
	if got := bestMember(all, nil); got != "" {
		t.Errorf("bestMember = %q, want empty when nothing was measured", got)
	}
	if got := bestMember([]string{"香港 01"}, map[string]int{"香港 01": 0}); got != "" {
		t.Errorf("bestMember = %q, want empty when the only member timed out", got)
	}
}
