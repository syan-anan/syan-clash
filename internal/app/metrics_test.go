//go:build windows

package app

import (
	"encoding/json"
	"os"
	"testing"
)

// TestStatusProcessMetrics asserts the six process counters the console reads
// are present in the JSON and, for the process running this test, populated.
func TestStatusProcessMetrics(t *testing.T) {
	a := newTestApp(t)
	st := a.Status()

	if st.ClientRSSBytes == 0 {
		t.Errorf("client_rss_bytes = 0, want > 0 for the running test process")
	}
	if st.ClientThreads < 1 {
		t.Errorf("client_threads = %d, want >= 1", st.ClientThreads)
	}
	if st.ClientHandles == 0 {
		t.Errorf("client_handles = 0, want > 0")
	}
	// No external core is running in a test app, so the core counters must be
	// zero rather than stale or missing.
	if st.CoreRSSBytes != 0 || st.CoreThreads != 0 || st.CoreHandles != 0 {
		t.Errorf("core metrics = (%d, %d, %d), want all zero without a running core",
			st.CoreRSSBytes, st.CoreThreads, st.CoreHandles)
	}

	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	for _, key := range []string{
		"client_rss_bytes", "client_threads", "client_handles",
		"core_rss_bytes", "core_threads", "core_handles",
	} {
		v, ok := decoded[key]
		if !ok {
			t.Errorf("status JSON is missing %q", key)
			continue
		}
		if _, isNum := v.(float64); !isNum {
			t.Errorf("status JSON %q = %#v, want a number", key, v)
		}
	}
}

// TestProcessMetricsByPID exercises the path used for the external core: a real
// PID opened through OpenProcess, not the current-process pseudo-handle.
func TestProcessMetricsByPID(t *testing.T) {
	got := processMetrics(os.Getpid())
	if got.RSSBytes == 0 || got.Threads < 1 || got.Handles == 0 {
		t.Errorf("processMetrics(self pid) = %+v, want every counter > 0", got)
	}
	if zero := processMetrics(0); zero != (procMetrics{}) {
		t.Errorf("processMetrics(0) = %+v, want zeroes", zero)
	}
}
