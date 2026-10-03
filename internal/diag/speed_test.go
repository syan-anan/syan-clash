package diag

import (
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"vvpn/internal/config"
)

// These tests drive both backends against local httptest servers, so they run
// with no internet access and no kernel. The prober dials them directly
// (ViaDirect), which also keeps the tests independent of any running client.

func newSpeedProber(t *testing.T) *Prober {
	t.Helper()
	return New(Options{
		TimeoutMS:   func() int { return 3000 },
		Concurrency: func() int { return 4 },
	})
}

var speedTestZeroChunk = make([]byte, 64<<10)

// streamTestZeros writes n bytes as fast as the test client reads them. The
// content is irrelevant, only the volume matters for a rate measurement.
func streamTestZeros(w io.Writer, n int64) {
	for n > 0 {
		step := int64(len(speedTestZeroChunk))
		if step > n {
			step = n
		}
		if _, err := w.Write(speedTestZeroChunk[:step]); err != nil {
			return
		}
		n -= step
	}
}

// fakeCloudflareServer speaks the parts of the speed.cloudflare.com protocol
// the job uses: GET /__down?bytes=N streams N bytes, POST /__up consumes the
// body.
func fakeCloudflareServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/__down":
			n, _ := strconv.ParseInt(r.URL.Query().Get("bytes"), 10, 64)
			if n <= 0 {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			streamTestZeros(w, n)
		case "/__up":
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
}

// fakeSlowCloudflareServer answers the latency probe immediately but parks
// every bulk download request after 64KB, holding the connection open so the
// client is mid-read when the test cancels.
func fakeSlowCloudflareServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/__down":
			n, _ := strconv.ParseInt(r.URL.Query().Get("bytes"), 10, 64)
			if n <= 0 {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusOK)
			streamTestZeros(w, 64<<10)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		case "/__up":
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
}

// fakeLibreSpeedServer speaks the LibreSpeed backend: empty.php for latency
// and uploads, garbage.php for downloads, getIP.php for the exit address.
func fakeLibreSpeedServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/backend/empty.php":
			if r.Method == http.MethodPost {
				_, _ = io.Copy(io.Discard, r.Body)
			}
			w.WriteHeader(http.StatusOK)
		case "/backend/garbage.php":
			mb, _ := strconv.ParseInt(r.URL.Query().Get("ckSize"), 10, 64)
			if mb < 1 {
				mb = 1
			}
			w.WriteHeader(http.StatusOK)
			streamTestZeros(w, mb<<20)
		case "/backend/getIP.php":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"processedString":"198.51.100.7 - Test ISP","rawIspInfo":false}`))
		default:
			http.NotFound(w, r)
		}
	}))
}

func waitSpeedJob(t *testing.T, job *Job, timeout time.Duration) map[string]any {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		st := job.Status()
		if st["state"] != JobRunning {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("job %s did not finish within %s", job.ID, timeout)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func waitSpeedPhase(t *testing.T, job *Job, phase string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		st := job.Status()
		if st["phase"] == phase {
			return
		}
		if st["state"] != JobRunning {
			t.Fatalf("job ended (state=%v) before reaching phase %q", st["state"], phase)
		}
		if time.Now().After(deadline) {
			t.Fatalf("phase %q was not reached within %s", phase, timeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func waitSpeedBytes(t *testing.T, job *Job, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		st := job.Status()
		if speedNum(st["bytes_down"]) > 0 {
			return
		}
		if st["state"] != JobRunning {
			t.Fatalf("job ended before any download bytes arrived (state=%v)", st["state"])
		}
		if time.Now().After(deadline) {
			t.Fatal("no download bytes arrived in time")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// speedNum reads a numeric snapshot value; the snapshot travels through JSON,
// so whole numbers arrive as float64.
func speedNum(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int64:
		return float64(x)
	case int:
		return float64(x)
	}
	return 0
}

// TestSpeedMedianAndJitter pins the reduction used for the latency phase: a
// known RTT sequence must produce the exact median and adjacent-difference
// mean.
func TestSpeedMedianAndJitter(t *testing.T) {
	seq := []time.Duration{
		10 * time.Millisecond,
		12 * time.Millisecond,
		11 * time.Millisecond,
		13 * time.Millisecond,
		50 * time.Millisecond,
	}
	if got := medianMS(seq); math.Abs(got-12) > 0.001 {
		t.Errorf("medianMS = %v, want 12", got)
	}
	// mean(|12-10|,|11-12|,|13-11|,|50-13|) = (2+1+2+37)/4 = 10.5
	if got := jitterMS(seq); math.Abs(got-10.5) > 0.001 {
		t.Errorf("jitterMS = %v, want 10.5", got)
	}
	if got := medianMS([]time.Duration{10 * time.Millisecond, 20 * time.Millisecond}); math.Abs(got-15) > 0.001 {
		t.Errorf("medianMS even count = %v, want 15", got)
	}
	if got := jitterMS([]time.Duration{5 * time.Millisecond}); got != 0 {
		t.Errorf("jitterMS single sample = %v, want 0", got)
	}
}

// TestSpeedtestCloudflare runs a full job against the fake Cloudflare backend
// and checks the contract: a done state, positive rates and bytes in both
// directions, at least one curve sample, and every snapshot key present.
func TestSpeedtestCloudflare(t *testing.T) {
	srv := fakeCloudflareServer(t)
	defer srv.Close()
	p := newSpeedProber(t)

	job, err := p.StartSpeedtest(ViaDirect, config.SpeedtestServer{Name: "FakeCF", Kind: "cloudflare", Base: srv.URL}, 1, 2, 30)
	if err != nil {
		t.Fatalf("StartSpeedtest: %v", err)
	}
	st := waitSpeedJob(t, job, 30*time.Second)
	if st["state"] != JobDone {
		t.Fatalf("state = %v, error = %v", st["state"], st["error"])
	}
	for _, key := range []string{
		"server", "mode", "phase", "progress", "ping_ms", "jitter_ms",
		"mbps_down", "mbps_up", "bytes_down", "bytes_up", "cap_ms",
		"sample", "error", "ts",
	} {
		if _, ok := st[key]; !ok {
			t.Errorf("snapshot is missing key %q", key)
		}
	}

	hist := p.SpeedHistory()
	if len(hist) == 0 {
		t.Fatal("history is empty after a finished run")
	}
	r := hist[0]
	if r.Phase != "done" {
		t.Errorf("phase = %q, want done", r.Phase)
	}
	if r.Mode != "direct" {
		t.Errorf("mode = %q, want direct", r.Mode)
	}
	if r.Server != "FakeCF" {
		t.Errorf("server = %q, want FakeCF", r.Server)
	}
	if r.PingMS <= 0 {
		t.Errorf("ping_ms = %v, want > 0", r.PingMS)
	}
	if r.MbpsDown <= 0 || r.BytesDown <= 0 {
		t.Errorf("download measured nothing: %.2f Mbps / %d bytes", r.MbpsDown, r.BytesDown)
	}
	if r.MbpsUp <= 0 || r.BytesUp <= 0 {
		t.Errorf("upload measured nothing: %.2f Mbps / %d bytes", r.MbpsUp, r.BytesUp)
	}
	if len(r.Sample) == 0 {
		t.Error("no samples in the live curve")
	}
	if r.CapMS != 30000 {
		t.Errorf("cap_ms = %d, want 30000", r.CapMS)
	}
}

// TestSpeedtestLibreSpeed runs the same contract against the LibreSpeed
// protocol, with two parallel streams, and checks the exit-address bonus.
func TestSpeedtestLibreSpeed(t *testing.T) {
	srv := fakeLibreSpeedServer(t)
	defer srv.Close()
	p := newSpeedProber(t)

	job, err := p.StartSpeedtest(ViaDirect, config.SpeedtestServer{Name: "FakeLS", Kind: "librespeed", Base: srv.URL}, 2, 2, 30)
	if err != nil {
		t.Fatalf("StartSpeedtest: %v", err)
	}
	st := waitSpeedJob(t, job, 30*time.Second)
	if st["state"] != JobDone {
		t.Fatalf("state = %v, error = %v", st["state"], st["error"])
	}
	hist := p.SpeedHistory()
	if len(hist) == 0 {
		t.Fatal("history is empty after a finished run")
	}
	r := hist[0]
	if r.BytesDown <= 0 || r.MbpsDown <= 0 {
		t.Errorf("download measured nothing: %.2f Mbps / %d bytes", r.MbpsDown, r.BytesDown)
	}
	if r.BytesUp <= 0 || r.MbpsUp <= 0 {
		t.Errorf("upload measured nothing: %.2f Mbps / %d bytes", r.MbpsUp, r.BytesUp)
	}
	if len(r.Sample) == 0 {
		t.Error("no samples in the live curve")
	}
	if !strings.Contains(r.Server, "198.51.100.7") {
		t.Errorf("server = %q, want the backend exit IP", r.Server)
	}
}

// TestSpeedtestCancel cancels a run that is parked mid-read and checks the
// promise: the state flips to canceled, the worker exits within one small
// block of time, and no more bytes are counted afterwards.
func TestSpeedtestCancel(t *testing.T) {
	srv := fakeSlowCloudflareServer(t)
	defer srv.Close()
	p := newSpeedProber(t)
	spec := config.SpeedtestServer{Name: "Slow", Kind: "cloudflare", Base: srv.URL}

	job, err := p.StartSpeedtest(ViaDirect, spec, 1, 30, 60)
	if err != nil {
		t.Fatalf("StartSpeedtest: %v", err)
	}
	done := speedRunDone(job)
	if done == nil {
		t.Fatal("run tracker missing")
	}
	if _, err := p.StartSpeedtest(ViaDirect, spec, 1, 30, 60); err == nil {
		t.Fatal("a second speedtest was accepted while one was running")
	}

	waitSpeedPhase(t, job, "download", 15*time.Second)
	waitSpeedBytes(t, job, 15*time.Second)

	start := time.Now()
	if !p.Jobs().Cancel(job.ID) {
		t.Fatal("Cancel returned false")
	}
	select {
	case <-done:
		if el := time.Since(start); el > 2*time.Second {
			t.Fatalf("worker took %s to stop after cancel", el)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not stop within 3s of cancel")
	}
	if state, _ := job.State(); state != JobCanceled {
		t.Fatalf("state = %s, want canceled", state)
	}
	a := speedNum(job.Status()["bytes_down"])
	time.Sleep(300 * time.Millisecond)
	b := speedNum(job.Status()["bytes_down"])
	if a != b {
		t.Fatalf("bytes_down still growing after cancel: %v -> %v", a, b)
	}
}

// TestSpeedHistoryRing checks the ring: at most eight entries, newest first,
// and no sharing between two Probers.
func TestSpeedHistoryRing(t *testing.T) {
	p := newSpeedProber(t)
	for i := 0; i < speedHistoryLen+3; i++ {
		p.speedRing().push(SpeedResult{Server: "s" + itoa(i), TS: int64(i)})
	}
	got := p.SpeedHistory()
	if len(got) != speedHistoryLen {
		t.Fatalf("history length = %d, want %d", len(got), speedHistoryLen)
	}
	if got[0].Server != "s10" || got[len(got)-1].Server != "s3" {
		t.Fatalf("history order wrong: %s .. %s", got[0].Server, got[len(got)-1].Server)
	}
	other := newSpeedProber(t)
	if len(other.SpeedHistory()) != 0 {
		t.Fatal("history leaked across probers")
	}
}
