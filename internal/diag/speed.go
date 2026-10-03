package diag

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"vvpn/internal/config"
)

// This file implements the speed test job for the two backends the client
// ships with: Cloudflare's __down/__up protocol and the LibreSpeed backend.
// Every request leaves through p.newClient / p.do, so the run shares the
// dialer, the timeouts and the "no visible window" discipline of the other
// probes: there is no child process and no browser anywhere in the path.

// SpeedSample is one point of the live curve: the rate observed during second
// T of the running phase.
type SpeedSample struct {
	T    int     `json:"t"`
	Down float64 `json:"down"`
	Up   float64 `json:"up"`
}

// SpeedResult is the full state of one run. It is both the payload behind the
// job snapshot and the record kept in memory, so a finished run can be shown
// again without re-measuring.
type SpeedResult struct {
	Server    string        `json:"server"`
	Mode      string        `json:"mode"`
	Phase     string        `json:"phase"`
	Progress  float64       `json:"progress"`
	PingMS    float64       `json:"ping_ms"`
	JitterMS  float64       `json:"jitter_ms"`
	MbpsDown  float64       `json:"mbps_down"`
	MbpsUp    float64       `json:"mbps_up"`
	BytesDown int64         `json:"bytes_down"`
	BytesUp   int64         `json:"bytes_up"`
	CapMS     int64         `json:"cap_ms"`
	Sample    []SpeedSample `json:"sample"`
	Error     string        `json:"error"`
	TS        int64         `json:"ts"`
}

// The phase vocabulary the UI renders.
const (
	phaseLatency  = "latency"
	phaseDownload = "download"
	phaseUpload   = "upload"
	phaseDone     = "done"
	phaseFailed   = "failed"
)

const (
	speedLatencySamples = 10
	speedChunkSmall     = 5 << 20
	speedChunkBig       = 100 << 20
	speedUpBlock        = 2 << 20
	speedReadBuf        = 32 << 10
	speedMaxSamples     = 120
	speedStreamMax      = 4
	speedHistoryLen     = 8
	// speedBigChunkMbps is the measured rate above which the small probe block
	// is replaced by the big one: at 100Mbps a 5MB request lasts under half a
	// second, and the per-request overhead starts to distort the number.
	speedBigChunkMbps = 100.0
)

// The fraction of the progress bar each phase owns.
const (
	speedProgressLatency  = 0.10
	speedProgressDownload = 0.55
	speedProgressUpload   = 0.30
)

// speedState is the mutex-guarded state shared by the worker, the per-second
// samplers and the snapshot callback.
type speedState struct {
	mu  sync.Mutex
	res SpeedResult
	now func() time.Time

	phaseStart time.Time
	lastSec    int
	curDown    int64
	curUp      int64
}

// snapshot is the incremental view a polling UI renders. It is produced by
// marshalling the same struct that ends up in the history, so the keys are
// exactly the JSON names of SpeedResult.
func (st *speedState) snapshot() map[string]any {
	st.mu.Lock()
	res := st.res
	res.Sample = append([]SpeedSample(nil), st.res.Sample...)
	st.mu.Unlock()
	raw, err := json.Marshal(res)
	if err != nil {
		return map[string]any{}
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return map[string]any{}
	}
	return out
}

func (st *speedState) setPhase(phase string) {
	st.mu.Lock()
	st.res.Phase = phase
	st.mu.Unlock()
}

func (st *speedState) setServer(name string) {
	st.mu.Lock()
	st.res.Server = name
	st.mu.Unlock()
}

func (st *speedState) setPing(ping, jitter float64) {
	st.mu.Lock()
	st.res.PingMS, st.res.JitterMS = ping, jitter
	st.mu.Unlock()
}

// setProgress raises the bar; a later phase never moves it backwards.
func (st *speedState) setProgress(v float64) {
	if v < 0 {
		v = 0
	}
	if v > 1 {
		v = 1
	}
	st.mu.Lock()
	if v > st.res.Progress {
		st.res.Progress = v
	}
	st.mu.Unlock()
}

// setOverall turns the byte totals into the average rate of a finished phase.
func (st *speedState) setOverall(down bool, seconds float64) {
	if seconds <= 0 {
		seconds = 1
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if down {
		st.res.MbpsDown = float64(st.res.BytesDown) * 8 / 1e6 / seconds
	} else {
		st.res.MbpsUp = float64(st.res.BytesUp) * 8 / 1e6 / seconds
	}
}

// beginRate starts a new sampling window. Bytes counted from now on are sliced
// into one-second buckets.
func (st *speedState) beginRate(start time.Time) {
	st.mu.Lock()
	st.phaseStart = start
	st.lastSec = -1
	st.curDown, st.curUp = 0, 0
	st.mu.Unlock()
}

// add records n bytes moved in one direction, flushing the previous second's
// bucket when the clock has moved on. It is called from the copy loop and from
// the upload reader, possibly on several goroutines at once.
func (st *speedState) add(up bool, n int64) {
	if n <= 0 {
		return
	}
	now := st.now()
	st.mu.Lock()
	defer st.mu.Unlock()
	sec := int(now.Sub(st.phaseStart) / time.Second)
	if sec < 0 {
		sec = 0
	}
	switch {
	case st.lastSec < 0:
		st.lastSec = sec
	case sec != st.lastSec:
		st.flushLocked()
		st.lastSec = sec
	}
	if up {
		st.curUp += n
		st.res.BytesUp += n
	} else {
		st.curDown += n
		st.res.BytesDown += n
	}
}

// endRate flushes the trailing partial second so even a very short phase still
// produces a sample.
func (st *speedState) endRate() {
	st.mu.Lock()
	if st.lastSec >= 0 {
		st.flushLocked()
	}
	st.lastSec = -1
	st.mu.Unlock()
}

// flushLocked appends one sample from the accumulated bucket. It keeps at most
// speedMaxSamples points; the byte totals are unaffected by the clamp.
func (st *speedState) flushLocked() {
	if st.curDown == 0 && st.curUp == 0 {
		return
	}
	if len(st.res.Sample) >= speedMaxSamples {
		st.curDown, st.curUp = 0, 0
		return
	}
	st.res.Sample = append(st.res.Sample, SpeedSample{
		T:    st.lastSec,
		Down: float64(st.curDown) * 8 / 1e6,
		Up:   float64(st.curUp) * 8 / 1e6,
	})
	st.curDown, st.curUp = 0, 0
}

// mark freezes the result for a terminal state and returns the copy that goes
// into the history.
func (st *speedState) mark(state, msg string) SpeedResult {
	st.mu.Lock()
	defer st.mu.Unlock()
	switch state {
	case JobDone:
		st.res.Phase = phaseDone
		st.res.Progress = 1
	case JobFailed:
		st.res.Phase = phaseFailed
		st.res.Error = msg
	}
	st.res.TS = st.now().Unix()
	res := st.res
	res.Sample = append([]SpeedSample(nil), st.res.Sample...)
	return res
}

// speedRing is the small in-memory history: the last runs, newest first.
type speedRing struct {
	mu    sync.Mutex
	max   int
	items []SpeedResult
}

func (r *speedRing) push(res SpeedResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	items := make([]SpeedResult, 0, r.max)
	items = append(items, res)
	items = append(items, r.items...)
	if len(items) > r.max {
		items = items[:r.max]
	}
	r.items = items
}

func (r *speedRing) list() []SpeedResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]SpeedResult, len(r.items))
	copy(out, r.items)
	return out
}

// Histories are kept per Prober in a side table instead of on the struct, so
// two Probers in one process (the tests build several) never see each other's
// runs. The application builds one Prober, so the table holds one entry.
var speedRings = struct {
	mu sync.Mutex
	m  map[*Prober]*speedRing
}{m: map[*Prober]*speedRing{}}

func (p *Prober) speedRing() *speedRing {
	speedRings.mu.Lock()
	defer speedRings.mu.Unlock()
	r := speedRings.m[p]
	if r == nil {
		r = &speedRing{max: speedHistoryLen}
		speedRings.m[p] = r
	}
	return r
}

// SpeedHistory returns the most recent runs, newest first, at most eight.
func (p *Prober) SpeedHistory() []SpeedResult { return p.speedRing().list() }

// speedRunTracker maps a job to a channel closed when its worker returns, so
// the package tests can observe that a cancel really stopped the loop instead
// of merely marking the job. The control layer polls Job.Status instead.
var speedRunTracker sync.Map // map[*Job]chan struct{}

// speedRunDone returns the channel for a run; fetch it right after
// StartSpeedtest, because it is removed once the worker has exited.
func speedRunDone(job *Job) <-chan struct{} {
	v, ok := speedRunTracker.Load(job)
	if !ok {
		return nil
	}
	return v.(chan struct{})
}

// StartSpeedtest launches a run and returns immediately. One speed test runs
// at a time: a second call while one is in flight returns the registry's busy
// error. streams (1..4) split the bulk phases across parallel connections,
// durationSec is the target length of each bulk phase, and capSec is the hard
// ceiling after which the run settles with whatever it managed to measure.
func (p *Prober) StartSpeedtest(via Via, srv config.SpeedtestServer, streams, durationSec, capSec int) (*Job, error) {
	srv = normaliseSpeedServer(srv)
	streams = speedClamp(streams, 1, 1, speedStreamMax)
	capSec = speedClamp(capSec, 60, 5, 300)
	durationSec = speedClamp(durationSec, 10, 1, capSec)
	via = ParseVia(string(via))

	st := &speedState{now: p.nowTime}
	st.res = SpeedResult{
		Server: srv.Name,
		Mode:   string(via),
		Phase:  phaseLatency,
		CapMS:  int64(capSec) * 1000,
		Sample: []SpeedSample{},
		TS:     p.nowTime().Unix(),
	}

	job, ctx, err := p.jobs.Begin("speedtest", st.snapshot)
	if err != nil {
		return nil, err
	}
	done := make(chan struct{})
	speedRunTracker.Store(job, done)
	go func() {
		defer func() {
			close(done)
			speedRunTracker.Delete(job)
		}()
		p.runSpeedtest(ctx, job, st, via, srv, streams, durationSec, capSec)
	}()
	return job, nil
}

// runSpeedtest walks the three phases and settles the job exactly once.
func (p *Prober) runSpeedtest(parent context.Context, job *Job, st *speedState, via Via, srv config.SpeedtestServer, streams, dur, capSec int) {
	start := p.nowTime()
	capCtx, cancelCap := context.WithDeadline(parent, start.Add(time.Duration(capSec)*time.Second))
	defer cancelCap()

	// cause tells why a phase ended early: a user cancel outranks the cap.
	cause := func() string {
		if parent.Err() != nil {
			return "cancel"
		}
		if capCtx.Err() != nil {
			return "cap"
		}
		return ""
	}
	finish := func(state, msg string, keep bool) {
		res := st.mark(state, msg)
		if keep {
			p.speedRing().push(res)
		}
		p.jobs.Finish(job, state, msg)
	}

	st.setPhase(phaseLatency)
	st.setProgress(0.02)

	ping, jitter, err := p.speedLatency(capCtx, via, srv)
	if cause() == "cancel" {
		finish(JobCanceled, "", false)
		return
	}
	if err != nil {
		finish(JobFailed, err.Error(), true)
		return
	}
	st.setPing(ping, jitter)
	st.setProgress(speedProgressLatency)
	if cause() == "cap" {
		finish(JobDone, "", true)
		return
	}

	st.setPhase(phaseDownload)
	dlStart := p.nowTime()
	dlEnd := dlStart.Add(time.Duration(dur) * time.Second)
	st.beginRate(dlStart)
	err = p.speedDownload(capCtx, via, srv, st, dlStart, dlEnd, streams)
	st.endRate()
	st.setOverall(true, p.nowTime().Sub(dlStart).Seconds())
	if cause() == "cancel" {
		finish(JobCanceled, "", false)
		return
	}
	if err != nil {
		finish(JobFailed, err.Error(), true)
		return
	}
	if cause() == "cap" {
		finish(JobDone, "", true)
		return
	}

	st.setPhase(phaseUpload)
	ulStart := p.nowTime()
	ulEnd := ulStart.Add(time.Duration(dur) * time.Second)
	st.beginRate(ulStart)
	err = p.speedUpload(capCtx, via, srv, st, ulStart, ulEnd, streams)
	st.endRate()
	st.setOverall(false, p.nowTime().Sub(ulStart).Seconds())
	if cause() == "cancel" {
		finish(JobCanceled, "", false)
		return
	}
	if err != nil {
		finish(JobFailed, err.Error(), true)
		return
	}

	// The server-side exit address is a bonus for LibreSpeed; a failure here
	// must not spoil a run that already measured everything else.
	if isLibreSpeed(srv) {
		if ip, ok := p.libreExitIP(capCtx, via, srv); ok {
			st.setServer(srv.Name + " (" + ip + ")")
		}
	}

	finish(JobDone, "", true)
}

// normaliseSpeedServer fills in what a caller may have left out.
func normaliseSpeedServer(srv config.SpeedtestServer) config.SpeedtestServer {
	srv.Name = strings.TrimSpace(srv.Name)
	srv.Kind = strings.ToLower(strings.TrimSpace(srv.Kind))
	srv.Base = strings.TrimRight(strings.TrimSpace(srv.Base), "/")
	if srv.Base == "" {
		srv.Base = "https://speed.cloudflare.com"
	}
	if srv.Kind != "librespeed" {
		srv.Kind = "cloudflare"
	}
	if srv.Name == "" {
		srv.Name = srv.Base
	}
	return srv
}

func isLibreSpeed(srv config.SpeedtestServer) bool {
	return strings.EqualFold(srv.Kind, "librespeed")
}

// speedClamp applies the shipped bounds to a caller-provided number.
func speedClamp(v, fallback, lo, hi int) int {
	if v <= 0 {
		v = fallback
	}
	if v < lo {
		v = lo
	}
	if v > hi {
		v = hi
	}
	return v
}

// speedLatency measures the round trip ten times and reduces the set to its
// median and the mean absolute difference between neighbours.
func (p *Prober) speedLatency(ctx context.Context, via Via, srv config.SpeedtestServer) (float64, float64, error) {
	rtts := make([]time.Duration, 0, speedLatencySamples)
	var lastErr error
	for i := 0; i < speedLatencySamples; i++ {
		if ctx.Err() != nil {
			break
		}
		req, err := http.NewRequest(http.MethodGet, speedLatencyURL(srv), nil)
		if err != nil {
			lastErr = err
			continue
		}
		t0 := p.nowTime()
		resp, _, err := p.do(ctx, via, req, clientOpts{})
		rtt := p.nowTime().Sub(t0)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			lastErr = &statusError{URL: req.URL.String(), Code: resp.StatusCode}
			continue
		}
		rtts = append(rtts, rtt)
	}
	if len(rtts) == 0 {
		if lastErr == nil {
			lastErr = &sourceError{Msg: "没有测到延迟"}
		}
		return 0, 0, lastErr
	}
	return medianMS(rtts), jitterMS(rtts), nil
}

// medianMS is the median of a sample set in milliseconds. It sorts a copy, so
// the caller's measurement order is preserved for the jitter pass.
func medianMS(xs []time.Duration) float64 {
	if len(xs) == 0 {
		return 0
	}
	cp := append([]time.Duration(nil), xs...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	n := len(cp)
	if n%2 == 1 {
		return float64(cp[n/2]) / float64(time.Millisecond)
	}
	return (float64(cp[n/2-1]) + float64(cp[n/2])) / 2 / float64(time.Millisecond)
}

// jitterMS is the mean absolute difference between adjacent samples.
func jitterMS(xs []time.Duration) float64 {
	if len(xs) < 2 {
		return 0
	}
	var sum time.Duration
	for i := 1; i < len(xs); i++ {
		d := xs[i] - xs[i-1]
		if d < 0 {
			d = -d
		}
		sum += d
	}
	return float64(sum) / float64(len(xs)-1) / float64(time.Millisecond)
}

func speedLatencyURL(srv config.SpeedtestServer) string {
	if isLibreSpeed(srv) {
		return srv.Base + "/backend/empty.php?r=" + speedToken()
	}
	return srv.Base + "/__down?bytes=0"
}

func speedDownloadURL(srv config.SpeedtestServer, chunk int64) string {
	if isLibreSpeed(srv) {
		mb := chunk >> 20
		if mb < 1 {
			mb = 1
		}
		return srv.Base + "/backend/garbage.php?ckSize=" + strconv.FormatInt(mb, 10) + "&r=" + speedToken()
	}
	return srv.Base + "/__down?bytes=" + strconv.FormatInt(chunk, 10)
}

func speedUploadURL(srv config.SpeedtestServer) string {
	if isLibreSpeed(srv) {
		return srv.Base + "/backend/empty.php"
	}
	return srv.Base + "/__up"
}

var speedTokenSeq atomic.Int64

// speedToken makes a request unique, which keeps caches and CDN edges from
// answering a measurement request with a stored reply.
func speedToken() string {
	return strconv.FormatInt(time.Now().UnixNano(), 36) + strconv.FormatInt(speedTokenSeq.Add(1), 36)
}

// runSpeedStreams fans the same phase out over the configured connections and
// returns the first real failure. The phase context is canceled on that first
// failure so the surviving streams stop at once.
func runSpeedStreams(phaseCtx context.Context, cancel context.CancelFunc, streams int, fn func(context.Context) error) error {
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		first error
	)
	fail := func(err error) {
		if err == nil {
			return
		}
		mu.Lock()
		if first == nil {
			first = err
		}
		mu.Unlock()
		cancel()
	}
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fail(fn(phaseCtx))
		}()
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	return first
}

// speedPhaseErr discards the errors this job caused itself: when the phase
// deadline or a cancel fires, the read failure is expected and the caller
// decides what the state means.
func speedPhaseErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// speedSink counts what the copy loop pulled off the wire.
type speedSink struct{ st *speedState }

func (w speedSink) Write(p []byte) (int, error) {
	w.st.add(false, int64(len(p)))
	return len(p), nil
}

// ctxReader stops a streaming body the moment the job is canceled: every read
// checks the context first, so a cancel lands within one buffer block instead
// of waiting for the peer to send more.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *ctxReader) Read(p []byte) (int, error) {
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	default:
	}
	return r.r.Read(p)
}

// speedDownload runs the download phase: one streaming GET per connection,
// restarted with a bigger block when the link turns out to be fast.
func (p *Prober) speedDownload(ctx context.Context, via Via, srv config.SpeedtestServer, st *speedState, start, end time.Time, streams int) error {
	phaseCtx, cancel := context.WithDeadline(ctx, end)
	defer cancel()
	return runSpeedStreams(phaseCtx, cancel, streams, func(streamCtx context.Context) error {
		return p.speedDownloadStream(streamCtx, via, srv, st, start, end)
	})
}

func (p *Prober) speedDownloadStream(ctx context.Context, via Via, srv config.SpeedtestServer, st *speedState, start, end time.Time) error {
	client := p.newClient(via, clientOpts{ua: UAProbe})
	chunk := int64(speedChunkSmall)
	buf := make([]byte, speedReadBuf)
	for ctx.Err() == nil {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, speedDownloadURL(srv, chunk), nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", UAProbe)
		t0 := p.nowTime()
		resp, err := client.Do(req)
		if err != nil {
			return speedPhaseErr(ctx, err)
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			_ = resp.Body.Close()
			return &statusError{URL: req.URL.String(), Code: resp.StatusCode}
		}
		n, err := io.CopyBuffer(speedSink{st: st}, &ctxReader{ctx: ctx, r: resp.Body}, buf)
		_ = resp.Body.Close()
		if err != nil {
			return speedPhaseErr(ctx, err)
		}
		p.noteDlProgress(st, start, end)
		if n <= 0 || n < chunk {
			return nil
		}
		if el := p.nowTime().Sub(t0); el > 0 {
			rate := float64(n) * 8 / 1e6 / el.Seconds()
			if rate > speedBigChunkMbps && chunk < speedChunkBig {
				chunk = speedChunkBig
			}
		}
	}
	return nil
}

// noteDlProgress moves the bar through the slice the download phase owns.
func (p *Prober) noteDlProgress(st *speedState, start, end time.Time) {
	total := end.Sub(start).Seconds()
	if total <= 0 {
		return
	}
	frac := p.nowTime().Sub(start).Seconds() / total
	st.setProgress(speedProgressLatency + speedProgressDownload*frac)
}

// speedUpload runs the upload phase: 2MB random blocks posted in a loop, one
// request in flight per connection.
func (p *Prober) speedUpload(ctx context.Context, via Via, srv config.SpeedtestServer, st *speedState, start, end time.Time, streams int) error {
	phaseCtx, cancel := context.WithDeadline(ctx, end)
	defer cancel()
	payload := make([]byte, speedUpBlock)
	if _, err := rand.Read(payload); err != nil {
		return err
	}
	return runSpeedStreams(phaseCtx, cancel, streams, func(streamCtx context.Context) error {
		return p.speedUploadStream(streamCtx, via, srv, st, payload, start, end)
	})
}

func (p *Prober) speedUploadStream(ctx context.Context, via Via, srv config.SpeedtestServer, st *speedState, payload []byte, start, end time.Time) error {
	client := p.newClient(via, clientOpts{ua: UAProbe})
	for ctx.Err() == nil {
		body := &speedUploadReader{ctx: ctx, st: st, data: payload, left: int64(len(payload))}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, speedUploadURL(srv), body)
		if err != nil {
			return err
		}
		req.ContentLength = int64(len(payload))
		req.Header.Set("User-Agent", UAProbe)
		req.Header.Set("Content-Type", "application/octet-stream")
		resp, err := client.Do(req)
		if err != nil {
			return speedPhaseErr(ctx, err)
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 512<<10))
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return &statusError{URL: req.URL.String(), Code: resp.StatusCode}
		}
		p.noteUlProgress(st, start, end)
	}
	return nil
}

// noteUlProgress moves the bar through the slice the upload phase owns.
func (p *Prober) noteUlProgress(st *speedState, start, end time.Time) {
	total := end.Sub(start).Seconds()
	if total <= 0 {
		return
	}
	frac := p.nowTime().Sub(start).Seconds() / total
	st.setProgress(speedProgressLatency + speedProgressDownload + speedProgressUpload*frac)
}

// speedUploadReader feeds one random block to the transport and counts every
// byte handed over, which is what makes the live upload curve possible.
type speedUploadReader struct {
	ctx  context.Context
	st   *speedState
	data []byte
	left int64
}

func (r *speedUploadReader) Read(p []byte) (int, error) {
	if r.left <= 0 {
		return 0, io.EOF
	}
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	default:
	}
	n := len(p)
	if int64(n) > r.left {
		n = int(r.left)
	}
	copy(p[:n], r.data[:n])
	r.left -= int64(n)
	r.st.add(true, int64(n))
	return n, nil
}

// libreExitIP asks the LibreSpeed backend which address it sees. It is a
// best-effort extra: any failure just leaves the server name untouched.
func (p *Prober) libreExitIP(ctx context.Context, via Via, srv config.SpeedtestServer) (string, bool) {
	if ctx.Err() != nil {
		return "", false
	}
	gctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequest(http.MethodGet, srv.Base+"/backend/getIP.php?r="+speedToken(), nil)
	if err != nil {
		return "", false
	}
	resp, body, err := p.do(gctx, via, req, clientOpts{maxBytes: 8 << 10})
	if err != nil {
		return "", false
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", false
	}
	if ip := firstIPIn(string(body)); ip != "" {
		return ip, true
	}
	return "", false
}

// firstIPIn extracts the first token of a small text or JSON body that parses
// as an IP address. The LibreSpeed reply shape varies between versions, so the
// scanner is deliberately loose instead of keyed to one JSON schema.
func firstIPIn(s string) string {
	for _, field := range strings.FieldsFunc(s, func(r rune) bool {
		if unicode.IsSpace(r) {
			return true
		}
		switch r {
		case '"', ',', ';', '(', ')', '{', '}', '<', '>':
			return true
		}
		return false
	}) {
		field = strings.TrimSpace(field)
		if field != "" && net.ParseIP(field) != nil {
			return field
		}
	}
	return ""
}
