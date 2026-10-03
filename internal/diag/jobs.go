package diag

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Job states. A job is always in exactly one of these.
const (
	JobRunning  = "running"
	JobDone     = "done"
	JobCanceled = "canceled"
	JobFailed   = "failed"
)

// Job is one long-running probe (matrix sweep, speed test, traceroute). It owns
// the context that cancels its workers, and a snapshot callback that produces
// the current partial result, so polling a running job is cheap and never
// blocks the workers.
type Job struct {
	ID   string
	Kind string

	mu      sync.Mutex
	state   string
	errMsg  string
	started time.Time
	ended   time.Time
	cancel  context.CancelFunc
	snap    func() map[string]any
}

// Status is the envelope every job route returns: identity, state, elapsed
// time, and the partial result the job wants to show.
func (j *Job) Status() map[string]any {
	j.mu.Lock()
	state, errMsg, started, ended, snap := j.state, j.errMsg, j.started, j.ended, j.snap
	j.mu.Unlock()

	elapsed := time.Since(started)
	if !ended.IsZero() {
		elapsed = ended.Sub(started)
	}
	out := map[string]any{
		"job":        j.ID,
		"kind":       j.Kind,
		"state":      state,
		"error":      errMsg,
		"elapsed_ms": elapsed.Milliseconds(),
	}
	if snap != nil {
		for k, v := range snap() {
			if _, taken := out[k]; !taken {
				out[k] = v
			}
		}
	}
	return out
}

// State reports the state and error without building the whole status.
func (j *Job) State() (string, string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.state, j.errMsg
}

// finish marks the job terminal. A canceled job stays canceled even if the
// worker reports the context error afterwards.
func (j *Job) finish(state, errMsg string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.state != JobRunning {
		return
	}
	j.state, j.errMsg, j.ended = state, errMsg, time.Now()
	if j.cancel != nil {
		j.cancel()
	}
}

// Jobs is the registry. One job of each kind may run at a time: two matrix
// sweeps at once would fight over the same nodes and produce a worse answer
// than either would alone.
type Jobs struct {
	mu      sync.Mutex
	items   map[string]*Job
	active  map[string]string
	seq     int
	now     func() time.Time
	keepFor time.Duration
}

func newJobs(now func() time.Time) *Jobs {
	if now == nil {
		now = time.Now
	}
	return &Jobs{
		items:   map[string]*Job{},
		active:  map[string]string{},
		now:     now,
		keepFor: 10 * time.Minute,
	}
}

var jobPrefix = map[string]string{
	"matrix":    "mx",
	"speedtest": "st",
	"trace":     "tr",
	"ai":        "ai",
}

// Begin registers a new job and returns it with the context its workers must
// watch. A second job of the same kind is refused with ErrJobRunning.
func (r *Jobs) Begin(kind string, snap func() map[string]any) (*Job, context.Context, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gcLocked()
	if id, busy := r.active[kind]; busy {
		return nil, nil, &JobBusyError{Kind: kind, ID: id}
	}
	r.seq++
	prefix := jobPrefix[kind]
	if prefix == "" {
		prefix = "job"
	}
	now := r.now()
	id := fmt.Sprintf("%s-%s-%d", prefix, now.Format("20060102-150405"), r.seq)
	ctx, cancel := context.WithCancel(context.Background())
	j := &Job{ID: id, Kind: kind, state: JobRunning, started: now, cancel: cancel, snap: snap}
	r.items[id] = j
	r.active[kind] = id
	return j, ctx, nil
}

// Finish marks a job terminal and frees its kind for the next run.
func (r *Jobs) Finish(j *Job, state, errMsg string) {
	if j == nil {
		return
	}
	j.finish(state, errMsg)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active[j.Kind] == j.ID {
		delete(r.active, j.Kind)
	}
}

// Get finds a job by id.
func (r *Jobs) Get(id string) (*Job, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	j, ok := r.items[id]
	return j, ok
}

// Active reports the running job of a kind, if any.
func (r *Jobs) Active(kind string) (*Job, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.active[kind]
	if !ok {
		return nil, false
	}
	j, ok := r.items[id]
	return j, ok
}

// Cancel stops a running job. It reports whether there was one to stop.
func (r *Jobs) Cancel(id string) bool {
	r.mu.Lock()
	j, ok := r.items[id]
	if ok && r.active[j.Kind] == j.ID {
		delete(r.active, j.Kind)
	}
	r.mu.Unlock()
	if !ok {
		return false
	}
	j.finish(JobCanceled, "")
	return true
}

// Recent lists the jobs still held, newest first, for the diagnostics page.
func (r *Jobs) Recent() []*Job {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gcLocked()
	out := make([]*Job, 0, len(r.items))
	for _, j := range r.items {
		out = append(out, j)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].started.After(out[b].started) })
	return out
}

// gcLocked drops finished jobs whose results nobody can still be waiting for.
func (r *Jobs) gcLocked() {
	cutoff := r.now().Add(-r.keepFor)
	for id, j := range r.items {
		j.mu.Lock()
		ended, state := j.ended, j.state
		j.mu.Unlock()
		if state != JobRunning && !ended.IsZero() && ended.Before(cutoff) {
			delete(r.items, id)
		}
	}
}

// JobBusyError tells the caller which run is already in flight, so the UI can
// attach to it instead of starting a second sweep.
type JobBusyError struct {
	Kind string
	ID   string
}

func (e *JobBusyError) Error() string {
	return "已有任务在运行（" + e.Kind + " " + e.ID + "）"
}
