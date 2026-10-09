package app

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

// procTracker remembers processes that have sent traffic through a core.
//
// The core's connection table only lists live connections, and most connections
// are short lived, so sampling it once cannot tell the user "chrome.exe has gone
// through here". The tracker samples periodically and accumulates the result, so
// the process picker fills up within a few seconds of normal use.
type procTracker struct {
	mu      sync.Mutex
	byKey   map[string]*ProcessSeen
	order   []string
	lastRun time.Time
}

var tracker = &procTracker{byKey: map[string]*ProcessSeen{}}

// seenProcesses samples a core and merges new observations into the history.
func (a *App) seenProcesses(ctx context.Context, id string) ([]ProcessSeen, error) {
	views, _, _, err := a.CoreConnectionView(ctx, id)
	if err != nil {
		return nil, err
	}

	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	tracker.lastRun = time.Now()

	for _, v := range views {
		name := v.ProcessName
		if name == "" {
			continue
		}
		// Key by name and path together: the same executable started from two
		// locations should be distinguishable when the user wants to write a
		// process-path rule.
		key := strings.ToLower(name) + "\x00" + strings.ToLower(v.Process)
		entry, ok := tracker.byKey[key]
		if !ok {
			entry = &ProcessSeen{Name: name, Path: v.Process}
			tracker.byKey[key] = entry
			tracker.order = append(tracker.order, key)
		}
		entry.Conns++
		entry.Upload += v.Upload
		entry.Download += v.Download
	}
	if len(tracker.order) > 500 {
		// Bound the history so a long-running install cannot grow it forever.
		drop := tracker.order[:len(tracker.order)-500]
		for _, key := range drop {
			delete(tracker.byKey, key)
		}
		tracker.order = append([]string{}, tracker.order[len(drop):]...)
	}

	out := make([]ProcessSeen, 0, len(tracker.order))
	for _, key := range tracker.order {
		if entry, ok := tracker.byKey[key]; ok {
			out = append(out, *entry)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		ti := out[i].Download + out[i].Upload
		tj := out[j].Download + out[j].Upload
		if ti != tj {
			return ti > tj
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// StartProcessSampler periodically folds live connections into the process
// history, so the picker has data before the user opens it.
func (a *App) StartProcessSampler(ctx context.Context, every time.Duration) {
	if every <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.guardTick("进程采样", func() {
					id := a.Config().Core.ID
					if id == "" {
						return
					}
					// Not running or no control API: nothing to sample.
					_, _ = a.seenProcesses(ctx, id)
				})
			}
		}
	}()
}
