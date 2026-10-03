// Package logbus provides a bounded in-memory log ring buffer with fan-out to
// live subscribers. The proxy hot path must never block on a slow UI reader,
// so subscribers are lossy by design: a lagging reader drops entries instead
// of stalling the connection handler.
package logbus

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Level is a log severity.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

// String returns the lowercase name used in the JSON API.
func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "info"
	}
}

// ParseLevel maps a config string to a Level; unknown values fall back to info.
func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

// Entry is a single log record.
type Entry struct {
	Time  time.Time `json:"time"`
	Level string    `json:"level"`
	Msg   string    `json:"msg"`
}

type subscriber struct {
	ch     chan Entry
	mu     sync.Mutex
	closed bool
}

func (s *subscriber) send(e Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	select {
	case s.ch <- e:
	default:
	}
}

func (s *subscriber) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	close(s.ch)
}

// Bus is a ring buffer plus subscriber fan-out, safe for concurrent use.
type Bus struct {
	mu      sync.RWMutex
	min     Level
	ring    []Entry
	next    int
	full    bool
	subs    map[int]*subscriber
	nextSub int
}

// New creates a Bus keeping at most capacity entries at or above min.
func New(capacity int, min Level) *Bus {
	if capacity < 16 {
		capacity = 16
	}
	return &Bus{min: min, ring: make([]Entry, capacity), subs: make(map[int]*subscriber)}
}

func (b *Bus) logf(level Level, format string, args ...any) {
	b.mu.Lock()
	if level < b.min {
		b.mu.Unlock()
		return
	}
	e := Entry{Time: time.Now(), Level: level.String(), Msg: fmt.Sprintf(format, args...)}
	b.ring[b.next] = e
	b.next = (b.next + 1) % len(b.ring)
	if b.next == 0 {
		b.full = true
	}
	subs := make([]*subscriber, 0, len(b.subs))
	for _, s := range b.subs {
		subs = append(subs, s)
	}
	b.mu.Unlock()

	for _, s := range subs {
		s.send(e)
	}
}

// Debugf logs at debug level.
func (b *Bus) Debugf(format string, args ...any) { b.logf(LevelDebug, format, args...) }

// Infof logs at info level.
func (b *Bus) Infof(format string, args ...any) { b.logf(LevelInfo, format, args...) }

// Warnf logs at warn level.
func (b *Bus) Warnf(format string, args ...any) { b.logf(LevelWarn, format, args...) }

// Errorf logs at error level.
func (b *Bus) Errorf(format string, args ...any) { b.logf(LevelError, format, args...) }

// Recent returns up to n most recent entries in chronological order.
func (b *Bus) Recent(n int) []Entry {
	b.mu.RLock()
	defer b.mu.RUnlock()
	size := b.next
	if b.full {
		size = len(b.ring)
	}
	if n <= 0 || n > size {
		n = size
	}
	out := make([]Entry, 0, n)
	for i := size - n; i < size; i++ {
		idx := i
		if b.full {
			idx = (b.next + i) % len(b.ring)
		}
		out = append(out, b.ring[idx])
	}
	return out
}

// Subscribe registers a live listener.
func (b *Bus) Subscribe() (int, <-chan Entry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	id := b.nextSub
	b.nextSub++
	s := &subscriber{ch: make(chan Entry, 256)}
	b.subs[id] = s
	return id, s.ch
}

// Unsubscribe removes a listener registered by Subscribe.
func (b *Bus) Unsubscribe(id int) {
	b.mu.Lock()
	s, ok := b.subs[id]
	delete(b.subs, id)
	b.mu.Unlock()
	if ok {
		s.close()
	}
}

// SetLevel changes the minimum level emitted from now on.
func (b *Bus) SetLevel(min Level) {
	b.mu.Lock()
	b.min = min
	b.mu.Unlock()
}
