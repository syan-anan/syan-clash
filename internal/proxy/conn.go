package proxy

import (
	"context"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"vvpn/internal/logbus"
)

// ConnInfo is a snapshot of one proxied connection, as exposed to the UI.
type ConnInfo struct {
	ID       uint64    `json:"id"`
	Source   string    `json:"source"`
	Host     string    `json:"host"`
	Target   string    `json:"target"`
	Rule     string    `json:"rule"`
	Action   string    `json:"action"`
	Outbound string    `json:"outbound"`
	Start    time.Time `json:"start"`
	Ended    time.Time `json:"ended,omitempty"`
	Up       int64     `json:"up"`
	Down     int64     `json:"down"`
	Closed   bool      `json:"closed"`
	Err      string    `json:"err,omitempty"`
}

// Session tracks one live connection so the UI can count and kill it.
type Session struct {
	reg    *Registry
	cancel context.CancelFunc

	mu     sync.Mutex
	info   ConnInfo
	conns  []net.Conn
	closed bool

	up   atomic.Int64
	down atomic.Int64
}

func (s *Session) snapshot() ConnInfo {
	s.mu.Lock()
	info := s.info
	s.mu.Unlock()
	info.Up = s.up.Load()
	info.Down = s.down.Load()
	return info
}

// setRoute records the routing decision on the session.
func (s *Session) setRoute(res ruleResult) {
	s.mu.Lock()
	s.info.Action = string(res.Action)
	s.info.Rule = res.Rule
	s.info.Outbound = res.Outbound
	if res.Err != nil {
		s.info.Err = res.Err.Error()
	}
	s.mu.Unlock()
}

// attach registers a socket so Close can tear it down.
func (s *Session) attach(c net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		_ = c.Close()
		return
	}
	s.conns = append(s.conns, c)
}

// Close aborts the session and records it in the recent list.
func (s *Session) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	conns := s.conns
	s.conns = nil
	s.mu.Unlock()

	if s.cancel != nil {
		s.cancel()
	}
	for _, c := range conns {
		_ = c.Close()
	}
	s.reg.finish(s)
}

// Registry is the live connection table.
type Registry struct {
	mu     sync.RWMutex
	nextID uint64
	active map[uint64]*Session
	recent []ConnInfo
	log    *logbus.Bus
	total  atomic.Uint64
}

// NewRegistry creates an empty connection registry. log may be nil.
func NewRegistry(log *logbus.Bus) *Registry {
	return &Registry{active: make(map[uint64]*Session), log: log}
}

// Add starts tracking a connection and returns its session plus the context
// that gets cancelled when the session is killed.
func (r *Registry) Add(ctx context.Context, info ConnInfo) (*Session, context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	info.Start = time.Now()
	s := &Session{reg: r, cancel: cancel, info: info}

	r.mu.Lock()
	r.nextID++
	s.info.ID = r.nextID
	r.active[s.info.ID] = s
	r.mu.Unlock()

	r.total.Add(1)
	return s, ctx
}

func (r *Registry) finish(s *Session) {
	info := s.snapshot()
	info.Closed = true
	info.Ended = time.Now()

	r.mu.Lock()
	_, live := r.active[info.ID]
	delete(r.active, info.ID)
	if live {
		r.recent = append(r.recent, info)
		if len(r.recent) > 200 {
			r.recent = r.recent[len(r.recent)-200:]
		}
	}
	r.mu.Unlock()

	if live && r.log != nil {
		r.log.Infof("conn #%d %s -> %s [%s/%s] up=%dB down=%dB", info.ID, info.Source, info.Target, info.Rule, info.Action, info.Up, info.Down)
	}
}

// Snapshot returns live sessions first, then the most recently closed ones.
func (r *Registry) Snapshot() []ConnInfo {
	r.mu.RLock()
	out := make([]ConnInfo, 0, len(r.active)+len(r.recent))
	for _, s := range r.active {
		out = append(out, s.snapshot())
	}
	out = append(out, r.recent...)
	r.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].Closed != out[j].Closed {
			return !out[i].Closed
		}
		return out[i].Start.After(out[j].Start)
	})
	return out
}

// Close kills one session by ID. It reports whether a live session matched.
func (r *Registry) Close(id uint64) bool {
	r.mu.RLock()
	s, ok := r.active[id]
	r.mu.RUnlock()
	if !ok {
		return false
	}
	s.Close()
	return true
}

// CloseAll kills every live session (used on shutdown).
func (r *Registry) CloseAll() {
	r.mu.RLock()
	sessions := make([]*Session, 0, len(r.active))
	for _, s := range r.active {
		sessions = append(sessions, s)
	}
	r.mu.RUnlock()
	for _, s := range sessions {
		s.Close()
	}
}

// Counts returns (live, total) connection counts.
func (r *Registry) Counts() (int, uint64) {
	r.mu.RLock()
	live := len(r.active)
	r.mu.RUnlock()
	return live, r.total.Load()
}

// countingConn attributes traffic to a session. read counts bytes flowing
// away from the wrapped socket's peer, write counts bytes written into it.
type countingConn struct {
	net.Conn
	read  *atomic.Int64
	write *atomic.Int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && c.read != nil {
		c.read.Add(int64(n))
	}
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 && c.write != nil {
		c.write.Add(int64(n))
	}
	return n, err
}

// CloseWrite forwards a TCP half-close so the peer sees EOF cleanly.
func (c *countingConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
