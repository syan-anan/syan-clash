package diag

import (
	"net/http"
	"sync"
	"time"
)

// Options is everything the prober needs from the application layer. Every
// value is a function: the configuration can be edited while the client runs,
// and a probe must pick up the new timeout or concurrency on its next call
// rather than after a restart.
type Options struct {
	ProxyAddr    func() string
	FallbackAddr func() string
	TimeoutMS    func() int
	Concurrency  func() int
	CacheTTL     func() time.Duration
	Now          func() time.Time
	// AICookies returns the stored sign-in cookies for one AI service, so the
	// session probes run as the signed-in user. Nil, or an empty slice, means
	// "nobody has signed in", which is exactly the 黄绿 tier: the network
	// answered, the account did not.
	AICookies func(service string) []*http.Cookie
}

// Prober owns the concurrency gate, the answer cache and the job registry, and
// hands out HTTP clients that leave through a chosen path. It is safe for
// concurrent use; the panels call it from HTTP handlers.
type Prober struct {
	opts Options

	mu    sync.Mutex
	gate_ *limiter
	cache *cache

	jobs *Jobs
}

// New builds a prober. Nil option functions fall back to the values the client
// ships with, so a caller can pass only what it knows.
func New(opts Options) *Prober {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.ProxyAddr == nil {
		opts.ProxyAddr = func() string { return "" }
	}
	if opts.FallbackAddr == nil {
		opts.FallbackAddr = func() string { return "" }
	}
	if opts.TimeoutMS == nil {
		opts.TimeoutMS = func() int { return 8000 }
	}
	if opts.Concurrency == nil {
		opts.Concurrency = func() int { return 4 }
	}
	if opts.CacheTTL == nil {
		opts.CacheTTL = func() time.Duration { return 10 * time.Minute }
	}
	p := &Prober{opts: opts, jobs: newJobs(opts.Now)}
	p.cache = newCache(opts.CacheTTL, opts.Now)
	return p
}

// gate returns the concurrency limiter, rebuilding it when the configured size
// changed. An in-flight probe keeps the limiter it acquired from; the next one
// uses the new size.
func (p *Prober) gate() *limiter {
	want := p.opts.Concurrency()
	if want < 1 {
		want = 1
	}
	if want > 8 {
		want = 8
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.gate_ == nil || p.gate_.size() != want {
		p.gate_ = newLimiter(want)
	}
	return p.gate_
}

// timeout is the per-request budget in force.
func (p *Prober) timeout() time.Duration {
	ms := p.opts.TimeoutMS()
	if ms < 1000 {
		ms = 1000
	}
	if ms > 120000 {
		ms = 120000
	}
	return time.Duration(ms) * time.Millisecond
}

func (p *Prober) proxyAddr() string    { return p.opts.ProxyAddr() }
func (p *Prober) fallbackAddr() string { return p.opts.FallbackAddr() }
func (p *Prober) nowTime() time.Time   { return p.opts.Now() }

// Jobs exposes the registry so the handlers can start and poll long runs.
func (p *Prober) Jobs() *Jobs { return p.jobs }

// CacheSize reports how many probe answers are cached, for the page footer.
func (p *Prober) CacheSize() int { return p.cache.size() }

// Concurrency reports the gate size in force.
func (p *Prober) Concurrency() int { return p.gate().size() }

// ViaUsed describes where a probe actually went, for the answer headers.
func (p *Prober) ViaUsed(via Via) string {
	return describeVia(via, p.proxyAddr(), p.fallbackAddr())
}

// uncached key helpers keep the cache keys in one place so a probe and its
// refresh path cannot disagree about the name.
func cacheKey(parts ...string) string {
	out := ""
	for i, s := range parts {
		if i > 0 {
			out += "|"
		}
		out += s
	}
	return out
}
