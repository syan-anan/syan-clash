package diag

import (
	"sync"
	"time"
)

// cacheEntry is one TTL value plus the moment it was produced, because the UI
// shows the answer's age and "10 分钟前测的" is a different claim from "just now".
type cacheEntry struct {
	value   any
	expires time.Time
	stored  time.Time
}

// cache is a tiny TTL map. It never spawns a goroutine: entries are pruned on
// read and on write, and the map only ever holds a handful of probe answers.
// The TTL comes from a function so a configuration change takes effect on the
// next write instead of needing the client to restart.
type cache struct {
	mu   sync.Mutex
	ttl  func() time.Duration
	data map[string]cacheEntry
	now  func() time.Time
}

func newCache(ttl func() time.Duration, now func() time.Time) *cache {
	if now == nil {
		now = time.Now
	}
	if ttl == nil {
		ttl = func() time.Duration { return 0 }
	}
	return &cache{ttl: ttl, data: map[string]cacheEntry{}, now: now}
}

// ttlNow reports the TTL in force.
func (c *cache) ttlNow() time.Duration {
	if c == nil || c.ttl == nil {
		return 0
	}
	return c.ttl()
}

// get returns a live entry. Expired entries are dropped on the way past.
func (c *cache) get(key string) (any, time.Time, bool) {
	if c == nil {
		return nil, time.Time{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	ent, ok := c.data[key]
	if !ok {
		return nil, time.Time{}, false
	}
	if c.now().After(ent.expires) {
		delete(c.data, key)
		return nil, time.Time{}, false
	}
	return ent.value, ent.stored, true
}

// put stores a value. A zero or negative TTL disables caching entirely.
func (c *cache) put(key string, value any) {
	if c == nil {
		return
	}
	ttl := c.ttlNow()
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for k, ent := range c.data {
		if now.After(ent.expires) {
			delete(c.data, k)
		}
	}
	c.data[key] = cacheEntry{value: value, expires: now.Add(ttl), stored: now}
}

// drop removes one key, which is what refresh=1 does before recomputing.
func (c *cache) drop(key string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	delete(c.data, key)
	c.mu.Unlock()
}

// size reports how many entries are held, for the diagnostics page.
func (c *cache) size() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.data)
}
