package diag

import "context"

// limiter is the concurrency gate every outbound probe passes through. A probe
// panel that opens 200 sockets at once is indistinguishable from a flood and
// makes the whole client feel slow, so the gate is deliberately small and the
// callers that need more spread the work over time instead.
type limiter struct {
	slots chan struct{}
}

func newLimiter(n int) *limiter {
	if n < 1 {
		n = 1
	}
	return &limiter{slots: make(chan struct{}, n)}
}

// acquire blocks until a slot is free or the context ends.
func (l *limiter) acquire(ctx context.Context) error {
	if l == nil {
		return nil
	}
	select {
	case l.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// release returns a slot. It is safe to call more times than acquire only if
// the extra calls are guarded by a successful acquire bit - callers use the
// defer form below, which always pairs one release with one acquire.
func (l *limiter) release() {
	if l == nil {
		return
	}
	select {
	case <-l.slots:
	default:
	}
}

// size reports the configured concurrency.
func (l *limiter) size() int {
	if l == nil {
		return 0
	}
	return cap(l.slots)
}
