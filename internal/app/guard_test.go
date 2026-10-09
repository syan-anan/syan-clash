package app

import "testing"

// A panic inside one tick must not escape. The loops that call this run for the
// whole life of the client: letting it through would take the process down, and
// stopping the loop would silently disable the watcher.
func TestGuardTickSwallowsPanicAndKeepsTheLoopGoing(t *testing.T) {
	a := &App{}
	ticks := 0
	for i := 0; i < 4; i++ {
		a.guardTick("test", func() {
			ticks++
			if ticks == 2 {
				panic("synthetic tick failure")
			}
		})
	}
	if ticks != 4 {
		t.Fatalf("guardTick stopped the loop: %d ticks, want 4", ticks)
	}
}
