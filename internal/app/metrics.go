package app

// Process metrics for the status card.
//
// The console shows two processes: the client itself and the external core it
// started. Both are ordinary Windows processes, so the numbers come straight
// from the OS instead of from a self-reported counter - the client through its
// own pseudo-handle, the core through a handle opened on the PID the
// supervisor recorded. When a value cannot be read the field stays 0: the JSON
// shape never changes, so the UI can render the card without null checks.

// procMetrics is the portable shape of one process's runtime counters.
type procMetrics struct {
	RSSBytes uint64
	Threads  int
	Handles  int
}

// corePID is the PID of the external core currently serving traffic, or 0 when
// no core runs. The supervisor only fills PID for a live process, so a stale
// entry cannot leak a reused PID into the status response.
func (a *App) corePID() int {
	if a.cores == nil {
		return 0
	}
	if id := a.RunningCoreID(); id != "" {
		if st := a.cores.StatusFor(id); st.Running && st.PID > 0 {
			return st.PID
		}
	}
	for _, st := range a.cores.Status() {
		if st.Running && st.PID > 0 {
			return st.PID
		}
	}
	return 0
}

// attachMetrics fills the six process counters. It runs at the end of Status()
// so every response carries the same keys whether or not a core is up.
func (a *App) attachMetrics(st *Status) {
	self := selfMetrics()
	st.ClientRSSBytes = self.RSSBytes
	st.ClientThreads = self.Threads
	st.ClientHandles = self.Handles
	if pid := a.corePID(); pid > 0 {
		core := processMetrics(pid)
		st.CoreRSSBytes = core.RSSBytes
		st.CoreThreads = core.Threads
		st.CoreHandles = core.Handles
	}
}
