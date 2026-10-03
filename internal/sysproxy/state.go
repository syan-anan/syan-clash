package sysproxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// Snapshot is what the machine's WinINET proxy looked like before this client
// turned it on, plus the process that did it.
//
// It is written to disk because the system proxy outlives the process that set
// it: a crash or a "结束任务" runs no cleanup at all, and the user is then left
// with a browser pointed at a port nothing listens on. Recording the previous
// values is what lets the guard process - and, failing that, the next launch -
// put the machine back exactly as it was found.
type Snapshot struct {
	// PID owns the change. A snapshot whose owner is still alive belongs to
	// another running copy and must not be undone from under it.
	PID int `json:"pid"`
	// Applied is false for a snapshot that has already been undone. The file
	// is normally deleted instead; the flag covers a half-written cleanup.
	Applied bool `json:"applied"`
	// WasOn, Server and Override are the previous values. WasOn=false means
	// the machine had no system proxy before this client turned one on.
	WasOn    bool   `json:"was_on"`
	Server   string `json:"server"`
	Override string `json:"override"`
	// Addr is what this client published, kept for the log and for the
	// "is the registry still pointing at us" question.
	Addr string `json:"addr"`
	At   string `json:"at"`
}

var (
	stateMu   sync.RWMutex
	statePath string
)

// SetStatePath tells the package where to remember the pre-enable values. It is
// called once at startup; an empty path turns persistence off, which is what a
// build with no writable folder next to it gets.
func SetStatePath(p string) {
	stateMu.Lock()
	statePath = p
	stateMu.Unlock()
}

// StatePath reports the file the snapshot is kept in.
func StatePath() string {
	stateMu.RLock()
	defer stateMu.RUnlock()
	return statePath
}

// DefaultStatePath is the file next to the configuration. It stays out of the
// registry on purpose: deleting the folder must not leave a half-restored
// proxy behind.
func DefaultStatePath(configPath string) string {
	if configPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(configPath), "sysproxy-state.json")
}

// LoadSnapshot reads the saved snapshot. A missing or unreadable file is not an
// error: it is the normal state of a machine whose proxy was never touched.
func LoadSnapshot(path string) (Snapshot, bool) {
	if path == "" {
		return Snapshot{}, false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, false
	}
	var s Snapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		return Snapshot{}, false
	}
	return s, true
}

// OwnedBy reports whether the snapshot on disk was written by pid, i.e.
// whether that process is the one that turned the system proxy on and is
// therefore the one that has to hand it back.
//
// This is deliberately not the same question as "is the switch up". On a
// machine where another client owns the setting the registry says 1 while
// this client has written nothing at all, and both the tray and the guard
// have to answer the ownership question, not the registry one.
func OwnedBy(path string, pid int) bool {
	snap, ok := LoadSnapshot(path)
	return ok && snap.Applied && snap.PID == pid
}

// SaveSnapshot writes the snapshot atomically, so a crash mid-write cannot
// leave a truncated file that would restore garbage.
func SaveSnapshot(path string, s Snapshot) error {
	if path == "" {
		return nil
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".sysproxy-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// ClearSnapshot forgets the saved state. Removing a file that is not there is
// success, not an error.
func ClearSnapshot(path string) error {
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
