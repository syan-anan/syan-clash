package sysproxy

import (
	"os"
	"path/filepath"
	"testing"
)

// The snapshot is the only thing standing between a killed client and a
// machine whose browser points at a dead port, so the file round-trip is
// checked directly rather than through the registry.
func TestSnapshotRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := DefaultStatePath(filepath.Join(dir, "config.json"))
	if path != filepath.Join(dir, "sysproxy-state.json") {
		t.Fatalf("snapshot path = %q", path)
	}

	if _, ok := LoadSnapshot(path); ok {
		t.Fatal("a missing snapshot must report ok=false")
	}

	want := Snapshot{
		PID:      4321,
		Applied:  true,
		WasOn:    true,
		Server:   "127.0.0.1:7890",
		Override: "localhost",
		Addr:     "http=127.0.0.1:2890",
		At:       "2026-10-02T12:00:00+08:00",
	}
	if err := SaveSnapshot(path, want); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, ok := LoadSnapshot(path)
	if !ok {
		t.Fatal("saved snapshot did not load")
	}
	if got != want {
		t.Fatalf("snapshot mismatch\n got %+v\nwant %+v", got, want)
	}

	// No temp files may be left behind: the guard reads this path while the
	// client is writing it.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "sysproxy-state.json" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("unexpected leftovers in %s: %v", dir, names)
	}

	if err := ClearSnapshot(path); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if _, ok := LoadSnapshot(path); ok {
		t.Fatal("snapshot still readable after ClearSnapshot")
	}
	// Clearing twice is success, not an error: every exit path calls it.
	if err := ClearSnapshot(path); err != nil {
		t.Fatalf("second clear: %v", err)
	}
}

// A garbage file must be treated as "no snapshot" instead of restoring
// nonsense into the registry.
func TestSnapshotIgnoresCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sysproxy-state.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, ok := LoadSnapshot(path); ok {
		t.Fatal("a corrupt snapshot must not load")
	}
}

// An empty path is what a build without a writable folder gets: every call has
// to be a no-op rather than a panic or a stray file in the working directory.
func TestSnapshotEmptyPathIsNoop(t *testing.T) {
	if err := SaveSnapshot("", Snapshot{PID: 1, Applied: true}); err != nil {
		t.Fatalf("save with empty path: %v", err)
	}
	if err := ClearSnapshot(""); err != nil {
		t.Fatalf("clear with empty path: %v", err)
	}
	if _, ok := LoadSnapshot(""); ok {
		t.Fatal("empty path must not load a snapshot")
	}
	if p := DefaultStatePath(""); p != "" {
		t.Fatalf("DefaultStatePath(\"\") = %q", p)
	}
}
