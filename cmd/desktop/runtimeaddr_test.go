package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The published address has to survive a restart of the reader and disappear
// with its owner: a leftover would send the next double-click at a port that
// nobody owns.
func TestRuntimeAddrPublishReadWithdraw(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("OwnerAlive is only meaningful on Windows")
	}
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")

	if got := liveRuntimeAddr(cfg); got != "" {
		t.Fatalf("liveRuntimeAddr with no record = %q, want empty", got)
	}

	withdraw := publishRuntimeAddr(cfg, "127.0.0.1:3090")
	if got := liveRuntimeAddr(cfg); got != "127.0.0.1:3090" {
		t.Fatalf("liveRuntimeAddr after publish = %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, runtimeAddrName)); err != nil {
		t.Fatalf("record file: %v", err)
	}

	withdraw()
	if got := liveRuntimeAddr(cfg); got != "" {
		t.Fatalf("liveRuntimeAddr after withdraw = %q, want empty", got)
	}
}

// A record written by a process that is gone must be ignored rather than
// tried, and withdrawing somebody else's record must not delete it.
func TestRuntimeAddrIgnoresDeadOwner(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")

	// pid 1 is never a live user process on Windows.
	blob := []byte(`{"pid":1,"console":"127.0.0.1:3091","started":"2026-10-02T00:00:00Z"}` + "\n")
	if err := os.WriteFile(filepath.Join(dir, runtimeAddrName), blob, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := liveRuntimeAddr(cfg); got != "" {
		t.Fatalf("liveRuntimeAddr with a dead owner = %q, want empty", got)
	}

	// A second process publishing over the record must not be able to have the
	// first one's withdraw remove the new record.
	withdraw := publishRuntimeAddr(cfg, "127.0.0.1:3092")
	other := []byte(`{"pid":4242,"console":"127.0.0.1:3093","started":"2026-10-02T00:00:00Z"}` + "\n")
	if err := os.WriteFile(filepath.Join(dir, runtimeAddrName), other, 0o644); err != nil {
		t.Fatal(err)
	}
	withdraw()
	if _, err := os.Stat(filepath.Join(dir, runtimeAddrName)); err != nil {
		t.Fatalf("a foreign record must survive somebody else's withdraw: %v", err)
	}
}
