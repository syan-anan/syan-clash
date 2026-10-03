package wintun

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestEnsureLifecycle covers the three cases Ensure exists for: a fresh
// release, an untouched verified copy (no rewrite) and a corrupted copy that
// has to be replaced.
func TestEnsureLifecycle(t *testing.T) {
	if !Supported() {
		t.Skipf("no embedded driver for %s", runtime.GOARCH)
	}
	dir := t.TempDir()

	target, err := Ensure(dir)
	if err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	if filepath.Base(target) != FileName {
		t.Fatalf("unexpected target %q", target)
	}
	if !Present(dir) {
		t.Fatal("Present is false right after a successful release")
	}
	if _, err := os.Stat(target + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temporary file left behind")
	}

	// A verified copy must not be rewritten: an install on a slow disk should
	// not pay 427 KB of writes on every core start.
	old := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(target, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	if _, err := Ensure(dir); err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	st, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !st.ModTime().Equal(old) {
		t.Fatal("verified copy was rewritten")
	}

	// A tampered copy is replaced, not trusted.
	if err := os.WriteFile(target, []byte("not a dll"), 0o644); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	if _, err := Ensure(dir); err != nil {
		t.Fatalf("third Ensure: %v", err)
	}
	if !Present(dir) {
		t.Fatal("corrupted copy was not replaced by a verified one")
	}
}
