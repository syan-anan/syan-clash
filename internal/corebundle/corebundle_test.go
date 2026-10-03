package corebundle

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestAssetsMatchRecordedDigests unpacks every embedded asset and checks it
// against the size and digest recorded in the source. This is what keeps the
// constants honest: swapping an asset without updating them fails here instead
// of silently shipping a core the client will refuse to trust.
func TestAssetsMatchRecordedDigests(t *testing.T) {
	for _, a := range assets() {
		zr, err := gzip.NewReader(bytes.NewReader(a.packed))
		if err != nil {
			t.Fatalf("%s: gzip: %v", a.Name, err)
		}
		data, err := io.ReadAll(zr)
		_ = zr.Close()
		if err != nil {
			t.Fatalf("%s: read: %v", a.Name, err)
		}
		if int64(len(data)) != a.RawSize {
			t.Errorf("%s: size %d, recorded %d", a.Name, len(data), a.RawSize)
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != a.SHA256 {
			t.Errorf("%s: sha256 %s, recorded %s", a.Name, got, a.SHA256)
		}
	}
}

// TestEnsureUnpacksAndSkips is the contract the client relies on: the first call
// unpacks everything, every later call is a no-op that only stats the files.
func TestEnsureUnpacksAndSkips(t *testing.T) {
	root := t.TempDir()
	first, err := Ensure(root)
	if err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	if len(first.Wrote) != len(assets()) {
		t.Fatalf("first call wrote %v, want all %d assets", first.Wrote, len(assets()))
	}
	for _, a := range assets() {
		st, err := os.Stat(filepath.Join(root, "mihomo", a.Name))
		if err != nil {
			t.Fatalf("%s: %v", a.Name, err)
		}
		if st.Size() != a.RawSize {
			t.Errorf("%s: size %d, want %d", a.Name, st.Size(), a.RawSize)
		}
	}
	second, err := Ensure(root)
	if err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	if second.Changed() {
		t.Errorf("second call wrote %v, want nothing", second.Wrote)
	}
	if len(second.Skipped) != len(assets()) {
		t.Errorf("second call skipped %v, want all", second.Skipped)
	}
}

// TestEnsureRepairsWrongSize covers the truncated-download case: a file that is
// there but the wrong size must be replaced, not trusted.
func TestEnsureRepairsWrongSize(t *testing.T) {
	root := t.TempDir()
	if _, err := Ensure(root); err != nil {
		t.Fatalf("seed: %v", err)
	}
	target := filepath.Join(root, "mihomo", "mihomo.exe")
	if err := os.Truncate(target, 1024); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	res, err := Ensure(root)
	if err != nil {
		t.Fatalf("repair: %v", err)
	}
	if len(res.Wrote) != 1 || res.Wrote[0] != "mihomo.exe" {
		t.Fatalf("wrote %v, want just mihomo.exe", res.Wrote)
	}
	st, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != 61047808 {
		t.Errorf("repaired size %d, want 61047808", st.Size())
	}
}

// TestDirForConfig pins the path rule: core.dir is relative to the folder that
// holds the configuration file, an absolute value wins, and a missing file
// falls back to "cores".
func TestDirForConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	if got, want := DirForConfig(cfg), filepath.Join(dir, "cores"); got != want {
		t.Errorf("missing config: got %s, want %s", got, want)
	}
	write := func(coreDir string) {
		t.Helper()
		raw, err := json.Marshal(map[string]any{"core": map[string]any{"dir": coreDir}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cfg, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("mycores")
	if got, want := DirForConfig(cfg), filepath.Join(dir, "mycores"); got != want {
		t.Errorf("relative dir: got %s, want %s", got, want)
	}
	abs := filepath.Join(dir, "absolute-cores")
	write(abs)
	if got := DirForConfig(cfg); got != abs {
		t.Errorf("absolute dir: got %s, want %s", got, abs)
	}
}

// TestReportStringIsReadable keeps the startup log line honest: a run that wrote
// nothing must not claim it did.
func TestReportStringIsReadable(t *testing.T) {
	quiet := Result{Dir: "C:\\Apps\\syan-clash\\cores\\mihomo", Skipped: []string{"mihomo.exe"}}
	if quiet.Changed() {
		t.Fatal("quiet report claims a change")
	}
	if quiet.String() == "" {
		t.Fatal("empty report string")
	}
	loud := Result{Dir: "d", Wrote: []string{"mihomo.exe"}}
	if !loud.Changed() || loud.String() == quiet.String() {
		t.Fatal("loud report does not differ from quiet one")
	}
}
