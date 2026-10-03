package core

import (
	"os"
	"path/filepath"
	"testing"

	"vvpn/internal/logbus"
)

func newVersionTestSupervisor(t *testing.T) *Supervisor {
	t.Helper()
	return NewSupervisor(t.TempDir(), logbus.New(64, logbus.LevelInfo))
}

func writeFakeBinary(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// restoreCatalogVersion undoes the global catalog mutation an activation makes,
// so one test cannot change what another one sees.
func restoreCatalogVersion(t *testing.T, id string) {
	t.Helper()
	spec, ok := Lookup(id)
	if !ok {
		t.Fatalf("core %q is not in the catalog", id)
	}
	version, url := spec.Version, spec.DownloadURL
	t.Cleanup(func() { SetCoreVersion(id, version, url) })
}

func TestSafeVersionNameRejectsTraversal(t *testing.T) {
	cases := map[string]string{
		"1.19.31":     "1.19.31",
		"v1.19.31":    "v1.19.31",
		"../../etc":   "etc",
		"1.0.0/../x":  "1.0.0..x",
		"":            "unknown",
		"..":          "unknown",
		"...":         "unknown",
		"C:\\windows": "Cwindows",
	}
	for in, want := range cases {
		if got := safeVersionName(in); got != want {
			t.Errorf("safeVersionName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestArchiveCurrentIsANoOpBeforeTheFirstInstall(t *testing.T) {
	s := newVersionTestSupervisor(t)
	spec, _ := Lookup("mihomo")
	path, err := s.archiveCurrent(spec)
	if err != nil {
		t.Fatalf("archiveCurrent: %v", err)
	}
	if path != "" {
		t.Errorf("archiveCurrent archived %q, want nothing", path)
	}
}

func TestArchiveCurrentAndListVersions(t *testing.T) {
	s := newVersionTestSupervisor(t)
	spec, ok := Lookup("mihomo")
	if !ok {
		t.Fatal("mihomo is missing from the catalog")
	}
	live := s.BinaryPath(spec)
	writeFakeBinary(t, live, "live-binary")

	archived, err := s.archiveCurrent(spec)
	if err != nil {
		t.Fatalf("archiveCurrent: %v", err)
	}
	if archived == "" {
		t.Fatal("archiveCurrent archived nothing")
	}
	if _, err := os.Stat(archived); err != nil {
		t.Fatalf("archive is missing: %v", err)
	}
	// The live binary has to stay where it was: archiving must not move it.
	body, err := os.ReadFile(live)
	if err != nil || string(body) != "live-binary" {
		t.Fatalf("live binary = %q err=%v", body, err)
	}

	versions, err := s.CoreVersions(spec.ID)
	if err != nil {
		t.Fatalf("CoreVersions: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("versions = %d, want 2: %+v", len(versions), versions)
	}
	if !versions[0].Current || versions[0].Version != spec.Version {
		t.Errorf("first entry = %+v, want the live binary at %s", versions[0], spec.Version)
	}
	if versions[1].Current || versions[1].Version != spec.Version {
		t.Errorf("second entry = %+v, want the archive of %s", versions[1], spec.Version)
	}

	// Archiving twice with the same size must not rewrite the archive.
	before, _ := os.Stat(archived)
	again, err := s.archiveCurrent(spec)
	if err != nil || again != archived {
		t.Fatalf("second archiveCurrent = %q err=%v", again, err)
	}
	after, _ := os.Stat(archived)
	if !after.ModTime().Equal(before.ModTime()) {
		t.Error("archiveCurrent rewrote an archive that already matched")
	}
}

func TestPruneVersionsKeepsTheNewest(t *testing.T) {
	s := newVersionTestSupervisor(t)
	spec, _ := Lookup("mihomo")
	dir := s.versionsDir(spec.ID)
	for _, v := range []string{"1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0"} {
		writeFakeBinary(t, filepath.Join(dir, v, spec.Binary), v)
	}
	if err := s.pruneVersions(spec); err != nil {
		t.Fatalf("pruneVersions: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	if len(entries) != maxArchivedVersions {
		t.Fatalf("kept %d archives, want %d", len(entries), maxArchivedVersions)
	}
	for _, want := range []string{"1.4.0", "1.3.0", "1.2.0"} {
		if _, err := os.Stat(filepath.Join(dir, want, spec.Binary)); err != nil {
			t.Errorf("newest archive %s was pruned: %v", want, err)
		}
	}
	for _, gone := range []string{"1.0.0", "1.1.0"} {
		if _, err := os.Stat(filepath.Join(dir, gone)); !os.IsNotExist(err) {
			t.Errorf("oldest archive %s survived pruning", gone)
		}
	}

	// Fewer archives than the cap is not an error and prunes nothing.
	small := newVersionTestSupervisor(t)
	smallDir := small.versionsDir(spec.ID)
	writeFakeBinary(t, filepath.Join(smallDir, "2.0.0", spec.Binary), "x")
	if err := small.pruneVersions(spec); err != nil {
		t.Fatalf("pruneVersions on a short list: %v", err)
	}
	if _, err := os.Stat(filepath.Join(smallDir, "2.0.0", spec.Binary)); err != nil {
		t.Errorf("pruning removed an archive below the cap: %v", err)
	}
}

func TestActivateCoreVersionSwapsTheBinary(t *testing.T) {
	restoreCatalogVersion(t, "mihomo")
	s := newVersionTestSupervisor(t)
	spec, _ := Lookup("mihomo")
	live := s.BinaryPath(spec)
	writeFakeBinary(t, live, "new-binary")
	writeFakeBinary(t, filepath.Join(s.versionsDir(spec.ID), "1.18.0", spec.Binary), "old-binary")

	got, err := s.ActivateCoreVersion(spec.ID, "1.18.0")
	if err != nil {
		t.Fatalf("ActivateCoreVersion: %v", err)
	}
	if !got.Current || got.Version != "1.18.0" {
		t.Errorf("activated = %+v", got)
	}
	body, err := os.ReadFile(live)
	if err != nil || string(body) != "old-binary" {
		t.Fatalf("live binary = %q err=%v, want old-binary", body, err)
	}
	// The release we left has to be parked, otherwise the swap is one-way.
	parked := filepath.Join(s.versionsDir(spec.ID), spec.Version, spec.Binary)
	if _, err := os.Stat(parked); err != nil {
		t.Errorf("the previous binary was not archived: %v", err)
	}
	// The catalog follows the file, so the console reports what is installed.
	restored, _ := Lookup(spec.ID)
	if restored.Version != "1.18.0" {
		t.Errorf("catalog version = %q, want 1.18.0", restored.Version)
	}
	// A version that was never archived is refused instead of silently doing
	// nothing.
	if _, err := s.ActivateCoreVersion(spec.ID, "9.9.9"); err == nil {
		t.Error("activating a version that is not archived must fail")
	}
	if _, err := s.ActivateCoreVersion("nope", "1.0.0"); err == nil {
		t.Error("activating a version of an unknown core must fail")
	}
}

func TestCoreVersionsRejectsAnUnknownCore(t *testing.T) {
	s := newVersionTestSupervisor(t)
	if _, err := s.CoreVersions("nope"); err == nil {
		t.Error("CoreVersions accepted an unknown core")
	}
}
