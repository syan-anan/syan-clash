package core

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// maxArchivedVersions is how many superseded core binaries stay on disk. Three
// is enough to undo a bad update and still have the release before it, without
// keeping every build the operator has ever run.
const maxArchivedVersions = 3

// CoreVersion is one core binary that exists on disk: either the live one or an
// archived release that an update replaced.
type CoreVersion struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	SavedAt string `json:"saved_at,omitempty"`
	Current bool   `json:"current"`
}

// versionsDir is where superseded binaries are parked, next to the live one.
func (s *Supervisor) versionsDir(id string) string {
	return filepath.Join(s.Dir(id), "versions")
}

// safeVersionName turns a version string into a directory name. Everything that
// is not a letter, digit, dot, dash or underscore is dropped, so a version that
// arrived from a release tag can never escape the core directory.
func safeVersionName(version string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(version) {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
			r == '.', r == '-', r == '_':
			b.WriteRune(r)
		}
	}
	if name := strings.Trim(b.String(), "."); name != "" {
		return name
	}
	return "unknown"
}

// archiveCurrent copies the live binary of a core into the version archive so
// an install that overwrites it can be undone. It is a no-op when nothing is
// installed yet, and it does not rewrite an archive that already matches the
// live binary's size.
func (s *Supervisor) archiveCurrent(spec CoreSpec) (string, error) {
	live := s.BinaryPath(spec)
	st, err := os.Stat(live)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	if st.Size() == 0 {
		return "", nil
	}
	name := safeVersionName(spec.Version)
	dir := filepath.Join(s.versionsDir(spec.ID), name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	dest := filepath.Join(dir, spec.Binary)
	if existing, err := os.Stat(dest); err == nil && existing.Size() == st.Size() {
		return dest, nil
	}
	if err := copyFileAtomic(live, dest); err != nil {
		return "", fmt.Errorf("archive core %s %s: %w", spec.ID, name, err)
	}
	if err := s.pruneVersions(spec); err != nil {
		// Pruning is housekeeping: a core that updated fine must not be
		// reported as a failure because an old archive could not be removed.
		s.log.Infof("core %s: pruning old versions failed: %v", spec.ID, err)
	}
	return dest, nil
}

// pruneVersions keeps the newest maxArchivedVersions archives and deletes the
// rest.
func (s *Supervisor) pruneVersions(spec CoreSpec) error {
	dir := s.versionsDir(spec.ID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	if len(names) <= maxArchivedVersions {
		return nil
	}
	sort.Slice(names, func(i, j int) bool { return compareVersions(names[i], names[j]) > 0 })
	for _, name := range names[maxArchivedVersions:] {
		if err := os.RemoveAll(filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return nil
}

// CoreVersions lists the live binary plus every archived release, the live one
// first and the archives newest-first.
func (s *Supervisor) CoreVersions(id string) ([]CoreVersion, error) {
	spec, ok := Lookup(id)
	if !ok {
		return nil, fmt.Errorf("unknown core %q", id)
	}
	out := make([]CoreVersion, 0, maxArchivedVersions+1)
	if st, err := os.Stat(s.BinaryPath(spec)); err == nil {
		out = append(out, CoreVersion{
			ID:      spec.ID,
			Version: spec.Version,
			Path:    s.BinaryPath(spec),
			Size:    st.Size(),
			SavedAt: st.ModTime().Format(time.RFC3339),
			Current: true,
		})
	}
	entries, err := os.ReadDir(s.versionsDir(id))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	archives := make([]CoreVersion, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := filepath.Join(s.versionsDir(id), e.Name(), spec.Binary)
		st, err := os.Stat(path)
		if err != nil {
			continue
		}
		archives = append(archives, CoreVersion{
			ID:      spec.ID,
			Version: e.Name(),
			Path:    path,
			Size:    st.Size(),
			SavedAt: st.ModTime().Format(time.RFC3339),
		})
	}
	sort.Slice(archives, func(i, j int) bool {
		return compareVersions(archives[i].Version, archives[j].Version) > 0
	})
	return append(out, archives...), nil
}

// ActivateCoreVersion restores an archived release over the live binary and
// repoints the catalog at it, so the console reports the version that is now on
// disk. The binary currently live is archived first, which makes switching back
// and forth symmetric.
//
// The caller must stop the core before calling this on Windows: a running
// executable cannot be replaced, and the rename would fail with a sharing
// violation rather than a helpful message.
func (s *Supervisor) ActivateCoreVersion(id, version string) (CoreVersion, error) {
	spec, ok := Lookup(id)
	if !ok {
		return CoreVersion{}, fmt.Errorf("unknown core %q", id)
	}
	name := safeVersionName(version)
	src := filepath.Join(s.versionsDir(id), name, spec.Binary)
	st, err := os.Stat(src)
	if err != nil {
		return CoreVersion{}, fmt.Errorf("core %s has no archived version %q", id, version)
	}
	if _, err := s.archiveCurrent(spec); err != nil {
		return CoreVersion{}, err
	}
	if err := copyFileAtomic(src, s.BinaryPath(spec)); err != nil {
		return CoreVersion{}, fmt.Errorf("activate core %s %s: %w", id, name, err)
	}
	SetCoreVersion(id, name, "")
	return CoreVersion{
		ID:      id,
		Version: name,
		Path:    s.BinaryPath(spec),
		Size:    st.Size(),
		SavedAt: time.Now().Format(time.RFC3339),
		Current: true,
	}, nil
}

// copyFileAtomic writes src to dst through a temporary file in the destination
// directory, so a failure cannot leave a half-written core binary in place.
func copyFileAtomic(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".core-version-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return err
	}
	return os.Rename(tmpName, dst)
}
