package control

import (
	"io/fs"
	"path"
	"strings"
	"testing"
)

// TestEmbeddedWebCarriesNoBackupFiles guards both the size and the surface of
// the shipped console.
//
// //go:embed web takes the entire directory, so a *.bak left beside index.html
// during a patch round rides straight into the binary. Twenty-three of them once
// cost 4.89 MB - 50.77 MB instead of 45.88 MB - and put old console revisions
// into the embedded filesystem, where the file server could hand them out.
// Backups belong in lab/backups, not next to the source they back up.
func TestEmbeddedWebCarriesNoBackupFiles(t *testing.T) {
	suffixes := []string{".bak", ".orig", ".rej", ".tmp", ".swp", ".swo", "~"}
	var found []string
	err := fs.WalkDir(webFS, "web", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		name := strings.ToLower(path.Base(p))
		for _, s := range suffixes {
			if strings.HasSuffix(name, s) || strings.Contains(name, ".bak") {
				found = append(found, p)
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk embedded web assets: %v", err)
	}
	if len(found) > 0 {
		t.Errorf("%d backup file(s) are embedded in the console and would ship inside the binary:\n  %s",
			len(found), strings.Join(found, "\n  "))
	}
}
