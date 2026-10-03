package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// UpdateInfo describes whether a newer release of a core exists.
type UpdateInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Current   string `json:"current"`
	Latest    string `json:"latest"`
	Available bool   `json:"update_available"`
	Asset     string `json:"asset,omitempty"`
	Page      string `json:"page,omitempty"`
	Published string `json:"published,omitempty"`
	CheckedAt string `json:"checked_at"`
	Error     string `json:"error,omitempty"`
}

// assetMatcher picks the right release asset for a core on this platform.
type assetMatcher func(name string) bool

var assetMatchers = map[string]assetMatcher{
	"sing-box": func(n string) bool {
		return strings.Contains(n, "windows-amd64") && strings.HasSuffix(n, ".zip") && !strings.Contains(n, "legacy")
	},
	"mihomo": func(n string) bool {
		return strings.Contains(n, "windows-amd64") && strings.HasSuffix(n, ".zip") &&
			!strings.Contains(n, "compatible") && !strings.Contains(n, "go1") &&
			// mihomo also ships GOAMD64-level builds such as
			// "mihomo-windows-amd64-v3-v1.19.31.zip"; prefer the plain build.
			!strings.Contains(n, "-v1-") && !strings.Contains(n, "-v2-") && !strings.Contains(n, "-v3-")
	},
	"xray": func(n string) bool {
		return strings.EqualFold(n, "Xray-windows-64.zip")
	},
}

// githubRepo extracts "owner/name" from a repository URL.
func githubRepo(url string) string {
	trimmed := strings.TrimSuffix(strings.TrimSpace(url), "/")
	trimmed = strings.TrimPrefix(trimmed, "https://github.com/")
	return trimmed
}

var (
	updateCacheMu  sync.Mutex
	updateCache    = map[string]UpdateInfo{}
	updateCacheAt  = map[string]time.Time{}
	updateCacheTTL = 10 * time.Minute
)

// CheckUpdate asks GitHub for the newest release of one core. Results are
// cached briefly so the UI can poll without burning the anonymous rate limit.
func (s *Supervisor) CheckUpdate(ctx context.Context, id string) UpdateInfo {
	spec, ok := Lookup(id)
	if !ok {
		return UpdateInfo{ID: id, Error: "unknown core", CheckedAt: time.Now().Format(time.RFC3339)}
	}
	updateCacheMu.Lock()
	if cached, ok := updateCache[id]; ok && time.Since(updateCacheAt[id]) < updateCacheTTL {
		updateCacheMu.Unlock()
		return cached
	}
	updateCacheMu.Unlock()

	info := UpdateInfo{
		ID:        spec.ID,
		Name:      spec.Name,
		Current:   spec.Version,
		CheckedAt: time.Now().Format(time.RFC3339),
	}
	release, err := s.latestRelease(ctx, githubRepo(spec.Repo))
	if err != nil {
		info.Error = err.Error()
		return info
	}
	info.Latest = strings.TrimPrefix(release.TagName, "v")
	info.Page = release.HTMLURL
	info.Published = release.PublishedAt
	info.Available = compareVersions(info.Latest, spec.Version) > 0
	if matcher, ok := assetMatchers[spec.ID]; ok {
		best := ""
		for _, a := range release.Assets {
			if !matcher(a.Name) {
				continue
			}
			// Prefer the shortest matching name: vendors add suffixes for
			// CPU levels and build toolchains, and the plain name is the
			// widely compatible one.
			if best == "" || len(a.Name) < len(best) {
				best = a.Name
				info.Asset = a.BrowserDownloadURL
			}
		}
	}

	updateCacheMu.Lock()
	updateCache[id] = info
	updateCacheAt[id] = time.Now()
	updateCacheMu.Unlock()
	return info
}

// CheckAll checks every known core.
func (s *Supervisor) CheckAll(ctx context.Context) []UpdateInfo {
	out := make([]UpdateInfo, 0, len(Catalog))
	for _, spec := range Catalog {
		out = append(out, s.CheckUpdate(ctx, spec.ID))
	}
	return out
}

type githubRelease struct {
	TagName     string `json:"tag_name"`
	HTMLURL     string `json:"html_url"`
	PublishedAt string `json:"published_at"`
	Assets      []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Size               int64  `json:"size"`
	} `json:"assets"`
}

func (s *Supervisor) latestRelease(ctx context.Context, repo string) (githubRelease, error) {
	if repo == "" {
		return githubRelease{}, fmt.Errorf("core has no repository")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/repos/"+repo+"/releases/latest", nil)
	if err != nil {
		return githubRelease{}, err
	}
	req.Header.Set("User-Agent", "syan-clash/0.1")
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := s.dl.Do(req)
	if err != nil {
		return githubRelease{}, fmt.Errorf("query %s: %w", repo, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return githubRelease{}, fmt.Errorf("query %s: %s", repo, resp.Status)
	}
	var release githubRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&release); err != nil {
		return githubRelease{}, fmt.Errorf("query %s: %w", repo, err)
	}
	return release, nil
}

// InstallLatest downloads and installs the newest release of a core, then
// repoints the in-memory catalog so the UI shows the version actually present.
func (s *Supervisor) InstallLatest(ctx context.Context, id, mirror string) (UpdateInfo, error) {
	info := s.CheckUpdate(ctx, id)
	if info.Error != "" {
		return info, fmt.Errorf("core %s: %s", id, info.Error)
	}
	if !info.Available {
		return info, nil
	}
	if info.Asset == "" {
		return info, fmt.Errorf("core %s: release %s has no matching asset for this platform", id, info.Latest)
	}
	spec, _ := Lookup(id)
	// Reuse the normal download path, which handles mirrors and extraction.
	if err := s.installFrom(ctx, spec, info.Asset, mirror); err != nil {
		return info, err
	}
	SetCoreVersion(id, info.Latest, info.Asset)
	s.log.Infof("core %s: updated to %s", id, info.Latest)
	info.Current = info.Latest
	info.Available = false
	return info, nil
}

// installFrom downloads one explicit URL, trying mirrors as usual.
func (s *Supervisor) installFrom(ctx context.Context, spec CoreSpec, url, mirror string) error {
	if err := os.MkdirAll(s.Dir(spec.ID), 0o755); err != nil {
		return err
	}
	candidates := DownloadCandidates(url, mirror)
	failures := make([]string, 0, len(candidates))
	for i, source := range candidates {
		label := "direct"
		if i > 0 {
			label = "mirror"
		}
		s.log.Infof("core %s: downloading (%s) %s", spec.ID, label, source)
		if err := s.downloadAndExtract(ctx, spec, source); err != nil {
			failures = append(failures, fmt.Sprintf("%s (%s): %v", source, label, err))
			continue
		}
		return nil
	}
	return fmt.Errorf("core %s: all %d download sources failed:\n  %s",
		spec.ID, len(candidates), strings.Join(failures, "\n  "))
}

// SetCoreVersion repoints a catalog entry at the version that is now installed.
func SetCoreVersion(id, version, downloadURL string) {
	catalogMu.Lock()
	defer catalogMu.Unlock()
	for i := range Catalog {
		if Catalog[i].ID == id {
			Catalog[i].Version = version
			if downloadURL != "" {
				Catalog[i].DownloadURL = downloadURL
			}
			return
		}
	}
}

// CompareVersions is compareVersions for callers outside this package. The
// client's own update check compares the same dotted versions the core updater
// does, and two implementations of that would eventually disagree.
func CompareVersions(a, b string) int { return compareVersions(a, b) }

// compareVersions compares dotted version numbers; a leading "v" and any
// non-numeric suffix (such as "-beta.1") are ignored.
func compareVersions(a, b string) int {
	as := versionParts(a)
	bs := versionParts(b)
	for i := 0; i < len(as) || i < len(bs); i++ {
		var av, bv int
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		if av != bv {
			if av > bv {
				return 1
			}
			return -1
		}
	}
	return 0
}

func versionParts(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	// Drop pre-release suffixes like "-beta.1" or "+meta".
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	fields := strings.Split(v, ".")
	out := make([]int, 0, len(fields))
	for _, f := range fields {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil {
			break
		}
		out = append(out, n)
	}
	return out
}
