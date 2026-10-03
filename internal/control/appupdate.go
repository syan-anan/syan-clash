package control

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"vvpn/internal/core"
)

// The about card answers "is there a newer build of this client?" with one
// request. There is no auto-install here on purpose: replacing a running exe is
// exactly the kind of thing that must stay a visible user action, so this file
// only reports what it found and where to get it.
//
// Two kinds of update channel are accepted, because a self-built client has no
// reason to be tied to one forge:
//
//   - a release manifest: any HTTPS URL returning a small JSON document
//   - a GitHub repository: "owner/name" or its full https://github.com/... URL
//
// The manifest shape is deliberately tiny:
//
//	{
//	  "version":   "0.2.0",
//	  "page":      "https://example.com/syan-clash/0.2.0",
//	  "asset":     "https://example.com/syan-clash-0.2.0.exe",
//	  "sha256":    "...",
//	  "notes":     "one line",
//	  "published": "2026-10-02T10:00:00Z"
//	}

const (
	appUpdateTimeout = 15 * time.Second
	appUpdateMaxBody = 256 << 10
	appUpdateTTL     = 10 * time.Minute
)

// appUpdateView is what the about card renders.
type appUpdateView struct {
	Current   string `json:"current"`
	Latest    string `json:"latest,omitempty"`
	Available bool   `json:"update_available"`
	Source    string `json:"source"`
	Kind      string `json:"kind,omitempty"`
	Asset     string `json:"asset,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	Page      string `json:"page,omitempty"`
	Notes     string `json:"notes,omitempty"`
	Published string `json:"published,omitempty"`
	CheckedAt string `json:"checked_at"`
	Error     string `json:"error,omitempty"`
}

// updateManifest is the JSON document a manifest-style channel serves.
type updateManifest struct {
	Version   string `json:"version"`
	Page      string `json:"page"`
	Asset     string `json:"asset"`
	SHA256    string `json:"sha256"`
	Notes     string `json:"notes"`
	Published string `json:"published"`
}

// githubRelease is the subset of the GitHub release API this needs.
type githubRelease struct {
	TagName     string        `json:"tag_name"`
	HTMLURL     string        `json:"html_url"`
	Body        string        `json:"body"`
	PublishedAt string        `json:"published_at"`
	Assets      []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

var (
	appUpdateMu    sync.Mutex
	appUpdateCache appUpdateView
	appUpdateKey   string
	appUpdateAt    time.Time
)

var githubRepoPattern = regexp.MustCompile("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")

// classifyUpdateSource decides which kind of channel a string names. It is
// deliberately strict: anything that is neither a usable http(s) URL nor a
// plausible repository is reported as unsupported rather than fetched.
func classifyUpdateSource(raw string) (kind, target string) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", ""
	}
	if !strings.Contains(s, "://") {
		if githubRepoPattern.MatchString(strings.TrimSuffix(s, "/")) {
			return "github", strings.TrimSuffix(s, "/")
		}
		return "invalid", s
	}
	lower := strings.ToLower(s)
	if strings.Contains(lower, "github.com/") {
		repo := s
		if i := strings.Index(lower, "github.com/"); i >= 0 {
			repo = s[i+len("github.com/"):]
		}
		repo = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(repo), "/"), ".git")
		if githubRepoPattern.MatchString(repo) {
			return "github", repo
		}
		return "invalid", s
	}
	if strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "http://") {
		return "manifest", s
	}
	return "invalid", s
}

// appUpdateClient is the HTTP client the check uses. The timeout covers the
// whole exchange: a version check that hangs is worse than one that fails.
func appUpdateClient() *http.Client {
	return &http.Client{Timeout: appUpdateTimeout}
}

// handleAppUpdate answers GET /api/app/update. The result is cached for ten
// minutes so a user clicking around cannot burn a rate limit; ?refresh=1 asks
// for a fresh look.
func (h *API) handleAppUpdate(w http.ResponseWriter, r *http.Request) {
	current := h.app.Status().Version
	source := strings.TrimSpace(h.app.UpdateSource())
	refresh := r.URL.Query().Get("refresh") != ""

	if source == "" {
		writeJSON(w, http.StatusOK, appUpdateView{
			Current:   current,
			Source:    "",
			CheckedAt: time.Now().Format(time.RFC3339),
			Error:     "未配置更新源：在设置页填入发布清单 URL 或 GitHub 仓库（owner/name）后再检查",
		})
		return
	}

	kind, target := classifyUpdateSource(source)
	if kind == "" || kind == "invalid" {
		writeJSON(w, http.StatusOK, appUpdateView{
			Current:   current,
			Source:    source,
			CheckedAt: time.Now().Format(time.RFC3339),
			Error:     "更新源无法识别：需要 http(s) 发布清单 URL，或 owner/name 形式的 GitHub 仓库",
		})
		return
	}

	key := kind + "|" + target + "|" + current
	appUpdateMu.Lock()
	if !refresh && appUpdateKey == key && time.Since(appUpdateAt) < appUpdateTTL {
		cached := appUpdateCache
		appUpdateMu.Unlock()
		writeJSON(w, http.StatusOK, cached)
		return
	}
	appUpdateMu.Unlock()

	ctx, cancel := context.WithTimeout(r.Context(), appUpdateTimeout)
	defer cancel()

	var view appUpdateView
	if kind == "github" {
		view = h.checkAppUpdateGitHub(ctx, current, source, target)
	} else {
		view = h.checkAppUpdateManifest(ctx, current, source, target)
	}

	appUpdateMu.Lock()
	// Only a completed lookup is cached; a failure is re-tried next time so a
	// transient network error does not stick for ten minutes.
	if view.Error == "" {
		appUpdateCache = view
		appUpdateKey = key
		appUpdateAt = time.Now()
	}
	appUpdateMu.Unlock()

	writeJSON(w, http.StatusOK, view)
}

func (h *API) checkAppUpdateManifest(ctx context.Context, current, source, target string) appUpdateView {
	view := appUpdateView{
		Current:   current,
		Source:    source,
		Kind:      "manifest",
		CheckedAt: time.Now().Format(time.RFC3339),
	}
	body, err := h.fetchUpdateDocument(ctx, target)
	if err != nil {
		view.Error = err.Error()
		return view
	}
	var m updateManifest
	if err := json.Unmarshal(body, &m); err != nil {
		view.Error = fmt.Sprintf("发布清单不是合法 JSON：%v", err)
		return view
	}
	latest := strings.TrimPrefix(strings.TrimSpace(m.Version), "v")
	if latest == "" {
		view.Error = "发布清单缺少 version 字段"
		return view
	}
	view.Latest = latest
	view.Page = strings.TrimSpace(m.Page)
	view.Asset = strings.TrimSpace(m.Asset)
	view.SHA256 = strings.ToLower(strings.TrimSpace(m.SHA256))
	view.Notes = strings.TrimSpace(m.Notes)
	view.Published = strings.TrimSpace(m.Published)
	view.Available = core.CompareVersions(latest, current) > 0
	return view
}

func (h *API) checkAppUpdateGitHub(ctx context.Context, current, source, repo string) appUpdateView {
	view := appUpdateView{
		Current:   current,
		Source:    source,
		Kind:      "github",
		CheckedAt: time.Now().Format(time.RFC3339),
	}
	url := "https://api.github.com/repos/" + repo + "/releases/latest"
	body, err := h.fetchUpdateDocument(ctx, url)
	if err != nil {
		view.Error = err.Error()
		return view
	}
	var rel githubRelease
	if err := json.Unmarshal(body, &rel); err != nil {
		view.Error = fmt.Sprintf("GitHub 返回的不是合法 JSON：%v", err)
		return view
	}
	latest := strings.TrimPrefix(strings.TrimSpace(rel.TagName), "v")
	if latest == "" {
		view.Error = "该仓库没有可用的 release"
		return view
	}
	view.Latest = latest
	view.Page = rel.HTMLURL
	view.Published = rel.PublishedAt
	view.Notes = firstLine(rel.Body)
	view.Asset = pickWindowsAsset(rel.Assets)
	view.Available = core.CompareVersions(latest, current) > 0
	return view
}

// pickWindowsAsset prefers an asset that is obviously this client's Windows
// build, then falls back to the shortest .exe. Vendors add suffixes for CPU
// levels and toolchains, and the plain name is the widely compatible one.
func pickWindowsAsset(assets []githubAsset) string {
	bestURL := ""
	bestName := ""
	bestRank := 0
	for _, a := range assets {
		name := strings.ToLower(a.Name)
		if !strings.HasSuffix(name, ".exe") {
			continue
		}
		rank := 1
		if strings.Contains(name, "windows") || strings.Contains(name, "win") {
			rank = 2
		}
		if strings.Contains(name, "syan-clash") || strings.Contains(name, "syanv") {
			rank = 3
		}
		// A CPU-level build (v1/v2/v3) only runs where that CPU generation is
		// present; the plain build is the widely compatible one. The core
		// updater drops those suffixes for the same reason.
		if strings.Contains(name, "-v1-") || strings.Contains(name, "-v2-") || strings.Contains(name, "-v3-") {
			rank--
		}
		if bestURL == "" || rank > bestRank || (rank == bestRank && len(a.Name) < len(bestName)) {
			bestURL = a.BrowserDownloadURL
			bestName = a.Name
			bestRank = rank
		}
	}
	return bestURL
}

// fetchUpdateDocument performs the one GET both channel kinds need, with the
// body capped so a hostile or broken endpoint cannot stream forever.
func (h *API) fetchUpdateDocument(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "syan-clash/"+h.app.Status().Version)
	req.Header.Set("Accept", "application/json, */*")
	resp, err := appUpdateClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求更新源失败：%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("更新源返回 %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, appUpdateMaxBody+1))
	if err != nil {
		return nil, fmt.Errorf("读取更新源失败：%w", err)
	}
	if len(body) > appUpdateMaxBody {
		return nil, fmt.Errorf("更新源文档超过 %d KiB", appUpdateMaxBody>>10)
	}
	return body, nil
}

// firstLine keeps a changelog short enough for a one-line notice.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}
