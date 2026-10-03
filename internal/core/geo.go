package core

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Upstream locations of the geodata files the mihomo family loads before it
// accepts a configuration that references GEOIP / GEOSITE rules. All four live
// in one GitHub release, so a single mirror prefix works for every one of them.
const (
	GeoURLMMDB    = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb"
	GeoURLGeoSite = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat"
	GeoURLGeoIP   = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat"
	GeoURLASN     = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb"
)

const (
	// geoMaxSize caps one geodata download so a hostile or broken URL cannot
	// fill the disk. The largest of the four is under 20 MB today.
	geoMaxSize = 256 << 20
	// geoAttemptTimeout bounds one ordinary source, geoPatientTimeout is the
	// budget for the final source (which is allowed to be slow because after it
	// there is nothing left to try), and geoIdleTimeout drops a transfer that
	// produces nothing at all.
	geoAttemptTimeout = 3 * time.Minute
	geoPatientTimeout = 20 * time.Minute
	geoIdleTimeout    = 45 * time.Second
	// geoRateGrace is how long a paced attempt may run before its average rate
	// is judged; geoMinRate is the rate it has to beat to keep going.
	geoRateGrace = 25 * time.Second
	geoMinRate   = 48 << 10
)

// GeoAsset is one auxiliary data file a core loads at startup.
type GeoAsset struct {
	// Name is the file name inside the core's working directory, because that
	// is where the core looks for it.
	Name string
	// URL is the canonical upstream download URL.
	URL string
	// MinSize is the smallest plausible complete file: anything smaller is a
	// truncated download and has to be fetched again.
	MinSize int64
	// Kind selects the structural check: "mmdb" (MaxMind-style database) or
	// "dat" (v2ray geodata).
	Kind string
	// Optional marks a database that the configurations this client emits never
	// read. It is reported but not downloaded: between them, the two optional
	// files are 28 MB of a 40 MB first run.
	Optional bool
}

// GeoAssetsFor lists the geodata a core needs, keyed by core ID. A core that is
// absent from the map needs none.
var GeoAssetsFor = map[string][]GeoAsset{
	"mihomo": {
		{Name: "geoip.metadb", URL: GeoURLMMDB, MinSize: 3 << 20, Kind: "mmdb"},
		{Name: "geosite.dat", URL: GeoURLGeoSite, MinSize: 2 << 20, Kind: "dat"},
		// Only a configuration that turns on geodata-mode reads geoip.dat, and
		// only ASN rules read the ASN database; this client emits neither, and
		// a core that ever needs them still has geox-url pointing at a mirror.
		{Name: "geoip.dat", URL: GeoURLGeoIP, MinSize: 8 << 20, Kind: "dat", Optional: true},
		{Name: "GeoLite2-ASN.mmdb", URL: GeoURLASN, MinSize: 5 << 20, Kind: "mmdb", Optional: true},
	},
}

// GeoFileStatus is the UI-facing state of one geodata file.
type GeoFileStatus struct {
	Core     string `json:"core"`
	Name     string `json:"name"`
	Path     string `json:"path"`
	Present  bool   `json:"present"`
	OK       bool   `json:"ok"`
	Size     int64  `json:"size"`
	MinSize  int64  `json:"min_size"`
	Optional bool   `json:"optional"`
	Download string `json:"download_url,omitempty"`
}

// GeoStatus reports the geodata files of one core.
func (s *Supervisor) GeoStatus(id string) []GeoFileStatus {
	assets := GeoAssetsFor[id]
	out := make([]GeoFileStatus, 0, len(assets))
	for _, a := range assets {
		path := filepath.Join(s.Dir(id), a.Name)
		st := GeoFileStatus{Core: id, Name: a.Name, Path: path, MinSize: a.MinSize, Download: a.URL, Optional: a.Optional}
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			st.Present = true
			st.Size = info.Size()
			st.OK = geoFileValid(path, a)
		}
		out = append(out, st)
	}
	return out
}

// GeoReady reports whether every geodata file a core actually needs is present
// and intact. Optional files are reported but never gate this.
func (s *Supervisor) GeoReady(id string) bool {
	assets := GeoAssetsFor[id]
	if len(assets) == 0 {
		return true
	}
	for _, a := range assets {
		if a.Optional {
			continue
		}
		if !geoFileValid(filepath.Join(s.Dir(id), a.Name), a) {
			return false
		}
	}
	return true
}

// EnsureGeo makes sure every geodata file of a core is present and complete,
// fetching whatever is missing. It returns the names it had to download.
//
// mihomo downloads these itself on first use: from GitHub, with no mirror and a
// deadline that expires long before the transfer finishes on a restricted
// network. When that fails, its own configuration check fails with it and the
// core refuses to start with a bare "can't download MMDB". Fetching the files
// here means one clear failure mode, on the client's own terms, instead of a
// core that will not run.
func (s *Supervisor) EnsureGeo(ctx context.Context, id, mirror string) ([]string, error) {
	assets := GeoAssetsFor[id]
	if len(assets) == 0 {
		return nil, nil
	}
	dir := s.Dir(id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	// The four files together are tens of megabytes. A caller that runs out of
	// its own patience (the start button waits two minutes) must not cut the
	// transfer in half, so the download keeps a budget of its own.
	dlCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 45*time.Minute)
	defer cancel()

	fetched := make([]string, 0, len(assets))
	failures := make([]string, 0)
	for _, a := range assets {
		if a.Optional {
			continue
		}
		if geoFileValid(filepath.Join(dir, a.Name), a) {
			continue
		}
		if err := s.fetchGeo(dlCtx, dir, a, mirror); err != nil {
			failures = append(failures, fmt.Sprintf("%s（%v）", a.Name, err))
			continue
		}
		fetched = append(fetched, a.Name)
	}
	if len(failures) > 0 {
		return fetched, fmt.Errorf("地理数据下载失败：%s", strings.Join(failures, "；"))
	}
	return fetched, nil
}

// fetchGeo downloads one geodata file. Sources are tried best first: the
// user's own mirror, then the measured-fast built-in mirrors, and the canonical
// GitHub URL last. A source that is merely slow is dropped for the next one,
// and the final source gets a long patient attempt, so a working-but-glacial
// connection still finishes instead of hanging forever.
func (s *Supervisor) fetchGeo(ctx context.Context, dir string, a GeoAsset, mirror string) error {
	sources := geoDownloadSources(a.URL, mirror)
	failures := make([]string, 0, len(sources))
	for i, source := range sources {
		patient := i == len(sources)-1
		s.log.Infof("core: fetching %s（%s）%s", a.Name, source.label, source.url)
		written, err := s.downloadGeo(ctx, dir, a, source.url, patient)
		if err != nil {
			s.log.Warnf("core: %s via %s failed after %s: %v", a.Name, source.label, geoHumanBytes(written), err)
			failures = append(failures, fmt.Sprintf("%s: %v", source.label, err))
			continue
		}
		s.log.Infof("core: %s ready (%s)", a.Name, geoHumanBytes(geoFileSize(filepath.Join(dir, a.Name))))
		return nil
	}
	return fmt.Errorf("all %d sources failed: %s", len(sources), strings.Join(failures, "; "))
}

// geoSource is one place a geodata file can come from.
type geoSource struct {
	url   string
	label string
}

// geoDownloadSources lists every source for one geodata file, best first.
//
// The canonical URL is last on purpose: these files are exactly what the
// mirrors exist for, and a direct GitHub transfer can "work" while crawling.
// Measured from this network on 2026-09-30: GitHub delivered about 5 KB/s while
// gh-proxy.com delivered 460 KB/s — 40 minutes against 30 seconds for the same
// two databases.
func geoDownloadSources(canonical, userMirror string) []geoSource {
	sources := make([]geoSource, 0, len(DefaultMirrors)+2)
	if m := strings.TrimSpace(userMirror); m != "" {
		sources = append(sources, geoSource{JoinMirror(m, canonical), "自定义镜像"})
	}
	for _, m := range DefaultMirrors {
		if url := JoinMirror(m, canonical); url != canonical {
			sources = append(sources, geoSource{url, "镜像"})
		}
	}
	return append(sources, geoSource{canonical, "官方源"})
}

// downloadGeo streams one source into the core directory and reports how many
// bytes arrived. Unless patient is set, a source that cannot sustain geoMinRate
// is abandoned: waiting on a 5 KB/s transfer is not patience, it is a window
// that looks hung.
func (s *Supervisor) downloadGeo(ctx context.Context, dir string, a GeoAsset, source string, patient bool) (int64, error) {
	budget := geoAttemptTimeout
	if patient {
		budget = geoPatientTimeout
	}
	attemptCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	watchCtx, watch := newGeoWatchdog(attemptCtx, geoIdleTimeout, !patient)
	defer watch.stop()

	req, err := http.NewRequestWithContext(watchCtx, http.MethodGet, source, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "syan-clash/0.1")
	resp, err := s.geo.Do(req)
	if err != nil {
		return 0, geoTransferError("request", err, attemptCtx, watchCtx, watch, budget)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unexpected status %s", resp.Status)
	}
	tmp, err := os.CreateTemp(dir, ".geo-*.tmp")
	if err != nil {
		return 0, err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	written, err := io.Copy(tmp, io.LimitReader(watch.wrap(resp.Body), geoMaxSize))
	if err != nil {
		tmp.Close()
		return written, geoTransferError("transfer", err, attemptCtx, watchCtx, watch, budget)
	}
	if err := tmp.Close(); err != nil {
		return written, err
	}
	if !geoFileValid(tmpName, a) {
		return written, fmt.Errorf("downloaded file is not a valid %s database", a.Kind)
	}
	if err := os.Rename(tmpName, filepath.Join(dir, a.Name)); err != nil {
		return written, err
	}
	return written, nil
}

// geoTransferError says who gave up and why: the attempt clock, the watchdog
// (stalled or too slow) or the caller.
func geoTransferError(stage string, err error, attemptCtx, watchCtx context.Context, watch *geoWatchdog, budget time.Duration) error {
	switch {
	case attemptCtx.Err() != nil:
		return fmt.Errorf("%s: gave up after %s (%s received)", stage, budget, geoHumanBytes(watch.received()))
	case watchCtx.Err() != nil:
		if reason := watch.failure(); reason != "" {
			return fmt.Errorf("%s: %s (%s received)", stage, reason, geoHumanBytes(watch.received()))
		}
		return fmt.Errorf("%s: cancelled", stage)
	default:
		return fmt.Errorf("%s: %w", stage, err)
	}
}

// geoWatchdog aborts a transfer that stops moving, or that moves too slowly to
// ever finish. Both are failures that actually happen in the field: a mirror
// can answer and then go silent, and the canonical URL can accept the
// connection and then dribble kilobytes for as long as anyone lets it.
type geoWatchdog struct {
	cancel context.CancelFunc
	last   atomic.Int64
	bytes  atomic.Int64
	start  time.Time
	idle   time.Duration
	// paced enables the minimum-rate rule. The patient final attempt runs
	// without it: by then there is nothing better to switch to.
	paced bool

	mu     sync.Mutex
	reason string
}

func newGeoWatchdog(parent context.Context, idle time.Duration, paced bool) (context.Context, *geoWatchdog) {
	ctx, cancel := context.WithCancel(parent)
	w := &geoWatchdog{cancel: cancel, idle: idle, paced: paced, start: time.Now()}
	w.last.Store(w.start.UnixNano())
	go func() {
		tick := time.NewTicker(idle / 4)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				elapsed := time.Since(w.start)
				if time.Since(time.Unix(0, w.last.Load())) > w.idle {
					w.fail(fmt.Sprintf("stalled, no data for %s", w.idle))
					cancel()
					return
				}
				if w.paced && elapsed > geoRateGrace && w.bytes.Load() < int64(geoMinRate)*int64(elapsed.Seconds()) {
					w.fail(fmt.Sprintf("too slow, %s in %s", geoHumanBytes(w.bytes.Load()), elapsed.Round(time.Second)))
					cancel()
					return
				}
			}
		}
	}()
	return ctx, w
}

func (w *geoWatchdog) touch(n int) {
	w.bytes.Add(int64(n))
	w.last.Store(time.Now().UnixNano())
}

func (w *geoWatchdog) received() int64 { return w.bytes.Load() }

func (w *geoWatchdog) fail(reason string) {
	w.mu.Lock()
	if w.reason == "" {
		w.reason = reason
	}
	w.mu.Unlock()
}

func (w *geoWatchdog) failure() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.reason
}

// stop releases the watchdog and its context.
func (w *geoWatchdog) stop() { w.cancel() }

// wrap reports progress on every read, which is what keeps the watchdog quiet.
func (w *geoWatchdog) wrap(r io.Reader) io.Reader { return &geoReader{r: r, w: w} }

type geoReader struct {
	r io.Reader
	w *geoWatchdog
}

func (g *geoReader) Read(p []byte) (int, error) {
	n, err := g.r.Read(p)
	if n > 0 {
		g.w.touch(n)
	}
	return n, err
}

// geoFileValid reports whether a file is plausible as the given asset: big
// enough not to be truncated, and shaped like the format the core will parse.
// A misconfigured mirror that answers every request with an HTML page is the
// failure this catches.
func geoFileValid(path string, a GeoAsset) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Size() < a.MinSize {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 16)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	if n == 0 || bytes.Contains(head, []byte("<")) {
		return false
	}
	switch a.Kind {
	case "mmdb":
		// metacubex's databases and GeoLite2 both start with this prefix;
		// MaxMind's own container starts with the classic magic instead.
		return bytes.HasPrefix(head, []byte{0x00, 0x00, 0x01}) || bytes.HasPrefix(head, []byte{0xAB, 0xCD, 0xEF})
	case "dat":
		// v2ray geodata is a protobuf stream; field 1 is the country code.
		return head[0] == 0x0a
	}
	return true
}

func geoFileSize(path string) int64 {
	if info, err := os.Stat(path); err == nil {
		return info.Size()
	}
	return 0
}

func geoHumanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	value := float64(n)
	units := []string{"KB", "MB", "GB"}
	for _, u := range units {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f %s", value, u)
		}
	}
	return fmt.Sprintf("%.1f TB", value/unit)
}

// GeoHint explains a start failure that is really a missing geodata file, which
// is by far the most common reason a freshly installed core refuses to run on a
// network where GitHub is unreachable.
func GeoHint(id, text string) string {
	if len(GeoAssetsFor[id]) == 0 {
		return ""
	}
	low := strings.ToLower(text)
	for _, needle := range []string{"can't download mmdb", "cant download mmdb", "can't initial geoip", "download mmdb", "geo database", "geodata"} {
		if strings.Contains(low, needle) {
			return "\n提示：该内核启动前需要地理数据库（geoip / geosite），自动补全没有成功。请在内核页点『补全数据』重试，或在设置里换一个下载镜像（core.mirror）。"
		}
	}
	return ""
}
