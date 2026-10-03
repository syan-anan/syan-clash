package core

import (
	"archive/zip"
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"vvpn/internal/logbus"
	"vvpn/internal/wintun"
)

// maxArchiveSize caps a core download so a bad URL cannot fill the disk.
const maxArchiveSize = 300 << 20

// Supervisor owns the external core processes: it compiles their native
// configuration, installs their binaries and keeps them running.
type Supervisor struct {
	root string
	log  *logbus.Bus

	mu    sync.Mutex
	procs map[string]*instance
	// restarts counts consecutive automatic relaunches of a core, so a core
	// that cannot stay up is reported instead of being restarted forever.
	restarts map[string]int
	// watchdog relaunches a core that died on its own; the client turns it off
	// for one-shot runs.
	watchdog    bool
	maxRestarts int

	api *http.Client
	dl  *http.Client
	// geo is the client for the geodata databases. It differs from dl on
	// purpose: geodata come from mirrors of wildly uneven speed, so the
	// transfer is bounded by a per-attempt clock and an idle watchdog rather
	// than one long timeout.
	geo *http.Client
}

type instance struct {
	spec       CoreSpec
	cmd        *exec.Cmd
	configPath string
	clashAPI   string
	secret     string
	started    time.Time
	done       chan struct{}

	// profile is the description this run was compiled from. The watchdog
	// reuses it, which is what keeps a relaunched core on exactly the same
	// configuration as the one that died.
	profile Profile

	mu      sync.Mutex
	exitErr string
	// wantRunning is cleared once the core is stopped deliberately: the
	// watchdog must never fight a stop the user asked for.
	wantRunning bool
}

func (i *instance) setExitError(err error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if err == nil {
		i.exitErr = "exited cleanly"
		return
	}
	i.exitErr = err.Error()
}

func (i *instance) lastError() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.exitErr
}

func (i *instance) setWantRunning(v bool) {
	i.mu.Lock()
	i.wantRunning = v
	i.mu.Unlock()
}

func (i *instance) wanted() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.wantRunning
}

// CoreStatus is the UI-facing state of one known core.
type CoreStatus struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Repo       string `json:"repo"`
	License    string `json:"license"`
	Version    string `json:"version"`
	Installed  bool   `json:"installed"`
	Running    bool   `json:"running"`
	PID        int    `json:"pid,omitempty"`
	BinaryPath string `json:"binary_path"`
	ConfigPath string `json:"config_path,omitempty"`
	ClashAPI   string `json:"clash_api,omitempty"`
	APIStatus  string `json:"api_status,omitempty"`
	StartedAt  string `json:"started_at,omitempty"`
	UptimeSec  int64  `json:"uptime_sec,omitempty"`
	Restarts   int    `json:"restarts,omitempty"`
	LastError  string `json:"last_error,omitempty"`
	Emitter    bool   `json:"emitter_ready"`
	Notes      string `json:"notes,omitempty"`
}

// NewSupervisor creates a supervisor rooted at dir, where each core gets its
// own subdirectory holding the binary, the generated config and its cache.
func NewSupervisor(dir string, log *logbus.Bus) *Supervisor {
	return &Supervisor{
		root:        dir,
		log:         log,
		procs:       make(map[string]*instance),
		restarts:    make(map[string]int),
		watchdog:    true,
		maxRestarts: maxAutoRestarts,
		api:         &http.Client{Timeout: 3 * time.Second},
		dl:          &http.Client{Timeout: 15 * time.Minute},
		geo: &http.Client{Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			ForceAttemptHTTP2:     true,
		}},
	}
}

// Root is the directory holding all core working directories.
func (s *Supervisor) Root() string { return s.root }

// Dir is the working directory of one core.
func (s *Supervisor) Dir(id string) string { return filepath.Join(s.root, id) }

// BinaryPath is where the core executable is expected to live.
func (s *Supervisor) BinaryPath(spec CoreSpec) string {
	return filepath.Join(s.Dir(spec.ID), spec.Binary)
}

// Installed reports whether the core binary is present on disk.
func (s *Supervisor) Installed(spec CoreSpec) bool {
	st, err := os.Stat(s.BinaryPath(spec))
	return err == nil && !st.IsDir()
}

// Compile renders the profile into the core's native configuration and writes
// it into the core's working directory.
func (s *Supervisor) Compile(id string, p Profile) (string, []byte, error) {
	spec, ok := Lookup(id)
	if !ok {
		return "", nil, fmt.Errorf("core: unknown core %q", id)
	}
	raw, warnings, err := RenderWithWarnings(id, p)
	if err != nil {
		return "", nil, err
	}
	for _, w := range warnings {
		s.log.Warnf("core %s: %s", id, w)
	}

	dir := s.Dir(id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", nil, err
	}
	path := filepath.Join(dir, spec.ConfigName)
	if err := writeFileAtomic(path, raw); err != nil {
		return "", nil, err
	}
	return path, raw, nil
}

// Render compiles a profile into the core's native configuration bytes without
// touching the disk.
func Render(id string, p Profile) ([]byte, error) {
	raw, _, err := RenderWithWarnings(id, p)
	return raw, err
}

// RenderWithWarnings also returns notes about anything the target core cannot
// represent, so the caller can tell the user instead of silently dropping it.
func RenderWithWarnings(id string, p Profile) ([]byte, []string, error) {
	spec, ok := Lookup(id)
	if !ok {
		return nil, nil, fmt.Errorf("core: unknown core %q", id)
	}
	switch spec.Emitter {
	case "sing-box":
		doc, warnings, err := EmitSingBoxWithWarnings(p)
		if err != nil {
			return nil, nil, err
		}
		raw, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return nil, nil, err
		}
		return append(raw, '\n'), warnings, nil
	case "mihomo":
		doc, err := EmitMihomo(p)
		if err != nil {
			return nil, nil, err
		}
		return []byte(yamlEmit(doc)), nil, nil
	case "xray":
		doc, warnings, err := EmitXrayWithWarnings(p)
		if err != nil {
			return nil, nil, err
		}
		raw, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return nil, nil, err
		}
		return append(raw, '\n'), warnings, nil
	case "":
		return nil, nil, fmt.Errorf("core: %s has no configuration emitter yet; see docs/REUSE.md", id)
	default:
		return nil, nil, fmt.Errorf("core: unknown emitter %q for %s", spec.Emitter, id)
	}
}

// Check runs the core's own validator, which is the only authority on whether
// a generated document is actually valid for that core.
func (s *Supervisor) Check(id, configPath string) (string, error) {
	spec, ok := Lookup(id)
	if !ok {
		return "", fmt.Errorf("core: unknown core %q", id)
	}
	if !s.Installed(spec) {
		return "", fmt.Errorf("core: %s is not installed (%s)", id, s.BinaryPath(spec))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.BinaryPath(spec), expandArgs(spec.CheckArgs, configPath, s.Dir(id))...)
	cmd.Dir = s.Dir(id)
	hideWindow(cmd)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("core: %s rejected the configuration: %w: %s%s", id, err, text, GeoHint(id, text))
	}
	return text, nil
}

// Install downloads the pinned release archive and extracts the core binary.
// mirror, when set, is tried before the canonical URL; the built-in mirror list
// is tried after it, because the GitHub release CDN is often unreachable.
func (s *Supervisor) Install(ctx context.Context, id, mirror string) error {
	spec, ok := Lookup(id)
	if !ok {
		return fmt.Errorf("core: unknown core %q", id)
	}
	if spec.DownloadURL == "" {
		return fmt.Errorf("core: %s has no pinned download URL", id)
	}
	if err := os.MkdirAll(s.Dir(id), 0o755); err != nil {
		return err
	}

	candidates := DownloadCandidates(spec.DownloadURL, mirror)
	failures := make([]string, 0, len(candidates))
	for i, source := range candidates {
		label := "direct"
		if i > 0 {
			label = "mirror"
		}
		s.log.Infof("core %s: downloading (%s) %s", id, label, source)
		if err := s.downloadAndExtract(ctx, spec, source); err != nil {
			s.log.Warnf("core %s: %s source failed: %v", id, label, err)
			failures = append(failures, fmt.Sprintf("%s (%s): %v", source, label, err))
			continue
		}
		s.log.Infof("core %s: installed %s", id, s.BinaryPath(spec))
		// The binary alone is not enough: a core whose configuration mentions
		// GEOIP/GEOSITE also needs its databases, and fetching them now means
		// the first start is not the moment the user discovers they are gone.
		if _, err := s.EnsureGeo(ctx, id, mirror); err != nil {
			s.log.Warnf("core %s: %v", id, err)
		}
		return nil
	}
	return fmt.Errorf("core %s: all %d download sources failed:\n  %s",
		id, len(candidates), strings.Join(failures, "\n  "))
}

// downloadAndExtract fetches one archive URL and writes the core executable.
func (s *Supervisor) downloadAndExtract(ctx context.Context, spec CoreSpec, source string) error {
	id := spec.ID
	dir := s.Dir(id)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return err
	}
	resp, err := s.dl.Do(req)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %s", resp.Status)
	}

	tmp, err := os.CreateTemp(dir, "download-*.zip")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	n, err := io.Copy(tmp, io.LimitReader(resp.Body, maxArchiveSize))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	s.log.Infof("core %s: downloaded %d bytes, extracting", id, n)

	zr, err := zip.OpenReader(tmpName)
	if err != nil {
		return fmt.Errorf("%s is not a zip archive: %w", source, err)
	}
	defer zr.Close()

	extracted := false
	// Archive entry names differ per core and release: sing-box ships
	// "sing-box.exe", mihomo ships "mihomo-windows-amd64.exe". Prefer an exact
	// match, otherwise take the first executable named after the core.
	entry := findBinary(zr.File, spec.Binary, spec.ID, true)
	if entry == nil {
		entry = findBinary(zr.File, spec.Binary, spec.ID, false)
	}
	if entry != nil {
		f := entry
		// Park the binary that is live right now so this update can be undone
		// without another download (see ActivateCoreVersion).
		if _, err := s.archiveCurrent(spec); err != nil {
			return fmt.Errorf("archive previous core: %w", err)
		}
		if err := extractZipFile(f, s.BinaryPath(spec)); err != nil {
			return fmt.Errorf("extract %s: %w", f.Name, err)
		}
		extracted = true
	}
	if !extracted {
		return fmt.Errorf("archive contains no %s", spec.Binary)
	}
	return nil
}

// findBinary looks for the core executable inside an archive. When exact is
// true only an exact base-name match counts; otherwise the first executable
// whose name starts with the core ID is accepted.
func findBinary(files []*zip.File, binary, id string, exact bool) *zip.File {
	want := strings.ToLower(binary)
	prefix := strings.ToLower(id)
	for _, f := range files {
		if f.FileInfo().IsDir() {
			continue
		}
		base := strings.ToLower(filepath.Base(f.Name))
		if exact {
			if base == want {
				return f
			}
			continue
		}
		if !strings.HasSuffix(base, ".exe") || !strings.HasPrefix(base, prefix) {
			continue
		}
		return f
	}
	return nil
}

// Start compiles the profile, validates it with the core's own checker, runs
// the core as a child process and waits for its control API to answer.
func (s *Supervisor) Start(ctx context.Context, id string, p Profile) (CoreStatus, error) {
	spec, ok := Lookup(id)
	if !ok {
		return CoreStatus{}, fmt.Errorf("core: unknown core %q", id)
	}
	if !s.Installed(spec) {
		return s.StatusFor(id), fmt.Errorf("core: %s is not installed; run install first", id)
	}
	s.mu.Lock()
	_, already := s.procs[id]
	s.mu.Unlock()
	if already {
		return s.StatusFor(id), fmt.Errorf("core: %s is already running", id)
	}

	// TUN mode loads a kernel driver through wintun.dll, which has to sit
	// next to the core executable. Release the embedded, hash-pinned copy
	// before the core starts so a missing driver cannot surface later as an
	// opaque core crash.
	if profileHasTun(p) {
		if _, err := wintun.Ensure(s.Dir(id)); err != nil {
			return s.StatusFor(id), err
		}
	}

	configPath, _, err := s.Compile(id, p)
	if err != nil {
		return s.StatusFor(id), err
	}
	// A configuration that mentions GEOIP/GEOSITE will not load until those
	// databases exist. Fetch them through the client's own mirrors first, so
	// the core's checker does not have to reach GitHub from a network that
	// cannot.
	if _, err := s.EnsureGeo(ctx, id, p.GeoMirror); err != nil {
		s.log.Warnf("core %s: %v", id, err)
	}
	if _, err := s.Check(id, configPath); err != nil {
		return s.StatusFor(id), err
	}

	// A core left behind by an earlier run would hold the control port and the
	// inbound ports, so refuse to start a second one instead of silently
	// producing a broken instance.
	if spec.ClashAPI && p.ClashAPI != "" {
		if version, verr := s.queryVersion(p.ClashAPI, p.ClashSecret); verr == nil {
			return s.StatusFor(id), fmt.Errorf(
				"core %s: control address %s is already answering (%s); another core (probably left over from a previous run) is still running",
				id, p.ClashAPI, version)
		}
	}

	cmd := exec.Command(s.BinaryPath(spec), expandArgs(spec.RunArgs, configPath, s.Dir(id))...)
	cmd.Dir = s.Dir(id)
	hideWindow(cmd)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return s.StatusFor(id), err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return s.StatusFor(id), err
	}
	if err := cmd.Start(); err != nil {
		return s.StatusFor(id), fmt.Errorf("core %s: start: %w", id, err)
	}
	// Tie the child to this process so a force-killed console cannot orphan it.
	if err := attachToJob(cmd); err != nil {
		s.log.Warnf("core %s: could not tie the child process to this console (%v); it will survive a crash and must be stopped manually", id, err)
	}

	inst := &instance{
		spec:        spec,
		cmd:         cmd,
		configPath:  configPath,
		clashAPI:    p.ClashAPI,
		secret:      p.ClashSecret,
		started:     time.Now(),
		done:        make(chan struct{}),
		profile:     p,
		wantRunning: true,
	}
	s.mu.Lock()
	s.procs[id] = inst
	s.mu.Unlock()

	s.log.Infof("core %s: started pid %d with %s", id, cmd.Process.Pid, configPath)
	go s.pump(id, stdout)
	go s.pump(id, stderr)
	go s.reap(id, inst)

	if spec.ClashAPI && p.ClashAPI != "" {
		version, err := s.waitForAPI(ctx, p.ClashAPI, p.ClashSecret, 10*time.Second)
		if err != nil {
			select {
			case <-inst.done:
				return s.StatusFor(id), fmt.Errorf("core %s: exited right after start: %s", id, inst.lastError())
			default:
			}
			s.log.Warnf("core %s: control API %s not answering: %v", id, p.ClashAPI, err)
		} else {
			s.log.Infof("core %s: control API ready, version %s", id, version)
		}
	}
	return s.StatusFor(id), nil
}

// Stop terminates a running core.
func (s *Supervisor) Stop(id string) error {
	s.mu.Lock()
	inst, ok := s.procs[id]
	s.mu.Unlock()
	if !ok {
		return nil
	}
	// A stop is deliberate: the watchdog must not bring the core back, and the
	// next start gets a fresh restart budget.
	inst.setWantRunning(false)
	s.mu.Lock()
	delete(s.restarts, id)
	s.mu.Unlock()
	if inst.cmd.Process != nil {
		_ = inst.cmd.Process.Kill()
	}
	select {
	case <-inst.done:
		return nil
	case <-time.After(10 * time.Second):
		return fmt.Errorf("core: %s did not exit after kill", id)
	}
}

// StopAll terminates every running core.
func (s *Supervisor) StopAll() {
	s.mu.Lock()
	ids := make([]string, 0, len(s.procs))
	for id := range s.procs {
		ids = append(ids, id)
	}
	s.mu.Unlock()
	for _, id := range ids {
		if err := s.Stop(id); err != nil {
			s.log.Warnf("core %s: %v", id, err)
		}
	}
}

// Status lists every known core.
func (s *Supervisor) Status() []CoreStatus {
	entries := CatalogEntries()
	out := make([]CoreStatus, 0, len(entries))
	for _, spec := range entries {
		out = append(out, s.statusFor(spec))
	}
	return out
}

// StatusFor returns the state of one core.
func (s *Supervisor) StatusFor(id string) CoreStatus {
	spec, ok := Lookup(id)
	if !ok {
		return CoreStatus{ID: id, LastError: "unknown core"}
	}
	return s.statusFor(spec)
}

func (s *Supervisor) statusFor(spec CoreSpec) CoreStatus {
	st := CoreStatus{
		ID:         spec.ID,
		Name:       spec.Name,
		Repo:       spec.Repo,
		License:    spec.License,
		Version:    spec.Version,
		Installed:  s.Installed(spec),
		BinaryPath: s.BinaryPath(spec),
		Emitter:    spec.Emitter != "",
		Notes:      spec.Notes,
	}
	s.mu.Lock()
	inst, running := s.procs[spec.ID]
	st.Restarts = s.restarts[spec.ID]
	s.mu.Unlock()
	if !running {
		return st
	}
	st.Running = true
	st.ConfigPath = inst.configPath
	st.ClashAPI = inst.clashAPI
	st.StartedAt = inst.started.Format(time.RFC3339)
	st.UptimeSec = int64(time.Since(inst.started).Seconds())
	if inst.cmd.Process != nil {
		st.PID = inst.cmd.Process.Pid
	}
	return st
}

// ControlAPI reports the Clash-compatible control address of a running core,
// which is what the UI uses to talk to it.
func (s *Supervisor) ControlAPI(id string) (addr, secret string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inst, running := s.procs[id]
	if !running || inst.clashAPI == "" {
		return "", "", false
	}
	return inst.clashAPI, inst.secret, true
}

// ClashVersion queries a running core's Clash-compatible control API.
func (s *Supervisor) ClashVersion(apiAddr, secret string) (string, error) {
	return s.queryVersion(apiAddr, secret)
}

func (s *Supervisor) queryVersion(apiAddr, secret string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, "http://"+apiAddr+"/version", nil)
	if err != nil {
		return "", err
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := s.api.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %s", resp.Status)
	}
	var body struct {
		Version string `json:"version"`
		Meta    bool   `json:"meta"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&body); err != nil {
		return "", err
	}
	if body.Version == "" {
		return "", errors.New("empty version in API response")
	}
	return body.Version, nil
}

func (s *Supervisor) waitForAPI(ctx context.Context, apiAddr, secret string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		version, err := s.queryVersion(apiAddr, secret)
		if err == nil {
			return version, nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			return "", lastErr
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (s *Supervisor) pump(id string, r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		s.log.Infof("[%s] %s", id, line)
	}
}

func (s *Supervisor) reap(id string, inst *instance) {
	err := inst.cmd.Wait()
	s.mu.Lock()
	if cur, ok := s.procs[id]; ok && cur == inst {
		delete(s.procs, id)
	}
	s.mu.Unlock()
	inst.setExitError(err)
	if err != nil {
		s.log.Warnf("core %s: exited: %v", id, err)
	} else {
		s.log.Infof("core %s: exited cleanly", id)
	}
	close(inst.done)
	s.maybeRestart(id, inst)
}

const (
	// restartHealthyAfter is how long a run has to last before the restart
	// budget is considered fresh again: a core that dies once an hour is an
	// accident, a core that dies every two seconds is a crash loop.
	restartHealthyAfter = 5 * time.Minute
	// maxAutoRestarts bounds the consecutive relaunches of one core.
	maxAutoRestarts = 5
)

// SetWatchdog turns the automatic relaunch of crashed cores on or off.
func (s *Supervisor) SetWatchdog(on bool) {
	s.mu.Lock()
	s.watchdog = on
	s.mu.Unlock()
}

// maybeRestart is the watchdog: a core that was asked to run but is no longer
// there gets started again, with growing backoff and on the very profile it
// died with - the compiled configuration on disk is not touched, so a
// relaunched core keeps its node selection and rules.
func (s *Supervisor) maybeRestart(id string, inst *instance) {
	if !inst.wanted() {
		return
	}
	// A profile with a TUN inbound is never relaunched automatically. Creating
	// the virtual adapter makes Windows enumerate a PnP device, and a crash
	// loop would therefore turn into a storm of device-arrival notifications
	// flickering across the screen - the exact behaviour this client must not
	// have. A failed tunnel start is reported and left for the user to retry.
	if profileHasTun(inst.profile) {
		s.log.Errorf("内核 %s 带 TUN 入站且已退出：不自动拉起（避免反复创建虚拟网卡），请在内核页手动启动", id)
		return
	}
	s.mu.Lock()
	watchdog, max := s.watchdog, s.maxRestarts
	if time.Since(inst.started) >= restartHealthyAfter {
		s.restarts[id] = 0
	}
	attempt := s.restarts[id] + 1
	s.restarts[id] = attempt
	s.mu.Unlock()
	if !watchdog {
		return
	}
	if attempt > max {
		s.log.Errorf("内核 %s 连续 %d 次异常退出，已停止自动拉起（可在内核页手动启动）", id, max)
		return
	}
	s.log.Warnf("内核 %s 已退出，看门狗 %s 后自动拉起（第 %d/%d 次）", id, restartBackoff(attempt), attempt, max)
	go s.restartLoop(id, inst.profile, attempt)
}

// restartLoop relaunches a core after this attempt's backoff. A failed start is
// retried here too: no process exists to reap, so the watchdog would otherwise
// never get a second chance.
func (s *Supervisor) restartLoop(id string, p Profile, attempt int) {
	select {
	case <-time.After(restartBackoff(attempt)):
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	st, err := s.Start(ctx, id, p)
	if err == nil {
		s.log.Infof("内核 %s 已自动拉起（pid %d，第 %d 次尝试）", id, st.PID, attempt)
		return
	}
	s.log.Errorf("内核 %s 第 %d 次自动拉起失败：%v", id, attempt, err)
	s.mu.Lock()
	watchdog, max := s.watchdog, s.maxRestarts
	if next := attempt + 1; next > s.restarts[id] {
		s.restarts[id] = next
	}
	next := s.restarts[id]
	s.mu.Unlock()
	if !watchdog || next > max {
		s.log.Errorf("内核 %s 自动拉起次数已用尽（%d 次），停止重试", id, max)
		return
	}
	go s.restartLoop(id, p, next)
}

// restartBackoff is the pause before the n-th relaunch: 1s, 2s, 4s ... capped
// at 30s, so a core that is still releasing its ports is not hammered.
func restartBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 6 {
		return 30 * time.Second
	}
	return time.Second << uint(attempt-1)
}

func extractZipFile(f *zip.File, dest string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	// #nosec G304 -- dest is derived from the fixed catalog entry, not user input.
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, rc); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".write-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// expandArgs substitutes the {config} and {dir} placeholders used by the core
// catalog.
func expandArgs(args []string, configPath, dir string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		a = strings.ReplaceAll(a, "{config}", configPath)
		a = strings.ReplaceAll(a, "{dir}", dir)
		out = append(out, a)
	}
	return out
}

// profileHasTun reports whether a profile routes through a TUN device, which
// is the signal that the core needs wintun.dll in its own directory.
func profileHasTun(p Profile) bool {
	for _, in := range p.Inbounds {
		if in.Type == InboundTun {
			return true
		}
	}
	return false
}
