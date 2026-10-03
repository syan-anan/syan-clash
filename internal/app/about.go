package app

import "path/filepath"

// The about card is the one place that answers "which build is this, and what is
// it made of?". Everything here is read-only state the app already has, plus the
// facts the desktop shell registers through SetHostInfo.

// SetHostInfo records one fact about the host the shell embedded, such as the
// WebView2 runtime version. An empty key or value is ignored rather than stored,
// so a shell that cannot read a version does not leave a blank row behind.
func (a *App) SetHostInfo(key, value string) {
	if key == "" || value == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.hostInfo == nil {
		a.hostInfo = map[string]string{}
	}
	a.hostInfo[key] = value
}

// HostInfo returns a copy of the shell-reported facts.
func (a *App) HostInfo() map[string]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.hostInfo) == 0 {
		return nil
	}
	out := make(map[string]string, len(a.hostInfo))
	for k, v := range a.hostInfo {
		out[k] = v
	}
	return out
}

// SetBuild records the build stamp the linker embedded.
func (a *App) SetBuild(stamp, commit string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.buildStamp, a.buildCommit = stamp, commit
}

// Build returns the build stamp and the build identifier, either of which may be
// empty when the binary was produced by a plain "go build".
func (a *App) Build() (string, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.buildStamp, a.buildCommit
}

// DataDir is the folder holding the configuration and everything the client
// keeps beside it. It is what a user copies to move their setup elsewhere.
func (a *App) DataDir() string { return filepath.Dir(a.cfgPath) }

// LogDir is where an exported log lands and where the console's 日志 page
// points. It is derived here, once, so the tray menu, the 设置 page and the
// export endpoint can never disagree about the folder.
func (a *App) LogDir() string { return filepath.Join(a.DataDir(), "logs") }
