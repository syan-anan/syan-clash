package app

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"

	"vvpn/internal/config"
	"vvpn/internal/winsvc"
)

// The service block (P0-1). A Windows service is the only way to get a
// privileged helper that survives the client and does not ask for a UAC prompt
// on every launch. Everything here is deliberately optional: with no service
// installed the client behaves exactly as it did before the block existed.

// ProxyGuardEnabled reports whether the invisible system-proxy guard process
// should be kept alive while the system proxy is on.
func (a *App) ProxyGuardEnabled() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg.Service.ProxyGuardEnabled()
}

// SetProxyGuard records the switch.
//
// It writes the file first and only then updates memory, so a failed write
// leaves the running client consistent with what is on disk. It never goes
// through Reload: the switch changes no listener, and tearing every inbound
// down to flip a boolean would drop the user's traffic for nothing.
func (a *App) SetProxyGuard(on bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	// An explicit false has to be written even when the resolved answer is
	// already false, otherwise "off" would stay "never configured" (which
	// resolves to on) and the switch would appear to do nothing.
	if a.cfg.Service.ProxyGuard != nil && *a.cfg.Service.ProxyGuard == on {
		return nil
	}
	next := a.cfg
	v := on
	next.Service.ProxyGuard = &v
	if err := config.Save(a.cfgPath, next); err != nil {
		return err
	}
	a.cfg = next
	return nil
}

// SetProxyGuardRunning is called by the supervisor in cmd/desktop, which owns
// the guard's lifetime; the API only reads it.
func (a *App) SetProxyGuardRunning(on bool) {
	a.mu.Lock()
	a.guardRunning = on
	a.mu.Unlock()
}

// ProxyGuardRunning reports whether the guard copy is alive right now.
func (a *App) ProxyGuardRunning() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.guardRunning
}

// ServiceAddr is the loopback address the installed service listens on.
func (a *App) ServiceAddr() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg.Service.Addr
}

// ServiceToken is the shared secret the service requires on every request. An
// empty answer means the service was never installed; the caller must generate
// one with EnsureServiceToken before installing.
func (a *App) ServiceToken() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg.Service.Token
}

// EnsureServiceToken generates the client/service shared secret once and
// persists it, keeping the in-memory copy in step with the file.
func (a *App) EnsureServiceToken() (string, error) {
	token, err := EnsureServiceTokenAt(a.cfgPath)
	if err != nil {
		return "", err
	}
	a.mu.Lock()
	if a.cfg.Service.Token != token {
		a.cfg.Service.Token = token
	}
	a.mu.Unlock()
	return token, nil
}

// ServiceStatus is what the settings card renders. It never fails: a machine
// that cannot answer the service control manager gets Err filled in and the
// rest of the fields left at their zero values, because "the service is not
// installed" and "the service cannot be asked" are both normal states on a
// machine that never turned service mode on.
type ServiceStatus struct {
	Name       string `json:"name"`
	Supported  bool   `json:"supported"`
	Installed  bool   `json:"installed"`
	Running    bool   `json:"running"`
	State      string `json:"state"`
	StateLabel string `json:"state_label"`
	PID        uint32 `json:"pid,omitempty"`
	BinPath    string `json:"bin_path,omitempty"`
	AutoStart  bool   `json:"auto_start"`
	Addr       string `json:"addr"`
	TokenSet   bool   `json:"token_set"`
	ProxyGuard bool   `json:"proxy_guard"`
	Err        string `json:"err,omitempty"`
}

// ServiceStatus reports what the service control manager knows about the
// service, plus the two switches that live beside it.
func (a *App) ServiceStatus() ServiceStatus {
	st := ServiceStatus{
		Name:       winsvc.DefaultName,
		Supported:  runtime.GOOS == "windows",
		Addr:       a.ServiceAddr(),
		ProxyGuard: a.ProxyGuardEnabled(),
	}
	a.mu.Lock()
	st.TokenSet = a.cfg.Service.Token != ""
	a.mu.Unlock()
	if !st.Supported {
		st.Err = winsvc.ErrUnsupported.Error()
		return st
	}
	q, err := winsvc.Query(winsvc.DefaultName)
	if err != nil {
		st.Err = err.Error()
		return st
	}
	st.Installed = q.Installed
	st.State = q.State.String()
	st.StateLabel = q.State.Label()
	st.PID = q.PID
	st.BinPath = q.BinPath
	st.AutoStart = q.AutoStart
	st.Running = q.State == winsvc.StateRunning
	return st
}

// ServiceBinPath is the command line this instance would register the service
// with.
func (a *App) ServiceBinPath() (string, error) { return ServiceBinPathAt(a.cfgPath) }

// ServiceInstall registers the service. It requires administrator rights: the
// service control manager refuses CreateService for an unprivileged caller,
// which surfaces here as an access-denied error the UI turns into "以管理员身份
// 重新执行".
func (a *App) ServiceInstall() error {
	bin, err := a.ServiceBinPath()
	if err != nil {
		return err
	}
	// The token has to exist before the service does: the service refuses to
	// start without one, and a service that starts and then rejects every
	// request is worse than one that is not installed.
	if _, err := a.EnsureServiceToken(); err != nil {
		return err
	}
	return winsvc.Install(winsvc.InstallConfig{
		Name:        winsvc.DefaultName,
		DisplayName: "syan-clash 服务",
		Description: "syan-clash 的特权辅助服务：以系统身份托管代理内核，使 TUN 模式不必每次提权。",
		BinPath:     bin,
		AutoStart:   true,
	})
}

// ServiceUninstall stops and removes the service. Removing a service that is
// not installed is success, not an error: the button is idempotent so a user
// who clicks it twice does not get a failure message.
func (a *App) ServiceUninstall() error {
	if err := winsvc.Uninstall(winsvc.DefaultName); err != nil {
		return err
	}
	return nil
}

// ServiceStart asks the service control manager to start the service.
func (a *App) ServiceStart() error { return winsvc.Start(winsvc.DefaultName) }

// ServiceStop asks the service control manager to stop the service.
func (a *App) ServiceStop() error { return winsvc.Stop(winsvc.DefaultName) }

// ServiceLive reports whether the privileged helper is installed and running,
// which is the only state in which the client may delegate work to it.
func (a *App) ServiceLive() bool {
	if runtime.GOOS != "windows" {
		return false
	}
	st := a.ServiceStatus()
	return st.Installed && st.Running
}

// ServiceConfigPath is the configuration file this instance is running from.
// The service is told the same path so both halves read one file.
func (a *App) ServiceConfigPath() string { return a.cfgPath }

// EnsureServiceTokenAt generates the client/service shared secret for the
// configuration at path and writes it back. It is a free function because the
// elevated -service-install helper has to create the secret without starting a
// whole client, and it is idempotent so a second install never invalidates the
// copy a running service already holds.
func EnsureServiceTokenAt(cfgPath string) (string, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return "", err
	}
	if cfg.Service.Token != "" {
		return cfg.Service.Token, nil
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("生成服务密钥失败：%w", err)
	}
	cfg.Service.Token = hex.EncodeToString(buf)
	if err := config.Save(cfgPath, cfg); err != nil {
		return "", err
	}
	return cfg.Service.Token, nil
}

// ServiceBinPathAt is the command line the service is registered with. The
// running executable is the service host, which is what keeps the deployed
// service and the installed client from drifting apart after an update.
//
// Windows wants the program quoted and the arguments after it; the config path
// is quoted too, so a folder with spaces survives the round trip.
func ServiceBinPathAt(cfgPath string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("找不到本程序路径：%w", err)
	}
	return `"` + exe + `" -service -config "` + cfgPath + `"`, nil
}
