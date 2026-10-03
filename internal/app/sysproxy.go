package app

import (
	"os"
	"strings"

	"vvpn/internal/config"
	"vvpn/internal/sysproxy"
)

// Logf writes a line to the client's log bus.
func (a *App) Logf(format string, args ...any) { a.log.Infof(format, args...) }

// RestoreSystemProxyOnExit puts the OS proxy back the way it was found before
// the client shuts down.
//
// A system proxy left pointing at a port nothing listens on is the one failure
// mode a user cannot debug on their own - every browser simply stops working -
// so this runs on every exit path the client controls, not only when the
// switch is turned off by hand.
func (a *App) RestoreSystemProxyOnExit() {
	restored, err := sysproxy.Restore()
	if err != nil {
		a.log.Warnf("退出时还原系统代理失败：%v", err)
		return
	}
	if restored {
		a.log.Infof("退出时已还原系统代理设置")
	}
}

// cleanupLeftoverSystemProxy undoes a proxy that a previous run never got to
// restore. A crash or a "结束任务" leaves the registry pointing at our port
// with no process behind it, and the next launch is the only place left to fix
// that. A snapshot owned by a live process belongs to another running copy and
// is left alone.
func (a *App) cleanupLeftoverSystemProxy() {
	snap, ok := sysproxy.LoadSnapshot(sysproxy.StatePath())
	if !ok || !snap.Applied {
		return
	}
	if snap.PID == os.Getpid() || sysproxy.OwnerAlive(snap.PID) {
		return
	}
	restored, err := sysproxy.Restore()
	if err != nil {
		a.log.Warnf("清理上次遗留的系统代理失败：%v", err)
		return
	}
	if restored {
		a.log.Infof("上次运行遗留的系统代理已还原（pid=%d）", snap.PID)
	}
}

// SysProxyBypass is the ProxyOverride value the client would publish right now:
// the configured list, or the built-in default when the user never wrote one.
// The settings page shows this, so what it displays is exactly what a toggle
// would write.
func (a *App) SysProxyBypass() string {
	return sysproxy.BypassOrDefault(a.Config().SysProxy.BypassString())
}

// SysProxyBypassList is the user's own list, without the default folded in.
// An empty answer means "never configured"; the UI uses that to say so.
func (a *App) SysProxyBypassList() []string {
	list := a.Config().SysProxy.Bypass
	out := make([]string, 0, len(list))
	for _, item := range list {
		if v := strings.TrimSpace(item); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// SetSysProxyBypass stores a new ProxyOverride list and, when the system proxy
// is already on, republishes it immediately: the user edits the list from the
// settings page while the switch is on, and a value that only takes effect
// after an off/on cycle is a value that looks broken.
//
// A proxy owned by another program is left alone: the list is still saved, but
// nothing is written to the registry, because taking the setting over is a
// decision the user has to make on the toggle, not as a side effect of an edit.
func (a *App) SetSysProxyBypass(list []string) error {
	clean := make([]string, 0, len(list))
	for _, item := range list {
		if v := strings.TrimSpace(item); v != "" {
			clean = append(clean, v)
		}
	}
	a.mu.Lock()
	a.cfg.SysProxy.Bypass = clean
	cfg := a.cfg
	a.mu.Unlock()
	if err := config.Save(a.cfgPath, cfg); err != nil {
		return err
	}
	on, _, err := sysproxy.Current()
	if err != nil || !on {
		return nil
	}
	httpAddr, socksAddr := a.ActiveInbound()
	if owner, foreign := sysproxy.ForeignOwner(httpAddr, socksAddr); foreign {
		a.log.Warnf("系统代理当前由 %s 占用，绕过名单已保存，未写入注册表", owner)
		return nil
	}
	if err := sysproxy.EnableForced(httpAddr, socksAddr, cfg.SysProxy.BypassString(), false); err != nil {
		return err
	}
	a.log.Infof("系统代理绕过名单已更新：%s", sysproxy.BypassOrDefault(cfg.SysProxy.BypassString()))
	return nil
}
