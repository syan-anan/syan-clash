package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"vvpn/internal/app"
	"vvpn/internal/config"
	"vvpn/internal/service"
	"vvpn/internal/winsvc"
)

// The privileged half of the client (P0-1).
//
// Windows asks for administrator rights for exactly the things a proxy client
// cannot do as a normal user - creating a TUN adapter above all - and the
// alternative to a UAC prompt on every launch is a service installed once. This
// file is that service: it runs no window, no tray icon and no console server,
// it only serves a tiny loopback command channel that the unprivileged client
// drives.
//
// Nothing here is reachable without the shared secret from config.json, and the
// channel only ever starts a program the caller names by absolute path, so the
// service cannot be turned into a general-purpose "run anything as SYSTEM".

// serviceLogger appends to a file next to the configuration. A service has no
// console and no window, so a file is the only place a failure can be seen.
func serviceLogger(cfgPath string) func(string, ...any) {
	path := filepath.Join(filepath.Dir(cfgPath), "syan-clash-service.log")
	return func(format string, args ...any) {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return
		}
		defer func() { _ = f.Close() }()
		fmt.Fprintf(f, "%s %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
	}
}

// runServiceWorker is the service body, shared by the SCM entry point and by
// -service-console (which exists so the same code can be driven in a terminal
// during testing, without installing anything).
func runServiceWorker(ctx context.Context, cfgPath, name string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("读取配置失败：%w", err)
	}
	if cfg.Service.Token == "" {
		return errors.New("配置里没有服务密钥：请先在客户端里安装服务（密钥在安装时生成）")
	}
	logf := serviceLogger(cfgPath)
	logf("服务启动 addr=%s version=%s pid=%d", cfg.Service.Addr, version, os.Getpid())

	srv := service.NewServer(cfg.Service.Addr, cfg.Service.Token, version, logf)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	srv.Shutdown = cancel

	if err := srv.Serve(runCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logf("服务异常退出：%v", err)
		return err
	}
	logf("服务已停止")
	return nil
}

// runServiceHost connects the worker to the service control manager.
func runServiceHost(cfgPath, name string) error {
	h := winsvc.Handler{
		Name: name,
		Run: func(ctx context.Context, report func(winsvc.State, string)) error {
			report(winsvc.StateRunning, "服务已就绪")
			return runServiceWorker(ctx, cfgPath, name)
		},
	}
	err := winsvc.Dispatch(h)
	if errors.Is(err, winsvc.ErrNotService) {
		return errors.New("本进程不是由服务控制管理器启动的；前台调试请用 -service-console")
	}
	return err
}

// printServiceStatus writes one JSON line and is what the lab checks with.
func printServiceStatus(name string) {
	out := map[string]any{"name": name}
	st, err := winsvc.Query(name)
	if err != nil {
		out["error"] = err.Error()
	} else {
		out["installed"] = st.Installed
		out["state"] = st.State.String()
		out["state_label"] = st.State.Label()
		out["pid"] = st.PID
		out["bin_path"] = st.BinPath
		out["auto_start"] = st.AutoStart
	}
	raw, _ := json.Marshal(out)
	fmt.Println(string(raw))
}

// installService registers the service. It runs in the elevated copy of this
// exe (started through the UAC prompt by the settings page, or run by hand from
// an administrator terminal); a normal client process cannot create a service.
func installService(cfgPath, name string) error {
	bin, err := app.ServiceBinPathAt(cfgPath)
	if err != nil {
		return err
	}
	// The secret has to exist before the service does: a service that starts
	// and then rejects every request is worse than one that is not installed.
	if _, err := app.EnsureServiceTokenAt(cfgPath); err != nil {
		return err
	}
	err = winsvc.Install(winsvc.InstallConfig{
		Name:        name,
		DisplayName: "syan-clash 服务",
		Description: "syan-clash 的特权辅助服务：以系统身份托管代理内核，使 TUN 模式不必每次提权。",
		BinPath:     bin,
		AutoStart:   true,
	})
	if errors.Is(err, winsvc.ErrExists) {
		fmt.Println("syan-clash 服务：已经安装过了，没有改动")
		return nil
	}
	if err != nil {
		return err
	}
	fmt.Println("syan-clash 服务：安装完成")
	return nil
}

// uninstallService removes the service. Removing one that is not installed is
// success: the button is idempotent.
func uninstallService(name string) error {
	if err := winsvc.Uninstall(name); err != nil {
		return err
	}
	fmt.Println("syan-clash 服务：已卸载")
	return nil
}
