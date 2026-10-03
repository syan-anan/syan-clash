package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"vvpn/internal/autostart"
	"vvpn/internal/shellopen"
	"vvpn/internal/tray"
)

// traySnapshot is everything the tray menu and the tooltip need. The menu is
// built on the tray's own thread, so reading it must never block: the snapshot
// is filled by a background refresher and the menu only ever reads the cache.
type traySnapshot struct {
	mode        string // rule | global | direct
	proxyOn     bool
	coreRunning bool
	coreID      string
	conns       int
	rules       int
	subs        int
	autostart   bool
	tun         bool
	lastError   string
}

// trayState guards the snapshot.
type trayState struct {
	mu   sync.Mutex
	snap traySnapshot
}

func (s *trayState) get() traySnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snap
}

func (s *trayState) update(fn func(*traySnapshot)) {
	s.mu.Lock()
	fn(&s.snap)
	s.mu.Unlock()
}

// RunTray puts an icon in the notification area and keeps it in sync with the
// running state. It blocks until the icon is closed, so callers run it on its
// own goroutine.
//
// The tray owns the lifetime of the client: closing the window is not an exit
// (every desktop proxy client behaves this way), which is why onOpenWindow
// exists - the menu and a left click bring the window back. onQuit is what
// actually stops the program.
//
// The menu is rebuilt every time it opens, so it always shows the mode and the
// master switch as they are right now, the same way Clash Verge's tray does.
func (a *App) RunTray(ctx context.Context, consoleAddr string, onOpenWindow func(), onQuit func()) {
	// The console lives in the client's own embedded window, so the tray has
	// no URL to open any more; the parameter stays in the signature because
	// cmd/desktop passes it and the tray is the only other caller of the
	// window opener.
	_ = consoleAddr
	openWindow := func() {
		// The console belongs in the client's own window. There is no
		// external-browser fallback any more: a browser window popping up on
		// the user is exactly the failure mode this client must not have.
		if onOpenWindow != nil {
			onOpenWindow()
			return
		}
		a.log.Warnf("托盘：没有窗口可打开（当前运行方式禁用了窗口）")
	}
	quit := func() {
		if onQuit != nil {
			onQuit()
			return
		}
		tray.Quit()
	}

	st := &trayState{}
	st.update(func(s *traySnapshot) {
		s.mode = "rule"
		s.coreID = a.Config().Core.ID
		s.subs = len(a.Subscriptions())
		if enabled, _ := autostart.Enabled(); enabled {
			s.autostart = true
		}
	})

	// ensureCore mirrors what the control API does for the master switch: a
	// running core is reused, a stopped one is started so the kernel is warm
	// and the next click is instant.
	ensureCore := func(ctx context.Context) string {
		id, err := a.EnsureCore(ctx)
		if err != nil {
			a.log.Warnf("托盘：内核不可用：%v", err)
			return ""
		}
		return id
	}

	setMode := func(mode string) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		id := ensureCore(ctx)
		if id == "" {
			a.log.Warnf("托盘：没有可用内核，无法切换模式")
			st.update(func(s *traySnapshot) { s.lastError = "no core" })
			return
		}
		if _, err := a.SetCoreMode(ctx, id, mode); err != nil {
			a.log.Warnf("托盘：切换模式失败：%v", err)
			st.update(func(s *traySnapshot) { s.lastError = err.Error() })
			return
		}
		a.log.Infof("托盘：路由模式已切换为 %s", mode)
		st.update(func(s *traySnapshot) {
			s.mode = mode
			s.coreRunning = true
			s.coreID = id
			s.lastError = ""
		})
	}

	cycleMode := func() {
		modes := CoreModes() // rule, global, direct
		current := st.get().mode
		next := modes[0]
		for i, m := range modes {
			if m == current {
				next = modes[(i+1)%len(modes)]
				break
			}
		}
		setMode(next)
	}

	// toggleProxy is the master switch: one click sends traffic through the
	// node, the next sends it straight out. The kernel is started first and
	// left running, so both directions are instant.
	toggleProxy := func() {
		snap := st.get()
		want := !snap.proxyOn
		if want {
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			id := ensureCore(ctx)
			cancel()
			if id != "" {
				st.update(func(s *traySnapshot) { s.coreRunning = true; s.coreID = id })
			}
		}
		if err := a.SetSystemProxy(want); err != nil {
			a.log.Warnf("托盘：系统代理切换失败：%v", err)
			st.update(func(s *traySnapshot) { s.lastError = err.Error() })
			return
		}
		if want {
			a.log.Infof("托盘：系统代理已开启，流量走节点")
		} else {
			a.log.Infof("托盘：系统代理已关闭，流量直连")
		}
		st.update(func(s *traySnapshot) {
			s.proxyOn = want
			s.lastError = ""
		})
	}

	toggleAutostart := func() {
		snap := st.get()
		want := !snap.autostart
		if want {
			exe, err := os.Executable()
			if err != nil {
				a.log.Warnf("托盘：开机自启失败：%v", err)
				return
			}
			if err := autostart.Enable(exe, []string{"-config", a.ConfigPath()}); err != nil {
				a.log.Warnf("托盘：开机自启失败：%v", err)
				return
			}
		} else if err := autostart.Disable(); err != nil {
			a.log.Warnf("托盘：关闭开机自启失败：%v", err)
			return
		}
		st.update(func(s *traySnapshot) { s.autostart = want })
	}

	// toggleTun is the second half of the master switch: 系统代理 only covers
	// applications that honour the Windows proxy setting, TUN covers the rest.
	// It runs off the tray thread because bringing a TUN device up (and
	// restarting the core behind it) takes seconds, and a frozen icon is what
	// users notice first.
	toggleTun := func() {
		want := !st.get().tun
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			if err := a.SetTunMode(ctx, want); err != nil {
				a.log.Warnf("托盘：TUN 模式切换失败：%v", err)
				st.update(func(s *traySnapshot) { s.lastError = err.Error() })
				return
			}
			if want {
				a.log.Infof("托盘：TUN 模式已开启，整机流量走内核")
			} else {
				a.log.Infof("托盘：TUN 模式已关闭")
			}
			st.update(func(s *traySnapshot) { s.tun = want; s.lastError = "" })
		}()
	}

	// openDataDir is the tray's answer to "where is everything?". It opens the
	// same folder the 设置 page's button does.
	openDataDir := func() {
		dir := a.DataDir()
		if err := shellopen.Dir(dir); err != nil {
			a.log.Warnf("托盘：打开数据目录失败：%v", err)
			return
		}
		a.log.Infof("托盘：已在文件管理器打开 %s", dir)
	}

	// openLogDir opens the folder the 日志 page exports into. It shares
	// a.LogDir() with the 设置 page and the export endpoint, so the three can
	// never drift apart.
	openLogDir := func() {
		dir := a.LogDir()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			a.log.Warnf("托盘：创建日志目录失败：%v", err)
			return
		}
		if err := shellopen.Dir(dir); err != nil {
			a.log.Warnf("托盘：打开日志目录失败：%v", err)
			return
		}
		a.log.Infof("托盘：已在文件管理器打开 %s", dir)
	}

	updateSubs := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		a.log.Infof("托盘：开始更新全部订阅")
		if _, err := a.UpdateAllSubscriptions(ctx); err != nil {
			a.log.Warnf("托盘：更新订阅失败：%v", err)
			return
		}
		a.log.Infof("托盘：订阅更新完成")
	}

	restartCore := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		id := a.RunningCoreID()
		if id == "" {
			id = ensureCore(ctx)
			if id == "" {
				a.log.Warnf("托盘：没有运行中的内核可重启")
				return
			}
		}
		if err := a.StopCore(id); err != nil {
			a.log.Warnf("托盘：停止内核 %s 失败：%v", id, err)
		}
		if _, err := a.StartCore(ctx, id); err != nil {
			a.log.Warnf("托盘：重启内核 %s 失败：%v", id, err)
			st.update(func(s *traySnapshot) { s.lastError = err.Error() })
			return
		}
		a.log.Infof("托盘：内核 %s 已重启", id)
	}

	menu := func() []tray.MenuItem {
		snap := st.get()
		proxyLabel := "系统代理：已关闭（点击开启）"
		if snap.proxyOn {
			proxyLabel = "系统代理：已开启（点击关闭）"
		}
		tunLabel := "TUN 模式：已关闭（点击开启）"
		if snap.tun {
			tunLabel = "TUN 模式：已开启（点击关闭）"
		}
		return []tray.MenuItem{
			{Label: "打开窗口", Action: openWindow},
			{Label: ""},
			{Label: "规则模式：按规则分流", Checked: snap.mode == "rule", Action: func() { setMode("rule") }},
			{Label: "全局模式：所有流量走节点", Checked: snap.mode == "global", Action: func() { setMode("global") }},
			{Label: "直连模式：所有流量直连", Checked: snap.mode == "direct", Action: func() { setMode("direct") }},
			{Label: ""},
			{Label: proxyLabel, Checked: snap.proxyOn, Action: toggleProxy},
			{Label: tunLabel, Checked: snap.tun, Action: toggleTun},
			{Label: "开机自启", Checked: snap.autostart, Action: toggleAutostart},
			{Label: ""},
			{Label: fmt.Sprintf("更新全部订阅（%d）", snap.subs), Action: updateSubs},
			{Label: "重启内核", Action: restartCore},
			{Label: "打开数据目录", Action: openDataDir},
			{Label: "打开日志目录", Action: openLogDir},
			{Label: ""},
			{Label: "彻底退出", Action: quit},
		}
	}

	// The refresher keeps the icon, the tooltip and the menu cache current. It
	// is the only place that talks to the core from the tray path, and it never
	// runs on the tray thread.
	go func() {
		refresh := func() {
			status := a.Status()
			snap := traySnapshot{
				mode: st.get().mode,
				// proxyOn is "our" proxy: another client holding the machine-wide
				// setting must not make the tray claim the switch, or the next
				// click would try to switch off a proxy this client never set.
				proxyOn:     status.SystemProxy && status.SystemProxyOwned,
				coreRunning: status.Engine != "" && status.Engine != "builtin",
				coreID:      status.Engine,
				conns:       status.ActiveConns,
				rules:       status.RuleCount,
				subs:        len(a.Subscriptions()),
				autostart:   st.get().autostart,
				tun:         a.TunEnabled(),
			}
			if snap.coreRunning {
				mctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				if mode, err := a.CoreMode(mctx, snap.coreID); err == nil && mode != "" {
					snap.mode = mode
				}
				cancel()
			}
			st.update(func(s *traySnapshot) {
				s.mode, s.proxyOn, s.coreRunning = snap.mode, snap.proxyOn, snap.coreRunning
				s.coreID, s.conns, s.rules, s.subs = snap.coreID, snap.conns, snap.rules, snap.subs
				s.tun = snap.tun
			})

			state := tray.StateDirect
			switch {
			case snap.lastError != "":
				state = tray.StateError
			case snap.proxyOn:
				state = tray.StateProxy
			}
			tray.SetStatus(state)

			core := "内核未运行"
			if snap.coreRunning {
				core = snap.coreID
			}
			modeName := map[string]string{"rule": "规则", "global": "全局", "direct": "直连"}[snap.mode]
			if modeName == "" {
				modeName = snap.mode
			}
			proxy := "直连"
			if snap.proxyOn {
				proxy = "系统代理开"
			}
			tray.SetTooltip(fmt.Sprintf("syan-clash %s · %s · %s · %s · %d 连接",
				a.Version(), modeName, proxy, core, snap.conns))
		}

		refresh()
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				tray.SetStatus(tray.StateStopped)
				return
			case <-ticker.C:
				refresh()
			}
		}
	}()

	opts := tray.Options{
		Tooltip:      "syan-clash 代理客户端",
		IconPath:     trayIconPath(),
		OnClick:      openWindow,
		DynamicItems: menu,
		// Defaults were chosen by probing this desktop: Ctrl+Alt+S and
		// Ctrl+Alt+W are already owned by other software, Ctrl+Alt+M and the
		// Ctrl+Alt+Shift variants are free. A shortcut that is taken at
		// startup is reported and skipped, never fatal.
		HotKeys: []tray.HotKey{
			{Modifiers: tray.ModControl | tray.ModAlt | tray.ModShift, VirtualKey: 'S', Description: "Ctrl+Alt+Shift+S 系统代理开关", Action: toggleProxy},
			{Modifiers: tray.ModControl | tray.ModAlt, VirtualKey: 'M', Description: "Ctrl+Alt+M 切换路由模式", Action: cycleMode},
			{Modifiers: tray.ModControl | tray.ModAlt | tray.ModShift, VirtualKey: 'W', Description: "Ctrl+Alt+Shift+W 打开窗口", Action: openWindow},
		},
		Logf: func(format string, args ...any) { a.log.Warnf(format, args...) },
	}

	if err := tray.Run(opts); err != nil {
		a.log.Warnf("托盘不可用：%v", err)
	}
}

// trayIconPath is the brand icon that ships beside the executable. Returning an
// empty string is fine: the tray then falls back to the icon embedded in the
// executable's own resources, so a missing file degrades instead of breaking.
func trayIconPath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	path := filepath.Join(filepath.Dir(exe), "syan-clash.ico")
	if _, err := os.Stat(path); err != nil {
		return ""
	}
	return path
}
