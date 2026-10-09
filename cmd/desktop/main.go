// Command desktop is the Windows client: a real .exe that opens its own
// window, runs the control server in-process, and owns the tray icon.
//
// It is the same program as cmd/core plus a window: the console UI is served
// over loopback and displayed in an application window, so the browser chrome
// (tabs, address bar, menu) is gone and it behaves like a desktop app.
//
// Lifetime: the process is tray-resident. Closing the window does not stop the
// client (the way every desktop proxy client behaves), the tray menu can open
// the window again, and launching the exe a second time simply asks the
// running copy to surface its window instead of refusing to start.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"vvpn/internal/aisession"
	"vvpn/internal/app"
	"vvpn/internal/autostart"
	"vvpn/internal/control"
	"vvpn/internal/corebundle"
	"vvpn/internal/sysproxy"
	"vvpn/internal/tray"
	"vvpn/internal/urlscheme"
	"vvpn/internal/winsvc"
)

// The linker stamps the build stamp and identifier (see build.ps1). The
// defaults are what a plain "go build" leaves behind, which is why an empty
// stamp is allowed all the way through to the about card.
var (
	version     = "0.2.1"
	buildStamp  = ""
	buildCommit = ""
)

// flagWasSet reports whether the caller named the flag on the command line.
// The difference matters for -config: the flag always has a value (the default
// path), but only an explicit one proves the caller thought about which
// configuration this process is about to run.
func flagWasSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func main() {
	cfgPath := flag.String("config", defaultConfigPath(), "path to the configuration file")
	addr := flag.String("addr", "127.0.0.1:3090", "control server address")
	noWindow := flag.Bool("no-window", false, "run headless: no window, no tray icon (automation/debug)")
	allowMulti := flag.Bool("allow-multi", false, "allow a second instance")
	instanceName := flag.String("instance-name", "syan-clash-desktop", "internal: single-instance scope; automation passes a private name so a test instance never fights the client that is already running")
	dialogDryRun := flag.Bool("dialog-dry-run", false, "internal: print what the launch-failure dialog would say instead of showing it (automation)")
	webViewSelfTest := flag.Bool("webview-selftest", false, "run the embedded window hidden, report what the page says, then exit")
	aiLogin := flag.String("ai-login", "", "sign in to an AI service (chatgpt / gemini) in the embedded browser and store the cookies the 诊断 panel grades 绿 with")
	trayIconSelfTest := flag.Bool("tray-icon-selftest", false, "draw the notification-icon states to PNG files and exit (headless check)")
	traySelfTest := flag.Bool("tray-selftest", false, "create the notification icon, cycle its states and exit (headless check; the icon is visible for a few seconds)")
	hotKeyProbe := flag.Bool("hotkey-probe", false, "report which candidate global shortcuts are free on this desktop, then exit")
	proxyGuardPID := flag.String("proxy-guard", "", "internal: wait for the given process id to exit, then put the system proxy back")
	serviceName := flag.String("service-name", winsvc.DefaultName, "internal: service name; the lab installs a private one so a test never touches the real service")
	serviceMode := flag.Bool("service", false, "run as the installed Windows service host (the service control manager starts this)")
	serviceConsole := flag.Bool("service-console", false, "run the service worker in the foreground instead of through the service control manager (debugging)")
	serviceInstall := flag.Bool("service-install", false, "install the Windows service and exit (needs administrator rights)")
	serviceUninstall := flag.Bool("service-uninstall", false, "uninstall the Windows service and exit (needs administrator rights)")
	serviceStatus := flag.Bool("service-status", false, "print the Windows service status as one JSON line and exit")
	coreBundle := flag.Bool("core-bundle", false, "internal: unpack the embedded core even in an -allow-multi run (automation supplies its own cores, so it is off there by default)")
	flag.Parse()

	// The captured AI sign-ins live beside the configuration: the sign-in
	// window writes them and the diagnostics panel reads them from there.
	aisession.SetPath(aisession.DefaultPath(*cfgPath))

	// -allow-multi is the automation escape hatch: it skips the single-instance
	// guard, so a second process is allowed to start a second core. Without an
	// explicit -config that second core reads the real config.json and binds the
	// real ports, which silently fights the client the user is already running -
	// the running core loses its listeners and the user experiences "the client
	// stopped working". Refuse the combination outright: no window, no core, no
	// damage. Automation must name a configuration, which is also the only way it
	// can be told apart from a real double-click.
	if (*allowMulti || *webViewSelfTest) && !flagWasSet("config") {
		fmt.Fprintln(os.Stderr, "syan-clash: -allow-multi / -webview-selftest 必须同时给出 -config <独立配置>，否则会占用正在运行的客户端的内核端口")
		os.Exit(2)
	}

	// A clash:// link arrives as an ordinary argument: Windows runs the
	// registered command with the link appended. It is picked out before
	// anything else because both the "already running" branch below and a fresh
	// start need it.
	schemeURL := firstSchemeArg(os.Args[1:])

	// The service switches are handled before anything else. They are separate
	// programs that happen to live in the same exe: none of them opens a
	// window, a tray icon or a console server, and the single-instance guard
	// must not stand in their way - the elevated install helper is a second
	// process by design.
	if *serviceStatus {
		printServiceStatus(*serviceName)
		return
	}
	if *serviceInstall {
		if err := installService(*cfgPath, *serviceName); err != nil {
			fmt.Fprintln(os.Stderr, "syan-clash 服务：安装失败：", err)
			os.Exit(1)
		}
		return
	}
	if *serviceUninstall {
		if err := uninstallService(*serviceName); err != nil {
			fmt.Fprintln(os.Stderr, "syan-clash 服务：卸载失败：", err)
			os.Exit(1)
		}
		return
	}
	if *serviceConsole {
		ctx, cancel := context.WithCancel(context.Background())
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		go func() { <-sig; cancel() }()
		if err := runServiceWorker(ctx, *cfgPath, *serviceName); err != nil {
			fmt.Fprintln(os.Stderr, "syan-clash 服务：", err)
			os.Exit(1)
		}
		return
	}
	if *serviceMode {
		if err := runServiceHost(*cfgPath, *serviceName); err != nil {
			fmt.Fprintln(os.Stderr, "syan-clash 服务：", err)
			os.Exit(1)
		}
		return
	}

	// -proxy-guard is the invisible half of the system proxy switch: a copy of
	// this exe that outlives a kill and puts the machine's proxy settings back.
	// It returns before a window, a tray icon or a console server exists, so it
	// can never flash anything on screen.
	if *proxyGuardPID != "" {
		pid, err := strconv.Atoi(*proxyGuardPID)
		if err != nil {
			os.Exit(2)
		}
		sysproxy.SetStatePath(sysproxy.DefaultStatePath(*cfgPath))
		runProxyGuard(pid)
		return
	}

	// -ai-login is a third program inside the same exe: it opens one window on
	// the service's own sign-in page and stores the cookie jar it finds there.
	// It has to work while the real client is already running, so neither the
	// single-instance guard nor the control server applies to it.
	if *aiLogin != "" {
		if err := runAILogin(*cfgPath, *aiLogin, !*noWindow); err != nil {
			fmt.Fprintln(os.Stderr, "syan-clash: AI 登录失败：", err)
			os.Exit(1)
		}
		return
	}

	if *webViewSelfTest {
		// A self-test is a diagnostic run: it must work while the real client
		// is already running, so the single-instance guard does not apply.
		*allowMulti = true
	}

	closeLog := initStartupLog()
	defer closeLog()

	// -tray-icon-selftest is a pure drawing check: it never creates the icon in
	// the notification area, it only proves the compositor and the GDI icon
	// path work, and leaves the pictures in lab\evidence for a human look.
	if *trayIconSelfTest {
		dir := filepath.Join(exeDir(), "lab", "evidence")
		files, err := tray.ExportStateIcons(dir)
		for _, f := range files {
			fmt.Println("tray-icon-selftest: wrote", f)
		}
		if err != nil {
			fmt.Println("tray-icon-selftest: failed:", err)
			os.Exit(1)
		}
		fmt.Println("tray-icon-selftest: ok")
		return
	}

	if !*allowMulti {
		ok, err := autostart.AcquireSingleInstance(*instanceName)
		if err != nil {
			fmt.Fprintln(os.Stderr, "syan-clash: 单实例检查失败：", err)
		} else if !ok {
			// Already running. A second double-click means "show me the
			// window", so that request is forwarded and this process leaves.
			//
			// The instance that is running is not necessarily on this launch's
			// -addr: 3090 is the default for every launch, so the first one may
			// have found it taken and slid to the next free port. The address
			// it published when it bound its listener is tried first, and when
			// neither answers the user is told why instead of being left with
			// a double-click that visibly did nothing.
			tried := make([]string, 0, 2)
			if pub := liveRuntimeAddr(*cfgPath); pub != "" && pub != *addr {
				tried = append(tried, pub)
			}
			tried = append(tried, *addr)
			// A clash:// link that arrived with this launch belongs to the
			// instance that is already running - it owns the window, the
			// subscriptions and the lock file. Handing it over first means a
			// double-clicked link does what it says even when the client was
			// already up, and the process that was started for the link leaves
			// without opening a second window.
			if schemeURL != "" {
				var forwardErr error
				forwarded := ""
				for _, a := range tried {
					if err := requestURLScheme(a, schemeURL); err != nil {
						forwardErr = err
						continue
					}
					forwarded = a
					break
				}
				if forwarded != "" {
					_ = requestWindow(forwarded)
					fmt.Fprintf(os.Stderr, "syan-clash: clash:// 链接已交给正在运行的客户端（%s）\n", forwarded)
					closeLog()
					os.Exit(0)
				}
				fmt.Fprintf(os.Stderr, "syan-clash: clash:// 链接没能交给正在运行的客户端：%v\n", forwardErr)
			}
			var lastErr error
			usedAddr := ""
			for _, a := range tried {
				if err := requestWindow(a); err != nil {
					lastErr = err
					continue
				}
				usedAddr = a
				break
			}
			if usedAddr != "" {
				fmt.Fprintf(os.Stderr, "syan-clash: 已经在运行，窗口已唤起（%s）\n", usedAddr)
				closeLog()
				os.Exit(0)
			}
			msg := fmt.Sprintf("syan-clash 已经在运行，但没能唤起它的窗口。\n\n"+
				"尝试过的控制端口：%s\n最后一次的错误：%v\n\n"+
				"请点任务栏右下角的 syan-clash 托盘图标打开窗口；如果托盘图标也不在，"+
				"先在任务管理器里结束 syan-clash.exe，再重新双击打开。",
				strings.Join(tried, "、"), lastErr)
			fmt.Fprintln(os.Stderr, "syan-clash: "+strings.ReplaceAll(msg, "\n", " "))
			switch {
			case *noWindow:
				// A headless run must never put anything on screen: the log line
				// above is the whole report.
			case *dialogDryRun:
				// Automation proves the dialog branch is wired without showing
				// a window nobody asked for.
				fmt.Println("dialog-dry-run: " + strings.ReplaceAll(msg, "\n", " | "))
			default:
				messageBox("syan-clash", msg)
			}
			closeLog()
			os.Exit(1)
		}
		defer autostart.ReleaseSingleInstance()
	}

	// The core, its geo databases and the wintun driver travel inside this exe.
	// Unpacking them here - before the app exists, so before the core is
	// started - is what makes the client one file to copy: drop the exe in an
	// empty folder and the first start fills in cores\mihomo beside it. A run
	// that already has them only stats four files.
	//
	// -allow-multi is the automation escape hatch and automation always names
	// its own configuration, whose cores it manages itself; unpacking 74 MB
	// into every scratch directory would be waste, so it is skipped there
	// unless -core-bundle asks for it explicitly.
	if !*allowMulti || *coreBundle {
		if rep, err := corebundle.EnsureForConfig(*cfgPath); err != nil {
			fmt.Fprintln(os.Stderr, "syan-clash: 内嵌内核释放失败：", err)
		} else if rep.Changed() {
			fmt.Fprintln(os.Stderr, "syan-clash: "+rep.String())
		}
	} else {
		// Say it out loud: without this line a core that fails to start in an
		// automation run looks like a broken build instead of a run that was
		// told not to unpack anything.
		fmt.Fprintln(os.Stderr, "syan-clash: -allow-multi 未加 -core-bundle，跳过内嵌内核释放（该配置的 cores 目录需自备）")
	}

	a, err := app.New(*cfgPath, version)
	if err != nil {
		logFatal(closeLog, "syan-clash: 启动失败：%v", err)
	}
	defer a.Stop()
	a.SetBuild(buildStamp, buildCommit)
	// The clash:// registration is re-applied on every start while the switch
	// is on: the exe may have been moved since it was registered, and a machine
	// where another client owns the scheme is reported rather than fought over.
	// A headless automation run never writes the registry - it is a test, not
	// the client the user double-clicks.
	if !*allowMulti {
		if st, err := a.ApplyURLScheme(); err != nil {
			fmt.Fprintf(os.Stderr, "syan-clash: clash:// 注册未生效：%v\n", err)
		} else if st.Enabled && st.Ours {
			fmt.Println("syan-clash: clash:// 链接已注册给本客户端")
		}
	}
	if !*noWindow {
		// Reading the runtime version unpacks WebView2Loader.dll, which a
		// headless run has no reason to do; the about card then simply has one
		// row less.
		a.SetHostInfo("WebView2 运行时", webView2RuntimeVersion())
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		// A stale instance or another client's console can already hold the
		// port. Sliding to the next free one beats refusing to start, which is
		// what a user would experience as "the client is broken today".
		if alt, ok := app.NextFreeAddr(*addr); ok {
			if ln2, err2 := net.Listen("tcp", alt); err2 == nil {
				fmt.Fprintf(os.Stderr, "syan-clash: 控制端口 %s 被占用，改用 %s\n", *addr, alt)
				ln, err = ln2, nil
			}
		}
	}
	if err != nil {
		logFatal(closeLog, "syan-clash: 监听控制端口失败：%v", err)
	}
	// The console port lives in a flag, not in the configuration file, so the
	// app has to be told what it ended up on before the API can report it.
	a.SetConsoleAddr(ln.Addr().String())
	// Publish the address this instance actually bound so the next double-click
	// can find this window even when the default port was taken and the client
	// slid to the next free one. Only the guarded instance publishes: a headless
	// -allow-multi run is a test and must not rewrite where the real client lives.
	if !*allowMulti {
		withdrawRuntimeAddr := publishRuntimeAddr(*cfgPath, ln.Addr().String())
		defer withdrawRuntimeAddr()
	}
	srv, err := control.Serve(ln, a)
	if err != nil {
		logFatal(closeLog, "syan-clash: 启动控制服务失败：%v", err)
	}

	url := "http://" + ln.Addr().String() + "/"
	fmt.Printf("syan-clash %s\n  控制台 %s\n", version, url)

	// -hotkey-probe answers "which shortcut can this desktop actually give
	// me?" before a default is picked, because RegisterHotKey fails silently
	// for the user when another program owns the combination.
	if *hotKeyProbe {
		type candidate struct {
			name string
			mods uint32
			key  uint32
		}
		candidates := []candidate{
			{"Ctrl+Alt+S", tray.ModControl | tray.ModAlt, 'S'},
			{"Ctrl+Alt+M", tray.ModControl | tray.ModAlt, 'M'},
			{"Ctrl+Alt+W", tray.ModControl | tray.ModAlt, 'W'},
			{"Ctrl+Alt+Shift+S", tray.ModControl | tray.ModAlt | tray.ModShift, 'S'},
			{"Ctrl+Alt+Shift+M", tray.ModControl | tray.ModAlt | tray.ModShift, 'M'},
			{"Ctrl+Alt+Shift+W", tray.ModControl | tray.ModAlt | tray.ModShift, 'W'},
			{"Ctrl+Shift+S", tray.ModControl | tray.ModShift, 'S'},
			{"Ctrl+Shift+M", tray.ModControl | tray.ModShift, 'M'},
			{"Ctrl+Shift+W", tray.ModControl | tray.ModShift, 'W'},
			{"Ctrl+Alt+F9", tray.ModControl | tray.ModAlt, 0x78},
			{"Ctrl+Alt+F10", tray.ModControl | tray.ModAlt, 0x79},
			{"Ctrl+Alt+F11", tray.ModControl | tray.ModAlt, 0x7A},
			{"Ctrl+Alt+F12", tray.ModControl | tray.ModAlt, 0x7B},
			{"Ctrl+Alt+Shift+1", tray.ModControl | tray.ModAlt | tray.ModShift, '1'},
			{"Ctrl+Alt+Shift+2", tray.ModControl | tray.ModAlt | tray.ModShift, '2'},
			{"Ctrl+Alt+Shift+3", tray.ModControl | tray.ModAlt | tray.ModShift, '3'},
		}
		var free, taken []string
		for _, c := range candidates {
			if tray.ProbeHotKey(c.mods, c.key) {
				free = append(free, c.name)
			} else {
				taken = append(taken, c.name)
			}
		}
		fmt.Println("hotkey-probe: free  : " + strings.Join(free, ", "))
		fmt.Println("hotkey-probe: taken : " + strings.Join(taken, ", "))
		closeLog()
		os.Exit(0)
	}

	// -tray-selftest exercises the notification area for real - window
	// creation, Shell_NotifyIcon, the status icon swaps, the hot keys - without
	// depending on anyone clicking a menu. It is the only way to prove that
	// path on a machine that is in use, so it runs the tray alone and exits.
	if *traySelfTest {
		selfTestDone := make(chan struct{})
		trayOpts := tray.Options{
			Tooltip:  "syan-clash 托盘自检中",
			IconPath: filepath.Join(exeDir(), "syan-clash.ico"),
			DynamicItems: func() []tray.MenuItem {
				return []tray.MenuItem{
					{Label: "托盘自检：菜单可构建", Checked: true},
					{Label: "退出", Action: func() { close(selfTestDone) }},
				}
			},
			// Same combinations the client ships, so the self-test proves the
			// production defaults are actually claimable here.
			HotKeys: []tray.HotKey{
				{Modifiers: tray.ModControl | tray.ModAlt | tray.ModShift, VirtualKey: 'S', Description: "Ctrl+Alt+Shift+S 自检", Action: func() {}},
				{Modifiers: tray.ModControl | tray.ModAlt, VirtualKey: 'M', Description: "Ctrl+Alt+M 自检", Action: func() {}},
				{Modifiers: tray.ModControl | tray.ModAlt | tray.ModShift, VirtualKey: 'W', Description: "Ctrl+Alt+Shift+W 自检", Action: func() {}},
			},
			Logf: func(format string, args ...any) { fmt.Printf("tray-selftest: "+format+"\n", args...) },
		}
		trayErr := make(chan error, 1)
		go func() { trayErr <- tray.Run(trayOpts) }()
		time.Sleep(2 * time.Second)
		for _, state := range []tray.State{tray.StateProxy, tray.StateDirect, tray.StateError, tray.StateStopped} {
			tray.SetStatus(state)
			tray.SetTooltip(fmt.Sprintf("syan-clash 托盘自检：状态 %d", state))
			fmt.Printf("tray-selftest: status %d applied\n", state)
			time.Sleep(1200 * time.Millisecond)
		}
		select {
		case err := <-trayErr:
			if err != nil {
				fmt.Println("tray-selftest: failed:", err)
				closeLog()
				os.Exit(2)
			}
		default:
		}
		tray.Quit()
		fmt.Println("tray-selftest: ok")
		closeLog()
		os.Exit(0)
	}

	// Optional startup work, same as the headless build.
	startupCtx, stopStartup := context.WithCancel(context.Background())
	defer stopStartup()
	// The sweep runs often; each subscription is only refreshed when its own
	// interval has elapsed (the provider's profile-update-interval, or the
	// client default), so a short tick costs nothing.
	a.StartupTasks(startupCtx, app.StartupOptions{
		UpdateSubscriptions:  true,
		SubscriptionInterval: 30 * time.Minute,
	})
	a.StartProcessSampler(startupCtx, 2*time.Second)

	// A clash:// link that came with this launch is acted on once the client is
	// up, in the background: the import talks to the network, and the window
	// must not wait for it. The outcome goes to the startup log and to the
	// 订阅 page, which is where a user looks after clicking such a link.
	if schemeURL != "" {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			res, err := a.HandleURLScheme(ctx, schemeURL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "syan-clash: clash:// 链接处理失败：%v\n", err)
				return
			}
			fmt.Fprintf(os.Stderr, "syan-clash: clash:// 链接已处理：订阅 %v，%v 个节点\n", res["name"], res["nodes"])
		}()
	}

	// The OS proxy outlives this process by design, so a guard copy of the exe
	// watches for the one exit that runs no code: a kill.
	// The switch on the 系统与服务 card can turn that copy off; the client
	// still restores the proxy on every exit path it controls, the guard only
	// covers the one exit that runs no code at all.
	if a.ProxyGuardEnabled() {
		guardCtx, stopGuard := context.WithCancel(startupCtx)
		defer stopGuard()
		go superviseProxyGuard(guardCtx, a, *cfgPath)
	} else {
		fmt.Println("syan-clash: 系统代理守卫已关闭（设置页可开启）")
	}

	// -webview-selftest drives the embedded window once with the window hidden,
	// records what the page reports and exits. Nothing appears on screen, which
	// is what makes it safe to run on a desktop that is in use - it is how the
	// embedded browser gets verified without a user watching.
	if *webViewSelfTest {
		var result string
		err := runWebViewWindow(webViewOptions{url: url, selfTest: true, result: &result})
		if err != nil {
			fmt.Printf("webview-selftest: 失败：%v\n", err)
			closeLog()
			os.Exit(2)
		}
		fmt.Printf("webview-selftest: %s\n", result)
		closeLog()
		os.Exit(0)
	}

	// The console is embedded (WebView2) and nothing else: this client never
	// starts Edge, Chrome or any other browser window. When the WebView2
	// runtime is missing the failure is reported through the log and the tray
	// instead of falling back to an external window.
	host := newWindowHost(url, func() error {
		msg := "内嵌界面不可用：缺少 Microsoft Edge WebView2 运行时，装好 WebView2 Runtime 后重试"
		fmt.Fprintln(os.Stderr, "syan-clash: "+msg)
		tray.Notify("syan-clash", msg)
		return errors.New(msg)
	})

	// Opening the window twice is a mistake, not a feature: when one is
	// already on screen it is brought to the front instead of piling up a
	// second Edge window on top of it.
	var windowMu sync.Mutex
	var lastWindowCall time.Time
	openWin := func() error {
		// The embedded window comes first: when it exists it is surfaced, and
		// none of the fallback logic below is reached.
		if host.Focus() {
			return nil
		}
		windowMu.Lock()
		defer windowMu.Unlock()
		// Debounce: a double-clicked exe, a stuck caller or a retry storm must
		// not turn into a pile of windows flashing open on the user's screen.
		if time.Since(lastWindowCall) < 2*time.Second {
			return nil
		}
		lastWindowCall = time.Now()
		if err := host.Open(); err != nil {
			fmt.Fprintln(os.Stderr, "syan-clash: 打开窗口失败：", err)
			return err
		}
		fmt.Fprintln(os.Stderr, "syan-clash: 已请求打开客户端窗口")
		return nil
	}
	// The window is optional and disposable; the tray icon owns the lifetime.
	// A headless run never registers the opener, so nothing - not even a
	// second double-click - can pop a window on a screen that asked for none.
	if !*noWindow {
		a.SetWindowOpener(openWin)
		// 静默启动（设置页 / config.json 的 app.silent_start）：开机自启的用户
		// 要的是直接进托盘，不是每次开机都被一个窗口糊脸。窗口本身照建，托盘
		// 图标、全局热键和再双击一次 exe 都能随时把它叫出来。
		if a.SilentStart() {
			fmt.Println("syan-clash: 静默启动，窗口保持隐藏（点托盘图标唤起）")
		} else {
			_ = openWin()
		}
	}

	quit := make(chan struct{})
	var quitOnce sync.Once
	requestQuit := func() { quitOnce.Do(func() { close(quit) }) }
	a.SetQuitFunc(requestQuit)

	// The tray runs on its own goroutine because it owns a message loop.
	if !*noWindow {
		go a.RunTray(startupCtx, ln.Addr().String(), func() { _ = openWin() }, requestQuit)
	}

	// Exit on Ctrl+C or on "退出" from the tray / the UI.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sig:
	case <-quit:
	}

	// A proxy pointing at a port nothing listens on is the one failure a user
	// cannot debug, so every exit path this process controls undoes it.
	a.RestoreSystemProxyOnExit()

	fmt.Println("\nsyan-clash: 正在退出")
	closeOwnWindows()
	stopStartup()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	_ = srv.Shutdown(shutdownCtx)
	cancel()
}

// requestWindow asks the copy that already owns the single-instance mutex to
// surface its window. Loopback-only and best-effort.
func requestWindow(addr string) error {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Post("http://"+addr+"/api/app/window", "application/json", nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("控制服务返回 %s", resp.Status)
	}
	return nil
}

// firstSchemeArg picks the first clash:// link out of a command line. Windows
// runs the registered command with the link appended, so it arrives as an
// ordinary argument next to the flags.
func firstSchemeArg(args []string) string {
	for _, a := range args {
		arg := strings.TrimSpace(a)
		if strings.HasPrefix(strings.ToLower(arg), urlscheme.Scheme+"://") {
			return arg
		}
	}
	return ""
}

// requestURLScheme hands a link to the instance that already owns the
// single-instance mutex. Loopback-only, like requestWindow. The timeout is
// generous because the running instance answers only after the import has
// finished; a timeout therefore means "still importing", not "failed", which
// is why the caller treats it as a hand-over and says so.
func requestURLScheme(addr, link string) error {
	body, err := json.Marshal(map[string]string{"url": link})
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Post("http://"+addr+"/api/app/url-scheme/handle", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("控制服务返回 %s", resp.Status)
	}
	return nil
}

var _ = tray.Available
