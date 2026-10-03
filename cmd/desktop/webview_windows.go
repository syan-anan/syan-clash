//go:build windows

package main

// The client's window content is an embedded WebView2 control. The whole point
// of this file is that the product stays a single .exe: no browser is
// installed, launched or driven externally, and no runtime files have to be
// shipped by hand.
//
// Three pieces make that work without cgo and without a C compiler:
//
//  1. WebView2Loader.dll is embedded in the executable and written to a
//     runtime folder next to it on first use. It is Microsoft's loader and the
//     supported way to reach the WebView2 runtime that ships with Windows.
//  2. COM is driven through vtable slots (see comCall). WebView2 hosts the
//     browser in msedgewebview2.exe children, and the interface pointers here
//     are real vtable pointers the runtime hands back.
//  3. The completion handlers WebView2 calls back into are three tiny COM
//     objects whose vtables point at Go callbacks (syscall.NewCallback). They
//     are pinned for the lifetime of the process, so the garbage collector can
//     never take memory Windows still calls into.
//
// The vtable slots used below were checked against WebView2 SDK 1.0.4258.31,
// build/native/include/WebView2.h. Slots count the three IUnknown methods:
//
//	ICoreWebView2Environment: CreateCoreWebView2Controller = 3
//	ICoreWebView2Controller:  put_IsVisible = 4, put_Bounds = 6,
//	                          Close = 24, get_CoreWebView2 = 25
//	ICoreWebView2:            Navigate = 5, ExecuteScript = 29
//	*CompletedHandler:        Invoke = 3

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"vvpn/internal/aisession"
)

//go:embed assets/WebView2Loader.dll
var webView2LoaderDLL []byte

const (
	coinitApartmentThreaded = 0x2

	// The sign-in capture re-reads the cookie jar on this cadence. It is slow
	// on purpose: a sign-in flow takes a person tens of seconds, and the jar
	// only has to be current by the time the window closes.
	webViewLoginTimerID = 4
	webViewLoginDelayMS = 4000
	rpcEChangedMode     = 0x80010106 // RPC_E_CHANGED_MODE

	// Self-test pacing: long enough for the page and its first state poll to
	// have finished, short enough that a diagnostic run is not a coffee break.
	webViewSelfTestTimerID = 1
	webViewSelfTestDelayMS = 9000
	webViewPollTimerID     = 2
	// A self-test waits for the page's first state poll, which is a real
	// loopback round trip through a freshly started embedded browser. On a
	// loaded machine that round trip can still be in flight when the first
	// probe fires, so the probe is re-armed a few times instead of reporting
	// a false failure.
	webViewSelfTestRetryDelayMS = 4000
	webViewSelfTestRetries      = 8
	webViewPollPeriodMS         = 100

	// The expression the self-test evaluates inside the page. Its JSON result
	// is the evidence that the embedded browser really loaded the console.
	// The self-test also flips to the 诊断 page and reports what it finds there:
	// navigate() runs loadDiagPage() synchronously, so a binding to a missing
	// element surfaces as a caught exception instead of a silent no-op.
	webViewSelfTestScript = "(function () {" +
		// P52: drive the title bar's channel for real, first thing, so the
		// result is read back before anything else can overwrite it.
		" try { window.chrome.webview.postMessage('{\"cmd\":\"selftest-ping\"}'); } catch (e) {}" +
		" var out = document.title + ' | ' + (document.querySelector('#side-state') ? document.querySelector('#side-state').textContent.trim() : 'no-side-state')" +
		" + ' | boot=' + (window.__syanBoot || 'none') + ' | status=' + (window.__syanStatus || 'none')" +
		" + ' | font=' + (document.fonts && document.fonts.check ? document.fonts.check('14px SyanRound') : 'n/a');" +
		" try { navigate('diag'); } catch (e) { window.__syanBoot = 'error: ' + (e && e.message ? e.message : e); }" +
		" var sec = document.querySelector('#page-diag');" +
		" var ids = ['diag-ip-run', 'diag-ul-run', 'diag-mx-run', 'diag-st-run', 'diag-nd-tab', 'diag-external', 'conns-pause', 'conns-chart'];" +
		" var miss = ids.filter(function (id) { return !document.getElementById(id); });" +
		" out += ' | diag=' + (sec && sec.classList.contains('active') ? 'active' : 'inactive')" +
		" + ' cards=' + (sec ? sec.querySelectorAll('.card').length : 0) + ' missing=' + (miss.length ? miss.join(',') : 'none');" +
		" var dtitle = document.querySelector('#page-title').textContent.trim();" +
		" try { navigate('panel'); } catch (e) { window.__syanBoot = 'error: ' + (e && e.message ? e.message : e); }" +
		" var psec = document.querySelector('#page-panel');" +
		" var pids = ['panel-base-input', 'panel-base-save', 'panel-notice-card', 'panel-notice-list'];" +
		" var pmiss = pids.filter(function (id) { return !document.getElementById(id); });" +
		" out += ' | panel=' + (psec && psec.classList.contains('active') ? 'active' : 'inactive')" +
		" + ' pmissing=' + (pmiss.length ? pmiss.join(',') : 'none');" +
		// P9: the pages that gained controls (设置 / 日志 / 节点) are visited the
		// same way, so a renamed element or a broken binding shows up as a name
		// in the missing list instead of as a silently dead button.
		" try { navigate('settings'); } catch (e) { window.__syanBoot = 'error: ' + (e && e.message ? e.message : e); }" +
		" var ssec = document.querySelector('#page-settings');" +
		// P32: the 网络与系统代理 card added a bypass editor, so its controls are
		// checked by name like every other control on the page.
		" var sids = ['silent-start', 'open-data-dir', 'open-log-dir', 'prefs-data-dir', 'prefs-config-path', 'autostart', 'cfg-text', 'about-info'," +
		"   'sysproxy-bypass', 'sysproxy-bypass-save', 'sysproxy-bypass-reset', 'sysproxy-bypass-msg', 'sysproxy-bypass-state'];" +
		" var smiss = sids.filter(function (id) { return !document.getElementById(id); });" +
		" out += ' | settings=' + (ssec && ssec.classList.contains('active') ? 'active' : 'inactive') + ' smissing=' + (smiss.length ? smiss.join(',') : 'none');" +
		" try { navigate('logs'); } catch (e) { window.__syanBoot = 'error: ' + (e && e.message ? e.message : e); }" +
		" var lids = ['log-export', 'log-level', 'log-filter', 'log-follow', 'log-clear'];" +
		" var lmiss = lids.filter(function (id) { return !document.getElementById(id); });" +
		" out += ' lmissing=' + (lmiss.length ? lmiss.join(',') : 'none');" +
		" try { navigate('nodes'); } catch (e) { window.__syanBoot = 'error: ' + (e && e.message ? e.message : e); }" +
		" var nids = ['nodes-sort', 'nodes-search', 'nodes-pick', 'nodes-test-all'];" +
		" var nmiss = nids.filter(function (id) { return !document.getElementById(id); });" +
		" out += ' nmissing=' + (nmiss.length ? nmiss.join(',') : 'none');" +
		// P11: the connection table's header is click-to-sort. The self-test
		// drives the real handler on the 下行 column and reports the full state
		// cycle (asc -> desc -> back to the kernel's own order), so a broken
		// binding shows up here instead of as a column that silently does nothing.
		" try { navigate('conns'); } catch (e) { window.__syanBoot = 'error: ' + (e && e.message ? e.message : e); }" +
		" var cth = document.querySelectorAll('#page-conns thead th[data-conn-sort]');" +
		" var csort = 'n/a';" +
		" try {" +
		"   var dth = document.querySelector('#page-conns thead th[data-conn-sort=\"down\"]');" +
		"   dth.click();" +
		"   var k1 = state.connSortKey + '/' + state.connSortDir + '/' + (dth.dataset.dir || '-');" +
		"   dth.click();" +
		"   var k2 = state.connSortKey + '/' + state.connSortDir + '/' + (dth.dataset.dir || '-');" +
		"   dth.click();" +
		"   var k3 = (state.connSortKey || 'none') + '/' + (dth.dataset.dir || '-');" +
		"   csort = cth.length + 'th ' + k1 + ' ' + k2 + ' ' + k3;" +
		" } catch (e) { csort = 'error:' + (e && e.message ? e.message : e); }" +
		" out += ' | connsort=' + csort;" +
		// P12: the 网络参数 card owns the TUN data plane selector. Visiting the
		// cores page proves the control exists and that the two switches beside it
		// are still there after the card grew a row.
		" try { navigate('cores'); } catch (e) { window.__syanBoot = 'error: ' + (e && e.message ? e.message : e); }" +
		" var kids = ['tun-stack', 'net-allow-lan', 'net-ipv6', 'core-net-reload', 'core-net-state'];" +
		" var kmiss = kids.filter(function (id) { return !document.getElementById(id); });" +
		" var kstack = document.getElementById('tun-stack');" +
		" out += ' | net=' + (kmiss.length ? kmiss.join(',') : 'ok')" +
		" + ' stacks=' + (kstack ? kstack.options.length : 0) + '/' + (kstack ? kstack.value : '-');" +
		// P51: every <select> is wrapped by the syanUI combo layer. Counting the
		// wrapped selects proves the enhancement ran, and opening one proves the
		// menu renders and closes again (Escape), so a dead dropdown cannot hide
		// behind a green boot flag.
		" out += ' | combo=' + (function () {" +
		"   var n = document.querySelectorAll('select.syan-native').length;" +
		"   var w = document.querySelectorAll('.combo').length;" +
		"   var items = 'n/a';" +
		"   try {" +
		"     var s = document.getElementById('tun-stack');" +
		"     var inp = s && s.parentNode ? s.parentNode.querySelector('input.combo-ro') : null;" +
		"     if (inp) {" +
		"       inp.click();" +
		"       items = document.querySelectorAll('.combo-menu:not(.hidden) .combo-item').length;" +
		"       document.dispatchEvent(new KeyboardEvent('keydown', {key: 'Escape'}));" +
		"       items += '/' + document.querySelectorAll('.combo-menu:not(.hidden)').length;" +
		"     }" +
		"   } catch (e) { items = 'err:' + (e && e.message ? e.message : e); }" +
		"   return 'native=' + n + ' wrap=' + w + ' items=' + items;" +
		" })();" +
		// P52: the page's own title bar only exists when the frame is custom.
		// Reporting the class and the bridge separately says which half is
		// missing when one of them regresses.
		" out += ' | winbar=' + (document.getElementById('winbar') ? 'ok' : 'none')" +
		" + '/' + (document.documentElement.classList.contains('win-frameless') ? 'frameless' : 'native')" +
		" + ' bridge=' + ((window.chrome && window.chrome.webview && window.chrome.webview.postMessage) ? 'ok' : 'none');" +
		// P32: the core row gained a restart button and the settings card a bypass
		// editor. Both are plain top-level functions, so their presence is what says
		// the script parsed and the handlers are bound.
		" out += ' | p32=' + (typeof restartCore === 'function' ? 'restart' : 'NO-restart')" +
		" + '/' + (typeof loadSysProxyBypass === 'function' ? 'bypass' : 'NO-bypass')" +
		" + '/' + (typeof saveSysProxyBypass === 'function' ? 'save' : 'NO-save');" +
		// P13: the 订阅 page gained a per-row editor and a local-file import, so
		// the row template and the hidden file input are both checked by name.
		" try { navigate('subs'); } catch (e) { window.__syanBoot = 'error: ' + (e && e.message ? e.message : e); }" +
		" var subIds = ['subs-body', 'sub-add', 'sub-import', 'sub-clip', 'sub-file', 'sub-file-pick', 'sub-preview', 'sub-result'];" +
		" var subMiss = subIds.filter(function (id) { return !document.getElementById(id); });" +
		" out += ' | subs=' + (subMiss.length ? subMiss.join(',') : 'ok');" +
		// The QR dialog is driven for real: showQR is the exact call the 二维码
		// buttons make, and the check is that it points the image at the
		// client's own endpoint and that closing it cleans up again.
		" var qr = 'n/a';" +
		" try {" +
		"   showQR('selftest', 'https://example.com/api/v1/client/subscribe?token=selftest');" +
		"   var qsrc = document.querySelector('#qr-img').getAttribute('src') || '';" +
		"   var qopen = !document.querySelector('#qr-modal').hidden;" +
		"   hideQR();" +
		"   var qshut = document.querySelector('#qr-modal').hidden;" +
		"   qr = (qopen && qshut && qsrc.indexOf('/api/qr?size=') === 0) ? 'ok' : ('bad:' + qopen + '/' + qshut + '/' + qsrc.slice(0, 20));" +
		" } catch (e) { qr = 'error:' + (e && e.message ? e.message : e); }" +
		" out += ' | qr=' + qr;" +
		" out += ' | boot2=' + (window.__syanBoot || 'none') + ' | dtitle=' + dtitle + ' | title=' + document.querySelector('#page-title').textContent.trim();" +
		// The virtual node list is the one piece of the UI whose whole point is
		// behaviour under load, so the self-test drives it with a thousand
		// synthetic nodes and reports the DOM size and the timings.
		" var bench = (window.__syanClashNodeBench ? window.__syanClashNodeBench(1000) : null);" +
		" out += ' | nodes=' + (bench ? ('rows=' + bench.dom_rows + ' matched=' + bench.matched + ' build=' + bench.build_ms + 'ms scroll=' + bench.scroll_ms + 'ms filter=' + bench.filter_ms + 'ms') : 'n/a');" +
		// P17: the node order, the log level + search box and the connection-table
		// sort are persisted so they survive a restart. The check drives the real
		// handlers, reads back what they stored, rebuilds the page state the way a
		// fresh load does and compares the controls - then puts the stored value
		// back, because the profile under webview-data is the real one and a hidden
		// run must not leave test preferences behind for the next real launch.
		" var prefs = 'n/a';" +
		" var presid = 'n/a';" +
		" try {" +
		"   var pkey = 'syan-clash-ui-prefs';" +
		"   var psaved = localStorage.getItem(pkey);" +
		"   var pns = document.querySelector('#nodes-sort');" +
		"   pns.value = 'name'; pns.onchange({ target: pns });" +
		"   document.querySelectorAll('#log-level button')[3].click();" +
		"   var plf = document.querySelector('#log-filter');" +
		"   plf.value = 'SelftestToken'; plf.oninput({ target: plf });" +
		"   var pth = document.querySelector('#page-conns thead th[data-conn-sort=up]');" +
		"   pth.click();" +
		"   var pgs = document.querySelector('#conn-group');" +
		"   pgs.value = 'process'; pgs.onchange({ target: pgs });" +
		"   var pseed = [{ id: 'a', source: 'chrome.exe', rule: 'MATCH', exit: 'N1', up: 1, down: 2, closed: false }," +
		"                { id: 'b', source: 'chrome.exe', rule: 'MATCH', exit: 'N1', up: 3, down: 4, closed: false }," +
		"                { id: 'c', source: 'curl.exe', rule: 'GEOIP,CN', exit: 'DIRECT', up: 5, down: 6, closed: false }];" +
		"   var pgb = groupConns(pseed, 'process');" +
		"   var pgr = groupConns(pseed, 'rule');" +
		"   var pgn = groupConns(pseed, 'node');" +
		"   var pgb2 = pgb.slice().sort(function (x, y) { return x.label < y.label ? -1 : 1; });" +
		"   var pggroup = pgb.length === 2 && pgb[0].label === 'curl.exe' &&" +
		"     pgb2[0].label === 'chrome.exe' && pgb2[0].rows.length === 2 && pgb2[0].up === 4 && pgb2[0].down === 6 &&" +
		"     pgb2[1].label === 'curl.exe' && pgb2[1].rows.length === 1 &&" +
		"     pgr.length === 2 && pgn.length === 2 && pgn[0].label === 'DIRECT' &&" +
		"     groupConns(pseed, '').length === 0 && groupConns([], 'process').length === 0;" +
		"   toggleConnGroup('chrome.exe');" +
		"   var pcfold = state.connCollapsed.has('chrome.exe');" +
		"   toggleConnGroup('chrome.exe');" +
		"   var pcunfold = !state.connCollapsed.has('chrome.exe');" +
		"   var prec = JSON.parse(localStorage.getItem(pkey) || '{}');" +
		"   var pwrote = prec.nodesSort === 'name' && prec.logLevel === 'error' && prec.logFilter === 'SelftestToken' && prec.connSortKey === 'up' && prec.connSortDir === 1 && prec.connGroupBy === 'process';" +
		"   state.nodeSort = ''; state.logLevel = 'all'; state.logFilter = ''; state.connSortKey = ''; state.connSortDir = 1;" +
		"   state.connGroupBy = ''; state.connCollapsed = new Set();" +
		"   pns.value = 'default'; plf.value = ''; pgs.value = '';" +
		"   document.querySelectorAll('#log-level button').forEach(function (b) { b.classList.toggle('active', b.dataset.level === 'all'); });" +
		"   applyUiPrefs();" +
		"   var pback = state.nodeSort === 'name' && pns.value === 'name' && state.logLevel === 'error' &&" +
		"     document.querySelector('#log-level button.active').dataset.level === 'error' &&" +
		"     state.logFilter === 'selftesttoken' && plf.value === 'SelftestToken' &&" +
		"     state.connSortKey === 'up' && state.connSortDir === 1 && pth.dataset.dir === 'asc' &&" +
		"     state.connGroupBy === 'process' && pgs.value === 'process';" +
		"   prefs = (pwrote && pback && pggroup && pcfold && pcunfold) ? 'ok' :" +
		"     ('bad:w' + pwrote + '/r' + pback + '/g' + pggroup + '/f' + pcfold + '/u' + pcunfold);" +
		"   if (psaved === null) { localStorage.removeItem(pkey); } else { localStorage.setItem(pkey, psaved); }" +
		"   presid = (localStorage.getItem(pkey) === psaved) ? 'ok' : 'bad';" +
		"   applyUiPrefs();" +
		" } catch (e) { prefs = 'error:' + (e && e.message ? e.message : e); }" +
		" out += ' | prefs=' + prefs + ' resid=' + presid;" +
		" return out; })()"

	// Vtable slots; see the file comment for where these numbers come from.
	envCreateController  = 3
	ctrlPutIsVisible     = 4
	ctrlPutBounds        = 6
	ctrlClose            = 24
	ctrlGetWebView       = 25
	webviewNavigate      = 5
	webviewExecuteScript = 29
	webviewReload        = 31
	// ICoreWebView2::add_WebMessageReceived, counting IUnknown's three slots.
	webviewAddWebMessageReceived = 34
	// ICoreWebView2WebMessageReceivedEventArgs: get_Source = 3,
	// get_WebMessageAsJson = 4.
	msgArgsGetJSON = 4
	// ICoreWebView2::CallDevToolsProtocolMethod = 36.
	webviewCallCDP = 36

	// Normal runs probe the page after its first paint; a page that never
	// answered a single request is reloaded, at most webViewBootReloads times,
	// before the watchdog stops for good.
	webViewBootTimerID = 3
	webViewBootDelayMS = 15000
	webViewBootProbes  = 6
	webViewBootReloads = 2

	// Chromium's own "never use a proxy" switch. The console only ever talks
	// to 127.0.0.1, so the system proxy can add nothing but failure modes: with
	// the WinINET proxy pointed at the core's mixed port, the requests the page
	// makes after that first paint (state polls, font fetches) have been
	// observed to hang behind the proxy instead of failing over.
	webViewNoProxyArgs = "--no-proxy-server"

	// WebView2 validates TargetCompatibleBrowserVersion and rejects the whole
	// options object when the property reads back empty (E_INVALIDARG), so a
	// well-formed fallback covers the case where the loader cannot name the
	// installed runtime.
	webViewFallbackBrowserVersion = "100.0.0.0"

	// What the boot watchdog asks the page: "ok" means a state poll against
	// the console server has completed.
	webViewProbeScript = "(function () { return window.__syanStatus === 'ok' ? 'ok' : 'no'; })()"

	// The ICoreWebView2EnvironmentOptions object (WebView2.h, IID
	// 2fde08a8-1e9a-4766-8c05-95a9ceb9d1c5) is built in the var block below.
	// Its vtable is IUnknown plus get/put pairs for AdditionalBrowserArguments,
	// Language, TargetCompatibleBrowserVersion and AllowSingleSignOnUsingOS-
	// PrimaryAccount - eleven slots, in that order.

	// HRESULTs the environment-options object returns.
	sOK              = 0
	eNoInterface     = 0x80004002
	eInvalidArgument = 0x80070057
	eOutOfMemory     = 0x8007000E
)

var (
	ole32              = syscall.NewLazyDLL("ole32.dll")
	procCoInitializeEx = ole32.NewProc("CoInitializeEx")
	procCoUninitialize = ole32.NewProc("CoUninitialize")
	procCoTaskMemAlloc = ole32.NewProc("CoTaskMemAlloc")
	procCoTaskMemFree  = ole32.NewProc("CoTaskMemFree")

	procLoadLibraryW  = kernel32.NewProc("LoadLibraryW")
	procGetProcAddr   = kernel32.NewProc("GetProcAddress")
	procGetClientRect = user32.NewProc("GetClientRect")
	procSetTimer      = user32.NewProc("SetTimer")
	procKillTimer     = user32.NewProc("KillTimer")
)

// hresultFailed reports whether an HRESULT is a failure. Only the low 32 bits
// of the register are meaningful; HRESULT is negative when read as signed.
func hresultFailed(hr uintptr) bool {
	return int32(uint32(hr)) < 0
}

// comCall invokes vtable slot of a COM interface. Every COM method receives
// the interface pointer as its first argument, so it is prepended here;
// SyscallN places the leading arguments in registers exactly like a compiled
// call does on amd64.
func comCall(obj uintptr, slot int, args ...uintptr) uintptr {
	vtbl := *(*uintptr)(unsafe.Pointer(obj))
	fn := *(*uintptr)(unsafe.Pointer(vtbl + uintptr(slot)*unsafe.Sizeof(uintptr(0))))
	all := make([]uintptr, 0, len(args)+1)
	all = append(all, obj)
	all = append(all, args...)
	r1, _, _ := syscall.SyscallN(fn, all...)
	return r1
}

// comRelease drops a reference (IUnknown::Release, slot 2).
func comRelease(obj uintptr) {
	if obj != 0 {
		comCall(obj, 2)
	}
}

// vtblOf reads the vtable pointer of a COM interface. Diagnostics only: the
// self-test uses it to tell a live interface apart from recycled memory.
func vtblOf(obj uintptr) uintptr {
	if obj == 0 {
		return 0
	}
	return *(*uintptr)(unsafe.Pointer(obj))
}

// qwordAt reads one machine word at obj+off. Same diagnostic use as vtblOf.
func qwordAt(obj uintptr, off uintptr) uintptr {
	if obj == 0 {
		return 0
	}
	return *(*uintptr)(unsafe.Pointer(obj + off))
}

// dbg writes one diagnostic line while the window runs a self-test (or when
// SYANV_WEBVIEW_DEBUG is set). Normal desktop use stays quiet.
func (c *webViewContext) dbg(format string, args ...any) {
	if !c.selfTest && os.Getenv("SYANV_WEBVIEW_DEBUG") == "" {
		return
	}
	fmt.Fprintf(os.Stderr, "[wv2] "+format+"\n", args...)
}

// The WebView2 loader, unpacked on first use and cached for the process.
var (
	loaderOnce sync.Once
	loaderMod  uintptr
	loaderProc uintptr
	loaderErr  error
)

// ensureWebView2Loader unpacks the embedded loader next to the executable and
// resolves CreateCoreWebView2EnvironmentWithOptions from it.
func ensureWebView2Loader() (uintptr, uintptr, error) {
	loaderOnce.Do(func() {
		path, err := unpackWebView2Loader()
		if err != nil {
			loaderErr = err
			return
		}
		wide, err := syscall.UTF16PtrFromString(path)
		if err != nil {
			loaderErr = err
			return
		}
		mod, _, callErr := procLoadLibraryW.Call(uintptr(unsafe.Pointer(wide)))
		if mod == 0 {
			loaderErr = fmt.Errorf("加载 WebView2Loader.dll 失败：%v", callErr)
			return
		}
		name, _ := syscall.BytePtrFromString("CreateCoreWebView2EnvironmentWithOptions")
		proc, _, _ := procGetProcAddr.Call(mod, uintptr(unsafe.Pointer(name)))
		if proc == 0 {
			loaderErr = fmt.Errorf("WebView2Loader.dll 里没有 CreateCoreWebView2EnvironmentWithOptions")
			return
		}
		loaderMod, loaderProc = mod, proc
	})
	return loaderMod, loaderProc, loaderErr
}

// unpackWebView2Loader writes the embedded DLL where Windows can load it.
// Next to the executable is the natural place; when that folder cannot be
// written the per-user app folder is used instead. A file that already has the
// expected size is reused, so a previous run's mapped DLL is never overwritten.
func unpackWebView2Loader() (string, error) {
	if len(webView2LoaderDLL) == 0 {
		return "", fmt.Errorf("可执行文件里没有内置 WebView2Loader.dll")
	}
	locations := []string{filepath.Join(exeDir(), ".runtime")}
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		locations = append(locations, filepath.Join(local, "syan-clash", "runtime"))
	}
	var firstErr error
	for _, dir := range locations {
		path := filepath.Join(dir, "WebView2Loader.dll")
		if st, err := os.Stat(path); err == nil && st.Size() == int64(len(webView2LoaderDLL)) {
			return path, nil
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		tmp := filepath.Join(dir, fmt.Sprintf("WebView2Loader.%d.tmp", os.Getpid()))
		if err := os.WriteFile(tmp, webView2LoaderDLL, 0o644); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := os.Rename(tmp, path); err != nil {
			// A running copy may still have the old file mapped, which makes
			// the rename fail; the fresh copy under its temporary name loads
			// just as well.
			if _, statErr := os.Stat(tmp); statErr == nil {
				return tmp, nil
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		return path, nil
	}
	if firstErr == nil {
		firstErr = fmt.Errorf("没有可写的目录")
	}
	return "", fmt.Errorf("释放 WebView2Loader.dll 失败：%w", firstErr)
}

const (
	handlerEnv = iota
	handlerController
	handlerScript
	handlerProbe
	handlerMessage
	handlerCookies
)

// webViewHandler is a minimal COM object for the completion handlers. All of
// them have the same shape - IUnknown followed by Invoke(HRESULT, pointer) -
// so one layout and one set of callbacks serves all three; kind selects what
// Invoke does.
//
// COM object layout: the first word of the object is a *pointer* to the
// vtable array, never the array itself. A C++ caller compiles
// handler->QueryInterface(...) into two loads - mov rax, [this] followed by
// call [rax + slot*8] - so an object that stores the function pointers
// directly at offset zero makes the caller read the first eight bytes of a
// callback stub and treat them as a function pointer.
type webViewHandler struct {
	vtbl *[4]uintptr
	kind int
	ctx  *webViewContext
}

var (
	handlerQueryInterface = syscall.NewCallback(func(this, riid, ppv uintptr) uintptr {
		// The only interfaces WebView2 asks these objects for are IUnknown
		// and the handler interface itself, and the answer is the same for
		// both: this object.
		h := (*webViewHandler)(unsafe.Pointer(this))
		h.ctx.dbg("handler QI kind=%d riid=%016X%016X", h.kind, qwordAt(riid, 0), qwordAt(riid, 8))
		if ppv != 0 {
			*(*uintptr)(unsafe.Pointer(ppv)) = this
			comCall(this, 1) // AddRef
		}
		return 0
	})
	handlerAddRef = syscall.NewCallback(func(this uintptr) uintptr {
		h := (*webViewHandler)(unsafe.Pointer(this))
		h.ctx.dbg("handler AddRef kind=%d", h.kind)
		return 1
	})
	handlerRelease = syscall.NewCallback(func(this uintptr) uintptr {
		h := (*webViewHandler)(unsafe.Pointer(this))
		h.ctx.dbg("handler Release kind=%d", h.kind)
		return 1
	})
	handlerInvoke = syscall.NewCallback(func(this, a, b uintptr) uintptr {
		h := (*webViewHandler)(unsafe.Pointer(this))
		h.ctx.dbg("invoke kind=%d hr=0x%08X ptr=0x%X", h.kind, uint32(a), b)
		h.ctx.invoke(h.kind, a, b)
		return 0
	})
)

// handlerKeepAlive pins every handler object handed to WebView2. The objects
// contain the vtables the runtime calls into; without this the garbage
// collector would be free to collect memory Windows still uses.
var (
	handlerKeepAliveMu sync.Mutex
	handlerKeepAlive   []*webViewHandler
)

func newWebViewHandler(kind int, ctx *webViewContext) *webViewHandler {
	vtbl := &[4]uintptr{handlerQueryInterface, handlerAddRef, handlerRelease, handlerInvoke}
	h := &webViewHandler{vtbl: vtbl, kind: kind, ctx: ctx}
	handlerKeepAliveMu.Lock()
	handlerKeepAlive = append(handlerKeepAlive, h)
	handlerKeepAliveMu.Unlock()
	return h
}

// webViewEnvOptions is the ICoreWebView2EnvironmentOptions object handed to
// CreateCoreWebView2EnvironmentWithOptions. WebView2 reads the additional
// browser arguments from it before the browser process starts, which is the
// only chance to pass a switch such as --no-proxy-server.
//
// Like the handlers, the object is a plain struct whose first word points at
// its vtable array; the runtime calls through those slots while it starts
// the browser process.
type webViewEnvOptions struct {
	vtbl *[11]uintptr
	ctx  *webViewContext
	args []uint16
	lang []uint16
	ver  []uint16
}

// guid mirrors the 16-byte in-memory layout of a Windows GUID.
type guid struct {
	data1 uint32
	data2 uint16
	data3 uint16
	data4 [8]byte
}

// The two IIDs the options object answers to: IUnknown and its own
// interface. Everything else must be refused - see envOptQueryInterface.
var (
	iidUnknown    = guid{0x00000000, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	iidEnvOptions = guid{0x2fde08a8, 0x1e9a, 0x4766, [8]byte{0x8c, 0x05, 0x95, 0xa9, 0xce, 0xb9, 0xd1, 0xc5}}
)

var (
	envOptQueryInterface = syscall.NewCallback(func(this, riid, ppv uintptr) uintptr {
		o := (*webViewEnvOptions)(unsafe.Pointer(this))
		if o.ctx != nil {
			o.ctx.dbg("options QI riid=%016X%016X", qwordAt(riid, 0), qwordAt(riid, 8))
		}
		if ppv == 0 {
			return eInvalidArgument
		}
		*(*uintptr)(unsafe.Pointer(ppv)) = 0
		if riid != 0 {
			id := *(*guid)(unsafe.Pointer(riid))
			if id == iidUnknown || id == iidEnvOptions {
				*(*uintptr)(unsafe.Pointer(ppv)) = this
				comCall(this, 1) // AddRef, as QueryInterface must
				if o.ctx != nil {
					o.ctx.dbg("options QI -> S_OK")
				}
				return sOK
			}
		}
		if o.ctx != nil {
			o.ctx.dbg("options QI -> E_NOINTERFACE")
		}
		// Anything else - the ICoreWebView2EnvironmentOptions2 and later
		// revisions - has to answer E_NOINTERFACE: claiming an interface would
		// make the runtime call vtable slots this object does not have.
		return eNoInterface
	})
	envOptAddRef = syscall.NewCallback(func(this uintptr) uintptr {
		return 1
	})
	envOptRelease = syscall.NewCallback(func(this uintptr) uintptr {
		return 1
	})
	envOptGetArgs = syscall.NewCallback(func(this, value uintptr) uintptr {
		o := (*webViewEnvOptions)(unsafe.Pointer(this))
		res := writeTaskMemString(value, o.args)
		if o.ctx != nil {
			o.ctx.dbg("options get_AdditionalBrowserArguments res=0x%08X units=%d", uint32(res), len(o.args))
		}
		return res
	})
	envOptPutArgs = syscall.NewCallback(func(this, value uintptr) uintptr {
		(*webViewEnvOptions)(unsafe.Pointer(this)).args = utf16Copy(value)
		return sOK
	})
	envOptGetLanguage = syscall.NewCallback(func(this, value uintptr) uintptr {
		o := (*webViewEnvOptions)(unsafe.Pointer(this))
		if o.ctx != nil {
			o.ctx.dbg("options get_Language")
		}
		return writeTaskMemString(value, o.lang)
	})
	envOptPutLanguage = syscall.NewCallback(func(this, value uintptr) uintptr {
		(*webViewEnvOptions)(unsafe.Pointer(this)).lang = utf16Copy(value)
		return sOK
	})
	envOptGetBrowserVersion = syscall.NewCallback(func(this, value uintptr) uintptr {
		o := (*webViewEnvOptions)(unsafe.Pointer(this))
		if o.ctx != nil {
			o.ctx.dbg("options get_TargetCompatibleBrowserVersion")
		}
		return writeTaskMemString(value, o.ver)
	})
	envOptPutBrowserVersion = syscall.NewCallback(func(this, value uintptr) uintptr {
		(*webViewEnvOptions)(unsafe.Pointer(this)).ver = utf16Copy(value)
		return sOK
	})
	envOptGetSingleSignOn = syscall.NewCallback(func(this, value uintptr) uintptr {
		if o := (*webViewEnvOptions)(unsafe.Pointer(this)); o.ctx != nil {
			o.ctx.dbg("options get_AllowSingleSignOn")
		}
		if value != 0 {
			*(*int32)(unsafe.Pointer(value)) = 0 // BOOL FALSE: no OS-account sign-in
		}
		return sOK
	})
	envOptPutSingleSignOn = syscall.NewCallback(func(this, value uintptr) uintptr {
		return sOK
	})
)

var (
	envOptionsMu        sync.Mutex
	envOptionsKeepAlive []*webViewEnvOptions
)

// browserVersionForOptions asks the loader which WebView2 runtime is
// installed. The options object has to answer get_TargetCompatibleBrowserVersion
// with a real version string - an empty one makes the runtime reject the
// object (E_INVALIDARG) - and the installed runtime's own version is the one
// value that can never ask for a version that is not there.
func browserVersionForOptions(ctx *webViewContext) string {
	if loaderMod != 0 {
		name, _ := syscall.BytePtrFromString("GetAvailableCoreWebView2BrowserVersionString")
		if proc, _, _ := procGetProcAddr.Call(loaderMod, uintptr(unsafe.Pointer(name))); proc != 0 {
			var version uintptr
			res, _, _ := syscall.SyscallN(proc, 0, uintptr(unsafe.Pointer(&version)))
			if !hresultFailed(res) && version != 0 {
				out := utf16String(version)
				procCoTaskMemFree.Call(version)
				if out != "" {
					if ctx != nil {
						ctx.dbg("options target browser version=%s", out)
					}
					return out
				}
			}
		}
	}
	if ctx != nil {
		ctx.dbg("options target browser version: loader query failed, using %s", webViewFallbackBrowserVersion)
	}
	return webViewFallbackBrowserVersion
}

// webView2RuntimeVersion reports the installed runtime's version, or "" when it
// cannot be read. It is the one number that explains why the embedded UI behaves
// differently on two machines with the same client build.
func webView2RuntimeVersion() string {
	mod, _, err := ensureWebView2Loader()
	if err != nil || mod == 0 {
		return ""
	}
	name, err := syscall.BytePtrFromString("GetAvailableCoreWebView2BrowserVersionString")
	if err != nil {
		return ""
	}
	proc, _, _ := procGetProcAddr.Call(mod, uintptr(unsafe.Pointer(name)))
	if proc == 0 {
		return ""
	}
	var version uintptr
	res, _, _ := syscall.SyscallN(proc, 0, uintptr(unsafe.Pointer(&version)))
	if hresultFailed(res) || version == 0 {
		return ""
	}
	out := utf16String(version)
	procCoTaskMemFree.Call(version)
	return out
}

// newWebViewEnvOptions builds the options object and pins it for the life of
// the process: WebView2 keeps reading it while it starts the browser, and the
// strings it hands out are freed by the runtime with CoTaskMemFree, which is
// why every getter copies into memory from CoTaskMemAlloc.
func newWebViewEnvOptions(ctx *webViewContext, args string) *webViewEnvOptions {
	vtbl := &[11]uintptr{
		envOptQueryInterface,
		envOptAddRef,
		envOptRelease,
		envOptGetArgs,
		envOptPutArgs,
		envOptGetLanguage,
		envOptPutLanguage,
		envOptGetBrowserVersion,
		envOptPutBrowserVersion,
		envOptGetSingleSignOn,
		envOptPutSingleSignOn,
	}
	argsWide, _ := syscall.UTF16FromString(args)
	verWide, _ := syscall.UTF16FromString(browserVersionForOptions(ctx))
	o := &webViewEnvOptions{vtbl: vtbl, ctx: ctx, args: argsWide, ver: verWide}
	envOptionsMu.Lock()
	envOptionsKeepAlive = append(envOptionsKeepAlive, o)
	envOptionsMu.Unlock()
	return o
}

// writeTaskMemString stores a CoTaskMemAlloc copy of wide through out, an
// LPWSTR* out-parameter. A nil slice is reported as NULL, which is how the
// runtime spells "not specified".
func writeTaskMemString(out uintptr, wide []uint16) uintptr {
	if out == 0 {
		return eInvalidArgument
	}
	*(*uintptr)(unsafe.Pointer(out)) = 0
	if len(wide) == 0 {
		return sOK
	}
	ptr, _, _ := procCoTaskMemAlloc.Call(uintptr(len(wide)) * 2)
	if ptr == 0 {
		return eOutOfMemory
	}
	dst := unsafe.Slice((*uint16)(unsafe.Pointer(ptr)), len(wide))
	copy(dst, wide)
	*(*uintptr)(unsafe.Pointer(out)) = ptr
	return sOK
}

// utf16Copy duplicates the NUL-terminated string at ptr, a string the caller
// owns (a put_ argument), into a Go slice.
func utf16Copy(ptr uintptr) []uint16 {
	if ptr == 0 {
		return nil
	}
	wide, _ := syscall.UTF16FromString(utf16String(ptr))
	return wide
}

// webViewContext is the state machine of one WebView2 window: it walks the
// asynchronous creation sequence (environment -> controller -> web view) and
// keeps the objects and their handlers alive for as long as the window exists.
//
// Everything in it runs on the single UI thread of the window, which is the
// only thread WebView2 may be called from. The handlers are invoked by that
// same thread through the window's message loop.
type webViewContext struct {
	url      string
	visible  bool
	selfTest bool

	hwnd uintptr

	env     uintptr
	ctrl    uintptr
	webview uintptr

	envHandler     *webViewHandler
	ctrlHandler    *webViewHandler
	scriptHandler  *webViewHandler
	probeHandler   *webViewHandler
	msgHandler     *webViewHandler
	cookiesHandler *webViewHandler
	// login is set when this window exists only to sign in to an AI service.
	// The capture timer then reads the cookie jar and stores what it finds.
	login        *aiLoginTarget
	cookiesSaved int
	cookieRounds int
	pollCount    int
	bootProbes   int
	bootReloads  int

	selfTestProbes int    // how many times the self-test probe was re-armed
	windowPing     bool   // the self-test ping crossed the JS/native bridge
	result         string // what the self-test script reported
	failed         error  // first asynchronous failure, surfaced to the caller
}

func (c *webViewContext) invoke(kind int, a, b uintptr) {
	switch kind {
	case handlerEnv:
		c.onEnvironment(a, b)
	case handlerController:
		c.onController(a, b)
	case handlerScript:
		c.onScriptResult(a, b)
	case handlerProbe:
		c.onProbeResult(a, b)
	case handlerMessage:
		// Invoke(sender, args): the args pointer is the second one, exactly as
		// for every other event handler in this file.
		c.onWebMessage(b)
	case handlerCookies:
		c.onCookies(a, b)
	}
}

// onWebMessage receives one window-control command from the page's own title
// bar. get_WebMessageAsJson serialises the posted value, and the page posts a
// string, so a message of {"cmd":"min"} arrives as "{\"cmd\":\"min\"}" - outer
// quotes kept and every inner quote backslashed. That escaped form is why a
// plain substring test never matched and the whole title bar stayed dead. The
// payload must be unquoted before its cmd property can be decoded.
//
// The four commands are the four things a title bar does: drag the window,
// minimise it, toggle maximise, and close it - which for this client means
// "hide to the tray", exactly like the native close button already did.
// lastWebMessage is the last title-bar command the page sent. It exists so the
// self-test can prove the JS -> native channel end to end instead of assuming
// it, because a wrong argument index there fails silently.
var (
	lastWebMessage  string
	lastWebCmd      string
	webMessageCount int
)

// WebView2 serializes both postMessage({cmd: ...}) and the older
// postMessage(JSON.stringify({cmd: ...})) form. Only cmd may select an action;
// unrelated fields must never turn into window operations.
func decodeWindowCommand(text string) string {
	if inner := ""; json.Unmarshal([]byte(text), &inner) == nil {
		text = inner
	}
	var message struct {
		Command string `json:"cmd"`
	}
	if json.Unmarshal([]byte(text), &message) != nil {
		return ""
	}
	switch message.Command {
	case "drag", "min", "max", "close", "selftest-ping":
		return message.Command
	default:
		return ""
	}
}

func (c *webViewContext) onWebMessage(args uintptr) {
	if args == 0 || c.hwnd == 0 {
		return
	}
	var msg uintptr
	if res := comCall(args, msgArgsGetJSON, uintptr(unsafe.Pointer(&msg))); hresultFailed(res) || msg == 0 {
		return
	}
	text := utf16String(msg)
	lastWebMessage = text
	webMessageCount++
	procCoTaskMemFree.Call(msg)
	c.dbg("web message: %s", text)
	lastWebCmd = decodeWindowCommand(text)
	switch lastWebCmd {
	case "selftest-ping":
		c.windowPing = true
	case "drag":
		// A synchronous caption drag enters a modal message loop inside the
		// WebView2 callback. Queue it so the callback returns before Windows
		// starts tracking the mouse, using the real screen-space drag origin.
		var cursor struct{ X, Y int32 }
		procGetCursorPos.Call(uintptr(unsafe.Pointer(&cursor)))
		procReleaseCapture.Call()
		procPostMessageW.Call(c.hwnd, wmNCLButtonDown, htCaption, packPoint(cursor.X, cursor.Y))
	case "min":
		procShowWindow.Call(c.hwnd, swMinimize)
	case "max":
		if isZoomed(c.hwnd) {
			procShowWindow.Call(c.hwnd, swRestore)
		} else {
			procShowWindow.Call(c.hwnd, swMaximize)
		}
	case "close":
		procPostMessageW.Call(c.hwnd, wmClose, 0, 0)
	}
}

func (c *webViewContext) onEnvironment(hr, env uintptr) {
	c.dbg("onEnvironment hr=0x%08X env=0x%X", uint32(hr), env)
	if hresultFailed(hr) {
		c.fail(fmt.Errorf("创建 WebView2 环境失败（0x%08X）", uint32(hr)))
		return
	}
	// Completion-handler arguments are borrowed references: the runtime drops
	// its own reference as soon as Invoke returns. Keeping one means taking
	// one - without this the environment is freed under us.
	comCall(env, 1) // AddRef
	c.env = env
	c.dbg("env vtbl=0x%X", vtblOf(env))
	// CreateCoreWebView2Controller(parentWindow, completedHandler): the
	// controller binds a web view to our window.
	res := comCall(c.env, envCreateController, c.hwnd, uintptr(unsafe.Pointer(c.ctrlHandler)))
	c.dbg("CreateController res=0x%08X hwnd=0x%X", uint32(res), c.hwnd)
	if hresultFailed(res) {
		c.fail(fmt.Errorf("创建 WebView2 控制器失败（0x%08X）", uint32(res)))
	}
}

func (c *webViewContext) onController(hr, ctrl uintptr) {
	if hresultFailed(hr) {
		c.fail(fmt.Errorf("WebView2 控制器回调失败（0x%08X）", uint32(hr)))
		return
	}
	// Same borrowed-reference rule as the environment above. This is the
	// reference the client keeps for the whole window lifetime.
	comCall(ctrl, 1) // AddRef
	c.ctrl = ctrl
	c.dbg("onController ctrl=0x%X vtbl=0x%X q1=0x%X q2=0x%X q3=0x%X",
		ctrl, vtblOf(ctrl), qwordAt(ctrl, 8), qwordAt(ctrl, 16), qwordAt(ctrl, 24))
	c.resize()
	if c.visible {
		comCall(c.ctrl, ctrlPutIsVisible, 1)
	}
	var webview uintptr
	res := comCall(c.ctrl, ctrlGetWebView, uintptr(unsafe.Pointer(&webview)))
	if hresultFailed(res) || webview == 0 {
		c.fail(fmt.Errorf("获取 WebView2 核心对象失败（0x%08X）", uint32(res)))
		return
	}
	c.webview = webview
	c.dbg("webview=0x%X vtbl=0x%X getres=0x%08X", webview, vtblOf(webview), uint32(res))
	target, err := syscall.UTF16PtrFromString(c.url)
	if err != nil {
		c.fail(err)
		return
	}
	// The page's own title bar talks back through postMessage; this is the only
	// JS -> native channel and it carries nothing but window commands.
	if c.msgHandler != nil {
		var token int64
		res = comCall(c.webview, webviewAddWebMessageReceived,
			uintptr(unsafe.Pointer(c.msgHandler)), uintptr(unsafe.Pointer(&token)))
		c.dbg("add_WebMessageReceived res=0x%08X", uint32(res))
		if hresultFailed(res) {
			c.fail(fmt.Errorf("注册窗口控制消息失败（0x%08X）", uint32(res)))
			return
		}
	}
	res = comCall(c.webview, webviewNavigate, uintptr(unsafe.Pointer(target)))
	c.dbg("navigate res=0x%08X", uint32(res))
	if c.login != nil {
		// The sign-in page needs a person; the capture timer just keeps the
		// stored jar current while they work.
		procSetTimer.Call(c.hwnd, webViewLoginTimerID, webViewLoginDelayMS, 0)
	}
	if hresultFailed(res) {
		c.fail(fmt.Errorf("打开控制台页面失败（0x%08X）", uint32(res)))
		return
	}
	if c.selfTest {
		procSetTimer.Call(c.hwnd, webViewSelfTestTimerID, webViewSelfTestDelayMS, 0)
		procSetTimer.Call(c.hwnd, webViewPollTimerID, webViewPollPeriodMS, 0)
		c.dbg("timers armed")
		return
	}
	// The visible window gets the boot watchdog: a console that never answers
	// a single request looks exactly like a working one from the outside.
	procSetTimer.Call(c.hwnd, webViewBootTimerID, webViewBootDelayMS, 0)
}

// resize keeps the web view glued to the window's client area. RECT is a
// 16-byte struct, which the x64 calling convention passes by reference.
func (c *webViewContext) resize() {
	if c.ctrl == 0 || c.hwnd == 0 {
		return
	}
	var client rect
	ok, _, _ := procGetClientRect.Call(c.hwnd, uintptr(unsafe.Pointer(&client)))
	if ok == 0 {
		return
	}
	bounds := client
	if r := comCall(c.ctrl, ctrlPutBounds, uintptr(unsafe.Pointer(&bounds))); c.selfTest {
		c.dbg("putBounds res=0x%08X", uint32(r))
	}
}

// onTimer drives both timer arms: the boot watchdog asks a visible window
// whether its page is healthy, and the self-test script (hidden window) asks
// the page what it rendered before taking the window down.
func (c *webViewContext) onTimer(id uintptr) {
	if id == webViewBootTimerID {
		c.onBootWatchdog()
		return
	}
	if id == webViewPollTimerID {
		c.pollCount++
		if c.pollCount <= 12 {
			c.dbg("poll#%d ctrl q0=0x%X q1=0x%X q2=0x%X q3=0x%X", c.pollCount,
				qwordAt(c.ctrl, 0), qwordAt(c.ctrl, 8), qwordAt(c.ctrl, 16), qwordAt(c.ctrl, 24))
			c.dbg("poll#%d webview q0=0x%X q1=0x%X env q0=0x%X", c.pollCount,
				qwordAt(c.webview, 0), qwordAt(c.webview, 8), qwordAt(c.env, 0))
		}
		if c.pollCount == 12 {
			var vis uint32
			hr := comCall(c.ctrl, 3, uintptr(unsafe.Pointer(&vis)))
			c.dbg("poll#12 get_IsVisible hr=0x%08X vis=%d", uint32(hr), vis)
		}
		return
	}
	if id == webViewLoginTimerID {
		c.captureCookies()
		return
	}
	if id != webViewSelfTestTimerID || c.webview == 0 {
		return
	}
	c.dbg("onTimer id=%d webview=0x%X vtbl=0x%X", id, c.webview, vtblOf(c.webview))
	procKillTimer.Call(c.hwnd, id)
	script, err := syscall.UTF16PtrFromString(webViewSelfTestScript)
	if err != nil {
		c.result = "script-encode-error"
		procDestroyWindow.Call(c.hwnd)
		return
	}
	res := comCall(c.webview, webviewExecuteScript, uintptr(unsafe.Pointer(script)), uintptr(unsafe.Pointer(c.scriptHandler)))
	c.dbg("ExecuteScript res=0x%08X", uint32(res))
	if hresultFailed(res) {
		c.result = fmt.Sprintf("script-error:0x%08X", uint32(res))
		procDestroyWindow.Call(c.hwnd)
	}
}

// onScriptResult stores what the page answered and takes the window down,
// which ends the message loop and returns control to runWebViewWindow.
// frameProbe reports what the custom frame actually produced: the non-client
// area Windows left the window (0x0 means the page owns the whole thing) and
// the answer WM_NCHITTEST gives at the top-left corner and in the middle. It
// exists so the self-test can prove the frameless frame is real instead of
// trusting that the code ran.
func frameProbe(hwnd uintptr) string {
	var wr, cr rect
	if ok, _, _ := procGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&wr))); ok == 0 {
		return "n/a"
	}
	if ok, _, _ := procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&cr))); ok == 0 {
		return "n/a"
	}
	ncW := (wr.Right - wr.Left) - cr.Right
	ncH := (wr.Bottom - wr.Top) - cr.Bottom
	corner := hitTestResize(hwnd, packPoint(wr.Left+2, wr.Top+2))
	mid := hitTestResize(hwnd, packPoint(wr.Left+(wr.Right-wr.Left)/2, wr.Top+(wr.Bottom-wr.Top)/2))
	return fmt.Sprintf("nc=%dx%d corner=%d mid=%d ncc=%d/%d msg=%d:%s decoded=%s",
		ncW, ncH, corner, mid, ncCalcCount, ncCalcWParam, webMessageCount, lastWebMessage, lastWebCmd)
}

// packPoint builds the lParam WM_NCHITTEST expects: x in the low word, y in
// the high word, both as signed 16-bit screen coordinates.
func packPoint(x, y int32) uintptr {
	return uintptr(uint32(uint16(x)) | uint32(uint16(y))<<16)
}

func (c *webViewContext) onScriptResult(hr, json uintptr) {
	if hresultFailed(hr) {
		c.result = fmt.Sprintf("script-error:0x%08X", uint32(hr))
	} else {
		c.result = utf16String(json)
	}
	// "status=none" means the page is loaded but its first state poll has not
	// come back yet. That is a cold-start timing, not a broken UI, so the probe
	// is re-armed until the page answers or the budget runs out.
	if c.selfTest && !hresultFailed(hr) &&
		(strings.Contains(c.result, "status=none") || !c.windowPing) && c.selfTestProbes < webViewSelfTestRetries {
		c.selfTestProbes++
		c.dbg("selftest probe retry #%d (page or window bridge not ready)", c.selfTestProbes)
		procSetTimer.Call(c.hwnd, webViewSelfTestTimerID, webViewSelfTestRetryDelayMS, 0)
		return
	}
	if c.selfTest {
		c.result += " | frame=" + frameProbe(c.hwnd)
		if !c.windowPing {
			c.failed = fmt.Errorf("窗口控制自检失败：未收到 WebView2 窗口消息")
		}
	}
	procDestroyWindow.Call(c.hwnd)
}

// onBootWatchdog asks the page whether it ever completed a state poll. The
// interesting failure is silent: the document paints, but every request the
// page makes hangs, so neither the page nor the host sees an error. Only a
// fresh load clears that state, and the page cannot ask for one while its
// own script is stuck behind the same failure, which is why the host asks.
// A healthy page answers "ok" and nothing else happens.
func (c *webViewContext) onBootWatchdog() {
	if c.selfTest || c.webview == 0 || c.hwnd == 0 {
		return
	}
	c.bootProbes++
	if c.bootProbes > webViewBootProbes {
		procKillTimer.Call(c.hwnd, webViewBootTimerID)
		c.dbg("boot watchdog: page never became healthy after %d probes", c.bootProbes-1)
		return
	}
	script, err := syscall.UTF16PtrFromString(webViewProbeScript)
	if err != nil {
		return
	}
	res := comCall(c.webview, webviewExecuteScript, uintptr(unsafe.Pointer(script)), uintptr(unsafe.Pointer(c.probeHandler)))
	c.dbg("boot watchdog probe #%d res=0x%08X", c.bootProbes, uint32(res))
	if hresultFailed(res) {
		c.reloadStalledPage("probe rejected")
	}
}

// onProbeResult reads the watchdog's answer and reloads a page that has not
// finished a single state poll yet. The retry budget is small on purpose: a
// browser broken beyond its network requests must not become a reload loop.
func (c *webViewContext) onProbeResult(hr, json uintptr) {
	if c.webview == 0 {
		return
	}
	if hresultFailed(hr) {
		c.reloadStalledPage(fmt.Sprintf("probe failed 0x%08X", uint32(hr)))
		return
	}
	answer := utf16String(json)
	c.dbg("boot watchdog answer=%s", answer)
	if strings.Contains(answer, "ok") {
		return
	}
	c.reloadStalledPage("no completed state poll")
}

// reloadStalledPage reloads the page after a failed probe. The page is the
// console only - no user input is lost - and a reload is what clears a
// stalled request queue. The watchdog is re-armed so the fresh load is
// checked as well, and the reload count is capped.
func (c *webViewContext) reloadStalledPage(why string) {
	if c.webview == 0 || c.hwnd == 0 {
		return
	}
	c.bootReloads++
	if c.bootReloads > webViewBootReloads {
		c.dbg("boot watchdog: giving up after %d reloads (%s)", c.bootReloads-1, why)
		return
	}
	c.dbg("boot watchdog reload #%d (%s)", c.bootReloads, why)
	comCall(c.webview, webviewReload)
	procSetTimer.Call(c.hwnd, webViewBootTimerID, webViewBootDelayMS, 0)
}

// fail records the first asynchronous failure and closes the window, so
// runWebViewWindow can report it and the caller can fall back to a browser
// window instead of showing an empty shell.
func (c *webViewContext) fail(err error) {
	if c.failed == nil {
		c.failed = err
	}
	if c.hwnd != 0 {
		procDestroyWindow.Call(c.hwnd)
	}
}

// close tears the WebView2 objects down in reverse order of creation.
func (c *webViewContext) close() {
	// The window is gone (or going): no further messages are expected, and
	// the hooks must not outlive it.
	windowHooks = nil
	ctrl, webview, env := c.ctrl, c.webview, c.env
	c.dbg("close ctrl=0x%X vtbl=0x%X webview=0x%X vtbl=0x%X env=0x%X vtbl=0x%X",
		ctrl, vtblOf(ctrl), webview, vtblOf(webview), env, vtblOf(env))
	c.ctrl, c.webview, c.env = 0, 0, 0
	if ctrl != 0 {
		comCall(ctrl, ctrlClose)
		comRelease(ctrl)
	}
	if webview != 0 {
		comRelease(webview)
	}
	if env != 0 {
		comRelease(env)
	}
}

// utf16String reads a NUL-terminated UTF-16 string the runtime owns.
func utf16String(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	out := make([]uint16, 0, 64)
	for i := 0; i < 1<<20; i++ {
		ch := *(*uint16)(unsafe.Pointer(ptr + uintptr(i)*2))
		if ch == 0 {
			break
		}
		out = append(out, ch)
	}
	return string(utf16.Decode(out))
}

// webViewOptions describes one run of the embedded window. selfTest runs with
// visible=false, asks the page a question and returns what it said; the normal
// mode returns only when the window is finally closed.
type webViewOptions struct {
	url      string
	visible  bool
	selfTest bool
	ready    func(hwnd uintptr)
	result   *string
	// login turns this window into the sign-in capture: it opens the service's
	// own page and reads the cookie jar back out, instead of hosting the
	// console. It is the only window in the client that talks to the internet.
	login *aiLoginTarget
}

// runWebViewWindow creates the window and drives the WebView2 creation
// sequence. The thread is locked because a window and its messages belong to
// one OS thread, and WebView2 may only be called from that thread.
func runWebViewWindow(opts webViewOptions) (err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// A panic on the window thread must not take the whole client down
	// silently (the GUI build has no console to show it): it becomes an error
	// the caller can fall back from, and the window it created is destroyed.
	var hwnd uintptr
	defer func() {
		if r := recover(); r != nil {
			if hwnd != 0 {
				procDestroyWindow.Call(hwnd)
			}
			err = fmt.Errorf("内嵌窗口内部错误：%v", r)
		}
	}()

	if err := coInitialize(); err != nil {
		return err
	}
	defer procCoUninitialize.Call()

	_, createEnv, err := ensureWebView2Loader()
	if err != nil {
		return err
	}

	created, err := createMainWindow("syan-clash", cwUseDefault, cwUseDefault, 1360, 900, opts.visible)
	if err != nil {
		return err
	}
	hwnd = created

	ctx := &webViewContext{url: opts.url, visible: opts.visible, selfTest: opts.selfTest, hwnd: hwnd}
	ctx.envHandler = newWebViewHandler(handlerEnv, ctx)
	ctx.ctrlHandler = newWebViewHandler(handlerController, ctx)
	ctx.scriptHandler = newWebViewHandler(handlerScript, ctx)
	ctx.probeHandler = newWebViewHandler(handlerProbe, ctx)
	ctx.msgHandler = newWebViewHandler(handlerMessage, ctx)
	ctx.login = opts.login
	if ctx.login != nil {
		ctx.cookiesHandler = newWebViewHandler(handlerCookies, ctx)
	}

	windowHooks = &windowCallbacks{
		resize:  func(width, height int32) { ctx.resize() },
		destroy: func() { ctx.close() },
		timer:   func(id uintptr) { ctx.onTimer(id) },
		close:   func() bool { return true },
	}
	if opts.ready != nil {
		opts.ready(hwnd)
	}

	userData, err := webViewDataDir()
	if opts.login != nil {
		// WebView2 pins one browser process per profile and the sign-in window
		// needs different browser switches than the console (it goes through
		// the client's proxy, the console must not), so the two cannot share a
		// profile: a second environment on the same folder fails to start.
		userData, err = loginDataDir()
	}
	if err != nil {
		procDestroyWindow.Call(hwnd)
		return err
	}
	folder, err := syscall.UTF16PtrFromString(userData)
	if err != nil {
		procDestroyWindow.Call(hwnd)
		return err
	}
	// The options object carries the browser switches, and this call is the
	// only place they can be handed over: WebView2 reads them once, while it
	// starts the browser process.
	// The console must never loop back through the client's own proxy; the
	// sign-in window must, because the page it opens is usually unreachable
	// from the operator's network without it.
	proxyArgs := webViewNoProxyArgs
	if opts.login != nil && opts.login.ProxyArgs != "" {
		proxyArgs = opts.login.ProxyArgs
	}
	envOptions := newWebViewEnvOptions(ctx, proxyArgs)
	res, _, _ := syscall.SyscallN(createEnv, 0, uintptr(unsafe.Pointer(folder)), uintptr(unsafe.Pointer(envOptions)), uintptr(unsafe.Pointer(ctx.envHandler)))
	if hresultFailed(res) {
		procDestroyWindow.Call(hwnd)
		return fmt.Errorf("WebView2 运行时不可用（0x%08X），请确认系统已安装 WebView2 运行时", uint32(res))
	}

	runMessageLoop()

	if ctx.failed != nil {
		return ctx.failed
	}
	if opts.result != nil {
		*opts.result = ctx.result
	}
	return nil
}

// aiLoginTarget is one AI service's sign-in page, the cookie domains that
// belong to it, and the browser switch that points the window at the client's
// own inbound. The domains are what separates a session cookie from the pile of
// analytics cookies the same browser profile collects.
type aiLoginTarget struct {
	Service string
	URL     string
	Domains []string
	// CookieURL is the page whose cookies the capture asks for. It is the
	// service root, because the sign-in page itself may redirect.
	CookieURL string
	ProxyArgs string
}

// aiLoginTargets is the fixed set of services the AI panel can grade green.
//
// lastCookiesSeen is what the last capture round read out of the browser at
// all, before the service filter. It is the evidence that the DevTools call
// really answered, which a count of stored cookies cannot show on its own.
var lastCookiesSeen int
var lastCookieRounds int

var aiLoginTargets = map[string]aiLoginTarget{
	"chatgpt": {
		Service:   "chatgpt",
		URL:       "https://chatgpt.com/auth/login",
		Domains:   []string{"chatgpt.com", "openai.com"},
		CookieURL: "https://chatgpt.com/",
	},
	"gemini": {
		Service:   "gemini",
		URL:       "https://gemini.google.com/app",
		Domains:   []string{"google.com"},
		CookieURL: "https://gemini.google.com/",
	},
}

// aiLoginTargetFor resolves one service's target and fills in the proxy switch.
func aiLoginTargetFor(service, cfgPath string) (aiLoginTarget, bool) {
	t, ok := aiLoginTargets[service]
	if !ok {
		return aiLoginTarget{}, false
	}
	t.ProxyArgs = loginProxyArgs(cfgPath)
	return t, true
}

// loginProxyArgs reads the client's own inbound address out of the
// configuration and turns it into the browser switch the sign-in window needs.
// It reads the file directly: the sign-in window runs beside the application,
// so there is no live configuration object to ask.
func loginProxyArgs(cfgPath string) string {
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return ""
	}
	var cfg struct {
		Inbound struct {
			HTTPAddr string `json:"http_addr"`
		} `json:"inbound"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return ""
	}
	addr := strings.TrimSpace(cfg.Inbound.HTTPAddr)
	if addr == "" {
		return ""
	}
	return "--proxy-server=http://" + addr
}

// captureCookies asks the page's own browser for its cookie jar through the
// DevTools protocol. Reading the jar here - rather than from the page's own
// script - is what reaches the HttpOnly session cookies a sign-in actually
// sets, which document.cookie can never see.
//
// It has to be the page-target pair Network.enable + Network.getCookies: the
// browser-wide Network.getAllCookies is not reachable through
// CallDevToolsProtocolMethod, and asking for it returns S_OK while the
// completion handler is never called at all.
func (c *webViewContext) captureCookies() {
	if c.webview == 0 || c.login == nil || c.cookiesHandler == nil {
		return
	}
	c.callCDP("Network.enable", "{}")
	c.callCDP("Network.getCookies", `{"urls":["`+c.login.CookieURL+`"]}`)
}

// callCDP issues one DevTools command; whatever it answers arrives in
// onCookies.
func (c *webViewContext) callCDP(method, params string) {
	m, err := syscall.UTF16PtrFromString(method)
	if err != nil {
		return
	}
	p, err := syscall.UTF16PtrFromString(params)
	if err != nil {
		return
	}
	res := comCall(c.webview, webviewCallCDP,
		uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(c.cookiesHandler)))
	c.dbg("cdp %s res=0x%08X", method, uint32(res))
}

// cdpCookie is one entry of Network.getAllCookies.
type cdpCookie struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Domain string `json:"domain"`
	Path   string `json:"path"`
}

type cdpCookieList struct {
	Cookies []cdpCookie `json:"cookies"`
}

// onCookies stores the cookies that belong to the service being signed in to.
// Everything else in the profile is left alone: the store is a session, not a
// copy of the browser.
func (c *webViewContext) onCookies(hr, jsonResult uintptr) {
	if c.login == nil || hresultFailed(hr) || jsonResult == 0 {
		return
	}
	var list cdpCookieList
	if err := json.Unmarshal([]byte(utf16String(jsonResult)), &list); err != nil {
		c.dbg("cookies: unreadable result: %v", err)
		return
	}
	c.cookieRounds++
	lastCookieRounds = c.cookieRounds
	if n := len(list.Cookies); n > lastCookiesSeen {
		lastCookiesSeen = n
	}
	var picked []aisession.Cookie
	for _, ck := range list.Cookies {
		if ck.Name == "" {
			continue
		}
		for _, want := range c.login.Domains {
			if strings.Contains(ck.Domain, want) {
				picked = append(picked, aisession.Cookie{
					Name: ck.Name, Value: ck.Value, Domain: ck.Domain, Path: ck.Path,
				})
				break
			}
		}
	}
	// An empty capture means "not signed in yet", and writing it would wipe a
	// jar captured on an earlier run - so only a real capture is kept.
	if len(picked) == 0 {
		c.dbg("cookies: nothing for %s yet", c.login.Service)
	} else {
		store := aisession.Load()
		if store == nil {
			store = map[string][]aisession.Cookie{}
		}
		store[c.login.Service] = picked
		if err := aisession.Save(store); err != nil {
			c.dbg("cookies: save failed: %v", err)
		} else {
			c.cookiesSaved = len(picked)
			c.dbg("cookies: stored %d for %s", len(picked), c.login.Service)
		}
	}
	if !c.visible {
		// A headless capture asked for exactly one round.
		procDestroyWindow.Call(c.hwnd)
	}
}

// runAILogin is the whole of "syan-clash.exe -ai-login <service>": it opens the
// service's sign-in page in the embedded browser, keeps the captured cookie jar
// current while the person signs in, and closes when they close the window. A
// headless run captures once and exits, which is also how the plumbing is
// verified without putting anything on screen.
func runAILogin(cfgPath, service string, visible bool) error {
	target, ok := aiLoginTargetFor(service, cfgPath)
	if !ok {
		return fmt.Errorf("不认识的 AI 服务 %q（只支持 chatgpt / gemini）", service)
	}
	aisession.SetPath(aisession.DefaultPath(cfgPath))
	if err := runWebViewWindow(webViewOptions{url: target.URL, visible: visible, login: &target}); err != nil {
		return err
	}
	stored := len(aisession.Load()[service])
	fmt.Printf("ai-login: %s -> 抓取 %d 轮，浏览器里看到 %d 条 cookie，属于该服务 %d 条，存到 %s\n",
		service, lastCookieRounds, lastCookiesSeen, stored, aisession.Path())
	if stored == 0 {
		fmt.Println("ai-login: 这一轮没有抓到该服务的 cookie（可能还没登录）")
	}
	return nil
}

// loginDataDir is the sign-in window's own browser profile. Keeping it apart
// from the console's profile also keeps the operator's sign-in out of the
// window that renders the console.
func loginDataDir() (string, error) {
	dir := filepath.Join(exeDir(), "webview-data-login")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("创建 AI 登录数据目录失败：%w", err)
	}
	return dir, nil
}

// coInitialize puts this thread into a single-threaded apartment, which COM
// (and therefore WebView2) requires. A thread that is already initialised is
// fine: RPC_E_CHANGED_MODE means something initialised it as MTA first, which
// still allows hosting the control.
func coInitialize() error {
	hr, _, _ := procCoInitializeEx.Call(0, coinitApartmentThreaded)
	if hresultFailed(hr) && uint32(hr) != rpcEChangedMode {
		return fmt.Errorf("CoInitializeEx 失败（0x%08X）", uint32(hr))
	}
	return nil
}

// webViewDataDir is where the embedded browser keeps its profile. It lives
// beside the executable, with everything else the client owns.
func webViewDataDir() (string, error) {
	if override := os.Getenv("SYANV_WEBVIEW_DATA_DIR"); override != "" {
		if err := os.MkdirAll(override, 0o755); err != nil {
			return "", fmt.Errorf("创建 WebView2 数据目录失败：%w", err)
		}
		return override, nil
	}
	// The client is portable: everything it owns stays in its own folder, so the
	// profile is created beside the executable first. The embedded browser keeps
	// a real browser profile (small files, mapped files, locks) which is why the
	// per-user application folder remains the fallback for the case where the
	// install location itself is read-only.
	candidates := []string{filepath.Join(exeDir(), "webview-data")}
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		candidates = append(candidates, filepath.Join(local, "syan-clash", "webview-data"))
	}
	var firstErr error
	for _, dir := range candidates {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		return dir, nil
	}
	fallback := filepath.Join(os.TempDir(), "syan-clash-webview-data")
	if err2 := os.MkdirAll(fallback, 0o755); err2 != nil {
		return "", fmt.Errorf("创建 WebView2 数据目录失败：%w", firstErr)
	}
	return fallback, nil
}

// windowHost owns the one embedded window. Open is idempotent: a second call
// surfaces the existing window instead of creating another one, and a creation
// that fails falls back to the browser window the client used before (that
// fallback is only reachable when WebView2 is unavailable).
type windowHost struct {
	url      string
	fallback func() error

	mu       sync.Mutex
	hwnd     uintptr
	opening  bool
	lastCall time.Time
}

func newWindowHost(url string, fallback func() error) *windowHost {
	return &windowHost{url: url, fallback: fallback}
}

// Focus surfaces the embedded window if it exists and reports whether it did.
func (h *windowHost) Focus() bool {
	h.mu.Lock()
	hwnd := h.hwnd
	h.mu.Unlock()
	if hwnd == 0 {
		return false
	}
	procPostMessageW.Call(hwnd, wmAppFocus, 0, 0)
	return true
}

// Open creates the window if that has not happened yet.
func (h *windowHost) Open() error {
	h.mu.Lock()
	if h.hwnd != 0 {
		hwnd := h.hwnd
		h.mu.Unlock()
		procPostMessageW.Call(hwnd, wmAppFocus, 0, 0)
		return nil
	}
	// Debounce: a double-clicked exe, a stuck caller or a retry storm must not
	// turn into a pile of windows flashing open on the user's screen.
	if h.opening || time.Since(h.lastCall) < 2*time.Second {
		h.mu.Unlock()
		return nil
	}
	h.opening = true
	h.lastCall = time.Now()
	h.mu.Unlock()

	go func() {
		err := runWebViewWindow(webViewOptions{
			url:     h.url,
			visible: true,
			ready: func(hwnd uintptr) {
				h.mu.Lock()
				h.hwnd = hwnd
				h.mu.Unlock()
			},
		})
		h.mu.Lock()
		h.opening = false
		h.hwnd = 0
		h.mu.Unlock()
		if err == nil {
			return
		}
		fmt.Fprintf(os.Stderr, "syan-clash: 内嵌窗口不可用（%v）\n", err)
		if h.fallback != nil {
			if ferr := h.fallback(); ferr != nil {
				fmt.Fprintln(os.Stderr, "syan-clash: 打开窗口失败：", ferr)
			}
		}
	}()
	return nil
}

// findOwnWindowState collects the client's own windows while EnumWindows runs.
var findOwnWindowState struct {
	found []uintptr
}

var findOwnWindowCallback = syscall.NewCallback(func(hwnd, _ uintptr) uintptr {
	class := make([]uint16, 256)
	n, _, _ := procGetClassNameW.Call(hwnd, uintptr(unsafe.Pointer(&class[0])), uintptr(len(class)))
	if n > 0 && syscall.UTF16ToString(class[:n]) == mainWindowClassName {
		findOwnWindowState.found = append(findOwnWindowState.found, hwnd)
	}
	return 1
})

// ownWindows lists the client's own top-level windows by class.
func ownWindows() []uintptr {
	findOwnWindowState.found = nil
	_, _, _ = procEnumWindows.Call(findOwnWindowCallback, 0)
	return findOwnWindowState.found
}

// closeOwnWindows asks the embedded windows to close for real. Closing by the
// user only hides the window, so quitting has to say what it means.
func closeOwnWindows() {
	n := 0
	for _, hwnd := range ownWindows() {
		procPostMessageW.Call(hwnd, wmAppQuit, 0, 0)
		n++
	}
	if n == 0 {
		return
	}
	// Give the window a moment to run its teardown (WebView2 flushes its
	// profile while closing); quitting does not depend on it finishing.
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(ownWindows()) == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}
