package control

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// The console is a single hand-written HTML file, so nothing else checks that
// its pieces still line up. These tests work on the embedded asset that the
// server actually ships, which is what catches a page that lost its section or
// a script that references an element that was renamed away.

func webAsset(t *testing.T) string {
	t.Helper()
	raw, err := fs.ReadFile(webFS, "web/index.html")
	if err != nil {
		t.Fatalf("the embedded console asset is missing: %v", err)
	}
	return string(raw)
}

var (
	idPattern  = regexp.MustCompile(`id="([^"]+)"`)
	refPattern = regexp.MustCompile(`\$\("#([A-Za-z0-9_-]+)"\)`)
	// Only section elements count as pages: the header title reuses the
	// "page-" prefix for its id, and it is not a navigable page.
	pagePattern = regexp.MustCompile(`<section class="page[^"]*" id="page-([a-z]+)"`)
	navPattern  = regexp.MustCompile(`data-page="([a-z]+)"`)
	scriptBlock = regexp.MustCompile(`(?s)<script>(.*?)</script>`)
)

// longestScript returns the body of the largest <script> block. The console
// ships a tiny pre-paint theme bootstrap in <head> plus the main script, and
// callers always mean the main one.
func longestScript(t *testing.T, html string) string {
	t.Helper()
	best := ""
	for _, m := range scriptBlock.FindAllStringSubmatch(html, -1) {
		if len(m[1]) > len(best) {
			best = m[1]
		}
	}
	if best == "" {
		t.Fatal("the console has no script block")
	}
	return best
}

func TestConsolePagesAndNavMatch(t *testing.T) {
	html := webAsset(t)

	pages := map[string]bool{}
	for _, m := range pagePattern.FindAllStringSubmatch(html, -1) {
		pages[m[1]] = true
	}
	navs := map[string]bool{}
	for _, m := range navPattern.FindAllStringSubmatch(html, -1) {
		navs[m[1]] = true
	}

	if len(pages) == 0 {
		t.Fatal("no page sections found")
	}
	for page := range navs {
		if !pages[page] {
			t.Errorf("nav button %q has no matching section id=page-%s", page, page)
		}
	}
	for page := range pages {
		if !navs[page] {
			t.Errorf("page-%s has no navigation button", page)
		}
	}
}

func TestEveryElementReferenceExists(t *testing.T) {
	html := webAsset(t)

	ids := map[string]bool{}
	for _, m := range idPattern.FindAllStringSubmatch(html, -1) {
		ids[m[1]] = true
	}
	refs := map[string]bool{}
	for _, m := range refPattern.FindAllStringSubmatch(html, -1) {
		refs[m[1]] = true
	}

	if len(refs) < 40 {
		t.Fatalf("only %d element references found; the extraction is probably broken", len(refs))
	}
	for ref := range refs {
		if !ids[ref] {
			t.Errorf("script references #%s but no such element exists", ref)
		}
	}
}

func TestAPIPathsReferencedByTheConsoleExist(t *testing.T) {
	html := webAsset(t)
	script := longestScript(t, html)

	// Endpoints the console calls. Keep this list in step with the API; the test
	// fails when the UI asks for something the server does not serve.
	known := []string{
		"/api/status", "/api/config", "/api/profile", "/api/presets",
		"/api/about",
		"/api/connections", "/api/connections/close", "/api/cores",
		"/api/cores/install", "/api/cores/start", "/api/cores/stop",
		"/api/cores/config", "/api/cores/updates", "/api/cores/update",
		"/api/cores/proxies", "/api/cores/select", "/api/cores/pick",
		// "全部测速" measures a group without switching; the 选优 buttons use pick.
		"/api/cores/sweep",
		"/api/cores/delay", "/api/cores/mode", "/api/cores/traffic", "/api/cores/connections",
		// P34: the kernel page reads and writes its tuning block (log level,
		// sniffer, tunnel details) through one small document.
		"/api/cores/params",
		"/api/cores/geo",
		"/api/cores/connections/close", "/api/cores/processes",
		"/api/subscriptions", "/api/subscriptions/update", "/api/subscriptions/auto",
		"/api/subscription/parse", "/api/subscription/import",
		"/api/profile/nodes", "/api/profile/rules", "/api/profile/net", "/api/rules/match",
		// P15: rule sets (mihomo rule-providers) - list, upsert, delete.
		"/api/rule-providers",
		// P1-3: proxy sets (mihomo's proxy-providers) - the core keeps the list
		// fresh on its own schedule and a group reaches it through "use".
		"/api/providers",
		"/api/dns",
		"/api/profiles", "/api/profile/nodes/filter", "/api/profile/groups",
		"/api/ports", "/api/ports/relocate",
		"/api/system", "/api/system/tun", "/api/system/autostart",
		"/api/system-proxy",
		// P32: the 设置 page edits the bypass list that sits beside the switch.
		"/api/system-proxy/bypass",
		// P0-1: the 设置 page gains a 系统与服务 card: the service's own
		// install/uninstall lifecycle and the independent proxy-guard switch.
		"/api/system/service", "/api/system/proxy-guard",
		"/api/app/window", "/api/app/quit",
		"/api/panel/state", "/api/panel/login", "/api/panel/logout",
		"/api/panel/info", "/api/panel/subscribe", "/api/panel/import",
		"/api/panel/base", "/api/panel/notice",
		// P49: the "记住密码" switch (default off; off erases what was stored).
		"/api/panel/remember-password",
		"/api/rules/kinds",
		"/api/backup", "/api/logs", "/api/logs/stream",
		// P1-11: the 设置 page keeps a backup rotation on a WebDAV directory.
		"/api/backup/webdav", "/api/backup/webdav/config",
		"/api/backup/webdav/upload", "/api/backup/webdav/download",
		// P1-8 / P1-9: per-subscription User-Agent and refresh interval.
		"/api/subscriptions/options",
		// P1-10: the 内核 page lists archived core builds and rolls back.
		"/api/cores/versions", "/api/cores/versions/activate",
		"/api/cores/connections/close-all",
		"/api/diag/ip", "/api/diag/unlock",
		"/api/diag/matrix/run", "/api/diag/matrix/status", "/api/diag/matrix/cancel",
		"/api/diag/speedtest/start", "/api/diag/speedtest/status",
		"/api/diag/speedtest/cancel", "/api/diag/speedtest/history",
		"/api/diag/dns", "/api/diag/dnsleak", "/api/diag/tcp", "/api/diag/tls", "/api/diag/mtu",
		"/api/diag/trace/start", "/api/diag/trace/status", "/api/diag/trace/cancel",
		// P22: the AI 直达 page probes ChatGPT and Gemini once per node and
		// restores the previous selector when it is done.
		"/api/diag/ai/run", "/api/diag/ai/status", "/api/diag/ai/cancel",
		// P52: the sign-in that makes the green grade mean "the account
		// answered", not just "the network answered".
		"/api/diag/ai/login",
		// P9: the desktop shell's own surface - preferences, the folder
		// buttons, the log export and the subscription QR image.
		"/api/app/prefs", "/api/app/open-dir", "/api/logs/export", "/api/qr",
		// P0-3: the about card checks for a newer build of the client itself.
		"/api/app/update",
		// P2-6: the clash:// link - who owns the scheme, the switch that
		// registers it, and the call that acts on a link.
		"/api/app/url-scheme", "/api/app/url-scheme/handle",
		// The console builds some paths by concatenation ("/api/cores/" + id),
		// so the bare prefix shows up in the script as well.
		"/api/cores/",
	}
	pathPattern := regexp.MustCompile(`"(/api/[a-z0-9/_-]+)`)
	used := map[string]bool{}
	for _, m := range pathPattern.FindAllStringSubmatch(script, -1) {
		used[m[1]] = true
	}
	if len(used) < 15 {
		t.Fatalf("only %d API paths found in the console script", len(used))
	}

	knownSet := map[string]bool{}
	for _, k := range known {
		knownSet[k] = true
	}
	for path := range used {
		if !knownSet[path] {
			t.Errorf("the console calls %s, which is not in the API surface list", path)
		}
	}
}

func TestConsoleDeclaresItsKeyFeatures(t *testing.T) {
	html := webAsset(t)
	// A short list of things the console must offer; losing one of these means a
	// feature was dropped from the UI without anyone noticing.
	required := map[string]string{
		"系统代理开关": `id="sysproxy"`,
		"TUN 开关": `id="tunmode"`,
		"主题切换":   `id="theme-toggle"`,
		"主题三档选择": `id="theme-mode"`,
		// P2-1: the console can be switched to English; the dictionary is a separate
		// asset and i18n_test.go keeps the two in step.
		"界面语言选择":  `id="appearance-lang"`,
		"侧栏品牌标识":  `id="brand-logo"`,
		"规则集管理":   `id="rule-providers-list"`,
		"规则集来源选择": `id="rp-type"`,
		// P2-8: every rule set shows how many entries it carries and when the
		// core last refreshed it, so a set that failed to download is visible.
		"规则集条目数":    `条目 / 更新`,
		"关于页标识":     `id="about-logo"`,
		"实时流量图":     `id="traffic-chart"`,
		"代理组选择":     `data-group=`,
		"节点测速":      `data-test=`,
		"自动选优":      `/api/cores/pick`,
		"订阅管理":      `id="subs-body"`,
		"预设规则集":     `id="presets-list"`,
		"进程分流下拉":    `id="rule-new-process"`,
		"内核管理":      `id="cores-body"`,
		"地理数据补全":    `id="core-geo-fetch"`,
		"当前代理卡片":    `id="ov-node"`,
		"仪表盘测速":     `id="ov-test"`,
		"仪表盘全部测速选优": `id="ov-test-all"`,
		"仪表盘模式切换":   `id="ov-mode"`,
		"配置备份":      `id="backup-export"`,
		"开机自启":      `id="autostart"`,
		"日志过滤":      `id="log-filter"`,
		"内核网络开关":    `id="net-allow-lan"`,
		"DNS 解析器设置": `id="dns-servers"`,
		"DNS 泄漏检测":  `id="dns-leak-run"`,
		"端口冲突修复":    `id="core-ports-fix"`,
		"订阅自动刷新":    `data-sub-auto=`,
		"配置档案":      `id="profiles-body"`,
		"节点过滤":      `id="nodefilter-apply"`,
		"代理组编辑":     `id="groups-body"`,
		// P1-3: the 档案 page manages proxy sets, and a group's member editor
		// carries the checkboxes that reference one.
		"代理集合": `id="providers-body"`,
		"集合引用": `data-me-use=`,
		// P1-3 follow-up: a set's liveness probe is editable from the same
		// card - the add row writes it, the per-set button flips it.
		"代理集合健康检查": `id="providers-newhealth"`,
		"健康检查开关":   `data-provider-hc=`,
		// P1-2: a node can be dialed through another outbound first (mihomo's
		// dialer-proxy). The node table gained the button that opens it, and the
		// dialog saves the whole profile so the core can reject a chain cycle.
		"链式前置代理":    `data-chain="`,
		"剪贴板导入":     `id="sub-clip"`,
		"订阅流量条":     `quotaBar(`,
		"档案页导航":     `data-page="profile"`,
		"诊断页导航":     `data-page="diag"`,
		"AI 直达页导航":  `data-page="ai"`,
		"AI 直达检测按钮": `id="ai-run"`,
		"AI 直达结果表":  `data-ai-pick=`,
		"IP 纯净度卡片":  `id="diag-ip-run"`,
		"解锁检测卡片":    `id="diag-ul-run"`,
		"延迟矩阵卡片":    `id="diag-mx-run"`,
		"测速卡片":      `id="diag-st-run"`,
		"网络工具箱":     `id="diag-nd-tab"`,
		"静默启动":      `id="silent-start"`,
		"数据目录入口":    `id="open-data-dir"`,
		"日志导出":      `id="log-export"`,
		"节点排序":      `id="nodes-sort"`,
		"订阅二维码":     `id="qr-modal"`,
		// P11: the connection table's header sorts, and the 设置 page gained a
		// second folder button beside 打开数据目录.
		"连接页表头排序":  `data-conn-sort="down"`,
		"日志目录入口":   `id="open-log-dir"`,
		"TUN 堆栈选择": `id="tun-stack"`,
		// P13: a saved subscription can be renamed or re-pointed, and a node list
		// can come from a local file instead of the clipboard.
		"订阅编辑":    `data-sub-edit="`,
		"从文件导入订阅": `id="sub-file-pick"`,
		// P32: the system proxy bypass list is editable, and the core table can
		// restart a running core without going through the tray.
		"系统代理绕过名单": `id="sysproxy-bypass"`,
		"内核重启按钮":   `data-restart="`,
		// P34: the kernel page can set the core log level, turn the protocol
		// sniffer on or off, and edit the four tunnel details.
		"内核日志级别":    `id="core-log-level"`,
		"协议嗅探开关":    `id="core-sniff"`,
		"隧道 MTU":    `id="tun-mtu"`,
		"隧道自动路由":    `id="tun-auto-route"`,
		"隧道严格路由":    `id="tun-strict-route"`,
		"隧道 DNS 劫持": `id="tun-dns-hijack"`,
		"内核参数保存":    `id="core-net-save"`,
		"内核参数手动重启":  `id="core-net-restart"`,
		// P0-3: the about card can check for a newer build and remember where
		// that check looks; the overview shows a dismissible notice when one is
		// available, and the download address is copied rather than opened.
		"应用更新检查": `id="about-check-update"`,
		"应用更新源":  `id="about-update-source"`,
		"应用更新提示": `id="app-update-notice"`,
		// P0-1: the service card and the guard switch.
		"服务安装按钮": `id="service-install"`,
		"服务状态":   `id="service-state"`,
		"代理守卫开关": `id="proxy-guard"`,
		// P2-6: the clash:// link. The card shows who owns the scheme, and the
		// switch is the only thing in the console that writes the registry.
		"clash 链接注册开关": `id="urlscheme-toggle"`,
		"clash 链接归属":   `id="urlscheme-owner"`,
	}
	for feature, marker := range required {
		if !strings.Contains(html, marker) {
			t.Errorf("the console no longer offers %s (looked for %s)", feature, marker)
		}
	}
}

func TestConsoleHasNoUnbalancedScriptTag(t *testing.T) {
	html := webAsset(t)
	if strings.Count(html, "<script") != strings.Count(html, "</script>") {
		t.Error("unbalanced script tags")
	}
	if strings.Count(html, "<style") != strings.Count(html, "</style>") {
		t.Error("unbalanced style tags")
	}
	// Tabs in the emitted page come from Go string literals; the HTML itself may
	// have them, but the served asset should be valid UTF-8 without replacement
	// characters.
	if strings.ContainsRune(html, '\uFFFD') {
		t.Error("the console contains replacement characters, which means an encoding mistake")
	}
}
