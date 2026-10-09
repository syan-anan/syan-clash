const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
// Resolved by walking up to the module root, so the suite runs from wherever
// it is checked out instead of depending on its depth below the repo.
function findRepoRoot(start) {
  let d = start;
  for (;;) {
    if (fs.existsSync(path.join(d, 'go.mod'))) return d;
    const up = path.dirname(d);
    if (up === d) throw new Error('go.mod not found above ' + start);
    d = up;
  }
}
const ROOT = findRepoRoot(__dirname);
const OUTPUT = path.join(ROOT, 'lab/evidence/node-route-20261008');
const CHROME = process.env.CHROME_PATH || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
function loadPlaywright() {
  const bases = [
    process.env.CODEX_NODE_MODULES,
    'C:/Users/\u5b89\u4e09\u5c81/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules',
  ].filter(Boolean);
  for (const base of bases) {
    try { return require(path.join(base, 'playwright')); } catch (e) {}
  }
  return require('playwright');
}
const { chromium } = loadPlaywright();
const source = fs.readFileSync(path.join(ROOT, 'internal/control/web/index.html'), 'utf8');
fs.mkdirSync(OUTPUT, { recursive: true });
const report = { checks: [], page_errors: [] };

const NODES = ['N1', 'N2', 'N3', 'N4', 'N5', 'N6'];
async function record(name, fn) {
  try { const d = await fn(); report.checks.push({ name, pass: true, detail: d }); console.log('PASS ' + name); }
  catch (e) { report.checks.push({ name, pass: false, error: e.message }); console.log('FAIL ' + name + ': ' + e.message); }
}

async function makePage(browser, { staleXBoard }) {
  const context = await browser.newContext({ viewport: { width: 1366, height: 940 }, serviceWorkers: 'block' });
  const page = await context.newPage();
  page.on('pageerror', (e) => report.page_errors.push(e.message));
  await context.addInitScript(() => { window.chrome = window.chrome || {}; window.chrome.webview = { postMessage() {} }; });
  const xboardMembers = staleXBoard ? ['\u81ea\u52a8\u9009\u62e9', '\u6545\u969c\u8f6c\u79fb', 'OLD-1', 'OLD-2'] : ['\u81ea\u52a8\u9009\u62e9', '\u6545\u969c\u8f6c\u79fb', ...NODES];
  const selectCalls = [];
  await context.route('**/*', async (route) => {
    const url = new URL(route.request().url());
    if (url.origin !== 'http://127.0.0.1:18753') return route.abort('blockedbyclient');
    const e = url.pathname;
    if (e === '/') return route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: source });
    if (e === '/i18n.en.json') return route.fulfill({ status: 200, contentType: 'application/json', body: fs.readFileSync(path.join(ROOT, 'internal/control/web/i18n.en.json')) });
    if (e === '/logo.png') return route.fulfill({ status: 200, contentType: 'image/png', body: fs.readFileSync(path.join(ROOT, 'internal/control/web/logo.png')) });
    let body = {};
    let data = null;
    try { data = route.request().postDataJSON(); } catch {}
    if (e === '/api/status') body = { version: 'x', uptime_sec: 60, engine: 'mihomo', outbound: 'proxy', outbound_name: 'N1', active_http: '127.0.0.1:2903', active_socks: '127.0.0.1:2894', active_conns: 0, total_conns: 0 };
    else if (e === '/api/cores') body = [{ id: 'mihomo', name: 'mihomo', installed: true, running: true, emitter_ready: true, clash_api: '127.0.0.1:2901', pid: 1 }];
    else if (e === '/api/cores/mode') body = { mode: 'rule' };
    else if (e === '/api/cores/proxies') body = {
      groups: [
        { name: 'GLOBAL', type: 'Selector', now: 'XBoard', members: ['XBoard', '\u6545\u969c\u8f6c\u79fb', '\u81ea\u52a8\u9009\u62e9', ...NODES] },
        { name: 'XBoard', type: 'Selector', now: 'N1', members: xboardMembers },
        { name: '\u81ea\u52a8\u9009\u62e9', type: 'URLTest', now: 'N1', members: NODES.slice(0, 3) },
        { name: '\u6545\u969c\u8f6c\u79fb', type: 'Fallback', now: 'N1', members: NODES.slice(0, 3) },
      ],
      nodes: NODES.map((n, i) => ({ name: n, type: 'trojan', delay: 100 + i })),
    };
    else if (e === '/api/cores/select') { selectCalls.push(data); body = { ok: true }; }
    else if (e === '/api/config') body = {
      rules: [], engine: 'mihomo',
      core: { profile: { final: 'XBoard', nodes: NODES.map((n) => ({ name: n })), groups: [
        { name: 'XBoard', type: 'select', members: xboardMembers },
        { name: '\u81ea\u52a8\u9009\u62e9', type: 'url-test', members: NODES.slice(0, 3) },
        { name: '\u6545\u969c\u8f6c\u79fb', type: 'fallback', members: NODES.slice(0, 3) },
      ] } },
    };
    else if (e === '/api/cores/traffic') body = { up: 0, down: 0 };
    else if (e === '/api/diag/ip') body = { ip: '1.2.3.4', country_name: '\u7f8e\u56fd', region: '\u52a0\u5dde', city: '\u6d1b\u6749\u77f6', isp: 'x' };
    else if (e === '/api/subscriptions') body = [];
    else if (e === '/api/system') body = { os: 'windows' };
    else if (e === '/api/system/autostart') body = { enabled: false };
    else if (e === '/api/ports') body = [];
    else if (e === '/api/cores/geo') body = { files: [] };
    else if (e === '/api/profile/groups') body = { groups: [] };
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
  });
  await page.goto('http://127.0.0.1:18753/?nosse=1&theme=dark');
  await page.waitForFunction(() => window.__syanBoot === 'ok' && window.__syanStatus === 'ok');
  await page.locator('#nav button[data-page="nodes"]').click();
  await page.waitForFunction(() => document.querySelector('#nodes-body [data-switch]') !== null, null, { timeout: 15000 });
  await page.waitForTimeout(300);
  return { context, page, selectCalls };
}

(async () => {
  const browser = await chromium.launch({ executablePath: CHROME, headless: true, args: ['--no-proxy-server', '--disable-background-networking'] });
  try {
    await record('\u5206\u7ec4\u4e0e\u8282\u70b9\u4e00\u81f4\u65f6\u53ef\u4ee5\u5207\u6362', async () => {
      const f = await makePage(browser, { staleXBoard: false });
      await f.page.locator('#nodes-body [data-switch="N3"]').click();
      await f.page.waitForTimeout(900);
      const toasts = await f.page.evaluate(() => [...document.querySelectorAll('#toasts .toast')].map((t) => t.textContent));
      await f.page.screenshot({ path: path.join(OUTPUT, 'route-ok.png') });
      await f.context.close();
      assert.ok(!toasts.some((t) => t.includes('\u6ca1\u6709\u53ef\u624b\u52a8\u5207\u6362')), 'tip shown: ' + JSON.stringify(toasts));
      assert.ok(f.selectCalls.length > 0, 'no select was issued: ' + JSON.stringify(toasts));
      return { toasts, selects: f.selectCalls.length };
    });
    await record('\u5206\u7ec4\u91cc\u6ca1\u6709\u8be5\u8282\u70b9\u65f6\u624d\u4f1a\u62a5\u8fd9\u4e2a\u63d0\u793a', async () => {
      const f = await makePage(browser, { staleXBoard: true });
      await f.page.locator('#nodes-body [data-switch="N3"]').click();
      await f.page.waitForTimeout(700);
      const toasts = await f.page.evaluate(() => [...document.querySelectorAll('#toasts .toast')].map((t) => t.textContent));
      await f.page.screenshot({ path: path.join(OUTPUT, 'route-stale.png') });
      await f.context.close();
      assert.ok(toasts.some((t) => t.includes('\u6ca1\u6709\u53ef\u624b\u52a8\u5207\u6362')), 'expected the tip: ' + JSON.stringify(toasts));
      return { toasts };
    });
  } finally { await browser.close(); }
  const failed = report.checks.filter((c) => !c.pass).length;
  fs.writeFileSync(path.join(OUTPUT, 'node-route-report.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify({ passed: report.checks.length - failed, failed }));
})();
