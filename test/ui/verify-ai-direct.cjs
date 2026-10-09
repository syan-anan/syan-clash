const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const vm = require('node:vm');

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
const OUTPUT = path.join(ROOT, 'lab/evidence/ai-direct-20261006');
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
const report = { stage: 'ai-direct', source_sha256: crypto.createHash('sha256').update(source).digest('hex'), created_at: new Date().toISOString(), checks: [], screenshots: [], page_errors: [] };
fs.mkdirSync(OUTPUT, { recursive: true });

const chatgptOK = { status: 'ok', http_status: 200, ms: 420, path: 'https://chatgpt.com/api/auth/session', keyword: 'session endpoint answered', exit_ip: '1.2.3.4', colo: 'LHR', detail: '{"WARNING_BANNER":"do not share"}', at: '2026-10-06T13:00:00Z' };
const geminiOK = { status: 'ok', http_status: 200, ms: 980, path: 'https://aistudio.google.com/prompts/new_chat?model=gemini-3-flash-preview', keyword: 'sign-in redirect', final_url: 'https://accounts.google.com/v3/signin/identifier?continue=https://aistudio.google.com/prompts/new_chat', exit_ip: '1.2.3.4', colo: 'LHR', detail: '<html>Sign in</html>', at: '2026-10-06T13:00:00Z' };
const rows = [
  { node: 'Alpha 01', verdict: 'both', chatgpt: chatgptOK, gemini: geminiOK },
  { node: 'Beta 01', verdict: 'gemini', chatgpt: { status: 'risk', http_status: 403, ms: 300, path: 'https://chatgpt.com/api/auth/session', keyword: 'cloudflare challenge', detail: '<html><title>Just a moment...</title>' }, gemini: geminiOK },
  { node: 'Gamma 01', verdict: 'none', chatgpt: { status: 'region', http_status: 403, ms: 210, path: 'https://chatgpt.com/api/auth/session', keyword: 'unsupported_country', detail: '{"detail":"unsupported_country"}' }, gemini: { status: 'timeout', http_status: 0, ms: 8000, path: 'https://aistudio.google.com/prompts/new_chat', detail: 'context deadline exceeded' } },
];
const aiStatus = { job: '', group: 'XBoard', running: false, phase: 'done', total: rows.length, done: rows.length, restore_state: 'ok', restore_detail: '\u5df2\u5207\u56de\u539f\u8282\u70b9', rows, best: { node: 'Alpha 01', chatgpt: true, gemini: true, ms: 1400 }, errors: [] };

async function record(name, action) {
  try { const detail = await action(); report.checks.push({ name, pass: true, detail }); console.log('PASS ' + name); }
  catch (error) { report.checks.push({ name, pass: false, error: error.message }); console.log('FAIL ' + name + ': ' + error.message); }
}

async function screenshot(page, name) {
  const filename = 'ai-direct-' + name + '.png';
  await page.screenshot({ path: path.join(OUTPUT, filename), fullPage: false });
  report.screenshots.push(filename);
}

async function main() {
  await record('Inline JavaScript syntax', () => {
    const scripts = [...source.matchAll(/<script>([\s\S]*?)<\/script>/g)];
    scripts.forEach((m, i) => new vm.Script(m[1], { filename: 'index-inline-' + i }));
    return { blocks: scripts.length };
  });
  const browser = await chromium.launch({ executablePath: CHROME, headless: true, args: ['--no-proxy-server', '--disable-background-networking'] });
  try {
    const context = await browser.newContext({ viewport: { width: 1280, height: 940 }, deviceScaleFactor: 1, serviceWorkers: 'block' });
    const page = await context.newPage();
    page.on('pageerror', (e) => report.page_errors.push(e.message));
    await context.addInitScript(() => { window.chrome = window.chrome || {}; window.chrome.webview = { postMessage() {} }; });
    await context.route('**/*', async (route) => {
      const url = new URL(route.request().url());
      if (url.origin !== 'http://127.0.0.1:18753') return route.abort('blockedbyclient');
      const endpoint = url.pathname;
      if (endpoint === '/') return route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: source });
      if (endpoint === '/i18n.en.json') return route.fulfill({ status: 200, contentType: 'application/json', body: fs.readFileSync(path.join(ROOT, 'internal/control/web/i18n.en.json')) });
      if (endpoint === '/logo.png' || endpoint === '/qr.png') return route.fulfill({ status: 200, contentType: 'image/png', body: fs.readFileSync(path.join(ROOT, 'internal/control/web/logo.png')) });
      let body = {};
      if (endpoint === '/api/status') body = { version: 'fixture', uptime_sec: 400, started_at: '2026-10-06T02:00:00Z', config_path: 'fixture.json', system_proxy: false, system_proxy_owned: false, engine: 'mihomo', outbound: 'proxy', outbound_name: 'Alpha 01', active_http: '127.0.0.1:17890', active_socks: '127.0.0.1:17891', active_conns: 0, total_conns: 0, rule_count: 0 };
      else if (endpoint === '/api/cores') body = [];
      else if (endpoint === '/api/cores/proxies') body = { groups: [{ name: 'XBoard', type: 'Selector', now: 'Alpha 01', members: ['Alpha 01', 'Beta 01', 'Gamma 01'] }], nodes: [{ name: 'Alpha 01', type: 'trojan', delay: 60 }, { name: 'Beta 01', type: 'vless', delay: 90 }, { name: 'Gamma 01', type: 'ss', delay: 0 }] };
      else if (endpoint === '/api/profile/groups') body = { groups: [{ name: 'XBoard' }, { name: 'GLOBAL' }] };
      else if (endpoint === '/api/diag/ai/status') body = aiStatus;
      else if (endpoint === '/api/diag/ip') body = { via_used: 'proxy', ip: '203.0.113.47', country: 'US', country_name: '\u7f8e\u56fd', region: '\u52a0\u5dde', city: '\u6d1b\u6749\u77f6', isp: 'Psychz Networks', cached: false };
      else if (endpoint === '/api/cores/traffic') body = { up: 0, down: 0 };
      else if (endpoint === '/api/subscriptions') body = [];
      else if (endpoint === '/api/config') body = { rules: [], engine: 'mihomo', profile: { nodes: [], groups: [], rules: [] } };
      else if (endpoint === '/api/system') body = { os: 'windows', arch: 'amd64', elevated: false };
      else if (endpoint === '/api/system/autostart') body = { enabled: false };
      else if (endpoint === '/api/ports') body = [];
      else if (endpoint === '/api/cores/geo') body = { files: [] };
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
    });
    await page.goto('http://127.0.0.1:18753/?nosse=1&theme=dark');
    await page.waitForFunction(() => window.__syanBoot === 'ok' && window.__syanStatus === 'ok');
    await page.locator('#nav button[data-page="ai"]').click();
    await page.locator('#ai-body table').waitFor({ timeout: 8000 });
    await page.waitForTimeout(150);

    await record('Tab bar offers \u5168\u90e8 / \u53cc\u901a\u8fc7 / \u4ec5 ChatGPT / \u4ec5 Gemini with \u5168\u90e8 active', async () => {
      const tabs = await page.evaluate(() => [...document.querySelectorAll('#ai-tabs button')].map((b) => ({ label: b.textContent.trim(), active: b.classList.contains('active') })));
      assert.deepEqual(tabs.map((t) => t.label), ['\u5168\u90e8', '\u53cc\u901a\u8fc7', '\u4ec5 ChatGPT', '\u4ec5 Gemini']);
      assert.equal(tabs[0].active, true, JSON.stringify(tabs));
      return tabs;
    });
    await record('A reachable node reads \u53ef\u7528 without a signed-in session', async () => {
      const cell = await page.evaluate(() => {
        const tr = document.querySelector('#ai-body tbody tr');
        const badge = tr.children[1].querySelector('span.badge');
        return { text: badge.textContent.trim(), cls: badge.className, tip: badge.getAttribute('title') };
      });
      assert.equal(cell.text, '\u53ef\u7528', JSON.stringify(cell));
      assert.match(cell.cls, /\bok\b/);
      assert.match(cell.tip, /WARNING_BANNER/, cell.tip);
      return cell;
    });
    await record('A challenged exit is marked \u9700\u8fc7\u9a8c\u8bc1, not \u53ef\u7528', async () => {
      const cell = await page.evaluate(() => {
        const tr = document.querySelectorAll('#ai-body tbody tr')[1];
        const badge = tr.children[1].querySelector('span.badge');
        return { text: badge.textContent.trim(), cls: badge.className };
      });
      assert.equal(cell.text, '\u9700\u8fc7\u9a8c\u8bc1', JSON.stringify(cell));
      assert.match(cell.cls, /warn/);
      return cell;
    });
    await record("The region test's final URL rides along as evidence", async () => {
      const tip = await page.evaluate(() => document.querySelectorAll('#ai-body tbody tr')[0].children[2].querySelector('span.badge').getAttribute('title'));
      assert.match(tip, /accounts\.google\.com\/v3\/signin/, tip);
      assert.match(tip, /\u6700\u7ec8\u5730\u5740/);
      return { tip: tip.slice(0, 220) };
    });
    await record('\u5168\u90e8 lists every node; \u53cc\u901a\u8fc7 filters to the clean pair', async () => {
      const all = await page.locator('#ai-body tbody tr').count();
      await page.locator('#ai-tabs button[data-tab="both"]').click();
      await page.waitForTimeout(80);
      const both = await page.locator('#ai-body tbody tr').count();
      await page.locator('#ai-tabs button[data-tab="all"]').click();
      await page.waitForTimeout(80);
      const back = await page.locator('#ai-body tbody tr').count();
      assert.equal(all, 3, 'all tab rows');
      assert.equal(both, 1, 'both tab rows');
      assert.equal(back, 3, 'back to all');
      return { all, both, back };
    });
    await record('The sign-in card is optional', async () => {
      const heading = await page.locator('#page-ai .card h3').first().innerText();
      assert.match(heading, /\u53ef\u9009/, heading);
      return heading;
    });
    await screenshot(page, 'page');
    await record('No uncaught browser errors', async () => {
      assert.deepEqual(report.page_errors, []);
      return report.page_errors;
    });
  } finally {
    await browser.close();
  }
  const passed = report.checks.filter((c) => c.pass).length;
  const failed = report.checks.length - passed;
  fs.writeFileSync(path.join(OUTPUT, 'ai-direct-report.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify({ passed, failed }));
  if (failed) process.exit(1);
}

main().catch((error) => { console.error(error); process.exit(1); });
