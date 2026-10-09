const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const vm = require('node:vm');

// Locks in the 0.2.1 feedback work: the refresh buttons spin and report back,
// the AI page always has a group the backend can accept, the diagnostics page
// can probe the exit IP for real instead of answering from cache, the
// dashboard's active-connection card reads the core's own table, and no
// segmented control carries its own backdrop-filter (the nested blur is what
// made the pill's background flicker).
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
const OUTPUT = path.join(ROOT, 'lab/evidence/ui-feedback-20261009');
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
const report = { stage: 'ui-feedback', source_sha256: crypto.createHash('sha256').update(source).digest('hex'), created_at: new Date().toISOString(), checks: [], screenshots: [], page_errors: [], requests: [] };
fs.mkdirSync(OUTPUT, { recursive: true });

async function record(name, action) {
  try { const detail = await action(); report.checks.push({ name, pass: true, detail }); console.log('PASS ' + name); }
  catch (error) { report.checks.push({ name, pass: false, error: error.message }); console.log('FAIL ' + name + ': ' + error.message); }
}

const CONNS = [1, 2, 3, 4, 5, 6, 7].map((n) => ({ id: 'c' + n, host: 'h' + n, destination: 'd' + n, network: 'tcp' }));

async function main() {
  await record('Inline JavaScript syntax', () => {
    const scripts = [...source.matchAll(/<script>([\s\S]*?)<\/script>/g)];
    scripts.forEach((m, i) => new vm.Script(m[1], { filename: 'index-inline-' + i }));
    return { blocks: scripts.length };
  });
  await record('\u5206\u6bb5\u63a7\u4ef6\u4e0d\u518d\u81ea\u5e26 backdrop-filter', () => {
    const rule = /\.seg \{([^}]*)\}/.exec(source);
    assert.ok(rule, '.seg rule is missing');
    assert.doesNotMatch(rule[1], /backdrop-filter/, 'the nested blur is back: ' + rule[1]);
    return rule[1].trim();
  });

  const browser = await chromium.launch({ executablePath: CHROME, headless: true, args: ['--no-proxy-server', '--disable-background-networking'] });
  try {
    const context = await browser.newContext({ viewport: { width: 1360, height: 940 }, deviceScaleFactor: 1, serviceWorkers: 'block' });
    const page = await context.newPage();
    page.on('pageerror', (e) => report.page_errors.push(e.message));
    await context.addInitScript(() => { window.chrome = window.chrome || {}; window.chrome.webview = { postMessage() {} }; });
    let ipHits = 0;
    await context.route('**/*', async (route) => {
      const url = new URL(route.request().url());
      if (url.origin !== 'http://127.0.0.1:18753') return route.abort('blockedbyclient');
      const endpoint = url.pathname;
      report.requests.push({ path: endpoint, query: url.search, method: route.request().method(), body: route.request().postData() || '' });
      if (endpoint === '/') return route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: source });
      if (endpoint === '/i18n.en.json') return route.fulfill({ status: 200, contentType: 'application/json', body: fs.readFileSync(path.join(ROOT, 'internal/control/web/i18n.en.json')) });
      if (endpoint === '/logo.png' || endpoint === '/qr.png') return route.fulfill({ status: 200, contentType: 'image/png', body: fs.readFileSync(path.join(ROOT, 'internal/control/web/logo.png')) });
      let body = {};
      if (endpoint === '/api/status') body = { version: 'fixture', uptime_sec: 400, started_at: '2026-10-09T02:00:00Z', config_path: 'fixture.json', system_proxy: true, system_proxy_owned: true, engine: 'mihomo', outbound: 'proxy', outbound_name: 'Alpha 01', active_http: '127.0.0.1:2903', active_socks: '127.0.0.1:2894', active_conns: 0, total_conns: 0, rule_count: 3 };
      else if (endpoint === '/api/cores') body = [{ id: 'mihomo', name: 'mihomo', installed: true, running: true, emitter_ready: true, version: 'fixture', clash_api: '127.0.0.1:2901', license: 'MIT', repo: 'fixture', pid: 1 }];
      else if (endpoint === '/api/cores/proxies') body = {
        groups: [
          { name: 'GLOBAL', type: 'Selector', now: 'Alpha 01', members: ['Alpha 01'] },
          { name: 'Auto', type: 'URLTest', now: 'Alpha 01', members: ['Alpha 01', 'Beta 01'] },
          { name: 'Pick One', type: 'Selector', now: 'Alpha 01', members: ['Alpha 01', 'Beta 01'] },
        ],
        nodes: [{ name: 'Alpha 01', type: 'trojan', delay: 60 }, { name: 'Beta 01', type: 'vless', delay: 90 }],
      };
      else if (endpoint === '/api/cores/connections') body = { connections: CONNS, upload_total: 10, download_total: 20 };
      else if (endpoint === '/api/cores/traffic') body = { up: 0, down: 0 };
      else if (endpoint === '/api/profile/groups') body = { groups: [{ name: 'Stale Config Group' }, { name: 'GLOBAL' }] };
      else if (endpoint === '/api/profiles') body = [];
      else if (endpoint === '/api/subscriptions') body = [];
      else if (endpoint === '/api/config') body = { rules: [], engine: 'mihomo', profile: { nodes: [], groups: [], rules: [] } };
      else if (endpoint === '/api/system') body = { os: 'windows', arch: 'amd64', elevated: false };
      else if (endpoint === '/api/system/autostart') body = { enabled: false };
      else if (endpoint === '/api/ports') body = [];
      else if (endpoint === '/api/cores/geo') body = { files: [] };
      else if (endpoint === '/api/diag/ai/status') body = { job: '', phase: 'idle', rows: [], errors: [] };
      else if (endpoint === '/api/diag/ai/run') body = { job: 'job-1', group: 'Pick One', total: 2, restore: 'Alpha 01' };
      else if (endpoint === '/api/diag/ip') { ipHits += 1; await new Promise((r) => setTimeout(r, 600)); body = { via_used: 'proxy', ip: '203.0.113.9', country: 'US', country_name: '\u7f8e\u56fd', region: '\u52a0\u5dde', city: '\u6d1b\u6749\u77f6', isp: 'Example ISP', cached: url.searchParams.get('refresh') !== '1' }; }
      else if (endpoint === '/api/diag/unlock') body = { results: [], cached: false };
      else if (endpoint === '/api/diag/matrix') body = { sites: [], nodes: [], cells: [] };
      else if (endpoint === '/api/logs/stream') body = {};
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
    });
    await page.goto('http://127.0.0.1:18753/?nosse=1&theme=dark');
    await page.waitForFunction(() => window.__syanBoot === 'ok' && window.__syanStatus === 'ok');

    await record('\u4eea\u8868\u76d8\u7684\u6d3b\u8dc3\u8fde\u63a5\u8bfb\u5185\u6838\u7684\u8fde\u63a5\u8868', async () => {
      await page.waitForFunction(() => {
        const el = document.querySelector('#ov-conns');
        return el && el.textContent.trim() === '7 \u6761';
      }, null, { timeout: 12000 });
      const sub = await page.locator('#ov-conns-s').innerText();
      assert.equal(sub.trim(), '\u5185\u6838\u5b9e\u65f6', sub);
      const asked = report.requests.filter((r) => r.path === '/api/cores/connections');
      assert.ok(asked.length >= 1, 'the core connection table was never read');
      return { text: await page.locator('#ov-conns').innerText(), sub, hits: asked.length };
    });

    await record('\u5237\u65b0\u6309\u94ae\u5148\u8f6c\u5708\uff0c\u62ff\u5230\u7ed3\u679c\u518d\u590d\u539f\u5e76\u63d0\u793a', async () => {
      const before = ipHits;
      const original = await page.locator('#ov-ip-refresh').evaluate((el) => el.innerHTML);
      await page.locator('#ov-ip-refresh').click();
      await page.waitForFunction(() => !!document.querySelector('#ov-ip-refresh .spin'), null, { timeout: 3000 });
      const spinning = await page.locator('#ov-ip-refresh').evaluate((el) => ({ disabled: el.disabled, hasSpin: !!el.querySelector('.spin') }));
      assert.equal(spinning.disabled, true, JSON.stringify(spinning));
      await page.waitForFunction(() => !document.querySelector('#ov-ip-refresh .spin'), null, { timeout: 8000 });
      const restored = await page.locator('#ov-ip-refresh').evaluate((el) => ({ html: el.innerHTML, disabled: el.disabled }));
      assert.equal(restored.html, original, 'the button must get its own markup back');
      assert.equal(restored.disabled, false, JSON.stringify(restored));
      await page.waitForFunction(() => /203\.0\.113\.9/.test(document.querySelector('#toasts').innerText), null, { timeout: 4000 });
      assert.equal(ipHits, before + 1, 'exactly one probe');
      const toast = await page.locator('#toasts').innerText();
      return { spinning, toast: toast.trim() };
    });

    await record('AI \u76f4\u8fbe\u9884\u9009\u4e00\u4e2a\u5185\u6838\u91cc\u771f\u5b58\u5728\u7684\u5206\u7ec4', async () => {
      await page.locator('#nav button[data-page="ai"]').click();
      await page.waitForFunction(() => document.querySelectorAll('#ai-group option').length > 1, null, { timeout: 8000 });
      const opts = await page.evaluate(() => [...document.querySelectorAll('#ai-group option')].map((o) => o.value));
      const value = await page.locator('#ai-group').inputValue();
      assert.equal(value, 'Pick One', 'expected the first selector group, got ' + JSON.stringify(opts));
      assert.ok(!opts.includes('Stale Config Group'), 'the configured-only group must not be offered: ' + JSON.stringify(opts));
      return { value, opts };
    });

    await record('\u5f00\u59cb\u68c0\u6d4b\u53d1\u51fa\u7684\u5206\u7ec4\u540d\u4e0d\u4e3a\u7a7a', async () => {
      const before = report.requests.length;
      await page.locator('#ai-run').click();
      await page.waitForTimeout(300);
      const posts = report.requests.slice(before).filter((r) => r.path === '/api/diag/ai/run' && r.method === 'POST');
      assert.equal(posts.length, 1, JSON.stringify(posts));
      const sent = JSON.parse(posts[0].body);
      assert.equal(sent.group, 'Pick One', JSON.stringify(sent));
      assert.equal(sent.only_missing, false, JSON.stringify(sent));
      return sent;
    });

    await record('\u8bca\u65ad\u9875\u7684\u73b0\u573a\u68c0\u6d4b\u5ffd\u7565\u7f13\u5b58', async () => {
      await page.locator('#nav button[data-page="diag"]').click();
      await page.waitForTimeout(300);
      const before = report.requests.length;
      await page.evaluate(() => document.querySelector('#diag-ip-live').click());
      await page.waitForTimeout(900);
      const live = report.requests.slice(before).filter((r) => r.path === '/api/diag/ip');
      assert.equal(live.length, 1, JSON.stringify(live));
      assert.match(live[0].query, /refresh=1/, live[0].query);
      assert.doesNotMatch(live[0].query, /compare=1/, live[0].query);
      const cachedBadge = await page.locator('#diag-ip-cached').innerText();
      assert.equal(cachedBadge.trim(), '', 'a live probe must not be labelled as cached');
      return { query: live[0].query, cachedBadge: cachedBadge.trim() };
    });

    await record('\u68c0\u6d4b\u51fa\u53e3 IP \u6309\u94ae\u4ecd\u7136\u8d70\u7f13\u5b58\u8def\u5f84', async () => {
      const before = report.requests.length;
      await page.evaluate(() => document.querySelector('#diag-ip-run').click());
      await page.waitForTimeout(900);
      const hit = report.requests.slice(before).filter((r) => r.path === '/api/diag/ip');
      assert.equal(hit.length, 1, JSON.stringify(hit));
      assert.match(hit[0].query, /refresh=0/, hit[0].query);
      return hit[0].query;
    });

    await page.screenshot({ path: path.join(OUTPUT, 'ui-feedback.png'), fullPage: false });
    report.screenshots.push('ui-feedback.png');
    await record('No uncaught browser errors', () => {
      assert.deepEqual(report.page_errors, []);
      return report.page_errors;
    });
  } finally {
    await browser.close();
  }
  const passed = report.checks.filter((c) => c.pass).length;
  const failed = report.checks.length - passed;
  fs.writeFileSync(path.join(OUTPUT, 'ui-feedback-report.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify({ passed, failed }));
  if (failed) process.exit(1);
}

main().catch((error) => { console.error(error); process.exit(1); });
