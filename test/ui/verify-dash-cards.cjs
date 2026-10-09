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
const OUTPUT = path.join(ROOT, 'lab/evidence/dash-20261007');
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
const report = { stage: 'dash', source_sha256: crypto.createHash('sha256').update(source).digest('hex'), created_at: new Date().toISOString(), checks: [], screenshots: [], page_errors: [] };
fs.mkdirSync(OUTPUT, { recursive: true });

async function record(name, action) {
  try { const detail = await action(); report.checks.push({ name, pass: true, detail }); console.log('PASS ' + name); }
  catch (e) { report.checks.push({ name, pass: false, error: e.message }); console.log('FAIL ' + name + ': ' + e.message); }
}

async function makePage(browser, width, opts = {}) {
  const context = await browser.newContext({ viewport: { width, height: 900 }, deviceScaleFactor: 1, serviceWorkers: 'block' });
  const page = await context.newPage();
  page.on('pageerror', (e) => report.page_errors.push(e.message));
  await context.addInitScript(() => { window.chrome = window.chrome || {}; window.chrome.webview = { postMessage() {} }; });
  let delayHits = 0;
  let trafficTick = 0;
  let trafficHits = 0;
  await context.route('**/*', async (route) => {
    const url = new URL(route.request().url());
    if (url.origin !== 'http://127.0.0.1:18753') return route.abort('blockedbyclient');
    const endpoint = url.pathname;
    if (endpoint === '/') return route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: source });
    if (endpoint === '/i18n.en.json') return route.fulfill({ status: 200, contentType: 'application/json', body: fs.readFileSync(path.join(ROOT, 'internal/control/web/i18n.en.json')) });
    if (endpoint === '/logo.png') return route.fulfill({ status: 200, contentType: 'image/png', body: fs.readFileSync(path.join(ROOT, 'internal/control/web/logo.png')) });
    let body = {};
    if (endpoint === '/api/status') body = { version: 'fixture', uptime_sec: 400, started_at: '2026-10-07T02:00:00Z', config_path: 'fixture.json', system_proxy: true, system_proxy_owned: true, engine: 'mihomo', outbound: 'proxy', outbound_name: 'us\u7f8e\u56fd\u795e\u901fHY02-\u63a8\u8350', active_http: '127.0.0.1:2903', active_socks: '127.0.0.1:2894', active_conns: 0, total_conns: 0, rule_count: 0 };
    else if (endpoint === '/api/cores') body = [{ id: 'mihomo', name: 'mihomo', installed: true, running: true, emitter_ready: true, version: 'fixture', clash_api: '127.0.0.1:2901', license: 'GPL', repo: 'fixture', pid: 1 }];
    else if (endpoint === '/api/cores/proxies') body = {
      groups: [{ name: 'XBoard', type: 'Selector', now: 'us\u7f8e\u56fd\u795e\u901fHY02-\u63a8\u8350', members: ['us\u7f8e\u56fd\u795e\u901fHY02-\u63a8\u8350'] }],
      nodes: [{ name: 'us\u7f8e\u56fd\u795e\u901fHY02-\u63a8\u8350', type: 'trojan', delay: 560 }],
    };
    else if (endpoint === '/api/cores/delay') { delayHits += 1; await new Promise((r) => setTimeout(r, 120)); body = { delays: { XBoard: 185 } }; }
    else if (endpoint === '/api/cores/traffic') {
      trafficHits += 1;
      if (opts.slowTraffic) await new Promise((r) => setTimeout(r, opts.slowTraffic));
      trafficTick += 1;
      body = { up: trafficTick * 512, down: trafficTick * 1024 };
    }
    else if (endpoint === '/api/diag/ip') body = { via_used: 'proxy', ip: '203.0.113.47', country: 'US', country_name: '\u7f8e\u56fd', region: '\u52a0\u5dde', city: '\u6d1b\u6749\u77f6', isp: 'Psychz Networks', cached: false };
    else if (endpoint === '/api/subscriptions') body = [];
    else if (endpoint === '/api/config') body = { rules: [], engine: 'mihomo', profile: { nodes: [], groups: [], rules: [] } };
    else if (endpoint === '/api/system') body = { os: 'windows', arch: 'amd64', elevated: false };
    else if (endpoint === '/api/system/autostart') body = { enabled: false };
    else if (endpoint === '/api/ports') body = [];
    else if (endpoint === '/api/cores/geo') body = { files: [] };
    else if (endpoint === '/api/profile/groups') body = { groups: [{ name: 'XBoard' }] };
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
  });
  await page.goto('http://127.0.0.1:18753/?nosse=1&theme=dark');
  await page.waitForFunction(() => window.__syanBoot === 'ok' && window.__syanStatus === 'ok');
  await page.waitForTimeout(220);
  return { context, page, hits: () => delayHits, trafficHits: () => trafficHits };
}

async function main() {
  await record('Inline JavaScript syntax', () => {
    const scripts = [...source.matchAll(/<script>([\s\S]*?)<\/script>/g)];
    scripts.forEach((m, i) => new vm.Script(m[1], { filename: 'index-inline-' + i }));
    return { blocks: scripts.length };
  });
  const browser = await chromium.launch({ executablePath: CHROME, headless: true, args: ['--no-proxy-server', '--disable-background-networking'] });
  try {
    const probe = async (width) => {
      const f = await makePage(browser, width);
      const box = await f.page.evaluate(() => {
        const card = document.querySelector('#ov-mode').closest('.dash-card');
        const t = card.querySelector('.t');
        const r = t.getBoundingClientRect();
        const cs = getComputedStyle(t);
        return { w: Math.round(r.width), h: Math.round(r.height), lh: parseFloat(cs.lineHeight) || 0, cardW: Math.round(card.getBoundingClientRect().width), cardH: Math.round(card.getBoundingClientRect().height) };
      });
      await f.page.screenshot({ path: path.join(OUTPUT, 'dash-' + width + '.png'), fullPage: false });
      report.screenshots.push('dash-' + width + '.png');
      await f.context.close();
      return box;
    };
    for (const width of [1366, 1280, 1100, 940, 880]) {
      await record('\u4ee3\u7406\u6a21\u5f0f\u5361\u7247\u6807\u9898\u4e0d\u88ab\u6324\u6210\u7ad6\u6392 @' + width, async () => {
        const b = await probe(width);
        assert.ok(b.w >= 45, '\u6807\u9898\u5bbd\u5ea6 ' + b.w + 'px\uff08\u88ab\u6324\u6210\u7ad6\u6392\uff09 ' + JSON.stringify(b));
        assert.ok(b.h <= 26, '\u6807\u9898\u9ad8\u5ea6 ' + b.h + 'px\uff08\u4e0d\u662f\u4e00\u884c\uff09 ' + JSON.stringify(b));
        return b;
      });
    }
    await record('\u6d4b\u901f\u628a\u65b0\u6570\u5b57\u5199\u5230\u5f53\u524d\u8282\u70b9\u4e0a', async () => {
      const f = await makePage(browser, 1280);
      // The overview card fills in from the 5 s proxy poll, so wait for the node
      // to actually land before clicking the test button.
      await f.page.waitForFunction(() => { const el = document.querySelector('#ov-node-sub'); return el && el.textContent.includes('\u5206\u7ec4'); }, null, { timeout: 15000 });
      const before = await f.page.locator('#ov-delay').innerText();
      await f.page.locator('#ov-test').click();
      await f.page.waitForFunction(() => document.querySelector('#ov-delay').textContent.trim() === '185 ms', null, { timeout: 6000 });
      const after = await f.page.locator('#ov-delay').innerText();
      const sub = await f.page.locator('#ov-node-sub').innerText();
      await f.page.screenshot({ path: path.join(OUTPUT, 'dash-delay-refresh.png'), fullPage: false });
      report.screenshots.push('dash-delay-refresh.png');
      await f.context.close();
      assert.equal(before.trim(), '560 ms', 'stale value before the test: ' + before);
      assert.equal(after.trim(), '185 ms');
      assert.match(sub, /185 ms/, sub);
      return { before: before.trim(), after: after.trim(), sub, delayHits: f.hits() };
    });
    await record('仪表盘指标卡不再被整块重建', async () => {
      const f = await makePage(browser, 1280);
      await f.page.waitForFunction(() => document.querySelector('#ov-down') !== null, null, { timeout: 12000 });
      await f.page.evaluate(() => {
        const el = document.querySelector('#ov-down');
        el.__probeKept = 'kept';
        window.__ovDownNode = el;
        window.__ovDownText = el.textContent;
      });
      // Two status polls (2.5 s each) with the traffic sample moving underneath:
      // the old render baked the numbers into the markup and replaced the block.
      await f.page.waitForTimeout(6500);
      const kept = await f.page.evaluate(() => {
        const el = document.querySelector('#ov-down');
        return { same: el === window.__ovDownNode, marker: el.__probeKept, before: window.__ovDownText, after: el.textContent };
      });
      await f.context.close();
      assert.equal(kept.same, true, 'the metric value element was replaced by a re-render');
      assert.equal(kept.marker, 'kept');
      assert.notEqual(kept.after, kept.before, 'the value stopped updating: ' + JSON.stringify(kept));
      return kept;
    });
    await record('慢响应不会让轮询堆叠', async () => {
      // 2.5 s answers against a 1 s ticker: without the guard this is ~6 requests
      // in 6 s, with it the in-flight answer blocks the next two ticks.
      const f = await makePage(browser, 1280, { slowTraffic: 2500 });
      await f.page.waitForTimeout(6000);
      const hits = f.trafficHits();
      await f.context.close();
      assert.ok(hits <= 4, 'traffic polls stacked: ' + hits + ' requests in 6 s');
      return { hits };
    });
    await record('No uncaught browser errors', async () => { assert.deepEqual(report.page_errors, []); return report.page_errors; });
  } finally {
    await browser.close();
  }
  const passed = report.checks.filter((c) => c.pass).length;
  const failed = report.checks.length - passed;
  fs.writeFileSync(path.join(OUTPUT, 'dash-report.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify({ passed, failed }));
  if (failed) process.exit(1);
}
main().catch((e) => { console.error(e); process.exit(1); });
