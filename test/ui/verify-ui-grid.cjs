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
const OUTPUT = path.join(ROOT, 'lab/evidence/ui-grid-20261006');
const stage = 'grid-final';
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
const report = { stage, source_sha256: crypto.createHash('sha256').update(source).digest('hex'), created_at: new Date().toISOString(), checks: [], requests: [], screenshots: [], page_errors: [] };
fs.mkdirSync(OUTPUT, { recursive: true });

const fixtureNodes = [
  { name: 'Alpha 01', type: 'vmess', delay: 62 },
  { name: 'Alpha 02', type: 'trojan', delay: 91 },
  { name: 'Shared Node', type: 'ss', delay: 33 },
  { name: 'Beta 01', type: 'vless', delay: 44 },
  { name: 'Unassigned Node', type: 'ss', delay: 0 },
];
const fixtureGroups = [
  { name: 'Alpha Selector', type: 'Selector', now: 'Alpha 01', members: ['Alpha 01', 'Alpha 02', 'Shared Node', 'DIRECT'] },
  { name: 'Beta Selector', type: 'Selector', now: 'Beta 01', members: ['Beta 01', 'Shared Node'] },
  { name: 'Auto Group', type: 'URLTest', now: 'Alpha 01', members: ['Alpha 01', 'Alpha 02'] },
];
const fixtureSub = {
  name: 'Synthetic subscription', url: 'https://fixture.invalid/subscription', nodes: 5,
  auto: false, interval_hours: 24, updated_at: '2026-10-03T02:00:00Z',
  info: { upload: 1024, download: 2048, total: 100000000000, expire: 1893456000 },
  node_names: ['Alpha 01', 'Alpha 02', 'Shared Node', 'Beta 01', 'Unassigned Node'],
};
const core = { id: 'mihomo', name: 'mihomo', installed: true, running: true, emitter_ready: true, version: 'fixture', clash_api: '127.0.0.1:19090', license: 'GPL', repo: 'fixture', pid: 1 };
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function record(name, action) {
  try {
    const detail = await action();
    report.checks.push({ name, pass: true, detail });
    console.log('PASS ' + name);
  } catch (error) {
    report.checks.push({ name, pass: false, error: error.message });
    console.log('FAIL ' + name + ': ' + error.message);
  }
}

async function screenshot(page, name) {
  const filename = stage + '-' + name + '.png';
  await page.screenshot({ path: path.join(OUTPUT, filename), fullPage: false });
  report.screenshots.push(filename);
}

async function setup(browser, { width = 1280, height = 900, frameless = true, many = false, empty = false, noCore = false, theme = 'dark' } = {}) {
  const context = await browser.newContext({ viewport: { width, height }, deviceScaleFactor: 1, serviceWorkers: 'block' });
  const page = await context.newPage();
  const model = { subs: empty ? [] : [structuredClone(fixtureSub)], nodes: empty ? [] : structuredClone(fixtureNodes), groups: empty ? [] : structuredClone(fixtureGroups), mode: 'rule', rejectSelect: false };
  if (many) {
    model.groups = Array.from({ length: 24 }, (_, i) => ({ name: 'Selector ' + String(i + 1).padStart(2, '0'), type: 'Selector', now: 'Alpha 01', members: ['Alpha 01', 'Alpha 02', 'Shared Node'] }));
  }
  page.on('pageerror', (error) => report.page_errors.push(error.message));
  await context.addInitScript(({ frameless }) => {
    window.__fixtureWindowMessages = [];
    if (frameless) {
      window.chrome = window.chrome || {};
      window.chrome.webview = { postMessage(value) { window.__fixtureWindowMessages.push(typeof value === 'string' ? JSON.parse(value) : value); } };
    }
  }, { frameless });
  await context.route('**/*', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const endpoint = url.pathname;
    if (url.origin !== 'http://127.0.0.1:18753') {
      report.requests.push({ method: request.method(), path: 'BLOCKED_EXTERNAL', blocked: true });
      return route.abort('blockedbyclient');
    }
    if (endpoint === '/') return route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: source });
    if (endpoint === '/logo.png' || endpoint === '/fonts/syan-round.woff2') {
      const asset = path.join(ROOT, 'internal/control/web', endpoint);
      return route.fulfill({ status: 200, contentType: endpoint.endsWith('.png') ? 'image/png' : 'font/woff2', body: fs.readFileSync(asset) });
    }
    if (endpoint === '/i18n.en.json') return route.fulfill({ status: 200, contentType: 'application/json', body: fs.readFileSync(path.join(ROOT, 'internal/control/web/i18n.en.json')) });
    let body = {};
    let status = 200;
    let data = null;
    try { data = request.postDataJSON(); } catch {}
    const entry = { method: request.method(), path: endpoint, query: url.search, body: data };
    report.requests.push(entry);
    if (endpoint === '/api/status') body = { version: 'fixture', uptime_sec: 400, started_at: '2026-10-03T02:00:00Z', config_path: 'fixture.json', system_proxy: false, system_proxy_owned: false, engine: 'mihomo', outbound: 'proxy', outbound_name: 'Alpha 01', active_http: '127.0.0.1:17890', active_socks: '127.0.0.1:17891', active_conns: 0, total_conns: 0, rule_count: 0 };
    else if (endpoint === '/api/cores') body = noCore ? [] : [core];
    else if (endpoint === '/api/cores/proxies') body = { groups: model.groups, nodes: model.nodes };
    else if (endpoint === '/api/cores/select') {
      await delay(320);
      if (model.rejectSelect) { status = 500; body = { error: 'Synthetic selection failure' }; }
      else {
        const group = model.groups.find((group) => group.name === data.group);
        if (!group || !group.members.includes(data.name)) { status = 400; body = { error: 'Invalid synthetic group selection' }; }
        else { group.now = data.name; body = { ok: true }; }
      }
    } else if (endpoint === '/api/cores/mode') { if (data) model.mode = data.mode; body = { mode: model.mode }; }
    else if (endpoint === '/api/cores/delay') {
      const target = url.searchParams.get('name') || '';
      const node = model.nodes.find((item) => item.name === target);
      await delay(40);
      body = { delays: { [target]: node && node.delay ? node.delay : 120 } };
    }
    else if (endpoint === '/api/diag/ip') body = { via_used: 'proxy', ip: '203.0.113.47', country: 'US', country_name: '美国', region: '加州', city: '洛杉矶', isp: 'Psychz Networks', cached: false };
    else if (endpoint === '/api/cores/traffic') body = { up: 0, down: 0 };
    else if (endpoint === '/api/subscriptions' && request.method() === 'GET') body = model.subs;
    else if (endpoint === '/api/subscriptions' && request.method() === 'PATCH') {
      const sub = model.subs.find((sub) => sub.name === data.name);
      Object.assign(sub, { name: data.new_name, url: data.url }); body = sub;
    } else if (endpoint === '/api/subscriptions' && request.method() === 'DELETE') {
      model.subs = model.subs.filter((sub) => sub.name !== url.searchParams.get('name')); body = { ok: true };
    } else if (endpoint === '/api/subscriptions/update') { await delay(320); body = model.subs.find((sub) => sub.name === data.name); }
    else if (endpoint === '/api/subscriptions/options') {
      const sub = model.subs.find((sub) => sub.name === data.name);
      Object.assign(sub, { user_agent: data.user_agent, interval_override_hours: data.interval_hours }); body = sub;
    } else if (endpoint === '/api/config') body = { rules: [], engine: 'mihomo', profile: { nodes: model.nodes, groups: model.groups, rules: [] } };
    else if (endpoint === '/api/system') body = { os: 'windows', arch: 'amd64', elevated: false };
    else if (endpoint === '/api/system/autostart') body = { enabled: false };
    else if (endpoint === '/api/ports') body = [];
    else if (endpoint === '/api/cores/geo') body = { files: [] };
    else if (endpoint === '/api/qr') return route.fulfill({ status: 200, contentType: 'image/png', body: fs.readFileSync(path.join(ROOT, 'internal/control/web/logo.png')) });
    return route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
  });
  await page.goto('http://127.0.0.1:18753/?nosse=1&theme=' + theme);
  await page.waitForFunction(() => window.__syanBoot === 'ok' && window.__syanStatus === 'ok');
  await page.waitForTimeout(180);
  return { context, page, model };
}

async function nodePage(page) {
  await page.locator('#nav button[data-page="nodes"]').click();
  await page.locator('#nodes-rows').waitFor();
  await page.waitForTimeout(100);
}

async function main() {
  await record('Inline JavaScript syntax', () => {
    const scripts = [...source.matchAll(/<script>([\s\S]*?)<\/script>/g)];
    scripts.forEach((match, i) => new vm.Script(match[1], { filename: 'index-inline-' + i }));
    return { blocks: scripts.length };
  });
  const browser = await chromium.launch({ executablePath: CHROME, headless: true, args: ['--no-proxy-server', '--disable-background-networking'] });
  try {
    const base = await setup(browser);
    const { page } = base;
    await record('Dashboard shows the exit IP with country and region', async () => {
      await page.waitForFunction(() => {
        const el = document.querySelector('#ov-ip');
        return el && el.textContent.trim() && el.textContent.trim() !== '-';
      }, null, { timeout: 8000 });
      const ip = await page.locator('#ov-ip').innerText();
      const where = await page.locator('#ov-ip-isp').innerText();
      assert.match(ip, /^\d+\.\d+\.\d+\.\d+$/, ip);
      assert.match(where, /\u7f8e\u56fd/, where);
      assert.match(where, /\u52a0\u5dde/, where);
      assert.match(where, /\u6d1b\u6749\u77f6/, where);
      // The whole line has to read Chinese: the English carrier name is dropped.
      assert.equal(/[A-Za-z]/.test(where), false, 'the location line still carries Latin text: ' + where);
      return { ip, where };
    });
    await record('Window controls send one command each', async () => {
      for (const button of ['#wb-min', '#wb-max', '#wb-close']) await page.locator(button).click();
      const messages = await page.evaluate(() => window.__fixtureWindowMessages);
      assert.deepEqual(messages.map((item) => item.cmd), ['min', 'max', 'close']);
      return messages;
    });
    await record('Title bar drag emits drag command', async () => {
      const box = await page.locator('#wb-grip').boundingBox();
      await page.mouse.move(box.x + 25, box.y + box.height / 2);
      await page.mouse.down(); await page.mouse.move(box.x + 65, box.y + box.height / 2 + 30); await page.mouse.up();
      const messages = await page.evaluate(() => window.__fixtureWindowMessages);
      assert.equal(messages.at(-1).cmd, 'drag');
      return messages.slice(3);
    });
    await nodePage(page);
    await screenshot(page, 'nodes-desktop');
    await record('Node table precedes proxy group controls', async () => {
      const detail = await page.evaluate(() => {
        const list = document.querySelector('#nodes-scroll').getBoundingClientRect();
        const control = document.querySelector('#nodes-body [data-pick]');
        const group = control && control.getBoundingClientRect();
        return { list_top: list.top, list_bottom: list.bottom, group_top: group && group.top, first_node_top: document.querySelector('[data-node-row]').getBoundingClientRect().top, viewport: innerHeight };
      });
      assert.ok(detail.first_node_top < detail.viewport - 80, JSON.stringify(detail));
      if (detail.group_top !== null) assert.ok(detail.list_top < detail.group_top, JSON.stringify(detail));
      return detail;
    });
    await record('A card with no route says why instead of doing nothing', async () => {
      const before = report.requests.length;
      await page.locator('[data-switch="Unassigned Node"]').click();
      await page.waitForTimeout(250);
      const requests = report.requests.slice(before).filter((item) => item.path === '/api/cores/select');
      assert.equal(requests.length, 0, JSON.stringify(requests));
      assert.match(await page.locator('#toasts').innerText(), /\u6ca1\u6709\u53ef\u624b\u52a8\u5207\u6362\u5230\u6b64\u8282\u70b9\u7684\u4ee3\u7406\u7ec4\u8def\u5f84/);
      return { requests: 0, title: await page.locator('[data-switch="Unassigned Node"]').getAttribute('title') };
    });
    await record('Clicking the card switches and keeps the same card', async () => {
      const card = page.locator('[data-switch="Alpha 02"]');
      const before = report.requests.length;
      await card.evaluate((el) => { window.__selectedNodeElement = el; });
      await card.click();
      await page.waitForTimeout(60);
      assert.match(await card.getAttribute('class') || '', /switching/, 'the card should show a pending mark while its request runs');
      await page.waitForTimeout(560);
      const requests = report.requests.slice(before).filter((item) => item.path === '/api/cores/select');
      assert.deepEqual(requests.map((item) => item.body), [{ id: 'mihomo', group: 'Alpha Selector', name: 'Alpha 02' }]);
      const selected = page.locator('[data-node-row="Alpha 02"]');
      assert.match(await selected.getAttribute('class') || '', /row-sel/);
      assert.doesNotMatch(await card.getAttribute('class') || '', /switching/, 'the pending mark must be gone');
      const replaced = await page.evaluate(() => window.__selectedNodeElement !== document.querySelector('[data-switch="Alpha 02"]'));
      return { requests, dom_replaced_by_refresh: replaced };
    });
    await record('The card icon re-tests that one node', async () => {
      const before = report.requests.length;
      await page.locator('[data-test="Alpha 01"]').click();
      await page.waitForTimeout(400);
      const requests = report.requests.slice(before).filter((item) => item.path === '/api/cores/delay');
      assert.equal(requests.length, 1, JSON.stringify(requests));
      assert.match(await page.locator('[id="delay-Alpha 01"]').innerText(), /ms/);
      return { requests: requests.length, badge: await page.locator('[id="delay-Alpha 01"]').innerText() };
    });
    await record('Sweep shows a progress bar and paints each node as it lands', async () => {
      const before = report.requests.length;
      await page.locator('#nodes-test-all').click();
      await page.waitForTimeout(120);
      assert.equal(await page.locator('#nodes-test-panel').isVisible(), true);
      const early = await page.locator('#nodes-test-count').innerText();
      await page.waitForFunction(() => {
        const el = document.querySelector('#nodes-test-count');
        return el && el.textContent.trim().startsWith('5 / 5');
      }, null, { timeout: 8000 });
      const requests = report.requests.slice(before).filter((item) => item.path === '/api/cores/delay');
      const width = await page.locator('#nodes-test-bar span').evaluate((el) => el.style.width);
      const badges = await page.locator('#nodes-rows .nc-delay').allInnerTexts();
      assert.equal(width, '100%', width);
      assert.equal(badges.filter((text) => /ms/.test(text)).length, badges.length, JSON.stringify(badges));
      return { early, requests: requests.length, width, badges };
    });
    await record('The speed button sorts the cards fastest-first', async () => {
      await page.locator('#nodes-sort-speed').click();
      await page.waitForTimeout(350);
      const sorted = await page.locator('#nodes-rows .node-card .nc-name').allInnerTexts();
      assert.deepEqual(sorted.slice(0, 3), ['Shared Node', 'Alpha 01', 'Alpha 02'], JSON.stringify(sorted));
      const cls = (await page.locator('#nodes-sort-speed').getAttribute('class')) || '';
      assert.match(cls, /primary/, cls);
      await page.locator('#nodes-sort-speed').click();
      await page.waitForTimeout(350);
      const restored = await page.locator('#nodes-rows .node-card .nc-name').allInnerTexts();
      assert.deepEqual(restored.slice(0, 3), ['Alpha 01', 'Alpha 02', 'Shared Node'], JSON.stringify(restored));
      const off = (await page.locator('#nodes-sort-speed').getAttribute('class')) || '';
      assert.doesNotMatch(off, /primary/, off);
      return { sorted: sorted.slice(0, 3), restored: restored.slice(0, 3) };
    });
    await record('Toast avoids top navigation', async () => {
      const detail = await page.locator('#toasts').evaluate((el) => {
        const r = el.getBoundingClientRect(); const s = getComputedStyle(el);
        return { top: r.top, bottom: r.bottom, viewport: innerHeight, position: s.position, css_top: s.top, css_bottom: s.bottom };
      });
      assert.ok(detail.top > 100, JSON.stringify(detail));
      assert.ok(detail.bottom <= detail.viewport, JSON.stringify(detail));
      return detail;
    });
    await screenshot(page, 'nodes-selected-toast');
    await record('Switch request failure clears pending state', async () => {
      base.model.rejectSelect = true;
      await page.locator('[data-switch="Alpha 01"]').click();
      await page.waitForTimeout(700);
      const cls = (await page.locator('[data-switch="Alpha 01"]').getAttribute('class')) || '';
      assert.doesNotMatch(cls, /switching/, cls);
      assert.match(await page.locator('#toasts').innerText(), /Synthetic selection failure/);
      base.model.rejectSelect = false;
      return { recoverable: true, class: cls };
    });
    await record('Rapid double-click on a card issues exactly one request', async () => {
      const before = report.requests.length;
      await page.locator('[data-switch="Alpha 01"]').dblclick();
      await page.waitForTimeout(900);
      const requests = report.requests.slice(before).filter((item) => item.path === '/api/cores/select');
      assert.equal(requests.length, 1, JSON.stringify(requests));
      const cls = (await page.locator('[data-switch="Alpha 01"]').getAttribute('class')) || '';
      assert.doesNotMatch(cls, /switching/, cls);
      return { requests: requests.length };
    });
    await record('Polling preserves button DOM and fill', async () => {
      await page.mouse.move(6, 6);
      await page.waitForTimeout(150);
      const detail = await page.locator('[data-node-row="Alpha 01"]').evaluate(async (el) => {
        const samples = [];
        const start = performance.now();
        while (performance.now() - start < 4450) {
          const current = document.querySelector('[data-node-row="Alpha 01"]');
          const css = getComputedStyle(current);
          // Hover repaints the card on purpose, so only the resting fill counts.
          if (!current.matches(':hover')) samples.push({ same: current === el, background: css.backgroundColor, opacity: css.opacity });
          await new Promise((resolve) => setTimeout(resolve, 100));
        }
        return { same_dom: samples.every((sample) => sample.same), styles: [...new Set(samples.map((sample) => sample.background + '|' + sample.opacity))], count: samples.length };
      });
      assert.equal(detail.same_dom, true, JSON.stringify(detail));
      assert.equal(detail.styles.length, 1, JSON.stringify(detail));
      return detail;
    });
    await page.locator('#nav button[data-page="subs"]').click();
    await page.locator('[data-sub-row]').waitFor();
    await record('Subscription actions align with matching fonts and sizes', async () => {
      const detail = await page.locator('[data-sub-row]').evaluate((row) => [...row.querySelectorAll('button')].map((el) => {
        const r = el.getBoundingClientRect(), c = getComputedStyle(el);
        return { text: el.textContent, title: el.getAttribute('title'), x: r.x, y: r.y, width: r.width, height: r.height, font: c.fontFamily, size: c.fontSize, weight: c.fontWeight, nowrap: c.whiteSpace };
      }));
      assert.ok(detail.length >= 4, JSON.stringify(detail));
      assert.equal(new Set(detail.map((x) => x.y)).size, 1, JSON.stringify(detail));
      assert.equal(new Set(detail.map((x) => x.height)).size, 1, JSON.stringify(detail));
      assert.equal(new Set(detail.map((x) => x.font + x.size + x.weight)).size, 1, JSON.stringify(detail));
      assert.equal(new Set(detail.map((x) => x.width)).size, 1, JSON.stringify(detail));
      assert.equal(detail.every((x) => x.title), true, JSON.stringify(detail));
      return detail;
    });
    await screenshot(page, 'subscriptions-desktop');
    await record('Subscription update click issues request', async () => {
      const before = report.requests.length;
      await page.locator('[data-sub-update]').click();
      await page.waitForTimeout(50);
      assert.equal(await page.locator('[data-sub-update]').isDisabled(), true);
      await page.waitForTimeout(500);
      assert.equal(await page.locator('[data-sub-update]').isDisabled(), false);
      const requests = report.requests.slice(before).filter((item) => item.path === '/api/subscriptions/update');
      assert.deepEqual(requests.map((item) => item.body), [{ name: fixtureSub.name }]);
      return requests;
    });
    await record('Delegated QR button opens dialog', async () => {
      await page.locator('[data-sub-qr]').click();
      await page.waitForTimeout(250);
      const opened = await page.locator('#qr-modal').evaluate((el) => el.hidden === false);
      assert.equal(opened, true, 'QR modal did not open');
      const title = await page.locator('#qr-title').innerText();
      await page.evaluate(() => hideQR());
      await page.waitForTimeout(100);
      assert.equal(await page.locator('#qr-modal').evaluate((el) => el.hidden), true);
      return { opened: true, title };
    });
    await record('Subscription editor opens and sends patch', async () => {
      await page.locator('[data-sub-edit]').click();
      const editor = page.locator('[data-sub-edit-row]');
      assert.equal(await editor.isVisible(), true, 'edit button did not open editor');
      await editor.locator('.sub-edit-name').fill('Renamed synthetic');
      const before = report.requests.length;
      await editor.locator('.sub-edit-save').click();
      await page.waitForTimeout(250);
      const requests = report.requests.slice(before).filter((item) => item.path === '/api/subscriptions' && item.method === 'PATCH');
      assert.deepEqual(requests.map((item) => item.body), [{ name: fixtureSub.name, new_name: 'Renamed synthetic', url: fixtureSub.url }]);
      return requests;
    });
    await base.context.close();

    for (const viewport of [{ width: 900, height: 700 }, { width: 390, height: 844 }]) {
      const fixture = await setup(browser, { ...viewport, many: true });
      await nodePage(fixture.page);
      await record(`Many groups keep nodes visible at ${viewport.width}px`, async () => {
        const detail = await fixture.page.evaluate(() => {
          const r = document.querySelector('[data-node-row]').getBoundingClientRect();
          return { top: r.top, bottom: r.bottom, viewport: innerHeight, page_width: document.documentElement.scrollWidth, screen_width: innerWidth };
        });
        assert.ok(detail.top < detail.viewport - 60, JSON.stringify(detail));
        if (viewport.width >= 900) assert.ok(detail.page_width <= detail.screen_width + 1, JSON.stringify(detail));
        else report.checks.push({ name: `Informational: ${viewport.width}px horizontal extent`, pass: true, detail: { page_width: detail.page_width, screen_width: detail.screen_width, overflows: detail.page_width > detail.screen_width + 1, note: 'narrow-browser limitation, outside stated desktop scope' } });
        return detail;
      });
      await record(`Card rows keep a gap instead of overlapping at ${viewport.width}px`, async () => {
        const detail = await fixture.page.evaluate(() => {
          const rows = [...document.querySelectorAll('#nodes-rows .ng-row')];
          const measured = rows.map((r) => {
            const rb = r.getBoundingClientRect();
            const cb = r.querySelector('.node-card').getBoundingClientRect();
            return { row_h: Math.round(rb.height), card_h: Math.round(cb.height), spill: Math.round(cb.bottom - rb.bottom) };
          });
          // The rows sit flush by design; the breathing room is the row's own
          // bottom padding, so the gap that matters is card-to-card.
          const cards = rows.map((r) => r.querySelector('.node-card').getBoundingClientRect());
          const gaps = [];
          for (let i = 1; i < cards.length; i++) gaps.push(Math.round(cards[i].top - cards[i - 1].bottom));
          return { measured, gaps };
        });
        assert.ok(detail.measured.length >= 2, JSON.stringify(detail));
        assert.equal(detail.measured.every((r) => r.spill <= 0), true, JSON.stringify(detail.measured));
        assert.equal(detail.gaps.every((g) => g >= 12), true, JSON.stringify(detail.gaps));
        return detail;
      });
      await screenshot(fixture.page, 'nodes-many-' + viewport.width);
      await fixture.page.locator('#nav button[data-page="subs"]').click();
      await fixture.page.locator('[data-sub-row]').waitFor();
      await record(`Subscription actions remain one row at ${viewport.width}px`, async () => {
        const detail = await fixture.page.locator('[data-sub-row]').evaluate((row) => [...row.querySelectorAll('button')].map((el) => {
          const r = el.getBoundingClientRect(); return { text: el.textContent, top: r.top, height: r.height, width: r.width, scroll_width: el.scrollWidth, client_width: el.clientWidth };
        }));
        assert.equal(new Set(detail.map((x) => x.top)).size, 1, JSON.stringify(detail));
        assert.ok(detail.every((x) => x.scroll_width <= x.client_width + 1), JSON.stringify(detail));
        return detail;
      });
      await screenshot(fixture.page, 'subscriptions-' + viewport.width);
      await fixture.context.close();
    }

    const empty = await setup(browser, { empty: true, frameless: false, theme: 'light' });
    await nodePage(empty.page);
    await record('Empty node state remains usable in browser mode', async () => {
      assert.equal(await empty.page.locator('[data-node-row]').count(), 0);
      assert.equal(await empty.page.locator('#wb-min').isVisible(), false);
      assert.match(await empty.page.locator('#nodes-body').innerText(), /还没有节点/);
      return { empty: true, window_controls: 'hidden' };
    });
    await screenshot(empty.page, 'nodes-empty-light-browser');
    await empty.page.locator('#nav button[data-page="subs"]').click();
    await record('Empty subscription state remains usable', async () => {
      assert.equal(await empty.page.locator('[data-sub-row]').count(), 0);
      assert.match(await empty.page.locator('#subs-body').innerText(), /还没有保存的订阅/);
      return { empty: true };
    });
    await empty.context.close();
    await record('No uncaught browser errors', () => { assert.deepEqual(report.page_errors, []); return []; });
    await record('No requests escaped mock interception', () => {
      assert.equal(report.requests.filter((item) => item.blocked).length, 0);
      return { requests: report.requests.length, all_local_mock: true };
    });
  } finally { await browser.close(); }
}

main().catch((error) => { report.fatal = error.stack; console.error(error.stack); process.exitCode = 1; }).finally(() => {
  report.summary = { passed: report.checks.filter((item) => item.pass).length, failed: report.checks.filter((item) => !item.pass).length };
  fs.writeFileSync(path.join(OUTPUT, stage + '-report.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report.summary));
  if (report.summary.failed) process.exitCode = 1;
});
