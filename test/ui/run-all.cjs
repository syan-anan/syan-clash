#!/usr/bin/env node
/* Runs the whole browser-level regression suite and reports one summary line.
   Each file is self-contained (it boots its own mocked console), so they run one
   after another rather than in parallel - two Chromium instances racing for the
   same fixed mock port is how a suite starts failing for the wrong reason.

   Usage:  node test/ui/run-all.cjs
   Env:    CODEX_NODE_MODULES  where playwright lives
           CHROME_PATH         chrome.exe to drive                */
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const dir = __dirname;
const files = fs.readdirSync(dir).filter((f) => /^verify-.*\.cjs$/.test(f)).sort();
let pass = 0, fail = 0;
for (const f of files) {
  // Output is piped rather than inherited: the last line of each file is its
  // JSON verdict, and that has to be readable to be summed.
  const r = spawnSync(process.execPath, [path.join(dir, f)], { encoding: 'utf8', env: process.env });
  const out = (r.stdout || '') + (r.stderr || '');
  process.stdout.write(out);
  const last = (r.stdout || '').trim().split(/\r?\n/).pop() || '';
  let p = 0, x = 0;
  try { const j = JSON.parse(last); p = j.passed || 0; x = j.failed || 0; } catch (e) {}
  if (x === 0 && r.status !== 0) x = 1;
  pass += p; fail += x;
  console.log(`  -> ${f}: ${p} passed, ${x} failed`);
}
console.log(`TOTAL ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
