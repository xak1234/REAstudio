// Real optimized EXE/DLL benchmark. Requires a dedicated app profile and licensed IDA.
// --runtime-only executes only the source-known fixture; no model or provider is simulated.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { performance } = require('node:perf_hooks');
const { version } = require('./version.cjs');
const hash = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const report = { version: 1, appVersion: version, startedAt: new Date().toISOString(), status: 'running',
  scope: 'Source-known optimized EXE/DLL fixture; selected static facts and optional runtime baseline, not reconstruction equivalence or large-application coverage.',
  modules: [], operations: [], runtime: { status: 'skipped', reason: 'Set REA_STUDIO_COMPLEX_RUNTIME=1 or pass --runtime-only to execute the compiled fixture.' }, jsErrors: [] };
let output;
const start = performance.now();
async function main() {
  const root = process.env.REA_STUDIO_COMPLEX_ROOT || (process.env.QUIXI_SMOKE_ROOT && path.join(process.env.QUIXI_SMOKE_ROOT, 'complex'));
  assert(root, 'Set REA_STUDIO_COMPLEX_ROOT, or prepare QUIXI_SMOKE_ROOT with -IncludeComplex');
  const expectationPath = path.join(__dirname, 'fixtures', 'complex', 'expected.json');
  const expected = JSON.parse(fs.readFileSync(expectationPath, 'utf8'));
  report.expectationSha256 = hash(expectationPath);
  assert.equal(expected.version, 1);
  const build = JSON.parse(fs.readFileSync(path.join(root, 'build.json'), 'utf8'));
  report.build = build;
  for (const source of build.sources.filter(s => /\.(cpp|h)$/.test(s.file))) {
    assert.equal(hash(path.join(__dirname, 'fixtures', 'complex', source.file)), source.sha256, 'Fixture source changed; rebuild before testing: ' + source.file);
  }
  for (const module of expected.modules) {
    const sha256 = hash(path.join(root, module.file));
    assert.equal(sha256, build.modules.find(m => m.file === module.file)?.sha256, 'Fixture changed after compilation: ' + module.file);
    report.modules.push({ file: module.file, sha256, status: 'skipped', reason: 'Static analysis not reached.' });
  }
  output = path.resolve(process.env.REA_STUDIO_BENCHMARK_REPORT || path.join(root, 'benchmark-' + Date.now() + '.json'));
  const runtimeOnly = process.argv.includes('--runtime-only');
  if (runtimeOnly || process.env.REA_STUDIO_COMPLEX_RUNTIME === '1') {
    report.runtime = { status: 'running', cases: [], startedAt: new Date().toISOString() };
    const runtimeStart = performance.now();
    const exe = path.join(root, 'rea-complex-fixture.exe');
    const runCase = (test, args) => {
      const caseStart = performance.now();
      const actual = spawnSync(exe, args, { cwd: root, encoding: 'utf8', windowsHide: true, timeout: 10000, maxBuffer: 65536 });
      const receipt = { args, durationMs: Math.round(performance.now() - caseStart), exitCode: actual.status, status: 'failed' };
      report.runtime.cases.push(receipt);
      assert.ifError(actual.error); assert.equal(actual.signal, null);
      assert.equal(actual.status, test.exitCode); assert.equal(actual.stdout, test.stdout); assert.equal(actual.stderr, test.stderr);
      receipt.status = 'passed';
    };
    for (const test of expected.runtimeCases) runCase(test, test.args);
    const invoicePath = path.join(root, 'invoice-' + crypto.randomUUID() + '.txt');
    try {
      runCase(expected.invoiceCase, [...expected.invoiceCase.args, invoicePath]);
      assert.equal(fs.readFileSync(invoicePath, 'utf8'), expected.invoiceCase.fileContent, 'Invoice bytes differ');
    } finally { if (fs.existsSync(invoicePath)) fs.unlinkSync(invoicePath); }
    report.runtime.status = 'passed'; report.runtime.durationMs = Math.round(performance.now() - runtimeStart);
  }
  if (runtimeOnly) { report.static = { status: 'skipped', reason: '--runtime-only selected; no analysis provider contacted.' }; return; }
  assert(process.env.REA_STUDIO_TEST_DATA, 'Set REA_STUDIO_TEST_DATA to the dedicated app profile, never the normal profile');
  const { chromium } = require(process.env.QUIXI_TEST_PLAYWRIGHT_MODULE || 'playwright-core');
  const browser = await chromium.connectOverCDP(process.env.REA_STUDIO_TEST_CDP || 'http://127.0.0.1:9323');
  let native;
  try {
    const page = browser.contexts()[0].pages().find(p => p.url().includes('app.localhost/playground'));
    assert(page, 'REA Studio WebView not found');
    page.setDefaultTimeout(20000); page.on('pageerror', e => report.jsErrors.push(e.message));
    native = (route, data = {}) => page.evaluate(async ({ route, data }) => {
      const response = await fetch('/api/quixi/playground/' + route, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
      const result = await response.json(); if (!response.ok) throw Error(result.error || String(response.status)); return result;
    }, { route, data });
    await page.reload(); await page.locator('#connection').filter({ hasText: 'Connected' }).waitFor();
    const before = await native('ida/status');
    assert.equal(before.connected, false, 'Dedicated benchmark profile must start with IDA disabled');
    assert.equal(before.installed, true, 'Install/configure the licensed headless IDA bridge first');
    const enabled = await native('ida/enable', { transport: 'headless' });
    assert.equal(enabled.connected, true);
    for (const name of ['list_funcs', 'lookup_funcs', 'decompile', 'xrefs_to', 'imports']) {
      assert(enabled.tools.some(t => t.name === name && t.enabled), 'Live catalog missing required tool: ' + name);
    }
    report.catalogCount = enabled.tools.length;
    const payload = record => {
      assert.equal(record.failed, false, JSON.stringify(record.response));
      const parsed = record.response?.structuredContent || JSON.parse((record.response?.content || []).filter(c => c.type === 'text').map(c => c.text).join('\n'));
      return parsed.result ?? parsed;
    };
    const call = async (tool, args, file) => {
      const operation = { module: file, tool, status: 'running' }; report.operations.push(operation);
      const began = performance.now();
      try {
        const record = await native('ida/call', { tool, arguments: args });
        operation.recordId = record.id; operation.durationMs = Math.round(performance.now() - began);
        const result = payload(record); operation.status = 'passed'; return result;
      } catch (error) { operation.status = 'failed'; operation.durationMs = Math.round(performance.now() - began); throw error; }
    };
    for (let index = 0; index < expected.modules.length; index++) {
      const module = expected.modules[index], receipt = report.modules[index];
      const target = path.join(root, module.file), began = performance.now();
      receipt.status = 'running'; delete receipt.reason;
      await native('rea/select', { path: target });
      const openStart = performance.now(), opened = await native('ida/open');
      assert.equal(opened.failed, false, JSON.stringify(opened.response));
      assert.equal(opened.provenance.sha256, receipt.sha256);
      receipt.openMs = Math.round(performance.now() - openStart); receipt.openRecord = opened.id;
      const functions = []; let offset = 0;
      for (let pages = 0; pages < 20; pages++) {
        const rows = await call('list_funcs', { queries: { offset, count: 100 } }, module.file);
        assert(Array.isArray(rows) && Array.isArray(rows[0]?.data), 'Unexpected live list_funcs response');
        functions.push(...rows[0].data);
        const next = rows[0].next_offset;
        if (next == null) { offset = null; break; }
        assert(Number.isInteger(next) && next > offset, 'Non-advancing inventory cursor'); offset = next;
      }
      assert.equal(offset, null, 'Fixture inventory exceeded the explicit 2000-function benchmark bound');
      receipt.functionCount = functions.length; receipt.expectedFunctionCount = module.functions.length;
      const addresses = new Map();
      for (const name of module.functions) {
        assert(functions.some(f => f.name === name), 'Expected exported function absent from real inventory: ' + name);
        const found = await call('lookup_funcs', { queries: name }, module.file);
        assert(found[0]?.fn?.addr && !found[0]?.error, 'Expected function lookup failed: ' + name);
        addresses.set(name, found[0].fn.addr);
      }
      receipt.decompiled = [];
      for (const fact of module.decompile) {
        const result = await call('decompile', { addr: addresses.get(fact.name), include_addresses: false }, module.file);
        assert(typeof result.code === 'string' && result.code.length > 0 && !result.error, 'Missing pseudocode: ' + fact.name);
        assert.equal(result.truncated, false, 'Fixture pseudocode must be complete');
        for (const pattern of fact.allPatterns) assert.match(result.code, new RegExp(pattern), fact.name + ': missing source-known fact ' + pattern);
        let fileHandleFlow;
        if (fact.fileHandleFlow) {
          // Static CRT helpers may be unnamed. Check the actual same-handle flow,
          // never substitute an expected library name or an address from a prior build.
          const openedHandle = result.code.match(/\b\w+\s*\(\s*&(\w+)\s*,[^,\n]+,\s*"wb"\s*\)/);
          assert(openedHandle, fact.name + ': no binary-mode open producing a handle');
          const handle = openedHandle[1];
          const write = result.code.match(new RegExp('\\b(\\w+)\\s*=\\s*\\w+\\(\\s*' + handle + '\\s*,\\s*"REA-INVOICE-V1'));
          assert(write, fact.name + ': invoice formatter does not use the opened handle');
          const rest = result.code.slice(write.index + write[0].length);
          const closedHandle = rest.match(new RegExp('\\b(\\w+)\\s*=\\s*\\w+\\(\\s*' + handle + '\\s*\\)\\s*;'));
          assert(closedHandle, fact.name + ': no subsequent cleanup call on the same handle');
          const failure = new RegExp('if\\s*\\([^)]*\\b' + write[1] + '\\s*<\\s*0[^)]*\\b' + closedHandle[1] + '\\b[^)]*\\)\\s*return\\s+4\\s*;');
          assert.match(rest, failure, fact.name + ': write/cleanup errors do not reach the source-known error result');
          fileHandleFlow = { binaryMode: 'wb', sameHandle: true, writeAndCleanupFailureExit: 4,
            limitation: 'Verifies recovered call/data flow; unnamed static CRT callees are not independently identified as library APIs.' };
        }
        receipt.decompiled.push({ name: fact.name, factCount: fact.allPatterns.length, lines: result.total_lines, fileHandleFlow });
      }
      receipt.xrefs = [];
      for (const edge of module.xrefs) {
        const result = await call('xrefs_to', { addrs: addresses.get(edge.callee), limit: 100 }, module.file);
        assert(Array.isArray(result[0]?.xrefs) && !result[0]?.error, 'Missing xref result: ' + edge.callee);
        const codeRefs = result[0].xrefs.filter(x => x.type === 'code' && x.fn);
        assert(codeRefs.length > 0, 'Expected actual code caller for ' + edge.callee);
        if (edge.caller) assert(codeRefs.some(x => x.fn.name === edge.caller), 'Expected call edge absent: ' + edge.caller + ' -> ' + edge.callee);
        receipt.xrefs.push({ callee: edge.callee, expectedCaller: edge.caller, codeReferenceCount: codeRefs.length });
      }
      if (module.imports) {
        const imports = await call('imports', { offset: 0, count: 1000 }, module.file);
        assert(Array.isArray(imports.data) && imports.next_offset == null, 'Imports incomplete');
        for (const name of module.imports) assert(imports.data.some(i => i.imported_name === name && /^rea-fixture-core(?:\.dll)?$/i.test(i.module)), 'Expected DLL import absent: ' + name);
        receipt.importCount = imports.data.length; receipt.expectedImportsVerified = module.imports.length;
      }
      assert.equal(hash(target), receipt.sha256, 'Static analysis changed fixture bytes');
      assert.equal((await native('ida/close')).failed, false);
      receipt.status = 'passed'; receipt.durationMs = Math.round(performance.now() - began);
    }
    assert.deepEqual(report.jsErrors, []);
    report.static = { status: 'passed', modules: report.modules.length, decompiledFunctions: report.modules.reduce((n, m) => n + m.decompiled.length, 0) };
  } finally { if (native) await native('ida/disable').catch(() => {}); await browser.close(); }
}
main().then(() => { report.status = 'passed'; }).catch(error => {
  report.status = 'failed'; report.error = error.stack || String(error); process.exitCode = 1;
  if (report.runtime.status === 'running') report.runtime.status = 'failed';
  for (const module of report.modules) if (module.status === 'running') module.status = 'failed';
}).finally(() => {
  report.durationMs = Math.round(performance.now() - start); report.finishedAt = new Date().toISOString();
  if (output) { fs.mkdirSync(path.dirname(output), { recursive: true }); fs.writeFileSync(output, JSON.stringify(report, null, 2) + '\n'); }
  console.log(JSON.stringify({ ...report, reportPath: output }));
});
