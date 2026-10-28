'use strict';
// Bounded real IDA paging + string/xref discovery. Runtime baseline is separately opt-in.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { performance } = require('node:perf_hooks');
const { version } = require('./version.cjs');
const { FUNCTION_COUNT, generateSource, inspectPe } = require('./fixtures/scale/generate.cjs');
const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const hash = file => digest(fs.readFileSync(file));
const canonicalAddress = value => {
  assert.equal(typeof value, 'string', 'Expected a real returned address');
  assert.match(value, /^0x[0-9a-f]+$/i); return BigInt(value).toString(16);
};
const started = performance.now();
const report = { version: 1, appVersion: version, startedAt: new Date().toISOString(), status: 'running',
  scope: 'Source-known synthetic /O2 fixture with no application exports, COFF symbol table or debug directory. This measures bounded paging and one unnamed feature discovery, not general stripped recovery, production scale or reconstruction equivalence.',
  static: { status: 'skipped', reason: 'Static analysis has not executed.' },
  runtime: { status: 'skipped', reason: 'Set REA_STUDIO_SCALE_RUNTIME=1 or use --runtime-only to execute the compiled fixture.' }, operations: [], jsErrors: [] };
let output;
async function main() {
  const root = process.env.REA_STUDIO_SCALE_ROOT;
  assert(root, 'Set REA_STUDIO_SCALE_ROOT to a newly compiled dedicated scale fixture');
  output = path.resolve(process.env.REA_STUDIO_SCALE_REPORT || path.join(root, 'scale-report-' + Date.now() + '.json'));
  const expectationPath = path.join(__dirname, 'fixtures', 'scale', 'expected.json');
  const expected = JSON.parse(fs.readFileSync(expectationPath, 'utf8'));
  const build = JSON.parse(fs.readFileSync(path.join(root, 'build.json'), 'utf8'));
  assert.equal(expected.version, 1); assert.equal(build.version, 1);
  assert.equal(expected.generatedFunctions, FUNCTION_COUNT); assert.equal(build.generatedFunctions, FUNCTION_COUNT);
  const requiredSources = ['scripts/fixtures/scale/generate.cjs', 'scripts/fixtures/scale/expected.json', 'scripts/prepare-scale-fixture.ps1'];
  assert.equal(build.sources.length, requiredSources.length, 'Unexpected fixture source manifest');
  for (const file of requiredSources) {
    const matches = build.sources.filter(source => source.file === file); assert.equal(matches.length, 1);
    assert.equal(hash(path.join(__dirname, '..', file)), matches[0].sha256, 'Fixture source changed; rebuild before testing: ' + file);
  }
  assert.equal(build.generated.file, 'scale_fixture.cpp');
  assert.equal(digest(generateSource()), build.generated.sha256, 'Generated source does not match the current deterministic generator');
  assert.equal(hash(path.join(root, 'scale_fixture.cpp')), build.generated.sha256, 'Generated source changed after compilation');
  assert.equal(build.binary.file, expected.file);
  const target = path.join(root, expected.file), pe = inspectPe(target), binaryHash = hash(target);
  assert.equal(binaryHash, build.binary.sha256, 'Fixture binary changed after compilation');
  assert.equal(build.metadataCleanup?.afterSha256, binaryHash); assert.equal(build.metadataCleanup.executableCodeUnchanged, true);
  assert.deepEqual(pe, build.pe);
  assert(!fs.readdirSync(root).some(name => /\.pdb$/i.test(name)), 'Remove debug databases by rebuilding in a new folder');
  report.fixture = { file: expected.file, sha256: binaryHash, generatedFunctions: FUNCTION_COUNT, bytes: pe.bytes,
    expectationSha256: hash(expectationPath), generatedSourceSha256: build.generated.sha256, pe, flags: build.flags, metadataCleanup:build.metadataCleanup };
  const runtimeOnly = process.argv.includes('--runtime-only');
  if (runtimeOnly || process.env.REA_STUDIO_SCALE_RUNTIME === '1') {
    const began = performance.now(); report.runtime = { status: 'running', cases: [] };
    for (const test of expected.runtimeCases) {
      const caseStart = performance.now();
      const actual = spawnSync(target, test.args, { cwd: root, encoding: 'utf8', timeout: 10000, maxBuffer: 65536, windowsHide: true });
      const receipt = { id: test.id, args: test.args, status: 'failed', durationMs: Math.round(performance.now() - caseStart), exitCode: actual.status };
      report.runtime.cases.push(receipt);
      assert.ifError(actual.error); assert.equal(actual.signal, null, test.id);
      assert.equal(actual.status, test.exitCode, test.id + ': exit code');
      assert.equal(actual.stdout, test.stdout, test.id + ': exact stdout');
      assert.equal(actual.stderr, test.stderr, test.id + ': exact stderr');
      receipt.status = 'passed';
    }
    report.runtime.status = 'passed'; report.runtime.durationMs = Math.round(performance.now() - began);
  }
  if (runtimeOnly) { report.static.reason = '--runtime-only selected; no analysis provider contacted.'; return; }
  assert(process.env.REA_STUDIO_TEST_DATA, 'Set REA_STUDIO_TEST_DATA for the dedicated app profile');
  const maxFunctions = Number(process.env.REA_STUDIO_SCALE_MAX_FUNCTIONS || 10000), pageSize = 128;
  assert(Number.isSafeInteger(maxFunctions) && maxFunctions >= 100 && maxFunctions <= 50000, 'REA_STUDIO_SCALE_MAX_FUNCTIONS must be an integer from 100 to 50,000');
  report.static = { status: 'running', maxFunctions, pageSize, pages: [], discovery: [] };
  const { chromium } = require(process.env.QUIXI_TEST_PLAYWRIGHT_MODULE || 'playwright-core');
  const browser = await chromium.connectOverCDP(process.env.REA_STUDIO_TEST_CDP || 'http://127.0.0.1:9323');
  let native, opened = false, enabled = false;
  try {
    const page = browser.contexts()[0].pages().find(p => p.url().includes('app.localhost/playground')); assert(page, 'REA Studio WebView not found');
    page.setDefaultTimeout(20000); page.on('pageerror', error => report.jsErrors.push(error.message));
    native = (route, data = {}) => page.evaluate(async ({route, data}) => {
      const response = await fetch('/api/quixi/playground/' + route, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(data) });
      const result = await response.json(); if (!response.ok) throw Error(result.error || String(response.status)); return result;
    }, {route, data});
    await page.reload(); await page.locator('#connection').filter({hasText:'Connected'}).waitFor();
    assert.equal(await page.title(), 'REA Studio V' + version + ' · Coding & Reverse Engineering');
    const before = await native('ida/status'); assert.equal(before.connected, false, 'Dedicated profile must start with IDA disabled'); assert.equal(before.installed, true);
    const catalog = await native('ida/enable', {transport:'headless'}); assert.equal(catalog.connected, true); enabled = true;
    for (const name of ['list_funcs', 'find_regex', 'xrefs_to', 'decompile', 'imports']) assert(catalog.tools.some(tool => tool.name === name && tool.enabled), 'Live IDA catalog missing required tool: ' + name);
    report.static.catalogCount = catalog.tools.length;
    const payload = record => {
      assert.equal(record.failed, false, JSON.stringify(record.response));
      const value = record.response?.structuredContent || JSON.parse((record.response?.content || []).filter(c => c.type === 'text').map(c => c.text).join('\n'));
      return value.result ?? value;
    };
    const call = async (tool, args) => {
      const operation = {tool, status:'running'}; report.operations.push(operation); const began = performance.now();
      try {
        const record = await native('ida/call', {tool, arguments:args}); operation.recordId = record.id;
        operation.responseBytes = Buffer.byteLength(JSON.stringify(record.response));
        const result = payload(record);
        assert.equal(record.artifactIdentity?.status, 'verified', 'Analysis evidence must identify the current fixture');
        assert.equal(record.artifactIdentity.sha256, binaryHash, 'Tool evidence belongs to another artifact');
        operation.status = 'passed'; return result;
      } catch (error) {operation.status = 'failed';throw error;}
      finally {operation.durationMs = Math.round(performance.now() - began);}
    };
    await native('rea/select', {path:target});
    const began = performance.now(), opening = await native('ida/open'); opened = true;
    assert.equal(opening.failed, false); assert.equal(opening.provenance.sha256, binaryHash);
    report.static.open = {recordId:opening.id, durationMs:Math.round(performance.now() - began)};
    const addresses = new Set(), names = []; let offset = 0, complete = false;
    const inventoryStart = performance.now();
    for (let pageNumber = 0; pageNumber <= Math.ceil(maxFunctions / pageSize); pageNumber++) {
      const rows = await call('list_funcs', {queries:{offset, count:pageSize}});
      assert(Array.isArray(rows) && Array.isArray(rows[0]?.data) && rows.length === 1, 'Unexpected paged inventory response');
      assert(rows[0].data.length <= pageSize, 'Provider ignored page bound');
      for (const fn of rows[0].data) {
        const addr = canonicalAddress(fn.addr); assert(!addresses.has(addr), 'Duplicate function across inventory pages'); addresses.add(addr); names.push(String(fn.name));
      }
      assert(addresses.size <= maxFunctions, 'Inventory exceeded the explicit configured function bound');
      report.static.pages.push({offset, count:rows[0].data.length, nextOffset:rows[0].next_offset ?? null});
      if (rows[0].next_offset == null) {complete = true;break;}
      assert(rows[0].data.length > 0, 'Empty page has a continuation cursor');
      assert.equal(rows[0].next_offset, offset + rows[0].data.length, 'Non-contiguous/non-advancing inventory cursor'); offset = rows[0].next_offset;
    }
    assert(complete, 'Inventory did not terminate within its explicit paging budget');
    assert(addresses.size >= FUNCTION_COUNT && addresses.size > 2000, 'Compiler/provider did not retain/discover the required scale population');
    assert(!names.some(name => /^scale_(?:quote|lane_)/i.test(name)), 'Application source names are present in the analysis');
    report.static.inventory = {functionCount:addresses.size, pages:report.static.pages.length, durationMs:Math.round(performance.now() - inventoryStart), uniqueAddresses:true, complete:true};
    const found = await call('find_regex', {pattern:'^' + expected.anchor, limit:20, offset:0});
    assert(Array.isArray(found.matches) && found.matches.length === 1, 'Expected one actual format-string anchor');
    assert.equal(found.cursor?.done, true, 'Anchor search must be complete');
    const anchor = found.matches[0]; assert.match(anchor.string, /^REA-SCALE-QUOTE-V1/);
    const refs = await call('xrefs_to', {addrs:anchor.addr, limit:100});
    assert(Array.isArray(refs) && Array.isArray(refs[0]?.xrefs) && !refs[0].error); assert.equal(refs[0].more, false);
    const candidates = new Map();
    for (const ref of refs[0].xrefs) if (ref.fn?.addr) candidates.set(canonicalAddress(ref.fn.addr), ref.fn);
    assert(candidates.size > 0 && candidates.size <= 8, 'Anchor must identify a bounded set of containing functions');
    let recovered;
    for (const fn of candidates.values()) {
      assert(addresses.has(canonicalAddress(fn.addr)), 'String reference points outside the complete inventory');
      assert.match(fn.name, /^sub_[0-9a-f]+$/i, 'Application function must be recovered without a source symbol');
      const result = await call('decompile', {addr:fn.addr, include_addresses:false});
      assert(typeof result.code === 'string' && result.code.length && !result.error); assert.equal(result.truncated, false);
      const facts = expected.quoteFacts.map(fact => ({name:fact.name, passed:new RegExp(fact.pattern).test(result.code)}));
      report.static.discovery.push({address:fn.addr, providerName:fn.name, anchorAddress:anchor.addr, facts, lines:result.total_lines});
      if (facts.every(fact => fact.passed)) {recovered = fn;break;}
    }
    assert(recovered, 'No address-discovered function contains all source-known quote facts');
    const callers = await call('xrefs_to', {addrs:recovered.addr, limit:100});
    assert(Array.isArray(callers[0]?.xrefs) && !callers[0].error); assert.equal(callers[0].more, false);
    const codeCallers = callers[0].xrefs.filter(ref => ref.type === 'code' && ref.fn?.addr);
    assert(codeCallers.length > 0, 'Recovered unnamed feature has no actual code caller');
    for (const ref of codeCallers) assert(addresses.has(canonicalAddress(ref.fn.addr)), 'Caller lies outside the complete inventory');
    report.static.callerCount = codeCallers.length;
    const imports = await call('imports', {offset:0, count:1000}); assert(Array.isArray(imports.data) && imports.next_offset == null);
    for (const name of expected.requiredImports) assert(imports.data.some(item => item.imported_name === name), 'Required actual platform import absent: ' + name);
    report.static.imports = {count:imports.data.length, required:expected.requiredImports};
    assert.equal(hash(target), binaryHash, 'Static analysis changed fixture bytes'); assert.deepEqual(report.jsErrors, []);
    report.static.status = 'passed'; report.static.maxResponseBytes = Math.max(...report.operations.map(operation => operation.responseBytes || 0));
  } finally {
    if (native && opened) await native('ida/close').then(result => assert.notEqual(result.failed, true, 'Closing the fixture failed')).catch(error => {report.cleanupError = String(error);});
    if (native && enabled) await native('ida/disable').then(result => assert.equal(result.connected, false, 'Disabling the test bridge failed')).catch(error => {report.cleanupError = String(error);});
    await browser.close();
  }
  assert(!report.cleanupError, 'IDA fixture cleanup failed: ' + report.cleanupError);
}
main().then(() => {report.status = 'passed';}).catch(error => {
  report.status = 'failed'; report.error = error.stack || String(error); process.exitCode = 1;
  if (report.static.status === 'running') report.static.status = 'failed'; if (report.runtime.status === 'running') report.runtime.status = 'failed';
}).finally(() => {
  report.durationMs = Math.round(performance.now() - started); report.finishedAt = new Date().toISOString();
  if (output) {fs.mkdirSync(path.dirname(output), {recursive:true}); fs.writeFileSync(output, JSON.stringify(report, null, 2) + '\n');}
  console.log(JSON.stringify({...report, reportPath:output}));
});
