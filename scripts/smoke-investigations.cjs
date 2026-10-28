'use strict';
// Real multi-module evidence and UI workflow in a dedicated profile, never simulated records.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { performance } = require('node:perf_hooks');
const { version } = require('./version.cjs');
const connectAppMcp = require('./mcp-test-client.cjs');
const {showPanel, showAnalysisSection} = require('./ui-test-navigation.cjs');
const { chromium } = require(process.env.QUIXI_TEST_PLAYWRIGHT_MODULE || 'playwright-core');
const hash = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const key = value => path.resolve(value).replace(/^\\\\\?\\/, '').replaceAll('/', '\\').toLowerCase();
function treeSnapshot(directory) {
  const entries = [];
  const visit = (current, relative, depth) => {
    assert(depth <= 16 && entries.length <= 8192, 'Test export exceeded its tree bound');
    for (const entry of fs.readdirSync(current, {withFileTypes:true})) {
      assert(entries.length < 8192, 'Test export exceeded its tree bound');
      assert(!entry.isSymbolicLink(), 'Unexpected link in the test workspace');
      const file = path.join(current, entry.name), name = relative ? relative + '/' + entry.name : entry.name;
      if (entry.isDirectory()) {entries.push({path:name + '/'}); visit(file, name, depth + 1);}
      else {assert(entry.isFile()); const bytes = fs.statSync(file).size; assert(bytes <= 16 * 1024 * 1024); entries.push({path:name, bytes, sha256:hash(file)});}
    }
  };
  visit(directory, '', 0); return entries.sort((a, b) => a.path.localeCompare(b.path));
}
const started = performance.now();
const report = {version:1, appVersion:version, status:'running', startedAt:new Date().toISOString(),
  scope:'Real copied source-known EXE/DLL evidence, immutable investigation snapshots and file export. No target execution, simulated provider response or whole-application equivalence claim.',
  checks:[], evidence:[], exports:[], jsErrors:[]};
let reportPath, root, originals, browser, native, mcp, enabled = false, open = false;
const copies = [];
async function main() {
  assert(process.env.REA_STUDIO_TEST_DATA, 'Set the dedicated REA_STUDIO_TEST_DATA profile');
  assert(process.env.REA_STUDIO_TEST_SDK, 'Set the official MCP SDK package directory');
  const sourceRoot = process.env.REA_STUDIO_COMPLEX_ROOT;
  assert(sourceRoot, 'Set REA_STUDIO_COMPLEX_ROOT to the compiled source-known EXE/DLL fixture');
  const build = JSON.parse(fs.readFileSync(path.join(sourceRoot, 'build.json'), 'utf8'));
  for (const file of ['fixture_api.h', 'main.cpp', 'pricing.cpp', 'storage.cpp']) {
    const matches = build.sources.filter(item => item.file === file); assert.equal(matches.length, 1, 'Original fixture source manifest is incomplete');
    assert.equal(hash(path.join(__dirname, 'fixtures', 'complex', file)), matches[0].sha256, 'Original fixture source changed; rebuild it');
  }
  root = path.resolve(process.env.REA_STUDIO_INVESTIGATION_ROOT || path.join(path.dirname(sourceRoot), 'investigation-check-' + crypto.randomUUID()));
  assert(!fs.existsSync(root), 'Choose a new investigation test root; existing paths are not reused');
  originals = path.join(root, 'originals'); const workspace = path.join(root, 'workspace');
  fs.mkdirSync(originals, {recursive:true}); fs.mkdirSync(workspace);
  fs.writeFileSync(path.join(workspace, 'README.md'), '# Dedicated investigation verification project\n');
  reportPath = path.resolve(process.env.REA_STUDIO_INVESTIGATION_REPORT || path.join(root, 'investigation-report.json'));
  report.root = root;
  for (const [file, procedure] of [['rea-fixture-core.dll','rea_price'], ['rea-complex-fixture.exe','rea_parse_quantity']]) {
    const source = path.join(sourceRoot, file), sha256 = hash(source);
    assert.equal(sha256, build.modules.find(item => item.file === file)?.sha256, 'Original fixture bytes changed');
    const target = path.join(originals, file); fs.copyFileSync(source, target);
    assert.equal(hash(target), sha256); copies.push({file, source, target, sha256, procedure, originalBytes:fs.readFileSync(target)});
  }
  browser = await chromium.connectOverCDP(process.env.REA_STUDIO_TEST_CDP || 'http://127.0.0.1:9323');
  const page = browser.contexts()[0].pages().find(item => item.url().includes('app.localhost/playground')); assert(page, 'REA Studio WebView not found');
  page.setDefaultTimeout(30000); page.on('pageerror', error => report.jsErrors.push(error.message));
  native = (route, data = {}) => page.evaluate(async ({route, data}) => {
    const response = await fetch('/api/quixi/playground/' + route, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data)});
    const result = await response.json(); if (!response.ok) throw Error(result.error || String(response.status)); return result;
  }, {route, data});
  const project = await native('project', {path:workspace}); report.project = project.id;
  await page.reload(); await page.locator('#connection').filter({hasText:'Connected'}).waitFor();
  assert.equal(await page.title(), 'REA Studio V' + version + ' · Coding & Reverse Engineering');
  await showPanel(page,'explorer'); await page.locator('#project').selectOption(project.id);
  const before = await native('ida/status'); assert.equal(before.connected, false, 'IDA must start disabled in this dedicated test profile'); assert.equal(before.installed, true);
  const catalog = await native('ida/enable', {transport:'headless'}); assert.equal(catalog.connected, true); enabled = true;
  for (const name of ['lookup_funcs','decompile']) assert(catalog.tools.some(tool => tool.name === name && tool.enabled), 'Missing live IDA tool: ' + name);
  const retained = [];
  const keep = (record, fixture) => {
    assert.equal(record.failed, false, JSON.stringify(record.response));
    assert.equal(record.artifactIdentity?.status, 'verified'); assert.equal(record.artifactIdentity.sha256, fixture.sha256);
    assert.equal(key(record.target), key(fixture.target)); retained.push(record);
    report.evidence.push({id:record.id, target:fixture.target, sha256:fixture.sha256, tool:record.tool});
    const parsed = record.response?.structuredContent || JSON.parse((record.response?.content || []).filter(item => item.type === 'text').map(item => item.text).join('\n'));
    return parsed.result ?? parsed;
  };
  for (const fixture of copies) {
    await native('rea/select', {path:fixture.target});
    const opened = await native('ida/open'); open = true; assert.equal(opened.provenance.sha256, fixture.sha256); keep(opened, fixture);
    const lookup = keep(await native('ida/call', {tool:'lookup_funcs', arguments:{queries:fixture.procedure}}), fixture);
    assert(lookup[0]?.fn?.addr && !lookup[0]?.error, 'Real exported fixture function not recovered');
    const code = keep(await native('ida/call', {tool:'decompile', arguments:{addr:lookup[0].fn.addr, include_addresses:false}}), fixture);
    assert(typeof code.code === 'string' && code.code.length && !code.error); assert.equal(code.truncated, false); assert.match(code.code, new RegExp(fixture.procedure));
    assert.notEqual((await native('ida/close')).failed, true); open = false;
  }
  assert.equal((await native('ida/disable')).connected, false); enabled = false;
  report.checks.push({name:'real-two-module-evidence', status:'passed', records:retained.length});
  await showAnalysisSection(page,'inv-panel');
  const idle = () => page.waitForFunction(() => window.QuixiInvestigations && !QuixiInvestigations.busy);
  await idle();
  const waitResponse = (route, id) => page.waitForResponse(response => {
    if (!response.url().endsWith('/api/quixi/playground/investigation/' + route) || response.request().method() !== 'POST') return false;
    return !id || response.request().postDataJSON()?.id === id;
  });
  const uiCall = async (button, route, id) => {
    await idle();
    await page.waitForFunction(selector => {const node = document.querySelector(selector);return node && !node.disabled;}, button);
    const pending = waitResponse(route, id); await page.locator(button).click(); const response = await pending;
    const result = await response.json(); assert(response.ok(), JSON.stringify(result)); await idle(); return result;
  };
  const name = 'Evidence check ' + crypto.randomUUID();
  await page.locator('#inv-name').fill(name); await page.locator('#inv-targets').fill(copies.map(item => item.target).join('\n'));
  const created = await uiCall('#inv-create', 'create'); const snapshot = created.investigation;
  assert.match(snapshot.id, /^[0-9a-f-]{36}$/i); assert.equal(snapshot.name, name); assert.equal(snapshot.artifacts.length, 2); report.snapshotId = snapshot.id;
  for (const artifact of snapshot.artifacts) assert.equal(artifact.artifactIdentity.sha256, copies.find(item => key(item.target) === key(artifact.target))?.sha256);
  await page.waitForFunction(id => document.getElementById('inv-select').value === id, snapshot.id);
  const inspect = async () => {
    const result = await uiCall('#inv-check', 'inspect', snapshot.id);
    await page.waitForFunction(rows => {
      const rendered = [...document.querySelectorAll('#inv-rows tr.investigation-artifact')].map(row => row.dataset.status).sort();
      return JSON.stringify(rendered) === JSON.stringify(rows.slice().sort());
    }, result.artifacts.map(item => item.status));
    return result;
  };
  const current = await inspect(); assert.equal(current.allArtifactsCurrent, true); assert.equal(current.readyToExport, true);
  assert(current.artifacts.every(item => item.status === 'current' && item.matchingRecordCount > 0));
  report.checks.push({name:'ui-create-inspect', status:'passed'});
  const knownRecords = new Map(retained.map(record => [record.id, record]));
  const exportedEvidence = new Map(), exportedBundles = [];
  const verifyExport = async (result, expectedSnapshot = snapshot) => {
    assert.equal(result.id, expectedSnapshot.id); assert.equal(result.artifactCount, 2); assert(result.recordCount >= retained.length);
    const destination = path.resolve(workspace, result.relativePath); assert.equal(key(destination), key(result.path));
    assert(destination.startsWith(workspace + path.sep), 'Export escaped its workspace');
    const manifestPath = path.join(destination, 'manifest.json'), manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    assert.equal(manifest.format, 'rea-investigation-v1'); assert.equal(manifest.investigation.id, expectedSnapshot.id); assert.equal(manifest.artifacts.length, 2);
    assert.equal(manifest.records.length, result.recordCount); assert.equal(new Set(manifest.records.map(record => record.id)).size, manifest.records.length, 'Duplicate evidence IDs in export');
    for (const fixture of copies) {
      const artifact = manifest.artifacts.find(item => key(item.target) === key(fixture.target)); assert(artifact);
      assert.equal(artifact.artifactIdentity.sha256, fixture.sha256); assert(artifact.recordCount > 0); assert.equal(artifact.evidenceCoverage, 'saved-observations-only');
    }
    for (const id of knownRecords.keys()) assert(manifest.records.some(record => record.id === id), 'Actual saved evidence is missing from manifest: ' + id);
    for (const record of manifest.records) {
      const fixture = copies.find(item => key(item.target) === key(record.target)); assert(fixture, 'Unrelated artifact entered the export');
      assert.equal(record.artifactIdentity.sha256, fixture.sha256);
      const file = path.resolve(destination, record.file); assert(file.startsWith(destination + path.sep), 'Manifest evidence path escapes export');
      assert.equal(hash(file), record.sha256); assert.equal(fs.statSync(file).size, record.bytes);
      const raw = JSON.parse(fs.readFileSync(file, 'utf8')); assert.equal(raw.id, record.id); assert.equal(raw.artifactIdentity.sha256, fixture.sha256);
      assert.deepEqual(raw, knownRecords.get(record.id) || await native('rea/evidence', {id:record.id}), 'Export altered actual saved evidence content');
      if (exportedEvidence.has(record.id)) assert.deepEqual(raw, exportedEvidence.get(record.id), 'Later export altered the same evidence record');
      exportedEvidence.set(record.id, raw);
    }
    exportedBundles.push({path:destination, tree:treeSnapshot(destination)});
    report.exports.push({path:destination, snapshotId:expectedSnapshot.id, artifactCount:manifest.artifacts.length, recordCount:manifest.records.length, manifestSha256:hash(manifestPath)});
    return destination;
  };
  const first = await verifyExport(await uiCall('#inv-export', 'export', snapshot.id));
  await page.waitForFunction(() => !document.getElementById('inv-open-manifest').disabled);
  mcp = await connectAppMcp(page);
  assert((await mcp.client.listTools()).tools.some(tool => tool.name === 'studio_investigation'), 'Investigation tool is not advertised through real MCP');
  assert((await mcp.call('studio_investigation', {action:'list', project:project.id})).investigations.some(item => item.id === snapshot.id));
  const extra = (await mcp.call('studio_investigation', {action:'create', project:project.id, name:'MCP ' + name, targets:copies.map(item => item.target)})).investigation;
  assert.notEqual(extra.id, snapshot.id);
  const inspectedMcp = await mcp.call('studio_investigation', {action:'inspect', project:project.id, id:extra.id});
  assert.equal(inspectedMcp.allArtifactsCurrent, true); assert.equal(inspectedMcp.readyToExport, true);
  await verifyExport(await mcp.call('studio_investigation', {action:'export', project:project.id, id:extra.id}), extra);
  for (const args of [{action:'delete', project:project.id, id:extra.id}, {action:'list', project:project.id, id:extra.id}]) {
    const rejected = await mcp.client.callTool({name:'studio_investigation', arguments:args});
    assert.equal(rejected.isError, true, 'MCP must reject unconfirmed deletion and irrelevant fields');
  }
  assert((await mcp.call('studio_investigation', {action:'list', project:project.id})).investigations.some(item => item.id === extra.id), 'Unconfirmed deletion removed a snapshot');
  assert.equal((await mcp.call('studio_investigation', {action:'delete', project:project.id, id:extra.id, confirmDelete:true})).deleted, extra.id);
  const afterMcpDelete = (await mcp.call('studio_investigation', {action:'list', project:project.id})).investigations;
  assert(!afterMcpDelete.some(item => item.id === extra.id), 'Confirmed MCP deletion left its snapshot in the store');
  assert(afterMcpDelete.some(item => item.id === snapshot.id), 'Confirmed MCP deletion removed another snapshot');
  await mcp.close(); mcp = null;
  report.checks.push({name:'real-mcp-create-list-inspect-export-confirmed-delete', status:'passed'});
  const rejectExport = async expectedMissingPath => {
    const beforeTree = treeSnapshot(workspace);
    const rejected = await page.evaluate(async ({project, id}) => {
      const response = await fetch('/api/quixi/playground/investigation/export', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({project, id})});
      return {status:response.status, body:await response.json()};
    }, {project:project.id, id:snapshot.id});
    assert.equal(rejected.status, 400);
    if (expectedMissingPath && rejected.body.error === 'Could not inspect investigation path component ' + expectedMissingPath) {
      assert(!fs.existsSync(expectedMissingPath), 'The exact rejected path must be the intentionally missing copy');
    } else assert.match(rejected.body.error, /changed|current|missing|pinned|cannot find.*file|os error 2/i);
    assert.deepEqual(treeSnapshot(workspace), beforeTree, 'Rejected export changed the workspace or left staging/partial output');
  };
  fs.appendFileSync(copies[0].target, Buffer.from([0x7f]));
  const changed = await inspect(); assert.equal(changed.allArtifactsCurrent, false); assert.equal(changed.readyToExport, false);
  assert.equal(changed.artifacts.find(item => key(item.target) === key(copies[0].target)).status, 'changed');
  await rejectExport(); fs.writeFileSync(copies[0].target, copies[0].originalBytes);
  report.checks.push({name:'changed-copy-export-rejected', status:'passed'});
  fs.renameSync(copies[1].target, copies[1].target + '.held');
  const missing = await inspect(); assert.equal(missing.allArtifactsCurrent, false); assert.equal(missing.readyToExport, false);
  assert.equal(missing.artifacts.find(item => key(item.target) === key(copies[1].target)).status, 'missing');
  await rejectExport(copies[1].target); fs.renameSync(copies[1].target + '.held', copies[1].target);
  report.checks.push({name:'missing-copy-export-rejected', status:'passed'});
  const restored = await inspect(); assert.equal(restored.allArtifactsCurrent, true); assert.equal(restored.readyToExport, true);
  const second = await verifyExport(await uiCall('#inv-export', 'export', snapshot.id)); assert.notEqual(first, second, 'Fresh export reused an earlier output folder');
  await page.reload(); await page.locator('#connection').filter({hasText:'Connected'}).waitFor(); await showPanel(page,'explorer'); await page.locator('#project').selectOption(project.id);
  await showAnalysisSection(page,'inv-panel');
  await page.locator('#inv-select option[value="' + snapshot.id + '"]').waitFor({state:'attached'});
  await page.locator('#inv-select').selectOption(snapshot.id);
  await idle();
  const listed = await native('investigation/list', {project:project.id}); assert(listed.investigations.some(item => item.id === snapshot.id));
  report.checks.push({name:'restored-files-new-export-and-reload', status:'passed'});
  const acceptDelete = dialog => {assert.match(dialog.message(), /delete|remove/i); dialog.accept();}; page.on('dialog', acceptDelete);
  let deleted;
  try {deleted = await uiCall('#inv-delete', 'delete', snapshot.id);} finally {page.off('dialog', acceptDelete);}
  assert.equal(deleted.deleted, snapshot.id);
  assert(!(await native('investigation/list', {project:project.id})).investigations.some(item => item.id === snapshot.id));
  for (const bundle of exportedBundles) assert.deepEqual(treeSnapshot(bundle.path), bundle.tree, 'Deleting snapshot altered an exported bundle');
  for (const [id, record] of exportedEvidence) assert.deepEqual(await native('rea/evidence', {id}), record, 'Deleting snapshot altered saved evidence');
  for (const fixture of copies) {assert.equal(hash(fixture.source), fixture.sha256, 'Original source fixture changed'); assert.equal(hash(fixture.target), fixture.sha256);}
  report.checks.push({name:'delete-snapshot-preserves-exports-and-evidence', status:'passed'});
  assert.deepEqual(report.jsErrors, []);
}
main().then(() => {report.status = 'passed';}).catch(error => {report.status = 'failed';report.error = error.stack || String(error);process.exitCode = 1;}).finally(async () => {
  if (mcp) await mcp.close().catch(error => {report.cleanupError = String(error); report.status = 'failed';process.exitCode = 1;});
  if (native && open) await native('ida/close').catch(() => {});
  if (native && enabled) await native('ida/disable').catch(() => {});
  for (const fixture of copies) {
    try {if (fs.existsSync(fixture.target + '.held')) fs.renameSync(fixture.target + '.held', fixture.target);fs.writeFileSync(fixture.target, fixture.originalBytes);} catch (error) {report.cleanupError = String(error); report.status = 'failed';process.exitCode = 1;}
  }
  if (browser) await browser.close().catch(error => {report.cleanupError = String(error); report.status = 'failed';process.exitCode = 1;});
  report.finishedAt = new Date().toISOString(); report.durationMs = Math.round(performance.now() - started);
  if (reportPath) {fs.mkdirSync(path.dirname(reportPath), {recursive:true});fs.writeFileSync(reportPath, JSON.stringify(report, null, 2) + '\n');}
  console.log(JSON.stringify({...report, reportPath}));
});
