// Real 1.3 runtime/oracle UI regressions; run alone against an isolated desktop profile.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { performance } = require('node:perf_hooks');
const { chromium } = require(process.env.QUIXI_TEST_PLAYWRIGHT_MODULE || 'playwright-core');
const report = { version: 1, status: 'running', startedAt: new Date().toISOString(), checks: [], jsErrors: [] };
const began = performance.now();
let output;
(async () => {
  const root = process.env.QUIXI_SMOKE_ROOT;
  assert(root && process.env.REA_STUDIO_TEST_DATA, 'Set a dedicated QUIXI_SMOKE_ROOT and REA_STUDIO_TEST_DATA');
  const target = path.join(root, 'quixi-fixture.exe'); assert(fs.existsSync(target));
  const destination = root + '-controls-' + Date.now(); fs.mkdirSync(destination);
  output = path.join(destination, 'controls-report.json'); report.projectPath = destination;
  const browser = await chromium.connectOverCDP(process.env.REA_STUDIO_TEST_CDP || 'http://127.0.0.1:9323');
  let native, original, project, activeOperation;
  try {
    const page = browser.contexts()[0].pages().find(p => p.url().includes('app.localhost/playground')); assert(page);
    page.setDefaultTimeout(20000); page.on('pageerror', e => report.jsErrors.push(e.message));
    const raw = (route, data = {}) => page.evaluate(async ({ route, data }) => {
      const response = await fetch('/api/quixi/playground/' + route, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
      return { status: response.status, ok: response.ok, body: await response.json() };
    }, { route, data });
    native = async (route, data = {}) => { const r = await raw(route, data); assert(r.ok, JSON.stringify(r)); return r.body; };
    const other = await native('project', { path: root });
    project = await native('project', { path: destination });
    await native('rea/select', { project: project.id, path: target });
    original = await native('rea/settings', { project: project.id });
    assert(original.settings && original.limits, 'Reading with the project envelope must not be treated as a settings mutation');
    await native('rea/connect', { project: project.id, mode: 'bundled' });
    const connected = await native('rea/settings', { project: project.id });
    assert.equal(connected.connected, true); assert.equal(connected.runtime.serverInfo.version, '6.8.0');
    for (const patch of [{ ghidraHeapMiB: 511 }, { ghidraStartupTimeoutSecs: 59 }, { callTimeoutSecs: 14401 }]) {
      const denied = await raw('rea/settings', { project: project.id, ...patch });
      assert.equal(denied.ok, false, 'Invalid resource setting was accepted');
      const after = await native('rea/settings', { project: project.id });
      assert.equal(after.connected, true, 'Validation failure disconnected the live provider');
      assert.deepEqual(after.settings, connected.settings); assert.equal(after.runtime.catalogStatus, 'live');
    }
    report.checks.push({ name: 'settings-envelope-and-preflight', status: 'passed', rejectedLimits: 3 });
    await page.reload(); await page.locator('#connection').filter({ hasText: 'Connected' }).waitFor();
    await page.locator('#project').selectOption(project.id); await page.locator('[data-view=analysis]').click();
    const source = await page.locator('#analysis-source option').evaluateAll(nodes => nodes.map(n => n.value).find(v => v === 'ghidra') || nodes.map(n => n.value).find(v => v === 'rea'));
    assert(source, 'No native REA analysis source in UI'); await page.locator('#analysis-source').selectOption(source);
    await page.locator('.runtime-settings summary').click();
    const heap = connected.settings.ghidraHeapMiB === 4096 ? 4352 : 4096;
    await page.locator('#rea-heap').fill(String(heap));
    await page.locator('#rea-startup-timeout').fill('900'); await page.locator('#rea-call-timeout').fill('1800');
    await page.locator('#rea-runtime-save').click();
    await page.waitForFunction(() => document.getElementById('rea-runtime-message').textContent.includes('Settings saved'), null, { timeout: 120000 });
    const saved = await native('rea/settings', { project: project.id });
    assert.equal(saved.settings.ghidraHeapMiB, heap); assert.equal(saved.connected, true);
    assert.equal(saved.runtime.mode, 'bundled'); assert.equal(saved.runtime.serverInfo.version, '6.8.0');
    const identityText = await page.locator('#rea-runtime-info').textContent();
    assert.match(identityText, /Connected:.*6\.8\.0/); assert.match(identityText, /Bundled: REA 6\.8\.0/);
    report.checks.push({ name: 'ui-resource-save-reconnect', status: 'passed', heapMiB: heap, liveIdentity: saved.runtime.serverInfo });

    const dossier = await native('reconstruction-export', { project: project.id, scope: 'feature', goal: 'Source-known oracle controls acceptance test', observations: 'Test programs are created by this integration script.' });
    const config = path.join(destination, dossier.relativePath, 'oracle-cases.json');
    const text = 'line one\nline two\n', sha = crypto.createHash('sha256').update(text).digest('hex');
    fs.writeFileSync(path.join(destination, 'write-outputs.cjs'), "const fs=require('node:fs');fs.writeFileSync('output.txt','line one\\nline two\\n');fs.writeFileSync('value.json','null\\n');process.stdout.write('controls-ok\\n');\n");
    const suite = { version: 1, cases: [{ id: 'file-outputs', requirement: 'REQ-FILES', expectationSource: 'Source-known write-outputs.cjs',
      argv: [process.execPath, 'write-outputs.cjs'], timeoutSeconds: 15, expected: { exitCode: 0, stdout: 'controls-ok\n', stderr: '', files: [
        { path: 'output.txt', exists: true, text, sha256: sha }, { path: 'value.json', exists: true, json: null }, { path: 'absent.tmp', exists: false }
      ] } }] };
    fs.writeFileSync(config, JSON.stringify(suite, null, 2));
    await page.reload(); await page.locator('#connection').filter({ hasText: 'Connected' }).waitFor();
    await page.locator('#project').selectOption(project.id); await page.locator('[data-view=analysis]').click();
    await page.locator('#reconstruction-dossier').selectOption(dossier.relativePath); await page.locator('#mode').selectOption('code');
    await page.locator('#oracle-run').click(); await page.locator('#oracle-consent').waitFor({ state: 'visible' });
    const approvalText = await page.locator('#oracle-consent-cases').textContent();
    for (const expected of ['exit code 0', 'stdout: controls-ok', 'stderr:', 'timeout: 15 seconds', 'output.txt', text, sha, 'JSON value: null', 'absent.tmp: must be absent']) {
      assert(approvalText.includes(expected), 'Missing approval disclosure: ' + expected);
    }
    const approvedDigest = await page.locator('#oracle-consent-sha').textContent();
    assert(approvedDigest.includes(crypto.createHash('sha256').update(fs.readFileSync(config)).digest('hex')));
    await page.locator('#oracle-approve').click();
    await page.waitForFunction(() => { try { return JSON.parse(document.getElementById('oracle-result').textContent).status === 'passed'; } catch { return false; } }, null, { timeout: 20000 });
    const comparison = JSON.parse(await page.locator('#oracle-result').textContent());
    assert.equal(comparison.passed, 1); assert(fs.existsSync(path.join(destination, comparison.reportPath)));
    assert.equal(fs.readFileSync(path.join(destination, 'output.txt'), 'utf8'), text);
    report.checks.push({ name: 'oracle-file-approval-and-comparison', status: 'passed', reportPath: comparison.reportPath });

    fs.writeFileSync(path.join(destination, 'sleep.cjs'), "const fs=require('node:fs');fs.writeFileSync('sleep-started.txt',String(process.pid));setTimeout(()=>{fs.writeFileSync('sleep-finished.txt','finished');process.stdout.write('finished');},30000);\n");
    fs.writeFileSync(config, JSON.stringify({ version: 1, cases: [{ id: 'cancel-long-case', requirement: 'REQ-CANCEL', expectationSource: 'Source-known 30-second sleep.cjs', argv: [process.execPath, 'sleep.cjs'], timeoutSeconds: 45, expected: { exitCode: 0, stdout: 'finished', stderr: '' } }] }, null, 2));
    const reportsBefore = fs.readdirSync(path.join(destination, 'quixi-oracle-runs')).sort();
    await page.locator('#oracle-run').click(); await page.locator('#oracle-consent').waitFor({ state: 'visible' });
    assert.notEqual(await page.locator('#oracle-consent-sha').textContent(), approvedDigest);
    assert.match(await page.locator('#oracle-consent-note').textContent(), /changed since/);
    const requestPromise = page.waitForRequest(request => request.url().endsWith('/oracle-run') && request.method() === 'POST');
    await page.locator('#oracle-approve').click();
    activeOperation = (await requestPromise).postDataJSON();
    assert.equal(activeOperation.project, project.id); assert.match(activeOperation.operationId, /^[0-9a-f-]{36}$/i);
    await page.locator('#oracle-stop').waitFor({ state: 'visible' });
    const deadline = performance.now() + 10000;
    while (!fs.existsSync(path.join(destination, 'sleep-started.txt')) && performance.now() < deadline) await new Promise(resolve => setTimeout(resolve, 100));
    assert(fs.existsSync(path.join(destination, 'sleep-started.txt')), 'Controlled child did not begin');
    const childPid = Number(fs.readFileSync(path.join(destination, 'sleep-started.txt'), 'utf8')); assert(Number.isInteger(childPid) && childPid > 0);
    for (const wrong of [{ project: project.id, operationId: crypto.randomUUID() }, { project: other.id, operationId: activeOperation.operationId }]) {
      const denied = await raw('oracle-stop', wrong); assert.equal(denied.ok, false); assert.match(denied.body.error, /no longer active/);
    }
    const stopBegan = performance.now(); await page.locator('#oracle-stop').click();
    await page.locator('#oracle-stop').waitFor({ state: 'hidden', timeout: 10000 });
    const elapsed = Math.round(performance.now() - stopBegan), resultText = await page.locator('#oracle-result').textContent();
    assert.match(resultText, /cancelled/i); assert(elapsed < 10000, 'Cancellation was not prompt');
    assert(!fs.existsSync(path.join(destination, 'sleep-finished.txt')), 'Cancelled child reached completion');
    let childAlive = true; const exitDeadline = performance.now() + 2000;
    while (childAlive && performance.now() < exitDeadline) {
      try { process.kill(childPid, 0); } catch (error) { if (error.code === 'ESRCH') childAlive = false; else throw error; }
      if (childAlive) await new Promise(resolve => setTimeout(resolve, 50));
    }
    assert.equal(childAlive, false, 'Cancelled oracle left its actual child process alive');
    assert.deepEqual(fs.readdirSync(path.join(destination, 'quixi-oracle-runs')).sort(), reportsBefore, 'Cancellation saved a comparison report');
    activeOperation = null;
    report.checks.push({ name: 'oracle-scoped-cancellation', status: 'passed', durationMs: elapsed, rejectedStopRequests: 2, savedCancelledReport: false });
    assert.deepEqual(report.jsErrors, []);
  } finally {
    if (native && activeOperation) await native('oracle-stop', { project: activeOperation.project, operationId: activeOperation.operationId }).catch(() => {});
    if (native && original && project) {
      await native('rea/settings', { project: project.id, ...original.settings }).catch(() => {});
      await native('rea/connect', { project: project.id, mode: original.settings.mode }).catch(() => {});
    }
    await browser.close();
  }
})().then(() => { report.status = 'passed'; }).catch(error => { report.status = 'failed'; report.error = error.stack || String(error); process.exitCode = 1; }).finally(() => {
  report.durationMs = Math.round(performance.now() - began); report.finishedAt = new Date().toISOString();
  if (output) fs.writeFileSync(output, JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify({ ...report, reportPath: output }));
});
