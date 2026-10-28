// Real attached IDA integration. Use a separate app profile and the native fixture.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { chromium } = require(process.env.QUIXI_TEST_PLAYWRIGHT_MODULE || 'playwright-core');

(async () => {
  const root = process.env.QUIXI_SMOKE_ROOT;
  assert(root, 'Set QUIXI_SMOKE_ROOT and open its quixi-fixture.exe in IDA first');
  const target = path.join(root, 'quixi-fixture.exe');
  const original = fs.readFileSync(target);
  const hash = crypto.createHash('sha256').update(original).digest('hex');
  const output = fs.mkdtempSync(path.join(os.tmpdir(), 'rea-ida-check-'));
  const browser = await chromium.connectOverCDP(process.env.REA_STUDIO_TEST_CDP || 'http://127.0.0.1:9323');
  const page = browser.contexts()[0].pages().find(p => p.url().includes('app.localhost/playground'));
  assert(page, 'REA Studio test WebView was not found');
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  const pg = (route, data = {}) => page.evaluate(async ({ route, data }) => {
    const response = await fetch('/api/quixi/playground/' + route, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
    });
    const result = await response.json();
    if (!response.ok) throw Error(JSON.stringify(result));
    return result;
  }, { route, data });
  const connected = async () => (await pg('toolchain/sources')).sources.find(s => s.id === 'ida')?.connected;
  const invoke = (tool, args = {}) => pg('rea/tool', { tool, arguments: args });
  try {
    await pg('project', { path: root });
    await pg('rea/select', { path: target });
    const catalog = await pg('rea/connect', { mode: 'bundled' });
    for (const name of ['open_binary', 'list_procedures', 'procedure_pseudo_code', 'procedure_assembly', 'close_binary']) {
      assert(catalog.tools.some(t => t.name === name), 'Required live tool missing: ' + name);
    }
    assert.equal((await invoke('open_binary', { path: target, provider_id: 'ida' })).failed, false);
    assert.equal(await connected(), false, 'A lazy file opening is not proof that IDA answered');
    const records = [];
    for (const [tool, args] of [
      ['list_procedures', {}],
      ['procedure_pseudo_code', { procedure: 'quixi_add' }],
      ['procedure_pseudo_code', { procedure: 'main' }],
      ['procedure_assembly', { procedure: 'quixi_add' }],
    ]) {
      const record = await invoke(tool, args);
      assert.equal(record.failed, false, JSON.stringify(record));
      const evidence = record.response.structuredContent;
      assert.equal(evidence.provider.id, 'ida');
      assert.equal(evidence.subject.digest.sha256, hash);
      assert.equal(evidence.raw_result.metadata_before.sha256, hash);
      assert.equal(evidence.raw_result.metadata_after.sha256, hash);
      assert(JSON.stringify(evidence.normalized_result).includes('quixi_add') || tool === 'procedure_assembly');
      if (tool === 'procedure_assembly') assert.match(evidence.normalized_result, /\badd\b/);
      assert.deepEqual(await pg('rea/evidence', { id: record.id }), record);
      records.push(record);
    }
    assert.equal(await connected(), true);
    await page.locator('[data-view=analysis]').click();
    await page.evaluate(async () => { await refreshState(); await refreshAnalysisSources(); await loadAnalysisHistory(); });
    await page.locator('#analysis-source').selectOption('ida');
    await page.evaluate(() => refreshConnectionBadges());
    assert.match(await page.locator('#analysis-connections').textContent(), /IDA.*Connected/);
    const badge = page.locator('#analysis-connections .badge.completed').filter({ hasText: 'IDA' });
    assert.equal(await badge.count(), 1);
    await page.evaluate(async id => renderEvidence(await pg('rea/evidence', { id })), records[1].id);
    await page.screenshot({ path: path.join(output, 'ida-connected.png'), fullPage: true });

    assert.equal((await invoke('close_binary')).failed, false);
    assert.equal(await connected(), false);
    // The adapter checks IDA's input identity on the first actual provider call.
    const different = path.join(output, 'different-fixture.exe');
    fs.writeFileSync(different, Buffer.concat([original, Buffer.from('IDA identity check\n')]));
    assert.equal((await invoke('open_binary', { path: different, provider_id: 'ida' })).failed, false);
    assert.equal(await connected(), false);
    const mismatch = await invoke('list_procedures');
    assert.equal(mismatch.failed, true);
    assert.match(JSON.stringify(mismatch.response), /SHA-256 does not match/);
    assert.equal(await connected(), false);
    await page.evaluate(() => refreshConnectionBadges());
    assert(!/IDA.*Connected/.test(await page.locator('#analysis-connections').textContent()));
    assert.equal(crypto.createHash('sha256').update(fs.readFileSync(target)).digest('hex'), hash);
    assert.deepEqual(errors, []);
    const result = { passed: true, tools: catalog.tools.length, records: records.map(r => r.id), mismatchRecord: mismatch.id, output, jsErrors: errors };
    fs.writeFileSync(path.join(output, 'result.json'), JSON.stringify(result, null, 2));
    console.log(JSON.stringify(result));
  } finally {
    await invoke('close_binary').catch(() => {});
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
