// Real headless IDA bridge integration against an isolated Windows app profile.
// Requires your licensed IDA Pro 9.x with idalib and Install-IDA-Bridge.ps1 (or a chosen
// rea-headless-registration.json in Toolchain). Nothing is mocked.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const connectAppMcp = require('./mcp-test-client.cjs');
const { chromium } = require(process.env.QUIXI_TEST_PLAYWRIGHT_MODULE || 'playwright-core');
(async () => {
  const root = process.env.QUIXI_SMOKE_ROOT;
  assert(root, 'Set QUIXI_SMOKE_ROOT to the compiled native fixture');
  const target = path.join(root, 'quixi-fixture.exe');
  const hash = crypto.createHash('sha256').update(fs.readFileSync(target)).digest('hex');
  const browser = await chromium.connectOverCDP(process.env.REA_STUDIO_TEST_CDP || 'http://127.0.0.1:9323');
  const page = browser.contexts()[0].pages().find(p => p.url().includes('app.localhost/playground')); assert(page);
  page.setDefaultTimeout(15000); const errors = []; page.on('pageerror', e => errors.push(e.message));
  const native = (route, data = {}) => page.evaluate(async ({ route, data }) => {
    const r = await fetch('/api/quixi/playground/' + route, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
    const v = await r.json(); if (!r.ok) throw Error(v.error || String(r.status)); return v;
  }, { route, data });
  const call = (tool, args = {}) => native('ida/call', { tool, arguments: args });
  const text = r => (r.response?.content || []).filter(c => c.type === 'text').map(c => c.text).join('\n');
  const json = r => r.response?.structuredContent || JSON.parse(text(r));
  const sidecars = () => fs.readdirSync(root).filter(n => /\.(i64|idb|id0|id1|id2|nam|til)$/i.test(n));
  let mcp, restoreAddress;
  try {
    await page.reload(); await page.locator('#connection').filter({ hasText: 'Connected' }).waitFor();
    const before = await native('ida/status');
    assert.equal(before.installed, true, 'Install the headless IDA bridge first: ' + (before.registrationError || 'no registration'));
    assert.equal(before.connected, false, 'The bridge must start disabled');
    const existingSidecars = sidecars();
    await native('rea/select', { path: target });
    const enabled = await native('ida/enable', { transport: 'headless' });
    assert.equal(enabled.connected, true); assert.equal(enabled.transport, 'headless');
    for (const name of ['decompile', 'list_funcs', 'rename']) assert(enabled.tools.some(t => t.name === name && t.enabled), 'Missing live tool ' + name);
    for (const t of enabled.tools.filter(t => /^(py_|dbg_)|^(patch|patch_asm|put_int|idb_open|idb_close)$/.test(t.name))) assert.equal(t.kind, 'blocked', t.name);
    console.log('IDA bridge check: live catalog with ' + enabled.tools.length + ' tools');
    const opened = await native('ida/open');
    assert.equal(opened.provider, 'ida-bridge'); assert.equal(opened.kind, 'ida'); assert.equal(opened.failed, false, text(opened));
    assert.equal(opened.provenance.sha256, hash);
    const status = await native('ida/status');
    assert.equal(status.session.sha256, hash); assert.match(status.session.idbPath, /\.i64$/i);
    assert(!status.session.idbPath.toLowerCase().startsWith(root.toLowerCase()), 'The IDB must live in the private cache');
    assert.deepEqual(sidecars(), existingSidecars, 'Nothing may be written beside the original artifact');
    const funcs = await call('list_funcs', { queries: { filter: '*quixi_add*', count: 5 } });
    assert.equal(funcs.failed, false, text(funcs));
    const listing = json(funcs); const page0 = (listing.result || listing)[0];
    let address = (page0?.data || []).find(f => f.name === 'quixi_add')?.addr;
    if (!address) {
      const looked = json(await call('lookup_funcs', { queries: 'quixi_add' }));
      address = (looked.result || looked)[0]?.fn?.addr;
    }
    if (!address) {
      // An interrupted earlier smoke may have persisted its own rename in this fixture's private cache.
      const prior = json(await call('list_funcs', { queries: { filter: 'rea_smoke_*', count: 100 } }));
      const candidates = ((prior.result || prior)[0]?.data || []).filter(f => /^rea_smoke_[a-f0-9]{8}$/.test(f.name));
      assert.equal(candidates.length, 1, 'Expected quixi_add or exactly one prior smoke-owned rename in the fixture IDB');
      address = candidates[0].addr;
    }
    assert(address, 'IDA did not identify the fixture function quixi_add'); restoreAddress = address;
    const decompiled = await call('decompile', { addr: address });
    assert.equal(decompiled.failed, false, text(decompiled)); assert.match(text(decompiled), /return|\+/);
    const xrefs = await call('xrefs_to', { addrs: address }); assert.equal(xrefs.failed, false, text(xrefs));
    const newName = 'rea_smoke_' + crypto.randomBytes(4).toString('hex');
    const renamed = await call('rename', { batch: { func: [{ addr: address, name: newName }] } });
    assert.equal(renamed.failed, false, text(renamed)); assert.equal(renamed.provenance.savedAfterAnnotation, true);
    await assert.rejects(() => call('py_eval', { code: '1+1' }), /not available through the IDA bridge/);
    await assert.rejects(() => call('patch', { patches: [{ addr: address, data: '90' }] }), /not available through the IDA bridge/);
    await assert.rejects(() => call('idb_save', { path: path.join(root, 'elsewhere.i64') }), /destination/);
    assert.equal(fs.existsSync(path.join(root, 'elsewhere.i64')), false, 'Rejected save must not write another database');
    await native('ida/settings', { allowAnnotations: false });
    await assert.rejects(() => call('set_comments', { items: { addr: address, comment: 'x' } }), /Allow annotations/);
    await native('ida/settings', { allowAnnotations: true });
    await native('rea/select', { path: path.join(root, 'app.js') });
    await assert.rejects(() => call('decompile', { addr: address }), /differs/);
    await native('rea/select', { path: target });
    const saved = await native('rea/evidence', { id: decompiled.id });
    assert.equal(saved.provider, 'ida-bridge'); assert.equal(saved.kind, 'ida'); assert.equal(saved.provenance.sha256, hash);
    mcp = await connectAppMcp(page);
    assert.equal((await mcp.call('studio_ida_status')).connected, true);
    assert((await mcp.call('studio_ida_status', { tool: 'decompile' })).inputSchema);
    const external = await mcp.call('studio_ida_call', { tool: 'decompile', arguments: { addr: address } });
    assert.equal(external.failed, false); assert.equal(external.provider, 'ida-bridge');
    const refused = await mcp.client.callTool({ name: 'studio_ida_call', arguments: { tool: 'py_eval', arguments: { code: '1' } } });
    assert.equal(refused.isError, true);
    // Close saves the database; a fresh supervisor reopens it with the annotation intact.
    assert.equal((await native('ida/close')).failed, false);
    await native('ida/disable'); assert.equal((await native('ida/status')).connected, false);
    await native('ida/enable', { transport: 'headless' }); await native('ida/open');
    const after = await call('lookup_funcs', { queries: address });
    assert.match(text(after), new RegExp(newName), 'The rename must persist in the cached database');
    assert.equal(crypto.createHash('sha256').update(fs.readFileSync(target)).digest('hex'), hash, 'The artifact must be unchanged');
    const restored = await call('rename', { batch: { func: [{ addr: address, name: 'quixi_add' }] } });
    assert.equal(restored.failed, false, text(restored)); assert.equal(restored.provenance.savedAfterAnnotation, true);
    assert.match(text(await call('lookup_funcs', { queries: address })), /quixi_add/); restoreAddress = null;
    assert.equal((await native('ida/close')).failed, false);
    await native('ida/disable');
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ passed: true, tools: enabled.tools.length, function: address, renamedTo: newName,
      openRecord: opened.id, decompileRecord: decompiled.id, renameRecord: renamed.id, idbPath: status.session.idbPath, jsErrors: errors }));
  } finally {
    if (restoreAddress) {
      try {
        const status = await native('ida/status');
        if (status.connected && status.session) {
          await native('rea/select', { path: target }); await native('ida/settings', { allowAnnotations: true });
          const restored = await call('rename', { batch: { func: [{ addr: restoreAddress, name: 'quixi_add' }] } });
          assert.equal(restored.failed, false, text(restored));
        }
      } catch (error) { console.error('Fixture-name cleanup failed; the next smoke can recover its own prior rename:', error.message); }
    }
    try { await native('ida/disable'); } catch {} if (mcp) await mcp.close(); await browser.close();
  }
})().catch(e => { console.error(e); process.exitCode = 1; });
