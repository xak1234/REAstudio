// Optional real Agent model integration. No fixture server or simulated replies.
// Default: exact file read/write. --analysis: actual Ghidra calls and cited evidence.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { chromium } = require(process.env.QUIXI_TEST_PLAYWRIGHT_MODULE || 'playwright-core');

function payload(record) {
  if (record.response?.structuredContent) return record.response.structuredContent;
  const text = record.response?.content?.find(item => item.type === 'text')?.text;
  assert(text, 'The actual tool response must contain evidence');
  return JSON.parse(text);
}

(async () => {
  const root = process.env.QUIXI_SMOKE_ROOT, config = process.env.REA_STUDIO_PROVIDER_CONFIG;
  assert(root && config, 'Set the dedicated fixture and private provider configuration path');
  const analysis = process.argv.includes('--analysis');
  const saved = JSON.parse(fs.readFileSync(config, 'utf8'));
  const provider = saved.providers.find(p => p.id === (process.env.REA_STUDIO_PROVIDER_ID || 'custom'));
  assert(provider, 'Provider is not configured');
  const model = process.env.REA_STUDIO_AGENT_MODEL || provider.selectedModel;
  assert(model, 'Choose an actual served Agent model');
  const browser = await chromium.connectOverCDP(process.env.REA_STUDIO_TEST_CDP || 'http://127.0.0.1:9323');
  const page = browser.contexts()[0].pages().find(p => p.url().includes('app.localhost/playground'));
  assert(page);
  const errors = []; page.on('pageerror', e => errors.push(e.message));
  const call = (route, data = {}) => page.evaluate(async ({route, data}) => {
    const r = await fetch('/api/quixi/' + route, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
    const v = await r.json(); if (!r.ok || v.error) throw Error(v.error || String(r.status)); return v;
  }, {route, data});
  const pg = (route, data = {}) => call('playground/' + route, data);
  const nonce = crypto.randomUUID(), name = 'agent-check-' + nonce;
  const target = path.join(root, 'quixi-fixture.exe');
  let run;
  const started = Date.now();
  try {
    const project = await pg('project', {path:root});
    await call('providers/save', {providerId:provider.id,baseUrl:provider.baseUrl,apiKey:provider.apiKeyRaw || '',selectedModel:model,customModel:model,contextWindow:32768,setAsActive:true,completeOnboarding:true});
    const connection = await call('providers/test', {providerId:provider.id});
    assert(connection.ok && connection.discoveredModels.includes(model), 'The exact chosen Agent model must be advertised by the actual endpoint');
    await assert.rejects(pg('run', {project:project.id,provider:provider.id,model:'unconfigured-model-' + nonce,mode:'ask',prompt:'This request must be rejected before calling a model.'}), /does not substitute|not offered/, 'Unknown explicit models must not silently fall back');
    let prompt;
    if (analysis) {
      assert(fs.existsSync(target), 'Build the source-known native fixture first');
      await pg('rea/select', {path:target});
      await pg('rea/connect');
      const opened = await pg('rea/tool', {tool:'open_binary',arguments:{path:target,provider_id:'ghidra'}});
      assert.equal(opened.failed, false, 'The actual Ghidra target must open');
      prompt = 'Inspect only the selected source-known test fixture function quixi_add. First use rea_tools to read the canonical schema for analyze_function, then call rea analyze_function with procedure quixi_add and detail summary. Next read the schema for procedure_pseudo_code, then call that tool for quixi_add. Finish with a done action explaining the arithmetic actually visible in its pseudocode, citing a returned saved record ID or Evidence ID. State that static decompilation does not establish whole-application equivalence. Do not read source files, execute commands or the target, write files, or call the Decompile helper. Use actual returned evidence; if either operation fails, report that failure.';
    } else {
      fs.writeFileSync(path.join(root, name + '.txt'), nonce + '\n');
      prompt = 'Read the file ' + name + '.txt using the read action. Then use the write action to create ' + name + '-result.txt containing exactly the same bytes, including the newline. Do not run shell commands or change other files. Finish with a done action after the write succeeds.';
    }
    run = await pg('run', {project:project.id,provider:provider.id,model,mode:analysis?'ask':'code',reaEnabled:analysis,maxSteps:analysis?12:8,maxOutputTokens:analysis?2048:1024,confirmCommands:'all',prompt});
    let final;
    for (let i = 0; i < (analysis ? 300 : 180); i++) {
      const state = await page.evaluate(async () => { const r = await fetch('/api/quixi/playground/state'); if (!r.ok) throw Error('Could not read run status'); return r.json(); });
      final = state.runs.find(r => r.id === run.id);
      if (final && !['running','stopping','awaiting_approval'].includes(final.status)) break;
      if (final?.status === 'awaiting_approval') throw Error('Model requested an unexpected shell command');
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
    assert.equal(final?.status, 'completed', final?.reply || 'Agent did not finish within the bounded test window');
    assert.equal(final.provider, provider.id, 'The requested connection must handle this run');
    assert.equal(final.model, model, 'The exact requested model must handle this run');
    assert(!final.actualModel, 'The run must not substitute another model');
    assert(final.contextLimits && final.checkpoint, 'Run must retain context and checkpoint metadata');
    const result = {passed:true,mode:analysis?'analysis':'files',model,provider:provider.id,run:run.id,steps:final.steps,durationMs:Date.now()-started,exactProvider:true,unknownModelRejected:true,checkpoint:true};
    if (analysis) {
      assert(final.events.some(e => e.kind === 'rea_tools'), 'The real model must inspect live tool schemas');
      assert(!final.events.some(e => ['command','write','read','decompile_assist'].includes(e.kind)), 'Analysis must be driven by actual native tool evidence');
      const records = [];
      for (const tool of ['analyze_function','procedure_pseudo_code']) {
        const event = final.events.find(e => e.kind === 'rea' && e.detail.tool === tool && e.detail.failed === false);
        assert(event?.detail.record, 'Model must successfully call ' + tool);
        const record = await pg('rea/evidence', {id:event.detail.record});
        assert.equal(record.failed, false);
        assert.equal(record.tool, tool);
        assert.equal(record.arguments.procedure, 'quixi_add');
        assert.equal(record.artifactIdentity.status, 'verified');
        assert.equal(record.artifactIdentity.sha256, crypto.createHash('sha256').update(fs.readFileSync(target)).digest('hex'));
        const evidence = payload(record);
        if (tool === 'analyze_function' && evidence.provider.id === 'rea-analysis-view') {
          assert.equal(evidence.operation, 'inspect_analysis_view');
          assert.equal(evidence.normalized_result.parent_operation, 'analyze_function');
          assert.equal(evidence.normalized_result.summary.procedure.name, 'quixi_add');
          const bundleRecord = await pg('rea/tool', {tool:'get_evidence_bundle',arguments:{detail:'complete'},persist:false});
          assert.equal(bundleRecord.failed, false);
          const parent = payload(bundleRecord).result.records.find(r => r.evidence_id === evidence.normalized_result.parent_evidence_id);
          assert(parent, 'Summary must resolve to its actual retained parent evidence');
          assert.equal(parent.operation, 'analyze_function');
          assert.equal(parent.provider.id, 'ghidra', 'The original observation must come from actual Ghidra');
          assert.equal(parent.analysis_profile.provider.id, 'ghidra');
          assert.equal(parent.subject.digest.sha256, record.artifactIdentity.sha256);
        } else {
          assert.equal(evidence.provider.id, 'ghidra');
          assert.equal(evidence.analysis_profile.provider.id, 'ghidra');
        }
        assert(evidence.evidence_id || evidence.normalized_result?.parent_evidence_id, 'Saved result must carry genuine evidence identity');
        if (tool === 'procedure_pseudo_code') {
          const code = JSON.stringify(evidence.normalized_result);
          assert.match(code, /quixi_add/);
          assert.match(code, /\+/, 'Source-known addition must occur in actual pseudocode');
        }
        records.push({tool,record:record.id,evidence:evidence.evidence_id || evidence.normalized_result.parent_evidence_id});
      }
      assert(records.some(r => final.reply.includes(r.record) || final.reply.includes(r.evidence)), 'Final answer must cite an actual saved evidence identifier');
      assert.match(final.reply, /add|sum|\+/i, 'Final answer must explain the observed addition');
      assert.match(final.reply, /static|equivalence|runtime|unverified/i, 'Final answer must preserve analysis limitations');
      result.records = records; result.realNativeAnalysis = true;
    } else {
      assert(final.events.some(e => e.kind === 'read'), 'Model must actually read the random input file');
      assert(final.events.some(e => e.kind === 'write'), 'Model must actually write the result');
      assert.equal(fs.readFileSync(path.join(root, name + '-result.txt'), 'utf8'), nonce + '\n');
      Object.assign(result, {realRead:true,realWrite:true,exactOutput:true});
    }
    assert.deepEqual(errors, []);
    result.jsErrors = errors;
    console.log(JSON.stringify(result));
  } finally {
    if (run) { try { await pg('cancel', {id:run.id}); } catch {} }
    await browser.close();
  }
})().catch(e => { console.error(e); process.exitCode = 1; });
